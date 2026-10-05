// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at

//   http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package account

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/bsostech/vault-blockchain/internal/byokcrypto"
	"github.com/bsostech/vault-blockchain/internal/model"
	"github.com/bsostech/vault-blockchain/internal/path/byok"
	"github.com/bsostech/vault-blockchain/internal/version"
	"github.com/bsostech/vault-blockchain/pkg/utils"
)

// maxKIDLength bounds the kid accepted on export, which is copied into the blob header.
const maxKIDLength = 1024

// pathSingleKeyImportBYOK registers accounts/:name/import-byok for importing a key wrapped as a .byok blob.
func pathSingleKeyImportBYOK() *framework.Path {
	return &framework.Path{
		Pattern:      "accounts/" + framework.GenericNameRegex("name") + "/import-byok",
		HelpSynopsis: "Import a private key wrapped for a BYOK key exchange key (KEK).",
		HelpDescription: "Takes a .byok blob wrapped with the public key of a KEK created under byok/keks, " +
			"unwraps it inside the plugin, and stores the secp256k1 key as a single-key account.",
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Logical account name in the path.",
			},
			"byok_blob": {
				Type:        framework.TypeString,
				Required:    true,
				Description: "Contents of the .byok file, Base64 encoded.",
			},
		},
		ExistenceCheck: ExistenceSingleKeyAccountSeed(),
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: handleSingleKeyAccountImportBYOK,
			logical.UpdateOperation: handleSingleKeyAccountUpdate,
		},
	}
}

// pathSingleKeyExportBYOK registers byok/export/:name for exporting an account key wrapped as a .byok blob.
//
// It deliberately lives outside accounts/: the user policy grants accounts/<entity>/*, and a path under it
// would hand every user a way to take their own private key out. Policies that do not name byok/export/
// never match it.
func pathSingleKeyExportBYOK() *framework.Path {
	return &framework.Path{
		Pattern:      "byok/export/" + framework.GenericNameRegex("name"),
		HelpSynopsis: "Export an account private key wrapped for another party's key exchange key (KEK).",
		HelpDescription: "Wraps the account's private key for the given RSA public key and returns a .byok blob. " +
			"The account is not changed. Only the holder of the matching KEK private key can unwrap it, " +
			"so grant byok/export/ only to trusted operators.",
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the account to export, in the path.",
			},
			"kid": {
				Type:        framework.TypeString,
				Required:    true,
				Description: "Identifier of the receiving KEK, written to the blob header.",
			},
			"kek_public_key_pem": {
				Type:        framework.TypeString,
				Required:    true,
				Description: "Receiving KEK public key as PEM (RSA 2048, 3072, or 4096 bits).",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: handleSingleKeyAccountExportBYOK,
		},
	}
}

// respondCode returns an error response whose message starts with a machine-readable code, with the given
// HTTP status. A 400 is a plain Vault error response.
func respondCode(req *logical.Request, status int, code, msg string) (*logical.Response, error) {
	resp := logical.ErrorResponse("%s: %s", code, msg)
	if status == http.StatusBadRequest {
		return resp, nil
	}
	return logical.RespondWithStatusCode(resp, req, status)
}

// handleSingleKeyAccountImportBYOK unwraps a .byok blob with a stored KEK and stores the key as an account.
func handleSingleKeyAccountImportBYOK(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	wrapper := model.NewFieldDataWrapper(data)
	name, err := wrapper.MustGetString("name")
	if err != nil || name == "" {
		return logical.ErrorResponse("name is required"), nil
	}
	b64 := wrapper.GetString("byok_blob", "")
	if b64 == "" {
		return logical.ErrorResponse("byok_blob is required"), nil
	}

	blob, err := byokcrypto.ParseBlob(b64)
	if err != nil {
		return respondCode(req, http.StatusBadRequest, "invalid_blob", err.Error())
	}

	kekName, kekID, ok := byok.ParseKID(blob.Header.KID)
	if !ok {
		return respondCode(req, http.StatusNotFound, "kek_not_found", "no kek matches the blob kid")
	}
	kek, err := byok.LoadKEK(ctx, req.Storage, kekName)
	if err != nil {
		return nil, err
	}
	if kek == nil || kek.ID != kekID {
		return respondCode(req, http.StatusNotFound, "kek_not_found", "no kek matches the blob kid")
	}
	defer utils.ZeroBytes(kek.PrivateKeyDER)
	if kek.Expired(time.Now()) {
		return respondCode(req, http.StatusGone, "kek_expired", "the kek has expired")
	}

	// Fail early on a taken name, before doing any private key work.
	if _, err := ReadSingleKeyAccount(ctx, req.Storage, name); err == nil {
		return respondCode(req, http.StatusConflict, "account_exists", "account already exists")
	} else if !errors.Is(err, ErrSingleKeyAccountMissing) {
		return nil, err
	}

	rsaKey, err := kek.PrivateKey()
	if err != nil {
		return nil, err
	}
	pkcs8, err := byokcrypto.UnwrapKey(rsaKey, blob)
	if err != nil {
		if errors.Is(err, byokcrypto.ErrInvalidBlob) {
			return respondCode(req, http.StatusBadRequest, "invalid_blob", err.Error())
		}
		return respondCode(req, http.StatusBadRequest, "unwrap_failed", "the blob could not be unwrapped with this kek")
	}
	defer utils.ZeroBytes(pkcs8)

	priv, err := byokcrypto.ParseSecp256k1PKCS8(pkcs8)
	if err != nil {
		if errors.Is(err, byokcrypto.ErrUnsupportedCurve) {
			return respondCode(req, http.StatusBadRequest, "unsupported_curve", err.Error())
		}
		return respondCode(req, http.StatusBadRequest, "invalid_key", err.Error())
	}
	defer utils.ZeroKey(priv)

	address := crypto.PubkeyToAddress(priv.PublicKey).Hex()
	publicKeyString := hexutil.Encode(crypto.FromECDSAPub(&priv.PublicKey))[4:]
	privHex := hexutil.Encode(crypto.FromECDSA(priv))[2:]

	acct := model.NewAccount(address, privHex, publicKeyString)
	if err := putSingleKeyAccountIfAbsent(ctx, req, name, acct); err != nil {
		if errors.Is(err, errSingleKeyAccountAlreadyExists) {
			return respondCode(req, http.StatusConflict, "account_exists", "account already exists")
		}
		return nil, err
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"address":    acct.AddressStr,
			"public_key": acct.PublicKeyStr,
		},
	}, nil
}

// handleSingleKeyAccountExportBYOK wraps an account private key for a receiving KEK public key.
func handleSingleKeyAccountExportBYOK(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	wrapper := model.NewFieldDataWrapper(data)
	name, err := wrapper.MustGetString("name")
	if err != nil || name == "" {
		return logical.ErrorResponse("name is required"), nil
	}
	kid := strings.TrimSpace(wrapper.GetString("kid", ""))
	if kid == "" {
		return logical.ErrorResponse("kid is required"), nil
	}
	if len(kid) > maxKIDLength {
		return logical.ErrorResponse("kid is longer than %d bytes", maxKIDLength), nil
	}
	pemStr := wrapper.GetString("kek_public_key_pem", "")
	if pemStr == "" {
		return logical.ErrorResponse("kek_public_key_pem is required"), nil
	}
	kekPub, err := byokcrypto.ParseKEKPublicKeyPEM(pemStr)
	if err != nil {
		return respondCode(req, http.StatusBadRequest, "invalid_kek_public_key",
			"kek_public_key_pem must be an RSA public key of 2048, 3072, or 4096 bits")
	}

	acct, err := ReadSingleKeyAccount(ctx, req.Storage, name)
	if err != nil {
		if errors.Is(err, ErrSingleKeyAccountMissing) {
			return respondCode(req, http.StatusNotFound, "account_not_found", "account not found")
		}
		return nil, err
	}
	priv, err := acct.GetPrivateKeyECDSA()
	if err != nil {
		return nil, fmt.Errorf("parse stored private key for %s: %w", name, err)
	}
	defer utils.ZeroKey(priv)

	pkcs8, err := byokcrypto.MarshalSecp256k1PKCS8(priv)
	if err != nil {
		return nil, fmt.Errorf("encode private key for %s: %w", name, err)
	}
	defer utils.ZeroBytes(pkcs8)

	blob, err := byokcrypto.WrapKey(kekPub, kid, pkcs8, "vault-blockchain v"+version.Version)
	if err != nil {
		return nil, fmt.Errorf("wrap private key for %s: %w", name, err)
	}
	encoded, err := blob.Encode()
	if err != nil {
		return nil, err
	}
	fingerprint, err := byokcrypto.PublicKeyFingerprint(kekPub)
	if err != nil {
		return nil, err
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"byok_blob":             encoded,
			"address":               acct.AddressStr,
			"kek_public_key_sha256": fingerprint,
		},
	}, nil
}
