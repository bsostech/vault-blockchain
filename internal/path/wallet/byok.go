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

package wallet

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/tyler-smith/go-bip39"

	"github.com/bsostech/vault-blockchain/internal/byokcrypto"
	"github.com/bsostech/vault-blockchain/internal/model"
	"github.com/bsostech/vault-blockchain/internal/path/byok"
	"github.com/bsostech/vault-blockchain/internal/version"
	"github.com/bsostech/vault-blockchain/pkg/utils"
)

// pathWalletExportBYOK registers byok/export/wallet/:wallet_id for exporting an HD wallet's BIP-39 seed
// wrapped as a .byok blob.
//
// It deliberately lives outside wallets/: the user policy grants wallets/<entity>/*, and a path under it
// would hand every user a way to take their own seed out. Policies that do not name byok/export/ never
// match it.
func pathWalletExportBYOK() *framework.Path {
	return &framework.Path{
		Pattern:      "byok/export/wallet/" + framework.GenericNameRegex("wallet_id"),
		HelpSynopsis: "Export an HD wallet's BIP-39 seed wrapped for another party's key exchange key (KEK).",
		HelpDescription: "Wraps the wallet's 64-byte BIP-39 seed (empty passphrase) for the given RSA public key and " +
			"returns a .byok blob with key_type bip39-seed. The wallet is not changed. The seed derives every " +
			"account of the wallet, so grant byok/export/ only to trusted operators.",
		Fields: map[string]*framework.FieldSchema{
			"wallet_id": {
				Type:        framework.TypeString,
				Description: "Identifier of the wallet to export, in the path.",
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
			logical.UpdateOperation: handleWalletExportBYOK,
		},
	}
}

// handleWalletExportBYOK wraps a wallet's BIP-39 seed for a receiving KEK public key.
func handleWalletExportBYOK(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	wrapper := model.NewFieldDataWrapper(data)
	walletID, err := wrapper.MustGetString("wallet_id")
	if err != nil || walletID == "" {
		return logical.ErrorResponse("wallet_id is required"), nil
	}
	kid := strings.TrimSpace(wrapper.GetString("kid", ""))
	if kid == "" {
		return logical.ErrorResponse("kid is required"), nil
	}
	if len(kid) > byok.MaxKIDLength {
		return logical.ErrorResponse("kid is longer than %d bytes", byok.MaxKIDLength), nil
	}
	pemStr := wrapper.GetString("kek_public_key_pem", "")
	if pemStr == "" {
		return logical.ErrorResponse("kek_public_key_pem is required"), nil
	}
	kekPub, err := byokcrypto.ParseKEKPublicKeyPEM(pemStr)
	if err != nil {
		return byok.RespondCode(req, http.StatusBadRequest, "invalid_kek_public_key", byok.InvalidKEKPublicKeyMessage)
	}

	stored, err := ReadWalletSeed(ctx, req.Storage, walletID)
	if err != nil {
		return nil, err
	}
	if stored == nil || stored.Mnemonic == "" {
		return byok.RespondCode(req, http.StatusNotFound, "wallet_not_found", "wallet not found")
	}
	if !bip39.IsMnemonicValid(stored.Mnemonic) {
		return nil, fmt.Errorf("stored mnemonic for wallet %s is invalid", walletID)
	}
	// Same seed the wallet derives its accounts from: BIP-39 with an empty passphrase.
	seed := bip39.NewSeed(stored.Mnemonic, "")
	defer utils.ZeroBytes(seed)

	blob, err := byokcrypto.WrapKey(kekPub, kid, seed, "vault-blockchain v"+version.Version)
	if err != nil {
		return nil, fmt.Errorf("wrap seed for wallet %s: %w", walletID, err)
	}
	blob.KeyType = byokcrypto.KeyTypeBIP39Seed
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
			"wallet_id":             walletID,
			"key_type":              byokcrypto.KeyTypeBIP39Seed,
			"kek_public_key_sha256": fingerprint,
		},
	}, nil
}
