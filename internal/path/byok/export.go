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

package byok

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/bsostech/vault-blockchain/internal/byokcrypto"
	"github.com/bsostech/vault-blockchain/internal/model"
	"github.com/bsostech/vault-blockchain/internal/version"
	"github.com/bsostech/vault-blockchain/pkg/utils"
)

// ExportRequest is the validated receiving side of an export call.
type ExportRequest struct {
	// KID identifies the receiving KEK and is written to the blob header.
	KID string
	// KEK is the receiving KEK public key the plaintext is wrapped for.
	KEK *rsa.PublicKey
}

// ExportFields returns the request fields shared by every export path, merged with the path's own fields.
func ExportFields(pathFields map[string]*framework.FieldSchema) map[string]*framework.FieldSchema {
	fields := map[string]*framework.FieldSchema{
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
	}
	for name, schema := range pathFields {
		fields[name] = schema
	}
	return fields
}

// ParseExportRequest validates kid and kek_public_key_pem. When they are invalid it returns the error
// response to send back instead of an ExportRequest.
func ParseExportRequest(data *framework.FieldData) (*ExportRequest, *logical.Response) {
	wrapper := model.NewFieldDataWrapper(data)
	kid := strings.TrimSpace(wrapper.GetString("kid", ""))
	if kid == "" {
		return nil, logical.ErrorResponse("kid is required")
	}
	if len(kid) > MaxKIDLength {
		return nil, logical.ErrorResponse("kid is longer than %d bytes", MaxKIDLength)
	}
	pemStr := wrapper.GetString("kek_public_key_pem", "")
	if pemStr == "" {
		return nil, logical.ErrorResponse("kek_public_key_pem is required")
	}
	kekPub, err := byokcrypto.ParseKEKPublicKeyPEM(pemStr)
	if err != nil {
		// A 400 from RespondCode is a plain error response; build it directly so no error can be dropped.
		return nil, logical.ErrorResponse("%s: %s", "invalid_kek_public_key", InvalidKEKPublicKeyMessage)
	}
	return &ExportRequest{KID: kid, KEK: kekPub}, nil
}

// WrappedExport is a wrapped plaintext ready to return to the caller.
type WrappedExport struct {
	// Blob is the whole .byok file, Base64 encoded (standard alphabet).
	Blob string
	// KEKFingerprint is the SHA-256 of the KEK public key's DER, for the caller to compare with the receiver.
	KEKFingerprint string
}

// Wrap wraps plaintext for the request's KEK. keyType is empty for PKCS#8 and names the format otherwise.
// The caller owns and zeroes plaintext.
func (r *ExportRequest) Wrap(plaintext []byte, keyType string) (*WrappedExport, error) {
	blob, err := byokcrypto.WrapKey(r.KEK, r.KID, plaintext, "vault-blockchain v"+version.Version)
	if err != nil {
		return nil, err
	}
	blob.KeyType = keyType
	encoded, err := blob.Encode()
	if err != nil {
		return nil, err
	}
	fingerprint, err := byokcrypto.PublicKeyFingerprint(r.KEK)
	if err != nil {
		return nil, err
	}
	return &WrappedExport{Blob: encoded, KEKFingerprint: fingerprint}, nil
}

// WrapPrivateKey encodes priv as secp256k1 PKCS#8 and wraps it for the request's KEK. The PKCS#8 bytes are
// zeroed before returning; priv is left to the caller.
func (r *ExportRequest) WrapPrivateKey(priv *ecdsa.PrivateKey) (*WrappedExport, error) {
	pkcs8, err := byokcrypto.MarshalSecp256k1PKCS8(priv)
	if err != nil {
		return nil, fmt.Errorf("encode private key: %w", err)
	}
	defer utils.ZeroBytes(pkcs8)
	return r.Wrap(pkcs8, "")
}
