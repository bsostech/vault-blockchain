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
	"errors"
	"fmt"
	"net/http"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/bsostech/vault-blockchain/internal/model"
	"github.com/bsostech/vault-blockchain/internal/path/byok"
	"github.com/bsostech/vault-blockchain/pkg/utils"
)

// pathDerivedAccountExportBYOK registers byok/export/wallet/:wallet_id/accounts/:index for exporting one
// derived account's private key wrapped as a .byok blob, in the same PKCS#8 format as
// byok/export/account/:name. It is for receivers without BIP-32, such as cloud KMSs, which cannot use the
// seed from byok/export/wallet/:wallet_id.
//
// Like the other exports it lives outside wallets/, so the user policy's wallets/<entity>/* never grants it.
func pathDerivedAccountExportBYOK() *framework.Path {
	return &framework.Path{
		Pattern: "byok/export/wallet/" + framework.GenericNameRegex("wallet_id") +
			"/accounts/(?P<index>\\d+)",
		HelpSynopsis: "Export one derived HD wallet account's private key wrapped for another party's KEK.",
		HelpDescription: "Derives the private key at m/44'/60'/0'/0/<index>, checks it against the stored " +
			"account address, and returns it wrapped as PKCS#8 in a .byok blob, the same format as an " +
			"account export. The account must already exist. The wallet is not changed. Only that one key " +
			"leaves vault-blockchain, but grant byok/export/ only to trusted operators.",
		Fields: byok.ExportFields(map[string]*framework.FieldSchema{
			"wallet_id": {
				Type:        framework.TypeString,
				Description: "Identifier of the wallet, in the path.",
			},
			"index": {
				Type:        framework.TypeString,
				Description: "BIP-44 address index of an existing derived account (max 2147483647), in the path.",
			},
		}),
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: handleDerivedAccountExportBYOK,
		},
	}
}

// handleDerivedAccountExportBYOK wraps one derived account's private key for a receiving KEK public key.
func handleDerivedAccountExportBYOK(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	wrapper := model.NewFieldDataWrapper(data)
	walletID, err := wrapper.MustGetString("wallet_id")
	if err != nil || walletID == "" {
		return logical.ErrorResponse("wallet_id is required"), nil
	}
	indexStr, err := wrapper.MustGetString("index")
	if err != nil || indexStr == "" {
		return logical.ErrorResponse("index is required"), nil
	}
	index, err := ParseAddressIndex(indexStr)
	if err != nil {
		return byok.RespondCode(req, http.StatusBadRequest, "invalid_index", err.Error())
	}
	export, errResp := byok.ParseExportRequest(data)
	if errResp != nil {
		return errResp, nil
	}

	// Checks the derived key against the stored address, so a damaged entry fails here instead of exporting
	// a key for a different address than the caller sees.
	priv, derived, err := LoadWalletDerivedPrivateKey(ctx, req.Storage, walletID, indexStr)
	if err != nil {
		if errors.Is(err, ErrDerivedAccountMissing) {
			return byok.RespondCode(req, http.StatusNotFound, "account_not_found", "derived account not found")
		}
		return nil, err
	}
	defer utils.ZeroKey(priv)

	wrapped, err := export.WrapPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("wrap private key for wallet %s index %d: %w", walletID, index, err)
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"byok_blob":             wrapped.Blob,
			"wallet_id":             walletID,
			"index":                 index,
			"address":               derived.Address,
			"derivation_path":       derived.DerivationPath,
			"kek_public_key_sha256": wrapped.KEKFingerprint,
		},
	}, nil
}
