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

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/bsostech/vault-blockchain/internal/model"
	"github.com/bsostech/vault-blockchain/internal/path/byok"
	"github.com/bsostech/vault-blockchain/pkg/utils"
)

// pathSingleKeyExportBYOK registers byok/export/account/:name for exporting an account key wrapped as a .byok blob.
//
// It deliberately lives outside accounts/: the user policy grants accounts/<entity>/*, and a path under it
// would hand every user a way to take their own private key out. Policies that do not name byok/export/
// never match it.
func pathSingleKeyExportBYOK() *framework.Path {
	return &framework.Path{
		Pattern:      "byok/export/account/" + framework.GenericNameRegex("name"),
		HelpSynopsis: "Export an account private key wrapped for another party's key exchange key (KEK).",
		HelpDescription: "Wraps the account's private key for the given RSA public key and returns a .byok blob. " +
			"The account is not changed. Only the holder of the matching KEK private key can unwrap it, " +
			"so grant byok/export/ only to trusted operators.",
		Fields: byok.ExportFields(map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the account to export, in the path.",
			},
		}),
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: handleSingleKeyAccountExportBYOK,
		},
	}
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
	export, errResp := byok.ParseExportRequest(data)
	if errResp != nil {
		return errResp, nil
	}

	acct, err := ReadSingleKeyAccount(ctx, req.Storage, name)
	if err != nil {
		if errors.Is(err, ErrSingleKeyAccountMissing) {
			return byok.RespondCode(req, http.StatusNotFound, "account_not_found", "account not found")
		}
		return nil, err
	}
	priv, err := acct.GetPrivateKeyECDSA()
	if err != nil {
		return nil, fmt.Errorf("parse stored private key for %s: %w", name, err)
	}
	defer utils.ZeroKey(priv)

	wrapped, err := export.WrapPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("wrap private key for %s: %w", name, err)
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"byok_blob":             wrapped.Blob,
			"address":               acct.AddressStr,
			"kek_public_key_sha256": wrapped.KEKFingerprint,
		},
	}, nil
}
