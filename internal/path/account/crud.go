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
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/bsostech/vault-blockchain/internal/model"
	"github.com/bsostech/vault-blockchain/internal/path/storagekey"
	"github.com/bsostech/vault-blockchain/pkg/utils"
)

// errSingleKeyAccountAlreadyExists indicates a account already exists for name.
var errSingleKeyAccountAlreadyExists = errors.New("account already exists")

// respondSingleKeyAccountConflict returns HTTP 409 for duplicate single-key account operations.
func respondSingleKeyAccountConflict(req *logical.Request) (*logical.Response, error) {
	return logical.RespondWithStatusCode(
		logical.ErrorResponse("%s", errSingleKeyAccountAlreadyExists.Error()),
		req,
		http.StatusConflict,
	)
}

// putSingleKeyAccountIfAbsent writes the account JSON under accounts/<name>/address if missing.
func putSingleKeyAccountIfAbsent(
	ctx context.Context,
	req *logical.Request,
	name string,
	account *model.Account,
) error {
	key := storagekey.SingleKeyAccountKey(name)
	existing, err := req.Storage.Get(ctx, key)
	if err != nil {
		return fmt.Errorf("get single-key account %s: %w", name, err)
	}
	if existing != nil {
		return errSingleKeyAccountAlreadyExists
	}
	entry, err := logical.StorageEntryJSON(key, account)
	if err != nil {
		return fmt.Errorf("encode single-key account %s: %w", name, err)
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return fmt.Errorf("put single-key account %s: %w", name, err)
	}
	return nil
}

// handleSingleKeyAccountCreate generates a new keypair and stores it under the given account name.
func handleSingleKeyAccountCreate(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	name, err := model.NewFieldDataWrapper(data).MustGetString("name")
	if err != nil || name == "" {
		return logical.ErrorResponse("name is required"), nil
	}

	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	defer utils.ZeroKey(privateKey)

	privateKeyBytes := crypto.FromECDSA(privateKey)
	privateKeyString := hexutil.Encode(privateKeyBytes)[2:]

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("cast public key to ECDSA")
	}
	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)
	publicKeyString := hexutil.Encode(publicKeyBytes)[4:]

	address := crypto.PubkeyToAddress(privateKey.PublicKey).Hex()

	account := model.NewAccount(address, privateKeyString, publicKeyString)
	if err := putSingleKeyAccountIfAbsent(ctx, req, name, account); err != nil {
		if errors.Is(err, errSingleKeyAccountAlreadyExists) {
			return respondSingleKeyAccountConflict(req)
		}
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"address": account.AddressStr,
		},
	}, nil
}

// handleSingleKeyAccountImport stores an existing private key under the given account name.
func handleSingleKeyAccountImport(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	wrapper := model.NewFieldDataWrapper(data)
	name, err := wrapper.MustGetString("name")
	if err != nil || name == "" {
		return logical.ErrorResponse("name is required"), nil
	}
	privHex, err := wrapper.MustGetString("private_key")
	if err != nil {
		return logical.ErrorResponse("%s", err.Error()), nil
	}
	privHex = normalizeHexNo0x(privHex)
	if privHex == "" {
		return logical.ErrorResponse("private_key is required"), nil
	}

	privateKey, err := crypto.HexToECDSA(privHex)
	if err != nil {
		return logical.ErrorResponse("invalid private_key"), nil
	}
	defer utils.ZeroKey(privateKey)

	address := crypto.PubkeyToAddress(privateKey.PublicKey).Hex()
	publicKeyBytes := crypto.FromECDSAPub(&privateKey.PublicKey)
	publicKeyString := hexutil.Encode(publicKeyBytes)[4:]

	account := model.NewAccount(address, privHex, publicKeyString)
	if err := putSingleKeyAccountIfAbsent(ctx, req, name, account); err != nil {
		if errors.Is(err, errSingleKeyAccountAlreadyExists) {
			return respondSingleKeyAccountConflict(req)
		}
		return nil, err
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"address": account.AddressStr,
		},
	}, nil
}

func normalizeHexNo0x(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	return s
}

// handleSingleKeyAccountUpdate rejects updates with HTTP 409 because accounts are immutable after create.
func handleSingleKeyAccountUpdate(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	_ = ctx
	if _, err := model.NewFieldDataWrapper(data).MustGetString("name"); err != nil {
		return logical.ErrorResponse("name is required"), nil
	}
	return respondSingleKeyAccountConflict(req)
}

// handleSingleKeyAccountRead returns public account metadata for the given name.
func handleSingleKeyAccountRead(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	name, err := model.NewFieldDataWrapper(data).MustGetString("name")
	if err != nil || name == "" {
		return logical.ErrorResponse("name is required"), nil
	}
	account, err := ReadSingleKeyAccount(ctx, req.Storage, name)
	if err != nil {
		return RespondLoadSingleKeyAccountError(err)
	}
	out := map[string]interface{}{
		"address": account.AddressStr,
	}
	if account.PublicKeyStr != "" {
		out["public_key"] = account.PublicKeyStr
	}
	return &logical.Response{Data: out}, nil
}

// handleSingleKeyAccountsList returns sorted account names that have a stored key record.
func handleSingleKeyAccountsList(
	ctx context.Context,
	req *logical.Request,
	_ *framework.FieldData,
) (*logical.Response, error) {
	children, err := req.Storage.List(ctx, storagekey.SingleKeyAccountsRootPrefix())
	if err != nil {
		return nil, fmt.Errorf("list accounts: %w", err)
	}
	seen := make(map[string]struct{}, len(children))
	var names []string
	for _, child := range children {
		id := strings.TrimSuffix(child, "/")
		if id == "" {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		names = append(names, id)
	}
	sort.Strings(names)
	return logical.ListResponse(names), nil
}
