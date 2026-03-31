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
	"sync"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"golang.org/x/crypto/sha3"

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

// existenceSingleKeyAccountSeed reports whether a stored record exists for the path name field.
func existenceSingleKeyAccountSeed() framework.ExistenceFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
		name, err := model.NewFieldDataWrapper(data).MustGetString("name")
		if err != nil || name == "" {
			return false, nil
		}
		entry, err := req.Storage.Get(ctx, storagekey.SingleKeyAccountKey(name))
		if err != nil {
			return false, fmt.Errorf("single-key account existence check for %s: %w", name, err)
		}
		return entry != nil, nil
	}
}

// putSingleKeyAccountIfAbsent writes the account JSON under accounts/<name>/address if missing.
func putSingleKeyAccountIfAbsent(
	ctx context.Context,
	req *logical.Request,
	singleKeyAccountMu *sync.Mutex,
	name string,
	account *model.Account,
) error {
	singleKeyAccountMu.Lock()
	defer singleKeyAccountMu.Unlock()

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
	singleKeyAccountMu *sync.Mutex,
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

	hash := sha3.NewLegacyKeccak256()
	if _, err := hash.Write(publicKeyBytes[1:]); err != nil {
		return nil, fmt.Errorf("hash public key: %w", err)
	}
	address := hexutil.Encode(hash.Sum(nil)[12:])

	account := model.NewAccount(address, privateKeyString, publicKeyString)
	if err := putSingleKeyAccountIfAbsent(ctx, req, singleKeyAccountMu, name, account); err != nil {
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
		entry, err := req.Storage.Get(ctx, storagekey.SingleKeyAccountKey(id))
		if err != nil {
			return nil, fmt.Errorf("get single-key account %q: %w", id, err)
		}
		if entry == nil {
			continue
		}
		seen[id] = struct{}{}
		names = append(names, id)
	}
	sort.Strings(names)
	return logical.ListResponse(names), nil
}
