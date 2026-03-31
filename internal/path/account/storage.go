// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
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

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/bsostech/vault-blockchain/internal/model"
	"github.com/bsostech/vault-blockchain/internal/path/storagekey"
)

// ErrSingleKeyAccountMissing is returned when no accounts/<name>/address entry exists.
var ErrSingleKeyAccountMissing = errors.New("single-key account not found")

// ReadSingleKeyAccount loads and decodes a stored single-key account for name.
func ReadSingleKeyAccount(ctx context.Context, s logical.Storage, name string) (*model.Account, error) {
	key := storagekey.SingleKeyAccountKey(name)
	entry, err := s.Get(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("get single-key account %s: %w", name, err)
	}
	if entry == nil {
		return nil, ErrSingleKeyAccountMissing
	}
	var account model.Account
	if err := entry.DecodeJSON(&account); err != nil {
		return nil, fmt.Errorf("decode single-key account %s: %w", name, err)
	}
	if account.PrivateKeyStr == "" {
		return nil, fmt.Errorf("single-key account %s: empty private key", name)
	}
	return &account, nil
}

// ExistenceSingleKeyAccount returns true when the single-key account key exists for name.
func ExistenceSingleKeyAccount() framework.ExistenceFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
		name := model.NewFieldDataWrapper(data).GetString("name", "")
		if name == "" {
			return false, nil
		}
		entry, err := req.Storage.Get(ctx, storagekey.SingleKeyAccountKey(name))
		if err != nil {
			return false, fmt.Errorf("existence check single-key account %s: %w", name, err)
		}
		return entry != nil, nil
	}
}

// ExistenceSingleKeyAccountSeed returns true when an account seed exists for name.
//
// This is used by create/import paths to let Vault route write operations based on existence.
func ExistenceSingleKeyAccountSeed() framework.ExistenceFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
		name := model.NewFieldDataWrapper(data).GetString("name", "")
		if name == "" {
			return false, nil
		}
		entry, err := req.Storage.Get(ctx, storagekey.SingleKeyAccountKey(name))
		if err != nil {
			return false, fmt.Errorf("single-key account existence check for %s: %w", name, err)
		}
		return entry != nil, nil
	}
}

// RespondLoadSingleKeyAccountError maps loader errors to logical responses for Vault handlers.
func RespondLoadSingleKeyAccountError(err error) (*logical.Response, error) {
	if errors.Is(err, ErrSingleKeyAccountMissing) {
		return logical.ErrorResponse("account not found"), nil
	}
	return nil, err
}

