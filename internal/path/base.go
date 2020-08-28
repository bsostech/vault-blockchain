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

package path

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/bsostech/vault-blockchain/internal/model"
)

type basePathConfig struct {
	config
}

func (b basePathConfig) getExistenceFunc() framework.ExistenceFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
		entry, err := req.Storage.Get(ctx, req.Path)
		if err != nil {
			return false, fmt.Errorf("existence check failed, %v", err)
		}
		return entry != nil, nil
	}
}

func (b *basePathConfig) readAccount(ctx context.Context, req *logical.Request, name string) (*model.Account, error) {
	path := fmt.Sprintf("accounts/%s/address", name)
	entry, err := req.Storage.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, fmt.Errorf("entry not existed at %v", path)
	}
	var account *model.Account
	err = entry.DecodeJSON(&account)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize account at %s", path)
	}
	if account == nil {
		return nil, fmt.Errorf("account not existed at %s", path)
	}
	return account, nil
}
