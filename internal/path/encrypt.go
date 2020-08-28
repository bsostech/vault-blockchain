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
	"crypto/rand"
	"fmt"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/bsostech/vault-blockchain/internal/model"
)

type encryptPathConfig struct {
	basePathConfig
}

func (e *encryptPathConfig) getPattern() string {
	return "accounts/" + framework.GenericNameRegex("name") + "/encrypt"
}

func (e *encryptPathConfig) getHelpSynopsis() string {
	return "Encrypt data"
}

func (e *encryptPathConfig) getFields() map[string]*framework.FieldSchema {
	return map[string]*framework.FieldSchema{
		"name": {
			Type: framework.TypeString,
		},
		"data": {
			Type:        framework.TypeString,
			Description: "The data to encrypt.",
		},
	}
}

func (e *encryptPathConfig) getCallbacks() map[logical.Operation]framework.OperationFunc {
	return map[logical.Operation]framework.OperationFunc{
		logical.CreateOperation: e.encrypt,
	}
}

func (e *encryptPathConfig) encrypt(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	dataWrapper := model.NewFieldDataWrapper(data)
	name, err := dataWrapper.MustGetString("name")
	if err != nil {
		return nil, err
	}
	account, err := e.readAccount(ctx, req, name)
	if err != nil {
		return nil, fmt.Errorf("error reading account, %v", err)
	}
	// get data to encrypt
	dataToEncrypt, err := dataWrapper.MustGetString("data")
	if err != nil {
		return nil, err
	}
	dataBytes, err := hexutil.Decode(dataToEncrypt)
	if err != nil {
		return nil, err
	}
	// get ecies public key from account for encrypting data
	publicKeyECIES, err := account.GetPublicKeyECIES()
	if err != nil {
		return nil, err
	}
	// encrypt data
	cipherText, err := ecies.Encrypt(rand.Reader, publicKeyECIES, dataBytes, nil, nil)
	if err != nil {
		return nil, err
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"ciphertext": hexutil.Encode(cipherText),
		},
	}, nil
}
