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
	"bytes"
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/bsostech/vault-blockchain/internal/model"
	"github.com/bsostech/vault-blockchain/pkg/utils"
)

type signTransactionPathConfig struct {
	basePathConfig
}

func (s *signTransactionPathConfig) getPattern() string {
	return "accounts/" + framework.GenericNameRegex("name") + "/sign-tx"
}

func (s *signTransactionPathConfig) getHelpSynopsis() string {
	return "Sign a provided transaction."
}

func (s *signTransactionPathConfig) getFields() map[string]*framework.FieldSchema {
	return map[string]*framework.FieldSchema{
		"name": {
			Type: framework.TypeString,
		},
		"address_to": {
			Type:        framework.TypeString,
			Description: "The address of the account to send tx to.",
		},
		"chainID": {
			Type:        framework.TypeString,
			Description: "The chain ID of the blockchain network.",
		},
		"data": {
			Type:        framework.TypeString,
			Description: "The data to sign.",
		},
		"is_private": {
			Type:        framework.TypeBool,
			Default:     false,
			Description: "Private for column is null or not",
		},
		"amount": {
			Type:        framework.TypeString,
			Description: "Amount of ETH (in wei).",
		},
		"nonce": {
			Type:        framework.TypeString,
			Description: "The transaction nonce.",
		},
		"gas_limit": {
			Type:        framework.TypeString,
			Description: "The gas limit for the transaction - defaults to 21000.",
			Default:     "21000",
		},
		"gas_price": {
			Type:        framework.TypeString,
			Description: "The gas price for the transaction in wei.",
			Default:     "0",
		},
	}
}

func (s *signTransactionPathConfig) getCallbacks() map[logical.Operation]framework.OperationFunc {
	return map[logical.Operation]framework.OperationFunc{
		logical.CreateOperation: s.signTransaction,
	}
}

func (s *signTransactionPathConfig) signTransaction(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	dataWrapper := model.NewFieldDataWrapper(data)
	name, err := dataWrapper.MustGetString("name")
	if err != nil {
		return nil, err
	}
	account, err := s.readAccount(ctx, req, name)
	if err != nil {
		return nil, fmt.Errorf("error reading account, %v", err)
	}
	chainID, err := dataWrapper.MustGetBigInt("chainID")
	if err != nil {
		return nil, err
	}
	amount, err := dataWrapper.MustGetBigInt("amount")
	if err != nil {
		return nil, err
	}
	gasLimit, err := dataWrapper.MustGetUint64("gas_limit")
	if err != nil {
		return nil, err
	}
	gasPrice, err := dataWrapper.MustGetBigInt("gas_price")
	if err != nil {
		return nil, err
	}
	nonce := dataWrapper.GetUint64("nonce", 0)
	inputData, err := dataWrapper.MustGetString("data")
	if err != nil {
		return nil, err
	}
	var txDataToSign []byte
	txDataToSign, err = hexutil.Decode(inputData)
	if err != nil {
		return nil, err
	}
	// get transaction to sign
	address := dataWrapper.GetString("address_to", "")
	var tx *types.Transaction
	if address == "" {
		tx = types.NewContractCreation(nonce, amount, gasLimit, gasPrice, txDataToSign)
	} else {
		tx = types.NewTransaction(nonce, common.HexToAddress(address), amount, gasLimit, gasPrice, txDataToSign)
	}
	// get signer
	isPrivate := dataWrapper.GetBool("is_private", false)
	var signer types.Signer
	if isPrivate {
		signer = types.HomesteadSigner{}
	} else {
		signer = types.NewEIP155Signer(chainID)
	}
	// get private ecdsa key from account for signing data
	privateKey, err := account.GetPrivateKeyECDSA()
	if err != nil {
		return nil, fmt.Errorf("error reconstructing private key, %v", err)
	}
	defer utils.ZeroKey(privateKey)
	// Sign Tx
	signedTx, err := types.SignTx(tx, signer, privateKey)
	if err != nil {
		return nil, err
	}
	var signedTxBuff bytes.Buffer
	err = signedTx.EncodeRLP(&signedTxBuff)
	if err != nil {
		return nil, err
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"transaction_hash":   signedTx.Hash().Hex(),
			"signed_transaction": hexutil.Encode(signedTxBuff.Bytes()),
			"address_from":       account.AddressStr,
			"address_to":         address,
			"amount":             amount.String(),
			"gas_price":          gasPrice.String(),
			"gas_limit":          gasLimit,
		},
	}, nil
}
