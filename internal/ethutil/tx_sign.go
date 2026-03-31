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

package ethutil

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
)

// SignType0EIP155 builds and signs a type-0 transaction with EIP-155.
func SignType0EIP155(
	chainID *big.Int,
	nonce, gasLimit uint64,
	value *big.Int,
	txData []byte,
	toPtr *common.Address,
	gasPrice *big.Int,
	key *ecdsa.PrivateKey,
) (*ethtypes.Transaction, error) {
	if chainID == nil {
		return nil, fmt.Errorf("chain id is nil")
	}
	if key == nil {
		return nil, fmt.Errorf("signing key is nil")
	}
	if value == nil {
		value = big.NewInt(0)
	}
	if gasPrice == nil {
		gasPrice = big.NewInt(0)
	}
	var tx *ethtypes.Transaction
	if toPtr == nil {
		tx = ethtypes.NewContractCreation(nonce, value, gasLimit, gasPrice, txData)
	} else {
		tx = ethtypes.NewTransaction(nonce, *toPtr, value, gasLimit, gasPrice, txData)
	}
	signer := ethtypes.NewEIP155Signer(chainID)
	signedTx, err := ethtypes.SignTx(tx, signer, key)
	if err != nil {
		return nil, fmt.Errorf("sign type-0 tx: %w", err)
	}
	return signedTx, nil
}

// SignEIP1559 builds and signs a type-2 (London) transaction.
func SignEIP1559(
	chainID *big.Int,
	nonce, gasLimit uint64,
	value *big.Int,
	txData []byte,
	toPtr *common.Address,
	tip, feeCap *big.Int,
	accessList ethtypes.AccessList,
	key *ecdsa.PrivateKey,
) (*ethtypes.Transaction, error) {
	if chainID == nil {
		return nil, fmt.Errorf("chain id is nil")
	}
	if key == nil {
		return nil, fmt.Errorf("signing key is nil")
	}
	if tip == nil {
		return nil, fmt.Errorf("max_priority_fee_per_gas is nil")
	}
	if feeCap == nil {
		return nil, fmt.Errorf("max_fee_per_gas is nil")
	}
	if value == nil {
		value = big.NewInt(0)
	}
	if feeCap.Cmp(tip) < 0 {
		return nil, fmt.Errorf("max_fee_per_gas must be >= max_priority_fee_per_gas")
	}
	inner := &ethtypes.DynamicFeeTx{
		ChainID:    chainID,
		Nonce:      nonce,
		GasTipCap:  tip,
		GasFeeCap:  feeCap,
		Gas:        gasLimit,
		To:         toPtr,
		Value:      value,
		Data:       txData,
		AccessList: accessList,
	}
	tx := ethtypes.NewTx(inner)
	signer := ethtypes.NewLondonSigner(chainID)
	signedTx, err := ethtypes.SignTx(tx, signer, key)
	if err != nil {
		return nil, fmt.Errorf("sign eip1559 tx: %w", err)
	}
	return signedTx, nil
}

// SignedTxResponseData builds the Vault response data map for a signed transaction.
//
// The response is derived from the signed transaction itself (to/value/gas/fee/type), and the
// sender is recovered from the signature using go-ethereum's latest signer for the tx ChainID.
func SignedTxResponseData(signedTx *ethtypes.Transaction) (map[string]interface{}, error) {
	if signedTx == nil {
		return nil, fmt.Errorf("signed tx is nil")
	}

	chainID := signedTx.ChainId()
	if chainID == nil {
		return nil, fmt.Errorf("signed tx chain_id is nil")
	}
	signer := ethtypes.LatestSignerForChainID(chainID)
	from, err := ethtypes.Sender(signer, signedTx)
	if err != nil {
		return nil, fmt.Errorf("recover sender: %w", err)
	}

	// MarshalBinary returns the wire format (EIP-2718 type byte + payload for type-1/2 txs).
	// EncodeRLP alone omits the type prefix for typed txs, which breaks ethers/eth_sendRawTransaction.
	raw, err := signedTx.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal signed tx: %w", err)
	}

	toHex := ""
	if toPtr := signedTx.To(); toPtr != nil {
		toHex = toPtr.Hex()
	}

	txType := "unknown"
	switch signedTx.Type() {
	case ethtypes.LegacyTxType:
		txType = "legacy"
	case ethtypes.AccessListTxType:
		txType = "eip2930"
	case ethtypes.DynamicFeeTxType:
		txType = "eip1559"
	}

	gasPriceOrFeeCap := ""
	if signedTx.Type() == ethtypes.DynamicFeeTxType {
		gasPriceOrFeeCap = signedTx.GasFeeCap().String()
	} else {
		gasPriceOrFeeCap = signedTx.GasPrice().String()
	}

	value := signedTx.Value()
	if value == nil {
		value = big.NewInt(0)
	}

	return map[string]interface{}{
		"type":               txType,
		"transaction_hash":   signedTx.Hash().Hex(),
		"signed_transaction": hexutil.Encode(raw),
		"address_from":       from.Hex(),
		"address_to":         toHex,
		"value":              value.String(),
		"gas_limit":          signedTx.Gas(),
		"gas_price":          gasPriceOrFeeCap,
	}, nil
}
