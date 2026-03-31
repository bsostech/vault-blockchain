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
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/bsostech/vault-blockchain/internal/model"
)

// TestSignType0EIP155 verifies a type-0 EIP-155 signed tx recovers to the signer address.
func TestSignType0EIP155(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	chainID := big.NewInt(1)
	nonce := uint64(7)
	gasLimit := uint64(21_000)
	value := big.NewInt(123)
	gasPrice := big.NewInt(1_000_000_000)
	to := common.HexToAddress("0x0000000000000000000000000000000000000001")

	tx, err := SignType0EIP155(chainID, nonce, gasLimit, value, nil, &to, gasPrice, key)
	if err != nil {
		t.Fatal(err)
	}
	if tx.Type() != ethtypes.LegacyTxType {
		t.Fatalf("tx.Type()=%d want %d.", tx.Type(), ethtypes.LegacyTxType)
	}
	if tx.To() == nil || *tx.To() != to {
		t.Fatalf("tx.To()=%v want %s.", tx.To(), to.Hex())
	}

	signer := ethtypes.NewEIP155Signer(chainID)
	from, err := ethtypes.Sender(signer, tx)
	if err != nil {
		t.Fatal(err)
	}
	wantFrom := crypto.PubkeyToAddress(key.PublicKey)
	if from != wantFrom {
		t.Fatalf("from=%s want %s.", from, wantFrom)
	}
}

// TestSignType0EIP155_contractCreation verifies contract-creation tx has a nil To field after signing.
func TestSignType0EIP155_contractCreation(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	chainID := big.NewInt(1)

	tx, err := SignType0EIP155(chainID, 0, 1, big.NewInt(0), []byte{0x60, 0x00}, nil, big.NewInt(1), key)
	if err != nil {
		t.Fatal(err)
	}
	if tx.To() != nil {
		t.Fatalf("tx.To()=%v want nil.", tx.To())
	}
}

// TestSignType0EIP155_nilKey verifies SignType0EIP155 returns an error when the signing key is nil.
func TestSignType0EIP155_nilKey(t *testing.T) {
	t.Parallel()

	_, err := SignType0EIP155(big.NewInt(1), 0, 0, big.NewInt(0), nil, nil, big.NewInt(0), nil)
	if err == nil {
		t.Fatal("expected error.")
	}
}

// TestSignType0EIP155_nilChainID verifies SignType0EIP155 returns an error when chain ID is nil.
func TestSignType0EIP155_nilChainID(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	_, err = SignType0EIP155(nil, 0, 0, big.NewInt(0), nil, nil, big.NewInt(0), key)
	if err == nil {
		t.Fatal("expected error.")
	}
}

// TestSignEIP1559 verifies a dynamic-fee tx recovers to the signer address.
func TestSignEIP1559(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	chainID := big.NewInt(1)
	nonce := uint64(9)
	gasLimit := uint64(21_000)
	value := big.NewInt(456)
	tip := big.NewInt(1_500_000_000)
	feeCap := big.NewInt(2_000_000_000)
	to := common.HexToAddress("0x0000000000000000000000000000000000000002")

	tx, err := SignEIP1559(chainID, nonce, gasLimit, value, nil, &to, tip, feeCap, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	if tx.Type() != ethtypes.DynamicFeeTxType {
		t.Fatalf("tx.Type()=%d want %d.", tx.Type(), ethtypes.DynamicFeeTxType)
	}
	if tx.To() == nil || *tx.To() != to {
		t.Fatalf("tx.To()=%v want %s.", tx.To(), to.Hex())
	}

	signer := ethtypes.NewLondonSigner(chainID)
	from, err := ethtypes.Sender(signer, tx)
	if err != nil {
		t.Fatal(err)
	}
	wantFrom := crypto.PubkeyToAddress(key.PublicKey)
	if from != wantFrom {
		t.Fatalf("from=%s want %s.", from, wantFrom)
	}
}

// TestSignEIP1559_feeCapLtTip verifies SignEIP1559 rejects max_fee_per_gas below max_priority_fee_per_gas.
func TestSignEIP1559_feeCapLtTip(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	_, err = SignEIP1559(
		big.NewInt(1),
		0,
		0,
		big.NewInt(0),
		nil,
		nil,
		big.NewInt(2),
		big.NewInt(1),
		nil,
		key,
	)
	if err == nil {
		t.Fatal("expected error.")
	}
}

// TestSignEIP1559_nilKey verifies SignEIP1559 returns an error when the signing key is nil.
func TestSignEIP1559_nilKey(t *testing.T) {
	t.Parallel()

	_, err := SignEIP1559(big.NewInt(1), 0, 0, big.NewInt(0), nil, nil, big.NewInt(0), big.NewInt(0), nil, nil)
	if err == nil {
		t.Fatal("expected error.")
	}
}

// TestSignEIP1559_nilChainID verifies SignEIP1559 returns an error when chain ID is nil.
func TestSignEIP1559_nilChainID(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	_, err = SignEIP1559(nil, 0, 0, big.NewInt(0), nil, nil, big.NewInt(0), big.NewInt(0), nil, key)
	if err == nil {
		t.Fatal("expected error.")
	}
}

// TestSignEIP1559_nilTip verifies SignEIP1559 returns an error when max_priority_fee_per_gas is nil.
func TestSignEIP1559_nilTip(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	_, err = SignEIP1559(big.NewInt(1), 0, 0, big.NewInt(0), nil, nil, nil, big.NewInt(0), nil, key)
	if err == nil {
		t.Fatal("expected error.")
	}
}

// TestSignEIP1559_nilFeeCap verifies SignEIP1559 returns an error when max_fee_per_gas is nil.
func TestSignEIP1559_nilFeeCap(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	_, err = SignEIP1559(big.NewInt(1), 0, 0, big.NewInt(0), nil, nil, big.NewInt(0), nil, nil, key)
	if err == nil {
		t.Fatal("expected error.")
	}
}

// TestSignedTxResponseData verifies SignedTxResponseData fields for a legacy signed transfer transaction.
func TestSignedTxResponseData(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	chainID := big.NewInt(1)
	to := common.HexToAddress("0x0000000000000000000000000000000000000001")
	tx, err := SignType0EIP155(chainID, 1, 21_000, big.NewInt(7), nil, &to, big.NewInt(1), key)
	if err != nil {
		t.Fatal(err)
	}
	if tx.Type() != ethtypes.LegacyTxType {
		t.Fatalf("sanity: tx.Type()=%d want %d.", tx.Type(), ethtypes.LegacyTxType)
	}

	acct := &model.Account{AddressStr: "0xabc"}

	got, err := SignedTxResponseData(
		tx,
		acct,
		&to,
		big.NewInt(7),
		"1",
		21_000,
		"legacy",
	)
	if err != nil {
		t.Fatal(err)
	}

	if got["type"] != "legacy" {
		t.Fatalf("type=%v want %v.", got["type"], "legacy")
	}
	if got["transaction_hash"] != tx.Hash().Hex() {
		t.Fatalf("transaction_hash=%v want %v.", got["transaction_hash"], tx.Hash().Hex())
	}
	if got["address_from"] != "0xabc" {
		t.Fatalf("address_from=%v want %v.", got["address_from"], "0xabc")
	}
	if got["address_to"] != to.Hex() {
		t.Fatalf("address_to=%v want %v.", got["address_to"], to.Hex())
	}
	if got["value"] != "7" {
		t.Fatalf("value=%v want %v.", got["value"], "7")
	}
	if got["gas_limit"] != uint64(21_000) {
		t.Fatalf("gas_limit=%v want %v.", got["gas_limit"], uint64(21_000))
	}
	if got["gas_price"] != "1" {
		t.Fatalf("gas_price=%v want %v.", got["gas_price"], "1")
	}

	signedTxHex, ok := got["signed_transaction"].(string)
	if !ok {
		t.Fatalf("signed_transaction type=%T want string.", got["signed_transaction"])
	}
	if len(signedTxHex) < 3 || signedTxHex[:2] != "0x" {
		t.Fatalf("signed_transaction=%q want 0x-prefixed hex string.", signedTxHex)
	}
}

// TestSignedTxResponseData_toNil verifies address_to is empty when the transaction has no recipient (contract creation).
func TestSignedTxResponseData_toNil(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	tx, err := SignType0EIP155(big.NewInt(1), 1, 1, big.NewInt(0), nil, nil, big.NewInt(1), key)
	if err != nil {
		t.Fatal(err)
	}

	acct := &model.Account{AddressStr: "0xabc"}
	got, err := SignedTxResponseData(tx, acct, nil, big.NewInt(0), "1", 1, "legacy")
	if err != nil {
		t.Fatal(err)
	}
	if got["address_to"] != "" {
		t.Fatalf("address_to=%v want empty string.", got["address_to"])
	}
}

// TestSignedTxResponseData_nilSignedTx verifies SignedTxResponseData returns an error when the signed tx is nil.
func TestSignedTxResponseData_nilSignedTx(t *testing.T) {
	t.Parallel()

	acct := &model.Account{AddressStr: "0xabc"}
	_, err := SignedTxResponseData(nil, acct, nil, big.NewInt(0), "1", 1, "legacy")
	if err == nil {
		t.Fatal("expected error.")
	}
}

// TestSignedTxResponseData_nilAccount verifies SignedTxResponseData returns an error when the account is nil.
func TestSignedTxResponseData_nilAccount(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	tx, err := SignType0EIP155(big.NewInt(1), 1, 1, big.NewInt(0), nil, nil, big.NewInt(1), key)
	if err != nil {
		t.Fatal(err)
	}

	_, err = SignedTxResponseData(tx, nil, nil, big.NewInt(0), "1", 1, "legacy")
	if err == nil {
		t.Fatal("expected error.")
	}
}

// TestSignedTxResponseData_nilValue_defaultsZero verifies nil value is treated as zero in the response map.
func TestSignedTxResponseData_nilValue_defaultsZero(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	tx, err := SignType0EIP155(big.NewInt(1), 1, 1, big.NewInt(0), nil, nil, big.NewInt(1), key)
	if err != nil {
		t.Fatal(err)
	}

	acct := &model.Account{AddressStr: "0xabc"}
	got, err := SignedTxResponseData(tx, acct, nil, nil, "1", 1, "legacy")
	if err != nil {
		t.Fatal(err)
	}
	if got["value"] != "0" {
		t.Fatalf("value=%v want %v.", got["value"], "0")
	}
}
