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
	"math/big"
	"net/http"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/bsostech/vault-blockchain/internal/model"
	"github.com/bsostech/vault-blockchain/internal/path/storagekey"
	"github.com/bsostech/vault-blockchain/pkg/utils"
)

// mustPutSingleKeyAccount stores a generated single-key account and returns a cleanup that zeroes the test key.
func mustPutSingleKeyAccount(t *testing.T, ctx context.Context, s logical.Storage, name string) (*model.Account, func()) {
	t.Helper()

	pk, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	addr := crypto.PubkeyToAddress(pk.PublicKey)
	acct := &model.Account{
		AddressStr:    hexutil.Encode(addr.Bytes()),
		PrivateKeyStr: hexutil.Encode(crypto.FromECDSA(pk))[2:],
	}

	entry, err := logical.StorageEntryJSON(storagekey.SingleKeyAccountKey(name), acct)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, entry); err != nil {
		t.Fatal(err)
	}

	cleanup := func() { utils.ZeroKey(pk) }
	return acct, cleanup
}

// fieldData builds FieldData with TypeString schema for raw keys and common handler field names.
func fieldData(raw map[string]interface{}) *framework.FieldData {
	baseKeys := []string{
		"name",
		"private_key",
		"data",
		"to",
		"address_to",
		"chain_id",
		"chainID",
		"nonce",
		"value",
		"amount",
		"gas_limit",
		"gas_price",
		"max_fee_per_gas",
		"maxFeePerGas",
		"max_priority_fee_per_gas",
		"maxPriorityFeePerGas",
		"access_list",
		"payload",
	}

	schema := make(map[string]*framework.FieldSchema, len(raw)+len(baseKeys))
	for k := range raw {
		schema[k] = &framework.FieldSchema{Type: framework.TypeString}
	}
	for _, k := range baseKeys {
		if _, ok := schema[k]; ok {
			continue
		}
		schema[k] = &framework.FieldSchema{Type: framework.TypeString}
	}
	return &framework.FieldData{Raw: raw, Schema: schema}
}

func TestHandleSingleKeyAccountImport_success(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s := new(logical.InmemStorage)
	req := &logical.Request{Storage: s}

	pk, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { utils.ZeroKey(pk) })
	privHexNo0x := hexutil.Encode(crypto.FromECDSA(pk))[2:]

	resp, err := handleSingleKeyAccountImport(
		ctx,
		req,
		fieldData(map[string]interface{}{"name": "imp1", "private_key": "0x" + privHexNo0x}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || resp.Data == nil {
		t.Fatal("expected response data.")
	}
	gotAddr, _ := resp.Data["address"].(string)
	if gotAddr == "" {
		t.Fatal("expected non-empty address.")
	}

	out, err := ReadSingleKeyAccount(ctx, s, "imp1")
	if err != nil {
		t.Fatal(err)
	}
	if out == nil {
		t.Fatal("expected stored account.")
	}
	if out.PrivateKeyStr != privHexNo0x {
		t.Fatalf("stored private_key mismatch.")
	}
	if hexutil.Encode(common.HexToAddress(out.AddressStr).Bytes()) != hexutil.Encode(crypto.PubkeyToAddress(pk.PublicKey).Bytes()) {
		t.Fatalf("stored address mismatch.")
	}
}

func TestHandleSingleKeyAccountImport_conflict(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s := new(logical.InmemStorage)
	req := &logical.Request{Storage: s}

	_, cleanup := mustPutSingleKeyAccount(t, ctx, s, "dupimp")
	t.Cleanup(cleanup)

	resp, err := handleSingleKeyAccountImport(
		ctx,
		req,
		fieldData(map[string]interface{}{"name": "dupimp", "private_key": "01"}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected response.")
	}
	if !resp.IsError() {
		t.Fatal("expected error response.")
	}
}

// TestHandleSingleKeySign_roundTripRecover verifies handleSingleKeySign recovers the account address from the signature.
func TestHandleSingleKeySign_roundTripRecover(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s := new(logical.InmemStorage)
	acct, cleanup := mustPutSingleKeyAccount(t, ctx, s, "a1")
	t.Cleanup(cleanup)

	req := &logical.Request{Storage: s}
	dataBytes := []byte("hello")

	resp, err := handleSingleKeySign(ctx, req, fieldData(map[string]interface{}{
		"name": "a1",
		"data": hexutil.Encode(dataBytes),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || resp.Data == nil {
		t.Fatal("expected response data.")
	}

	sigHex, _ := resp.Data["signature"].(string)
	sig, err := hexutil.Decode(sigHex)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 65 {
		t.Fatalf("len(sig)=%d want 65.", len(sig))
	}

	hash := crypto.Keccak256Hash(dataBytes)
	pub, err := crypto.SigToPub(hash.Bytes(), sig)
	if err != nil {
		t.Fatal(err)
	}
	gotAddr := crypto.PubkeyToAddress(*pub)
	wantAddr := common.HexToAddress(acct.AddressStr)
	if gotAddr != wantAddr {
		t.Fatalf("recovered address=%s want %s.", gotAddr, wantAddr)
	}
}

// TestHandleSingleKeyEncryptDecrypt_roundTrip verifies ECIES encrypt then decrypt round-trip for a stored account.
func TestHandleSingleKeyEncryptDecrypt_roundTrip(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s := new(logical.InmemStorage)
	_, cleanup := mustPutSingleKeyAccount(t, ctx, s, "a2")
	t.Cleanup(cleanup)

	req := &logical.Request{Storage: s}
	plaintext := []byte("secret")

	encResp, err := handleSingleKeyEncrypt(ctx, req, fieldData(map[string]interface{}{
		"name": "a2",
		"data": hexutil.Encode(plaintext),
	}))
	if err != nil {
		t.Fatal(err)
	}
	cipherHex, _ := encResp.Data["ciphertext"].(string)

	decResp, err := handleSingleKeyDecrypt(ctx, req, fieldData(map[string]interface{}{
		"name": "a2",
		"data": cipherHex,
	}))
	if err != nil {
		t.Fatal(err)
	}

	gotHex, _ := decResp.Data["plaintext"].(string)
	got, err := hexutil.Decode(gotHex)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("got %q want %q.", string(got), string(plaintext))
	}
}

// TestHandleSingleKeySignEIP712_recoversAddress verifies EIP-712 signature recovers the signer address.
func TestHandleSingleKeySignEIP712_recoversAddress(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s := new(logical.InmemStorage)
	acct, cleanup := mustPutSingleKeyAccount(t, ctx, s, "a3")
	t.Cleanup(cleanup)

	payload := `{"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"}],"Mail":[{"name":"contents","type":"string"}]},"primaryType":"Mail","domain":{"name":"VaultBlockchain","version":"1","chainId":1},"message":{"contents":"hello"}}`

	req := &logical.Request{Storage: s}
	resp, err := handleSingleKeySignEIP712(ctx, req, fieldData(map[string]interface{}{
		"name":    "a3",
		"payload": payload,
	}))
	if err != nil {
		t.Fatal(err)
	}
	sigHex, _ := resp.Data["signature"].(string)
	sig, err := hexutil.Decode(sigHex)
	if err != nil {
		t.Fatal(err)
	}

	td, err := typedDataFromPayloadSingleKey(payload)
	if err != nil {
		t.Fatal(err)
	}
	sighash, _, err := apitypes.TypedDataAndHash(*td)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := crypto.SigToPub(sighash, sig)
	if err != nil {
		t.Fatal(err)
	}
	gotAddr := crypto.PubkeyToAddress(*pub)
	wantAddr := common.HexToAddress(acct.AddressStr)
	if gotAddr != wantAddr {
		t.Fatalf("recovered address=%s want %s.", gotAddr, wantAddr)
	}
}

func TestHandleSingleKeySignEIP712_invalidPayloadReturnsLogicalError(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s := new(logical.InmemStorage)
	_, cleanup := mustPutSingleKeyAccount(t, ctx, s, "eipbad")
	t.Cleanup(cleanup)

	req := &logical.Request{Storage: s}
	resp, err := handleSingleKeySignEIP712(ctx, req, fieldData(map[string]interface{}{
		"name":    "eipbad",
		"payload": "{",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("resp=%v want logical error response.", resp)
	}
}

func TestHandleSingleKeySignEIP712_emptyPayloadReturnsLogicalError(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s := new(logical.InmemStorage)
	_, cleanup := mustPutSingleKeyAccount(t, ctx, s, "eipempty")
	t.Cleanup(cleanup)

	req := &logical.Request{Storage: s}
	resp, err := handleSingleKeySignEIP712(ctx, req, fieldData(map[string]interface{}{
		"name":    "eipempty",
		"payload": "   ",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("resp=%v want logical error response.", resp)
	}
}

// TestHandleSingleKeySignTxType0_smoke verifies legacy sign-tx response fields for a simple transfer.
func TestHandleSingleKeySignTxType0_smoke(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s := new(logical.InmemStorage)
	acct, cleanup := mustPutSingleKeyAccount(t, ctx, s, "a4")
	t.Cleanup(cleanup)

	req := &logical.Request{Storage: s}
	to := common.HexToAddress("0x0000000000000000000000000000000000000001")

	resp, err := handleSingleKeySignTxType0(ctx, req, fieldData(map[string]interface{}{
		"name":      "a4",
		"chain_id":  "1",
		"gas_limit": "21000",
		"gas_price": "1",
		"nonce":     "0",
		"value":     "7",
		"to":        to.Hex(),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || resp.Data == nil {
		t.Fatal("expected response data.")
	}
	if resp.Data["type"] != txTypeLabelEthereumType0 {
		t.Fatalf("type=%v want %v.", resp.Data["type"], txTypeLabelEthereumType0)
	}
	gotFrom, _ := resp.Data["address_from"].(string)
	if common.HexToAddress(gotFrom) != common.HexToAddress(acct.AddressStr) {
		t.Fatalf("address_from=%v want %v.", gotFrom, acct.AddressStr)
	}
	if resp.Data["address_to"] != to.Hex() {
		t.Fatalf("address_to=%v want %v.", resp.Data["address_to"], to.Hex())
	}

	signedHex, _ := resp.Data["signed_transaction"].(string)
	raw, err := hexutil.Decode(signedHex)
	if err != nil {
		t.Fatal(err)
	}
	var tx ethtypes.Transaction
	if err := tx.UnmarshalBinary(raw); err != nil {
		t.Fatal(err)
	}
	if tx.Type() != ethtypes.LegacyTxType {
		t.Fatalf("tx.Type()=%d want %d.", tx.Type(), ethtypes.LegacyTxType)
	}
	if tx.ChainId() == nil || tx.ChainId().Int64() != 1 {
		t.Fatalf("tx.ChainId()=%v want 1.", tx.ChainId())
	}
	signer := ethtypes.LatestSignerForChainID(tx.ChainId())
	from, err := ethtypes.Sender(signer, &tx)
	if err != nil {
		t.Fatal(err)
	}
	if from != common.HexToAddress(acct.AddressStr) {
		t.Fatalf("recovered from=%s want %s.", from.Hex(), acct.AddressStr)
	}
}

// TestHandleSingleKeySignTxEIP1559_smoke verifies EIP-1559 sign-tx returns expected type in response data.
func TestHandleSingleKeySignTxEIP1559_smoke(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s := new(logical.InmemStorage)
	acct, cleanup := mustPutSingleKeyAccount(t, ctx, s, "a5")
	t.Cleanup(cleanup)

	req := &logical.Request{Storage: s}

	resp, err := handleSingleKeySignTxEIP1559(ctx, req, fieldData(map[string]interface{}{
		"name":                     "a5",
		"chain_id":                 "1",
		"gas_limit":                "21000",
		"max_fee_per_gas":          "2",
		"max_priority_fee_per_gas": "1",
		"nonce":                    "0",
		"value":                    "0",
		"access_list":              "[]",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || resp.Data == nil {
		t.Fatal("expected response data.")
	}
	if resp.Data["type"] != "eip1559" {
		t.Fatalf("type=%v want %v.", resp.Data["type"], "eip1559")
	}

	signedHex, _ := resp.Data["signed_transaction"].(string)
	raw, err := hexutil.Decode(signedHex)
	if err != nil {
		t.Fatal(err)
	}
	var tx ethtypes.Transaction
	if err := tx.UnmarshalBinary(raw); err != nil {
		t.Fatal(err)
	}
	if tx.Type() != ethtypes.DynamicFeeTxType {
		t.Fatalf("tx.Type()=%d want %d.", tx.Type(), ethtypes.DynamicFeeTxType)
	}
	if tx.ChainId() == nil || tx.ChainId().Int64() != 1 {
		t.Fatalf("tx.ChainId()=%v want 1.", tx.ChainId())
	}
	signer := ethtypes.LatestSignerForChainID(tx.ChainId())
	from, err := ethtypes.Sender(signer, &tx)
	if err != nil {
		t.Fatal(err)
	}
	if from != common.HexToAddress(acct.AddressStr) {
		t.Fatalf("recovered from=%s want %s.", from.Hex(), acct.AddressStr)
	}
}

func TestTypedDataFromPayloadSingleKey_rejectsInvalidJSON(t *testing.T) {
	t.Parallel()

	_, err := typedDataFromPayloadSingleKey("{")
	if err == nil {
		t.Fatal("expected error.")
	}
}

func TestTypedDataFromPayloadSingleKey_requiresPrimaryType(t *testing.T) {
	t.Parallel()

	_, err := typedDataFromPayloadSingleKey(`{"types":{},"primaryType":"   ","domain":{},"message":{}}`)
	if err == nil {
		t.Fatal("expected error.")
	}
}

// TestSignEIP1559TxSingleKey_feeCapLtTip_returnsLogicalError verifies fee cap below tip yields a logical error response.
func TestSignEIP1559TxSingleKey_feeCapLtTip_returnsLogicalError(t *testing.T) {
	t.Parallel()

	wrapper := model.NewFieldDataWrapper(fieldData(map[string]interface{}{
		"max_priority_fee_per_gas": "2",
		"max_fee_per_gas":          "1",
	}))

	resp, err := signEIP1559TxSingleKey(
		wrapper,
		big.NewInt(1),
		0,
		21_000,
		big.NewInt(0),
		nil,
		nil,
		nil,
		&model.Account{AddressStr: "0xabc"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected logical error response.")
	}
}

// TestSignType0TxSingleKey_invalidGasPrice_returnsLogicalError verifies non-decimal gas_price yields a logical error.
func TestSignType0TxSingleKey_invalidGasPrice_returnsLogicalError(t *testing.T) {
	t.Parallel()

	wrapper := model.NewFieldDataWrapper(fieldData(map[string]interface{}{
		"gas_price": "not-a-number",
	}))

	resp, err := signType0TxSingleKey(
		wrapper,
		big.NewInt(1),
		0,
		21_000,
		big.NewInt(0),
		nil,
		nil,
		nil,
		&model.Account{AddressStr: "0xabc"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected logical error response.")
	}
}

func TestTypedDataFromPayloadSingleKey_validJSON(t *testing.T) {
	t.Parallel()

	_, err := typedDataFromPayloadSingleKey(`{"types":{"EIP712Domain":[],"Mail":[]},"primaryType":"Mail","domain":{},"message":{}}`)
	if err != nil {
		t.Fatal(err)
	}
}

func TestTypedDataFromPayloadSingleKey_acceptsSnakeCasePrimaryType(t *testing.T) {
	t.Parallel()

	_, err := typedDataFromPayloadSingleKey(`{"types":{"EIP712Domain":[],"Mail":[]},"primary_type":"Mail","domain":{},"message":{}}`)
	if err != nil {
		t.Fatal(err)
	}
}

// TestHandleSingleKeyAccountCreate_conflictReturns409 verifies duplicate create returns HTTP 409.
func TestHandleSingleKeyAccountCreate_conflictReturns409(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s := new(logical.InmemStorage)
	req := &logical.Request{Storage: s}

	resp, err := handleSingleKeyAccountCreate(ctx, req, fieldData(map[string]interface{}{"name": "dup"}))
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || resp.Data == nil {
		t.Fatal("expected response.")
	}

	resp2, err := handleSingleKeyAccountCreate(ctx, req, fieldData(map[string]interface{}{"name": "dup"}))
	if err != nil {
		t.Fatal(err)
	}
	if resp2 == nil {
		t.Fatal("expected response.")
	}
	code, _ := resp2.Data[logical.HTTPStatusCode].(int)
	if code != http.StatusConflict {
		t.Fatalf("status=%d want %d.", code, http.StatusConflict)
	}
}

// TestHandleSingleKeyAccountsList_sorted verifies listed account names are sorted lexicographically.
func TestHandleSingleKeyAccountsList_sorted(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s := new(logical.InmemStorage)
	_, c1 := mustPutSingleKeyAccount(t, ctx, s, "b")
	_, c2 := mustPutSingleKeyAccount(t, ctx, s, "a")
	t.Cleanup(c1)
	t.Cleanup(c2)

	req := &logical.Request{Storage: s}
	resp, err := handleSingleKeyAccountsList(ctx, req, fieldData(map[string]interface{}{}))
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || len(resp.Data) == 0 {
		t.Fatal("expected list response data.")
	}

	keys, ok := resp.Data["keys"].([]string)
	if !ok {
		t.Fatalf("keys type=%T want []string.", resp.Data["keys"])
	}
	if len(keys) != 2 || keys[0] != "a" || keys[1] != "b" {
		t.Fatalf("keys=%v want [a b].", keys)
	}
}
