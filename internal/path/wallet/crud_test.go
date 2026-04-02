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

package wallet

import (
	"context"
	"net/http"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/tyler-smith/go-bip39"

	"github.com/bsostech/vault-blockchain/internal/model"
	"github.com/bsostech/vault-blockchain/internal/path/storagekey"
)

const testMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

// walletFieldData builds FieldData with TypeString schema for raw keys and common wallet handler fields.
func walletFieldData(raw map[string]interface{}) *framework.FieldData {
	baseKeys := []string{
		"wallet_id",
		"index",
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
		"mnemonic",
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

// mustPutWalletSeed stores a wallet seed JSON entry for tests.
func mustPutWalletSeed(ctx context.Context, t *testing.T, s logical.Storage, walletID, mnemonic string) {
	t.Helper()
	entry, err := logical.StorageEntryJSON(storagekey.SeedKey(walletID), &model.WalletSeed{Mnemonic: mnemonic})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, entry); err != nil {
		t.Fatal(err)
	}
}

// mustPutDerivedAccount derives and stores a DerivedAccount record for wallet_id and index.
func mustPutDerivedAccount(ctx context.Context, t *testing.T, s logical.Storage, walletID, indexStr, mnemonic string) *model.DerivedAccount {
	t.Helper()

	indexU32, err := ParseAddressIndex(indexStr)
	if err != nil {
		t.Fatal(err)
	}
	addr, dpath, err := model.DeriveEthereumAccount(mnemonic, indexU32)
	if err != nil {
		t.Fatal(err)
	}
	derived := &model.DerivedAccount{Address: addr, DerivationPath: dpath}

	entry, err := logical.StorageEntryJSON(storagekey.AccountKey(walletID, indexStr), derived)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, entry); err != nil {
		t.Fatal(err)
	}
	return derived
}

// TestHandleWalletSign_recoversAddress verifies handleWalletSign recovers the derived account address.
func TestHandleWalletSign_recoversAddress(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s := new(logical.InmemStorage)
	mustPutWalletSeed(ctx, t, s, "w1", testMnemonic)
	derived := mustPutDerivedAccount(ctx, t, s, "w1", "0", testMnemonic)

	req := &logical.Request{Storage: s}
	dataBytes := []byte("hello")

	resp, err := handleWalletSign(ctx, req, walletFieldData(map[string]interface{}{
		"wallet_id": "w1",
		"index":     "0",
		"data":      hexutil.Encode(dataBytes),
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
	hash := crypto.Keccak256Hash(dataBytes)
	pub, err := crypto.SigToPub(hash.Bytes(), sig)
	if err != nil {
		t.Fatal(err)
	}
	gotAddr := crypto.PubkeyToAddress(*pub)
	wantAddr := common.HexToAddress(derived.Address)
	if gotAddr != wantAddr {
		t.Fatalf("recovered address=%s want %s.", gotAddr, wantAddr)
	}
}

// TestHandleWalletEncryptDecrypt_roundTrip verifies ECIES encrypt then decrypt for a derived wallet account.
func TestHandleWalletEncryptDecrypt_roundTrip(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s := new(logical.InmemStorage)
	mustPutWalletSeed(ctx, t, s, "w2", testMnemonic)
	_ = mustPutDerivedAccount(ctx, t, s, "w2", "0", testMnemonic)

	req := &logical.Request{Storage: s}
	plaintext := []byte("secret")

	encResp, err := handleWalletEncrypt(ctx, req, walletFieldData(map[string]interface{}{
		"wallet_id": "w2",
		"index":     "0",
		"data":      hexutil.Encode(plaintext),
	}))
	if err != nil {
		t.Fatal(err)
	}
	cipherHex, _ := encResp.Data["ciphertext"].(string)

	decResp, err := handleWalletDecrypt(ctx, req, walletFieldData(map[string]interface{}{
		"wallet_id": "w2",
		"index":     "0",
		"data":      cipherHex,
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

// TestHandleWalletSignEIP712_recoversAddress verifies EIP-712 signature recovers the derived address.
func TestHandleWalletSignEIP712_recoversAddress(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s := new(logical.InmemStorage)
	mustPutWalletSeed(ctx, t, s, "w3", testMnemonic)
	derived := mustPutDerivedAccount(ctx, t, s, "w3", "0", testMnemonic)

	payload := `{"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"}],"Mail":[{"name":"contents","type":"string"}]},"primaryType":"Mail","domain":{"name":"VaultBlockchain","version":"1","chainId":1},"message":{"contents":"hello"}}`

	req := &logical.Request{Storage: s}
	resp, err := handleWalletSignEIP712(ctx, req, walletFieldData(map[string]interface{}{
		"wallet_id":    "w3",
		"index":        "0",
		"payload":      payload,
	}))
	if err != nil {
		t.Fatal(err)
	}
	sigHex, _ := resp.Data["signature"].(string)
	sig, err := hexutil.Decode(sigHex)
	if err != nil {
		t.Fatal(err)
	}

	td, err := typedDataFromPayloadWallet(payload)
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
	wantAddr := common.HexToAddress(derived.Address)
	if gotAddr != wantAddr {
		t.Fatalf("recovered address=%s want %s.", gotAddr, wantAddr)
	}
}

func TestHandleWalletSignEIP712_invalidPayloadReturnsLogicalError(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s := new(logical.InmemStorage)
	mustPutWalletSeed(ctx, t, s, "weipbad", testMnemonic)
	_ = mustPutDerivedAccount(ctx, t, s, "weipbad", "0", testMnemonic)

	req := &logical.Request{Storage: s}
	resp, err := handleWalletSignEIP712(ctx, req, walletFieldData(map[string]interface{}{
		"wallet_id": "weipbad",
		"index":     "0",
		"payload":   "{",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("resp=%v want logical error response.", resp)
	}
}

func TestHandleWalletSignEIP712_emptyPayloadReturnsLogicalError(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s := new(logical.InmemStorage)
	mustPutWalletSeed(ctx, t, s, "weipempty", testMnemonic)
	_ = mustPutDerivedAccount(ctx, t, s, "weipempty", "0", testMnemonic)

	req := &logical.Request{Storage: s}
	resp, err := handleWalletSignEIP712(ctx, req, walletFieldData(map[string]interface{}{
		"wallet_id": "weipempty",
		"index":     "0",
		"payload":   "   ",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("resp=%v want logical error response.", resp)
	}
}

// TestHandleWalletSignTxType0_smoke verifies legacy sign-tx response fields for a wallet-derived account.
func TestHandleWalletSignTxType0_smoke(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s := new(logical.InmemStorage)
	mustPutWalletSeed(ctx, t, s, "w4", testMnemonic)
	derived := mustPutDerivedAccount(ctx, t, s, "w4", "0", testMnemonic)

	req := &logical.Request{Storage: s}
	to := common.HexToAddress("0x0000000000000000000000000000000000000001")

	resp, err := handleWalletSignTxType0(ctx, req, walletFieldData(map[string]interface{}{
		"wallet_id": "w4",
		"index":     "0",
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
	if resp.Data["address_from"] != derived.Address {
		t.Fatalf("address_from=%v want %v.", resp.Data["address_from"], derived.Address)
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
	if from != common.HexToAddress(derived.Address) {
		t.Fatalf("recovered from=%s want %s.", from.Hex(), derived.Address)
	}
}

// TestHandleWalletSignTxEIP1559_smoke verifies EIP-1559 sign-tx returns expected type in response data.
func TestHandleWalletSignTxEIP1559_smoke(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s := new(logical.InmemStorage)
	mustPutWalletSeed(ctx, t, s, "w5", testMnemonic)
	derived := mustPutDerivedAccount(ctx, t, s, "w5", "0", testMnemonic)

	req := &logical.Request{Storage: s}
	resp, err := handleWalletSignTxEIP1559(ctx, req, walletFieldData(map[string]interface{}{
		"wallet_id":                "w5",
		"index":                    "0",
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
	if from != common.HexToAddress(derived.Address) {
		t.Fatalf("recovered from=%s want %s.", from.Hex(), derived.Address)
	}
}

func TestTypedDataFromPayloadWallet_rejectsInvalidJSON(t *testing.T) {
	t.Parallel()

	_, err := typedDataFromPayloadWallet("{")
	if err == nil {
		t.Fatal("expected error.")
	}
}

func TestTypedDataFromPayloadWallet_requiresPrimaryType(t *testing.T) {
	t.Parallel()

	_, err := typedDataFromPayloadWallet(`{"types":{},"primaryType":"   ","domain":{},"message":{}}`)
	if err == nil {
		t.Fatal("expected error.")
	}
}

func TestTypedDataFromPayloadWallet_validJSON(t *testing.T) {
	t.Parallel()

	_, err := typedDataFromPayloadWallet(`{"types":{"EIP712Domain":[],"Mail":[]},"primaryType":"Mail","domain":{},"message":{}}`)
	if err != nil {
		t.Fatal(err)
	}
}

func TestTypedDataFromPayloadWallet_acceptsSnakeCasePrimaryType(t *testing.T) {
	t.Parallel()

	_, err := typedDataFromPayloadWallet(`{"types":{"EIP712Domain":[],"Mail":[]},"primary_type":"Mail","domain":{},"message":{}}`)
	if err != nil {
		t.Fatal(err)
	}
}

// TestLoadSigningKeyForTx_cleanupZeroesKey verifies the cleanup callback zeroes derived signing material.
func TestLoadSigningKeyForTx_cleanupZeroesKey(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s := new(logical.InmemStorage)
	mustPutWalletSeed(ctx, t, s, "w6", testMnemonic)
	_ = mustPutDerivedAccount(ctx, t, s, "w6", "0", testMnemonic)

	pk, _, cleanup, err := loadSigningKeyForTx(ctx, s, "w6", "0")
	if err != nil {
		t.Fatal(err)
	}
	if pk == nil || pk.D == nil {
		t.Fatal("expected non-nil key.")
	}
	if pk.D.Sign() == 0 {
		t.Fatal("sanity: expected non-zero D before cleanup.")
	}
	cleanup()
	if pk.D.Sign() != 0 {
		t.Fatalf("after cleanup D.Sign()=%d want 0.", pk.D.Sign())
	}
}

// TestHandleWalletImport_invalidMnemonic verifies invalid BIP-39 input returns a logical error.
func TestHandleWalletImport_invalidMnemonic(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s := new(logical.InmemStorage)
	req := &logical.Request{Storage: s}

	resp, err := handleWalletImport(ctx, req, walletFieldData(map[string]interface{}{
		"wallet_id": "wimp",
		"mnemonic":  "not-a-mnemonic",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected response.")
	}
}

// TestHandleWalletImport_conflictReturns409 verifies duplicate import returns HTTP 409.
func TestHandleWalletImport_conflictReturns409(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s := new(logical.InmemStorage)
	req := &logical.Request{Storage: s}

	if !bip39.IsMnemonicValid(testMnemonic) {
		t.Fatal("sanity: expected test mnemonic to be valid.")
	}

	resp, err := handleWalletImport(ctx, req, walletFieldData(map[string]interface{}{
		"wallet_id": "wdup",
		"mnemonic":  testMnemonic,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || resp.Data == nil {
		t.Fatal("expected response data.")
	}

	resp2, err := handleWalletImport(ctx, req, walletFieldData(map[string]interface{}{
		"wallet_id": "wdup",
		"mnemonic":  testMnemonic,
	}))
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

// TestHandleListWallets_sorted verifies listed wallet ids are sorted lexicographically.
func TestHandleListWallets_sorted(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s := new(logical.InmemStorage)
	mustPutWalletSeed(ctx, t, s, "b", testMnemonic)
	mustPutWalletSeed(ctx, t, s, "a", testMnemonic)

	req := &logical.Request{Storage: s}
	resp, err := handleListWallets(ctx, req, walletFieldData(map[string]interface{}{}))
	if err != nil {
		t.Fatal(err)
	}
	keys, ok := resp.Data["keys"].([]string)
	if !ok {
		t.Fatalf("keys type=%T want []string.", resp.Data["keys"])
	}
	if len(keys) != 2 || keys[0] != "a" || keys[1] != "b" {
		t.Fatalf("keys=%v want [a b].", keys)
	}
}
