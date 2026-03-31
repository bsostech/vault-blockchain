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

package wallet_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/bsostech/vault-blockchain/internal/model"
	"github.com/bsostech/vault-blockchain/internal/path/storagekey"
	walletpkg "github.com/bsostech/vault-blockchain/internal/path/wallet"
	"github.com/bsostech/vault-blockchain/pkg/utils"
)

const testMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

// TestParseAddressIndex verifies ParseAddressIndex for valid bounds and sentinel errors.
func TestParseAddressIndex(t *testing.T) {
	t.Parallel()
	u, err := walletpkg.ParseAddressIndex("0")
	if err != nil || u != 0 {
		t.Fatalf("0: %v %d", err, u)
	}
	u, err = walletpkg.ParseAddressIndex("2147483647")
	if err != nil || u != 2147483647 {
		t.Fatalf("max: %v %d", err, u)
	}
	if _, err := walletpkg.ParseAddressIndex("x"); !errors.Is(err, walletpkg.ErrInvalidPathIndexFormat) {
		t.Fatalf("format: %v", err)
	}
	if _, err := walletpkg.ParseAddressIndex("2147483648"); !errors.Is(err, walletpkg.ErrInvalidPathIndexRange) {
		t.Fatalf("range: %v", err)
	}
}

// TestLoadWalletDerivedPrivateKey_success verifies a matching seed and derived record load without error.
func TestLoadWalletDerivedPrivateKey_success(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := new(logical.InmemStorage)
	walletID := "w1"
	indexStr := "0"
	addr, dpath, err := model.DeriveEthereumAccount(testMnemonic, 0)
	if err != nil {
		t.Fatal(err)
	}
	seedEntry, err := logical.StorageEntryJSON(storagekey.SeedKey(walletID), &model.WalletSeed{Mnemonic: testMnemonic})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, seedEntry); err != nil {
		t.Fatal(err)
	}
	acct := &model.DerivedAccount{Address: addr, DerivationPath: dpath}
	acctEntry, err := logical.StorageEntryJSON(storagekey.AccountKey(walletID, indexStr), acct)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, acctEntry); err != nil {
		t.Fatal(err)
	}
	pk, _, err := walletpkg.LoadWalletDerivedPrivateKey(ctx, s, walletID, indexStr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { utils.ZeroKey(pk) })
}

// TestLoadWalletDerivedPrivateKey_missingAccount verifies ErrDerivedAccountMissing when account row is absent.
func TestLoadWalletDerivedPrivateKey_missingAccount(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := new(logical.InmemStorage)
	seedEntry, err := logical.StorageEntryJSON(storagekey.SeedKey("w2"), &model.WalletSeed{Mnemonic: testMnemonic})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, seedEntry); err != nil {
		t.Fatal(err)
	}
	_, _, err = walletpkg.LoadWalletDerivedPrivateKey(ctx, s, "w2", "9")
	if !errors.Is(err, walletpkg.ErrDerivedAccountMissing) {
		t.Fatalf("got %v", err)
	}
}

// TestLoadWalletDerivedPrivateKey_addressMismatch verifies mismatch between stored address and derived key fails.
func TestLoadWalletDerivedPrivateKey_addressMismatch(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := new(logical.InmemStorage)
	walletID := "w3"
	seedEntry, err := logical.StorageEntryJSON(storagekey.SeedKey(walletID), &model.WalletSeed{Mnemonic: testMnemonic})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, seedEntry); err != nil {
		t.Fatal(err)
	}
	wrong := &model.DerivedAccount{
		Address:        "0x0000000000000000000000000000000000000001",
		DerivationPath: "m/44'/60'/0'/0/0",
	}
	acctEntry, err := logical.StorageEntryJSON(storagekey.AccountKey(walletID, "0"), wrong)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, acctEntry); err != nil {
		t.Fatal(err)
	}
	_, _, err = walletpkg.LoadWalletDerivedPrivateKey(ctx, s, walletID, "0")
	if err == nil {
		t.Fatal("expected mismatch error")
	}
}

// TestPrivateKeyECDSA_compatibleWithGoEthereumSign verifies hdwallet keys use secp256k1 expected by crypto.Sign.
func TestPrivateKeyECDSA_compatibleWithGoEthereumSign(t *testing.T) {
	t.Parallel()
	pk, err := model.PrivateKeyECDSA(testMnemonic, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { utils.ZeroKey(pk) })
	if pk.Curve != crypto.S256() {
		t.Fatalf("expected S256 curve for crypto.Sign, got %T", pk.Curve)
	}
	hash := crypto.Keccak256Hash([]byte("hello"))
	if _, err := crypto.Sign(hash.Bytes(), pk); err != nil {
		t.Fatal(err)
	}
}
