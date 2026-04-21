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

package model

import (
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/bsostech/vault-blockchain/pkg/utils"
)

// testMnemonicHD is a standard BIP-39 test vector (do not use on mainnet).
const testMnemonicHD = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

// TestValidateAddressIndex checks boundary behavior for BIP-44 address index validation.
func TestValidateAddressIndex(t *testing.T) {
	t.Parallel()
	if err := ValidateAddressIndex(0); err != nil {
		t.Fatalf("0: %v", err)
	}
	if err := ValidateAddressIndex(uint64(MaxBIP44AddressIndex)); err != nil {
		t.Fatalf("max: %v", err)
	}
	if err := ValidateAddressIndex(uint64(MaxBIP44AddressIndex) + 1); !errors.Is(err, ErrIndexOutOfRange) {
		t.Fatalf("above max: got %v want %v", err, ErrIndexOutOfRange)
	}
}

// TestDeriveEthereumAccount_deterministic verifies deterministic addresses and distinct indices for a test mnemonic.
func TestDeriveEthereumAccount_deterministic(t *testing.T) {
	t.Parallel()
	addr0, path0, err := DeriveEthereumAccount(testMnemonicHD, 0)
	if err != nil {
		t.Fatalf("derive 0: %v", err)
	}
	if path0 != "m/44'/60'/0'/0/0" {
		t.Fatalf("path0: got %q", path0)
	}
	addr0b, _, err := DeriveEthereumAccount(testMnemonicHD, 0)
	if err != nil {
		t.Fatal(err)
	}
	if addr0 != addr0b {
		t.Fatalf("non-deterministic address")
	}
	addr1, path1, err := DeriveEthereumAccount(testMnemonicHD, 1)
	if err != nil {
		t.Fatal(err)
	}
	if path1 != "m/44'/60'/0'/0/1" {
		t.Fatalf("path1: got %q", path1)
	}
	if addr1 == addr0 {
		t.Fatal("index 0 and 1 should differ")
	}
}

// TestPrivateKeyECDSA_matches_DeriveEthereumAccount verifies PrivateKeyECDSA matches DeriveEthereumAccount address.
func TestPrivateKeyECDSA_matches_DeriveEthereumAccount(t *testing.T) {
	t.Parallel()
	addr, _, err := DeriveEthereumAccount(testMnemonicHD, 2)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := PrivateKeyECDSA(testMnemonicHD, 2)
	if err != nil {
		t.Fatalf("private key: %v", err)
	}
	t.Cleanup(func() { utils.ZeroKey(pk) })
	got := crypto.PubkeyToAddress(pk.PublicKey).Hex()
	if got != addr {
		t.Fatalf("address mismatch: derived %s pubkey %s", addr, got)
	}
}

// TestDeriveEthereumAccount_invalidMnemonic verifies derivation fails for an invalid mnemonic.
func TestDeriveEthereumAccount_invalidMnemonic(t *testing.T) {
	t.Parallel()
	_, _, err := DeriveEthereumAccount("not a valid mnemonic phrase", 0)
	if err == nil {
		t.Fatal("expected error")
	}
}

// TestPrivateKeyECDSA_indexOutOfRange verifies PrivateKeyECDSA returns ErrIndexOutOfRange above the max index.
func TestPrivateKeyECDSA_indexOutOfRange(t *testing.T) {
	t.Parallel()
	_, err := PrivateKeyECDSA(testMnemonicHD, MaxBIP44AddressIndex+1)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrIndexOutOfRange) {
		t.Fatalf("expected %v, got %v", ErrIndexOutOfRange, err)
	}
}
