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

package model

import (
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tyler-smith/go-bip39"

	"github.com/bsostech/vault-blockchain/pkg/utils"
)

// WalletSeed holds the BIP-39 mnemonic for a wallet; stored at wallets/<wallet_id>/seed.
type WalletSeed struct {
	Mnemonic string `json:"mnemonic"`
}

// DerivedAccount holds public metadata for a derived address; stored at wallets/<wallet_id>/accounts/<index>.
type DerivedAccount struct {
	Address        string `json:"address"`
	DerivationPath string `json:"derivation_path"`
}

// MaxBIP44AddressIndex is the inclusive upper bound for the address index segment (2^31-1).
const MaxBIP44AddressIndex uint32 = 0x7FFFFFFF

var (
	// ErrIndexOutOfRange indicates the address index is outside BIP-44 limits.
	ErrIndexOutOfRange = errors.New("address index out of BIP-44 range")
)

// ValidateAddressIndex returns ErrIndexOutOfRange when index exceeds MaxBIP44AddressIndex.
func ValidateAddressIndex(index uint64) error {
	if index > uint64(MaxBIP44AddressIndex) {
		return ErrIndexOutOfRange
	}
	return nil
}

// ethereumBIP44ChildIndices is m/44'/60'/0'/0/<index> as successive BIP-32 child indices.
func ethereumBIP44ChildIndices(index uint32) []uint32 {
	return []uint32{
		44 + hdkeychain.HardenedKeyStart,
		60 + hdkeychain.HardenedKeyStart,
		0 + hdkeychain.HardenedKeyStart,
		0,
		index,
	}
}

// derivePrivateKeyAtEthereumPath uses BIP-39 seed + BIP-32 (via btcsuite hdkeychain) to reach
// m/44'/60'/0'/0/<index>, then returns the secp256k1 key as *ecdsa.PrivateKey for go-ethereum.
func derivePrivateKeyAtEthereumPath(mnemonic string, index uint32) (*ecdsa.PrivateKey, error) {
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, fmt.Errorf("invalid mnemonic")
	}
	seed := bip39.NewSeed(mnemonic, "")
	defer func() {
		for i := range seed {
			seed[i] = 0
		}
	}()

	master, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("hd master: %w", err)
	}

	cur := master
	for _, childIdx := range ethereumBIP44ChildIndices(index) {
		next, derr := cur.Derive(childIdx)
		if derr != nil {
			cur.Zero()
			return nil, fmt.Errorf("hd derive: %w", derr)
		}
		cur.Zero()
		cur = next
	}

	btcecPriv, err := cur.ECPrivKey()
	cur.Zero()
	if err != nil {
		return nil, fmt.Errorf("hd leaf ecdsa: %w", err)
	}
	d := btcecPriv.Serialize()
	btcecPriv.Zero()
	defer func() {
		for i := range d {
			d[i] = 0
		}
	}()
	// Use go-ethereum's ToECDSA so Curve is crypto.S256(); btcecPriv.ToECDSA() sets a different
	// Curve identity and breaks github.com/ethereum/go-ethereum/crypto.Sign's curve check.
	ecdsaPriv, err := crypto.ToECDSA(d)
	if err != nil {
		return nil, fmt.Errorf("secp256k1 scalar to ecdsa: %w", err)
	}
	return ecdsaPriv, nil
}

// DeriveEthereumAccount returns the checksummed hex address and path string m/44'/60'/0'/0/<index>.
func DeriveEthereumAccount(mnemonic string, index uint32) (address string, derivationPath string, err error) {
	if err := ValidateAddressIndex(uint64(index)); err != nil {
		return "", "", fmt.Errorf("validate index: %w", err)
	}
	pk, err := derivePrivateKeyAtEthereumPath(mnemonic, index)
	if err != nil {
		return "", "", err
	}
	defer utils.ZeroKey(pk)
	derivationPath = fmt.Sprintf("m/44'/60'/0'/0/%d", index)
	return crypto.PubkeyToAddress(pk.PublicKey).Hex(), derivationPath, nil
}

// PrivateKeyECDSA derives the secp256k1 private key at m/44'/60'/0'/0/<index>.
// Callers must clear sensitive material when done.
func PrivateKeyECDSA(mnemonic string, index uint32) (*ecdsa.PrivateKey, error) {
	if err := ValidateAddressIndex(uint64(index)); err != nil {
		return nil, fmt.Errorf("validate index: %w", err)
	}
	return derivePrivateKeyAtEthereumPath(mnemonic, index)
}
