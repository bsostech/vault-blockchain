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

package wallet

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/bsostech/vault-blockchain/internal/model"
	"github.com/bsostech/vault-blockchain/internal/path/storagekey"
	"github.com/bsostech/vault-blockchain/pkg/utils"
)

var (
	// ErrInvalidPathIndexFormat means the path segment is not a non-negative decimal integer.
	ErrInvalidPathIndexFormat = errors.New("index must be a non-negative decimal integer")
	// ErrInvalidPathIndexRange means the index exceeds the BIP-44 address_index bound.
	ErrInvalidPathIndexRange = errors.New("index must be 0..2147483647")
	// ErrDerivedAccountMissing is returned when the wallet or derived account entry is absent.
	ErrDerivedAccountMissing = errors.New("derived account not found")
)

// ExistenceWalletDerivedAccount returns true when storage has a derived account for wallet_id and index.
func ExistenceWalletDerivedAccount() framework.ExistenceFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
		walletID := model.NewFieldDataWrapper(data).GetString("wallet_id", "")
		indexStr := model.NewFieldDataWrapper(data).GetString("index", "")
		if walletID == "" || indexStr == "" {
			return false, nil
		}
		entry, err := req.Storage.Get(ctx, storagekey.AccountKey(walletID, indexStr))
		if err != nil {
			return false, fmt.Errorf("existence check derived account %s/%s: %w", walletID, indexStr, err)
		}
		return entry != nil, nil
	}
}

// ReadWalletSeed loads and decodes the wallet seed entry, or returns nil if missing.
func ReadWalletSeed(ctx context.Context, s logical.Storage, walletID string) (*model.WalletSeed, error) {
	entry, err := s.Get(ctx, storagekey.SeedKey(walletID))
	if err != nil {
		return nil, fmt.Errorf("get wallet seed %s: %w", walletID, err)
	}
	if entry == nil {
		return nil, nil
	}
	var seed model.WalletSeed
	if err := entry.DecodeJSON(&seed); err != nil {
		return nil, fmt.Errorf("decode wallet seed %s: %w", walletID, err)
	}
	return &seed, nil
}

// ParseAddressIndex parses a non-negative decimal index string within BIP-44 address_index bounds.
func ParseAddressIndex(indexStr string) (uint32, error) {
	v, err := strconv.ParseUint(indexStr, 10, 32)
	if err != nil {
		return 0, ErrInvalidPathIndexFormat
	}
	if err := model.ValidateAddressIndex(v); err != nil {
		return 0, ErrInvalidPathIndexRange
	}
	return uint32(v), nil
}

// LoadWalletDerivedPrivateKey loads seed and derived metadata, derives the ECDSA key, and checks the address.
// The caller must invoke utils.ZeroKey on the key after use.
func LoadWalletDerivedPrivateKey(
	ctx context.Context,
	s logical.Storage,
	walletID, indexStr string,
) (*ecdsa.PrivateKey, *model.DerivedAccount, error) {
	indexU32, err := ParseAddressIndex(indexStr)
	if err != nil {
		return nil, nil, err
	}
	acctEntry, err := s.Get(ctx, storagekey.AccountKey(walletID, indexStr))
	if err != nil {
		return nil, nil, fmt.Errorf("get derived account %s/%s: %w", walletID, indexStr, err)
	}
	if acctEntry == nil {
		return nil, nil, ErrDerivedAccountMissing
	}
	var derived model.DerivedAccount
	if err := acctEntry.DecodeJSON(&derived); err != nil {
		return nil, nil, fmt.Errorf("decode derived account %s/%s: %w", walletID, indexStr, err)
	}
	seed, err := ReadWalletSeed(ctx, s, walletID)
	if err != nil {
		return nil, nil, err
	}
	if seed == nil || seed.Mnemonic == "" {
		return nil, nil, ErrDerivedAccountMissing
	}
	pk, err := model.PrivateKeyECDSA(seed.Mnemonic, indexU32)
	if err != nil {
		return nil, nil, fmt.Errorf("derive private key: %w", err)
	}
	if common.HexToAddress(derived.Address) != crypto.PubkeyToAddress(pk.PublicKey) {
		utils.ZeroKey(pk)
		return nil, nil, fmt.Errorf(
			"derived key does not match stored address for wallet %s index %s",
			walletID,
			indexStr,
		)
	}
	return pk, &derived, nil
}

// ModelAccountFromDerivedKey builds an in-memory model.Account for ECIES/ECDSA helpers (not read from storage).
func ModelAccountFromDerivedKey(pk *ecdsa.PrivateKey, derived *model.DerivedAccount) *model.Account {
	privBytes := crypto.FromECDSA(pk)
	privStr := hexutil.Encode(privBytes)[2:]
	return model.NewAccount(derived.Address, privStr, "")
}

// RespondLoadWalletKeyError maps loader errors to logical responses for Vault handlers.
func RespondLoadWalletKeyError(err error) (*logical.Response, error) {
	switch {
	case errors.Is(err, ErrDerivedAccountMissing):
		return logical.ErrorResponse("derived account not found"), nil
	case errors.Is(err, ErrInvalidPathIndexFormat), errors.Is(err, ErrInvalidPathIndexRange):
		return logical.ErrorResponse("%s", err.Error()), nil
	default:
		return nil, err
	}
}
