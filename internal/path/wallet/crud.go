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
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/tyler-smith/go-bip39"

	"github.com/bsostech/vault-blockchain/internal/model"
	"github.com/bsostech/vault-blockchain/internal/path/storagekey"
)

// errWalletAlreadyExists indicates a seed is already stored for wallet_id.
var errWalletAlreadyExists = errors.New("wallet_id already exists")

// putWalletSeedIfAbsent writes the BIP-39 seed JSON under wallets/<id>/seed if absent.
func putWalletSeedIfAbsent(
	ctx context.Context,
	req *logical.Request,
	walletID, mnemonic string,
) error {
	seedKey := storagekey.SeedKey(walletID)
	existing, err := req.Storage.Get(ctx, seedKey)
	if err != nil {
		return fmt.Errorf("get wallet seed %s: %w", walletID, err)
	}
	if existing != nil {
		return errWalletAlreadyExists
	}

	seed := &model.WalletSeed{Mnemonic: mnemonic}
	entry, err := logical.StorageEntryJSON(seedKey, seed)
	if err != nil {
		return fmt.Errorf("encode wallet seed %s: %w", walletID, err)
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return fmt.Errorf("put wallet seed %s: %w", walletID, err)
	}
	return nil
}

// generateMnemonic24 returns a random BIP-39 mnemonic with 256-bit entropy (24 words).
func generateMnemonic24() (string, error) {
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		return "", fmt.Errorf("generate entropy: %w", err)
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", fmt.Errorf("generate mnemonic: %w", err)
	}
	return mnemonic, nil
}

// respondWalletConflict returns HTTP 409 when the wallet_id already has a stored seed.
func respondWalletConflict(req *logical.Request) (*logical.Response, error) {
	return logical.RespondWithStatusCode(
		logical.ErrorResponse("%s", errWalletAlreadyExists.Error()),
		req,
		http.StatusConflict,
	)
}

// handleWalletCreateAuto generates a 24-word mnemonic, stores it for wallet_id, and returns only the id.
func handleWalletCreateAuto(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	walletID, err := model.NewFieldDataWrapper(data).MustGetString("wallet_id")
	if err != nil || walletID == "" {
		return logical.ErrorResponse("wallet_id is required"), nil
	}

	mnemonic, err := generateMnemonic24()
	if err != nil {
		return nil, err
	}

	if err := putWalletSeedIfAbsent(ctx, req, walletID, mnemonic); err != nil {
		if errors.Is(err, errWalletAlreadyExists) {
			return respondWalletConflict(req)
		}
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"wallet_id": walletID,
		},
	}, nil
}

// handleWalletImport validates and stores an existing mnemonic for wallet_id without returning it.
func handleWalletImport(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	wrapper := model.NewFieldDataWrapper(data)
	walletID, err := wrapper.MustGetString("wallet_id")
	if err != nil {
		return logical.ErrorResponse("%s", err.Error()), nil
	}
	mnemonic, err := wrapper.MustGetString("mnemonic")
	if err != nil {
		return logical.ErrorResponse("%s", err.Error()), nil
	}
	if !bip39.IsMnemonicValid(mnemonic) {
		return logical.ErrorResponse("invalid mnemonic"), nil
	}

	if err := putWalletSeedIfAbsent(ctx, req, walletID, mnemonic); err != nil {
		if errors.Is(err, errWalletAlreadyExists) {
			return respondWalletConflict(req)
		}
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"wallet_id": walletID,
		},
	}, nil
}

// handleListWallets returns sorted wallet_id values that have a stored seed entry.
func handleListWallets(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	children, err := req.Storage.List(ctx, "wallets/")
	if err != nil {
		return nil, fmt.Errorf("list wallets: %w", err)
	}
	seen := make(map[string]struct{}, len(children))
	var ids []string
	for _, child := range children {
		id := strings.TrimSuffix(child, "/")
		if id == "" {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return logical.ListResponse(ids), nil
}

// makeHandleDerivedAccountCreate returns a handler that derives m/44'/60'/0'/0/<counter> and
// persists address metadata for the wallet. The index is assigned automatically using a
// per-wallet counter. walletMu serialises the counter read-increment-write sequence so that
// concurrent requests to the same wallet_id cannot derive the same address.
func makeHandleDerivedAccountCreate(walletMu *sync.Map) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		walletID, err := model.NewFieldDataWrapper(data).MustGetString("wallet_id")
		if err != nil || walletID == "" {
			return logical.ErrorResponse("wallet_id is required"), nil
		}

		mu, _ := walletMu.LoadOrStore(walletID, &sync.Mutex{})
		mu.(*sync.Mutex).Lock()
		defer mu.(*sync.Mutex).Unlock()

		seed, err := ReadWalletSeed(ctx, req.Storage, walletID)
		if err != nil {
			return nil, err
		}
		if seed == nil || seed.Mnemonic == "" {
			return logical.ErrorResponse("wallet not found"), nil
		}

		nextIndex, err := ReadWalletCounter(ctx, req.Storage, walletID)
		if err != nil {
			return nil, err
		}
		if err := model.ValidateAddressIndex(uint64(nextIndex)); err != nil {
			return logical.ErrorResponse("account index limit reached (max 2147483647)"), nil
		}

		address, derivationPath, err := model.DeriveEthereumAccount(seed.Mnemonic, nextIndex)
		if err != nil {
			return nil, fmt.Errorf("derive account %s/%d: %w", walletID, nextIndex, err)
		}

		indexStr := fmt.Sprintf("%d", nextIndex)
		derived := &model.DerivedAccount{
			Address:        address,
			DerivationPath: derivationPath,
		}
		entry, err := logical.StorageEntryJSON(storagekey.AccountKey(walletID, indexStr), derived)
		if err != nil {
			return nil, fmt.Errorf("encode derived account %s/%s: %w", walletID, indexStr, err)
		}
		if err := req.Storage.Put(ctx, entry); err != nil {
			return nil, fmt.Errorf("put derived account %s/%s: %w", walletID, indexStr, err)
		}
		if err := WriteWalletCounter(ctx, req.Storage, walletID, nextIndex+1); err != nil {
			return nil, err
		}

		return &logical.Response{
			Data: map[string]interface{}{
				"address":         address,
				"account_index":   indexStr,
				"derivation_path": derivationPath,
			},
		}, nil
	}
}

// handleDerivedAccountRead returns stored address and derivation path for wallet_id and index.
func handleDerivedAccountRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	walletID, err := model.NewFieldDataWrapper(data).MustGetString("wallet_id")
	if err != nil || walletID == "" {
		return logical.ErrorResponse("wallet_id is required"), nil
	}
	indexStr, err := model.NewFieldDataWrapper(data).MustGetString("index")
	if err != nil || indexStr == "" {
		return logical.ErrorResponse("index is required"), nil
	}

	entry, err := req.Storage.Get(ctx, storagekey.AccountKey(walletID, indexStr))
	if err != nil {
		return nil, fmt.Errorf("get derived account %s/%s: %w", walletID, indexStr, err)
	}
	if entry == nil {
		return logical.ErrorResponse("derived account not found"), nil
	}

	var derived model.DerivedAccount
	if err := entry.DecodeJSON(&derived); err != nil {
		return nil, fmt.Errorf("decode derived account %s/%s: %w", walletID, indexStr, err)
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"address":         derived.Address,
			"account_index":   indexStr,
			"derivation_path": derived.DerivationPath,
		},
	}, nil
}

// handleListDerivedAccounts returns sorted index strings for derived accounts that exist in storage.
// Optional start and end query parameters (inclusive) filter the returned indices to a range.
func handleListDerivedAccounts(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	walletID, err := model.NewFieldDataWrapper(data).MustGetString("wallet_id")
	if err != nil || walletID == "" {
		return logical.ErrorResponse("wallet_id is required"), nil
	}
	children, err := req.Storage.List(ctx, storagekey.AccountsListPrefix(walletID))
	if err != nil {
		return nil, fmt.Errorf("list derived accounts %s: %w", walletID, err)
	}

	startStr := model.NewFieldDataWrapper(data).GetString("start", "")
	endStr := model.NewFieldDataWrapper(data).GetString("end", "")

	hasStart := startStr != ""
	hasEnd := endStr != ""

	var startVal, endVal int
	if hasStart {
		startVal, err = strconv.Atoi(startStr)
		if err != nil || startVal < 0 {
			return logical.ErrorResponse("start must be a non-negative integer"), nil
		}
	}
	if hasEnd {
		endVal, err = strconv.Atoi(endStr)
		if err != nil || endVal < 0 {
			return logical.ErrorResponse("end must be a non-negative integer"), nil
		}
	}
	if hasStart && hasEnd && startVal > endVal {
		return logical.ErrorResponse("start must be <= end"), nil
	}

	indices := make([]int, 0, len(children))
	for _, child := range children {
		idxStr := strings.TrimSuffix(child, "/")
		if idxStr == "" {
			continue
		}
		idxInt, err := strconv.Atoi(idxStr)
		if err != nil {
			continue
		}
		if hasStart && idxInt < startVal {
			continue
		}
		if hasEnd && idxInt > endVal {
			continue
		}
		indices = append(indices, idxInt)
	}
	sort.Ints(indices)

	keys := make([]string, len(indices))
	for i, idx := range indices {
		keys[i] = fmt.Sprintf("%d", idx)
	}
	return logical.ListResponse(keys), nil
}
