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

package byok

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/bsostech/vault-blockchain/internal/model"
	"github.com/bsostech/vault-blockchain/internal/path/storagekey"
	"github.com/bsostech/vault-blockchain/pkg/utils"
)

const defaultKEKKeySize = 3072

// errKEKAlreadyExists indicates a KEK already exists for the name.
var errKEKAlreadyExists = errors.New("kek_exists: kek already exists")

// validKEKKeySize reports whether bits is a supported RSA modulus size.
func validKEKKeySize(bits int) bool {
	return bits == 2048 || bits == 3072 || bits == 4096
}

// respondKEKConflict returns HTTP 409 for duplicate KEK names.
func respondKEKConflict(req *logical.Request) (*logical.Response, error) {
	return logical.RespondWithStatusCode(
		logical.ErrorResponse("%s", errKEKAlreadyExists.Error()),
		req,
		http.StatusConflict,
	)
}

// existenceKEK reports whether a KEK record exists, so Vault routes the write to create or update.
func existenceKEK() framework.ExistenceFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
		name := model.NewFieldDataWrapper(data).GetString("kek_name", "")
		if name == "" {
			return false, nil
		}
		entry, err := req.Storage.Get(ctx, storagekey.KEKKey(name))
		if err != nil {
			return false, fmt.Errorf("kek existence check for %s: %w", name, err)
		}
		return entry != nil, nil
	}
}

// loadKEK returns the stored KEK, or nil when none exists.
func loadKEK(ctx context.Context, s logical.Storage, name string) (*model.KEK, error) {
	entry, err := s.Get(ctx, storagekey.KEKKey(name))
	if err != nil {
		return nil, fmt.Errorf("get kek %s: %w", name, err)
	}
	if entry == nil {
		return nil, nil
	}
	var k model.KEK
	if err := entry.DecodeJSON(&k); err != nil {
		return nil, fmt.Errorf("decode kek %s: %w", name, err)
	}
	return &k, nil
}

// kekResponseData builds the public view of a KEK. It never includes private key material.
func kekResponseData(req *logical.Request, k *model.KEK) (map[string]interface{}, error) {
	pubPEM, err := k.PublicKeyPEM()
	if err != nil {
		return nil, err
	}
	fp, err := k.PublicKeyFingerprint()
	if err != nil {
		return nil, err
	}
	expires := ""
	if !k.ExpiresAt.IsZero() {
		expires = k.ExpiresAt.Format(time.RFC3339)
	}
	return map[string]interface{}{
		"kid":               k.KID(req.MountPoint),
		"kek_name":          k.Name,
		"key_size":          k.KeySize,
		"public_key_pem":    pubPEM,
		"public_key_sha256": fp,
		"created_at":        k.CreatedAt.Format(time.RFC3339),
		"expires_at":        expires,
	}, nil
}

// handleKEKCreate generates a KEK and stores it under the given name.
func handleKEKCreate(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	name, err := model.NewFieldDataWrapper(data).MustGetString("kek_name")
	if err != nil || name == "" {
		return logical.ErrorResponse("kek_name is required"), nil
	}
	keySize := data.Get("key_size").(int)
	if !validKEKKeySize(keySize) {
		return logical.ErrorResponse("key_size must be 2048, 3072, or 4096"), nil
	}
	ttlSeconds := data.Get("ttl").(int)
	if ttlSeconds < 0 {
		return logical.ErrorResponse("ttl must not be negative"), nil
	}

	existing, err := loadKEK(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return respondKEKConflict(req)
	}

	k, err := model.NewKEK(name, keySize, time.Duration(ttlSeconds)*time.Second, time.Now())
	if err != nil {
		return nil, err
	}
	defer utils.ZeroBytes(k.PrivateKeyDER)

	entry, err := logical.StorageEntryJSON(storagekey.KEKKey(name), k)
	if err != nil {
		return nil, fmt.Errorf("encode kek %s: %w", name, err)
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, fmt.Errorf("put kek %s: %w", name, err)
	}

	out, err := kekResponseData(req, k)
	if err != nil {
		return nil, err
	}
	return &logical.Response{Data: out}, nil
}

// handleKEKUpdate rejects writes to an existing KEK; a KEK is immutable once created.
func handleKEKUpdate(
	_ context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	if _, err := model.NewFieldDataWrapper(data).MustGetString("kek_name"); err != nil {
		return logical.ErrorResponse("kek_name is required"), nil
	}
	return respondKEKConflict(req)
}

// handleKEKRead returns the public view of a KEK, or nothing (HTTP 404) when it does not exist.
func handleKEKRead(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	name, err := model.NewFieldDataWrapper(data).MustGetString("kek_name")
	if err != nil || name == "" {
		return logical.ErrorResponse("kek_name is required"), nil
	}
	k, err := loadKEK(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if k == nil {
		return nil, nil
	}
	defer utils.ZeroBytes(k.PrivateKeyDER)

	out, err := kekResponseData(req, k)
	if err != nil {
		return nil, err
	}
	return &logical.Response{Data: out}, nil
}

// handleKEKDelete removes a KEK and its private key. Deleting a missing KEK succeeds.
func handleKEKDelete(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	name, err := model.NewFieldDataWrapper(data).MustGetString("kek_name")
	if err != nil || name == "" {
		return logical.ErrorResponse("kek_name is required"), nil
	}
	if err := req.Storage.Delete(ctx, storagekey.KEKKey(name)); err != nil {
		return nil, fmt.Errorf("delete kek %s: %w", name, err)
	}
	return nil, nil
}

// handleKEKList returns the sorted names of stored KEKs.
func handleKEKList(
	ctx context.Context,
	req *logical.Request,
	_ *framework.FieldData,
) (*logical.Response, error) {
	names, err := req.Storage.List(ctx, storagekey.KEKsListPrefix())
	if err != nil {
		return nil, fmt.Errorf("list keks: %w", err)
	}
	sort.Strings(names)
	return logical.ListResponse(names), nil
}
