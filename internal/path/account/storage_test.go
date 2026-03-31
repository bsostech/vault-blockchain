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

package account_test

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/bsostech/vault-blockchain/internal/model"
	"github.com/bsostech/vault-blockchain/internal/path/account"
	"github.com/bsostech/vault-blockchain/internal/path/storagekey"
)

// TestReadSingleKeyAccount covers missing storage, bad JSON, empty key, and successful decode paths.
func TestReadSingleKeyAccount(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	t.Run("missing", func(t *testing.T) {
		t.Parallel()

		s := new(logical.InmemStorage)
		_, err := account.ReadSingleKeyAccount(ctx, s, "a1")
		if !errors.Is(err, account.ErrSingleKeyAccountMissing) {
			t.Fatalf("got %v want %v.", err, account.ErrSingleKeyAccountMissing)
		}
	})

	t.Run("invalid_json", func(t *testing.T) {
		t.Parallel()

		s := new(logical.InmemStorage)
		key := storagekey.SingleKeyAccountKey("a2")
		if err := s.Put(ctx, &logical.StorageEntry{Key: key, Value: []byte("{")}); err != nil {
			t.Fatal(err)
		}

		_, err := account.ReadSingleKeyAccount(ctx, s, "a2")
		if err == nil {
			t.Fatal("expected error.")
		}
	})

	t.Run("empty_private_key", func(t *testing.T) {
		t.Parallel()

		s := new(logical.InmemStorage)
		key := storagekey.SingleKeyAccountKey("a3")
		entry, err := logical.StorageEntryJSON(key, &model.Account{AddressStr: "0xabc"})
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Put(ctx, entry); err != nil {
			t.Fatal(err)
		}

		_, err = account.ReadSingleKeyAccount(ctx, s, "a3")
		if err == nil {
			t.Fatal("expected error.")
		}
	})

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		s := new(logical.InmemStorage)
		key := storagekey.SingleKeyAccountKey("a4")
		entry, err := logical.StorageEntryJSON(key, &model.Account{
			AddressStr:    "0xabc",
			PrivateKeyStr: "deadbeef",
			PublicKeyStr:  "beef",
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Put(ctx, entry); err != nil {
			t.Fatal(err)
		}

		got, err := account.ReadSingleKeyAccount(ctx, s, "a4")
		if err != nil {
			t.Fatal(err)
		}
		if got.AddressStr != "0xabc" {
			t.Fatalf("AddressStr=%q want %q.", got.AddressStr, "0xabc")
		}
		if got.PrivateKeyStr != "deadbeef" {
			t.Fatalf("PrivateKeyStr=%q want %q.", got.PrivateKeyStr, "deadbeef")
		}
	})
}

// TestExistenceSingleKeyAccount verifies existence false for empty name and true when storage has the account.
func TestExistenceSingleKeyAccount(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s := new(logical.InmemStorage)
	req := &logical.Request{Storage: s}

	exists, err := account.ExistenceSingleKeyAccount()(ctx, req, &framework.FieldData{
		Raw:    map[string]interface{}{"name": ""},
		Schema: map[string]*framework.FieldSchema{"name": {Type: framework.TypeString}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("exists=true want false.")
	}

	key := storagekey.SingleKeyAccountKey("x")
	entry, err := logical.StorageEntryJSON(key, &model.Account{AddressStr: "0xabc", PrivateKeyStr: "deadbeef"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, entry); err != nil {
		t.Fatal(err)
	}

	exists, err = account.ExistenceSingleKeyAccount()(ctx, req, &framework.FieldData{
		Raw:    map[string]interface{}{"name": "x"},
		Schema: map[string]*framework.FieldSchema{"name": {Type: framework.TypeString}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("exists=false want true.")
	}
}

func TestExistenceSingleKeyAccountSeed(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s := new(logical.InmemStorage)
	req := &logical.Request{Storage: s}

	exists, err := account.ExistenceSingleKeyAccountSeed()(ctx, req, &framework.FieldData{
		Raw:    map[string]interface{}{"name": ""},
		Schema: map[string]*framework.FieldSchema{"name": {Type: framework.TypeString}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("exists=true want false.")
	}

	key := storagekey.SingleKeyAccountKey("y")
	entry, err := logical.StorageEntryJSON(key, &model.Account{AddressStr: "0xabc", PrivateKeyStr: "deadbeef"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, entry); err != nil {
		t.Fatal(err)
	}

	exists, err = account.ExistenceSingleKeyAccountSeed()(ctx, req, &framework.FieldData{
		Raw:    map[string]interface{}{"name": "y"},
		Schema: map[string]*framework.FieldSchema{"name": {Type: framework.TypeString}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("exists=false want true.")
	}
}

// TestRespondLoadSingleKeyAccountError maps ErrSingleKeyAccountMissing to a logical error and passes through other errors.
func TestRespondLoadSingleKeyAccountError(t *testing.T) {
	t.Parallel()

	resp, err := account.RespondLoadSingleKeyAccountError(account.ErrSingleKeyAccountMissing)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected logical response.")
	}

	sentinel := errors.New("boom")
	resp, err = account.RespondLoadSingleKeyAccountError(sentinel)
	if !errors.Is(err, sentinel) {
		t.Fatalf("got %v want %v.", err, sentinel)
	}
	if resp != nil {
		t.Fatalf("resp=%v want nil.", resp)
	}
}

