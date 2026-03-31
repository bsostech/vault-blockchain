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
	"math/big"
	"testing"

	"github.com/hashicorp/vault/sdk/framework"
)

// fieldDataForTest builds FieldData with TypeString schema for raw keys and every key in schemaKeys.
func fieldDataForTest(t *testing.T, raw map[string]interface{}, schemaKeys ...string) *FieldDataWrapper {
	t.Helper()
	keySet := make(map[string]struct{})
	for k := range raw {
		keySet[k] = struct{}{}
	}
	for _, k := range schemaKeys {
		keySet[k] = struct{}{}
	}
	schema := make(map[string]*framework.FieldSchema)
	for k := range keySet {
		schema[k] = &framework.FieldSchema{Type: framework.TypeString}
	}
	return NewFieldDataWrapper(&framework.FieldData{Raw: raw, Schema: schema})
}

// TestGetStringFirstNonEmpty verifies GetStringFirstNonEmpty skips empty strings and handles all-missing keys.
func TestGetStringFirstNonEmpty(t *testing.T) {
	t.Parallel()
	w := fieldDataForTest(t, map[string]interface{}{
		"a": "",
		"b": "ok",
	}, "a", "b", "missing", "x")
	if got := w.GetStringFirstNonEmpty("a", "b"); got != "ok" {
		t.Fatalf("got %q", got)
	}
	if got := w.GetStringFirstNonEmpty("missing", "x"); got != "" {
		t.Fatalf("got %q want empty", got)
	}
}

// TestBigIntWithAliases verifies BigIntWithAliases prefers the first alias with a valid decimal.
func TestBigIntWithAliases(t *testing.T) {
	t.Parallel()
	def := big.NewInt(99)
	w := fieldDataForTest(t, map[string]interface{}{
		"amount": "5",
	}, "value", "amount")
	if got := w.BigIntWithAliases("value", "amount", def); got.Cmp(big.NewInt(5)) != 0 {
		t.Fatalf("amount branch: got %v", got)
	}
	w2 := fieldDataForTest(t, map[string]interface{}{
		"value": "7",
	}, "value", "amount")
	if got := w2.BigIntWithAliases("value", "amount", def); got.Cmp(big.NewInt(7)) != 0 {
		t.Fatalf("value branch: got %v", got)
	}
	w3 := fieldDataForTest(t, map[string]interface{}{}, "value", "amount")
	if got := w3.BigIntWithAliases("value", "amount", def); got.Cmp(def) != 0 {
		t.Fatalf("default: got %v", got)
	}
}

// TestMustGetBigIntAny verifies MustGetBigIntAny accepts either of two alias keys and errors when empty.
func TestMustGetBigIntAny(t *testing.T) {
	t.Parallel()
	w := fieldDataForTest(t, map[string]interface{}{
		"chain_id": "1",
	}, "chain_id", "chainID")
	bi, err := w.MustGetBigIntAny("chain_id", "chainID")
	if err != nil {
		t.Fatal(err)
	}
	if bi.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("got %v", bi)
	}
	w2 := fieldDataForTest(t, map[string]interface{}{
		"chainID": "42161",
	}, "chain_id", "chainID")
	bi2, err := w2.MustGetBigIntAny("chain_id", "chainID")
	if err != nil {
		t.Fatal(err)
	}
	if bi2.Cmp(big.NewInt(42161)) != 0 {
		t.Fatalf("alias: got %v", bi2)
	}
	w3 := fieldDataForTest(t, map[string]interface{}{}, "chain_id")
	if _, err := w3.MustGetBigIntAny("chain_id"); err == nil {
		t.Fatal("expected error for missing value")
	}
}

func TestMustGetBigInt_rejectsInvalidDecimal(t *testing.T) {
	t.Parallel()

	w := fieldDataForTest(t, map[string]interface{}{"n": "abc"}, "n")
	if bi, err := w.MustGetBigInt("n"); err == nil || bi != nil {
		t.Fatalf("expected error and nil big.Int, got bi=%v err=%v", bi, err)
	}
}

func TestMustGetUint64_rejectsInvalidDecimal(t *testing.T) {
	t.Parallel()

	w := fieldDataForTest(t, map[string]interface{}{"n": "abc"}, "n")
	if _, err := w.MustGetUint64("n"); err == nil {
		t.Fatal("expected error")
	}
}

func TestGetBigInt_invalidReturnsDefault(t *testing.T) {
	t.Parallel()

	def := big.NewInt(7)
	w := fieldDataForTest(t, map[string]interface{}{"n": "abc"}, "n")
	got := w.GetBigInt("n", def)
	if got == nil || got.Cmp(def) != 0 {
		t.Fatalf("got %v want %v", got, def)
	}
}
