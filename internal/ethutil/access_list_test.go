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

package ethutil

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// TestParseAccessListJSON verifies ParseAccessListJSON for empty input, whitespace, valid JSON, and invalid JSON.
func TestParseAccessListJSON(t *testing.T) {
	t.Parallel()

	t.Run("empty_string_returns_nil", func(t *testing.T) {
		t.Parallel()

		got, err := ParseAccessListJSON("")
		if err != nil {
			t.Fatal(err)
		}
		if got != nil {
			t.Fatalf("got %v want nil.", got)
		}
	})

	t.Run("whitespace_only_returns_nil", func(t *testing.T) {
		t.Parallel()

		got, err := ParseAccessListJSON("   \n\t")
		if err != nil {
			t.Fatal(err)
		}
		if got != nil {
			t.Fatalf("got %v want nil.", got)
		}
	})

	t.Run("valid_json", func(t *testing.T) {
		t.Parallel()

		raw := `[{"address":"0x0000000000000000000000000000000000000001","storageKeys":["0x0000000000000000000000000000000000000000000000000000000000000002"]}]`
		got, err := ParseAccessListJSON(raw)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 {
			t.Fatalf("len(got)=%d want 1.", len(got))
		}
		if got[0].Address != common.HexToAddress("0x0000000000000000000000000000000000000001") {
			t.Fatalf("address=%s want %s.", got[0].Address, common.HexToAddress("0x0000000000000000000000000000000000000001"))
		}
		if len(got[0].StorageKeys) != 1 {
			t.Fatalf("len(storageKeys)=%d want 1.", len(got[0].StorageKeys))
		}
		if got[0].StorageKeys[0] != common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000002") {
			t.Fatalf("storageKey=%s want %s.", got[0].StorageKeys[0], common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000002"))
		}
	})

	t.Run("invalid_json_returns_error", func(t *testing.T) {
		t.Parallel()

		_, err := ParseAccessListJSON("{")
		if err == nil {
			t.Fatal("expected error.")
		}
	})
}

