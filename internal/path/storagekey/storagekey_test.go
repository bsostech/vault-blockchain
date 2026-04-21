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

package storagekey_test

import (
	"testing"

	"github.com/bsostech/vault-blockchain/internal/path/storagekey"
)

// TestKeys verifies storage-key helper output paths.
func TestKeys(t *testing.T) {
	t.Parallel()
	if got := storagekey.SingleKeyAccountKey("alice"); got != "accounts/alice/address" {
		t.Fatal(got)
	}
	if got := storagekey.SingleKeyAccountsRootPrefix(); got != "accounts/" {
		t.Fatal(got)
	}
	if got := storagekey.SeedKey("my-id"); got != "wallets/my-id/seed" {
		t.Fatal(got)
	}
	if got := storagekey.AccountKey("my-id", "3"); got != "wallets/my-id/accounts/3" {
		t.Fatal(got)
	}
	if got := storagekey.AccountsListPrefix("my-id"); got != "wallets/my-id/accounts/" {
		t.Fatal(got)
	}
}
