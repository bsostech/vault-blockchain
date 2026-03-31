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

package path_test

import (
	"sync"
	"testing"

	"github.com/hashicorp/vault/sdk/framework"

	"github.com/bsostech/vault-blockchain/internal/path"
	"github.com/bsostech/vault-blockchain/internal/path/account"
	"github.com/bsostech/vault-blockchain/internal/path/wallet"
)

// TestGetPaths verifies merged account and wallet paths are non-empty, unique, and cover both prefixes.
func TestGetPaths(t *testing.T) {
	t.Parallel()

	var walletMu sync.RWMutex
	var singleKeyMu sync.Mutex

	got := path.GetPaths(&walletMu, &singleKeyMu)
	if len(got) == 0 {
		t.Fatal("expected non-empty paths.")
	}

	wantLen := len(account.Paths(&singleKeyMu)) + len(wallet.Paths(&walletMu))
	if len(got) != wantLen {
		t.Fatalf("len(got)=%d want %d.", len(got), wantLen)
	}

	seen := make(map[string]struct{}, len(got))
	for _, p := range got {
		if p == nil {
			t.Fatal("expected non-nil path.")
		}
		if p.Pattern == "" {
			t.Fatal("expected non-empty pattern.")
		}
		if _, dup := seen[p.Pattern]; dup {
			t.Fatalf("duplicate pattern %q.", p.Pattern)
		}
		seen[p.Pattern] = struct{}{}
	}

	var hasAccounts, hasWallets bool
	for pattern := range seen {
		if len(pattern) >= len("accounts/") && pattern[:len("accounts/")] == "accounts/" {
			hasAccounts = true
		}
		if len(pattern) >= len("wallets/") && pattern[:len("wallets/")] == "wallets/" {
			hasWallets = true
		}
	}
	if !hasAccounts {
		t.Fatal("expected at least one accounts/ path.")
	}
	if !hasWallets {
		t.Fatal("expected at least one wallets/ path.")
	}

	_ = framework.Path{}
}

