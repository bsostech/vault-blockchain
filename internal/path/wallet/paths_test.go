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
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

//nolint:staticcheck // reads Callbacks when Operations unset; production paths still register Callbacks
func pathRegisteredOps(p *framework.Path) map[logical.Operation]bool {
	if len(p.Operations) > 0 {
		ops := make(map[logical.Operation]bool, len(p.Operations))
		for op := range p.Operations {
			ops[op] = true
		}
		return ops
	}
	ops := make(map[logical.Operation]bool)
	for op := range p.Callbacks {
		ops[op] = true
	}
	return ops
}

// TestPaths_registerUpdateOnWriteEndpoints verifies write endpoints register UpdateOperation as well as CreateOperation.
func TestPaths_registerUpdateOnWriteEndpoints(t *testing.T) {
	t.Parallel()

	var walletMu sync.Map
	paths := Paths(&walletMu)
	if len(paths) == 0 {
		t.Fatal("expected non-empty paths.")
	}

	byPattern := make(map[string]map[logical.Operation]bool, len(paths))
	for _, p := range paths {
		if p == nil || p.Pattern == "" {
			t.Fatal("expected non-nil path with non-empty pattern.")
		}
		byPattern[p.Pattern] = pathRegisteredOps(p)
	}

	// These endpoints use ExistenceCheck; Vault often routes HTTP writes to UpdateOperation.
	// Ensure both create and update are wired to avoid 405s during `vault write`.
	wantSuffixes := []string{
		"/accounts/(?P<index>\\d+)/sign",
		"/accounts/(?P<index>\\d+)/sign-eip712",
		"/accounts/(?P<index>\\d+)/encrypt",
		"/accounts/(?P<index>\\d+)/decrypt",
		"/accounts/(?P<index>\\d+)/sign-tx/legacy",
		"/accounts/(?P<index>\\d+)/sign-tx/eip1559",
	}

	for _, suffix := range wantSuffixes {
		var (
			foundPattern string
			foundOps     map[logical.Operation]bool
		)
		for pattern, ops := range byPattern {
			if strings.HasPrefix(pattern, "wallets/") && strings.HasSuffix(pattern, suffix) {
				foundPattern = pattern
				foundOps = ops
				break
			}
		}
		if foundPattern == "" {
			t.Fatalf("missing wallets/* pattern with suffix %q.", suffix)
		}
		if !foundOps[logical.CreateOperation] {
			t.Fatalf("pattern %q missing CreateOperation.", foundPattern)
		}
		if !foundOps[logical.UpdateOperation] {
			t.Fatalf("pattern %q missing UpdateOperation.", foundPattern)
		}
	}
}

// TestPaths_batchDerivedAccounts_registersCreateUpdate verifies batch path wires Create and Update.
func TestPaths_batchDerivedAccounts_registersCreateUpdate(t *testing.T) {
	t.Parallel()

	var walletMu sync.Map
	paths := Paths(&walletMu)
	var batchPattern string
	for _, p := range paths {
		if p == nil {
			continue
		}
		if strings.HasSuffix(p.Pattern, "/accounts/batch") {
			batchPattern = p.Pattern
			ops := pathRegisteredOps(p)
			if !ops[logical.CreateOperation] || !ops[logical.UpdateOperation] {
				t.Fatalf("pattern %q ops=%v want Create+Update.", p.Pattern, ops)
			}
			break
		}
	}
	if batchPattern == "" {
		t.Fatal("missing wallets/*/accounts/batch path.")
	}
}

// TestPaths_listDerivedAccounts_registersRead verifies the accounts/? path wires ReadOperation
// alongside the existing List, Create, and Update operations.
func TestPaths_listDerivedAccounts_registersRead(t *testing.T) {
	t.Parallel()

	var walletMu sync.Map
	for _, p := range Paths(&walletMu) {
		if p == nil || !strings.HasSuffix(p.Pattern, "/accounts/?") {
			continue
		}
		ops := pathRegisteredOps(p)
		if !ops[logical.ReadOperation] {
			t.Fatalf("pattern %q missing ReadOperation.", p.Pattern)
		}
		if !ops[logical.ListOperation] {
			t.Fatalf("pattern %q missing ListOperation.", p.Pattern)
		}
		if !ops[logical.CreateOperation] || !ops[logical.UpdateOperation] {
			t.Fatalf("pattern %q missing Create+Update.", p.Pattern)
		}
		return
	}
	t.Fatal("missing wallets/*/accounts/? path.")
}
