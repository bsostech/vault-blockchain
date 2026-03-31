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

	"github.com/hashicorp/vault/sdk/logical"
)

// TestPaths_registerUpdateOnWriteEndpoints verifies write endpoints register UpdateOperation as well as CreateOperation.
func TestPaths_registerUpdateOnWriteEndpoints(t *testing.T) {
	t.Parallel()

	var walletMu sync.RWMutex
	paths := Paths(&walletMu)
	if len(paths) == 0 {
		t.Fatal("expected non-empty paths.")
	}

	byPattern := make(map[string]map[logical.Operation]bool, len(paths))
	for _, p := range paths {
		if p == nil || p.Pattern == "" {
			t.Fatal("expected non-nil path with non-empty pattern.")
		}
		ops := make(map[logical.Operation]bool, len(p.Callbacks))
		for op := range p.Callbacks {
			ops[op] = true
		}
		byPattern[p.Pattern] = ops
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
