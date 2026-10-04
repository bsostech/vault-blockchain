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
	"testing"
	"time"
)

// TestKEKExpired verifies expiry is inclusive of the expiry instant and absent without a ttl.
func TestKEKExpired(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

	noTTL, err := NewKEK("k", 2048, 0, now)
	if err != nil {
		t.Fatal(err)
	}
	if !noTTL.ExpiresAt.IsZero() || noTTL.Expired(now.Add(1000*time.Hour)) {
		t.Fatal("KEK without ttl must never expire")
	}

	withTTL, err := NewKEK("k", 2048, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if !withTTL.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("ExpiresAt=%v", withTTL.ExpiresAt)
	}
	if withTTL.Expired(now.Add(time.Hour - time.Second)) {
		t.Fatal("expired too early")
	}
	if !withTTL.Expired(now.Add(time.Hour)) {
		t.Fatal("must be expired at the expiry instant")
	}
}

// TestKEKKID verifies the kid layout with and without a mount point.
func TestKEKKID(t *testing.T) {
	t.Parallel()
	k := &KEK{Name: "kek1", ID: "abcd"}
	if got := k.KID("blockchain/"); got != "blockchain/byok/keks/kek1/abcd" {
		t.Fatal(got)
	}
	if got := k.KID(""); got != "byok/keks/kek1/abcd" {
		t.Fatal(got)
	}
}
