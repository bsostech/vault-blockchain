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

// Package storagekey builds logical storage paths for wallet seeds, derived accounts, and single-key accounts.
package storagekey

import "fmt"

// SingleKeyAccountKey returns the storage path for a single-key account (JSON with private key material).
func SingleKeyAccountKey(name string) string {
	return fmt.Sprintf("accounts/%s/address", name)
}

// SingleKeyAccountsRootPrefix is the list prefix for top-level names under accounts/.
func SingleKeyAccountsRootPrefix() string {
	return "accounts/"
}

// SeedKey returns the storage path for a wallet's BIP-39 seed.
func SeedKey(walletID string) string {
	return fmt.Sprintf("wallets/%s/seed", walletID)
}

// AccountKey returns the storage path for a single derived account record.
func AccountKey(walletID, index string) string {
	return fmt.Sprintf("wallets/%s/accounts/%s", walletID, index)
}

// AccountsListPrefix returns the list prefix for derived account indices under a wallet.
func AccountsListPrefix(walletID string) string {
	return fmt.Sprintf("wallets/%s/accounts/", walletID)
}
