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

package path

import (
	"github.com/hashicorp/vault/sdk/framework"

	"github.com/bsostech/vault-blockchain/internal/path/account"
	"github.com/bsostech/vault-blockchain/internal/path/wallet"
)

// GetPaths returns all framework paths.
func GetPaths() []*framework.Path {
	acctPaths := account.Paths()
	walletPaths := wallet.Paths()
	out := make([]*framework.Path, 0, len(acctPaths)+len(walletPaths))
	out = append(out, acctPaths...)
	out = append(out, walletPaths...)
	return out
}
