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
	"crypto/ecdsa"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
)

// SignKeccak256 signs keccak256(data) using the ECDSA private key.
func SignKeccak256(data []byte, pk *ecdsa.PrivateKey) ([]byte, error) {
	if pk == nil {
		return nil, fmt.Errorf("signing key is nil")
	}
	hash := crypto.Keccak256Hash(data)
	sig, err := crypto.Sign(hash.Bytes(), pk)
	if err != nil {
		return nil, fmt.Errorf("sign hash: %w", err)
	}
	return sig, nil
}
