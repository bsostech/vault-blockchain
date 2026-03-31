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
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

// TypedDataFromJSON parses EIP-712 JSON fields into go-ethereum TypedData.
func TypedDataFromJSON(domainJSON, typesJSON, primaryType, messageJSON string) (*apitypes.TypedData, error) {
	primaryType = strings.TrimSpace(primaryType)
	if primaryType == "" {
		return nil, fmt.Errorf("primary_type is required")
	}

	var typesDef apitypes.Types
	if err := json.Unmarshal([]byte(typesJSON), &typesDef); err != nil {
		return nil, fmt.Errorf("invalid types JSON: %w", err)
	}
	var domain apitypes.TypedDataDomain
	if err := json.Unmarshal([]byte(domainJSON), &domain); err != nil {
		return nil, fmt.Errorf("invalid domain JSON: %w", err)
	}
	var message apitypes.TypedDataMessage
	if err := json.Unmarshal([]byte(messageJSON), &message); err != nil {
		return nil, fmt.Errorf("invalid message JSON: %w", err)
	}

	td := &apitypes.TypedData{
		Types:       typesDef,
		PrimaryType: primaryType,
		Domain:      domain,
		Message:     message,
	}
	return td, nil
}

// SignEIP712TypedData signs the EIP-712 typed-data hash using the provided ECDSA private key.
func SignEIP712TypedData(td *apitypes.TypedData, pk *ecdsa.PrivateKey) ([]byte, error) {
	if td == nil {
		return nil, fmt.Errorf("typed data is nil")
	}
	if pk == nil {
		return nil, fmt.Errorf("ecdsa private key is nil")
	}

	sighash, _, err := apitypes.TypedDataAndHash(*td)
	if err != nil {
		return nil, fmt.Errorf("eip712 typed data hash: %w", err)
	}
	sig, err := crypto.Sign(sighash, pk)
	if err != nil {
		return nil, fmt.Errorf("eip712 sign: %w", err)
	}
	return sig, nil
}
