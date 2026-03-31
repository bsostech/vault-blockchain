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

	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

func mustTypedData(t *testing.T) *apitypes.TypedData {
	chainID := math.NewHexOrDecimal256(1)

	return &apitypes.TypedData{
		Types: apitypes.Types{
			"EIP712Domain": {
				{Name: "name", Type: "string"},
				{Name: "version", Type: "string"},
				{Name: "chainId", Type: "uint256"},
			},
			"Mail": {
				{Name: "contents", Type: "string"},
			},
		},
		PrimaryType: "Mail",
		Domain: apitypes.TypedDataDomain{
			Name:    "VaultBlockchain",
			Version: "1",
			ChainId: chainID,
		},
		Message: apitypes.TypedDataMessage{
			"contents": "hello",
		},
	}
}

// TestSignEIP712TypedData verifies SignEIP712TypedData produces a signature recoverable to the signer.
func TestSignEIP712TypedData(t *testing.T) {
	t.Parallel()

	td := mustTypedData(t)
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := SignEIP712TypedData(td, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) == 0 {
		t.Fatal("expected non-empty signature.")
	}

	sighash, _, err := apitypes.TypedDataAndHash(*td)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := crypto.SigToPub(sighash, sig)
	if err != nil {
		t.Fatal(err)
	}
	got := crypto.PubkeyToAddress(*pub)
	want := crypto.PubkeyToAddress(key.PublicKey)
	if got != want {
		t.Fatalf("recovered=%s want %s.", got, want)
	}
}

func TestSignEIP712TypedData_nilTypedData(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	_, err = SignEIP712TypedData(nil, key)
	if err == nil {
		t.Fatal("expected error.")
	}
}

func TestSignEIP712TypedData_nilKey(t *testing.T) {
	t.Parallel()

	td := mustTypedData(t)
	_, err := SignEIP712TypedData(td, nil)
	if err == nil {
		t.Fatal("expected error.")
	}
}
