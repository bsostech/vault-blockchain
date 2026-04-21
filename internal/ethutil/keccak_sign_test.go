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

	"github.com/ethereum/go-ethereum/crypto"
)

// TestSignKeccak256 verifies keccak256 signing and signature recovery to the signer address.
func TestSignKeccak256(t *testing.T) {
	t.Parallel()

	pk, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("hello")
	sig, err := SignKeccak256(data, pk)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 65 {
		t.Fatalf("len(sig)=%d want 65.", len(sig))
	}

	hash := crypto.Keccak256Hash(data)
	pub, err := crypto.SigToPub(hash.Bytes(), sig)
	if err != nil {
		t.Fatal(err)
	}
	gotAddr := crypto.PubkeyToAddress(*pub)
	wantAddr := crypto.PubkeyToAddress(pk.PublicKey)
	if gotAddr != wantAddr {
		t.Fatalf("recovered address=%s want %s.", gotAddr, wantAddr)
	}
}

// TestSignKeccak256_nilKey verifies SignKeccak256 returns an error when the private key is nil.
func TestSignKeccak256_nilKey(t *testing.T) {
	t.Parallel()

	_, err := SignKeccak256([]byte("x"), nil)
	if err == nil {
		t.Fatal("expected error.")
	}
}

