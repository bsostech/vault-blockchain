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
	"bytes"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
)

// TestECIES_RoundTrip checks EncryptECIES and DecryptECIES round-trip with a generated key pair.
func TestECIES_RoundTrip(t *testing.T) {
	t.Parallel()

	ecdsaKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	priv := ecies.ImportECDSA(ecdsaKey)
	pub := &priv.PublicKey

	plaintext := []byte("hello-ecies")

	ciphertext, err := EncryptECIES(pub, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("ciphertext unexpectedly equals plaintext.")
	}

	got, err := DecryptECIES(priv, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("got %q want %q.", string(got), string(plaintext))
	}
}

// TestEncryptECIES_nilKey verifies EncryptECIES returns an error when the public key is nil.
func TestEncryptECIES_nilKey(t *testing.T) {
	t.Parallel()

	_, err := EncryptECIES(nil, []byte("x"))
	if err == nil {
		t.Fatal("expected error.")
	}
}

// TestDecryptECIES_nilKey verifies DecryptECIES returns an error when the private key is nil.
func TestDecryptECIES_nilKey(t *testing.T) {
	t.Parallel()

	_, err := DecryptECIES(nil, []byte("x"))
	if err == nil {
		t.Fatal("expected error.")
	}
}

// TestDecryptECIES_wrongKey verifies decryption fails when ciphertext was encrypted with a different key.
func TestDecryptECIES_wrongKey(t *testing.T) {
	t.Parallel()

	key1, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	key2, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	priv1 := ecies.ImportECDSA(key1)
	pub1 := &priv1.PublicKey
	priv2 := ecies.ImportECDSA(key2)

	ciphertext, err := EncryptECIES(pub1, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = DecryptECIES(priv2, ciphertext)
	if err == nil {
		t.Fatal("expected error.")
	}
}

