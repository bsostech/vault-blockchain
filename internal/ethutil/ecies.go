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
	"crypto/rand"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto/ecies"
)

// EncryptECIES encrypts plaintext using an ECIES public key.
func EncryptECIES(publicKey *ecies.PublicKey, plaintext []byte) ([]byte, error) {
	if publicKey == nil {
		return nil, fmt.Errorf("ecies public key is nil")
	}
	cipherText, err := ecies.Encrypt(rand.Reader, publicKey, plaintext, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("ecies encrypt: %w", err)
	}
	return cipherText, nil
}

// DecryptECIES decrypts ciphertext using an ECIES private key.
func DecryptECIES(privateKey *ecies.PrivateKey, ciphertext []byte) ([]byte, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("ecies private key is nil")
	}
	plainText, err := privateKey.Decrypt(ciphertext, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("ecies decrypt: %w", err)
	}
	return plainText, nil
}
