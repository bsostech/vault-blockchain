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
	"crypto/ecdsa"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"

	"github.com/bsostech/vault-blockchain/pkg/utils"
)

// Account holds address and key material as hex strings. Loaded from single-key mode
// accounts/<name>/address storage or built in-memory from a derived HD key to reuse
// ECIES/ECDSA helpers.
type Account struct {
	AddressStr    string `json:"address"` // Ethereum account address derived from the private key
	PrivateKeyStr string `json:"private_key"`
	PublicKeyStr  string `json:"public_key"` // Ethereum public key derived from the private key
}

// NewAccount builds an Account from hex address and key strings.
func NewAccount(addressStr string, privateKeyStr string, publicKeyStr string) *Account {
	return &Account{
		AddressStr:    addressStr,
		PrivateKeyStr: privateKeyStr,
		PublicKeyStr:  publicKeyStr,
	}
}

// GetPrivateKeyECDSA parses and returns the ECDSA private key for signing.
func (a *Account) GetPrivateKeyECDSA() (*ecdsa.PrivateKey, error) {
	// Get private key from account
	return crypto.HexToECDSA(a.PrivateKeyStr)
}

// GetPublicKeyECDSA derives the ECDSA public key from the stored private key hex.
func (a *Account) GetPublicKeyECDSA() (*ecdsa.PublicKey, error) {
	privateKeyECDSA, err := a.GetPrivateKeyECDSA()
	if err != nil {
		return nil, err
	}
	defer utils.ZeroKey(privateKeyECDSA)
	publicKey := privateKeyECDSA.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("error casting public key to ECDSA")
	}
	return publicKeyECDSA, nil
}

// GetPrivateKeyECIES returns the ECIES private key for decryption of ciphertext.
func (a *Account) GetPrivateKeyECIES() (*ecies.PrivateKey, error) {
	privateKeyECDSA, err := a.GetPrivateKeyECDSA()
	if err != nil {
		return nil, err
	}
	privateKeyECIES := ecies.ImportECDSA(privateKeyECDSA)
	return privateKeyECIES, nil
}

// GetPublicKeyECIES returns the ECIES public key for encryption to this account.
func (a *Account) GetPublicKeyECIES() (*ecies.PublicKey, error) {
	publicKeyECDSA, err := a.GetPublicKeyECDSA()
	if err != nil {
		return nil, err
	}
	publicKeyECIES := ecies.ImportECDSAPublic(publicKeyECDSA)
	return publicKeyECIES, nil
}
