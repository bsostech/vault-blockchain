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

	"github.com/bsostech/vault-bridgex/pkg/utils"
)

// Account is an Ethereum account
type Account struct {
	AddressStr    string `json:"address"` // Ethereum account address derived from the private key
	PrivateKeyStr string `json:"private_key"`
	PublicKeyStr  string `json:"public_key"` // Ethereum public key derived from the private key
}

// NewAccount returns Account
func NewAccount(addressStr string, privateKeyStr string, publicKeyStr string) *Account {
	return &Account{
		AddressStr:    addressStr,
		PrivateKeyStr: privateKeyStr,
		PublicKeyStr:  publicKeyStr,
	}
}

// GetPrivateKeyECDSA key for signing data
func (a *Account) GetPrivateKeyECDSA() (*ecdsa.PrivateKey, error) {
	// Get private key from account
	return crypto.HexToECDSA(a.PrivateKeyStr)
}

// GetPublicKeyECDSA key for validating signature
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

// GetPrivateKeyECIES key for encrypting data
func (a *Account) GetPrivateKeyECIES() (*ecies.PrivateKey, error) {
	privateKeyECDSA, err := a.GetPrivateKeyECDSA()
	if err != nil {
		return nil, err
	}
	privateKeyECIES := ecies.ImportECDSA(privateKeyECDSA)
	return privateKeyECIES, nil
}

// GetPublicKeyECIES key for decrypting data
func (a *Account) GetPublicKeyECIES() (*ecies.PublicKey, error) {
	publicKeyECDSA, err := a.GetPublicKeyECDSA()
	if err != nil {
		return nil, err
	}
	publicKeyECIES := ecies.ImportECDSAPublic(publicKeyECDSA)
	return publicKeyECIES, nil
}
