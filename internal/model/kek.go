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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/bsostech/vault-blockchain/pkg/utils"
)

// KEK is a BYOK key exchange key: an RSA key pair whose public half is handed to the party that wraps
// a private key, and whose private half unwraps it. The private key is stored as PKCS#8 DER.
type KEK struct {
	Name          string    `json:"name"`
	ID            string    `json:"id"` // random per instance, so a recreated KEK with the same name gets a new kid
	KeySize       int       `json:"key_size"`
	PrivateKeyDER []byte    `json:"private_key_der"`
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at"` // zero value means no expiry
}

// NewKEK generates an RSA key pair of keySize bits. A ttl greater than zero sets the expiry.
func NewKEK(name string, keySize int, ttl time.Duration, now time.Time) (*KEK, error) {
	priv, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, fmt.Errorf("generate rsa key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		utils.ZeroBytes(der)
		return nil, fmt.Errorf("generate kek id: %w", err)
	}
	k := &KEK{
		Name:          name,
		ID:            hex.EncodeToString(id),
		KeySize:       keySize,
		PrivateKeyDER: der,
		CreatedAt:     now.UTC(),
	}
	if ttl > 0 {
		k.ExpiresAt = k.CreatedAt.Add(ttl)
	}
	return k, nil
}

// KID returns the key identifier written into a .byok header: <mountPoint>byok/keks/<name>/<id>.
// mountPoint is the plugin mount path with a trailing slash (for example "blockchain/"), or empty.
func (k *KEK) KID(mountPoint string) string {
	return fmt.Sprintf("%sbyok/keks/%s/%s", mountPoint, k.Name, k.ID)
}

// Expired reports whether the KEK has a ttl that has elapsed at now.
func (k *KEK) Expired(now time.Time) bool {
	return !k.ExpiresAt.IsZero() && !now.Before(k.ExpiresAt)
}

// PrivateKey parses the stored PKCS#8 DER into an RSA private key.
func (k *KEK) PrivateKey() (*rsa.PrivateKey, error) {
	parsed, err := x509.ParsePKCS8PrivateKey(k.PrivateKeyDER)
	if err != nil {
		return nil, fmt.Errorf("parse kek private key: %w", err)
	}
	priv, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("kek private key is %T, want *rsa.PrivateKey", parsed)
	}
	return priv, nil
}

// publicKeyDER returns the public key as DER-encoded SubjectPublicKeyInfo.
func (k *KEK) publicKeyDER() ([]byte, error) {
	priv, err := k.PrivateKey()
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	return der, nil
}

// PublicKeyPEM returns the public key as a PEM "PUBLIC KEY" block (SubjectPublicKeyInfo).
func (k *KEK) PublicKeyPEM() (string, error) {
	der, err := k.publicKeyDER()
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

// PublicKeyFingerprint returns the hex SHA-256 of the DER-encoded public key. The party holding the
// other end can compare it out of band to confirm the public key was not replaced in transit.
func (k *KEK) PublicKeyFingerprint() (string, error) {
	der, err := k.publicKeyDER()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}
