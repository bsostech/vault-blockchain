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

package byokcrypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // RSA-OAEP with SHA-1 is required by the Azure BYOK transfer format and HSM interop.
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// Fixed values of the .byok transfer blob (Azure Key Vault BYOK specification).
const (
	// SchemaVersion is the only supported blob schema version.
	SchemaVersion = "1.0.0"
	// Alg is the JWE direct-mode algorithm: the referenced kid directly protects the ciphertext.
	Alg = "dir"
	// Enc names the key wrap mechanism. Luna builds the same bytes with two PKCS#11 calls.
	Enc = "CKM_RSA_AES_KEY_WRAP"

	// MaxBlobSize bounds the Base64 input accepted from callers.
	MaxBlobSize = 64 * 1024

	aesKeyBytes = 32
)

// Errors returned for the blob and key wrapping.
var (
	// ErrInvalidBlob means the .byok blob is malformed or uses unsupported parameters.
	ErrInvalidBlob = errors.New("invalid byok blob")
	// ErrUnwrapFailed means the ciphertext could not be unwrapped. The cause is deliberately not distinguished.
	ErrUnwrapFailed = errors.New("unwrap failed")
	// ErrInvalidKEKPublicKey means the KEK public key cannot be parsed or has an unsupported size.
	ErrInvalidKEKPublicKey = errors.New("invalid kek public key")
)

// Header is the protected header of a .byok blob.
type Header struct {
	KID string `json:"kid"`
	Alg string `json:"alg"`
	Enc string `json:"enc"`
}

// Blob is the .byok key transfer blob.
type Blob struct {
	SchemaVersion string `json:"schema_version"`
	Header        Header `json:"header"`
	Ciphertext    string `json:"ciphertext"` // base64url, no padding
	Generator     string `json:"generator,omitempty"`
}

// ValidKEKSize reports whether bits is a supported KEK RSA modulus size.
func ValidKEKSize(bits int) bool {
	return bits == 2048 || bits == 3072 || bits == 4096
}

// ParseKEKPublicKeyPEM parses an RSA public key from PEM ("PUBLIC KEY" SubjectPublicKeyInfo or
// "RSA PUBLIC KEY" PKCS#1) and checks its size.
func ParseKEKPublicKeyPEM(s string) (*rsa.PublicKey, error) {
	block, rest := pem.Decode([]byte(s))
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, ErrInvalidKEKPublicKey
	}
	var pub *rsa.PublicKey
	switch block.Type {
	case "PUBLIC KEY":
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, ErrInvalidKEKPublicKey
		}
		rsaPub, ok := parsed.(*rsa.PublicKey)
		if !ok {
			return nil, ErrInvalidKEKPublicKey
		}
		pub = rsaPub
	case "RSA PUBLIC KEY":
		parsed, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, ErrInvalidKEKPublicKey
		}
		pub = parsed
	default:
		return nil, ErrInvalidKEKPublicKey
	}
	if !ValidKEKSize(pub.N.BitLen()) {
		return nil, ErrInvalidKEKPublicKey
	}
	return pub, nil
}

// WrapKey wraps pkcs8 (a PKCS#8 private key) for the holder of kek and returns the .byok blob.
// A fresh AES-256 key wraps the private key with AES-KWP, and kek wraps that AES key with
// RSA-OAEP (SHA-1, MGF1-SHA1, empty label). The ciphertext is the RSA part followed by the AES part.
func WrapKey(kek *rsa.PublicKey, kid string, pkcs8 []byte, generator string) (*Blob, error) {
	if kek == nil || !ValidKEKSize(kek.N.BitLen()) {
		return nil, ErrInvalidKEKPublicKey
	}
	if kid == "" {
		return nil, fmt.Errorf("%w: empty kid", ErrInvalidBlob)
	}
	aesKey := make([]byte, aesKeyBytes)
	defer zero(aesKey)
	if _, err := rand.Read(aesKey); err != nil {
		return nil, fmt.Errorf("generate aes key: %w", err)
	}
	wrappedKey, err := KWPWrap(aesKey, pkcs8)
	if err != nil {
		return nil, err
	}
	wrappedAES, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, kek, aesKey, nil) //nolint:gosec // see import comment.
	if err != nil {
		return nil, fmt.Errorf("rsa-oaep wrap: %w", err)
	}
	ct := append(wrappedAES, wrappedKey...)
	return &Blob{
		SchemaVersion: SchemaVersion,
		Header:        Header{KID: kid, Alg: Alg, Enc: Enc},
		Ciphertext:    base64.RawURLEncoding.EncodeToString(ct),
		Generator:     generator,
	}, nil
}

// UnwrapKey recovers the PKCS#8 private key from blob using kek. The returned bytes must be zeroed by
// the caller. Wrong key, wrong OAEP parameters, and tampered data all return ErrUnwrapFailed.
func UnwrapKey(kek *rsa.PrivateKey, blob *Blob) ([]byte, error) {
	ct, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(blob.Ciphertext, "="))
	if err != nil {
		return nil, fmt.Errorf("%w: ciphertext is not base64url", ErrInvalidBlob)
	}
	k := kek.PublicKey.Size()
	// RSA part is exactly one modulus; the AES-KWP part is at least 16 bytes and a multiple of 8.
	if len(ct) < k+16 || (len(ct)-k)%8 != 0 {
		return nil, fmt.Errorf("%w: ciphertext length does not match the kek", ErrInvalidBlob)
	}

	aesKey, err := rsa.DecryptOAEP(sha1.New(), nil, kek, ct[:k], nil) //nolint:gosec // see import comment.
	if err != nil {
		return nil, ErrUnwrapFailed
	}
	defer zero(aesKey)
	if l := len(aesKey); l != 16 && l != 24 && l != 32 {
		return nil, ErrUnwrapFailed
	}
	pkcs8, err := KWPUnwrap(aesKey, ct[k:])
	if err != nil {
		return nil, ErrUnwrapFailed
	}
	return pkcs8, nil
}

// Encode returns the blob as .byok JSON, Base64 encoded for use as the byok_blob API value.
func (b *Blob) Encode() (string, error) {
	raw, err := json.Marshal(b)
	if err != nil {
		return "", fmt.Errorf("marshal blob: %w", err)
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// ParseBlob decodes a Base64 .byok file and validates its fixed fields. Unknown JSON fields are ignored
// so blobs from vendor tools that add metadata are accepted.
func ParseBlob(b64 string) (*Blob, error) {
	if len(b64) > MaxBlobSize {
		return nil, fmt.Errorf("%w: larger than %d bytes", ErrInvalidBlob, MaxBlobSize)
	}
	b64 = strings.TrimSpace(b64)
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(b64, "="))
		if err != nil {
			return nil, fmt.Errorf("%w: not base64", ErrInvalidBlob)
		}
	}
	var blob Blob
	if err := json.Unmarshal(raw, &blob); err != nil {
		return nil, fmt.Errorf("%w: not json", ErrInvalidBlob)
	}
	switch {
	case blob.SchemaVersion != SchemaVersion:
		return nil, fmt.Errorf("%w: unsupported schema_version", ErrInvalidBlob)
	case blob.Header.Alg != Alg:
		return nil, fmt.Errorf("%w: unsupported alg", ErrInvalidBlob)
	case blob.Header.Enc != Enc:
		return nil, fmt.Errorf("%w: unsupported enc", ErrInvalidBlob)
	case blob.Header.KID == "":
		return nil, fmt.Errorf("%w: missing kid", ErrInvalidBlob)
	case blob.Ciphertext == "":
		return nil, fmt.Errorf("%w: missing ciphertext", ErrInvalidBlob)
	}
	return &blob, nil
}

// PublicKeyFingerprint returns the hex SHA-256 of the DER SubjectPublicKeyInfo of pub. The two parties of a
// transfer compare it out of band to confirm the KEK public key was not replaced in transit.
func PublicKeyFingerprint(pub *rsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}
