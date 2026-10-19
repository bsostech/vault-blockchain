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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // matches the wrapped format under test.
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

// mustRSA generates an RSA key or fails the test.
func mustRSA(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// wrapTestKey returns a fresh secp256k1 key, its PKCS#8 encoding, and the blob wrapping it for kek.
func wrapTestKey(t *testing.T, kek *rsa.PrivateKey) (priv []byte, der []byte, blob *Blob) {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	der, err = MarshalSecp256k1PKCS8(key)
	if err != nil {
		t.Fatal(err)
	}
	blob, err = WrapKey(&kek.PublicKey, "blockchain/byok/keks/k/abcd", der, "test")
	if err != nil {
		t.Fatal(err)
	}
	return crypto.FromECDSA(key), der, blob
}

// TestWrapUnwrapRoundTrip verifies wrapping then unwrapping returns the exact PKCS#8 for every KEK size.
func TestWrapUnwrapRoundTrip(t *testing.T) {
	t.Parallel()
	for _, bits := range []int{2048, 3072} {
		kek := mustRSA(t, bits)
		_, der, blob := wrapTestKey(t, kek)
		got, err := UnwrapKey(kek, blob)
		if err != nil {
			t.Fatalf("bits=%d: %v", bits, err)
		}
		if !bytes.Equal(got, der) {
			t.Fatalf("bits=%d: unwrapped bytes differ", bits)
		}
	}
}

// TestWrapBlobLayout verifies the documented layout: modulus-sized RSA-OAEP(SHA-1) part, then AES-KWP part.
func TestWrapBlobLayout(t *testing.T) {
	t.Parallel()
	kek := mustRSA(t, 2048)
	_, der, blob := wrapTestKey(t, kek)

	ct, err := base64.RawURLEncoding.DecodeString(blob.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	k := kek.Size()
	if want := k + (len(der)+7)/8*8 + 8; len(ct) != want {
		t.Fatalf("len=%d want %d", len(ct), want)
	}

	// Decrypt the RSA part independently with SHA-1 OAEP and an empty label: an AES-256 key.
	aesKey, err := rsa.DecryptOAEP(sha1.New(), nil, kek, ct[:k], nil) //nolint:gosec // format under test.
	if err != nil || len(aesKey) != 32 {
		t.Fatalf("rsa part: len=%d err=%v", len(aesKey), err)
	}
	// And the AES part independently with AES-KWP.
	plain, err := KWPUnwrap(aesKey, ct[k:])
	if err != nil || !bytes.Equal(plain, der) {
		t.Fatalf("aes part: %v", err)
	}
	// The same key with SHA-256 OAEP must not decrypt: parameters are fixed to SHA-1.
	if _, err := rsa.DecryptOAEP(sha256.New(), nil, kek, ct[:k], nil); err == nil {
		t.Fatal("rsa part decrypts with SHA-256; parameters are not SHA-1")
	}
}

// TestWrapEachKeyFresh verifies two wraps of the same key differ (random AES key and OAEP seed).
func TestWrapEachKeyFresh(t *testing.T) {
	t.Parallel()
	kek := mustRSA(t, 2048)
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	der, err := MarshalSecp256k1PKCS8(key)
	if err != nil {
		t.Fatal(err)
	}
	a, err := WrapKey(&kek.PublicKey, "kid", der, "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := WrapKey(&kek.PublicKey, "kid", der, "")
	if err != nil {
		t.Fatal(err)
	}
	if a.Ciphertext == b.Ciphertext {
		t.Fatal("two wraps produced identical ciphertext")
	}
}

// TestUnwrapFailures verifies a wrong KEK, tampering, wrong OAEP hash, and bad lengths all fail as expected.
func TestUnwrapFailures(t *testing.T) {
	t.Parallel()
	kek := mustRSA(t, 2048)
	_, der, blob := wrapTestKey(t, kek)
	ct, err := base64.RawURLEncoding.DecodeString(blob.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	k := kek.Size()

	withCT := func(b []byte) *Blob {
		c := *blob
		c.Ciphertext = base64.RawURLEncoding.EncodeToString(b)
		return &c
	}
	flip := func(i int) []byte {
		b := append([]byte(nil), ct...)
		b[i] ^= 1
		return b
	}

	// A blob whose RSA part used SHA-256 (what a mismatched tool would produce).
	aesKey := bytes.Repeat([]byte{9}, 32)
	sha256RSA, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &kek.PublicKey, aesKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := KWPWrap(aesKey, der)
	if err != nil {
		t.Fatal(err)
	}
	// A 20-byte "AES key" cannot be used with AES.
	badLenKey, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &kek.PublicKey, make([]byte, 20), nil) //nolint:gosec // format under test.
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		kek  *rsa.PrivateKey
		blob *Blob
		want error
	}{
		{"wrong kek of same size", mustRSA(t, 2048), blob, ErrUnwrapFailed},
		{"tampered rsa part", kek, withCT(flip(3)), ErrUnwrapFailed},
		{"tampered aes part", kek, withCT(flip(k + 4)), ErrUnwrapFailed},
		{"oaep with sha-256", kek, withCT(append(sha256RSA, wrapped...)), ErrUnwrapFailed},
		{"aes key length 20", kek, withCT(append(badLenKey, wrapped...)), ErrUnwrapFailed},
		{"too short", kek, withCT(ct[:k+8]), ErrInvalidBlob},
		{"not multiple of 8", kek, withCT(ct[:len(ct)-3]), ErrInvalidBlob},
		{"not base64url", kek, &Blob{Ciphertext: "!!!"}, ErrInvalidBlob},
		{"kek of other size", mustRSA(t, 3072), blob, ErrUnwrapFailed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			_, err := UnwrapKey(c.kek, c.blob)
			if !errors.Is(err, c.want) {
				t.Fatalf("err=%v want %v", err, c.want)
			}
		})
	}
}

// TestParseKEKPublicKeyPEM verifies accepted and rejected PEM inputs.
func TestParseKEKPublicKeyPEM(t *testing.T) {
	t.Parallel()
	k2048, k3072 := mustRSA(t, 2048), mustRSA(t, 3072)
	k1024 := mustRSA(t, 1024)

	spki := func(k *rsa.PrivateKey) string {
		der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	}
	pkcs1 := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&k2048.PublicKey)}))
	ecDER, err := x509.MarshalPKIXPublicKey(&mustECDSA(t).PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	ecPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: ecDER}))

	for name, in := range map[string]string{"spki 2048": spki(k2048), "spki 3072": spki(k3072), "pkcs1 2048": pkcs1} {
		if _, err := ParseKEKPublicKeyPEM(in); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	for name, in := range map[string]string{
		"1024-bit":     spki(k1024),
		"ec key":       ecPEM,
		"not pem":      "hello",
		"empty":        "",
		"wrong type":   strings.Replace(spki(k2048), "PUBLIC KEY", "CERTIFICATE", 2),
		"trailing pem": spki(k2048) + spki(k3072),
	} {
		if _, err := ParseKEKPublicKeyPEM(in); !errors.Is(err, ErrInvalidKEKPublicKey) {
			t.Fatalf("%s: err=%v", name, err)
		}
	}
}

// TestWrapKeyRejectsBadInput verifies WrapKey validates the KEK size and kid.
func TestWrapKeyRejectsBadInput(t *testing.T) {
	t.Parallel()
	if _, err := WrapKey(nil, "kid", []byte("x"), ""); !errors.Is(err, ErrInvalidKEKPublicKey) {
		t.Fatalf("nil kek: %v", err)
	}
	small := mustRSA(t, 1024)
	if _, err := WrapKey(&small.PublicKey, "kid", []byte("x"), ""); !errors.Is(err, ErrInvalidKEKPublicKey) {
		t.Fatalf("1024-bit kek: %v", err)
	}
	ok := mustRSA(t, 2048)
	if _, err := WrapKey(&ok.PublicKey, "", []byte("x"), ""); !errors.Is(err, ErrInvalidBlob) {
		t.Fatalf("empty kid: %v", err)
	}
}

// TestBlobEncodeParse verifies Encode then ParseBlob round trips and keeps the fixed header fields.
func TestBlobEncodeParse(t *testing.T) {
	t.Parallel()
	kek := mustRSA(t, 2048)
	_, _, blob := wrapTestKey(t, kek)
	enc, err := blob.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseBlob(enc)
	if err != nil {
		t.Fatal(err)
	}
	if got.SchemaVersion != "1.0.0" || got.Header.Alg != "dir" || got.Header.Enc != "CKM_RSA_AES_KEY_WRAP" ||
		got.Header.KID != blob.Header.KID || got.Ciphertext != blob.Ciphertext || got.Generator != "test" {
		t.Fatalf("blob=%+v", got)
	}

	// Azure's example JSON shape, with an extra unknown field and no trailing padding on the Base64.
	raw := `{"schema_version":"1.0.0","header":{"kid":"https://v.vault.azure.net/keys/k/1","alg":"dir","enc":"CKM_RSA_AES_KEY_WRAP"},"ciphertext":"AAAA","generator":"x","extra":1}`
	if _, err := ParseBlob(strings.TrimRight(base64.StdEncoding.EncodeToString([]byte(raw)), "=")); err != nil {
		t.Fatalf("azure-style blob: %v", err)
	}
}

// TestParseBlobRejects verifies each fixed field is enforced.
func TestParseBlobRejects(t *testing.T) {
	t.Parallel()
	good := Blob{SchemaVersion: "1.0.0", Header: Header{KID: "k", Alg: "dir", Enc: "CKM_RSA_AES_KEY_WRAP"}, Ciphertext: "AAAA"}
	mod := func(f func(b *Blob)) string {
		b := good
		f(&b)
		raw, err := json.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(raw)
	}
	cases := map[string]string{
		"schema version": mod(func(b *Blob) { b.SchemaVersion = "2.0.0" }),
		"alg":            mod(func(b *Blob) { b.Header.Alg = "RSA-OAEP" }),
		"enc":            mod(func(b *Blob) { b.Header.Enc = "A256GCM" }),
		"empty kid":      mod(func(b *Blob) { b.Header.KID = "" }),
		"empty ct":       mod(func(b *Blob) { b.Ciphertext = "" }),
		"not json":       base64.StdEncoding.EncodeToString([]byte("nope")),
		"not base64":     "%%%",
		"empty":          "",
		"too large":      strings.Repeat("A", MaxBlobSize+1),
	}
	for name, in := range cases {
		if _, err := ParseBlob(in); !errors.Is(err, ErrInvalidBlob) {
			t.Fatalf("%s: err=%v", name, err)
		}
	}
}

// mustECDSA returns a P-256 key for negative tests.
func mustECDSA(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}
