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

package byok

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// newTestBackend returns a framework backend serving only the byok paths, plus in-memory storage.
func newTestBackend(t *testing.T) (*framework.Backend, logical.Storage) {
	t.Helper()
	return &framework.Backend{Paths: Paths()}, &logical.InmemStorage{}
}

// do sends one request through the framework router.
func do(
	t *testing.T,
	b *framework.Backend,
	s logical.Storage,
	op logical.Operation,
	path string,
	data map[string]interface{},
) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation:  op,
		Path:       path,
		Data:       data,
		Storage:    s,
		MountPoint: "blockchain/",
	})
	if err != nil {
		t.Fatalf("%s %s: %v", op, path, err)
	}
	return resp
}

// statusOf returns the HTTP status carried by an error response, or 0.
func statusOf(resp *logical.Response) int {
	if resp == nil {
		return 0
	}
	code, _ := resp.Data[logical.HTTPStatusCode].(int)
	return code
}

// parsePublicKey decodes the PEM in a response and returns the RSA public key.
func parsePublicKey(t *testing.T, pemStr string) *rsa.PublicKey {
	t.Helper()
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil || block.Type != "PUBLIC KEY" {
		t.Fatalf("bad pem block: %v", block)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("public key is %T", pub)
	}
	return rsaPub
}

// TestKEKCreate verifies a created KEK returns its public key, kid, and fingerprint but no private key.
func TestKEKCreate(t *testing.T) {
	t.Parallel()
	b, s := newTestBackend(t)

	resp := do(t, b, s, logical.CreateOperation, "byok/keks/kek1", map[string]interface{}{"key_size": 2048})
	if resp == nil || resp.IsError() {
		t.Fatalf("create failed: %#v", resp)
	}

	if got := resp.Data["kek_name"]; got != "kek1" {
		t.Fatalf("kek_name=%v", got)
	}
	if got := resp.Data["key_size"]; got != 2048 {
		t.Fatalf("key_size=%v", got)
	}
	kid, _ := resp.Data["kid"].(string)
	if !strings.HasPrefix(kid, "blockchain/byok/keks/kek1/") || len(kid) <= len("blockchain/byok/keks/kek1/") {
		t.Fatalf("kid=%q", kid)
	}
	if got := resp.Data["expires_at"]; got != "" {
		t.Fatalf("expires_at=%v want empty", got)
	}
	if _, err := time.Parse(time.RFC3339, resp.Data["created_at"].(string)); err != nil {
		t.Fatalf("created_at: %v", err)
	}

	pub := parsePublicKey(t, resp.Data["public_key_pem"].(string))
	if pub.N.BitLen() != 2048 {
		t.Fatalf("modulus bits=%d want 2048", pub.N.BitLen())
	}

	// fingerprint is the SHA-256 of the DER SubjectPublicKeyInfo.
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	if got := resp.Data["public_key_sha256"]; got != hex.EncodeToString(sum[:]) {
		t.Fatalf("public_key_sha256=%v", got)
	}

	for k := range resp.Data {
		if strings.Contains(k, "private") {
			t.Fatalf("response must not contain private key field %q", k)
		}
	}
}

// TestKEKCreateDefaultKeySize verifies the default modulus size is 3072 bits.
func TestKEKCreateDefaultKeySize(t *testing.T) {
	t.Parallel()
	b, s := newTestBackend(t)

	resp := do(t, b, s, logical.CreateOperation, "byok/keks/kek1", nil)
	if resp == nil || resp.IsError() {
		t.Fatalf("create failed: %#v", resp)
	}
	if got := resp.Data["key_size"]; got != 3072 {
		t.Fatalf("key_size=%v want 3072", got)
	}
	if pub := parsePublicKey(t, resp.Data["public_key_pem"].(string)); pub.N.BitLen() != 3072 {
		t.Fatalf("modulus bits=%d want 3072", pub.N.BitLen())
	}
}

// TestKEKCreateKeySize4096 verifies the largest supported size works.
func TestKEKCreateKeySize4096(t *testing.T) {
	if testing.Short() {
		t.Skip("4096-bit key generation is slow")
	}
	t.Parallel()
	b, s := newTestBackend(t)

	resp := do(t, b, s, logical.CreateOperation, "byok/keks/kek1", map[string]interface{}{"key_size": 4096})
	if resp == nil || resp.IsError() {
		t.Fatalf("create failed: %#v", resp)
	}
	if pub := parsePublicKey(t, resp.Data["public_key_pem"].(string)); pub.N.BitLen() != 4096 {
		t.Fatalf("modulus bits=%d want 4096", pub.N.BitLen())
	}
}

// TestKEKCreateInvalidParams verifies unsupported sizes and negative ttl are rejected and store nothing.
func TestKEKCreateInvalidParams(t *testing.T) {
	t.Parallel()
	cases := map[string]map[string]interface{}{
		"key_size 1024": {"key_size": 1024},
		"key_size 2049": {"key_size": 2049},
		"key_size 8192": {"key_size": 8192},
		"key_size 0":    {"key_size": 0},
		"negative ttl":  {"key_size": 2048, "ttl": -1},
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			b, s := newTestBackend(t)
			resp := do(t, b, s, logical.CreateOperation, "byok/keks/kek1", data)
			if resp == nil || !resp.IsError() {
				t.Fatalf("expected error response, got %#v", resp)
			}
			if got := do(t, b, s, logical.ReadOperation, "byok/keks/kek1", nil); got != nil {
				t.Fatalf("nothing should be stored, read returned %#v", got)
			}
		})
	}
}

// TestKEKCreateDuplicate verifies writing to an existing name returns 409 and keeps the original key.
func TestKEKCreateDuplicate(t *testing.T) {
	t.Parallel()
	b, s := newTestBackend(t)

	first := do(t, b, s, logical.CreateOperation, "byok/keks/kek1", map[string]interface{}{"key_size": 2048})
	if first == nil || first.IsError() {
		t.Fatalf("create failed: %#v", first)
	}

	// Vault routes a write to an existing name as an update; a direct create call must also conflict.
	for _, op := range []logical.Operation{logical.UpdateOperation, logical.CreateOperation} {
		resp := do(t, b, s, op, "byok/keks/kek1", map[string]interface{}{"key_size": 2048})
		if got := statusOf(resp); got != http.StatusConflict {
			t.Fatalf("%s: status=%d want %d (resp=%#v)", op, got, http.StatusConflict, resp)
		}
		if body, _ := resp.Data[logical.HTTPRawBody].(string); !strings.Contains(body, "kek_exists") {
			t.Fatalf("%s: body=%q", op, body)
		}
	}

	got := do(t, b, s, logical.ReadOperation, "byok/keks/kek1", nil)
	if got == nil || got.Data["kid"] != first.Data["kid"] || got.Data["public_key_pem"] != first.Data["public_key_pem"] {
		t.Fatal("original KEK must be unchanged")
	}
}

// TestKEKExistenceCheck verifies the existence check drives Vault's create-versus-update routing.
func TestKEKExistenceCheck(t *testing.T) {
	t.Parallel()
	b, s := newTestBackend(t)

	check := func() bool {
		t.Helper()
		found, exists, err := b.HandleExistenceCheck(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "byok/keks/kek1",
			Storage:   s,
		})
		if err != nil {
			t.Fatal(err)
		}
		if !found {
			t.Fatal("existence check not registered")
		}
		return exists
	}

	if check() {
		t.Fatal("kek should not exist yet")
	}
	do(t, b, s, logical.CreateOperation, "byok/keks/kek1", map[string]interface{}{"key_size": 2048})
	if !check() {
		t.Fatal("kek should exist")
	}
}

// TestKEKRead verifies read returns the same public view as create, and nothing for a missing KEK.
func TestKEKRead(t *testing.T) {
	t.Parallel()
	b, s := newTestBackend(t)

	created := do(t, b, s, logical.CreateOperation, "byok/keks/kek1", map[string]interface{}{"key_size": 2048})
	read := do(t, b, s, logical.ReadOperation, "byok/keks/kek1", nil)
	if read == nil || read.IsError() {
		t.Fatalf("read failed: %#v", read)
	}
	for _, k := range []string{"kid", "kek_name", "key_size", "public_key_pem", "public_key_sha256", "created_at", "expires_at"} {
		if read.Data[k] != created.Data[k] {
			t.Fatalf("%s: read=%v create=%v", k, read.Data[k], created.Data[k])
		}
	}
	for k := range read.Data {
		if strings.Contains(k, "private") {
			t.Fatalf("response must not contain private key field %q", k)
		}
	}

	if got := do(t, b, s, logical.ReadOperation, "byok/keks/nope", nil); got != nil {
		t.Fatalf("missing KEK should return nil (HTTP 404), got %#v", got)
	}
}

// TestKEKUniqueKID verifies two KEKs, and a KEK recreated under the same name, never share a kid or key.
func TestKEKUniqueKID(t *testing.T) {
	t.Parallel()
	b, s := newTestBackend(t)

	a := do(t, b, s, logical.CreateOperation, "byok/keks/kek1", map[string]interface{}{"key_size": 2048})
	other := do(t, b, s, logical.CreateOperation, "byok/keks/kek2", map[string]interface{}{"key_size": 2048})
	if a.Data["kid"] == other.Data["kid"] {
		t.Fatal("different KEKs share a kid")
	}

	do(t, b, s, logical.DeleteOperation, "byok/keks/kek1", nil)
	again := do(t, b, s, logical.CreateOperation, "byok/keks/kek1", map[string]interface{}{"key_size": 2048})
	if again.Data["kid"] == a.Data["kid"] {
		t.Fatal("recreated KEK reuses the old kid, so an old .byok could be accepted by a new key")
	}
	if again.Data["public_key_pem"] == a.Data["public_key_pem"] {
		t.Fatal("recreated KEK reuses the old key pair")
	}
}

// TestKEKTTL verifies ttl sets expires_at relative to created_at.
func TestKEKTTL(t *testing.T) {
	t.Parallel()
	b, s := newTestBackend(t)

	resp := do(t, b, s, logical.CreateOperation, "byok/keks/kek1", map[string]interface{}{
		"key_size": 2048,
		"ttl":      "1h",
	})
	if resp == nil || resp.IsError() {
		t.Fatalf("create failed: %#v", resp)
	}
	created, err := time.Parse(time.RFC3339, resp.Data["created_at"].(string))
	if err != nil {
		t.Fatal(err)
	}
	expires, err := time.Parse(time.RFC3339, resp.Data["expires_at"].(string))
	if err != nil {
		t.Fatalf("expires_at: %v", err)
	}
	if got := expires.Sub(created); got != time.Hour {
		t.Fatalf("expires-created=%v want 1h", got)
	}
}

// TestKEKDelete verifies delete removes the KEK and is idempotent.
func TestKEKDelete(t *testing.T) {
	t.Parallel()
	b, s := newTestBackend(t)

	do(t, b, s, logical.CreateOperation, "byok/keks/kek1", map[string]interface{}{"key_size": 2048})
	if resp := do(t, b, s, logical.DeleteOperation, "byok/keks/kek1", nil); resp != nil && resp.IsError() {
		t.Fatalf("delete failed: %#v", resp)
	}
	if got := do(t, b, s, logical.ReadOperation, "byok/keks/kek1", nil); got != nil {
		t.Fatalf("KEK still readable after delete: %#v", got)
	}
	if entry, err := s.Get(context.Background(), "byok/keks/kek1"); err != nil || entry != nil {
		t.Fatalf("storage entry still present: %v, %v", entry, err)
	}
	if resp := do(t, b, s, logical.DeleteOperation, "byok/keks/kek1", nil); resp != nil && resp.IsError() {
		t.Fatalf("deleting a missing KEK should succeed: %#v", resp)
	}
}

// TestKEKList verifies list returns sorted names and an empty result when none exist.
func TestKEKList(t *testing.T) {
	t.Parallel()
	b, s := newTestBackend(t)

	empty := do(t, b, s, logical.ListOperation, "byok/keks/", nil)
	if empty != nil {
		if keys, _ := empty.Data["keys"].([]string); len(keys) != 0 {
			t.Fatalf("expected no keys, got %v", keys)
		}
	}

	for _, name := range []string{"zeta", "alpha", "mid"} {
		do(t, b, s, logical.CreateOperation, "byok/keks/"+name, map[string]interface{}{"key_size": 2048})
	}
	resp := do(t, b, s, logical.ListOperation, "byok/keks/", nil)
	keys, _ := resp.Data["keys"].([]string)
	want := []string{"alpha", "mid", "zeta"}
	if len(keys) != len(want) {
		t.Fatalf("keys=%v want %v", keys, want)
	}
	for i := range want {
		if keys[i] != want[i] {
			t.Fatalf("keys=%v want %v", keys, want)
		}
	}
}

// TestKEKStoredPrivateKeyMatchesPublic verifies the stored private key pairs with the returned public key.
func TestKEKStoredPrivateKeyMatchesPublic(t *testing.T) {
	t.Parallel()
	b, s := newTestBackend(t)

	resp := do(t, b, s, logical.CreateOperation, "byok/keks/kek1", map[string]interface{}{"key_size": 2048})
	pub := parsePublicKey(t, resp.Data["public_key_pem"].(string))

	k, err := LoadKEK(context.Background(), s, "kek1")
	if err != nil || k == nil {
		t.Fatalf("loadKEK: %v, %v", k, err)
	}
	priv, err := k.PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if !priv.PublicKey.Equal(pub) {
		t.Fatal("stored private key does not match returned public key")
	}
}

// TestParseKID verifies kid parsing accepts the issued format and rejects malformed values.
func TestParseKID(t *testing.T) {
	t.Parallel()
	good := map[string][2]string{
		"blockchain/byok/keks/kek1/abcd": {"kek1", "abcd"},
		"byok/keks/kek1/abcd":            {"kek1", "abcd"},
		"a/b/byok/keks/k-1/0123":         {"k-1", "0123"},
	}
	for kid, want := range good {
		name, id, ok := ParseKID(kid)
		if !ok || name != want[0] || id != want[1] {
			t.Fatalf("%q: got %q %q %v", kid, name, id, ok)
		}
	}
	for _, kid := range []string{"", "kek1/abcd", "byok/keks/", "byok/keks/kek1", "byok/keks/kek1/", "byok/keks//abcd", "byok/keks/a/b/c"} {
		if _, _, ok := ParseKID(kid); ok {
			t.Fatalf("%q accepted", kid)
		}
	}
}
