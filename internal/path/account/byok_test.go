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

package account

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/bsostech/vault-blockchain/internal/byokcrypto"
	"github.com/bsostech/vault-blockchain/internal/model"
	"github.com/bsostech/vault-blockchain/internal/path/byok"
	"github.com/bsostech/vault-blockchain/internal/path/storagekey"
)

// byokEnv is a framework backend serving account and byok paths over in-memory storage.
type byokEnv struct {
	t *testing.T
	b *framework.Backend
	s logical.Storage
}

func newBYOKEnv(t *testing.T) *byokEnv {
	t.Helper()
	return &byokEnv{
		t: t,
		b: &framework.Backend{Paths: append(Paths(), byok.Paths()...)},
		s: &logical.InmemStorage{},
	}
}

func (e *byokEnv) do(op logical.Operation, path string, data map[string]interface{}) *logical.Response {
	e.t.Helper()
	resp, err := e.b.HandleRequest(context.Background(), &logical.Request{
		Operation:  op,
		Path:       path,
		Data:       data,
		Storage:    e.s,
		MountPoint: "blockchain/",
	})
	if err != nil {
		e.t.Fatalf("%s %s: %v", op, path, err)
	}
	return resp
}

// createKEK creates a 2048-bit KEK and returns its create response data.
func (e *byokEnv) createKEK(name string) map[string]interface{} {
	e.t.Helper()
	resp := e.do(logical.CreateOperation, "byok/keks/"+name, map[string]interface{}{"key_size": 2048})
	if resp == nil || resp.IsError() {
		e.t.Fatalf("create kek: %#v", resp)
	}
	return resp.Data
}

// kekPublicKey parses the public key from a KEK response.
func (e *byokEnv) kekPublicKey(kek map[string]interface{}) *rsa.PublicKey {
	e.t.Helper()
	pub, err := byokcrypto.ParseKEKPublicKeyPEM(kek["public_key_pem"].(string))
	if err != nil {
		e.t.Fatal(err)
	}
	return pub
}

// blobFor wraps key for kek and returns the Base64 byok_blob value.
func (e *byokEnv) blobFor(kek map[string]interface{}, key *ecdsa.PrivateKey) string {
	e.t.Helper()
	der, err := byokcrypto.MarshalSecp256k1PKCS8(key)
	if err != nil {
		e.t.Fatal(err)
	}
	return e.blobForDER(kek, der)
}

// blobForDER wraps raw PKCS#8 bytes for kek.
func (e *byokEnv) blobForDER(kek map[string]interface{}, der []byte) string {
	e.t.Helper()
	blob, err := byokcrypto.WrapKey(e.kekPublicKey(kek), kek["kid"].(string), der, "test")
	if err != nil {
		e.t.Fatal(err)
	}
	enc, err := blob.Encode()
	if err != nil {
		e.t.Fatal(err)
	}
	return enc
}

// importBYOK sends an import-byok write.
func (e *byokEnv) importBYOK(name, blob string) *logical.Response {
	e.t.Helper()
	return e.do(logical.CreateOperation, "accounts/"+name+"/import-byok", map[string]interface{}{"byok_blob": blob})
}

// exportBYOK sends an export-byok write for the account, wrapping for kek.
func (e *byokEnv) exportBYOK(name string, kek map[string]interface{}) *logical.Response {
	e.t.Helper()
	return e.do(logical.UpdateOperation, "byok/export/account/"+name, map[string]interface{}{
		"kid":                kek["kid"],
		"kek_public_key_pem": kek["public_key_pem"],
	})
}

// importKey stores key under name using the plain private-key import path.
func (e *byokEnv) importKey(name string, key *ecdsa.PrivateKey) {
	e.t.Helper()
	resp := e.do(logical.CreateOperation, "accounts/"+name+"/import", map[string]interface{}{"private_key": keyHex(key)})
	if resp == nil || resp.IsError() {
		e.t.Fatalf("import: %#v", resp)
	}
}

// accountExists reports whether a single-key account record is stored.
func (e *byokEnv) accountExists(name string) bool {
	e.t.Helper()
	entry, err := e.s.Get(context.Background(), storagekey.SingleKeyAccountKey(name))
	if err != nil {
		e.t.Fatal(err)
	}
	return entry != nil
}

// keyHex returns the 32-byte scalar of key as lowercase hex.
func keyHex(key *ecdsa.PrivateKey) string {
	return hex.EncodeToString(crypto.FromECDSA(key))
}

// failure asserts resp is an error carrying the given HTTP status and code. Status 400 is a plain Vault
// error response whose message starts with "<code>:"; other statuses use a raw status-code response.
func failure(t *testing.T, resp *logical.Response, status int, code string) {
	t.Helper()
	if resp == nil {
		t.Fatalf("expected %s error, got nil response", code)
	}
	if status == http.StatusBadRequest {
		if !resp.IsError() || !strings.HasPrefix(resp.Error().Error(), code+":") {
			t.Fatalf("want 400 %q, got %#v", code, resp)
		}
		return
	}
	got, _ := resp.Data[logical.HTTPStatusCode].(int)
	body, _ := resp.Data[logical.HTTPRawBody].(string)
	if got != status || !strings.Contains(body, code) {
		t.Fatalf("want %d %q, got status=%d body=%s", status, code, got, body)
	}
}

// requireNoSecrets fails if resp exposes the private key or a private-key field.
func requireNoSecrets(t *testing.T, resp *logical.Response, key *ecdsa.PrivateKey) {
	t.Helper()
	raw, err := json.Marshal(resp.Data)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(raw)), keyHex(key)) {
		t.Fatal("response contains the private key")
	}
	for k := range resp.Data {
		if strings.Contains(k, "private") {
			t.Fatalf("response has private field %q", k)
		}
	}
}

// mutateBlob decodes a Base64 blob, applies f, and re-encodes it.
func mutateBlob(t *testing.T, b64 string, f func(b *byokcrypto.Blob)) string {
	t.Helper()
	blob, err := byokcrypto.ParseBlob(b64)
	if err != nil {
		t.Fatal(err)
	}
	f(blob)
	out, err := blob.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// pkcs8WithScalar builds a PKCS#8 secp256k1 key around an arbitrary scalar encoding, without a public key.
func pkcs8WithScalar(t *testing.T, scalar []byte) []byte {
	t.Helper()
	type ecPriv struct {
		Version    int
		PrivateKey []byte
	}
	type info struct {
		Version int
		Alg     pkix.AlgorithmIdentifier
		Key     []byte
	}
	inner, err := asn1.Marshal(ecPriv{Version: 1, PrivateKey: scalar})
	if err != nil {
		t.Fatal(err)
	}
	curve, err := asn1.Marshal(asn1.ObjectIdentifier{1, 3, 132, 0, 10})
	if err != nil {
		t.Fatal(err)
	}
	der, err := asn1.Marshal(info{
		Alg: pkix.AlgorithmIdentifier{
			Algorithm:  asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1},
			Parameters: asn1.RawValue{FullBytes: curve},
		},
		Key: inner,
	})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// TestImportBYOK verifies a wrapped key imports into an account with the right address and no secret leak.
func TestImportBYOK(t *testing.T) {
	t.Parallel()
	e := newBYOKEnv(t)
	kek := e.createKEK("k1")
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	resp := e.importBYOK("alice", e.blobFor(kek, key))
	if resp == nil || resp.IsError() {
		t.Fatalf("import failed: %#v", resp)
	}
	wantAddr := crypto.PubkeyToAddress(key.PublicKey).Hex()
	if resp.Data["address"] != wantAddr {
		t.Fatalf("address=%v want %v", resp.Data["address"], wantAddr)
	}
	requireNoSecrets(t, resp, key)

	// The stored record is the same shape accounts/:name/import writes.
	stored, err := ReadSingleKeyAccount(context.Background(), e.s, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if stored.AddressStr != wantAddr || stored.PrivateKeyStr != keyHex(key) {
		t.Fatalf("stored account mismatch: %+v", stored)
	}
	read := e.do(logical.ReadOperation, "accounts/alice/address", nil)
	if read == nil || read.Data["address"] != wantAddr || read.Data["public_key"] != resp.Data["public_key"] {
		t.Fatalf("read=%#v", read)
	}
}

// TestImportBYOKSigns verifies an imported account can sign with the existing sign path.
func TestImportBYOKSigns(t *testing.T) {
	t.Parallel()
	e := newBYOKEnv(t)
	kek := e.createKEK("k1")
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if resp := e.importBYOK("alice", e.blobFor(kek, key)); resp == nil || resp.IsError() {
		t.Fatalf("import failed: %#v", resp)
	}
	resp := e.do(logical.UpdateOperation, "accounts/alice/sign", map[string]interface{}{"data": "0x68656c6c6f"})
	if resp == nil || resp.IsError() {
		t.Fatalf("sign failed: %#v", resp)
	}
	if sig, _ := resp.Data["signature"].(string); sig == "" {
		t.Fatalf("no signature in %#v", resp.Data)
	}
}

// TestImportBYOKRejects verifies each failure returns the documented status and code and stores nothing.
func TestImportBYOKRejects(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p256DER, err := x509.MarshalPKCS8PrivateKey(p256)
	if err != nil {
		t.Fatal(err)
	}
	zeroScalarDER := pkcs8WithScalar(t, make([]byte, 32))

	type tc struct {
		name   string
		build  func(e *byokEnv, kek map[string]interface{}) string
		status int
		code   string
	}
	notFound := http.StatusNotFound
	bad := http.StatusBadRequest
	cases := []tc{
		{"not base64", func(*byokEnv, map[string]interface{}) string { return "%%%" }, bad, "invalid_blob"},
		{"not json", func(*byokEnv, map[string]interface{}) string {
			return base64.StdEncoding.EncodeToString([]byte("nope"))
		}, bad, "invalid_blob"},
		{"wrong enc", func(e *byokEnv, kek map[string]interface{}) string {
			return mutateBlob(t, e.blobFor(kek, key), func(b *byokcrypto.Blob) { b.Header.Enc = "A256GCM" })
		}, bad, "invalid_blob"},
		{"ciphertext too short", func(e *byokEnv, kek map[string]interface{}) string {
			return mutateBlob(t, e.blobFor(kek, key), func(b *byokcrypto.Blob) { b.Ciphertext = "AAAA" })
		}, bad, "invalid_blob"},
		{"unknown kek name", func(e *byokEnv, kek map[string]interface{}) string {
			return mutateBlob(t, e.blobFor(kek, key), func(b *byokcrypto.Blob) { b.Header.KID = "blockchain/byok/keks/nope/abcd" })
		}, notFound, "kek_not_found"},
		{"right name wrong id", func(e *byokEnv, kek map[string]interface{}) string {
			return mutateBlob(t, e.blobFor(kek, key), func(b *byokcrypto.Blob) { b.Header.KID = "blockchain/byok/keks/k1/deadbeefdeadbeef" })
		}, notFound, "kek_not_found"},
		{"malformed kid", func(e *byokEnv, kek map[string]interface{}) string {
			return mutateBlob(t, e.blobFor(kek, key), func(b *byokcrypto.Blob) { b.Header.KID = "https://example/keys/k/1" })
		}, notFound, "kek_not_found"},
		{"tampered ciphertext", func(e *byokEnv, kek map[string]interface{}) string {
			return mutateBlob(t, e.blobFor(kek, key), func(b *byokcrypto.Blob) {
				raw, _ := base64.RawURLEncoding.DecodeString(b.Ciphertext)
				raw[len(raw)-1] ^= 1
				b.Ciphertext = base64.RawURLEncoding.EncodeToString(raw)
			})
		}, bad, "unwrap_failed"},
		{"wrapped for another kek", func(e *byokEnv, kek map[string]interface{}) string {
			other := e.createKEK("other")
			return mutateBlob(t, e.blobFor(other, key), func(b *byokcrypto.Blob) { b.Header.KID = kek["kid"].(string) })
		}, bad, "unwrap_failed"},
		{"p-256 key", func(e *byokEnv, kek map[string]interface{}) string { return e.blobForDER(kek, p256DER) }, bad, "unsupported_curve"},
		{"zero scalar", func(e *byokEnv, kek map[string]interface{}) string { return e.blobForDER(kek, zeroScalarDER) }, bad, "invalid_key"},
		{"garbage plaintext", func(e *byokEnv, kek map[string]interface{}) string {
			return e.blobForDER(kek, []byte("not a key"))
		}, bad, "invalid_key"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			e := newBYOKEnv(t)
			kek := e.createKEK("k1")
			failure(t, e.importBYOK("alice", c.build(e, kek)), c.status, c.code)
			if e.accountExists("alice") {
				t.Fatal("a failed import must not store an account")
			}
		})
	}
}

// TestImportBYOKMissingParams verifies required parameters.
func TestImportBYOKMissingParams(t *testing.T) {
	t.Parallel()
	e := newBYOKEnv(t)
	resp := e.do(logical.CreateOperation, "accounts/alice/import-byok", map[string]interface{}{})
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected error, got %#v", resp)
	}
}

// TestImportBYOKKEKDeletedAndRecreated verifies a blob for a deleted KEK is not accepted by a KEK
// recreated under the same name.
func TestImportBYOKKEKDeletedAndRecreated(t *testing.T) {
	t.Parallel()
	e := newBYOKEnv(t)
	old := e.createKEK("k1")
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	blob := e.blobFor(old, key)

	e.do(logical.DeleteOperation, "byok/keks/k1", nil)
	failure(t, e.importBYOK("alice", blob), http.StatusNotFound, "kek_not_found")

	e.createKEK("k1")
	failure(t, e.importBYOK("alice", blob), http.StatusNotFound, "kek_not_found")
	if e.accountExists("alice") {
		t.Fatal("no account may be stored")
	}
}

// TestImportBYOKExpiredKEK verifies a KEK past its ttl returns 410.
func TestImportBYOKExpiredKEK(t *testing.T) {
	t.Parallel()
	e := newBYOKEnv(t)

	// Store a KEK created two hours ago with a one hour ttl.
	k, err := model.NewKEK("old", 2048, time.Hour, time.Now().Add(-2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	entry, err := logical.StorageEntryJSON(storagekey.KEKKey("old"), k)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.s.Put(context.Background(), entry); err != nil {
		t.Fatal(err)
	}
	read := e.do(logical.ReadOperation, "byok/keks/old", nil)
	if read == nil || read.IsError() {
		t.Fatalf("read: %#v", read)
	}

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	failure(t, e.importBYOK("alice", e.blobFor(read.Data, key)), http.StatusGone, "kek_expired")
	if e.accountExists("alice") {
		t.Fatal("no account may be stored")
	}
}

// TestImportBYOKUnexpiredTTL verifies a KEK within its ttl still works.
func TestImportBYOKUnexpiredTTL(t *testing.T) {
	t.Parallel()
	e := newBYOKEnv(t)
	resp := e.do(logical.CreateOperation, "byok/keks/k1", map[string]interface{}{"key_size": 2048, "ttl": "1h"})
	if resp == nil || resp.IsError() {
		t.Fatalf("create: %#v", resp)
	}
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if got := e.importBYOK("alice", e.blobFor(resp.Data, key)); got == nil || got.IsError() {
		t.Fatalf("import: %#v", got)
	}
}

// TestImportBYOKAccountExists verifies an existing account is never overwritten.
func TestImportBYOKAccountExists(t *testing.T) {
	t.Parallel()
	e := newBYOKEnv(t)
	kek := e.createKEK("k1")
	original, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	e.importKey("alice", original)

	other, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	blob := e.blobFor(kek, other)
	// Vault routes a write to an existing name as an update; a direct create must conflict too.
	for _, op := range []logical.Operation{logical.UpdateOperation, logical.CreateOperation} {
		resp := e.do(op, "accounts/alice/import-byok", map[string]interface{}{"byok_blob": blob})
		failure(t, resp, http.StatusConflict, "exist")
	}
	stored, err := ReadSingleKeyAccount(context.Background(), e.s, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if stored.PrivateKeyStr != keyHex(original) {
		t.Fatal("existing account was overwritten")
	}
}

// TestExportBYOK verifies an export unwraps with the receiving KEK to the original key and changes nothing.
func TestExportBYOK(t *testing.T) {
	t.Parallel()
	e := newBYOKEnv(t)
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	e.importKey("alice", key)
	kek := e.createKEK("k1")

	resp := e.exportBYOK("alice", kek)
	if resp == nil || resp.IsError() {
		t.Fatalf("export failed: %#v", resp)
	}
	if resp.Data["address"] != crypto.PubkeyToAddress(key.PublicKey).Hex() {
		t.Fatalf("address=%v", resp.Data["address"])
	}
	if resp.Data["kek_public_key_sha256"] != kek["public_key_sha256"] {
		t.Fatalf("fingerprint=%v want %v", resp.Data["kek_public_key_sha256"], kek["public_key_sha256"])
	}
	if strings.Contains(resp.Data["byok_blob"].(string), keyHex(key)) {
		t.Fatal("blob contains the private key in the clear")
	}

	blob, err := byokcrypto.ParseBlob(resp.Data["byok_blob"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if blob.Header.KID != kek["kid"] || blob.Generator == "" {
		t.Fatalf("blob header=%+v generator=%q", blob.Header, blob.Generator)
	}
	k, err := byok.LoadKEK(context.Background(), e.s, "k1")
	if err != nil || k == nil {
		t.Fatalf("LoadKEK: %v %v", k, err)
	}
	rsaKey, err := k.PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	der, err := byokcrypto.UnwrapKey(rsaKey, blob)
	if err != nil {
		t.Fatal(err)
	}
	got, err := byokcrypto.ParseSecp256k1PKCS8(der)
	if err != nil {
		t.Fatal(err)
	}
	if got.D.Cmp(key.D) != 0 {
		t.Fatal("exported key differs from the account key")
	}

	stored, err := ReadSingleKeyAccount(context.Background(), e.s, "alice")
	if err != nil || stored.PrivateKeyStr != keyHex(key) {
		t.Fatalf("export changed the account: %v", err)
	}
}

// TestExportImportRoundTrip verifies export-byok output imports with import-byok to an account with the same key.
func TestExportImportRoundTrip(t *testing.T) {
	t.Parallel()
	e := newBYOKEnv(t)
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	e.importKey("alice", key)
	kek := e.createKEK("k1")

	exp := e.exportBYOK("alice", kek)
	if exp == nil || exp.IsError() {
		t.Fatalf("export: %#v", exp)
	}
	imp := e.importBYOK("bob", exp.Data["byok_blob"].(string))
	if imp == nil || imp.IsError() {
		t.Fatalf("import: %#v", imp)
	}
	if imp.Data["address"] != exp.Data["address"] {
		t.Fatalf("addresses differ: %v vs %v", imp.Data["address"], exp.Data["address"])
	}
	requireNoSecrets(t, imp, key)
	alice, _ := ReadSingleKeyAccount(context.Background(), e.s, "alice")
	bob, _ := ReadSingleKeyAccount(context.Background(), e.s, "bob")
	if alice == nil || bob == nil || alice.PrivateKeyStr != bob.PrivateKeyStr {
		t.Fatal("round trip changed the key")
	}
}

// TestExportBYOKRejects verifies parameter and lookup failures.
func TestExportBYOKRejects(t *testing.T) {
	t.Parallel()
	e := newBYOKEnv(t)
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	e.importKey("alice", key)
	kek := e.createKEK("k1")

	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	smallPEM := pemOf(t, &small.PublicKey)
	ecPEM := pemOf(t, &mustP256(t).PublicKey)

	send := func(name string, data map[string]interface{}) *logical.Response {
		return e.do(logical.UpdateOperation, "byok/export/account/"+name, data)
	}

	t.Run("missing kid", func(t *testing.T) {
		resp := send("alice", map[string]interface{}{"kek_public_key_pem": kek["public_key_pem"]})
		if resp == nil || !resp.IsError() {
			t.Fatalf("got %#v", resp)
		}
	})
	t.Run("missing public key", func(t *testing.T) {
		resp := send("alice", map[string]interface{}{"kid": kek["kid"]})
		if resp == nil || !resp.IsError() {
			t.Fatalf("got %#v", resp)
		}
	})
	t.Run("kid too long", func(t *testing.T) {
		resp := send("alice", map[string]interface{}{"kid": strings.Repeat("k", maxKIDLength+1), "kek_public_key_pem": kek["public_key_pem"]})
		if resp == nil || !resp.IsError() {
			t.Fatalf("got %#v", resp)
		}
	})
	for name, pemStr := range map[string]string{"garbage pem": "hello", "1024-bit key": smallPEM, "ec key": ecPEM} {
		t.Run(name, func(t *testing.T) {
			failure(t, send("alice", map[string]interface{}{"kid": kek["kid"], "kek_public_key_pem": pemStr}), http.StatusBadRequest, "invalid_kek_public_key")
		})
	}
	t.Run("account not found", func(t *testing.T) {
		failure(t, e.exportBYOK("nobody", kek), http.StatusNotFound, "account_not_found")
	})
}

// TestExportBYOKTwiceDiffers verifies repeated exports are independent (fresh AES key and OAEP seed).
func TestExportBYOKTwiceDiffers(t *testing.T) {
	t.Parallel()
	e := newBYOKEnv(t)
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	e.importKey("alice", key)
	kek := e.createKEK("k1")
	a, b := e.exportBYOK("alice", kek), e.exportBYOK("alice", kek)
	if a.Data["byok_blob"] == b.Data["byok_blob"] {
		t.Fatal("two exports are byte-identical")
	}
}

func pemOf(t *testing.T, pub interface{}) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func mustP256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestExportPathOutsideAccounts guards the policy design: export must not live under accounts/, where the
// user policy's accounts/<entity>/* wildcard would grant it to every user.
func TestExportPathOutsideAccounts(t *testing.T) {
	t.Parallel()
	for _, p := range Paths() {
		if strings.Contains(p.Pattern, "export-byok") || strings.HasPrefix(p.Pattern, "accounts/") && strings.Contains(p.Pattern, "export") {
			t.Fatalf("export path %q is under accounts/", p.Pattern)
		}
	}
	if got := pathSingleKeyExportBYOK().Pattern; !strings.HasPrefix(got, "byok/export/account/") {
		t.Fatalf("export pattern=%q, want prefix byok/export/account/", got)
	}
}
