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
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/bsostech/vault-blockchain/internal/byokcrypto"
	"github.com/bsostech/vault-blockchain/internal/path/byok"
)

// byokEnv is a framework backend serving account paths over in-memory storage. keks holds the private
// halves of the receiving KEKs a test created, standing in for the HSM that unwraps the export.
type byokEnv struct {
	t    *testing.T
	b    *framework.Backend
	s    logical.Storage
	keks map[string]*rsa.PrivateKey
}

func newBYOKEnv(t *testing.T) *byokEnv {
	t.Helper()
	return &byokEnv{
		t:    t,
		b:    &framework.Backend{Paths: Paths()},
		s:    &logical.InmemStorage{},
		keks: map[string]*rsa.PrivateKey{},
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

// createKEK generates a 2048-bit receiving KEK and returns its kid, public key PEM, and fingerprint.
func (e *byokEnv) createKEK(name string) map[string]interface{} {
	e.t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		e.t.Fatal(err)
	}
	fp, err := byokcrypto.PublicKeyFingerprint(&priv.PublicKey)
	if err != nil {
		e.t.Fatal(err)
	}
	e.keks[name] = priv
	return map[string]interface{}{
		"kid":               "hsm/keks/" + name,
		"public_key_pem":    pemOf(e.t, &priv.PublicKey),
		"public_key_sha256": fp,
	}
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
	der, err := byokcrypto.UnwrapKey(e.keks["k1"], blob)
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
		resp := send("alice", map[string]interface{}{"kid": strings.Repeat("k", byok.MaxKIDLength+1), "kek_public_key_pem": kek["public_key_pem"]})
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
