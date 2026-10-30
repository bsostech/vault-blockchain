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

package wallet

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/tyler-smith/go-bip39"

	"github.com/bsostech/vault-blockchain/internal/byokcrypto"
	"github.com/bsostech/vault-blockchain/internal/path/account"
	"github.com/bsostech/vault-blockchain/internal/path/byok"
)

// walletBYOKEnv is a framework backend serving wallet paths over in-memory storage. keks holds the private
// halves of the receiving KEKs a test created, standing in for the HSM that unwraps the export.
type walletBYOKEnv struct {
	t    *testing.T
	b    *framework.Backend
	s    logical.Storage
	keks map[string]*rsa.PrivateKey
}

func newWalletBYOKEnv(t *testing.T) *walletBYOKEnv {
	t.Helper()
	var mu sync.Map
	return &walletBYOKEnv{
		t:    t,
		b:    &framework.Backend{Paths: Paths(&mu)},
		s:    &logical.InmemStorage{},
		keks: map[string]*rsa.PrivateKey{},
	}
}

func (e *walletBYOKEnv) do(op logical.Operation, path string, data map[string]interface{}) *logical.Response {
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

// importWallet stores mnemonic as walletID through the import path.
func (e *walletBYOKEnv) importWallet(walletID, mnemonic string) {
	e.t.Helper()
	resp := e.do(logical.CreateOperation, "wallets/"+walletID+"/import", map[string]interface{}{"mnemonic": mnemonic})
	if resp == nil || resp.IsError() {
		e.t.Fatalf("import wallet: %#v", resp)
	}
}

// deriveNext creates the next derived account and returns its address.
func (e *walletBYOKEnv) deriveNext(walletID string) string {
	e.t.Helper()
	resp := e.do(logical.CreateOperation, "wallets/"+walletID+"/accounts", nil)
	if resp == nil || resp.IsError() {
		e.t.Fatalf("derive account: %#v", resp)
	}
	addr, _ := resp.Data["address"].(string)
	if addr == "" {
		e.t.Fatalf("no address in %#v", resp.Data)
	}
	return addr
}

// createKEK generates a 2048-bit receiving KEK and returns its kid, public key PEM, and fingerprint.
func (e *walletBYOKEnv) createKEK(name string) map[string]interface{} {
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
		"public_key_pem":    pemOfPublicKey(e.t, &priv.PublicKey),
		"public_key_sha256": fp,
	}
}

// exportWallet sends a wallet export write, wrapping for kek.
func (e *walletBYOKEnv) exportWallet(walletID string, kek map[string]interface{}) *logical.Response {
	e.t.Helper()
	return e.do(logical.UpdateOperation, "byok/export/wallet/"+walletID, map[string]interface{}{
		"kid":                kek["kid"],
		"kek_public_key_pem": kek["public_key_pem"],
	})
}

// addressFromSeed derives m/44'/60'/0'/0/<index> from seed with hdkeychain directly, independent of model.
func addressFromSeed(t *testing.T, seed []byte, index uint32) string {
	t.Helper()
	cur, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []uint32{
		44 + hdkeychain.HardenedKeyStart,
		60 + hdkeychain.HardenedKeyStart,
		hdkeychain.HardenedKeyStart,
		0,
		index,
	} {
		if cur, err = cur.Derive(c); err != nil {
			t.Fatal(err)
		}
	}
	ec, err := cur.ECPrivKey()
	if err != nil {
		t.Fatal(err)
	}
	pk, err := crypto.ToECDSA(ec.Serialize())
	if err != nil {
		t.Fatal(err)
	}
	return crypto.PubkeyToAddress(pk.PublicKey).Hex()
}

// wantCode asserts resp is an error with the given status whose message carries code.
func wantCode(t *testing.T, resp *logical.Response, status int, code string) {
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

func pemOfPublicKey(t *testing.T, pub interface{}) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// TestWalletExportBYOK_roundTrip verifies the exported seed unwraps to the wallet's BIP-39 seed and derives
// every stored account address.
func TestWalletExportBYOK_roundTrip(t *testing.T) {
	t.Parallel()
	e := newWalletBYOKEnv(t)
	e.importWallet("w1", testMnemonic)
	addrs := []string{e.deriveNext("w1"), e.deriveNext("w1"), e.deriveNext("w1")}
	kek := e.createKEK("k1")

	resp := e.exportWallet("w1", kek)
	if resp == nil || resp.IsError() {
		t.Fatalf("export failed: %#v", resp)
	}
	if resp.Data["wallet_id"] != "w1" || resp.Data["key_type"] != byokcrypto.KeyTypeBIP39Seed {
		t.Fatalf("data=%#v", resp.Data)
	}
	if resp.Data["kek_public_key_sha256"] != kek["public_key_sha256"] {
		t.Fatalf("fingerprint=%v want %v", resp.Data["kek_public_key_sha256"], kek["public_key_sha256"])
	}
	for k := range resp.Data {
		if strings.Contains(k, "mnemonic") || strings.Contains(k, "private") || k == "seed" {
			t.Fatalf("response has secret field %q", k)
		}
	}

	want := bip39.NewSeed(testMnemonic, "")
	encoded := resp.Data["byok_blob"].(string)
	if strings.Contains(encoded, hex.EncodeToString(want)) {
		t.Fatal("blob contains the seed in the clear")
	}
	blob, err := byokcrypto.ParseBlob(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if blob.Header.KID != kek["kid"] || blob.Generator == "" || blob.KeyType != byokcrypto.KeyTypeBIP39Seed {
		t.Fatalf("blob header=%+v generator=%q key_type=%q", blob.Header, blob.Generator, blob.KeyType)
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"key_type":"bip39-seed"`) {
		t.Fatalf("blob JSON lacks key_type: %s", raw)
	}

	seed, err := byokcrypto.UnwrapKey(e.keks["k1"], blob)
	if err != nil {
		t.Fatal(err)
	}
	if len(seed) != 64 || !bytes.Equal(seed, want) {
		t.Fatalf("unwrapped seed (%d bytes) differs from the wallet seed", len(seed))
	}
	for i, addr := range addrs {
		if got := addressFromSeed(t, seed, uint32(i)); got != addr {
			t.Fatalf("index %d: seed derives %s, stored %s", i, got, addr)
		}
	}

	// Export changes nothing.
	stored, err := ReadWalletSeed(context.Background(), e.s, "w1")
	if err != nil || stored == nil || stored.Mnemonic != testMnemonic {
		t.Fatalf("export changed the wallet: %v", err)
	}
}

// TestWalletExportBYOK_twiceDiffers verifies repeated exports are independent (fresh AES key and OAEP seed).
func TestWalletExportBYOK_twiceDiffers(t *testing.T) {
	t.Parallel()
	e := newWalletBYOKEnv(t)
	e.importWallet("w1", testMnemonic)
	kek := e.createKEK("k1")
	a, b := e.exportWallet("w1", kek), e.exportWallet("w1", kek)
	if a.Data["byok_blob"] == b.Data["byok_blob"] {
		t.Fatal("two exports are byte-identical")
	}
}

// TestAccountExportBYOK_noKeyType verifies account export blobs keep the original format without key_type.
func TestAccountExportBYOK_noKeyType(t *testing.T) {
	t.Parallel()
	e := newWalletBYOKEnv(t)
	e.b.Paths = append(e.b.Paths, account.Paths()...)
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	imp := e.do(logical.CreateOperation, "accounts/alice/import", map[string]interface{}{
		"private_key": hex.EncodeToString(crypto.FromECDSA(key)),
	})
	if imp == nil || imp.IsError() {
		t.Fatalf("import: %#v", imp)
	}
	kek := e.createKEK("k1")
	resp := e.do(logical.UpdateOperation, "byok/export/account/alice", map[string]interface{}{
		"kid":                kek["kid"],
		"kek_public_key_pem": kek["public_key_pem"],
	})
	if resp == nil || resp.IsError() {
		t.Fatalf("export: %#v", resp)
	}
	raw, err := base64.StdEncoding.DecodeString(resp.Data["byok_blob"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "key_type") {
		t.Fatalf("account blob has key_type: %s", raw)
	}
	if _, ok := resp.Data["key_type"]; ok {
		t.Fatal("account export response has key_type")
	}
}

// TestWalletExportBYOK_rejects verifies parameter and lookup failures.
func TestWalletExportBYOK_rejects(t *testing.T) {
	t.Parallel()
	e := newWalletBYOKEnv(t)
	e.importWallet("w1", testMnemonic)
	kek := e.createKEK("k1")

	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	send := func(walletID string, data map[string]interface{}) *logical.Response {
		return e.do(logical.UpdateOperation, "byok/export/wallet/"+walletID, data)
	}
	plainError := func(t *testing.T, resp *logical.Response) {
		t.Helper()
		if resp == nil || !resp.IsError() {
			t.Fatalf("got %#v", resp)
		}
	}

	t.Run("missing kid", func(t *testing.T) {
		plainError(t, send("w1", map[string]interface{}{"kek_public_key_pem": kek["public_key_pem"]}))
	})
	t.Run("blank kid", func(t *testing.T) {
		plainError(t, send("w1", map[string]interface{}{"kid": "   ", "kek_public_key_pem": kek["public_key_pem"]}))
	})
	t.Run("kid too long", func(t *testing.T) {
		plainError(t, send("w1", map[string]interface{}{
			"kid":                strings.Repeat("k", byok.MaxKIDLength+1),
			"kek_public_key_pem": kek["public_key_pem"],
		}))
	})
	t.Run("missing public key", func(t *testing.T) {
		plainError(t, send("w1", map[string]interface{}{"kid": kek["kid"]}))
	})
	for name, pemStr := range map[string]string{
		"garbage pem":  "hello",
		"1024-bit key": pemOfPublicKey(t, &small.PublicKey),
		"ec key":       pemOfPublicKey(t, &p256.PublicKey),
	} {
		t.Run(name, func(t *testing.T) {
			resp := send("w1", map[string]interface{}{"kid": kek["kid"], "kek_public_key_pem": pemStr})
			wantCode(t, resp, http.StatusBadRequest, "invalid_kek_public_key")
		})
	}
	t.Run("wallet not found", func(t *testing.T) {
		wantCode(t, e.exportWallet("nobody", kek), http.StatusNotFound, "wallet_not_found")
	})
	t.Run("empty mnemonic", func(t *testing.T) {
		mustPutWalletSeed(context.Background(), t, e.s, "blank", "")
		wantCode(t, e.exportWallet("blank", kek), http.StatusNotFound, "wallet_not_found")
	})
}

// TestWalletExportPathOutsideWallets guards the policy design: wallet export must not live under wallets/,
// where the user policy's wallets/<entity>/* wildcard would grant it to every user.
func TestWalletExportPathOutsideWallets(t *testing.T) {
	t.Parallel()
	var mu sync.Map
	for _, p := range Paths(&mu) {
		if strings.HasPrefix(p.Pattern, "wallets/") && strings.Contains(p.Pattern, "export") {
			t.Fatalf("export path %q is under wallets/", p.Pattern)
		}
	}
	if got := pathWalletExportBYOK().Pattern; !strings.HasPrefix(got, "byok/export/wallet/") {
		t.Fatalf("export pattern=%q, want prefix byok/export/wallet/", got)
	}
}
