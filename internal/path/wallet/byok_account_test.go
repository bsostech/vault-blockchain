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
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/tyler-smith/go-bip39"

	"github.com/bsostech/vault-blockchain/internal/byokcrypto"
	"github.com/bsostech/vault-blockchain/internal/model"
	"github.com/bsostech/vault-blockchain/internal/path/account"
	"github.com/bsostech/vault-blockchain/internal/path/byok"
	"github.com/bsostech/vault-blockchain/internal/path/storagekey"
)

// exportDerived sends a derived-account export write for walletID/index, wrapping for kek.
func (e *walletBYOKEnv) exportDerived(walletID, index string, kek map[string]interface{}) *logical.Response {
	e.t.Helper()
	return e.do(logical.UpdateOperation, derivedExportPath(walletID, index), map[string]interface{}{
		"kid":                kek["kid"],
		"kek_public_key_pem": kek["public_key_pem"],
	})
}

func derivedExportPath(walletID, index string) string {
	return "byok/export/wallet/" + walletID + "/accounts/" + index
}

// unwrapPKCS8 parses the response blob, unwraps it with the named KEK, and returns the PKCS#8 plaintext.
func (e *walletBYOKEnv) unwrapPKCS8(resp *logical.Response, kekName string) (*byokcrypto.Blob, []byte) {
	e.t.Helper()
	blob, err := byokcrypto.ParseBlob(resp.Data["byok_blob"].(string))
	if err != nil {
		e.t.Fatal(err)
	}
	der, err := byokcrypto.UnwrapKey(e.keks[kekName], blob)
	if err != nil {
		e.t.Fatal(err)
	}
	return blob, der
}

// TestDerivedAccountExportBYOK_roundTrip verifies one derived account's private key is exported as PKCS#8,
// matches the stored address and an independent BIP-32 derivation, and leaves the wallet unchanged.
func TestDerivedAccountExportBYOK_roundTrip(t *testing.T) {
	t.Parallel()
	// Arrange
	e := newWalletBYOKEnv(t)
	e.importWallet("w1", testMnemonic)
	addrs := []string{e.deriveNext("w1"), e.deriveNext("w1"), e.deriveNext("w1")}
	kek := e.createKEK("k1")
	counterBefore, err := ReadWalletCounter(context.Background(), e.s, "w1")
	if err != nil {
		t.Fatal(err)
	}

	// Act
	resp := e.exportDerived("w1", "1", kek)

	// Assert
	if resp == nil || resp.IsError() {
		t.Fatalf("export failed: %#v", resp)
	}
	if resp.Data["wallet_id"] != "w1" || resp.Data["account_index"] != "1" ||
		resp.Data["address"] != addrs[1] || resp.Data["derivation_path"] != "m/44'/60'/0'/0/1" {
		t.Fatalf("data=%#v", resp.Data)
	}
	if resp.Data["kek_public_key_sha256"] != kek["public_key_sha256"] {
		t.Fatalf("fingerprint=%v want %v", resp.Data["kek_public_key_sha256"], kek["public_key_sha256"])
	}
	for k := range resp.Data {
		if strings.Contains(k, "mnemonic") || strings.Contains(k, "private") || k == "seed" || k == "key_type" {
			t.Fatalf("response has unexpected field %q", k)
		}
	}

	blob, der := e.unwrapPKCS8(resp, "k1")
	if blob.Header.KID != kek["kid"] || blob.Generator == "" || blob.KeyType != "" {
		t.Fatalf("blob header=%+v generator=%q key_type=%q", blob.Header, blob.Generator, blob.KeyType)
	}
	priv, err := byokcrypto.ParseSecp256k1PKCS8(der)
	if err != nil {
		t.Fatal(err)
	}
	got := crypto.PubkeyToAddress(priv.PublicKey).Hex()
	if got != addrs[1] {
		t.Fatalf("unwrapped key is %s, stored account 1 is %s", got, addrs[1])
	}
	if want := addressFromSeed(t, bip39.NewSeed(testMnemonic, ""), 1); got != want {
		t.Fatalf("unwrapped key is %s, independent BIP-32 derivation gives %s", got, want)
	}
	requireNotInBlob(t, resp.Data["byok_blob"].(string), crypto.FromECDSA(priv))
	requireNotInBlob(t, resp.Data["byok_blob"].(string), bip39.NewSeed(testMnemonic, ""))

	counterAfter, err := ReadWalletCounter(context.Background(), e.s, "w1")
	if err != nil || counterAfter != counterBefore {
		t.Fatalf("export changed the counter: %d -> %d (%v)", counterBefore, counterAfter, err)
	}
	stored, err := ReadWalletSeed(context.Background(), e.s, "w1")
	if err != nil || stored == nil || stored.Mnemonic != testMnemonic {
		t.Fatalf("export changed the wallet: %v", err)
	}
}

// TestDerivedAccountExportBYOK_sameFormatAsAccountExport verifies a derived account exports byte-for-byte
// the same PKCS#8 as a single-key account holding the same key, so receivers need no new import flow.
func TestDerivedAccountExportBYOK_sameFormatAsAccountExport(t *testing.T) {
	t.Parallel()
	// Arrange
	e := newWalletBYOKEnv(t)
	e.b.Paths = append(e.b.Paths, account.Paths()...)
	e.importWallet("w1", testMnemonic)
	e.deriveNext("w1")
	kek := e.createKEK("k1")
	pk, err := model.PrivateKeyECDSA(testMnemonic, 0)
	if err != nil {
		t.Fatal(err)
	}
	imp := e.do(logical.CreateOperation, "accounts/same/import", map[string]interface{}{
		"private_key": hex.EncodeToString(crypto.FromECDSA(pk)),
	})
	if imp == nil || imp.IsError() {
		t.Fatalf("import: %#v", imp)
	}

	// Act
	derived := e.exportDerived("w1", "0", kek)
	single := e.do(logical.UpdateOperation, "byok/export/account/same", map[string]interface{}{
		"kid":                kek["kid"],
		"kek_public_key_pem": kek["public_key_pem"],
	})

	// Assert
	if derived == nil || derived.IsError() || single == nil || single.IsError() {
		t.Fatalf("derived=%#v single=%#v", derived, single)
	}
	_, derivedDER := e.unwrapPKCS8(derived, "k1")
	_, singleDER := e.unwrapPKCS8(single, "k1")
	if !bytes.Equal(derivedDER, singleDER) {
		t.Fatal("derived account PKCS#8 differs from the single-key account export of the same key")
	}
	raw, err := base64.StdEncoding.DecodeString(derived.Data["byok_blob"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "key_type") {
		t.Fatalf("derived account blob has key_type: %s", raw)
	}
	if derived.Data["address"] != single.Data["address"] {
		t.Fatalf("addresses differ: %v vs %v", derived.Data["address"], single.Data["address"])
	}
}

// TestDerivedAccountExportBYOK_rejects verifies parameter and lookup failures.
func TestDerivedAccountExportBYOK_rejects(t *testing.T) {
	t.Parallel()
	e := newWalletBYOKEnv(t)
	e.importWallet("w1", testMnemonic)
	e.deriveNext("w1")
	kek := e.createKEK("k1")
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}

	send := func(walletID, index string, data map[string]interface{}) *logical.Response {
		return e.do(logical.UpdateOperation, derivedExportPath(walletID, index), data)
	}
	plainError := func(t *testing.T, resp *logical.Response) {
		t.Helper()
		if resp == nil || !resp.IsError() {
			t.Fatalf("got %#v", resp)
		}
	}

	t.Run("missing kid", func(t *testing.T) {
		plainError(t, send("w1", "0", map[string]interface{}{"kek_public_key_pem": kek["public_key_pem"]}))
	})
	t.Run("blank kid", func(t *testing.T) {
		plainError(t, send("w1", "0", map[string]interface{}{"kid": "  ", "kek_public_key_pem": kek["public_key_pem"]}))
	})
	t.Run("kid too long", func(t *testing.T) {
		plainError(t, send("w1", "0", map[string]interface{}{
			"kid":                strings.Repeat("k", byok.MaxKIDLength+1),
			"kek_public_key_pem": kek["public_key_pem"],
		}))
	})
	t.Run("missing public key", func(t *testing.T) {
		plainError(t, send("w1", "0", map[string]interface{}{"kid": kek["kid"]}))
	})
	for name, pemStr := range map[string]string{
		"garbage pem":  "hello",
		"1024-bit key": pemOfPublicKey(t, &small.PublicKey),
	} {
		t.Run(name, func(t *testing.T) {
			resp := send("w1", "0", map[string]interface{}{"kid": kek["kid"], "kek_public_key_pem": pemStr})
			wantCode(t, resp, http.StatusBadRequest, "invalid_kek_public_key")
		})
	}
	t.Run("index out of range", func(t *testing.T) {
		wantCode(t, e.exportDerived("w1", "2147483648", kek), http.StatusBadRequest, "invalid_index")
	})
	for _, index := range []string{"00", "01"} {
		t.Run("leading zero index "+index, func(t *testing.T) {
			// One account must have one path: a policy naming accounts/0 must not be avoidable through accounts/00.
			wantCode(t, e.exportDerived("w1", index, kek), http.StatusBadRequest, "invalid_index")
		})
	}
	t.Run("index not derived yet", func(t *testing.T) {
		wantCode(t, e.exportDerived("w1", "5", kek), http.StatusNotFound, "account_not_found")
	})
	t.Run("wallet not found", func(t *testing.T) {
		wantCode(t, e.exportDerived("nobody", "0", kek), http.StatusNotFound, "wallet_not_found")
	})
	t.Run("empty mnemonic", func(t *testing.T) {
		mustPutWalletSeed(context.Background(), t, e.s, "blank", "")
		wantCode(t, e.exportDerived("blank", "0", kek), http.StatusNotFound, "wallet_not_found")
	})
	t.Run("account entry without a wallet", func(t *testing.T) {
		mustPutDerivedAccount(context.Background(), t, e.s, "orphan", "0", testMnemonic)
		wantCode(t, e.exportDerived("orphan", "0", kek), http.StatusNotFound, "wallet_not_found")
	})
}

// TestDerivedAccountExportBYOK_storedAddressMismatch verifies a derived account whose stored address does
// not match the key derived from the seed is refused instead of exporting a key for a different address.
func TestDerivedAccountExportBYOK_storedAddressMismatch(t *testing.T) {
	t.Parallel()
	// Arrange
	e := newWalletBYOKEnv(t)
	e.importWallet("w1", testMnemonic)
	e.deriveNext("w1")
	kek := e.createKEK("k1")
	entry, err := logical.StorageEntryJSON(storagekey.AccountKey("w1", "0"), &model.DerivedAccount{
		Address:        "0x000000000000000000000000000000000000dEaD",
		DerivationPath: "m/44'/60'/0'/0/0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.s.Put(context.Background(), entry); err != nil {
		t.Fatal(err)
	}

	// Act
	resp, err := e.b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      derivedExportPath("w1", "0"),
		Data:      map[string]interface{}{"kid": kek["kid"], "kek_public_key_pem": kek["public_key_pem"]},
		Storage:   e.s,
	})

	// Assert
	if err == nil {
		t.Fatalf("expected an internal error, got %#v", resp)
	}
	if resp != nil && resp.Data["byok_blob"] != nil {
		t.Fatal("a blob was returned for a mismatched account")
	}
}

// TestDerivedAccountExportPathOutsideWallets guards the policy design like TestWalletExportPathOutsideWallets.
func TestDerivedAccountExportPathOutsideWallets(t *testing.T) {
	t.Parallel()
	if got := pathDerivedAccountExportBYOK().Pattern; !strings.HasPrefix(got, "byok/export/wallet/") {
		t.Fatalf("export pattern=%q, want prefix byok/export/wallet/", got)
	}
}
