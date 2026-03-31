package model

import (
	"crypto/ecdsa"
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestNewAccount_fields(t *testing.T) {
	t.Parallel()

	a := NewAccount("0xabc", "deadbeef", "beefdead")
	if a.AddressStr != "0xabc" {
		t.Fatalf("AddressStr=%q", a.AddressStr)
	}
	if a.PrivateKeyStr != "deadbeef" {
		t.Fatalf("PrivateKeyStr=%q", a.PrivateKeyStr)
	}
	if a.PublicKeyStr != "beefdead" {
		t.Fatalf("PublicKeyStr=%q", a.PublicKeyStr)
	}
}

func TestAccount_GetPrivateKeyECDSA_invalidHex(t *testing.T) {
	t.Parallel()

	a := NewAccount("0x0", "not-hex", "")
	if _, err := a.GetPrivateKeyECDSA(); err == nil {
		t.Fatal("expected error")
	}
}

func TestAccount_GetPublicKeyECDSA_matchesPrivateKey(t *testing.T) {
	t.Parallel()

	pk, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	privHexNo0x := hexutil.Encode(crypto.FromECDSA(pk))[2:]
	a := NewAccount(crypto.PubkeyToAddress(pk.PublicKey).Hex(), privHexNo0x, "")

	pub, err := a.GetPublicKeyECDSA()
	if err != nil {
		t.Fatal(err)
	}
	if !publicKeysEqual(pub, &pk.PublicKey) {
		t.Fatal("public key mismatch")
	}
}

func TestAccount_GetPublicKeyECIES_smoke(t *testing.T) {
	t.Parallel()

	pk, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	privHexNo0x := hexutil.Encode(crypto.FromECDSA(pk))[2:]
	a := NewAccount(crypto.PubkeyToAddress(pk.PublicKey).Hex(), privHexNo0x, "")

	pub, err := a.GetPublicKeyECIES()
	if err != nil {
		t.Fatal(err)
	}
	if pub == nil {
		t.Fatal("expected non-nil ECIES public key")
	}
}

func publicKeysEqual(a, b *ecdsa.PublicKey) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.Curve != b.Curve {
		return false
	}
	return a.X.Cmp(b.X) == 0 && a.Y.Cmp(b.Y) == 0
}

