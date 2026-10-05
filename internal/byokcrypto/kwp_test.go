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
	"crypto/aes"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestKWPRFC5649Vectors checks the two test vectors from RFC 5649, section 6.
func TestKWPRFC5649Vectors(t *testing.T) {
	t.Parallel()
	kek := mustHex(t, "5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8")
	cases := []struct{ name, plain, wrapped string }{
		{
			name:    "20 octets",
			plain:   "c37b7e6492584340bed12207808941155068f738",
			wrapped: "138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a",
		},
		{
			name:    "7 octets",
			plain:   "466f7250617369",
			wrapped: "afbeb0f07dfbf5419200f2ccb50bb24f",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			plain, want := mustHex(t, c.plain), mustHex(t, c.wrapped)
			got, err := KWPWrap(kek, plain)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("wrap=%x want %x", got, want)
			}
			back, err := KWPUnwrap(kek, want)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(back, plain) {
				t.Fatalf("unwrap=%x want %x", back, plain)
			}
		})
	}
}

// TestWrapCoreRFC3394Vector checks the underlying RFC 3394 rounds against the RFC 3394 section 4.1 vector
// (128-bit KEK, 128-bit key data, default initial value A6A6A6A6A6A6A6A6).
func TestWrapCoreRFC3394Vector(t *testing.T) {
	t.Parallel()
	kek := mustHex(t, "000102030405060708090A0B0C0D0E0F")
	plain := mustHex(t, "00112233445566778899AABBCCDDEEFF")
	want := mustHex(t, "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")

	block, err := aes.NewCipher(kek)
	if err != nil {
		t.Fatal(err)
	}
	buf := append(mustHex(t, "A6A6A6A6A6A6A6A6"), plain...)
	wrapCore(block, buf)
	if !bytes.Equal(buf, want) {
		t.Fatalf("wrap=%x want %x", buf, want)
	}
	unwrapCore(block, buf)
	if !bytes.Equal(buf[8:], plain) || !bytes.Equal(buf[:8], mustHex(t, "A6A6A6A6A6A6A6A6")) {
		t.Fatalf("unwrap=%x", buf)
	}
}

// TestKWPRoundTrip verifies every plaintext length from 1 to 130 bytes with all AES key sizes.
func TestKWPRoundTrip(t *testing.T) {
	t.Parallel()
	for _, kekLen := range []int{16, 24, 32} {
		kek := make([]byte, kekLen)
		if _, err := rand.Read(kek); err != nil {
			t.Fatal(err)
		}
		for n := 1; n <= 130; n++ {
			plain := make([]byte, n)
			if _, err := rand.Read(plain); err != nil {
				t.Fatal(err)
			}
			wrapped, err := KWPWrap(kek, plain)
			if err != nil {
				t.Fatalf("kek=%d n=%d: %v", kekLen, n, err)
			}
			if want := (n+7)/8*8 + 8; len(wrapped) != want {
				t.Fatalf("kek=%d n=%d: len=%d want %d", kekLen, n, len(wrapped), want)
			}
			back, err := KWPUnwrap(kek, wrapped)
			if err != nil || !bytes.Equal(back, plain) {
				t.Fatalf("kek=%d n=%d: round trip failed: %v", kekLen, n, err)
			}
		}
	}
}

// TestKWPUnwrapRejectsTampering verifies any single-bit change, wrong key, or bad length fails.
func TestKWPUnwrapRejectsTampering(t *testing.T) {
	t.Parallel()
	kek := bytes.Repeat([]byte{7}, 32)
	for _, n := range []int{1, 8, 20, 32, 121} {
		plain := bytes.Repeat([]byte{0xAB}, n)
		wrapped, err := KWPWrap(kek, plain)
		if err != nil {
			t.Fatal(err)
		}
		for i := range wrapped {
			bad := append([]byte(nil), wrapped...)
			bad[i] ^= 0x01
			if _, err := KWPUnwrap(kek, bad); err == nil {
				t.Fatalf("n=%d: flipping byte %d was accepted", n, i)
			}
		}
		if _, err := KWPUnwrap(bytes.Repeat([]byte{8}, 32), wrapped); err == nil {
			t.Fatalf("n=%d: wrong key accepted", n)
		}
		if _, err := KWPUnwrap(kek, wrapped[:len(wrapped)-8]); err == nil {
			t.Fatalf("n=%d: truncated ciphertext accepted", n)
		}
		if _, err := KWPUnwrap(kek, append(wrapped, make([]byte, 8)...)); err == nil {
			t.Fatalf("n=%d: extended ciphertext accepted", n)
		}
	}
}

// TestKWPInvalidInput verifies argument validation.
func TestKWPInvalidInput(t *testing.T) {
	t.Parallel()
	good := bytes.Repeat([]byte{1}, 32)
	if _, err := KWPWrap(good, nil); err == nil {
		t.Fatal("empty plaintext accepted")
	}
	if _, err := KWPWrap(make([]byte, 10), []byte("x")); err == nil {
		t.Fatal("bad kek length accepted")
	}
	if _, err := KWPUnwrap(make([]byte, 10), make([]byte, 16)); err == nil {
		t.Fatal("bad kek length accepted")
	}
	for _, n := range []int{0, 8, 15, 17, 23} {
		if _, err := KWPUnwrap(good, make([]byte, n)); err == nil {
			t.Fatalf("ciphertext length %d accepted", n)
		}
	}
}
