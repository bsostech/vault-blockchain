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

// Package byokcrypto implements the cryptography of the BYOK key transfer format: AES Key Wrap with
// Padding (RFC 5649), RSA-OAEP key wrapping, PKCS#8 encoding for secp256k1 keys, and the .byok blob.
package byokcrypto

import (
	"crypto/aes"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
)

// kwpAIV is the RFC 5649 alternative initial value prefix (A65959A6).
var kwpAIV = [4]byte{0xA6, 0x59, 0x59, 0xA6}

// errKWPIntegrity is returned when AES-KWP unwrapping fails its integrity check.
var errKWPIntegrity = errors.New("aes-kwp integrity check failed")

// KWPWrap wraps plaintext (at least 1 byte) with AES Key Wrap with Padding (RFC 5649).
// kek must be 16, 24, or 32 bytes. The output is 8 bytes longer than plaintext rounded up to a multiple of 8.
func KWPWrap(kek, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("aes-kwp: %w", err)
	}
	n := len(plaintext)
	if n == 0 {
		return nil, errors.New("aes-kwp: plaintext must not be empty")
	}
	if uint64(n) > 1<<32-1 {
		return nil, errors.New("aes-kwp: plaintext too long")
	}

	padded := (n + 7) / 8 * 8
	// buf holds AIV followed by the zero-padded plaintext.
	buf := make([]byte, 8+padded)
	copy(buf[:4], kwpAIV[:])
	binary.BigEndian.PutUint32(buf[4:8], uint32(n))
	copy(buf[8:], plaintext)

	if padded == 8 {
		// A single 64-bit block: one AES encryption of AIV || P (RFC 5649, section 4.1).
		out := make([]byte, 16)
		block.Encrypt(out, buf)
		return out, nil
	}
	wrapCore(block, buf)
	return buf, nil
}

// KWPUnwrap reverses KWPWrap. Any failure returns an error without revealing which check failed.
func KWPUnwrap(kek, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("aes-kwp: %w", err)
	}
	if len(ciphertext) < 16 || len(ciphertext)%8 != 0 {
		return nil, errKWPIntegrity
	}

	buf := append([]byte(nil), ciphertext...)
	if len(buf) == 16 {
		block.Decrypt(buf, buf)
	} else {
		unwrapCore(block, buf)
	}
	defer zero(buf)

	blocks := len(buf)/8 - 1 // number of 64-bit plaintext blocks
	mli := int(binary.BigEndian.Uint32(buf[4:8]))
	padded := blocks * 8

	// Every check is evaluated before deciding, so failure modes are not distinguishable by timing.
	ok := subtle.ConstantTimeCompare(buf[:4], kwpAIV[:])
	if !(mli > padded-8 && mli <= padded) {
		ok = 0
	}
	// mli is only used as an index if it is in range, so clamp it for the padding check.
	idx := mli
	if idx < 0 || idx > padded {
		idx = padded
	}
	var pad byte
	for _, b := range buf[8+idx:] {
		pad |= b
	}
	ok &= subtle.ConstantTimeByteEq(pad, 0)
	if ok != 1 {
		return nil, errKWPIntegrity
	}

	out := make([]byte, mli)
	copy(out, buf[8:8+mli])
	return out, nil
}

// wrapCore runs the RFC 3394 wrapping rounds in place over buf, where buf[:8] is the initial value A
// and buf[8:] holds the n >= 2 plaintext blocks R[1..n].
func wrapCore(block interface{ Encrypt(dst, src []byte) }, buf []byte) {
	n := len(buf)/8 - 1
	var b [16]byte
	for j := 0; j < 6; j++ {
		for i := 1; i <= n; i++ {
			copy(b[:8], buf[:8])
			copy(b[8:], buf[8*i:8*i+8])
			block.Encrypt(b[:], b[:])
			t := uint64(n*j + i)
			binary.BigEndian.PutUint64(buf[:8], binary.BigEndian.Uint64(b[:8])^t)
			copy(buf[8*i:8*i+8], b[8:])
		}
	}
}

// unwrapCore reverses wrapCore in place; buf[:8] ends as the recovered initial value A.
func unwrapCore(block interface{ Decrypt(dst, src []byte) }, buf []byte) {
	n := len(buf)/8 - 1
	var b [16]byte
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			t := uint64(n*j + i)
			binary.BigEndian.PutUint64(b[:8], binary.BigEndian.Uint64(buf[:8])^t)
			copy(b[8:], buf[8*i:8*i+8])
			block.Decrypt(b[:], b[:])
			copy(buf[:8], b[:8])
			copy(buf[8*i:8*i+8], b[8:])
		}
	}
}

// zero overwrites b with zeros.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
