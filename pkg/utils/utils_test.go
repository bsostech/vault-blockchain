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

package utils

import (
	"crypto/ecdsa"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

func TestZeroKey(t *testing.T) {
	t.Parallel()
	raw := make([]byte, 32)
	raw[31] = 42
	pk, err := crypto.ToECDSA(raw)
	if err != nil {
		t.Fatal(err)
	}
	if pk.D.Sign() == 0 {
		t.Fatal("sanity: expected non-zero D before ZeroKey.")
	}
	ZeroKey(pk)
	if pk.D.Sign() != 0 {
		t.Fatalf("after ZeroKey D.Sign()=%d want 0.", pk.D.Sign())
	}
}

func TestZeroKey_nilReceiver(t *testing.T) {
	t.Parallel()
	ZeroKey(nil)
}

func TestZeroKey_nilD(t *testing.T) {
	t.Parallel()
	var pk ecdsa.PrivateKey
	ZeroKey(&pk)
}

func TestValidNumber(t *testing.T) {
	t.Parallel()
	t.Run("empty", func(t *testing.T) {
		t.Parallel()
		if got := ValidNumber(""); got.Cmp(big.NewInt(0)) != 0 {
			t.Fatalf("got %v want 0.", got)
		}
	})
	t.Run("zero", func(t *testing.T) {
		t.Parallel()
		if got := ValidNumber("0"); got.Cmp(big.NewInt(0)) != 0 {
			t.Fatalf("got %v want 0.", got)
		}
	})
	t.Run("decimal", func(t *testing.T) {
		t.Parallel()
		if got := ValidNumber("100"); got.Cmp(big.NewInt(100)) != 0 {
			t.Fatalf("got %v want 100.", got)
		}
	})
	t.Run("abs_negative", func(t *testing.T) {
		t.Parallel()
		if got := ValidNumber("-5"); got.Cmp(big.NewInt(5)) != 0 {
			t.Fatalf("got %v want 5.", got)
		}
	})
	t.Run("hex", func(t *testing.T) {
		t.Parallel()
		if got := ValidNumber("0xff"); got.Cmp(big.NewInt(255)) != 0 {
			t.Fatalf("got %v want 255.", got)
		}
	})
	t.Run("no_digit", func(t *testing.T) {
		t.Parallel()
		if got := ValidNumber("not-a-number"); got != nil {
			t.Fatalf("got %v want nil.", got)
		}
	})
	t.Run("whitespace_only", func(t *testing.T) {
		t.Parallel()
		if got := ValidNumber("   "); got != nil {
			t.Fatalf("got %v want nil.", got)
		}
	})
	t.Run("malformed_decimal_panics", func(t *testing.T) {
		t.Parallel()
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected panic: MustParseBig256 rejects digit-then-junk strings.")
			}
		}()
		_ = ValidNumber("12abc")
	})
}
