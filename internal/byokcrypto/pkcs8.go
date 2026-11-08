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
	"crypto/ecdsa"
	"crypto/subtle"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"
)

// Errors returned for secp256k1 private key encoding and parsing.
var (
	// ErrUnsupportedCurve means the PKCS#8 key is not an EC key on secp256k1.
	ErrUnsupportedCurve = errors.New("private key is not an secp256k1 EC key")
	// ErrInvalidKey means the key material is malformed or not a valid secp256k1 scalar.
	ErrInvalidKey = errors.New("invalid private key")
)

var (
	oidECPublicKey = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidSecp256k1   = asn1.ObjectIdentifier{1, 3, 132, 0, 10}
)

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type pkcs8PrivateKeyInfo struct {
	Version             int
	PrivateKeyAlgorithm algorithmIdentifier
	PrivateKey          []byte
	Attributes          asn1.RawValue `asn1:"optional,tag:0"`
}

// ecPrivateKey is the RFC 5915 ECPrivateKey structure.
type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

// MarshalSecp256k1PKCS8 encodes priv as a PKCS#8 PrivateKeyInfo (DER) holding an RFC 5915 ECPrivateKey
// with the public key included, the same shape OpenSSL produces. The caller must zero the result.
func MarshalSecp256k1PKCS8(priv *ecdsa.PrivateKey) ([]byte, error) {
	if priv == nil || priv.D == nil || priv.D.Sign() == 0 {
		return nil, ErrInvalidKey
	}
	if priv.Curve != crypto.S256() {
		return nil, ErrUnsupportedCurve
	}
	d := priv.D.FillBytes(make([]byte, 32))
	inner, err := asn1.Marshal(ecPrivateKey{
		Version:    1,
		PrivateKey: d,
		PublicKey:  asn1.BitString{Bytes: crypto.FromECDSAPub(&priv.PublicKey), BitLength: 65 * 8},
	})
	zero(d)
	if err != nil {
		return nil, fmt.Errorf("marshal ec private key: %w", err)
	}
	defer zero(inner)

	params, err := asn1.Marshal(oidSecp256k1)
	if err != nil {
		return nil, fmt.Errorf("marshal curve oid: %w", err)
	}
	out, err := asn1.Marshal(pkcs8PrivateKeyInfo{
		Version: 0,
		PrivateKeyAlgorithm: algorithmIdentifier{
			Algorithm:  oidECPublicKey,
			Parameters: asn1.RawValue{FullBytes: params},
		},
		PrivateKey: inner,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal pkcs8: %w", err)
	}
	return out, nil
}

// ParseSecp256k1PKCS8 parses a PKCS#8 PrivateKeyInfo (DER) holding a secp256k1 EC private key.
// It returns ErrUnsupportedCurve for any other key type or curve and ErrInvalidKey for malformed data,
// a scalar outside [1, n-1], or a public key that does not match the private key.
// The caller should clear the returned key with utils.ZeroKey.
func ParseSecp256k1PKCS8(der []byte) (*ecdsa.PrivateKey, error) {
	var info pkcs8PrivateKeyInfo
	rest, err := asn1.Unmarshal(der, &info)
	if err != nil || len(rest) != 0 {
		return nil, ErrInvalidKey
	}
	defer zero(info.PrivateKey)
	if info.Version != 0 && info.Version != 1 {
		return nil, ErrInvalidKey
	}
	if !info.PrivateKeyAlgorithm.Algorithm.Equal(oidECPublicKey) {
		return nil, ErrUnsupportedCurve
	}
	var algCurve asn1.ObjectIdentifier
	if len(info.PrivateKeyAlgorithm.Parameters.FullBytes) == 0 {
		return nil, ErrUnsupportedCurve
	}
	if _, err := asn1.Unmarshal(info.PrivateKeyAlgorithm.Parameters.FullBytes, &algCurve); err != nil {
		return nil, ErrUnsupportedCurve
	}
	if !algCurve.Equal(oidSecp256k1) {
		return nil, ErrUnsupportedCurve
	}

	var ec ecPrivateKey
	rest, err = asn1.Unmarshal(info.PrivateKey, &ec)
	if err != nil || len(rest) != 0 || ec.Version != 1 {
		return nil, ErrInvalidKey
	}
	defer zero(ec.PrivateKey)
	if len(ec.NamedCurveOID) != 0 && !ec.NamedCurveOID.Equal(oidSecp256k1) {
		return nil, ErrUnsupportedCurve
	}
	if n := len(ec.PrivateKey); n == 0 || n > 32 {
		return nil, ErrInvalidKey
	}

	// Left-pad: some encoders strip leading zero bytes. crypto.ToECDSA rejects zero and values >= n.
	d := make([]byte, 32)
	defer zero(d)
	copy(d[32-len(ec.PrivateKey):], ec.PrivateKey)
	priv, err := crypto.ToECDSA(d)
	if err != nil {
		return nil, ErrInvalidKey
	}

	if ec.PublicKey.BitLength != 0 {
		if ec.PublicKey.BitLength%8 != 0 ||
			subtle.ConstantTimeCompare(ec.PublicKey.Bytes, crypto.FromECDSAPub(&priv.PublicKey)) != 1 {
			zeroScalar(priv.D)
			return nil, ErrInvalidKey
		}
	}
	return priv, nil
}

// zeroScalar clears a big.Int in place.
func zeroScalar(d *big.Int) {
	if d != nil {
		d.SetInt64(0)
	}
}
