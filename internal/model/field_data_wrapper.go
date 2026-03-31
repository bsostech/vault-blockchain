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

package model

import (
	"fmt"
	"math/big"

	"github.com/hashicorp/vault/sdk/framework"

	"github.com/bsostech/vault-blockchain/pkg/utils"
)

// FieldDataWrapper adds typed getters on top of framework.FieldData.
type FieldDataWrapper struct {
	*framework.FieldData
}

// NewFieldDataWrapper wraps framework.FieldData for typed access.
func NewFieldDataWrapper(data *framework.FieldData) *FieldDataWrapper {
	return &FieldDataWrapper{
		FieldData: data,
	}
}

// GetStringFirstNonEmpty returns the first non-empty string among keys (API alias / evolution).
func (f *FieldDataWrapper) GetStringFirstNonEmpty(keys ...string) string {
	for _, k := range keys {
		if s := f.GetString(k, ""); s != "" {
			return s
		}
	}
	return ""
}

// BigIntWithAliases parses decimal integers from a then b; falls back to defaultVal when both empty.
func (f *FieldDataWrapper) BigIntWithAliases(a, b string, defaultVal *big.Int) *big.Int {
	if s := f.GetString(a, ""); s != "" {
		if bi := utils.ValidNumber(s); bi != nil {
			return bi
		}
	}
	if s := f.GetString(b, ""); s != "" {
		if bi := utils.ValidNumber(s); bi != nil {
			return bi
		}
	}
	return defaultVal
}

// MustGetBigIntAny requires a non-empty decimal string at one of the given keys.
func (f *FieldDataWrapper) MustGetBigIntAny(keys ...string) (*big.Int, error) {
	for _, k := range keys {
		s := f.GetString(k, "")
		if s == "" {
			continue
		}
		bi := utils.ValidNumber(s)
		if bi == nil {
			return nil, fmt.Errorf("invalid decimal integer for key %q", k)
		}
		return bi, nil
	}
	return nil, fmt.Errorf("missing non-empty decimal field: need one of %v", keys)
}

// GetString reads a string field, or defaultValue when unset or not a string.
func (f *FieldDataWrapper) GetString(key string, defaultValue string) string {
	valueInterface := f.Get(key)
	if valueInterface == nil {
		return defaultValue
	}
	value, ok := valueInterface.(string)
	if !ok {
		return defaultValue
	}
	return value
}

// MustGetString returns the string at key or an error when missing or not a string.
func (f *FieldDataWrapper) MustGetString(key string) (string, error) {
	valueInterface := f.Get(key)
	if valueInterface == nil {
		return "", f.errorResolve(key)
	}
	value, ok := valueInterface.(string)
	if !ok {
		return "", f.errorTypeMismatch(key)
	}
	return value, nil
}

// GetStringSlice reads a []string field, or defaultValue when unset or wrong type.
func (f *FieldDataWrapper) GetStringSlice(key string, defaultValue []string) []string {
	valueInterface := f.Get(key)
	if valueInterface == nil {
		return defaultValue
	}
	interfaceArray, ok := valueInterface.([]interface{})
	if !ok {
		return defaultValue
	}
	var value []string
	for _, strInterface := range interfaceArray {
		str, ok := strInterface.(string)
		if !ok {
			return defaultValue
		}
		value = append(value, str)
	}
	return value
}

// MustGetStringSlice returns a string slice at key or an error when missing or not a string slice.
func (f *FieldDataWrapper) MustGetStringSlice(key string) ([]string, error) {
	valueInterface := f.Get(key)
	if valueInterface == nil {
		return nil, f.errorResolve(key)
	}
	interfaceArray, ok := valueInterface.([]interface{})
	if !ok {
		return nil, f.errorTypeMismatch(key)
	}
	var value []string
	for _, strInterface := range interfaceArray {
		str, ok := strInterface.(string)
		if !ok {
			return nil, f.errorTypeMismatch(key)
		}
		value = append(value, str)
	}
	return value, nil
}

// GetBool reads a bool field, or defaultValue when unset or not a bool.
func (f *FieldDataWrapper) GetBool(key string, defaultValue bool) bool {
	valueInterface := f.Get(key)
	if valueInterface == nil {
		return defaultValue
	}
	value, ok := valueInterface.(bool)
	if !ok {
		return defaultValue
	}
	return value
}

// MustGetBool returns the bool at key or an error when missing or not a bool.
func (f *FieldDataWrapper) MustGetBool(key string) (bool, error) {
	valueInterface := f.Get(key)
	if valueInterface == nil {
		return false, f.errorResolve(key)
	}
	value, ok := valueInterface.(bool)
	if !ok {
		return false, f.errorTypeMismatch(key)
	}
	return value, nil
}

// GetBigInt parses a decimal string field into *big.Int, or returns defaultValue.
func (f *FieldDataWrapper) GetBigInt(key string, defaultValue *big.Int) *big.Int {
	valueInterface := f.Get(key)
	if valueInterface == nil {
		return defaultValue
	}
	value, ok := valueInterface.(string)
	if !ok {
		return defaultValue
	}
	return utils.ValidNumber(value)
}

// MustGetBigInt parses a required decimal string field into *big.Int.
func (f *FieldDataWrapper) MustGetBigInt(key string) (*big.Int, error) {
	valueInterface := f.Get(key)
	if valueInterface == nil {
		return nil, f.errorResolve(key)
	}
	value, ok := valueInterface.(string)
	if !ok {
		return nil, f.errorTypeMismatch(key)
	}
	return utils.ValidNumber(value), nil
}

// GetUint64 parses a decimal string field into uint64, or returns defaultValue on error.
func (f *FieldDataWrapper) GetUint64(key string, defaultValue uint64) uint64 {
	bigInt, err := f.MustGetBigInt(key)
	if err != nil {
		return defaultValue
	}
	return bigInt.Uint64()
}

// MustGetUint64 parses a required decimal string field into uint64.
func (f *FieldDataWrapper) MustGetUint64(key string) (uint64, error) {
	bigInt, err := f.MustGetBigInt(key)
	if err != nil {
		return 0, err
	}
	return bigInt.Uint64(), nil
}

// errorResolve returns a missing-field error for MustGet* helpers.
func (f *FieldDataWrapper) errorResolve(key string) error {
	return fmt.Errorf("failed to resolve value with key %v", key)
}

// errorTypeMismatch returns a wrong-type error for MustGet* helpers.
func (f *FieldDataWrapper) errorTypeMismatch(key string) error {
	return fmt.Errorf("failed to resolve value with key %v, type mismatch", key)
}
