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

	"github.com/bsostech/vault-bridgex/pkg/utils"
)

// FieldDataWrapper used to processing data from framework.FieldData
type FieldDataWrapper struct {
	*framework.FieldData
}

// NewFieldDataWrapper returns FieldDataWrapper
func NewFieldDataWrapper(data *framework.FieldData) *FieldDataWrapper {
	return &FieldDataWrapper{
		FieldData: data,
	}
}

// GetString get string value from framework.FieldData with specific key,
// returns defaultValue when the key doesn't exist or the value of the key is not type of string.
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

// MustGetString get string value from framework.FieldData with specific key,
// returns error when the key doesn't exist or the value of the key is not type of string.
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

// GetStringSlice get string slice value from framework.FieldData with specific key,
// returns defaultValue when the key doesn't exist or the value of the key is not type of string slice.
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

// MustGetStringSlice get string slice value from framework.FieldData with specific key,
// returns error when the key doesn't exist or the value of the key is not type of string slice.
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

// GetBool get bool value from framework.FieldData with specific key,
// returns defaultValue when the key doesn't exist or the value of the key is not type of bool.
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

// MustGetBool get bool value from framework.FieldData with specific key,
// returns error when the key doesn't exist or the value of the key is not type of bool.
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

// GetBigInt get big.Int value from framework.FieldData with specific key,
// returns defaultValue when the key doesn't exist or the value of the key is not type of big.Int.
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

// MustGetBigInt get big.Int value from framework.FieldData with specific key,
// returns error when the key doesn't exist or the value of the key is not type of big.Int.
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

// GetUint64 get unit64 value from framework.FieldData with specific key,
// returns defaultValue when the key doesn't exist or the value of the key is not type of unit64.
func (f *FieldDataWrapper) GetUint64(key string, defaultValue uint64) uint64 {
	bigInt, err := f.MustGetBigInt(key)
	if err != nil {
		return defaultValue
	}
	return bigInt.Uint64()
}

// MustGetUint64 get unit64 value from framework.FieldData with specific key,
// returns error when the key doesn't exist or the value of the key is not type of unit64.
func (f *FieldDataWrapper) MustGetUint64(key string) (uint64, error) {
	bigInt, err := f.MustGetBigInt(key)
	if err != nil {
		return 0, err
	}
	return bigInt.Uint64(), nil
}

func (f *FieldDataWrapper) errorResolve(key string) error {
	return fmt.Errorf("failed to resolve value with key %v", key)
}

func (f *FieldDataWrapper) errorTypeMismatch(key string) error {
	return fmt.Errorf("failed to resolve value with key %v, type mismatch", key)
}
