// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package ethutil

import (
	"encoding/json"
	"fmt"
	"strings"

	ethtypes "github.com/ethereum/go-ethereum/core/types"
)

// ParseAccessListJSON parses an EIP-2930 access list from JSON.
func ParseAccessListJSON(raw string) (ethtypes.AccessList, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var al ethtypes.AccessList
	if err := json.Unmarshal([]byte(raw), &al); err != nil {
		return nil, fmt.Errorf("access_list JSON: %w", err)
	}
	return al, nil
}
