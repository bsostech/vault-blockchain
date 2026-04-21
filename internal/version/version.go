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

// Package version holds the plugin version reported to Vault (framework.Backend.RunningVersion).
package version

import "fmt"

// Version is the semantic version without the leading "v" (RunningVersion uses "v"+Version).
// It is a const so it cannot be overridden with -ldflags=-X; bump this value for releases.
// Name and GitCommit remain injectable at link time below.
const Version = "0.1.0"

var (
	// Name is the plugin or distribution name; optional, set at link time, e.g.
	// -ldflags="-X github.com/bsostech/vault-blockchain/internal/version.Name=vault-blockchain"
	Name string
	// GitCommit is the source revision; optional, set at link time, e.g.
	// -ldflags="-X github.com/bsostech/vault-blockchain/internal/version.GitCommit=$(git rev-parse --short HEAD)"
	GitCommit string

	// HumanVersion is a printable full version for logs and support.
	HumanVersion = fmt.Sprintf("%s v%s (%s)", Name, Version, GitCommit)
)
