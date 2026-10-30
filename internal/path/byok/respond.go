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

// Package byok holds helpers shared by the BYOK export paths.
package byok

import (
	"net/http"

	"github.com/hashicorp/vault/sdk/logical"
)

// MaxKIDLength bounds the kid accepted on export, which is copied into the blob header.
const MaxKIDLength = 1024

// InvalidKEKPublicKeyMessage is the message returned with invalid_kek_public_key on export.
const InvalidKEKPublicKeyMessage = "kek_public_key_pem must be an RSA public key of 2048, 3072, or 4096 bits"

// RespondCode returns an error response whose message starts with a machine-readable code, with the given
// HTTP status. A 400 is a plain Vault error response.
func RespondCode(req *logical.Request, status int, code, msg string) (*logical.Response, error) {
	resp := logical.ErrorResponse("%s: %s", code, msg)
	if status == http.StatusBadRequest {
		return resp, nil
	}
	return logical.RespondWithStatusCode(resp, req, status)
}
