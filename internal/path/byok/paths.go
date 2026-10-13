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

// Package byok implements the BYOK key exchange key (KEK) API: create, read, list, and delete KEKs.
package byok

import (
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// Paths returns all BYOK paths.
func Paths() []*framework.Path {
	return []*framework.Path{
		pathListKEKs(),
		pathKEK(),
	}
}

// pathKEK registers create/read/delete for byok/keks/:kek_name.
func pathKEK() *framework.Path {
	return &framework.Path{
		Pattern:      "byok/keks/" + framework.GenericNameRegex("kek_name"),
		HelpSynopsis: "Create, read, or delete a BYOK key exchange key (KEK).",
		HelpDescription: "A KEK is an RSA key pair used only to import wrapped private keys. " +
			"The private half never leaves the plugin; read returns the public key.",
		Fields: map[string]*framework.FieldSchema{
			"kek_name": {
				Type:        framework.TypeString,
				Description: "KEK name in the path.",
			},
			"key_size": {
				Type:        framework.TypeInt,
				Default:     defaultKEKKeySize,
				Description: "RSA modulus size in bits: 2048, 3072, or 4096.",
			},
			"ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Optional lifetime. After it elapses the KEK can no longer be used for imports.",
			},
		},
		ExistenceCheck: existenceKEK(),
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: handleKEKCreate,
			logical.UpdateOperation: handleKEKUpdate,
			logical.ReadOperation:   handleKEKRead,
			logical.DeleteOperation: handleKEKDelete,
		},
	}
}

// pathListKEKs registers LIST on byok/keks/ for stored KEK names.
func pathListKEKs() *framework.Path {
	return &framework.Path{
		Pattern:      "byok/keks/?",
		HelpSynopsis: "List BYOK key exchange key names.",
		Fields:       map[string]*framework.FieldSchema{},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: handleKEKList,
		},
	}
}
