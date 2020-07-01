package backend

import (
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/bsostech/vault-bridgex/internal/path"
)

// backend for this plugin
type ethereumBackend struct {
	*framework.Backend
}

// returns ethereumBackend
func newBackend(conf *logical.BackendConfig) (*ethereumBackend, error) {
	var b ethereumBackend
	b.Backend = &framework.Backend{
		Help: "",
		Paths: framework.PathAppend(
			path.GetPaths(),
		),
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"accounts/",
			},
		},
		Secrets:     []*framework.Secret{},
		BackendType: logical.TypeLogical,
	}
	return &b, nil
}
