package backend

import (
	"context"

	"github.com/hashicorp/vault/sdk/logical"
)

// Factory returns the backend
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b, err := newBackend(conf)
	if err != nil {
		return nil, err
	}
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}
