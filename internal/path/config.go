package path

import (
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type config interface {
	getPattern() string
	getHelpSynopsis() string
	getFields() map[string]*framework.FieldSchema
	getExistenceFunc() framework.ExistenceFunc
	getCallbacks() map[logical.Operation]framework.OperationFunc
}
