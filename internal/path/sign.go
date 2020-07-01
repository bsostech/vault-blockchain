package path

import (
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/bsostech/vault-bridgex/internal/model"
	"github.com/bsostech/vault-bridgex/pkg/utils"
)

type signPathConfig struct {
	basePathConfig
}

func (s *signPathConfig) getPattern() string {
	return "accounts/" + framework.GenericNameRegex("name") + "/sign"
}

func (s *signPathConfig) getHelpSynopsis() string {
	return "Sign data"
}

func (s *signPathConfig) getFields() map[string]*framework.FieldSchema {
	return map[string]*framework.FieldSchema{
		"name": {
			Type: framework.TypeString,
		},
		"data": {
			Type:        framework.TypeString,
			Description: "The data to hash (keccak) and sign.",
		},
	}
}

func (s *signPathConfig) getCallbacks() map[logical.Operation]framework.OperationFunc {
	return map[logical.Operation]framework.OperationFunc{
		logical.CreateOperation: s.sign,
	}
}

func (s *signPathConfig) sign(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	dataWrapper := model.NewFieldDataWrapper(data)
	name, err := dataWrapper.MustGetString("name")
	if err != nil {
		return nil, err
	}
	account, err := s.readAccount(ctx, req, name)
	if err != nil {
		return nil, fmt.Errorf("error reading account, %v", err)
	}
	// get data to sign
	dataToSign, err := dataWrapper.MustGetString("data")
	if err != nil {
		return nil, err
	}
	dataBytes, err := hexutil.Decode(dataToSign)
	if err != nil {
		return nil, err
	}
	hash := crypto.Keccak256Hash(dataBytes)
	// get private ecdsa key from account for signing data
	privateKey, err := account.GetPrivateKeyECDSA()
	if err != nil {
		return nil, fmt.Errorf("error reconstructing private key, %v", err)
	}
	defer utils.ZeroKey(privateKey)
	// sign data
	signature, err := crypto.Sign(hash.Bytes(), privateKey)
	if err != nil {
		return nil, err
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"signature": hexutil.Encode(signature),
			"address":   account.AddressStr,
		},
	}, nil
}
