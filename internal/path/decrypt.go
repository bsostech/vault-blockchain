package path

import (
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/bsostech/vault-bridgex/internal/model"
	"github.com/bsostech/vault-bridgex/pkg/utils"
)

type decryptPathConfig struct {
	basePathConfig
}

func (d *decryptPathConfig) getPattern() string {
	return "accounts/" + framework.GenericNameRegex("name") + "/decrypt"
}

func (d *decryptPathConfig) getHelpSynopsis() string {
	return "Decrypt data"
}

func (d *decryptPathConfig) getFields() map[string]*framework.FieldSchema {
	return map[string]*framework.FieldSchema{
		"name": {
			Type: framework.TypeString,
		},
		"data": {
			Type:        framework.TypeString,
			Description: "The data to decrypt.",
		},
	}
}

func (d *decryptPathConfig) getCallbacks() map[logical.Operation]framework.OperationFunc {
	return map[logical.Operation]framework.OperationFunc{
		logical.CreateOperation: d.decrypt,
	}
}

func (d *decryptPathConfig) decrypt(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	dataWrapper := model.NewFieldDataWrapper(data)
	name, err := dataWrapper.MustGetString("name")
	if err != nil {
		return nil, err
	}
	account, err := d.readAccount(ctx, req, name)
	if err != nil {
		return nil, fmt.Errorf("error reading account, %v", err)
	}
	// get data to decrypt
	dataToDecrypt, err := dataWrapper.MustGetString("data")
	if err != nil {
		return nil, err
	}
	dataBytes, err := hexutil.Decode(dataToDecrypt)
	if err != nil {
		return nil, err
	}
	// get private ecies key for decrypting data
	privateKeyECIES, err := account.GetPrivateKeyECIES()
	if err != nil {
		return nil, fmt.Errorf("error reconstructing private key, %v", err)
	}
	defer utils.ZeroKey(privateKeyECIES.ExportECDSA())
	// decrypt data
	plainText, err := privateKeyECIES.Decrypt(dataBytes, nil, nil)
	if err != nil {
		return nil, err
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"plaintext": hexutil.Encode(plainText),
		},
	}, nil
}
