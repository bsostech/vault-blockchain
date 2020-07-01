package path

import (
	"context"
	"crypto/ecdsa"
	"fmt"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"golang.org/x/crypto/sha3"

	"github.com/bsostech/vault-bridgex/internal/model"
	"github.com/bsostech/vault-bridgex/pkg/utils"
)

type createAccountPathConfig struct {
	basePathConfig
}

func (c *createAccountPathConfig) getPattern() string {
	name := framework.GenericNameRegex("name")
	fmt.Println("name: ", name)
	return "accounts/" + name + "/address"
}

func (c *createAccountPathConfig) getHelpSynopsis() string {
	return "Create an Ethereum account using a generated passphrase"
}

func (c *createAccountPathConfig) getFields() map[string]*framework.FieldSchema {
	return map[string]*framework.FieldSchema{
		"name": {
			Type: framework.TypeString,
		},
	}
}

func (c *createAccountPathConfig) getCallbacks() map[logical.Operation]framework.OperationFunc {
	return map[logical.Operation]framework.OperationFunc{
		logical.CreateOperation: c.createAccount,
	}
}

func (c *createAccountPathConfig) createAccount(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// create private key
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, err
	}
	defer utils.ZeroKey(privateKey)
	privateKeyBytes := crypto.FromECDSA(privateKey)
	privateKeyString := hexutil.Encode(privateKeyBytes)[2:]
	// create public key
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("error casting public key to ECDSA")
	}
	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)
	publicKeyString := hexutil.Encode(publicKeyBytes)[4:]
	// create address
	hash := sha3.NewLegacyKeccak256()
	_, err = hash.Write(publicKeyBytes[1:])
	if err != nil {
		return nil, err
	}
	address := hexutil.Encode(hash.Sum(nil)[12:])
	// store account info
	account := model.NewAccount(address, privateKeyString, publicKeyString)
	entry, err := logical.StorageEntryJSON(req.Path, account)
	if err != nil {
		return nil, err
	}
	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return nil, err
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"address": account.AddressStr,
		},
	}, nil
}
