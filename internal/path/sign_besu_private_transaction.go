package path

import (
	"context"
	"fmt"

	"github.com/bsostech/go-besu/privacy"
	"github.com/bsostech/go-besu/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/bsostech/vault-bridgex/internal/model"
	"github.com/bsostech/vault-bridgex/pkg/utils"
)

type signBesuPrivateTransactionPathConfig struct {
	basePathConfig
}

func (s *signBesuPrivateTransactionPathConfig) getPattern() string {
	return "accounts/" + framework.GenericNameRegex("name") + "/sign-besu-private-tx"
}

func (s *signBesuPrivateTransactionPathConfig) getHelpSynopsis() string {
	return "Sign a provided besu private transaction."
}

func (s *signBesuPrivateTransactionPathConfig) getFields() map[string]*framework.FieldSchema {
	return map[string]*framework.FieldSchema{
		"name": {
			Type: framework.TypeString,
		},
		"address_to": {
			Type:        framework.TypeString,
			Description: "The address of the account to send tx to.",
		},
		"chainID": {
			Type:        framework.TypeString,
			Description: "The chain ID of the blockchain network.",
		},
		"data": {
			Type:        framework.TypeString,
			Description: "The data to sign.",
		},
		"amount": {
			Type:        framework.TypeString,
			Description: "Amount of ETH (in wei).",
			Default:     "0",
		},
		"private_nonce": {
			Type:        framework.TypeString,
			Description: "The besu private transaction nonce.",
		},
		"gas_limit": {
			Type:        framework.TypeString,
			Description: "The gas limit for the transaction - defaults to 21000.",
			Default:     "21000",
		},
		"gas_price": {
			Type:        framework.TypeString,
			Description: "The gas price for the transaction in wei.",
			Default:     "0",
		},
		"private_from": {
			Type:        framework.TypeString,
			Description: "The privateFrom",
		},
		"private_for": {
			Type:        framework.TypeStringSlice,
			Description: "The privateFor",
		},
	}
}

func (s *signBesuPrivateTransactionPathConfig) getCallbacks() map[logical.Operation]framework.OperationFunc {
	return map[logical.Operation]framework.OperationFunc{
		logical.CreateOperation: s.signPrivateTransaction,
	}
}

func (s *signBesuPrivateTransactionPathConfig) signPrivateTransaction(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	dataWrapper := model.NewFieldDataWrapper(data)
	name, err := dataWrapper.MustGetString("name")
	if err != nil {
		return nil, err
	}
	account, err := s.readAccount(ctx, req, name)
	if err != nil {
		return nil, fmt.Errorf("error reading account, %v", err)
	}
	chainID, err := dataWrapper.MustGetBigInt("chainID")
	if err != nil {
		return nil, err
	}
	amount, err := dataWrapper.MustGetBigInt("amount")
	if err != nil {
		return nil, err
	}
	gasLimit, err := dataWrapper.MustGetUint64("gas_limit")
	if err != nil {
		return nil, err
	}
	gasPrice, err := dataWrapper.MustGetBigInt("gas_price")
	if err != nil {
		return nil, err
	}
	privateNonce := dataWrapper.GetUint64("private_nonce", 0)
	// parse private from
	privateFromString, err := dataWrapper.MustGetString("private_from")
	if err != nil {
		return nil, err
	}
	privateFromKey, err := privacy.ToPublicKey(privateFromString)
	if err != nil {
		return nil, fmt.Errorf("invalid privateFrom, %v", err)
	}
	privateFrom := []byte(privateFromKey)
	// parse private for
	privateForStringSlice := dataWrapper.GetStringSlice("private_for", []string{}) // empty for self transaction
	privateFor := make([][]byte, len(privateForStringSlice))
	var publicKey privacy.PublicKey
	for _, s := range privateForStringSlice {
		publicKey, err = privacy.ToPublicKey(s)
		if err != nil {
			return nil, fmt.Errorf("invalid privateFor, %v", err)
		}
		privateFor = append(privateFor, publicKey)
	}
	// get data to sign
	inputData, err := dataWrapper.MustGetString("data")
	if err != nil {
		return nil, err
	}
	var txDataToSign []byte
	txDataToSign, err = hexutil.Decode(inputData)
	if err != nil {
		return nil, err
	}
	// get transaction to sign
	address := dataWrapper.GetString("address_to", "")
	var besuTx *types.PrivateTransaction
	if address == "" {
		besuTx = types.NewContractCreation(privateNonce, amount, gasLimit, gasPrice, txDataToSign, privateFrom, privateFor)
	} else {
		contractAddress := common.HexToAddress(address)
		besuTx = types.NewTransaction(privateNonce, &contractAddress, amount, gasLimit, gasPrice, txDataToSign, privateFrom, privateFor)
	}
	// get private ecdsa key from account for signing data
	privateKeyECDSA, err := account.GetPrivateKeyECDSA()
	if err != nil {
		return nil, fmt.Errorf("error reconstructing private key, %v", err)
	}
	defer utils.ZeroKey(privateKeyECDSA)
	// Sign Tx
	besuSignedTx, err := besuTx.SignTx(chainID, privateKeyECDSA)
	if err != nil {
		return nil, err
	}
	besuRawTxData, err := rlp.EncodeToBytes(besuSignedTx)
	if err != nil {
		return nil, err
	}
	for i := range besuRawTxData {
		tmp, _ := rlp.EncodeToBytes(besuSignedTx)
		tmp = append(tmp[:1], tmp[i:]...)
		var txSlice []interface{}
		err = rlp.DecodeBytes(tmp, &txSlice)
		if err != nil {
			continue
		}
		if len(txSlice) == 12 { // 12 args in private transaction
			besuRawTxData = tmp
			break
		}
	}
	return &logical.Response{
		Data: map[string]interface{}{
			// "transaction_hash":   signedTx.Hash().Hex(),
			"signed_transaction": hexutil.Encode(besuRawTxData),
			"address_from":       account.AddressStr,
			"address_to":         address,
			"amount":             amount.String(),
			"gas_price":          gasPrice.String(),
			"gas_limit":          gasLimit,
		},
	}, nil
}
