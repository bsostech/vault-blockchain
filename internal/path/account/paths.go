// Package account implements Vault API paths for single-key accounts under accounts/.
package account

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/bsostech/vault-blockchain/internal/ethutil"
	"github.com/bsostech/vault-blockchain/internal/model"
	"github.com/bsostech/vault-blockchain/pkg/utils"
)

// Paths returns all single-key account paths. singleKeyAccountMu serializes account creation.
func Paths(singleKeyAccountMu *sync.Mutex) []*framework.Path {
	return []*framework.Path{
		pathListSingleKeyAccounts(),
		pathSingleKeyAccountAddress(singleKeyAccountMu),
		pathSingleKeySign(),
		pathSingleKeySignTxLegacy(),
		pathSingleKeySignTxEIP1559(),
		pathSingleKeySignEIP712(),
		pathSingleKeyEncrypt(),
		pathSingleKeyDecrypt(),
	}
}

// pathSingleKeyAccountAddress registers create/read/update for accounts/:name/address.
func pathSingleKeyAccountAddress(singleKeyAccountMu *sync.Mutex) *framework.Path {
	return &framework.Path{
		Pattern:      "accounts/" + framework.GenericNameRegex("name") + "/address",
		HelpSynopsis: "Create or read a single-key Ethereum account.",
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Logical account name in the path.",
			},
		},
		ExistenceCheck: existenceSingleKeyAccountSeed(),
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
				return handleSingleKeyAccountCreate(ctx, req, data, singleKeyAccountMu)
			},
			logical.UpdateOperation: handleSingleKeyAccountUpdate,
			logical.ReadOperation:   handleSingleKeyAccountRead,
		},
	}
}

// pathListSingleKeyAccounts registers LIST on accounts/ for stored account names.
func pathListSingleKeyAccounts() *framework.Path {
	return &framework.Path{
		Pattern:        "accounts/?",
		HelpSynopsis:   "List single-key account names that have a stored key record.",
		Fields:         map[string]*framework.FieldSchema{},
		ExistenceCheck: nil,
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: handleSingleKeyAccountsList,
		},
	}
}

// pathSingleKeySign registers Keccak256-then-ECDSA sign on accounts/:name/sign.
func pathSingleKeySign() *framework.Path {
	return &framework.Path{
		Pattern:      "accounts/" + framework.GenericNameRegex("name") + "/sign",
		HelpSynopsis: "Sign data (Keccak-256 hash then ECDSA) for a single-key account.",
		Fields: map[string]*framework.FieldSchema{
			"name": {Type: framework.TypeString},
			"data": {
				Type:        framework.TypeString,
				Description: "The data to hash (keccak) and sign.",
			},
		},
		ExistenceCheck: ExistenceSingleKeyAccount(),
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: handleSingleKeySign,
			logical.UpdateOperation: handleSingleKeySign,
		},
	}
}

// handleSingleKeySign signs hex-encoded payload data for the named single-key account.
func handleSingleKeySign(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	wrapper := model.NewFieldDataWrapper(data)
	name, err := wrapper.MustGetString("name")
	if err != nil {
		return nil, err
	}
	acct, err := ReadSingleKeyAccount(ctx, req.Storage, name)
	if err != nil {
		return RespondLoadSingleKeyAccountError(err)
	}
	pk, err := acct.GetPrivateKeyECDSA()
	if err != nil {
		return nil, fmt.Errorf("single-key sign: %w", err)
	}
	defer utils.ZeroKey(pk)

	dataToSign, err := wrapper.MustGetString("data")
	if err != nil {
		return nil, err
	}
	dataBytes, err := hexutil.Decode(dataToSign)
	if err != nil {
		return nil, fmt.Errorf("decode data hex: %w", err)
	}
	signature, err := ethutil.SignKeccak256(dataBytes, pk)
	if err != nil {
		return nil, fmt.Errorf("sign hash: %w", err)
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"signature": hexutil.Encode(signature),
			"address":   acct.AddressStr,
		},
	}, nil
}

// pathSingleKeyEncrypt registers ECIES encrypt on accounts/:name/encrypt.
func pathSingleKeyEncrypt() *framework.Path {
	return &framework.Path{
		Pattern:      "accounts/" + framework.GenericNameRegex("name") + "/encrypt",
		HelpSynopsis: "Encrypt data with the account public key (ECIES).",
		Fields: map[string]*framework.FieldSchema{
			"name": {Type: framework.TypeString},
			"data": {
				Type:        framework.TypeString,
				Description: "The data to encrypt.",
			},
		},
		ExistenceCheck: ExistenceSingleKeyAccount(),
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: handleSingleKeyEncrypt,
			logical.UpdateOperation: handleSingleKeyEncrypt,
		},
	}
}

// handleSingleKeyEncrypt encrypts hex plaintext to the account's ECIES public key.
func handleSingleKeyEncrypt(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	dataWrapper := model.NewFieldDataWrapper(data)
	name, err := dataWrapper.MustGetString("name")
	if err != nil {
		return nil, err
	}
	acct, err := ReadSingleKeyAccount(ctx, req.Storage, name)
	if err != nil {
		return RespondLoadSingleKeyAccountError(err)
	}

	dataToEncrypt, err := dataWrapper.MustGetString("data")
	if err != nil {
		return nil, err
	}
	dataBytes, err := hexutil.Decode(dataToEncrypt)
	if err != nil {
		return nil, fmt.Errorf("decode plaintext hex: %w", err)
	}
	publicKeyECIES, err := acct.GetPublicKeyECIES()
	if err != nil {
		return nil, fmt.Errorf("ecies public key: %w", err)
	}
	cipherText, err := ethutil.EncryptECIES(publicKeyECIES, dataBytes)
	if err != nil {
		return nil, fmt.Errorf("ecies encrypt: %w", err)
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"ciphertext": hexutil.Encode(cipherText),
		},
	}, nil
}

// pathSingleKeyDecrypt registers ECIES decrypt on accounts/:name/decrypt.
func pathSingleKeyDecrypt() *framework.Path {
	return &framework.Path{
		Pattern:      "accounts/" + framework.GenericNameRegex("name") + "/decrypt",
		HelpSynopsis: "Decrypt data with the account private key (ECIES).",
		Fields: map[string]*framework.FieldSchema{
			"name": {Type: framework.TypeString},
			"data": {
				Type:        framework.TypeString,
				Description: "The data to decrypt.",
			},
		},
		ExistenceCheck: ExistenceSingleKeyAccount(),
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: handleSingleKeyDecrypt,
			logical.UpdateOperation: handleSingleKeyDecrypt,
		},
	}
}

// handleSingleKeyDecrypt decrypts hex ciphertext with the account's ECIES private key.
func handleSingleKeyDecrypt(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	dataWrapper := model.NewFieldDataWrapper(data)
	name, err := dataWrapper.MustGetString("name")
	if err != nil {
		return nil, err
	}
	acct, err := ReadSingleKeyAccount(ctx, req.Storage, name)
	if err != nil {
		return RespondLoadSingleKeyAccountError(err)
	}

	dataToDecrypt, err := dataWrapper.MustGetString("data")
	if err != nil {
		return nil, err
	}
	dataBytes, err := hexutil.Decode(dataToDecrypt)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext hex: %w", err)
	}
	privateKeyECIES, err := acct.GetPrivateKeyECIES()
	if err != nil {
		return nil, fmt.Errorf("ecies private key: %w", err)
	}
	defer utils.ZeroKey(privateKeyECIES.ExportECDSA())
	plainText, err := ethutil.DecryptECIES(privateKeyECIES, dataBytes)
	if err != nil {
		return nil, fmt.Errorf("ecies decrypt: %w", err)
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"plaintext": hexutil.Encode(plainText),
		},
	}, nil
}

// pathSingleKeySignEIP712 registers EIP-712 typed-data signing on accounts/:name/sign-eip712.
func pathSingleKeySignEIP712() *framework.Path {
	return &framework.Path{
		Pattern:      "accounts/" + framework.GenericNameRegex("name") + "/sign-eip712",
		HelpSynopsis: "Sign EIP-712 typed data for a single-key account.",
		Fields: map[string]*framework.FieldSchema{
			"name": {Type: framework.TypeString},
			"domain": {
				Type:        framework.TypeString,
				Description: "EIP-712 domain as JSON (matches TypedData.domain).",
			},
			"types": {
				Type:        framework.TypeString,
				Description: "EIP-712 types map as JSON (matches TypedData.types).",
			},
			"primary_type": {
				Type:        framework.TypeString,
				Description: "Primary type name to sign.",
			},
			"message": {
				Type:        framework.TypeString,
				Description: "Message object as JSON (matches TypedData.message).",
			},
		},
		ExistenceCheck: ExistenceSingleKeyAccount(),
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: handleSingleKeySignEIP712,
			logical.UpdateOperation: handleSingleKeySignEIP712,
		},
	}
}

// handleSingleKeySignEIP712 builds TypedData from request fields and returns an EIP-712 signature.
func handleSingleKeySignEIP712(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	wrapper := model.NewFieldDataWrapper(data)
	td, err := typedDataFromWrapperSingleKey(wrapper)
	if err != nil {
		return logical.ErrorResponse("%s", err.Error()), nil
	}
	name, err := wrapper.MustGetString("name")
	if err != nil {
		return nil, err
	}
	acct, err := ReadSingleKeyAccount(ctx, req.Storage, name)
	if err != nil {
		return RespondLoadSingleKeyAccountError(err)
	}
	pk, err := acct.GetPrivateKeyECDSA()
	if err != nil {
		return nil, fmt.Errorf("single-key eip712 ecdsa key: %w", err)
	}
	defer utils.ZeroKey(pk)
	sig, err := ethutil.SignEIP712TypedData(td, pk)
	if err != nil {
		return logical.ErrorResponse("%s", err.Error()), nil
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"signature": hexutil.Encode(sig),
			"address":   acct.AddressStr,
		},
	}, nil
}

// typedDataFromWrapperSingleKey parses domain, types, primary_type, and message JSON into TypedData.
func typedDataFromWrapperSingleKey(wrapper *model.FieldDataWrapper) (*apitypes.TypedData, error) {
	domainJSON, err := wrapper.MustGetString("domain")
	if err != nil {
		return nil, err
	}
	typesJSON, err := wrapper.MustGetString("types")
	if err != nil {
		return nil, err
	}
	primaryType, err := wrapper.MustGetString("primary_type")
	if err != nil {
		return nil, err
	}
	messageJSON, err := wrapper.MustGetString("message")
	if err != nil {
		return nil, err
	}
	return ethutil.TypedDataFromJSON(domainJSON, typesJSON, primaryType, messageJSON)
}

// patternSingleKeyAccountSignTxBase returns the path prefix for single-key sign-tx endpoints.
func patternSingleKeyAccountSignTxBase() string {
	return "accounts/" + framework.GenericNameRegex("name") + "/sign-tx"
}

// pathSingleKeySignTxLegacy registers EIP-155 legacy transaction signing on .../sign-tx/legacy.
func pathSingleKeySignTxLegacy() *framework.Path {
	return &framework.Path{
		Pattern:        patternSingleKeyAccountSignTxBase() + "/legacy",
		HelpSynopsis:   "Sign an EIP-155 type-0 EVM transaction for a single-key account.",
		Fields:         singleKeySignTxType0Fields(),
		ExistenceCheck: ExistenceSingleKeyAccount(),
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: handleSingleKeySignTxType0,
			logical.UpdateOperation: handleSingleKeySignTxType0,
		},
	}
}

// singleKeySignTxType0Fields returns field schemas for type-0 transaction requests.
func singleKeySignTxType0Fields() map[string]*framework.FieldSchema {
	return map[string]*framework.FieldSchema{
		"name": {Type: framework.TypeString},
		"chain_id": {
			Type:        framework.TypeString,
			Description: "Chain ID (decimal). Alias: chainID.",
		},
		"nonce": {
			Type:        framework.TypeString,
			Description: "Transaction nonce (decimal).",
		},
		"to": {
			Type:        framework.TypeString,
			Description: "Recipient hex address. Alias: address_to. Omit for contract creation.",
		},
		"address_to": {
			Type:        framework.TypeString,
			Description: "Alias for `to`.",
		},
		"value": {
			Type:        framework.TypeString,
			Description: "Value in wei (decimal). Alias: amount. Default 0.",
		},
		"amount": {
			Type:        framework.TypeString,
			Description: "Alias for `value`.",
		},
		"gas_limit": {
			Type:        framework.TypeString,
			Description: "Gas limit (decimal).",
			Default:     "21000",
		},
		"data": {
			Type:        framework.TypeString,
			Description: "Transaction calldata hex. Optional; default empty.",
		},
		"gas_price": {
			Type:        framework.TypeString,
			Description: "Gas price in wei (decimal).",
			Default:     "0",
		},
		"chainID": {
			Type:        framework.TypeString,
			Description: "Alias for chain_id.",
		},
	}
}

// handleSingleKeySignTxType0 parses legacy tx fields and returns a signed EIP-155 type-0 transaction.
func handleSingleKeySignTxType0(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	wrapper := model.NewFieldDataWrapper(data)
	name, err := wrapper.MustGetString("name")
	if err != nil {
		return nil, err
	}
	signingKey, acct, cleanup, err := loadSingleKeySigningKeyForTx(ctx, req.Storage, name)
	if err != nil {
		return RespondLoadSingleKeyAccountError(err)
	}
	defer cleanup()

	chainID, err := wrapper.MustGetBigIntAny("chain_id", "chainID")
	if err != nil {
		return logical.ErrorResponse("%s", err.Error()), nil
	}
	gasLimit, err := wrapper.MustGetUint64("gas_limit")
	if err != nil {
		return nil, err
	}
	nonce := wrapper.GetUint64("nonce", 0)
	value := wrapper.BigIntWithAliases("value", "amount", big.NewInt(0))
	inputStr := wrapper.GetString("data", "")
	var txData []byte
	if strings.TrimSpace(inputStr) != "" {
		txData, err = hexutil.Decode(inputStr)
		if err != nil {
			return logical.ErrorResponse("invalid data hex: %s", err.Error()), nil
		}
	}
	toStr := wrapper.GetStringFirstNonEmpty("to", "address_to")
	var toPtr *common.Address
	if toStr != "" {
		addr := common.HexToAddress(toStr)
		toPtr = &addr
	}
	return signType0TxSingleKey(wrapper, chainID, nonce, gasLimit, value, txData, toPtr, signingKey, acct)
}

const txTypeLabelEthereumType0 = "legacy"

// pathSingleKeySignTxEIP1559 registers EIP-1559 transaction signing on .../sign-tx/eip1559.
func pathSingleKeySignTxEIP1559() *framework.Path {
	return &framework.Path{
		Pattern:        patternSingleKeyAccountSignTxBase() + "/eip1559",
		HelpSynopsis:   "Sign an EIP-1559 (type-2) EVM transaction for a single-key account.",
		Fields:         singleKeySignTxEIP1559Fields(),
		ExistenceCheck: ExistenceSingleKeyAccount(),
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: handleSingleKeySignTxEIP1559,
			logical.UpdateOperation: handleSingleKeySignTxEIP1559,
		},
	}
}

// singleKeySignTxEIP1559Fields returns field schemas for EIP-1559 transaction requests.
func singleKeySignTxEIP1559Fields() map[string]*framework.FieldSchema {
	return map[string]*framework.FieldSchema{
		"name": {Type: framework.TypeString},
		"chain_id": {
			Type:        framework.TypeString,
			Description: "Chain ID (decimal). Alias: chainID.",
		},
		"nonce": {
			Type:        framework.TypeString,
			Description: "Transaction nonce (decimal).",
		},
		"to": {
			Type:        framework.TypeString,
			Description: "Recipient hex address. Alias: address_to. Omit for contract creation.",
		},
		"address_to": {
			Type:        framework.TypeString,
			Description: "Alias for `to`.",
		},
		"value": {
			Type:        framework.TypeString,
			Description: "Value in wei (decimal). Alias: amount. Default 0.",
		},
		"amount": {
			Type:        framework.TypeString,
			Description: "Alias for `value`.",
		},
		"gas_limit": {
			Type:        framework.TypeString,
			Description: "Gas limit (decimal).",
			Default:     "21000",
		},
		"data": {
			Type:        framework.TypeString,
			Description: "Transaction calldata hex. Optional; default empty.",
		},
		"max_fee_per_gas": {
			Type:        framework.TypeString,
			Description: "Max fee per gas (wei, decimal). Alias: maxFeePerGas.",
		},
		"maxFeePerGas": {
			Type:        framework.TypeString,
			Description: "CamelCase alias for max_fee_per_gas.",
		},
		"max_priority_fee_per_gas": {
			Type:        framework.TypeString,
			Description: "Max priority fee per gas (wei, decimal). Alias: maxPriorityFeePerGas.",
		},
		"maxPriorityFeePerGas": {
			Type:        framework.TypeString,
			Description: "CamelCase alias for max_priority_fee_per_gas.",
		},
		"access_list": {
			Type:        framework.TypeString,
			Description: "Optional EIP-2930 access list as JSON array.",
		},
		"chainID": {
			Type:        framework.TypeString,
			Description: "Alias for chain_id.",
		},
	}
}

// handleSingleKeySignTxEIP1559 parses dynamic-fee tx fields and returns a signed type-2 transaction.
func handleSingleKeySignTxEIP1559(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	wrapper := model.NewFieldDataWrapper(data)
	name, err := wrapper.MustGetString("name")
	if err != nil {
		return nil, err
	}
	signingKey, acct, cleanup, err := loadSingleKeySigningKeyForTx(ctx, req.Storage, name)
	if err != nil {
		return RespondLoadSingleKeyAccountError(err)
	}
	defer cleanup()

	chainID, err := wrapper.MustGetBigIntAny("chain_id", "chainID")
	if err != nil {
		return logical.ErrorResponse("%s", err.Error()), nil
	}
	gasLimit, err := wrapper.MustGetUint64("gas_limit")
	if err != nil {
		return nil, err
	}
	nonce := wrapper.GetUint64("nonce", 0)
	value := wrapper.BigIntWithAliases("value", "amount", big.NewInt(0))
	inputStr := wrapper.GetString("data", "")
	var txData []byte
	if strings.TrimSpace(inputStr) != "" {
		txData, err = hexutil.Decode(inputStr)
		if err != nil {
			return logical.ErrorResponse("invalid data hex: %s", err.Error()), nil
		}
	}
	toStr := wrapper.GetStringFirstNonEmpty("to", "address_to")
	var toPtr *common.Address
	if toStr != "" {
		addr := common.HexToAddress(toStr)
		toPtr = &addr
	}
	return signEIP1559TxSingleKey(wrapper, chainID, nonce, gasLimit, value, txData, toPtr, signingKey, acct)
}

// loadSingleKeySigningKeyForTx loads the account and returns an ECDSA key plus a zeroing cleanup.
func loadSingleKeySigningKeyForTx(
	ctx context.Context,
	storage logical.Storage,
	name string,
) (signingKey *ecdsa.PrivateKey, acct *model.Account, cleanup func(), err error) {
	acct, err = ReadSingleKeyAccount(ctx, storage, name)
	if err != nil {
		return nil, nil, nil, err
	}
	signingKey, err = acct.GetPrivateKeyECDSA()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ecdsa key for single-key sign-tx: %w", err)
	}
	cleanup = func() {
		utils.ZeroKey(signingKey)
	}
	return signingKey, acct, cleanup, nil
}

// signType0TxSingleKey signs a type-0 tx and builds the Vault response map for handlers.
func signType0TxSingleKey(
	wrapper *model.FieldDataWrapper,
	chainID *big.Int,
	nonce, gasLimit uint64,
	value *big.Int,
	txData []byte,
	toPtr *common.Address,
	signingKey *ecdsa.PrivateKey,
	account *model.Account,
) (*logical.Response, error) {
	gasPrice, err := wrapper.MustGetBigIntAny("gas_price")
	if err != nil {
		return logical.ErrorResponse("%s", err.Error()), nil
	}
	signedTx, err := ethutil.SignType0EIP155(
		chainID, nonce, gasLimit, value, txData, toPtr, gasPrice, signingKey,
	)
	if err != nil {
		return nil, fmt.Errorf("sign type-0 tx: %w", err)
	}
	data, err := ethutil.SignedTxResponseData(
		signedTx, account, toPtr, value, gasPrice.String(), gasLimit, txTypeLabelEthereumType0,
	)
	if err != nil {
		return nil, err
	}
	return &logical.Response{Data: data}, nil
}

// signEIP1559TxSingleKey signs a type-2 tx with access list and builds the Vault response map.
func signEIP1559TxSingleKey(
	wrapper *model.FieldDataWrapper,
	chainID *big.Int,
	nonce, gasLimit uint64,
	value *big.Int,
	txData []byte,
	toPtr *common.Address,
	signingKey *ecdsa.PrivateKey,
	account *model.Account,
) (*logical.Response, error) {
	tip, err := wrapper.MustGetBigIntAny(
		"max_priority_fee_per_gas", "maxPriorityFeePerGas",
	)
	if err != nil {
		return logical.ErrorResponse("eip1559 requires max_priority_fee_per_gas: %s", err.Error()), nil
	}
	feeCap, err := wrapper.MustGetBigIntAny("max_fee_per_gas", "maxFeePerGas")
	if err != nil {
		return logical.ErrorResponse("eip1559 requires max_fee_per_gas: %s", err.Error()), nil
	}
	if feeCap.Cmp(tip) < 0 {
		return logical.ErrorResponse("max_fee_per_gas must be >= max_priority_fee_per_gas"), nil
	}
	al, err := ethutil.ParseAccessListJSON(wrapper.GetString("access_list", ""))
	if err != nil {
		return logical.ErrorResponse("%s", err.Error()), nil
	}
	signedTx, err := ethutil.SignEIP1559(
		chainID, nonce, gasLimit, value, txData, toPtr, tip, feeCap, al, signingKey,
	)
	if err != nil {
		return nil, fmt.Errorf("sign eip1559 tx: %w", err)
	}
	data, err := ethutil.SignedTxResponseData(
		signedTx, account, toPtr, value, feeCap.String(), gasLimit, "eip1559",
	)
	if err != nil {
		return nil, err
	}
	return &logical.Response{Data: data}, nil
}
