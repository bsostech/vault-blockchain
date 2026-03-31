// Package wallet implements Vault API paths for HD wallets under wallets/.
package wallet

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/bsostech/vault-blockchain/internal/ethutil"
	"github.com/bsostech/vault-blockchain/internal/model"
	"github.com/bsostech/vault-blockchain/pkg/utils"
)

// Paths returns all wallet (HD) paths.
func Paths() []*framework.Path {
	return []*framework.Path{
		pathListWallets(),
		pathWalletCreateAuto(),
		pathWalletImport(),
		pathDerivedAccount(),
		pathListDerivedAccounts(),
		pathWalletSignTxLegacy(),
		pathWalletSignTxEIP1559(),
		pathWalletSign(),
		pathWalletSignEIP712(),
		pathWalletEncrypt(),
		pathWalletDecrypt(),
	}
}

// pathListWallets registers LIST on wallets/ for wallet_id values with a seed.
func pathListWallets() *framework.Path {
	return &framework.Path{
		Pattern:        "wallets/?",
		HelpSynopsis:   "List wallet_id values that have a stored seed",
		Fields:         map[string]*framework.FieldSchema{},
		ExistenceCheck: nil,
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: handleListWallets,
		},
	}
}

// pathWalletCreateAuto registers wallets/:wallet_id/create for auto-generated mnemonics.
func pathWalletCreateAuto() *framework.Path {
	return &framework.Path{
		Pattern:      "wallets/" + framework.GenericNameRegex("wallet_id") + "/create",
		HelpSynopsis: "Create a new wallet with a randomly generated BIP-39 mnemonic (24 words).",
		Fields: map[string]*framework.FieldSchema{
			"wallet_id": {
				Type:        framework.TypeString,
				Description: "Logical wallet identifier in the path.",
			},
		},
		ExistenceCheck: ExistenceWalletSeed(),
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
				return handleWalletCreateAuto(ctx, req, data)
			},
			logical.UpdateOperation: func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
				_ = ctx
				if _, ok := data.Get("wallet_id").(string); !ok {
					return logical.ErrorResponse("wallet_id is required"), nil
				}
				return respondWalletConflict(req)
			},
		},
	}
}

// pathWalletImport registers wallets/:wallet_id/import for user-supplied mnemonics.
func pathWalletImport() *framework.Path {
	return &framework.Path{
		Pattern:      "wallets/" + framework.GenericNameRegex("wallet_id") + "/import",
		HelpSynopsis: "Create a wallet from an existing BIP-39 mnemonic.",
		Fields: map[string]*framework.FieldSchema{
			"wallet_id": {
				Type:        framework.TypeString,
				Description: "Logical wallet identifier in the path.",
			},
			"mnemonic": {
				Type:        framework.TypeString,
				Required:    true,
				Description: "BIP-39 mnemonic phrase for this wallet.",
			},
		},
		ExistenceCheck: ExistenceWalletSeed(),
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
				return handleWalletImport(ctx, req, data)
			},
			logical.UpdateOperation: func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
				_ = ctx
				if _, err := model.NewFieldDataWrapper(data).MustGetString("wallet_id"); err != nil {
					return logical.ErrorResponse("%s", err.Error()), nil
				}
				return respondWalletConflict(req)
			},
		},
	}
}

// pathDerivedAccount registers CRUD-style access on wallets/:wallet_id/accounts/:index.
func pathDerivedAccount() *framework.Path {
	walletID := framework.GenericNameRegex("wallet_id")
	return &framework.Path{
		Pattern:      "wallets/" + walletID + "/accounts/(?P<index>\\d+)",
		HelpSynopsis: "Create, update, or read a derived Ethereum account at m/44'/60'/0'/0/<index>",
		Fields: map[string]*framework.FieldSchema{
			"wallet_id": {
				Type:        framework.TypeString,
				Description: "Wallet identifier.",
			},
			"index": {
				Type:        framework.TypeString,
				Description: "BIP-44 address index (non-negative integer, max 2147483647).",
			},
		},
		ExistenceCheck: ExistenceWalletDerivedAccount(),
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: handleDerivedAccountRead,
			logical.CreateOperation: func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
				return handleDerivedAccountCreate(ctx, req, data)
			},
			logical.UpdateOperation: handleDerivedAccountUpdateConflict,
		},
	}
}

// pathListDerivedAccounts registers LIST on wallets/:wallet_id/accounts/ for index keys.
func pathListDerivedAccounts() *framework.Path {
	walletID := framework.GenericNameRegex("wallet_id")
	return &framework.Path{
		Pattern:      "wallets/" + walletID + "/accounts/?",
		HelpSynopsis: "List derived account indices with address and derivation_path",
		Fields: map[string]*framework.FieldSchema{
			"wallet_id": {Type: framework.TypeString},
		},
		ExistenceCheck: nil,
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: handleListDerivedAccounts,
		},
	}
}

// patternWalletAccountSignTxBase returns the path prefix for wallet sign-tx endpoints.
func patternWalletAccountSignTxBase() string {
	walletID := framework.GenericNameRegex("wallet_id")
	return "wallets/" + walletID + "/accounts/(?P<index>\\d+)/sign-tx"
}

// walletSignTxType0Fields returns field schemas for wallet legacy transaction requests.
func walletSignTxType0Fields() map[string]*framework.FieldSchema {
	return map[string]*framework.FieldSchema{
		"wallet_id": {Type: framework.TypeString},
		"index":     {Type: framework.TypeString},
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

// pathWalletSignTxLegacy registers EIP-155 legacy signing on .../sign-tx/legacy.
func pathWalletSignTxLegacy() *framework.Path {
	return &framework.Path{
		Pattern:        patternWalletAccountSignTxBase() + "/legacy",
		HelpSynopsis:   "Sign an EIP-155 type-0 EVM transaction (fixed gas price).",
		Fields:         walletSignTxType0Fields(),
		ExistenceCheck: ExistenceWalletDerivedAccount(),
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: handleWalletSignTxType0,
			// Vault maps HTTP writes to Update when ExistenceCheck is true; register same handler.
			logical.UpdateOperation: handleWalletSignTxType0,
		},
	}
}

// handleWalletSignTxType0 parses legacy tx fields and returns a signed EIP-155 type-0 transaction.
func handleWalletSignTxType0(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	wrapper := model.NewFieldDataWrapper(data)
	walletID, err := wrapper.MustGetString("wallet_id")
	if err != nil {
		return nil, err
	}
	indexStr, err := wrapper.MustGetString("index")
	if err != nil {
		return nil, err
	}
	signingKey, acct, cleanup, err := loadSigningKeyForTx(ctx, req.Storage, walletID, indexStr)
	if err != nil {
		return RespondLoadWalletKeyError(err)
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
	return signType0Tx(wrapper, chainID, nonce, gasLimit, value, txData, toPtr, signingKey, acct)
}

// walletSignTxEIP1559Fields returns field schemas for wallet EIP-1559 transaction requests.
func walletSignTxEIP1559Fields() map[string]*framework.FieldSchema {
	return map[string]*framework.FieldSchema{
		"wallet_id": {Type: framework.TypeString},
		"index":     {Type: framework.TypeString},
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

// pathWalletSignTxEIP1559 registers EIP-1559 signing on .../sign-tx/eip1559.
func pathWalletSignTxEIP1559() *framework.Path {
	return &framework.Path{
		Pattern:        patternWalletAccountSignTxBase() + "/eip1559",
		HelpSynopsis:   "Sign an EIP-1559 (type-2) EVM transaction with dynamic fees.",
		Fields:         walletSignTxEIP1559Fields(),
		ExistenceCheck: ExistenceWalletDerivedAccount(),
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: handleWalletSignTxEIP1559,
			logical.UpdateOperation: handleWalletSignTxEIP1559,
		},
	}
}

// handleWalletSignTxEIP1559 parses dynamic-fee tx fields and returns a signed type-2 transaction.
func handleWalletSignTxEIP1559(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	wrapper := model.NewFieldDataWrapper(data)
	walletID, err := wrapper.MustGetString("wallet_id")
	if err != nil {
		return nil, err
	}
	indexStr, err := wrapper.MustGetString("index")
	if err != nil {
		return nil, err
	}
	signingKey, acct, cleanup, err := loadSigningKeyForTx(ctx, req.Storage, walletID, indexStr)
	if err != nil {
		return RespondLoadWalletKeyError(err)
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
	return signEIP1559Tx(wrapper, chainID, nonce, gasLimit, value, txData, toPtr, signingKey, acct)
}

// loadSigningKeyForTx loads the derived signing key and builds a model.Account for tx response helpers.
func loadSigningKeyForTx(
	ctx context.Context,
	storage logical.Storage,
	walletID, indexStr string,
) (signingKey *ecdsa.PrivateKey, account *model.Account, cleanup func(), err error) {
	pk, derived, err := LoadWalletDerivedPrivateKey(ctx, storage, walletID, indexStr)
	if err != nil {
		return nil, nil, nil, err
	}
	signingKey = pk
	account = &model.Account{AddressStr: derived.Address}
	cleanup = func() {
		utils.ZeroKey(pk)
	}
	return signingKey, account, cleanup, nil
}

// txTypeLabelEthereumType0 is the response `type` value for EIP-155 type-0 (Ethereum convention).
const txTypeLabelEthereumType0 = "legacy"

// signType0Tx signs a type-0 tx for a wallet-derived account and builds the Vault response map.
func signType0Tx(
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
		signedTx,
	)
	if err != nil {
		return nil, err
	}
	return &logical.Response{Data: data}, nil
}

// signEIP1559Tx signs a type-2 tx with access list and builds the Vault response map.
func signEIP1559Tx(
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
		signedTx,
	)
	if err != nil {
		return nil, err
	}
	return &logical.Response{Data: data}, nil
}

// pathWalletSign registers Keccak256-then-ECDSA sign on wallets/.../accounts/:index/sign.
func pathWalletSign() *framework.Path {
	walletID := framework.GenericNameRegex("wallet_id")
	return &framework.Path{
		Pattern:      "wallets/" + walletID + "/accounts/(?P<index>\\d+)/sign",
		HelpSynopsis: "Sign data (Keccak-256 hash then ECDSA) for a wallet-derived account",
		Fields: map[string]*framework.FieldSchema{
			"wallet_id": {Type: framework.TypeString},
			"index":     {Type: framework.TypeString},
			"data": {
				Type:        framework.TypeString,
				Description: "The data to hash (keccak) and sign.",
			},
		},
		ExistenceCheck: ExistenceWalletDerivedAccount(),
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: handleWalletSign,
			logical.UpdateOperation: handleWalletSign,
		},
	}
}

// handleWalletSign signs hex-encoded payload data for a wallet-derived account.
func handleWalletSign(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	dataWrapper := model.NewFieldDataWrapper(data)
	walletID, err := dataWrapper.MustGetString("wallet_id")
	if err != nil {
		return nil, err
	}
	indexStr, err := dataWrapper.MustGetString("index")
	if err != nil {
		return nil, err
	}
	pk, derived, err := LoadWalletDerivedPrivateKey(ctx, req.Storage, walletID, indexStr)
	if err != nil {
		return RespondLoadWalletKeyError(err)
	}
	defer utils.ZeroKey(pk)

	dataToSign, err := dataWrapper.MustGetString("data")
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
			"address":   derived.Address,
		},
	}, nil
}

// pathWalletSignEIP712 registers EIP-712 typed-data signing on wallets/.../sign-eip712.
func pathWalletSignEIP712() *framework.Path {
	walletID := framework.GenericNameRegex("wallet_id")
	return &framework.Path{
		Pattern:      "wallets/" + walletID + "/accounts/(?P<index>\\d+)/sign-eip712",
		HelpSynopsis: "Sign EIP-712 typed data for a wallet-derived account",
		Fields: map[string]*framework.FieldSchema{
			"wallet_id": {Type: framework.TypeString},
			"index":     {Type: framework.TypeString},
			"payload": {
				Type:        framework.TypeString,
				Description: "The complete EIP-712 JSON payload (contains domain, types, primaryType, message).",
			},
		},
		ExistenceCheck: ExistenceWalletDerivedAccount(),
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: handleWalletSignEIP712,
			logical.UpdateOperation: handleWalletSignEIP712,
		},
	}
}

// handleWalletSignEIP712 parses a TypedData payload and returns an EIP-712 signature for a derived address.
func handleWalletSignEIP712(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	wrapper := model.NewFieldDataWrapper(data)
	payload, err := wrapper.MustGetString("payload")
	if err != nil {
		return nil, err
	}
	td, err := typedDataFromPayloadWallet(payload)
	if err != nil {
		return logical.ErrorResponse("%s", err.Error()), nil
	}
	walletID, err := wrapper.MustGetString("wallet_id")
	if err != nil {
		return nil, err
	}
	indexStr, err := wrapper.MustGetString("index")
	if err != nil {
		return nil, err
	}
	pk, derived, err := LoadWalletDerivedPrivateKey(ctx, req.Storage, walletID, indexStr)
	if err != nil {
		return RespondLoadWalletKeyError(err)
	}
	defer utils.ZeroKey(pk)
	sig, err := ethutil.SignEIP712TypedData(td, pk)
	if err != nil {
		return logical.ErrorResponse("%s", err.Error()), nil
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"signature": hexutil.Encode(sig),
			"address":   derived.Address,
		},
	}, nil
}

// typedDataFromPayloadWallet parses a single JSON payload into go-ethereum TypedData.
//
// Notes:
// - Standard EIP-712 uses "primaryType" (camelCase). For ergonomics, we also accept
//   "primary_type" (snake_case) and map it to TypedData.PrimaryType.
func typedDataFromPayloadWallet(payload string) (*apitypes.TypedData, error) {
	payload = strings.TrimSpace(payload)
	if payload == "" {
		return nil, fmt.Errorf("payload is required")
	}

	var td apitypes.TypedData
	if err := json.Unmarshal([]byte(payload), &td); err != nil {
		return nil, fmt.Errorf("invalid eip712 payload JSON: %w", err)
	}
	if strings.TrimSpace(td.PrimaryType) == "" {
		var raw map[string]json.RawMessage
		if err := json.Unmarshal([]byte(payload), &raw); err == nil {
			if v, ok := raw["primary_type"]; ok {
				var pt string
				if err := json.Unmarshal(v, &pt); err == nil {
					td.PrimaryType = pt
				}
			}
		}
	}
	td.PrimaryType = strings.TrimSpace(td.PrimaryType)
	if td.PrimaryType == "" {
		return nil, fmt.Errorf("primaryType is required")
	}
	return &td, nil
}

// pathWalletEncrypt registers ECIES encrypt on wallets/.../accounts/:index/encrypt.
func pathWalletEncrypt() *framework.Path {
	walletID := framework.GenericNameRegex("wallet_id")
	return &framework.Path{
		Pattern:      "wallets/" + walletID + "/accounts/(?P<index>\\d+)/encrypt",
		HelpSynopsis: "Encrypt data with the derived account public key (ECIES)",
		Fields: map[string]*framework.FieldSchema{
			"wallet_id": {Type: framework.TypeString},
			"index":     {Type: framework.TypeString},
			"data": {
				Type:        framework.TypeString,
				Description: "The data to encrypt.",
			},
		},
		ExistenceCheck: ExistenceWalletDerivedAccount(),
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: handleWalletEncrypt,
			logical.UpdateOperation: handleWalletEncrypt,
		},
	}
}

// handleWalletEncrypt encrypts hex plaintext to the derived account ECIES public key.
func handleWalletEncrypt(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	dataWrapper := model.NewFieldDataWrapper(data)
	walletID, err := dataWrapper.MustGetString("wallet_id")
	if err != nil {
		return nil, err
	}
	indexStr, err := dataWrapper.MustGetString("index")
	if err != nil {
		return nil, err
	}
	pk, _, err := LoadWalletDerivedPrivateKey(ctx, req.Storage, walletID, indexStr)
	if err != nil {
		return RespondLoadWalletKeyError(err)
	}
	defer utils.ZeroKey(pk)

	dataToEncrypt, err := dataWrapper.MustGetString("data")
	if err != nil {
		return nil, err
	}
	dataBytes, err := hexutil.Decode(dataToEncrypt)
	if err != nil {
		return nil, fmt.Errorf("decode plaintext hex: %w", err)
	}
	publicKeyECIES := ecies.ImportECDSAPublic(&pk.PublicKey)
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

// pathWalletDecrypt registers ECIES decrypt on wallets/.../accounts/:index/decrypt.
func pathWalletDecrypt() *framework.Path {
	walletID := framework.GenericNameRegex("wallet_id")
	return &framework.Path{
		Pattern:      "wallets/" + walletID + "/accounts/(?P<index>\\d+)/decrypt",
		HelpSynopsis: "Decrypt data with the derived account private key (ECIES)",
		Fields: map[string]*framework.FieldSchema{
			"wallet_id": {Type: framework.TypeString},
			"index":     {Type: framework.TypeString},
			"data": {
				Type:        framework.TypeString,
				Description: "The data to decrypt.",
			},
		},
		ExistenceCheck: ExistenceWalletDerivedAccount(),
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: handleWalletDecrypt,
			logical.UpdateOperation: handleWalletDecrypt,
		},
	}
}

// handleWalletDecrypt decrypts hex ciphertext with the derived account ECIES private key.
func handleWalletDecrypt(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	dataWrapper := model.NewFieldDataWrapper(data)
	walletID, err := dataWrapper.MustGetString("wallet_id")
	if err != nil {
		return nil, err
	}
	indexStr, err := dataWrapper.MustGetString("index")
	if err != nil {
		return nil, err
	}
	pk, _, err := LoadWalletDerivedPrivateKey(ctx, req.Storage, walletID, indexStr)
	if err != nil {
		return RespondLoadWalletKeyError(err)
	}
	defer utils.ZeroKey(pk)

	dataToDecrypt, err := dataWrapper.MustGetString("data")
	if err != nil {
		return nil, err
	}
	dataBytes, err := hexutil.Decode(dataToDecrypt)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext hex: %w", err)
	}
	privateKeyECIES := ecies.ImportECDSA(pk)
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
