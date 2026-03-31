# vault-blockchain

vault-blockchain is a Vault plugin to generate and store Ethereum private keys. It supports signing and encryption operations in Vault without revealing private keys.

It supports two modes:

- **Wallet mode (HD)**: `wallets/:wallet_id/accounts/:index/...` (derived accounts from a wallet seed).
- **Single-key account mode**: `accounts/:name/...` (one independently generated key per logical name).

## Workflow

![1. Register](/images/workflow_01.png)
![2. Login](/images/workflow_02.png)
![3. Sign Transaction](/images/workflow_03.png)

## HCL Policies

There are two types of token in Vault-BX. One is master token. Another is user token. We use master token to register user accounts, but not retrieve any credentials in user account. Master token is only used for registration.

```hcl
# bx_master.hcl (see configs/blockchain_master.hcl)
path "auth/userpass/users/*" {
    capabilities = [ "create" ]
}

path "identity/entity-alias" {
    capabilities = [ "read", "update" ]
}

path "identity/entity" {
    capabilities = [ "read", "update" ]
}

path "blockchain/wallets/" {
    capabilities = [ "list" ]
}

path "blockchain/accounts/" {
    capabilities = [ "list" ]
}

path "blockchain/wallets/+/create" {
    capabilities = [ "create", "update" ]
}

path "blockchain/wallets/+/import" {
    capabilities = [ "create", "update" ]
}
```

Each of user token is corresponding to identity, so it can only operate private key under that identity.

```hcl
# bx_user.hcl (see configs/blockchain_user.hcl)
path "identity/lookup/entity" {
    capabilities = [ "create", "read", "update" ]
}

path "blockchain/wallets/{{identity.entity.name}}/*" {
    capabilities = [ "create", "read", "update", "list" ]
}

# Optional: single-key account mode scoped to the Vault identity name.
path "blockchain/accounts/{{identity.entity.name}}/*" {
    capabilities = [ "create", "read", "update", "list" ]
}
```

## API

### Wallets

| Method | Path |
| ------ | ---- |
| `LIST` | `blockchain/wallets/` |
| `POST` | `blockchain/wallets/:wallet_id/create` — random 24-word mnemonic (seed stays in Vault). |
| `POST` | `blockchain/wallets/:wallet_id/import` — body **`mnemonic`** (required). |

#### Parameters

##### `LIST blockchain/wallets/`

No parameters.

##### `POST blockchain/wallets/:wallet_id/create`

* `wallet_id` `(string: <required>)` - Logical wallet identifier in the path.

##### `POST blockchain/wallets/:wallet_id/import`

* `wallet_id` `(string: <required>)` - Logical wallet identifier in the path.
* `mnemonic` `(string: <required>)` - BIP-39 mnemonic phrase.

### Derived accounts (per wallet)

| Method | Path |
| ------ | ---- |
| `POST` | `blockchain/wallets/:wallet_id/accounts/:index` |
| `LIST` | `blockchain/wallets/:wallet_id/accounts/` |
| `GET`  | `blockchain/wallets/:wallet_id/accounts/:index` |

#### Parameters

##### `POST blockchain/wallets/:wallet_id/accounts/:index`

* `wallet_id` `(string: <required>)` - Wallet identifier in the path.
* `index` `(string: <required>)` - BIP-44 address index (non-negative integer; range `0..2147483647`).

##### `LIST blockchain/wallets/:wallet_id/accounts/`

* `wallet_id` `(string: <required>)` - Wallet identifier in the path.

##### `GET blockchain/wallets/:wallet_id/accounts/:index`

* `wallet_id` `(string: <required>)` - Wallet identifier in the path.
* `index` `(string: <required>)` - BIP-44 address index (non-negative integer; range `0..2147483647`).

### Wallet sign transaction

| Method | Path |
| ------ | ---- |
| `POST` | `blockchain/wallets/:wallet_id/accounts/:index/sign-tx/legacy` (EIP-155) |
| `POST` | `blockchain/wallets/:wallet_id/accounts/:index/sign-tx/eip1559` (London / type-2) |

#### Parameters

##### `POST blockchain/wallets/:wallet_id/accounts/:index/sign-tx/legacy`

* `wallet_id` `(string: <required>)` - Wallet identifier in the path.
* `index` `(string: <required>)` - BIP-44 address index in the path.
* `chain_id` `(string: <required>)` - Chain ID (decimal). Alias: `chainID`.
* `nonce` `(string: <optional>)` - Transaction nonce (decimal).
* `to` `(string: <optional>)` - Recipient hex address. Alias: `address_to`. Omit for contract creation.
* `value` `(string: <optional>)` - Value in wei (decimal). Alias: `amount`. Default `0`.
* `gas_limit` `(string: <optional>)` - Gas limit (decimal). Default `21000`.
* `gas_price` `(string: <optional>)` - Gas price in wei (decimal). Default `0`.
* `data` `(string: <optional>)` - Transaction calldata hex. Default empty.

##### `POST blockchain/wallets/:wallet_id/accounts/:index/sign-tx/eip1559`

* `wallet_id` `(string: <required>)` - Wallet identifier in the path.
* `index` `(string: <required>)` - BIP-44 address index in the path.
* `chain_id` `(string: <required>)` - Chain ID (decimal). Alias: `chainID`.
* `nonce` `(string: <optional>)` - Transaction nonce (decimal).
* `to` `(string: <optional>)` - Recipient hex address. Alias: `address_to`. Omit for contract creation.
* `value` `(string: <optional>)` - Value in wei (decimal). Alias: `amount`. Default `0`.
* `gas_limit` `(string: <optional>)` - Gas limit (decimal). Default `21000`.
* `max_fee_per_gas` `(string: <required>)` - Max fee per gas in wei (decimal). Alias: `maxFeePerGas`.
* `max_priority_fee_per_gas` `(string: <required>)` - Max priority fee per gas in wei (decimal). Alias: `maxPriorityFeePerGas`.
* `access_list` `(string: <optional>)` - Optional EIP-2930 access list as JSON array.
* `data` `(string: <optional>)` - Transaction calldata hex. Default empty.

### Wallet sign data

| Method | Path |
| ------ | ---- |
| `POST` | `blockchain/wallets/:wallet_id/accounts/:index/sign` |

#### Parameters

* `wallet_id` `(string: <required>)` - Wallet identifier in the path.
* `index` `(string: <required>)` - BIP-44 address index in the path.
* `data` `(string: <required>)` - Hex payload to Keccak-256 and sign.

### Wallet sign EIP-712

| Method | Path |
| ------ | ---- |
| `POST` | `blockchain/wallets/:wallet_id/accounts/:index/sign-eip712` |

#### Parameters

* `wallet_id` `(string: <required>)` - Wallet identifier in the path.
* `index` `(string: <required>)` - BIP-44 address index in the path.
* `payload` `(string: <required>)` - The complete EIP-712 JSON payload (contains `domain`, `types`, `primaryType`, `message`).

### Wallet encrypt / decrypt data

| Method | Path |
| ------ | ---- |
| `POST` | `blockchain/wallets/:wallet_id/accounts/:index/encrypt` |
| `POST` | `blockchain/wallets/:wallet_id/accounts/:index/decrypt` |

#### Parameters

##### `POST blockchain/wallets/:wallet_id/accounts/:index/encrypt`

* `wallet_id` `(string: <required>)` - Wallet identifier in the path.
* `index` `(string: <required>)` - BIP-44 address index in the path.
* `data` `(string: <required>)` - Hex plaintext.

##### `POST blockchain/wallets/:wallet_id/accounts/:index/decrypt`

* `wallet_id` `(string: <required>)` - Wallet identifier in the path.
* `index` `(string: <required>)` - BIP-44 address index in the path.
* `data` `(string: <required>)` - Hex ciphertext.

### Create account

| Method | Path                        |
| ------ | --------------------------- |
| `POST` | `blockchain/accounts/:name/address` |

#### Parameters

* `name` `(string: <required>)` - Name of user. You can also use UUID of user in your system.

### Sign transaction

| Method | Path                        |
| ------ | --------------------------- |
| `POST` | `blockchain/accounts/:name/sign-tx/legacy` |
| `POST` | `blockchain/accounts/:name/sign-tx/eip1559` |

#### Parameters

##### `POST blockchain/accounts/:name/sign-tx/legacy`

* `name` `(string: <required>)` - Logical account name in the path.
* `chain_id` `(string: <required>)` - Chain ID (decimal). Alias: `chainID`.
* `nonce` `(string: <optional>)` - Transaction nonce (decimal).
* `to` `(string: <optional>)` - Recipient hex address. Alias: `address_to`. Omit for contract creation.
* `value` `(string: <optional>)` - Value in wei (decimal). Alias: `amount`. Default `0`.
* `gas_limit` `(string: <optional>)` - Gas limit (decimal). Default `21000`.
* `gas_price` `(string: <optional>)` - Gas price in wei (decimal). Default `0`.
* `data` `(string: <optional>)` - Transaction calldata hex. Default empty.

##### `POST blockchain/accounts/:name/sign-tx/eip1559`

* `name` `(string: <required>)` - Logical account name in the path.
* `chain_id` `(string: <required>)` - Chain ID (decimal). Alias: `chainID`.
* `nonce` `(string: <optional>)` - Transaction nonce (decimal).
* `to` `(string: <optional>)` - Recipient hex address. Alias: `address_to`. Omit for contract creation.
* `value` `(string: <optional>)` - Value in wei (decimal). Alias: `amount`. Default `0`.
* `gas_limit` `(string: <optional>)` - Gas limit (decimal). Default `21000`.
* `max_fee_per_gas` `(string: <required>)` - Max fee per gas in wei (decimal). Alias: `maxFeePerGas`.
* `max_priority_fee_per_gas` `(string: <required>)` - Max priority fee per gas in wei (decimal). Alias: `maxPriorityFeePerGas`.
* `access_list` `(string: <optional>)` - Optional EIP-2930 access list as JSON array.
* `data` `(string: <optional>)` - Transaction calldata hex. Default empty.

### Sign data

| Method | Path                     |
| ------ | ------------------------ |
| `POST` | `blockchain/accounts/:name/sign` |

#### Parameters

* `name` `(string: <required>)` - Name of user. You can also use UUID of user in your system.
* `data` `(string: <required>)` - The data to hash (keccak) and sign.

### Sign EIP-712

| Method | Path |
| ------ | ---- |
| `POST` | `blockchain/accounts/:name/sign-eip712` |

#### Parameters

* `name` `(string: <required>)` - Logical account name in the path.
* `payload` `(string: <required>)` - The complete EIP-712 JSON payload (contains `domain`, `types`, `primaryType`, `message`).

### Encrypt data

| Method | Path                        |
| ------ | --------------------------- |
| `POST` | `blockchain/accounts/:name/encrypt` |

#### Parameters

* `name` `(string: <required>)` - Name of user. You can also use UUID of user in your system.
* `data` `(string: <required>)` - The data to encrypt.

### Decrypt data

| Method | Path                        |
| ------ | --------------------------- |
| `POST` | `blockchain/accounts/:name/decrypt` |

#### Parameters

* `name` `(string: <required>)` - Name of user. You can also use UUID of user in your system.
* `data` `(string: <required>)` - The data to decrypt.

