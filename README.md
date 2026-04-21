# vault-blockchain

vault-blockchain is a Vault plugin to generate and store Ethereum private keys. It supports signing and encryption operations in Vault without revealing private keys.

It supports two modes:

- **Wallet mode (HD)**: `wallets/:wallet_id/accounts/:index/...` — accounts derived from a BIP-39 mnemonic seed at path `m/44'/60'/0'/0/<index>`.
- **Single-key account mode**: `accounts/:name/...` — one independently generated (or imported) key per logical name.

## Quick Start

```bash
# Build the plugin binary
make build-local
```

## Workflow

![1. Register](/images/workflow_01.png)
![2. Login](/images/workflow_02.png)
![3. Sign Transaction](/images/workflow_03.png)

## HCL Policies

There are two types of Vault token used with this plugin: a **master token** and a **user token**.
The master token is used only to register accounts; it cannot read credentials. Each user token is bound to a Vault identity, so it can only operate keys under that identity.

```hcl
# master token policy (see configs/blockchain_master.hcl)
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

```hcl
# user token policy (see configs/blockchain_user.hcl)
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

---

## API — Wallet Mode (HD)

Accounts are derived from a BIP-39 mnemonic at `m/44'/60'/0'/0/<index>`. The mnemonic is stored in Vault and never returned.

### Wallets

| Method | Path |
| ------ | ---- |
| `LIST` | `blockchain/wallets/` |
| `POST` | `blockchain/wallets/:wallet_id/create` — generate a random 24-word mnemonic. |
| `POST` | `blockchain/wallets/:wallet_id/import` — import an existing mnemonic. |

#### Parameters

##### `LIST blockchain/wallets/`

No parameters.

##### `POST blockchain/wallets/:wallet_id/create`

* `wallet_id` `(string: <required>)` - Logical wallet identifier in the path.

**Response:** `{ "wallet_id": "alice" }`

##### `POST blockchain/wallets/:wallet_id/import`

* `wallet_id` `(string: <required>)` - Logical wallet identifier in the path.
* `mnemonic` `(string: <required>)` - BIP-39 mnemonic phrase.

**Response:** `{ "wallet_id": "alice" }`

### Derived Accounts

| Method | Path |
| ------ | ---- |
| `POST` | `blockchain/wallets/:wallet_id/accounts/:index` |
| `GET`  | `blockchain/wallets/:wallet_id/accounts/:index` |
| `LIST` | `blockchain/wallets/:wallet_id/accounts/` |

#### Parameters

##### `POST blockchain/wallets/:wallet_id/accounts/:index`

* `wallet_id` `(string: <required>)` - Wallet identifier in the path.
* `index` `(string: <required>)` - BIP-44 address index (non-negative integer; range `0..2147483647`).

**Response:** `{ "address": "0x...", "account_index": "0", "derivation_path": "m/44'/60'/0'/0/0" }`

##### `GET blockchain/wallets/:wallet_id/accounts/:index`

* `wallet_id` `(string: <required>)` - Wallet identifier in the path.
* `index` `(string: <required>)` - BIP-44 address index.

**Response:** `{ "address": "0x...", "account_index": "0", "derivation_path": "m/44'/60'/0'/0/0" }`

##### `LIST blockchain/wallets/:wallet_id/accounts/`

* `wallet_id` `(string: <required>)` - Wallet identifier in the path.

### Wallet Sign Transaction

| Method | Path |
| ------ | ---- |
| `POST` | `blockchain/wallets/:wallet_id/accounts/:index/sign-tx/legacy` (EIP-155 type-0) |
| `POST` | `blockchain/wallets/:wallet_id/accounts/:index/sign-tx/eip1559` (London type-2) |

**Response (both):**
```json
{
  "type": "legacy",
  "transaction_hash": "0x...",
  "signed_transaction": "0x...",
  "address_from": "0x...",
  "address_to": "0x...",
  "value": "0",
  "gas_limit": 21000,
  "gas_price": "0"
}
```

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
* `access_list` `(string: <optional>)` - EIP-2930 access list as JSON array.
* `data` `(string: <optional>)` - Transaction calldata hex. Default empty.

### Wallet Sign Data

| Method | Path |
| ------ | ---- |
| `POST` | `blockchain/wallets/:wallet_id/accounts/:index/sign` |

#### Parameters

* `wallet_id` `(string: <required>)` - Wallet identifier in the path.
* `index` `(string: <required>)` - BIP-44 address index in the path.
* `data` `(string: <required>)` - Hex-encoded payload to Keccak-256 hash and sign.

**Response:** `{ "signature": "0x...", "address": "0x..." }`

### Wallet Sign EIP-712

| Method | Path |
| ------ | ---- |
| `POST` | `blockchain/wallets/:wallet_id/accounts/:index/sign-eip712` |

#### Parameters

* `wallet_id` `(string: <required>)` - Wallet identifier in the path.
* `index` `(string: <required>)` - BIP-44 address index in the path.
* `payload` `(string: <required>)` - The complete EIP-712 JSON payload (contains `domain`, `types`, `primaryType`, `message`).

**Response:** `{ "signature": "0x...", "address": "0x..." }`

### Wallet Encrypt / Decrypt Data

| Method | Path |
| ------ | ---- |
| `POST` | `blockchain/wallets/:wallet_id/accounts/:index/encrypt` |
| `POST` | `blockchain/wallets/:wallet_id/accounts/:index/decrypt` |

#### Parameters

##### `POST blockchain/wallets/:wallet_id/accounts/:index/encrypt`

* `wallet_id` `(string: <required>)` - Wallet identifier in the path.
* `index` `(string: <required>)` - BIP-44 address index in the path.
* `data` `(string: <required>)` - Hex plaintext to encrypt (ECIES).

**Response:** `{ "ciphertext": "0x..." }`

##### `POST blockchain/wallets/:wallet_id/accounts/:index/decrypt`

* `wallet_id` `(string: <required>)` - Wallet identifier in the path.
* `index` `(string: <required>)` - BIP-44 address index in the path.
* `data` `(string: <required>)` - Hex ciphertext to decrypt (ECIES).

**Response:** `{ "plaintext": "0x..." }`

---

## API — Single-Key Account Mode

Each account holds one independently generated or imported ECDSA key pair.

### Accounts

| Method | Path |
| ------ | ---- |
| `LIST` | `blockchain/accounts/` |
| `POST` | `blockchain/accounts/:name/address` — generate a new key pair. |
| `GET`  | `blockchain/accounts/:name/address` — read account metadata. |
| `POST` | `blockchain/accounts/:name/import` — import an existing private key. |

#### Parameters

##### `LIST blockchain/accounts/`

No parameters.

##### `POST blockchain/accounts/:name/address`

* `name` `(string: <required>)` - Logical account name (or UUID) in the path.

**Response:** `{ "address": "0x..." }`

##### `GET blockchain/accounts/:name/address`

* `name` `(string: <required>)` - Logical account name in the path.

**Response:** `{ "address": "0x...", "public_key": "..." }`

##### `POST blockchain/accounts/:name/import`

* `name` `(string: <required>)` - Logical account name in the path.
* `private_key` `(string: <required>)` - ECDSA private key as a hex string (optional `0x` prefix).

**Response:** `{ "address": "0x..." }`

### Sign Transaction

| Method | Path |
| ------ | ---- |
| `POST` | `blockchain/accounts/:name/sign-tx/legacy` |
| `POST` | `blockchain/accounts/:name/sign-tx/eip1559` |

**Response (both):**
```json
{
  "type": "legacy",
  "transaction_hash": "0x...",
  "signed_transaction": "0x...",
  "address_from": "0x...",
  "address_to": "0x...",
  "value": "0",
  "gas_limit": 21000,
  "gas_price": "0"
}
```

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
* `access_list` `(string: <optional>)` - EIP-2930 access list as JSON array.
* `data` `(string: <optional>)` - Transaction calldata hex. Default empty.

### Sign Data

| Method | Path |
| ------ | ---- |
| `POST` | `blockchain/accounts/:name/sign` |

#### Parameters

* `name` `(string: <required>)` - Logical account name in the path.
* `data` `(string: <required>)` - Hex-encoded payload to Keccak-256 hash and sign.

**Response:** `{ "signature": "0x...", "address": "0x..." }`

### Sign EIP-712

| Method | Path |
| ------ | ---- |
| `POST` | `blockchain/accounts/:name/sign-eip712` |

#### Parameters

* `name` `(string: <required>)` - Logical account name in the path.
* `payload` `(string: <required>)` - The complete EIP-712 JSON payload (contains `domain`, `types`, `primaryType`, `message`).

**Response:** `{ "signature": "0x...", "address": "0x..." }`

### Encrypt / Decrypt Data

| Method | Path |
| ------ | ---- |
| `POST` | `blockchain/accounts/:name/encrypt` |
| `POST` | `blockchain/accounts/:name/decrypt` |

#### Parameters

##### `POST blockchain/accounts/:name/encrypt`

* `name` `(string: <required>)` - Logical account name in the path.
* `data` `(string: <required>)` - Hex plaintext to encrypt (ECIES).

**Response:** `{ "ciphertext": "0x..." }`

##### `POST blockchain/accounts/:name/decrypt`

* `name` `(string: <required>)` - Logical account name in the path.
* `data` `(string: <required>)` - Hex ciphertext to decrypt (ECIES).

**Response:** `{ "plaintext": "0x..." }`

