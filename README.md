# vault-blockchain

vault-blockchain is a Vault plugin to generate and store Ethereum private keys. It supports signing and encryption operations in Vault without revealing private keys.

It supports two modes:

- **Wallet mode (HD)**: `wallets/:wallet_id/...` — BIP-39 mnemonic seed; derived Ethereum accounts at `m/44'/60'/0'/0/<index>` using a per-wallet counter. Create one account per write on `.../accounts/`, up to **10000** per write on `.../accounts/batch`, **`LIST`** on `.../accounts/` lists stored indices, and **`GET .../accounts?start=N&end=M`** returns address metadata for an inclusive **`start`..`end`** range (max **10000** indices per call).
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

Accounts are derived from a BIP-39 mnemonic at `m/44'/60'/0'/0/<index>`. The mnemonic is stored in Vault and never returned. Indices are allocated in order by a **counter** (with per-wallet locking on each Vault active node). `LIST .../accounts/` returns **all** stored index keys (sorted only; no range filter). For a bounded inclusive range of **`start`..`end`** with **address** and **derivation_path** for each index, use **`GET .../accounts?start=N&end=M`** (see below). `LIST` is not a preview of unused counter slots.

### Wallets

| Method | Path |
| ------ | ---- |
| `LIST` | `blockchain/wallets/` |
| `POST` | `blockchain/wallets/:wallet_id/create` — generate a random 24-word mnemonic. |
| `POST` | `blockchain/wallets/:wallet_id/import` — import an existing mnemonic. |

#### Parameters

##### `LIST blockchain/wallets/`

No parameters.

**Response:** Vault list payload with `keys` — sorted `wallet_id` strings that appear under the `wallets/` storage prefix (in normal operation these correspond to wallets created via `create` or `import`).

##### `POST blockchain/wallets/:wallet_id/create`

* `wallet_id` `(string: <required>)` - Logical wallet identifier in the path.

**Response:** `{ "wallet_id": "alice" }`

##### `POST blockchain/wallets/:wallet_id/import`

* `wallet_id` `(string: <required>)` - Logical wallet identifier in the path.
* `mnemonic` `(string: <required>)` - BIP-39 mnemonic phrase.

**Response:** `{ "wallet_id": "alice" }`

### Derived Accounts

New accounts are assigned the next free **address index** from a per-wallet counter (serialized with a mutex on each Vault active node). Storage holds public metadata per index; the mnemonic is never returned.

| Method | Path |
| ------ | ---- |
| `LIST` | `blockchain/wallets/:wallet_id/accounts/` |
| `POST` | `blockchain/wallets/:wallet_id/accounts/` — create **one** derived account at the next counter index (`Create` and `Update` are both wired for Vault HTTP routing). |
| `POST` | `blockchain/wallets/:wallet_id/accounts/batch` — create **many** accounts in one request (see below). |
| `GET`  | `blockchain/wallets/:wallet_id/accounts` — read metadata for every index in an inclusive **`start`..`end`** range (query params; see below). |
| `GET`  | `blockchain/wallets/:wallet_id/accounts/:index` — read stored address and derivation path for a **decimal** non-negative index (`0..2147483647`). |

#### Parameters

##### `LIST blockchain/wallets/:wallet_id/accounts/`

* `wallet_id` `(string: <required>)` - Wallet identifier in the path.

**Response:** Vault list payload with `keys` — sorted decimal index strings for which a derived account record exists (not the counter “next index” itself). There is **no** `start`/`end` filtering on `LIST`; use **`GET .../accounts?start=N&end=M`** for a bounded index range with full metadata.

##### `GET blockchain/wallets/:wallet_id/accounts`

Range read — returns full metadata for every index in an inclusive `start`..`end` window. Use `vault read` or HTTP `GET` with query parameters.

```bash
vault read blockchain/wallets/alice/accounts start=2 end=5
# curl equivalent:
# curl -H "X-Vault-Token: $VAULT_TOKEN" \
#   "$VAULT_ADDR/v1/blockchain/wallets/alice/accounts?start=2&end=5"
```

* `wallet_id` `(string: <required>)` - Wallet identifier in the path.
* `start` `(string: <required>)` - Inclusive lower index (decimal non-negative; max `2147483647`).
* `end` `(string: <required>)` - Inclusive upper index (same bounds). Must satisfy `start <= end`.
* Span limit: **`end - start + 1` ≤ `10000`**. Every index in the range must already exist in storage; otherwise the plugin returns an error (no partial payload).

**Response:** `{ "wallet_id": "...", "accounts": [ { "account_index": "...", "address": "0x...", "derivation_path": "..." }, ... ] }` — one element per index from `start` through `end`, in order.

##### `POST blockchain/wallets/:wallet_id/accounts/`

* `wallet_id` `(string: <required>)` - Wallet identifier in the path.

**Response:** `{ "address": "0x...", "account_index": "0", "derivation_path": "m/44'/60'/0'/0/0" }`

##### `POST blockchain/wallets/:wallet_id/accounts/batch`

* `wallet_id` `(string: <required>)` - Wallet identifier in the path.
* `count` `(string: <required>)` - Number of accounts to create in one call. Must be a positive integer **`1`..`10000`**. The plugin rejects the **entire** request up front if any index in the batch would exceed the BIP-44 address index maximum (`2147483647`), so you do not get a half-applied batch for that case.

**Response:** `{ "wallet_id": "...", "accounts": [ { "account_index": "...", "address": "0x...", "derivation_path": "..." }, ... ] }`

If the batch is rejected because it would exceed the BIP-44 index bound, **no** new accounts are written for that request. If a **storage** error occurs partway through an otherwise valid batch, accounts already persisted in that call remain (there is no multi-key transaction).

##### `GET blockchain/wallets/:wallet_id/accounts/:index`

* `wallet_id` `(string: <required>)` - Wallet identifier in the path.
* `index` `(string: <required>)` - BIP-44 address index in the path (decimal `0..2147483647`).

**Response:** `{ "address": "0x...", "account_index": "0", "derivation_path": "m/44'/60'/0'/0/0" }`

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

