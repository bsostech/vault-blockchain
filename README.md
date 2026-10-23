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


## API — BYOK (Bring Your Own Key)

BYOK moves a secp256k1 private key between vault-blockchain and another key store, such as an HSM, without the key ever being in the clear in transit. The receiving side creates a key exchange key (KEK), an RSA key pair whose private half never leaves it. The sending side wraps its private key with the KEK public key and produces a `.byok` blob. Only the receiving side can unwrap it. vault-blockchain can also send the BIP-39 seed of an HD wallet the same way.

It works in both directions, and the blob format is the same for both:

| Direction | What moves | Receiving side | Sending side |
| --------- | ---------- | -------------- | ------------ |
| Other store → vault-blockchain | secp256k1 private key | `byok/keks` (create KEK) then `accounts/:name/import-byok` | the other store |
| vault-blockchain → other store | secp256k1 private key | the other store | `byok/export/account/:name` |
| vault-blockchain → other store | HD wallet BIP-39 seed | the other store; needs BIP-32 to derive accounts | `byok/export/wallet/:wallet_id` |

The format follows the [Azure Key Vault BYOK specification](https://learn.microsoft.com/azure/key-vault/keys/byok-specification), so tools that already produce Azure `.byok` files for a secp256k1 key can feed vault-blockchain.

### Supported HSMs

These HSMs were tested in both directions with KEKs of 2048, 3072, and 4096 bits. The guides list the PKCS#11 call sequence, the templates, and what is specific to each HSM.

| HSM | Guide |
| --- | ----- |
| Thales Luna HSM 7 | [docs/integrations/LunaHSM-integration.md](docs/integrations/LunaHSM-integration.md) |
| SoftHSM2 | [docs/integrations/SoftHSM-integration.md](docs/integrations/SoftHSM-integration.md) |

Other PKCS#11 HSMs follow the same steps; see [docs/integrations](docs/integrations/README.md). Wallet seed export uses the same unwrap steps; deriving accounts from the seed needs BIP-32 in the HSM, which SoftHSM2 does not have (see [HD Wallet Seed](docs/integrations/README.md#hd-wallet-seed)).

### Transfer Format

A `.byok` file is JSON:

```json
{
  "schema_version": "1.0.0",
  "header": { "kid": "<kek id>", "alg": "dir", "enc": "CKM_RSA_AES_KEY_WRAP" },
  "ciphertext": "<base64url, no padding>",
  "generator": "<tool name and version>",
  "key_type": "bip39-seed"
}
```

* `kid` is the KEK identifier returned by `byok/keks`.
* `ciphertext` is `RSA-OAEP(KEK public key, AES key)` followed by `AES-KWP(AES key, private key)`. The RSA part is exactly as long as the KEK modulus (256 bytes for a 2048-bit KEK), which is how the two parts are split.
* RSA-OAEP uses SHA-1 for both the hash and MGF1, with an empty label. This is fixed by the Azure format and is what HSMs expect.
* AES-KWP is AES Key Wrap with Padding (RFC 5649). The AES key may be 128, 192, or 256 bits.
* The wrapped private key is a PKCS#8 `PrivateKeyInfo` (DER) holding an RFC 5915 `ECPrivateKey` on secp256k1 (OID `1.3.132.0.10`).
* `key_type` is optional and not part of the Azure format. It is absent for a private key. `byok/export/wallet/:wallet_id` sets it to `bip39-seed`; the wrapped value is then the raw 64-byte BIP-39 seed instead of PKCS#8 (see [Wallet Export](#wallet-export)). There is no API to import a seed: `import-byok` takes private keys only.
* The API takes the whole `.byok` file Base64 encoded (standard alphabet) as `byok_blob`.

### Key Exchange Keys

| Method | Path |
| ------ | ---- |
| `LIST` | `blockchain/byok/keks/` |
| `POST` | `blockchain/byok/keks/:kek_name` — create a KEK. |
| `GET` | `blockchain/byok/keks/:kek_name` — read the KEK public key and metadata. |
| `DELETE` | `blockchain/byok/keks/:kek_name` — delete the KEK and its private key. |

A KEK is only used to unwrap imports. There is no API that returns its private key. Create one KEK per transfer and delete it afterwards.

##### `POST blockchain/byok/keks/:kek_name`

* `kek_name` `(string: <required>)` - KEK name in the path.
* `key_size` `(int: 3072)` - RSA modulus size in bits: `2048`, `3072`, or `4096`.
* `ttl` `(duration: "")` - Optional lifetime. After it elapses the KEK can no longer be used for imports (HTTP 410).

**Response:**

```json
{
  "kid": "blockchain/byok/keks/<kek_name>/<id>",
  "kek_name": "<kek_name>",
  "key_size": 3072,
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...",
  "public_key_sha256": "<hex SHA-256 of the DER public key>",
  "created_at": "2026-10-05T00:00:00Z",
  "expires_at": ""
}
```

The `<id>` at the end of the `kid` is random per KEK, so a KEK deleted and recreated under the same name does not accept blobs wrapped for the old one. `GET` returns the same fields. A name that already exists returns HTTP 409 (`kek_exists`); a missing KEK on `GET` returns 404; `DELETE` of a missing KEK succeeds.

### Import

##### `POST blockchain/accounts/:name/import-byok`

* `name` `(string: <required>)` - Logical account name in the path. Same namespace as `accounts/:name/import`.
* `byok_blob` `(string: <required>)` - The `.byok` file, Base64 encoded.

**Response:** `{ "address": "0x...", "public_key": "..." }`

The account behaves like one created with `accounts/:name/import`: it can sign, sign transactions, and use ECIES. The private key is never returned. An existing account is never overwritten.

| HTTP | Error | Cause |
| ---- | ----- | ----- |
| 400 | `invalid_blob` | Not Base64 or JSON, wrong `schema_version`, `alg`, or `enc`, or `ciphertext` length does not fit the KEK. |
| 400 | `unwrap_failed` | The blob could not be unwrapped: wrong KEK, wrong OAEP parameters, or tampered data. The cause is deliberately not distinguished. |
| 400 | `unsupported_curve` | The wrapped key is not a secp256k1 EC key. |
| 400 | `invalid_key` | The wrapped key is malformed, zero, or outside the curve order. |
| 404 | `kek_not_found` | No KEK matches the `kid`. |
| 409 | `account_exists` | The account name is taken. |
| 410 | `kek_expired` | The KEK is past its `ttl`. |

### Export

#### Account Export

##### `POST blockchain/byok/export/account/:name`

* `name` `(string: <required>)` - Name of the account to export, in the path.
* `kid` `(string: <required>)` - Identifier of the receiving KEK, written to the blob header.
* `kek_public_key_pem` `(string: <required>)` - Receiving KEK public key as PEM (RSA, 2048, 3072, or 4096 bits).

**Response:** `{ "byok_blob": "<base64>", "address": "0x...", "kek_public_key_sha256": "<hex>" }`

Export copies the key: the account is unchanged. Compare `kek_public_key_sha256` with the fingerprint shown by the receiving side to confirm the public key was not replaced before it reached you.

Export returns the account's private key wrapped for whatever public key the caller supplies, so it must only be granted to trusted operators. It is deliberately under `byok/export/` and not under `accounts/`: the `accounts/<entity>/*` wildcard in `configs/blockchain_user.hcl` therefore does not cover it, and no deny rule is needed. `configs/blockchain_byok.hcl` is a policy for the operators who may use it. If you wrote your own policies, make sure none of them grants `blockchain/byok/*`.

| HTTP | Error | Cause |
| ---- | ----- | ----- |
| 400 | `invalid_kek_public_key` | The PEM cannot be parsed, is not RSA, or is not 2048, 3072, or 4096 bits. |
| 404 | `account_not_found` | No such account. |

#### Wallet Export

##### `POST blockchain/byok/export/wallet/:wallet_id`

* `wallet_id` `(string: <required>)` - Wallet to export, in the path.
* `kid` `(string: <required>)` - Identifier of the receiving KEK, written to the blob header (up to 1024 bytes).
* `kek_public_key_pem` `(string: <required>)` - Receiving KEK public key as PEM, `PUBLIC KEY` or `RSA PUBLIC KEY` (RSA, 2048, 3072, or 4096 bits).

**Response:**

```json
{
  "byok_blob": "<base64>",
  "wallet_id": "alice",
  "key_type": "bip39-seed",
  "kek_public_key_sha256": "<hex>"
}
```

What is exported is the wallet's BIP-39 **seed**, not its mnemonic. The seed is `PBKDF2-HMAC-SHA512(password = mnemonic, salt = "mnemonic", 2048 iterations, 64 bytes)`, the BIP-39 seed with an empty passphrase, which is what vault-blockchain derives its accounts from. The mnemonic itself never leaves vault-blockchain, and the seed cannot be turned back into it. The blob is the same `.byok` envelope as an account export; the plaintext is the raw 64-byte seed instead of PKCS#8, and the blob carries `"key_type": "bip39-seed"`.

The receiving side unwraps the seed as a 64-byte generic secret. That alone does not give it any accounts: to use the wallet, it needs BIP-32 to derive the master key from the seed and then the account keys at `m/44'/60'/0'/0/<index>`, the same path vault-blockchain uses. Not every HSM offers BIP-32; see [docs/integrations](docs/integrations/README.md#hd-wallet-seed). Compare the derived addresses with `GET wallets/:wallet_id/accounts/:index` to confirm the transfer.

Export copies the seed: the wallet and its accounts in vault-blockchain are unchanged. Compare `kek_public_key_sha256` with the fingerprint shown by the receiving side, as for an account export.

The seed gives every account of the wallet, those already created and any created later, so this endpoint is even more sensitive than account export and must only be granted to trusted operators. Like account export it is under `byok/export/`, not under `wallets/`, so the `wallets/<entity>/*` wildcard in `configs/blockchain_user.hcl` does not cover it: users cannot export their own wallets. `configs/blockchain_byok.hcl` grants it to operators. If you wrote your own policies, make sure none of them grants `blockchain/byok/*`.

| HTTP | Error | Cause |
| ---- | ----- | ----- |
| 400 | `invalid_kek_public_key` | The PEM cannot be parsed, is not RSA, or is not 2048, 3072, or 4096 bits. |
| 404 | `wallet_not_found` | No such wallet. |

### End-to-End Check

`scripts/e2e_byok.sh` exercises all of the above against a live Vault over HTTP, including the policies in `configs/`: users are refused `byok/export/` and `byok/keks/`, operators are not. For wallet export it imports a known mnemonic, unwraps the exported blob with OpenSSL using a local RSA key in place of an HSM KEK, and checks the seed against the mnemonic and the wallet's derived addresses. It creates an auth mount, policies, and users, so run it against a throwaway dev server:

```bash
VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=<root token> bash scripts/e2e_byok.sh
```

### Example: Wrapping a Key With OpenSSL

This produces a `.byok` blob for a key created with OpenSSL, using only standard tools. Any HSM that can perform the same two operations (AES-KWP, then RSA-OAEP with SHA-1) can produce the same blob.

```bash
# 1. Create a KEK and save its public key and kid.
curl -s -X POST -H "X-Vault-Token: $VAULT_TOKEN" -d '{"key_size": 2048}' \
  "$VAULT_ADDR/v1/blockchain/byok/keks/transfer1" > kek.json
jq -r .data.public_key_pem kek.json > kek_pub.pem
KID=$(jq -r .data.kid kek.json)

# 2. The key to send, as PKCS#8 DER (here a new secp256k1 key).
openssl ecparam -name secp256k1 -genkey -noout \
  | openssl pkcs8 -topk8 -nocrypt -outform DER -out key.der

# 3. Wrap it: a random AES key wraps the private key (AES-KWP), and the KEK wraps the AES key (RSA-OAEP, SHA-1).
AES=$(openssl rand -hex 32)
openssl enc -id-aes256-wrap-pad -K "$AES" -iv A65959A6 -in key.der -out wrapped_key.bin
echo -n "$AES" | xxd -r -p \
  | openssl pkeyutl -encrypt -pubin -inkey kek_pub.pem \
      -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha1 -pkeyopt rsa_mgf1_md:sha1 \
      -out wrapped_aes.bin

# 4. Assemble the .byok file: the RSA part first, then the AES part, base64url without padding.
CT=$(cat wrapped_aes.bin wrapped_key.bin | openssl base64 -A | tr '+/' '-_' | tr -d '=')
printf '{"schema_version":"1.0.0","header":{"kid":"%s","alg":"dir","enc":"CKM_RSA_AES_KEY_WRAP"},"ciphertext":"%s","generator":"openssl"}' \
  "$KID" "$CT" > key.byok

# 5. Import it, then delete the KEK.
curl -s -X POST -H "X-Vault-Token: $VAULT_TOKEN" \
  -d "{\"byok_blob\": \"$(openssl base64 -A -in key.byok)\"}" \
  "$VAULT_ADDR/v1/blockchain/accounts/alice/import-byok"
curl -s -X DELETE -H "X-Vault-Token: $VAULT_TOKEN" "$VAULT_ADDR/v1/blockchain/byok/keks/transfer1"
```

To send a key the other way, create a KEK on the receiving side, then call `byok/export/account/:name` with its `kid` and public key PEM:

```bash
curl -s -X POST -H "X-Vault-Token: $VAULT_TOKEN" \
  --data "$(jq -n --arg kid "$KID" --rawfile pem kek_pub.pem '{kid: $kid, kek_public_key_pem: $pem}')" \
  "$VAULT_ADDR/v1/blockchain/byok/export/account/alice" | jq -r .data.byok_blob | base64 -d > alice.byok
```

### Example: Unwrapping an Exported Wallet With OpenSSL

To check the wrapping format of a wallet export without an HSM, let a local RSA key play the receiving KEK. This handles the seed in the clear, so use it only with a test wallet.

```bash
# 1. A local KEK, in place of the HSM's.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out kek.pem
openssl pkey -in kek.pem -pubout -out kek_pub.pem

# 2. Export the wallet for it.
curl -s -X POST -H "X-Vault-Token: $VAULT_TOKEN" \
  --data "$(jq -n --rawfile pem kek_pub.pem '{kid: "local-test", kek_public_key_pem: $pem}')" \
  "$VAULT_ADDR/v1/blockchain/byok/export/wallet/test-wallet" | jq -r .data.byok_blob | base64 -d > wallet.byok
jq -r .key_type wallet.byok   # bip39-seed

# 3. Split the ciphertext at the KEK modulus length (384 bytes for 3072 bits) and unwrap both parts.
#    b64url_decode is in docs/integrations/README.md (Shell Helpers).
jq -r .ciphertext wallet.byok | b64url_decode > ct.bin
head -c 384 ct.bin | openssl pkeyutl -decrypt -inkey kek.pem \
  -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha1 -pkeyopt rsa_mgf1_md:sha1 -out aes.bin
tail -c +385 ct.bin > kwp.bin   # openssl enc cannot read a key wrap from a pipe
openssl enc -d -id-aes256-wrap-pad -K "$(xxd -p -c 64 aes.bin)" -iv A65959A6 -in kwp.bin -out seed.bin

# 4. The 64-byte seed equals the BIP-39 seed of the wallet's mnemonic (empty passphrase).
xxd -p -c 64 seed.bin
openssl kdf -keylen 64 -kdfopt digest:SHA512 -kdfopt pass:"$MNEMONIC" -kdfopt salt:mnemonic \
  -kdfopt iter:2048 PBKDF2 | tr -d ':' | tr 'A-F' 'a-f'
```
