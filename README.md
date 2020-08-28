# vault-blockchain

vault-blockchain is a vault plugin to generate and store Ethereum private keys. We can use it to sign transaction in Vault without revealing private keys.

## Workflow

![1. Register](/images/workflow_01.png)
![2. Login](/images/workflow_02.png)
![3. Sign Transaction](/images/workflow_03.png)

## HCL Policies

There are two types of token in Vault-BX. One is master token. Another is user token. We use master token to register user accounts, but not retrieve any credentials in user account. Master token is only used for registration.

```hcl
# bx_master.hcl
path "auth/userpass/users/*" {
    capabilities = [ "create" ]
}

path "identity/entity-alias" {
    capabilities = [ "read", "update" ]
}

path "identity/entity" {
    capabilities = [ "read", "update" ]
}

path "blockchain/accounts/+/address" {
    capabilities = [ "create" ]
}
```

Each of user token is corresponding to identity, so it can only operate private key under that identity.

```hcl
# bx_user.hcl
path "blockchain/accounts/{{identity.entity.name}}/*" {
    capabilities = [ "create" ]
}
```

## API

### Create account

| Method | Path                        |
| ------ | --------------------------- |
| `POST` | `blockchain/accounts/:name/address` |

#### Parameters

* `name` `(string: <required>)` - Name of user. You can also use UUID of user in your system.

### Sign transaction

| Method | Path                        |
| ------ | --------------------------- |
| `POST` | `blockchain/accounts/:name/sign-tx` |

#### Parameters

* `name` `(string: <required>)` - Name of user. You can also use UUID of user in your system.
* `address_to` `(string: <required>)` - A Hex string specifying the Ethereum address to send the transaction to.
* `chainID` `(string: <required>)` - The chain ID of the blockchain network.
* `amount` `(string: <optional>)` - Amount of ETH (in wei).
* `gas_price` `(string: <optional>)` - The gas price for the transaction in wei.
* `gas_limit` `(string: <optional>)` - The gas limit for the transaction.
* `nonce` `(string: <optional>)` - The transaction nonce.
* `data` `(string: <required>)` - The data to sign.
* `is_private` `(bool: <optional>)` - Private transaction or not.

### Sign Besu Private Transaction

| Method | Path                                     |
| ------ | ---------------------------------------- |
| `POST` | `blockchain/accounts/:name/sign-besu-private-tx` |

#### Parameters

* `name` `(string: <required>)` - Name of user. You can also use UUID of user in your system.
* `address_to` `(string: <required>)` - A Hex string specifying the Ethereum address to send the transaction to.
* `chainID` `(string: <required>)` - The chain ID of the blockchain network.
* `amount` `(string: <optional>)` - Amount of ETH (in wei).
* `gas_price` `(string: <optional>)` - The gas price for the transaction in wei.
* `gas_limit` `(string: <optional>)` - The gas limit for the transaction.
* `private_nonce` `(string: <required>)` - The besu private transaction nonce.
* `data` `(string: <required>)` - The data to sign.
* `is_private` `(bool: <optional>)` - Private transaction or not.
* `private_from` `(string: <required>)` - The Orion public key of the transaction sender.
* `private_for` `(string: <required>)` - The Orion public keys of the transaction recipients.

### Sign data

| Method | Path                     |
| ------ | ------------------------ |
| `POST` | `blockchain/accounts/:name/sign` |

#### Parameters

* `name` `(string: <required>)` - Name of user. You can also use UUID of user in your system.
* `data` `(string: <required>)` - The data to hash (keccak) and sign.

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

