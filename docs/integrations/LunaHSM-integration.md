# Thales Luna HSM 7 Integration

This guide lists what is specific to Luna. Follow the common call sequence and templates in [README.md](README.md).

## Connection

| Item | Value |
| ---- | ----- |
| PKCS#11 library | `/usr/safenet/lunaclient/lib/libCryptoki2_64.so` (Luna Client on Linux) |
| Login | `C_Login(CKU_USER, <partition Crypto Officer password>)` |
| Slot | The slot of the partition, as shown by `lunacm` |

The Luna Client must be installed and registered with the HSM (`/etc/Chrystoki.conf` and client certificates in place) so that `lunacm` lists the partition.

## Mechanisms

| Purpose | Mechanism |
| ------- | --------- |
| AES-KWP (RFC 5649) | `CKM_AES_KWP` = `0x80000171` (`CKM_VENDOR_DEFINED + 0x171`) |
| RSA-OAEP | `CKM_RSA_PKCS_OAEP`; `hashAlg` and `mgf` must use the same hash, otherwise `CKR_MECHANISM_PARAM_INVALID` |

- Do not use `0x210A` (`CKM_AES_KEY_WRAP_PAD`) on Luna: it is not RFC 5649 key wrap there.
- `CKM_RSA_AES_KEY_WRAP` (`0x1054`) and PKCS#11 v3.0 `CKM_AES_KEY_WRAP_KWP` (`0x210B`) are not offered, so use the two-step sequence.

## Templates

- Unwrapping the private key: do not set `CKA_EC_PARAMS` (`CKR_ATTRIBUTE_TYPE_INVALID`). The curve comes from the PKCS#8 data.
- Unwrapping the AES key: `CKA_VALUE_LEN=32` may be set or left out.
- `CKA_TRUSTED` is not needed on the KEK public key.

## Partition Policies

| Policy | Name | Needed for |
| ------ | ---- | ---------- |
| 2 | Allow private key unwrapping | Unwrapping an account private key |
| 6 | Allow secret key unwrapping | Unwrapping the temporary AES key and a wallet seed |

Private key wrapping (policy 1) is not needed, so a partition in Cloning mode (policy 0 on), as production deployments usually keep, can receive keys.

The Crypto Officer can view the policies; changing them needs the partition Security Officer:

```text
lunacm:> partition showpolicies -verbose
lunacm:> slot set -slot <slot>
lunacm:> role login -name po
lunacm:> partition changepolicy -policy 2 -value 1
```

## HD Wallets (BIP-32)

A wallet seed exported with `byok/export/wallet/:wallet_id` is unwrapped as a 64-byte generic secret, as in [HD Wallet Seed](README.md#hd-wallet-seed). Luna can then derive the wallet's accounts with its vendor BIP-32 mechanisms:

| Purpose | Mechanism |
| ------- | --------- |
| Seed → BIP-32 master key pair | `CKM_BIP32_MASTER_DERIVE` = `0x80000E00` |
| Master or parent key → child key pair | `CKM_BIP32_CHILD_DERIVE` = `0x80000E01` |

The derived keys have the vendor key type `CKK_BIP32`. The parameter structures (`CK_BIP32_MASTER_DERIVE_PARAMS`, `CK_BIP32_CHILD_DERIVE_PARAMS`) are defined in the Luna SDK headers; each call takes a public and a private key template and returns both handles.

1. Unwrap the seed with `CKA_KEY_TYPE=CKK_GENERIC_SECRET` and `CKA_DERIVE=true` (`hSeed`).
2. `C_DeriveKey(CKM_BIP32_MASTER_DERIVE, hSeed)` → master public and private key. Give the private key `CKA_DERIVE=true` so that children can be derived from it.
3. `C_DeriveKey(CKM_BIP32_CHILD_DERIVE, hMasterPriv)` with the path `44'/60'/0'/0/<index>`, that is `{0x8000002C, 0x8000003C, 0x80000000, 0, <index>}`. Hardened indices carry the `0x80000000` flag. The whole path can be given in one call. Give the derived private key `CKA_SIGN=true`.
4. Compute the address from the derived public key ([Public Key and Address](README.md#public-key-and-address)) and compare it with vault-blockchain's `wallets/:wallet_id/accounts/<index>`.
5. Sign a 32-byte digest with `CKM_ECDSA` and the derived private key, and verify it with that public key ([Signatures](README.md#signatures)).

Requirements:

- BIP-32 is not a FIPS-approved algorithm, so the HSM must be configured to allow non-FIPS algorithms. This is an HSM-wide setting made by the HSM Security Officer; check the HSM policies with `hsm showpolicies` before planning on it.
- Receiving the seed is an unwrap of secret keys only (the AES key and the seed), which needs policy 6 but not policy 2.
