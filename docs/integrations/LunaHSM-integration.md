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
- The wrapped private key that Luna produces is PKCS#8 without the public key (72 bytes after AES-KWP). vault-blockchain imports it as is.

## Partition Policies

| Policy | Name | Needed for |
| ------ | ---- | ---------- |
| 1 | Allow private key wrapping | HSM → vault-blockchain. When it is off, `C_WrapKey` fails with `CKR_KEY_NOT_WRAPPABLE`. |
| 2 | Allow private key unwrapping | vault-blockchain → HSM |
| 5, 6 | Allow secret key wrapping, unwrapping | Wrapping and unwrapping the temporary AES key |

The Crypto Officer can view the policies; changing them needs the partition Security Officer:

```text
lunacm:> partition showpolicies -verbose
lunacm:> slot set -slot <slot>
lunacm:> role login -name po
lunacm:> partition changepolicy -policy 1 -value 1
```

Read this before turning on policy 1 (see Thales, *Configuring the Partition for Cloning or Export of Private/Secret Keys*):

- Changing policy 1 from off to on is always destructive: every object on the partition is deleted.
- Policy 0 (Allow private key cloning) and policy 1 cannot both be on. A partition is either in Cloning mode or in Key Export mode.
- So do not turn on policy 1 on a partition that already holds keys. Prepare a partition in Key Export mode first, then create the keys to transfer in it, with `CKA_EXTRACTABLE=true`.
- While policy 1 is on, the Crypto Officer can wrap and take away any extractable private key. Decide whether to turn it off after the transfer; `partition showpolicies -verbose` shows whether that change is destructive.

### Which Directions a Partition Supports

| Partition mode | vault-blockchain → HSM | HSM → vault-blockchain |
| -------------- | ---------------------- | ---------------------- |
| Cloning (policy 0 on) | Supported: needs only policies 2 and 6 | Not possible: private keys cannot be wrapped |
| Key Export (policy 1 on) | Supported | Supported |

Production deployments usually keep Cloning mode, for example to replicate keys across several HSMs in a high-availability group. On such partitions, plan for vault-blockchain → HSM only: create or import the keys in vault-blockchain and export them to the HSM.

## Tools

Thales also offers `hsmbyok`, which produces the same Azure `.byok` format for Azure Key Vault. Thales lists only P-256, P-384, and P-521 for it; it has not been verified with secp256k1.
