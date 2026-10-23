# SoftHSM2 Integration

This guide lists what is specific to SoftHSM2. Follow the common call sequence and templates in [README.md](README.md).

SoftHSM2 keeps its keys in files under its token directory. Use it for development and CI, not to hold production keys.

## Setup

```bash
export SOFTHSM2_CONF=$PWD/softhsm2.conf      # must contain at least: directories.tokendir = <token directory>
softhsm2-util --init-token --free --label byok --so-pin "$SO_PIN" --pin "$HSM_PIN"
softhsm2-util --show-slots                   # use the slot id of the token labelled byok
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so -M   # lists RSA-PKCS-OAEP and mechtype-0x210A
```

| Item | Value |
| ---- | ----- |
| PKCS#11 library | `/usr/lib/softhsm/libsofthsm2.so` (Debian and Ubuntu package) |
| Login | `C_Login(CKU_USER, <token user PIN>)` |
| Slot | Assigned when the token is initialised, usually not 0; read it with `softhsm2-util --show-slots` |

## Mechanisms

| Purpose | Mechanism |
| ------- | --------- |
| AES-KWP (RFC 5649) | `CKM_AES_KEY_WRAP_PAD` = `0x210A` |
| RSA-OAEP | `CKM_RSA_PKCS_OAEP` with SHA-1 and MGF1-SHA1. SHA-256 OAEP is not supported (`CKR_ARGUMENTS_BAD`) |

`CKM_RSA_AES_KEY_WRAP` (`0x1054`) and `CKM_AES_KEY_WRAP_KWP` (`0x210B`) are not offered, so use the two-step sequence.

## Templates

- Unwrapping the AES key: do not set `CKA_VALUE_LEN` (`CKR_ATTRIBUTE_READ_ONLY`). The length comes from the unwrapped value.
- Unwrapping the private key: do not set `CKA_EC_PARAMS` (`CKR_ATTRIBUTE_READ_ONLY`).
- No policy needs to be configured: an extractable private key can be wrapped directly.
- The wrapped private key that SoftHSM2 produces is PKCS#8 without the public key (72 bytes after AES-KWP). vault-blockchain imports it as is.
