# HSM Integration Guides

These guides show how a PKCS#11 HSM exchanges secp256k1 keys with vault-blockchain through the BYOK API, in both directions. The API itself (parameters, responses, error codes) is documented in the [BYOK section of the main README](../../README.md#api--byok-bring-your-own-key).

| HSM | vault-blockchain → HSM | HSM → vault-blockchain | Guide |
| --- | --- | --- | --- |
| Thales Luna HSM 7 | Supported | Supported | [LunaHSM-integration.md](LunaHSM-integration.md) |
| SoftHSM2 | Supported | Supported | [SoftHSM-integration.md](SoftHSM-integration.md) |

Both HSMs were tested with KEKs of 2048, 3072, and 4096 bits. The table covers account keys; for HD wallet seeds see [HD Wallet Seed](#hd-wallet-seed). On Luna, HSM → vault-blockchain needs a partition in Key Export mode; see [Which Directions a Partition Supports](LunaHSM-integration.md#which-directions-a-partition-supports). Other PKCS#11 HSMs follow the same steps; what usually differs is the AES-KWP mechanism code, which template attributes the token accepts, and its key export policy. See [Other HSMs](#other-hsms).

This page covers what is common to every HSM: the call sequence, the templates, and the format conversions. The vendor guides only list what is specific to each HSM.

## How It Works

vault-blockchain has no PKCS#11 code. The HSM side is done with the HSM's own tools or a small program that calls PKCS#11. Two PKCS#11 operations produce exactly the bytes of the `.byok` ciphertext, so no HSM needs `CKM_RSA_AES_KEY_WRAP`:

```text
ciphertext = RSA-OAEP(KEK public key, AES key) || AES-KWP(AES key, PKCS#8 private key)
             └── first k bytes, k = KEK modulus length (256, 384, or 512) ──┘
```

| Item | Value |
| ---- | ----- |
| RSA-OAEP | `CKM_RSA_PKCS_OAEP` with `CK_RSA_PKCS_OAEP_PARAMS{CKM_SHA_1, CKG_MGF1_SHA1, CKZ_DATA_SPECIFIED, NULL, 0}` |
| AES-KWP | AES Key Wrap with Padding (RFC 5649). The mechanism code depends on the HSM |
| AES key | vault-blockchain always uses AES-256 when it exports; it accepts 128, 192, or 256 bits on import |
| Private key | PKCS#8 `PrivateKeyInfo` (DER) holding an RFC 5915 `ECPrivateKey` on secp256k1 |

In the steps below, `<KWP>` is the HSM's AES-KWP mechanism and `<OAEP>` is `CKM_RSA_PKCS_OAEP` with the parameters above. The templates use session objects (`CKA_TOKEN=false`); to keep an imported key, set `CKA_TOKEN=true` and give it a `CKA_LABEL` and `CKA_ID`.

Use one KEK per transfer and delete it afterwards. Both sides should compute the KEK public key fingerprint and compare it over a separate channel, so that a replaced public key is noticed.

## HSM → vault-blockchain

1. Create a KEK in vault-blockchain and save its public key and `kid`:

   ```bash
   curl -s -X POST -H "X-Vault-Token: $VAULT_TOKEN" -d '{"key_size": 3072, "ttl": "1h"}' \
     "$VAULT_ADDR/v1/blockchain/byok/keks/transfer1" > kek.json
   jq -r .data.public_key_pem kek.json > kek_pub.pem
   jq -r .data.public_key_sha256 kek.json   # compare with the HSM side
   ```

2. On the HSM side, check the fingerprint and convert the PEM to a modulus and exponent ([Format Conversions](#kek-public-key)).

3. Wrap the key in the HSM:

   ```text
   1. C_CreateObject → hKekPub
        CKA_CLASS=CKO_PUBLIC_KEY  CKA_KEY_TYPE=CKK_RSA  CKA_TOKEN=false  CKA_WRAP=true
        CKA_MODULUS=<n>  CKA_PUBLIC_EXPONENT=<e, usually 01 00 01>
   2. C_GenerateKey(CKM_AES_KEY_GEN) → hAES
        CKA_CLASS=CKO_SECRET_KEY  CKA_KEY_TYPE=CKK_AES  CKA_VALUE_LEN=32  CKA_TOKEN=false
        CKA_SENSITIVE=true  CKA_EXTRACTABLE=true  CKA_WRAP=true
   3. C_WrapKey(<KWP>, hAES, hECPriv)   → wrapped_key.bin
   4. C_WrapKey(<OAEP>, hKekPub, hAES)  → wrapped_aes.bin (k bytes)
   5. C_DestroyObject(hAES), C_DestroyObject(hKekPub)
   ```

   The key to transfer, `hECPriv`, must have been created with `CKA_EXTRACTABLE=true`. That attribute cannot be changed from false to true later, so a key that was created non-extractable cannot be moved with BYOK.

4. Build the `.byok` file, import it, and delete the KEK:

   ```bash
   CT=$(cat wrapped_aes.bin wrapped_key.bin | b64url_encode)   # RSA part first
   jq -n --arg kid "$(jq -r .data.kid kek.json)" --arg ct "$CT" '{schema_version: "1.0.0",
     header: {kid: $kid, alg: "dir", enc: "CKM_RSA_AES_KEY_WRAP"},
     ciphertext: $ct, generator: "my-hsm-tool 1.0"}' > key.byok

   curl -s -X POST -H "X-Vault-Token: $VAULT_TOKEN" \
     -d "{\"byok_blob\": \"$(openssl base64 -A -in key.byok)\"}" \
     "$VAULT_ADDR/v1/blockchain/accounts/alice/import-byok"
   curl -s -X DELETE -H "X-Vault-Token: $VAULT_TOKEN" "$VAULT_ADDR/v1/blockchain/byok/keks/transfer1"
   ```

5. Check that the returned `address` matches the address derived from the HSM key's `CKA_EC_POINT` ([Format Conversions](#public-key-and-address)).

## vault-blockchain → HSM

1. Create a KEK in the HSM:

   ```text
   C_GenerateKeyPair(CKM_RSA_PKCS_KEY_PAIR_GEN) → hKekPub, hKekPriv
     public:  CKA_CLASS=CKO_PUBLIC_KEY  CKA_TOKEN=false  CKA_WRAP=true  CKA_ENCRYPT=false
              CKA_MODULUS_BITS=3072  CKA_PUBLIC_EXPONENT=01 00 01
     private: CKA_CLASS=CKO_PRIVATE_KEY  CKA_TOKEN=false  CKA_UNWRAP=true  CKA_DECRYPT=false
              CKA_SIGN=false  CKA_SENSITIVE=true  CKA_EXTRACTABLE=false
   ```

2. Read `CKA_MODULUS` and `CKA_PUBLIC_EXPONENT` from `hKekPub`, convert them to PEM ([Format Conversions](#kek-public-key)), and compute the fingerprint. The `kid` is yours to choose, for example the KEK's `CKA_LABEL`; vault-blockchain copies it into the blob header (up to 1024 bytes).

3. Export from vault-blockchain and compare the fingerprint:

   ```bash
   curl -s -X POST -H "X-Vault-Token: $VAULT_TOKEN" \
     --data "$(jq -n --arg kid "hsm-kek-01" --rawfile pem kek_pub.pem '{kid: $kid, kek_public_key_pem: $pem}')" \
     "$VAULT_ADDR/v1/blockchain/byok/export/account/alice" > export.json
   jq -r .data.kek_public_key_sha256 export.json   # must equal the HSM side's fingerprint
   jq -r .data.byok_blob export.json | base64 -d > alice.byok
   ```

4. Split the ciphertext:

   ```bash
   jq -r .ciphertext alice.byok | b64url_decode > ct.bin
   k=$(kek_bytes kek_pub.pem)
   head -c "$k" ct.bin > rsa_part.bin
   tail -c +$((k + 1)) ct.bin > kwp_part.bin
   ```

5. Unwrap in the HSM:

   ```text
   1. C_UnwrapKey(<OAEP>, hKekPriv, rsa_part.bin) → hAES
        CKA_CLASS=CKO_SECRET_KEY  CKA_KEY_TYPE=CKK_AES  CKA_TOKEN=false
        CKA_SENSITIVE=true  CKA_EXTRACTABLE=false  CKA_UNWRAP=true
   2. C_UnwrapKey(<KWP>, hAES, kwp_part.bin) → hECPriv
        CKA_CLASS=CKO_PRIVATE_KEY  CKA_KEY_TYPE=CKK_EC  CKA_TOKEN=false
        CKA_SENSITIVE=true  CKA_EXTRACTABLE=false  CKA_SIGN=true
        Do not set CKA_EC_PARAMS: the curve comes from the PKCS#8 data, and tokens reject it.
   3. C_DestroyObject(hAES); destroy the KEK once the transfer is done.
   ```

6. Sign a 32-byte digest in the HSM with `CKM_ECDSA` and verify it with the account's public key ([Signatures](#signatures)).

7. If the key is kept (`CKA_TOKEN=true`) for an application that finds it by `CKA_LABEL` and reads its address from `CKA_EC_POINT`, check that the attribute can be read. `C_UnwrapKey` creates only the private key, and some tokens do not expose `CKA_EC_POINT` on an unwrapped private key (see the vendor guides). In that case, create a public key object with the same label:

   ```text
   C_CreateObject → hECPub
     CKA_CLASS=CKO_PUBLIC_KEY  CKA_KEY_TYPE=CKK_EC  CKA_TOKEN=true  CKA_VERIFY=true
     CKA_LABEL=<label of the private key>  CKA_EC_PARAMS=<secp256k1 OID 06 05 2B 81 04 00 0A>
     CKA_EC_POINT=<DER OCTET STRING of the account's uncompressed public key, 04 41 04 || X || Y>
   ```

   `GET accounts/:name/address` returns the account's public key as `public_key`: X || Y in hex (128 characters, without the `04` prefix), so `CKA_EC_POINT` is `044104` followed by that value.

Export copies the key: the account in vault-blockchain is unchanged.

### HD Wallet Seed

`byok/export/wallet/:wallet_id` sends the BIP-39 seed of an HD wallet instead of a single account key. The steps are the same as above, with these differences:

- Step 3 calls `byok/export/wallet/<wallet_id>` instead of `byok/export/account/<name>`. The blob carries `"key_type": "bip39-seed"`.
- The plaintext is the raw 64-byte seed (`PBKDF2-HMAC-SHA512` of the mnemonic, salt `"mnemonic"`, 2048 iterations), not PKCS#8. After AES-KWP it is 72 bytes. The mnemonic is never exported.
- Step 5.2 unwraps it as a generic secret:

  ```text
  2. C_UnwrapKey(<KWP>, hAES, kwp_part.bin) → hSeed
       CKA_CLASS=CKO_SECRET_KEY  CKA_KEY_TYPE=CKK_GENERIC_SECRET  CKA_TOKEN=true
       CKA_LABEL=<label>  CKA_ID=<id>  CKA_VALUE_LEN=64
       CKA_SENSITIVE=true  CKA_EXTRACTABLE=false  CKA_DERIVE=true
  ```

  Use `CKA_TOKEN=true` to keep the seed, since it is the root of every account of the wallet; `CKA_TOKEN=false` is enough to test the transfer. Some tokens set `CKA_VALUE_LEN` themselves and reject it in the template (see the vendor guide). `CKA_DERIVE=true` is what lets the seed be used for BIP-32.

The seed on its own does not sign anything. To use the wallet, the HSM must derive keys from it with BIP-32:

1. Derive the BIP-32 master key from the seed (HMAC-SHA512 with the key `"Bitcoin seed"`).
2. Derive the account key at `m/44'/60'/0'/0/<index>`, the path vault-blockchain uses. The first three levels are hardened (index `| 0x80000000`).
3. Read the public key of the derived key, compute its address ([Public Key and Address](#public-key-and-address)), and compare it with vault-blockchain's address for the same index:

   ```bash
   curl -s -H "X-Vault-Token: $VAULT_TOKEN" "$VAULT_ADDR/v1/blockchain/wallets/alice/accounts/0" | jq -r .data.address
   ```

4. Sign a 32-byte digest with the derived key and verify it as in step 6 above.

BIP-32 is not part of standard PKCS#11; HSMs that support it do so with vendor mechanisms (see the vendor guides). An HSM without BIP-32 can still unwrap and store the seed, which is enough to check the wrapping format, but it cannot derive or sign with the wallet's accounts.

## Format Conversions

The commands need OpenSSL 3, `jq`, and `xxd`.

### Shell Helpers

```bash
# base64url without padding <-> binary
b64url_encode() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
b64url_decode() { local s; s=$(tr '_-' '/+'); while [ $(( ${#s} % 4 )) -ne 0 ]; do s="$s="; done; printf %s "$s" | openssl base64 -d -A; }
# KEK modulus length in bytes, which is the length of the RSA part of the ciphertext
kek_bytes() { echo $(( $(openssl pkey -pubin -in "$1" -noout -text | sed -n 's/.*(\([0-9]*\) bit).*/\1/p') / 8 )); }
```

Do not decode unpadded base64url with `base64 -d` or `openssl base64 -d` directly. Depending on the tool, they either fail or silently drop the last bytes. `b64url_decode` adds the padding first.

### KEK Public Key

```bash
# PEM -> PKCS#11 attributes for C_CreateObject
openssl rsa -pubin -in kek_pub.pem -noout -modulus | cut -d= -f2   # CKA_MODULUS as hex
openssl rsa -pubin -in kek_pub.pem -noout -text | grep Exponent     # CKA_PUBLIC_EXPONENT, usually 65537

# PKCS#11 attributes -> PEM (MODULUS_HEX is CKA_MODULUS as hex; change e if the exponent is not 65537)
printf 'asn1=SEQUENCE:pubkey\n[pubkey]\nn=INTEGER:0x%s\ne=INTEGER:0x010001\n' "$MODULUS_HEX" > rsapub.cnf
openssl asn1parse -genconf rsapub.cnf -noout -out rsapub.der
openssl rsa -RSAPublicKey_in -inform DER -in rsapub.der -pubout -out kek_pub.pem

# Fingerprint: equals public_key_sha256 and kek_public_key_sha256 (SHA-256 of the DER SubjectPublicKeyInfo)
openssl pkey -pubin -in kek_pub.pem -outform DER | openssl dgst -sha256 -r | cut -d' ' -f1
```

`byok/export/account/:name` and `byok/export/wallet/:wallet_id` accept both `PUBLIC KEY` (SubjectPublicKeyInfo) and `RSA PUBLIC KEY` (PKCS#1) PEM.

### Private Key Encoding

| Produced by | Content | DER | After AES-KWP |
| ----------- | ------- | --- | ------------- |
| vault-blockchain `byok/export/account/:name` | `ECPrivateKey` with the uncompressed public key, no `[0]` parameters; byte-identical to OpenSSL `pkcs8 -topk8` | 135 bytes | 144 bytes |
| Luna and SoftHSM2 `C_WrapKey` | `ECPrivateKey` without the public key | 64 bytes | 72 bytes |

vault-blockchain and both HSMs accept either form. On import, vault-blockchain also accepts the `[0]` curve parameters if they name secp256k1 and checks that an included public key matches the private key. It rejects a compressed public key or a bare SEC1 key (`BEGIN EC PRIVATE KEY`, not wrapped in PKCS#8) with `invalid_key`, and any other curve with `unsupported_curve`.

To build test material with OpenSSL (never for production keys):

```bash
openssl pkcs8 -topk8 -nocrypt -in key_sec1.pem -outform DER -out key.der    # SEC1 -> PKCS#8 DER
printf '303e020100301006072a8648ce3d020106052b8104000a042730250201010420%s' "$PRIV_HEX" \
  | xxd -r -p > key.der                                                    # 32-byte hex -> PKCS#8 DER
```

To put an existing hex private key into vault-blockchain, use `accounts/:name/import` instead; BYOK is not needed for that.

### Public Key and Address

`CKA_EC_POINT` is a DER OCTET STRING, `04 41 04 || X || Y`; some tokens return the bare `04 || X || Y`. The address is the last 20 bytes of keccak256(X || Y). vault-blockchain returns EIP-55 mixed-case addresses, so compare case-insensitively. `keccak-256` needs OpenSSL 3.2 or newer.

```bash
printf %s "$EC_POINT_HEX" | tail -c 128 | xxd -r -p | openssl dgst -keccak-256 -binary | tail -c 20 | xxd -p
```

### Signatures

`CKM_ECDSA` returns the 64-byte `r || s`, not DER. Ethereum requires a low `s`: if `s > n/2`, use `n - s`, where `n` is the secp256k1 group order. An Ethereum 65-byte signature also needs the recovery id `v`.

## Troubleshooting

| Error | Likely cause |
| ----- | ------------ |
| `CKR_MECHANISM_INVALID` (0x70) | Wrong AES-KWP mechanism code for this HSM. |
| `CKR_KEY_NOT_WRAPPABLE` (0x69) | The HSM does not allow private keys to be wrapped (on Luna, partition policy 1). |
| `CKR_KEY_UNEXTRACTABLE` (0x6A) | The source key has `CKA_EXTRACTABLE=false`. |
| `CKR_ATTRIBUTE_TYPE_INVALID` (0x12), `CKR_ATTRIBUTE_READ_ONLY` (0x10) | The unwrap template contains an attribute the token sets itself, such as `CKA_EC_PARAMS` or, on SoftHSM2, `CKA_VALUE_LEN`. |
| `CKR_MECHANISM_PARAM_INVALID` (0x71) | OAEP `hashAlg` and `mgf` differ; use SHA-1 for both. |
| `invalid_blob` | `byok_blob` is not standard Base64, `ciphertext` is not base64url, a fixed header field is wrong, or the ciphertext length does not fit the KEK (often a truncated base64url decode). |
| `unwrap_failed` | Wrong OAEP hash (for example SHA-256), the two parts swapped, a different KEK, or an AES key wrap that is not RFC 5649. The cause is deliberately not distinguished. |
| `kek_not_found` | The `kid` is not the one vault-blockchain returned, or the KEK was deleted or recreated. |
| `invalid_key`, `unsupported_curve` | See [Private Key Encoding](#private-key-encoding). |

## Other HSMs

1. List the token's mechanisms, for example with `pkcs11-tool --module <library> -M`, and find `RSA-PKCS-OAEP` with wrap and unwrap, and an RFC 5649 AES key wrap mechanism.
2. Follow the steps above with that mechanism.
3. If the token rejects a template, remove `CKA_VALUE_LEN` and `CKA_EC_PARAMS` first.
