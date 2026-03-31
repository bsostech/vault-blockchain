#!/usr/bin/env bash
# End-to-end checks against a live Vault with blockchain/ mounted.
# Covers: wallet import, read derived, list wallets/accounts, sign, sign-tx/legacy + sign-tx/eip1559,
# sign-eip712, ECIES encrypt/decrypt roundtrip.
# Uses a fixed BIP-39 test vector so the derived address is deterministic.
#
# There is no standalone read/write on blockchain/wallets/:wallet_id (touch was removed); use LIST
# wallets/ or derived account paths instead.
#
# Wallet paths under .../accounts/:index/{sign,sign-tx,...} register both Create and Update with
# the same handler so Vault can route HTTP writes after ExistenceCheck (usually Update).
#
# If vault read returns 405 unsupported operation after you rebuild the plugin, the mount may
# still be running an old process — run make setup-plugin-local (catalog + plugin reload).
#
# Env:
#   VAULT_ADDR   — default http://127.0.0.1:8200
#   VAULT_TOKEN  — optional if you already `vault login` (token helper); otherwise set it (e.g. root from dev server)
#   E2E_WALLET   — default e2e-<unix_ts> (unique each run); set fixed id to reuse one wallet
#   E2E_ACCOUNT  — default e2e-acct-<unix_ts> (unique each run); set fixed name to reuse one single-key account

set -euo pipefail

VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
E2E_WALLET="${E2E_WALLET:-e2e-$(date +%s)}"
E2E_ACCOUNT="${E2E_ACCOUNT:-e2e-acct-$(date +%s)}"
export VAULT_ADDR

for cmd in vault jq; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "error: required command not found: ${cmd}" >&2
    exit 1
  fi
done

if [[ -z "${VAULT_TOKEN:-}" ]]; then
  # Allow vault CLI token helper (e.g. after `vault login`) without forcing VAULT_TOKEN env var.
  if ! vault token lookup >/dev/null 2>&1; then
    echo "error: no Vault token found. Either run `vault login` or set VAULT_TOKEN (e.g. export VAULT_TOKEN=root)" >&2
    exit 1
  fi
fi

# Standard test mnemonic — do not use on mainnet.
MNEMONIC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
# m/44'/60'/0'/0/0 for the above mnemonic (go-ethereum checksummed hex)
EXPECT_ADDR="0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
# Hex for ASCII "hello" — sign / ECIES roundtrip.
PLAINTEXT_HEX="0x68656c6c6f"

# Minimal EIP-712 payload.
# - payload: new API (single JSON object; matches eth_signTypedData_v4 style).
# - split fields: legacy API (domain/types/primary_type/message).
EIP712_TYPES='{"EIP712Domain":[{"name":"name","type":"string"}],"Person":[{"name":"name","type":"string"}]}'
EIP712_DOMAIN='{"name":"Test Domain"}'
EIP712_MESSAGE='{"name":"Cow"}'
EIP712_PRIMARY_TYPE="Person"
EIP712_PAYLOAD='{"types":{"EIP712Domain":[{"name":"name","type":"string"}],"Person":[{"name":"name","type":"string"}]},"primaryType":"Person","domain":{"name":"Test Domain"},"message":{"name":"Cow"}}'

acct_base="blockchain/wallets/${E2E_WALLET}/accounts/0"
single_base="blockchain/accounts/${E2E_ACCOUNT}"

hex_lc() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

require_jq() {
  local json="$1" expr="$2" err_msg="$3"
  local v
  v="$(echo "${json}" | jq -r "${expr}")"
  if [[ -z "${v}" || "${v}" == "null" ]]; then
    echo "error: ${err_msg}" >&2
    echo "${json}" >&2
    exit 1
  fi
  printf '%s' "${v}"
}

vault_write_json() {
  # Usage: vault_write_json <path> [k=v ...]
  # Retries are intentionally not added here; failures should be visible to the caller.
  local p="$1"
  shift
  vault write -format=json "${p}" "$@"
}

vault_write_force_json() {
  # Usage: vault_write_force_json <path>
  local p="$1"
  shift
  vault write -force -format=json "${p}" "$@"
}

echo "== import wallet ${E2E_WALLET} (deterministic mnemonic) =="
vault write "blockchain/wallets/${E2E_WALLET}/import" mnemonic="${MNEMONIC}"

echo "== derive account index 0 =="
# Vault CLI requires -force when there are no key=value fields; wallet_id and index come from the path.
vault write -force "${acct_base}"

echo "== read derived account =="
OUT="$(vault read -format=json "${acct_base}")"
ADDR="$(require_jq "${OUT}" '.data.address // empty' 'expected .data.address in read response')"
ADDR_LC="$(hex_lc "${ADDR}")"
EXPECT_LC="$(hex_lc "${EXPECT_ADDR}")"
if [[ "${ADDR_LC}" != "${EXPECT_LC}" ]]; then
  echo "error: address mismatch" >&2
  echo "  got:      ${ADDR}" >&2
  echo "  expected: ${EXPECT_ADDR}" >&2
  exit 1
fi
echo "  address: ${ADDR}"

echo "== list wallets =="
vault list blockchain/wallets/

echo "== list accounts for wallet =="
vault list "blockchain/wallets/${E2E_WALLET}/accounts/" || echo "(no list entries; if you just rebuilt the plugin, run make setup-plugin-local to reload)"

echo "== sign (keccak + ecdsa) =="
SIGN_JSON="$(vault_write_json "${acct_base}/sign" data="${PLAINTEXT_HEX}")"
SIG="$(require_jq "${SIGN_JSON}" '.data.signature // empty' 'expected .data.signature from sign')"
SIGN_ADDR="$(require_jq "${SIGN_JSON}" '.data.address // empty' 'expected .data.address from sign')"
if [[ "$(hex_lc "${SIGN_ADDR}")" != "${EXPECT_LC}" ]]; then
  echo "error: sign response address mismatch" >&2
  exit 1
fi
if [[ "${SIG}" != 0x* ]] || [[ "${#SIG}" -lt 10 ]]; then
  echo "error: unexpected signature format: ${SIG}" >&2
  exit 1
fi
echo "  address:   ${SIGN_ADDR}"
echo "  signature: ${SIG}"

echo "== sign-tx (legacy eip155) =="
LEG_JSON="$(vault_write_json "${acct_base}/sign-tx/legacy" \
  chain_id=1 \
  nonce=0 \
  gas_limit=21000 \
  gas_price=1 \
  to=0x0000000000000000000000000000000000000001 \
  value=0)"
require_jq "${LEG_JSON}" '.data.signed_transaction // empty' 'expected .data.signed_transaction from legacy sign-tx' >/dev/null
require_jq "${LEG_JSON}" '.data.transaction_hash // empty' 'expected .data.transaction_hash from legacy sign-tx' >/dev/null
LEG_TYPE="$(echo "${LEG_JSON}" | jq -r '.data.type // empty')"
if [[ "${LEG_TYPE}" != "legacy" ]]; then
  echo "error: expected legacy tx type, got ${LEG_TYPE}" >&2
  exit 1
fi
LEG_HASH="$(echo "${LEG_JSON}" | jq -r '.data.transaction_hash // empty')"
LEG_RAW="$(echo "${LEG_JSON}" | jq -r '.data.signed_transaction // empty')"
echo "  type:             ${LEG_TYPE}"
echo "  transaction_hash: ${LEG_HASH}"
echo "  signed_tx:        ${LEG_RAW:0:42}... (${#LEG_RAW} hex chars)"

echo "== sign-tx (eip1559) =="
EIP1559_JSON="$(vault_write_json "${acct_base}/sign-tx/eip1559" \
  chain_id=1 \
  nonce=1 \
  gas_limit=21000 \
  max_fee_per_gas=2000000000 \
  max_priority_fee_per_gas=1000000000 \
  to=0x0000000000000000000000000000000000000001 \
  value=0)"
require_jq "${EIP1559_JSON}" '.data.signed_transaction // empty' 'expected .data.signed_transaction from eip1559 sign-tx' >/dev/null
EIP1559_TYPE="$(echo "${EIP1559_JSON}" | jq -r '.data.type // empty')"
if [[ "${EIP1559_TYPE}" != "eip1559" ]]; then
  echo "error: expected eip1559 tx type, got ${EIP1559_TYPE}" >&2
  exit 1
fi
EIP1559_HASH="$(echo "${EIP1559_JSON}" | jq -r '.data.transaction_hash // empty')"
EIP1559_RAW="$(echo "${EIP1559_JSON}" | jq -r '.data.signed_transaction // empty')"
echo "  type:             ${EIP1559_TYPE}"
echo "  transaction_hash: ${EIP1559_HASH}"
echo "  signed_tx:        ${EIP1559_RAW:0:42}... (${#EIP1559_RAW} hex chars)"

echo "== sign-eip712 =="
set +e
EIP_JSON="$(vault_write_json "${acct_base}/sign-eip712" payload="${EIP712_PAYLOAD}" 2>&1)"
EIP_RC=$?
set -e
if [[ "${EIP_RC}" -ne 0 ]]; then
  # If Vault is still running an older plugin build, sign-eip712 may require split fields.
  if echo "${EIP_JSON}" | tr '[:upper:]' '[:lower:]' | grep -Fq "primary_type is required"; then
    echo "  note: sign-eip712 payload rejected; retrying legacy fields (plugin likely not reloaded)"
    EIP_JSON="$(vault_write_json "${acct_base}/sign-eip712" \
      types="${EIP712_TYPES}" \
      domain="${EIP712_DOMAIN}" \
      primary_type="${EIP712_PRIMARY_TYPE}" \
      message="${EIP712_MESSAGE}")"
  else
    echo "${EIP_JSON}" >&2
    exit "${EIP_RC}"
  fi
fi
EIP_SIG="$(require_jq "${EIP_JSON}" '.data.signature // empty' 'expected .data.signature from sign-eip712')"
if [[ "${EIP_SIG}" != 0x* ]] || [[ "${#EIP_SIG}" -lt 10 ]]; then
  echo "error: unexpected eip712 signature: ${EIP_SIG}" >&2
  exit 1
fi
echo "  signature: ${EIP_SIG}"

echo "== encrypt (ECIES) =="
ENC_JSON="$(vault_write_json "${acct_base}/encrypt" data="${PLAINTEXT_HEX}")"
CIPHER="$(require_jq "${ENC_JSON}" '.data.ciphertext // empty' 'expected .data.ciphertext from encrypt')"
if [[ "${CIPHER}" != 0x* ]]; then
  echo "error: unexpected ciphertext format: ${CIPHER}" >&2
  exit 1
fi
echo "  ciphertext: ${CIPHER:0:42}... (${#CIPHER} hex chars)"

echo "== decrypt (ECIES roundtrip) =="
DEC_JSON="$(vault_write_json "${acct_base}/decrypt" data="${CIPHER}")"
PLAIN="$(require_jq "${DEC_JSON}" '.data.plaintext // empty' 'expected .data.plaintext from decrypt')"
PLAIN_LC="$(hex_lc "${PLAIN}")"
PT_EXPECT_LC="$(hex_lc "${PLAINTEXT_HEX}")"
if [[ "${PLAIN_LC}" != "${PT_EXPECT_LC}" ]]; then
  echo "error: decrypt plaintext mismatch" >&2
  echo "  got:      ${PLAIN}" >&2
  echo "  expected: ${PLAINTEXT_HEX}" >&2
  exit 1
fi
echo "  plaintext: ${PLAIN}"

echo "== create single-key account ${E2E_ACCOUNT} =="
SK_CREATE_JSON="$(vault_write_force_json "${single_base}/address")"
SK_ADDR="$(require_jq "${SK_CREATE_JSON}" '.data.address // empty' 'expected .data.address from single-key create')"
if [[ "$(hex_lc "${SK_ADDR}")" == "" ]]; then
  echo "error: expected non-empty single-key address" >&2
  exit 1
fi
echo "  address: ${SK_ADDR}"

echo "== read single-key account =="
SK_READ_JSON="$(vault read -format=json "${single_base}/address")"
require_jq "${SK_READ_JSON}" '.data.address // empty' 'expected .data.address from single-key read' >/dev/null

echo "== list single-key accounts (must include ${E2E_ACCOUNT}) =="
SK_LIST_JSON="$(vault list -format=json blockchain/accounts/)"
echo "${SK_LIST_JSON}" | jq .
if ! echo "${SK_LIST_JSON}" | jq -e --arg n "${E2E_ACCOUNT}" '
  if type == "array" then
    index($n) != null
  elif (has("data") and (.data | type == "object") and (.data | has("keys"))) then
    (.data.keys | index($n)) != null
  else
    false
  end
' >/dev/null; then
  echo "error: expected account name in list: ${E2E_ACCOUNT}" >&2
  echo "${SK_LIST_JSON}" >&2
  exit 1
fi

echo "== single-key sign (keccak + ecdsa) =="
SK_SIGN_JSON="$(vault_write_json "${single_base}/sign" data="${PLAINTEXT_HEX}")"
SK_SIG="$(require_jq "${SK_SIGN_JSON}" '.data.signature // empty' 'expected .data.signature from single-key sign')"
SK_SIGN_ADDR="$(require_jq "${SK_SIGN_JSON}" '.data.address // empty' 'expected .data.address from single-key sign')"
if [[ "$(hex_lc "${SK_SIGN_ADDR}")" != "$(hex_lc "${SK_ADDR}")" ]]; then
  echo "error: single-key sign response address mismatch" >&2
  echo "  got:      ${SK_SIGN_ADDR}" >&2
  echo "  expected: ${SK_ADDR}" >&2
  exit 1
fi
if [[ "${SK_SIG}" != 0x* ]] || [[ "${#SK_SIG}" -lt 10 ]]; then
  echo "error: unexpected single-key signature format: ${SK_SIG}" >&2
  exit 1
fi
echo "  address:   ${SK_SIGN_ADDR}"
echo "  signature: ${SK_SIG}"

echo "== single-key sign-tx (legacy eip155) =="
SK_LEG_JSON="$(vault_write_json "${single_base}/sign-tx/legacy" \
  chain_id=1 \
  nonce=0 \
  gas_limit=21000 \
  gas_price=1 \
  to=0x0000000000000000000000000000000000000001 \
  value=0)" || {
    echo "error: single-key sign-tx legacy failed (if you just rebuilt the plugin, run make setup-plugin-local to reload)" >&2
    exit 1
  }
require_jq "${SK_LEG_JSON}" '.data.signed_transaction // empty' 'expected .data.signed_transaction from single-key legacy sign-tx' >/dev/null
SK_LEG_TYPE="$(echo "${SK_LEG_JSON}" | jq -r '.data.type // empty')"
SK_LEG_HASH="$(echo "${SK_LEG_JSON}" | jq -r '.data.transaction_hash // empty')"
SK_LEG_RAW="$(echo "${SK_LEG_JSON}" | jq -r '.data.signed_transaction // empty')"
echo "  type:             ${SK_LEG_TYPE}"
echo "  transaction_hash: ${SK_LEG_HASH}"
echo "  signed_tx:        ${SK_LEG_RAW:0:42}... (${#SK_LEG_RAW} hex chars)"

echo "== single-key sign-tx (eip1559) =="
SK_EIP1559_JSON="$(vault_write_json "${single_base}/sign-tx/eip1559" \
  chain_id=1 \
  nonce=1 \
  gas_limit=21000 \
  max_fee_per_gas=2000000000 \
  max_priority_fee_per_gas=1000000000 \
  to=0x0000000000000000000000000000000000000001 \
  value=0)" || {
    echo "error: single-key sign-tx eip1559 failed (if you just rebuilt the plugin, run make setup-plugin-local to reload)" >&2
    exit 1
  }
require_jq "${SK_EIP1559_JSON}" '.data.signed_transaction // empty' 'expected .data.signed_transaction from single-key eip1559 sign-tx' >/dev/null
SK_EIP1559_TYPE="$(echo "${SK_EIP1559_JSON}" | jq -r '.data.type // empty')"
SK_EIP1559_HASH="$(echo "${SK_EIP1559_JSON}" | jq -r '.data.transaction_hash // empty')"
SK_EIP1559_RAW="$(echo "${SK_EIP1559_JSON}" | jq -r '.data.signed_transaction // empty')"
echo "  type:             ${SK_EIP1559_TYPE}"
echo "  transaction_hash: ${SK_EIP1559_HASH}"
echo "  signed_tx:        ${SK_EIP1559_RAW:0:42}... (${#SK_EIP1559_RAW} hex chars)"

echo "== single-key sign-eip712 =="
set +e
SK_EIP_JSON="$(vault_write_json "${single_base}/sign-eip712" payload="${EIP712_PAYLOAD}" 2>&1)"
SK_EIP_RC=$?
set -e
if [[ "${SK_EIP_RC}" -ne 0 ]]; then
  if echo "${SK_EIP_JSON}" | tr '[:upper:]' '[:lower:]' | grep -Fq "primary_type is required"; then
    echo "  note: single-key sign-eip712 payload rejected; retrying legacy fields (plugin likely not reloaded)"
    SK_EIP_JSON="$(vault_write_json "${single_base}/sign-eip712" \
      types="${EIP712_TYPES}" \
      domain="${EIP712_DOMAIN}" \
      primary_type="${EIP712_PRIMARY_TYPE}" \
      message="${EIP712_MESSAGE}")"
  else
    echo "${SK_EIP_JSON}" >&2
    exit "${SK_EIP_RC}"
  fi
fi
SK_EIP_SIG="$(require_jq "${SK_EIP_JSON}" '.data.signature // empty' 'expected .data.signature from single-key sign-eip712')"
echo "  signature: ${SK_EIP_SIG}"

echo "== single-key encrypt (ECIES) =="
SK_ENC_JSON="$(vault_write_json "${single_base}/encrypt" data="${PLAINTEXT_HEX}")"
SK_CIPHER="$(require_jq "${SK_ENC_JSON}" '.data.ciphertext // empty' 'expected .data.ciphertext from single-key encrypt')"
echo "  ciphertext: ${SK_CIPHER:0:42}... (${#SK_CIPHER} hex chars)"

echo "== single-key decrypt (ECIES roundtrip) =="
SK_DEC_JSON="$(vault_write_json "${single_base}/decrypt" data="${SK_CIPHER}")"
SK_PLAIN="$(require_jq "${SK_DEC_JSON}" '.data.plaintext // empty' 'expected .data.plaintext from single-key decrypt')"
if [[ "$(hex_lc "${SK_PLAIN}")" != "${PT_EXPECT_LC}" ]]; then
  echo "error: single-key decrypt plaintext mismatch" >&2
  echo "  got:      ${SK_PLAIN}" >&2
  echo "  expected: ${PLAINTEXT_HEX}" >&2
  exit 1
fi
echo "  plaintext: ${SK_PLAIN}"

echo "e2e_smoke: OK (wallet=${ADDR} single_key=${SK_ADDR})"
