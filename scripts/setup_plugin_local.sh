#!/usr/bin/env bash
# Register the vault-blockchain plugin against a running dev Vault and enable the secrets engine.
# Prerequisites: vault CLI, jq, make; Vault already running (e.g. make run-local).
#
# Env:
#   ROOT_TOKEN      — defaults to root
#   VAULT_ADDR      — defaults to http://127.0.0.1:8200
#   PLUGIN_VERSION  — semver registered in catalog; must match plugin RunningVersion (v + internal/version.Version const).
#                     Change the const in code for a new release; override PLUGIN_VERSION here if catalog must differ while testing.
#   SMOKE           — if set to 1, run scripts/e2e_smoke.sh after setup

set -euo pipefail

ROOT_TOKEN="${ROOT_TOKEN:-root}"
VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
export VAULT_ADDR
export VAULT_TOKEN="${ROOT_TOKEN}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

for cmd in vault jq make; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "error: required command not found: ${cmd}" >&2
    exit 1
  fi
done

sha256_bin() {
  local f="$1"
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "${f}" | cut -d' ' -f1
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${f}" | cut -d' ' -f1
  else
    echo "error: need shasum (macOS) or sha256sum (Linux)" >&2
    exit 1
  fi
}

install_plugin() {
  make build-local
  local sha
  sha="$(sha256_bin "${REPO_ROOT}/plugins/vault-blockchain")"
  # Vault matches catalog entry to the plugin's self-reported semver (framework.Backend.RunningVersion).
  # Must match "v" + internal/version.Version (see version.go const).
  local ver="${PLUGIN_VERSION:-v0.1.0}"
  vault write sys/plugins/catalog/blockchain-plugin \
    sha_256="${sha}" \
    command="vault-blockchain --tls-skip-verify=true" \
    version="${ver}"

  if vault secrets list -format=json 2>/dev/null | jq -e 'has("blockchain/")' >/dev/null 2>&1; then
    echo "secrets engine blockchain/ already enabled; skipping vault secrets enable"
  else
    vault secrets enable -path=blockchain -description="BSOS Wallet" -plugin-name=blockchain-plugin plugin
  fi

  # After a catalog SHA bump, existing mounts keep the old plugin process until reload;
  # otherwise vault read can return 405 unsupported operation while vault write still works.
  echo "reloading plugin blockchain-plugin (pick up new binary on existing mounts)..."
  vault plugin reload -plugin=blockchain-plugin || {
    echo "warning: vault plugin reload failed — restart Vault or re-enable blockchain/ if reads stay 405" >&2
  }
}

create_policy() {
  vault policy write blockchain_user ./configs/blockchain_user.hcl
  vault policy write blockchain_master ./configs/blockchain_master.hcl
}

enable_userpass() {
  if vault auth list -format=json 2>/dev/null | jq -e 'has("userpass/")' >/dev/null 2>&1; then
    echo "auth userpass/ already enabled; skipping vault auth enable userpass"
  else
    vault auth enable userpass
  fi
}

# VAULT_TOKEN is exported above; no vault login needed for non-interactive use.
install_plugin
create_policy
enable_userpass

ACCESSOR=""
if vault auth list -format=json 2>/dev/null | jq -e 'has("userpass/")' >/dev/null 2>&1; then
  ACCESSOR="$(vault auth list -format=json | jq -r '.["userpass/"].accessor')"
fi

echo "VAULT_ADDR=${VAULT_ADDR}"
echo "Root token (dev): ${ROOT_TOKEN}"
echo "UserPass accessor: ${ACCESSOR:-<n/a>}"

if [[ "${SMOKE:-0}" == "1" ]]; then
  echo "--- running smoke (SMOKE=1) ---"
  bash "${SCRIPT_DIR}/e2e_smoke.sh"
fi
