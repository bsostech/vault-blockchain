#!/bin/bash

function install_plugin {
  make build-local
  export SHASUM256=$(shasum -a 256 "./plugins/vault-bridgex" | cut -d' ' -f1)
  vault write sys/plugins/catalog/bridgex-plugin \
        sha_256="${SHASUM256}" \
        command="vault-bridgex --tls-skip-verify=true"
  vault secrets enable -path=bx -description="BSOS Wallet" -plugin-name=bridgex-plugin plugin
}

function create_policy {
  vault policy write bx_user ./configs/bx_user.hcl
  vault policy write bx_master ./configs/bx_master.hcl
}

function enable_userpass {
  vault auth enable userpass
  export GET_ACCESSOR=$(vault auth list -format=json)
  export ACCESSOR=$(echo $GET_ACCESSOR | jq -r '.["userpass/"].accessor')
  unset GET_ACCESSOR
}

vault login $ROOT_TOKEN
install_plugin
create_policy
enable_userpass

echo 'UserPass Accessor: '$ACCESSOR
echo 'Root Token: '$ROOT_TOKEN

