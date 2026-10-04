path "auth/userpass/users/*" {
    capabilities = [ "create" ]
}

path "identity/entity-alias" {
    capabilities = ["read", "update" ]
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

path "blockchain/byok/keks/" {
    capabilities = [ "list" ]
}

path "blockchain/byok/keks/*" {
    capabilities = [ "create", "read", "update", "delete" ]
}
