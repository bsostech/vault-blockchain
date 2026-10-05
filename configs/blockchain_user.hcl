path "identity/lookup/entity" {
    capabilities = [ "create", "read", "update" ]
}

path "blockchain/wallets/{{identity.entity.name}}/*" {
    capabilities = [ "create", "read", "update", "list" ]
}

path "blockchain/accounts/{{identity.entity.name}}/*" {
    capabilities = [ "create", "read", "update", "list" ]
}

