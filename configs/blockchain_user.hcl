path "identity/lookup/entity" {
    capabilities = [ "create", "read", "update" ]
}

path "blockchain/wallets/{{identity.entity.name}}/*" {
    capabilities = [ "create", "read", "update", "list" ]
}

path "blockchain/accounts/{{identity.entity.name}}/*" {
    capabilities = [ "create", "read", "update", "list" ]
}

# The wildcard above would also grant export-byok, which returns the account's private key wrapped for any
# RSA public key the caller supplies. An exact-path deny takes precedence over the wildcard.
path "blockchain/accounts/{{identity.entity.name}}/export-byok" {
    capabilities = [ "deny" ]
}
