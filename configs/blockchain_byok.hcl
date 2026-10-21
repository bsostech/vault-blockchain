# BYOK operator policy: manage key exchange keys (KEKs) and move private keys in and out as .byok blobs.
#
# Export hands out the private key of an account, or the BIP-39 seed of an HD wallet (which derives every
# account of that wallet), wrapped for a public key the caller supplies, so grant this policy only to trusted
# operators. Do not attach it to user tokens.

path "blockchain/byok/keks/" {
    capabilities = [ "list" ]
}

path "blockchain/byok/keks/*" {
    capabilities = [ "create", "read", "update", "delete" ]
}

path "blockchain/accounts/+/import-byok" {
    capabilities = [ "create", "update" ]
}

path "blockchain/byok/export/account/+" {
    capabilities = [ "update" ]
}

path "blockchain/byok/export/wallet/+" {
    capabilities = [ "update" ]
}
