# BYOK operator policy: export private keys as .byok blobs wrapped for a receiving HSM's key exchange key (KEK).
#
# Export hands out the private key of an account, or the BIP-39 seed of an HD wallet (which derives every
# account of that wallet), wrapped for a public key the caller supplies, so grant this policy only to trusted
# operators. Do not attach it to user tokens.

path "blockchain/byok/export/account/+" {
    capabilities = [ "update" ]
}

path "blockchain/byok/export/wallet/+" {
    capabilities = [ "update" ]
}
