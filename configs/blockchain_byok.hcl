# BYOK operator policy: export private keys as .byok blobs wrapped for a receiving HSM's key exchange key (KEK).
#
# Export hands out the private key of an account, the private key of one derived account of an HD wallet,
# or the BIP-39 seed of an HD wallet (which derives every account of that wallet), wrapped for a public key
# the caller supplies, so grant this policy only to trusted operators. Do not attach it to user tokens.
#
# Each export is a separate path: drop a block to withhold that kind of export. byok/export/wallet/+ does
# not cover byok/export/wallet/+/accounts/+, so granting only the derived-account export does not hand out
# the seed.

path "blockchain/byok/export/account/+" {
    capabilities = [ "update" ]
}

path "blockchain/byok/export/wallet/+" {
    capabilities = [ "update" ]
}

path "blockchain/byok/export/wallet/+/accounts/+" {
    capabilities = [ "update" ]
}
