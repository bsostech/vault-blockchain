#!/usr/bin/env bash
# End-to-end checks of the BYOK API against a live Vault with the plugin mounted at blockchain/.
#
# Covers: account export unwrapped with OpenSSL and checked against the original key, wallet (BIP-39 seed)
# export unwrapped with OpenSSL and checked against the mnemonic and the wallet's derived addresses, the error
# statuses, that the removed KEK and import-byok paths are gone, and that the policies in configs/ actually
# keep users away from byok/export/ while operators can use it. A local RSA key plays the receiving HSM's KEK.
#
# Needs: curl, jq, openssl (3.2 or newer, for keccak-256), xxd, bc, and a Vault whose root token is in
# VAULT_TOKEN.
# It creates a userpass auth mount, two policies, and a few users and entities. Run it against a throwaway
# dev server, not a Vault you care about.
#
#   VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=<root token> bash scripts/e2e_byok.sh
set -u

VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
: "${VAULT_TOKEN:?set VAULT_TOKEN to the root token}"
MOUNT="${MOUNT:-blockchain}"
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
RUN="$(openssl rand -hex 3)"

PASS=0
FAIL=0
STATUS=""
BODY=""

api() { # api METHOD PATH TOKEN [JSON]  -> sets STATUS and BODY
	local method="$1" path="$2" token="$3" data="${4:-}"
	local args=(-sS -o "$WORK/body" -w '%{http_code}' -X "$method" -H "X-Vault-Token: $token")
	[ -n "$data" ] && args+=(-d "$data")
	STATUS="$(curl "${args[@]}" "$VAULT_ADDR/v1/$path")"
	BODY="$(cat "$WORK/body")"
}
root() { api "$1" "$2" "$VAULT_TOKEN" "${3:-}"; }

ok() { PASS=$((PASS + 1)); printf '  PASS  %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL  %s\n' "$1"; [ -n "${2:-}" ] && printf '        %s\n' "$2"; }
expect_status() { # expect_status NAME WANT
	if [ "$STATUS" = "$2" ]; then ok "$1 (HTTP $STATUS)"; else bad "$1: want HTTP $2, got $STATUS" "$(printf '%s' "$BODY" | head -c 300)"; fi
}
expect_eq() { # expect_eq NAME GOT WANT
	if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2' want '$3'"; fi
}
expect_contains() { # expect_contains NAME HAYSTACK NEEDLE
	case "$2" in *"$3"*) ok "$1" ;; *) bad "$1" "'$3' not found in: $(printf '%s' "$2" | head -c 300)" ;; esac
}
section() { printf '\n== %s\n' "$1"; }

# new_key N -> writes $WORK/N.der (PKCS#8) and $WORK/N.hex (32-byte scalar), and prints the uncompressed
# public key X||Y as hex.
new_key() {
	openssl ecparam -name secp256k1 -genkey -noout -out "$WORK/$1.pem" 2>/dev/null
	openssl pkcs8 -topk8 -nocrypt -in "$WORK/$1.pem" -outform DER -out "$WORK/$1.der"
	openssl ec -in "$WORK/$1.pem" -outform DER 2>/dev/null | head -c 39 | tail -c 32 | xxd -p -c 200 >"$WORK/$1.hex"
	openssl ec -in "$WORK/$1.pem" -pubout -outform DER 2>/dev/null | tail -c 65 | xxd -p -c 200 | cut -c3-
}

# base64url without padding -> binary
b64url_decode() { local s; s=$(tr '_-' '/+'); while [ $((${#s} % 4)) -ne 0 ]; do s="$s="; done; printf %s "$s" | openssl base64 -d -A; }
# kek_bytes PUB_PEM -> RSA modulus length in bytes, the length of the RSA part of the ciphertext
kek_bytes() { echo $(($(openssl pkey -pubin -in "$1" -noout -text | sed -n 's/.*(\([0-9]*\) bit).*/\1/p') / 8)); }
# unwrap BYOK_FILE KEK_PEM OUT -> unwraps the blob the way an HSM would: RSA-OAEP (SHA-1) gives the AES key,
# AES-KWP gives the plaintext. Sets AES_LEN to the AES key length in bytes.
unwrap() {
	local k
	jq -r .ciphertext "$1" | b64url_decode >"$WORK/unwrap.ct"
	k="$(kek_bytes "$2.pub")"
	head -c "$k" "$WORK/unwrap.ct" | openssl pkeyutl -decrypt -inkey "$2" \
		-pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha1 -pkeyopt rsa_mgf1_md:sha1 -out "$WORK/unwrap.aes"
	AES_LEN="$(wc -c <"$WORK/unwrap.aes" | tr -d ' ')"
	tail -c +$((k + 1)) "$WORK/unwrap.ct" >"$WORK/unwrap.kwp" # openssl enc cannot read a key wrap from a pipe
	openssl enc -d -id-aes$((AES_LEN * 8))-wrap-pad -K "$(xxd -p -c 200 "$WORK/unwrap.aes")" -iv A65959A6 \
		-in "$WORK/unwrap.kwp" -out "$3"
}

# bip39_seed MNEMONIC -> writes the 64-byte BIP-39 seed (empty passphrase) to stdout
bip39_seed() {
	openssl kdf -binary -keylen 64 -kdfopt digest:SHA512 -kdfopt pass:"$1" -kdfopt salt:mnemonic -kdfopt iter:2048 PBKDF2
}
# hmac512 KEY_HEX DATA_HEX -> HMAC-SHA512 as lower-case hex
hmac512() {
	printf %s "$2" | xxd -r -p >"$WORK/hmac.bin"
	openssl mac -digest SHA512 -macopt hexkey:"$1" -in "$WORK/hmac.bin" HMAC | tr 'A-F' 'a-f'
}
# ec_pub PRIV_HEX [compressed] -> secp256k1 public key as hex (65 bytes uncompressed, or 33 compressed)
ec_pub() {
	local form=uncompressed len=65
	[ "${2:-}" = compressed ] && form=compressed len=33
	printf '302e0201010420%sa00706052b8104000a' "$1" | xxd -r -p |
		openssl ec -inform DER -pubout -conv_form "$form" -outform DER 2>/dev/null | tail -c "$len" | xxd -p -c 200
}
# eth_address_at SEED_FILE INDEX -> lower-case address (no 0x) of m/44'/60'/0'/0/INDEX, by BIP-32 with OpenSSL and bc
eth_address_at() {
	local n=FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 i k c d il
	i="$(hmac512 "$(printf 'Bitcoin seed' | xxd -p)" "$(xxd -p -c 200 "$1")")"
	k="${i:0:64}" c="${i:64:64}"
	for d in 8000002c 8000003c 80000000 00000000 "$(printf '%08x' "$2")"; do
		if [ $((0x$d & 0x80000000)) -ne 0 ]; then i="$(hmac512 "$c" "00$k$d")"; else i="$(hmac512 "$c" "$(ec_pub "$k" compressed)$d")"; fi
		il="${i:0:64}" c="${i:64:64}"
		k="$(printf 'obase=16;ibase=16;(%s+%s)%%%s\n' "$(printf %s "$il" | tr a-f A-F)" "$(printf %s "$k" | tr a-f A-F)" "$n" | BC_LINE_LENGTH=0 bc)"
		k="$(printf '%064s' "$k" | tr ' ' 0 | tr A-F a-f)"
	done
	ec_pub "$k" | cut -c3- | xxd -r -p | openssl dgst -keccak-256 -binary | tail -c 20 | xxd -p
}

section "setup ($VAULT_ADDR, mount $MOUNT/, run $RUN)"
root GET "sys/mounts"
if ! printf '%s' "$BODY" | jq -e --arg m "$MOUNT/" '.data[$m]' >/dev/null 2>&1; then
	root POST "sys/mounts/$MOUNT" '{"type":"vault-blockchain"}'
	expect_status "mount plugin at $MOUNT/" 204
else
	ok "plugin already mounted at $MOUNT/"
fi

root PUT "sys/policies/acl/blockchain-user" "$(jq -n --rawfile p "$ROOT_DIR/configs/blockchain_user.hcl" '{policy:$p}')"
expect_status "write configs/blockchain_user.hcl as policy blockchain-user" 204
root PUT "sys/policies/acl/blockchain-byok" "$(jq -n --rawfile p "$ROOT_DIR/configs/blockchain_byok.hcl" '{policy:$p}')"
expect_status "write configs/blockchain_byok.hcl as policy blockchain-byok" 204

root POST "sys/auth/userpass" '{"type":"userpass"}' # 400 when it already exists; harmless
root GET "sys/auth"
ACCESSOR="$(printf '%s' "$BODY" | jq -r '.data["userpass/"].accessor')"
[ -n "$ACCESSOR" ] && [ "$ACCESSOR" != null ] && ok "userpass auth mount present" || bad "userpass auth mount missing"

PASSWORD="$(openssl rand -hex 16)"
ALICE="alice$RUN"
BOB="bob$RUN"
make_user() { # make_user USER POLICY [ENTITY]
	root POST "auth/userpass/users/$1" "$(jq -n --arg p "$PASSWORD" --arg pol "$2" '{password:$p,token_policies:$pol}')"
	if [ -n "${3:-}" ]; then
		root POST "identity/entity" "$(jq -n --arg n "$3" '{name:$n}')"
		local id
		id="$(printf '%s' "$BODY" | jq -r '.data.id // empty')"
		if [ -z "$id" ]; then root GET "identity/entity/name/$3"; id="$(printf '%s' "$BODY" | jq -r .data.id)"; fi
		root POST "identity/entity-alias" "$(jq -n --arg n "$1" --arg id "$id" --arg a "$ACCESSOR" '{name:$n,canonical_id:$id,mount_accessor:$a}')"
	fi
}
login() { # login USER -> prints token
	api POST "auth/userpass/login/$1" "" "$(jq -n --arg p "$PASSWORD" '{password:$p}')"
	printf '%s' "$BODY" | jq -r .auth.client_token
}
make_user "$ALICE" blockchain-user "$ALICE"
make_user "$BOB" blockchain-user "$BOB"
make_user "ops$RUN" blockchain-byok
ALICE_TOKEN="$(login "$ALICE")"
BOB_TOKEN="$(login "$BOB")"
OPS_TOKEN="$(login "ops$RUN")"
for t in "$ALICE_TOKEN" "$BOB_TOKEN" "$OPS_TOKEN"; do [ -n "$t" ] && [ "$t" != null ] || bad "login failed"; done
ok "users $ALICE, $BOB (policy blockchain-user) and ops$RUN (policy blockchain-byok) can log in"

section "receiving KEK"
# The receiving HSM's KEK, played by a local RSA key.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$WORK/hsm.pem" 2>/dev/null
openssl pkey -in "$WORK/hsm.pem" -pubout -out "$WORK/hsm.pem.pub"
HSM_KID="hsm-kek-$RUN"
HSM_REQ="$(jq -n --arg kid "$HSM_KID" --rawfile pem "$WORK/hsm.pem.pub" '{kid:$kid,kek_public_key_pem:$pem}')"
HSM_FP="$(openssl pkey -pubin -in "$WORK/hsm.pem.pub" -outform DER 2>/dev/null | openssl dgst -sha256 -hex | awk '{print $NF}')"
ok "3072-bit KEK $HSM_KID"

section "account export"
PUB_A="$(new_key a)"
KEY_A="$(cat "$WORK/a.hex")"
root POST "$MOUNT/accounts/acct-$RUN/import" "$(jq -n --arg k "$KEY_A" '{private_key:$k}')"
expect_status "import an account with an OpenSSL key" 200
expect_eq "imported public key equals the OpenSSL key's" "$(printf '%s' "$BODY" | jq -r .data.public_key)" "$PUB_A"
ADDR_A="$(printf '%s' "$BODY" | jq -r .data.address)"
api POST "$MOUNT/byok/export/account/acct-$RUN" "$OPS_TOKEN" "$HSM_REQ"
expect_status "operator exports an account" 200
expect_eq "export reports the account address" "$(printf '%s' "$BODY" | jq -r .data.address)" "$ADDR_A"
expect_eq "export fingerprint equals the SHA-256 of the DER public key" "$(printf '%s' "$BODY" | jq -r .data.kek_public_key_sha256)" "$HSM_FP"
case "$BODY" in *"$KEY_A"*) bad "the export response contains the private key" ;; *) ok "the export response does not contain the private key" ;; esac
printf '%s' "$BODY" | jq -r .data.byok_blob | openssl base64 -d -A >"$WORK/acct.byok"
expect_eq "blob header carries the kid" "$(jq -r .header.kid "$WORK/acct.byok")" "$HSM_KID"
expect_eq "blob header is the standard one" "$(jq -c '[.schema_version, .header.alg, .header.enc]' "$WORK/acct.byok")" '["1.0.0","dir","CKM_RSA_AES_KEY_WRAP"]'
expect_eq "account export blobs carry no key_type" "$(jq -r '.key_type // "absent"' "$WORK/acct.byok")" absent
unwrap "$WORK/acct.byok" "$WORK/hsm.pem" "$WORK/acct.der"
expect_eq "the AES key unwraps and is 256 bits" "$AES_LEN" 32
expect_eq "the unwrapped PKCS#8 equals OpenSSL pkcs8 -topk8 of the key" "$(xxd -p -c 200 "$WORK/acct.der")" "$(xxd -p -c 200 "$WORK/a.der")"
root GET "$MOUNT/accounts/acct-$RUN/address"
expect_eq "export leaves the account unchanged" "$(printf '%s' "$BODY" | jq -r .data.address)" "$ADDR_A"

api POST "$MOUNT/byok/export/account/acct-$RUN" "$OPS_TOKEN" '{"kid":"x","kek_public_key_pem":"not pem"}'
expect_status "export with a bad public key is 400" 400
expect_contains "400 carries invalid_kek_public_key" "$BODY" "invalid_kek_public_key"
api POST "$MOUNT/byok/export/account/none-$RUN" "$OPS_TOKEN" "$HSM_REQ"
expect_status "export of a missing account is 404" 404
expect_contains "404 carries account_not_found" "$BODY" "account_not_found"

section "removed paths"
root POST "$MOUNT/accounts/acct-$RUN/export-byok" "$HSM_REQ"
[ "$STATUS" != 200 ] && ok "the old accounts/:name/export-byok path no longer exists (HTTP $STATUS)" || bad "accounts/:name/export-byok still answers"
root POST "$MOUNT/byok/export/acct-$RUN" "$HSM_REQ"
[ "$STATUS" != 200 ] && ok "the old byok/export/:name path no longer exists (HTTP $STATUS)" || bad "byok/export/:name still answers"
root POST "$MOUNT/byok/keks/k-$RUN" '{"key_size":2048}'
[ "$STATUS" != 200 ] && ok "byok/keks/:kek_name no longer exists (HTTP $STATUS)" || bad "byok/keks/:kek_name still answers"
root POST "$MOUNT/accounts/new-$RUN/import-byok" "$(jq -n --arg b "$(openssl base64 -A -in "$WORK/acct.byok")" '{byok_blob:$b}')"
[ "$STATUS" != 200 ] && ok "accounts/:name/import-byok no longer exists (HTTP $STATUS)" || bad "accounts/:name/import-byok still answers"

section "wallet export"
# The standard BIP-39 test mnemonic (24 words). Its seed is public, so never use it for real funds.
MNEMONIC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
WALLET="w-$RUN"
root POST "$MOUNT/wallets/$WALLET/import" "$(jq -n --arg m "$MNEMONIC" '{mnemonic:$m}')"
expect_status "import a wallet with a known mnemonic" 200
root POST "$MOUNT/wallets/$WALLET/accounts/batch" '{"count":"2"}'
expect_status "derive two accounts in the wallet" 200
WADDR0="$(printf '%s' "$BODY" | jq -r '.data.accounts[0].address' | tr 'A-F' 'a-f')"
WADDR1="$(printf '%s' "$BODY" | jq -r '.data.accounts[1].address' | tr 'A-F' 'a-f')"
api POST "$MOUNT/byok/export/wallet/$WALLET" "$OPS_TOKEN" "$HSM_REQ"
expect_status "operator exports a wallet" 200
expect_eq "export echoes the wallet_id" "$(printf '%s' "$BODY" | jq -r .data.wallet_id)" "$WALLET"
expect_eq "export reports key_type bip39-seed" "$(printf '%s' "$BODY" | jq -r .data.key_type)" bip39-seed
expect_eq "wallet export fingerprint equals the SHA-256 of the DER public key" "$(printf '%s' "$BODY" | jq -r .data.kek_public_key_sha256)" "$HSM_FP"
case "$BODY" in *abandon*) bad "the export response contains the mnemonic" ;; *) ok "the export response does not contain the mnemonic" ;; esac
printf '%s' "$BODY" | jq -r .data.byok_blob | openssl base64 -d -A >"$WORK/wallet.byok"
expect_eq "blob key_type is bip39-seed" "$(jq -r .key_type "$WORK/wallet.byok")" bip39-seed
expect_eq "blob header carries the kid" "$(jq -r .header.kid "$WORK/wallet.byok")" "$HSM_KID"
expect_eq "blob header is the standard one" "$(jq -c '[.schema_version, .header.alg, .header.enc]' "$WORK/wallet.byok")" '["1.0.0","dir","CKM_RSA_AES_KEY_WRAP"]'

unwrap "$WORK/wallet.byok" "$WORK/hsm.pem" "$WORK/wallet.seed"
expect_eq "the AES key unwraps and is 256 bits" "$AES_LEN" 32
expect_eq "the unwrapped seed is 64 bytes" "$(wc -c <"$WORK/wallet.seed" | tr -d ' ')" 64
expect_eq "the seed equals PBKDF2-HMAC-SHA512 of the mnemonic" "$(xxd -p -c 200 "$WORK/wallet.seed")" "$(bip39_seed "$MNEMONIC" | xxd -p -c 200)"
expect_eq "BIP-32 from the seed gives the address of account 0" "0x$(eth_address_at "$WORK/wallet.seed" 0)" "$WADDR0"
expect_eq "BIP-32 from the seed gives the address of account 1" "0x$(eth_address_at "$WORK/wallet.seed" 1)" "$WADDR1"

api POST "$MOUNT/byok/export/wallet/$WALLET" "$OPS_TOKEN" '{"kid":"x","kek_public_key_pem":"not pem"}'
expect_status "wallet export with a bad public key is 400" 400
expect_contains "400 carries invalid_kek_public_key" "$BODY" "invalid_kek_public_key"
api POST "$MOUNT/byok/export/wallet/none-$RUN" "$OPS_TOKEN" "$HSM_REQ"
expect_status "export of a missing wallet is 404" 404
expect_contains "404 carries wallet_not_found" "$BODY" "wallet_not_found"

api POST "$MOUNT/wallets/$ALICE/create" "$ALICE_TOKEN"
expect_status "user creates their own wallet" 200
api POST "$MOUNT/byok/export/wallet/$ALICE" "$ALICE_TOKEN" "$HSM_REQ"
expect_status "user cannot export their own wallet" 403
api POST "$MOUNT/byok/export/wallet/$WALLET" "$ALICE_TOKEN" "$HSM_REQ"
expect_status "user cannot export someone else's wallet" 403

section "policies: users"
api POST "$MOUNT/accounts/$ALICE/address" "$ALICE_TOKEN"
expect_status "user creates their own account" 200
api POST "$MOUNT/accounts/$ALICE/sign" "$ALICE_TOKEN" '{"data":"0x68656c6c6f"}'
expect_status "user signs with their own account" 200
api POST "$MOUNT/byok/export/account/$ALICE" "$ALICE_TOKEN" "$HSM_REQ"
expect_status "user cannot export their own account" 403
api POST "$MOUNT/byok/export/account/acct-$RUN" "$ALICE_TOKEN" "$HSM_REQ"
expect_status "user cannot export someone else's account" 403
api POST "$MOUNT/accounts/$BOB/address" "$BOB_TOKEN"
api POST "$MOUNT/accounts/$BOB/sign" "$ALICE_TOKEN" '{"data":"0x68656c6c6f"}'
expect_status "user cannot sign with another user's account" 403

section "policies: operator"
api POST "$MOUNT/accounts/$ALICE/sign" "$OPS_TOKEN" '{"data":"0x68656c6c6f"}'
expect_status "operator policy does not grant signing" 403

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
