#!/usr/bin/env bash
# End-to-end checks of the BYOK API against a live Vault with the plugin mounted at blockchain/.
#
# Covers: KEK create/read/list/delete, import-byok with a key wrapped by plain OpenSSL commands, signing
# with the imported account, ttl expiry, export and re-import, the error statuses, and that the policies in
# configs/ actually keep users away from byok/export/ and byok/keks/ while operators can use them.
#
# Needs: curl, jq, openssl (3.x), xxd, and a Vault whose root token is in VAULT_TOKEN.
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

# new_key N -> writes $WORK/N.der (PKCS#8) and prints the uncompressed public key X||Y as hex.
new_key() {
	openssl ecparam -name secp256k1 -genkey -noout -out "$WORK/$1.pem" 2>/dev/null
	openssl pkcs8 -topk8 -nocrypt -in "$WORK/$1.pem" -outform DER -out "$WORK/$1.der"
	openssl ec -in "$WORK/$1.pem" -pubout -outform DER 2>/dev/null | tail -c 65 | xxd -p -c 200 | cut -c3-
}

# wrap_for KEY_DER KID KEK_PUB_PEM_FILE -> prints the base64 .byok file, built with plain OpenSSL commands.
wrap_for() {
	local der="$1" kid="$2" pub="$3" aes ct
	aes="$(openssl rand -hex 32)"
	openssl enc -id-aes256-wrap-pad -K "$aes" -iv A65959A6 -in "$der" -out "$WORK/wk.bin"
	printf '%s' "$aes" | xxd -r -p | openssl pkeyutl -encrypt -pubin -inkey "$pub" \
		-pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha1 -pkeyopt rsa_mgf1_md:sha1 -out "$WORK/wa.bin"
	ct="$(cat "$WORK/wa.bin" "$WORK/wk.bin" | openssl base64 -A | tr '+/' '-_' | tr -d '=')"
	printf '{"schema_version":"1.0.0","header":{"kid":"%s","alg":"dir","enc":"CKM_RSA_AES_KEY_WRAP"},"ciphertext":"%s","generator":"e2e"}' "$kid" "$ct" | openssl base64 -A
}

# create_kek NAME [JSON] -> sets KID and writes $WORK/NAME.pem
create_kek() {
	local body="${2:-}"
	[ -z "$body" ] && body='{"key_size":2048}'
	root POST "$MOUNT/byok/keks/$1" "$body"
	KID="$(printf '%s' "$BODY" | jq -r .data.kid)"
	printf '%s' "$BODY" | jq -r .data.public_key_pem >"$WORK/$1.pem.pub"
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

section "KEK API"
create_kek "k1-$RUN"
KEK1_ID="$KID"
expect_status "create KEK" 200
expect_contains "kid carries the mount point and name" "$KID" "$MOUNT/byok/keks/k1-$RUN/"
expect_eq "response never holds a private key" "$(printf '%s' "$BODY" | jq '[.. | strings | select(test("PRIVATE KEY"))] | length')" 0
expect_eq "default expires_at is empty" "$(printf '%s' "$BODY" | jq -r .data.expires_at)" ""
root POST "$MOUNT/byok/keks/k1-$RUN" '{"key_size":2048}'
expect_status "creating the same KEK again conflicts" 409
root POST "$MOUNT/byok/keks/bad-$RUN" '{"key_size":1024}'
expect_status "unsupported key_size is rejected" 400
root GET "$MOUNT/byok/keks/k1-$RUN"
expect_status "read KEK" 200
expect_eq "read returns the same kid" "$(printf '%s' "$BODY" | jq -r .data.kid)" "$KEK1_ID"
root LIST "$MOUNT/byok/keks/"
expect_contains "KEK is listed" "$BODY" "k1-$RUN"
root GET "$MOUNT/byok/keks/missing-$RUN"
expect_status "reading a missing KEK is 404" 404

section "import-byok with a key wrapped by plain OpenSSL"
PUB_A="$(new_key a)"
BLOB_A="$(wrap_for "$WORK/a.der" "$KEK1_ID" "$WORK/k1-$RUN.pem.pub")"
api POST "$MOUNT/accounts/imp-$RUN/import-byok" "$OPS_TOKEN" "$(jq -n --arg b "$BLOB_A" '{byok_blob:$b}')"
expect_status "operator imports the blob" 200
expect_eq "imported public key equals the OpenSSL key's" "$(printf '%s' "$BODY" | jq -r .data.public_key)" "$PUB_A"
ADDR_A="$(printf '%s' "$BODY" | jq -r .data.address)"
expect_eq "no private key in the response" "$(printf '%s' "$BODY" | jq '[.. | strings | select(test("^0x[0-9a-fA-F]{64}$"))] | length')" 0
root POST "$MOUNT/accounts/imp-$RUN/sign" '{"data":"0x68656c6c6f"}'
expect_status "imported account signs" 200
root GET "$MOUNT/accounts/imp-$RUN/address"
expect_eq "address is stable on read" "$(printf '%s' "$BODY" | jq -r .data.address)" "$ADDR_A"

section "import-byok errors over HTTP"
api POST "$MOUNT/accounts/imp-$RUN/import-byok" "$OPS_TOKEN" "$(jq -n --arg b "$BLOB_A" '{byok_blob:$b}')"
expect_status "importing into an existing account conflicts" 409
api POST "$MOUNT/accounts/x1-$RUN/import-byok" "$OPS_TOKEN" '{"byok_blob":"%%%"}'
expect_status "invalid base64 is 400" 400
expect_contains "error carries a code" "$BODY" "invalid_blob"
BAD_KID="$(printf '%s' "$BLOB_A" | openssl base64 -d -A | jq -c '.header.kid="blockchain/byok/keks/nope/abcd"' | openssl base64 -A)"
api POST "$MOUNT/accounts/x2-$RUN/import-byok" "$OPS_TOKEN" "$(jq -n --arg b "$BAD_KID" '{byok_blob:$b}')"
expect_status "unknown kid is 404" 404
expect_contains "404 carries kek_not_found" "$BODY" "kek_not_found"
TAMPERED="$(printf '%s' "$BLOB_A" | openssl base64 -d -A | jq -c '.ciphertext |= (.[0:-2] + "AA")' | openssl base64 -A)"
api POST "$MOUNT/accounts/x3-$RUN/import-byok" "$OPS_TOKEN" "$(jq -n --arg b "$TAMPERED" '{byok_blob:$b}')"
expect_status "tampered ciphertext is 400" 400
expect_contains "tampered ciphertext reports unwrap_failed" "$BODY" "unwrap_failed"
P256="$WORK/p256.der"
openssl ecparam -name prime256v1 -genkey -noout 2>/dev/null | openssl pkcs8 -topk8 -nocrypt -outform DER -out "$P256"
BLOB_P256="$(wrap_for "$P256" "$KEK1_ID" "$WORK/k1-$RUN.pem.pub")"
api POST "$MOUNT/accounts/x4-$RUN/import-byok" "$OPS_TOKEN" "$(jq -n --arg b "$BLOB_P256" '{byok_blob:$b}')"
expect_status "a P-256 key is rejected" 400
expect_contains "P-256 reports unsupported_curve" "$BODY" "unsupported_curve"
root GET "$MOUNT/accounts/x4-$RUN/address"
[ "$STATUS" = 404 ] || [ "$STATUS" = 400 ] && ok "failed imports store no account" || bad "a failed import left an account"

section "ttl expiry"
create_kek "short-$RUN" '{"key_size":2048,"ttl":"2s"}'
SHORT_KID="$KID"
expect_status "create KEK with ttl 2s" 200
expect_eq "expires_at is set" "$([ -n "$(printf '%s' "$BODY" | jq -r .data.expires_at)" ] && echo set)" set
PUB_S="$(new_key s)"
BLOB_S="$(wrap_for "$WORK/s.der" "$SHORT_KID" "$WORK/short-$RUN.pem.pub")"
sleep 3
api POST "$MOUNT/accounts/exp-$RUN/import-byok" "$OPS_TOKEN" "$(jq -n --arg b "$BLOB_S" '{byok_blob:$b}')"
expect_status "an expired KEK is 410" 410
expect_contains "410 carries kek_expired" "$BODY" "kek_expired"

section "deleted and recreated KEK"
create_kek "re-$RUN"
OLD_KID="$KID"
PUB_R="$(new_key r)"
BLOB_R="$(wrap_for "$WORK/r.der" "$OLD_KID" "$WORK/re-$RUN.pem.pub")"
root DELETE "$MOUNT/byok/keks/re-$RUN"
expect_status "delete KEK" 204
create_kek "re-$RUN"
[ "$KID" != "$OLD_KID" ] && ok "a recreated KEK gets a new kid" || bad "recreated KEK reuses the old kid"
api POST "$MOUNT/accounts/re-$RUN/import-byok" "$OPS_TOKEN" "$(jq -n --arg b "$BLOB_R" '{byok_blob:$b}')"
expect_status "a blob for the old KEK is refused by the new one" 404

section "export and re-import"
create_kek "k2-$RUN"
KEK2_ID="$KID"
api POST "$MOUNT/byok/export/imp-$RUN" "$OPS_TOKEN" "$(jq -n --arg kid "$KEK2_ID" --rawfile pem "$WORK/k2-$RUN.pem.pub" '{kid:$kid,kek_public_key_pem:$pem}')"
expect_status "operator exports an account" 200
EXPORTED="$(printf '%s' "$BODY" | jq -r .data.byok_blob)"
expect_eq "export reports the account address" "$(printf '%s' "$BODY" | jq -r .data.address)" "$ADDR_A"
EXPECTED_FP="$(openssl pkey -pubin -in "$WORK/k2-$RUN.pem.pub" -outform DER 2>/dev/null | openssl dgst -sha256 -hex | awk '{print $NF}')"
expect_eq "export fingerprint equals the SHA-256 of the DER public key" "$(printf '%s' "$BODY" | jq -r .data.kek_public_key_sha256)" "$EXPECTED_FP"
api POST "$MOUNT/accounts/back-$RUN/import-byok" "$OPS_TOKEN" "$(jq -n --arg b "$EXPORTED" '{byok_blob:$b}')"
expect_status "the exported blob imports under another name" 200
expect_eq "re-imported account has the same public key" "$(printf '%s' "$BODY" | jq -r .data.public_key)" "$PUB_A"
api POST "$MOUNT/byok/export/imp-$RUN" "$OPS_TOKEN" '{"kid":"x","kek_public_key_pem":"not pem"}'
expect_status "export with a bad public key is 400" 400
api POST "$MOUNT/byok/export/none-$RUN" "$OPS_TOKEN" "$(jq -n --arg kid "$KEK2_ID" --rawfile pem "$WORK/k2-$RUN.pem.pub" '{kid:$kid,kek_public_key_pem:$pem}')"
expect_status "export of a missing account is 404" 404
root POST "$MOUNT/accounts/imp-$RUN/export-byok" "$(jq -n --arg kid "$KEK2_ID" '{kid:$kid,kek_public_key_pem:"x"}')"
[ "$STATUS" != 200 ] && ok "the old accounts/:name/export-byok path no longer exists (HTTP $STATUS)" || bad "accounts/:name/export-byok still answers"

section "policies: users"
api POST "$MOUNT/accounts/$ALICE/address" "$ALICE_TOKEN"
expect_status "user creates their own account" 200
api POST "$MOUNT/accounts/$ALICE/sign" "$ALICE_TOKEN" '{"data":"0x68656c6c6f"}'
expect_status "user signs with their own account" 200
api POST "$MOUNT/byok/export/$ALICE" "$ALICE_TOKEN" "$(jq -n --arg kid "$KEK2_ID" --rawfile pem "$WORK/k2-$RUN.pem.pub" '{kid:$kid,kek_public_key_pem:$pem}')"
expect_status "user cannot export their own account" 403
api POST "$MOUNT/byok/export/imp-$RUN" "$ALICE_TOKEN" "$(jq -n --arg kid "$KEK2_ID" --rawfile pem "$WORK/k2-$RUN.pem.pub" '{kid:$kid,kek_public_key_pem:$pem}')"
expect_status "user cannot export someone else's account" 403
api POST "$MOUNT/byok/keks/u-$RUN" "$ALICE_TOKEN" '{"key_size":2048}'
expect_status "user cannot create a KEK" 403
api LIST "$MOUNT/byok/keks/" "$ALICE_TOKEN"
expect_status "user cannot list KEKs" 403
api GET "$MOUNT/byok/keks/k1-$RUN" "$ALICE_TOKEN"
expect_status "user cannot read a KEK" 403
api DELETE "$MOUNT/byok/keks/k1-$RUN" "$ALICE_TOKEN"
expect_status "user cannot delete a KEK" 403
api POST "$MOUNT/accounts/$BOB/address" "$BOB_TOKEN"
api POST "$MOUNT/accounts/$BOB/sign" "$ALICE_TOKEN" '{"data":"0x68656c6c6f"}'
expect_status "user cannot sign with another user's account" 403

section "policies: operator"
api GET "$MOUNT/byok/keks/k1-$RUN" "$OPS_TOKEN"
expect_status "operator reads a KEK" 200
api POST "$MOUNT/accounts/$ALICE/sign" "$OPS_TOKEN" '{"data":"0x68656c6c6f"}'
expect_status "operator policy does not grant signing" 403

section "cleanup"
for k in "k1-$RUN" "k2-$RUN" "short-$RUN" "re-$RUN"; do root DELETE "$MOUNT/byok/keks/$k"; done
ok "KEKs deleted"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
