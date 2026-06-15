#!/usr/bin/env bash
# Nostr transport binding (#227 D3.1, RFC-007 curve spike Option 1): `wire enroll
# nostr` mints a transport-only secp256k1 key, cross-signed by the Ed25519
# identity, carried as an additive `nostr_pubkey` card field. This drives the
# producer side end-to-end: mint → republish → whoami surfaces the VERIFIED npub.
# No network (offline init); the transport itself (NostrWs) is a later slice.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
it_init

A="$(it_home alice)"
CARD="$A/config/wire/agent-card.json"

step "a session with NO nostr key has no nostr_pubkey on its card (additive)"
w "$A" init --offline >/dev/null
assert "no nostr_pubkey before enroll" \
  "[ \"\$(jq -r '.nostr_pubkey // \"none\"' '$CARD')\" = none ]"

step "wire enroll nostr mints a transport key"
MINT="$(w "$A" enroll nostr --json)"
NPUB="$(echo "$MINT" | jq -r .nostr_pubkey_hex)"
assert "minted=true on first mint" "[ \"\$(echo '$MINT' | jq -r .minted)\" = true ]"
assert "npub is 64 hex chars (32-byte x-only)" "[ \"\$(echo -n '$NPUB' | wc -c | tr -d ' ')\" = 64 ]"

step "republish attaches the cross-signed binding to the card"
w "$A" enroll republish >/dev/null
assert "card carries nostr_pubkey.pubkey"      "jq -e '.nostr_pubkey.pubkey' '$CARD'"
assert "card carries nostr_pubkey.ed_sig"      "jq -e '.nostr_pubkey.ed_sig' '$CARD'"
assert "card carries nostr_pubkey.schnorr_sig" "jq -e '.nostr_pubkey.schnorr_sig' '$CARD'"

step "whoami surfaces the VERIFIED npub (binding checks out under the identity key)"
WHO_NPUB="$(w "$A" whoami --json | jq -r '.nostr_pubkey_hex // "none"')"
assert "whoami npub matches the minted key" "[ \"$WHO_NPUB\" = \"$NPUB\" ]"

step "mint is idempotent without --rotate (same key reused)"
MINT2="$(w "$A" enroll nostr --json)"
assert "second mint reports minted=false" "[ \"\$(echo '$MINT2' | jq -r .minted)\" = false ]"
assert "second mint returns the SAME npub" "[ \"\$(echo '$MINT2' | jq -r .nostr_pubkey_hex)\" = \"$NPUB\" ]"

step "--rotate mints a FRESH transport key"
MINT3="$(w "$A" enroll nostr --rotate --json)"
assert "rotate reports minted=true" "[ \"\$(echo '$MINT3' | jq -r .minted)\" = true ]"
assert "rotate yields a DIFFERENT npub" "[ \"\$(echo '$MINT3' | jq -r .nostr_pubkey_hex)\" != \"$NPUB\" ]"

pass "nostr binding: minted, cross-signed, verified through whoami, idempotent + rotatable"
