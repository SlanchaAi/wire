#!/usr/bin/env bash
# Same-machine fleet-link (#182, RFC-001 amendment): `wire enroll fleet-link`
# walks every sibling session on this machine and attaches an op_sk-signed
# same-machine attestation to each card. Two of the operator's sessions on the
# same (machine, OS user) can then auto-pin each other at ORG_VERIFIED without a
# per-pair dial. This test drives the real verb over a minimal sibling layout
# and asserts (AC-SM1 substrate) the attestation lands and (AC-SM4) the verb is
# idempotent.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
it_init

# A fleet root holding two sibling sessions under sessions/by-key/<hash>, the
# layout `wire` uses for named sessions. list_sessions() (WIRE_HOME=$ROOT) walks
# sessions/* — so fleet-link discovers both.
ROOT="$_IT_TMP/fleet"
A="$ROOT/sessions/by-key/aaaaaaaa"
B="$ROOT/sessions/by-key/bbbbbbbb"
mkdir -p "$A" "$B"
CARD_A="$A/config/wire/agent-card.json"
CARD_B="$B/config/wire/agent-card.json"

step "init two sibling sessions (offline — fleet-link needs no network)"
w "$A" init --offline >/dev/null
w "$B" init --offline >/dev/null

step "enroll ONE operator and share its key across both siblings (same operator)"
w "$A" enroll op --handle fleetop >/dev/null
# Same operator owns both sessions: copy the op key + handle into B.
cp "$A/config/wire/op.key" "$B/config/wire/op.key"
cp "$A/config/wire/op.json" "$B/config/wire/op.json" 2>/dev/null || true

step "fleet-link --dry-run names both siblings without writing"
DRY="$(w "$ROOT" enroll fleet-link --dry-run --json)"
assert "dry-run reports 2 linked, 0 written" \
  "[ \"\$(echo '$DRY' | jq '.linked | length')\" = 2 ]"
assert "dry-run did NOT attach an attestation to A's card" \
  "[ \"\$(jq -r '.same_machine_attestation // \"none\"' '$CARD_A')\" = none ]"

step "fleet-link attaches a same_machine_attestation to every sibling card"
w "$ROOT" enroll fleet-link --json >/dev/null
assert "A's card carries machine_fingerprint" \
  "jq -e '.same_machine_attestation.machine_fingerprint' '$CARD_A'"
assert "A's card carries signature" \
  "jq -e '.same_machine_attestation.signature' '$CARD_A'"
assert "B's card carries the attestation too" \
  "jq -e '.same_machine_attestation.machine_fingerprint' '$CARD_B'"

step "both siblings share the SAME machine_fingerprint (same machine + uid)"
FP_A="$(jq -r '.same_machine_attestation.machine_fingerprint' "$CARD_A")"
FP_B="$(jq -r '.same_machine_attestation.machine_fingerprint' "$CARD_B")"
assert "fingerprints match across siblings" "[ \"$FP_A\" = \"$FP_B\" ]"

step "AC-SM4: re-running fleet-link is idempotent (cards byte-identical)"
SUM_A1="$(shasum -a256 "$CARD_A" | awk '{print $1}')"
w "$ROOT" enroll fleet-link --json >/dev/null
SUM_A2="$(shasum -a256 "$CARD_A" | awk '{print $1}')"
assert "A's card unchanged on second fleet-link" "[ \"$SUM_A1\" = \"$SUM_A2\" ]"

pass "fleet-link: signed same-machine attestation attached to all siblings, idempotent"
