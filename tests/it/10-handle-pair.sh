#!/usr/bin/env bash
# Two agents on one box pair zero-paste over a loopback relay and exchange
# bidirectional signed messages. The core "wire connection" flow.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
it_init

RELAY="$(boot_relay 18910)"
HOST=127.0.0.1
A="$(it_home alice)"; B="$(it_home bob)"

step "two agents mint identities + claim on the relay"
w "$A" init --relay "$RELAY" >/dev/null
w "$A" claim "$(handle_of "$A")" --public-url "$RELAY" >/dev/null
w "$B" init --relay "$RELAY" >/dev/null
AH="$(handle_of "$A")"; BH="$(handle_of "$B")"
pass "A=$AH  B=$BH (personas DID-derived, no name typed)"
assert "A and B got distinct personas" "[ \"$AH\" != \"$BH\" ]"

step "B pairs with A — one command, zero paste"
w "$B" add "$AH@$HOST" --relay "$RELAY" --json >/dev/null

step "A sees the inbound pair and accepts (bilateral consent gate)"
assert "A receives B's pending pair_drop" \
  "wait_until 20 'w \"$A\" pull --json; w \"$A\" pending --json | grep -q $BH'"
w "$A" accept "$BH" --json >/dev/null
w "$B" pull --json >/dev/null   # B consumes A's pair_drop_ack

step "both sides pinned each other VERIFIED"
# accept writes trust.json in one process; `peers` reads it in another — poll
# (don't single-shot) so a filesystem write/read beat can't flake the check.
a_has_b()      { w "$A" peers --json | grep -q "$BH"; }
b_has_a()      { w "$B" peers --json | grep -q "$AH"; }
a_b_verified() { w "$A" peers --json | jq -e --arg h "$BH" '.[]|select(.handle==$h)|.tier=="VERIFIED"' >/dev/null; }
assert "A pinned B"             "wait_until 10 a_has_b"
assert "B pinned A"             "wait_until 10 b_has_a"
assert "A pinned B at VERIFIED" "wait_until 10 a_b_verified"

step "A → B  signed message, delivered + verified"
w "$A" send --queue "$BH" decision "hello from $AH" >/dev/null
w "$A" push --json >/dev/null
assert "B received + verified A's message" \
  "wait_until 20 'w \"$B\" pull --json; w \"$B\" tail \"$AH\" --json | grep -q \"hello from $AH\"'"

step "B → A  reply, delivered + verified"
w "$B" send --queue "$AH" decision "ack from $BH" >/dev/null
w "$B" push --json >/dev/null
assert "A received + verified B's reply" \
  "wait_until 20 'w \"$A\" pull --json; w \"$A\" tail \"$BH\" --json | grep -q \"ack from $BH\"'"

pass "handle-pair: bidirectional signed connection on one box OK"
