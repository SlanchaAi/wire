#!/usr/bin/env bash
# Rotation-refresh (#15): a re-intro from an ALREADY-TRUSTED (VERIFIED) peer —
# e.g. after a rude slot rotation — is a transport refresh. The receiver's daemon
# auto-re-acks (restoring the write-token) WITHOUT a fresh manual accept and
# WITHOUT stashing the peer in pending-inbound. A first-contact stranger still
# goes to pending (the consent gate is unchanged) — that's covered elsewhere.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
it_init

RELAY="$(boot_relay 18980)"
A="$(it_home alice)"; B="$(it_home bob)"

step "pair alice + bob (bilateral VERIFIED)"
pair_handle "$RELAY" "$A" "$B"
AH="$(handle_of "$A")"; BH="$(handle_of "$B")"
# pair_handle only claims the host; claim bob too so alice can re-resolve him.
w "$B" claim "$BH" --public-url "$RELAY" >/dev/null
pass "paired $AH <-> $BH"

step "start bob's daemon so it processes the re-intro"
WIRE_HOME="$B" "$WIRE" daemon --interval 1 >"$_IT_TMP/bob-daemon.log" 2>&1 &
_IT_PIDS="$_IT_PIDS $!"
sleep 1

step "alice re-intros bob (simulating recovery after a rotation)"
w "$A" add "$BH@127.0.0.1" --relay "$RELAY" --json >/dev/null
sleep 2

step "bob auto-refreshed: NO pending-inbound entry for alice (no manual accept)"
assert "bob's pending does NOT contain alice" \
  "! (w \"$B\" pending --json 2>/dev/null | grep -q $AH)"

step "bob still has alice pinned VERIFIED (tier unchanged by the refresh)"
assert "alice still VERIFIED on bob's side" \
  "w \"$B\" peers --json 2>/dev/null | grep -A3 $AH | grep -q VERIFIED"

pass "rotation-refresh: already-trusted re-intro auto-refreshed, no manual accept, tier intact"
