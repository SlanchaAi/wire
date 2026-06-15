#!/usr/bin/env bash
# RFC-004 Tier-1 connection health probing (#142): `wire ping` sends a probe and
# the PEER'S DAEMON auto-responds with a probe_ack — no LLM/MCP in the loop
# (AC-HP2 kill criterion). Validates the full round-trip end to end.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
it_init

RELAY="$(boot_relay 18970)"
A="$(it_home alice)"; B="$(it_home bob)"

step "pair alice + bob (bilateral VERIFIED, both hold slot tokens)"
pair_handle "$RELAY" "$A" "$B"
AH="$(handle_of "$A")"; BH="$(handle_of "$B")"
pass "paired $AH <-> $BH"

step "start bob's DAEMON so it auto-responds to probes (no LLM)"
WIRE_HOME="$B" "$WIRE" daemon --interval 1 >"$_IT_TMP/bob-daemon.log" 2>&1 &
_IT_PIDS="$_IT_PIDS $!"
sleep 1

step "alice pings bob — expect alive + a round-trip time"
assert "wire ping bob reports alive (daemon auto-responded)" \
  "wait_until 12 'w \"$A\" ping $BH --json | grep -q \"\\\"alive\\\": *true\"'"
RTT="$(w "$A" ping "$BH" --json 2>/dev/null | grep -o '\"rtt_ms\": *[0-9]*' | grep -o '[0-9]*' | head -1)"
assert "round-trip time is a non-negative integer" "test -n \"$RTT\""
pass "probe round-trip OK (rtt_ms=$RTT)"

pass "health-probe: wire ping → peer daemon auto-ack → round-trip OK"
