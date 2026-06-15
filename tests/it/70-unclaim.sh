#!/usr/bin/env bash
# Handle unclaim (#247.1): a claimed nick resolves via the relay directory, and
# `wire unclaim` (owner-gated by the slot token) frees it so it stops resolving
# and could be re-claimed. Without this a claim is FCFS-permanent (squatting).
set -euo pipefail
. "$(dirname "$0")/lib.sh"
it_init

RELAY="$(boot_relay 18960)"
A="$(it_home alice)"

step "alice claims her persona on the relay"
w "$A" init --relay "$RELAY" >/dev/null
AH="$(handle_of "$A")"
w "$A" claim "$AH" --public-url "$RELAY" >/dev/null
pass "claimed $AH"

step "the handle resolves via the relay directory"
assert "GET .well-known resolves $AH" \
  "curl -fsS \"$RELAY/.well-known/wire/agent?handle=$AH\" | grep -q '\"nick\"'"

step "alice unclaims her handle"
w "$A" unclaim --relay "$RELAY" --json >/dev/null
pass "unclaim returned OK"

step "the handle no longer resolves (freed)"
assert "GET .well-known now 404s for $AH" \
  "test \"\$(curl -s -o /dev/null -w '%{http_code}' \"$RELAY/.well-known/wire/agent?handle=$AH\")\" = 404"

step "unclaiming an already-unclaimed handle is a clean 404, not a crash"
assert "second unclaim fails (handle not found), CLI exits non-zero without panic" \
  "! w \"$A\" unclaim --relay \"$RELAY\" --json 2>/dev/null"

pass "unclaim: claim → resolves → unclaim → 404 OK"
