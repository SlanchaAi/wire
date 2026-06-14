#!/usr/bin/env bash
# The on-box sister mesh — wire's "many agents on one machine" core. Three
# local-only sessions under one box, mesh-paired in one command, then a
# sister-to-sister signed message. No federation relay, loopback only.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
it_init

RELAY="$(boot_relay 18930 --local-only)"
BOX="$(it_home box)"

step "create three local-only sister sessions on the box"
for n in alpha beth charlie; do
  w "$BOX" session new "$n" --local-only --local-relay "$RELAY" --no-daemon --json >/dev/null
done
# Resolve each session's real home + persona handle (session env emits an
# `export WIRE_HOME=<path>` line; the typed name is just a locator, the handle
# is DID-derived).
home_of() { w "$BOX" session env "$1" 2>/dev/null | sed -n 's/^export WIRE_HOME=//p' | head -1 | tr -d '"'; }
AH_HOME="$(home_of alpha)"; BE_HOME="$(home_of beth)"; CH_HOME="$(home_of charlie)"
AHANDLE="$(handle_of "$AH_HOME")"; BHANDLE="$(handle_of "$BE_HOME")"; CHANDLE="$(handle_of "$CH_HOME")"
pass "sisters: $AHANDLE / $BHANDLE / $CHANDLE"

step "mesh-pair every sister in one command"
w "$BOX" session pair-all-local --settle-secs 1 --json >/dev/null

step "the mesh formed — each sister pinned the other two"
peers_of() { jq -r '.peers | keys[]' "$1/config/wire/relay.json" 2>/dev/null; }
assert "alpha pinned beth"    "wait_until 15 'peers_of \"$AH_HOME\" | grep -q $BHANDLE'"
assert "alpha pinned charlie" "wait_until 15 'peers_of \"$AH_HOME\" | grep -q $CHANDLE'"
assert "beth pinned alpha"    "wait_until 15 'peers_of \"$BE_HOME\" | grep -q $AHANDLE'"
assert "charlie pinned alpha" "wait_until 15 'peers_of \"$CH_HOME\" | grep -q $AHANDLE'"

step "sister → sister signed message (alpha → beth over loopback)"
w "$AH_HOME" send --queue "$BHANDLE" decision "loopback hello from $AHANDLE" >/dev/null
w "$AH_HOME" push --json >/dev/null
assert "beth received + verified alpha's message" \
  "wait_until 20 'w \"$BE_HOME\" pull --json; w \"$BE_HOME\" tail \"$AHANDLE\" --json | grep -q \"loopback hello from $AHANDLE\"'"

pass "local-mesh: 3-sister on-box mesh + signed sister send OK"
