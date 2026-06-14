#!/usr/bin/env bash
# Group chat with the standout property: a member who joins by CODE and never
# pairs with anyone is still verified by the others — introduce-pinned from the
# creator's signed roster. alice+bob pair, alice opens a room + adds bob, dave
# joins by code, and bob reads dave's message VERIFIED without ever pairing dave.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
it_init

RELAY="$(boot_relay 18940)"
ALICE="$(it_home alice)"; BOB="$(it_home bob)"; DAVE="$(it_home dave)"

step "alice + bob come up and pair; dave is a bystander (joins later by code)"
pair_handle "$RELAY" "$ALICE" "$BOB"
w "$DAVE" init --relay "$RELAY" >/dev/null
AH="$(handle_of "$ALICE")"; BH="$(handle_of "$BOB")"; DH="$(handle_of "$DAVE")"
pass "alice=$AH  bob=$BH  dave=$DH (dave un-paired)"

step "alice opens a room and adds bob (signed roster)"
w "$ALICE" group create open-room >/dev/null
GID="$(w "$ALICE" group list --json | jq -r '.groups[0].id')"
assert "group id resolved" "[ -n \"$GID\" ] && [ \"$GID\" != null ]"
w "$ALICE" group add "$GID" "$BH" >/dev/null
w "$ALICE" push --json >/dev/null
w "$BOB" pull --json >/dev/null

step "alice mints a join code; dave (never paired anyone) redeems it"
CODE="$(w "$ALICE" group invite "$GID" --json | jq -r '.code')"
assert "join code minted" "echo \"$CODE\" | grep -q '^wire-group:'"
w "$DAVE" group join "$CODE" >/dev/null

step "dave and bob both post to the room"
w "$DAVE" group send "$GID" "hi from dave (joined by code)" >/dev/null
w "$BOB"  group send "$GID" "welcome dave" >/dev/null

step "bob reads dave's message — VERIFIED, despite never pairing dave"
assert "bob sees dave's message, verified via the room-announced key" \
  "wait_until 20 'w \"$BOB\" group tail \"$GID\" --json | jq -e \".messages[] | select(.text==\\\"hi from dave (joined by code)\\\") | .verified==true\"'"

step "dave reads bob's reply — verified (dave pinned the roster on join)"
assert "dave sees bob's welcome" \
  "wait_until 20 'w \"$DAVE\" group tail \"$GID\" --json | jq -e \".messages[] | select(.text==\\\"welcome dave\\\")\"'"

pass "group-chat: join-by-code + cross-member verified read OK"
