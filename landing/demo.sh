#!/bin/bash
# Replayable cast script — wire v0.7-alpha federated flow.
#
# Two operators (alice + bob) claim handles on wireup.net. Wire gives
# each of them a face: emoji + adjective-noun nickname + sticky color,
# derived from their DID. Bob calls alice using her federation handle.
# Alice sees the toast, accepts with one command. Bob sends — addressed
# by alice's character nickname, not her handle. v0.7's "they find each
# other by name" magic.
#
# Re-record with:
#   asciinema rec landing/demo.cast --overwrite \
#     --output-format asciicast-v2 \
#     --command 'bash landing/demo.sh'

set -e

ALICE_HOME=/tmp/wire-demo-cast/alice
BOB_HOME=/tmp/wire-demo-cast/bob
WIRE="$(cd "$(dirname "$0")/.." && pwd)/target/release/wire"
[ -x "$WIRE" ] || WIRE=wire

rm -rf /tmp/wire-demo-cast
mkdir -p "$ALICE_HOME" "$BOB_HOME"
TS=$$
ANICK="demo-alice-$TS"
BNICK="demo-bob-$TS"

pause() { sleep "${1:-0.9}"; }

# Substitute throwaway demo handles → readable names in displayed output.
# Actual relay records use unique nicks so re-recording never collides on
# a public claim. Strips WIRE_QUIET_AUTOSESSION noise too.
clean() {
  sed -E \
    -e "s/$ANICK/alice/g" \
    -e "s/$BNICK/bob/g" \
    -e "s/demo-alice-$TS/alice/g" \
    -e "s/demo-bob-$TS/bob/g"
}

# Silent daemon helper — pulls/pushes both sides one cycle, no output.
sync_silently() {
  WIRE_HOME=$ALICE_HOME $WIRE daemon --once > /dev/null 2>&1 || true
  WIRE_HOME=$BOB_HOME $WIRE daemon --once > /dev/null 2>&1 || true
}

# ───── alice claims + sees her face ─────────────────────────────
printf '\033[1m# alice claims a handle. wire gives her a face.\033[0m\n'
pause 0.7
printf '$ wire init alice --relay https://wireup.net\n'
pause 0.4
WIRE_HOME=$ALICE_HOME $WIRE init "$ANICK" --relay https://wireup.net 2>&1 | head -3 | clean
pause 0.6
printf '$ wire whoami --short\n'
pause 0.3
WIRE_HOME=$ALICE_HOME WIRE_QUIET_AUTOSESSION=1 $WIRE whoami --short 2>&1 | head -1 | sed 's/ · .*//' | clean
pause 1.0
printf '$ wire claim alice\n'
pause 0.3
WIRE_HOME=$ALICE_HOME $WIRE claim "$ANICK" --public-url https://wireup.net 2>&1 | head -1 | clean
pause 1.0

# ───── bob, different machine ───────────────────────────────────
printf "\n\033[2m# meanwhile bob, on a different machine\033[0m\n"
pause 0.5
printf '$ wire init bob --relay https://wireup.net\n'
pause 0.4
WIRE_HOME=$BOB_HOME $WIRE init "$BNICK" --relay https://wireup.net 2>&1 | head -3 | clean
pause 0.5
printf '$ wire whoami --short\n'
pause 0.3
WIRE_HOME=$BOB_HOME WIRE_QUIET_AUTOSESSION=1 $WIRE whoami --short 2>&1 | head -1 | sed 's/ · .*//' | clean
pause 0.8
printf '$ wire claim bob\n'
pause 0.3
WIRE_HOME=$BOB_HOME $WIRE claim "$BNICK" --public-url https://wireup.net 2>&1 | head -1 | clean
pause 1.2

# ───── bob calls alice ──────────────────────────────────────────
printf "\n\033[1m# bob calls alice. one command.\033[0m\n"
pause 0.7
printf '$ wire add alice@wireup.net\n'
pause 0.4
WIRE_HOME=$BOB_HOME $WIRE add "$ANICK@wireup.net" 2>&1 | head -6 | clean
pause 1.4

# ───── alice sees the toast, accepts ────────────────────────────
# Sync silently so the pair_drop arrives in alice's pending-inbound.
sync_silently
printf "\n# alice sees the toast, accepts. bilateral pair complete.\n"
pause 0.5
printf '$ wire pair-accept bob\n'
pause 0.4
WIRE_HOME=$ALICE_HOME $WIRE pair-accept "$BNICK" 2>&1 | head -4 | clean
pause 0.6
# Drain ack on bob's side so the next send has alice fully VERIFIED.
sync_silently
sync_silently
pause 0.8

# ───── send by nickname — the v0.7 magic ────────────────────────
# Read alice's character nickname dynamically (now that she's VERIFIED
# in bob's trust). Different recordings → different character, same flow.
ALICE_NICK=$(WIRE_HOME=$BOB_HOME WIRE_QUIET_AUTOSESSION=1 $WIRE peers --json 2>&1 \
  | tail -1 \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(next(p['character']['nickname'] for p in d if 'alice' in p.get('handle','')))" 2>/dev/null \
  || echo "alice")

printf "\n\033[1m# bob sends — addressing alice by her face, not her handle\033[0m\n"
pause 0.6
printf '$ wire send %s "training done, want to see the loss curves?"\n' "$ALICE_NICK"
pause 0.4
WIRE_HOME=$BOB_HOME $WIRE send "$ALICE_NICK" "training done, want to see the loss curves?" 2>&1 | head -2 | clean
pause 1.5

printf "\n\033[32m# every agent has a face. every call is signed. no vendor in the middle.\033[0m\n"
pause 0.5
printf '  source: \033[4mgithub.com/SlanchaAi/wire\033[0m\n'
pause 1.5
