#!/bin/bash
# Replayable cast script — wire's handle-based pair flow on wireup.net.
# Two operators (alice + bob) claim handles, bob runs `wire add` (one
# command, no SAS, no code phrase), alice's daemon auto-pins, bob sends
# a signed message. Real run against https://wireup.net.
#
# Re-record with:  asciinema rec landing/demo.cast --overwrite \
#                    --output-format asciicast-v2 \
#                    --command 'bash landing/demo.sh'

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

# Substitute throwaway demo handles → readable names in the displayed output.
# Actual relay records use the unique nicks so re-recording never collides.
clean() {
  sed -E \
    -e "s/$ANICK/alice/g" \
    -e "s/$BNICK/bob/g" \
    -e "s/alice-$TS-[a-f0-9]+/alice/g" \
    -e "s/bob-$TS-[a-f0-9]+/bob/g" \
    -e "s/alice-$TS/alice/g" \
    -e "s/bob-$TS/bob/g"
}

# ───── alice ────────────────────────────────────────────────────
printf '\033[1m# alice claims a handle\033[0m\n'
pause 0.7
printf '$ wire init alice --relay https://wireup.net\n'
pause 0.4
WIRE_HOME=$ALICE_HOME $WIRE init "alice-$TS" --relay https://wireup.net 2>&1 | head -3 | clean
pause 0.9
printf '$ wire claim alice\n'
pause 0.4
WIRE_HOME=$ALICE_HOME $WIRE claim "$ANICK" --public-url https://wireup.net 2>&1 | head -2 | clean
pause 1.4

# ───── bob ──────────────────────────────────────────────────────
printf "\n\033[2m# meanwhile bob does the same\033[0m\n"
pause 0.5
printf '$ wire init bob --relay https://wireup.net\n'
pause 0.4
WIRE_HOME=$BOB_HOME $WIRE init "bob-$TS" --relay https://wireup.net 2>&1 | head -3 | clean
pause 0.7
printf '$ wire claim bob\n'
pause 0.4
WIRE_HOME=$BOB_HOME $WIRE claim "$BNICK" --public-url https://wireup.net 2>&1 | head -2 | clean
pause 1.4

# ───── the marquee one-command pair ─────────────────────────────
printf "\n\033[1m# bob adds alice — one command, zero paste, no SAS\033[0m\n"
pause 0.7
printf '$ wire add alice@wireup.net\n'
pause 0.4
WIRE_HOME=$BOB_HOME $WIRE add "$ANICK@wireup.net" 2>&1 | head -6 | clean
pause 1.5

printf "\n# alice\xe2\x80\x99s daemon pulls, auto-pins bob, sends ack back\n"
pause 0.5
printf '$ wire daemon --once\n'
pause 0.4
WIRE_HOME=$ALICE_HOME $WIRE daemon --once 2>&1 | head -3 | clean
pause 0.6
# bob picks up the ack silently so his outbox can flow next
WIRE_HOME=$BOB_HOME $WIRE daemon --once > /dev/null 2>&1
pause 1.0

# ───── signed message ──────────────────────────────────────────
printf "\n# bilateral pair complete — bob sends a signed event\n"
pause 0.5
printf '$ wire send alice decision "hey alice from bob"\n'
pause 0.4
WIRE_HOME=$BOB_HOME $WIRE send "$ANICK" decision "hey alice from bob" 2>&1 | head -1 | clean
pause 1.6

printf "\n\033[32m# done. handle-based, signed end-to-end, no code phrase, no SAS.\033[0m\n"
pause 0.5
printf '  source: \033[4mgithub.com/SlanchaAi/wire\033[0m\n'
pause 1.5
