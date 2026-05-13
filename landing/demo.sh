#!/bin/bash
# Replayable demo script for the landing-page asciinema cast.
# Drives a real pair-host / pair-join handshake against https://wireup.net
# using two throwaway identities under /tmp/wire-demo-cast/.
#
# Re-record with:  asciinema rec landing/demo.cast --command 'bash landing/demo.sh'

set -e

HOST_HOME=/tmp/wire-demo-cast/host
GUEST_HOME=/tmp/wire-demo-cast/guest
rm -rf /tmp/wire-demo-cast
mkdir -p "$HOST_HOME" "$GUEST_HOME"

pause() { sleep "${1:-0.9}"; }

# ───── alice's terminal ─────────────────────────────────────────
printf '\033[1m# alice gets a wire identity (one-time setup)\033[0m\n'
pause 0.8
printf '$ wire init alice --relay https://wireup.net\n'
pause 0.6
WIRE_HOME=$HOST_HOME wire init alice --relay https://wireup.net 2>&1 | head -3
pause 1.5

printf '\n\033[1m# alice opens a pair session — wire mints a code phrase\033[0m\n'
pause 0.8
printf '$ wire pair-host --relay https://wireup.net\n'
pause 0.6
# start pair-host in background, capture stdout
rm -f /tmp/wire-demo-cast/host.out
( WIRE_HOME=$HOST_HOME wire pair-host --relay https://wireup.net --yes > /tmp/wire-demo-cast/host.out 2>&1 ) &
HOST_PID=$!
# wait until the code phrase appears
while ! grep -qE '[0-9]+-[A-Z0-9]+' /tmp/wire-demo-cast/host.out 2>/dev/null; do sleep 0.3; done
CODE=$(grep -oE '[0-9]+-[A-Z0-9]+' /tmp/wire-demo-cast/host.out | head -1)
printf '\n  share this code phrase with your peer:\n\n      \033[33m%s\033[0m\n\n  waiting for peer to run `wire pair-join %s --relay https://wireup.net` ...\n' "$CODE" "$CODE"
pause 2.2

# ───── bob's terminal ───────────────────────────────────────────
printf "\n\033[2m# ──── meanwhile on bob\xe2\x80\x99s machine ────────────────────────────\033[0m\n"
pause 1.0
printf '$ wire init bob --relay https://wireup.net\n'
pause 0.5
WIRE_HOME=$GUEST_HOME wire init bob --relay https://wireup.net 2>&1 | head -3 > /dev/null
printf '  bound to https://wireup.net (slot allocated)\n'
pause 1.2

printf '\n$ wire pair-join %s --relay https://wireup.net\n' "$CODE"
pause 0.6
WIRE_HOME=$GUEST_HOME wire pair-join "$CODE" --relay https://wireup.net --yes 2>&1 | head -8
pause 1.0
wait $HOST_PID 2>/dev/null

printf '\n\033[32m# both sides verified the same SAS — pair complete, peer pinned at VERIFIED\033[0m\n'
pause 1.5
printf '$ wire send bob "hey from alice"\n'
pause 0.4
printf '  queued kind=2000 message → bob (sig=ed25519:alice:%s)\n' "$(WIRE_HOME=$HOST_HOME wire whoami 2>/dev/null | grep -oE 'ed25519:[^ )]+' | head -1 | cut -d: -f3)"
pause 1.8

printf "\n\033[1m# that\xe2\x80\x99s it. signed messages, end-to-end, \$0/mo public relay.\033[0m\n"
pause 1.5
printf '  source: \033[4mgithub.com/SlanchaAi/wire\033[0m\n'
pause 1.5
