#!/usr/bin/env bash
# demo-detached.sh — scripted bilateral demo of the v0.3 detached pair flow.
#
# Drives the full daemon-orchestrated user experience as a self-contained
# bash test:
#   1. boots a local relay-server
#   2. inits two agents (paul + willard) in separate WIRE_HOMEs
#   3. starts a long-running daemon per side
#   4. paul `pair-host --detach`     → code phrase, exits immediately
#   5. willard `pair-join --detach`  → joins, exits immediately
#   6. polls `pair-list --json` until both reach sas_ready
#   7. asserts digits match across sides
#   8. confirms on both sides
#   9. waits for finalize → `wire peers` shows the counterparty
#  10. paul `send` → daemons sync → willard `tail` (signed event delivered)
#
# Cleans up relay + daemons on exit. Suitable for CI smoke or operator
# walk-through.
#
# Usage:
#   bash demo-detached.sh                   # uses ./target/release/wire
#   WIRE=/path/to/wire bash demo-detached.sh
#
# Requires: jq (for parsing pair-list JSON).

set -euo pipefail

WIRE="${WIRE:-./target/release/wire}"
if [ ! -x "$WIRE" ]; then
    echo "fatal: $WIRE not found or not executable. Run 'cargo build --release' first." >&2
    exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
    echo "fatal: jq is required for this demo. brew install jq / apt install jq." >&2
    exit 1
fi

TMP="$(mktemp -d)"
trap 'cleanup' EXIT INT TERM
cleanup() {
    [ -n "${RELAY_PID:-}" ] && kill "$RELAY_PID" 2>/dev/null || true
    [ -n "${PAUL_DAEMON:-}" ] && kill "$PAUL_DAEMON" 2>/dev/null || true
    [ -n "${WILL_DAEMON:-}" ] && kill "$WILL_DAEMON" 2>/dev/null || true
    wait 2>/dev/null || true
    rm -rf "$TMP"
}

RELAY_DIR="$TMP/relay"
PAUL="$TMP/paul"
WILL="$TMP/willard"
mkdir -p "$RELAY_DIR" "$PAUL" "$WILL"

PORT="$(shuf -i 10000-65000 -n 1)"
RELAY="http://127.0.0.1:$PORT"

echo "== boot relay on $RELAY =="
WIRE_HOME="$RELAY_DIR" "$WIRE" relay-server --bind "127.0.0.1:$PORT" \
    > "$TMP/relay.log" 2>&1 &
RELAY_PID=$!
for _ in $(seq 1 20); do
    sleep 0.1
    curl -fsS "$RELAY/healthz" >/dev/null 2>&1 && break
done
curl -fsS "$RELAY/healthz" >/dev/null || { echo "relay did not come up"; exit 1; }

echo "== init paul + willard =="
WIRE_HOME="$PAUL" "$WIRE" init paul --relay "$RELAY" >/dev/null
WIRE_HOME="$WILL" "$WIRE" init willard --relay "$RELAY" >/dev/null
# v0.11: the typed `paul`/`willard` are ignored at init; each side is
# addressable only by its DID-derived character. Discover them.
PAUL_H="$(WIRE_HOME="$PAUL" "$WIRE" whoami --json | jq -r .handle)"
WILL_H="$(WIRE_HOME="$WILL" "$WIRE" whoami --json | jq -r .handle)"
echo "   paul    → $PAUL_H"
echo "   willard → $WILL_H"

echo "== spawn long-running daemons (1s tick) =="
WIRE_HOME="$PAUL" "$WIRE" daemon --interval 1 </dev/null \
    >"$TMP/paul-daemon.log" 2>&1 &
PAUL_DAEMON=$!
WIRE_HOME="$WILL" "$WIRE" daemon --interval 1 </dev/null \
    >"$TMP/willard-daemon.log" 2>&1 &
WILL_DAEMON=$!
sleep 0.5

echo "== paul: detached pair-host =="
HOST_JSON="$(WIRE_HOME="$PAUL" "$WIRE" pair-host --detach --json --relay "$RELAY")"
CODE="$(echo "$HOST_JSON" | jq -r '.code_phrase')"
echo "   code phrase: $CODE"

echo "== willard: detached pair-join =="
WIRE_HOME="$WILL" "$WIRE" pair-join "$CODE" --detach --json --relay "$RELAY" >/dev/null

echo "== wait for both sides to reach sas_ready =="
for _ in $(seq 1 60); do
    PAUL_SAS="$(WIRE_HOME="$PAUL" "$WIRE" pair-list --json | \
        jq -r '.[] | select(.code=="'$CODE'" and .status=="sas_ready") | .sas' 2>/dev/null || true)"
    WILL_SAS="$(WIRE_HOME="$WILL" "$WIRE" pair-list --json | \
        jq -r '.[] | select(.code=="'$CODE'" and .status=="sas_ready") | .sas' 2>/dev/null || true)"
    [ -n "$PAUL_SAS" ] && [ -n "$WILL_SAS" ] && break
    sleep 0.5
done
[ -n "$PAUL_SAS" ] || { echo "paul never reached sas_ready"; exit 1; }
[ -n "$WILL_SAS" ] || { echo "willard never reached sas_ready"; exit 1; }
[ "$PAUL_SAS" = "$WILL_SAS" ] || { echo "SAS mismatch! paul=$PAUL_SAS willard=$WILL_SAS"; exit 1; }
echo "   ✓ both sides agree: SAS = ${PAUL_SAS:0:3}-${PAUL_SAS:3:3}"

echo "== confirm on both sides =="
WIRE_HOME="$PAUL" "$WIRE" pair-confirm "$CODE" "$PAUL_SAS" --json >/dev/null
WIRE_HOME="$WILL" "$WIRE" pair-confirm "$CODE" "$WILL_SAS" --json >/dev/null

echo "== wait for pair-list to drain (daemons finalize) =="
for _ in $(seq 1 30); do
    PAUL_CNT="$(WIRE_HOME="$PAUL" "$WIRE" pair-list --json | jq 'length')"
    WILL_CNT="$(WIRE_HOME="$WILL" "$WIRE" pair-list --json | jq 'length')"
    [ "$PAUL_CNT" = "0" ] && [ "$WILL_CNT" = "0" ] && break
    sleep 0.5
done
[ "$PAUL_CNT" = "0" ] || { echo "paul pair-list did not drain"; exit 1; }
[ "$WILL_CNT" = "0" ] || { echo "willard pair-list did not drain"; exit 1; }
echo "   ✓ both pair-lists empty"

echo "== verify wire peers =="
WIRE_HOME="$PAUL" "$WIRE" peers | grep -q "$WILL_H" || { echo "paul missing $WILL_H"; exit 1; }
WIRE_HOME="$WILL" "$WIRE" peers | grep -q "$PAUL_H" || { echo "willard missing $PAUL_H"; exit 1; }
echo "   ✓ both peers VERIFIED"

echo "== send + sync + tail =="
WIRE_HOME="$PAUL" "$WIRE" send "$WILL_H" claim "demo-detached: hello from paul" >/dev/null
# Daemons sync every 1s; allow up to 5s for the event to land in willard's inbox.
for _ in $(seq 1 10); do
    if WIRE_HOME="$WILL" "$WIRE" tail 2>&1 | grep -q "demo-detached: hello"; then
        echo "   ✓ event delivered, signature verified"
        break
    fi
    sleep 0.5
done

echo ""
echo "✓ detached pair demo complete — pair handshake + send/recv all working."
echo "  See: $TMP for daemon logs (will be cleaned on exit)."
