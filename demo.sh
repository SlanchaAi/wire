#!/usr/bin/env bash
# demo.sh — scripted bilateral demo of `wire`.
#
# Drives the full v0.1 user flow as a self-contained bash test:
#   1. boots a local relay-server
#   2. inits two agents (paul + willard) in separate WIRE_HOMEs
#   3. pair-host + pair-join via SAS (using --yes for non-interactive run;
#      in real life operators read SAS digits aloud and confirm)
#   4. paul sends a "decision" event to willard
#   5. paul push → willard pull → willard tail
#   6. asserts the verified event lands in willard's inbox with body roundtrip
#
# Usage:
#   ./demo.sh              # uses ./target/release/wire
#   WIRE_BIN=/usr/local/bin/wire ./demo.sh
#
# Exit codes: 0 success; 1 bin missing; 2 relay didn't bind; 3 demo assertion failed.

set -euo pipefail

WIRE_BIN="${WIRE_BIN:-$(pwd)/target/release/wire}"
if [ ! -x "$WIRE_BIN" ]; then
    if command -v wire >/dev/null 2>&1; then
        WIRE_BIN="$(command -v wire)"
    else
        echo "FATAL: wire binary not found at $WIRE_BIN and not on PATH" >&2
        echo "Run: cargo build --release  (or set WIRE_BIN to the binary path)" >&2
        exit 1
    fi
fi

echo "▶ using wire binary: $WIRE_BIN"
"$WIRE_BIN" --version

# Ephemeral state dirs — all under one demo root that we clean on exit.
DEMO_ROOT="$(mktemp -d -t wire-demo.XXXXXX)"
RELAY_HOME="$DEMO_ROOT/relay"
PAUL_HOME="$DEMO_ROOT/paul"
WILLARD_HOME="$DEMO_ROOT/willard"
mkdir -p "$RELAY_HOME" "$PAUL_HOME" "$WILLARD_HOME"

cleanup() {
    if [ -n "${RELAY_PID:-}" ] && kill -0 "$RELAY_PID" 2>/dev/null; then
        kill "$RELAY_PID" 2>/dev/null || true
        wait "$RELAY_PID" 2>/dev/null || true
    fi
    rm -rf "$DEMO_ROOT"
}
trap cleanup EXIT

# Pick a free port on localhost.
RELAY_PORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])' 2>/dev/null || echo 18770)"
RELAY_URL="http://127.0.0.1:$RELAY_PORT"

echo "▶ starting relay-server on $RELAY_URL ..."
WIRE_HOME="$RELAY_HOME" "$WIRE_BIN" relay-server --bind "127.0.0.1:$RELAY_PORT" \
    > "$DEMO_ROOT/relay.log" 2>&1 &
RELAY_PID=$!

# Wait up to 5s for relay to bind.
for i in $(seq 1 50); do
    if curl -fsS "$RELAY_URL/healthz" >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done
if ! curl -fsS "$RELAY_URL/healthz" >/dev/null 2>&1; then
    echo "FATAL: relay didn't come up; log:" >&2
    cat "$DEMO_ROOT/relay.log" >&2
    exit 2
fi
echo "▶ relay up"

# ----- init paul + willard -----
WIRE_HOME="$PAUL_HOME"    "$WIRE_BIN" init paul    >/dev/null
WIRE_HOME="$WILLARD_HOME" "$WIRE_BIN" init willard >/dev/null
echo "▶ paul + willard init done"

# ----- pair via SAS -----
echo "▶ paul opening pair-slot ..."
WIRE_HOME="$PAUL_HOME" "$WIRE_BIN" pair-host \
    --relay "$RELAY_URL" --yes --timeout 30 \
    > "$DEMO_ROOT/paul-pair.json" 2> "$DEMO_ROOT/paul-pair.stderr" &
PAUL_PAIR_PID=$!

# Wait for the code phrase to appear on stderr.
CODE=""
for i in $(seq 1 100); do
    CODE="$(grep -E '^    [0-9]{2}-[A-Z2-7]{6}$' "$DEMO_ROOT/paul-pair.stderr" 2>/dev/null \
        | head -1 | tr -d ' ' || true)"
    if [ -n "$CODE" ]; then break; fi
    sleep 0.1
done
if [ -z "$CODE" ]; then
    echo "FATAL: never got code phrase from pair-host:" >&2
    cat "$DEMO_ROOT/paul-pair.stderr" >&2
    exit 3
fi
echo "▶ paul printed code: $CODE"

echo "▶ willard joining ..."
WIRE_HOME="$WILLARD_HOME" "$WIRE_BIN" pair-join "$CODE" \
    --relay "$RELAY_URL" --yes --timeout 30 \
    > "$DEMO_ROOT/willard-pair.json"

wait "$PAUL_PAIR_PID"
echo "▶ pairing complete"

# Assert SAS digits matched (both files contain matching `sas` field).
PAUL_SAS="$(   grep -o '"sas":"[^"]*"' "$DEMO_ROOT/paul-pair.json"    || echo '?')"
WILLARD_SAS="$(grep -o '"sas":"[^"]*"' "$DEMO_ROOT/willard-pair.json" || echo '?')"
if [ "$PAUL_SAS" != "$WILLARD_SAS" ]; then
    echo "FATAL: SAS mismatch: paul=$PAUL_SAS willard=$WILLARD_SAS" >&2
    exit 3
fi
echo "▶ SAS confirmed matching: $PAUL_SAS"

# ----- send / push / pull / tail -----
WIRE_HOME="$PAUL_HOME" "$WIRE_BIN" send willard decision "ship the v0.1 demo" >/dev/null
echo "▶ paul wrote signed event to outbox"

PUSH_OUT="$(WIRE_HOME="$PAUL_HOME" "$WIRE_BIN" push --json)"
PUSHED_COUNT="$(echo "$PUSH_OUT" | python3 -c 'import json,sys;print(len(json.load(sys.stdin)["pushed"]))' 2>/dev/null || echo 0)"
if [ "$PUSHED_COUNT" != "1" ]; then
    echo "FATAL: expected 1 pushed event, got $PUSHED_COUNT" >&2
    exit 3
fi
echo "▶ paul pushed 1 event to relay"

PULL_OUT="$(WIRE_HOME="$WILLARD_HOME" "$WIRE_BIN" pull --json)"
WRITTEN_COUNT="$(echo "$PULL_OUT" | python3 -c 'import json,sys;print(len(json.load(sys.stdin)["written"]))' 2>/dev/null || echo 0)"
REJECTED_COUNT="$(echo "$PULL_OUT" | python3 -c 'import json,sys;print(len(json.load(sys.stdin)["rejected"]))' 2>/dev/null || echo 0)"
if [ "$WRITTEN_COUNT" != "1" ] || [ "$REJECTED_COUNT" != "0" ]; then
    echo "FATAL: expected 1 verified pull / 0 rejected; got written=$WRITTEN_COUNT rejected=$REJECTED_COUNT" >&2
    echo "$PULL_OUT" >&2
    exit 3
fi
echo "▶ willard pulled, verified, wrote 1 event to inbox"

TAIL_OUT="$(WIRE_HOME="$WILLARD_HOME" "$WIRE_BIN" tail paul --json)"
BODY="$(echo "$TAIL_OUT" | head -1 | python3 -c 'import json,sys;e=json.loads(sys.stdin.read());print(e["body"]); print("verified" if e.get("verified") else "UNVERIFIED")' 2>/dev/null || echo 'parse-failed')"
if ! echo "$BODY" | grep -q '^ship the v0.1 demo$' || ! echo "$BODY" | grep -q '^verified$'; then
    echo "FATAL: tail body roundtrip failed:" >&2
    echo "$TAIL_OUT" >&2
    exit 3
fi
echo "▶ willard tail confirmed: body roundtripped + signature verified"

echo
echo "✓ demo passed — wire v0.1 round-trip works end-to-end"
echo "  $PAUL_SAS, body=\"ship the v0.1 demo\", signature verified"
