#!/usr/bin/env bash
# demo-invite.sh — scripted demo of the v0.4.0 one-paste invite pair.
#
# Drives the entire pair flow as a single bash test:
#   1. boots a local relay-server
#   2. inits two wire homes (paul + willard) on the local relay
#   3. paul: `wire invite` → URL
#   4. willard: `wire accept <URL>` → sends signed pair_drop event
#   5. paul `wire pull` → consumes pair_drop → pins willard
#   6. paul `wire send willard` → willard `wire pull` → message lands
#   7. willard `wire send paul` → paul `wire pull` → ack lands
#   8. assert both inboxes contain expected messages
#
# Compare to demo-detached.sh: that one runs the v0.3 SPAKE2 + SAS flow
# with a daemon-orchestrated handshake and a 6-digit operator confirm
# step. This one is the v0.4.0 default: no SAS, no daemon needed for the
# pair itself (a single `pull` suffices), no turn-taking.
#
# Usage:
#   bash demo-invite.sh
#   WIRE=/path/to/wire bash demo-invite.sh
#
# Requires: jq.

set -euo pipefail

WIRE="${WIRE:-./target/release/wire}"
if [ ! -x "$WIRE" ]; then
    echo "fatal: $WIRE not found or not executable. Run 'cargo build --release' first." >&2
    exit 1
fi
command -v jq >/dev/null || { echo "fatal: jq required"; exit 1; }

WORK="$(mktemp -d -t wire-invite-demo.XXXXXX)"
RELAY_DIR="$WORK/relay"
PAUL_HOME="$WORK/paul"
WILLARD_HOME="$WORK/willard"
RELAY_PORT=18791
RELAY_URL="http://127.0.0.1:$RELAY_PORT"

cleanup() {
    [ -n "${RELAY_PID:-}" ] && kill "$RELAY_PID" 2>/dev/null || true
    wait 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

mkdir -p "$RELAY_DIR" "$PAUL_HOME" "$WILLARD_HOME"

echo "→ booting local relay on $RELAY_URL"
WIRE_HOME="$RELAY_DIR" "$WIRE" relay-server --bind "127.0.0.1:$RELAY_PORT" \
    >"$WORK/relay.log" 2>&1 &
RELAY_PID=$!
sleep 0.5
curl -fsS "$RELAY_URL/healthz" >/dev/null || { echo "relay did not come up"; cat "$WORK/relay.log"; exit 1; }

echo "→ paul + willard init on $RELAY_URL"
WIRE_HOME="$PAUL_HOME"    "$WIRE" init paul    --relay "$RELAY_URL" >/dev/null
WIRE_HOME="$WILLARD_HOME" "$WIRE" init willard --relay "$RELAY_URL" >/dev/null

echo "→ paul mints invite URL"
INVITE_JSON=$(WIRE_HOME="$PAUL_HOME" "$WIRE" invite --relay "$RELAY_URL" --json)
INVITE_URL=$(echo "$INVITE_JSON" | jq -r '.invite_url')
case "$INVITE_URL" in
    wire://pair?v=1\&inv=*)
        echo "    URL ok (${#INVITE_URL} bytes)"
        ;;
    *)
        echo "    FAIL: unexpected URL shape: $INVITE_URL"
        exit 1
        ;;
esac

echo "→ willard accepts URL (one paste)"
ACCEPT_JSON=$(WIRE_HOME="$WILLARD_HOME" "$WIRE" accept "$INVITE_URL" --json)
PAIRED_WITH=$(echo "$ACCEPT_JSON" | jq -r '.paired_with')
case "$PAIRED_WITH" in
    "did:wire:paul-"*) ;;
    *) echo "    FAIL: paired_with=$PAIRED_WITH (expected did:wire:paul-<hex>)"; exit 1 ;;
esac
echo "    willard pinned paul. drop sent to paul's slot."

echo "→ paul pulls (consumes pair_drop → pins willard)"
PULL=$(WIRE_HOME="$PAUL_HOME" "$WIRE" pull --json)
WRITTEN=$(echo "$PULL" | jq '.written | length')
[ "$WRITTEN" = "1" ] || { echo "    FAIL: expected 1 written event, got $WRITTEN"; echo "$PULL"; exit 1; }

PAUL_PEERS=$(WIRE_HOME="$PAUL_HOME" "$WIRE" peers --json | jq -r '.[].handle' | sort | tr '\n' ',' | sed 's/,$//')
echo "    paul peers: $PAUL_PEERS"
case ",$PAUL_PEERS," in *,willard,*) ;; *) echo "    FAIL: willard not in paul peers"; exit 1 ;; esac

echo "→ paul → willard send"
WIRE_HOME="$PAUL_HOME" "$WIRE" send willard decision "hello via v0.4.0 invite" >/dev/null
WIRE_HOME="$PAUL_HOME" "$WIRE" push --json | jq -r '.pushed | length' | xargs -I{} echo "    pushed {} event(s)"
WIRE_HOME="$WILLARD_HOME" "$WIRE" pull --json | jq -r '.written | length' | xargs -I{} echo "    willard pulled {} event(s)"

grep -q "hello via v0.4.0 invite" "$WILLARD_HOME/state/wire/inbox/paul.jsonl" \
    || { echo "    FAIL: message not in willard inbox"; exit 1; }
echo "    paul → willard verified"

echo "→ willard → paul ack"
WIRE_HOME="$WILLARD_HOME" "$WIRE" send paul decision "ack from willard" >/dev/null
WIRE_HOME="$WILLARD_HOME" "$WIRE" push --json | jq -r '.pushed | length' | xargs -I{} echo "    pushed {} event(s)"
WIRE_HOME="$PAUL_HOME" "$WIRE" pull --json | jq -r '.written | length' | xargs -I{} echo "    paul pulled {} event(s)"

grep -q "ack from willard" "$PAUL_HOME/state/wire/inbox/willard.jsonl" \
    || { echo "    FAIL: ack not in paul inbox"; exit 1; }
echo "    willard → paul verified"

echo
echo "✓ invite-pair demo complete — one paste, bidirectional signed events."
