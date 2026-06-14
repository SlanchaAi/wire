#!/usr/bin/env bash
# demo-hotline.sh — scripted demo of the v0.5 agentic hotline.
#
# Five agents with five different vibes claim handles on a local relay,
# then `wire add` each other into a fully-connected 5-mesh. Each sets
# personality fields (emoji, motto, vibe). Bidirectional signed sends
# round-trip cleanly. The goal is to show that v0.5 collapses a 5-agent
# pair from N*(N-1)/2 invite-URL exchanges (10 pastes) to N*(N-1)/2
# single-command `wire add`s — fully zero-paste.
#
# Compare to demo-detached.sh (v0.3 SPAKE2 + SAS) and demo-invite.sh
# (v0.4 single-paste URL). v0.5 is single-command per pair, after the
# host claim.
#
# Usage:
#   bash demo-hotline.sh
#   WIRE=/path/to/wire bash demo-hotline.sh
#
# Requires: jq.

set -euo pipefail

WIRE="${WIRE:-./target/release/wire}"
[ -x "$WIRE" ] || { echo "fatal: $WIRE not found. Run 'cargo build --release' first." >&2; exit 1; }
command -v jq >/dev/null || { echo "fatal: jq required"; exit 1; }

WORK="$(mktemp -d -t wire-hotline-demo.XXXXXX)"
RELAY_DIR="$WORK/relay"
RELAY_PORT=18793
RELAY_URL="http://127.0.0.1:$RELAY_PORT"
HANDLE_DOMAIN="127.0.0.1"

cleanup() {
    [ -n "${RELAY_PID:-}" ] && kill "$RELAY_PID" 2>/dev/null || true
    wait 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

mkdir -p "$RELAY_DIR"
echo "→ booting local relay on $RELAY_URL"
WIRE_HOME="$RELAY_DIR" "$WIRE" relay-server --bind "127.0.0.1:$RELAY_PORT" \
    >"$WORK/relay.log" 2>&1 &
RELAY_PID=$!
sleep 0.5
curl -fsS "$RELAY_URL/healthz" >/dev/null || { echo "relay did not come up"; cat "$WORK/relay.log"; exit 1; }

# Five agents, five vibes.
declare -a HANDLES=("coffee-ghost" "tide-pool" "kuiper" "bramble" "marginalia")
declare -A EMOJI=(
    ["coffee-ghost"]="👻"
    ["tide-pool"]="🌊"
    ["kuiper"]="🛰️"
    ["bramble"]="🪴"
    ["marginalia"]="📖"
)
declare -A MOTTO=(
    ["coffee-ghost"]="haunts late-night PR reviews"
    ["tide-pool"]="watches the arxiv firehose"
    ["kuiper"]="outer-system telemetry"
    ["bramble"]="compost daemon"
    ["marginalia"]="reads footnotes professionally"
)

# Boot all five — init + profile + claim. v0.11: the wire-card handle
# is the DID-derived character, not the operator-typed name. We keep the
# operator-friendly label `$h` (coffee-ghost, tide-pool, ...) for the
# directory + emoji/motto labelling, but discover each agent's actual
# wire handle right after init and use that everywhere on-wire.
declare -A CHAR_OF
for h in "${HANDLES[@]}"; do
    home="$WORK/$h"
    mkdir -p "$home"
    echo "→ $h: init + claim"
    WIRE_HOME="$home" "$WIRE" init --relay "$RELAY_URL" >/dev/null
    char="$(WIRE_HOME="$home" "$WIRE" whoami --json | jq -r .handle)"
    CHAR_OF[$h]="$char"
    WIRE_HOME="$home" "$WIRE" profile set emoji "${EMOJI[$h]}" >/dev/null
    WIRE_HOME="$home" "$WIRE" profile set motto "${MOTTO[$h]}" >/dev/null
    WIRE_HOME="$home" "$WIRE" claim "$char" --public-url "$RELAY_URL" >/dev/null
    echo "    label=$h   wire-handle=$char"
done

# Each agent wire-adds every other agent — by character handle on the wire.
echo
echo "→ building 5-mesh via wire add (10 commands, no paste, no SAS)"
for adder in "${HANDLES[@]}"; do
    for target in "${HANDLES[@]}"; do
        [ "$adder" = "$target" ] && continue
        target_char="${CHAR_OF[$target]}"
        # Skip if already added (idempotent — adding twice is fine but verbose).
        if [ ! -f "$WORK/$adder/state/wire/inbox/$target_char.jsonl" ]; then
            WIRE_HOME="$WORK/$adder" "$WIRE" add "$target_char@$HANDLE_DOMAIN" \
                --relay "$RELAY_URL" --json >/dev/null
        fi
    done
done

# Drain pair_drops into pending_inbound, accept each to finalize the
# bilateral pin, then drain pair_drop_acks so both sides record each other's
# slot_token. v0.5.14 removed receiver auto-promote on pull (phonebook-scrape
# mitigation): a stashed pair_drop now requires explicit `wire accept`
# before the slot_token flows back via pair_drop_ack. Without this step,
# `wire push` later reports `no reachable endpoint pinned for peer` and the
# ring-send phase silently drops every message. v0.11: accept by character.
for _ in 1 2 3 4 5; do
    for h in "${HANDLES[@]}"; do
        WIRE_HOME="$WORK/$h" "$WIRE" pull --json >/dev/null
        for peer in "${HANDLES[@]}"; do
            [ "$peer" = "$h" ] && continue
            WIRE_HOME="$WORK/$h" "$WIRE" accept "${CHAR_OF[$peer]}" --json >/dev/null 2>&1 || true
        done
    done
done

# Each agent should have 4 peers.
echo
echo "→ verifying mesh — each agent should see 4 peers:"
for h in "${HANDLES[@]}"; do
    n=$(WIRE_HOME="$WORK/$h" "$WIRE" peers --json | jq 'length')
    handles=$(WIRE_HOME="$WORK/$h" "$WIRE" peers --json | jq -r '.[] | .handle' | sort | paste -sd ',' -)
    if [ "$n" != "4" ]; then
        echo "  FAIL: $h (${CHAR_OF[$h]}) has $n peers (expected 4): $handles"
        exit 1
    fi
    echo "  $h (${EMOJI[$h]}, ${CHAR_OF[$h]}): $handles"
done

# Round-trip a message from each agent to its alphabetically-next peer.
echo
echo "→ ring-send: each agent → next agent"
declare -a RING=("${HANDLES[@]}")
N=${#RING[@]}
for i in "${!RING[@]}"; do
    src=${RING[$i]}
    dst=${RING[$(( (i + 1) % N ))]}
    dst_char="${CHAR_OF[$dst]}"
    WIRE_HOME="$WORK/$src" "$WIRE" send "$dst_char" decision \
        "hi $dst (${EMOJI[$dst]}), $src (${EMOJI[$src]}) here" >/dev/null
done
for h in "${HANDLES[@]}"; do
    WIRE_HOME="$WORK/$h" "$WIRE" push --json >/dev/null
done
for h in "${HANDLES[@]}"; do
    WIRE_HOME="$WORK/$h" "$WIRE" pull --json >/dev/null
done
for i in "${!RING[@]}"; do
    src=${RING[$i]}
    dst=${RING[$(( (i + 1) % N ))]}
    src_char="${CHAR_OF[$src]}"
    # D1: paired peers' messages are encrypted at rest — read decrypted via tail.
    if ! WIRE_HOME="$WORK/$dst" "$WIRE" tail "$src_char" --json 2>/dev/null | grep -q "hi $dst"; then
        echo "  FAIL: $dst (${CHAR_OF[$dst]}) did not receive $src ($src_char)'s ring message"
        exit 1
    fi
    echo "  $src → $dst ✓"
done

echo
echo "✓ agentic hotline demo complete — 5-mesh, 10 zero-paste pairs, signed ring."
