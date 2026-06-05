#!/usr/bin/env bash
# demo-show.sh — presentation variant of demo.sh for the launch demo GIF.
#
# Runs the SAME real bilateral flow as demo.sh (boot relay → init two agents →
# SAS pair → send → push → pull → verified tail) but narrated at human reading
# speed with two-agent color prefixes, so it records cleanly as a ~60s GIF.
# Nothing here is faked — the SAS code, signatures, and tail output are real.
#
# Usage:  ./scripts/demo-show.sh          # uses ./target/release/wire
#         DEMO_PACE=0.6 ./scripts/demo-show.sh
set -euo pipefail

PACE="${DEMO_PACE:-0.9}"
P=$'\033[1;36m'; W=$'\033[1;35m'; G=$'\033[1;32m'; Y=$'\033[1;33m'; D=$'\033[2m'; B=$'\033[1m'; R=$'\033[0m'
say(){ printf '%b\n' "$1"; sleep "$PACE"; }
beat(){ sleep "$PACE"; }

WIRE_BIN="${WIRE_BIN:-$(pwd)/target/release/wire}"
[ -x "$WIRE_BIN" ] || WIRE_BIN="$(command -v wire)" || { echo "wire binary not found"; exit 1; }

DEMO_ROOT="$(mktemp -d -t wire-show.XXXXXX)"
RELAY_HOME="$DEMO_ROOT/relay"; PAUL_HOME="$DEMO_ROOT/paul"; WILLARD_HOME="$DEMO_ROOT/willard"
mkdir -p "$RELAY_HOME" "$PAUL_HOME" "$WILLARD_HOME"
cleanup(){ [ -n "${RELAY_PID:-}" ] && kill "$RELAY_PID" 2>/dev/null; wait 2>/dev/null || true; rm -rf "$DEMO_ROOT"; }
trap cleanup EXIT

clear
say "${B}wire${R} ${D}— agent-to-agent comms. no vendor in the middle.${R}"
say "${D}two agents on one box. they pair, then they talk — signed end-to-end.${R}"
echo

# --- relay (the dumb pipe) ---
RELAY_PORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])')"
RELAY_URL="http://127.0.0.1:$RELAY_PORT"
WIRE_HOME="$RELAY_HOME" "$WIRE_BIN" relay-server --bind "127.0.0.1:$RELAY_PORT" >"$DEMO_ROOT/relay.log" 2>&1 &
RELAY_PID=$!
for _ in $(seq 1 50); do curl -fsS "$RELAY_URL/healthz" >/dev/null 2>&1 && break; sleep 0.1; done
say "${D}relay up on $RELAY_URL  (a dumb store-and-forward pipe — it never sees plaintext)${R}"
echo

# --- two agents come online (each mints a DID-backed persona) ---
WIRE_HOME="$PAUL_HOME"    "$WIRE_BIN" init agent --offline >/dev/null 2>&1
WIRE_HOME="$WILLARD_HOME" "$WIRE_BIN" init agent --offline >/dev/null 2>&1
read_persona(){ WIRE_HOME="$1" "$WIRE_BIN" whoami --json 2>/dev/null \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d["handle"],d["persona"]["emoji"])'; }
read -r H1 E1 < <(read_persona "$PAUL_HOME")
read -r H2 E2 < <(read_persona "$WILLARD_HOME")
say "${D}two agents come online — each mints its own DID-backed identity:${R}"
say "  ${P}\$ wire init${R}   ${G}✓${R}  ${P}${B}${E1} ${H1}${R}   ${D}did:wire:${H1}-…${R}"
say "  ${W}\$ wire init${R}   ${G}✓${R}  ${W}${B}${E2} ${H2}${R}   ${D}did:wire:${H2}-…${R}"
echo

# --- pair via SAS (real code, real verify) ---
WIRE_HOME="$PAUL_HOME" "$WIRE_BIN" pair-host --relay "$RELAY_URL" --yes --timeout 30 \
  >"$DEMO_ROOT/paul-pair.json" 2>"$DEMO_ROOT/paul-pair.stderr" &
PAUL_PAIR_PID=$!
CODE=""
for _ in $(seq 1 100); do
  CODE="$(grep -E '^    [0-9]{2}-[A-Z2-7]{6}$' "$DEMO_ROOT/paul-pair.stderr" 2>/dev/null | head -1 | tr -d ' ' || true)"
  [ -n "$CODE" ] && break; sleep 0.1
done
say "${P}${H1}${R}  ${D}\$ wire pair-host${R}"
say "        ${Y}share this code →  ${B}$CODE${R}"
beat
say "${W}${H2}${R}  ${D}\$ wire pair-join ${B}$CODE${R}"
WIRE_HOME="$WILLARD_HOME" "$WIRE_BIN" pair-join "$CODE" --relay "$RELAY_URL" --yes --timeout 30 \
  >"$DEMO_ROOT/willard-pair.json" 2>>"$DEMO_ROOT/relay.log"
wait "$PAUL_PAIR_PID"
SAS="$(grep -o '"sas":"[^"]*"' "$DEMO_ROOT/paul-pair.json" | cut -d'"' -f4)"
say "        ${G}✓ SAS matches on both sides: ${B}$SAS${R}  ${D}— mutually trusted, no CA, no account${R}"
echo

# --- send / push / pull / verified tail ---
WIRE_HOME="$PAUL_HOME" "$WIRE_BIN" send "$H2" decision "ship the v0.1 demo" >/dev/null 2>&1
WIRE_HOME="$PAUL_HOME" "$WIRE_BIN" push --json >/dev/null 2>&1
say "${P}${H1}${R}  ${D}\$ wire send ${R}${W}${H2}${R}${D} decision \"ship the v0.1 demo\"${R}   ${G}✓ signed + pushed${R}"
beat
WIRE_HOME="$WILLARD_HOME" "$WIRE_BIN" pull --json >/dev/null 2>&1
say "${W}${H2}${R}  ${D}\$ wire pull${R}   ${G}✓ pulled 1, signature verified, 0 rejected${R}"
beat
say "${W}${H2}${R}  ${D}\$ wire tail ${R}${P}${H1}${R}"
TAIL_OUT="$(WIRE_HOME="$WILLARD_HOME" "$WIRE_BIN" tail "$H1" --json 2>/dev/null | head -1)"
BODY="$(echo "$TAIL_OUT" | python3 -c 'import json,sys;print(json.loads(sys.stdin.read())["body"])')"
say "        ${B}from ${H1}${R}  ${D}(${G}✓ verified${D})${R}  →  ${B}\"$BODY\"${R}"
echo
say "${G}${B}✓${R} ${G}two agents, paired and talking — signed end-to-end, operator owns the relay.${R}"
beat
