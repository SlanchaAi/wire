#!/usr/bin/env bash
# hello-world-validate.sh — validate the README "60-second local demo"
# single-line connection end-to-end, repeatably, each run on a fresh state dir.
#
# Reproduces exactly:
#   wire relay-server --bind 127.0.0.1:PORT --local-only      # == `wire service install --local-relay`
#   WIRE_SESSION_ID=agent-a wire up http://127.0.0.1:PORT --no-local
#   WIRE_SESSION_ID=agent-b wire up http://127.0.0.1:PORT --no-local
#   WIRE_SESSION_ID=agent-b wire dial <agent-a persona> "hello from terminal B"
# then asserts agent-a actually RECEIVES "hello from terminal B".
#
# Usage:  ./scripts/hello-world-validate.sh [ITERATIONS]   (default 10)
#         WIRE_BIN=/path/to/wire ./scripts/hello-world-validate.sh 25
#
# Exit 0 iff every iteration connected and the hello landed.
#
# NOTE (2026-06-13): on current main this harness FAILS on a fresh box — the
# receiver's `wire up`-spawned daemon does not survive in a non-interactive
# (scripted / CI / agent) context, so it never pulls the delivered message and
# the round-trip never completes. Root-caused to `ensure_up::ensure_background`
# spawning the daemon without session-detachment (no setsid / new-session); it
# persists only under a launchd/systemd supervisor (`wire service install`) or
# an interactive terminal. This script is the repro AND the regression guard
# for that fix — promote it to a required CI job once daemon-survival is fixed.
# Until then it is a manual/local validation tool, not a blocking gate.

set -uo pipefail

WIRE_BIN="${WIRE_BIN:-$(pwd)/target/release/wire}"
ITERS="${1:-10}"
MSG="hello from terminal B"
REPLY="ack from terminal A — autonomous reply"

if [ ! -x "$WIRE_BIN" ]; then
  if command -v wire >/dev/null 2>&1; then WIRE_BIN="$(command -v wire)"; else
    echo "FATAL: wire binary not found at $WIRE_BIN (run: cargo build --release)" >&2
    exit 1
  fi
fi

echo "▶ wire binary: $WIRE_BIN ($("$WIRE_BIN" --version 2>/dev/null))"
echo "▶ iterations:  $ITERS"
echo

pick_port() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()'; }

PASS=0; FAIL=0; FAIL_ITERS=()

run_once() {
  local n="$1"
  local ROOT RELAY_HOME PORT RELAY_URL RELAY_PID A_NAME ok="" t0 t1
  ROOT="$(mktemp -d -t wire-hw.XXXXXX)"
  RELAY_HOME="$ROOT/relay"
  # Fresh, isolated HOME per run; the two agents share it (only WIRE_SESSION_ID differs) — exactly as the README demo does.
  export HOME="$ROOT/home"
  export XDG_CONFIG_HOME="$HOME/.config"
  export XDG_DATA_HOME="$HOME/.local/share"
  export XDG_STATE_HOME="$HOME/.local/state"
  unset WIRE_HOME
  mkdir -p "$RELAY_HOME" "$XDG_CONFIG_HOME" "$XDG_DATA_HOME" "$XDG_STATE_HOME"

  PORT="$(pick_port)"; RELAY_URL="http://127.0.0.1:$PORT"
  t0=$(date +%s.%N)

  # 1. local relay
  WIRE_HOME="$RELAY_HOME" "$WIRE_BIN" relay-server --bind "127.0.0.1:$PORT" --local-only \
    >"$ROOT/relay.log" 2>&1 &
  RELAY_PID=$!
  local up=""
  for _ in $(seq 1 100); do curl -fsS "$RELAY_URL/healthz" >/dev/null 2>&1 && { up=1; break; }; sleep 0.1; done
  if [ -z "$up" ]; then echo "  iter $n: ✗ relay never bound on $PORT"; sed 's/^/      relay| /' "$ROOT/relay.log"; teardown; return 1; fi

  # 2. agent-a up
  if ! WIRE_SESSION_ID=agent-a "$WIRE_BIN" up "$RELAY_URL" --no-local >"$ROOT/a-up.log" 2>&1; then
    echo "  iter $n: ✗ agent-a 'wire up' failed"; sed 's/^/      a-up| /' "$ROOT/a-up.log"; teardown; return 1; fi
  A_NAME="$(WIRE_SESSION_ID=agent-a "$WIRE_BIN" whoami --json 2>/dev/null \
    | python3 -c 'import json,sys;print(json.load(sys.stdin).get("handle","").split("@")[0])' 2>/dev/null)"
  if [ -z "$A_NAME" ]; then echo "  iter $n: ✗ could not read agent-a persona"; sed 's/^/      a-up| /' "$ROOT/a-up.log"; teardown; return 1; fi

  # 3. agent-b up
  if ! WIRE_SESSION_ID=agent-b "$WIRE_BIN" up "$RELAY_URL" --no-local >"$ROOT/b-up.log" 2>&1; then
    echo "  iter $n: ✗ agent-b 'wire up' failed"; sed 's/^/      b-up| /' "$ROOT/b-up.log"; teardown; return 1; fi
  B_NAME="$(WIRE_SESSION_ID=agent-b "$WIRE_BIN" whoami --json 2>/dev/null \
    | python3 -c 'import json,sys;print(json.load(sys.stdin).get("handle","").split("@")[0])' 2>/dev/null)"

  # 4. the single line: dial agent-a by persona + send hello
  if ! WIRE_SESSION_ID=agent-b "$WIRE_BIN" dial "$A_NAME" "$MSG" >"$ROOT/dial.log" 2>&1; then
    echo "  iter $n: ✗ agent-b 'wire dial $A_NAME' failed"; sed 's/^/      dial| /' "$ROOT/dial.log"; teardown; return 1; fi

  # 5. assert agent-a receives the hello (daemons sync through the relay)
  for _ in $(seq 1 150); do
    if WIRE_SESSION_ID=agent-a "$WIRE_BIN" tail --json 2>/dev/null | grep -qF "$MSG"; then ok=1; break; fi
    sleep 0.2
  done
  t1=$(date +%s.%N)

  if [ -z "$ok" ]; then
    echo "  iter $n: ✗ hello never landed in agent-a inbox"
    echo "      --- agent-a tail ---"; WIRE_SESSION_ID=agent-a "$WIRE_BIN" tail --json 2>&1 | sed 's/^/      tail| /' | head -20
    sed 's/^/      dial| /' "$ROOT/dial.log"
    teardown; return 1
  fi

  # 6. autonomous reply: agent-a answers back; agent-b must receive it.
  if [ -z "$B_NAME" ]; then echo "  iter $n: ✗ could not read agent-b persona for reply"; teardown; return 1; fi
  if ! WIRE_SESSION_ID=agent-a "$WIRE_BIN" send "$B_NAME" "$REPLY" >"$ROOT/reply.log" 2>&1; then
    echo "  iter $n: ✗ agent-a 'wire send $B_NAME' (reply) failed"; sed 's/^/      reply| /' "$ROOT/reply.log"; teardown; return 1; fi
  local got_reply=""
  for _ in $(seq 1 150); do
    if WIRE_SESSION_ID=agent-b "$WIRE_BIN" tail --json 2>/dev/null | grep -qF "$REPLY"; then got_reply=1; break; fi
    sleep 0.2
  done
  t1=$(date +%s.%N)

  if [ -n "$got_reply" ]; then
    printf "  iter %s: ✓ %s →\"%s\"→ %s →\"reply\"→ %s  (%.1fs)\n" "$n" "$B_NAME" "$MSG" "$A_NAME" "$B_NAME" "$(echo "$t1-$t0"|bc)"
    teardown; return 0
  else
    echo "  iter $n: ✗ reply never landed in agent-b inbox"
    echo "      --- agent-b tail ---"; WIRE_SESSION_ID=agent-b "$WIRE_BIN" tail --json 2>&1 | sed 's/^/      tail| /' | head -20
    sed 's/^/      reply| /' "$ROOT/reply.log"
    teardown; return 1
  fi
}

teardown() {
  # Kill per-session daemons (pidfiles live under the unique HOME), then relay, then state.
  if [ -n "${HOME:-}" ] && [ -d "$HOME" ]; then
    while IFS= read -r pf; do
      # pidfile is JSON ({"pid":N,...}); parse the pid field, not the schema string.
      pid="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["pid"])' "$pf" 2>/dev/null)"
      [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
    done < <(find "$HOME" -name 'daemon.pid' 2>/dev/null)
  fi
  [ -n "${RELAY_PID:-}" ] && kill "$RELAY_PID" 2>/dev/null || true
  [ -n "${ROOT:-}" ] && rm -rf "$ROOT" 2>/dev/null || true
}

# Clean up the in-flight run's daemons + relay even if we're killed (timeout,
# Ctrl-C). Without this, an interrupted run leaks setsid-detached daemons that
# survive (by design) and busy-spin against their now-deleted temp HOME,
# starving later runs — the contention that made earlier stress runs flaky.
trap teardown EXIT INT TERM

for n in $(seq 1 "$ITERS"); do
  if run_once "$n"; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); FAIL_ITERS+=("$n"); fi
done

echo
echo "════════════════════════════════════════"
echo "  hello-world demo: $PASS/$ITERS passed"
[ "$FAIL" -gt 0 ] && echo "  failed iterations: ${FAIL_ITERS[*]}"
echo "════════════════════════════════════════"
[ "$FAIL" -eq 0 ]
