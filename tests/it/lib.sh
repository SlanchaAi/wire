# Shared helpers for wire integration tests (real CLI, on-machine, end-to-end).
#
# These are NOT unit tests: each script boots real relay processes and drives
# the shipped `wire` binary exactly as a user/script would, then asserts on
# observable behaviour (pinned peers, delivered+verified messages, trust tier).
#
# A test script sources this, then uses: it_init / boot_relay / w / wait_until /
# assert / pass. Cleanup (kill relays, remove temp homes) is automatic on exit.
#
# Binary: $WIRE (absolute path) or `wire` on PATH.

WIRE="${WIRE:-wire}"
# Isolate from any host session-key adapter (CLAUDE_CODE_SESSION_ID etc.): force
# the per-invocation WIRE_HOME to win so each agent's home is honoured.
export WIRE_HOME_FORCE=1
export WIRE_QUIET_AUTOSESSION=1

_IT_PIDS=""
_IT_TMP=""
_IT_NAME="${0##*/}"

it_init() {
  command -v "$WIRE" >/dev/null 2>&1 || { echo "FATAL: wire binary not found ($WIRE)"; exit 1; }
  command -v jq   >/dev/null 2>&1 || { echo "FATAL: jq not found"; exit 1; }
  command -v curl >/dev/null 2>&1 || { echo "FATAL: curl not found"; exit 1; }
  _IT_TMP="$(mktemp -d)"
  trap _it_cleanup EXIT INT TERM
  echo "── ${_IT_NAME} ──"
}

_it_cleanup() {
  local pid
  for pid in $_IT_PIDS; do kill "$pid" 2>/dev/null || true; done
  [ -n "$_IT_TMP" ] && rm -rf "$_IT_TMP" 2>/dev/null || true
}

# it_home <label> -> echoes a fresh per-agent WIRE_HOME under the test tmp.
it_home() { local d="$_IT_TMP/$1"; mkdir -p "$d"; echo "$d"; }

# boot_relay_on <host> <port> [--local-only] -> starts a relay-server bound to
# <host>:<port>, waits for /healthz, tracks the pid for cleanup. Echoes the URL.
boot_relay_on() {
  local host="$1" port="$2"; shift 2
  local home="$_IT_TMP/relay-$port"; mkdir -p "$home"
  WIRE_HOME="$home" "$WIRE" relay-server --bind "$host:$port" "$@" \
    >"$_IT_TMP/relay-$port.log" 2>&1 &
  _IT_PIDS="$_IT_PIDS $!"
  local url="http://$host:$port" i
  for i in $(seq 1 40); do
    curl -fsS "$url/healthz" >/dev/null 2>&1 && { echo "$url"; return 0; }
    sleep 0.25
  done
  echo "FATAL: relay on $host:$port never became healthy" >&2
  cat "$_IT_TMP/relay-$port.log" >&2
  exit 1
}

# boot_relay <port> [--local-only] -> boot_relay_on loopback (the common case).
boot_relay() { local port="$1"; shift; boot_relay_on "127.0.0.1" "$port" "$@"; }

# nonloopback_ip -> a routable, non-loopback IPv4 of this host (empty if none).
nonloopback_ip() {
  local ip
  ip="$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.*src \([0-9.]*\).*/\1/p' | head -1)"
  [ -n "$ip" ] || ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  echo "$ip"
}

# w <home> <wire args...> -> run the wire CLI against a specific home, quietly.
w() { local home="$1"; shift; WIRE_HOME="$home" "$WIRE" "$@"; }

# handle_of <home> -> the agent's DID-derived persona handle.
handle_of() { w "$1" whoami --json | jq -r .handle; }

# wait_until <timeout_secs> <shell-cmd-string> -> poll until the command exits 0.
wait_until() {
  local secs="$1"; shift
  local deadline=$(( $(date +%s) + secs ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if eval "$@" >/dev/null 2>&1; then return 0; fi
    sleep 0.4
  done
  return 1
}

# assert <description> <shell-cmd-string> -> fail the whole script if it exits !=0.
assert() {
  local desc="$1"; shift
  if eval "$@" >/dev/null 2>&1; then
    echo "  ✓ $desc"
  else
    echo "  ✗ FAIL: $desc"
    echo "    cmd: $*"
    exit 1
  fi
}

pass() { echo "  ✓ $*"; }
step() { echo "→ $*"; }

# pair_handle <relay_url> <host_home> <guest_home>
# Drives a full zero-paste handle pair: host claims, guest `wire add`s the host,
# host accepts (bilateral gate), guest consumes the ack. Both end up pinned
# VERIFIED. Used as setup by tests that need an established line.
pair_handle() {
  local relay="$1" host="$2" guest="$3"
  local hh gh
  w "$host" init --relay "$relay" >/dev/null
  hh="$(handle_of "$host")"
  w "$host" claim "$hh" --public-url "$relay" >/dev/null
  w "$guest" init --relay "$relay" >/dev/null
  gh="$(handle_of "$guest")"
  w "$guest" add "$hh@127.0.0.1" --relay "$relay" --json >/dev/null
  wait_until 20 "w \"$host\" pull --json; w \"$host\" pending --json | grep -q $gh" || return 1
  w "$host" accept "$gh" --json >/dev/null
  w "$guest" pull --json >/dev/null
  wait_until 15 "w \"$host\" peers --json | grep -q $gh" || return 1
  wait_until 15 "w \"$guest\" peers --json | grep -q $hh" || return 1
}
