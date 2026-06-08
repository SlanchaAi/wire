#!/usr/bin/env bash
# Fresh-env RUNTIME validation of the #210 regression fix (RFC-008 §C).
#
# The cargo test suite proves the unit invariants; this proves the *behavior*
# an operator actually hits: distinct sessions get distinct identities, and a
# legacy-shape WIRE_HOME pin no longer silently collapses them onto one.
#
# Runs inside the wire-testenv container against a throwaway XDG root so it
# never touches the operator's real wire state. Offline-only (no relay).
set -uo pipefail

BIN=/wire/target/release/wire
PASS=0; FAIL=0
ok(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
no(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }

echo "== build (release) =="
cargo build --release --quiet || { echo "build failed"; exit 1; }

SBX="$(mktemp -d)"
export XDG_STATE_HOME="$SBX/state" XDG_DATA_HOME="$SBX/share" XDG_CONFIG_HOME="$SBX/config"
export WIRE_VERBOSE=1
unset WIRE_SESSION_ID CLAUDE_CODE_SESSION_ID CODEX_SESSION_ID \
      COPILOT_AGENT_SESSION_ID VSCODE_GIT_REPOSITORY_ROOT WIRE_HOME WIRE_HOME_FORCE

# Bring an identity online (offline keygen) under the env's resolved home, then
# read it back. Each call is a fresh process => fresh OnceLock capture, exactly
# like a brand-new terminal tab. init is idempotent on an already-keyed home.
who(){
  env "$@" "$BIN" init seed --offline >/dev/null 2>&1
  env "$@" "$BIN" whoami --json 2>/dev/null \
    | jq -r '"\(.handle)|\(.config_dir)|\(.session_source)"'
}

echo
echo "== 1. distinct session keys -> distinct identities (#210 core) =="
A=$(who WIRE_SESSION_ID=alpha-session-001)
B=$(who WIRE_SESSION_ID=beta-session-002)
echo "    alpha: $A"
echo "    beta : $B"
ha=${A%%|*}; hb=${B%%|*}
da=$(echo "$A"|cut -d'|' -f2); db=$(echo "$B"|cut -d'|' -f2)
{ [ -n "$ha" ] && [ "$ha" != "null" ] && [ "$ha" != "$hb" ]; } \
  && ok "distinct handles ($ha != $hb)" || no "handles not distinct ($ha vs $hb)"
{ [ "$da" != "$db" ] && echo "$da" | grep -q '/by-key/'; } \
  && ok "distinct by-key homes" || no "homes not distinct / not by-key"

echo
echo "== 2. same key -> stable identity (re-run determinism) =="
A2=$(who WIRE_SESSION_ID=alpha-session-001)
[ "$A" = "$A2" ] && ok "alpha stable across processes" || no "alpha drifted ($A -> $A2)"

echo
echo "== 3. legacy-shape WIRE_HOME + session key -> SESSION KEY WINS (the fix) =="
# Pre-#210: a WIRE_HOME pin silently overrode the session key -> every tab
# collapsed onto one identity. Post-§C: a non-by-key WIRE_HOME loses to a
# present session key.
LEGACY="$SBX/legacy-pin-home"
G=$(who WIRE_HOME="$LEGACY" WIRE_SESSION_ID=gamma-session-003)
echo "    legacy WIRE_HOME=$LEGACY + WIRE_SESSION_ID=gamma -> $G"
dg=$(echo "$G"|cut -d'|' -f2); sg=$(echo "$G"|cut -d'|' -f3)
echo "$dg" | grep -q '/by-key/' \
  && ok "session-key home won over legacy pin" || no "legacy pin still overrode (REGRESSION) home=$dg"
[ "$sg" != "env:WIRE_HOME" ] && [ "$sg" != "null" ] \
  && ok "session_source=$sg (not env:WIRE_HOME)" || no "session_source=$sg"
Gpure=$(who WIRE_SESSION_ID=gamma-session-003)
[ "${G%%|*}" = "${Gpure%%|*}" ] && [ "${G%%|*}" != "null" ] \
  && ok "identity == pure session-key identity (pin fully dropped)" || no "identity diverged ($G vs $Gpure)"

echo
echo "== 4. by-key-shape WIRE_HOME -> HONORED (deliberate fleet-share preserved) =="
# A modern operator-explicit pin (sessions/by-key/<16hex>) must still win even
# with a session key present -- the two-tabs-one-fleet contract.
HEX=0123456789abcdef
BYKEY="$XDG_STATE_HOME/wire/sessions/by-key/$HEX"
mkdir -p "$BYKEY"
K=$(who WIRE_HOME="$BYKEY" WIRE_SESSION_ID=delta-session-004)
echo "    by-key WIRE_HOME=$BYKEY + WIRE_SESSION_ID=delta -> $K"
dk=$(echo "$K"|cut -d'|' -f2); sk=$(echo "$K"|cut -d'|' -f3)
echo "$dk" | grep -q "by-key/$HEX" \
  && ok "by-key pin honored over session key" || no "by-key pin NOT honored home=$dk"
[ "$sk" = "env:WIRE_HOME" ] && ok "session_source=env:WIRE_HOME" || no "session_source=$sk (expected env:WIRE_HOME)"

echo
echo "== 5. WIRE_HOME_FORCE=1 legacy-shape -> HONORED (escape hatch) =="
F=$(who WIRE_HOME="$LEGACY" WIRE_HOME_FORCE=1 WIRE_SESSION_ID=epsilon-session-005)
echo "    forced legacy pin -> $F"
df=$(echo "$F"|cut -d'|' -f2); sf=$(echo "$F"|cut -d'|' -f3)
echo "$df" | grep -q "legacy-pin-home" \
  && ok "forced legacy home honored (home=$df)" || no "forced legacy home NOT honored (home=$df)"
[ "$sf" = "env:WIRE_HOME_FORCE" ] && ok "session_source=env:WIRE_HOME_FORCE" || no "session_source=$sf (expected env:WIRE_HOME_FORCE)"

echo
echo "== 6. bare CLI, no session key, no pin -> machine-default (no cwd collapse) =="
M=$(cd /tmp && who)
echo "    bare -> $M"
sm=$(echo "$M"|cut -d'|' -f3)
[ "$sm" = "machine-default" ] && ok "session_source=machine-default" || no "session_source=$sm (expected machine-default)"

rm -rf "$SBX"
echo
echo "================ $PASS passed, $FAIL failed ================"
[ "$FAIL" -eq 0 ]
