#!/usr/bin/env bash
# Claude Code statusline for wire — installed by `wire setup --statusline`.
#
# Renders: <liveness-dot> <persona-emoji> <nickname-in-accent-color> · <cwd>
# e.g.     ● 🐶 glossy-magnolia · ~/project
#
# Data source is `wire whoami --json` (persona.emoji / .nickname /
# .palette.ansi256_accent / config_dir). Daemon liveness is read the reliable
# way: the pid from <session>/state/wire/daemon.pid, confirmed live via
# `tasklist` on Windows or `kill -0` on Unix. No jq dependency — fields are
# pulled with grep/sed so this runs anywhere bash does (incl. Git Bash).
#
# Tested on Windows 10 x86_64 + Git Bash and macOS, wire v0.13.1+.

input="$(cat)"
WIRE="$(command -v wire 2>/dev/null || true)"
[ -n "$WIRE" ] || WIRE="$(command -v wire.exe 2>/dev/null || true)"
[ -n "$WIRE" ] || WIRE="$HOME/.local/bin/wire"

field()    { printf '%s' "$1" | grep -o "\"$2\":\"[^\"]*\"" | head -1 | sed "s/.*\"$2\":\"//; s/\"$//"; }
numfield() { printf '%s' "$1" | grep -o "\"$2\":[0-9]*"     | head -1 | sed "s/.*://"; }
# Normalize a Windows path to a Git-Bash path: unescape \\, backslash->slash, C:/ -> /c/
winpath()  { local p="${1//\\\\/\\}"; p="${p//\\//}"; printf '%s' "$p" | sed -E 's#^([A-Za-z]):/#/\L\1/#'; }

# --- current directory (Claude Code stdin, fall back to $PWD) ---
dir="$(winpath "$(field "$input" current_dir)")"
[ -z "$dir" ] && dir="$(winpath "$PWD")"
home="${HOME//\\//}"
case "$dir" in "$home"*) dir="~${dir#"$home"}";; esac

# --- resolve THIS session's identity ---
# Claude Code passes session_id on STDIN (not in the statusLine subprocess's
# env), but `wire` keys each session's identity off $WIRE_SESSION_ID /
# $CLAUDE_CODE_SESSION_ID. Without bridging stdin->env, `wire whoami` here can't
# see the session key and falls back to a cwd-detected default home — showing
# the wrong persona (or none) instead of this session's. Export it so whoami
# resolves the same by-key identity the MCP server bootstrapped for the session.
sid="$(field "$input" session_id)"
[ -n "$sid" ] && export WIRE_SESSION_ID="$sid"

# --- wire persona ---
wj="$("$WIRE" whoami --json 2>/dev/null)"
emoji="$(field "$wj" emoji)"
name="$(field "$wj" nickname)"
accent="$(numfield "$wj" ansi256_accent)"
[ -z "$accent" ] && accent=212

# --- daemon liveness: pidfile (<session>/state/wire/daemon.pid) + live check ---
live=0
cfg="$(winpath "$(field "$wj" config_dir)")"   # .../<session>/config/wire
if [ -n "$cfg" ]; then
  pidfile="${cfg%/config/wire}/state/wire/daemon.pid"
  pid="$(grep -o '"pid":[[:space:]]*[0-9]\+' "$pidfile" 2>/dev/null | head -1 | grep -o '[0-9]\+')"
  if [ -n "$pid" ]; then
    if command -v tasklist >/dev/null 2>&1; then
      tasklist //NH //FI "PID eq $pid" 2>/dev/null | grep -qi wire && live=1
    elif kill -0 "$pid" 2>/dev/null; then
      live=1
    fi
  fi
fi

esc=$(printf '\033')
col="${esc}[38;5;${accent}m"; dim="${esc}[2m"; rst="${esc}[0m"
if [ "$live" = 1 ]; then dot="${esc}[32m●${rst}"; else dot="${esc}[90m●${rst}"; fi  # green / dim grey

if [ -n "$name" ]; then
  printf '%s %s %s%s%s %s· %s%s' "$dot" "$emoji" "$col" "$name" "$rst" "$dim" "$dir" "$rst"
else
  printf '%s %s(wire: not initialized) · %s%s' "$dot" "$dim" "$dir" "$rst"
fi
