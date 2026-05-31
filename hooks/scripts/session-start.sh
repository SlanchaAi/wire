#!/bin/bash
# wire-plugin SessionStart hook.
#
# Purpose: probe wire's reachability at session start and emit a one-line
# status. Does NOT auto-arm `wire monitor` — that's an assistant-level
# action via the Monitor tool (persistent: true) per the wire MCP server
# instructions ("ARM A PERSISTENT MONITOR on `wire monitor --json
# --include-handshake`"). Shell-launched background processes here would
# be invisible to Claude Code's task system; the assistant arms the
# Monitor itself when it sees this status line.
#
# Output goes back to Claude Code as stdout; non-zero exit warns the
# operator but doesn't block session start.

set -uo pipefail

# 1. Is the wire binary on PATH?
if ! command -v wire >/dev/null 2>&1; then
  cat <<EOF
wire-plugin: wire binary not on PATH.
  Install: cargo install slancha-wire
  OR download a prebuilt binary from https://github.com/SlanchaAi/wire/releases
EOF
  exit 0
fi

WIRE_VERSION=$(wire --version 2>/dev/null | awk '{print $2}' || echo "?")

# 2. Is wire initialized?
if ! wire whoami --short >/dev/null 2>&1; then
  cat <<EOF
wire-plugin: wire ${WIRE_VERSION} installed, NOT initialized for this session.
  Run: /wire:wire-init  (or:  wire up  for the public-relay default)
EOF
  exit 0
fi

# 3. All systems green.
HANDLE=$(wire whoami --short 2>/dev/null || echo "?")
cat <<EOF
wire-plugin: ready (${HANDLE}, wire ${WIRE_VERSION}).
  Slash commands: /wire:wire-pair, /wire:wire-monitor, /wire:wire-send, /wire:wire-enroll, /wire:wire-quiet
  Arm the inbox watcher (persistent Monitor on wire monitor --json) as an early action — see /wire:wire-monitor.
EOF
