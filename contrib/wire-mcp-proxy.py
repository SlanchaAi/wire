#!/usr/bin/env python3
"""
wire MCP launcher for Claude Code — proven reference for per-session identity.

Why this exists
---------------
Claude Code does NOT reliably expose the session id to a wire MCP server:
  * the MCP server process often does not inherit CLAUDE_CODE_SESSION_ID,
  * `"env": {"WIRE_SESSION_ID": "${CLAUDE_CODE_SESSION_ID}"}` is passed through
    UNEXPANDED (the literal string) when the host can't resolve it,
  * the MCP `initialize` handshake carries no session id (clientInfo only).
So wire's resolve_session_key() finds nothing and every session collapses to a
single identity (or, post-cwd-removal, fails to initialize).

The reliable signal: Claude Code writes ~/.claude/sessions/<pid>.json
  {"pid": ..., "sessionId": "...", "cwd": "...", ...}
for each live session, named by the owning `claude` process PID. The MCP server
runs as a descendant of that process, so we walk the parent chain to the first
ancestor whose PID-file exists and read its sessionId, then export
WIRE_SESSION_ID before launching `wire mcp`.

This shim is the cross-platform reference; the same logic now lives natively in
wire's resolve_session_key() (src/session.rs). Use the shim if you run a wire
build without the native adapter.

Requires: psutil (for the parent-process walk).
"""
import os
import sys
import json
import shutil
import subprocess


def find_wire():
    for cand in ("wire", "wire.exe"):
        p = shutil.which(cand)
        if p:
            return p
    fallback = os.path.join(
        os.path.expanduser("~"), ".local", "bin",
        "wire.exe" if os.name == "nt" else "wire",
    )
    return fallback if os.path.exists(fallback) else "wire"


def resolve_session_id():
    sid = os.environ.get("CLAUDE_CODE_SESSION_ID", "").strip()
    if sid and "${" not in sid:
        return sid
    try:
        import psutil
    except Exception:
        return ""
    sdir = os.path.join(os.path.expanduser("~"), ".claude", "sessions")
    try:
        p = psutil.Process()
        for _ in range(16):
            p = p.parent()
            if p is None:
                break
            f = os.path.join(sdir, "%d.json" % p.pid)
            if os.path.isfile(f):
                with open(f, encoding="utf-8") as fh:
                    return str(json.load(fh).get("sessionId", "")).strip()
    except Exception:
        pass
    return ""


def main():
    sid = resolve_session_id()
    env = os.environ.copy()
    if sid:
        env["WIRE_SESSION_ID"] = sid
    elif "${" in env.get("WIRE_SESSION_ID", ""):
        env.pop("WIRE_SESSION_ID", None)  # never hash an unexpanded literal
    return subprocess.run([find_wire(), "mcp"], env=env).returncode


if __name__ == "__main__":
    sys.exit(main())
