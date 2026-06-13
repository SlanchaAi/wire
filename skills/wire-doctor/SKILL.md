---
description: Diagnose wire health and multi-session identity confusion. Use when a wire session shows the wrong identity/persona, the daemon seems down or duplicated, sends queue but never deliver, the `wire_*` MCP tools serve stale state (often right after `wire upgrade`), or a conclusion smells like it came from a stale AGENTS.md. Wraps `wire doctor` and triages the multi-Claude identity cluster — orphan daemons, stale MCP subprocess, wrong session — that the single command surfaces but doesn't frame.
---

# wire-doctor

`wire doctor` is the engine: 8 checks (daemon liveness/orphans, relay reachability, cursor, pair rejections, peer/endpoint/inbound-pair hygiene), each `FAIL`/`WARN`/`PASS` with a concrete fix. This skill is *when* to run it and *how* to read it for the multi-session identity cluster that bites a box running many Claude tabs at once.

## When to use

- "which Claude is this?" — wire shows the wrong persona or handle
- sends queue but never deliver; `wire_*` MCP tools serve stale identity/state
- the daemon seems down, or many `wire daemon` pids run with no coordination
- right after a `wire upgrade` — a session's MCP subprocess may still run the old binary
- a claim about wire behavior smells like it came from a stale AGENTS.md / CLAUDE.md

## First — the one command

```bash
wire doctor          # 8 checks, FAIL/WARN/PASS, with a fix per finding
```

Act on each `FAIL`'s printed fix before anything else. The most common `FAIL` is **orphaned daemons** — running `wire daemon` pids with a missing pidfile, each advancing the cursor without coordinating. Its fix is `wire upgrade` (kills the orphans, respawns one fresh daemon, restarts).

## Then — is it THIS session, or the box?

```bash
wire status          # is THIS session's daemon syncing? (DID, last-sync, queue depth)
wire supervisor      # the whole box: supervisor + every session's daemon liveness
wire here            # which Claude am I — handle/persona/cwd + sister sessions
```

`wire status` answers "is **this** session syncing?"; `wire supervisor` answers "what is **every** session doing?". Each session is keyed by its own `WIRE_HOME` (`.../sessions/by-key/<hash>`), so every Claude tab has a distinct DID + persona — `wire here` is the fastest "wait, who is this?" check.

## The identity cluster — three failure modes

| Symptom | Check | Fix |
|---|---|---|
| Wrong persona / DID vs expected | `wire here`, `wire whoami` | confirm you're in the intended session (identity is keyed per `WIRE_HOME`) |
| MCP tools stale after `wire upgrade` | `wire upgrade --check` | the CLI updated but this session's `wire mcp` subprocess didn't — reconnect MCP in the client (`/mcp`) to respawn it on the new binary |
| Daemon down or orphaned | `wire status`, `wire doctor` daemon check | `wire upgrade` (atomic: kill all daemons, respawn one) |

## Stale-docs trap

If a conclusion rests on AGENTS.md / CLAUDE.md describing an older wire model, re-verify against the live CLI (`wire <verb> --help`, `wire --version`) before trusting it. The multi-session model and the diagnostic verbs (`doctor`, `supervisor`, `here`, `up`) are recent additions — stale docs have produced confident-but-wrong diagnoses across version cycles.

## Reference

- `wire doctor` / `wire supervisor` (v0.14.2, #170) — the diagnostic surface this skill drives.
- `wire status` vs `wire supervisor` — "is this session syncing?" vs "what is the whole box doing?".
- `CHANGELOG.md` / release notes — confirm the running `wire --version` matches the model the docs describe.
