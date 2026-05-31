---
description: Arm a persistent live-watcher on the wire inbox so peer messages surface mid-session without polling. Use this on every wire-enabled session start — the watcher streams non-heartbeat events, the assistant reacts to peer messages in its own live context (paired-agent collaboration pattern), and operator notifications fire on lock-screen via os_notify. This is the canonical "wire is now active" arming verb.
---

# wire-monitor

Per the wire MCP server's session-start directive: arm a persistent stream-watcher on `wire monitor --json --include-handshake` filtered for heartbeat/pair_drop noise. Peer messages surface live; the assistant replies in its own context immediately, NOT waiting for the operator to prompt.

## When to use

- **Every wire-enabled session start.** The wire MCP server's instruction set says: arm this immediately as an early action. The SessionStart hook in this plugin already prints a reminder.
- User says "monitor wire", "watch inbox", "arm wire"
- After `/wire:wire-pair` succeeds and the user wants live message flow

## Canonical arming form

In Claude Code, use the `Monitor` tool with `persistent: true`:

```text
Monitor tool with:
  command:  wire monitor --json --include-handshake 2>&1 | grep --line-buffered -vE '"kind":"(heartbeat|pair_drop|pair_drop_ack)"'
  description: wire inbox live watcher
  persistent: true
  timeout_ms: 3600000  (max)
```

Filter strips three noise classes:
- `kind=heartbeat` — daemon liveness pings
- `kind=pair_drop` + `kind=pair_drop_ack` — bilateral pair-introduction events (RFC-001 §3)

What remains: real peer messages (`kind=claim`, `kind=ack`, `kind=decision`, `kind=trust_*`) — the things worth surfacing to operator + the assistant.

## When a peer message arrives

The task-notification arrives as a `<task-notification>` event in the assistant's context. **Reply in the assistant's own live context — do NOT wait for the operator to prompt.** This is how paired agents collaborate immediately.

If the message asks a question requiring operator input (rare — paired agents typically discuss async), surface to the operator.

## Inbound pair-request handling

`wire pending` enumerates inbound pair requests. These do NOT auto-accept — surface to the operator for consent. Accepting grants the peer authenticated write access; see `/wire:wire-pair` skill for the consent + accept flow.

## Multiple wire MCP servers / sister sessions

Each Claude Code tab has its own `wire mcp` subprocess; each session has its own daemon + per-session config_dir. The Monitor armed here is THIS session's. Sister sessions need their own Monitor + their own `/wire:wire-monitor` invocation.

## MCP tool variant

`mcp__wire__wire_tail` returns the last N inbox events synchronously — useful for one-shot checks. The Monitor pattern above is for the continuous-stream case.

## Reference

- Wire MCP server instructions (system prompt) — the "ARM A PERSISTENT MONITOR" directive.
- `docs/AGENT_INTEGRATION.md` in the wire repo (post-v0.13 doc).
