---
description: Send a signed message to a paired wire peer. Use when user wants to message another agent by handle/nick. Wire send writes a signed event to the per-peer outbox; the daemon pushes to the relay; the peer's daemon pulls + delivers to their inbox. End-to-end via Ed25519 signatures; relays are transport, never authority.
---

# wire-send

Send to a paired peer. Auto-pairs on miss when the operator allows (default: yes — `--no-auto-pair` to refuse).

## When to use

- User says "send `<msg>` to `<peer>`", "tell `<peer>` `<msg>`", "wire `<peer>` `<msg>`"
- User wants to push an event-shaped notification to a paired agent

## Workflow

```bash
wire send <peer> "<body>"
```

`<peer>` accepts bare nick / federation handle / DID. `<body>` is free-form text by default; structured shapes (`@/path/to/body.json` for JSON body, `-` for stdin, explicit kind for non-`claim` events) are supported.

### Body from a file (safer for bodies with shell metachars)

```bash
wire send <peer> @/tmp/message.txt
```

**Critical:** Bodies containing backticks, `$()`, `${}`, parens, etc. should ALWAYS be written to a file first and sent via `@/path`. Inline strings get shell-evaluated and corrupted. (Memory note: `feedback_wire_send_shell_metachars`.) Same caution as `git commit -F` and `gh pr --body-file`.

### Body from stdin

```bash
echo "hello" | wire send <peer> -
```

### Explicit kind (e.g. `decision`, `ack`, `trust_add_key`)

```bash
wire send <peer> <kind> "<body>"
```

Kinds: see `wire signing kinds` — `claim`, `decision`, `ack`, `agent_card`, `trust_add_key`, `trust_revoke_key`. (Default kind = `claim`.)

## Auto-pair-on-miss

By default if `<peer>` is not yet paired, `wire send` will auto-pair (drops a pair_drop). Refuse with `--no-auto-pair`:

```bash
wire send <peer> "<body>" --no-auto-pair
```

When auto-pair fires, the message is queued; delivery happens when the peer accepts the pair request bilaterally.

## MCP tool variant

`mcp__wire__wire_send({peer: "<nick>", body: "<body>"})` from the assistant context. Same semantics; same shell-metachar caution does NOT apply (MCP carries the body as a parameter, not a shell arg).

## Verify delivery

```bash
wire tail <peer> --limit 3
```

Shows the most-recent N events on the inbound side of that peer's channel — peer's responses + own outbound that's been ack'd.

## Reference

- `wire send --help` for full flag matrix.
- v0.5.13 history: federation suffix stripping; outbox filename is always bare-handle.jsonl.
