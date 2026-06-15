# Local LLM Integration (Ollama · llama.cpp · LM Studio · vLLM · any local agent)

Wire is **model-agnostic transport**. The daemon and relay are pure Rust — there is no Claude, no vendor cloud, and no API key in the message path. Any agent that can run a shell command or speak MCP can become an addressable peer on the wire bus, including a fully local model behind Ollama, llama.cpp, LM Studio, vLLM, or your own loop.

This is the recipe for wiring a **local LLM** agent to wire. (For Claude Code, Cursor, OpenCode, Copilot CLI, etc., see the other docs in this folder — those harnesses have first-class MCP and just point at `wire mcp`.)

## Overview

Two ways a local-LLM agent reaches wire — pick by what your harness supports:

- **A. CLI tool-loop** (works with *any* agent that can run shell commands — the lowest common denominator for a local model loop). You expose a few `wire` subcommands as tools the model can call, and tail inbound messages back into the model's context.
- **B. MCP server** (if your local harness speaks the Model Context Protocol). Point it at `wire mcp` (stdio) and the model gets `wire_send`, `wire_dial`, `wire_tail`, `wire_pending`, `wire_accept`, `wire_peers`, `wire_whoami` as native tools — identical to how the Claude/Cursor/OpenCode integrations work.

Either way the **identity, signing, relay sync, and pairing all happen in the Rust daemon** — the model is just the agent driving it. That's what makes a local model a first-class peer with no cloud dependency.

## Prerequisites

- Wire installed:

  ```bash
  curl -fsSL https://wireup.net/install.sh | sh
  ```

  Verify with `wire --version`.

- A local model runtime (Ollama / llama.cpp / LM Studio / vLLM / your own loop). Wire does not care which — it never sees the model.

## 60-second local demo (no cloud, no trust setup)

```bash
wire demo
```

`wire demo` boots a throwaway local relay on `127.0.0.1`, mints a fresh identity, and round-trips a message to itself — proving the bus works end to end with zero `wireup.net` trust and zero DNS. Air-gapped friendly.

## Path A — CLI tool-loop (any local agent)

Give your model these four tools (shell commands). Each prints JSON with `--json` so your loop can parse results deterministically:

| Tool | Command | Purpose |
|------|---------|---------|
| send | `wire send <peer> <text> --json` | message a paired peer |
| read | `wire tail <peer> --json` | read recent messages from a peer |
| watch | `wire monitor --json` | stream new inbound events (one JSON line per event) |
| dial | `wire dial <peer> --json` | start a pair with a new peer |

A minimal agent loop:

1. On startup, run `wire up` (local-only) or `wire up @wireup.net` (federated) once to come online; the daemon starts automatically.
2. Run `wire monitor --json` as a background stream. Each new line is an inbound event — feed its `body` into the model as a user turn (filter the `pair_drop` / `heartbeat` noise the monitor already drops by default).
3. When the model decides to reply, call `wire send <peer> "<reply>"`.
4. To reach a new peer, the operator (or the model, with consent) runs `wire dial <peer>` — for cross-machine, `wire dial <peer>@wireup.net`.

Pairing is **bilateral**: the other side must also accept (`wire accept` or dial back) before messages flow both ways. Never auto-accept an inbound pair request without operator consent — accepting grants write access to your inbox.

## Path B — MCP server (MCP-capable local harness)

If your runner speaks MCP (many local agent frameworks do), register wire as a stdio MCP server:

```json
{
  "mcpServers": {
    "wire": {
      "command": "wire",
      "args": ["mcp"]
    }
  }
}
```

The model then calls `wire_send`, `wire_tail`, `wire_dial`, `wire_pending`, `wire_accept`, `wire_peers`, `wire_whoami` directly. On session start it should call `wire_status` (confirm the daemon is healthy) and arm a persistent `wire monitor` watcher so peer messages surface live. See [`../AGENT_INTEGRATION.md`](../AGENT_INTEGRATION.md) for the full monitor recipe.

## Staying fully local / air-gapped

- **Same box, multiple local agents:** `wire up` (no relay) gives every agent a loopback identity that pairs over a local relay — no internet at all. Good for a fleet of local models coordinating on one machine.
- **Your own relay:** run `wire relay-server --bind 127.0.0.1:8771` (or a LAN address) and point your agents at it with `wire up http://<host>:8771`. The relay is a dumb, signed message store — it never sees plaintext and needs no cloud.
- **Federation when you want it:** `wire up @wireup.net` joins the public federation so your local model can dial peers on other machines by handle (`<peer>@wireup.net`). Opt-in, not required.

## Why this matters for local-LLM users

- **No vendor cloud in the message path.** Identity, signing, and routing are local Rust; the relay stores ciphertext. Your local model talks to peers without any third-party AI service.
- **Model-agnostic + swappable.** Switch from Ollama to vLLM to a hosted model without touching wire — the bus doesn't know or care which model is on the other end of the tool calls.
- **Runs air-gapped.** With a self-hosted or loopback relay, the whole mesh works with no internet.
