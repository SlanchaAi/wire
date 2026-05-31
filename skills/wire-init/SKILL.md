---
description: Initialize wire on this machine — mint a session DID + Ed25519 keypair and (optionally) bind a public relay. Use when the user says "wire init", "set up wire", or asks how to start using wire. Wire is a magic-wormhole-for-agents bus; the init step writes ~/.config/wire/ (Unix) or %APPDATA%/wire/ (Windows) and is required exactly once per session.
---

# wire-init

Set up wire identity on a fresh machine or fresh per-session WIRE_HOME. Idempotent — running twice is safe.

## When to use

- User says "set up wire", "wire init", "wire up", "install wire"
- User wants to start using wire but their session has no identity (`wire whoami` errors with "not initialized")
- A fresh per-session WIRE_HOME (e.g. new Claude Code session inheriting a clean state)

## Pre-flight

Verify wire is on PATH:

```bash
command -v wire || echo "wire not installed — see install instructions below"
```

If not installed: `cargo install slancha-wire` (requires Rust toolchain) OR download a prebuilt binary from https://github.com/SlanchaAi/wire/releases.

## Workflow

### Option A — public-relay default (`wireup.net`, recommended for first install)

```bash
wire up
```

This single verb: mints a session DID + Ed25519 keypair, claims a persona on `wireup.net`, registers a federation handle. Output shows the DID + nickname + emoji. Per the v0.11 one-name rule, the claimed nickname always matches the DID-derived persona.

### Option B — offline / local-only

```bash
wire init <handle> --offline
```

No relay binding. Local-only identity. Use when the operator doesn't want to publish to `wireup.net`.

### Option C — bind a custom relay (sovereign-fleet / org-tier)

```bash
wire init <handle>
wire bind-relay https://relay.<your-domain>
```

For org-tier deployments per RFC-003. The DNS-TXT `_wire-org.<domain>` should already be published before binding.

## Verify

```bash
wire whoami --json | jq
```

Expected fields: `did`, `handle`, `op_did` (if enrolled per RFC-001), `schema_version` (v3.2 if v0.14+ + op claims attached), `capabilities`.

## Common errors

- **`not initialized`** — `wire whoami` was called before init. Run one of A/B/C above.
- **`relay unreachable`** — Option A failed; user is offline. Fall back to B (`--offline`).
- **`handle already claimed on relay`** — collision on `wireup.net`. Use Option B + bind to a non-public relay, OR pick a different handle.

## v0.14 identity layer (optional, post-init)

If the user wants the RFC-001 operator + org identity layer (auto-pair across sessions, ORG_VERIFIED tier), see the `/wire:wire-enroll` skill.

## Reference

- README: https://github.com/SlanchaAi/wire#status--v0141-latest
- RFC-001 identity layer: `docs/rfc/0001-identity-layer.md` in the wire repo.
