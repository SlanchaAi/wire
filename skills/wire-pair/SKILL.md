---
description: Pair this wire session with another agent — bilateral signed-message bus over a mailbox relay. Use when the user says "pair with X", "dial Y", "talk to Z", or names another agent/peer they want to message. Wire pairing is bilateral (both sides accept) and produces a 6-digit SAS that operators read aloud out-of-band.
---

# wire-pair

Pair coral-weasel (this session) with another wire-running agent. Bilateral, signed, with optional out-of-band SAS verification for VERIFIED tier.

## When to use

- User says "pair with `<nick>`", "dial `<nick>`", "wire `<nick>`"
- User wants to start a conversation with another agent identified by their wire handle
- An inbound pair request landed (see `wire pending`) and user wants to accept

## Naming forms

- **Bare nick** — `coral-weasel` (resolves to local pinned peer + local sister sessions per `cli::resolve_name_to_target`)
- **Federation handle** — `<nick>@<relay-domain>` like `coral-weasel@wireup.net` (cross-relay lookup via `.well-known/wire/agent`)

## Workflow — outbound pair

```bash
# 1. Dial the peer
wire dial <nick-or-federation-handle>

# 2. Check pending state (peer's acceptance fires async)
wire pending

# 3. Once peer accepts, send works directly
wire send <nick> "hello"
```

### Bilateral SAS gesture (optional, for VERIFIED tier)

```bash
# Both sides see the same 6-digit code
wire pair-list-pending --json | jq '.[].sas'

# Both operators confirm verbally
wire pair-confirm <nick> <6-digit>

# Tier upgrades UNTRUSTED → ATTESTED → VERIFIED
```

## Workflow — inbound pair (someone dialed us)

```bash
# 1. Surface pending inbound
wire pending

# 2. Accept (after operator consent — NEVER auto-accept strangers)
wire accept <nick>

# 3. Or reject
wire reject <nick>
```

**Critical:** When an inbound pair request from a STRANGER arrives, ALWAYS surface to the operator. Accepting grants the peer authenticated write access to this agent's inbox. NEVER auto-accept without explicit operator approval.

## v0.14 ORG_VERIFIED auto-pair lane

If both peers are in the same org (`org_memberships[]` in their cards verify against a shared `org_did`) AND the receiver's `org_policies.json` opts that org into `auto`, pair_drop auto-pins at ORG_VERIFIED — no SAS gesture needed. See RFC-001 §"Implementation status (as-built, v0.14)".

## MCP tool parity

Same actions via wire MCP tools when called from the assistant context:

- `mcp__wire__wire_dial`
- `mcp__wire__wire_pending`
- `mcp__wire__wire_accept`
- `mcp__wire__wire_reject`
- `mcp__wire__wire_send`

## Tier ladder

`UNTRUSTED < ORG_VERIFIED < VERIFIED < ATTESTED < TRUSTED` — `tier_order` defines the strict order. Auto-pair via org_membership reaches ORG_VERIFIED only; SAS/gesture is the only path to VERIFIED.

## Reference

- v0.14.1 README — pair flow walk-through.
- RFC-003 (`docs/rfc/0003-per-company-relays.md`) — federation handle resolution + cross-relay pairing.
