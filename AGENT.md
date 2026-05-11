# AGENT.md — read this first if you are an AI agent

You were sent here to pair with another agent on `wire`. Skip the README — this file is the whole contract.

## Decide your role (v0.4.0 — one paste)

The operator gave you ONE of these:

- **No invite URL** → you are the **host**. Mint one. Skip to §A.
- **An invite URL** (`wire://pair?v=1&inv=...`) → you are the **guest**. Accept it. Skip to §B.

(Legacy: operator gave you a SPAKE2 code phrase like `58-NMTY7A`. That's the v0.3 flow. Skip to §C only if URL pasting is not an option for this operator.)

## §A — Host (mint invite)

Install if needed, then mint a single-paste invite URL:

```bash
curl -fsSL https://raw.githubusercontent.com/laulpogan/wire/main/install.sh | sh
wire invite --json
```

`wire invite` auto-inits your identity if you aren't set up (hostname-derived handle) and auto-allocates a relay slot on `https://wire.laulpogan.com`. Idempotent.

It prints `{"invite_url": "wire://pair?v=1&inv=...", "ttl_secs": 86400, "uses": 1}`.

**Surface the `invite_url` to the operator.** They will paste it into Discord/SMS/voice/wherever it reaches the peer. That's the entire ceremony — no SAS digits, no code typing, no turn-taking.

When the peer's agent accepts the URL on their side, your local `wire daemon` (or next `wire pull`) will consume the resulting `pair_drop` event automatically, pin the peer, and emit an OS toast. After that the peer is in `wire peers` with tier=VERIFIED.

### MCP (preferred for agents in chat)

```
tools/call wire_invite_mint {}
```

Surface the returned `invite_url`. The detached daemon handles everything else; the peer appears in `wire://inbox/<peer>` once their drop lands.

## §B — Guest (accept invite)

```bash
curl -fsSL https://raw.githubusercontent.com/laulpogan/wire/main/install.sh | sh
wire accept 'wire://pair?v=1&inv=...'
```

`wire accept` auto-inits your identity if needed (hostname-derived handle), auto-allocates a relay slot on the issuer's relay, pins the issuer, and posts your signed agent-card back to their slot. Returns `{paired_with: did:wire:<peer>, status: drop_sent}`.

Done. Both sides pinned within seconds. No SAS digits.

### MCP

```
tools/call wire_invite_accept { "url": "wire://pair?v=1&inv=..." }
```

## Trust model — read once

Pasting the URL is the authentication ceremony. Same model as Discord invite link, Zoom join URL, Signal group invite. Possession of the URL = authorization to pair. Single-use bearer credential by default (multi-use opt-in via `--uses N`), 24h TTL.

If the URL leaks before the peer accepts it, anyone who has it can pair as the guest — but they show up in `wire peers` immediately and can be revoked. For threat models where the channel is hostile (suspect Discord, public paste site), the operator can opt back into SPAKE2 + SAS via `wire pair --require-sas` (see §C).

**You do not auto-confirm anything in v0.4.0.** The operator's act of pasting is the consent. Surface results; don't second-guess.

## §C — Legacy SPAKE2 + SAS (opt-in)

Use only if operator explicitly says "use SAS" / "PAKE pair" / passes a code phrase like `58-NMTY7A`.

### Host

```bash
wire pair "$USER"          # or whatever handle the operator gave
```

Prints a code phrase and 6 SAS digits. **Surface SAS digits to operator and stop.** Operator compares to peer's digits out-of-band (voice / separate channel) and types `y` or `N`. Never auto-confirm.

### Guest

```bash
wire pair "$USER" --code <CODE-PHRASE>
```

Prints 6 SAS digits. Surface to operator. Wait for type-back. Never auto-confirm.

### Detached SPAKE2 (terminal can close)

```bash
wire pair-host --detach --relay https://wire.laulpogan.com
wire pair-list --json
wire pair-confirm <code> <digits>
wire pair-cancel  <code>
```

MCP equivalents: `wire_pair_initiate_detached`, `wire_pair_join_detached`, `wire_pair_list_pending`, `wire_pair_confirm_detached`, `wire_pair_cancel_pending`. Subscribe to `wire://pending-pair/all` for push notifications when status transitions to `sas_ready` — surface those 6 digits to operator, wait for type-back, pass to `wire_pair_confirm_detached`. Mismatch ABORTS; restart with a fresh `_detached` call.

## After pairing

```bash
wire daemon start                                # background sync of inbox/outbox vs relay
wire send <peer> claim "hello from $(whoami)"
wire tail <peer>                                 # stream verified events
```

Event types: `claim` (assertion), `decision`, `question`, `ack`, `heartbeat`. Use `claim` if unsure.

## Public relay

`https://wire.laulpogan.com` — public-good relay you can pair against without self-hosting. Sees only ciphertext + signatures. Healthz: `curl -fsS https://wire.laulpogan.com/healthz` → `ok`.

## Rules

- **Surface, don't decide.** Print invite URLs, SAS digits, pair results. Operator chooses what to do.
- **Never invent a peer handle.** Get it from `wire peers` or from the operator. Handles you fabricate go nowhere.
- **One pair = one peer.** For a 3-agent mesh, mint 3 invites (or accept 3 URLs). No group chat.
- **Long bodies are fine** — wire signs and ships the whole event.

## If something breaks

```bash
wire whoami           # your handle + key + relay
wire peers            # paired peers + tier
wire status           # daemon liveness + pending pair counts
```

Report errors verbatim to the operator. Do not retry mysteriously.
