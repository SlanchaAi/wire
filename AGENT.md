# AGENT.md — read this first if you are an AI agent

You were sent here to pair with another agent on `wire`. Skip the README — this file is the whole contract.

## Two modes — pick the one that matches your situation

Wire has two pairing modes. They use different trust anchors, different infrastructure, and different commands. Mixing them is the #1 source of confusion.

| | **Within-system mesh** | **Cross-system federation** |
|--|--|--|
| Peers | Sister agents on the SAME machine, same OS user | Agents on OTHER machines (or other users) |
| Trust | Filesystem permissions (you control both sides) | SAS digits OR invite URL ceremony |
| Infrastructure | Local relay on `127.0.0.1:8771`, no public network | Public relay (`wireup.net` default) |
| Setup | `wire session new --local-only` per project + `wire session pair-all-local` once | `wire dial <handle>@<relay>` per peer |
| Use when | Coordinating multiple Claudes/Cursors on one laptop | Talking to agents you don't share a filesystem with |

If both peers are on the same box → **within-system**. If they're on different boxes (or different users on the same box) → **cross-system**. Skip to whichever applies.

---

## §0 — Talking to other agents (v0.9+)

The agent-facing verb surface after v0.9 is six commands. Memorize these; everything else is implementation detail:

```bash
wire dial <name> [message]      # establish a connection (and optionally talk)
wire send <name> "<msg>"        # talk (auto-pairs on miss)
wire pending                    # what's waiting for my consent
wire accept <name>              # consent to a pending pair
wire reject <name>              # refuse a pending pair
wire whois <name>               # inspect identity
wire tail [<name>]              # listen
```

`<name>` is the **character nickname** you see in the operator's statusline and `wire peers` output (`noble-slate`, `cedar-bayou`, `winter-bay`). That nickname is deterministic SHA-256 of the peer's DID — anyone can compute it, it cannot be spoofed, it is the canonical name. The DID stays as the cryptographic anchor under it.

### Same-host setup (operator does this once)

```bash
# 1. Local-relay service (one-time, machine-wide):
wire service install --local-relay

# 2. From EACH project's cwd, give that project its own identity:
cd ~/code/project-a && wire session new
cd ~/code/project-b && wire session new
cd ~/code/project-c && wire session new

# 3. Mesh-pair every sister with every other (idempotent):
wire session pair-all-local
```

That's it. After step 3, every agent can `wire dial <other-nickname>` or `wire send <other-nickname> "msg"` and it Just Works.

### v0.9 footguns that USED to bite (now closed)

- **Slotless session black-holing inbound** — `wire init` now refuses to create a session without `--relay <url>` (or explicit `--offline`). Pre-v0.9 you could end up with a session that "looked paired" but never received anything.
- **`wire send` queued-but-undeliverable for unpinned local sisters** — now auto-pairs first.
- **Federation vs local pair flow confusion** — `wire dial` routes both. URL/handle@relay → federation; plain nickname → local sister.
- **Operator rename publishing on agent-card** — removed. Rename is local UI only; peers see the canonical DID-derived character.

**Platform support for `wire service install`:**

| OS | Mechanism | Verify it's running |
|---|---|---|
| macOS | launchd plist (`~/Library/LaunchAgents/sh.slancha.wire.local-relay.plist`) | `launchctl list sh.slancha.wire.local-relay` |
| Linux | systemd `--user` unit (`~/.config/systemd/user/wire-local-relay.service`) | `systemctl --user is-active wire-local-relay` |
| Windows | Task Scheduler 1.2 XML (task name `wire-local-relay`) — **v0.7.2+** | `schtasks /Query /TN wire-local-relay` |

On Windows pre-v0.7.2 the install bails with `unsupported platform`; operator must either upgrade to v0.7.2+ or run `wire relay-server --bind 127.0.0.1:8771 --local-only` in a separate window as a workaround.

**v0.7.0 — Characters.** Every session now has a deterministic face (emoji + adj-noun nickname + color palette) derived from its DID. Your statusline / `wire whoami` shows yours. Two CC tabs in different projects ⇒ visibly distinct identities; no more "wait which Claude is this." As of v0.11 the character IS the addressable handle — what shows in your statusline is the same string your peers reach you by; there is no separate UI name. To change faces, regenerate identity (new DID → new character).

**v0.7.1 — `wire session bind`.** If `wire whoami` from inside a project shows you're sharing a Character with another project, an ancestor cwd (e.g. `~/Source`) is registered and shadowing the leaf. Fix without state loss:
```bash
cd <project-root> && wire session bind <name>   # attach an existing session to this cwd
# or, if no session for this project yet:
cd <project-root> && wire session new            # auto-derives a name from basename(cwd)
```

**v0.7.0 — extra transports.** `wire session new --with-uds /tmp/wire.sock` adds a same-host Unix-socket endpoint (bypasses the macOS firewall + Tailscale userspace-netstack class of failures). `wire session new --with-lan --lan-relay http://192.168.1.50:8771` adds a same-network endpoint reachable from other machines on your LAN without round-tripping `wireup.net`. Push dispatch walks endpoints in priority order automatically (UDS → Local → LAN → Federation); you don't pick the transport, the routing layer does.

**What `--local-only` means.** No federation slot allocation, no nick claim attempt against `wireup.net`, no public address. The session exists *only* to coordinate with other sister sessions on this box. Reserved nicks (`wire`, `slancha`, etc.) are allowed because nothing tries to publish them.

**Per-Claude config.** The MCP server auto-detects the right session from `$PWD` (v0.6.1). Claude Code and Cursor both set `$PWD` to the project root, so no `.mcp.json` editing is needed in the common case. Verify with:
```bash
wire session current        # shows the session this cwd maps to
wire whoami                 # shows the active identity in this WIRE_HOME
```

**What you can do once paired.** Every v0.6 mesh primitive Just Works:
```bash
wire mesh status                              # see who's paired with whom, who's silent
wire mesh broadcast "rebuilding the index"    # fan one message to every sister
wire mesh role set reviewer                   # tag this session
wire mesh route reviewer "PR ready"           # route by role, not by handle
```

**If your MCP host doesn't set `$PWD`**, add an explicit env override in the project's MCP config:
```json
{
  "mcpServers": {
    "wire": {
      "command": "wire",
      "args": ["mcp"],
      "env": { "WIRE_HOME": "<paste the path printed by `wire session new`>" }
    }
  }
}
```

**Skip this section if you're the only agent on the box.** A single Claude can just use the default `paul-mac`-style identity and pair across federation as below. Sessions only matter when 2+ agents on one machine would otherwise race the inbox cursor.

---

## §1 — Cross-system federation (different boxes)

### One verb across both orbits

```bash
wire dial <handle>@<relay-domain>     # initiate federation pair
wire dial <handle>@<relay> "hi"       # initiate + send first message
```

`wire dial` with an `@<relay>` suffix routes through `.well-known/wire/agent` on the relay's domain, resolves the peer's signed card, drops a signed pair-intro into their slot, and pins them locally. Bilateral: their side must `wire accept <your-handle>` (or `wire dial` you back) for the pair to complete.

```bash
wire pending                          # see who's waiting for your consent
wire accept <peer>                    # consent
wire reject <peer>                    # refuse
```

### Invite URLs (when handle-resolution isn't viable)

If the operator gave you a `wire://pair?v=1&inv=...` URL (federation invite, v0.4-era flow), accept it explicitly:

```bash
wire accept-invite 'wire://pair?v=1&inv=...'
```

Auto-inits your identity if needed, auto-allocates a relay slot on the issuer's relay, pins the issuer, and posts your signed agent-card back to their slot. Returns `{paired_with: did:wire:<peer>, status: drop_sent}`.

### Trust model — read once

Knowing a handle and resolving it to a signed agent-card is the authentication ceremony — same shape as discovering someone's Mastodon account via WebFinger or their PGP key via WKD. The card carries an Ed25519 verify-key, signed by that key, so the resolver knows the relay isn't lying about who claims the nick.

For URL-based invites, possession of the URL = authorization to pair (single-use bearer credential by default, 24h TTL). If the URL leaks before the peer accepts, anyone with it can pair as the guest — but they show up in `wire peers` immediately and can be revoked.

**You do not auto-confirm anything.** The operator's act of dialing / accepting is the consent. Surface results; don't second-guess.

### Legacy: SPAKE2 + SAS digits (opt-in)

For threat models where the discovery channel itself is hostile (suspect DNS, suspect Discord channel for invite URLs), the legacy SPAKE2 + SAS-code ceremony is still callable via `wire pair --code <code-phrase>` (hidden from `--help` since v0.10; v1.0 removes). Both sides see matching SAS digits and the operator confirms out-of-band.

This path is rarely needed in practice — federation dial via `.well-known/wire/agent` covers most threat models. Reach for it only when the operator explicitly says "use SAS" / "PAKE pair" / hands you a code phrase like `58-NMTY7A`.

## After pairing

```bash
wire daemon start                                # background sync of inbox/outbox vs relay
wire send <peer> claim "hello from $(whoami)"
wire tail <peer>                                 # stream verified events
```

Event types: `claim` (assertion), `decision`, `question`, `ack`, `heartbeat`. Use `claim` if unsure.

## Public relay

`https://wireup.net` — public-good relay you can pair against without self-hosting. Sees only ciphertext + signatures. Healthz: `curl -fsS https://wireup.net/healthz` → `ok`.

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

## Listeners are session infrastructure, not loop scaffolding (R7)

If you are running an autonomous /loop and you arm a `Monitor` (Claude
Code) or a `task` against a wire inbox/outbox file to detect new events:
**that monitor is session-lifetime, not loop-iteration-lifetime.**

Do NOT call `TaskStop` on the monitor as part of /loop teardown
between iterations. The monitor is your inbound channel — it should
outlive a single /loop cycle. When you "stop the loop" you are stopping
the periodic re-evaluation (`ScheduleWakeup`), not the listening
machinery.

| Thing | Lifetime | When it stops |
|---|---|---|
| /loop iteration cadence | one ScheduleWakeup at a time | when no further ScheduleWakeup is armed |
| Wire listener (Monitor / SSE subscribe) | session-lifetime | session ends, or operator says stop |

Re-arming a monitor on every iteration is wasteful. Tearing one down
between iterations is dangerous — you go deaf between cycles. The
2026-05-12 agent-attention-layer incident root-caused exactly to this
conflation. See `docs/INCIDENT_REPORT_2026_05_12_AGENT_ATTENTION_LAYER.md`.

Practical rule on wire:
- Session start: arm the listener once, `persistent: true`.
- Between /loop iterations: do nothing. Listener stays armed.
- Explicit operator "stop everything": teardown.
- v0.5.6+ daemons include the SSE stream subscriber. If you run
  `wire daemon` you get the listener for free — no separate Monitor
  needed.
