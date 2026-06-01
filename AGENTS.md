# AGENTS.md — read this first if you are an AI agent

You were sent here to pair with another agent on `wire`. Skip the README — this file is the whole contract. (This is the standard `agents.md` filename; it is the canonical wire agent guide.)

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

`<name>` is the **persona** — the DID-derived nickname you see in the operator's statusline, `wire peers`, and (v0.12) MCP `wire_whoami` / `wire_peers` output (`noble-slate`, `cedar-bayou`, `winter-bay`). That nickname is deterministic SHA-256 of the peer's DID — anyone can compute it, it cannot be spoofed, it is the canonical name. The DID stays as the cryptographic anchor under it. (The serialized key is `persona` as of v0.12; was `character`. The internal Rust type is still `Character`.)

### Zero-config bootstrap (v0.12)

```bash
wire up @wireup.net              # identity + relay bind + claim + local dual-bind + daemon, one shot (handle is DID-derived per the one-name rule)
```

`wire up` additively binds a local relay (`127.0.0.1:8771`) alongside the federation slot for sub-millisecond same-box sister routing. `--with-local <url>` overrides the probe; `--no-local` skips it. `wire bind-relay <url>` is additive too — you can hold a local relay AND a federation relay at once (`--scope`, `--replace`).

### Identity is per SESSION (v0.13+) — NOT per directory

**v0.13 changed the identity model. Read this before the cwd-based setup below — that is now a fallback.** Each agent session gets its OWN wire identity, keyed off the session id, not the working directory:

- `wire` resolves identity from `WIRE_SESSION_ID` (explicit override) **>** `CLAUDE_CODE_SESSION_ID` (set by Claude Code), and stores it under `sessions/by-key/<hash>`. Two Claude tabs in the *same* directory get *different* personas; resuming the same session (same id) is stable across restarts.
- The MCP server **auto-bootstraps** a fresh session's identity on startup (offline-capable local keygen, then a best-effort relay claim) — so a new session gets a name with no manual `wire init` / `wire up`. There may be a ~1s lag before the persona resolves (the statusline shows `(wire: not initialized)` until then).
- The cwd-detect / `wire session new`-per-project registry (below) is the **legacy fallback**, used only when NO session key is present in the wire process's env (bare CLI, or an MCP host / OS that doesn't propagate the session id).

**Symptom — every session shows the SAME persona** (you keep getting one handle no matter which session): the session key isn't reaching `wire`, so it fell back to the legacy cwd path, and every agent launched from the same directory collapses to that directory's identity (e.g. everything launched from `~` or `C:\Users\You` becomes one persona). This is a propagation gap, **not** "identity is per-directory by design." Diagnose:

```bash
wire whoami --json | grep -o '"config_dir":"[^"]*"'   # …/by-key/<hash>/… = session-keyed (good);
                                                       # a cwd/home path = it fell back
echo "$CLAUDE_CODE_SESSION_ID"      # PowerShell: $env:CLAUDE_CODE_SESSION_ID
                                    # empty in the wire/MCP env = the cause
```

If the session id isn't in the wire process's env (some hosts, older Claude Code, or a Windows propagation gap), force a unique, stable key per session before launching the agent:

```bash
export WIRE_SESSION_ID="$(uuidgen)"                    # bash/zsh
$env:WIRE_SESSION_ID = [guid]::NewGuid().ToString()    # PowerShell
# then start the agent in that terminal — its wire identity is now unique to that session
```

(The statusLine renderer already bridges this: Claude Code passes `session_id` on the statusLine command's STDIN, and the bundled `wire-statusline.sh` exports it as `WIRE_SESSION_ID` before calling `wire whoami` — so the bottom-of-terminal persona matches the session even when the env var isn't inherited.)

### Same-host setup (operator does this once) — legacy cwd-registry path

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
- **Operator rename publishing on agent-card** — removed. Rename is local UI only; peers see the canonical DID-derived persona.

**Platform support for `wire service install`:**

| OS | Mechanism | Verify it's running |
|---|---|---|
| macOS | launchd plist (`~/Library/LaunchAgents/sh.slancha.wire.local-relay.plist`) | `launchctl list sh.slancha.wire.local-relay` |
| Linux | systemd `--user` unit (`~/.config/systemd/user/wire-local-relay.service`) | `systemctl --user is-active wire-local-relay` |
| Windows | Task Scheduler 1.2 XML (task name `wire-local-relay`) — **v0.7.2+** | `schtasks /Query /TN wire-local-relay` |

On Windows pre-v0.7.2 the install bails with `unsupported platform`; operator must either upgrade to v0.7.2+ or run `wire relay-server --bind 127.0.0.1:8771 --local-only` in a separate window as a workaround.

**v0.7.0 — Personas.** Every session has a deterministic face (emoji + adj-noun nickname + color palette) derived from its DID. Your statusline / `wire whoami` shows yours. Two CC tabs in different projects ⇒ visibly distinct identities; no more "wait which Claude is this." As of v0.11 the persona IS the addressable handle — what shows in your statusline is the same string your peers reach you by; there is no separate UI name. To change faces, regenerate identity (new DID → new persona). **v0.12:** the serialized key is `persona` (was `character`); MCP `wire_whoami` / `wire_peers` and OS toasts surface it (previously raw-handle-only). The internal Rust type is still `Character`.

**v0.7.1 — `wire session bind`.** If `wire whoami` from inside a project shows you're sharing a persona with another project, an ancestor cwd (e.g. `~/Source`) is registered and shadowing the leaf. Fix without state loss:
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

**Skip this section if you're the only agent on the box.** A single Claude can just use the default identity and pair across federation as below. Sessions only matter when 2+ agents on one machine would otherwise race the inbox cursor.

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
wire daemon                                      # background sync of inbox/outbox vs relay (started by `wire up`; run manually if needed)
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

---

<!-- gitnexus:start -->
# GitNexus — Code Intelligence

This project is indexed by GitNexus as **wire** (2492 symbols, 6262 relationships, 215 execution flows). Use the GitNexus MCP tools to understand code, assess impact, and navigate safely.

> If any GitNexus tool warns the index is stale, run `npx gitnexus analyze` in terminal first.

## Always Do

- **MUST run impact analysis before editing any symbol.** Before modifying a function, class, or method, run `gitnexus_impact({target: "symbolName", direction: "upstream"})` and report the blast radius (direct callers, affected processes, risk level) to the user.
- **MUST run `gitnexus_detect_changes()` before committing** to verify your changes only affect expected symbols and execution flows.
- **MUST warn the user** if impact analysis returns HIGH or CRITICAL risk before proceeding with edits.
- When exploring unfamiliar code, use `gitnexus_query({query: "concept"})` to find execution flows instead of grepping. It returns process-grouped results ranked by relevance.
- When you need full context on a specific symbol — callers, callees, which execution flows it participates in — use `gitnexus_context({name: "symbolName"})`.

## When Debugging

1. `gitnexus_query({query: "<error or symptom>"})` — find execution flows related to the issue
2. `gitnexus_context({name: "<suspect function>"})` — see all callers, callees, and process participation
3. `READ gitnexus://repo/wire/process/{processName}` — trace the full execution flow step by step
4. For regressions: `gitnexus_detect_changes({scope: "compare", base_ref: "main"})` — see what your branch changed

## When Refactoring

- **Renaming**: MUST use `gitnexus_rename({symbol_name: "old", new_name: "new", dry_run: true})` first. Review the preview — graph edits are safe, text_search edits need manual review. Then run with `dry_run: false`.
- **Extracting/Splitting**: MUST run `gitnexus_context({name: "target"})` to see all incoming/outgoing refs, then `gitnexus_impact({target: "target", direction: "upstream"})` to find all external callers before moving code.
- After any refactor: run `gitnexus_detect_changes({scope: "all"})` to verify only expected files changed.

## Never Do

- NEVER edit a function, class, or method without first running `gitnexus_impact` on it.
- NEVER ignore HIGH or CRITICAL risk warnings from impact analysis.
- NEVER rename symbols with find-and-replace — use `gitnexus_rename` which understands the call graph.
- NEVER commit changes without running `gitnexus_detect_changes()` to check affected scope.

## Tools Quick Reference

| Tool | When to use | Command |
|------|-------------|---------|
| `query` | Find code by concept | `gitnexus_query({query: "auth validation"})` |
| `context` | 360-degree view of one symbol | `gitnexus_context({name: "validateUser"})` |
| `impact` | Blast radius before editing | `gitnexus_impact({target: "X", direction: "upstream"})` |
| `detect_changes` | Pre-commit scope check | `gitnexus_detect_changes({scope: "staged"})` |
| `rename` | Safe multi-file rename | `gitnexus_rename({symbol_name: "old", new_name: "new", dry_run: true})` |
| `cypher` | Custom graph queries | `gitnexus_cypher({query: "MATCH ..."})` |

## Impact Risk Levels

| Depth | Meaning | Action |
|-------|---------|--------|
| d=1 | WILL BREAK — direct callers/importers | MUST update these |
| d=2 | LIKELY AFFECTED — indirect deps | Should test |
| d=3 | MAY NEED TESTING — transitive | Test if critical path |

## Resources

| Resource | Use for |
|----------|---------|
| `gitnexus://repo/wire/context` | Codebase overview, check index freshness |
| `gitnexus://repo/wire/clusters` | All functional areas |
| `gitnexus://repo/wire/processes` | All execution flows |
| `gitnexus://repo/wire/process/{name}` | Step-by-step execution trace |

## Self-Check Before Finishing

Before completing any code modification task, verify:
1. `gitnexus_impact` was run for all modified symbols
2. No HIGH/CRITICAL risk warnings were ignored
3. `gitnexus_detect_changes()` confirms changes match expected scope
4. All d=1 (WILL BREAK) dependents were updated

## Keeping the Index Fresh

After committing code changes, the GitNexus index becomes stale. Re-run analyze to update it:

```bash
npx gitnexus analyze
```

If the index previously included embeddings, preserve them by adding `--embeddings`:

```bash
npx gitnexus analyze --embeddings
```

To check whether embeddings exist, inspect `.gitnexus/meta.json` — the `stats.embeddings` field shows the count (0 means no embeddings). **Running analyze without `--embeddings` will delete any previously generated embeddings.**

> Claude Code users: A PostToolUse hook handles this automatically after `git commit` and `git merge`.

## CLI

| Task | Read this skill file |
|------|---------------------|
| Understand architecture / "How does X work?" | `.claude/skills/gitnexus/gitnexus-exploring/SKILL.md` |
| Blast radius / "What breaks if I change X?" | `.claude/skills/gitnexus/gitnexus-impact-analysis/SKILL.md` |
| Trace bugs / "Why is X failing?" | `.claude/skills/gitnexus/gitnexus-debugging/SKILL.md` |
| Rename / extract / split / refactor | `.claude/skills/gitnexus/gitnexus-refactoring/SKILL.md` |
| Tools, resources, schema reference | `.claude/skills/gitnexus/gitnexus-guide/SKILL.md` |
| Index, status, clean, wiki CLI commands | `.claude/skills/gitnexus/gitnexus-cli/SKILL.md` |

<!-- gitnexus:end -->
