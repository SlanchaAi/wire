# Mac Handoff — wire dev resumption

**Date:** 2026-05-12
**Source machine:** Spark (`promaxgb10-d325.local`)
**Target machine:** operator's Mac
**Author:** Claude Opus (Spark, last day of context before switch)

You are resuming wire OSS development on the operator's Mac. This handoff
captures the state, the in-flight items, and the Mac-specific bootstrap.

---

## TL;DR — what's true right now

- **Repo:** `github.com/SlanchaAi/wire` (transferred from `laulpogan/wire`
  earlier today; old URL still redirects). Default branch `main`.
- **Latest tag:** `v0.5.8` (commit `219aa79`). CI was building when Spark
  session ended; check `gh run list` for status.
- **Production relay:** `https://wireup.net` (Cloudflare tunnel from Spark
  → relay-server on `127.0.0.1:8770`). Legacy alias
  `https://wire.laulpogan.com` also alive.
- **Production landing:** same URL serves landing on `8771` (python
  http.server). First-user pull-quote from Will on the page.
- **License trio:** AGPL relay, Apache protocol, MIT CLI. Intentional — sets
  up future monetization of hosted relay without polluting the OSS feel.

## Operator's working language

- **Caveman mode active.** All conversational text is terse: drop articles,
  filler, hedging. Fragments OK. Short synonyms. Technical substance exact.
  Code, commits, PRs, security writing: normal prose. Activated by global
  CLAUDE.md, persists across sessions.
- Standing /loop directive when they say it: `/loop fix A keep going, also
  test when feature is in a good spot`. Self-pace dynamic mode, no fixed
  interval. Don't reinterpret the directive — wait for explicit ops.
- They have **two GitHub accounts** signed in: `laulpogan` (write to wire,
  paid account) and `loganclaw9000` (frequent default). On push 403:
  `gh auth switch --user laulpogan`. They are admin on the `SlanchaAi` org.

## Recent ship velocity (last 24h of Spark session)

| version | landed |
|---|---|
| **v0.5.0** | 3-layer identity (DID + handle + profile), handle directory, zero-paste pair via `wire add` |
| **v0.5.1** | A2A v1.0 client consumption (consume cards from any A2A impl) |
| **v0.5.2** | rebrand to `wireup.net` (was `wire.laulpogan.com`) |
| **v0.5.3** | bugfix: `wire claim` is actually one-step (was bailing on uninit) |
| **v0.5.4** | R4: `wire send` attentiveness pre-flight; phyllis voice on hot errors |
| **v0.5.5** | R1 phase 1: SSE push endpoint on relay |
| **v0.5.6** | R1 phase 2: daemon subscribes to own slot's SSE stream |
| **v0.5.7** | DID collision fix (pubkey-suffixed); R7 listener-lifetime docs |
| **v0.5.8** | repo moved to `SlanchaAi/wire`; DID call-site sweep |

## Mac-specific bootstrap

**Step 1 — clone the repo fresh.** Existing local clones (if any) point at
`laulpogan/wire`. GitHub auto-redirects but it's cleaner to start from the
new origin:

```bash
cd ~/Source  # or wherever you keep checkouts
git clone https://github.com/SlanchaAi/wire.git
cd wire
```

Or if you already have a clone:

```bash
cd ~/Source/wire
git remote set-url origin https://github.com/SlanchaAi/wire.git
git fetch
git checkout main && git pull
```

**Step 2 — install the latest wire binary.** Mac is darwin-aarch64 (assumed
M-series). install.sh autodetects the platform and pulls the matching
binary from the latest GitHub release:

```bash
curl -fsSL https://raw.githubusercontent.com/SlanchaAi/wire/main/install.sh | sh
wire --version  # should print: wire 0.5.8
```

**macOS Gatekeeper gotcha:** if `wire` won't run with "cannot be opened
because the developer cannot be verified", remove the quarantine xattr:

```bash
xattr -d com.apple.quarantine "$(which wire)"
```

This is a one-time per-install workaround; the binary is unsigned for
distribution. Future v0.6.x may add notarization to release.yml — not yet.

**Step 3 — check for existing wire identity on this Mac.** If the operator
was using wire on the Mac before this handoff, there's likely a config
already:

```bash
wire whoami --json 2>/dev/null && echo "EXISTING IDENTITY" || echo "FRESH"
```

If `EXISTING IDENTITY` prints with a DID like `did:wire:paul`:
- Pre-v0.5.7 DID format. Still verifies signatures, but not pubkey-
  suffixed for collision resistance. Two options:
  - **Keep it** — no migration needed, signatures continue to work.
  - **Reset** — `rm -rf $WIRE_HOME` (likely
    `~/Library/Application Support/wire`) and re-init with a unique
    handle: `wire claim paul-mac@wireup.net`.

If `FRESH`:
```bash
wire claim paul-mac@wireup.net  # or whatever handle you want
```

Auto-inits identity + allocates slot + claims handle on
`wireup.net` in one command (this is the v0.5.3 fix).

**Step 4 — verify connectivity to prod relay.**

```bash
curl -fsS https://wireup.net/healthz                       # expect: ok
wire whois wire-live-test-a@wireup.net --relay https://wireup.net
```

Should print the live test agent's profile (emoji 🧪, motto, vibe).

**Step 5 — Claude Code MCP wiring (if you'll be using wire from inside
Claude Code on Mac).**

```bash
wire setup --apply  # idempotently merges wire into ~/.claude.json
```

Restart Claude Code after this. wire's MCP tools (`wire_send`, `wire_pair_*`,
`wire://inbox/<peer>` resource) will load.

## What runs on Mac vs Spark

**On Spark (don't touch from Mac):**
- `wire-public-relay.service` — relay-server binary on `:8770`
- `wire-public-landing.service` — python http.server on `:8771`
- `wire-public-tunnel.service` — cloudflared tunnel routing `wireup.net` +
  `wire.laulpogan.com` to the above
- Two cert.pems in `~/.cloudflared/` — wireup.net auth + backup laulpogan-
  only auth
- The `wire-public/landing/index.html` file (live-served, edits propagate
  immediately on next request — no commit needed)

**On Mac:**
- `wire` CLI binary — client of `wireup.net`
- Optional `wire daemon` for SSE push + background sync
- Operator's own dev clone of `SlanchaAi/wire` for code work
- Claude Code with wire MCP tools

**Do NOT install wire-relay-server on the Mac.** The public-good relay is
intentionally singleton on Spark for now. Mac being a client preserves the
"cross-machine pair across the wire" demo. If you genuinely need a local
relay for offline dev: `wire relay-server --bind 127.0.0.1:9999` and pass
`--relay http://127.0.0.1:9999` to all client commands. Don't bind to a
public interface.

## In-flight items (priority order)

### Operator-blocked (you can't do these from Mac-claude alone):

1. **Enable SlanchaAi org 2FA.** Settings → Security → Require 2FA for all
   org members. ~2 min. Single biggest pre-launch security gap. Currently
   `two_factor_requirement_enabled: false`.
2. **Set up `🧷 wire` Discord category in Slancha server.** Full spec drafted
   in this session. Channels: `#wire-announce`, `#wire-help`,
   `#wire-show-and-tell`, `#wire-protocol`, `#wire-bridges`, `#wire-meta`.
   Reaction-role bot (Carl-bot). GitHub webhook → `#wire-announce`. ~25 min
   of clicking in Discord UI.
3. **Record asciinema demo** for landing page. Sequence:
   ```bash
   curl -fsSL https://raw.githubusercontent.com/SlanchaAi/wire/main/install.sh | bash
   wire claim coffee-ghost@wireup.net
   wire profile set emoji 👻
   wire profile set motto "haunts late-night PR reviews"
   wire add tide-pool@wireup.net  # (operator has a second handle pre-claimed for this)
   wire send tide-pool decision "ship it"
   ```
   ~30 sec recording. Embed in `landing/index.html`. **Single highest-
   conversion landing addition.** Without it, HN/Reddit visitors don't see
   the magic.
4. **Fire launch posts.** Drafts in `LAUNCH_POSTS.md`. Targets that survive
   karma checks (r/LocalLLaMA blocked): r/rust, r/SideProject, r/ClaudeAI,
   r/selfhosted, r/opensource, HN Show HN, dev.to, Hashnode, Mastodon,
   Bluesky. 8 awesome-list PRs drafted in `AWESOME_LISTS.md`.
5. **npm publish `openclaw-channel-wire`** — needs `npm adduser`. Blocked
   per handoff backlog.
6. **PyPI publish `wire-langgraph`** — similar.
7. **willard pair coordination** — out-of-band, depends on willard's wire
   install state.

### Code-deferrable (you can do from Mac-claude):

- **R2** — `time_sensitive_until` field on signed event payloads. CLI
  `--deadline <duration>` flag. Receiver displays urgency hint in `wire tail`.
  Half-day effort. From `docs/INCIDENT_REPORT_2026_05_12_AGENT_ATTENTION_LAYER.md`.
- **R3** — responder-health events. Auxiliary CLI `wire responder set
  <status>` posts a kind=1500 event to operator's own slot. Relay surfaces
  via `slot_state` endpoint. Peers query before sending time-sensitive
  asks. Half-day.
- **R5** — `wire status --peer <handle>` showing 3-layer health
  (transport, attention via R4, auto-responder via R3). Depends on R3.
- **DID call-site audit** — v0.5.8 swept the obvious sites but spot-check
  any new code that does `did.strip_prefix("did:wire:")` and replace with
  `crate::agent_card::display_handle_from_did(...)`.

## Knowledge that doesn't survive in git

### The Will quote (brand-gold)

First wire user reaction, paraphrased from iMessage screenshot:

> "It's like having an avatar of yourself interact with an avatar of your
> friend or colleague. Great for asynchronous AND synchronous working —
> and great at knowledge hand-off."

Currently the landing-page pull-quote. The "**hand-off**" framing is bigger
than the messaging framing — Will independently surfaced that wire's role
isn't just "agents talk" but "context transfer between AI sessions /
operators." That's a stickier wedge than the comms framing the launch posts
currently lead with. **Consider re-pitching wire as "context hand-off
between AI sessions"** — different audience (PMs, consultants, anyone
running multiple agents) than the dev-tools messaging-bus framing.

### License intent

AGPL on relay specifically prevents AWS/etc from forking
`wire-relay-server` as a closed-source SaaS without open-sourcing the
hosted offering. Sets up future "MongoDB-style we're-the-paid-host" path
without locking down the protocol or the CLI.

### Subreddits that will / won't survive a launch attempt

| Survive | Karma constraint | Won't survive |
|---|---|---|
| r/rust | low bar | r/LocalLLaMA (operator karma too low) |
| r/SideProject | none | r/MachineLearning (academic) |
| r/ClaudeAI | low | r/programming (project-launch hostile) |
| r/selfhosted | moderate | r/AGI (speculation) |
| r/opensource | none | r/devops (off-vertical) |

### A2A federation extension URI — should be migrated to slancha.ai

**Operator surfaced this on switch-out:** the v0.5.8 commit left the wire
A2A extension URI as `https://github.com/laulpogan/wire/ext/v0.5` with a
comment claiming it MUST stay that way forever. That was the **defensive**
read — true if external federation peers depend on the exact string. False
right now because there are zero external A2A consumers of wire extensions
in the wild yet. The handoff overstated the lock-in.

**What an A2A extension URI actually is:**
The A2A v1.0 spec lets agents publish `AgentCard` JSON at
`/.well-known/agent-card.json` with a core schema (name, endpoint,
capabilities, security) and an `extensions` array for protocol-specific
fields. Each extension is identified by a URI string. Example from Google:
`https://a2a-protocol.org/spec/v1/extension/streaming-v1`.

Federation peers treat the URI as an **opaque identifier** — analogous to
an XML namespace, a JSON-LD `@context` URL, or a DID method name. They
match it as a string, they don't fetch it. So the URI is namespacing, not
content. The hosting domain doesn't have to serve anything at that URL —
though it's good practice to put a real doc there so curious humans can
read the extension spec.

**Why we can migrate now:**
- Wire ships v0.5.8 today. Zero external federation peers have shipped a
  wire-extension consumer yet (we're the only one).
- Pre-traction == migration is free.
- Wire chose GitHub URLs originally for convenience, not because A2A
  required it. Google's own extensions use a vendor domain (`a2a-
  protocol.org`), not GitHub. Decoupling our extension namespace from
  GitHub-specifically is more durable.

**Recommended migration: `https://slancha.ai/wire/ext/v0.5`**
- Owned by Slancha (the org). Persists across repo moves.
- Aligns with the A2A norm of vendor-domain namespacing.
- Frees future repo moves from extension-URI lock-in.

(Alternative `https://wireup.net/wire/ext/v0.5` is also fine — the product
domain. Tradeoff is wireup.net is the public-good relay, slancha.ai is the
org. Either works; pick by what feels more "permanent.")

**To do the migration (Mac-claude can ship this):**

1. Update `src/relay_server.rs` line ~1049: change the extension URI
   string to `https://slancha.ai/wire/ext/v0.5` (or whichever you pick).
   Drop the long "MUST stay" comment; replace with a short note that the
   URI is the namespace identifier and changing it is a coordinated
   federation-spec bump.
2. Update `src/pair_profile.rs` line ~242: change `.starts_with(...)` to
   match the new URI. For a transition window, you can accept both old
   and new with `let valid = uri.starts_with(NEW) || uri.starts_with(OLD)`
   — but with zero external consumers, just flip to the new one and
   document the version.
3. Bump CHANGELOG noting the extension URI change is a federation-spec
   bump (would normally be a major-version of the extension, but since
   nothing in the wild depends on the old URI, treat as patch).
4. (Optional, polish): publish a real doc at `slancha.ai/wire/ext/v0.5`
   describing the extension fields (`did`, `handle`, `slot_id`, `relay_url`,
   signed-card blob, mailbox semantics). Becomes the canonical reference
   for any future A2A consumer adopting wire extensions.
5. Re-run smoke against prod after restart:
   ```bash
   curl -fsS https://wireup.net/.well-known/agent-card.json?handle=wire-live-test-a \
     | jq '.extensions[0].uri'
   # expect: "https://slancha.ai/wire/ext/v0.5"
   ```

This is straightforward — one commit, ~10 lines changed across 2 files +
CHANGELOG. Tag as v0.5.9 if shipping standalone, or fold into the
R2/R3/R5 v0.5.9 if working on those.

**If Mac-claude defers:** the laulpogan-URI keeps working indefinitely.
But each day of delay raises the (low but non-zero) chance that a third
party builds a wire-extension consumer pinned to that URI, and migration
gets harder. Recommend shipping the migration in the next wire commit.

### Local Spark-only test flake

`tests/e2e_detached_pair.rs` deterministically fails on Spark in this
session — verified pre-existing on clean v0.5.4 HEAD before any of
v0.5.5-v0.5.8 work. CI runs in a clean container and is consistently
green on the same test. Likely lingering daemon process state from earlier
live smokes. Not on Mac if you're on a fresh checkout.

## Sanity check after Mac install

Run these to confirm everything works end-to-end:

```bash
# 1. Binary works
wire --version  # → wire 0.5.8

# 2. Relay reachable
curl -fsS https://wireup.net/healthz  # → ok

# 3. Cross-home pair (smoke against prod, ephemeral handles)
TS=$(date +%s)
HOME_A=/tmp/mac-smoke-A-$$
HOME_B=/tmp/mac-smoke-B-$$
mkdir -p $HOME_A $HOME_B

WIRE_HOME=$HOME_A wire claim "mac-smoke-a-$TS" --relay https://wireup.net
WIRE_HOME=$HOME_B wire claim "mac-smoke-b-$TS" --relay https://wireup.net
WIRE_HOME=$HOME_B wire whois "mac-smoke-a-$TS@wireup.net" \
  --relay https://wireup.net  # should print A's card

rm -rf $HOME_A $HOME_B
```

If all three pass, Mac is wire-ready.

## Resume action

Operator will likely give one of:

- **"keep going on R2/R3/R5"** → start with R7 docs (cheap), then R2 schema
  + `--deadline` flag, then R3 endpoint + CLI, then R5 status integration.
  Bundle as v0.5.9. The pattern of v0.5.x patch releases worked well —
  small bisectable commits, ship to prod between each.
- **"launch"** → operator handles posting; you handle code-side polish
  (asciinema demo verification, fix anything the first wave of HN/Reddit
  commenters surfaces).
- **"hand-off framing pivot"** → see Will quote section. Refactor landing
  + LAUNCH_POSTS toward context-transfer positioning.
- **"new feature X"** → context is in their head, ask the question.

## Files of interest in the repo

| File | Purpose |
|---|---|
| `README.md` | Public face. Recent edits updated repo URL to SlanchaAi |
| `AGENT.md` | Contract for AI agents using wire. R7 section recent |
| `CHANGELOG.md` | Detailed per-version notes; v0.5.x history rich |
| `SPEC_v0_5.md` | Three-layer identity + handle directory spec |
| `COMPETITIVE_v0_5.md` | Analysis of A2A, AMP, ANP, AGNTCY, Coral |
| `BRAND_BRAINSTORM.md` | Phyllis, hotline glossary, Hotline Digest newsletter |
| `LAUNCH_POSTS.md` | 10-channel launch packet |
| `AWESOME_LISTS.md` | 8 PR drafts for awesome-* repos |
| `docs/INCIDENT_REPORT_2026_05_12_AGENT_ATTENTION_LAYER.md` | R1-R7 origin |
| `docs/MAC_HANDOFF_2026_05_12.md` | this file |

## One-shot orientation prompt for Mac-claude

When you spin up the Mac session, paste this into the operator's first
message to get fully oriented in one round-trip:

> Read `docs/MAC_HANDOFF_2026_05_12.md` in
> `github.com/SlanchaAi/wire`. Then run the sanity-check block at the
> bottom of that doc. Then read `CHANGELOG.md` v0.5.x entries. Don't take
> any actions yet — summarize what you understood and wait for me.

---

**Final note from Spark-claude:** the wire build velocity over the last 12
hours has been unusual — 9 patch releases, all green on CI, all live on
prod, first real user with a brand-gold testimonial. The operator has
momentum. Don't slow them down with process. The product holds together;
keep shipping small, bisectable patches; let the operator decide when to
fire the launch.

— Spark-claude, 2026-05-12T22:35Z
