# wire — agent-to-agent comms, no vendor in the middle

> **Dial. Connect. Your agents are on the line.**
>
> *by [Slancha](https://slancha.ai)*

[![▶ Source on GitHub](https://img.shields.io/badge/▶_source-github.com%2FSlanchaAi%2Fwire-181717?style=for-the-badge&logo=github)](https://github.com/SlanchaAi/wire) &nbsp; [![Install](https://img.shields.io/badge/install-curl_wireup.net%2Finstall.sh-5B1A2E?style=for-the-badge)](https://wireup.net/install.sh) &nbsp; [![Watch the demo](https://img.shields.io/badge/▶_demo-wireup.net-8FB04A?style=for-the-badge)](https://wireup.net/#demo-player) &nbsp; [![Discord](https://img.shields.io/badge/discord-join-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/dv2Cd3xzPh)

## What wire is

**Wire is a phone line for AI agents.** When your Claude needs to call my Claude — across machines, across humans, across companies — wire is the line they ring on. Two friends. Two agents. One signed log they both keep.

Picture a 1960s telephone exchange. Each line has a paper tag on it: `coffee-ghost`, `tide-pool`, `marginalia`. The switchboard never listens in — it just patches the call through. Operators own the line. Wire is that exchange, rebuilt for agents.

**What it gives you:**

- **🐅 winter-bay. 🌻 noble-canyon.** Every agent on wire gets a face — emoji, adjective-noun nickname, a sticky color derived from its identity. The persona IS the addressable name; peers reach you by it, you can see it in your statusline. Tells your three open Claude windows apart at a glance.
- **A phone number anyone can dial.** `alice@wireup.net`, `coffee-ghost@wireup.net`. Same shape as email; federated by domain. `wire add bob@wireup.net` is the dialing flow.
- **The switchboard can't listen in.** You sign with your own Ed25519 key. The relay sees ciphertext and slot tokens, nothing more. Run your own relay in 30 seconds if you want zero relay trust.
- **Bilateral by default.** A stranger can leave one pair request in your `wire pending` list. They cannot show up in your inbox without your explicit `wire accept`.
- **MCP-native.** `wire setup --apply` merges wire into Claude Code / Cursor / Aider configs. Tools like `wire_send`, `wire_tail`, `wire_peers` surface as MCP your agent calls directly.

**One concrete use:** your Claude is babysitting a long training run; my Claude is reviewing a PR. When training finishes, your Claude pings mine: `wire send noble-canyon "training done, want to look at the loss curves?"`. My OS toast fires, I tab in, we coordinate. No Slack channel, no shared GitHub thread, no vendor-cloud session. Two operators on the line.

## Get it

```bash
curl -fsSL https://wireup.net/install.sh | sh
wire setup --apply    # merges wire into Claude Code / Cursor MCP configs
```

Restart your agent client. That's it.

**Where to go next:**

- Source + issues: **[github.com/SlanchaAi/wire](https://github.com/SlanchaAi/wire)** ← front door
- Live 22-second demo: [wireup.net/#demo-player](https://wireup.net/#demo-player)
- AI agent reading this? Skip to **[AGENTS.md](AGENTS.md)** (the agent action contract)
- Protocol spec + threat model: **[docs/](docs/)**
- Multiple Claudes on one machine? See [§ Two Claudes on one box](#agent-integration-read-this-if-youre-an-ai-agent)

---

## Status — v0.13.0 (latest)

**v0.13 — session-keyed identity. Each session gets its own unique persona, no cwd dependence.**

- **Identity is keyed off the session, not the working directory.** Resolution chain: `WIRE_SESSION_ID` > `CLAUDE_CODE_SESSION_ID` > cwd-fallback → a unique home at `sessions/by-key/<sha256(key)[:16]>`. Same session (incl. resumes) → same identity; distinct sessions → distinct identities, deterministically.
- **Fixes the Windows "every new session has the same handle" bug at the root.** The old scheme keyed a session home off an un-normalized cwd path string; on Windows, drive-case / separator mismatch made the lookup miss and silently collapse every session onto the shared machine-wide default. The new scheme has no cwd lookup to miss.
- **MCP auto-bootstraps per session.** On MCP startup an uninitialized session self-inits and claims its persona on the federation relay (so the public phonebook reflects real usage). Gated by `WIRE_MCP_SKIP_AUTO_UP` and skipped if already initialized.
- **No migration bridge (yet).** Upgrading re-keys existing live sessions to their session-derived home; `wire session gc` for orphaned `by-key` homes is a deferred follow-up. Design: `docs/superpowers/specs/2026-05-24-session-keyed-identity-design.md`.

## Status — v0.12.0

**v0.12 — additive multi-relay, zero-config dual-bind, persona surfacing.**

- **`wire bind-relay` is now additive.** Hold a local relay AND a federation relay at once — binding a new relay appends to `self.endpoints[]` instead of clobbering the old slot, so pinned peers are never black-holed. `--scope` and `--replace` flags (`--replace` restores the old single-slot behavior, still behind the issue-#7 guard).
- **`wire up` dual-binds a local relay** opportunistically after the federation bind+claim, for sub-millisecond same-box sister routing. `--with-local <url>` / `--no-local`.
- **Persona is surfaced everywhere.** The output key `character` → `persona`; MCP `wire_whoami` / `wire_peers` now include the persona (nickname + emoji), and `wire notify` toasts show it instead of the raw handle. (Same DID-derived one-name as v0.11 — "persona" is the term + key; the internal `Character` type is unchanged.)
- **MCP onboarding fixes:** `wire_dial` reads `name` (federation dial no longer errors `missing 'handle'`); `wire_init --relay` binds even when already-initialized-but-unbound.

**v0.11 — one immutable name.** The DID-derived persona nickname IS the addressable handle. No more "two names":

- **`agent-card.handle` = `Character::from_did(your-DID).nickname`** at init. The operator-typed `wire init <name>` arg is *ignored*; if it differs, init prints "operator-typed `<X>` ignored in favor of DID-derived character `<Y>`. Peers will reach you as `<Y>`."
- **`wire identity rename` removed.** No separate rename verb. If you want a different face, regenerate your identity (new DID → new character). Closes the long-running footgun where a local UI nickname could differ from the on-wire address.
- **Production paths now key peers by handle**, not session name. `session pair-all-local`'s already-paired short-circuit, `drive_bilateral_pair`, and `cmd_session_mesh_status`'s probe all look peers up by their card handle. Local-sister pair-accept no longer flakes when a session's directory name differs from its character.
- **`Character::from_did` seeds from the 8-hex fingerprint suffix only.** Stops the circular dependency where handle change → DID change → character change → infinite loop. Legacy DIDs without `-<fp>` suffix fall back to the v0.10 seed-the-whole-DID behavior.

Migration: existing v0.10.x homes pick up the new character on next `wire init` only if you re-init. Already-initialized homes keep their on-disk handle; new pairings use the v0.11 rule for both sides.

## Status — v0.10.1

v0.10.1 closes the ergonomics pass with a doc-canonicalization sweep:

- **MCP canonical tools added.** `wire_dial`, `wire_accept`, `wire_reject`, `wire_pending` appear in `tools/list`. Legacy `wire_pair_accept` / `wire_pair_reject` / `wire_pair_list_inbound` stay callable as aliases (same handler), tagged DEPRECATED in their descriptions.
- **README + AGENT.md + landing rewritten** to lead with the v0.9+ canonical surface (`wire dial`, `wire send`, `wire pending`, `wire accept`, `wire reject`, `wire whois`, `wire here`). Stale references to `pair-host` / `pair-join` / `wire add @relay` / `wire invite` / `wire accept <URL>` either updated or moved into a "Legacy flows" section with v1.0-removal note.
- **MCP top-level `instructions` field** now lists canonical verbs first.
- **docs/AGENT_INTEGRATION.md** flow rewritten to use `wire_dial` + `wire_pending` + `wire_accept`.
- **`wire identity rename` hidden + truth-warning.** (v0.11 fully removed the verb.) Rename was made local-only in v0.9 (peers couldn't reach you by the renamed name), so v0.10.1 hid it from `--help` and printed the truth on every invocation.

## Status — v0.10.0

v0.10 wraps the ergonomics pass:

- **`Pair` megacommand hidden from `--help`.** Federation pair is now `wire dial <handle>@<relay>` + `wire accept-invite <URL>`. Old `wire pair` stays callable for back-compat scripts; v1.0 removes.
- **`wire send --no-auto-pair`** opts out of the v0.9 auto-pair-on-miss behavior. Strict scripts that don't want side-effecting implicit pairs.
- **`CHANGELOG.md`** generated from the v0.7.0+ tag history.

Pragmatic note: the v0.10 plan included full removal of the 11 deprecated pair-* verbs from dispatch. That broke the e2e_detached_pair / e2e_invite_pair / e2e_handle_pair test suites (which exercise the SPAKE2 flows). Rolled back to "hidden, deprecated, still callable" — same operator surface as v0.9.1 plus the Pair hide. True removal happens in v1.0 with a proper test migration pass.

## Status — v0.9.5

v0.9.5 adds discovery + onboarding ergonomics:

- **Shell completions.** `wire completions <shell>` emits the completion script for bash / zsh / fish / elvish / powershell. Pipe into your shell's completion dir; tab completion covers every verb, subcommand, and flag.
  ```
  wire completions bash > /etc/bash_completion.d/wire
  wire completions zsh  > ~/.zsh/completions/_wire
  wire completions fish > ~/.config/fish/completions/wire.fish
  ```
- **Interactive init prompt.** First-time `wire init <handle>` from an interactive TTY (no `--relay`, local relay not running) now asks: "Bind to public federation relay https://wireup.net instead? [Y/n/offline/url]". CI / agents / non-TTY shells still get the v0.9.1 explicit error wall (no hang risk). `WIRE_NO_INTERACTIVE=1` forces non-interactive everywhere.

## Status — v0.9.4

v0.9.4 splits `wire accept` into two unambiguous verbs:

- **`wire accept <name>`** — accept a pending pair request by character nickname or handle. Always.
- **`wire accept-invite <URL>`** — accept a federation invite URL minted by `wire invite`.

Pre-v0.9.4 `wire accept` smart-dispatched on input shape (URL-detection branched to invite-accept; everything else to pair-accept). Edge cases — peer handles that happened to look URL-shaped — were ambiguous. v0.9.4 makes the dispatch explicit: the verb you type maps directly to the action you want.

Back-compat: `wire accept wire://pair?...` still works (one release of grace) but emits a deprecation banner pointing at `wire accept-invite`. v1.0 will reject URLs at the `wire accept` parser.

**Note on federation phonebook:** `wire dial <nickname>@<relay>` (resolve a character nickname against a remote relay without knowing the handle) is still a server-side feature gap. Today operators need the handle for federation dial. Tracked for v0.10+ — requires relay protocol additions.

## Status — v0.9.3

v0.9.3 turns operator-facing surfaces conversational:

- **`wire here`** — one screen for "you are this session, your neighbors are these." Combines what `wire whoami` + `wire peers` + `wire session list-local` would otherwise force into three calls.
- **`wire pending` is prose, not a database table.** "🛡 noble-creek (bob) wants to pair with you." Tabular goes to `--json`.
- **Emoji fallback.** On terminals that can't render emoji (default `cmd.exe`, restricted locale, `WIRE_EMOJI=off`), wire substitutes ASCII tags (`[bear] cedar-bayou`) instead of showing broken-glyph squares.
- **Quick start rewritten** to lead with `wire init <handle>` (smart-default), `wire here`, `wire dial <name>`, `wire accept <name>` — the v0.9 canonical surface.

## Status — v0.9.2

v0.9.2 makes resolution failures helpful:

- **Did-you-mean on typos.** `wire whois nobl-slat` → "Did you mean: `noble-slate`?". Levenshtein distance ≤ 3 against the union of pinned-peer handles + character nicknames + sister sessions.
- **JSON-mode misses return success.** `wire whois nobl-slat --json` → `{found: false, candidates: ["noble-slate"], ...}` with exit 0. Agents stop wrapping resolution in try/catch.
- **Deprecation banner suppressed in JSON mode.** Operator/script using `--json` (or piped stdout) doesn't get the banner polluting captured output.
- **Deprecation banner once per shell session.** `WIRE_DEPRECATION_NAGGED_<verb>=1` (auto-set inside one process; export to suppress across a shell) prevents the same nag firing N times.

## Status — v0.9.1

v0.9.1 is the first of a six-batch ergonomics pass:

- **Deprecated verbs hidden from `wire --help`.** Still callable; don't clutter the canonical surface.
- **`wire init` smart-default.** Bare `wire init <handle>` auto-attaches to the local relay at 127.0.0.1:8771 if running. `--offline` opt-in for slotless, `--relay <url>` to override. No more first-time-rejection wall.
- **JSON when piped.** `wire whoami` / `peers` / `pending` / `accept` / `reject` / `dial` / `send` emit JSON automatically when stdout isn't a TTY (agents in CC's Bash tool stop having to type `--json`). `WIRE_NO_AUTO_JSON=1` opts out.
- **Quiet auto-detect.** The `wire cli: auto-detected session ...` stderr chatter only emits in interactive TTYs. `WIRE_VERBOSE=1` forces on, `WIRE_QUIET_AUTOSESSION=1` forces off.

## Status — v0.9.0

**Clean cut.** The five-name surface (DID, handle, session-name, character nickname, operator rename) collapses to one operator-facing name. The 12-verb pair cluster collapses to 3.

Operator-facing verbs after v0.9:

```bash
wire dial <name> [message]      # talk to peer (local sister, federation, anything)
wire send <name> "<msg>"        # talk (auto-pairs on miss)
wire pending                    # what's waiting for my consent
wire accept <name>              # consent to a pending pair (or paste an invite URL)
wire reject <name>              # refuse pending pair
wire whois <name>               # inspect identity
wire tail [<name>]              # listen
```

Six verbs. Old verbs (`pair-host`, `pair-join`, `pair-accept`, `pair-reject`, `pair-list-inbound`, `invite`, `accept <URL>`) still work but emit a deprecation banner pointing at the new ones. v1.0 removes them.

Structural fixes in v0.9:

- **`wire init` refuses to create slotless sessions.** Root cause of the 2026-05-23 silent-fail incident. Pre-v0.9 default was "init, then maybe bind-relay later" — a slotless session looked healthy but black-holed every inbound message. Now init demands `--relay <url>` OR `--offline` (explicit opt-in to the slotless state).
- **Single canonical `self_primary_endpoint()` reader everywhere.** Pull, rotate-slot, ack-send all route through the same fallback chain (legacy top-level fields → `self.endpoints[0]`). Removes the silent class where v0.5.17+ sessions returned empty strings for what should have been their first endpoint.
- **`wire send <name>` auto-pairs on miss.** If you try to send to an unpinned local sister, wire dials first. Phone semantics.
- **`wire dial <handle>@<relay>` routes through federation.** One verb across local + cross-machine; no more "this is the wrong orbit."
- **`wire identity rename` was local-display only.** (v0.11 removes the verb entirely — the character IS the canonical public name everywhere.)



v0.7.5 fixes the silent-fail pair handshake. Before: pair-accept on a session created with `--with-local` (only `self.endpoints[]` populated, no top-level legacy fields) errored with `self relay state incomplete; cannot emit pair_drop_ack`, leaving peers black-holed despite both sides showing `VERIFIED`. Fix: `send_pair_drop_ack` now reads `self.endpoints[0]` as a fallback. If both readers return empty, the error message names the exact remediation (`wire bind-relay ... --migrate-pinned`).

v0.7.4 lets you address a peer by **character nickname only**. `wire add noble-slate` resolves to whichever local sister session has that nickname (or matching session name, or card handle), then routes through the disk-read sister path automatically — no `@<relay>` suffix, no `--local-sister` flag, no remembering machine-internal names. Also widens `wire session pair-all-local` to include sessions whose federation slot lives on a loopback URL (effectively local-mesh-reachable), so nickname-based pairing isn't silently blocked by a missing `scope:local` tag.

v0.7.3 made `wire upgrade` thorough and cross-platform. Two changes:

1. **Cross-platform process management.** `wire upgrade` now sweeps `wire daemon` *and* `wire relay-server` processes (the old upgrade left stale relay-servers behind). Process liveness checks and kill signals route through a new `platform` module that works on Linux (`/proc` + `kill`), macOS (`kill -0` + `kill`), and Windows (`tasklist` + `taskkill /T`). Fixes the cosmetic `wire session list` "daemon: down" lie on Windows, plus the hard failure of `wire upgrade` on Windows pre-0.7.3.
2. **Service-unit refresh.** After killing stale processes, `wire upgrade` now reinstalls every service unit that was already installed (launchd plist / systemd unit / Windows scheduled task), rewriting it with the new binary's path before the OS auto-respawns. Pre-0.7.3 upgrades left units pointing at the old binary, so the next reboot would resurrect the old version.

v0.7.2 brought **Windows service support** to `wire service install`. The macOS launchd / Linux systemd path now has a Windows peer via Task Scheduler — `wire service install` and `wire service install --local-relay` register hidden, restart-on-failure, run-at-logon tasks under the current user (no elevation, no stored password). Closes the cross-platform parity gap that was forcing Windows operators to keep `wire relay-server` open in a manual terminal window.

v0.7.1 ships `wire session bind <name>` — attach an existing session to the current cwd without losing keypair/slot/daemon. Fixes the case where a registered ancestor dir (`~/Source`) shadows leaf-project identities, so two CC tabs in different projects end up wearing the same Character. ([PR #28](https://github.com/SlanchaAi/wire/pull/28))

v0.7.0 elevated **identity** to a first-class noun. Each wire session has a deterministic **Character** — emoji + adjective-noun nickname + 256-color palette — derived from its DID via SHA-256. Sessions are addressable by either session name OR character nickname: `wire add --local-sister winter-bay`; `wire send noble-canyon "hi"`. Agents can rename themselves: `wire identity rename --name foxtrot-meadow --emoji 🦊` (operator-chosen overrides publish on the agent-card so federated peers see what we call ourselves). Full identity lifecycle CLI: `wire identity create / persist / publish / demote / rename / show / list / destroy`. ([PR #26](https://github.com/SlanchaAi/wire/pull/26))

v0.7.0 also unified transport scopes. The new `EndpointScope` enum — Federation / Local / **LAN** / **UDS** — drives both pull cursors and push dispatch in priority order: UDS → Local-loopback → LAN → Federation. **LAN endpoints** (`wire session new --with-lan`) reach cross-machine sister sessions on the same network without round-tripping the public relay. **UDS endpoints** (`wire session new --with-uds`) give same-host sister sessions a Unix-socket path that bypasses the macOS firewall + Tailscale userspace-netstack class of issues entirely.

The v0.6 line shipped the orchestration layer over the v0.5 federated protocol (bilateral consent pair v0.5.14, per-session identities + local relay v0.5.16/17, persistent service install v0.5.22, MCP collision warning v0.6.10). `wire session pair-all-local` mesh-pairs every sister Claude on a machine in one command — same-uid trust anchor, idempotent, zero paste.

> **A2A v1.0 compat.** Wire handles serve `.well-known/agent-card.json` in the A2A v1.0 AgentCard schema — Microsoft Agent Framework, AWS, Salesforce, SAP, and ServiceNow A2A tooling can resolve wire handles without speaking any wire-specific protocol.

---

## Quick start — pair two agents by name (one command each)

Install (both operators, once):

```bash
curl -fsSL https://wireup.net/install.sh | sh
wire setup --apply    # merges wire into Claude Code / Cursor / project-local MCP configs
```

Restart your agent client after `wire setup --apply` so wire's MCP tools load.

**Both operators — claim an identity:**

```bash
$ wire init alice              # auto-attaches to local relay if running, else error with options
generated did:wire:alice-... (ed25519:alice:...)
bound to relay http://127.0.0.1:8771 (slot ...)
```

Or attach to a specific relay: `wire init alice --relay https://wireup.net` (federation), `wire init alice --offline` (keypair only).

**Pair, by the name you see:**

```bash
$ wire here                    # who am I, who's around?
you are 🐅 winter-bay  (alice)

$ wire dial bob                # auto-pairs if not yet
$ wire dial bob "hi from alice"  # auto-pair + send
```

Or, if the other side initiates first, accept their request by character nickname:

```bash
$ wire pending
2 pending pair requests:
  🛡 noble-creek  (bob)  wants to pair with you

→ to accept any: `wire accept <name>`  (e.g. `wire accept noble-creek`)
→ to refuse:    `wire reject <name>`

$ wire accept noble-creek
→ accepted pending pair from bob
→ pinned VERIFIED, slot_token recorded
→ shipped our slot_token back via pair_drop_ack
bilateral pair complete. Send with `wire send bob "..."`.
```

Either side can `wire dial <name>` first or `wire accept <name>` second — same outcome. **No URL to paste. No SAS digits. One command per side.**

The bilateral handshake is the consent gesture: a stranger can deposit one pair request in your `wire pending` list, but **never** auto-pin themselves into your trust ring or get write access to your inbox. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the threat model that drove the design.

Watch the [18-second asciinema cast](https://wireup.net/#demo-player) for the real flow against `wireup.net`.

### Trust model (one paragraph)

Knowing a handle (`alice@wireup.net`) and being able to resolve it to a signed agent-card is the authentication ceremony — same shape as discovering someone's Mastodon account via WebFinger or their PGP key via WKD. The card carries an Ed25519 verify-key, signed by that key, so the resolver knows the relay isn't lying about who claims the nick. FCFS on nicks; same-DID re-claims allowed. For threat models where the discovery channel itself can't be trusted (suspect DNS, distrustful operator), opt back into the SPAKE2 + SAS-code legacy ceremony — see [Alternative flows](#alternative-flows) below.

### Agent-driven (zero CLI)

Same flow via MCP — bilateral as of v0.5.14:

- Operator A's agent: `wire_init`, then `wire_claim` (auto-allocates relay slot if missing).
- Operator B's agent: `wire_add` with `alice@wireup.net` (sends the outbound pair_drop).
- Operator A's agent: notice the OS toast or call `wire_pair_list_inbound` on a session-start poll, surface the request to operator A, then call `wire_pair_accept` (or `wire_pair_reject` to refuse).

Both sides need their `wire daemon` running so the bilateral pin completes in the background. Already running if you went through `wire setup --apply`.

**Agents must never auto-accept inbound pair requests.** Acceptance grants the peer authenticated write access to the agent's inbox; the operator must approve. The MCP server's `instructions` field reminds agents of this on every connect; `docs/AGENT_INTEGRATION.md` has the recipe.

---

## Alternative flows

Two older flows are still supported for the trust models that want them. They're not the default but they're not going away.

### Paste-URL (v0.4 — one paste, one-time bearer)

Mint a short-TTL signed URL (via the hidden `wire pair-host --invite` or by emitting a URL however your harness prefers). The receiver runs `wire accept-invite '<url>'` (v0.9.4 split this verb out so it's unambiguous from `wire accept <name>`). Useful when the recipient can't yet host a relay slot. Bearer-token-equivalent — possession of the URL = authorization to pair.

### SPAKE2 + SAS (v0.3 — code phrase + matching digits)

The legacy `wire pair --code <code>` flow is still callable for back-compat (hidden from `--help` since v0.10). Both sides see matching SAS digits and confirm out-of-band. Right call when the discovery channel itself can't be trusted (suspect DNS, distrustful operator). v1.0 removes; for active use prefer `wire dial <handle>@<relay>` + `wire accept-invite <URL>`.

Both flows live in `wire help`; the design contracts are in [docs/](docs/).

---

## What's in the box

- `wire init <handle> --relay <url>` — generates Ed25519 keypair, allocates a mailbox slot at the named relay (`wireup.net` is the public-good default)
- `wire claim <nick>` — claims `<nick>@<relay-domain>` in the relay's handle directory, FCFS
- `wire up <nick>@<relay>` — one-shot bootstrap (v0.12): init + bind federation relay + claim + opportunistic local dual-bind + background daemon. The fastest fresh-box-to-ready path. `--with-local <url>` overrides the default `127.0.0.1:8771` local probe; `--no-local` skips it.
- `wire bind-relay <url>` — bind a relay slot. **Additive by default** (v0.12): appends to `self.endpoints[]` so you hold a local relay AND a federation relay at once without black-holing pinned peers. `--scope <federation|local|lan|uds>` (inferred from the URL otherwise); `--replace` for the old destructive single-slot behavior.
- `wire dial <name> [message]` — establish a connection by character nickname / handle / DID. Auto-pairs local sisters via disk-read sister card; routes federation handles (`<handle>@<relay>`) through `.well-known/wire/agent`. Optional first message after pair.
- `wire send <name> "<msg>"` — talk on an established line. Auto-pairs on miss for local sisters (suppress with `--no-auto-pair`).
- `wire accept <peer>` — accept an inbound pair request from `wire pending`.
- `wire accept-invite <URL>` — accept a federation invite URL minted by another agent.
- `wire reject <peer>` — refuse an inbound pair request.
- `wire pending` — view pending-inbound pair requests (prose by default, `--json` for tables).
- `wire session new|list|env|current|bind|destroy` — manage isolated sessions on one machine (v0.5.16+). Each session = own identity + slot + daemon. Use when multiple agents run on the same box (e.g. Claude Code in different projects); otherwise they share one inbox and race the cursor. `wire session bind <name>` (v0.7.1) attaches an existing session to the current cwd when an ancestor's binding is shadowing it. See [the multi-session recipe](docs/AGENT_INTEGRATION.md#multi-session-on-one-machine-v0516).
- `wire identity create|persist|publish|demote|show|list|destroy` — lifecycle for the per-session **Character** (v0.7.0). Each session's emoji + nickname + color palette is deterministic from its DID. (v0.11: `rename` removed — the character IS the addressable name; to change face, regenerate identity.)
- `wire session new --with-lan` / `--with-uds` — allocate LAN-reachable or Unix-socket transport slots in addition to federation (v0.7.0). Push dispatch walks endpoints in priority order (UDS → Local → LAN → Federation), so within-host sister traffic prefers the cheapest viable path automatically.
- `wire relay-server --bind 127.0.0.1:8771 --local-only` + `wire session new --with-local` — dual-slot sessions (v0.5.17). Within-machine sister-agent traffic prefers a loopback relay (~sub-millisecond, zero metadata exposure, works offline); federation through `wireup.net` keeps working for cross-box traffic. Pure additive — `--with-local` is opt-in, federation behavior unchanged when not used.
- `wire session list-local` + `wire session pair-all-local` — **orchestration layer (v0.6.1)**. Discover every sister session on this box that has a local-relay endpoint, then mesh-pair them all in one command. Trust anchor: same-uid filesystem permission (the operator owns every session listed). Idempotent — re-running skips pairs already pinned. The entry point for the v0.6 control-plane primitives (`mesh status`, `mesh broadcast`, etc.) that follow.
- `wire send <peer> <kind> <body>` — appends a signed JSONL event to the peer's outbound mailbox
- `wire tail [<peer>]` — streams signed events from peers, sig-verifies each
- `wire daemon` — long-lived sync loop (push outbox + pull inbox + complete bilateral pairs)
- `wire relay-server` — self-host the mailbox relay binary (AGPL; serves the landing page + protocol endpoints + `/stats` from a single Rust binary, no extras to wire up)
- `wire mcp` — MCP server over stdio so Claude Code / Cursor / Claude Desktop see `wire_send`, `wire_tail`, `wire_add` etc. as native tools
- **Legacy flows** (hidden from `--help`, still callable, v1.0 removes): `wire pair-host` / `wire pair-join` (SPAKE2 + SAS, v0.3), `wire invite` + `wire accept-invite` (paste-URL, v0.4), `wire pair-accept` / `wire pair-reject` / `wire pair-list-inbound` (replaced by `wire accept` / `wire reject` / `wire pending` in v0.9).

---

## What's NOT in the box (and won't be)

See [ANTI_FEATURES.md](ANTI_FEATURES.md) for the full list.

The short version: no SaaS dependency, no OAuth, no central trust authority, no crypto tokens, no closed-source server, no vendor-cloud lock-in, no "agent platform" positioning, no compliance theater.

---

## Sending files

v0.1 events have a 256 KiB body cap on the relay. Wire is a coordination layer, not a file transfer layer — pass signed pointers, not bulk bytes:

```bash
# Sender side — upload to whatever storage you trust:
#   S3, Backblaze B2, Cloudflare R2, IPFS, raspi+nginx, friend's web server, Discord/Drive link.
$ HASH=$(sha256sum bigfile.tar.zst | awk '{print $1}')
$ aws s3 cp bigfile.tar.zst s3://my-bucket/share/abc123.tar.zst   # or whatever upload tool

$ wire send willard file_pointer "$(jq -nc \
    --arg url "https://my-bucket.s3.amazonaws.com/share/abc123.tar.zst" \
    --arg sha256 "$HASH" \
    --arg size 524288000 \
    --arg name bigfile.tar.zst \
    '{url:$url, sha256:$sha256, size:($size|tonumber), name:$name}')"
```

```bash
# Recipient side
$ wire tail willard
[2026-05-10T... willard kind=1 file_pointer]
  {"url":"https://...", "sha256":"a3c9...", "size": 524288000, "name":"bigfile.tar.zst"}
  sig verified ✓

$ curl -fsSL "<url-from-event>" -o bigfile.tar.zst
$ echo "<sha256-from-event>  bigfile.tar.zst" | sha256sum -c   # MUST match
```

This is the same pattern Slack, Signal, and iMessage use under the hood (CDN-backed attachments + signed pointers). Wire just doesn't bundle the CDN piece in v0.1.

**Why we punted:** wire is coordination infrastructure. Bundling file transfer = scope creep. The signed pointer is enough — recipient verifies the hash, gets cryptographic guarantee the bytes are what the sender sent. Magic-wormhole already nails ad-hoc human file transfer; rolling our own is duplicate work.

**v0.2 candidate (BACKLOG'd):** native `wire send-file <peer> <path>` that chunks, content-addresses, AEAD-encrypts under pairing-derived keys, streams through the same relay. ~400 LOC. Reuses pairing trust so no second handshake. Lands when real demand surfaces.

---

## Agent integration (read this if you're an AI agent)

`wire` is built to be picked up natively by any AI agent — Claude, GPT-4, local Llama, sandboxed evals — without bespoke glue. Three discovery paths:

### Path 1 — MCP server (recommended)

Add to your MCP config (`~/.config/claude/mcp.json` for Claude Desktop / Code; equivalent for Cursor / Cline / Zed):

```json
{
  "mcpServers": {
    "wire": {"command": "wire", "args": ["mcp"]}
  }
}
```

After restart you have these tools natively:

| Tool | Purpose |
|---|---|
| `wire_whoami`, `wire_peers`, `wire_send`, `wire_tail`, `wire_verify` | Identity + messaging (always agent-safe) |
| `wire_init` | Idempotent identity creation; same handle = no-op, different handle = error |
| `wire_pair_initiate`, `wire_pair_join`, `wire_pair_check`, `wire_pair_confirm` | Agent drives the full SAS pair flow; the user types the **6 SAS digits back into chat** as the trust gate |

Plus MCP resources: `wire://inbox/<peer>` and `wire://inbox/all` expose each pinned peer's verified inbox as `application/x-ndjson` for agents that want inbox context without polling `wire_tail`.

**Why pairing is now agent-callable:** the user-typed-digit gate replaces the "MCP refuses pair entirely" boundary from v0.1. `wire_pair_confirm(session_id, user_typed_digits)` validates the 6 SAS digits server-side; mismatch aborts permanently. A malicious agent that fabricates SAS in chat fails because the user reads their peer's independently-derived SAS over a side channel and compares. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) T10/T14.

### Path 1b — OpenClaw plugin

If your agent runs on [OpenClaw](https://openclaw.ai) (100k★ self-hosted personal-agent gateway with 20+ channels), the [`@slancha/openclaw-channel-wire`](https://github.com/slancha/openclaw-channel-wire) plugin adds wire as channel #21 — the one that doesn't route through Apple, Meta, Telegram, or Discord. Same pattern available for claude-flow, langgraph, crewai, autogen, smol-agents (BACKLOG'd, build when traction surfaces).

### Path 2 — CLI with `--json` everywhere

Every command emits structured output on demand:

```bash
$ wire whoami --json
{"did":"did:wire:paul","handle":"paul","fingerprint":"b2e5aae7","capabilities":["wire/v3.1"]}

$ wire send willard decision "ship the v0.1 demo" --json
{"event_id":"7cf276dc...","status":"queued","peer":"willard","outbox":"..."}
```

### Path 3 — File-system contract (sandboxed agents)

Agents that can't spawn processes still participate by reading `~/.local/state/wire/inbox/<peer>.jsonl` and appending to `outbox/<peer>.jsonl`. A daemon (lands iter 6+) signs and flushes.

See [docs/AGENT_INTEGRATION.md](docs/AGENT_INTEGRATION.md) for the full contract: capability negotiation, idempotent retry semantics, and the human/agent boundary.

---

## N-agent coordination

Mesh-of-bilateral. SyncThing model. Each pair is its own wire; group emerges from N pairs. Pairing with N peers concurrently via MCP is first-class — `wire dial` against each peer is independently locked, and `wire_send`/`wire_tail` are safe under concurrent multi-peer use.

```bash
# carol pairs with both paul and willard
$ wire dial paul@wireup.net
$ wire dial willard@wireup.net
$ wire tail
# carol now sees signed events from both peers
```

Agent-driven equivalent (one agent, two parallel pair flows):

```
agent: I want to pair with paul AND willard.
  → wire_pair_initiate → session_id_paul + code_phrase_paul
  → wire_pair_initiate → session_id_willard + code_phrase_willard
  (both stored in MCP server's session store, distinct pair_ids at relay)
user: shares each code phrase out-of-band with the right peer.
peers join via wire_pair_join; both reach sas_ready.
agent: reads both SAS pairs back to user, user types each back.
  → wire_pair_confirm(session_id_paul, digits_paul) → trust-pinned
  → wire_pair_confirm(session_id_willard, digits_willard) → trust-pinned
```

Native group rooms (member-set consensus + cross-member read-receipts) are explicitly NOT on the roadmap — mesh-of-bilateral is the point. SyncThing has 73k stars on mesh-of-bilateral alone and never needed group rooms.

---

## Comparable projects

This is the OSS tribe we live in:

- [magic-wormhole](https://magic-wormhole.readthedocs.io/) — SAS-pairing for file transfer. The UX template.
- [atuin](https://atuin.sh/) — Ed25519-signed shell history sync. Closest crypto sibling.
- [syncthing](https://syncthing.net/) — decentralized file sync, single binary, no central server.
- [headscale](https://headscale.net/) — self-host alternative to Tailscale's control plane.
- [mcp_agent_mail](https://github.com/Dicklesworthstone/mcp_agent_mail) — git+Ed25519 agent coordination. Spiritual predecessor.
- [claude-flow](https://github.com/ruvnet/claude-flow) — independently shipped Ed25519+mTLS+HMAC federation. Validates the primitive choice.
- [Egregore](https://github.com/egregore-labs/egregore) — the "two friends building dynamic ontology" pattern. We fill the identity-layer gap.

If those make sense, we probably do too.

---

## Install

**v0.6.1 — shipped.** Three paths:

```bash
# 1. install.sh — pre-built binaries (Linux x86_64/aarch64 gnu+musl, macOS aarch64, Windows x86_64)
curl -fsSL https://raw.githubusercontent.com/SlanchaAi/wire/main/install.sh | sh

# 2. crates.io (package name `slancha-wire`; the `wire` binary name is squatted by an
#    unrelated abandoned 2014 crate). Installs a `wire` executable to $CARGO_HOME/bin.
cargo install slancha-wire

# 3. from source
git clone https://github.com/SlanchaAi/wire
cd wire
cargo build --release
cargo test                  # 190 tests, ~30s
```

Requires Rust 1.88+ (edition 2024) for source / cargo-install builds. Install Rust via [rustup](https://rustup.rs).

After install:

```bash
wire init <nick>             # smart-default: auto-attaches to local relay if running
wire here                    # who am I, who's around?
wire dial <peer>@wireup.net  # establish a connection (federation), optional message
wire send <peer> "hi"        # talk on an established line; auto-pairs on miss
wire pending                 # what's waiting for my consent
wire monitor                 # live tail of inbox events
wire doctor                  # single-command health check
wire upgrade                 # atomic stale-daemon swap on version bump
```

### Running 2+ agents on one machine? (within-system mesh)

You have two pairing modes. Pick the one that matches your situation:

| | **Within-system mesh** | **Cross-system federation** |
|--|--|--|
| Peers on | Same machine, same OS user | Different machines (or different users) |
| Trust | Filesystem permission (you own both sides) | SAS digits OR invite URL paste |
| Infrastructure | Local relay on `127.0.0.1:8771` | Public relay (`wireup.net`) |
| Setup | `--local-only` sessions + `pair-all-local` | `wire dial <handle>@<relay>` per peer |

For the **within-system** case (2+ Claudes/Cursors on one laptop), the recipe is one-time and zero-paste:

```bash
# 1. One-time, machine-wide: bring up the local relay as a service
wire service install --local-relay

# 2. Per-project, in each cwd: federation-free session
cd ~/code/project-a && wire session new --local-only
cd ~/code/project-b && wire session new --local-only

# 3. Once per box (or any time a new session joins): bilaterally pair all sisters
wire session pair-all-local
```

**`--local-only` (v0.6.6)** skips the federation slot allocation and the nick-claim against `wireup.net` entirely. The session exists only to talk to sister sessions on the same box. Reserved nicks (`wire`, `slancha`, …) are allowed because nothing tries to publish them publicly. Pair-all-local uses `--local-sister` (v0.6.6) internally — direct disk read of the sister's card + endpoints, no `.well-known/wire/agent` round-trip.

**v0.6.1: MCP auto-detect.** When `wire mcp` starts up, it reads `$PWD`, looks up the session registry, and auto-adopts the matching session's WIRE_HOME. Claude Code, Cursor, and any other MCP host that sets `$PWD` to the project root at server-spawn time gets the right per-project identity automatically. Verify with `wire session current` + `wire whoami`.

**Once paired**, the v0.6 mesh primitives work:
```bash
wire mesh status                              # who's paired, who's silent, per-edge health
wire mesh broadcast "rebuilding the index"    # fan one event to every sister
wire mesh role set reviewer                   # tag this session
wire mesh route reviewer "PR ready"           # route by role, no hard-coded handles
```

**If your MCP host doesn't set $PWD** (rare), fall back to the explicit env override:
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

For the **cross-system** case, see [`AGENTS.md`](AGENTS.md) §1 (federation — invite URL flow + SAS-digit fallback). Federation pairing still needs a per-peer ceremony — that's by design, since you can't lean on filesystem permission across machines.

Skip both sections if you only run a single Claude on the box. One default identity (no session) handles it.

---

## License

- **Server** (`wire-relay-server`) — AGPL-3.0 (forks that host as SaaS must share back)
- **Spec** (`docs/PROTOCOL.md`, the protocol surface in `src/signing.rs`, `src/agent_card.rs`) — Apache-2.0 (max interop adoption)
- **Client** (`wire` CLI) — MIT (max embedding adoption)

Same model as [atuin](https://atuin.sh/) (closed Hub + MIT CLI), except our server is AGPL not closed.

See [LICENSE.md](LICENSE.md) for the trio explanation.

---

## Contributing

v0.1 is solo-maintained pre-launch. Contributions welcome once public launch lands.
