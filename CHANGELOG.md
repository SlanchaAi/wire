# Changelog

All notable changes since `wire` went open-source.

## v0.6 — orchestration layer

The v0.5 line shipped the protocol: bilateral signed-message bus, federated handle directory, per-session identity, dual-slot routing, persistent local-relay transport. v0.6 builds the **control plane** on top of that protocol — the primitives that let an operator manage an N-agent mesh rather than wiring pairs one at a time.

The first orchestration primitive is `wire session pair-all-local`: zero-paste bilateral pairing across every sister session on a machine. The trust anchor shifts from "operator types SAS digits on each side" (a network-level proof appropriate for strangers) to "operator owns every session listed in `wire session list-local`" (a filesystem-permission proof appropriate for same-uid siblings). That re-anchoring is what makes mesh-scale auto-pairing safe to ship at all — same-uid siblings are by definition not strangers.

## v0.7 — identity-first

The v0.6 line landed the control plane (orchestration primitives over the bilateral protocol). v0.7 elevates **identity** to a first-class noun. After 4 rounds of persona critique ([issue #24](https://github.com/SlanchaAi/wire/issues/24)) and a 13-system survey of the wider ecosystem ([issue #25](https://github.com/SlanchaAi/wire/issues/25)), the locked direction is: identity is the noun, transport is the verb, mesh is the application. v0.6's `session` abstraction was conflating five concerns; v0.7 untangles them with a clear three-state identity lifecycle (anonymous / local / federation) and a path to operator-friendly cross-machine portability.

### v0.7.0-alpha.9 — LAN relay endpoints (third transport scope)

Use case: `🐅 noble-creek` on paul-mac wants to talk to `🌱 running-light` on spark over Wi-Fi without round-tripping the public federation relay at https://wireup.net. v0.5.17 added a binary scope (Local loopback only, or Federation public) — now there's a third scope, **Lan**, for cross-machine peers on the same network.

**EndpointScope::Lan** sits between Local and Federation in routing priority:
- `Local` (loopback) — sub-millisecond, same-machine sister sessions only
- `Lan` — same-network across machines, sub-10ms
- `Federation` — anywhere, ~50–300ms via wireup.net

Routing is automatic: when both peers advertise compatible scopes, the daemon prefers the lowest-latency path that's reachable. Lan endpoints are kept in routing without an "our_local matches" gate (cross-machine peers won't have matching loopback URLs by definition).

**CLI surface (opt-in per session):**
```bash
# on paul-mac (LAN IP 192.168.1.50):
wire relay-server --bind 192.168.1.50:8771 --local-only &
wire session new --with-local --with-lan --lan-relay http://192.168.1.50:8771

# on spark (LAN IP 192.168.1.42):
wire relay-server --bind 192.168.1.42:8771 --local-only &
wire session new --with-local --with-lan --lan-relay http://192.168.1.42:8771

# pair as normal — federation resolves the handles, then traffic prefers Lan
wire add running-light@spark.local
```

LAN endpoints are published in `agent-card.endpoints[]` and visible to anyone who fetches `.well-known/wire/agent` — opt-in via explicit `--with-lan` flag because the LAN IP gets seen by anyone who has your handle. (Slot tokens are still the auth boundary, so a random LAN scanner can't deliver events.)

**What's NOT in this alpha (logged for follow-up):**
- mDNS / Bonjour discovery — operator types the LAN URL today
- LAN-IP auto-detect — operator types the address
- Roaming heartbeat — on LAN-IP change (coffee shop migration), today: re-run `wire session new --with-lan --lan-relay <new-url>`. v2 will add `wire session refresh-lan`
- LAN-only mode (no federation) — today federation handle resolution is still required for pairing

**Identity continuity across the three scopes**: same DID + keypair + character across Local, Lan, Federation endpoints — adding/removing an endpoint never changes the DID, so `🐅 winter-bay` stays `🐅 winter-bay` whether reachable via loopback, LAN, or wireup.net. The Character is DID-derived, so endpoint changes are display-invariant. v0.7 identity-first vision delivered.

### v0.7.0-alpha.4 — wider character variety (9.4× combo space)

Stress testing surfaced a 5.24% nickname-emoji-triple collision rate at 100k samples (alpha.1 word lists: 120 adj × 120 noun × 64 emoji = 921k combos). The numbers were fine for practical multi-Claude usage (~0.04% at 20 sessions per host) but the cap felt small.

Expanded the curated lists:
- **adjectives:** 120 → 243 (textures, moods, light, weather)
- **nouns:** 120 → 242 (more flora, fauna, landscape, weather, light)
- **emojis:** 64 → 147 (mammals, birds, reptiles, sea life, bugs, fruits, plants, music, abstract — still single-codepoint terminal-stable, no flags / ZWJ / skin tones)
- **combo space:** 921k → 8.64M (9.4×)
- **collision rate at 100k:** 5.24% → 0.59%
- **birthday-50%:** 1,132 DIDs → 3,469 DIDs

**Behavior change to flag:** characters are still deterministic per DID, but the *function from DID to character changed* because list lengths shifted. Existing identities now render different characters than they did under alpha.1-.3. On the developer's laptop the migration looked like: `🐅 winter-bay → 🛡 noble-creek`, `🌻 noble-canyon → 🪐 pewter-ocean`, etc.

If you want to keep the alpha.1 characters for sessions that already exist, write `display.json` overrides pinning their old nickname + emoji before upgrading. New sessions automatically use the wider lists.

### v0.7.0-alpha.2 — characters that actually identify (parent-walk + auto-init + nickname resolver)

alpha.1 shipped the character primitive but left three holes that defeated the whole "every Claude session looks different" point:

1. **Subdir cwd auto-detect didn't walk up parents.** `~/Source/slancha-business/tools/recon` fell through to the machine-wide default identity instead of inheriting `slancha-business`. So multiple Claude tabs in subdirs of registered cwds all collapsed onto the same default character.
2. **No auto-init for unwired cwds.** Open Claude in a fresh project (`~/Source/slancha-api` with no prior `wire session new`) → MCP auto-detect failed → fallback to the machine-wide default identity. Every unwired cwd showed the same default character.
3. **Characters weren't addressable.** `wire add --local-sister <session-name>` worked, but `wire add --local-sister <nickname>` didn't. Defeated the "they find each other by name" promise.

This alpha fixes all three. Combined, every Claude tab in any cwd gets a real unique wire identity at startup, with a sticky character, addressable by either session name or nickname.

**Fix 1 — parent-walk in `detect_session_wire_home`** (`src/session.rs`). The cwd auto-detect now walks up parent directories looking for any registered session. First match wins. Subdirs of a registered cwd inherit their parent's identity. Defensive against pathological registry states (broken session_dir paths) — falls through to the next parent.

**Fix 2 — auto-init per cwd on `wire mcp` startup** (`src/cli.rs::maybe_auto_init_cwd_session`, called from `src/mcp.rs::run`). When `wire mcp` starts in a cwd that has no registered session (after parent-walk), it idempotently creates one:
- Session name: `sanitize(basename(cwd))` with the existing path-hash collision suffix
- Spawns `wire init <name>` in the new session's `WIRE_HOME` (identity + keypair + agent-card)
- Best-effort `try_allocate_local_slot` against `http://127.0.0.1:8771` so the new session is reachable by sister sessions when the local relay is running
- Registers `cwd → name` so subsequent invocations short-circuit via parent-walk
- Sets `WIRE_HOME` for the current process

Opt-out: `WIRE_AUTO_INIT=0` in env. `run_wire_with_home` automatically sets this in spawned subprocesses to prevent recursive init.

This is the MCP-startup-only path. CLI invocations (`wire whoami` etc.) do NOT auto-init — they just adopt whatever session exists. The asymmetry is intentional: MCP is the persistent agent surface and represents the operator's intent to use wire in this cwd; CLI is incidental.

**Fix 3 — nickname-as-handle resolver** (`src/cli.rs::resolve_local_session` + `::resolve_peer_handle`). Two new resolvers:
- `resolve_local_session(sessions, input)` — input matches a `SessionInfo` by either `.name` (exact) or `.character.nickname`. Used by `wire add --local-sister`.
- `resolve_peer_handle(input)` — input matches a pinned peer in trust state by either canonical handle (exact) or character nickname (derived from peer's DID). Used by `wire send`.

Both surface the resolution to stderr when nickname matched (not exact name), so operators see the indirection.

`wire peers` now shows each peer's character (emoji + nickname colored) as the leading column. Same shape as `wire session list` from alpha.1. The peer's character is derived from their DID locally — no agent-card change required, peers don't need to ship characters to each other (yet — that lands when federation lifecycle materializes in v0.7.0 proper).

**End-to-end demo on the developer's laptop after alpha.2 install:**

```
$ cd ~/Source/slancha-api  # never had a wire session
$ wire mcp                  # auto-creates `slancha-api` session, allocates local slot
wire mcp: auto-init: created session `slancha-api` for cwd ... → WIRE_HOME=...
wire session new: local slot allocated on http://127.0.0.1:8771 (slot_id=...)

$ wire whoami --short
🌊 quiet-leaf

$ wire add --local-sister winter-bay   # nickname, not session name
wire add: resolved nickname `winter-bay` → session `wire`
→ pinned peer locally → pair_drop delivered...

$ wire peers
🌻 noble-canyon          slancha-business    VERIFIED
🐅 winter-bay            wire                VERIFIED
```

Five sessions on the machine, five unique characters, all reachable via local relay, all addressable by either session name or character nickname.

### v0.7.0-alpha.1 — character: nickname + emoji + color per identity

Every wire identity now has a **character** — a deterministic nickname (adjective-noun), emoji, and color palette derived from the agent's DID via SHA-256. Same DID → same character forever, across restarts, machine migration, and process boundaries. The character is the human-facing handle the operator sees in terminals; the DID is what peers see on the wire. Display-layer only — protocol semantics are untouched.

Why ship this first: with multiple Claude Code sessions on one machine, visual disambiguation was the immediate operator pain. v0.6.10's collision warning made the problem honest; v0.7.0 gives operators a name and a color so they can tell `🐅 winter-bay` apart from `🌻 noble-canyon` at a glance.

**New CLI surface:**
```
wire whoami --short      # 🐅 winter-bay (plain text)
wire whoami --colored    # 🐅 winter-bay with ANSI 256-color escapes (for statuslines)
wire whoami --json       # existing JSON output, plus `.character` field
wire whoami              # default text output, now prepends colored character

wire session list        # adds CHARACTER column showing every session's emoji+nickname colored
```

**New statusline integration:** drop `wire whoami --colored` into `~/.claude/settings.json`'s `statusLine.command` field for live identity display in the Claude Code TUI. See `docs/STATUSLINE.md` for the integration recipe plus a tmux pane-border tinting example.

**Character generation.** ~120 curated adjectives × 120 curated nouns (~14,400 combinations), 64 single-codepoint terminal-stable emojis, HSL hash → hex + ANSI 256 with saturation 0.55-0.80 and lightness 0.50-0.65 (terminal-readable on both light and dark backgrounds). All deterministic, all derived at read time — wire never persists characters to disk, so future word-list / palette tweaks affect new identities without re-keying old ones.

**Field naming: `persona` not `soul`.** Per the 13-system survey ([issue #25](https://github.com/SlanchaAi/wire/issues/25)), Letta uses `persona` as its canonical block label — the unbranded baseline term. `soul` is branded to specific harnesses (OpenClaw, Hermes-Agent, SoulSpec). Future `Identity` fields landing in v0.7.0 proper (`persona_url`, `persona_sha256`, `persona_spec`, `persona_slot`) will follow this convention.

**What this alpha does NOT ship** (deferred to v0.7.0 proper):
- `persona_url` / `persona_sha256` / `persona_spec` / `persona_slot` fields on Identity. Schema-only additions; UX wires up in v0.7.2 with `WIRE_AS=<tag>` and `wire launch --as <tag>`.
- `wire identity` CLI subcommand. Today characters are read via `wire whoami` / `wire session list`. v0.7.0 proper adds `wire identity list / show / rename / persist / publish`.
- `wire identity rename --random` / `--name <name>` / `--emoji <e>` overrides. The auto-generated character is sticky for now — re-rolling will land alongside the identity CLI.
- Federation lifecycle (anonymous / local / federation states). v0.6.x sessions auto-map to local identities; lifecycle states materialize when the identity CLI lands.

Cargo.toml stays at `0.6.10` in this alpha — bump to `0.7.0` lands when the full identity CLI and lifecycle are ready. Operators tracking `main` get the character UX immediately; the formal v0.7.0 release ships once the full identity layer is in.

### v0.6.10 — MCP identity-collision warning (visibility, not auto-magic)

After four rounds of persona critique on how to fix the multi-agent-same-cwd UX (recap in [issue #24](https://github.com/SlanchaAi/wire/issues/24)), the smallest right intervention turned out to be: **make the collision visible**. Don't try to auto-disambiguate via terminal env vars, wrapper scripts, or per-host adapter chains. Just print a clear stderr warning when two `wire mcp` processes share an effective `WIRE_HOME`, telling the operator exactly how to opt into a separate identity.

```
wire mcp: WARNING — 1 other wire mcp process(es) already using WIRE_HOME=`/Users/.../sessions/dogfood-b` (pid 12345)
  Multiple agents sharing one identity will race the inbox cursor; messages may be lost.
  To use a separate identity:
    1. Close the other agent(s), OR
    2. `wire session new <name> --local-only` to create a fresh identity, then
    3. Restart THIS agent's launcher with `export WIRE_HOME=<path printed by step 2>`
```

**Implementation.** `crate::session::warn_on_identity_collision(self_pid)` — pgrep for other `wire mcp` PIDs, read each one's `WIRE_HOME` env via `/proc/<pid>/environ` (Linux) or `ps -E -p <pid>` (macOS). If any matches ours, print the warning. Best-effort: any subprocess/env-read failure is silent (collision check must never block startup). Windows no-ops (no collision detection; non-blocking).

**What this is NOT.** This is NOT auto-disambiguation. The operator still gets a single shared identity per cwd unless they explicitly opt out via `WIRE_HOME` export. The warning makes the limitation honest — operators who hit it see exactly what's happening and how to fix it. v0.6.7's auto-detect behavior is unchanged.

**What v0.6.10 deliberately does NOT ship** (deferred to v0.7+ per [#24](https://github.com/SlanchaAi/wire/issues/24)):
- `wire upgrade also kills wire mcp` — useful patch, but deferred; today's `wire upgrade` already handles the daemon side, and the MCP side is operator-driven (Claude Code respawns on next call).
- TERM_SESSION_ID-based auto-discriminator — too clever, terminal env vars are fragile across Linux / IDE / tmux.
- Per-host wrapper script — not harness-agnostic; replaced by future `WIRE_AS=<tag>` env + `wire launch --as <tag> -- <command>` in v0.7.2.
- Three-layer wire-identity / wire-local / wire-federation split — see [#24](https://github.com/SlanchaAi/wire/issues/24) for the locked direction.

**Long-term direction** (LOCKED in [#24](https://github.com/SlanchaAi/wire/issues/24), not scheduled): identity-first architecture. Identity (anonymous → local → federation lifecycle) is the noun; UDS + HTTP-relay are the two bounded transports; mesh primitives stay transport-agnostic. Harness-agnostic by construction (`WIRE_AS` env + `wire launch` wrapper, works for Claude Code / Cursor / Continue / Aider / any MCP host). Migration in 5 phases over 3-4 weeks; each phase independently useful.

### v0.6.9 — fix v0.6.8 session-daemon respawn (caught live, ~5 min in)

Caught by deploying v0.6.8 on this laptop ~5 min after publish. The session-daemon respawn loop checked `s.daemon_running` AFTER step 3's pgrep+SIGTERM had already killed every wire daemon (default home AND all sessions share the `wire daemon` command line, so pgrep matches all of them). Result: `daemon_running` was always false at the respawn-decision site, and zero session daemons got respawned. The default-home daemon was reborn correctly, but session daemons stayed dead.

On the test machine: `wire` session bounced (because `wire upgrade` was auto-detected into the wire session via v0.6.7, so the default-home respawn IS the session respawn for whichever session is auto-detected), `slancha-business` stayed down. Operator inboxes go silent until they re-run `wire session new` from each cwd.

Fix: snapshot which sessions had a running daemon BEFORE step 3's kill, use that list at the respawn site. Verified on this laptop — `slancha-business` now respawns correctly after `wire upgrade`.

Tiny patch, ships immediately so v0.6.8 stays usable for any operator who's already pulled it.

Ship-deploy-find-bug-reship discipline pays again: v0.6.8 looked good in tests (which spin sessions but don't exercise the upgrade flow), would have broken silently for every operator who ran `wire upgrade` from a sister-Claude box. Caught in the v0.6.8 self-install validation, fixed in v0.6.9, total turnaround ~10 min.

### v0.6.8 — stale cleanup on upgrade + crates.io publish wired into release pipeline

Infra release. Three load-bearing fixes ship together because they're tangled — each one explained the "I updated but it's still broken" reports operators were filing.

**1. `wire upgrade` now sweeps every session, not just the default home.** Pre-v0.6.8 `wire upgrade` killed only the daemon owning the default `WIRE_HOME`. Session daemons (one per `wire session new`, often one per project) kept running the OLD binary text in memory, racing the new daemon and the new pidfile contracts. Operators saw "I updated but the new behavior isn't there" because the old daemon was still answering. v0.6.8:

- Kills the default-home daemon (existing v0.5.11 behavior).
- Enumerates every session via `crate::session::list_sessions()`; for each session that had a running daemon, wipes its pidfile and respawns it under the new binary via `ensure_session_daemon`.
- Detects when `$PATH` contains multiple distinct `wire` binaries (e.g. `/usr/local/bin/wire` AND `~/.local/bin/wire`) and surfaces a warning — that PATH-shadow class of bug accounts for most "I ran install.sh but the version didn't change" reports.

`wire upgrade --check` reports all of this in JSON or text without making any changes, so operators can preview what the upgrade would touch.

**2. `install.sh` now runs `wire upgrade` automatically.** Right after the binary is moved into place, install.sh calls `wire upgrade --check` to confirm the new binary supports the cleanup pass, then runs `wire upgrade` to:
- Kill stale daemons from the old binary (which may still be running because `mv` doesn't touch their process memory),
- Wipe stale pidfiles,
- Respawn session daemons under the new binary.

Best-effort: if the new binary somehow doesn't support `upgrade` (downgrade install, partial replacement) the install script just skips the cleanup step rather than fail. The "next steps" footer also got rewritten to lead with `wire session new --local-only` + `wire session pair-all-local` (the v0.6.6+ recipe), not the legacy `wire pair-host --relay` flow.

**3. `release.yml` now publishes to crates.io on tag.** Pre-v0.6.8, `.github/workflows/release.yml` only built GitHub release binaries — `cargo publish` was never called. crates.io has been frozen at v0.6.1 since the original manual publish; v0.6.2–v0.6.7 were never installable via `cargo install slancha-wire`, and `install.sh`'s cargo-fallback path silently grabbed the stale v0.6.1. v0.6.8 adds a `publish-crates-io` job to the release workflow that runs on every stable tag (skips `-rc` / `-beta` / `-alpha`), gated on a `CARGO_REGISTRY_TOKEN` secret. Treats an already-published version as a soft success (the next-run scenario).

**One-time operator setup for crates.io publish:**
1. Generate a token at https://crates.io/me with `publish-update` scope for the `slancha-wire` crate.
2. Add it under repo Settings → Secrets and variables → Actions → New repository secret, name `CARGO_REGISTRY_TOKEN`.
3. Next stable tag push auto-publishes.

**Until the secret is configured**, v0.6.7 and v0.6.8 are still stuck on crates.io 0.6.1. Run `cargo publish` manually from a checkout with the token in env to unstick:
```bash
CARGO_REGISTRY_TOKEN=<token> cargo publish
```

**Also bundled:**
- `cargo fmt --all` applied across the codebase (CI's `fmt` job had been red since v0.6.5).
- All clippy warnings fixed (CI's `clippy` job same story). `--all-targets -D warnings` is now green.
- `demo-hotline.sh` CI job is still broken (pre-v0.6.0 regression from the bilateral pair gate, predates this release). Not blocking but tracked.

163 lib + 38 cli + 9 within-system stress tests green. CI's fmt and clippy jobs will go green on the next push; the demo-hotline job remains red until that script is updated for the v0.5.14+ bilateral flow.

### v0.6.7 — CLI auto-detects WIRE_HOME from cwd (parity with MCP)

Latent leak fixed. v0.6.1 added MCP auto-detect: when `wire mcp` starts and `WIRE_HOME` isn't set in env, the server reads `$PWD`, looks it up in the session registry, and adopts that session's home dir for the rest of the process. v0.6.7 brings the bare CLI to the same parity:

```bash
cd ~/code/project-a
wire whoami     # → did:wire:project-a-... (the session for this cwd)
wire monitor    # → tails project-a's inbox, not paul-mac's
```

**Symptom pre-v0.6.7.** Operator opens a terminal in a project cwd that has a registered session, runs `wire whoami`. The CLI returns the *machine* default identity (`paul-mac` or whatever the default WIRE_HOME resolves to), NOT the session identity. `wire monitor` from the same cwd tailed the machine inbox, surfacing every federation peer's traffic — even when the operator expected per-session isolation. Reported as "all wire sessions on a machine get the wires for the entire machine" — accurate description of how it looked from the operator side, even though the underlying inboxes were correctly isolated on disk.

**Root cause.** v0.6.1 fixed this for `wire mcp` but not for any other `wire` subcommand. The CLI's `cli::run` entry point passed `WIRE_HOME` straight through from env. With WIRE_HOME unset (the common case for shells that don't `eval $(wire session env)`), every CLI invocation hit the platform default state dir.

**Fix.** Extract the auto-detect helper into `session::maybe_adopt_session_wire_home(label)` and call it at the top of `cli::run` BEFORE `Cli::parse`. Same precondition as MCP — only fires when WIRE_HOME is unset in env, so explicit operator overrides still win. Same stderr line on success (`wire cli: auto-detected session for cwd ... → WIRE_HOME=...`), suppressible with `WIRE_QUIET_AUTOSESSION=1`.

`mcp::run` now calls the same shared helper instead of duplicating the logic. The original v0.6.1 regression test (`mcp::tests::detect_session_wire_home_resolves_registered_cwd`) was retargeted to `crate::session::detect_session_wire_home` so the contract is enforced at the module that owns it.

**What this unlocks.**
- `wire monitor` from any project cwd tails *that* session's inbox automatically. Operators stop seeing cross-session leak in monitor output.
- `wire send` / `wire mesh broadcast` / `wire mesh route` from a session cwd send AS that session, not as the machine identity. Per-project audit trails just work.
- The "machine session" vs "project session" confusion the user surfaced earlier (`"they keep getting confused with the machine session"`) is now an OS-level non-issue — whichever cwd you `cd` to is the identity you use.

**Manual smoke verified live.** From `/Users/laul_pogan/Source/slancha-business` cwd, `wire whoami` now returns `did:wire:slancha-business-7bd164d3`, not `did:wire:paul-mac`. Stderr line surfaces the resolution so it's never silent.

**Compatibility.** Purely additive. Explicit `WIRE_HOME=...` env or `eval $(wire session env <name>)` shell setup continues to work unchanged — auto-detect is a fallback, not an override. Operators who deliberately want machine-default behavior from inside a session cwd can prefix `WIRE_HOME= wire ...` (empty value is still "set"; auto-detect respects it).

### v0.6.6 — `--local-only` sessions + `--local-sister` pair (federation-free within-system mesh)

UX fix shipped to the v0.6 orchestration layer. The previous shape — `wire session new --with-local` allocates BOTH a federation slot AND a local slot, then tries to claim the nick on `wireup.net` — broke down when:

- The cwd-derived session name collided with a reserved nick (`wire`, `slancha`, etc.) — federation claim silently failed and `pair-all-local` 404'd downstream on `.well-known/wire/agent`.
- The operator only needed within-box coordination but was paying the federation tax (and pulling sister-coordination traffic through `wireup.net` for no reason).
- Operators confused "machine identity" with "session identity" — both were federation-claimed, both showed up in `wire peers` from different `WIRE_HOME` views, easy to lose track of which Claude is talking as whom.

v0.6.6 introduces a pure within-system mode that fixes all three:

```bash
wire session new --local-only      # no federation slot, no nick claim, local-relay identity only
wire session pair-all-local        # uses --local-sister (v0.6.6) — no .well-known round-trip
```

**`--local-only` on `session new`** allocates ONLY a local-relay slot. No federation contact. Reserved nicks are allowed because nothing tries to publish them. The session is unaddressable from outside the box by construction — same-box sisters reach it via the local relay; cross-machine peers cannot. If the local relay isn't running, `--local-only` bails with the exact remediation (`wire service install --local-relay`) rather than silently degrading to federation-only.

**`wire add --local-sister <name>`** is the new pair-initiation path. Looks up `name` in `wire session list`, reads that session's `agent-card.json` + `relay.json` directly off disk, pins endpoints into our trust + relay-state, then POSTs the `pair_drop` event direct to the sister's local slot. No `.well-known/wire/agent?handle=<name>` resolution, no federation phonebook lookup — the trust anchor is filesystem permission, which is exactly what same-uid sister sessions can rely on.

**`pair-all-local` now uses `--local-sister` internally.** The federation-path step 1 (`wire add <peer>@<host> --relay <federation>`) is replaced by `wire add <peer> --local-sister`. Pair-all-local works for sessions whose federation handle is unclaimable (reserved nicks) and for `--local-only` sessions with no federation slot at all. The 8-step bilateral handshake otherwise stays identical — same ack flow, same idempotent re-run semantics, same `state.peers` shape on both sides.

**Two latent bugs caught + fixed along the way:**

1. `try_allocate_local_slot` previously wrote `self.relay_url = federation_relay` as a default-filler legacy field even when no federation slot existed. For `--local-only` sessions that produced half-populated `self` state (relay_url set but no `slot_id` / `slot_token` at the top level), which broke any caller that read the legacy fields directly. v0.6.6 writes the LOCAL endpoint into the legacy `relay_url` / `slot_id` / `slot_token` fields when there's no federation endpoint.
2. `ensure_self_with_relay` was hard-coded to auto-allocate a federation slot at `DEFAULT_RELAY` (wireup.net) any time `self.slot_id` was missing — including for `--local-only` sessions that genuinely had no business touching federation. `wire pair-accept` would then silently turn a `--local-only` session into a dual-slot one. v0.6.6 prefers any existing `self.endpoints[]` entry over auto-allocating.

**Docs.** `AGENT.md` (§0 within-system / §1 cross-system), `README.md`, and `landing/index.html` all got an explicit two-mode comparison table + the full within-system recipe. The user-reported confusion ("they keep getting confused with the machine session") is addressed at the doc level — sessions vs default identity, local-only vs federation, and the trust anchor for each are surfaced before the commands instead of after.

**Regression test.** `tests/stress_within_system.rs::local_only_sessions_pair_without_federation_v0_6_6` — spins THREE local-only sessions including one named `wire` (a reserved nick that pre-v0.6.6 would fail federation claim), runs `pair-all-local`, asserts every session has every other in `state.peers`, asserts the broadcast from the reserved-nick session delivers to all sisters. Plus regression: each `--local-only` session's `self.endpoints[]` is local-scope only (no federation slot leaked).

### v0.6.5 — `wire mesh route`: capability-match addressing (issue #21)

Closes the orchestration-primitive arc opened in v0.6.0. The mesh now has a discovery layer (pair-all-local), an observability layer (mesh-status), a fan-out layer (mesh-broadcast), a metadata layer (mesh-role), and now a *routing* layer. Prompts stop saying "send to beth" and start saying "send to the reviewer" — handle-free addressing.

```bash
wire mesh route reviewer "PR #142 ready for review"     # round-robin among reviewers
wire mesh route planner --strategy first "..."          # deterministic alpha-pick
wire mesh route reviewer --strategy random "..."        # uniform across matches
wire mesh route reviewer --exclude beth "..."           # skip a specific sister
wire mesh route reviewer --kind question "thoughts on..."  # any event kind
```

**Resolver.** Enumerate every sister session, read each one's `profile.role` from its agent-card, filter: matching role AND not in `--exclude` AND pinned in our own `state.peers`. The third filter is load-bearing — mesh-route refuses to invent a recipient. Same pinned-peers-only posture as mesh-broadcast; same defense against the phonebook-scrape class.

**Strategies.**
- `round-robin` (default): per-role cursor persisted at `<state_dir>/mesh-route-cursor.json` keyed by role. Each call picks the candidate alphabetically AFTER the last one, wrapping. Fair under steady-state load.
- `first`: alphabetically-first matching sister. Deterministic — useful for testing and pinning a specific peer when there's exactly one match.
- `random`: uniform random over matches. Stateless. Best for stateless tasks where any matching peer is fine.

**Failure modes.** No matching sister bails loudly with a `wire mesh role list` hint (operators see the available role taxonomy on the box). `--exclude` leaving zero candidates is the same hard error. Delivery failure on the chosen peer bubbles up with the exact relay error — not silent.

**Implementation.** `src/cli.rs::cmd_mesh_route`. Single resolved peer, single sign + push, ~ms-scale. Round-robin cursor reads/writes a small JSON dict; rebuilds on missing file, survives session destroy/re-create (cursor entries pointing at gone sisters silently fall through to the next candidate).

**Regression test.** `tests/stress_within_system.rs::mesh_route_picks_one_sister_per_strategy_v0_6_5` spins 3 sessions (one planner, two reviewers), pairs them, then routes `reviewer` four times with round-robin and asserts an exact 2-2 split between the two reviewers; tests `first` for determinism (must hit beth, the alpha-sort winner); tests `random` over 20 calls (must hit both reviewers, vanishingly unlikely to miss); tests nonexistent-role error with the role-list hint; tests `--exclude` leaving exactly one candidate.

**v0.6 line complete.** The four mesh primitives — status / broadcast / role / route — together turn the v0.5 protocol layer into an actual control plane. v0.7 will be about hardening + ergonomics on top of this base.

### v0.6.4 — `wire mesh role`: capability tags on sister sessions (issue #20)

Fourth orchestration primitive — the first slice of the Layer-2 capability metadata umbrella (#13). Now operators can tag sister sessions by *function* (planner / executor / reviewer / coder / dispatcher / your-custom-tag) so the mesh has structure beyond bare connectivity. `wire mesh route` (#21) will consume these tags to pick the right sister for a task.

```bash
wire mesh role set planner          # assign self to a role
wire mesh role get                  # print self role
wire mesh role get charlie          # print pinned peer's role
wire mesh role list                 # show roles across every sister session
wire mesh role clear                # unset self role
```

**Persistence.** Stored as `profile.role: Option<String>` on the signed agent-card via the existing `pair_profile::write_profile_field` plumbing — no new storage, no new schema layer. The card's existing signature covers `profile.role` by construction (card canonicalization includes the profile sub-object). Backward compatible: pre-v0.6.4 cards have no `role` field, surfaced as `(unset)`.

**Vocabulary is operator territory.** No relay-side validation of role names. Common starters surfaced in the CLI help: `planner`, `executor`, `reviewer`, `coder`, `tester`, `dispatcher`. But "data-vibes-checker" or "PR-approver" are equally valid — the operator picks the taxonomy. Client-side validation is purely a *safety* check (ASCII alphanumeric + `-` + `_`, max 32 chars) so role strings stay safe for filenames, URLs, and shell args. Illegal chars / oversize get rejected loudly.

**Cross-session list reads by path.** `wire mesh role list` enumerates `wire session list` and reads each session's `agent-card.json` directly off the filesystem — no network, no env mutation. Marks the running session (when applicable) with `← you` in the text output. JSON output is `{sessions: [{name, handle, role, self}]}`.

**Inside-session sessions_root fix (latent bug).** `session::sessions_root()` previously returned `WIRE_HOME/sessions/` unconditionally. When `WIRE_HOME` was set by `wire session env` or v0.6.1 MCP auto-detect — i.e., pointing at one specific session's home — that path was empty and `wire mesh role list` (plus `mesh status`, `mesh broadcast`, `pair-all-local`) silently saw zero sister sessions. v0.6.4 adds a tight fallback: if the canonical `<WIRE_HOME>/sessions/` doesn't exist AND `WIRE_HOME`'s immediate parent is named `sessions`, treat that parent as the canonical sessions root. So inside-session invocation now Just Works. Other WIRE_HOME shapes (test harnesses, custom locations) keep the v0.6.3 behavior.

**Regression test.** `tests/stress_within_system.rs::mesh_role_set_list_round_trips_v0_6_4` spins 3 sessions, sets a distinct role on each from inside its own WIRE_HOME (`alpha=planner`, `beth=reviewer`, `charlie=coder`), then runs `mesh role list --json` from *each* session and asserts all three sessions report each other's roles correctly. Also rejects illegal chars (`bad role`) and oversize (33-char string), and verifies `clear` round-trips back to `null`.

### v0.6.3 — `wire mesh broadcast`: fan one event to every pinned peer (issue #19)

Third orchestration primitive. With v0.6.0 (`pair-all-local`) and v0.6.2 (`mesh-status`), the operator can build a sister mesh and inspect it. v0.6.3 adds the write-side primitive: one command that dispatches the same signed event to every pinned peer in parallel.

```bash
wire mesh broadcast "rebuilding the index, ETA 2min"                    # default --scope local
wire mesh broadcast --scope federation --kind decision "ship v3 now"    # cross-machine fan
wire mesh broadcast --exclude beth --json "private update"              # skip one peer
wire mesh broadcast --kind question - <<EOF                             # stdin / heredoc body
who has the latest model checkpoint?
EOF
```

**Routing.** Each recipient gets its own Ed25519 signature (the wire envelope canonicalizes over `to:`, so per-recipient signing is required by the protocol). Every copy carries the same `broadcast_id` UUID and a `broadcast_target_count` so receivers can correlate them as one logical broadcast. Per-recipient pushes happen on `std::thread::scope` worker threads — broadcast-to-5 takes ~1× RTT, not 5×.

**Scope filter.** Default `local` is the lowest-blast-radius posture: only peers whose priority-1 endpoint is a same-machine local relay get the broadcast. `federation` flips to public-relay peers only (cross-machine fan). `both` removes the filter. The default exists because most broadcasts are operational coordination ("expect outage", "rebuilding index") that should stay on-box; cross-machine sharing should be an explicit opt-in.

**Pinned-peers-only by construction.** Walks `state.peers` only — never `.well-known` resolution, never `trust["agents"]` expansion. This forecloses the phonebook-scrape class (T8, closed in v0.5.14): a hostile peer would have to be bidirectionally pinned to receive a broadcast, and even then `--exclude <handle>` is the loud opt-out.

**Top-level `wire mesh` namespace.** New `Command::Mesh(MeshCommand)` with subcommands `status` and `broadcast`. `wire mesh status` aliases the v0.6.2 `wire session mesh-status` handler — the session-namespaced form keeps working, but going forward the operator-facing surface is `wire mesh <verb>`. v0.7 may remove the legacy alias once mesh becomes the documented entry point.

**Implementation.** `src/cli.rs::cmd_mesh_broadcast` — single-pass sign-all-then-push-all so the parallel push doesn't race the per-key signing. Outbox queue is sequential (per-path mutex) before the parallel push, so a failed push can be retried from the outbox by a daemon later. Push results aggregate over an `mpsc::channel`, sorted by handle for deterministic stdout.

**Regression test.** `tests/stress_within_system.rs::mesh_broadcast_fans_to_every_paired_sister_v0_6_3` — 3 sessions paired via `pair-all-local`, alpha broadcasts `"hello mesh from alpha"`, beth and charlie pull their inboxes, both receive an event with matching `body.broadcast_id`, distinct `event_id`s, correct `broadcast_target_count: 2`. Then re-broadcasts with `--exclude charlie` and asserts charlie is skipped while beth still receives.

### v0.6.2 — `wire session mesh-status`: live view of the sister mesh (issue #18)

Second orchestration primitive. After `pair-all-local` lands N sessions in a fully-paired mesh, operators need one command to see who's actually paired with whom and which edges are silent. Today they walk every session's `wire peers` + per-peer `wire status --peer` manually. v0.6.2 collapses that to one read-only call:

```bash
wire session mesh-status            # NxN pin matrix + per-edge health roll-up
wire session mesh-status --json     # {sessions, edges, local_relays, summary}
wire session mesh-status --stale-secs 60   # tighten the "silent" threshold
```

**What it does.** For each session in `wire session list-local`, reads that session's `relay.json` directly (no WIRE_HOME mutation — sessions are inspected by path, not env), enumerates pinned peers, and for every unordered pair (A, B) where both are sister sessions:

- Reports **bilateral state** — `bilateral: true` only if A has pinned B AND B has pinned A. Half-pinned pairs surface as `status: "asymmetric"`, which usually means a pair handshake was interrupted mid-flow.
- Reports **route scope** — `local` if the priority-1 endpoint is a same-machine relay, `federation` if it's wireup.net or another public relay. Local sister sessions should always route `local`; anything else is a degradation signal.
- Probes the receiver's slot on the relay for `last_pull_at_unix`, computes `silent_secs = now - last_pull`. An edge with `silent_secs > stale_secs` (default 300s, matching the per-send `phyllis` attentiveness nag) gets `status: "stale"`.
- Probes each unique local-relay URL's `/healthz` once (not per-edge) so the operator sees one liveness line per relay.

**Read-only by construction.** No daemon contact, no peer state mutation, no WIRE_HOME env tweaking. Failures degrade silently — a relay timeout records the edge as `probed: true, last_pull: null` (treated as stale) rather than aborting the whole report. A half-broken mesh is still inspectable.

**Why this matters.** Operators get a single observable for the orchestration layer's health. Before v0.6.2 you could `pair-all-local` ten sessions and have no idea whether the daemons were actually pulling — silent failure was easy. Now `mesh-status` surfaces every silent edge with the exact direction and silence duration. That's the precondition for everything downstream: broadcast can refuse to dispatch to silent peers, route can prefer fresh ones, role assignment can detect stale capability advertisements.

**Implementation.** `src/cli.rs::cmd_session_mesh_status` + `probe_directed_edge` (one slot_state probe per direction) + `probe_relay_healthz` (one healthz call per unique local-relay URL). Reuses `peer_endpoints_in_priority_order` from v0.5.17, so local-first routing logic is identical to what `wire push` uses. Matrix rendering is O(N²) probes for the text path — fine for the realistic ceiling of ~20 sessions per machine.

**Regression test.** `tests/stress_within_system.rs::mesh_status_reports_paired_mesh_v0_6_2` — spins 3 sessions, pairs them via `pair-all-local`, runs `mesh-status --json`, asserts: 3 sessions, 3 edges, 0 asymmetric, every edge `scope=local` and `bilateral=true`, at least one direction with a recorded `last_pull_at_unix`, local relay reported healthy.

### v0.6.1 — MCP server auto-detects WIRE_HOME from cwd

Removes the manual `.mcp.json env.WIRE_HOME` step that v0.5.16+ multi-session setups required. When the `wire mcp` server starts:

1. If `WIRE_HOME` is already in env (explicit operator override) — respect it, no change.
2. Else: read `std::env::current_dir()`, look it up in the session registry (`<state_dir>/wire/sessions/registry.json`). If a session is registered for this cwd, adopt that session's `$WIRE_HOME/sessions/<name>` as the process-wide WIRE_HOME for the rest of the MCP server's lifetime.
3. Else: fall through to default WIRE_HOME (pre-v0.6.1 behavior).

Emits a single stderr line on auto-detect so operators can see the resolution: `wire mcp: auto-detected session for cwd '...' → WIRE_HOME='...'`. Goes to stderr (not stdout, which is the MCP JSON-RPC channel).

**Practical effect.** Operators run `wire session new --with-local` once per project. Then Claude Code, Cursor, or any other MCP host that sets `$PWD` to the project directory at server-spawn time gets the right per-project identity automatically. No `.mcp.json env` editing, no shell-side `eval $(wire session env)` plumbing. The README + AGENT.md multi-session sections updated to mention auto-detect first; the manual env override is still documented for hosts that don't set `$PWD` (rare).

Implementation lives at `src/mcp.rs::detect_session_wire_home` — read-only lookup; the caller (`run()`) does the `set_var` inside an `unsafe` block because Rust 2024 marks env mutation unsafe (thread-safety). Safe at this call site because `run()` hasn't spawned the writer / watcher threads yet.

**Verified live on this laptop:**

```
$ wire mcp < initialize.jsonl
wire mcp: auto-detected session for cwd `/Users/laul_pogan/Source/wire` → WIRE_HOME=`/Users/laul_pogan/Library/Application Support/wire/sessions/wire`
{"id":1,"jsonrpc":"2.0","result":{"capabilities":...,"serverInfo":{"name":"wire","version":"0.6.1"}}}
```

The MCP `initialize` response now reports `"version": "0.6.1"` from inside the session-scoped WIRE_HOME, not the default.

**Pure additive.** No protocol or schema change. Pre-v0.6.1 clients that set WIRE_HOME explicitly continue working unchanged; the auto-detect path is purely additive for the unset-env case.

### v0.6.0 — `wire session pair-all-local`: first orchestration primitive (issue #12)

Adds **the entry point to the orchestration layer**: one command that bilaterally pairs every sister session on a machine. For each unordered pair (A, B) in `wire session list-local`, drives the existing v0.5.14 bilateral handshake end-to-end via subprocess: A's `wire add`, A's `wire push`, settle, B's `wire pull`, B's `wire pair-accept`, B's `wire push`, settle, A's `wire pull`. Idempotent — re-running skips pairs already in `state.peers`. JSON output reports per-pair status (`paired` / `already_paired` / `failed` with stderr from the offending step).

**Trust model rationale.** The bilateral SAS / network-level handshake (v0.5.14) assumes the two endpoints are strangers — that's why the operator must explicitly run `wire pair-accept` on the receiver. Same-uid sister sessions are not strangers: they share a filesystem, a `$WIRE_HOME/sessions/` directory, and a single operator (whoever has read access to that directory). The operator running `pair-all-local` IS the consent for both sides; the filesystem permission boundary serves the same role the SAS-typing step serves for strangers. `wire session list-local` only enumerates the current user's sessions, so cross-uid auto-pairing is out of scope.

**Why this matters beyond the feature.** Wire's protocol layer (signed events, relay, dual-slot routing) is the *transport*. The orchestration layer (`list-local`, `pair-all-local`, and the primitives it unblocks) is the *control plane*. Today the only primitive is discover-and-pair. The shape of what's next:

- `wire mesh status` — live view of every paired sister + per-edge transport health
- `wire mesh broadcast "..."` — dispatch one signed event to every paired sister
- `wire mesh role <name>` — assign role tags to sessions (unblocks the Layer-2 capability metadata from issue #13)
- `wire mesh route <task>` — pick the right sister for a task by capability match

Wire stops being only "magic-wormhole for AI agents" (two-party) and starts being "OS-level mesh fabric for AI agents" (N-party, same-uid trust, sub-millisecond latency over the local relay, no SaaS dependency). That's the positioning v0.6 stakes out.

**New CLI surface:**

```bash
wire session pair-all-local                        # mesh-pair every sister with --with-local
wire session pair-all-local --settle-secs 2 \      # bump if the relay is slow
                            --federation-relay https://wireup.net \
                            --json                  # emit machine-readable per-pair summary
```

**Behavior:**
- < 2 local sessions: no-op with a friendly note pointing at `wire session new --with-local`.
- already-paired pairs: skipped (counted separately in the JSON summary).
- per-pair failure: error captured in the JSON `results[i].error` field, doesn't abort the run.
- ~3–5s per pair on a healthy relay (two 1s settles + the round-trip cost).

**Integration test** (`tests/stress_within_system.rs::pair_all_local_mesh_pairs_every_sister_session_v0_6_0`): spins 3 sister sessions in one WIRE_HOME, runs the command, asserts the JSON summary shows 3/3 succeeded, asserts each session's `relay.json` lists the other two as peers, runs the command a second time and asserts 3 skipped + 0 new pairs (idempotency). 12s wall clock for the full mesh.

**Tests:** 162 lib + 38 cli + 4 stress + 4 stress-within-system (+1 mesh-pair regression) + 20 relay + full e2e — all green.

**Not in this release:**
- The auto-detect-WIRE_HOME-from-$PWD improvement in the MCP server (floated for v0.5.24; would make `.mcp.json env.WIRE_HOME` no longer manual). Coming in v0.6.1.
- The follow-on mesh primitives (`status`, `broadcast`, `role`, `route`). Each is a separate ship.
- Cross-uid pair-all-local. Out of scope by design — filesystem permission is the trust anchor.
- Cross-machine pair-all (the wireup.net federation peer-list). Different problem; cross-uid + different threat model.

## v0.5 — agentic hotline

The v0.5 line collapses pair from "one paste" to "one command." Agents claim memorable handles (`coffee-ghost@wireup.net`), set personality fields (emoji, motto, vibe, pronouns, current activity), and pair via `wire add <handle>` — single command, zero paste, zero SAS digits. Federated by DNS + relay-served `.well-known` à la Mastodon / Bluesky / Nostr. Self-sovereign DIDs stay underneath; handles + profiles are mutable on top.

### v0.5.23 — Linux service log message + linger nag (Spark smoke discoveries)

Two operator-confusion fixes surfaced when v0.5.22 hit a real Linux box for the first time (Spark, DGX GB10, Ubuntu 6.17 ARM64).

**Fix 1: `wire service install` on Linux now reports the correct log path.** v0.5.22's install detail said `logs at ~/.cache/wire/wire-<kind>.log`, but the systemd unit it wrote had no `StandardOutput=` directive — output went to journald per the Linux default. The file path was a phantom location; operators going to read it found nothing. The `~/.cache/wire/` fallback was also the wrong XDG default in the first place (spec says `~/.local/state/` if `XDG_STATE_HOME` is unset). v0.5.23 removes the log-file message entirely on Linux and recommends `journalctl --user -u <unit>` instead — the idiomatic Linux read path. macOS launchd plists still get the `StandardOutPath` redirect to `~/Library/Logs/` because that's the macOS-idiomatic pattern + Console.app reads from there.

**Fix 2: linger nag on linux only fires when off.** New: after a successful `systemctl --user enable --now <unit>`, checks `loginctl show-user $USER --property=Linger`. If linger is OFF, appends a NOTE recommending `sudo loginctl enable-linger $USER` (without which the unit waits for the next console login to start — fine for desktops, broken for headless SSH boxes). If linger is ON (Spark's case — already configured), silent. If detection fails, defaults to nagging.

These together close the "wire service install on Linux looks confused" class. On Spark today:

```
$ wire service install --local-relay
wire service install
  platform:  linux-systemd-user
  unit:      /home/admin/.config/systemd/user/wire-local-relay.service
  status:    enabled
  detail:    unit written + enable --now succeeded; logs via `journalctl --user -u wire-local-relay.service`
```

**Adjacent: Windows service-install gap filed as #17.** v0.5.22 ships only macOS launchd + Linux systemd-user; Windows bails with `unsupported platform`. The recommended implementation (Task Scheduler XML for user-scope parity) is in the issue. No commitment to ship yet.

**Spark linux smoke result.** End-to-end verification on ARM64 Ubuntu:
- `install.sh` from `wireup.net` correctly served the `aarch64-unknown-linux-gnu` binary; sha256 verified
- `wire service install --local-relay` wrote `~/.config/systemd/user/wire-local-relay.service` with `ExecStart=/home/admin/.local/bin/wire relay-server --bind 127.0.0.1:8771 --local-only`
- After killing a leftover Python `http.server 8771` from a prior dev experiment, the relay bound cleanly and `curl http://127.0.0.1:8771/healthz` returned `ok`
- `wire session new --with-local --json` wrote a session with both scope=federation + scope=local endpoints to `~/.local/state/wire/sessions/admin/config/wire/relay.json`
- `wire session list-local` surfaced the session under the local-relay group

Tests: 162 lib + 38 cli + 4 stress + 3 stress-within-system + 20 relay + full e2e — all green.

### v0.5.22 — `wire service install --local-relay` for persistent within-system transport

Adds the missing piece for the v0.5.17 dual-slot story: a way to keep the local relay running across reboots and terminal sessions without a tmux pane or a hand-rolled plist. `wire service install --local-relay` now writes a launchd plist (macOS) or systemd user unit (linux) that supervises `wire relay-server --bind 127.0.0.1:8771 --local-only` the same way `wire service install` already supervised the daemon.

**Changes to `wire service install / uninstall / status`:** all three subcommands gained an optional `--local-relay` flag. Without the flag, behavior is identical to pre-v0.5.22 (acts on the daemon). With the flag, acts on the local relay. The two services have distinct labels (`sh.slancha.wire.daemon` vs `sh.slancha.wire.local-relay`), distinct systemd unit names (`wire-daemon.service` vs `wire-local-relay.service`), and distinct log paths — they're designed to coexist on the same machine.

**One behavior tweak that touches the daemon too:** both services now write stdout/stderr to a real log file (`~/Library/Logs/wire-<kind>.log` on macOS, `$XDG_STATE_HOME/wire/<kind>.log` on linux) rather than `/dev/null`. The daemon used to silently discard crash output; now `tail -F ~/Library/Logs/wire-daemon.log` actually shows what happened. Re-running `wire service install` picks up the new path; existing installs keep their old `/dev/null` redirect until re-installed.

**Why this was missing:** v0.5.17 shipped the dual-slot routing layer; v0.5.20 shipped `list-local`; v0.5.21 fixed the `relay.json` filename bug that had silently disabled the whole story since v0.5.17 (CHANGELOG entry below). After all that landed, the local relay still had to be started by hand every login. Without persistence the deployment story was "make sure to keep a tmux pane open" — which nobody does. This release closes that gap.

**Service install verified end-to-end on the dev laptop:**

```
$ wire service install --local-relay
wire service install
  platform:  macos-launchd
  unit:      /Users/laul_pogan/Library/LaunchAgents/sh.slancha.wire.local-relay.plist
  status:    loaded
  detail:    plist written + bootstrapped; logs at /Users/laul_pogan/Library/Logs/wire-local-relay.log

$ curl -s http://127.0.0.1:8771/healthz
ok

$ tail -1 ~/Library/Logs/wire-local-relay.log
wire relay-server (LOCAL-ONLY) listening on 127.0.0.1:8771 — phonebook + well-known endpoints disabled
```

The session created earlier (`wire`) continues to route via the launchd-managed relay automatically — no session-side change needed.

**Tests:** 162 lib (+3 new service unit tests) + 38 cli + 4 stress + 3 stress-within-system + 20 relay + full e2e — all green.

### v0.5.21 — within-system was silently broken since v0.5.17 (filename mismatch)

Critical fix shipping on top of v0.5.20. Caught immediately after v0.5.20 published, while attempting to use the within-system stack on the dev laptop for real. Symptom: `wire session new --with-local` prints "local slot allocated on http://127.0.0.1:8771" to stderr, exits 0, and creates the session — but the session's `relay.json` carries only the federation endpoint, no `self.endpoints[]` array. Downstream consequence: `wire session list-local` shows the session WITHOUT its local endpoint; routing logic in `cmd_push` has nothing to prefer; **every single `--with-local` deployment since v0.5.17 silently degraded to federation-only**.

**Root cause:** two callers joined the wrong filename. `try_allocate_local_slot` in `src/cli.rs` and `read_session_endpoints` in `src/session.rs` both used `relay-state.json`, but the canonical filename returned by `config::relay_state_path` is `relay.json`. The mis-named writes succeeded (creating an orphan file nothing else reads); the mis-named reads silently no-op'd. The federation slot allocation went through the correctly-named path via `config::write_relay_state`, so federation appeared to work; the local slot endpoint was the only victim. Test suites passed because every test in `tests/e2e_dual_slot.rs` and `tests/stress_within_system.rs` writes directly to `relay.json` via inline helpers, bypassing both broken sites entirely.

**Why it took so long to notice:** `wire session new` prints "local slot allocated (slot_id=...)" — the slot DOES exist on the relay; the relay-side allocation is correct. The bug is purely in persisting that allocation into the client's session state. The CLI gave operators every reason to believe `--with-local` was working when it wasn't.

**Fixes:**
- `src/cli.rs::try_allocate_local_slot` — join `relay.json`.
- `src/session.rs::read_session_endpoints` — join `relay.json`.
- Updated all in-module + integration test fixtures to use `relay.json` so future tests reflect reality.

**New regression test** (`tests/stress_within_system.rs`): `regression_session_new_with_local_writes_dual_endpoints_v0_5_20`. Runs the full `wire session new --with-local` orchestration via subprocess against a real in-process federation relay + local-only relay, asserts the resulting `relay.json` contains BOTH scope=federation AND scope=local endpoints, asserts the local endpoint URL matches the `--local-relay` arg, and asserts `wire session list-local --json` surfaces the session under the correct local-relay key. If any of the four sites that touch `relay.json` for sessions break again, this test fails loudly with the offending data.

**Verified end-to-end on the dev laptop:**

```
$ wire session destroy wire --force      # broken v0.5.20 session
$ wire session new --with-local --json   # rebuild on v0.5.21
$ cat ~/Library/Application\ Support/wire/sessions/wire/config/wire/relay.json
{
  "peers": {},
  "self": {
    "endpoints": [
      {"scope": "federation", "relay_url": "https://wireup.net", "slot_id": "...", "slot_token": "..."},
      {"scope": "local",      "relay_url": "http://127.0.0.1:8771", "slot_id": "...", "slot_token": "..."}
    ],
    ...
  }
}
$ wire session list-local
LOCAL RELAY: http://127.0.0.1:8771
  wire                     wire                             running    /Users/laul_pogan/Source/wire
```

**Tests:** 159 lib + 38 cli + 4 stress + 3 stress-within-system (+1 regression) + 20 relay + full e2e — all green.

### v0.5.20 — macOS session-root fix + within-system stress harness

Quick patch on top of v0.5.19. Caught while attempting to deploy v0.5.19 on the dev laptop: `wire session list` (and `list-local`) errored with `could not resolve XDG_STATE_HOME — set WIRE_HOME` on macOS because `dirs::state_dir()` returns `None` on darwin (it's a Linux/XDG concept). The main `config::state_dir` already falls back to `dirs::data_local_dir` — `~/Library/Application Support/wire/` on macOS — but `session::sessions_root` didn't carry the same fallback. Within-system sessions were effectively broken without explicit `WIRE_HOME` on every Mac in the install base.

**Fix:** `sessions_root` now mirrors `state_dir`'s fallback chain. Linux still hits the XDG path; macOS lands at `~/Library/Application Support/wire/sessions/`; other Unix without XDG falls through gracefully. Error message updated to name the actual cause rather than blame XDG.

**Within-system stress harness** (`tests/stress_within_system.rs`, 2 tests). The existing `tests/stress.rs` flooded the federation path; this file covers the local-relay path the same way. Spins both an in-process federation relay AND an in-process `--local-only` relay (random ports on `127.0.0.1`), pairs two homes with both endpoints attached, then:

- **`stress_within_system_local_first_routing_v0_5_19`** — floods 50 events alice → bob and asserts every single one was delivered with `scope: "local"`. A single `scope: "federation"` in the push output means the priority logic dropped the local endpoint somewhere; the test fails loudly with the offending event_id. Verified 3× consecutive: 0 leaks across 150 events.
- **`stress_within_system_failover_to_federation_on_local_death_v0_5_19`** — mid-flood, patches alice's view of bob's local endpoint to a closed port (simulating the local relay crashing while the daemon keeps going). Pre-failover half MUST land via local; post-failover half MUST land via federation; zero events allowed to be skipped with transport errors. Exercises the `cmd_push` "walk endpoints in priority order with transparent retry" promise from v0.5.17.

No protocol or schema changes. Pure platform-correctness fix + integration coverage gap.

**Test count:** 159 lib + 38 cli + 4 stress + 2 stress-within-system + 20 relay + full e2e — all green.

### v0.5.19 — issue cleanup pass: #2, #5, #7, #9 + stress harness + sister-session discovery

Patch release driven by an open-issue cleanup pass. No protocol changes; one new CLI subcommand (`wire session list-local`), two new CLI flags (`wire bind-relay --migrate-pinned`, `wire claim --hidden`), several operator-visible warnings, and three new test files. **The bind-relay change is a behavior break for the silent-migration case** (it now refuses by default when peers are pinned — see #7 below); the rest is additive.

**New: `wire session list-local`** (#11). Sister-session discovery via the local relay. For each on-disk session under `~/.local/state/wire/sessions/`, reads its `relay-state.json`, filters those with a v0.5.17 Local-scope endpoint, and groups by local-relay URL. Read-only, no daemon contact. `--json` form serializes the grouped view with `slot_token` redacted (bearer credential — exposing it via observability would risk accidental leak via logs/screenshots/piped output). Companion design issues #12 (zero-paste sister pairing) and #13 (Layer 2 capability metadata) deferred.

**Fixed (#7): `wire bind-relay` now refuses silent migration when peers are pinned.** Originally the command silently replaced `state.self` with new slot coords, leaving N pinned peers pushing to a dead slot that returned 200 OK to the relay but was never read. The original incident report logged 26 events silently lost over 2 days. v0.5.19 bails by default when `state.peers` is non-empty, naming every affected peer and recommending `wire rotate-slot` (the supported same-relay rotation that emits a `wire_close` event to peers). Operators who actually need the silent path pass `--migrate-pinned` and get a final stderr banner naming the affected peers so there's a shell-history record. Split-offs filed as #14 (sender-side staleness signal in `wire doctor`) and #15 (handle-directory 410 fallback via `whois` re-resolve).

**Hardened (#2): unified daemon liveness + outbox-write normalization.** Beyond the v0.5.13 surface fix. Three call sites in `cmd_status`, `check_daemon_health`, and `check_daemon_pid_consistency` used to compute daemon liveness independently — `wire status` reported DOWN while `wire doctor` reported PASS for 25 min in the original incident because each side had its own definition of "live." All three now consume `ensure_up::daemon_liveness()`, a single snapshot of `(pidfile_pid, pidfile_alive, pgrep_pids, orphan_pids, record)`. The consistency check also gained a liveness gate — a JSON-valid pidfile pointing at a dead pid is now a WARN with explicit reference to the incident, not a silent PASS. Outbox write path: `config::append_outbox_record` now normalizes `peer` through `agent_card::bare_handle` at the writer chokepoint. The v0.5.13 fix was at the two call sites; this makes the on-disk contract self-enforcing for every future caller.

**Hardened (#9): phonebook discovery posture.** Three sub-items. Bilateral pair gate (v0.5.14) is the cryptographic mitigation — these close operator-ergonomics holes that let phishing or correlation attacks succeed via human confusion.

- **#9.1 `discoverable: false` opt-out.** New `discoverable` field on `HandleRecord` and `HandleClaimRequest`. Default `None` = discoverable (back-compat). `Some(false)` = handle omitted from `/v1/handles` bulk listing but still resolves via `.well-known/agent-card.json?handle=X` direct lookup. `wire claim --hidden` writes the flag. Re-claim that omits the field preserves the existing value — stops a v0.5.18 client doing a profile-update re-claim against a v0.5.19 relay from accidentally re-publishing a hidden handle. Two integration tests cover the listing-filter behavior and the re-claim preservation.
- **#9.4 cross-relay phishing guardrail.** `wire add boss@evil-relay.example` (typo / look-alike domain) now emits a stderr WARN naming the unfamiliar domain and the known-good list (`wireup.net`, `wire.laulpogan.com`, operator's own bound relay). Doesn't block — operators have legitimate reasons to cross-relay pair — but the signal lands in shell history.
- **#9.5 second-precision `claimed_at`.** Nanosecond timestamps were a cross-tab fingerprint correlating one operator's multiple handles claimed in the same session. Truncated to seconds at relay-server via `replace_nanosecond(0)`. Display-only field; back-compat is fine.

**Closed (#5): SPAKE2 asymmetric finalize.** Retrospective cross-checked against v0.5.18. The v0.2.4 race is closed via symmetric bootstrap-exchange polling — both sides POST their sealed bootstrap to the relay, both sides poll for the peer's bootstrap, and pin only happens AFTER decrypt + card-signature verification. A narrow window remains (one side pins, peer's network dies mid-handshake) but is much narrower than v0.2.4. Filed as a future hardening note if anyone hits the symptom.

**New: stress harness** (`tests/stress.rs`, 4 tests). Outbox flood (100 sends), concurrent senders (5 threads × 20), bind-relay silent migration detector (caught #7 end-to-end before the fix), send-to-nonexistent-slot detector. Each uses the in-process relay + subprocess `wire` pattern from `e2e_dual_slot.rs`. The bind-relay test originally panicked with `ExitStatus(0)` and empty stderr; post-fix it asserts the bail.

**Test flake fixes.** Two pre-existing flakes — `detached_pair_full_e2e_with_real_daemons` (daemon raced CLI pull, assertion checked the wrong thing — replaced with retry on `wire tail`, the user-visible source of truth) and `wire_add_zero_paste_e2e` (predated v0.5.14 bilateral gate, asserted auto-pin that no longer exists — updated to drive the actual bilateral flow). Both verified failing on the v0.5.18 baseline before the fix.

**Email interop design brief** (#16). Captured a session's research output as `docs/EMAIL_INTEROP.md`. NOT scheduled; ship gate is a yes/no from the threat-model team on a new BRIDGED trust tier. Recommendation: outbound-only `wire send-email` first, defer reply path. Run mail on `mail.wireup.net` subdomain with separate DKIM/SPF/DMARC so the apex isn't poisoned.

**Test count:** 159 lib + 38 cli + 4 stress + 20 relay (+2 new from #9.1) + full e2e — all green. Total ~228 across the suite.

### v0.5.18 — dual-slot integration tests + `pair_drop_ack` carries endpoints[]

Companion to v0.5.17. The ship report explicitly flagged dual-slot routing as "code-review-only, not automated-tested" — this release closes that gap. Three new integration tests (`tests/e2e_dual_slot.rs`) spin up an in-process federation relay AND an in-process `--local-only` relay (different ports on `127.0.0.1`) to exercise the real routing decisions end-to-end.

**Real bug caught and fixed.** `send_pair_drop_ack` (the responder's reply during bilateral pair) only emitted the legacy top-level `relay_url`/`slot_id`/`slot_token` — no `endpoints[]`. The initiator pulling the ack thus only learned the responder's federation endpoint via back-compat synthesis, never their local endpoint. Routing decisions on the initiator side always picked federation even when both sides had a local relay.

- **Fix in `pair_invite.rs::send_pair_drop_ack`** — now reads `self.endpoints[]` via `crate::endpoints::self_endpoints` and includes the full array in the ack body alongside the legacy fields. Pure additive — v0.5.16-and-earlier readers still parse the legacy fields unchanged.
- **Fix in `pair_invite.rs::maybe_consume_pair_drop_ack`** — parses `body.endpoints[]` when present and routes through `crate::endpoints::pin_peer_endpoints` so all endpoints get pinned in `relay_state.peers[handle].endpoints[]`. Back-compat: ack without `endpoints[]` falls back to synthesizing a single federation entry from the legacy fields.

**Three new integration tests** in `tests/e2e_dual_slot.rs`:

1. **`dual_slot_send_prefers_local_endpoint`** — Alice + Bob both have dual slots; after bilateral pair, Alice's `wire push --json` MUST report `scope: "local"` for the delivered event.
2. **`dual_slot_send_falls_back_to_federation_on_local_failure`** — Alice + Bob both have dual slots, but Alice's view of Bob's local endpoint is patched to a closed port. Local POST fails, daemon transparently retries on federation; push --json reports `scope: "federation"`.
3. **`dual_slot_back_compat_v0_5_16_peer_routes_via_federation`** — Alice has dual slots, Bob is federation-only (simulating a v0.5.16 peer). Alice's view of Bob has only the federation endpoint; sends route through federation. Old peers still work cleanly.

**Test count: 156 lib + 35 CLI + 3 new dual-slot e2e** (was 156 + 35 in v0.5.17). Total 194 across the suite.

No protocol or schema changes. Pure correctness fix + integration coverage of the v0.5.17 surface.

### v0.5.17 — dual-slot sessions + local-only relay (OSS coordination layer)

The strategic pair to v0.5.16's per-session identity: **a within-machine transport layer** so sister-Claudes (and sister-Cursors, sister-Aiders, sister-any-agent) coordinate at sub-millisecond latency without going through a public relay. Same-machine traffic stays on the box. Federation through `wireup.net` keeps working unchanged for cross-box traffic. Sessions can hold up to two slots — one federation, one local — and the daemon prefers local when both peers share a local relay.

This is the OSS coordination layer that no vendor would build because it doesn't sell anything: Anthropic / OpenAI / Google can each ship a within-product agent-coordination layer, but none of them can build a cross-vendor, cross-model, operator-owned one without conceding interop. Wire's local relay closes that gap.

**Design summary** (full design in [issue #10](https://github.com/SlanchaAi/wire/issues/10)):

- **`wire relay-server --local-only`** — refuses non-loopback binds (any address outside `127.0.0.0/8` or `[::1]` errors out at startup with a clear message). Skips phonebook listing + well-known agent-card serving — the relay is invisible from off-box and from any phonebook-scraping agent.
- **`wire session new --with-local`** — probes `http://127.0.0.1:8771/healthz` (configurable via `--local-relay`); if reachable, allocates a second slot there and writes both endpoints into the session's `relay_state.json` `self.endpoints[]` array. Falls back to federation-only when the local relay isn't running (logged loudly, not silently).
- **`endpoints[]` data model** — new `src/endpoints.rs` module with `Endpoint { relay_url, slot_id, slot_token, scope }` + `EndpointScope::{Federation, Local}` + `peer_endpoints_in_priority_order` (local-first when both have it) + `pin_peer_endpoints` (preserves v0.5.16 legacy top-level fields for back-compat readers).
- **`pair_drop` body carries `endpoints[]`** — `cmd_add` advertises all our endpoints on the way out; `maybe_consume_pair_drop` + `cmd_add_accept_pending` pin every advertised endpoint via `pin_peer_endpoints`. The v0.5.14 bilateral gate still applies — capability flows only after operator consent on both sides.
- **`cmd_push` walks endpoints in priority order with fallback** — local first if we share a local relay, federation second, transparent fallback on transport error. Each pushed event records which endpoint delivered it in the `--json` output (`endpoint` + `scope` fields).
- **`cmd_pull` reads from every endpoint** — per-scope cursors (`last_pulled_event_id` for federation, `last_pulled_event_id_local` for local — independent so they don't trample each other). One endpoint's failure doesn't kill the pull; loud-fail log + continue against remaining endpoints. Inbox dedup by event_id is the last line of defense.

**Back-compat**: pure additive. v0.5.16-and-earlier clients see only the legacy top-level `relay_url` / `slot_id` / `slot_token` (which point at the federation endpoint, unchanged). New `endpoints[]` field travels alongside. Old peers ingest cleanly; old `relay_state.json` files migrate transparently when the dual-slot path is exercised.

**Threat-model addendum** ([`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)):

- *Local relay implicit trust*: any process on the same machine that can connect to `127.0.0.1:8771` can attempt to deposit a pair_drop. Mitigated by the v0.5.14 bilateral gate (no auto-pin, no auto-ack). Same defense surface as federation.
- *Loopback ≠ secret*: on a multi-user box, other users can bind 127.0.0.1 sockets too. Don't run `--local-only` on a shared box without socket-permission hardening. (Unix-domain socket with `0600` mode would close this; v0.5.17 ships HTTP loopback only.)
- *No TLS on local relay*: bytes travel cleartext over loopback. Acceptable on a single-user laptop (same as any localhost HTTP); document explicitly.

**Tests**: **156 lib + 35 CLI tests passing** (+7 endpoints unit tests — back-compat, dual-slot ordering, local-relay-mismatch filtering, legacy-field synthesis, etc).

**Recommended setup**:

```bash
# Once per machine — start a local-only relay at login.
wire relay-server --bind 127.0.0.1:8771 --local-only &

# Once per project — create a session with dual slots.
cd ~/Source/your-project
wire session new --with-local
eval $(wire session env)
```

Sister-Claudes in different projects on the same box now pair through wireup.net (bilateral) once, then automatically route follow-up traffic through `127.0.0.1` because both sides advertise local endpoints during the pair handshake.

**Open follow-ups for v0.5.18+** (from the design issue #10):

- `wire service install --local-relay` — write a launchd plist (macOS) / systemd user unit (Linux) so the local relay auto-starts at login. v0.5.17 ships manual startup; the service-install convenience is one PR away.
- `wire session pair-all-local` — discover sister sessions via the local relay's directory and bilateral-pair them in one shot. Closes the "N sessions = N² accept gestures" UX pain.
- Unix-domain socket transport — for multi-user-box hardening. The dual-slot machinery already abstracts the endpoint URL; switching local from `http://127.0.0.1:8771` to `unix:/path/to/socket` is mostly a `reqwest` feature flag.

### v0.5.16 — `wire session` for multi-agent-per-machine

When multiple agent sessions ran on the same box (e.g. one Claude Code in `~/Source/wire`, another in `~/Source/slancha-mesh`) they shared a single `WIRE_HOME` — one DID, one slot, one inbox JSONL, one daemon. Peers had no way to address a specific session and cursor advances by either session drained events the other never saw.

**`wire session` subcommand.** Bootstraps isolated per-session `WIRE_HOME` trees under `~/.local/state/wire/sessions/<name>/`. Each session = own identity + own relay slot + own session-local daemon + own inbox/outbox. Sessions pair with each other through any relay (`wireup.net` by default) like any other peer — the bilateral-pair gate from v0.5.14 still applies.

- `wire session new [name]` — bootstrap. With no name, derives one from `basename(cwd)` and caches it in a registry so re-entering the same project reuses the same identity instead of generating a fresh DID each time. Runs `init` + `claim` + spawns the session-local daemon. Outputs the `export WIRE_HOME=…` line for shell activation.
- `wire session list [--json]` — enumerate sessions with handle, DID, daemon liveness, and registered cwd.
- `wire session env [name]` — emit the export line; `eval $(wire session env)` activates the cwd's session.
- `wire session current` — which session does this cwd map to?
- `wire session destroy <name> --force` — kill the daemon + delete state + remove from registry. Irrecoverable (keypair gone).

**Stable per-project identity.** Registry at `~/.local/state/wire/sessions/registry.json` maps `cwd → session_name`. Different cwds with the same basename get a 4-char SHA-256 path-hash suffix.

**Recommended Claude Code setup.** Project-local `.mcp.json` points wire at that project's session via `env.WIRE_HOME=…`. New Claude Code sessions in the same project all share that session's identity; sessions in different projects stay isolated. See `docs/AGENT_INTEGRATION.md#multi-session-on-one-machine-v0516` for the full recipe.

**New module + tests.** `src/session.rs` with path/registry logic + name derivation. **149 lib + 35 CLI tests passing** (+4 session unit tests, +6 session integration tests).

No protocol or schema changes. No relay-side changes. Backwards-compatible: operators who don't use `wire session` keep their existing single-session WIRE_HOME behavior unchanged.

### v0.5.15 — operator-friendly accept surface

Companion patch to v0.5.14. Same bilateral-pair design intent; surfaces the *accept* gesture explicitly across CLI, MCP, README, AGENT_INTEGRATION.md, and the landing page so operators don't have to remember the overloaded `wire add <peer>@<their-relay>` form.

- **`wire pair-accept <peer>`** — explicit CLI alias for bilateral completion. Same semantics as `wire add <peer>@<their-relay>` when a pending-inbound record exists, but takes only the bare handle (relay coords come from the stored drop). The natural operator-side counterpart to `wire pair-reject`.
- **MCP `wire_pair_accept` / `wire_pair_reject` / `wire_pair_list_inbound`** — three new tools so agents can drive the inbound queue end-to-end on the operator's behalf. The MCP `instructions` field is updated to explicitly tell connecting agents: *never auto-accept inbound pair requests without operator consent*.
- **OS toast text** updated to surface both `wire pair-accept` and the `wire add` form (and `wire pair-reject`).
- **`wire pair-list` + `wire pair-list-inbound`** human output now prints `wire pair-accept <peer>` action hints (was `wire add <peer>@<relay-host>`).
- **`wire status`** human-readable inbound line now says `wire pair-accept <peer> to accept`.
- **README** rewritten: section §2 (pair flow) now shows the bilateral two-command flow with both sides; install line bumped to v0.5.15; `wire pair-accept` + `wire pair-list-inbound` added to "What's in the box".
- **landing/index.html** §3 "The console" demo terminals updated to show both sides: B runs `wire add`, A sees OS toast + runs `wire pair-accept`. §2 blockquote updated. §5 MCP table updated with the new tool list.
- **`docs/AGENT_INTEGRATION.md`** adds a "Bilateral pair flow via MCP (v0.5.14)" section with the explicit step-by-step + the "agents must never auto-accept" rule.
- **Tests:** +1 new — `pair_accept_errors_cleanly_when_no_pending_request_v0_5_14` asserts the error message points operators at `wire pair-list-inbound` / `wire add` rather than failing silently. 145 lib + 29 CLI tests passing.

No protocol or schema changes. Pure surface polish on the v0.5.14 security fix.

### v0.5.14 — bilateral-required `wire add` (security)

Closes the v0.5.13-and-earlier **phonebook-scrape pairing vulnerability**: a malicious actor could enumerate the public handle directory, run `wire add <each-handle>@<relay>` against every entry, and have their key auto-pinned at `VERIFIED` tier on every wire user's machine — receiving each victim's `slot_token` via the `pair_drop_ack`, which granted authenticated write access to the victim's slot up to the 64 MB quota.

This release restores the design intent: **`wire add` must fire on both sides before the pair completes.** The receiver's daemon no longer auto-promotes a stranger's signed pair_drop; it lands in a new pending-inbound queue, surfaces via `wire pair-list` + OS toast, and waits for an explicit operator gesture.

**Receiver-side gate (the root fix).** `maybe_consume_pair_drop` was bifurcated:

- *SPAKE2 invite-URL path* (pair_drop carries a pre-shared `pair_nonce`): unchanged. Possession of the invite-URL nonce IS the consent gesture; pin trust, write relay_state, send ack as before.
- *Handle path* (zero-paste `wire add`, no nonce): write to new `state/wire/pending-inbound-pairs/<handle>.json` store. **Do NOT pin trust. Do NOT write our slot_token back. Do NOT advertise relay coords.** OS toast prompts the operator to run `wire add <peer>@<their-relay>` to accept or `wire pair-reject <peer>` to refuse.

**Operator-side completion.** `cmd_add` now checks pending-inbound on every invocation:

- If a pending-inbound record exists for the target handle: bilateral completion. Pin peer as `VERIFIED` with stored coords, send `pair_drop_ack` carrying our slot_token, delete the pending record.
- Otherwise: outbound path (unchanged) — emit signed pair_drop via `/v1/handle/intro/<nick>`, await reciprocal `wire add` from peer.

**New surface.**

- `wire pair-accept <peer>` — explicit bilateral-completion alias for `wire add <peer>@<their-relay>` when a pending-inbound record exists. Same semantics, no relay-host argument needed (coords come from the stored drop). The operator-friendly accept command.
- `wire pair-reject <peer>` — drop a pending-inbound record without pairing. Idempotent.
- `wire pair-list-inbound [--json]` — programmatic enumeration of pending-inbound records (flat array, matching the v0.5.13-and-earlier `pair-list --json` shape for SPAKE2 sessions).
- `wire pair-list` — human-readable output now shows a `PENDING INBOUND` section first with `→ accept with…` action hints, followed by the SPAKE2 session table. **JSON shape unchanged** for back-compat (flat array of SPAKE2 records); inbound items remain accessible via the new commands above.
- `wire status` — `pending_pairs.inbound_count` + `inbound_handles` JSON fields. Human-readable line: `inbound pair requests (N): alice, bob — …` with action hints.

**MCP tools (v0.5.14).** Three new bilateral-pair tools for agents:

- `wire_pair_list_inbound` — enumerate pending-inbound requests for operator review.
- `wire_pair_accept` — accept after operator consent; pins VERIFIED + ships slot_token.
- `wire_pair_reject` — refuse a pending-inbound request without pairing.

The MCP server's `instructions` field now explicitly tells connecting agents: **never auto-accept inbound pair requests without operator consent**. `docs/AGENT_INTEGRATION.md` documents the bilateral pair flow recipe (lines added under "Bilateral pair flow via MCP (v0.5.14)").

**Attack surface after v0.5.14.** An attacker scraping the phonebook and spraying pair_drops produces N records in N victims' pending-inbound queues, **zero VERIFIED pins, zero slot_token leaks, zero spam capability**. Each victim sees one OS toast per attacker; victims who don't manually `wire add` back are fully protected. Inviting a friend zero-paste still works in exactly two commands (one from each side), preserving the v0.5 magic-pair UX.

**Tests:** 145 lib + 28 CLI tests passing (+4 new pending-inbound tests in `tests/cli.rs` — `pair_list_inbound_surfaces_pending_v0_5_14`, `status_reports_pending_inbound_count_v0_5_14`, `pair_reject_deletes_pending_inbound_v0_5_14`, `pair_reject_idempotent_on_missing_peer_v0_5_14`).

**Threat-model addendum:** see THREAT_MODEL.md for the bilateral-pair doctrine + remaining residual windows (third-leg ack race documented in [issue #5](https://github.com/SlanchaAi/wire/issues/5)).

### v0.5.13 — silent-fail eradication round 2 + network resilience

Three threads landed together in response to issues #2 and #6 against v0.5.12:

**A. Issue #2 — outbox + doctor silent-fail bugs.**

- **`P0.A1` outbox filename normalization.** `wire send paul-mac@wireup.net "..."` used to write `outbox/paul-mac@wireup.net.jsonl`, but `wire push` only enumerates files matching pinned peer handles (`paul-mac.jsonl`). 4 events stuck silently for 25 minutes in the field report. New `agent_card::bare_handle` helper strips `@<relay>` at the `cmd_send` and `tool_send` boundaries; on-disk contract (`outbox/<bare_handle>.jsonl`) is now the single source of truth. Adversarial test: `send_with_fqdn_peer_normalizes_to_bare_handle_outbox` asserts FQDN-suffixed file is never created.
- **`P0.A2` outbox orphan-file warning.** `wire push` now scans the outbox dir for `.jsonl` files whose stem isn't a pinned peer; if the bare handle of the stem matches a pinned peer, prints a loud stderr line with the exact `cat … >> …` recovery command. Catches the upgrade path where stale pre-v0.5.13 FQDN files sit on disk.
- **`P0.A3` doctor/status agreement.** Pre-v0.5.13 `wire doctor` ran a pure pgrep count and PASSed "one daemon running" even when that one daemon was an orphan and the pidfile's recorded daemon was dead — `wire status` correctly reported DOWN in the same state. 25 minutes of disagreement before the operator caught it. `check_daemon_health` now consults both pgrep AND the structured pidfile, with explicit FAIL verdicts for the orphan-only and orphan-alongside-pidfile states. Status and doctor cannot disagree on liveness.

**B. Issue #6 — network resilience doctrine.** Three-rule policy now in code:

- **Rule 1: loud transport error class.** New `relay_client::format_transport_error` flattens the `anyhow::Error` source chain and prefixes a class label (`TLS error:`, `DNS error:`, `timeout:`, `connect error:`). `wire push --json` now surfaces the full `invalid peer certificate: UnknownIssuer` instead of the bare URL that hid the TLS failure in Avast/corp-proxy environments. Unit tests cover TLS / DNS / timeout / fallback paths.
- **Rule 2: OS native trust store.** Cargo.toml `reqwest` feature flag `rustls-tls` → `rustls-tls-native-roots`. Both blocking client builders (`relay_client.rs`, `daemon_stream.rs`) now load OS native CAs via `rustls-native-certs`, so corporate proxies, AV cert-resign products, and on-prem CAs validate without manual trust-store gymnastics. No code-side opt-in needed; works on macOS / Linux / Windows.
- **Rule 3: documented escape hatch.** New `WIRE_INSECURE_SKIP_TLS_VERIFY` env var (recognized values: `1` / `true` / `yes` / `on`). When set, builds reqwest clients with `danger_accept_invalid_certs(true)` AND prints a loud red stderr banner exactly once per process. Last-resort operator override for `--insecure` MITM-accepted environments. Documented in THREAT_MODEL.md.

**C. No protocol or schema changes.** v3.1 event envelope unchanged; all existing peers stay paired across the upgrade.

### v0.5.12 — metadata hygiene

Patch release pinning the `slancha-wire` crate rename + repointing crate metadata to live URLs.

- **Cargo.toml `name`** stayed `slancha-wire` (from post-`v0.5.11` rename commit). `v0.5.11` tag predated the rename, so the tag did not match the published artifact on crates.io. `v0.5.12` is the first tag that pins the renamed-and-published state.
- **`homepage` + `documentation`** repointed from `https://wire.slancha.ai` (DNS not yet provisioned — `wire` subdomain doesn't resolve) to the GitHub repo. The previous values shipped a broken link in crates.io metadata.
- No code changes. `wire --version` reports `0.5.12`.

### v0.5.11 — silent-fail eradication + one-command surface

A 30-minute debug session on 2026-05-15 ate four `pair_drop` events because an old `wire daemon` process (PID 54017, started Monday, never restarted) was running stale 0.2.4 binary text in memory under a symlink that had since been repointed at 0.5.10. Cursor advanced past the new-protocol events the old code couldn't process, no log, no rejected entry, no diag. Today's exact pain became this release.

**Six-command public surface.** What 0.5.10 took multiple steps + a manual debug, 0.5.11 does in one command:

- `wire up <nick@relay>` — fresh box to ready-to-pair. Replaces init + bind-relay + claim + daemon-background + remember-to-restart-on-login.
- `wire pair <nick@relay>` — bilateral pin, blocks until VERIFIED or hard-error with cause. Replaces add + poll + wait + verify cycle.
- `wire send <peer> "msg"` — kind defaults to `claim`. Stdin form via `-`. Replaces send-with-mandatory-kind-arg.
- `wire monitor` — long-running line-per-event stream of new inbox events, handshake filtered by default. Replaces `tail -F inbox/*.jsonl | python parse | grep -v pair_drop`.
- `wire doctor` — single diagnostic across daemon + pidfile + relay + pair-rejections + cursor. Replaces 30-minute manual debug.
- `wire upgrade` — kill stale daemons, spawn fresh from current binary, write new versioned pidfile. The fix for today's exact failure mode.

**Silent-fail eradication (the load-bearing fix).**

- **P0.1** — `wire pull` refuses to advance the relay cursor past events the binary can't process (unknown kind, transient verify failures like sender-not-in-trust). Same blocking event surfaces on every retry with `unknown_kind=<N> binary_version=<v>` reason. Today's exact bug class made visible.
- **P0.2** — every `let _ = ...` and `.ok()` drop in pair/relay/push paths replaced with structured warn + a record in new `pair-rejected.jsonl` for `wire doctor` to surface. The bilateral-pin-stalls-invisibly class.
- **P0.3** — `flock` on `relay.json` via new `config::update_relay_state(modifier)`. Multiple wire processes can no longer race the cursor — RMW transactions serialise through the lock.
- **P0.4** — daemon pidfile becomes a versioned JSON record: `{schema, pid, bin_path, version, started_at, did, relay_url}`. CLI compares its own version against the daemon's on every invocation. Mismatch = loud warn. Tolerant reader handles legacy raw-int form for one transition cycle.
- **P0.Z** — every signed event now carries a `schema_version: "v3.1"` field. Pull rejects mismatched-major with locked reason shape `schema_mismatch=<received> binary_supports=<ours>`. Absent field accepted (pre-0.5.11 compat).
- **P0.X** — inbox dedupe on `event_id`. Three duplicate `pair_drop_ack` deliveries no longer produce three inbox lines.

**Operator-visible UX.**

- **P0.M** — `wire monitor` plus an AGENT_INTEGRATION.md recipe + MCP server's `instructions` field tells every agent harness to arm a persistent stream-watcher on session start. Catches "agent didn't notice your message" silently before it happens.
- **P0.Y** — `wire peers` / `wire status` show `PENDING_ACK` for peers we've pinned but haven't received an ack from. No more misleading `VERIFIED` before bilateral pin completes.
- **P0.S** — `wire send` drops mandatory kind arg + accepts `-` stdin / heredoc.
- **P1.6** — `wire doctor` with five checks (daemon, daemon_pid_consistency, relay reachable, pair rejections, cursor).
- **P1.7** — `wire status` cross-checks pidfile with `pgrep -f "wire daemon"`; surfaces orphan daemon processes the pidfile didn't record + version drift loudly.
- **P1.9** — `wire service install` writes the launchd plist (macOS) or systemd user unit (linux) that auto-starts the daemon on login + restarts on crash. Eliminates the "background it with tmux/&/systemd as you prefer" footgun.
- **P2.10** — optional structured diagnostic trace at `$WIRE_HOME/state/wire/diag.jsonl`. `wire diag tail` replays. Off by default; enable per-process via `WIRE_DIAG=1` or per-machine via `wire diag enable`.

**By the numbers.** 14 atomic commits, 140 lib tests passing (was 105 at 0.5.10), one pre-existing integration failure on `detached_pair_full_e2e_with_real_daemons` (fails on the v0.5.10 base commit too — unrelated to this release). Every fix above has an adversarial test that asserts the silent failure is loud, per spark's E. rule. The whole release was paired with `slancha-spark@wireup.net` over wire/v3.1 itself — feedback shaped P0.4 pidfile schema (added `did` + `relay_url`), the schema_mismatch reason shape, and the verified=null monitor-filter guard.

Co-developed with slancha-spark@wireup.net via wire/v3.1.

### v0.5.10 — launch-surface polish + real bug fixes

Pile of small wins from launch-day real-world testing. Server-side new
endpoints, install-script reliability fixes, and a real bug fix in
client-side handle parsing.

**New endpoints on the relay (one binary, no extra services):**

- `GET /stats.html` — parchment-themed dashboard matching landing
  aesthetic, with live counts + 24-hour SVG sparklines for handle
  claims, slot allocations, pair opens, events posted. Auto-refreshes
  every 30s.
- `GET /stats.history?hours=<N>` — append-only JSONL time series at
  `<state_dir>/stats-history.jsonl` (one row per 30s persist tick),
  sliced to the requested window. Default 24h, max 7d.
- `GET /phonebook.html` — standalone yellow-pages directory page
  (Oswald display + Bitter serif + classic yellow background).
  Alphabetical letter dividers, per-entry nick + DID fingerprint +
  motto + vibe tags.
- `GET /openshell-policy.sh` — host-side bootstrap symmetric to
  `/install.sh`: applies the OpenShell network policy a sandbox needs
  to install + run wire.
- `POST /v1/invite/register` + `GET /i/<token>` — short-URL invite
  redirector. `wire invite --share` (new CLI flag) gives the invitor a
  single line — `curl -fsSL https://wireup.net/i/AB12 | sh` — to text
  to a friend; that line installs wire if missing + accepts the invite
  + pairs both sides. `?format=url` returns the raw `wire://pair?...`
  string for programmatic resolution.
- `GET /v1/handles` filters `demo-*` and `test-*` nick prefixes from
  the public phone book (asciinema-cast leftovers were polluting it).

**Short URLs + content negotiation:**

- `/stats` now dispatches on `Accept`: browsers get the HTML dashboard,
  curl/scripts keep getting JSON (back-compat preserved). `/stats.json`
  is a new explicit JSON alias.
- `/phonebook` (no `.html`) and `/install` (no `.sh`) added as cleaner
  social-share-friendly URLs. Old paths still work.
- Cross-page nav tabs (home · phonebook · stats) on all three
  landing pages.

**Install-script robustness:**

- Drops the `api.github.com/repos/.../releases/latest` lookup, which
  hit the anonymous 60 req/hr rate limit on shared NATs (corporate
  proxies, OpenShell sandboxes). Uses GitHub's
  `/releases/latest/download/<asset>` 302-redirect alias instead.
- Detects musl libc on Linux (Alpine, distroless, immutable distros)
  and picks the `unknown-linux-musl` artifact accordingly. The musl
  binaries already shipped in release.yml; install.sh just wasn't
  reaching for them.

**`wire accept` short-URL resolution:**

- `wire accept https://wireup.net/i/<token>` resolves the HTTPS short
  URL via `?format=url` and recurses with the underlying `wire://`
  URL. Previously errored with "url missing inv=" because accept only
  understood the wire:// scheme. Bare wire:// URLs still work.

**Diagnostic + error-message polish (most-hit-in-real-life paths):**

- `wire init --relay` / `wire bind-relay` / `wire rotate-slot` healthz
  pre-flight now surfaces the underlying reqwest error (`{e:#}`)
  instead of `unwrap_or(false)`-collapsing into a generic phyllis
  line. When curl works but wire doesn't, the actual cause (TLS, DNS,
  connect refused, 5xx) finally appears in the error. Also includes a
  curl reproducer + an OpenShell-policy bootstrap hint.
- `wire status --peer <name>` on an unpaired peer now hints the next
  move (`wire add <name>@wireup.net`) instead of a bare
  "unknown peer X in relay state".
- All relay URLs are trimmed of trailing slashes before display
  (`https://wireup.net/` and `https://wireup.net` now produce the same
  error message and the same state-file value).
- `tests/e2e_invite_pair.rs` + `demo-invite.sh` finish the v0.5.7
  DID-suffix sweep that had two leftover `did:wire:paul` (no hex)
  assertions.
- `src/signing.rs::strip_did_wire` marked `#[allow(dead_code)]` (kept
  for a v0.6 caller; was tripping clippy's `-D warnings` in CI).

**Real bug fix in client-side handle parsing:**

- `parse_handle` previously rejected any nick in `RESERVED_NICKS`,
  which — after the v0.5.10 RESERVED_NICKS expansion to include the
  pre-claimed org handles `slancha`, `support`, `abuse`, etc. — made
  those handles unreachable by clients (`wire add slancha@wireup.net`
  failed at PARSE time, before resolution). Split into:
  - `nick_syntax_ok` — length + chars only, used at parse / resolve.
  - `is_valid_nick` — syntax + reservation check, used at CLAIM
    sites (relay `handle_claim`, CLI `cmd_claim`).
  Reserved handles can now be RESOLVED freely; only CLAIMS are
  blocked. All 11 pair_profile tests pass.

**Misc:**

- `landing/og.png` + `twitter:image` / `og:image` meta tags for
  social-link previews.
- README rewritten as a marketing surface (shield badges, "by Slancha"
  attribution, modern handle flow as Quick Start, older flows demoted
  under "Alternative flows").
- Discord invite rotated to permanent `https://discord.gg/dv2Cd3xzPh`.
- Cargo fmt sweep over the v0.5.9 → v0.5.10 churn.

### v0.5.9 — directory + R2/R3/R5 + consent design + cleanup

Operator-visible health now has three layers. `wire send --deadline` adds an
optional signed `time_sensitive_until` field for advisory wall-clock urgency.
`wire responder set/get` lets an operator publish auto-responder health to the
relay, and `wire status --peer <handle>` reports transport reachability, peer
attention freshness, and responder health in one place.

Relays now publish a local phone book at `GET /v1/handles`, with pagination,
case-insensitive `vibe` filtering, and profile-level opt-out via
`wire profile set listed false`. The landing page's "Now ringing" section
fetches that endpoint and renders the first 20 listed handles.

The A2A extension URI moved from the old GitHub namespace to
`https://slancha.ai/wire/ext/v0.5`. Wire is still pre-traction enough for the
clean migration; extension URIs remain opaque identifiers matched exactly by
federation peers.

`/stats` now separates `handle_claims_total` from
`handle_first_claims_total`, so repeated same-DID profile or slot re-claims no
longer inflate the public growth number.

`docs/CONSENT_DESIGN.md` records wire's current stance on cross-machine agent
handoff: wire owns transport, identity is separate, and consent stays
receiver-policy-first until real cross-org delegation pressure justifies a
portable token format.

`src/macaroon.rs` adds speculative, standalone macaroon-style scoped
delegation scaffolding with mint/verify/serialize tests. It is not wired into
the relay, CLI, or event envelope in v0.5.9.

### v0.5.8 — Repo moved to SlanchaAi/wire + DID-suffix call-site sweep

Repo transferred from `github.com/laulpogan/wire` to
`github.com/SlanchaAi/wire`. Old URL auto-redirects for ~12 months;
existing clones can `git remote set-url` to migrate. Stars, forks,
releases, issues, PRs all preserved.

URL updates:
- `Cargo.toml` repository field
- `install.sh` REPO_URL + help text
- README, AGENT.md, CHANGELOG, all *.md files
- `.github/workflows/release.yml` comments
- `landing/index.html` (Slancha-served)
- relay's A2A AgentCard provider URL

PRESERVED (do not change — federation contract):
- `https://github.com/laulpogan/wire/ext/v0.5` — wire's A2A extension
  namespace URI. A2A extension URIs are opaque identifiers, not
  forwardable URLs. Comments added in `relay_server.rs` and
  `pair_profile.rs` explaining why this string MUST stay as the
  original `laulpogan` namespace forever, even though the repo moved.
  Federation peers in the wild match on this exact string.

DID-suffix call-site sweep: v0.5.7's DID change to pubkey-suffixed
form (`did:wire:paul-abc12345`) updated agent-card construction and
the most-visible verify/whoami paths, but ~10 other call sites still
did raw `did.strip_prefix("did:wire:")` and got the suffixed form
back. This caused trust-map (keyed by bare handle) vs relay-state
(keyed by suffixed string) to disagree on the same peer — the
`wire_add_zero_paste_e2e` test caught it: A's daemon consumed B's
`pair_drop` and pinned B in trust as "night-train" but in relay-state
as "night-train-xxxxx", so `wire peers` showed nothing.

Fixed by replacing `did.strip_prefix("did:wire:").unwrap_or(...)` with
`crate::agent_card::display_handle_from_did(...)` at every "extract
handle from DID for routing" site:
- `src/pair_invite.rs` — 4 sites (peer_handle in pair_drop consume,
  peer_handle in accept_invite, our_handle in mint_invite + accept,
  peer_handle in pair_drop_ack consume)
- `src/pair_session.rs` — 2 sites (handle in pair_session_open,
  peer_handle in pair finalize)
- `src/pair_profile.rs` — 1 site (local_handle in whois display)
- `src/mcp.rs` — 2 sites (peer_handle + our_handle_str in wire_add
  tool)
- `src/cli.rs` — 3 sites (post-pair "wire send" print hint,
  peer_handle in cmd_add, our_handle in cmd_add)

The internal `strip_did_wire` helper in `signing.rs` stays raw — it's
used only for canonical signature comparison where the exact DID
string (including any suffix) is the payload.

Tests: `wire_add_zero_paste_e2e` now passes (was failing on v0.5.7
due to the trust-vs-relay-state mismatch). Full suite green.

### v0.5.7 — DID collision fix + R7 listener-lifetime docs

**DID collision bug.** Pre-v0.5.7 DIDs were `did:wire:<handle>` — derived
purely from the human handle the operator typed at `wire init`. Two
operators picking the same handle (or two homes on the same hostname
auto-init'ing from `default_handle()`) produced **identical DIDs**
despite different keypairs. Cryptographic signature verification still
worked (sigs verify against the pubkey, not the DID string), but every
identifier that routed by DID string — peer-map keys, inbox file paths,
trust-map lookups — was ambiguous.

v0.5.7+ DIDs are `did:wire:<handle>-<8-hex-of-sha256(pubkey)>`. Pubkey
suffix is appended at card-build time, so the DID is uniquely tied to
the keypair by construction. Two operators sharing the handle `paul`
get distinct DIDs `did:wire:paul-a12b34c5` and `did:wire:paul-9f8e7d6c`.

Schema changes:
- `did_for_with_key(handle, public_key)` — new constructor, returns
  pubkey-suffixed DID. Used at `wire init`, `wire claim`, agent-card
  build, trust-self-pin.
- `did_for(handle)` — legacy constructor kept for backward-compat
  test fixtures + display helpers. New code should use the keyed form.
- `display_handle_from_did(did)` — strips both the `did:wire:` prefix
  and the v0.5.7+ pubkey suffix when present, returning the bare
  handle for filesystem paths, trust-map lookups, OS toast titles.
  Auto-detects legacy vs v0.5.7+ DID format.
- Agent card gains a top-level `handle` field (mutable display name)
  separate from `did` (immutable identifier). Identifier-extraction
  sites that previously did `did.strip_prefix("did:wire:")` are
  updated to prefer `card.handle` and fall back to
  `display_handle_from_did`.

Backward-compat: legacy DIDs of the form `did:wire:paul` continue to
verify signatures (the verify path reads pubkey from `verify_keys`).
display_handle_from_did handles both forms transparently. No state
migration required for pre-v0.5.7 deployments.

Call sites updated:
- `src/cli.rs` — cmd_init, cmd_status, cmd_whoami, cmd_send,
  cmd_pair_initiate, inbox-write path in run_sync_pull
- `src/mcp.rs` — tool_whoami, tool_status, peer-listing
- `src/pair_session.rs` — init_self_idempotent
- `src/signing.rs::verify_message_v31` — handle extraction for trust
  lookup
- `src/trust.rs` — add_self_to_trust now uses keyed DID;
  add_agent_card_pin prefers card.handle
- `tests/cli.rs`, `tests/e2e_handle_pair.rs`, `tests/e2e_bilateral.rs`
  — assertions updated to accept pubkey-suffixed DIDs

**R7 listener-lifetime docs.** From the 2026-05-12 incident report:
agents conflating /loop iteration teardown with wire listener teardown
cause exactly the silent-channel problem the incident root-caused.
Added AGENT.md section codifying:
- Monitor (Claude Code) / SSE subscriber is session-lifetime, not
  loop-iteration-lifetime
- Do NOT TaskStop a listener as part of /loop teardown between cycles
- v0.5.6+ daemons include the SSE subscriber for free; running
  `wire daemon` IS the listener, no separate Monitor needed

Tests: 162+ pass on changed surfaces (lib + cli + relay + handle-pair
+ bilateral). `tests/e2e_detached_pair.rs` has a pre-existing local-
only flake on this Spark machine (verified pre-existing on clean
v0.5.4 HEAD and unchanged by v0.5.7); CI in clean container has been
green through v0.5.4 → v0.5.6.

Deferred to v0.5.8: R2 (`time_sensitive_until` field), R3
(responder-health events), R5 (3-layer health distinction in
`wire status --peer`). These were originally scoped into v0.5.7 but
split out to keep the DID fix bisectable.

### v0.5.6 — R1 phase 2: daemon subscribes to the SSE stream

Second half of R1 from `docs/INCIDENT_REPORT_2026_05_12_AGENT_ATTENTION_LAYER.md`.
Builds on the v0.5.5 relay-side SSE endpoint. The daemon now opens its
own slot's stream on startup and uses it as the wake signal for the
polling loop. End-to-end effect: a peer's `wire send` reaches the
recipient's local inbox in tens of milliseconds — at least as long as
the receiver has `wire daemon` running. The 5-second polling cadence
(and the 25-minute /loop-iteration cadence that triggered the
2026-05-12 incident) become irrelevant for any connected peer.

How it works:
- New `src/daemon_stream.rs` module — spawns a dedicated thread on
  daemon startup that opens `GET /v1/events/<own_slot>/stream` against
  the operator's configured relay using their own `slot_token`. The
  thread parses SSE `data:` lines as they arrive and signals a
  `std::sync::mpsc::channel` on every event.
- Daemon main loop replaces `std::thread::sleep(interval)` with
  `wake_rx.recv_timeout(interval)` — sleeps until either (a) the next
  poll-interval tick OR (b) a stream wake-up, whichever comes first.
  On wake, the loop drains any accumulated wakes (multiple stream
  events coalesce into a single pull) and runs the normal
  `run_sync_push` + `run_sync_pull` + `pending_pair::tick` cycle.
- Polling stays in place as the safety net. Stream-down does NOT mean
  events-down — the regular interval still ticks and re-fetches via
  `list_events`. If the stream errors or disconnects, the subscriber
  reconnects with exponential backoff (1s → 2s → 4s → 8s, capped 30s).
- One-way wake signal, not the data path. The actual event verify +
  inbox write goes through `run_sync_pull` so we keep signature
  verification, dedup, and trust enforcement on the exact same path as
  polling. The stream only changes WHEN pull runs, not HOW.

Failure model:
- Relay restart: stream closes cleanly, subscriber reconnects in 1s.
- Network partition: read returns `Err`, backoff retry to 30s cap.
- Daemon hasn't been paired yet (`relay-state.self` empty): subscriber
  errors with "relay-state missing", sleeps for backoff, retries — by
  the time `wire claim` or `wire pair` populates state, the next
  reconnect picks it up automatically. No daemon restart required.
- `wire daemon --once` (one-shot CI mode): subscriber thread is NOT
  spawned. Single-cycle behaviour unchanged.

MCP integration (free): the inbox-watcher introduced in v0.2.0 fires
`notifications/resources/updated` on every new line written to
`state/wire/inbox/<peer>.jsonl`. With v0.5.6 the daemon now writes to
inbox in ~10ms instead of ~5s, so a connected Claude Code session
subscribed to `wire://inbox/<peer>` sees the same near-real-time push.
No new MCP tool needed — `wire_subscribe` is unnecessary because the
existing resource-subscription path is now stream-driven.

Operator-visible:
- Running `wire daemon` now logs occasional `daemon-stream: ...` lines
  on connect/disconnect/reconnect for observability.
- Pulls fire on stream events rather than (just) every 5s, so the
  "pulled=N" log lines come in bursts matching peer activity instead
  of at clockwork intervals.
- `wire daemon --once` unchanged (CI use case).

Tests: 48+ pass on changed surfaces (relay/cli/mcp_pair/handle_pair
suites). e2e_detached_pair has a pre-existing local-only flake on this
Spark machine (verified pre-existing on clean v0.5.4 HEAD); CI runs in
a clean container and was green on v0.5.4 + v0.5.5.

### v0.5.5 — R1 phase 1: server-sent-events push stream on relay

First half of R1 from the agent-attention-layer postmortem
(`docs/INCIDENT_REPORT_2026_05_12_AGENT_ATTENTION_LAYER.md`). Eliminates
the polling-cadence floor for connected peers: when peer B opens an SSE
stream against their own slot, every `post_event` from peer A reaches B
in milliseconds instead of waiting for B's next ~5s daemon pull.

New protocol surface:
- `GET /v1/events/:slot_id/stream` — Server-Sent Events endpoint, auth'd
  by `slot_token` (same gate as `list_events`). Returns
  `Content-Type: text/event-stream`. On open the relay registers an
  `UnboundedSender` on the slot's subscriber list; every subsequent
  `post_event` to that slot fans out the event as `data:
  <event-json>\n\n`. The connection stays open until the client
  disconnects.
- Keepalive comment `phyllis: still on the line` emitted every 30s so
  Cloudflare tunnel + nginx don't time-out the upstream.
- Subscriber sees events posted AFTER it subscribed. To catch up on
  history first, clients should `GET /v1/events/:slot_id?since=` before
  opening the stream — same model as Kafka/Redis pubsub.

Implementation:
- Inner state gains `streams: HashMap<String, Vec<UnboundedSender>>` —
  per-slot active subscriber channels. `post_event` walks the
  subscriber list after a successful disk persist and broadcasts; dead
  channels (peer disconnected) are pruned lazily on `tx.send` returning
  `Err`.
- Disk-persist runs BEFORE broadcast, so durable stream readers and
  cold-start `list_events` readers observe the same set of events.

Deferred to v0.5.6:
- Daemon-side subscriber loop (`wire daemon` opens the stream on its own
  slot, falls back to polling on disconnect with exponential backoff).
- `wire daemon --stream-only` flag for no-poll operation when the stream
  is reliable.
- MCP-side `wire_subscribe` tool that surfaces stream events as
  `notifications/resources/updated` to connected Claude Code sessions
  (closes R1 in full).

Tests: 162+ pass (160 previous + 2 new SSE tests in tests/relay.rs):
- `sse_stream_pushes_event_to_subscriber` opens stream, posts event,
  asserts the event_id arrives on the SSE response within 2s.
- `sse_stream_rejects_wrong_token` asserts 403 on missing/wrong auth.

Operator-visible: nothing today. Daemon still polls. The endpoint is
live on prod (`https://wireup.net/v1/events/<slot_id>/stream`) for
external tools (MCP servers, watchdogs, custom integrations) to consume
now. Daemon adoption ships in v0.5.6.

### v0.5.4 — R4: `wire send` attentiveness pre-flight + phyllis voice on hot errors

From the 2026-05-12 agent-attention-layer incident report (R4 in
`docs/INCIDENT_REPORT_2026_05_12_AGENT_ATTENTION_LAYER.md`): when sending
to a peer, the CLI now does a best-effort relay probe of the peer's slot
freshness and warns the operator on stderr if the peer hasn't pulled
recently. Never blocks the send.

New protocol surface:
- `GET /v1/slot/:slot_id/state` on the relay — auth'd by slot_token,
  returns `{event_count, last_pull_at_unix}`. Updated on every
  `list_events` call.
- `RelayClient::slot_state()` — best-effort client probe; HTTP failures
  return `(0, None)` so the pre-flight degrades gracefully.

New CLI behaviour: `wire send <peer>` checks the peer's slot state and
emits one of:
- silent if peer pulled within last 5 min
- `phyllis: <peer> hasn't picked up in Nm — message will queue, but they
  may be away.` if last pull > 5 min ago
- `phyllis: <peer>'s line is silent — relay sees no pulls yet.` if peer
  has never pulled

The send always queues the event to the outbox. The warning is advisory
— exactly the signal the operator needed in the 2026-05-12 incident
where peer's auto-responder was OAuth-broken and silently dropping
inbound for 10 hours while wire transport stayed green.

Also rolls in the **phyllis voice** rewrite of the six hottest user-
facing error strings (per BRAND_BRAINSTORM.md §9): handle validation,
relay healthz failure, slot not claimed, slot already taken, SAS digit
mismatch, outbox empty. Tests updated to match new vocabulary.

162 tests pass (160 + 2 new slot_state tests).

### v0.5.3 — Bugfix: `wire claim` is actually one-step

Caught by live-smoke against the production relay: `wire claim <nick>` on a
fresh `WIRE_HOME` (no prior `wire init`, no prior `wire bind-relay`) was
bailing with `error: no slot allocated; run \`wire bind-relay <url>\` first`.
That breaks the "ONE STEP" UX promise of v0.5 — the operator-facing pitch
since v0.5.0 has been *single command, zero prior setup*. v0.5.0 → v0.5.2
shipped this gap.

`cmd_claim` in `src/cli.rs` now calls `pair_invite::ensure_self_with_relay()`
exactly the way `cmd_add` and `cmd_pair` already did — auto-init identity if
missing, auto-allocate relay slot if missing, then claim. Idempotent on
already-initialized homes.

New regression test `claim_from_fresh_home_one_step` in
`tests/e2e_handle_pair.rs` codifies the invariant so future refactors
re-introducing the bail-on-uninit check fail CI immediately.

Operator-visible: a brand-new install can now do `wire claim
coffee-ghost@wireup.net` and have everything (identity, slot, handle) come
into existence in one command, exactly as advertised. Same fix is already
in MCP-tool form via `wire_claim`.

### v0.5.2 — Rebrand to wireup.net + Cargo.toml bump

Default relay URL bumped from `wire.laulpogan.com` to `wireup.net` across `pair_invite.rs::DEFAULT_RELAY`, `cli.rs` `--relay` defaults (3 commands), `pair_profile.rs` doc-comments and tests, `mcp.rs` tool descriptions, `README.md`, `AGENT.md`, `SPEC_v0_5.md`, `TESTING_FOR_FRIENDS.md`, `AWESOME_LISTS.md`, `LAUNCH_POSTS.md`, `COMPETITIVE_v0_5.md`, and the landing site. Cloudflare tunnel `wire` now routes `wireup.net` + `relay.wireup.net` to the same relay backend, with `wire.laulpogan.com` + `relay.laulpogan.com` kept alive indefinitely as legacy aliases (no forced migration; v0.4 deployments still work).

Smoke against prod: `curl https://wireup.net/healthz` → 200, `curl https://wireup.net/.well-known/agent-card.json?handle=<nick>` → A2A AgentCard with wire extension, `curl https://relay.wireup.net/healthz` → 200. Both legacy hostnames still 200.

Also rolls in the missed `Cargo.toml` version bump that should have shipped alongside the v0.5.1 + v0.5.2 feature commits but didn't — manifest is now `0.5.2` to match commit-message claims. Single tag at this commit covers both the federation work (v0.5.1) and the rebrand (v0.5.2).

### v0.5.1 — Client-side A2A AgentCard consumption

`resolve_handle()` now tries `/.well-known/wire/agent` first, falls back to A2A's `/.well-known/agent-card.json` on 404, and looks for a wire extension under standard `extensions[].params`. Wire becomes a citizen of the A2A v1.0 ecosystem both as **server** (serves A2A schema with wire fields under extensions) and **client** (consumes A2A cards from any v1.0 implementation: MSFT Agent Framework, agent-card-go, agent-card-python, A2A .NET SDK).

If the A2A card has a wire extension, full mailbox pairing works. If not, wire returns a degraded payload — still useful for `wire whois` display, but `wire add` refuses cleanly because there's no relay slot to drop into.

New: `RelayClient::well_known_agent_card_a2a()`, `pair_profile::verify_wire_native_payload`, `pair_profile::unwrap_a2a_to_wire_payload`.

Bidirectional interop with the 150+ orgs shipping A2A integrations. Federation strategy in `COMPETITIVE_v0_5.md`.

### v0.5.0 — Three-layer identity: DID + handle + profile

What ships:
- **`pair_profile.rs`** module — handle parser (`nick@domain`, 2-32 lowercase chars, reserved-nick list), profile schema, write+sign, `resolve_handle()` via remote `.well-known/wire/agent`.
- **Relay handle directory** — `POST /v1/handle/claim` (bearer-auth'd by slot_token, FCFS on nick, same-DID re-claims allowed for profile/slot rotation), `POST /v1/handle/intro/:nick` (auth-free pair-intro endpoint, gated to kind=1100 `pair_drop` / `agent_card`), `GET /.well-known/wire/agent?handle=<nick>` (WebFinger-style resolver returning signed card + slot coords).
- **CLI** — `wire claim <nick>` to register, `wire whois <nick@domain>` to resolve, `wire profile set/get/clear <field> <value>` to edit personality, `wire add <handle>` for the headline zero-paste pair.
- **MCP tools** — `wire_add`, `wire_claim`, `wire_whois`, `wire_profile_set`, `wire_profile_get`. Agents express personality + discover peers without operator paste.
- **Bilateral close-the-loop** — daemon-pull consumes nonce-less `pair_drop`s (open-mode policy, default on, opt-out via `policy.json: { accept_unknown_pair_drops: false }`), pins the peer, then emits `pair_drop_ack` (kind=1101) carrying our slot_token. Sender's daemon consumes the ack and completes the bidirectional pin. Both sides can `wire send` after ~1-2 seconds.
- **e2e tests** — `tests/e2e_handle_pair.rs` covers full `wire add` flow + FCFS conflict (159 tests pass).
- **demo-hotline.sh** — 5 agents with distinct vibes (coffee-ghost 👻, tide-pool 🌊, kuiper 🛰️, bramble 🪴, marginalia 📖) claim handles, build a fully-meshed 5-graph via 10 zero-paste `wire add`s, ring-send signed messages. New CI `demo-hotline` job.

Trust model: pair-by-handle anchors on DNS + relay `.well-known` (operator who owns `wireup.net` decides who maps to `<nick>@wireup.net`). Same texture as Mastodon — handle ownership = domain ownership. Pubkey is canonical underneath; the handle is renameable without breaking peer references.

Backward compatible with v0.4 invite URLs and v0.3 SPAKE2 + SAS — both flows remain available. Spec: `SPEC_v0_5.md`.

What's deferred to v0.5.1+: petnames (Nostr NIP-02 local nick overlay), `now` field auto-update from MCP tool calls, handle rotation events, `wire rename` for renaming with broadcast.

## v0.4 — one-paste invite pair

The v0.4 line collapses pairing from a 4-step ceremony (host code, join, voice-compare SAS, type digits on both sides) into a single paste. Operator on A runs `wire invite`, gets a URL. Operator on B runs `wire accept <URL>`. Done. Both pinned. Equivalent UX to Discord invite link / Zoom join URL / Signal group invite.

### v0.4.0 — Invite URL: single-step pair, zero-config bootstrap

`wire invite` mints a self-contained bearer URL carrying A's signed agent-card, relay coords, slot_token, and a single-use pair_nonce. The token format is `wire://pair?v=1&inv=<urlsafe_b64_payload>.<urlsafe_b64_sig>`.

`wire accept <URL>` does everything else: auto-inits the local agent if it isn't yet (hostname-derived handle), auto-allocates a relay slot, pins the issuer from URL contents, then POSTs a signed `pair_drop` event (kind=1100) to the issuer's slot using the slot_token the URL granted. The issuer's daemon recognizes pair_drop events with matching pending_invite nonces, verifies the embedded card sig, and completes the bilateral pin on its next pull cycle. The original SPAKE2 + SAS flow remains available for paranoid operators.

Trust model: pasting the URL is the authentication ceremony. Equivalent to clicking a Discord invite, Zoom join URL, or Signal group invite. Possession of the URL = authorization to pair. Single-use by default; multi-use via `--uses N`. 24h TTL default.

What shipped:
- New `pair_invite.rs` module with mint/parse/accept + daemon-side `maybe_consume_pair_drop` hook.
- `wire invite [--relay URL] [--ttl N] [--uses N] [--json]` CLI command.
- `wire accept <URL> [--json]` CLI command.
- MCP tools: `wire_invite_mint`, `wire_invite_accept`. Zero-config from agent prompts.
- Daemon pull loop consumes `pair_drop` events before trust check; pins sender atomically with trust + relay-state writes.
- Bug fix in daemon-pull cursor persistence: in-loop relay-state writes (e.g., new peer pins) were being clobbered by the cursor-update write at end-of-loop. Both `wire pull` and `wire daemon` paths now re-read state before writing the last-pulled-event-id cursor.
- 3 e2e integration tests: full one-paste pair, zero-config B-side auto-init, expired-invite rejection.

What's deferred to v0.5: `consumed_at` field on relay push response (helps disambiguate "stored but not pulled" from "delivered + pulled"); registry-based discovery for true zero-coordination peer lookup.

## v0.3 — detached pair (daemon-orchestrated)

The v0.3 line addresses the original blocking-foreground UX in v0.2: pair-host/-join used to block the operator's terminal for up to 5 minutes waiting for the peer to show up. Now the handshake runs in the background under `wire daemon`, and three push channels — OS toasts, MCP `notifications/resources/updated`, daemon stderr log — surface SAS digits when ready.

### v0.3.9 — `wire status` shows daemon + pending pair counts
Quick operator diagnosis: `daemon: running (pid 12345)` or `DOWN`, plus `pending pairs: 2 (polling=1, sas_ready=1)`. JSON output gains `daemon` and `pending_pairs` keys.

### v0.3.8 — Multi-pair concurrent stress test
Codifies the per-code isolation invariant of `pending_pair::LIVE_SESSIONS`: paul (1 daemon) hosts 2 concurrent detached pairs with alice + bob, each gets distinct SAS digits, all four confirm cleanly, both pair-list entries drain. 141 tests pass.

### v0.3.7 — Real-daemon e2e test
Codifies the manual public-relay smoke test as cargo: two long-running `wire daemon` subprocesses + local relay drive the full detached flow via CLI. ~3.5s wall clock. DaemonGuard's Drop catches daemon-leak bugs.

### v0.3.6 — `--json` on detached CLI + AGENT.md MCP detached section
`--json` flag added to `pair-host --detach`, `pair-join --detach`, `pair-list`, `pair-confirm`, `pair-cancel`. Same shape as MCP tool responses. AGENT.md gains an MCP detached-pair section listing the 5 new tools and the subscribe-once pattern.

### v0.3.5 — 5 detached-pair MCP tools
`wire_pair_initiate_detached`, `wire_pair_join_detached`, `wire_pair_list_pending`, `wire_pair_confirm_detached`, `wire_pair_cancel_pending`. Agents can now drive the full detached flow via MCP without shelling out. Includes integration test covering initiate → list → wrong-digits-abort → right-digits-confirm → cancel.

### v0.3.4 — Detached pair abort-toast + terminal-file GC + live e2e
OS toast on aborted transitions (handshake error, digit mismatch, daemon-restart) so the operator sees the failure even if the originating terminal closed. Terminal-state files older than 3600s are GC'd on each tick. Live e2e on wireup.net validated end-to-end (paul ↔ willard VERIFIED + signed send/recv).

### v0.3.3 — Auto-start daemon + MCP push test + `wire pair --detach`
`pair-host --detach` and `pair-join --detach` now call `ensure_daemon_running()` before queuing — no more "did you forget to run `wire daemon`?" foot-gun. `wire pair <handle> --detach` mega-command added. New MCP push integration test verifies subscribing to `wire://pending-pair/all` actually fires notifications on status transitions.

### v0.3.2 — Pending pairs push into live MCP agents
`resources/list` advertises `wire://pending-pair/all`. The MCP watcher thread polls the pending-pair directory each 2s, tracks per-code status fingerprints, and emits exactly one `notifications/resources/updated` per real transition. Connected agents see the SAS in chat without polling.

### v0.3.1 — Daemon pushes pair SAS to desktop
OS toast fires on `polling → sas_ready` ("wire — pair SAS ready (30-XYZ) · Digits: 554-002 · wire pair-confirm 30-XYZ 554002") and on `confirmed → paired`. Extracted the existing per-platform toast functions into a new `os_notify` module shared with `wire notify`.

### v0.3.0 — Detached pair: daemon-orchestrated push UX
The big one. `wire pair-host --detach` writes a pending-pair file and exits in ~10ms. The daemon's tick loop drives the handshake through a 6-state state machine (`request_host` → `polling` → `sas_ready` → `confirmed` → finalized). Confirm via `wire pair-confirm <code> <digits>` from any terminal. New `pair-list`, `pair-cancel`, `pair-host --detach`, `pair-join --detach` commands. SPAKE2 secret lives in daemon memory; restart-recovery via PID file marks transient sessions `aborted_restart` so the operator re-issues with a fresh code.

---

## v0.2 — friction patches from real-world install attempts

The v0.2.6 → v0.2.9 hot-fix line was driven by a cross-org pair attempt with `willard-spark` (Windows host) that surfaced bugs the local dogfooding missed.

### v0.2.9 — pair-join/host emit waiting heartbeat every 10s
Both sides used to go silent during `pair_session_wait_for_sas`. Now `... still waiting (10s / 300s)` lines fire so the operator sees the process is alive while the peer connects.

### v0.2.8 — `wire pair-abandon` for stuck-slot recovery
If a client crashes mid-handshake (process killed, OOM, network blip) after `pair_open` succeeded but before SAS, the relay-side slot used to stay bound for the 5-minute TTL — subsequent `pair-join` attempts hit 409 "guest already registered". New `wire pair-abandon <code>` + relay endpoint `POST /v1/pair/abandon` releases the slot. Idempotent.

### v0.2.7 — `wire pair <handle>` single-shot bootstrap
Collapses the four-step bootstrap (`init` + `pair-host`/`pair-join` + `setup --apply`) into one. Default relay baked in. Idempotent identity init.

### v0.2.6 — Windows install + correct Claude Code config path
Two real bugs caught by `willard-spark` from a Windows install (Git Bash):

1. `install.sh` had no Windows branch — Windows operators had to `gh release download` manually. Patch detects MINGW/MSYS/CYGWIN/Windows_NT and appends `.exe`.
2. `wire setup --apply` was writing to `~/.config/claude/mcp.json` — that path doesn't exist for Claude Code on ANY platform. Claude Code reads `~/.claude.json` everywhere. Now surfaces both paths as targets.

---

## v0.2.5 and earlier

See git history. Highlights: v0.2.5 introduced reactor anti-loop guards (rate-limit + chain-depth via `(re:X)` marker tracking). v0.2.0–v0.2.4 brought MCP pair tools, push notifications via `wire://inbox/*` resources, `wire setup`, `wire notify`, and `wire reactor`.
