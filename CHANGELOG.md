# Changelog

All notable changes to wire are tracked here. Format: 
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), 
semver-ish.

Generated from git tag annotations; for richer context see 
the PR description linked in each section.


## [Unreleased]

### Added

- **Nostr NIP-01 relay protocol — client⇄relay message framing** (#227 D3.2b-i, RFC-007): the JSON-array messages a Nostr relay speaks, on top of the D3.2a event codec. `nostr_relay` models client→relay (`EVENT` publish, `REQ` subscribe with a `Filter`, `CLOSE`) and relay→client (`EVENT`, `OK`, `EOSE`, `CLOSED`, `NOTICE`) messages with pure serialize/parse. `Filter` carries the fields wire needs (`#p` to pull events addressed to its npub, `kinds`, `since`, …) and omits empties. Unknown relay message types parse to `RelayMessage::Unknown` rather than erroring, so a relay extension can't wedge the read loop. Pure + offline; 9 unit tests cover the NIP-01 message shapes, the missing-OK-message tolerance, forward-compat, and malformed-input rejection. The `NostrWs` WebSocket that carries these messages over `wss://` (+ the `Transport` trait its first impl defines) is the **D3.2b-ii** slice — where the async websocket dependency + a relay-mock integration test enter.

- **Nostr NIP-01 event codec — wire events ⇄ Nostr events** (#227 D3.2a, RFC-007): the protocol heart of the Nostr transport, building on the D3.1 dual-key binding. `nostr_event::wire_to_nostr` packs a signed wire event into a NIP-01 event — `id = sha256([0,pubkey,created_at,kind,tags,content])`, schnorr-signed by the D3.1 secp transport key — carrying the **full signed wire event in `content`** so its inner Ed25519 signature survives intact. `verify_and_decode` authenticates the transport hop (recompute id + verify schnorr) and hands back the inner wire event. The result is a **two-signature chain**: the outer secp/transport sig proves "this npub sent it", the D3.1 binding proves "this npub is that `did:wire`", and the inner Ed25519 sig proves "that did authored it" — no single signature load-bearing alone, identity anchor stays Ed25519. Pure + offline; 7 unit tests lock the NIP-01 serialization, roundtrip, and tamper/forge rejection. The `NostrWs` WebSocket transport + `Transport` trait that carry these events over `wss://` are the **D3.2b** slice; NIP-44 DMs (D3.3) and NIP-W1 pairing + live-relay e2e (D3.4) follow.

- **Nostr transport binding — the dual-key identity foundation** (#227 D3.1, RFC-007 / curve spike Option 1): the first slice of speaking Nostr. An agent can now mint a **transport-only** secp256k1 key (`wire enroll nostr`) that is cross-signed by its Ed25519 identity and carried as an additive `nostr_pubkey` card field. The curve spike resolved the Ed25519↔secp256k1 gap to **dual-key, never derived** (scalar-reuse across curves is the anti-pattern SLIP-0010 exists to prevent), so the secp key is a *transport endpoint, never an identity anchor* — the ONE-NAME invariant holds (`did:wire` stays the only name). The binding is **mutual**: the Ed25519 identity signs `wire-nostr-binding-v1|<session_did>|<npub_hex>` ("this npub is my Nostr transport") AND the secp key schnorr-signs the same message (proof-of-possession), so a card can't squat someone else's npub. `wire whoami` surfaces the npub only when the binding verifies. Fully offline + additive (a session with no transport key is byte-identical to before; pre-binding cards unaffected). Crypto core is unit-tested (roundtrip, wrong-identity, npub-squat-without-possession, tamper); the producer flow is covered by `tests/it/110-nostr-binding.sh`. This unblocks the rest of RFC-007 D3 — the `NostrWs` WebSocket transport (D3.2), NIP-44 DMs (D3.3), and NIP-W1 pairing + live-relay e2e (D3.4) — which remain the follow-up slices.

- **Same-machine signed attestation — your own sessions on one box auto-pair, cryptographically** (#182, RFC-001 amendment): wire already auto-pinned *sister sessions* by reading their card off local disk, but that filesystem witness is weak — anything that can write the data-dir tree could mint a "sibling". Now an op-enrolled session carries a `same_machine_attestation` on its card: the operator root key (`op_sk`) signs `wire-same-machine-v1|<fingerprint_hex>|<session_did>`, where the fingerprint is `sha256(machine_id ‖ os_user_id ‖ tag)`. A receiver auto-pins the sender at **`ORG_VERIFIED`** only when (a) the peer's op-chain verifies, (b) its `op_did` equals the receiver's own (same operator — and because a wire `op_did` is a key commitment, that forces the same op key), (c) the attestation's fingerprint **byte-equals the receiver's own** freshly-recomputed one (a remote sender can't know it without already being on the box; per-OS-user salt blocks cross-user pairing on shared hosts), and (d) the signature verifies. Never crosses into `VERIFIED` (that still needs the bilateral SAS gesture). New verb **`wire enroll fleet-link [--dry-run] [--rotate-machine]`** batch-attaches the attestation to every enrolled sibling session; idempotent (the signed message is deterministic). Field-additive — pre-v0.15 receivers tolerate the field as an opaque extra. Producer + receiver + crypto core are unit-tested (incl. hostile-forge and different-uid rejection); the verb is covered by `tests/it/100-fleet-link.sh`. Deviations from the amendment doc (sha256 vs blake2b; domain-separated string payload reusing the audited cert path; `id -u`/`whoami` for the uid salt; the plugin-hook auto-dispatch left as a tracked follow-up) are documented in `src/same_machine.rs`.

- **Rotation-refresh: an already-trusted peer that rotates its relay slot re-pairs automatically** (#15): a rude slot rotation (no `wire_close`) used to leave peers holding a now-`410` slot, and re-pairing required a fresh **manual `wire accept`** on the receiver. Now a re-intro from a peer whose **DID is already pinned at a consented tier** (we accepted *that exact identity*) is treated as a transport refresh — the receiver's daemon re-pins their new endpoints and re-acks (restoring the write-token) with **no manual accept**, tier unchanged. Safe: keyed on the full DID with the verified card signature + the #245 collision guard, so only the real key-holder triggers it; a first-contact stranger still goes to pending-inbound (consent gate unchanged). (Sender-side auto-trigger of the re-intro on a `slot_stale` send — so no manual `wire dial` is needed at all — is a tracked follow-up on #15.)

- **`wire ping <peer>` — connection health probing (RFC-004 Tier-1)** (#142): liveness-probe a paired peer and get the round-trip time. The peer's **daemon auto-responds** — no LLM / MCP on the responder side (RFC-004's AC-HP2 kill criterion). Probe + ack ride the existing `kind=100` heartbeat carrier with a body `t` discriminator (`probe`/`probe_ack`), not a new top-level kind; they're plaintext (only a correlation nonce) and trust-neutral (never mutate a tier). Per-peer ack rate-limit bounds a probe flood (AC-HP3). Validated end-to-end (`tests/it/80-health-probe.sh`). Tier-2 (`responder_state` introspection), `wire health` rendering, and MCP `wire_ping` parity are tracked follow-ups.

### Security

- **Relay: backstop ceilings on slot / handle / pair / invite counts** (#291 H1): the relay's in-memory maps (and their persistence files) grew without bound — an unauthenticated client could `allocate_slot` (or open pairs / register invites) in a loop to exhaust RAM + disk. Allocating handlers now refuse with `503` once a generous ceiling is reached (200k slots / 100k handles / 50k pairs / 50k invites); same-DID handle re-claims are exempt (they don't grow the map). The remaining #291 items — per-IP rate keying (currently global; deferred-behind-WAF + fiddly across the UDS path) and governing/paginating the read endpoints — stay tracked.

### Added

- **`wire unclaim` + relay `DELETE /v1/handle/claim/:nick` — release a claimed handle** (#247 finding 1): a handle claim was FCFS-**permanent** (no expiry, no unclaim), so an abandoned/rotated nick squatted the directory forever. You can now release your persona: `wire unclaim` (owner-gated by your slot token) frees the nick so it stops resolving via `.well-known/wire/agent` and can be re-claimed. (Operator-TTL auto-expiry — the other half of #247.1 — needs persisted slot-activity to avoid evicting quiet-but-live agents on relay restart, and stays tracked.)
- **`wire status --wait-daemon-running [--timeout <secs>]`** (#284.2): a bounded, in-process replacement for fragile external shell loops like `until wire status … | grep -q 'daemon_running":true'; do sleep 3; done`. The external pattern + a never-healthy daemon piled up 254 stale `wire.exe` processes on Willard's box (each `wire status` invocation hanging on a wedged probe, the loop spawning a fresh one every 3s). The new flag polls the daemon-liveness snapshot every 200ms in-process, exits 0 with the full status when `daemon_running:true`, or bails after `--timeout` (default 30s) with the last-seen `pidfile_pid` / `pgrep_pids` on stderr so the operator knows what wasn't healthy. Replaces the loop with one bounded subcommand call; no spawn pressure, no orphan accumulation. Pure-logic `wait_step` decision is split out and unit-tested.

### Fixed

- **Relay: per-nick `/v1/handle/intro` rate limit closes the unauthenticated pair-intro flood** (#247 finding 3): the intro endpoint is unauthenticated by design (a stranger drops a pair-intro), and was protected only by the shared per-slot byte quota — so an attacker could flood a known nick's slot to `MAX_SLOT_BYTES` (~25s) and DoS the victim (the global governor doesn't help: it throttles everyone and 10/s × 256 KiB still fills 64 MB in ~25s). Intros to a given nick are now capped (5 per 5 min, sliding window) → `429` over the limit.

- **Trust pins are no longer lost-updated under concurrency** (#246): #288 made each `write_trust` atomic, but a foreground pin (`wire add`/`accept`) and the daemon's pull-path pin could still each `read_trust` → modify → `write_trust` from the *same* snapshot, dropping one of the two pins (last-write-wins). New `update_trust` read-modify-write transaction holds the `trust.lock` across the whole read+modify+write (mirroring `update_relay_state`); the concurrent pin call sites (pair-invite, `wire add`/accept, sister-pair, MCP accept/dial) now route through it.

- **Trust pins can no longer be hijacked by a grindable nick collision** (#245, partial): the trust store is keyed by the peer's persona nick, which is a deterministic function of the keypair over a ~65k word-list — so an attacker could grind keys (or simply spoof a card's `handle` field) until their nick matched a victim's, then OVERWRITE the victim's pin with their own DID + keys, hijacking the nick (the real victim's messages then fail signature verify, the attacker's verify as the victim). `add_agent_card_pin` now **refuses** to overwrite an existing nick whose pinned `did` differs from the incoming card's `did` (DIDs carry the key fingerprint, so they're not grindable to match a *specific* full DID; same-identity re-pins / key-succession keep the DID, so legitimate updates pass). The complete fix — re-keying the whole store by DID so two distinct identities that collide on a nick can *coexist* — remains tracked on #245.

- **`relay.lock` acquisition is now bounded + stale-owner-reclaimable** (#284.5): a hung wire daemon (or any wire process stuck in a relay long-poll — see #284.1) held `relay.lock` indefinitely, since the kernel only releases the flock at PID exit and the wedged process never exited. Every subsequent `wire status` / `wire send` / `wire daemon` then blocked on `lock_exclusive()` forever; on Windows this was the engine behind the 254-`wire.exe`-process pile-up Willard's SessionStart `until wire status …` loop spawned. The acquire path now (1) opens + `try_lock_exclusive` non-blocking; (2) on contention, reads the owner PID from a new `relay.lock.owner` sidecar and consults a pure-logic classifier — if the owner is dead/absent it retries immediately (the OS auto-released the flock on PID exit), if the owner is live it bounded-exponential-backoffs up to `WIRE_RELAY_LOCK_TIMEOUT_SECS` (default 10s) and then fails with the holder PID surfaced in the error so `wire doctor` can name a target. The sidecar pattern is needed because Windows `LockFileEx` denies reads to other handles against the locked file, so "who holds this?" can't be read out of `relay.lock` itself. No behavior change in the uncontended fast path.
- **`warn_on_identity_collision` now actually catches collisions on Windows** (#247 finding 4): the v0.6.10 collision check shelled out to POSIX `pgrep` and read `/proc/<pid>/environ` to compare `WIRE_HOME` between live wire processes — both POSIX-only, so Windows silently no-op'd. Two `wire mcp` servers in the same cwd shared one identity, raced the inbox cursor, and operators burned hours on "they look identical." The enumerator now routes through `crate::platform::find_processes_by_cmdline` (the existing PowerShell + `Get-CimInstance Win32_Process` adapter), and the cross-process `WIRE_HOME` lookup on Windows walks `list_sessions()` × every inbox-owning role's pidfile (`<session_home>/state/wire/<role>.pid`) and reverse-maps the candidate PID to its serving home. To make that reverse-map work for every role — not just daemon — `wire mcp`, `wire monitor`, and `wire notify` now drop their own `<role>.pid` on startup via a new `ensure_up::write_self_role_pid`, mirroring what `write_self_daemon_pid` has always done for the daemon. Pure-logic `find_home_for_pid` is split out and unit-tested; the path-based reader is `session::session_role_pid(home, role)`. POSIX path is unchanged (still `/proc/<pid>/environ` / `ps -E`).
- **`wire status` / `wire up` / `wire doctor` are now bounded on a wedged probe path** (#284.1): the Windows process-enumeration shell-outs in `platform.rs` (`Get-CimInstance Win32_Process` and `tasklist`) had no timeout, so any wedged CIM call — observed on Willard's box where 254 stale `wire.exe` processes piled up under heavy WMI contention, but the same shape on any corrupted CIM repository — blocked every CLI command that ran a process probe forever. A new `crate::platform::run_with_timeout(cmd, dur)` wraps every Windows shell-out in this module: spawn, hand `wait_with_output` to a reader thread, `recv_timeout` on the main thread, kill the wedged child by PID on timeout via `taskkill /F /T /PID`. Default 5s, overridable via `WIRE_PLATFORM_TIMEOUT_SECS`. On timeout each call falls through to its existing tool-error fallback (empty Vec, `None`, `false`) so the caller sees "no answer" instead of hanging forever, and `wire status` / `wire doctor` return promptly with whatever local state is readable.
- **`wire upgrade` prebuilt-download path no longer hangs silently** (#284.3): the toolchain-free update path called `resp.bytes()`, which blocks until the entire release binary lands with zero stderr output. On Willard's Windows host that looked indistinguishable from a hard hang — no progress, no error, mtime unchanged, even though crates.io and github.com were both reachable. The download now streams in 64 KiB chunks and prints a `wire upgrade: downloaded N / TOTAL bytes (PCT%)` line in-place every ≤500ms, so an operator sees forward motion (or sees it stall) instead of staring at a frozen terminal. The existing 120s wall-clock timeout on the blocking reqwest client stays as the hard backstop. Pure-logic `format_download_progress` is split out and unit-tested (clamps percent at 100 on overshoot; falls back to "unknown size" when `Content-Length` is missing or zero).
- **Long-running wire roles now warn (or fail-fast under `WIRE_STRICT_SESSION=1`) when the launcher dropped the session key** (#284.4): if a child process inherits neither `WIRE_HOME` nor `WIRE_SESSION_ID` (and no host-adapter env like `CLAUDE_CODE_SESSION_ID`), the session adapter falls through to a freshly-minted per-process key (MCP) or to the machine-default identity (CLI), and the operator only learns about it minutes later when they notice a sibling daemon racing the inbox cursor. Each of the four inbox-owning entry points (`wire mcp`, `wire daemon`, `wire monitor`, `wire notify`) now calls a new `crate::session::warn_if_unexpected_session_source(role)` at startup: it forces a clear stderr line naming the resolved source (`machine-default` / `minted`) and the remediation (set `WIRE_SESSION_ID` or `WIRE_HOME`), and — when `WIRE_STRICT_SESSION=1` is set — exits with code 2 instead of letting downstream init/bind block on a shared lock or quietly corrupt a sibling session's state. Pure-logic `is_unexpected_session_source` predicate is unit-tested across every adapter label.
- **Windows local dev — `cargo test` / `cargo clippy` gates now compile clean** (developer-experience hygiene): three small Windows-only pre-existing breakages blocked any local TDD on a Windows host. (1) `config::tests::private_key_is_mode_0600` used unix-only `PermissionsExt::mode()` without a `cfg(unix)` guard, failing to compile under `cargo test --lib` on MSVC. (2) `cli::upgrade::tests::no_shadow_warning_when_active_symlink_resolves_to_current_exe` declared `let link` that's only used inside its `#[cfg(unix)]` symlink call, triggering `unused_variables` on Windows. (3) `cli::lifecycle` had a collapsible-if pattern in the Windows-only `taskkill` enumerator and an `unneeded_return` on the Windows-only `purge_binary_and_shell` branch, both firing clippy under `-D warnings` on MSVC. All three are test/scaffold-only, no runtime behavior change; CI's `install-smoke-windows` job is untouched.
- **`wire_whoami` (MCP) flags `stale_binary` when the server's code has drifted from the daemon** (#247 finding 5): a long-lived `wire mcp` server keeps serving the binary it was spawned from, so after `wire upgrade` swaps the daemon it silently runs pre-upgrade code in memory (the "ghost identity" drift behind today's 0.14.1-vs-0.16.0 confusion). `wire_whoami` now compares the baked `server_version` against the live daemon's recorded version and emits `server_version`, `daemon_version`, and on mismatch `stale_binary:true` + a note to `/mcp` reconnect.
- **`peer_unknown` on a send now says WHY, and the MCP `wire_send` schema exposes `queue`** (#284 parts 6-7): a VERIFIED/pinned peer whose relay slot had an empty `slot_token` (the `pair_drop_ack` hadn't landed — common right after a daemon/MCP restart) returned the misleading "peer not pinned — run wire dial." The reason is now classified against live state — *not pinned* vs *pinned but no endpoint* vs *pinned but slot has no token* — and points at the **full `<peer>@<relay>` dial** (the bare nickname reports `already_pinned` without re-registering the slot). Separately, the MCP `wire_send` tool documented `queue:true` but omitted it from its input schema (the handler already supported it) — now exposed.

- **Relay: validate claimant `relay_url`, harden `responder-health` path, correct a false rate-limit comment** (relay security audit): `POST /v1/handle/claim` now rejects a `relay_url` that isn't clean `http(s)://host[:port]` — no userinfo (`handle@relay`), no alternate scheme — so a poisoned `endpoint` can't be planted in the public A2A directory. `POST /v1/slot/:slot_id/responder-health` now validates `slot_id` shape before using it in a filesystem path (defense-in-depth). The `handle_intro` doc comment that wrongly claimed governor coverage is corrected — that route is unauthenticated and ungoverned (per-nick intro rate-limit tracked in #247.3).

- **`wire whois` / `wire dial` / `wire add` now surface the resolved DID + key fingerprint and refuse a poisoned card** (#247 finding 4): relay-mediated discovery was trusted implicitly — a malicious/compromised relay could serve a card under someone else's DID pre-pair. These verbs now print the resolved key fingerprint with a "verify out-of-band — discovery is trusted for routing, not identity" reminder, surface `fingerprint`/`fingerprint_matches_did` in `--json`, and **hard-refuse the pair** when the card's advertised key doesn't hash to the fingerprint baked into its claimed DID.

- **`wire upgrade` no longer corrupts systemd/launchd units after a `cargo install` in-place replace** (#274): the kernel marks the replaced running binary's `/proc/self/exe` with a trailing ` (deleted)`, which was written verbatim into `ExecStart=`, leaving the daemon flapping forever (`error: unrecognized subcommand '(deleted)'`). The exe path is now resolved (marker stripped) before it reaches a unit file.
- **`wire upgrade` no longer false-warns about a PATH shadow when the active PATH entry is a symlink to the upgraded binary** (#276): the same `(deleted)` marker made `current_exe()` un-canonicalizable, so the symlink never matched and an "off-PATH / old binary" warning fired even though both PATH entries resolved to the freshly-upgraded binary.
- **`wire upgrade --refresh-stale-children` no longer kills stale daemons the supervisor can't respawn** (#275): the flag killed every stale-binary session daemon, but the `--all-sessions` supervisor only respawns sessions it's eligible for (registry-bound OR active within the idle cutoff). A free-floating/unbound+idle session was killed and never brought back — its identity silently stopped syncing while the upgrade reported success. It now kills only the daemons the supervisor will respawn and leaves the rest running, surfacing them (in human + JSON output, `wire status`, and `--check`) as "relaunch manually."
- **`wire claim --relay <URL>` (and `wire add --relay`, accept-invite) now honor the requested relay** (#279): the shared `ensure_self_with_relay` returned any existing self slot regardless of the relay asked for, so `claim --relay wireup.net` reused a loopback primary slot and POSTed the claim to `127.0.0.1`. It now reuses a slot only if it's already on the requested relay, otherwise allocates one there (additively).
- **`wire tail` / the `wire_tail` MCP tool / the `wire://inbox` resource no longer surface raw ciphertext for encrypted DMs they can't decrypt** (#281): an `enc=wire-x25519.v1` body that this build couldn't open (decrypt failed, no key, or an unknown `enc` scheme) was rendered as its raw `{"ct":…}` blob with a green `sig ✓` and no warning — an operator (or a reading agent over MCP) saw gibberish and believed they'd read the message. All three read surfaces now render an explicit `<encrypted DM … run \`wire upgrade\`>` placeholder and set `decryptable:false` (via one shared `enc` predicate). Forward-compatible for any future `enc` discriminator.
- **`wire add <nick>@<domain>` now warns when you are not federation-reachable** (#278): a federation add advertised whatever self slot existed — including a loopback one a remote peer can never reach — and reported `drop_sent` with no hint that the pair could never complete (the peer's `pair_drop_ack` has nowhere to land → permanent `PENDING_ACK`). It now detects a loopback-only self endpoint, warns with remediation (`wire bind-relay` / `wire up`), and surfaces `self_reachable: false` in `--json`.
- **`write_trust` is now atomic + lock-serialized** (#246): the trust store was written with a raw, lockless `fs::write`, so the daemon's pull-path pin and a concurrent foreground `wire add`/`accept`/`promote` could interleave bytes into a torn, unparseable `trust.json` (the same failure class as the relay.json Bug #3). It now writes via flock + tmp+rename, mirroring `write_relay_state`, so every reader sees a whole file. (Read-modify-write lost-updates remain a tracked follow-up under #246.)


## [v0.16.0] — 2026-06-14

**v0.16.0 — the 1.0 format freeze + onboarding cleanup. RFC-006 collapses the two dual on-disk representations into one each; the CLI stops pretending you name your own identity. BREAKING — on-disk session/peer state and a few CLI args changed; `wire nuke` resets a machine.**

Pre-1.0 housekeeping: freeze the on-disk formats so they never need migration, and make the identity surface honest (the crypto names you, not a typed flag). No production users, so it breaks freely.

### RFC-006 — format freeze (collapse the dual representations)

- **Part A — one session store** (#269): sessions live only under `sessions/by-key/<hash>/`; the legacy top-level `sessions/<name>/` layout is gone. A named session keys off its name, an agent session off its session-id — both into the one store. Kills the `cwd → identity` straddle behind the #170/#174 fork-storms. Sessions now surface uniformly by their persona handle.
- **Part B — one peer-routing source** (#268): a peer's relay slot lives only in `endpoints[]`; the flat `relay_url`/`slot_id`/`slot_token` top-level peer fields are gone. Delivery iterates `endpoints[]` with priority failover. (Fixed an `effective_tier` reader missed in the migration that wrongly showed freshly-paired peers as `PENDING_ACK`.)

### Identity surface — init is the sole naming event (#270)

- **No name to type.** Removed `wire init <handle>` (vestigial seed), `wire init --name` / `wire up --name` (these published a free-choice display name ≠ your handle — a one-name violation). Your persona is derived from the keypair at init; the card's display name is the handle, always.
- **One onboarding verb.** `wire up` is the front door; **`wire up --offline`** folds in offline keygen; `wire init` is demoted to an internal primitive users never type.
- `wire session new <name>` kept — that name is a home *locator*, not an identity.

### Stability + security (the v0.15.x backlog, #260)

- Daemon no longer self-aborts on its own singleton pidfile (#263); orphan-daemon detection scoped to the current `WIRE_HOME` (#248); the nuke unit-test no longer tears down the live host service (#243).
- Path-traversal rejected in group ids before any filesystem write (#238); five operator-input/IO error-path bugs in the CLI fixed, TDD'd (#239). DID-key binding gap + fresh-install status orphan fixed (#244/#248).
- Threat-model truth pass — honest D1 DM-sealing posture (#266); landing corrected to v0.15 reality (#264); root decluttered (#265); the 15.7k-line `cli.rs` split into a module tree (#242).

### Testing + release gating

- **Real integration suite** (`tests/it/`): boots actual relays and drives the shipped binary — zero-paste pairing, on-box sister mesh, onboarding, nuke/recovery, group join-by-code cross-member verified read, and federation over a **non-loopback remote relay**.
- New CI jobs: `integration-tests`, `install-script-smoke` (runs the real `install.sh`), and the demo jobs wired into the local `test-env` gate so it mirrors CI.
- `main` is branch-protected: all checks must pass (and be up-to-date) before merge, admins included.


## [v0.15.0] — 2026-06-07

**v0.15.0 — the de-deprecation: every backwards-compatibility surface removed. `wire dial` is now the sole pairing path; agents only ever see canonical verbs. BREAKING — old on-disk state is incompatible; `wire nuke` resets a machine.**

The deprecated surface was actively confusing agents — the MCP tool list advertised legacy `wire_pair_*` tools alongside the canonical verbs, so an LLM picked the wrong one. This release rips out **all** backwards compatibility (RFC-005 + follow-on). No production users, so it breaks freely; the new `wire nuke` is the clean-slate reset.

### New: `wire nuke` (the clean-slate command)

- **`wire nuke`** — hard machine reset: kills daemons + the `--all-sessions` supervisor, removes the launchd/systemd/schtasks service units, **de-registers the `wire` MCP entry from every host config** (Claude Code / Cursor / Copilot / VS Code / OpenCode — so a "fresh" machine doesn't show the agent a dead `wire` server), and wipes all wire dirs. Keeps the binary. `wire nuke --purge` also removes the binary + scrubs shell PATH/env lines (Windows prints the manual `del`). Safety: `--dry-run` → typed-`nuke` confirm → `--force`/`--yes`. New `install-smoke` CI (Linux + Windows) + a reproducible Rust `test-env` container.

### Removed: the deprecated agent + operator surface

- **Deprecated MCP alias tools** — `wire_pair_accept` / `wire_pair_reject` / `wire_pair_list_inbound` (pure aliases of canonical `wire_accept` / `wire_reject` / `wire_pending`) gone from `tools/list`. Old names return a helpful "use `wire_accept`" redirect; canonical verbs are the only thing advertised.
- **Deprecated CLI alias verbs** — `wire pair` (→ `wire dial`), `wire pair-accept` / `pair-reject` / `pair-list-inbound` (→ `accept` / `reject` / `pending`), and the `deprecation_warn` shim. `wire accept <url>` no longer silent-forwards an invite URL — use `wire accept-invite <url>`.

### Removed: the SAS code-phrase pairing flow (the big one)

- The entire **SAS / SPAKE2 / code-phrase / SAS-digit** pairing flow is gone — modules `sas.rs`, `pending_pair.rs`, `pair_session.rs`; CLI `pair-host` / `pair-join` / `pair-confirm` / `pair-list` / `pair-cancel` / `pair-watch` / `pair-abandon`; MCP `wire_pair_initiate` / `join` / `confirm` / `check` + the `_detached` variants. **`wire dial` (relay pair-drop) + bilateral `wire accept` is now the sole canonical pairing path.** Shared identity-bootstrap (`init_self_idempotent`) relocated to `src/init.rs`; the daemon pidfile write relocated to `ensure_up`.

### Removed: dead legacy on-disk formats

- Legacy **bare-integer pidfile** (`PidRecord::LegacyInt`) and the pre-v0.5.7 **no-suffix DID** builder. Version-tolerance shims with no current reader: **v3.1 agent-card** read path, **pre-v0.5.19 relay "discoverable default"**, **v0.4-card profile** default. The redundant `WIRE_QUIET_AUTOSESSION` session.rs check (the TTY check subsumes it).

### Kept (live, not old — see RFC-006)

- The **v0.6 named-session layout** (`wire session new/list/env/destroy` use it; `by-key/<hash>` is a *parallel* agent-resolution layout, not a replacement) and the **flat peer-endpoint fields** (the live invite flow reads/writes them) are current code, not dead shims. Consolidating them to a single representation is a deliberate redesign with the #170/#174 fork-storm risk — tracked in **[RFC-006](docs/rfc/0006-consolidate-dual-representations.md)**, not forced here.

### Operator notes

- **BREAKING:** pre-v0.15 on-disk state (old pidfiles, no-suffix DIDs, v3.1 cards) is no longer read. Run **`wire nuke`** to reset, then `wire up`. Old SAS pairings can't be resumed — re-pair with `wire dial`.
- Full per-PR detail: Phase 1 #220, Phase 2 #231, Phase 3 #232, Phase 4 #233, SAS removal #236. Design: `docs/rfc/0005-remove-backwards-compat.md`.


## [v0.14.2] — 2026-06-05

**v0.14.2 — the multi-session ops batch + the queue collapse: silent-send class closed, `--all-sessions` supervisor architecture lands, four hotfixes caught by live dogfood, send + pull both become synchronous verdict-on-demand verbs.**

honey-pine's 2026-06-01 multi-system dogfood (#162) surfaced an interlocking set of bugs that broke wire's daemon layer on any operator with more than one session: silent send failures, daemon-up-but-not-syncing on launchd, false-negative `wire status`, tier flap, notification storms. Paul (same day): *"why are we dealing with this whole outbox queued delivered thing it's a headache and always breaks can we streamline and collapse steps."* This release closes all of the dogfood bugs AND collapses the send/receive paths so the "queued ≠ delivered" silent-drop class can't reappear in the default surface.

Dozens of PRs since the v0.14.1 tag — the #162 multi-session batch below, plus a launch-hardening + reliability follow-on (see the final subsection). No trust ladder change, no protocol bump (v3.2 still the constant). Operator action required after upgrade: re-run `wire service install` (idempotent) so the launchd plist / systemd unit picks up the new `wire daemon --all-sessions --interval 5` ProgramArguments. `wire upgrade` does this automatically when a service was previously installed.

### Silent-send class closed (honey-pine's #162 bug report)

- **Send-lifecycle log + `pending_push_count` (#167).** Each successful relay POST appends `<outbox_dir>/<peer>.pushed.jsonl` so the caller can audit "queued → pushed" lifecycle. `wire_status` (MCP) now surfaces `pending_push_count` — the count of events in the outbox that have NOT yet appeared in the pushed log. With `stale_sync == true`, that's the diagnostic for the silent-send class honey-pine reported.
- **Canonical `to:` DID on outbound send (#165).** Pre-fix `wire send` wrote `to: did:wire:<peer-handle>` (bare); peers running v0.14.x rejected on `to:` mismatch against their full `did:wire:<handle>-<fingerprint>`. `cmd_send` / `tool_send` now resolve the canonical pinned DID via the new `trust::resolve_peer_did`. This was THE silent-drop root cause; honey-pine's "BUG 1" closed.
- **Durable `bilateral_completed_at` field stops tier flap (#166).** `effective_peer_tier` previously read slot_token presence to compute "VERIFIED vs PENDING_ACK". Re-pinning peer endpoints (which legitimately rewrites the slot_token block) made the tier flap. `bilateral_completed_at` is set monotonically on receipt of pair_drop_ack; never cleared. `pin_peer_endpoints` preserves it across re-pin events.
- **Daemon-down lifecycle visibility (#163).** Per-process pidfile singleton guard with same-pid Drop preservation. `last_sync.json` written after every cycle so `wire_status` can report `last_sync_age_seconds` distinct from "any `wire daemon` process exists".
- **Send response includes `daemon_seen` + `stale_sync` (#164).** `wire_send` (MCP) annotates its response with daemon-health hints so a caller seeing `status: queued` immediately knows whether the daemon is actually running and pushing or just silently no-op'ing into an outbox no daemon will drain.
- **Stale `pending_inbound` clear on bilateral completion (#171).** When `maybe_consume_pair_drop_ack` flips a peer to bilateral-VERIFIED via the inbound ack path, any leftover `pending_inbound` record from the earlier pair_drop is cleared idempotently. Pre-fix: VERIFIED peer lingered in `pending_pairs.inbound_handles` ("sunlit-aurora" in honey-pine's report).
- **Daemon stream resilience (#168).** SSE subscriber's TCP keepalive tightened from 60s → 30s. New `stream_state.json` writer tracks `state` (connecting/connected/reconnecting/error), `last_event_at`, `reconnect_count`. Surfaces via `wire_status`. honey's "BUG 2" closed.

### Supervisor architecture (honey-pine's launchd diagnosis)

- **`wire daemon --all-sessions` supervisor (#170).** Multi-session orchestrator: reads the session registry, fork-execs one child `wire daemon` per initialized session with `WIRE_HOME` env pinned to that session's home dir. Per-machine singleton on `<sessions_root>/supervisor.pid`. 10s registry-poll, rapid-failure backoff (1s → 60s cap), session-removal kill, pre-spawn pidfile check so operator-spawned tmux daemons coexist. Launchd plist + systemd unit + Windows task XML ProgramArguments updated. Closes the launchd-blind cwd-resolves-default-WIRE_HOME failure mode honey-pine spent multiple sessions diagnosing.

- **🚨 Supervisor fork-bomb hotfix (#174).** Caught immediately via live dogfood of #170 on a 133-session box. Supervisor was passing `--session <character-name>` to each child as a belt-and-suspenders check, but `session_dir(name)` only resolves the legacy v0.6 top-level layout — v0.13 by-key sessions where `name` is the persona handle bailed. Fix: drop the redundant flag entirely; `WIRE_HOME` env is the sole contract.

- **🚨 TLS hotfix: `rustls-tls-native-roots` → `rustls-tls-webpki-roots` (#176).** Also caught via the same dogfood pass. Once the supervisor put every daemon in launchd, every TLS handshake to wireup.net failed `UnknownIssuer`: launchd-spawned processes don't inherit Aqua-session keychain access on macOS, so `rustls-native-certs` returned an empty root set. Mozilla's bundled webpki-roots work in any process context. Was a temporary trade-off: corporate CA / AV-resign transparency lost; superseded same-day by #183 below.

- **Dual-roots TLS verifier (#183, closes #177).** The proper #176 replacement. New `tls::shared_client_config()` builds a single `Arc<rustls::ClientConfig>` consumed by every wire HTTPS surface via reqwest's `use_preconfigured_tls`. Webpki bundled roots ALWAYS loaded (the launchd-safe baseline). `rustls-native-certs` queried ADDITIVELY — contributes corp CAs / AV-resign roots / on-prem CAs when accessible, gracefully empty otherwise. Fail-soft on partial native-cert errors with a stderr breadcrumb (`wire tls: trust roots loaded — N webpki + M native = T total`). `WIRE_INSECURE_SKIP_TLS_VERIFY=1` still bypasses. Restores #176's corp-CA capability without re-breaking the launchd context #176 unblocked.

- **`wire daemon --session <name>` resolves v0.13 by-key (#180).** Operator-facing counterpart to #174: `cmd_daemon`'s `--session` resolver now uses the new `session::find_session_home_by_name` which handles both v0.6 top-level and v0.13 by-key/persona-handle layouts.

### Multi-session observability (honey-pine's "wire daemon status" ask)

- **CLI status surface gap closer (#169).** `pending_push_count` + `stale_sync` + `stream_state` (added to MCP `wire_status` in #167/#168) hoisted into CLI `wire status`. Shared helpers in `config.rs` (`compute_pending_push_count`, `read_stream_state`, `stale_sync`) so MCP / CLI / future doctor stay in lock-step. Plain-text `wire status` adds three lines in operator-triage order: last sync → pending push → stream.

- **Orphan-pid session annotation (#173).** When `wire status` flags orphan `wire daemon` processes (pidfile pid ≠ pgrep), each one now annotates with cmdline + parsed `--session` arg. Helps operators distinguish a stale leftover from a legitimate per-session child the supervisor is managing.

- **Per-session pidfile walk for annotation (#175).** Post-#174 supervisor children no longer carry `--session` in their cmdline, so `parse_session_arg` misses them. New `session::pid_to_session_map` walks every session's `<home>/state/wire/daemon.pid` and builds `{pid: session_name}`. `cmd_status` consults the map first when annotating orphans; falls back to cmdline `--session` arg. Bonus: fixed a latent bug in `session::session_daemon_pid` where a legacy bare-integer pidfile silently returned None because the JSON parser swallowed it as a Number without a `.pid` field.

- **`wire supervisor` CLI (#178).** New top-level command. `wire status` answers "is THIS session syncing?"; `wire supervisor` answers "what is the supervisor (and every session's daemon) doing across the box?". Pretty output collapses to one summary line when every session is healthy; JSON emits the full per-session topology. Closes honey-pine's BUG 3 ("wire daemon status CLI") ask.

- **Supervisor surfaces stale-binary daemon sessions (#198).** Caught via coral's 2026-06-01 dogfood probe: 1 of 10 sampled session daemons was still running v0.13.5 while the CLI was v0.14.1. Supervisor's existing-pidfile check intentionally protects alive daemons from respawn (would interrupt in-flight syncs), so mid-upgrade fleets accumulate version-drifted children silently. `SupervisedSession.daemon_version` reads from the JSON pidfile; `SupervisorState.stale_binary_sessions` is the derived list (alive + recorded version `<` `CARGO_PKG_VERSION` via a hand-rolled dotted-integer compare so `0.9.0 < 0.10.0` comes out right). `wire supervisor` pretty + JSON both surface; operator can `kill <pid>` to let the supervisor respawn on the fresh binary. Auto kill-and-respawn deferred — keeps operator-controlled timing.

- **🚨 Cross-process toast dedup (#179).** Caught via live operator complaint within minutes of #176 landing. The 134-daemon supervisor turned the existing in-process `Mutex<HashMap>` toast dedup into theater — every daemon polled its own inbox, every daemon fired its own toast, the operator saw the same notification 134 times within seconds. Fix: cross-process atomic claim via `O_CREAT|O_EXCL` on a sha256-named touch file under `<cache_dir>/wire/toast-dedup/`. Once a key is claimed, no wire process anywhere on the host re-emits — ever. Bare `toast()` now defers to `toast_dedup()` with a content-hash key so the 5 legacy bare-toast sites inherit the cross-process guarantee without per-site changes.

### The queue collapse (paul's "this is a headache" ask)

- **`wire send` returns the actual relay verdict synchronously (#187).** Pre-fix, every `wire send` (CLI and MCP) wrote to `<outbox_dir>/<peer>.jsonl` and returned `status: "queued"`. The daemon's 5s push loop later POSTed to the relay. Three distinct silent-drop classes hid in those steps: outbox-write-without-push (daemon dead, on wrong WIRE_HOME, TLS broken), stale-slot-token (peer rotated, half-paired), content-hash-dedup-blocks-retry. New default: `wire send` POSTs directly, returns `delivered` / `duplicate` / `peer_unknown` / `slot_stale` / `transport_error` inline, exits 2 on any non-delivered status. `--queue` CLI flag (and `queue: true` MCP arg) opts back into the legacy outbox→daemon-push path for offline-buffer / batch / pre-pair queueing. New `src/send.rs` module extracts the delivery primitive (`SyncDelivery` enum + `attempt_deliver`) shared by both CLI and MCP. Pushed-log append on the sync path keeps `pending_push_count` accurate across both paths.

- **MCP `wire_pull` — symmetric receive primitive (#189).** Paul (post-#187): *"This is the same on pull as push now?"* CLI `wire pull` has always been a sync GET-from-relay that drains the slot, verifies signatures, writes inbox, returns counts inline. The MCP surface had no equivalent — agents calling tools through Claude Code / Pi / OpenCode could only wait for the daemon's 5s pull cycle. New `wire_pull` MCP tool calls `cli::run_sync_pull()` directly; same code path the daemon uses. Returns `written[]` / `rejected[]` / `total_seen` / `cursor_blocked` / `endpoints_pulled`. Agents in tight loops no longer sleep 5s between turns.

### Adapter surface widens

- **Pi + OpenCode adapters in `wire setup` (#185).** Pi (https://pi.dev) uses the standard `mcpServers` shape — targets `$PI_CODING_AGENT_DIR/mcp.json` or `~/.pi/agent/mcp.json`. OpenCode (https://opencode.ai) uses a custom shape: top-level `mcp.<name>` (no `mcpServers` root, no `mcp.servers` intermediate), with `type: "local"`, combined `command: ["wire", "mcp"]` array, and `enabled: true`. `upsert_mcp_entry` detects OpenCode by path (`opencode.json` / `opencode/opencode.json`) and re-shapes the entry on write. Targets: `$XDG_CONFIG_HOME/opencode/opencode.json`, `~/.config/opencode/opencode.json`, project-local `opencode.json`. Closes the docs→code gap from v0.14.1's PI.md + OPENCODE.md.

### Surface honesty — same screen, same tier

Coral's 2026-06-01 dogfood found three status surfaces (`wire status`, `wire peers`, `wire here`) reporting different tiers for the same wedged peer + a `wire send --queue` path that silently accepted writes to peers that could never receive them. Four PRs tighten the surface:

- **Per-peer pending-push attribution (#199).** `pending push: 3 event(s)` was unactionable on its own — operator had to manually walk per-peer outbox files to learn which peer was wedged. New `config::compute_pending_push_breakdown()` returns one entry per peer with a tier and the unpushed event count, using `trust::effective_tier` so trust-promoted-but-handshake-incomplete peers show as `PENDING_ACK` not `VERIFIED`. CLI `wire status` expands the line with a tier-keyed hint (`pair never completed; daemon won't push until accept/reject`). MCP `wire_status` gains `daemon.pending_push_breakdown`. `effective_tier` moved from `cli.rs` to `trust.rs` so any future surface gets the canonical answer.

- **`wire send --queue` warns on unpushable peer (#200).** Coral's outbox carried a year-old `no-such-peer.jsonl` from a typo'd send — CLI exited 0 with `queued ... daemon will push` but the daemon had nowhere to push. `--queue` is the documented pre-pair-best-effort path, so refusing isn't right, but silent-success is a lie. CLI emits a stderr WARN (JSON stdout untouched) when the peer is BOTH not pinned in trust AND has no pending pair (outbound `PendingPair.peer_did` match or inbound `PendingInboundPair.peer_handle` match). MCP `wire_send` adds a structured `warning` field on the queued response so agents can branch.

- **`wire here` uses effective tier (#201).** Same surface drift caught the third status command: `wire here` was reading raw `agent.tier` from trust.json, so orchid-savanna showed `VERIFIED` here while `wire peers` and `wire status` showed `PENDING_ACK`. Route through `trust::effective_tier` so all three surfaces agree.

- **`wire doctor` surfaces pre-#171 stale `pending_inbound` (#202).** `wire status --json` carried `pending_pairs.stale_inbound_handles: [...]` for VERIFIED peers with leftover records from before #171's bilateral-completion cleanup. The pretty status surface filtered them out (intentional) but operators had no command pointing at the cleanup. New `stale-inbound-pairs` doctor check (8th of 8) emits WARN with chained `wire reject <handle>` commands in the `fix` string.

- **MCP `tool_peers` uses effective tier (#205).** The CLI's three status surfaces (status/peers/here) all routed through `trust::effective_tier` after #199 + #201; `tool_peers` was the remaining holdout still emitting raw trust-promoted VERIFIED. Agents calling `wire_peers` via MCP got a different answer than the same operator running `wire peers` — automation built on the MCP shape would believe a wedged peer was healthy + try to send. Fixed.

### Daemon resilience

- **`daemon-stream` preserves `last_event_at` + `reconnect_count` across reconnect (#204).** Every successful SSE reconnect overwrote `stream_state.json` with `last_event_at:null, reconnect_count:0`. The "connected" writer inside `connect_and_read` had no access to the accumulated state in the outer `run_subscriber` scope, so the file always reset the moment a fresh connection landed. Operator surface always read `last event never` on long-running daemons even after events had arrived. Threaded `accumulated_last_event_at` + `accumulated_reconnects` through the inner so the "connected" write preserves both — same pattern the outer writers already use.

- **Daemon-written sender-side staleness signal (#207, closes #14).** Extends `relay_state.peers[<handle>]` with `last_inbound_event_at` (RFC3339), stamped by the daemon on every successful pull where that peer was the sender. `check_peer_staleness` now prefers this field over inbox file mtime (which breaks on backup/restore, `cp -a`, `touch`, FAT32 resolution); falls back to mtime when the field is absent so upgrades are graceful. The asymmetric-stale-pin case #14 surfaced — push-to-dead-slot returns 200 OK + peer never sees us, both sides report green — now flips the doctor WARN with a daemon-side signal mtime can't corrupt.

### Operator UX polish

- **`wire upgrade` no longer fork-execs a redundant transient daemon (#186).** Pre-fix, `wire upgrade --local` output included `wire upgrade: spawned fresh daemon (pid N v0.14.1)` even when launchd was about to (re)start the `--all-sessions` supervisor on the new binary. The transient daemon lived ~30s before the supervisor's singleton-guard no-op'd it; operators saw the wrong pid as "the long-lived owner". Now reads `wire upgrade: daemon refresh deferred to launchd supervisor (will spawn within 10s)` when the OS bootstrap succeeded. Safety net intact: foreground spawn still fires when no service is installed or bootstrap failed.

### Identity / enrollment

- **`wire enroll republish` refreshes `capabilities[]` (#172, closes #126).** slate-lotus's v0.14.1 audit found that republish bumped `schema_version` v3.1 → v3.2 but left `capabilities=["wire/v3.1"]` stale, opening a stealth-skip vector for any future cap-gated feature. `rebuild_card_with_current_claims` now refreshes the wire/* entry to the binary's current `CARD_SCHEMA_VERSION` while preserving operator-defined non-wire caps (custom task tags, future feature flags) in their original order.

- **`wire enroll add-membership` — ingest an org-issued cert (#206, closes #127).** slate-lotus's same audit also flagged a load-bearing DX hole: `wire enroll org-add-member` printed the `{org_did, org_pubkey, member_cert}` bundle but the receiver had no verb to store it. Joining an org required hand-editing `<config>/wire/memberships.json` — exactly the friction the offline-minimal RFC-001 subset was meant to remove. New verb accepts either `--bundle '<verbatim-json>'` or the three flags separately, **verifies the cert against `org_pubkey` + this op_did via `identity::verify_member_cert` BEFORE storing** (a wrong-key bundle now fails at ingest, not at next republish), refuses when this operator isn't enrolled, and is idempotent on the org_did key. 4 lib tests covering happy-path + the 3 distinct rejection branches.

### RFC-004 (Willard's contributions)

- **AC-HP7 heartbeat body roundtrip proptest (#160).** Property-based test verifying that heartbeat bodies encode → relay → decode → re-encode → decode losslessly. WILLARDKLEIN.

### CI + repo hygiene

- **Re-run-friendly CI flake noted.** `uds_request_round_trips_200_with_body` hit again in this batch (the 4th observed instance per `feedback_uds_round_trips_ci_flake`). Recommend dedicated investigation alongside the dual-roots TLS work (#177); not yet a release blocker.

### Operator notes

- `wire upgrade` AUTOMATICALLY refreshes installed service units (rewrites plist / systemd unit with the new ProgramArguments). 0.14.1 → 0.14.2 operators don't need to manually re-run `wire service install` unless `wire upgrade` is skipped.
- The `--all-sessions` supervisor manages every session by default. To opt out (e.g. one specific session running in a tmux pane), the operator-spawned `wire daemon` claims the pidfile first and the supervisor's pre-spawn check honors it.
- Notification dedup state survives across daemon restarts. To re-see a notification class: `rm -rf ~/Library/Caches/wire/toast-dedup` (macOS) or `~/.cache/wire/toast-dedup` (linux).

### Launch hardening + reliability (post-#208 follow-on)

The batch that took the supervisor work from "lands" to "safe to put in front of strangers."

- **`wire upgrade --refresh-stale-children` (#209).** Companion to #198's stale-binary detection: force-reaps session daemons stuck on the old binary so an upgrade actually converges the whole box, instead of leaving version-drifted children alive behind the supervisor's respawn-protection.
- **🚨 `--all-sessions` fork-storm fix — idle filter (#212).** The supervisor spawned one daemon per session *home*, and a long-lived box accumulates hundreds of ephemeral persona homes (one per Claude tab / `wire session new`) → 100+ daemons for a handful of real sessions. `supervisor_eligible` now keeps a session only if it has a registry cwd binding OR synced within an idle cutoff (`WIRE_ALL_SESSIONS_MAX_IDLE_DAYS`, default 7; `0` disables). `list_sessions()` untouched — filter applied only at the supervisor call site.
- **Hermetic kill-switch tests — suite de-flake (#213).** Four `os_notify` tests mutated `WIRE_HOME`/`WIRE_NO_TOASTS` without the shared `ENV_LOCK`, racing every other test under the default parallel runner (a different subset failed each run; `--test-threads=1` masked it). Routed through `with_temp_home`; 20× parallel runs now 0 failures.
- **REUSE-compliant trio-license + stale-doc fix (#214).** The AGPL-server / Apache-spec / MIT-client split was sound but `LICENSE.md` still scoped it by pre-Rust-rewrite Python paths, and GitHub couldn't classify it (NOASSERTION). Texts moved to `LICENSES/`, a `REUSE.toml` encodes the per-path mapping, docs corrected.
- **README launch hardening (#215).** Status / API-stability section (pre-1.0, pin versions, `--json` is the stable surface), a real `CONTRIBUTING.md` (gates, DCO sign-off, per-component license), and good-first-issue pointers.
- **Fresh-user install-smoke CI + reproducible Rust test-env (#217).** New CI job builds the PR binary, installs it to PATH, and runs the offline first-run sequence from a clean `WIRE_HOME` — catches breakage that compiles + passes tests but breaks the out-of-the-box experience. Plus `test-env/` — a pinned-toolchain container that runs the exact CI gate against a mounted checkout.
- **Dead-code sweep (#218).** Dropped the unused `tower` direct dep, fixed the two real dead doc links, and fixed a `bash -lc` PATH bug in the test-env container's default gate command.

### Operator notes (launch-hardening addendum)

- After upgrading to 0.14.2, the `--all-sessions` supervisor will spawn daemons only for cwd-registered or recently-active sessions. If you rely on a long-idle unbound session keeping a daemon, set `WIRE_ALL_SESSIONS_MAX_IDLE_DAYS` higher (or `0` to disable the filter).


## [v0.14.1] — 2026-05-30

**v0.14.1 — v0.14.x DX completion: identity layer visible end-to-end, operator quality-of-life fixes.**

Closes every documented v0.14.0 follow-up plus operator-felt UX gaps surfaced during heavy dogfooding. 12 PRs since the v0.14.0 tag, no trust ladder change, no protocol bump (v3.2 was already the constant). All cards remain backward-compatible with v3.1 readers.

### Identity layer visible end-to-end

- **CLI op-claims surfacing (#114).** `wire whoami` / `wire peers` / `wire whois` JSON + human output now surface inline `op_did` / `op_pubkey` / `op_cert` / `org_memberships` / `schema_version` when present on the stored card. Pre-patch: the marquee v0.14 identity layer existed on disk but was stripped by every read surface — operators couldn't tell from `wire whoami --json` whether enrollment had taken. Single helper `cli::op_claims_from_card` centralizes the field list; pre-v0.14 / unenrolled cards surface identically (no JSON `null`-spam).
- **MCP op-claims surfacing (#115).** `mcp__wire__wire_whoami` and `mcp__wire__wire_peers` extend the same shared helper, closing the parallel-serializer gap (CLI and MCP had separate hard-coded JSON shapes that both stripped op_*).
- **MCP `wire_whois` bare-nick (#122).** Previously rejected bare nicks with `missing '@' separator`, even when the nick was a pinned peer or local sister already in the trust ring. Now routes through `cli::resolve_name_to_target` first (mirroring `wire whois <name>` in the CLI), federation handles fall through unchanged. Closes the agent-discovery surface for v0.14's marquee identity layer.
- **`schema_version` write-side bump (#121).** Cards carrying op claims now emit `v3.2` (was stuck at `v3.1` despite v0.14 fields). Bumps at `agent_card::with_identity_claims` via the new `max_schema_version` helper. Monotonic — a card already at `v3.5` (hypothetical future extension peer) is NOT downgraded. Numeric parse so `v3.10 > v3.2` (not lexicographic). Readers can now discriminate "carries op claims" from the version field alone.
- **`wire enroll republish` (#110).** Rebuilds the stored card with the **current** enrollment state and republishes. Closes the enroll-after-`init` DX gap: claims are normally attached at card-build time, but an operator who enrolls AFTER `init` had a stored card that pre-dated the claims. Idempotent: not-enrolled rebuilds a claims-free card; not-bound prints "local only".

### Operator quality of life

- **`wire quiet on/off/status` (#117).** Operator kill switch for desktop toasts. File-based (`<config_dir>/quiet`) for per-session silence + env-based (`WIRE_NO_TOASTS=1`) for launchd-spawned daemons. Both check at the single `os_notify::toast` guard — disabled means disabled, no dedup leakage. Status reports mechanism (`via file` / `via env` / `none`).
- **`wire upgrade` warns about stale `wire mcp` server subprocesses (#123).** `wire upgrade --local` swaps daemons but not the `wire mcp` server subprocesses that Claude Code / Claude.app pin at session start (macOS mmap semantics keep the old code in already-open processes when the file path is replaced). Now `--check`, action-run, and the `--json` shape surface the stale MCP pid list with explicit "each Claude tab must `/mcp` reconnect" guidance. The MCP procs are NEVER added to the kill set — killing them would disconnect every tab's wire toolset until each one explicitly reconnects. Warn-only, behavior unchanged.
- **Drop redundant `WIRE_SESSION_ID` env mapping in `wire setup` (#124).** Closes the MCP Config Diagnostics validator warning `Missing environment variables: CLAUDE_CODE_SESSION_ID`. Modern Claude Code (verified 2026-05-30) propagates `CLAUDE_CODE_SESSION_ID` into every MCP subprocess by default; wire's `session::resolve_session_key` reads it natively as a fallback. The historical mapping `{"WIRE_SESSION_ID": "${CLAUDE_CODE_SESSION_ID}"}` was duplicating a value wire already had AND triggering the validator warning. Dropped from the `wire setup` template; the existing fallback chain preserves per-session identity exactly.
- **Notify-mode wiring (#112 → shipped via #113 by branch-state accident).** The receive-side `notify` org-policy mode parses to `FileOrgPolicy::Notify` and routes the pending-stash toast through an enriched org-aware path (`notify-pair:<handle>` dedup key, "org-verified pair request from `<handle>`" wording). Pre-patch: `notify` parsed-but-unwired since v0.14.0; the generic toast fired regardless. Default-deny + `ORG_VERIFIED` ceiling + auto-wins-over-notify property all preserved.

### CI + repo hygiene

- **CI serializes test threads (#111).** `cargo test --all-targets -- --test-threads=1` eliminates heavy-e2e parallel-self-contention (a busy-polling subprocess-spawning e2e was starving sibling real-daemon e2es under `--test-threads=$(nproc)`).
- **Dead code removed (#118).** `signing::strip_did_wire` (added with `#[allow(dead_code)]` "kept for v0.6 — once a caller exists" comment) was never adopted; `agent_card::display_handle_from_did` covers the same need. Repo `#[allow]` count 4 → 3.
- **Repo-wide format-arg modernization (#119).** `cargo clippy --fix -- -W clippy::uninlined_format_args` across 14 files: `format!("{}", x)` → `format!("{x}")` and the same for `println!` / `eprintln!` / `assert_eq!` / `panic!` / `anyhow!` / `bail!` / `write!`. Net −16 LOC.
- **RFC-001 typo fix (#109).** "doubled" → "tail length quadrupled (8 hex → 32 hex)" in the rationale for op/org DID suffix width.

### Docs

- **SSO connectors prompt (#113 + #116).** `docs/PROMPT_v0.15_sso_connectors.md` — self-contained, paste-able prompt for the v0.15 SSO-connector buildout (auth flow runner + token lifecycle + verify + group/role enumeration + SCIM 2.0 ingest + deprovisioning hooks + CLI + card-emit + receive-side branch). 21 providers spec'd; 9 hard constraints; 12-PR landing order. Iterated via #116 to fold in the v0.14.x regression-debug lessons (CLI+MCP serializers must stay in lock-step via the shared helper; dual-surface JSON-RPC tests; post-`/compact` branch-state verification; MCP-server-pin in `wire upgrade`).
- **Repo-scrub prompt (#120).** `docs/PROMPT_repo_scrub.md` — durable artifact encoding the bounded-cleanup discipline (5-phase order of operations, per-PR `done` definition, suggested cuts by priority, anti-patterns to instant-reject, stop conditions).

### Net diff

Lib: 341 → 355 tests (+14 across the surfacing + identity + cleanup PRs). No release-surface protocol change. No trust ladder mutation. Six cross-platform binaries (`aarch64-apple-darwin`, `x86_64-pc-windows-msvc`, `aarch64-unknown-linux-{gnu,musl}`, `x86_64-unknown-linux-{gnu,musl}`) + `.sha256`s built via `release.yml` on tag push.


## [v0.14.0] — 2026-05-29

**v0.14.0 — RFC-001 identity layer: operator + organization + project, fully-offline self-certifying.**

Ships the offline-minimal subset of [RFC-001](docs/rfc/0001-identity-layer.md) — three optional, orthogonal-axis claims on the agent-card (`op_did`, `org_memberships[]`, `project`), a new tier `ORG_VERIFIED` between `UNTRUSTED` and `VERIFIED`, and the smallest receive-side surface that closes the N²-pair-discovery problem inside trust scopes without weakening the v0.5.14 phonebook-scrape closure or the bilateral SAS invariant.

The shipped design is **fully-offline self-certifying.** Each card carries `op_pubkey` and a per-membership `org_pubkey` inline; each operator/org DID is a hash commitment to its key (`agent_card::long_fingerprint` = first 16 B of `sha256(pubkey)`), so an attacker can't substitute an inline pubkey without breaking the DID match. `identity::verify_op_cert` / `verify_member_cert` take the inline pubkeys directly — no resolver, no registry, no `did:web`, no DNS-TXT, no `/v1/org/claim` on the pairing hot path. (Those = v0.15, per the "Implementation status (as-built, v0.14)" note added to the RFC in #106.)

- **`wire enroll` CLI (#99, #102).** Three subcommands: `wire enroll op --handle <h>` mints this machine's operator root key + prints `op_did`; `wire enroll org-create --handle <h>` mints an organisation root key + prints `org_did`; `wire enroll org-add-member <op_did> --org <org_did>` issues a membership cert binding the operator to the org and stores it locally. Keys saved 0600 under `config/wire/{op.key, orgs/<sanitized>.key}`; memberships persisted in `config/wire/memberships.json`.
- **Card-emit wiring (#103, #104).** When an enrolled agent runs `wire init` / `pair_session::init_self`, the card-build path attaches `op_did` + `op_cert` + `op_pubkey` + every stored membership inline before signing. **Fail-soft:** a corrupt identity config (unparseable `memberships.json`, etc.) degrades to "no claims" + a stderr warning rather than breaking card-build — `init` / `up` are critical-path and must never fail because of a stored-config parse error. Not-enrolled cards are byte-identical to v0.13 cards; v3.2 readers tolerate both schemas.
- **Receive-side auto-pin (#101).** When a peer pair_drop arrives carrying a v3.2 card with a verified membership in an org the receiver has explicitly opted into (`config/wire/org_policies.json` → `{"orgs":{"<org_did>":{"inbound":"auto"}}}`), the receiver auto-pins the peer at `ORG_VERIFIED` and emits the pair_drop_ack — bypassing the default-deny pending gate for that org. **Fail-closed:** an empty / missing / malformed policy file → no auto-pin → default-deny intact. A peer whose membership doesn't commit to the inline org_pubkey (substitution attempt) is rejected at `evaluate_card_membership`.
- **`Tier::OrgVerified` < `Tier::Verified` (#90).** Strict by `trust::tier_order` (NOT a derived `Ord`). An auto-pinned org-mate satisfies `>= ORG_VERIFIED` policy checks but NOT `>= VERIFIED` — bilateral SAS (SPAKE2 invite path) or the `wire add` / `pair-accept` gesture is still the only path to VERIFIED. Property-tested in `tests/trust_ceiling_prop.rs`.
- **File-backed org policy (#95, #98).** Minimal receiver-side per-org store. Two modes: `auto` (auto-pin on contact, wired in v0.14), `notify` (eligible — designated UI surface, parsed but not yet wired into the live receive path; lands in v0.14.x). Empty/malformed → empty policy → no easing.
- **SSO provider-adapter trait (#100).** Pluggable seam (`SsoProvider::normalize`) over Google (`hd`), Azure AD (`tid`), Keycloak (realm), and a generic IdP — claims-shape normalization only. The verify path (binding an SSO identity to an `op_did` via a relay attestation) is deferred to v0.15 per the SSO amendment.
- **Live two-process e2e (#105 + #107).** `tests/e2e_org_verified.rs` drives the real `wire` binary across two `WIRE_HOME`s + an in-process relay: A enrolls op+org+self-membership → `wire init` (card carries claims) → A dials B → B (with `org_policies.json` auto-trusting A's org) pulls → B auto-pins A at `ORG_VERIFIED` purely from the offline membership. Negative control: non-member dialer still gated to pending. `#[ignore]`d (run via `cargo test --test e2e_org_verified -- --ignored --test-threads=1`) — heavy real-process e2e + a gentle 750 ms poll cadence to avoid starving the other real-daemon e2e binaries under `cargo test --all-targets`.
- **A2A interop docs (#91 — @dthoma1 / swift-harbor).** `docs/a2a-extension/wire-identity-v1.md` formalises wire as an A2A v1.0 AgentCard extension (URI `https://slancha.ai/wire/ext/v0.5`); `docs/did-methods/did-wire-method.md` is the `did:wire` method specification covering session / operator / organisation shapes (`<handle>-<8hex>` and `<handle>-<32hex>` of `sha256(pubkey)`); `docs/PROTOCOL.md` audited through v0.13.5 with the v3.2 additions inlined; an introductory blog at `docs/blog/wire-and-a2a.md` covers what wire adds on top of the A2A floor.
- **RFC-001 as-built alignment (#106).** Added "Implementation status (as-built, v0.14)" demarcating built (offline-minimal) vs deferred (DNS-TXT / `did:web` / wireup registry / roster bundle / SSO verify / cross-relay → v0.15). Fixed the §1 card snippet that had omitted the inline `op_pubkey` and per-membership `org_pubkey`.

Net: an operator who runs the three `wire enroll` commands once on each machine, then sets a one-line `org_policies.json` opt-in for any org they're willing to auto-pair with, eliminates the SAS dance for every session-pair inside that org — bilaterally, offline, on the v0.13 mailbox substrate. Wire-format additions are ≤ 2 KB per card, backward-compatible with v3.1 readers; nothing on the relay protocol changed.

Known follow-ups (v0.14.x): `wire enroll … --republish` (or rebuild-on-enroll) to close the DX gap that `enroll`-after-`init` doesn't republish claims today (card is built at init only); wire `notify` mode into the live receive surface; serialize the heavy real-daemon e2e binaries behind a dedicated `-- --ignored --test-threads=1` CI step.


## [v0.13.5] — 2026-05-25

**v0.13.5 — Reliable per-session identity (the PID-file adapter) + unexpanded-`${}` guard.**

v0.13.4's env-forward (`WIRE_SESSION_ID=${CLAUDE_CODE_SESSION_ID}`) proved unreliable: Claude Code only expands `${}` when the var is in its OWN env, which on a clean top-level terminal (esp. Windows CC 2.1.150) it is NOT — so CC passes the LITERAL string, which wire hashed into ONE fixed identity (every session in every folder collapsed onto one persona). Two fixes:

- **`${...}` literal guard** — `resolve_session_key` treats any unexpanded `${...}` value (and empty) as unset, so it never hashes a placeholder into a shared identity.
- **Claude Code PID-file adapter** (thanks @WILLARDKLEIN, #56) — when the session id isn't in the env, wire walks its parent-process chain to the owning `claude` process and reads `~/.claude/sessions/<pid>.json` → `sessionId`. Deterministic, race-free, zero env/handshake dependency, cross-platform — validated on Windows (3 concurrent terminals → 3 distinct personas) and macOS. The MCP server now recovers the SAME session id the CLI uses, so CLI and MCP unify on one per-session identity, stable across reconnects.

Net: true per-session identity everywhere, even when Claude Code doesn't put the session id in the MCP env. Ships a reference cross-platform proxy shim (`contrib/wire-mcp-proxy.py`) for builds without the native adapter.

## [v0.13.4] — 2026-05-25

**v0.13.4 — Per-session identity (MCP + Windows), statusline fix, group chat, `wire update`.**

- **Per-session identity, fixed on the MCP path — the Windows "same persona every session" bug.** Claude Code sets `CLAUDE_CODE_SESSION_ID` for Bash-tool subprocesses but NOT for the stdio MCP server, and the MCP `initialize` handshake carries no session id — so the MCP server had no per-session signal and fell back to cwd-detection, collapsing every Claude session under a shared dir (`~/Source`, `C:\Users\<user>`) onto ONE identity. Two fixes: (1) `wire setup` now writes the MCP entry with `"env": {"WIRE_SESSION_ID": "${CLAUDE_CODE_SESSION_ID}"}`, which Claude Code expands into the MCP env at launch (validated on Win10 — a fresh session resolves to a distinct by-key persona); (2) **cwd resolution is removed everywhere** — the MCP mints a distinct per-process identity when no session id is present, and the CLI never cwd-resolves. Identity is the session, period. **Re-run `wire setup --apply` on this version** — and note a PROJECT-scoped `.mcp.json` takes precedence over the global config, so make sure the env block landed in the file your host actually uses.
- **Statusline shows the session's own persona.** The bundled renderer bridges the `session_id` Claude Code passes on STDIN into `WIRE_SESSION_ID` before calling `wire whoami`, so the bottom-of-terminal persona matches the session (was resolving a cwd default / nothing).
- **Group chat** — `wire group create / add / send / tail / list / invite / join` + MCP `wire_group_*` tools. A group is a shared relay-room slot; the creator-signed roster carries each member's key (introduce-on-vouch), so members verify each other without pairing. `invite` mints a self-contained join code; redeemers land at Introduced tier.
- **`wire update` ≡ `wire upgrade`** — one verb (alias). Always checks crates.io; installs a newer release if there is one (cargo install, else prebuilt + SHA-256 self-replace), then does the atomic daemon swap. `--check` reports; `--local` skips the fetch.
- **CI:** GitHub Actions bumped off deprecated Node 20 (checkout@v5, upload-artifact@v7, download-artifact@v8).
- **Docs:** AGENTS.md + AGENT_INTEGRATION.md now document the v0.13 session-keyed identity model (were the stale pre-v0.13 cwd model).

## [v0.13.3] — 2026-05-25

**v0.13.3 — Group chat + one update command.**

- **`wire group` — bidirectional group chat.** `create / add / send / tail / list`. A group is a **shared relay-room slot**: the creator allocates one slot and its token is the room key, distributed only to vouched members; everyone posts + pulls that one slot (no relay change, no daemon auto-rebroadcast, no per-member credential mesh — chosen because a `slot_token` is a read+write credential, so direct member-to-member delivery would leak each member's personal mailbox token). Membership is a **creator-signed roster** with a `GroupTier` (creator/member/introduced) that is a SEPARATE axis from bilateral peer trust. `add` takes a bilaterally-VERIFIED peer (T22 consent) and distributes a `group_invite` carrying the signed roster + room coords. On ingesting an invite a member **introduce-pins** every other member — adds their key to trust at bilateral UNTRUSTED so their group messages verify, WITHOUT granting bilateral trust and never lowering an existing tier (the axes stay disjoint). Net: members who never paired with each other can post to the room and read each other's messages with a verified signature, vouched by the creator's signature in place of a direct SAS handshake. Verified live on wireup.net + by an e2e star-topology test (one member reads another's message verified though they never paired).
- **`wire update` ≡ `wire upgrade` — merged.** One verb (`update` is an alias). It ALWAYS checks crates.io; if a newer stable release is published it installs it (`cargo install slancha-wire` when a Rust toolchain is on PATH, else downloads + SHA-256-verifies the prebuilt release binary and self-replaces — toolchain-free), then runs the atomic daemon swap so the restart picks up the new binary. No newer version → it skips the install and just restarts. A crates.io/network failure degrades to a warning and never blocks the restart. `--check` reports the available update + the processes that would restart without acting; `--local` skips the crates.io check (offline / local dev build).

## [v0.13.2] — 2026-05-24

**v0.13.2 — Windows hardening + `wire setup --statusline`.** Three Windows bugs (found by a paired Windows session dogfooding v0.13.1 over wire) plus the long-missing persona statusline and removal of the dead reactor:

- **relay.json torn-write fixed (CRITICAL).** A foreground `wire dial` racing the background daemon corrupted `relay.json`: both did a non-atomic, lockless `fs::write`, interleaving into invalid JSON ("trailing characters at line N") that broke ALL push/pull until hand-repaired. `write_relay_state` now writes via tmp+rename **and** holds the existing `relay.lock` flock (the RMW path calls an unlocked inner to avoid re-entrant deadlock). The race was cross-platform; Windows file-sharing semantics made it easy to hit.
- **`wire status` / `doctor` false-DOWN fixed.** Daemon-liveness had duplicate Linux/Unix-only copies (`ensure_up::pid_is_alive`, `daemon_liveness`'s `pgrep`, `ensure_up::process_alive`, `pending_pair::process_alive`) running `kill -0` / `pgrep` — absent on Windows → always false → daemon reported DOWN while alive. All now route through the already-Windows-correct `platform::process_alive` / `find_processes_by_cmdline` (tasklist / PowerShell CIM). Same root cause behind the `wire up` / `upgrade` 500 ms self-spawn probe orphaning `wire.exe`.
- **`wire setup --statusline`.** Installs a Claude Code statusLine showing your persona — liveness dot + emoji + nickname in the persona's accent color + cwd (`● 🪻 bright-camellia · ~/project`). Writes a bundled renderer + merges a `statusLine` block into settings.json (preserves keys, refuses to clobber invalid JSON, idempotent, `--remove` to uninstall, honors `$CLAUDE_CONFIG_DIR`). Closes the gap where personas existed but nothing installed the statusline that displays them.
- **`wire reactor` removed.** The `claude -p` shell-out reactor was superseded by live-session monitoring + auto-reply baked into the MCP instructions; removed the command, handler, helper, and landing section.
- **Same-box discovery fixed (v0.13 regression).** v0.13 moved session homes under `sessions/by-key/<hash>`, but `list_sessions` only scanned the top level (so every v0.13 session was invisible to `wire session list-local` / `pair-all-local`), and `sessions_root()`'s inside-session fallback only walked one level up (so an inside-session `WIRE_HOME` resolved to a nonexistent nested dir). Both fixed: `list_sessions` descends into `by-key/` (labeling each home by its persona), and `sessions_root()` walks up to the nearest `sessions` ancestor. Same-box sisters are visible to each other again. (The broader in-band local-pairing UX — additive `add-peer-slot`, loopback-relay dial, a leak-safe same-box pair verb — is tracked separately in `docs/V0_13_2_PLATFORM_HARDENING.md`.)
- **`wire upgrade` is now session-scoped — fixes daemon accumulation on Windows (critical).** Repeated `wire upgrade` spawned fresh daemons without killing the old ones (glossy-magnolia: 2→5→8→11 over three cycles — real multiple daemons racing the pull cursor). The old design was box-wide (kill every `wire daemon` process found, wipe every session's pidfile, respawn every session), which is wrong for a multi-session / shared-relay box AND broke on Windows: the CIM scan can't match the quoted `"...\wire.exe" daemon` command line (no contiguous `wire daemon`), so it found nothing to kill, then the respawn loop accumulated. `wire upgrade` now refreshes only THIS session: it kills this session's own daemon via its **pidfile pid** (reliable, CIM-independent) plus any TRUE orphans (`wire daemon` owned by no session), and SPARES sibling sessions' daemons and the shared `127.0.0.1:8771` relay-server (killing it would break every same-box session's loopback). Each session refreshes itself on its own `wire upgrade`.
- **`wire monitor` no longer dies silently.** wisp-blossom saw `wire monitor` exit 1 with zero output when a cursor-block (untrusted signer's pair event) tripped the watcher — indistinguishable from "still watching." The poll loop now surfaces the error to stderr and keeps watching instead of exiting on a swallowed `?`.
- **Re-dial no longer clobbers a peer's local endpoint or bleeds the federation token (E3-dial).** `wire dial peer@relay` (→ `cmd_add`) REPLACED the whole peer entry with a flat federation-only one and seeded the federation token from the entry's *top-level* `slot_token`. After a prior local `add-peer-slot`, that top-level token was the LOCAL token — so re-dialing made the federation endpoint inherit a stale local bearer (federation delivery would 401), and dropped the local endpoint entirely. Now the federation endpoint is merged additively into `endpoints[]` (local preserved), and its token is seeded only from a prior *federation* endpoint on the same relay (re-dial of an already-acked peer), never a local one — empty until the `pair_drop_ack` lands otherwise. (glossy-magnolia pinpointed the re-pin path; add-peer-slot itself was innocent.)
- **`wire add-peer-slot` is now additive (E3).** It used to REPLACE the whole peer entry, so pinning a local loopback slot clobbered the peer's federation endpoint — the peer became loopback-only and lost its public route (glossy-magnolia + wisp-blossom repro). Now it merges into the peer's `endpoints[]` (upsert by relay_url), mirroring `bind-relay`'s additive semantics, so a local slot ADDS to the federation route instead of dropping it.
- **Orphan-daemon detection is session-scoped (A2).** On a multi-session box (wire's core use case) every session runs its own daemon, but the orphan check flagged any `wire daemon` whose pid ≠ this session's pidfile as an orphan — so sibling sessions' legitimate daemons showed as orphans, `wire doctor` FAILed on a healthy shared box, and `wire upgrade` would cross-session-kill a sibling's daemon. A true orphan is now a wire daemon owned by NO session: detection excludes every session's pidfile pid (`session_daemon_pid` across `list_sessions`), not just the current one.
- **Daemon now services ALL slots, not just the primary (E2).** `run_sync_pull` (the background daemon's pull) only pulled `self_primary_endpoint` — the federation slot — so a session that additively bound a local loopback slot never had it serviced by the daemon (same-box loopback messages silently undelivered until a manual restart re-seeded the startup-only stream subscriber). Now it pulls every self endpoint with an independent per-slot cursor (`self.cursors.<slot_id>`), one endpoint's failure doesn't stall the others, and the legacy global cursor stays in sync with the primary for back-compat. (Manual `wire pull` was already multi-slot; this brings the daemon in line.)
- **No more phantom "?" sisters in `list-local` (E8).** `maybe_adopt_session_wire_home` created a session home unconditionally on every resolution — before any identity existed — so transient/probe session keys left permanent empty homes that surfaced as phantom handle-less sisters (degrading the same discovery the by-key fix restored). Homes are now created lazily on first real write, and `list_sessions` skips homes with no agent-card.

## [v0.13.1] — 2026-05-24

**v0.13.1 — one name, one command. Identity UX simplified; the last "same handle" leak closed.** A persona review found the one-name promise (v0.11) was still violated in several places, and that the real fix was to stop letting anyone *type* a name they will not get.

- **One-name now holds on EVERY init path.** `init_self_idempotent` — the auto-init used by `wire claim`, MCP `wire_init`, and all pairing — previously used the machine **hostname** (`default_handle()`) as the handle and never applied the persona derivation that `wire init` did. Result: every auto-initialized session on a box became `did:wire:<hostname>-<fp>`, all displaying the same hostname after the fp-strip — a second, more visible root of the Windows "every new session has the same handle" bug (v0.13 fixed the colliding HOME; this fixes the colliding displayed name). Both branches now derive the persona from the keypair fingerprint, so distinct sessions always get distinct fp-derived personas. Re-init with a different typed handle is now an idempotent no-op (the typed handle is vestigial) instead of an error.
- **Onboarding is one nickless command.** `wire up [relay]` does everything (init + bind + claim your persona + local dual-bind + daemon) and no longer takes a `<nick>` — your handle *is* your DID-derived persona, so there was never a name to type. Accepts `@wireup.net`, a bare host, a full URL, or nothing (defaults to the public relay).
- **`wire init`, `wire claim`, `wire identity publish` are hidden.** All three accepted a name the one-name rule ignores — terrible UX (you type `alice`, you get `winter-bay`; worse, on a fresh box the ignored name could be the invalid hostname and the command would fail). They are folded into `wire up` and removed from `--help`, kept callable for scripts/offline keygen. `wire init`'s handle arg is now `Option` (`None` = no typed name); `wire claim`/`wire_claim` coerce any typed nick to your persona (MCP `nick` is now optional + advisory).
- **`landing/install.sh` was stale.** The installer embedded in the relay and served at `wireup.net/install.sh` was an older, separate script showing a 3-step `init` → `claim` → `add` flow with the deprecated `wire add` verb — the first thing every new user saw, contradicting the model. Now byte-identical to the canonical root `install.sh` (one-command `wire up`, canonical `wire dial`, Windows MSYS/Cygwin detection, post-install `wire upgrade` stale-cleanup pass).
- **README quick-start** rewritten around `wire up` + the one-name model (dropped the pre-v0.11 `wire init alice` → `winter-bay (alice)` two-name example).

## [v0.13.0] — 2026-05-24

**v0.13 — session-keyed identity.** Replaces the cwd-registry + machine-wide-default session model with a host-agnostic session-key chain (`WIRE_SESSION_ID` > `CLAUDE_CODE_SESSION_ID` > legacy cwd-detect). Each session resolves to a unique, deterministic, cwd-independent WIRE_HOME (`sessions/by-key/<sha256(key)[:16]>`), so two sessions can never collapse onto a shared default. Fixes the Windows "every new session gets the same handle" bug at the root — there is no path string to mis-normalize or miss.

- **MCP startup auto-bootstraps** a fresh session home once (one-name init + federation slot + phonebook claim), so each session is its own reachable, claimed identity. Gated on `WIRE_MCP_SKIP_AUTO_UP` + already-initialized; best-effort on network.
- **Behavior change:** two windows in the same project are now DISTINCT identities (previously shared, via the bug). Existing sessions re-key on first run under v0.13.
- **Deferred:** migration bridge, GC of orphaned session homes (see the design spec). **The Windows fix is provisional until verified on a real Windows box.**

Design: `docs/superpowers/specs/2026-05-24-session-keyed-identity-design.md`.

## [v0.12.3] — 2026-05-24

**v0.12.3 — auto-collaborate, baked in.** The MCP server `instructions` (shipped in the binary, read by any agent that connects `wire mcp`) now DIRECT connecting agents to: (1) arm a persistent `wire monitor` stream-watcher on session start so peer messages surface live, and (2) reply to peer messages in their own live context without waiting for the operator to prompt them. Previously this was a soft "recommended"; now it's a baked-in directive, so anyone who installs wire gets auto-collaboration between paired agents — no per-machine hook required.

## [v0.12.2] — 2026-05-24

**v0.12.2 — persona rename cleanup.** Finishes the `character` → `persona` surface rename from v0.12.

Fixed:
- `wire session list` / `wire here` column header was still `CHARACTER` → now `PERSONA`.
- `wire init` one-name message said "DID-derived character" → "DID-derived persona".
- `docs/STATUSLINE.md` jq examples read the old `.character.palette` JSON key (returns `null` since v0.12's key rename) → fixed to `.persona.palette`, with persona terminology throughout and a naming note.

## [v0.12.1] — 2026-05-24

**v0.12.1 — `wire up` claims the persona; phonebook shows the face.** Closes the last one-name gap from v0.12.

Fixed:
- **`wire up <nick>@<relay>` now claims your DID-derived PERSONA, not the typed `<nick>`.** Under the v0.11 one-name rule the typed nick is vestigial (it can't select an identity), but `up`'s claim step was still registering it on the relay — re-opening a two-name split (claimed handle ≠ persona). `up` now resolves the persona from the freshly-inited card and claims that. It also no longer bails when the typed nick differs from the existing persona (the mismatch isn't an error — the nick is ignored).
- **Phonebook (`/v1/handles`) now shows the DID-derived emoji next to every name**, even when the claimant set no explicit profile emoji. The relay computes `Character::from_did(did).emoji` as a fallback, so `🦨 pine-puffin` renders instead of a bare `pine-puffin`.

## [v0.12.0] — 2026-05-24

**v0.12 — additive multi-relay, zero-config dual-bind, persona surfacing.** Onboarding and identity-surface polish on top of the v0.11 one-name rule.

Added:
- **`wire bind-relay` is additive.** Binding a new relay appends to `self.endpoints[]` instead of overwriting, so an agent can hold a local relay AND a federation relay simultaneously. New `--scope <federation|local|lan|uds>` (inferred from the URL by default) and `--replace` (the old destructive single-slot behavior, still guarded against black-holing pinned peers). A new-relay bind never black-holes pinned peers — resolves issue #7 by design.
- **`wire up` opportunistic local dual-bind.** After the federation bind+claim, `wire up` additively binds a local relay slot for sub-millisecond same-box sister routing. `--with-local <url>` overrides the default `http://127.0.0.1:8771` probe; `--no-local` opts out. Local relays carry no handle directory, so nothing is claimed there.

Changed:
- **Persona surfacing.** The serialized output key `character` → `persona` (and `character_override` → `persona_override`) in `wire whoami` / `here` / `peers`. MCP `wire_whoami` and `wire_peers` now include the persona (nickname + emoji + palette) — previously they emitted only the raw handle. `wire notify` OS toasts now show the persona (`wire ← 🦨 pine-puffin`) instead of the handle. The internal Rust `Character` type name is unchanged.

Fixed:
- **MCP `wire_dial`** read a required `handle` arg while the schema provided `name`, so every dial over MCP errored `missing 'handle'`. It now reads `name` and routes federation handles correctly.
- **MCP `wire_init` with `relay_url`** no longer no-ops the relay binding when the identity is already initialized but unbound — it binds the requested relay (additively) so a subsequent `wire claim` doesn't 404.

Breaking:
- Consumers parsing the `character` JSON key from `wire whoami` / `here` / `peers` (e.g. statusline scripts) must read `persona` instead.

## [v0.11.0] — 2026-05-23

**v0.11 — one immutable name.** The DID-derived character nickname IS the addressable handle. Operator-typed `wire init <name>` arg is ignored at init time; agent-card.handle is synthesized from the keypair fingerprint via Character::from_did so every peer sees you by the same name everywhere (statusline, `wire peers`, federation handle, inbox/outbox file path, route results, mesh-status, commit trailers). Closes the long-running "two names" footgun where a UI nickname could differ from the wire address.

Breaking:
- `wire identity rename` removed — there is no separate rename verb. If you want a different face, regenerate your identity (new DID → new character).
- `agent-card.handle` no longer reflects the `wire init <name>` argument. It is `Character::from_did(synthesized_did).nickname`. Init now prints "operator-typed `<X>` ignored in favor of DID-derived character `<Y>`. Peers will reach you as `<Y>`" when the two differ.
- Production code paths (already-paired check in `session pair-all-local`, `drive_bilateral_pair`, `cmd_session_mesh_status`) now key the in-memory peers map by handle, not session name — previously they conflated session name with handle and the local-sister pair-accept could fail when a session's directory name differed from its character.

Compat:
- `Character::from_did` now seeds from the 8-hex fingerprint suffix only (not the full DID string) to break the circular dependency where handle change → DID change → character change → infinite loop. Legacy DIDs without the `-<fp>` suffix fall through to the v0.10 seed-the-whole-DID behavior.
- Federation flow (`wire add <h>@<host>`) is unchanged on the wire — peers still reach you by your card handle, which is now always the character.

## [v0.9.5] — 2026-05-23

v0.9.5 — shell completions (bash/zsh/fish/elvish/powershell) + interactive init prompt


## [v0.9.4] — 2026-05-23

v0.9.4 — split wire accept into wire accept + wire accept-invite (kill smart-dispatch ambiguity)


## [v0.9.3] — 2026-05-23

v0.9.3 — conversational surfaces (wire here, prose pending, emoji fallback, README rewrite)


## [v0.9.2] — 2026-05-23

v0.9.2 — helpful errors (fuzzy resolution, miss-returns-empty in JSON, deprecation banner suppressed in JSON + once-per-session)


## [v0.9.1] — 2026-05-23

v0.9.1 — surface cleanup (hide deprecated, smart-default init, JSON-when-piped, quiet auto-detect)


## [v0.9.0] — 2026-05-23

v0.9.0 — clean cut

Six operator-facing verbs (was ~20):
  wire dial / send / pending / accept / reject / whois

One canonical public name per identity (DID-derived character).
Operator-rename is local-display-only — no longer publishes on
agent-card.

Structural fixes (silent-fail class closed):
- wire init refuses slotless sessions (root cause of 2026-05-23 incident)
- single self_primary_endpoint() reader everywhere
- wire send auto-pairs on miss for local sisters
- wire dial routes federation via @relay
- 12 legacy pair verbs collapse to 3 (pending/accept/reject)
- legacy verbs still work but emit deprecation banner (v1.0 removes)

PR #35 merged. Pre-existing test flake (detached_pair_survives_
daemon_restart_mid_handshake) carried over from main; unrelated.

Co-Authored-By: 🛡 noble-creek <wire+wire-b6f47edb@wire.id>


## [v0.7.5] — 2026-05-23

v0.7.5 — nickname-add + silent-fail pair_drop_ack fix


## [v0.7.3] — 2026-05-23

v0.7.3 — thorough cross-platform wire upgrade + AGENT.md §0.5

`wire upgrade` now sweeps daemons AND relay-servers, refreshes
installed service units to point at the new binary path before the
OS auto-respawns, and works on Windows (was hard-fail pre-0.7.3).

Cosmetic fix: `wire session list` now reports correct daemon
liveness on Windows (was always `down` because kill -0 is unix-only).

AGENT.md §0.5 redirects local agents to `wire session pair-all-local`
instead of the federation `wire pair-host` / `wire pair-join` flow
they kept reaching for.

New `src/platform.rs` exposes cross-platform process_alive /
find_processes_by_cmdline / kill_process primitives.

PR #32, merged. Full suite (193) green.

Co-Authored-By: 🛡 noble-creek <wire+wire-b6f47edb@wire.id>


## [v0.7.2] — 2026-05-23

v0.7.2 — Windows service backend (Task Scheduler)

Closes the cross-platform parity gap: `wire service install` and
`wire service install --local-relay` now register hidden, restart-
on-failure, run-at-logon scheduled tasks on Windows via schtasks.exe
+ Task Scheduler 1.2 XML.

LeastPrivilege + InteractiveToken — no UAC, no stored password.
Matches the user-scope footprint of launchd's gui/<uid> + systemd
--user paths.

PR #31, merged. Linux + macOS paths unchanged. Full release suite
(190 + 3 bind + 8 service) clean.

Co-Authored-By: 🛡 noble-creek <wire+wire-b6f47edb@wire.id>


## [v0.7.1] — 2026-05-23

v0.7.1 — wire session bind

Adds `wire session bind <name>` to attach an existing session to the
current cwd without going through destroy+new. Fixes the case where
a registered ancestor dir (e.g. `~/Source`) is shadowing leaf-project
identities, collapsing two CC sessions onto the same Character.

PR #28, merged 92af54b. Doc sweep 7b85d15.

Behavior:
- `wire session bind` (no name) auto-derives from basename(cwd)
- Errors loudly if the named session doesn't exist
- Idempotent: re-binding to the current binding is a no-op
- Re-binding to a different session overwrites with a stderr warning
- Uses update_registry (flock-serialized) so it composes safely with
  concurrent MCP auto-init writes

Tests: 3 new session_bind_* in tests/cli.rs. Full suite 190 + 3 pass.

Co-Authored-By: 🛡 noble-creek <wire+wire-b6f47edb@wire.id>


## [v0.7.0] — 2026-05-23

v0.7.0 — identity lifecycle + scope-aware routing + UDS transport

The v0.7.0-identity alpha track (22 commits) lands four arcs:

- Deterministic Character per session: DID-hash → emoji + adj-noun nickname
  + 256-color palette. Operator-stable visual ID across sessions, statusline,
  peer listings, commit trailers.
- `wire identity` lifecycle CLI: create / persist / publish / demote /
  rename / show / list / destroy. Anonymous-mode sessions (local-only,
  no federation) can be promoted to federation slots later; published
  identities can be demoted back to local-only.
- Operator-chosen overrides preserved across renames; palette stays
  DID-derived for hash-stability.

- EndpointScope enum unifies Federation / Local / Lan / Uds.
- Priority order: Uds → Local-loopback (with matching self) → Lan → Federation.
- Per-endpoint cursors for pull; per-endpoint dispatch for push.
- `post_event_to_endpoint(endpoint, event)` helper: scheme-aware POST
  that routes `unix://...` via uds_request, everything else via reqwest.

- Hand-rolled HTTP/1.1 over UnixStream (axum 0.7 serve is TcpListener-only).
- `wire relay-server --uds /path/to/sock` for same-host trust-anchored IPC.
- `wire session new --with-uds` allocates UDS slots.
- Same-uid, same-host sister-session shape — see project_wire_transport_substrate_research.

- Cross-machine same-network reachability between Federation and Local.
- Tailscale CGNAT (100.64.0.0/10) bind acceptance for `--local-only`.

- demo-hotline: fixed pair-accept-in-drain-loop regression (broken since
  v0.5.14 anti-phonebook-scrape change removed receiver auto-promote).
  All 5 ring sends now land. (#27)
- Clippy clean across all alpha-track commits.
- 190 tests pass.

- Holistic codebase audit at .planning/research/codebase-audit-2026-05-23.md
  with critique iteration. P0 priorities surfaced for v0.7.x and v0.8.

22 alpha commits preserved via merge commit (not squashed).

Co-Authored-By: 🐻 cedar-bayou <wire+wire-source-d8ae94a5@wire.id>

