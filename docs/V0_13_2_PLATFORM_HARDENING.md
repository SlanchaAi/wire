# v0.13.2 — Platform hardening + local-pairing (bug hunt tracker)

Goal (operator, 2026-05-24): **wire has zero bugs in local pairing and on Windows/Linux.**
Driven with paired Windows testers **glossy-magnolia** + **wisp-blossom** (two independent agents on ONE Win10 x86_64 box) and **feral-blossom** (build/verify lane).

Branch: `v0.13.2-windows-hardening`. Authoring lane: bright-camellia (this agent, macOS). Build/verify lane: feral-blossom (Windows). Shared loopback relay on `127.0.0.1:8771` — reinstall there restarts it and interrupts all local routing, so **coordinate before restarting**.

## STATUS: v0.13.2 SHIPPED + LIVE (2026-05-25)
Full rc10 Windows matrix GREEN (glossy): B + E2-bidirectional + pair-all-local + E3(additive+token-bleed) + A2 + C + E8 + statusline. **SHIPPED 2026-05-25**: crates.io 0.13.2, wireup.net relay redeployed (healthz 200; a Dockerfile assets/ COPY miss caught + fixed post-tag), binaries + ci green. Operator GO confirmed. Released-build Windows validation in progress with glossy/wisp. Non-blocking caveats: live sibling-daemon-survival re-test pending wisp recovery; true-orphan-sweep not yet staged. Separate: wisp daemon-stability (rc11).

## v0.13.3 — in progress (group chat + self-update)
- **`wire update`** (commit a511a77): self-update to the latest crates.io release — `cargo install slancha-wire --version <latest> --force --locked` when a toolchain is present, else download + SHA-256-verify + self-replace the prebuilt release binary (toolchain-free, for the Windows agents). `--check` reports current vs latest. Distinct from `wire upgrade` (daemon restart). Verified live against crates.io. **Windows agents' path** — they have no cargo, so the prebuilt branch matters; needs a real on-Win10 run before shipping.
- **Group chat I1** (commits fed60da model + 206896e commands/e2e): `wire group create/add/send/tail/list` over a creator-signed roster (`src/group.rs`). Creator-broadcast among VERIFIED members. Superseded by I2.
- **Group chat I2 — bidirectional** (commit 9a2c0f5): operator-approved. Members POST to the group, not just receive. **Architecture = shared group-room slot** (the relay `slot_token` is a read+write credential, so direct member-to-member would leak personal-mailbox tokens — E6; the creator allocates ONE slot, its token is the room key, everyone posts+pulls it; no relay/daemon change). **introduce-on-vouch**: the signed roster carries each member's key + the room coords; on ingesting a `group_invite` a member pins the other members' keys at bilateral UNTRUSTED (axes stay disjoint) so their group messages verify without a direct SAS handshake. 9 unit + e2e (star topology, the cross-member read — bob reads carol verified though they never paired). **Live-verified on wireup.net**: create→send→tail round-trip, verified=true on the production relay. See spec → "I2 architecture".
- **Still open for v0.13.3:** I3 (kick = slot rotation + roster epoch revocation); `wire group invite` join-code (the other half of I2 — Introduced-tier joins); docs (README group section, AGENT_INTEGRATION recipe, MCP group tools); a LIVE cross-agent bidirectional test (blocked on a second agent building the `group-chat` branch — mechanism already proven by e2e + the live self round-trip).
- Branch: `group-chat`. Not yet released — bundles with the next tag.

## Status legend
✅ fixed + verified · 🟡 fixed, awaiting Windows re-verify · 🔴 open · 🔵 epic (separate from "no bugs" core)

## Core bugs
| id | bug | status | fix |
|----|-----|--------|-----|
| relay.json | foreground dial + daemon tore relay.json (non-atomic, lockless) → invalid JSON, broke all push/pull | ✅ verified (glossy stress: 16 writers, 50-msg burst, new-peer add — zero tears) | atomic tmp+rename under `relay.lock`; unlocked inner for RMW |
| status-DOWN | `wire status`/`doctor` false-DOWN on Windows (Unix-only `kill -0`/`pgrep`) | ✅ verified | route through `platform::process_alive` (tasklist) |
| spawn-orphan | `wire up`/`upgrade` 500ms self-spawn probe orphaned wire.exe | ✅ verified | liveness dedup |
| A orphan-false+ | doctor reports phantom "orphan daemon" (pid changes every call = the query's own process) | ✅ verified (glossy, Win) | CIM query: `Name -like 'wire*'` + exclude `$PID` (kills powershell self-match) |
| A2 cross-session-orphan | doctor flagged daemons as orphans on a multi-session box | ✅ verified (glossy, Win — correctly spared registered daemon, flagged only a true orphan) | orphan = daemon owned by NO session; subtract every session's pidfile pid |
| E3-bleed | re-dial inherited the entry's top-level (stale LOCAL) token for the federation endpoint + clobbered the local endpoint → fed delivery 401 | ✅ verified (glossy, Win — local survives, fed token empty, no bleed) | cmd_add re-pin additive; fed token only from a prior FEDERATION endpoint |
| B upgrade-kill | **CRITICAL**: `wire upgrade` accumulated daemons on Windows | ✅ verified (glossy rc10: pid rotates, count stays 1, relay spared) | session-scoped kill (own daemon via pidfile + true orphans, spare siblings+relay) + force-kill survivors (taskkill /F /T — graceful is a no-op for a windowless daemon) |
| C bash-WSL | `setup --statusline` emitted bare `bash` → Windows resolves to System32\bash.exe (WSL) → statusline breaks | 🟡 rc2 | `resolve_git_bash()` — absolute git-bash path |
| D monitor-death | `wire monitor` exits 1 with ZERO output on P0.1 cursor-block (untrusted signer's event) — silent death | 🟡 rc4 | poll loop surfaces error to stderr + keeps watching; awaiting wisp exact repro |
| E8 orphan-home | empty/no-card by-key homes surfaced as phantom "?" sisters in list-local (unconditional create_dir_all at process entry) | 🟡 rc5 | lazy home creation + `list_sessions` skips no-card homes |
| discovery | v0.13 `by-key/` homes invisible to `list-local`/`pair-all-local` → same-box sisters fell to federation | ✅ verified (feral) | `list_sessions` descends into `by-key/`; `sessions_root()` ancestor-walks to `sessions` |

## Local-pairing UX (epic — beyond "no bugs" core; some are correctness bugs)
| id | gap | tier | note |
|----|-----|------|------|
| E3 | `add-peer-slot` REPLACES endpoints, doesn't merge → clobbers federation route (data loss) | 🟡 rc5 | now additive — upsert by relay_url into peer `endpoints[]` |
| E4 | domain validator rejects loopback/IP → `dial`/`add` can't express `nick@127.0.0.1:8771` | bug | relax validator when scope=local |
| E5 | `dial <peer>` on already-pinned returns `already_pinned`, won't refresh endpoints → peer that binds local AFTER pairing can't upgrade | bug | `wire repin/refresh <peer>` |
| E2 | daemon never serviced a bind-relay'd local slot (`run_sync_pull` pulled only the primary endpoint) | 🟡 rc6 | pull ALL self endpoints with per-slot cursors; resilient to one slot erroring |
| E1 | `wire up` doesn't register a local session / auto-start|detect local relay → same-box defaults to federation | feature | |
| E7 | local slot not auto-advertised into federated card after bind-relay → existing peers can't upgrade | feature | |
| E6 | no leak-safe in-band same-box pair verb (`wire pair-local`) — manual off-disk coord read + add-peer-slot today | feature | sending a slot_token over federation = credential leak (harness correctly blocks) |

## Sequence
1. **rc4**: B (upgrade-kill) + D (monitor diagnostics). → peers re-verify A,B,C,D + statusline render on Windows.
2. **E-bugs** (E3,E4,E5,E2): the local-pairing correctness bugs. → in-band local pairing works without clobbering federation.
3. **Tag v0.13.2 stable** once peers verify the core table is all ✅.
4. **E-features** (E1,E6,E7): the ergonomic local-pairing epic → v0.14 (separate).

## Verified PASS (glossy/wisp/feral, Win10 x86_64)
relay.json atomicity under stress · loopback throughput ~50 msg/s/agent bidirectional · status running · clean cold spawn · list-local sees by-key sisters (feral, rc3 build).

## Operator-decision items (NOT v0.13.2 blockers — for operator review on return)

- **~~MCP auto-act-on-peers worm vector~~ — RETRACTED (2026-05-25, overstatement).** Re-read of the actual instruction: it says REPLY/auto-converse to peer messages (the v0.12.3 behavior the operator wanted), NOT auto-execute or auto-rebroadcast. The self-propagating "worm" required a rebroadcast step the doctrine never instructs. Real residual = generic untrusted-input hygiene (treat peer text as data, don't auto-run irreversible actions on a peer's say-so) — NOT a wire-specific worm, NOT a v0.13.2 blocker. Operator decision: leave MCP instructions as-is; ship hardening only.
