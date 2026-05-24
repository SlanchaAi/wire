# v0.13.2 — Platform hardening + local-pairing (bug hunt tracker)

Goal (operator, 2026-05-24): **wire has zero bugs in local pairing and on Windows/Linux.**
Driven with paired Windows testers **glossy-magnolia** + **wisp-blossom** (two independent agents on ONE Win10 x86_64 box) and **feral-blossom** (build/verify lane).

Branch: `v0.13.2-windows-hardening`. Authoring lane: bright-camellia (this agent, macOS). Build/verify lane: feral-blossom (Windows). Shared loopback relay on `127.0.0.1:8771` — reinstall there restarts it and interrupts all local routing, so **coordinate before restarting**.

## Status legend
✅ fixed + verified · 🟡 fixed, awaiting Windows re-verify · 🔴 open · 🔵 epic (separate from "no bugs" core)

## Core bugs
| id | bug | status | fix |
|----|-----|--------|-----|
| relay.json | foreground dial + daemon tore relay.json (non-atomic, lockless) → invalid JSON, broke all push/pull | ✅ verified (glossy stress: 16 writers, 50-msg burst, new-peer add — zero tears) | atomic tmp+rename under `relay.lock`; unlocked inner for RMW |
| status-DOWN | `wire status`/`doctor` false-DOWN on Windows (Unix-only `kill -0`/`pgrep`) | ✅ verified | route through `platform::process_alive` (tasklist) |
| spawn-orphan | `wire up`/`upgrade` 500ms self-spawn probe orphaned wire.exe | ✅ verified | liveness dedup |
| A orphan-false+ | doctor reports phantom "orphan daemon" (pid changes every call = the query's own process) | ✅ verified (glossy, Win) | CIM query: `Name -like 'wire*'` + exclude `$PID` (kills powershell self-match) |
| A2 cross-session-orphan | on a multi-session box, orphan detector flags SIBLING sessions' daemons as orphans → doctor FAILs, `upgrade` cross-session-kills | 🟡 rc7 | orphan = daemon owned by NO session; subtract every session's pidfile pid |
| E3-bleed | (glossy rc6) after add-peer-slot, federation endpoint shows the LOCAL token → fed delivery would 401 | 🔴 investigating | NOT in any storage path (add-peer-slot + both pair-ack pins + self-upsert all preserve per-endpoint tokens, verified) — likely display or manual-coords; awaiting glossy before/after relay.json |
| B upgrade-kill | **CRITICAL**: `wire upgrade` doesn't kill daemons on Windows → they ACCUMULATE (2→3→4→5) → real cursor race | 🟡 rc4 | Windows cmdline pattern `*wire daemon*` never matched `wire.exe daemon` (.exe breaks it). Now match `Name like 'wire*'` + role (`daemon`/`relay-server`, pattern minus leading `wire `) |
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
