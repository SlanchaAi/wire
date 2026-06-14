use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

use crate::config;

// ---------- status ----------

pub(super) fn cmd_status(as_json: bool) -> Result<()> {
    let initialized = config::is_initialized()?;

    let mut summary = json!({
        "initialized": initialized,
    });

    if initialized {
        let card = config::read_agent_card()?;
        let did = card
            .get("did")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        // Prefer the explicit `handle` field added in v0.5.7. Fall back to
        // stripping the DID prefix (and the v0.5.7+ pubkey suffix) for
        // legacy cards.
        let handle = card
            .get("handle")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| crate::agent_card::display_handle_from_did(&did).to_string());
        let pk_b64 = card
            .get("verify_keys")
            .and_then(Value::as_object)
            .and_then(|m| m.values().next())
            .and_then(|v| v.get("key"))
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("agent-card missing verify_keys[*].key"))?;
        let pk_bytes = crate::signing::b64decode(pk_b64)?;
        summary["did"] = json!(did);
        summary["handle"] = json!(handle);
        summary["fingerprint"] = json!(crate::signing::fingerprint(&pk_bytes));
        summary["capabilities"] = card
            .get("capabilities")
            .cloned()
            .unwrap_or_else(|| json!([]));

        let trust = config::read_trust()?;
        let relay_state_for_tier =
            config::read_relay_state().unwrap_or_else(|_| json!({"peers": {}}));
        let mut peers = Vec::new();
        if let Some(agents) = trust.get("agents").and_then(Value::as_object) {
            for (peer_handle, _agent) in agents {
                if peer_handle == &handle {
                    continue; // self
                }
                // P0.Y (0.5.11): use effective tier — surfaces PENDING_ACK
                // for peers we've pinned but never received a pair_drop_ack
                // from, so the operator sees the "we can't send to them yet"
                // state instead of seeing a misleading VERIFIED.
                peers.push(json!({
                    "handle": peer_handle,
                    "tier": super::effective_peer_tier(&trust, &relay_state_for_tier, peer_handle),
                }));
            }
        }
        summary["peers"] = json!(peers);

        let relay_state = config::read_relay_state()?;
        summary["self_relay"] = relay_state.get("self").cloned().unwrap_or(Value::Null);
        if !summary["self_relay"].is_null() {
            // Hide slot_token from default view.
            if let Some(obj) = summary["self_relay"].as_object_mut() {
                obj.remove("slot_token");
            }
        }
        summary["peer_slots_count"] = json!(
            relay_state
                .get("peers")
                .and_then(Value::as_object)
                .map(|m| m.len())
                .unwrap_or(0)
        );

        // Outbox / inbox queue depth (file count + total events)
        let outbox = config::outbox_dir()?;
        let inbox = config::inbox_dir()?;
        summary["outbox"] = json!(super::scan_jsonl_dir(&outbox)?);
        summary["inbox"] = json!(super::scan_jsonl_dir(&inbox)?);

        // v0.5.19: liveness snapshot through a single helper so this
        // surface and `wire doctor` agree by construction. Issue #2:
        // doctor PASSed while status said DOWN for 25 min because each
        // computed liveness independently. ensure_up::daemon_liveness
        // is the only path now.
        let snap = crate::ensure_up::daemon_liveness();
        let mut daemon = json!({
            "running": snap.pidfile_alive,
            "pid": snap.pidfile_pid,
            "all_running_pids": snap.pgrep_pids,
            "orphans": snap.orphan_pids,
        });
        if let crate::ensure_up::PidRecord::Json(d) = &snap.record {
            daemon["version"] = json!(d.version);
            daemon["bin_path"] = json!(d.bin_path);
            daemon["did"] = json!(d.did);
            daemon["relay_url"] = json!(d.relay_url);
            daemon["started_at"] = json!(d.started_at);
            daemon["schema"] = json!(d.schema);
            if d.version != env!("CARGO_PKG_VERSION") {
                daemon["version_mismatch"] = json!({
                    "daemon": d.version.clone(),
                    "cli": env!("CARGO_PKG_VERSION"),
                });
            }
        }
        // v0.14.2 (#162): surface "is the sync loop actually running RIGHT NOW?"
        // distinct from "is there a process named `wire daemon` somewhere?".
        // pidfile_alive + a fresh last_sync are both required for "healthy
        // sync"; pidfile_alive + no recent last_sync = the daemon is up but
        // wedged. last_sync_age_seconds = null = no record (never ran here).
        let last_sync_age = crate::ensure_up::last_sync_age_seconds();
        if let Some(rec) = crate::ensure_up::read_last_sync_record() {
            daemon["last_sync_at"] = json!(rec.ts);
            daemon["last_sync_age_seconds"] = json!(last_sync_age);
            daemon["last_sync_push_n"] = json!(rec.push_n);
            daemon["last_sync_pull_n"] = json!(rec.pull_n);
            daemon["last_sync_rejected_n"] = json!(rec.rejected_n);
        } else {
            daemon["last_sync_at"] = Value::Null;
            daemon["last_sync_age_seconds"] = Value::Null;
        }
        // v0.14.2 (#162 fix #2 + #7 surface gap, post-merge of #167/#168):
        // honey-pine round-trip dogfood (2026-06-01) confirmed pending_push_count
        // + stale_sync + stream_state surface in MCP wire_status but not in CLI
        // `wire status`. Shared helpers in config.rs keep both surfaces in lock
        // so future doctor/web checks pick up the same numbers.
        // Per-peer breakdown introduced 2026-06-01 after coral
        // dogfood found 3 events stuck on `orchid-savanna`
        // (PENDING_ACK pair). Aggregate count was already
        // surfaced; the missing piece was attribution — operator
        // had to manually walk per-peer outbox files to learn
        // which pair was wedged. Compute both from a single
        // breakdown so total + per-peer detail can't diverge.
        let pending_breakdown = config::compute_pending_push_breakdown();
        let pending_total: u64 = pending_breakdown.iter().map(|p| p.count).sum();
        daemon["pending_push_count"] = json!(pending_total);
        daemon["pending_push_breakdown"] = json!(pending_breakdown);
        daemon["stale_sync"] = json!(config::stale_sync(last_sync_age));
        daemon["stream_state"] = config::read_stream_state();
        // v0.14.2 (#162 diagnostic, post-#170): annotate orphan pids
        // with their cmdline + the `--session <name>` arg the
        // supervisor (or operator) tagged them with. honey-pine spent
        // multiple sessions diagnosing "wire status reports DOWN
        // while comms work" — turned out the orphan was a launchd-
        // spawned daemon serving a different WIRE_HOME. Surfacing
        // "(serving session 'X')" on each orphan collapses the
        // diagnostic time. Best-effort: cmdline read can race exit
        // → fields just stay absent rather than failing the status
        // call.
        // v0.14.2 #173 follow-up (post-#174 hotfix): the supervisor's
        // children no longer carry `--session <name>` in their cmdline
        // (WIRE_HOME env is the sole contract), so the pid → session
        // mapping has to walk per-session pidfiles instead. The
        // cmdline `parse_session_arg` path is kept as a fallback for
        // operator-spawned `wire daemon --session foo` runs.
        let pid_session_map = crate::session::pid_to_session_map();
        let orphans_detail: Vec<Value> = snap
            .orphan_pids
            .iter()
            .map(|pid| {
                let cmdline = crate::platform::pid_cmdline(*pid);
                let session = pid_session_map.get(pid).cloned().or_else(|| {
                    cmdline
                        .as_deref()
                        .and_then(crate::platform::parse_session_arg)
                        .map(str::to_string)
                });
                json!({
                    "pid": pid,
                    "cmdline": cmdline,
                    "session": session,
                })
            })
            .collect();
        daemon["orphans_detail"] = json!(orphans_detail);
        summary["daemon"] = daemon;

        // v0.5.14: pending-inbound zero-paste pair_drops awaiting accept.
        // v0.14.2: filter out records whose peer is already pinned at
        // VERIFIED+ tier (i.e., bilateral completed via some other
        // path). Pre-#171 `maybe_consume_pair_drop_ack` didn't clear
        // pending_inbound on receipt of the peer's ack; operators
        // with pre-#171 data on disk see their VERIFIED peers show
        // up in `inbound pair requests`, prompting a misleading
        // `wire accept` suggestion. The stale records still exist on
        // disk (operator can clear via `wire reject` if they care);
        // the status surface just stops showing them.
        // Records for genuinely-not-pinned peers — or peers at
        // UNTRUSTED/PENDING_ACK — surface normally.
        let pinned_verified_handles: std::collections::HashSet<String> =
            crate::config::read_trust()
                .ok()
                .and_then(|t| t.get("agents").and_then(Value::as_object).cloned())
                .map(|agents| {
                    agents
                        .into_iter()
                        .filter_map(|(handle, agent)| {
                            let tier = agent.get("tier").and_then(Value::as_str).unwrap_or("");
                            if matches!(tier, "VERIFIED" | "ORG_VERIFIED") {
                                Some(handle)
                            } else {
                                None
                            }
                        })
                        .collect()
                })
                .unwrap_or_default();
        let raw_pending_inbound =
            crate::pending_inbound_pair::list_pending_inbound().unwrap_or_default();
        let stale_inbound_handles: Vec<&str> = raw_pending_inbound
            .iter()
            .filter(|p| pinned_verified_handles.contains(&p.peer_handle))
            .map(|p| p.peer_handle.as_str())
            .collect();
        let pending_inbound: Vec<_> = raw_pending_inbound
            .iter()
            .filter(|p| !pinned_verified_handles.contains(&p.peer_handle))
            .collect();
        let inbound_handles: Vec<&str> = pending_inbound
            .iter()
            .map(|p| p.peer_handle.as_str())
            .collect();
        summary["pending_pairs"] = json!({
            "inbound_count": pending_inbound.len(),
            "inbound_handles": inbound_handles,
            // Surface the filtered-as-stale set so operators with
            // pre-#171 leftover records can find + clean them via
            // `wire reject <handle>` if they care.
            "stale_inbound_count": stale_inbound_handles.len(),
            "stale_inbound_handles": stale_inbound_handles,
        });
    }

    if as_json {
        println!("{}", serde_json::to_string(&summary)?);
    } else if !initialized {
        println!("not initialized — run `wire up` first");
    } else {
        // Which identity is this status about? The "two Claudes look
        // identical" trap extends to the diagnostics themselves — print the
        // resolved on-disk home (and session id, if set) so an operator
        // running status in the wrong window can tell immediately.
        if let Ok(sd) = crate::config::state_dir() {
            println!("home:          {}", sd.display());
        }
        if let Ok(sid) = std::env::var("WIRE_SESSION_ID")
            && !sid.is_empty()
        {
            println!("session:       {sid}");
        }
        println!("did:           {}", summary["did"].as_str().unwrap_or("?"));
        println!(
            "fingerprint:   {}",
            summary["fingerprint"].as_str().unwrap_or("?")
        );
        println!("capabilities:  {}", summary["capabilities"]);
        if !summary["self_relay"].is_null() {
            println!(
                "self relay:    {} (slot {})",
                summary["self_relay"]["relay_url"].as_str().unwrap_or("?"),
                summary["self_relay"]["slot_id"].as_str().unwrap_or("?")
            );
        } else {
            println!("self relay:    (not bound — run `wire bind-relay <url>` to bind)");
        }
        println!(
            "peers:         {}",
            summary["peers"].as_array().map(|a| a.len()).unwrap_or(0)
        );
        for p in summary["peers"].as_array().unwrap_or(&Vec::new()) {
            println!(
                "  - {:<20} tier={}",
                p["handle"].as_str().unwrap_or(""),
                p["tier"].as_str().unwrap_or("?")
            );
        }
        println!(
            "outbox:        {} file(s), {} event(s) queued",
            summary["outbox"]["files"].as_u64().unwrap_or(0),
            summary["outbox"]["events"].as_u64().unwrap_or(0)
        );
        println!(
            "inbox:         {} file(s), {} event(s) received",
            summary["inbox"]["files"].as_u64().unwrap_or(0),
            summary["inbox"]["events"].as_u64().unwrap_or(0)
        );
        let daemon_running = summary["daemon"]["running"].as_bool().unwrap_or(false);
        let daemon_pid = summary["daemon"]["pid"]
            .as_u64()
            .map(|p| p.to_string())
            .unwrap_or_else(|| "—".to_string());
        let daemon_version = summary["daemon"]["version"].as_str().unwrap_or("");
        let version_suffix = if !daemon_version.is_empty() {
            format!(" v{daemon_version}")
        } else {
            String::new()
        };
        println!(
            "daemon:        {} (pid {}{})",
            if daemon_running { "running" } else { "DOWN" },
            daemon_pid,
            version_suffix,
        );
        if !daemon_running {
            // Don't dead-end on the #1 silent-receive cause — name the fix.
            println!(
                "               → run `wire up` to restart it, or `wire service install` to keep it alive across reboots"
            );
        }
        // P1.7: surface version mismatch + orphan procs loudly.
        if let Some(mm) = summary["daemon"].get("version_mismatch") {
            println!(
                "               !! version mismatch: daemon={} CLI={}. \
                 run `wire upgrade` to swap atomically.",
                mm["daemon"].as_str().unwrap_or("?"),
                mm["cli"].as_str().unwrap_or("?"),
            );
        }
        if let Some(orphans) = summary["daemon"]["orphans"].as_array()
            && !orphans.is_empty()
        {
            let pids: Vec<String> = orphans
                .iter()
                .filter_map(|v| v.as_u64().map(|p| p.to_string()))
                .collect();
            println!(
                "               !! orphan daemon process(es): pids {}. \
                 pgrep saw them but pidfile didn't — likely stale process from \
                 prior install. Multiple daemons race the relay cursor.",
                pids.join(", ")
            );
            // v0.14.2 (#162 diagnostic): per-orphan annotation so
            // operators don't have to grep ps themselves. Each orphan
            // shows its --session arg (or "(no --session)" for legacy
            // launchd daemons + operator-spawned `wire daemon` without
            // the flag — those default to dirs::state_dir() WIRE_HOME,
            // which often diverges from the shell's cwd-mapped session).
            if let Some(details) = summary["daemon"]["orphans_detail"].as_array() {
                for d in details {
                    let pid = d["pid"].as_u64().unwrap_or(0);
                    let session = d["session"].as_str();
                    let cmdline = d["cmdline"].as_str();
                    // v0.14.2: distinguish the supervisor (orchestrator —
                    // doesn't sync any single WIRE_HOME) from a legacy
                    // single-session daemon (DOES sync a WIRE_HOME, just
                    // not via --session). Pre-fix both were labelled "no
                    // --session — serving default WIRE_HOME" which was
                    // misleading for the supervisor case: it doesn't
                    // serve any home, it spawns child daemons that do.
                    let is_supervisor = cmdline
                        .map(|c| c.contains("--all-sessions"))
                        .unwrap_or(false);
                    match (session, cmdline, is_supervisor) {
                        (Some(s), _, _) => {
                            println!("                  pid {pid}: serving session '{s}'")
                        }
                        (None, Some(c), true) if !c.is_empty() => println!(
                            "                  pid {pid}: supervisor — orchestrates one daemon per session, doesn't sync directly (cmdline={c})"
                        ),
                        (None, Some(c), false) if !c.is_empty() => println!(
                            "                  pid {pid}: (no --session — serving default WIRE_HOME) cmdline={c}"
                        ),
                        _ => println!(
                            "                  pid {pid}: (cmdline unavailable — pid may have just exited)"
                        ),
                    }
                }
            }
        }
        // v0.14.2 (#162 #2/#7 surface): three lines that catch the
        // silent-send class operators kept missing on 0.14.1. Order matters
        // — last_sync first (is the loop running?), then pending_push_count
        // (am I leaking sends?), then stream_state (will live-monitor see
        // anything?).
        let last_sync_age = summary["daemon"]["last_sync_age_seconds"].as_u64();
        let last_sync_at = summary["daemon"]["last_sync_at"].as_str();
        match (last_sync_at, last_sync_age) {
            (Some(ts), Some(age)) => {
                let stale = summary["daemon"]["stale_sync"].as_bool().unwrap_or(false);
                let stale_tag = if stale { "  !! STALE (>60s)" } else { "" };
                let p = summary["daemon"]["last_sync_push_n"].as_u64().unwrap_or(0);
                let pl = summary["daemon"]["last_sync_pull_n"].as_u64().unwrap_or(0);
                let r = summary["daemon"]["last_sync_rejected_n"]
                    .as_u64()
                    .unwrap_or(0);
                println!(
                    "last sync:     {ts} ({age}s ago) push={p} pull={pl} rejected={r}{stale_tag}"
                );
            }
            _ => {
                println!(
                    "last sync:     (none recorded) — daemon hasn't completed a cycle in this WIRE_HOME"
                );
            }
        }
        let pending_push = summary["daemon"]["pending_push_count"]
            .as_u64()
            .unwrap_or(0);
        if pending_push > 0 {
            println!(
                "pending push:  {pending_push} event(s) queued but not yet pushed to relay — \
                 if stale_sync, this is the silent-send class (#162 fix #2)"
            );
            // v0.14.3: per-peer attribution. coral dogfood
            // (2026-06-01) found 3 events stuck on a PENDING_ACK
            // pair; the aggregate count gave no hint which pair.
            // Expand into one line per peer with tier + a hint
            // about the action the tier implies.
            if let Some(breakdown) = summary["daemon"]["pending_push_breakdown"].as_array() {
                for entry in breakdown {
                    let peer = entry.get("peer").and_then(Value::as_str).unwrap_or("?");
                    let tier = entry
                        .get("tier")
                        .and_then(Value::as_str)
                        .unwrap_or("UNKNOWN");
                    let count = entry.get("count").and_then(Value::as_u64).unwrap_or(0);
                    // Tier-specific hint. PENDING_ACK = wedged
                    // pair (operator action: `wire accept`
                    // or `wire reject`). UNTRUSTED = peer not yet
                    // pinned (rare but possible if trust file
                    // was hand-edited). VERIFIED + queued =
                    // #162 silent-send class; daemon should push
                    // imminently or `stale_sync` will flip.
                    let hint = match tier {
                        "PENDING_ACK" => {
                            " — pair never completed; daemon won't push until accept/reject"
                        }
                        "UNTRUSTED" => " — peer not pinned; daemon won't push to UNTRUSTED",
                        _ => "",
                    };
                    println!("  {count:>4} → {peer} ({tier}){hint}");
                }
            }
        } else {
            println!("pending push:  0");
        }
        match summary["daemon"]["stream_state"]
            .get("state")
            .and_then(Value::as_str)
        {
            Some(s) => {
                let last_evt = summary["daemon"]["stream_state"]
                    .get("last_event_at")
                    .and_then(Value::as_str)
                    .unwrap_or("never");
                let reconnects = summary["daemon"]["stream_state"]
                    .get("reconnect_count")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                println!("stream:        {s} (last event {last_evt}, reconnects {reconnects})");
            }
            None => {
                println!(
                    "stream:        (no stream_state.json) — daemon predates #168 or hasn't \
                     subscribed yet; live monitor will fall back to polling cadence"
                );
            }
        }
        let inbound_count = summary["pending_pairs"]["inbound_count"]
            .as_u64()
            .unwrap_or(0);
        if inbound_count == 0 {
            println!("pending pairs: none");
        }
        // v0.5.14: separate line for pending-inbound zero-paste requests.
        // Loud because each one is awaiting an operator gesture and the
        // capability hasn't flowed yet.
        if inbound_count > 0 {
            let handles: Vec<String> = summary["pending_pairs"]["inbound_handles"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            println!(
                "inbound pair requests ({inbound_count}): {} — `wire pending` to inspect, `wire accept <peer>` to accept, `wire reject <peer>` to refuse",
                handles.join(", "),
            );
        }
    }
    Ok(())
}

// ---------- responder health ----------

fn responder_status_allowed(status: &str) -> bool {
    matches!(
        status,
        "online" | "offline" | "oauth_locked" | "rate_limited" | "degraded"
    )
}

fn relay_slot_for(peer: Option<&str>) -> Result<(String, String, String, String)> {
    let state = config::read_relay_state()?;
    // RFC-006 Part B: resolve through the endpoint helpers. Peer routing comes
    // from `endpoints[]` (single source); self still synthesizes from its flat
    // fields (self-slot collapse is a separate step).
    let (label, ep) = match peer {
        Some(peer) => {
            if state.get("peers").and_then(|p| p.get(peer)).is_none() {
                anyhow::bail!(
                    "unknown peer {peer:?} in relay state — pair with them first:\n  \
                     wire add {peer}@wireup.net   (or {peer}@<their-relay>)\n\
                     (`wire peers` lists who you've already paired with.)"
                );
            }
            (
                peer.to_string(),
                crate::endpoints::peer_primary_endpoint(&state, peer)
                    .ok_or_else(|| anyhow!("{peer} has no pinned endpoints — re-pair"))?,
            )
        }
        None => (
            "self".to_string(),
            crate::endpoints::self_primary_endpoint(&state).ok_or_else(|| {
                anyhow!("self slot not bound — run `wire bind-relay <url>` first")
            })?,
        ),
    };
    Ok((label, ep.relay_url, ep.slot_id, ep.slot_token))
}

/// v0.14.2 (#170 / honey-pine BUG 3): `wire supervisor` — operator-
/// facing multi-session topology view. Reads `SupervisorState` and
/// renders it as JSON or pretty text. `wire status` covers the
/// "is THIS session syncing?" question; `wire supervisor` covers
/// "what is the supervisor and every session's daemon doing across
/// the box?". No mutation.
pub(super) fn cmd_supervisor(as_json: bool) -> Result<()> {
    let state = crate::daemon_supervisor::read_supervisor_state()?;
    if as_json {
        println!("{}", serde_json::to_string(&state)?);
        return Ok(());
    }
    let pid_label = state
        .supervisor_pid
        .map(|p| p.to_string())
        .unwrap_or_else(|| "—".to_string());
    println!(
        "supervisor:    {} (pid {pid_label})",
        if state.supervisor_alive {
            "running"
        } else {
            "DOWN"
        },
    );
    let sessions_total = state.sessions.len();
    let sessions_with_daemon = state.sessions.iter().filter(|s| s.daemon_alive).count();
    println!(
        "sessions:      {sessions_total} initialized, {sessions_with_daemon} with live daemon"
    );
    // Per-session table — only show sessions whose daemon state is
    // "interesting" (alive OR has a stale pidfile pointing at a dead
    // process) to keep the output bounded on a 100+-session box. Pure
    // healthy sessions get a single summary line above.
    let mut shown = 0usize;
    for s in &state.sessions {
        // Skip sessions with no pidfile at all — they've never had a
        // daemon, nothing to report.
        if s.daemon_pid.is_none() {
            continue;
        }
        // Skip a "boringly healthy" session: alive daemon + recent
        // sync. Only worth showing when something's off.
        let recent = matches!(s.last_sync_age_seconds, Some(age) if age <= 60);
        if s.daemon_alive && recent {
            continue;
        }
        shown += 1;
        let age = s
            .last_sync_age_seconds
            .map(|a| format!("{a}s"))
            .unwrap_or_else(|| "?".to_string());
        let pid = s
            .daemon_pid
            .map(|p| p.to_string())
            .unwrap_or_else(|| "—".to_string());
        let liveness = if s.daemon_alive { "running" } else { "DOWN" };
        println!(
            "  {:<24} pid {:<7} {} last_sync {}",
            s.name, pid, liveness, age
        );
    }
    if shown == 0 && sessions_with_daemon > 0 {
        println!(
            "  (every session with a daemon is alive + synced within 60s — pass --json for full per-session detail)"
        );
    }
    if !state.unmanaged_pids.is_empty() {
        let pids: Vec<String> = state.unmanaged_pids.iter().map(u32::to_string).collect();
        println!(
            "unmanaged:     {} pid(s) — {} — `wire daemon` processes not mapped to any session's pidfile.",
            state.unmanaged_pids.len(),
            pids.join(", ")
        );
        // Annotate each unmanaged pid the same way `wire status` does
        // for orphans: cmdline + parsed --session arg.
        for pid in &state.unmanaged_pids {
            let cmdline = crate::platform::pid_cmdline(*pid);
            let session = cmdline
                .as_deref()
                .and_then(crate::platform::parse_session_arg);
            match (session, cmdline.as_deref()) {
                (Some(s), _) => println!("  pid {pid}: --session '{s}'"),
                (None, Some(c)) if !c.is_empty() => println!("  pid {pid}: cmdline={c}"),
                _ => println!("  pid {pid}: cmdline unavailable"),
            }
        }
    }
    // v0.14.2: surface sessions whose live daemon is on a stale
    // binary version. Supervisor's existing-pidfile check protects
    // alive daemons from respawn regardless of binary age, so
    // mid-upgrade fleets accumulate version-drifted children.
    // Operators see the list here + can act (manual kill, or a
    // future `wire upgrade --refresh-stale-children`).
    if !state.stale_binary_sessions.is_empty() {
        let our_version = env!("CARGO_PKG_VERSION");
        println!(
            "stale binary:  {} session(s) running daemons older than this CLI (v{our_version}). Supervisor won't respawn them until they exit.",
            state.stale_binary_sessions.len()
        );
        for name in &state.stale_binary_sessions {
            // Look up the recorded version + pid so the diagnostic
            // line is actionable: operator can `kill <pid>` to let
            // the supervisor respawn on the fresh binary.
            let session = state.sessions.iter().find(|s| &s.name == name);
            let ver = session
                .and_then(|s| s.daemon_version.clone())
                .unwrap_or_else(|| "?".to_string());
            let pid = session
                .and_then(|s| s.daemon_pid)
                .map(|p| p.to_string())
                .unwrap_or_else(|| "?".to_string());
            println!("  {name:<24} running v{ver} (pid {pid})");
        }
    }
    Ok(())
}

pub(super) fn cmd_responder_set(status: &str, reason: Option<&str>, as_json: bool) -> Result<()> {
    if !responder_status_allowed(status) {
        bail!("status must be one of: online, offline, oauth_locked, rate_limited, degraded");
    }
    let (_label, relay_url, slot_id, slot_token) = relay_slot_for(None)?;
    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string());
    let mut record = json!({
        "status": status,
        "set_at": now,
    });
    if let Some(reason) = reason {
        record["reason"] = json!(reason);
    }
    if status == "online" {
        record["last_success_at"] = json!(now);
    }
    let client = crate::relay_client::RelayClient::new(&relay_url);
    let saved = client.responder_health_set(&slot_id, &slot_token, &record)?;
    if as_json {
        println!("{}", serde_json::to_string(&saved)?);
    } else {
        let reason = saved
            .get("reason")
            .and_then(Value::as_str)
            .map(|r| format!(" — {r}"))
            .unwrap_or_default();
        println!(
            "responder {}{}",
            saved
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or(status),
            reason
        );
    }
    Ok(())
}

pub(super) fn cmd_responder_get(peer: Option<&str>, as_json: bool) -> Result<()> {
    let (label, relay_url, slot_id, slot_token) = relay_slot_for(peer)?;
    let client = crate::relay_client::RelayClient::new(&relay_url);
    let health = client.responder_health_get(&slot_id, &slot_token)?;
    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "target": label,
                "responder_health": health,
            }))?
        );
    } else if health.is_null() {
        println!("{label}: responder health not reported");
    } else {
        let status = health
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let reason = health
            .get("reason")
            .and_then(Value::as_str)
            .map(|r| format!(" — {r}"))
            .unwrap_or_default();
        let last_success = health
            .get("last_success_at")
            .and_then(Value::as_str)
            .map(|t| format!(" (last_success: {t})"))
            .unwrap_or_default();
        println!("{label}: {status}{reason}{last_success}");
    }
    Ok(())
}

pub(super) fn cmd_status_peer(peer: &str, as_json: bool) -> Result<()> {
    let (_label, relay_url, slot_id, slot_token) = relay_slot_for(Some(peer))?;
    let client = crate::relay_client::RelayClient::new(&relay_url);

    let started = std::time::Instant::now();
    let transport_ok = client.healthz().unwrap_or(false);
    let latency_ms = started.elapsed().as_millis() as u64;

    let (event_count, last_pull_at_unix) = client.slot_state(&slot_id, &slot_token)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let attention = match last_pull_at_unix {
        Some(last) if now.saturating_sub(last) <= 300 => json!({
            "status": "ok",
            "last_pull_at_unix": last,
            "age_seconds": now.saturating_sub(last),
            "event_count": event_count,
        }),
        Some(last) => json!({
            "status": "stale",
            "last_pull_at_unix": last,
            "age_seconds": now.saturating_sub(last),
            "event_count": event_count,
        }),
        None => json!({
            "status": "never_pulled",
            "last_pull_at_unix": Value::Null,
            "event_count": event_count,
        }),
    };

    let responder_health = client.responder_health_get(&slot_id, &slot_token)?;
    let responder = if responder_health.is_null() {
        json!({"status": "not_reported", "record": Value::Null})
    } else {
        json!({
            "status": responder_health
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("unknown"),
            "record": responder_health,
        })
    };

    let report = json!({
        "peer": peer,
        "transport": {
            "status": if transport_ok { "ok" } else { "error" },
            "relay_url": relay_url,
            "latency_ms": latency_ms,
        },
        "attention": attention,
        "responder": responder,
    });

    if as_json {
        println!("{}", serde_json::to_string(&report)?);
    } else {
        let transport_line = if transport_ok {
            format!("ok relay reachable ({latency_ms}ms)")
        } else {
            "error relay unreachable".to_string()
        };
        println!("transport      {transport_line}");
        match report["attention"]["status"].as_str().unwrap_or("unknown") {
            "ok" => println!(
                "attention      ok last pull {}s ago",
                report["attention"]["age_seconds"].as_u64().unwrap_or(0)
            ),
            "stale" => println!(
                "attention      stale last pull {}m ago",
                report["attention"]["age_seconds"].as_u64().unwrap_or(0) / 60
            ),
            "never_pulled" => println!("attention      never pulled since relay reset"),
            other => println!("attention      {other}"),
        }
        if report["responder"]["status"] == "not_reported" {
            println!("auto-responder not reported");
        } else {
            let record = &report["responder"]["record"];
            let status = record
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let reason = record
                .get("reason")
                .and_then(Value::as_str)
                .map(|r| format!(" — {r}"))
                .unwrap_or_default();
            println!("auto-responder {status}{reason}");
        }
    }
    Ok(())
}

// ---------- diag (structured trace) ----------

pub(super) fn cmd_diag(action: super::DiagAction) -> Result<()> {
    let state = config::state_dir()?;
    let knob = state.join("diag.enabled");
    let log_path = state.join("diag.jsonl");
    match action {
        super::DiagAction::Tail { limit, json } => {
            let entries = crate::diag::tail(limit);
            if json {
                for e in entries {
                    println!("{}", serde_json::to_string(&e)?);
                }
            } else if entries.is_empty() {
                println!("wire diag: no entries (diag may be disabled — `wire diag enable`)");
            } else {
                for e in entries {
                    let ts = e["ts"].as_u64().unwrap_or(0);
                    let ty = e["type"].as_str().unwrap_or("?");
                    let pid = e["pid"].as_u64().unwrap_or(0);
                    let payload = e["payload"].to_string();
                    println!("[{ts}] pid={pid} {ty} {payload}");
                }
            }
        }
        super::DiagAction::Enable => {
            config::ensure_dirs()?;
            std::fs::write(&knob, "1")?;
            println!("wire diag: enabled at {knob:?}");
        }
        super::DiagAction::Disable => {
            if knob.exists() {
                std::fs::remove_file(&knob)?;
            }
            println!("wire diag: disabled (env WIRE_DIAG may still flip it on per-process)");
        }
        super::DiagAction::Status { json } => {
            let enabled = crate::diag::is_enabled();
            let size = std::fs::metadata(&log_path).map(|m| m.len()).unwrap_or(0);
            if json {
                println!(
                    "{}",
                    serde_json::to_string(&serde_json::json!({
                        "enabled": enabled,
                        "log_path": log_path,
                        "log_size_bytes": size,
                    }))?
                );
            } else {
                println!("wire diag status");
                println!("  enabled:    {enabled}");
                println!("  log:        {log_path:?}");
                println!("  log size:   {size} bytes");
            }
        }
    }
    Ok(())
}

// ---------- doctor (single-command diagnostic) ----------

/// One DoctorCheck = one verdict on one health dimension.
#[derive(Clone, Debug, serde::Serialize)]
pub struct DoctorCheck {
    /// Short stable identifier (`daemon`, `relay`, `pair_rejections`, ...).
    /// Stable across versions for tooling consumption.
    pub id: String,
    /// PASS / WARN / FAIL.
    pub status: String,
    /// One-line human summary.
    pub detail: String,
    /// Optional remediation hint shown after the failing line.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
}

impl DoctorCheck {
    fn pass(id: &str, detail: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            status: "PASS".into(),
            detail: detail.into(),
            fix: None,
        }
    }
    fn warn(id: &str, detail: impl Into<String>, fix: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            status: "WARN".into(),
            detail: detail.into(),
            fix: Some(fix.into()),
        }
    }
    fn fail(id: &str, detail: impl Into<String>, fix: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            status: "FAIL".into(),
            detail: detail.into(),
            fix: Some(fix.into()),
        }
    }
}

/// `wire doctor` — single-command diagnostic for the silent-fail classes
/// 0.5.11 ships fixes for. Surfaces what each fix produces (P0.1 cursor
/// blocks, P0.2 pair-rejection logs, P0.4 daemon version mismatch, etc.)
/// so operators don't have to know where each lives.
pub(super) fn cmd_doctor(as_json: bool, recent_rejections: usize) -> Result<()> {
    let checks: Vec<DoctorCheck> = vec![
        check_daemon_health(),
        check_daemon_pid_consistency(),
        check_relay_reachable(),
        check_pair_rejections(recent_rejections),
        check_sync_freshness(),
        check_cursor_progress(),
        check_peer_staleness(7),
        check_and_heal_self_userinfo_endpoints(),
        check_stale_inbound_pairs(),
    ];

    let fails = checks.iter().filter(|c| c.status == "FAIL").count();
    let warns = checks.iter().filter(|c| c.status == "WARN").count();

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "checks": checks,
                "fail_count": fails,
                "warn_count": warns,
                "ok": fails == 0,
            }))?
        );
    } else {
        println!("wire doctor — {} checks", checks.len());
        // Name the home this run diagnoses — the same "which Claude?"
        // disambiguator `wire status` prints, so a doctor run in the wrong
        // window is self-evident.
        if let Ok(sd) = crate::config::state_dir() {
            println!("  home: {}", sd.display());
        }
        for c in &checks {
            let bullet = match c.status.as_str() {
                "PASS" => "✓",
                "WARN" => "!",
                "FAIL" => "✗",
                _ => "?",
            };
            println!("  {bullet} [{}] {}: {}", c.status, c.id, c.detail);
            if let Some(fix) = &c.fix {
                println!("      fix: {fix}");
            }
        }
        println!();
        if fails == 0 && warns == 0 {
            println!("ALL GREEN");
        } else {
            println!("{fails} FAIL, {warns} WARN");
        }
    }

    if fails > 0 {
        std::process::exit(1);
    }
    Ok(())
}

/// Pure verdict for sync freshness given the last-sync age (seconds, None =
/// no completed cycle recorded) and the number of events queued unsent.
///
/// This is the silent-send class `wire doctor` is supposed to catch but
/// didn't: `check_daemon_health` only proves the *process* is alive — a live
/// daemon whose sync loop is wedged (cursor not advancing, relay throwing)
/// shows a stale `last_sync` with a growing outbox while doctor reported
/// ALL GREEN. Split out as a pure fn so the verdict logic is unit-tested
/// without touching the filesystem.
fn sync_freshness_verdict(last_sync_age: Option<u64>, pending_total: u64) -> DoctorCheck {
    match last_sync_age {
        None => DoctorCheck::warn(
            "sync_freshness",
            "no completed sync cycle recorded for this home",
            "the daemon may not be running here — `wire status` to confirm it's bound to this WIRE_HOME, `wire up` to (re)start it",
        ),
        Some(age) if age > 60 && pending_total > 0 => DoctorCheck::fail(
            "sync_freshness",
            format!(
                "daemon last synced {age}s ago (stale) with {pending_total} event(s) queued unsent — outbound messages are silently stuck"
            ),
            "restart sync: `wire up`. If it recurs, `wire service install` (durable daemon) and check the relay: `wire doctor` / `wire status`",
        ),
        Some(age) if age > 60 => DoctorCheck::warn(
            "sync_freshness",
            format!(
                "daemon last synced {age}s ago (stale, >60s) — nothing queued, but the loop may be wedged"
            ),
            "`wire status` for detail; `wire up` to restart the daemon",
        ),
        Some(age) => DoctorCheck::pass("sync_freshness", format!("synced {age}s ago")),
    }
}

/// Check: the daemon's sync loop is actually advancing, not just alive.
/// Reuses the same shared helpers `wire status` surfaces (last_sync age +
/// pending-push breakdown) so the two agree by construction.
fn check_sync_freshness() -> DoctorCheck {
    let last_sync_age = crate::ensure_up::last_sync_age_seconds();
    let pending_total: u64 = config::compute_pending_push_breakdown()
        .iter()
        .map(|p| p.count)
        .sum();
    sync_freshness_verdict(last_sync_age, pending_total)
}

/// Check: daemon running, exactly one instance, no orphans.
///
/// Today's debug surfaced PID 54017 (old-binary wire daemon running for 4
/// days, advancing cursor without pinning). `wire status` lied about it.
/// `wire doctor` must catch THIS class: multiple daemons running, OR
/// pid-file claims daemon down while a process is actually up.
fn check_daemon_health() -> DoctorCheck {
    // v0.5.13 (issue #2 bug A): doctor PASSed on orphan-only state while
    // `wire status` reported DOWN, disagreeing for 25 min. v0.5.19 (#2
    // hardening): every surface routes through ensure_up::daemon_liveness
    // so they share one view of the world. No more parallel liveness
    // logic to drift out of sync.
    let snap = crate::ensure_up::daemon_liveness();
    let pgrep_pids = &snap.pgrep_pids;
    let pidfile_pid = snap.pidfile_pid;
    let pidfile_alive = snap.pidfile_alive;
    let orphan_pids = &snap.orphan_pids;

    let fmt_pids = |xs: &[u32]| -> String {
        xs.iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };

    match (pgrep_pids.len(), pidfile_alive, orphan_pids.is_empty()) {
        (0, _, _) => DoctorCheck::fail(
            "daemon",
            "no `wire daemon` process running — nothing pulling inbox or pushing outbox",
            "`wire daemon &` to start, or re-run `wire up <handle>@<relay>` to bootstrap",
        ),
        // Single daemon AND it matches the pidfile → healthy.
        (1, true, true) => DoctorCheck::pass(
            "daemon",
            format!(
                "one daemon running (pid {}, matches pidfile)",
                pgrep_pids[0]
            ),
        ),
        // Pidfile is alive but pgrep ALSO sees orphan processes.
        (n, true, false) => DoctorCheck::fail(
            "daemon",
            format!(
                "{n} `wire daemon` processes running (pids: {}); pidfile claims pid {} but pgrep also sees orphan(s): {}. \
                 The orphans race the relay cursor — they advance past events your current binary can't process. \
                 (Issue #2 exact class.)",
                fmt_pids(pgrep_pids),
                pidfile_pid.unwrap(),
                fmt_pids(orphan_pids),
            ),
            "`wire upgrade` kills all orphans and spawns a fresh daemon with a clean pidfile",
        ),
        // Pidfile is dead but processes ARE running → all are orphans.
        (n, false, _) => DoctorCheck::fail(
            "daemon",
            format!(
                "{n} `wire daemon` process(es) running (pids: {}) but pidfile {} — \
                 every running daemon is an orphan, advancing the cursor without coordinating with the current CLI. \
                 (Issue #2 exact class: doctor previously PASSed this state while `wire status` said DOWN.)",
                fmt_pids(pgrep_pids),
                match pidfile_pid {
                    Some(p) => format!("claims pid {p} which is dead"),
                    None => "is missing".to_string(),
                },
            ),
            "`wire upgrade` to kill the orphan(s) and spawn a fresh daemon",
        ),
        // v0.14.2 (#170 supervisor follow-up): the
        // `(n>1, true, orphan_pids.is_empty())` case is the
        // legitimate `wire daemon --all-sessions` supervisor topology
        // — supervisor + N session children, all accounted for via
        // their per-session pidfiles + the central supervisor.pid.
        // Pre-fix this fell through to the legacy "Multiple daemons
        // race the relay cursor" warning with a destructive
        // `pkill -f "wire daemon"; wire daemon &` recommendation
        // that would WIPE the working supervisor + every session
        // child. Operators on the #170 path saw it on every
        // `wire doctor`.
        (n, true, true) => {
            // Probe: is one of these pids the supervisor?
            let supervisor_pid: Option<u32> = crate::session::sessions_root()
                .ok()
                .map(|root| root.join("supervisor.pid"))
                .filter(|p| p.exists())
                .and_then(|p| std::fs::read_to_string(p).ok())
                .and_then(|s| s.trim().parse::<u32>().ok())
                .filter(|p| crate::ensure_up::pid_is_alive(*p));
            if let Some(sup) = supervisor_pid
                && pgrep_pids.contains(&sup)
            {
                let child_count = n.saturating_sub(1);
                DoctorCheck::pass(
                    "daemon",
                    format!(
                        "supervisor (pid {sup}) + {child_count} session child daemon(s) — legitimate #170 `--all-sessions` topology, no orphans"
                    ),
                )
            } else {
                DoctorCheck::warn(
                    "daemon",
                    format!(
                        "{n} `wire daemon` processes running (pids: {}). Multiple daemons race the relay cursor.",
                        fmt_pids(pgrep_pids)
                    ),
                    "kill all-but-one: `pkill -f \"wire daemon\"; wire daemon &`",
                )
            }
        }
    }
}

/// Check: structured pidfile matches running daemon. Spark's P0.4 5th
/// check. Surfaces version mismatch (daemon running old binary text in
/// memory under a current symlink — today's exact bug class), schema
/// drift (future format bumps), and identity contamination (daemon's
/// recorded DID doesn't match this box's configured DID).
///
/// v0.5.19 (#2 hardening): also surfaces stale pidfiles — a well-formed
/// JSON pid record whose recorded `pid` is no longer a live OS process.
/// Pre-hardening this check PASSed in that state (it only validated
/// content, not liveness), letting `wire status: DOWN` and
/// `wire doctor: PASS` disagree for 25 min in incident #2.
fn check_daemon_pid_consistency() -> DoctorCheck {
    let snap = crate::ensure_up::daemon_liveness();
    match &snap.record {
        crate::ensure_up::PidRecord::Missing => DoctorCheck::pass(
            "daemon_pid_consistency",
            "no daemon.pid yet — fresh box or daemon never started",
        ),
        crate::ensure_up::PidRecord::Corrupt(reason) => DoctorCheck::warn(
            "daemon_pid_consistency",
            format!("daemon.pid is corrupt: {reason}"),
            "delete state/wire/daemon.pid; next `wire daemon &` will rewrite",
        ),
        crate::ensure_up::PidRecord::Json(d) => {
            // v0.5.19 liveness gate: if the recorded pid is dead, the
            // pidfile is stale and the rest of the content drift checks
            // are moot — `wire upgrade` is the answer regardless.
            if !snap.pidfile_alive {
                return DoctorCheck::warn(
                    "daemon_pid_consistency",
                    format!(
                        "daemon.pid records pid {pid} (v{version}) but that process is not running — \
                         pidfile is stale. `wire status` will report DOWN, but pre-v0.5.19 doctor \
                         silently PASSed this state and ignored any live orphan daemons (#2 root cause).",
                        pid = d.pid,
                        version = d.version,
                    ),
                    "`wire upgrade` to clean up the stale pidfile + spawn a fresh daemon \
                     (kills any orphan daemon advancing the cursor without coordination)",
                );
            }
            let mut issues: Vec<String> = Vec::new();
            if d.schema != crate::ensure_up::DAEMON_PID_SCHEMA {
                issues.push(format!(
                    "schema={} (expected {})",
                    d.schema,
                    crate::ensure_up::DAEMON_PID_SCHEMA
                ));
            }
            let cli_version = env!("CARGO_PKG_VERSION");
            if d.version != cli_version {
                issues.push(format!("version daemon={} cli={cli_version}", d.version));
            }
            if !std::path::Path::new(&d.bin_path).exists() {
                issues.push(format!("bin_path {} missing on disk", d.bin_path));
            }
            // Cross-check DID + relay against current config (best-effort).
            if let Ok(card) = config::read_agent_card()
                && let Some(current_did) = card.get("did").and_then(Value::as_str)
                && let Some(recorded_did) = &d.did
                && recorded_did != current_did
            {
                issues.push(format!(
                    "did daemon={recorded_did} config={current_did} — identity drift"
                ));
            }
            if let Ok(state) = config::read_relay_state()
                && let Some(current_relay) = state
                    .get("self")
                    .and_then(|s| s.get("relay_url"))
                    .and_then(Value::as_str)
                && let Some(recorded_relay) = &d.relay_url
                && recorded_relay != current_relay
            {
                issues.push(format!(
                    "relay_url daemon={recorded_relay} config={current_relay} — relay-migration drift"
                ));
            }
            if issues.is_empty() {
                DoctorCheck::pass(
                    "daemon_pid_consistency",
                    format!(
                        "daemon v{} bound to {} as {}",
                        d.version,
                        d.relay_url.as_deref().unwrap_or("?"),
                        d.did.as_deref().unwrap_or("?")
                    ),
                )
            } else {
                DoctorCheck::warn(
                    "daemon_pid_consistency",
                    format!("daemon pidfile drift: {}", issues.join("; ")),
                    "`wire upgrade` to atomically restart daemon with current config".to_string(),
                )
            }
        }
    }
}

/// Check: bound relay's /healthz returns 200.
fn check_relay_reachable() -> DoctorCheck {
    let state = match config::read_relay_state() {
        Ok(s) => s,
        Err(e) => {
            return DoctorCheck::fail(
                "relay",
                format!("could not read relay state: {e}"),
                "run `wire up <handle>@<relay>` to bootstrap",
            );
        }
    };
    let url = state
        .get("self")
        .and_then(|s| s.get("relay_url"))
        .and_then(Value::as_str)
        .unwrap_or("");
    if url.is_empty() {
        return DoctorCheck::warn(
            "relay",
            "no relay bound — wire send/pull will not work",
            "run `wire bind-relay <url>` or `wire up <handle>@<relay>`",
        );
    }
    let client = crate::relay_client::RelayClient::new(url);
    match client.check_healthz() {
        Ok(()) => DoctorCheck::pass("relay", format!("{url} healthz=200")),
        Err(e) => DoctorCheck::fail(
            "relay",
            format!("{url} unreachable: {e}"),
            format!("network reachable to {url}? relay running? check `curl {url}/healthz`"),
        ),
    }
}

/// Check: count recent entries in pair-rejected.jsonl (P0.2 output). Every
/// entry there is a silent failure that, pre-0.5.11, would have left the
/// operator wondering why pairing didn't complete.
fn check_pair_rejections(recent_n: usize) -> DoctorCheck {
    let path = match config::state_dir() {
        Ok(d) => d.join("pair-rejected.jsonl"),
        Err(e) => {
            return DoctorCheck::warn(
                "pair_rejections",
                format!("could not resolve state dir: {e}"),
                "set WIRE_HOME or fix XDG_STATE_HOME",
            );
        }
    };
    if !path.exists() {
        return DoctorCheck::pass(
            "pair_rejections",
            "no pair-rejected.jsonl — no recorded pair failures",
        );
    }
    let body = match std::fs::read_to_string(&path) {
        Ok(b) => b,
        Err(e) => {
            return DoctorCheck::warn(
                "pair_rejections",
                format!("could not read {path:?}: {e}"),
                "check file permissions",
            );
        }
    };
    let lines: Vec<&str> = body.lines().filter(|l| !l.is_empty()).collect();
    if lines.is_empty() {
        return DoctorCheck::pass("pair_rejections", "pair-rejected.jsonl present but empty");
    }
    let total = lines.len();
    let recent: Vec<&str> = lines.iter().rev().take(recent_n).rev().copied().collect();
    let mut summary: Vec<String> = Vec::new();
    for line in &recent {
        if let Ok(rec) = serde_json::from_str::<Value>(line) {
            let peer = rec.get("peer").and_then(Value::as_str).unwrap_or("?");
            let code = rec.get("code").and_then(Value::as_str).unwrap_or("?");
            summary.push(format!("{peer}/{code}"));
        }
    }
    DoctorCheck::warn(
        "pair_rejections",
        format!(
            "{total} pair failures recorded. recent: [{}]",
            summary.join(", ")
        ),
        format!(
            "inspect {path:?} for full details. Each entry is a pair-flow error that previously silently dropped — re-run `wire dial <handle>@<relay>` to retry."
        ),
    )
}

/// Check: cursor isn't stuck. We can't tell without polling — but we can
/// report the current cursor position so operators see if it changes.
/// Real "stuck" detection needs two pulls separated in time; defer that
/// behaviour to a `wire doctor --watch` mode.
///
/// Heal stale userinfo from this agent's own published relay endpoints.
///
/// Failure mode this check closes:
///   PR #61 added a guard at the WRITE side that prevents NEW userinfo-
///   bearing endpoints (`https://<handle>@<host>`) from ever being
///   persisted or published. But operators who ran a pre-#61 `wire up
///   <handle>@<relay>` already had the malformed endpoint baked into
///   their on-disk `self.endpoints[]` AND their signed agent-card AND
///   their phonebook entry. The fix prevented the bleeding; it didn't
///   heal the wound. Symptoms still visible:
///     - Every inbound POST to the malformed endpoint (pair_drop_ack,
///       messages) gets a Cloudflare 400 ("missing Bearer token" /
///       bare 400). Peers running pre-#62 wire can't deliver to us at
///       all (the failover from #62 lets newer peers walk past the
///       bad first endpoint to a clean one if both are published —
///       but two-endpoint operators still get a 400 for every event
///       on their FIRST attempt, and operators with only the
///       malformed endpoint are unreachable).
///     - `wire pull` from our own malformed slot 400s on every cycle
///       (the operator sees a stderr error line every poll).
///     - Surfaced concretely when swift-harbor ↔ slate-lotus paired
///       2026-05-27: slate-lotus's pair_drop_ack 400'd; my own pulls
///       400'd; bilateral handshake couldn't complete via the bad
///       endpoint.
///
/// This is a healable failure mode — the same `strip_relay_url_userinfo`
/// logic from #61 can be applied to existing on-disk state. We do it
/// inside `wire doctor` (rather than a separate `wire heal` command)
/// because:
///   1. `wire doctor` is the canonical "what's wrong + fix it" surface
///      operators already know to run when something looks off.
///   2. The mutation is unambiguously correct — userinfo on a self-
///      published relay endpoint has zero legitimate cases (the
///      one-name rule means the handle is DID-derived, never URL
///      userinfo).
///   3. Auto-heal is consistent with what `wire bind-relay https://...`
///      / `wire claim` already do at the WRITE side under #61 —
///      this just extends the same guard to read-side cleanup.
///
/// What this check does:
///   - Reads `relay.json` and inspects `self.endpoints[]` plus the
///     legacy top-level `self.relay_url`/`slot_id`/`slot_token` triple.
///   - If any endpoint's `relay_url` contains userinfo, removes that
///     endpoint from the array AND (if the legacy top-level was the
///     malformed one) promotes the first clean endpoint's coords to
///     the legacy slots.
///   - Atomically writes back via `write_relay_state` (full lock +
///     tmp+rename, same path every other writer uses).
///   - Reports PASS if nothing needed healing, WARN if healing happened
///     (with the list of stripped URLs + a remediation pointer to
///     `wire claim <persona>` for re-publishing the agent-card to the
///     phonebook).
///
/// Re-claim is NOT auto-run here: the doctor check is read-state-bound,
/// and `wire claim` requires a clean agent-card resign + network
/// round-trip + persona arg. Operators get the explicit next step in
/// the WARN fix text. Two-step is the right friction: heal silently,
/// claim explicitly.
fn check_and_heal_self_userinfo_endpoints() -> DoctorCheck {
    let mut state = match config::read_relay_state() {
        Ok(s) => s,
        Err(_) => {
            return DoctorCheck::pass(
                "self-userinfo-endpoints",
                "no relay state yet — nothing published to heal".to_string(),
            );
        }
    };
    let self_block = match state.get_mut("self").and_then(Value::as_object_mut) {
        Some(s) => s,
        None => {
            return DoctorCheck::pass(
                "self-userinfo-endpoints",
                "no self block in relay state — nothing published to heal".to_string(),
            );
        }
    };

    let mut stripped: Vec<String> = Vec::new();
    let mut clean_seed: Option<(String, String, String)> = None;

    if let Some(endpoints) = self_block
        .get_mut("endpoints")
        .and_then(Value::as_array_mut)
    {
        endpoints.retain(|ep| {
            let url = ep.get("relay_url").and_then(Value::as_str).unwrap_or("");
            // Reuse the exact same authority-only userinfo detection as
            // #61's assert_relay_url_clean_for_publish so any future
            // change to that authority parse stays in lockstep.
            if super::setup::assert_relay_url_clean_for_publish(url).is_err() {
                stripped.push(url.to_string());
                false
            } else {
                if clean_seed.is_none() {
                    clean_seed = Some((
                        url.to_string(),
                        ep.get("slot_id")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string(),
                        ep.get("slot_token")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string(),
                    ));
                }
                true
            }
        });
    }

    // Heal the legacy top-level relay_url/slot_id/slot_token triple if it
    // was the malformed one. Without this, v0.5.16-era readers (and the
    // pair_drop_ack path that falls back to legacy fields) still pick up
    // the userinfo URL even after we cleaned endpoints[].
    let mut legacy_healed = false;
    let legacy_url = self_block
        .get("relay_url")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if !legacy_url.is_empty()
        && super::setup::assert_relay_url_clean_for_publish(&legacy_url).is_err()
    {
        if let Some((url, sid, tok)) = &clean_seed {
            self_block.insert("relay_url".to_string(), Value::String(url.clone()));
            self_block.insert("slot_id".to_string(), Value::String(sid.clone()));
            self_block.insert("slot_token".to_string(), Value::String(tok.clone()));
            legacy_healed = true;
            stripped.push(format!("(legacy top-level) {legacy_url}"));
        } else {
            // No clean endpoint exists to promote — the operator only
            // has malformed endpoints. We can't auto-heal this safely
            // (would leave them with no inbox); surface as WARN with
            // explicit re-bind instructions and DON'T mutate.
            return DoctorCheck::warn(
                "self-userinfo-endpoints",
                format!(
                    "your published endpoint is malformed (`{legacy_url}` — handle as URL \
                     userinfo, the bug PR #61 prevents going forward) AND no clean endpoint \
                     exists to fall back to. Inbound POSTs to this endpoint 4xx; bilateral \
                     pairing can't complete."
                ),
                "Bind a clean federation slot first, then re-run doctor to heal: \
                 `wire bind-relay https://wireup.net` (or your own relay). The bind \
                 adds a clean endpoint additively; the next `wire doctor` run then \
                 strips the malformed one safely. Finally re-publish your card with \
                 `wire claim <your-persona>` so the phonebook serves the clean shape."
                    .to_string(),
            );
        }
    }

    if stripped.is_empty() && !legacy_healed {
        return DoctorCheck::pass(
            "self-userinfo-endpoints",
            "no malformed endpoints in self-state".to_string(),
        );
    }

    // Persist the healed state. Best-effort: if the write fails, the
    // operator still sees the WARN and can run `wire claim` to re-publish;
    // they keep the malformed entry on disk until the next doctor cycle.
    if let Err(e) = config::write_relay_state(&state) {
        return DoctorCheck::warn(
            "self-userinfo-endpoints",
            format!(
                "detected {} malformed userinfo-bearing endpoint(s) in self-state but \
                 failed to persist the heal: {e:#}. Found: {}",
                stripped.len(),
                stripped.join(", ")
            ),
            "re-run `wire doctor` — likely a transient lock contention".to_string(),
        );
    }

    DoctorCheck::warn(
        "self-userinfo-endpoints",
        format!(
            "healed {} malformed endpoint(s) in self-state on disk: {}. \
             These were the `https://<handle>@<host>` shape that PR #61 prevents \
             at the write side but couldn't retroactively scrub from existing \
             operators. relay.json is now clean.",
            stripped.len(),
            stripped.join(", ")
        ),
        "re-publish your agent-card to the phonebook so peers resolve to the \
         clean endpoint: `wire claim <your-persona>` (find your persona with \
         `wire whoami`)."
            .to_string(),
    )
}

/// v0.14.3: surface pre-#171 stale pending_inbound records for
/// peers already at VERIFIED+ tier. The record itself is benign
/// (operator can clear with `wire reject <handle>`) but until
/// cleared it keeps surfacing in `wire status --json` as
/// `stale_inbound_handles`, which leaks into automation. Doctor is
/// the right place to surface low-priority hygiene — operators
/// scan it intentionally instead of seeing it on every status
/// call.
fn check_stale_inbound_pairs() -> DoctorCheck {
    let pinned_verified: std::collections::HashSet<String> = config::read_trust()
        .ok()
        .and_then(|t| t.get("agents").and_then(Value::as_object).cloned())
        .map(|agents| {
            agents
                .into_iter()
                .filter_map(|(h, a)| {
                    let tier = a.get("tier").and_then(Value::as_str).unwrap_or("");
                    if matches!(tier, "VERIFIED" | "ORG_VERIFIED" | "ATTESTED") {
                        Some(h)
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    let stale: Vec<String> = crate::pending_inbound_pair::list_pending_inbound()
        .unwrap_or_default()
        .into_iter()
        .filter(|p| pinned_verified.contains(&p.peer_handle))
        .map(|p| p.peer_handle)
        .collect();
    if stale.is_empty() {
        return DoctorCheck::pass(
            "stale-inbound-pairs",
            "no pre-#171 leftover pending_inbound records for VERIFIED peers",
        );
    }
    let n = stale.len();
    let list = stale.join(", ");
    let fix_list = stale
        .iter()
        .map(|h| format!("wire reject {h}"))
        .collect::<Vec<_>>()
        .join(" && ");
    DoctorCheck::warn(
        "stale-inbound-pairs",
        format!(
            "{n} VERIFIED peer(s) still carry a pre-#171 pending_inbound record: {list}. Benign but leaks into `wire status --json.pending_pairs.stale_inbound_handles`."
        ),
        format!("clear with `{fix_list}`"),
    )
}

fn check_peer_staleness(max_silent_days: u64) -> DoctorCheck {
    let state = match config::read_relay_state() {
        Ok(s) => s,
        Err(_) => {
            return DoctorCheck::pass(
                "peer-staleness",
                "no relay state yet — nothing pinned to check".to_string(),
            );
        }
    };
    let peers = match state.get("peers").and_then(Value::as_object) {
        Some(p) => p,
        None => {
            return DoctorCheck::pass("peer-staleness", "no pinned peers".to_string());
        }
    };
    if peers.is_empty() {
        return DoctorCheck::pass("peer-staleness", "no pinned peers".to_string());
    }
    let inbox_dir = match config::inbox_dir() {
        Ok(d) => d,
        Err(_) => {
            return DoctorCheck::warn(
                "peer-staleness",
                "could not resolve inbox dir; skipping peer-staleness check".to_string(),
                "check `wire status` for state-dir resolution".to_string(),
            );
        }
    };
    let threshold_secs = max_silent_days * 24 * 60 * 60;
    let threshold = std::time::Duration::from_secs(threshold_secs);
    let now = std::time::SystemTime::now();
    // v0.14.3 (#14): prefer the daemon-written
    // `peers[<peer>].last_inbound_event_at` (RFC3339) over inbox
    // file mtime — mtime is fragile (backup/restore/cp/touch all
    // break it; FAT32 has 2s resolution etc.) and the daemon-side
    // field is the load-bearing sender-side staleness signal.
    // Falls back to mtime when the field is absent (pre-v0.14.3
    // sessions, or never-received-anything peers).
    let now_unix = now
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let mut stale: Vec<(String, u64, &'static str)> = Vec::new();
    for (peer, info) in peers {
        // v0.14.3 first-pass: the daemon-written field.
        let daemon_signal_ts = info
            .get("last_inbound_event_at")
            .and_then(Value::as_str)
            .and_then(|s| {
                time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()
            })
            .map(|odt| odt.unix_timestamp());
        if let Some(ts) = daemon_signal_ts {
            let age = now_unix.saturating_sub(ts) as u64;
            if age > threshold_secs {
                stale.push((peer.clone(), age / (24 * 60 * 60), "silent"));
            }
            continue;
        }
        // Fallback: inbox file mtime (pre-v0.14.3 or never-pulled peer).
        let path = inbox_dir.join(format!("{peer}.jsonl"));
        let (age_days, kind) = match std::fs::metadata(&path) {
            Ok(meta) => match meta
                .modified()
                .ok()
                .and_then(|m| now.duration_since(m).ok())
            {
                Some(d) if d > threshold => (d.as_secs() / (24 * 60 * 60), "silent"),
                Some(_) => continue, // fresh — not stale
                None => (0, "unknown-mtime"),
            },
            Err(_) => (max_silent_days + 1, "no-inbox-file"),
        };
        stale.push((peer.clone(), age_days, kind));
    }
    if stale.is_empty() {
        return DoctorCheck::pass(
            "peer-staleness",
            format!(
                "all {} pinned peer(s) have inbox traffic within the last {max_silent_days} day(s)",
                peers.len()
            ),
        );
    }
    let detail = stale
        .iter()
        .map(|(p, d, k)| match *k {
            "no-inbox-file" => format!("{p} (no inbox file)"),
            "unknown-mtime" => format!("{p} (unknown last-event time)"),
            _ => format!("{p} ({d}d silent)"),
        })
        .collect::<Vec<_>>()
        .join(", ");
    DoctorCheck::warn(
        "peer-staleness",
        format!(
            "{} pinned peer(s) silent for >{max_silent_days}d: {detail}. \
             If the peer re-bound their relay slot, our pin is now stale — \
             we push successfully to a dead slot and they never see us \
             (asymmetric failure, both sides report green).",
            stale.len()
        ),
        "re-pair with `wire add <peer>@<relay>` to refresh the slot. \
         Once issue #15 lands, this also auto-resolves on 410 Gone."
            .to_string(),
    )
}

fn check_cursor_progress() -> DoctorCheck {
    let state = match config::read_relay_state() {
        Ok(s) => s,
        Err(e) => {
            return DoctorCheck::warn(
                "cursor",
                format!("could not read relay state: {e}"),
                "check ~/Library/Application Support/wire/relay.json",
            );
        }
    };
    let cursor = state
        .get("self")
        .and_then(|s| s.get("last_pulled_event_id"))
        .and_then(Value::as_str)
        .map(|s| s.chars().take(16).collect::<String>())
        .unwrap_or_else(|| "<none>".to_string());
    DoctorCheck::pass(
        "cursor",
        format!(
            "current cursor: {cursor}. P0.1 cursor blocking is active — see `wire pull --json` for cursor_blocked / rejected[].blocks_cursor entries."
        ),
    )
}

#[cfg(test)]
mod doctor_tests {
    use super::*;

    #[test]
    fn sync_freshness_fails_when_stale_with_queued_events() {
        // The silent-send class doctor exists to catch: the daemon process
        // is alive (check_daemon_health PASSes) but its sync is wedged —
        // last sync is old AND events are queued unsent. Today doctor went
        // all-green here; this must FAIL.
        let c = sync_freshness_verdict(Some(3600), 4);
        assert_eq!(c.status, "FAIL");
        assert!(c.detail.contains('4'), "names the queued count");
        assert!(c.fix.is_some());
    }

    #[test]
    fn sync_freshness_warns_when_stale_but_nothing_queued() {
        // Stale sync with an empty outbox is suspicious but not a stuck
        // message — WARN, not FAIL (don't cry wolf on an idle box).
        let c = sync_freshness_verdict(Some(3600), 0);
        assert_eq!(c.status, "WARN");
    }

    #[test]
    fn sync_freshness_passes_when_recent() {
        let c = sync_freshness_verdict(Some(5), 0);
        assert_eq!(c.status, "PASS");
        // A fresh sync with queued events is mid-flight, not stuck.
        assert_eq!(sync_freshness_verdict(Some(5), 9).status, "PASS");
    }

    #[test]
    fn sync_freshness_warns_when_never_synced() {
        // No record at all: can't confirm freshness. WARN with a pointer at
        // the daemon, not a scary FAIL on a fresh box.
        let c = sync_freshness_verdict(None, 0);
        assert_eq!(c.status, "WARN");
    }

    #[test]
    fn doctor_check_constructors_set_status_correctly() {
        // Silent-fail-prevention rule: pass/warn/fail must be visibly
        // distinguishable to operators. If any constructor lets the wrong
        // status through, `wire doctor` lies and we're back to today's
        // 30-minute debug.
        let p = DoctorCheck::pass("x", "ok");
        assert_eq!(p.status, "PASS");
        assert_eq!(p.fix, None);

        let w = DoctorCheck::warn("x", "watch out", "do this");
        assert_eq!(w.status, "WARN");
        assert_eq!(w.fix, Some("do this".to_string()));

        let f = DoctorCheck::fail("x", "broken", "fix it");
        assert_eq!(f.status, "FAIL");
        assert_eq!(f.fix, Some("fix it".to_string()));
    }

    #[test]
    fn check_pair_rejections_no_file_is_pass() {
        // Fresh-box case: no pair-rejected.jsonl yet. Must NOT report this
        // as a problem.
        config::test_support::with_temp_home(|| {
            config::ensure_dirs().unwrap();
            let c = check_pair_rejections(5);
            assert_eq!(c.status, "PASS", "no file should be PASS, got {c:?}");
        });
    }

    #[test]
    fn check_pair_rejections_with_entries_warns() {
        // Existence of rejections is itself a signal — even if each entry
        // is a "known good failure," the operator wants to know they
        // happened.
        config::test_support::with_temp_home(|| {
            config::ensure_dirs().unwrap();
            crate::pair_invite::record_pair_rejection(
                "willard",
                "pair_drop_ack_send_failed",
                "POST 502",
            );
            let c = check_pair_rejections(5);
            assert_eq!(c.status, "WARN");
            assert!(c.detail.contains("1 pair failures"));
            assert!(c.detail.contains("willard/pair_drop_ack_send_failed"));
        });
    }

    #[test]
    fn check_peer_staleness_no_peers_is_pass() {
        // Fresh box / no pin yet: must NOT report this as a problem
        // (nothing to be stale about).
        config::test_support::with_temp_home(|| {
            config::ensure_dirs().unwrap();
            let c = check_peer_staleness(7);
            assert_eq!(c.status, "PASS", "no peers should be PASS, got {c:?}");
        });
    }

    #[test]
    fn check_peer_staleness_pinned_with_no_inbox_file_warns() {
        // Issue #14 asymmetric-stale-pin: peer is pinned but we've NEVER
        // received an event from them (no inbox file at all). That's
        // exactly the "we pushed N events, got 0 back" smell the WARN is
        // designed to catch.
        config::test_support::with_temp_home(|| {
            config::ensure_dirs().unwrap();
            // Seed a pinned peer with no corresponding inbox file.
            let mut state = json!({
                "peers": {
                    "stale-peer": {
                        "relay_url": "https://wireup.net",
                        "slot_id": "deadslot",
                        "slot_token": "tok",
                    }
                }
            });
            state["self"] = json!({});
            config::write_relay_state(&state).unwrap();

            let c = check_peer_staleness(7);
            assert_eq!(
                c.status, "WARN",
                "pinned peer with no inbox file must surface: {c:?}"
            );
            assert!(
                c.detail.contains("stale-peer"),
                "WARN must name the silent peer so the operator can act: {}",
                c.detail
            );
            assert!(
                c.detail.contains("asymmetric")
                    || c.detail.contains("stale")
                    || c.detail.contains("dead slot"),
                "WARN must surface the failure-mode language so the operator \
                 finds the diagnosis without re-tracing: {}",
                c.detail
            );
            assert!(
                c.fix
                    .as_ref()
                    .is_some_and(|f| f.contains("wire add") && f.contains("#15")),
                "fix pointer must reference both the manual re-pair AND the \
                 follow-up issue (#15) that will automate this: {:?}",
                c.fix
            );
        });
    }

    #[test]
    fn check_peer_staleness_pinned_with_fresh_inbox_is_pass() {
        // Negative case: pinned peer with a recent inbox event must NOT
        // be reported. This prevents the false-positive that would otherwise
        // make operators ignore the WARN.
        config::test_support::with_temp_home(|| {
            config::ensure_dirs().unwrap();
            let mut state = json!({
                "peers": {
                    "active-peer": {
                        "relay_url": "https://wireup.net",
                        "slot_id": "freshslot",
                        "slot_token": "tok",
                    }
                }
            });
            state["self"] = json!({});
            config::write_relay_state(&state).unwrap();

            let inbox = config::inbox_dir().unwrap();
            std::fs::create_dir_all(&inbox).unwrap();
            std::fs::write(
                inbox.join("active-peer.jsonl"),
                "{\"event_id\":\"recent\"}\n",
            )
            .unwrap();

            let c = check_peer_staleness(7);
            assert_eq!(c.status, "PASS", "fresh inbox should not warn: {c:?}");
        });
    }

    #[test]
    fn check_peer_staleness_daemon_field_overrides_mtime() {
        // v0.14.3 (#14): when peers[<p>].last_inbound_event_at is
        // present, that signal trumps file mtime. Even with a
        // fresh inbox file mtime, an OLD daemon-written timestamp
        // must trigger the WARN — backup-restore should not mask
        // the real silence.
        config::test_support::with_temp_home(|| {
            config::ensure_dirs().unwrap();
            let mut state = json!({
                "peers": {
                    "ghost-peer": {
                        "relay_url": "https://wireup.net",
                        "slot_id": "ghostslot",
                        "slot_token": "tok",
                        "last_inbound_event_at": "2026-05-01T00:00:00Z",
                    }
                }
            });
            state["self"] = json!({});
            config::write_relay_state(&state).unwrap();
            // Fresh inbox mtime — would PASS via the fallback.
            let inbox = config::inbox_dir().unwrap();
            std::fs::create_dir_all(&inbox).unwrap();
            std::fs::write(inbox.join("ghost-peer.jsonl"), "{\"event_id\":\"x\"}\n").unwrap();
            let c = check_peer_staleness(7);
            assert_eq!(
                c.status, "WARN",
                "daemon-field staleness must override fresh mtime: {c:?}"
            );
            assert!(c.detail.contains("ghost-peer"), "got: {}", c.detail);
        });
    }

    #[test]
    fn check_peer_staleness_daemon_field_fresh_overrides_old_mtime() {
        // Mirror case: a recent daemon-written timestamp must
        // PASS even with an old inbox file mtime. Backup-restore
        // case in reverse — operator restored an old inbox file
        // but pulled fresh events since.
        config::test_support::with_temp_home(|| {
            config::ensure_dirs().unwrap();
            // Stamp NOW-ish via OffsetDateTime so we don't drift.
            let now = time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap();
            let mut state = json!({
                "peers": {
                    "active-peer": {
                        "relay_url": "https://wireup.net",
                        "slot_id": "freshslot",
                        "slot_token": "tok",
                        "last_inbound_event_at": now,
                    }
                }
            });
            state["self"] = json!({});
            config::write_relay_state(&state).unwrap();
            // Old inbox file mtime — would FAIL via the fallback.
            // We skip making it old (today's mtime works since the
            // field-driven path runs first and short-circuits).
            let c = check_peer_staleness(7);
            assert_eq!(
                c.status, "PASS",
                "recent daemon-field stamp must PASS regardless of mtime: {c:?}"
            );
        });
    }

    #[test]
    fn check_self_userinfo_no_state_is_pass() {
        // Fresh box (no relay.json yet) must NOT WARN — there's nothing
        // published to heal, and treating a missing file as a problem
        // would scare every new operator on first `wire doctor` run.
        config::test_support::with_temp_home(|| {
            // Don't even call ensure_dirs — simulate truly fresh state.
            let c = check_and_heal_self_userinfo_endpoints();
            assert_eq!(c.status, "PASS", "no state should be PASS, got {c:?}");
        });
    }

    #[test]
    fn check_self_userinfo_clean_state_is_pass_no_mutation() {
        // Negative case: clean self.endpoints[] must not trigger a heal,
        // must not mutate relay.json. Prevents the false-positive that
        // would make operators distrust the doctor.
        config::test_support::with_temp_home(|| {
            config::ensure_dirs().unwrap();
            let state = json!({
                "self": {
                    "endpoints": [
                        {
                            "relay_url": "https://wireup.net",
                            "scope": "Federation",
                            "slot_id": "abc",
                            "slot_token": "tok"
                        }
                    ],
                    "relay_url": "https://wireup.net",
                    "slot_id": "abc",
                    "slot_token": "tok"
                },
                "peers": {}
            });
            config::write_relay_state(&state).unwrap();

            let c = check_and_heal_self_userinfo_endpoints();
            assert_eq!(c.status, "PASS", "clean state should be PASS: {c:?}");

            // Verify state is byte-identical (no spurious write).
            let after = config::read_relay_state().unwrap();
            assert_eq!(after, state, "PASS path must NOT mutate relay.json");
        });
    }

    #[test]
    fn check_self_userinfo_heals_malformed_endpoint_and_promotes_clean() {
        // THE regression case (swift-harbor / slate-lotus pairing 2026-05-27):
        // relay.json has a malformed first endpoint from before #61 AND a
        // clean second endpoint from a later `wire bind-relay`. The check
        // must (a) strip the malformed one, (b) promote the clean one's
        // coords to the legacy top-level triple, (c) write back, (d) emit
        // a WARN with the stripped URL + `wire claim` remediation pointer.
        config::test_support::with_temp_home(|| {
            config::ensure_dirs().unwrap();
            let state = json!({
                "self": {
                    "endpoints": [
                        {
                            "relay_url": "https://copilot-agent@wireup.net",
                            "scope": "Federation",
                            "slot_id": "stale-id",
                            "slot_token": "stale-token"
                        },
                        {
                            "relay_url": "https://wireup.net",
                            "scope": "Federation",
                            "slot_id": "clean-id",
                            "slot_token": "clean-token"
                        }
                    ],
                    "relay_url": "https://copilot-agent@wireup.net",
                    "slot_id": "stale-id",
                    "slot_token": "stale-token"
                },
                "peers": {}
            });
            config::write_relay_state(&state).unwrap();

            let c = check_and_heal_self_userinfo_endpoints();
            assert_eq!(c.status, "WARN", "heal should report WARN: {c:?}");
            assert!(
                c.detail.contains("healed") && c.detail.contains("copilot-agent@wireup.net"),
                "WARN must name the stripped URL so the operator sees what changed: {}",
                c.detail
            );
            assert!(
                c.fix.as_ref().is_some_and(|f| f.contains("wire claim")),
                "fix must point at re-publishing the agent-card so the phonebook entry \
                 matches the healed state on disk: {:?}",
                c.fix
            );

            // Verify the file on disk is healed:
            //   - endpoints[] contains ONLY the clean entry.
            //   - legacy top-level fields promoted from the clean entry.
            let after = config::read_relay_state().unwrap();
            let endpoints = after["self"]["endpoints"].as_array().unwrap();
            assert_eq!(endpoints.len(), 1, "malformed endpoint must be removed");
            assert_eq!(endpoints[0]["relay_url"], "https://wireup.net");
            assert_eq!(after["self"]["relay_url"], "https://wireup.net");
            assert_eq!(after["self"]["slot_id"], "clean-id");
            assert_eq!(after["self"]["slot_token"], "clean-token");
        });
    }

    #[test]
    fn check_self_userinfo_no_clean_fallback_warns_without_mutating() {
        // Edge: operator only has the malformed endpoint, no clean fallback
        // to promote. Auto-healing would leave them with NO inbox slot at
        // all — strictly worse than the malformed shape (peers can at least
        // try the bad endpoint). Check must surface a WARN with explicit
        // re-bind instructions and DO NOT touch the state.
        config::test_support::with_temp_home(|| {
            config::ensure_dirs().unwrap();
            let state = json!({
                "self": {
                    "endpoints": [
                        {
                            "relay_url": "https://copilot-agent@wireup.net",
                            "scope": "Federation",
                            "slot_id": "stale-id",
                            "slot_token": "stale-token"
                        }
                    ],
                    "relay_url": "https://copilot-agent@wireup.net",
                    "slot_id": "stale-id",
                    "slot_token": "stale-token"
                },
                "peers": {}
            });
            config::write_relay_state(&state).unwrap();

            let c = check_and_heal_self_userinfo_endpoints();
            assert_eq!(c.status, "WARN");
            assert!(
                c.fix
                    .as_ref()
                    .is_some_and(|f| f.contains("wire bind-relay") && f.contains("wire claim")),
                "no-clean-fallback fix must require BOTH a clean bind AND a re-claim: {:?}",
                c.fix
            );

            // CRITICAL: state must NOT be mutated (would leave operator with
            // no inbox slot). Verify byte-identical.
            let after = config::read_relay_state().unwrap();
            assert_eq!(
                after, state,
                "no-clean-fallback path must NOT mutate state (would strand operator)"
            );
        });
    }
}
