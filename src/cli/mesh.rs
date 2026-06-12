use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};

use super::MeshRoleAction;
use crate::config;

/// v0.6.5 (issue #21): capability-match routing. Walks sister sessions,
/// filters by `profile.role` + `--exclude` + must-be-pinned-in-our-peers,
/// picks ONE via the requested strategy, then signs + pushes the event
/// to that peer. Pinned-peers-only by construction (same as broadcast).
pub(super) fn cmd_mesh_route(
    role: &str,
    strategy: &str,
    exclude: &[String],
    kind: &str,
    body_arg: &str,
    as_json: bool,
) -> Result<()> {
    use std::time::Instant;

    if !config::is_initialized()? {
        bail!("not initialized — run `wire up` first");
    }
    let strategy = strategy.to_ascii_lowercase();
    if !matches!(strategy.as_str(), "round-robin" | "first" | "random") {
        bail!("unknown strategy `{strategy}` — use round-robin | first | random");
    }

    // Our pinned-peer set: only these handles are addressable. mesh-route
    // refuses to invent a recipient, same posture as broadcast.
    let state = config::read_relay_state()?;
    let pinned: std::collections::BTreeSet<String> = state["peers"]
        .as_object()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();

    let exclude_set: std::collections::HashSet<&str> = exclude.iter().map(String::as_str).collect();

    // Enumerate every sister on the box, read each one's role from its
    // signed agent-card. Filter: matching role AND pinned AND not
    // excluded. `list_sessions` returns the cross-session view (using the
    // v0.6.4 inside-session sessions_root fallback).
    let sessions = crate::session::list_sessions()?;
    let mut candidates: Vec<(String, Option<String>)> = Vec::new(); // (handle, did)
    for s in &sessions {
        let handle = match s.handle.as_ref() {
            Some(h) => h.clone(),
            None => continue,
        };
        if exclude_set.contains(handle.as_str()) {
            continue;
        }
        if !pinned.contains(&handle) {
            continue;
        }
        let card_path = s
            .home_dir
            .join("config")
            .join("wire")
            .join("agent-card.json");
        let card_role = std::fs::read(&card_path)
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .and_then(|c| {
                c.get("profile")
                    .and_then(|p| p.get("role"))
                    .and_then(Value::as_str)
                    .map(str::to_string)
            });
        if card_role.as_deref() == Some(role) {
            candidates.push((handle, s.did.clone()));
        }
    }

    candidates.sort_by(|a, b| a.0.cmp(&b.0));
    candidates.dedup_by(|a, b| a.0 == b.0);

    if candidates.is_empty() {
        bail!(
            "no pinned sister with role=`{role}` (run `wire mesh role list` to see what's available)"
        );
    }

    let chosen = match strategy.as_str() {
        "first" => candidates[0].clone(),
        "random" => {
            use rand::Rng;
            let idx = rand::thread_rng().gen_range(0..candidates.len());
            candidates[idx].clone()
        }
        "round-robin" => {
            // Cursor persisted at <state_dir>/mesh-route-cursor.json:
            // `{role: last_picked_handle}`. Next pick = first candidate
            // alphabetically AFTER last_picked, wrapping around when no
            // candidate is greater.
            let cursor_path = mesh_route_cursor_path()?;
            let mut cursors: std::collections::BTreeMap<String, String> =
                read_mesh_route_cursors(&cursor_path);
            let last = cursors.get(role).cloned();
            let pick = match last {
                None => candidates[0].clone(),
                Some(last_h) => candidates
                    .iter()
                    .find(|(h, _)| h.as_str() > last_h.as_str())
                    .cloned()
                    .unwrap_or_else(|| candidates[0].clone()),
            };
            cursors.insert(role.to_string(), pick.0.clone());
            write_mesh_route_cursors(&cursor_path, &cursors)?;
            pick
        }
        _ => unreachable!(),
    };

    let (chosen_handle, _chosen_did) = chosen;

    // Body parsing follows wire send / mesh broadcast.
    let body_value: Value = if body_arg == "-" {
        use std::io::Read;
        let mut raw = String::new();
        std::io::stdin()
            .read_to_string(&mut raw)
            .with_context(|| "reading body from stdin")?;
        serde_json::from_str(raw.trim_end()).unwrap_or(Value::String(raw))
    } else if let Some(path) = body_arg.strip_prefix('@') {
        let raw =
            std::fs::read_to_string(path).with_context(|| format!("reading body file {path:?}"))?;
        serde_json::from_str(&raw).unwrap_or(Value::String(raw))
    } else {
        Value::String(body_arg.to_string())
    };

    let sk_seed = config::read_private_key()?;
    let card = config::read_agent_card()?;
    let did = card
        .get("did")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("agent-card missing did"))?
        .to_string();
    let handle = crate::agent_card::display_handle_from_did(&did).to_string();
    let pk_b64 = card
        .get("verify_keys")
        .and_then(Value::as_object)
        .and_then(|m| m.values().next())
        .and_then(|v| v.get("key"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("agent-card missing verify_keys[*].key"))?;
    let pk_bytes = crate::signing::b64decode(pk_b64)?;

    let kind_id = super::parse_kind(kind)?;
    let now_iso = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string());

    let event = json!({
        "schema_version": crate::signing::EVENT_SCHEMA_VERSION,
        "timestamp": now_iso,
        "from": did,
        "to": format!("did:wire:{chosen_handle}"),
        "type": kind,
        "kind": kind_id,
        "body": json!({
            "content": body_value,
            "routed_via": {
                "role": role,
                "strategy": strategy,
            },
        }),
    });
    let signed = crate::signing::sign_message_v31(&event, &sk_seed, &pk_bytes, &handle)
        .map_err(|e| anyhow!("sign_message_v31 failed: {e:?}"))?;
    let event_id = signed["event_id"].as_str().unwrap_or("").to_string();

    let line = serde_json::to_vec(&signed)?;
    config::append_outbox_record(&chosen_handle, &line)?;

    let endpoints = crate::endpoints::peer_endpoints_in_priority_order(&state, &chosen_handle);
    if endpoints.is_empty() {
        bail!(
            "no reachable endpoint pinned for `{chosen_handle}` (the role matched, but we can't push)"
        );
    }
    let start = Instant::now();
    let mut delivered = false;
    let mut last_err: Option<String> = None;
    let mut via_scope: Option<String> = None;
    for ep in &endpoints {
        // v0.7.0-alpha.19: scheme-aware dispatch — `unix://` endpoints
        // route via uds_request, others via reqwest. Allows peers with
        // UDS-tagged endpoints in their agent-card to receive events
        // over the local socket instead of loopback HTTP.
        match crate::relay_client::post_event_to_endpoint(ep, &signed) {
            Ok(_) => {
                delivered = true;
                via_scope = Some(
                    match ep.scope {
                        crate::endpoints::EndpointScope::Local => "local",
                        crate::endpoints::EndpointScope::Lan => "lan",
                        crate::endpoints::EndpointScope::Uds => "uds",
                        crate::endpoints::EndpointScope::Federation => "federation",
                    }
                    .to_string(),
                );
                break;
            }
            Err(e) => last_err = Some(format!("{e:#}")),
        }
    }
    let rtt_ms = start.elapsed().as_millis() as u64;

    let summary = json!({
        "role": role,
        "strategy": strategy,
        "routed_to": chosen_handle,
        "event_id": event_id,
        "delivered": delivered,
        "delivered_via": via_scope,
        "rtt_ms": rtt_ms,
        "candidates": candidates.iter().map(|(h, _)| h.clone()).collect::<Vec<_>>(),
        "error": last_err,
    });

    if as_json {
        println!("{}", serde_json::to_string(&summary)?);
    } else if delivered {
        let via = via_scope.as_deref().unwrap_or("?");
        println!("wire mesh route: {role} → {chosen_handle} ({rtt_ms}ms, {via})");
    } else {
        let err = last_err.as_deref().unwrap_or("no endpoints reachable");
        bail!("delivery to `{chosen_handle}` failed: {err}");
    }
    Ok(())
}

fn mesh_route_cursor_path() -> Result<std::path::PathBuf> {
    Ok(config::state_dir()?.join("mesh-route-cursor.json"))
}

fn read_mesh_route_cursors(path: &std::path::Path) -> std::collections::BTreeMap<String, String> {
    std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn write_mesh_route_cursors(
    path: &std::path::Path,
    cursors: &std::collections::BTreeMap<String, String>,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("creating {parent:?}"))?;
    }
    let body = serde_json::to_vec_pretty(cursors)?;
    std::fs::write(path, body).with_context(|| format!("writing {path:?}"))?;
    Ok(())
}

/// v0.6.4 (issue #20): mesh role tag dispatcher. Wraps the existing
/// `profile.role` persistence (re-uses `pair_profile::write_profile_field`)
/// behind a discoverability-friendlier surface, plus cross-session
/// enumeration for the list path.
pub(super) fn cmd_mesh_role(action: MeshRoleAction) -> Result<()> {
    match action {
        MeshRoleAction::Set { role, json } => {
            validate_role_tag(&role)?;
            let new_profile =
                crate::pair_profile::write_profile_field("role", Value::String(role.clone()))?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string(&json!({
                        "role": role,
                        "profile": new_profile,
                    }))?
                );
            } else {
                println!("self role = {role} (signed into agent-card)");
            }
        }
        MeshRoleAction::Get { peer, json } => {
            let (who, role) = match peer.as_deref() {
                None => {
                    let card = config::read_agent_card()?;
                    let role = card
                        .get("profile")
                        .and_then(|p| p.get("role"))
                        .and_then(Value::as_str)
                        .map(str::to_string);
                    let who = card
                        .get("did")
                        .and_then(Value::as_str)
                        .map(|d| crate::agent_card::display_handle_from_did(d).to_string())
                        .unwrap_or_else(|| "self".to_string());
                    (who, role)
                }
                Some(handle) => {
                    let bare = crate::agent_card::bare_handle(handle).to_string();
                    let trust = config::read_trust()?;
                    let role = trust
                        .get("agents")
                        .and_then(|a| a.get(&bare))
                        .and_then(|a| a.get("card"))
                        .and_then(|c| c.get("profile"))
                        .and_then(|p| p.get("role"))
                        .and_then(Value::as_str)
                        .map(str::to_string);
                    (bare, role)
                }
            };
            if json {
                println!(
                    "{}",
                    serde_json::to_string(&json!({
                        "handle": who,
                        "role": role,
                    }))?
                );
            } else {
                match role {
                    Some(r) => println!("{who}: {r}"),
                    None => println!("{who}: (unset)"),
                }
            }
        }
        MeshRoleAction::List { json } => {
            let mut self_did: Option<String> = None;
            if let Ok(card) = config::read_agent_card() {
                self_did = card.get("did").and_then(Value::as_str).map(str::to_string);
            }
            let sessions = crate::session::list_sessions()?;
            let mut rows: Vec<Value> = Vec::new();
            for s in &sessions {
                let card_path = s
                    .home_dir
                    .join("config")
                    .join("wire")
                    .join("agent-card.json");
                let role = std::fs::read(&card_path)
                    .ok()
                    .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
                    .and_then(|c| {
                        c.get("profile")
                            .and_then(|p| p.get("role"))
                            .and_then(Value::as_str)
                            .map(str::to_string)
                    });
                let is_self = match (&self_did, &s.did) {
                    (Some(a), Some(b)) => a == b,
                    _ => false,
                };
                rows.push(json!({
                    "name": s.name,
                    "handle": s.handle,
                    "role": role,
                    "self": is_self,
                }));
            }
            rows.sort_by(|a, b| {
                a["name"]
                    .as_str()
                    .unwrap_or("")
                    .cmp(b["name"].as_str().unwrap_or(""))
            });
            if json {
                println!("{}", serde_json::to_string(&json!({"sessions": rows}))?);
            } else if rows.is_empty() {
                println!("no sister sessions on this machine.");
            } else {
                println!("SISTER ROLES (this machine):");
                for r in &rows {
                    let name = r["name"].as_str().unwrap_or("?");
                    let role = r["role"].as_str().unwrap_or("(unset)");
                    let marker = if r["self"].as_bool().unwrap_or(false) {
                        "    ← you"
                    } else {
                        ""
                    };
                    println!("  {name:<24} {role}{marker}");
                }
            }
        }
        MeshRoleAction::Clear { json } => {
            let new_profile = crate::pair_profile::write_profile_field("role", Value::Null)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string(&json!({
                        "cleared": true,
                        "profile": new_profile,
                    }))?
                );
            } else {
                println!("self role cleared");
            }
        }
    }
    Ok(())
}

/// v0.6.4: role tag must be ASCII alphanumeric + `-` + `_`, 1-32 chars.
/// No vocabulary check — operators choose the taxonomy (planner /
/// reviewer / dispatcher / your-custom-tag). The constraint is purely
/// to keep the tag safe for filenames / URLs / shell args.
fn validate_role_tag(role: &str) -> Result<()> {
    if role.is_empty() {
        bail!("role must not be empty (use `wire mesh role --clear` to unset)");
    }
    if role.len() > 32 {
        bail!("role too long ({} chars; max 32)", role.len());
    }
    for c in role.chars() {
        if !(c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            bail!("role contains illegal char {c:?} (allowed: A-Z a-z 0-9 - _)");
        }
    }
    Ok(())
}

/// v0.6.3 (issue #19): fan one signed event to every pinned peer.
///
/// **Routing.** Each recipient gets its own signed event (Ed25519 over the
/// canonical event including `to:`, so per-recipient signing is required;
/// the cost is one sign per peer = ~50µs each, dominated by relay RTT).
/// Per-recipient pushes happen in parallel via `std::thread::scope` so
/// broadcast-to-5 takes ~1× RTT, not 5×.
///
/// **Scope filter.** Default `local` — only peers reachable via a same-
/// machine local relay (priority-1 endpoint has `scope=local`). This is
/// the lowest-blast-radius default: local-only broadcasts cannot escape
/// the operator's machine. `federation` flips to public-relay peers
/// only; `both` removes the filter.
///
/// **Pinned-peers-only.** Walks `state.peers` — never .well-known
/// resolution, never trust["agents"] expansion. Closes #8-class
/// phonebook-scrape vectors by construction: an attacker pinning a
/// hostile handle has to first be pinned bidirectionally by the
/// operator, and even then `--exclude` is the loud opt-out.
pub(super) fn cmd_mesh_broadcast(
    kind: &str,
    scope_str: &str,
    exclude: &[String],
    _noreply: bool,
    body_arg: &str,
    as_json: bool,
) -> Result<()> {
    use std::time::Instant;

    if !config::is_initialized()? {
        bail!("not initialized — run `wire up` first");
    }

    let scope = match scope_str {
        "local" => crate::endpoints::EndpointScope::Local,
        "federation" => crate::endpoints::EndpointScope::Federation,
        "both" => {
            // Sentinel: we don't actually have a `Both` variant on the
            // scope enum; use a tri-state below. Treat as Local for the
            // typed match and special-case it via the bool below.
            crate::endpoints::EndpointScope::Local
        }
        other => bail!("unknown scope `{other}` — use local | federation | both"),
    };
    let any_scope = scope_str == "both";

    let state = config::read_relay_state()?;
    let peers = state["peers"].as_object().cloned().unwrap_or_default();
    if peers.is_empty() {
        bail!(
            "no peers pinned — run `wire accept-invite <invite-url>` or `wire dial <peer>@<relay>` first"
        );
    }

    let exclude_set: std::collections::HashSet<&str> = exclude.iter().map(String::as_str).collect();

    // Walk the pinned-peer set, filter by scope + exclude. Keep the
    // priority-ordered endpoint list for each match so the push can
    // try local first then fall through to federation (when scope=both).
    struct Target {
        handle: String,
        endpoints: Vec<crate::endpoints::Endpoint>,
    }
    let mut targets: Vec<Target> = Vec::new();
    let mut skipped_wrong_scope: Vec<String> = Vec::new();
    let mut skipped_excluded: Vec<String> = Vec::new();
    for handle in peers.keys() {
        if exclude_set.contains(handle.as_str()) {
            skipped_excluded.push(handle.clone());
            continue;
        }
        let ordered = crate::endpoints::peer_endpoints_in_priority_order(&state, handle);
        let filtered: Vec<crate::endpoints::Endpoint> = ordered
            .into_iter()
            .filter(|ep| any_scope || ep.scope == scope)
            .collect();
        if filtered.is_empty() {
            skipped_wrong_scope.push(handle.clone());
            continue;
        }
        targets.push(Target {
            handle: handle.clone(),
            endpoints: filtered,
        });
    }

    if targets.is_empty() {
        bail!(
            "no peers matched scope=`{scope_str}` after exclude filter ({} excluded, {} wrong-scope)",
            skipped_excluded.len(),
            skipped_wrong_scope.len()
        );
    }

    // Load signing material once; share across per-peer signatures.
    let sk_seed = config::read_private_key()?;
    let card = config::read_agent_card()?;
    let did = card
        .get("did")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("agent-card missing did"))?
        .to_string();
    let handle = crate::agent_card::display_handle_from_did(&did).to_string();
    let pk_b64 = card
        .get("verify_keys")
        .and_then(Value::as_object)
        .and_then(|m| m.values().next())
        .and_then(|v| v.get("key"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("agent-card missing verify_keys[*].key"))?;
    let pk_bytes = crate::signing::b64decode(pk_b64)?;

    let body_value: Value = if body_arg == "-" {
        use std::io::Read;
        let mut raw = String::new();
        std::io::stdin()
            .read_to_string(&mut raw)
            .with_context(|| "reading body from stdin")?;
        serde_json::from_str(raw.trim_end()).unwrap_or(Value::String(raw))
    } else if let Some(path) = body_arg.strip_prefix('@') {
        let raw =
            std::fs::read_to_string(path).with_context(|| format!("reading body file {path:?}"))?;
        serde_json::from_str(&raw).unwrap_or(Value::String(raw))
    } else {
        Value::String(body_arg.to_string())
    };

    let kind_id = super::parse_kind(kind)?;
    let now_iso = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string());

    let broadcast_id = generate_broadcast_id();
    let target_count = targets.len();

    // Build + sign every event up front (sequential, ~50µs/sig). Then
    // queue to outbox + push to relay in parallel per-peer. Returns
    // a per-peer outcome we then sort by handle for deterministic output.
    let mut signed_per_peer: Vec<(String, Vec<crate::endpoints::Endpoint>, Value, String)> =
        Vec::with_capacity(targets.len());
    for t in &targets {
        let body = json!({
            "content": body_value,
            "broadcast_id": broadcast_id,
            "broadcast_target_count": target_count,
        });
        let event = json!({
            "schema_version": crate::signing::EVENT_SCHEMA_VERSION,
            "timestamp": now_iso,
            "from": did,
            "to": format!("did:wire:{}", t.handle),
            "type": kind,
            "kind": kind_id,
            "body": body,
        });
        let signed = crate::signing::sign_message_v31(&event, &sk_seed, &pk_bytes, &handle)
            .map_err(|e| anyhow!("sign_message_v31 failed for `{}`: {e:?}", t.handle))?;
        let event_id = signed["event_id"].as_str().unwrap_or("").to_string();
        signed_per_peer.push((t.handle.clone(), t.endpoints.clone(), signed, event_id));
    }

    // Persist to per-peer outbox FIRST (sequential — `append_outbox_record`
    // holds a per-path mutex; writes are independent across handles but
    // we want the side-effect ordering deterministic).
    for (peer, _, signed, _) in &signed_per_peer {
        let line = serde_json::to_vec(signed)?;
        config::append_outbox_record(peer, &line)?;
    }

    // Per-peer parallel push. Each thread tries the priority-ordered
    // endpoint list; first 2xx wins. Aggregate (peer, delivered, rtt_ms,
    // error_opt) over a channel.
    use std::sync::mpsc;
    let (tx, rx) = mpsc::channel::<Value>();
    std::thread::scope(|s| {
        for (peer, endpoints, signed, event_id) in &signed_per_peer {
            let tx = tx.clone();
            let peer = peer.clone();
            let event_id = event_id.clone();
            let endpoints = endpoints.clone();
            let signed = signed.clone();
            s.spawn(move || {
                let start = Instant::now();
                let mut delivered = false;
                let mut last_err: Option<String> = None;
                let mut delivered_via: Option<String> = None;
                for ep in &endpoints {
                    // v0.7.0-alpha.19: scheme-aware dispatch (UDS via
                    // uds_request, else reqwest). Same as cmd_send's
                    // single-peer path above; this is the parallel
                    // multi-peer broadcast loop.
                    match crate::relay_client::post_event_to_endpoint(ep, &signed) {
                        Ok(_) => {
                            delivered = true;
                            delivered_via = Some(
                                match ep.scope {
                                    crate::endpoints::EndpointScope::Local => "local",
                                    crate::endpoints::EndpointScope::Lan => "lan",
                                    crate::endpoints::EndpointScope::Uds => "uds",
                                    crate::endpoints::EndpointScope::Federation => "federation",
                                }
                                .to_string(),
                            );
                            break;
                        }
                        Err(e) => last_err = Some(format!("{e:#}")),
                    }
                }
                let rtt_ms = start.elapsed().as_millis() as u64;
                let _ = tx.send(json!({
                    "peer": peer,
                    "event_id": event_id,
                    "delivered": delivered,
                    "delivered_via": delivered_via,
                    "rtt_ms": rtt_ms,
                    "error": last_err,
                }));
            });
        }
    });
    drop(tx);

    let mut results: Vec<Value> = rx.iter().collect();
    results.sort_by(|a, b| {
        a["peer"]
            .as_str()
            .unwrap_or("")
            .cmp(b["peer"].as_str().unwrap_or(""))
    });

    let delivered = results
        .iter()
        .filter(|r| r["delivered"].as_bool().unwrap_or(false))
        .count();
    let failed = results.len() - delivered;

    let summary = json!({
        "broadcast_id": broadcast_id,
        "kind": kind,
        "scope": scope_str,
        "target_count": target_count,
        "delivered": delivered,
        "failed": failed,
        "skipped_excluded": skipped_excluded,
        "skipped_wrong_scope": skipped_wrong_scope,
        "results": results,
    });

    if as_json {
        println!("{}", serde_json::to_string(&summary)?);
        return Ok(());
    }

    println!("wire mesh broadcast: scope={scope_str} → {target_count} pinned peer(s)");
    for r in &results {
        let peer = r["peer"].as_str().unwrap_or("?");
        let delivered = r["delivered"].as_bool().unwrap_or(false);
        let rtt = r["rtt_ms"].as_u64().unwrap_or(0);
        let via = r["delivered_via"].as_str().unwrap_or("");
        if delivered {
            println!("  {peer:<24} ✓ delivered ({rtt}ms, {via})");
        } else {
            let err = r["error"].as_str().unwrap_or("?");
            println!("  {peer:<24} ✗ failed — {err}");
        }
    }
    if !skipped_excluded.is_empty() {
        println!("  excluded: {}", skipped_excluded.join(", "));
    }
    if !skipped_wrong_scope.is_empty() {
        println!(
            "  skipped (wrong scope): {}",
            skipped_wrong_scope.join(", ")
        );
    }
    println!("broadcast_id: {broadcast_id}");
    Ok(())
}

/// Random 16-byte UUID-shaped id for correlating a broadcast's recipient
/// events. Not strictly UUID v4 (no version/variant bits set) — receivers
/// correlate by string equality, the shape is for human readability.
fn generate_broadcast_id() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut buf);
    let h = hex::encode(buf);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32],
    )
}
