use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};

use super::setup;
use crate::{config, signing::sign_message_v31};

// ---------- mcp / relay-server stubs ----------

pub(super) fn cmd_mcp() -> Result<()> {
    crate::mcp::run()
}

pub(super) fn cmd_relay_server(
    bind: &str,
    local_only: bool,
    uds: Option<&std::path::Path>,
) -> Result<()> {
    // v0.7.0-alpha.16: --uds <path> takes the UDS transport path,
    // overriding --bind. Implies --local-only semantics. Routed to a
    // separate serve_uds entry point with a manual hyper accept loop
    // (axum 0.7's `serve` is TcpListener-only).
    if let Some(socket_path) = uds {
        let base = if let Ok(home) = std::env::var("WIRE_HOME") {
            std::path::PathBuf::from(home)
                .join("state")
                .join("wire-relay")
                .join("uds")
        } else {
            dirs::state_dir()
                .or_else(dirs::data_local_dir)
                .ok_or_else(|| anyhow::anyhow!("could not resolve XDG_STATE_HOME — set WIRE_HOME"))?
                .join("wire-relay")
                .join("uds")
        };
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        return runtime.block_on(crate::relay_server::serve_uds(
            socket_path.to_path_buf(),
            base,
        ));
    }
    // v0.5.17: --local-only refuses non-loopback binds. Catches the
    // "wait did I just bind a publicly-reachable local-only relay" mistake
    // at startup rather than discovering it via an empty phonebook later.
    if local_only {
        validate_loopback_bind(bind)?;
    }
    // Default state dir for the relay process: $WIRE_HOME/state/wire-relay
    // (or `dirs::state_dir()/wire-relay`). Distinct from the CLI's state dir
    // so a single user can run both client and server on one machine.
    // For --local-only, suffix with /local so a single operator can run
    // both a federation relay and a local-only relay without state collision.
    let base = if let Ok(home) = std::env::var("WIRE_HOME") {
        std::path::PathBuf::from(home)
            .join("state")
            .join("wire-relay")
    } else {
        dirs::state_dir()
            .or_else(dirs::data_local_dir)
            .ok_or_else(|| anyhow::anyhow!("could not resolve XDG_STATE_HOME — set WIRE_HOME"))?
            .join("wire-relay")
    };
    let state_dir = if local_only { base.join("local") } else { base };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(crate::relay_server::serve_with_mode(
        bind,
        state_dir,
        crate::relay_server::ServerMode { local_only },
    ))
}

/// v0.5.17 loopback-bind guard. Refuses any address whose host portion
/// resolves to something outside `127.0.0.0/8` or `::1`.
///
/// v0.7.0-alpha.11: relaxed to also accept RFC 1918 private IPv4
/// (10/8, 172.16/12, 192.168/16) so `wire relay-server --bind
/// <LAN-IP>:8772 --local-only` works for the alpha.9 LAN feature.
///
/// v0.7.0-alpha.15: also accept RFC 6598 CGNAT (100.64.0.0/10), which
/// is the IP range Tailscale uses for tailnet addresses. Lets operators
/// pair wire across machines using their tailnet IPs (e.g. Mac at
/// 100.96.234.16, Spark at 100.91.57.17) — Tailscale handles
/// auth + encryption + NAT traversal, wire handles protocol + identity.
/// Sidesteps host firewall config entirely (utun interface bypass).
///
/// Still refuses: public IPv4/IPv6, wildcards (0.0.0.0/::), link-local,
/// multicast, broadcast. Those would publish a "local-only" relay to
/// the global internet — the v0.5.17 security gate's whole point.
fn validate_loopback_bind(bind: &str) -> Result<()> {
    // Split host:port. IPv6 literals use `[::]:port` form.
    let host = if let Some(stripped) = bind.strip_prefix('[') {
        let close = stripped
            .find(']')
            .ok_or_else(|| anyhow::anyhow!("malformed IPv6 bind {bind:?}"))?;
        stripped[..close].to_string()
    } else {
        bind.rsplit_once(':')
            .map(|(h, _)| h.to_string())
            .unwrap_or_else(|| bind.to_string())
    };
    use std::net::{IpAddr, ToSocketAddrs};
    let probe = format!("{host}:0");
    let resolved: Vec<_> = probe
        .to_socket_addrs()
        .with_context(|| format!("resolving bind host {host:?}"))?
        .collect();
    if resolved.is_empty() {
        bail!("--local-only: bind host {host:?} resolved to no addresses");
    }
    for addr in &resolved {
        let ip = addr.ip();
        let is_acceptable = match ip {
            IpAddr::V4(v4) => {
                v4.is_loopback() || v4.is_private() || {
                    // RFC 6598 CGNAT / Tailscale range: 100.64.0.0/10
                    let octets = v4.octets();
                    octets[0] == 100 && (64..=127).contains(&octets[1])
                }
            }
            IpAddr::V6(v6) => v6.is_loopback(), // ULA + Tailscale-v6 deferred
        };
        if !is_acceptable {
            bail!(
                "--local-only refuses non-private bind: {host:?} resolves to {ip} \
                 which is not loopback (127/8, ::1), RFC 1918 private \
                 (10/8, 172.16/12, 192.168/16), or RFC 6598 CGNAT/Tailscale \
                 (100.64.0.0/10). Remove --local-only to bind publicly."
            );
        }
    }
    Ok(())
}

// ---------- bind-relay ----------

fn parse_scope(s: &str) -> Result<crate::endpoints::EndpointScope> {
    use crate::endpoints::EndpointScope;
    match s.to_lowercase().as_str() {
        "federation" | "fed" => Ok(EndpointScope::Federation),
        "local" => Ok(EndpointScope::Local),
        "lan" => Ok(EndpointScope::Lan),
        "uds" => Ok(EndpointScope::Uds),
        other => bail!("unknown --scope `{other}` (expected federation|local|lan|uds)"),
    }
}

/// v0.12: bind a relay slot. ADDITIVE by default — the new slot is
/// appended to `self.endpoints[]`, keeping any existing slots so an agent
/// can hold a local relay AND a federation relay simultaneously without
/// black-holing pinned peers. `--replace` restores the pre-v0.12
/// destructive single-slot behavior (guarded by issue #7).
pub(crate) fn cmd_bind_relay(
    url: &str,
    scope: Option<&str>,
    replace: bool,
    migrate_pinned: bool,
    as_json: bool,
) -> Result<()> {
    use crate::endpoints::{Endpoint, self_endpoints};

    if !config::is_initialized()? {
        bail!("not initialized — run `wire up` first");
    }
    let card = config::read_agent_card()?;
    let did = card.get("did").and_then(Value::as_str).unwrap_or("");
    let handle = crate::agent_card::display_handle_from_did(did).to_string();

    let normalized_raw = url.trim_end_matches('/');
    // Refuse to record/publish a relay endpoint that embeds userinfo —
    // `https://<handle>@<host>` 4xxes every inbound event POST. Strip and
    // warn so operators learn the right shape without losing the call.
    let normalized_owned = setup::strip_relay_url_userinfo(normalized_raw);
    let normalized = normalized_owned.as_str();
    // Belt-and-suspenders: confirm the post-strip URL is clean before any
    // persist / publish. A future code path that bypasses the strip filter
    // MUST NOT be able to leak userinfo into the signed agent-card.
    setup::assert_relay_url_clean_for_publish(normalized)?;
    let new_scope = match scope {
        Some(s) => parse_scope(s)?,
        None => crate::endpoints::infer_scope_from_url(normalized),
    };

    let existing = config::read_relay_state().unwrap_or_else(|_| json!({}));
    let pinned: Vec<String> = existing
        .get("peers")
        .and_then(|p| p.as_object())
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default();

    let existing_eps = self_endpoints(&existing);
    let is_rebind_same = existing_eps.iter().any(|e| e.relay_url == normalized);

    // Destructive paths that black-hole pinned peers (issue #7):
    //   • `--replace` drops every other slot.
    //   • re-binding the SAME relay rotates that slot in place.
    // An additive bind of a NEW relay keeps existing slots, so peers stay
    // reachable — no acknowledgement required. This is the v0.12 default
    // that unblocks simultaneous local + remote.
    let destructive = replace || is_rebind_same;
    if destructive && !pinned.is_empty() && !migrate_pinned {
        let list = pinned.join(", ");
        let why = if replace {
            "`--replace` drops your other slot(s)"
        } else {
            "re-binding the same relay rotates its slot"
        };
        bail!(
            "bind-relay would black-hole {n} pinned peer(s): {list}. {why}; they are \
             pinned to your CURRENT slot and would keep pushing to a slot you no longer \
             read.\n\n\
             SAFE PATHS:\n\
             • Default (omit `--replace`) ADDITIVELY binds a NEW relay, keeping existing \
             slots — no black-hole.\n\
             • `wire rotate-slot` — same-relay rotation that emits wire_close to peers.\n\
             • `wire bind-relay {url} --migrate-pinned` — proceed anyway; re-pair each \
             peer out-of-band.\n\n\
             Issue #7 (silent black-hole on relay change) caught this.",
            n = pinned.len(),
        );
    }

    let client = crate::relay_client::RelayClient::new(normalized);
    client.check_healthz()?;
    let alloc = client.allocate_slot(Some(&handle))?;

    if destructive && !pinned.is_empty() {
        eprintln!(
            "wire bind-relay: {mode} with {n} pinned peer(s) — they will black-hole \
             until they re-pin: {peers}",
            mode = if replace { "replacing" } else { "rotating" },
            n = pinned.len(),
            peers = pinned.join(", "),
        );
    }

    // Write the new slot via the single source of truth for the self-slot
    // shape. Additive by default; --replace starts from an empty self so
    // only this slot remains.
    let mut state = existing;
    if replace {
        state["self"] = Value::Null;
    }
    crate::endpoints::upsert_self_endpoint(
        &mut state,
        Endpoint {
            relay_url: normalized.to_string(),
            slot_id: alloc.slot_id.clone(),
            slot_token: alloc.slot_token.clone(),
            scope: new_scope,
        },
    );
    config::write_relay_state(&state)?;
    let eps = self_endpoints(&state);

    let scope_str = format!("{new_scope:?}").to_lowercase();
    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "relay_url": normalized,
                "slot_id": alloc.slot_id,
                "scope": scope_str,
                "endpoints": eps.len(),
                "additive": !replace,
                "slot_token_present": true,
            }))?
        );
    } else {
        println!(
            "bound {scope_str} slot on {normalized} (slot {})",
            alloc.slot_id
        );
        println!(
            "self now has {n} endpoint(s): {list}",
            n = eps.len(),
            list = eps
                .iter()
                .map(|e| format!("{}({:?})", e.relay_url, e.scope))
                .collect::<Vec<_>>()
                .join(", "),
        );
    }
    Ok(())
}

// ---------- add-peer-slot ----------

pub(super) fn cmd_add_peer_slot(
    handle: &str,
    url: &str,
    slot_id: &str,
    slot_token: &str,
    as_json: bool,
) -> Result<()> {
    use crate::endpoints::{Endpoint, infer_scope_from_url, pin_peer_endpoints};
    let mut state = config::read_relay_state()?;

    // E3 (v0.13.2): ADD this slot to the peer's endpoint set — don't REPLACE
    // the whole entry. The old flat `peers.insert` clobbered an existing
    // peer's federation endpoint when pinning a local slot, silently dropping
    // the federation route (glossy-magnolia + wisp-blossom repro: pinning a
    // loopback slot made the peer flat loopback-only). Mirror bind-relay's
    // additive semantics: upsert by relay_url into the peer's endpoints[].
    let new_ep = Endpoint {
        relay_url: url.to_string(),
        slot_id: slot_id.to_string(),
        slot_token: slot_token.to_string(),
        scope: infer_scope_from_url(url),
    };
    // RFC-006 Part B: `endpoints[]` is the single peer-routing source — no flat
    // fallback (every pin carries `endpoints[]`).
    let mut endpoints: Vec<Endpoint> = state
        .get("peers")
        .and_then(|p| p.get(handle))
        .and_then(|e| e.get("endpoints"))
        .and_then(|a| serde_json::from_value::<Vec<Endpoint>>(a.clone()).ok())
        .unwrap_or_default();
    // Upsert by relay_url: refresh in place if already pinned, else append.
    if let Some(existing) = endpoints
        .iter_mut()
        .find(|e| e.relay_url == new_ep.relay_url)
    {
        *existing = new_ep;
    } else {
        endpoints.push(new_ep);
    }
    let n = endpoints.len();
    pin_peer_endpoints(&mut state, handle, &endpoints)?;
    config::write_relay_state(&state)?;
    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "handle": handle,
                "relay_url": url,
                "slot_id": slot_id,
                "added": true,
                "endpoint_count": n,
            }))?
        );
    } else {
        println!(
            "pinned peer slot for {handle} at {url} ({slot_id}) — peer now has {n} endpoint(s)"
        );
    }
    Ok(())
}

// ---------- push ----------

pub(super) fn cmd_push(peer_filter: Option<&str>, as_json: bool) -> Result<()> {
    let mut state = config::read_relay_state()?;
    let peers = state["peers"].as_object().cloned().unwrap_or_default();
    if peers.is_empty() {
        bail!(
            "no peer slots pinned — run `wire add-peer-slot <handle> <url> <slot_id> <token>` first"
        );
    }
    let outbox_dir = config::outbox_dir()?;
    // v0.5.13 loud-fail: warn on outbox files that don't match a pinned peer.
    // Pre-v0.5.13 `wire send peer@relay` wrote to `peer@relay.jsonl` while
    // push only enumerated bare-handle files. After upgrade, stale FQDN-named
    // files sit on disk forever; warn so operator can `cat fqdn.jsonl >> handle.jsonl`.
    if outbox_dir.exists() {
        let pinned: std::collections::HashSet<String> = peers.keys().cloned().collect();
        for entry in std::fs::read_dir(&outbox_dir)?.flatten() {
            let path = entry.path();
            if path.extension().and_then(|x| x.to_str()) != Some("jsonl") {
                continue;
            }
            let stem = match path.file_stem().and_then(|s| s.to_str()) {
                Some(s) => s.to_string(),
                None => continue,
            };
            if pinned.contains(&stem) {
                continue;
            }
            // Try the bare-handle of the orphaned stem — if THAT matches a
            // pinned peer, the stem is a stale FQDN-suffixed file.
            let bare = crate::agent_card::bare_handle(&stem);
            if pinned.contains(bare) {
                eprintln!(
                    "wire push: WARN stale outbox file `{}.jsonl` not enumerated (pinned peer is `{bare}`). \
                     Merge with: `cat {} >> {}` then delete the FQDN file.",
                    stem,
                    path.display(),
                    outbox_dir.join(format!("{bare}.jsonl")).display(),
                );
            }
        }
    }
    if !outbox_dir.exists() {
        if as_json {
            println!(
                "{}",
                serde_json::to_string(&json!({"pushed": [], "skipped": []}))?
            );
        } else {
            println!("phyllis: nothing to dial out — write a message first with `wire send`");
        }
        return Ok(());
    }

    let mut pushed = Vec::new();
    let mut skipped = Vec::new();

    // Issue #15: track which peers we've already re-resolved this push call
    // so we don't whois more than once per peer per push (the rate limit the
    // issue specifies). Lifetime is the whole `cmd_push` invocation; clears
    // every time the operator (or daemon) runs `wire push` again.
    let mut rotated_this_push: std::collections::HashSet<String> = std::collections::HashSet::new();
    // Track whether we mutated `state` so we can write it back exactly
    // once at the end (avoids a write per peer).
    let mut state_dirty = false;

    // v0.5.17: walk each peer's pinned endpoints in priority order (local
    // first if we share a local relay, federation second). Try POST on the
    // first endpoint; on transport failure, fall through to the next.
    // Falls back to the v0.5.16 legacy single-endpoint code path when the
    // peer record carries no `endpoints[]` array (back-compat).
    for (peer_handle, _) in peers.iter() {
        if let Some(want) = peer_filter
            && peer_handle != want
        {
            continue;
        }
        let outbox = outbox_dir.join(format!("{peer_handle}.jsonl"));
        if !outbox.exists() {
            continue;
        }
        let mut ordered_endpoints =
            crate::endpoints::peer_endpoints_in_priority_order(&state, peer_handle);
        if ordered_endpoints.is_empty() {
            // Unreachable peer (no federation endpoint AND our local
            // relay doesn't match the peer's). Skip with a loud reason
            // rather than silently dropping events.
            for line in std::fs::read_to_string(&outbox).unwrap_or_default().lines() {
                let event: Value = match serde_json::from_str(line) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let event_id = event
                    .get("event_id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                skipped.push(json!({
                    "peer": peer_handle,
                    "event_id": event_id,
                    "reason": "no reachable endpoint pinned for peer",
                }));
            }
            continue;
        }
        let body = std::fs::read_to_string(&outbox)?;
        for line in body.lines() {
            let event: Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let event_id = event
                .get("event_id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();

            // Capture the most recent per-endpoint error reason via a RefCell
            // so we can preserve cmd_push's pre-existing "last-error wins"
            // semantics for the skipped-with-reason path. The shared
            // try_post_event_with_failover helper (from #62) handles iteration,
            // priority order, and early-return on first success; the closure
            // applies the existing `format_transport_error` formatting on
            // each individual error so the operator sees the same diagnostic
            // text as before the dedup.
            let last_err: std::cell::RefCell<Option<String>> = std::cell::RefCell::new(None);
            match crate::relay_client::try_post_event_with_failover(
                &ordered_endpoints,
                &event,
                |endpoint, ev| {
                    let client = crate::relay_client::RelayClient::new(&endpoint.relay_url);
                    match client.post_event(&endpoint.slot_id, &endpoint.slot_token, ev) {
                        Ok(resp) => Ok(resp),
                        Err(e) => {
                            *last_err.borrow_mut() =
                                Some(crate::relay_client::format_transport_error(&e));
                            Err(e)
                        }
                    }
                },
            ) {
                Ok((endpoint, resp)) => {
                    if resp.status == "duplicate" {
                        skipped.push(json!({
                            "peer": peer_handle,
                            "event_id": event_id,
                            "reason": "duplicate",
                            "endpoint": endpoint.relay_url,
                            "scope": serde_json::to_value(endpoint.scope).unwrap_or(json!("?")),
                        }));
                    } else {
                        pushed.push(json!({
                            "peer": peer_handle,
                            "event_id": event_id,
                            "endpoint": endpoint.relay_url,
                            "scope": serde_json::to_value(endpoint.scope).unwrap_or(json!("?")),
                        }));
                    }
                }
                Err(_) => {
                    // Issue #15: before reporting the event as skipped, see
                    // if the failure smelled like a slot-rotation (4xx 404 /
                    // 410). If yes AND we haven't already re-resolved this
                    // peer in this push call, attempt one whois lookup. On
                    // a real rotation, the helper updates `state.peers[peer]`
                    // in place; we refresh `ordered_endpoints` from the
                    // mutated state and retry the same event once. Composes
                    // with the doctor #14 staleness check from PR #68: #14
                    // surfaces the symptom, #15 closes the loop.
                    let last_err_text = last_err.borrow().clone().unwrap_or_default();
                    let mut delivered_via_retry: Option<(crate::endpoints::Endpoint, _)> = None;
                    match try_reresolve_peer_on_slot_4xx(
                        &mut state,
                        peer_handle,
                        &last_err_text,
                        &rotated_this_push,
                    ) {
                        Ok(true) => {
                            // Mark this peer as already re-resolved this push.
                            rotated_this_push.insert(peer_handle.clone());
                            state_dirty = true;
                            // Refresh endpoints from the updated state and
                            // retry exactly once. last_err is also reset so
                            // the retry's error (if any) replaces the prior
                            // one in the eventual skipped reason.
                            ordered_endpoints = crate::endpoints::peer_endpoints_in_priority_order(
                                &state,
                                peer_handle,
                            );
                            *last_err.borrow_mut() = None;
                            if let Ok((endpoint, resp)) =
                                crate::relay_client::try_post_event_with_failover(
                                    &ordered_endpoints,
                                    &event,
                                    |endpoint, ev| {
                                        let client = crate::relay_client::RelayClient::new(
                                            &endpoint.relay_url,
                                        );
                                        match client.post_event(
                                            &endpoint.slot_id,
                                            &endpoint.slot_token,
                                            ev,
                                        ) {
                                            Ok(resp) => Ok(resp),
                                            Err(e) => {
                                                *last_err.borrow_mut() = Some(
                                                    crate::relay_client::format_transport_error(&e),
                                                );
                                                Err(e)
                                            }
                                        }
                                    },
                                )
                            {
                                delivered_via_retry = Some((endpoint, resp));
                            }
                        }
                        Ok(false) => {
                            // Either not a slot-rotation shape, or already
                            // re-resolved this push, or slot id unchanged —
                            // fall through to the original skipped path.
                        }
                        Err(e) => {
                            // Re-resolve itself failed (DNS down, relay 5xx,
                            // handle unclaimed, etc.). Don't fail the push —
                            // fall through to skipped with the resolve error
                            // appended for diagnostic context.
                            *last_err.borrow_mut() = Some(format!(
                                "{}; re-resolve also failed: {e:#}",
                                last_err.borrow().clone().unwrap_or_default()
                            ));
                            // Mark as tried so we don't loop on the next event.
                            rotated_this_push.insert(peer_handle.clone());
                        }
                    }
                    if let Some((endpoint, resp)) = delivered_via_retry {
                        if resp.status == "duplicate" {
                            skipped.push(json!({
                                "peer": peer_handle,
                                "event_id": event_id,
                                "reason": "duplicate",
                                "endpoint": endpoint.relay_url,
                                "scope": serde_json::to_value(endpoint.scope).unwrap_or(json!("?")),
                                "via": "slot_reresolve_retry",
                            }));
                        } else {
                            pushed.push(json!({
                                "peer": peer_handle,
                                "event_id": event_id,
                                "endpoint": endpoint.relay_url,
                                "scope": serde_json::to_value(endpoint.scope).unwrap_or(json!("?")),
                                "via": "slot_reresolve_retry",
                            }));
                        }
                    } else {
                        // Every endpoint failed even after (any) retry.
                        // Preserve the prior "last reason is what gets
                        // reported" UX (the closure captured the last per-
                        // endpoint error via `last_err`).
                        skipped.push(json!({
                            "peer": peer_handle,
                            "event_id": event_id,
                            "reason": last_err
                                .borrow()
                                .clone()
                                .unwrap_or_else(|| "all endpoints failed".to_string()),
                        }));
                    }
                }
            }
        }
    }

    // Issue #15: persist any in-place slot rotations from the per-peer loop
    // exactly once at the end. Best-effort: if the write fails the operator
    // still gets a valid push report, and the next push will re-attempt the
    // resolve (cheap) before retrying delivery.
    if state_dirty && let Err(e) = config::write_relay_state(&state) {
        eprintln!(
            "wire push: WARN failed to persist rotated peer slots: {e:#}. \
             Slot rotation will be re-attempted on next push."
        );
    }

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({"pushed": pushed, "skipped": skipped}))?
        );
    } else {
        println!(
            "pushed {} event(s); skipped {} ({})",
            pushed.len(),
            skipped.len(),
            if skipped.is_empty() {
                "none"
            } else {
                "see --json for detail"
            }
        );
    }
    Ok(())
}

// ---------- pull ----------

pub(super) fn cmd_pull(as_json: bool) -> Result<()> {
    let state = config::read_relay_state()?;
    let self_state = state.get("self").cloned().unwrap_or(Value::Null);
    if self_state.is_null() {
        bail!("self slot not bound — run `wire bind-relay <url>` first");
    }

    // v0.5.17: pull from every endpoint in self.endpoints (federation +
    // optional local). Each endpoint has its own per-scope cursor so we
    // don't re-pull events we've already seen on that path. Events from
    // all endpoints feed into the same inbox JSONL via process_events;
    // dedup by event_id is the last line of defense.
    // Falls back to a single federation endpoint synthesized from the
    // top-level legacy fields when self.endpoints is absent (v0.5.16
    // back-compat).
    let endpoints = crate::endpoints::self_endpoints(&state);
    if endpoints.is_empty() {
        bail!("self.relay_url / slot_id / slot_token missing in relay_state.json");
    }

    let inbox_dir = config::inbox_dir()?;
    config::ensure_dirs()?;

    let mut total_seen = 0usize;
    let mut all_written: Vec<Value> = Vec::new();
    let mut all_rejected: Vec<Value> = Vec::new();
    let mut all_blocked = false;
    let mut all_advance_cursor_to: Option<String> = None;

    for endpoint in &endpoints {
        let cursor_key = endpoint_cursor_key(endpoint.scope);
        let last_event_id = self_state
            .get(&cursor_key)
            .and_then(Value::as_str)
            .map(str::to_string);
        let client = crate::relay_client::RelayClient::new(&endpoint.relay_url);
        let events = match client.list_events(
            &endpoint.slot_id,
            &endpoint.slot_token,
            last_event_id.as_deref(),
            Some(1000),
        ) {
            Ok(ev) => ev,
            Err(e) => {
                // One endpoint's failure shouldn't kill the whole pull.
                // The local-relay-down case in particular needs to
                // gracefully continue against federation.
                eprintln!(
                    "wire pull: endpoint {} ({:?}) errored: {}; continuing",
                    endpoint.relay_url,
                    endpoint.scope,
                    crate::relay_client::format_transport_error(&e),
                );
                continue;
            }
        };
        total_seen += events.len();
        let result = crate::pull::process_events(&events, last_event_id.clone(), &inbox_dir)?;
        // RFC-004 AC-HP2: auto-respond to inbound probes from the daemon's pull
        // cycle — no LLM/MCP in the loop. Rate-limited + best-effort inside.
        crate::probe::respond_to_probes(&result.probes);
        all_written.extend(result.written.iter().cloned());
        all_rejected.extend(result.rejected.iter().cloned());
        if result.blocked {
            all_blocked = true;
        }
        // Advance per-endpoint cursor. The cursor key is scope-specific
        // so federation and local don't trample each other.
        if let Some(eid) = result.advance_cursor_to.clone() {
            if endpoint.scope == crate::endpoints::EndpointScope::Federation {
                all_advance_cursor_to = Some(eid.clone());
            }
            let key = cursor_key.clone();
            config::update_relay_state(|state| {
                if let Some(self_obj) = state.get_mut("self").and_then(Value::as_object_mut) {
                    self_obj.insert(key, Value::String(eid));
                }
                Ok(())
            })?;
        }
    }

    // Compatibility shim for the legacy single-cursor code paths below:
    // `result` used to come from one process_events call; we now have
    // per-endpoint results aggregated into the all_* accumulators.
    // Reconstruct a synthetic result for the remaining display logic.
    let result = crate::pull::PullResult {
        written: all_written,
        rejected: all_rejected,
        blocked: all_blocked,
        advance_cursor_to: all_advance_cursor_to,
        // Probes were already auto-responded to inside the per-endpoint loop
        // above; this aggregate result doesn't re-carry them.
        probes: Vec::new(),
    };
    let events_len = total_seen;

    // Cursor advance happened per-endpoint above; no aggregate cursor
    // write needed here.

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "written": result.written,
                "rejected": result.rejected,
                "total_seen": events_len,
                "cursor_blocked": result.blocked,
                "cursor_advanced_to": result.advance_cursor_to,
            }))?
        );
    } else {
        let blocking = result
            .rejected
            .iter()
            .filter(|r| r.get("blocks_cursor").and_then(Value::as_bool) == Some(true))
            .count();
        if blocking > 0 {
            println!(
                "pulled {} event(s); wrote {}; rejected {} ({} BLOCKING cursor — see `wire pull --json`)",
                events_len,
                result.written.len(),
                result.rejected.len(),
                blocking,
            );
        } else {
            println!(
                "pulled {} event(s); wrote {}; rejected {}",
                events_len,
                result.written.len(),
                result.rejected.len(),
            );
        }
    }
    Ok(())
}

/// v0.5.17: cursor key for an endpoint's per-scope read position.
/// Federation keeps the v0.5.16 legacy key `last_pulled_event_id` for
/// back-compat with on-disk relay_state files; local uses a
/// `_local` suffix.
fn endpoint_cursor_key(scope: crate::endpoints::EndpointScope) -> String {
    match scope {
        crate::endpoints::EndpointScope::Federation => "last_pulled_event_id".to_string(),
        crate::endpoints::EndpointScope::Local => "last_pulled_event_id_local".to_string(),
        crate::endpoints::EndpointScope::Lan => "last_pulled_event_id_lan".to_string(),
        crate::endpoints::EndpointScope::Uds => "last_pulled_event_id_uds".to_string(),
    }
}

// ---------- rotate-slot ----------

pub(super) fn cmd_rotate_slot(no_announce: bool, as_json: bool) -> Result<()> {
    if !config::is_initialized()? {
        bail!("not initialized — run `wire up` first");
    }
    let mut state = config::read_relay_state()?;
    let self_state = state.get("self").cloned().unwrap_or(Value::Null);
    if self_state.is_null() {
        bail!("self slot not bound — run `wire bind-relay <url>` first (nothing to rotate)");
    }
    // v0.9: route through self_primary_endpoint so v0.5.17+ sessions
    // (which write only self.endpoints[]) can rotate. Pre-v0.9 read
    // top-level legacy fields directly and bailed for those sessions.
    let primary = crate::endpoints::self_primary_endpoint(&state)
        .ok_or_else(|| anyhow!("self has no resolvable inbound endpoint to rotate"))?;
    let url = primary.relay_url.clone();
    let old_slot_id = primary.slot_id.clone();
    let old_slot_token = primary.slot_token.clone();

    // Read identity to sign the announcement.
    let card = config::read_agent_card()?;
    let did = card
        .get("did")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let handle = crate::agent_card::display_handle_from_did(&did).to_string();
    let pk_b64 = card
        .get("verify_keys")
        .and_then(Value::as_object)
        .and_then(|m| m.values().next())
        .and_then(|v| v.get("key"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("agent-card missing verify_keys[*].key"))?
        .to_string();
    let pk_bytes = crate::signing::b64decode(&pk_b64)?;
    let sk_seed = config::read_private_key()?;

    // Allocate new slot on the same relay.
    let normalized = url.trim_end_matches('/').to_string();
    let client = crate::relay_client::RelayClient::new(&normalized);
    client
        .check_healthz()
        .context("aborting rotation; old slot still valid")?;
    let alloc = client.allocate_slot(Some(&handle))?;
    let new_slot_id = alloc.slot_id.clone();
    let new_slot_token = alloc.slot_token.clone();

    // Optionally announce the rotation to every paired peer via the OLD slot.
    // Each peer's recipient-side `wire pull` will pick up this event before
    // their daemon next polls the new slot — but auto-update of peer's
    // relay.json from a wire_close event is a v0.2 daemon feature; for now
    // peers see the event and an operator must manually `add-peer-slot` the
    // new coords, OR re-pair via SAS.
    let mut announced: Vec<String> = Vec::new();
    if !no_announce {
        let now = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string());
        let body = json!({
            "reason": "operator-initiated slot rotation",
            "new_relay_url": url,
            "new_slot_id": new_slot_id,
            // NOTE: new_slot_token deliberately NOT shared in the broadcast.
            // In v0.1 slot tokens are bilateral-shared, so peer can post via
            // existing add-peer-slot flow if operator chooses to re-issue.
        });
        let peers = state["peers"].as_object().cloned().unwrap_or_default();
        for (peer_handle, _peer_info) in peers.iter() {
            let event = json!({
                "schema_version": crate::signing::EVENT_SCHEMA_VERSION,
                "timestamp": now.clone(),
                "from": did,
                "to": format!("did:wire:{peer_handle}"),
                "type": "wire_close",
                "kind": 1201,
                "body": body.clone(),
            });
            let signed = match sign_message_v31(&event, &sk_seed, &pk_bytes, &handle) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("warn: could not sign wire_close for {peer_handle}: {e}");
                    continue;
                }
            };
            // Post to OUR old slot (we're announcing on our own slot, NOT
            // peer's slot — peer reads from us). Wait, this is wrong: peers
            // read from THEIR OWN slot via wire pull. To reach peer A, we
            // post to peer A's slot. Use the existing per-peer slot mapping.
            let peer_info = match state["peers"].get(peer_handle) {
                Some(p) => p.clone(),
                None => continue,
            };
            let peer_url = peer_info["relay_url"].as_str().unwrap_or(&url);
            let peer_slot_id = peer_info["slot_id"].as_str().unwrap_or("");
            let peer_slot_token = peer_info["slot_token"].as_str().unwrap_or("");
            if peer_slot_id.is_empty() || peer_slot_token.is_empty() {
                continue;
            }
            let peer_client = if peer_url == url {
                client.clone()
            } else {
                crate::relay_client::RelayClient::new(peer_url)
            };
            match peer_client.post_event(peer_slot_id, peer_slot_token, &signed) {
                Ok(_) => announced.push(peer_handle.clone()),
                Err(e) => eprintln!("warn: announce to {peer_handle} failed: {e}"),
            }
        }
    }

    // Swap the self-slot to the new one.
    state["self"] = json!({
        "relay_url": url,
        "slot_id": new_slot_id,
        "slot_token": new_slot_token,
    });
    config::write_relay_state(&state)?;

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "rotated": true,
                "old_slot_id": old_slot_id,
                "new_slot_id": new_slot_id,
                "relay_url": url,
                "announced_to": announced,
            }))?
        );
    } else {
        println!("rotated slot on {url}");
        println!(
            "  old slot_id: {old_slot_id} (orphaned — abusive bearer-holders lose their leverage)"
        );
        println!("  new slot_id: {new_slot_id}");
        if !announced.is_empty() {
            println!(
                "  announced wire_close (kind=1201) to: {}",
                announced.join(", ")
            );
        }
        println!();
        println!("next steps:");
        println!("  - peers see the wire_close event in their next `wire pull`");
        println!(
            "  - paired peers must re-issue: tell them to run `wire add-peer-slot {handle} {url} {new_slot_id} <new-token>`"
        );
        println!("    (or full re-pair via `wire dial <handle>@<relay>`)");
        println!("  - until they do, you'll receive but they won't be able to reach you");
        // Suppress unused warning
        let _ = old_slot_token;
    }
    Ok(())
}

// ---------- forget-peer ----------

pub(super) fn cmd_forget_peer(handle: &str, purge: bool, as_json: bool) -> Result<()> {
    let mut trust = config::read_trust()?;
    let mut removed_from_trust = false;
    if let Some(agents) = trust.get_mut("agents").and_then(Value::as_object_mut)
        && agents.remove(handle).is_some()
    {
        removed_from_trust = true;
    }
    config::write_trust(&trust)?;

    let mut state = config::read_relay_state()?;
    let mut removed_from_relay = false;
    if let Some(peers) = state.get_mut("peers").and_then(Value::as_object_mut)
        && peers.remove(handle).is_some()
    {
        removed_from_relay = true;
    }
    config::write_relay_state(&state)?;

    let mut purged: Vec<String> = Vec::new();
    if purge {
        for dir in [config::inbox_dir()?, config::outbox_dir()?] {
            let path = dir.join(format!("{handle}.jsonl"));
            if path.exists() {
                std::fs::remove_file(&path).with_context(|| format!("removing {path:?}"))?;
                purged.push(path.to_string_lossy().into());
            }
        }
    }

    if !removed_from_trust && !removed_from_relay {
        if as_json {
            println!(
                "{}",
                serde_json::to_string(&json!({
                    "removed": false,
                    "reason": format!("peer {handle:?} not pinned"),
                }))?
            );
        } else {
            eprintln!("peer {handle:?} not found in trust or relay state — nothing to forget");
        }
        return Ok(());
    }

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "handle": handle,
                "removed_from_trust": removed_from_trust,
                "removed_from_relay_state": removed_from_relay,
                "purged_files": purged,
            }))?
        );
    } else {
        println!("forgot peer {handle:?}");
        if removed_from_trust {
            println!("  - removed from trust.json");
        }
        if removed_from_relay {
            println!("  - removed from relay.json");
        }
        if !purged.is_empty() {
            for p in &purged {
                println!("  - deleted {p}");
            }
        } else if !purge {
            println!("  (inbox/outbox files preserved; pass --purge to delete them)");
        }
    }
    Ok(())
}

// ---------- daemon (long-lived push+pull sync) ----------

pub(super) fn cmd_daemon(
    interval_secs: u64,
    once: bool,
    all_sessions: bool,
    session: Option<String>,
    as_json: bool,
) -> Result<()> {
    // v0.14.2 (#162): supervisor mode is mutually exclusive with --once and
    // --session — the supervisor IS the multi-session orchestrator, and
    // --once is a single-cycle exit (no supervision). Surface loudly
    // rather than silently picking one branch.
    if all_sessions {
        if once {
            bail!("--all-sessions and --once are mutually exclusive (supervisor runs forever)");
        }
        if session.is_some() {
            bail!(
                "--all-sessions and --session are mutually exclusive (supervisor manages every session, not a single named one)"
            );
        }
        return crate::daemon_supervisor::run_supervisor(interval_secs, as_json);
    }
    // v0.14.2 (#162): pin this process's WIRE_HOME to the named session's
    // home dir BEFORE any config read. Used by the supervisor when it
    // fork-execs children, and operator-facing when running a one-session
    // foreground daemon outside launchd.
    if let Some(ref name) = session {
        // v0.14.2 #44: resolve via the layout-aware helper so v0.13
        // by-key sessions (where the on-disk dir is a hash and the
        // operator-typed name is the persona handle, e.g.
        // "coral-weasel") work as well as legacy v0.6 top-level
        // sessions. Pre-fix: `session_dir(name)` only resolved the
        // legacy form → operator running `wire daemon --session
        // coral-weasel` in a tmux pane saw "session not found" even
        // though `wire session list` clearly enumerated it.
        let home = crate::session::find_session_home_by_name(name)
            .with_context(|| format!("resolving session home for --session {name}"))?
            .ok_or_else(|| {
                anyhow!(
                    "session '{name}' not found — run `wire session list` to see initialized sessions"
                )
            })?;
        // SAFETY: cmd_daemon is the one process-lifetime entrypoint that
        // chooses a session. No other thread reads WIRE_HOME yet.
        unsafe {
            std::env::set_var("WIRE_HOME", &home);
        }
        if !as_json {
            eprintln!(
                "wire daemon: pinned to session '{name}' (WIRE_HOME={})",
                home.display()
            );
        }
    }
    if !config::is_initialized()? {
        bail!("not initialized — run `wire up` first");
    }
    // v0.14.2 (#162): pidfile singleton on the persistent daemon. If
    // another live `wire daemon` already owns the pidfile, exit 0 with a
    // human/JSON message instead of starting a second polling loop —
    // honey-pine's report observed 3 concurrent daemons polling the same
    // slot, wasteful and a possible source of duplicate-pull races.
    // `--once` is a single sync cycle and doesn't own the cursor; the
    // singleton check is skipped for it (matches the existing collision
    // warning's `--once` carve-out). Test escape hatch:
    // `WIRE_DAEMON_NO_SINGLETON=1`.
    let _pid_guard = if !once && std::env::var("WIRE_DAEMON_NO_SINGLETON").is_err() {
        if let Some(holder_pid) = crate::ensure_up::daemon_singleton_holder() {
            if as_json {
                println!(
                    "{}",
                    serde_json::to_string(&json!({
                        "status": "skipped",
                        "reason": "daemon already running",
                        "holder_pid": holder_pid,
                    }))?
                );
            } else {
                eprintln!(
                    "wire daemon: another daemon is already running (pid {holder_pid}); not starting a second polling loop. Set WIRE_DAEMON_NO_SINGLETON=1 to override."
                );
            }
            return Ok(());
        }
        Some(crate::ensure_up::claim_daemon_singleton()?)
    } else {
        None
    };
    // v0.13.x identity work: a long-running daemon racing another wire
    // process for the same inbox cursor silently loses messages. Surface
    // the collision the same way `wire mcp` does. Skipped under `--once`:
    // a single sync cycle is atomic and doesn't own the cursor.
    if !once {
        crate::session::warn_on_identity_collision(std::process::id(), "daemon");
    }
    let interval = std::time::Duration::from_secs(interval_secs.max(1));

    if !as_json {
        if once {
            eprintln!("wire daemon: single sync cycle, then exit");
        } else {
            eprintln!("wire daemon: syncing every {interval_secs}s. SIGINT to stop.");
        }
    }

    // Claim the daemon pidfile for this process so `wire status` / doctor /
    // the singleton guard can see us when started directly (not via
    // ensure_background). Best-effort.
    if let Err(e) = crate::ensure_up::write_self_daemon_pid() {
        eprintln!("daemon: pidfile write error: {e:#}");
    }

    // R1 phase 2: spawn the SSE stream subscriber. On every event pushed
    // to our slot, the subscriber signals `wake_rx`; we use it as the
    // sleep-or-wake gate of the polling loop. Polling stays as the
    // safety net — stream errors fall back transparently to the existing
    // interval-based cadence.
    let (wake_tx, wake_rx) = std::sync::mpsc::channel::<()>();
    if !once {
        crate::daemon_stream::spawn_stream_subscriber(wake_tx);
    }

    // Arm inbound-message OS toasts inside the always-on daemon: fold the
    // `wire notify` sweep into the sync loop so the default `wire up` path
    // delivers toasts for incoming messages (previously nothing ever started
    // a notify sweep — inbound messages arrived silently). `--once` is a
    // single atomic cycle that doesn't own the cursor, so it stays opt-out.
    let mut notify_state: Option<(crate::inbox_watch::InboxWatcher, std::path::PathBuf)> = if once {
        None
    } else {
        let cursor_path = config::state_dir()?.join("notify.cursor");
        match crate::inbox_watch::InboxWatcher::from_cursor_file(&cursor_path) {
            Ok(w) => Some((w, cursor_path)),
            Err(e) => {
                // Non-fatal: the sync loop is the daemon's core job; toasts
                // are a side channel. Degrade to no toasts, keep syncing.
                eprintln!("daemon: notify watcher init failed, toasts disabled: {e:#}");
                None
            }
        }
    };

    loop {
        let pushed = run_sync_push().unwrap_or_else(|e| {
            eprintln!("daemon: push error: {e:#}");
            json!({"pushed": [], "skipped": [{"error": e.to_string()}]})
        });
        let pulled = run_sync_pull().unwrap_or_else(|e| {
            eprintln!("daemon: pull error: {e:#}");
            json!({"written": [], "rejected": [], "total_seen": 0, "error": e.to_string()})
        });

        // Toast any newly-arrived inbox events (folded-in `wire notify`).
        if let Some((ref mut watcher, ref cursor_path)) = notify_state {
            match super::comms::notify_sweep_new_events(watcher, cursor_path) {
                Ok(events) => super::comms::toast_inbox_events(&events),
                Err(e) => eprintln!("daemon: notify sweep error: {e:#}"),
            }
        }

        // v0.14.2 (#162): persist a `last_sync.json` record after every
        // cycle (including --once + cycles that pushed/pulled zero events
        // — the "idle daemon is alive" signal is exactly what the
        // detection layers need). Readers: `wire status`,
        // `mcp__wire__wire_status`, `mcp__wire__wire_send` annotations.
        // Best-effort: errors log + don't abort the loop.
        let cycle_push_n = pushed["pushed"].as_array().map(|a| a.len()).unwrap_or(0);
        let cycle_pull_n = pulled["written"].as_array().map(|a| a.len()).unwrap_or(0);
        let cycle_rejected_n = pulled["rejected"].as_array().map(|a| a.len()).unwrap_or(0);
        crate::ensure_up::write_last_sync_record(cycle_push_n, cycle_pull_n, cycle_rejected_n);

        if as_json {
            println!(
                "{}",
                serde_json::to_string(&json!({
                    "ts": time::OffsetDateTime::now_utc()
                        .format(&time::format_description::well_known::Rfc3339)
                        .unwrap_or_default(),
                    "push": pushed,
                    "pull": pulled,
                }))?
            );
        } else if cycle_push_n > 0 || cycle_pull_n > 0 || cycle_rejected_n > 0 {
            eprintln!(
                "daemon: pushed={cycle_push_n} pulled={cycle_pull_n} rejected={cycle_rejected_n}"
            );
        }

        if once {
            return Ok(());
        }
        // Wait either for the next poll-interval tick OR for a stream
        // wake signal — whichever comes first. Drain any additional
        // wake-ups that accumulated during the previous cycle since one
        // pull catches up everything.
        //
        // v0.13.2 (wisp-blossom): if the stream subscriber thread has gone
        // away, `wake_rx` is Disconnected and `recv_timeout` returns
        // INSTANTLY — which would busy-spin the sync loop (hammering push/pull
        // + the relay with zero delay). Fall back to a plain sleep so a dead
        // stream degrades to normal polling and never kills or pegs the
        // daemon. (Realizes the "decouple stream from sync" hardening — a
        // stream failure must never affect the push/pull loop.)
        match wake_rx.recv_timeout(interval) {
            Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                std::thread::sleep(interval);
            }
        }
        while wake_rx.try_recv().is_ok() {}
    }
}

/// Programmatic push (no stdout, no exit on errors). Returns the same JSON
/// shape `wire push --json` emits.
pub fn run_sync_push() -> Result<Value> {
    let state = config::read_relay_state()?;
    let peers = state["peers"].as_object().cloned().unwrap_or_default();
    if peers.is_empty() {
        return Ok(json!({"pushed": [], "skipped": []}));
    }
    let outbox_dir = config::outbox_dir()?;
    if !outbox_dir.exists() {
        return Ok(json!({"pushed": [], "skipped": []}));
    }
    let mut pushed = Vec::new();
    let mut skipped = Vec::new();
    for (peer_handle, slot_info) in peers.iter() {
        let outbox = outbox_dir.join(format!("{peer_handle}.jsonl"));
        if !outbox.exists() {
            continue;
        }
        let url = slot_info["relay_url"].as_str().unwrap_or("");
        let slot_id = slot_info["slot_id"].as_str().unwrap_or("");
        let slot_token = slot_info["slot_token"].as_str().unwrap_or("");
        if url.is_empty() || slot_id.is_empty() || slot_token.is_empty() {
            continue;
        }
        let client = crate::relay_client::RelayClient::new(url);
        let body = std::fs::read_to_string(&outbox)?;
        for line in body.lines() {
            let event: Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let event_id = event
                .get("event_id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            match client.post_event(slot_id, slot_token, &event) {
                Ok(resp) => {
                    // v0.14.2 (#162 fix #2): record the queued → pushed
                    // transition in the per-peer lifecycle log. Both
                    // `ok` and `duplicate` count as pushed — the relay
                    // has the event either way, and an operator who
                    // hits the dedup path didn't lose the event. Failure
                    // here is non-fatal: the sync loop must keep
                    // running even if the lifecycle log can't be
                    // appended.
                    let now = time::OffsetDateTime::now_utc()
                        .format(&time::format_description::well_known::Rfc3339)
                        .unwrap_or_default();
                    if let Err(e) = config::append_pushed_log(peer_handle, &event_id, &now) {
                        eprintln!(
                            "daemon: pushed-log append for {peer_handle}/{event_id} failed (non-fatal): {e:#}"
                        );
                    }
                    if resp.status == "duplicate" {
                        skipped.push(json!({"peer": peer_handle, "event_id": event_id, "reason": "duplicate"}));
                    } else {
                        pushed.push(json!({"peer": peer_handle, "event_id": event_id}));
                    }
                }
                Err(e) => {
                    // v0.5.13: flatten the anyhow chain so TLS / DNS / timeout
                    // errors aren't hidden behind the topmost-context URL string.
                    // Issue #6 highest-impact silent-fail fix.
                    let reason = crate::relay_client::format_transport_error(&e);
                    skipped
                        .push(json!({"peer": peer_handle, "event_id": event_id, "reason": reason}));
                }
            }
        }
    }
    Ok(json!({"pushed": pushed, "skipped": skipped}))
}

/// Programmatic pull. Same shape as `wire pull --json`.
///
/// v0.9: routes through `endpoints::self_primary_endpoint` so sessions
/// created via `wire session new --with-local` (which only writes
/// `self.endpoints[]`, not the legacy top-level fields) actually pull.
/// Pre-v0.9 this function read only the top-level fields and silently
/// returned `{}` for any v0.5.17+ session.
/// `wire ping <peer>` (RFC-004 Tier-1) — send a liveness probe and wait for the
/// peer's daemon to auto-respond, reporting the round-trip. Does its own
/// synchronous pull (works even if our local daemon is down — it's the PEER's
/// daemon liveness we're measuring). Trust-neutral: never mutates any tier.
pub fn cmd_ping(peer: &str, as_json: bool) -> Result<()> {
    use std::time::{Duration, Instant};
    let bare = crate::agent_card::bare_handle(peer);
    let nonce = hex::encode(rand::random::<[u8; 8]>());
    let inbox_path = config::inbox_dir()?.join(format!("{bare}.jsonl"));

    let start = Instant::now();
    crate::probe::send_probe(peer, &nonce).with_context(|| format!("sending probe to {peer}"))?;

    let deadline = start + Duration::from_secs(5);
    let mut rtt_ms: Option<u128> = None;
    while Instant::now() < deadline {
        // Pull our slot(s) so an auto-responded ack lands in the inbox.
        let _ = run_sync_pull();
        if inbox_contains_probe_ack(&inbox_path, &nonce) {
            rtt_ms = Some(start.elapsed().as_millis());
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    match rtt_ms {
        Some(ms) => {
            if as_json {
                println!(
                    "{}",
                    serde_json::to_string(&json!({
                        "peer": bare, "alive": true, "rtt_ms": ms,
                    }))?
                );
            } else {
                println!("{bare}: alive — probe round-trip {ms}ms");
            }
            Ok(())
        }
        None => {
            if as_json {
                println!(
                    "{}",
                    serde_json::to_string(&json!({
                        "peer": bare, "alive": false, "rtt_ms": null,
                        "reason": "no probe_ack within 5s",
                    }))?
                );
                Ok(())
            } else {
                bail!(
                    "{bare}: no response within 5s — their daemon may be down, unreachable, or not yet on a probe-capable build"
                )
            }
        }
    }
}

/// Scan an inbox JSONL file for a probe_ack carrying `nonce`. Best-effort:
/// unreadable file / unparsable lines are skipped.
fn inbox_contains_probe_ack(path: &std::path::Path, nonce: &str) -> bool {
    let Ok(body) = std::fs::read_to_string(path) else {
        return false;
    };
    body.lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .any(|e| crate::probe::is_probe_ack_for(&e, nonce))
}

pub fn run_sync_pull() -> Result<Value> {
    let state = config::read_relay_state()?;
    if state.get("self").map(Value::is_null).unwrap_or(true) {
        return Ok(json!({"written": [], "rejected": [], "total_seen": 0}));
    }
    // E2 (v0.13.2): pull EVERY self endpoint, not just the primary. A session
    // that bound a local slot (additive) alongside its federation slot used to
    // have the daemon pull ONLY the primary (federation) endpoint — the local
    // slot was never serviced, so same-box loopback delivery silently never
    // happened until a manual restart re-seeded the (startup-only) stream
    // subscriber. Now each endpoint is pulled with its OWN cursor.
    let endpoints = crate::endpoints::self_endpoints(&state);
    if endpoints.is_empty() {
        return Ok(json!({"written": [], "rejected": [], "total_seen": 0}));
    }
    let inbox_dir = config::inbox_dir()?;
    config::ensure_dirs()?;

    // Per-slot cursors live at `self.cursors.<slot_id>`. The legacy global
    // `self.last_pulled_event_id` is migrated as the cursor for the PRIMARY
    // slot only (a federation event id won't match a local slot's log); other
    // slots start from None and `process_events` dedups against the inbox.
    let self_obj = state.get("self").cloned().unwrap_or(Value::Null);
    let legacy_cursor = self_obj
        .get("last_pulled_event_id")
        .and_then(Value::as_str)
        .map(str::to_string);
    let primary_slot = crate::endpoints::self_primary_endpoint(&state).map(|e| e.slot_id);
    let mut cursors: serde_json::Map<String, Value> = self_obj
        .get("cursors")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();

    let mut all_written: Vec<Value> = Vec::new();
    let mut all_rejected: Vec<Value> = Vec::new();
    let mut total_seen = 0usize;
    let mut blocked_any = false;

    for ep in &endpoints {
        if ep.relay_url.is_empty() {
            continue;
        }
        let cursor = cursors
            .get(&ep.slot_id)
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| {
                if Some(&ep.slot_id) == primary_slot.as_ref() {
                    legacy_cursor.clone()
                } else {
                    None
                }
            });
        let client = crate::relay_client::RelayClient::new(&ep.relay_url);
        // One endpoint erroring (relay down, slot gone) must NOT stop the
        // others — a dead local relay shouldn't black-hole federation pulls.
        let events =
            match client.list_events(&ep.slot_id, &ep.slot_token, cursor.as_deref(), Some(1000)) {
                Ok(e) => e,
                Err(e) => {
                    eprintln!(
                        "daemon: pull error on {} slot {} (continuing): {e:#}",
                        ep.relay_url, ep.slot_id
                    );
                    continue;
                }
            };
        total_seen += events.len();
        // P0.1 shared cursor-blocking logic (matches `wire pull`). A block on
        // one slot only stalls THAT slot's cursor; other slots keep flowing.
        let result = crate::pull::process_events(&events, cursor, &inbox_dir)?;
        // RFC-004 AC-HP2: daemon auto-responds to inbound probes (no LLM).
        crate::probe::respond_to_probes(&result.probes);
        if let Some(eid) = &result.advance_cursor_to {
            cursors.insert(ep.slot_id.clone(), Value::String(eid.clone()));
        }
        blocked_any |= result.blocked;
        all_written.extend(result.written);
        all_rejected.extend(result.rejected);
    }

    // P0.3 flock-protected RMW: persist per-slot cursors + keep the legacy
    // global cursor in sync with the primary slot for back-compat with older
    // binaries that only read `last_pulled_event_id`.
    let primary_cursor = primary_slot
        .as_ref()
        .and_then(|s| cursors.get(s))
        .and_then(Value::as_str)
        .map(str::to_string);
    // v0.14.3 (#14): group `written` by sender handle, take max
    // timestamp, write to `peers[<handle>].last_inbound_event_at`.
    // RFC3339-comparable as lex sort (same offset, ISO 8601). This
    // is the daemon-written signal `check_peer_staleness` needs —
    // robust against backup/restore/`touch` that breaks inbox-mtime
    // detection. Additive field: pre-v0.14.3 readers ignore it,
    // older daemons just don't write it.
    let mut latest_inbound: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    for w in &all_written {
        let from = match w.get("from").and_then(Value::as_str) {
            Some(s) => s.to_string(),
            None => continue,
        };
        let ts = match w.get("timestamp").and_then(Value::as_str) {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => continue,
        };
        latest_inbound
            .entry(from)
            .and_modify(|existing| {
                if ts > *existing {
                    *existing = ts.clone();
                }
            })
            .or_insert(ts);
    }
    config::update_relay_state(|state| {
        if let Some(self_obj) = state.get_mut("self").and_then(Value::as_object_mut) {
            self_obj.insert("cursors".into(), Value::Object(cursors.clone()));
            if let Some(pc) = &primary_cursor {
                self_obj.insert("last_pulled_event_id".into(), Value::String(pc.clone()));
            }
        }
        if !latest_inbound.is_empty()
            && let Some(peers_obj) = state.get_mut("peers").and_then(Value::as_object_mut)
        {
            for (handle, ts) in &latest_inbound {
                let entry = peers_obj.entry(handle.clone()).or_insert_with(|| json!({}));
                if let Some(obj) = entry.as_object_mut() {
                    obj.insert("last_inbound_event_at".into(), Value::String(ts.clone()));
                }
            }
        }
        Ok(())
    })?;

    Ok(json!({
        "written": all_written,
        "rejected": all_rejected,
        "total_seen": total_seen,
        "cursor_blocked": blocked_any,
        "endpoints_pulled": endpoints.len(),
    }))
}

/// Issue #69 follow-up to #15: predicate "does this error smell like a
/// 4xx slot rotation?" — used by `try_reresolve_peer_on_slot_4xx` to
/// decide whether to spend a whois RTT on a re-resolve.
///
/// Original #15 implementation used `last_err.contains("410") ||
/// last_err.contains("404")`, which false-triggers on any unrelated
/// substring with `"410"`/`"404"` in it — e.g. `"slot 4101 expired"`,
/// `"request_id=410abc..."`, `"received 4040 bytes"`. False-trigger cost
/// is a single wasted whois per push call per peer (rate-limited by
/// `already_tried`), but it muddies the doctor diagnostic by inserting
/// spurious "peer slot rotated" log lines.
///
/// This predicate gates on the status code appearing as a *whole token*
/// — preceded by start-of-string / space / colon / tab / newline AND
/// followed by end-of-string / space / colon / tab / newline. That
/// matches both real-world shapes:
///
/// - `reqwest::StatusCode` Display, via `relay_client.rs` line ~339
///   `format!("post_event failed: {status}: {detail}")` →
///   `"post_event failed: 410 Gone: <body>"` (token `"410"` is followed
///   by space).
/// - UDS bare-`u16` Display, via `relay_client.rs` line ~227
///   `format!("post_event (uds {socket_path}) failed: {status}: ...")` →
///   `"post_event (uds /tmp/...sock) failed: 410: <body>"` (token
///   `"410"` is followed by colon).
///
/// And rejects the false-positive shapes documented in
/// `error_smells_like_slot_4xx_tests` below.
pub fn error_smells_like_slot_4xx(last_err: &str) -> bool {
    fn is_token_boundary(b: u8) -> bool {
        matches!(b, b' ' | b':' | b'\t' | b'\n' | b'\r')
    }
    let bytes = last_err.as_bytes();
    for code in ["410", "404"] {
        let code_bytes = code.as_bytes();
        let mut search_from = 0usize;
        while let Some(rel) = last_err[search_from..].find(code) {
            let abs = search_from + rel;
            let end = abs + code_bytes.len();
            let before_ok = abs == 0 || is_token_boundary(bytes[abs - 1]);
            let after_ok = end == bytes.len() || is_token_boundary(bytes[end]);
            if before_ok && after_ok {
                return true;
            }
            // Step past this candidate to find the next occurrence; using
            // `+ 1` (rather than `+ code_bytes.len()`) keeps the scan
            // cheap and guarantees forward progress even on overlap.
            search_from = abs + 1;
        }
    }
    false
}

/// Issue #15: detect a 4xx-shaped push failure that smells like "slot
/// rotated by peer" and update the peer's pin in place with the freshly
/// resolved slot from the relay's handle directory.
///
/// Returns:
/// - `Ok(true)` — peer's pin was rotated; caller should refresh
///   `peer_endpoints_in_priority_order(&state, ...)` and retry.
/// - `Ok(false)` — re-resolve completed but the slot id was unchanged
///   (false-alarm 4xx, e.g. throttling); caller should NOT retry.
/// - `Err(e)` — re-resolve itself failed (network down, relay 5xx,
///   handle no longer claimed, etc.); caller should fall through to the
///   existing "skipped" path.
///
/// Only triggers when:
///   - The error string carries a 4xx slot-rotation status token (`410`/`404`)
///     as a *whole token* — preceded by start/space/colon/tab/newline and
///     followed by end/space/colon/tab/newline. This matches both the
///     `reqwest::StatusCode` Display shape (`": 410 Gone"`) and the UDS
///     bare-`u16` shape (`": 410:"`) emitted by `post_event` in
///     `src/relay_client.rs`, while rejecting substring false-positives
///     like `"slot 4101 expired"` or `"request_id=410abc..."`. See
///     `error_smells_like_slot_4xx` below.
///   - The peer has a pinned `relay_url` we can parse a handle@domain from.
///   - The caller hasn't already re-resolved this peer in the current push
///     call (caller's responsibility — pass `already_tried` from a set kept
///     in the outer per-peer loop). One whois per peer per push call,
///     exactly the rate limit the issue specifies.
///
/// Updates `state.peers[peer_handle]` in place (rotates the federation
/// endpoint's slot_id + slot_token to the fresh resolve), and emits a
/// stderr WARN so the operator can see the rotation event in their
/// terminal alongside the unrelated `wire push` output. Caller is
/// responsible for persisting `state` back to disk via
/// `config::write_relay_state` after all per-peer re-resolves settle.
fn try_reresolve_peer_on_slot_4xx(
    state: &mut Value,
    peer_handle: &str,
    last_err: &str,
    already_tried: &std::collections::HashSet<String>,
) -> Result<bool> {
    if !error_smells_like_slot_4xx(last_err) {
        // Not the slot-rotation shape. Don't waste a whois on this.
        return Ok(false);
    }
    if already_tried.contains(peer_handle) {
        // Rate limit: at most one whois per peer per push call.
        return Ok(false);
    }
    // Find the peer's pinned federation endpoint to re-resolve against.
    let peer_entry = state
        .get("peers")
        .and_then(|p| p.get(peer_handle))
        .ok_or_else(|| anyhow!("peer `{peer_handle}` not in relay_state"))?;
    let peer_relay = peer_entry
        .get("endpoints")
        .and_then(Value::as_array)
        .and_then(|arr| {
            arr.iter().find(|e| {
                e.get("scope").and_then(Value::as_str) == Some("federation")
                    || e.get("scope").and_then(Value::as_str) == Some("Federation")
            })
        })
        .and_then(|e| e.get("relay_url").and_then(Value::as_str))
        .or_else(|| peer_entry.get("relay_url").and_then(Value::as_str))
        .ok_or_else(|| {
            anyhow!("peer `{peer_handle}` has no federation endpoint to re-resolve against")
        })?
        .to_string();
    // Strip scheme + path to get the relay domain. Same shape parse used by
    // pair_profile::resolve_handle's input contract.
    let domain = peer_relay
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(&peer_relay)
        .to_string();
    let handle = crate::pair_profile::Handle {
        nick: peer_handle.to_string(),
        domain,
    };
    let resolved = crate::pair_profile::resolve_handle(&handle, Some(&peer_relay))?;
    let new_slot_id = resolved
        .get("slot_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("re-resolved payload missing slot_id"))?
        .to_string();
    // Compare against the currently-pinned federation slot.
    let peers = state
        .get_mut("peers")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| anyhow!("relay_state.peers missing or wrong shape"))?;
    let peer_entry = peers
        .get_mut(peer_handle)
        .ok_or_else(|| anyhow!("peer `{peer_handle}` disappeared from state mid-resolve"))?;
    let current_slot_id = peer_entry
        .get("endpoints")
        .and_then(Value::as_array)
        .and_then(|arr| {
            arr.iter().find(|e| {
                let scope = e.get("scope").and_then(Value::as_str);
                scope == Some("federation") || scope == Some("Federation")
            })
        })
        .and_then(|e| e.get("slot_id").and_then(Value::as_str))
        .unwrap_or("")
        .to_string();
    if current_slot_id == new_slot_id {
        // Same slot — the 4xx was something else (rate limit, server burp).
        return Ok(false);
    }
    // Rotate in place. We update slot_id but DROP the slot_token: only the
    // peer's freshly-issued slot_token (which arrives via a new pair_drop_ack)
    // is valid. Sending against the new slot without a fresh token gets 401,
    // so the operator will see one more "skipped: 401" and the next pair
    // cycle (or a manual `wire add <peer>@<relay>` per the doctor #14 fix)
    // refreshes the token. This is the same trade-off the issue spells out:
    // auto-rotation closes the slot mismatch; token refresh still needs the
    // bilateral pair gate.
    if let Some(endpoints) = peer_entry
        .get_mut("endpoints")
        .and_then(Value::as_array_mut)
    {
        for ep in endpoints.iter_mut() {
            let scope = ep.get("scope").and_then(Value::as_str);
            if scope == Some("federation") || scope == Some("Federation") {
                ep["slot_id"] = Value::String(new_slot_id.clone());
                ep["slot_token"] = Value::String(String::new());
            }
        }
    }
    // Also update the legacy top-level fields for v0.5.16-era readers (the
    // same back-compat surface pair_drop_ack uses).
    peer_entry["slot_id"] = Value::String(new_slot_id.clone());
    peer_entry["slot_token"] = Value::String(String::new());
    eprintln!(
        "wire push: peer `{peer_handle}` rotated their relay slot (was `{current_slot_id}`, \
         now `{new_slot_id}`); pin updated in place. Re-pair via `wire add \
         {peer_handle}@<relay>` to refresh the slot_token."
    );
    Ok(true)
}

#[cfg(test)]
mod slot_reresolve_tests {
    use super::*;

    /// Issue #15: the gating logic of try_reresolve_peer_on_slot_4xx
    /// must short-circuit BEFORE any network call when the error shape
    /// doesn't smell like slot rotation, when the peer was already
    /// re-resolved this push, or when there's no peer entry to work
    /// against. Three of those four short-circuit paths are testable
    /// without a mock relay; the fourth (the actual whois + slot
    /// comparison) requires either a live test server or a mock
    /// transport, so it's covered manually via the failover_tests
    /// helper + integration check in a separate PR.
    ///
    /// What these tests pin:
    ///   - 200/500/timeout-shape errors do NOT trigger a re-resolve
    ///     (avoids wasted whois RTTs and churn in steady-state).
    ///   - Same peer twice in one push call only attempts re-resolve
    ///     once (rate limit the issue specifies).
    ///   - Missing peer entry surfaces as an explicit error, NOT a
    ///     silent skip (operator can see the malformed state).
    ///   - Peer with no federation endpoint surfaces as an explicit
    ///     error (you can't re-resolve a slot you can't address).

    #[test]
    fn try_reresolve_skips_when_error_is_not_4xx_shape() {
        let mut state = json!({"peers": {"some-peer": {"endpoints": []}}});
        let already = std::collections::HashSet::new();
        // 200 OK shouldn't ever land in this path, but sanity check the
        // negative filter: any error string without "404"/"410" is a no-op.
        let res =
            try_reresolve_peer_on_slot_4xx(&mut state, "some-peer", "post failed: 502", &already)
                .unwrap();
        assert!(!res, "502 must NOT trigger a re-resolve");

        let res =
            try_reresolve_peer_on_slot_4xx(&mut state, "some-peer", "connection refused", &already)
                .unwrap();
        assert!(!res, "transport errors must NOT trigger a re-resolve");

        let res = try_reresolve_peer_on_slot_4xx(
            &mut state,
            "some-peer",
            "post failed: 401 Unauthorized",
            &already,
        )
        .unwrap();
        assert!(
            !res,
            "401 (auth) is a token problem, not a slot rotation — must NOT trigger a re-resolve"
        );
    }

    #[test]
    fn try_reresolve_rate_limits_one_attempt_per_peer_per_push() {
        // The issue's rate limit: "at most one whois per peer per push call."
        // Caller tracks via `already_tried`; helper must honor it BEFORE
        // attempting any I/O (otherwise a bad-state peer would burn a
        // network call per event in the outbox).
        let mut state = json!({"peers": {"some-peer": {"endpoints": []}}});
        let mut already = std::collections::HashSet::new();
        already.insert("some-peer".to_string());
        let res = try_reresolve_peer_on_slot_4xx(
            &mut state,
            "some-peer",
            "post failed: 410 Gone",
            &already,
        )
        .unwrap();
        assert!(
            !res,
            "peer already in `already_tried` must NOT trigger another re-resolve in the same push"
        );
    }

    #[test]
    fn try_reresolve_errors_when_peer_missing_from_state() {
        // Surface state corruption explicitly rather than silently
        // returning Ok(false). If a peer disappeared from relay_state
        // mid-loop the operator needs to see it.
        let mut state = json!({"peers": {}});
        let already = std::collections::HashSet::new();
        let err = try_reresolve_peer_on_slot_4xx(
            &mut state,
            "missing-peer",
            "post failed: 410 Gone",
            &already,
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("missing-peer") && err.contains("not in relay_state"),
            "missing-peer error must name the peer + the failure: {err}"
        );
    }

    #[test]
    fn try_reresolve_errors_when_peer_has_no_federation_endpoint() {
        // A peer with only local-scope endpoints (UDS / 127.0.0.1) has
        // no relay domain to whois against. Helper must surface this as
        // an actionable error, not a silent skip — the operator's
        // remediation is "pair via federation" or "you're on the same
        // box, the slot can't be 410'd by a peer who controls the
        // socket."
        let mut state = json!({
            "peers": {
                "local-only": {
                    "endpoints": [
                        {
                            "scope": "Local",
                            "relay_url": "http://127.0.0.1:8771",
                            "slot_id": "loc",
                            "slot_token": "tok"
                        }
                    ]
                }
            }
        });
        let already = std::collections::HashSet::new();
        let err = try_reresolve_peer_on_slot_4xx(
            &mut state,
            "local-only",
            "post failed: 410 Gone",
            &already,
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("federation endpoint"),
            "no-federation error must name the problem: {err}"
        );
    }

    /// Issue #69: pin the word-boundary behavior of
    /// `error_smells_like_slot_4xx`. Prior implementation used a bare
    /// `contains("410") || contains("404")` substring match, which
    /// false-triggered on any unrelated error string containing those
    /// digits — e.g. slot ids that happen to start with `410`, request
    /// IDs, byte counts, etc.  Each false-positive cost a wasted whois
    /// per peer per push and a misleading "peer slot rotated" log line.
    ///
    /// These tests pin three classes:
    ///   - Real reqwest StatusCode Display shapes (`": 410 Gone"`,
    ///     `": 404 Not Found"`) trigger.
    ///   - Real UDS bare-`u16` shapes (`": 410:"`, `": 404:"`) trigger.
    ///   - Substring lookalikes (`"slot 4101 expired"`,
    ///     `"request_id=410abc"`, `"received 4040 bytes"`,
    ///     `"event 0x4104"`) do NOT trigger.
    #[test]
    fn error_smells_like_slot_4xx_matches_reqwest_status_display_shape() {
        // reqwest::StatusCode Display is "<u16> <reason>", embedded in
        // the post_event failure format string as "...failed: <status>: <detail>".
        assert!(error_smells_like_slot_4xx(
            "post_event failed: 410 Gone: slot rotated by peer"
        ));
        assert!(error_smells_like_slot_4xx(
            "post_event failed: 404 Not Found: handle no longer claimed"
        ));
    }

    #[test]
    fn error_smells_like_slot_4xx_matches_uds_bare_u16_shape() {
        // UDS path formats status as a bare u16, so the shape is
        // "...failed: 410: <detail>" with the status flanked by spaces
        // and colons (no reason phrase).
        assert!(error_smells_like_slot_4xx(
            "post_event (uds /tmp/wire-relay.sock) failed: 410: gone"
        ));
        assert!(error_smells_like_slot_4xx(
            "post_event (uds /tmp/wire-relay.sock) failed: 404: not found"
        ));
    }

    #[test]
    fn error_smells_like_slot_4xx_rejects_substring_lookalikes() {
        // The bug being fixed: the prior `contains("410")` predicate
        // matched ALL of these, burning a whois RTT and emitting a
        // spurious "peer slot rotated" log line each time.
        let false_positives = [
            "push aborted: slot 4101 expired",
            "post_event failed: 502 Bad Gateway: request_id=410abc-deadbeef",
            "post_event failed: 500: received 4040 bytes, expected envelope",
            "post_event failed: 500: event 0x4104 malformed",
            "post_event failed: 503: backlog=4102 entries pending",
            // 4044 is "received bytes" or anything containing 404 mid-token.
            "post_event failed: 500: tx_id=4044beef",
            // pure digit substrings inside identifiers / hashes:
            "post_event failed: 500: hash=abc410def",
        ];
        for case in false_positives {
            assert!(
                !error_smells_like_slot_4xx(case),
                "must NOT trigger re-resolve on substring lookalike: {case:?}"
            );
        }
    }

    #[test]
    fn error_smells_like_slot_4xx_handles_edge_positions() {
        // Token at start of string (no preceding char).
        assert!(error_smells_like_slot_4xx("410 Gone"));
        assert!(error_smells_like_slot_4xx("404 Not Found"));
        // Token at end of string (no trailing char).
        assert!(error_smells_like_slot_4xx("got 410"));
        assert!(error_smells_like_slot_4xx("got 404"));
        // Tab and newline as separators (logs sometimes carry these).
        assert!(error_smells_like_slot_4xx("post_event failed:\t410\tGone"));
        assert!(error_smells_like_slot_4xx("post_event failed:\n410\nGone"));
        // Pure digit-only input that IS the code — token at start AND end.
        assert!(error_smells_like_slot_4xx("410"));
        assert!(error_smells_like_slot_4xx("404"));
        // Empty / no-match.
        assert!(!error_smells_like_slot_4xx(""));
        assert!(!error_smells_like_slot_4xx("no relevant status"));
        // 411-414, 401-403, 405-409 must NOT trigger (only 410/404 are
        // the slot-rotation shape per issue #15).
        assert!(!error_smells_like_slot_4xx(
            "post_event failed: 401 Unauthorized"
        ));
        assert!(!error_smells_like_slot_4xx(
            "post_event failed: 403 Forbidden"
        ));
        assert!(!error_smells_like_slot_4xx(
            "post_event failed: 411 Length Required"
        ));
    }
}
