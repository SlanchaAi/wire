use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};

use crate::{config, signing::sign_message_v31};

// ---------- peers ----------

pub(super) fn cmd_peers(as_json: bool) -> Result<()> {
    let trust = config::read_trust()?;
    let agents = trust
        .get("agents")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let relay_state = config::read_relay_state().unwrap_or_else(|_| json!({"peers": {}}));

    let mut self_did: Option<String> = None;
    if let Ok(card) = config::read_agent_card() {
        self_did = card.get("did").and_then(Value::as_str).map(str::to_string);
    }

    let mut peers = Vec::new();
    for (handle, agent) in agents.iter() {
        let did = agent
            .get("did")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if Some(did.as_str()) == self_did.as_deref() {
            continue; // skip self-attestation
        }
        let tier = super::effective_peer_tier(&trust, &relay_state, handle);
        let capabilities = agent
            .get("card")
            .and_then(|c| c.get("capabilities"))
            .cloned()
            .unwrap_or_else(|| json!([]));
        // v0.7.0-alpha.6: prefer peer's published character override
        // (display.nickname / display.emoji on their pinned agent-card).
        // Falls back to auto-derived if peer hasn't renamed themselves
        // OR runs an older wire that doesn't publish the field.
        let character = if did.is_empty() {
            None
        } else {
            let card_obj = agent.get("card");
            Some(match card_obj {
                Some(card) => crate::character::Character::from_card(card),
                None => crate::character::Character::from_did(&did),
            })
        };
        // v0.14: surface peer's op claims when their pinned card carries
        // them (post-v0.14 peers). Older peers ⇒ absent keys; same shape
        // as `wire whoami --json` so operators have one mental model.
        let peer_op_claims = agent
            .get("card")
            .map(super::op_claims_from_card)
            .unwrap_or_default();
        let mut row = serde_json::Map::new();
        row.insert("handle".into(), json!(handle));
        row.insert("did".into(), json!(did));
        row.insert("tier".into(), json!(tier));
        row.insert("capabilities".into(), capabilities);
        row.insert("persona".into(), serde_json::to_value(&character)?);
        for (k, v) in peer_op_claims {
            row.insert(k, v);
        }
        peers.push(Value::Object(row));
    }

    if as_json {
        println!("{}", serde_json::to_string(&peers)?);
    } else if peers.is_empty() {
        println!("no peers pinned (run `wire join <code>` to pair)");
    } else {
        // v0.7.0-alpha.8 (review-fix #3): reuse the character we ALREADY
        // computed above (from peer's agent-card, honoring override) so
        // text and JSON output never diverge. Pre-alpha.8 the text loop
        // recomputed via Character::from_did (no override) — operators
        // saw different identities depending on --json flag.
        for p in &peers {
            let char_json = &p["persona"];
            let (colored_char, plain_len): (String, usize) = match char_json {
                serde_json::Value::Null => ("?".to_string(), 1),
                v => match serde_json::from_value::<crate::character::Character>(v.clone()) {
                    Ok(c) => {
                        let plain = c.short().chars().count() + 1; // +1 emoji-wide compensation
                        (c.colored(), plain)
                    }
                    Err(_) => ("?".to_string(), 1),
                },
            };
            let pad = 22usize.saturating_sub(plain_len);
            println!(
                "{}{}  {:<20} {:<10} {}",
                colored_char,
                " ".repeat(pad),
                p["handle"].as_str().unwrap_or(""),
                p["tier"].as_str().unwrap_or(""),
                p["did"].as_str().unwrap_or(""),
            );
        }
    }
    Ok(())
}

// ---------- send ----------

/// R4 attentiveness pre-flight. Best-effort: any failure is silent.
///
/// Looks up `peer` in relay-state for slot_id + slot_token + relay_url, asks
/// the relay for the slot's `last_pull_at_unix`, and prints a warning to
/// stderr if the peer hasn't polled in > 5min (or never has). Threshold of
/// 300s is the same wire daemon polling cadence rule-of-thumb — a peer
/// hasn't crossed two heartbeats means probably degraded.
fn maybe_warn_peer_attentiveness(peer: &str) {
    let state = match config::read_relay_state() {
        Ok(s) => s,
        Err(_) => return,
    };
    let p = state.get("peers").and_then(|p| p.get(peer));
    let slot_id = match p.and_then(|p| p.get("slot_id")).and_then(Value::as_str) {
        Some(s) if !s.is_empty() => s,
        _ => return,
    };
    let slot_token = match p.and_then(|p| p.get("slot_token")).and_then(Value::as_str) {
        Some(s) if !s.is_empty() => s,
        _ => return,
    };
    let relay_url = match p.and_then(|p| p.get("relay_url")).and_then(Value::as_str) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => match state
            .get("self")
            .and_then(|s| s.get("relay_url"))
            .and_then(Value::as_str)
        {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => return,
        },
    };
    let client = crate::relay_client::RelayClient::new(&relay_url);
    let (_count, last_pull) = match client.slot_state(slot_id, slot_token) {
        Ok(t) => t,
        Err(_) => return,
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    match last_pull {
        None => {
            eprintln!(
                "phyllis: {peer}'s line is silent — relay sees no pulls yet. message will queue, but they may not be listening."
            );
        }
        Some(t) if now.saturating_sub(t) > 300 => {
            let mins = now.saturating_sub(t) / 60;
            eprintln!(
                "phyllis: {peer} hasn't picked up in {mins}m — message will queue, but they may be away."
            );
        }
        _ => {}
    }
}

pub(crate) fn parse_deadline_until(input: &str) -> Result<String> {
    let trimmed = input.trim();
    if time::OffsetDateTime::parse(trimmed, &time::format_description::well_known::Rfc3339).is_ok()
    {
        return Ok(trimmed.to_string());
    }
    // Split before the LAST CHAR, not the last byte — a multi-byte final
    // char (`30分`) would land `split_at` mid-char and panic.
    let unit_start = trimmed.char_indices().next_back().map_or(0, |(i, _)| i);
    let (amount, unit) = trimmed.split_at(unit_start);
    let n: i64 = amount
        .parse()
        .with_context(|| format!("deadline must be `30m`, `2h`, `1d`, or RFC3339: {input:?}"))?;
    if n <= 0 {
        bail!("deadline duration must be positive: {input:?}");
    }
    let duration = match unit {
        "m" => time::Duration::minutes(n),
        "h" => time::Duration::hours(n),
        "d" => time::Duration::days(n),
        _ => bail!("deadline must end in m, h, d, or be RFC3339: {input:?}"),
    };
    Ok((time::OffsetDateTime::now_utc() + duration)
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string()))
}

#[cfg(test)]
mod deadline_tests {
    use super::*;

    #[test]
    fn duration_shorthand_parses() {
        assert!(parse_deadline_until("30m").is_ok());
        assert!(parse_deadline_until("2h").is_ok());
        assert!(parse_deadline_until("1d").is_ok());
    }

    #[test]
    fn rfc3339_passes_through() {
        assert_eq!(
            parse_deadline_until("2030-01-02T03:04:05Z").unwrap(),
            "2030-01-02T03:04:05Z"
        );
    }

    #[test]
    fn garbage_is_an_error_not_a_panic() {
        assert!(parse_deadline_until("soon").is_err());
        assert!(parse_deadline_until("").is_err());
        assert!(parse_deadline_until("-5m").is_err());
        assert!(parse_deadline_until("0h").is_err());
    }

    #[test]
    fn multibyte_final_char_is_an_error_not_a_panic() {
        // Regression: `split_at(len - 1)` used a byte index; a multi-byte
        // final char (`分`, `µ`, `日`) landed mid-char and panicked.
        assert!(parse_deadline_until("30分").is_err());
        assert!(parse_deadline_until("5µ").is_err());
        assert!(parse_deadline_until("日").is_err());
    }
}

pub(super) fn cmd_send(
    peer: &str,
    kind: &str,
    body_arg: &str,
    deadline: Option<&str>,
    // v0.10: when true, refuse to auto-pair on miss; fail loudly so
    // scripts can branch on the error instead of accepting an implicit
    // side effect.
    no_auto_pair: bool,
    // v0.14.2: opt back into the legacy outbox→daemon-push path. When
    // false (default), we POST synchronously and return a real
    // `delivered` / `duplicate` / `failed` verdict.
    queue: bool,
    as_json: bool,
) -> Result<()> {
    if !config::is_initialized()? {
        bail!("not initialized — run `wire up` first");
    }
    let peer_in = crate::agent_card::bare_handle(peer).to_string();
    // v0.7.0-alpha.2/.5: nickname-as-handle resolution. Exact handle
    // match wins; nickname (DID-hash auto-derived) is the fallback.
    // Ambiguous nicknames (two pinned peers DID-hash to the same
    // adj-noun pair) fail loudly with disambiguation; unknown handles
    // pass through and surface as `peer_unknown` from the sync
    // delivery layer (post-#187 `wire send` is sync by default;
    // `--queue` opts back into the legacy outbox-write path).
    let peer = match super::resolve_peer_handle(&peer_in) {
        Ok(Some(resolved)) if resolved != peer_in => {
            eprintln!("wire send: resolved nickname `{peer_in}` → peer `{resolved}`");
            resolved
        }
        Ok(Some(canonical)) => canonical, // exact handle match
        Ok(None) => peer_in,              // unknown — pass through, downstream errors
        Err(super::ResolveError::Ambiguous(candidates)) => bail!(
            "nickname `{peer_in}` is ambiguous — matches {} pinned peers: {}. \
             Disambiguate by passing the peer handle (one of those listed) instead of the nickname.",
            candidates.len(),
            candidates.join(", ")
        ),
        Err(super::ResolveError::NotFound) => peer_in, // (unreachable for this fn but defensive)
    };

    // v0.9 auto-pair-on-miss: if the resolved peer isn't pinned yet but
    // matches a local sister session, pair first (disk-read --local-sister
    // path) then continue. Pre-v0.14.2 closed the "wire send returns queued but
    // peer never receives because we were never paired" silent-fail
    // class. Equivalent to `wire dial <name>` followed by `wire send
    // <name> ...` in one step.
    let peer_is_pinned = config::read_relay_state()
        .ok()
        .and_then(|s| s.get("peers").and_then(Value::as_object).cloned())
        .map(|peers| peers.contains_key(&peer))
        .unwrap_or(false);
    if !peer_is_pinned && let Some(sister_name) = crate::session::resolve_local_sister(&peer) {
        if no_auto_pair {
            bail!(
                "wire send: `{peer}` resolves to local sister `{sister_name}` but is not pinned, \
                 and --no-auto-pair was passed. Run `wire dial {peer}` first, \
                 then re-run send."
            );
        }
        eprintln!(
            "wire send: `{peer}` not pinned yet — auto-pairing via local-sister `{sister_name}` first. \
             Pass --no-auto-pair to refuse implicit dialing."
        );
        super::cmd_add_local_sister(&sister_name, true).map_err(|e| {
            anyhow!("wire send: auto-pair to local sister `{sister_name}` failed: {e:#}")
        })?;
    }

    let peer = peer.as_str();
    let sk_seed = config::read_private_key()?;
    let card = config::read_agent_card()?;
    let did = card.get("did").and_then(Value::as_str).unwrap_or("");
    let handle = crate::agent_card::display_handle_from_did(did).to_string();
    let pk_b64 = card
        .get("verify_keys")
        .and_then(Value::as_object)
        .and_then(|m| m.values().next())
        .and_then(|v| v.get("key"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("agent-card missing verify_keys[*].key"))?;
    let pk_bytes = crate::signing::b64decode(pk_b64)?;

    // Body: literal string, `@/path/to/body.json`, or `-` for stdin.
    // P0.S (0.5.11): stdin support lets shells pipe in long content
    // without quoting/escaping ceremony, and supports heredocs naturally:
    //   wire send peer - <<EOF ... EOF
    let body_value: Value = if body_arg == "-" {
        use std::io::Read;
        let mut raw = String::new();
        std::io::stdin()
            .read_to_string(&mut raw)
            .with_context(|| "reading body from stdin")?;
        // Try parsing as JSON first; fall back to string literal for
        // plain-text bodies.
        serde_json::from_str(raw.trim_end()).unwrap_or(Value::String(raw))
    } else if let Some(path) = body_arg.strip_prefix('@') {
        let raw =
            std::fs::read_to_string(path).with_context(|| format!("reading body file {path:?}"))?;
        serde_json::from_str(&raw).unwrap_or(Value::String(raw))
    } else {
        Value::String(body_arg.to_string())
    };

    let kind_id = super::parse_kind(kind)?;

    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string());

    // v0.14.2 (#162 fix #4): canonicalize `to:` against the pinned
    // peer's full DID. Bare-handle `to:did:wire:<handle>` misses the
    // long-fingerprint suffix (`did:wire:sunlit-aurora-ec6f890d`) that
    // pinned peers actually publish; mismatch risks receiver rejection
    // at canonical/cursor verification. resolve_peer_did falls back to
    // the bare form for unknown peers (pre-pair queue best-effort).
    let trust_for_did = config::read_trust().unwrap_or_else(|_| json!({"agents": {}}));
    let to_did = crate::trust::resolve_peer_did(&trust_for_did, peer);
    let mut event = json!({
        "schema_version": crate::signing::EVENT_SCHEMA_VERSION,
        "timestamp": now,
        "from": did,
        "to": to_did,
        "type": kind,
        "kind": kind_id,
        "body": body_value,
    });
    if let Some(deadline) = deadline {
        event["time_sensitive_until"] = json!(parse_deadline_until(deadline)?);
    }
    // D1 (RFC-006): encrypt the body when the recipient is dh-capable (has a
    // pinned `dh_pubkey`). seal_event_body binds the event's OWN from/to and
    // runs BEFORE signing so the signature covers the `{ct}` body. Legacy peers
    // (no dh_pubkey) fall through to plaintext.
    if let Some(peer_dh) = crate::enc::wire_x25519::peer_dh_pubkey(&trust_for_did, peer) {
        crate::enc::wire_x25519::seal_event_body(&mut event, &peer_dh, &sk_seed)?;
    }
    let signed = sign_message_v31(&event, &sk_seed, &pk_bytes, &handle)?;
    let event_id = signed["event_id"].as_str().unwrap_or("").to_string();

    // R4: best-effort attentiveness pre-flight. Look up the peer's slot
    // coords in relay-state and ask the relay how recently the peer pulled.
    // Warn on stderr if the peer hasn't pulled in >5min OR has never pulled.
    // Never blocks the send — the sync POST or `--queue` outbox-write
    // happens below regardless.
    maybe_warn_peer_attentiveness(peer);

    // v0.14.2 (paul, 2026-06-01): collapse the legacy 3-step
    // (outbox-write → daemon push → relay) into a single synchronous
    // POST when `--queue` is NOT set. The old path silently dropped
    // events in three distinct classes (daemon-down,
    // wrong-WIRE_HOME, stale-slot); the new path returns the real
    // verdict inline.
    if !queue {
        let outcome = crate::send::attempt_deliver(peer, &signed)?;
        if as_json {
            println!(
                "{}",
                serde_json::to_string(&crate::send::delivery_json(&outcome, peer))?
            );
        } else {
            use crate::send::SyncDelivery;
            match &outcome {
                SyncDelivery::Delivered {
                    event_id,
                    relay_url,
                    slot_id,
                } => println!("delivered {event_id} → {peer} (relay {relay_url} slot {slot_id})"),
                SyncDelivery::Duplicate {
                    event_id,
                    relay_url,
                    slot_id,
                } => println!(
                    "duplicate {event_id} → {peer} (already on relay {relay_url} slot {slot_id} — change the body to send a distinct event)"
                ),
                SyncDelivery::PeerUnknown { event_id } => println!(
                    "FAILED {event_id} → {peer}: peer not pinned. Run `wire dial {peer}` to pair, or `wire send --queue {peer} ...` to write to outbox for the daemon to retry later."
                ),
                SyncDelivery::SlotStale {
                    event_id, detail, ..
                } => println!(
                    "FAILED {event_id} → {peer}: relay says slot is stale ({detail}). Run `wire dial {peer}` to re-pair."
                ),
                SyncDelivery::TransportError {
                    event_id, detail, ..
                } => println!(
                    "FAILED {event_id} → {peer}: transport error ({detail}). Retry, or pass --queue to outbox the event for daemon retry."
                ),
            }
        }
        // Non-zero exit for non-delivered states so scripts can
        // branch. Delivered + Duplicate both count as success (both
        // mean the peer can pull).
        if !outcome.reached_relay() {
            std::process::exit(2);
        }
        return Ok(());
    }

    // Legacy --queue path: append to per-peer outbox JSONL, daemon
    // push loop drains. Same code shape as pre-v0.14.2.
    //
    // Honesty check: if the peer is BOTH not pinned in trust AND has
    // no pending pair, the daemon has no relay endpoint to push to
    // and never will until the operator pairs. The CLI shouldn't
    // silently accept this — coral dogfood today (2026-06-01) found
    // a year-old `no-such-peer.jsonl` outbox file from a typo'd send,
    // still on disk because the daemon has nowhere to send it. Emit
    // a one-line stderr warning so the operator knows what's going
    // to happen (the write proceeds — `--queue` is the documented
    // pre-pair best-effort path and we don't want to break the
    // "queue → then dial → then push" workflow).
    let peer_pinned_in_trust = trust_for_did
        .get("agents")
        .and_then(Value::as_object)
        .map(|a| a.contains_key(peer))
        .unwrap_or(false);
    if !peer_pinned_in_trust && !peer_is_pinned {
        // We received an invite drop awaiting accept (explicit peer_handle).
        let pending_inbound = crate::pending_inbound_pair::list_pending_inbound()
            .ok()
            .map(|v| v.iter().any(|p| p.peer_handle == peer))
            .unwrap_or(false);
        if !pending_inbound {
            eprintln!(
                "wire send: WARN — `{peer}` is not pinned and has no pending pair. \
                 The event will sit in outbox forever unless you pair first \
                 (`wire dial {peer}` or accept an inbound invite)."
            );
        }
    }
    let line = serde_json::to_vec(&signed)?;
    let outbox = config::append_outbox_record(peer, &line)?;
    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "event_id": event_id,
                "status": "queued",
                "peer": peer,
                "outbox": outbox.to_string_lossy(),
            }))?
        );
    } else {
        println!(
            "queued event {event_id} → {peer} (outbox: {}; daemon will push)",
            outbox.display()
        );
    }
    Ok(())
}

/// `wire send-project <project> <body>` — RFC-001 §6 client-side project
/// fan-out. Sends one signed event to every pinned peer that is (a) at
/// effective tier **>= ORG_VERIFIED** and (b) tagged with `project == <project>`
/// on its pinned card. The relay sees N individual pushes, never a broadcast
/// primitive ("every event is to one slot"); `project` is unsigned routing
/// metadata, the tier floor is the trust gate.
///
/// Each recipient is delivered synchronously (the same `send::attempt_deliver`
/// path `wire send` uses), so the summary carries a real per-peer verdict.
/// Zero matching recipients is a no-op success, not an error.
#[allow(clippy::too_many_arguments)]
pub(super) fn cmd_send_project(
    project: &str,
    kind: &str,
    body_arg: &str,
    deadline: Option<&str>,
    as_json: bool,
) -> Result<()> {
    if !config::is_initialized()? {
        bail!("not initialized — run `wire up` first");
    }
    let sk_seed = config::read_private_key()?;
    let card = config::read_agent_card()?;
    let did = card.get("did").and_then(Value::as_str).unwrap_or("");
    let handle = crate::agent_card::display_handle_from_did(did).to_string();
    let pk_b64 = card
        .get("verify_keys")
        .and_then(Value::as_object)
        .and_then(|m| m.values().next())
        .and_then(|v| v.get("key"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("agent-card missing verify_keys[*].key"))?;
    let pk_bytes = crate::signing::b64decode(pk_b64)?;

    let trust = config::read_trust().unwrap_or_else(|_| json!({"agents": {}}));
    let relay_state = config::read_relay_state().unwrap_or_else(|_| json!({"peers": {}}));
    let recipients = crate::trust::project_recipients(&trust, &relay_state, &handle, project);

    if recipients.is_empty() {
        if as_json {
            println!(
                "{}",
                serde_json::to_string(&json!({
                    "project": project,
                    "recipients": [],
                    "delivered": 0,
                    "note": "no peers at ORG_VERIFIED+ tagged with this project",
                }))?
            );
        } else {
            println!(
                "no fan-out recipients: no pinned peer is at ORG_VERIFIED+ AND tagged \
                 project={project}. Check `wire peers` (tier) and that org-mates publish \
                 the same project tag on their card."
            );
        }
        return Ok(());
    }

    // Body parsed ONCE (shared across all recipients): literal, `@file`, or `-` stdin.
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
    let deadline_until = match deadline {
        Some(d) => Some(parse_deadline_until(d)?),
        None => None,
    };

    let mut results: Vec<Value> = Vec::new();
    let mut delivered = 0usize;
    for peer in &recipients {
        let now = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string());
        let to_did = crate::trust::resolve_peer_did(&trust, peer);
        let mut event = json!({
            "schema_version": crate::signing::EVENT_SCHEMA_VERSION,
            "timestamp": now,
            "from": did,
            "to": to_did,
            "type": kind,
            "kind": kind_id,
            "body": body_value.clone(),
        });
        if let Some(until) = &deadline_until {
            event["time_sensitive_until"] = json!(until);
        }
        // Same D1 (RFC-006) seal-before-sign path as single-peer send.
        if let Some(peer_dh) = crate::enc::wire_x25519::peer_dh_pubkey(&trust, peer) {
            crate::enc::wire_x25519::seal_event_body(&mut event, &peer_dh, &sk_seed)?;
        }
        let signed = sign_message_v31(&event, &sk_seed, &pk_bytes, &handle)?;
        let outcome = crate::send::attempt_deliver(peer, &signed)?;
        if outcome.reached_relay() {
            delivered += 1;
        }
        if !as_json {
            use crate::send::SyncDelivery;
            match &outcome {
                SyncDelivery::Delivered { event_id, .. } => {
                    println!("  delivered {event_id} → {peer}")
                }
                SyncDelivery::Duplicate { event_id, .. } => {
                    println!("  duplicate {event_id} → {peer} (change body for a distinct event)")
                }
                other => println!(
                    "  FAILED → {peer}: {}",
                    crate::send::delivery_json(other, peer)
                        .get("status")
                        .and_then(Value::as_str)
                        .unwrap_or("error")
                ),
            }
        }
        results.push(crate::send::delivery_json(&outcome, peer));
    }

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "project": project,
                "recipients": recipients,
                "delivered": delivered,
                "results": results,
            }))?
        );
    } else {
        println!(
            "fan-out project={project}: {delivered}/{} reached the relay.",
            recipients.len()
        );
    }
    // Partial failure → non-zero exit so scripts can branch, mirroring `wire send`.
    if delivered < recipients.len() {
        std::process::exit(2);
    }
    Ok(())
}

// ---------- here (v0.9.3 you-are-here view) ----------

/// `wire here` — one-screen "you are this session, your neighbors are
/// these." Combines what `wire whoami`, `wire peers`, and `wire session
/// list-local` would otherwise force the operator to call separately.
/// Gather the `wire here` view — self identity, same-machine sister sessions,
/// and pinned peers — as the JSON value `wire here --json` prints AND the
/// `wire_here` MCP tool returns. Pure (read-only). Single source of truth so
/// the CLI and the MCP surface can never drift (the cold-agent "who can I
/// talk to?" answer must match what the operator sees).
pub(crate) fn here_summary() -> Result<Value> {
    let initialized = config::is_initialized().unwrap_or(false);

    // Self identity.
    let (self_did, self_handle, self_character) = if initialized {
        let card = config::read_agent_card().ok();
        let did = card
            .as_ref()
            .and_then(|c| c.get("did").and_then(Value::as_str))
            .unwrap_or("")
            .to_string();
        let handle = if did.is_empty() {
            String::new()
        } else {
            crate::agent_card::display_handle_from_did(&did).to_string()
        };
        let character = if did.is_empty() {
            None
        } else {
            // v0.11: DID-derived only. No display.json overrides.
            Some(crate::character::Character::from_did(&did))
        };
        (did, handle, character)
    } else {
        (String::new(), String::new(), None)
    };

    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let wire_home = std::env::var("WIRE_HOME").unwrap_or_default();

    // Sister sessions (same-machine).
    let mut sisters: Vec<Value> = Vec::new();
    if let Ok(listing) = crate::session::list_local_sessions() {
        for group in listing.local.values() {
            for s in group {
                if s.handle.as_deref() == Some(self_handle.as_str()) {
                    continue; // skip self
                }
                let ch = s.did.as_deref().map(crate::character::Character::from_did);
                sisters.push(json!({
                    "session": s.name,
                    "handle": s.handle,
                    "persona": ch,
                }));
            }
        }
    }

    // Pinned peers (trust ring agents).
    let mut peers: Vec<Value> = Vec::new();
    if initialized
        && let Ok(trust) = config::read_trust()
        && let Some(agents) = trust.get("agents").and_then(Value::as_object)
    {
        // Read relay_state once so the effective-tier lookup
        // doesn't hammer disk per peer. Missing file is fine —
        // effective_tier handles it.
        let relay_state =
            config::read_relay_state().unwrap_or_else(|_| json!({"self": null, "peers": {}}));
        for (handle, agent) in agents {
            if handle == &self_handle {
                continue; // skip self
            }
            let did = agent.get("did").and_then(Value::as_str).unwrap_or("");
            let ch = if did.is_empty() {
                None
            } else {
                Some(crate::character::Character::from_did(did))
            };
            // v0.14.3: use effective tier so `wire here`, `wire
            // peers`, and `wire status` agree on what the daemon
            // can actually do. Raw trust tier alone was lying when
            // a VERIFIED peer's relay credentials were never
            // delivered (slot_token empty, bilateral_completed_at
            // missing). coral dogfood 2026-06-01 saw
            // orchid-savanna as VERIFIED here but PENDING_ACK in
            // the other two — same screen, two answers.
            peers.push(json!({
                "handle": handle,
                "did": did,
                "tier": crate::trust::effective_tier(&trust, &relay_state, handle),
                "persona": ch,
            }));
        }
    }

    Ok(json!({
        "self": {
            "handle": self_handle,
            "did": self_did,
            "persona": self_character,
            "cwd": cwd,
            "wire_home": wire_home,
        },
        "sister_sessions": sisters,
        "pinned_peers": peers,
    }))
}

pub(super) fn cmd_here(as_json: bool) -> Result<()> {
    let summary = here_summary()?;

    if as_json {
        println!("{}", serde_json::to_string(&summary)?);
        return Ok(());
    }

    // Human format.
    let self_handle = summary["self"]["handle"].as_str().unwrap_or("");
    if self_handle.is_empty() {
        println!("not initialized — run `wire up` to bootstrap.");
        return Ok(());
    }
    let self_persona = &summary["self"]["persona"];
    // Reconstruct the Character for self's glyph so output stays identical to
    // the pre-extraction path (emoji_with_fallback over the typed Character).
    let self_character: Option<crate::character::Character> =
        serde_json::from_value(self_persona.clone()).ok();
    let glyph = self_character
        .as_ref()
        .map(crate::character::emoji_with_fallback)
        .unwrap_or_else(|| "?".to_string());
    let nick = self_character
        .as_ref()
        .map(|c| c.nickname.clone())
        .unwrap_or_default();
    println!("you are {glyph} {nick}  ({self_handle})");
    let cwd = summary["self"]["cwd"].as_str().unwrap_or("");
    if !cwd.is_empty() {
        println!("  cwd:    {cwd}");
    }
    // Helper closure that mirrors emoji_with_fallback over a JSON-encoded
    // character object (sisters/peers personas are Value rows). Looks up the
    // canonical emoji-name and falls back to that — never repeats the
    // nickname inside the brackets.
    let render_glyph = |character: &Value| -> String {
        let emoji = character
            .get("emoji")
            .and_then(Value::as_str)
            .unwrap_or("?");
        let nickname = character
            .get("nickname")
            .and_then(Value::as_str)
            .unwrap_or("?");
        if crate::character::terminal_supports_emoji() {
            return emoji.to_string();
        }
        // Synthesize a minimal Character so emoji_with_fallback's
        // lookup table picks the right ASCII tag.
        let synth = crate::character::Character {
            nickname: nickname.to_string(),
            emoji: emoji.to_string(),
            palette: crate::character::Palette {
                primary_hex: String::new(),
                accent_hex: String::new(),
                ansi256_primary: 0,
                ansi256_accent: 0,
            },
        };
        crate::character::emoji_with_fallback(&synth)
    };
    let empty = Vec::new();
    let sisters = summary["sister_sessions"].as_array().unwrap_or(&empty);
    let peers = summary["pinned_peers"].as_array().unwrap_or(&empty);
    if !sisters.is_empty() {
        println!();
        println!("sister sessions on this machine:");
        for s in sisters {
            let session = s["session"].as_str().unwrap_or("?");
            let ch_nick = s["persona"]["nickname"].as_str().unwrap_or("?");
            let glyph = render_glyph(&s["persona"]);
            println!("  {glyph} {ch_nick}  ({session})");
        }
    }
    if !peers.is_empty() {
        println!();
        println!("pinned peers:");
        for p in peers {
            let handle = p["handle"].as_str().unwrap_or("?");
            let tier = p["tier"].as_str().unwrap_or("");
            let ch_nick = p["persona"]["nickname"].as_str().unwrap_or("?");
            let glyph = render_glyph(&p["persona"]);
            println!("  {glyph} {ch_nick}  ({handle})  [{tier}]");
        }
    }
    if sisters.is_empty() && peers.is_empty() {
        println!();
        println!(
            "no neighbors yet — `wire session new` to add a sister, or `wire dial <peer>` to reach out."
        );
    }
    Ok(())
}

// ---------- tail ----------

/// Print recent events from this agent's inbox.
///
/// **Orientation (wire #79):** defaults to NEWEST-N — with `limit > 0`, the
/// last `limit` events across all matched peer jsonl files are returned,
/// sorted chronologically (by `timestamp`, then by per-file append order as
/// tiebreaker) and printed oldest-of-window first / newest last. This matches
/// `tail -n` semantics on log files; previously `wire tail --limit N` returned
/// the OLDEST N which silently hid live-context for any agent harness that
/// re-tailed an established inbox.
///
/// `oldest=true` flips back to FIFO (first-N) for operators who need the
/// original orientation (e.g. replaying an inbox from the start). `limit=0`
/// prints every event in chronological order.
pub(super) fn cmd_tail(
    peer: Option<&str>,
    as_json: bool,
    limit: usize,
    oldest: bool,
) -> Result<()> {
    let inbox = config::inbox_dir()?;
    if !inbox.exists() {
        if !as_json {
            eprintln!("no inbox yet — daemon hasn't run, or no events received");
        }
        return Ok(());
    }
    let trust = config::read_trust()?;

    let entries: Vec<_> = std::fs::read_dir(&inbox)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension().map(|x| x == "jsonl").unwrap_or(false)
                && match peer {
                    Some(want) => p.file_stem().and_then(|s| s.to_str()) == Some(want),
                    None => true,
                }
        })
        .collect();

    // Collect every parseable event across all matched peer files. Each entry
    // carries a sort key `(timestamp, line_idx)` so multi-peer interleaving
    // sorts deterministically by event time, with append-order as the
    // tiebreaker for events that share a timestamp (or for events with no
    // timestamp string at all).
    let mut events: Vec<(String, usize, Value)> = Vec::new();
    for path in &entries {
        let body = std::fs::read_to_string(path)?;
        for (idx, line) in body.lines().enumerate() {
            let event: Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let ts = event
                .get("timestamp")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            events.push((ts, idx, event));
        }
    }
    events.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

    // Pick the window. limit=0 → all events; oldest → first N; default → last N.
    let total = events.len();
    let window: &[(String, usize, Value)] = if limit == 0 {
        &events[..]
    } else if oldest {
        &events[..limit.min(total)]
    } else {
        let start = total.saturating_sub(limit);
        &events[start..]
    };

    // Don't dead-end silently on the receive half of hello-world: an empty
    // window today printed nothing (exit 0), leaving "is it me, the peer, or
    // the daemon?" undiagnosed. Name what's tail-able and how fresh sync is.
    // stderr only — never pollutes --json or a piped event capture.
    if !as_json && window.is_empty() {
        let channels: Vec<String> = std::fs::read_dir(&inbox)?
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let p = e.path();
                (p.extension().map(|x| x == "jsonl").unwrap_or(false))
                    .then(|| p.file_stem().and_then(|s| s.to_str()).map(str::to_string))
                    .flatten()
            })
            .collect();
        let synced = match crate::ensure_up::last_sync_age_seconds() {
            Some(age) => format!("daemon last synced {age}s ago"),
            None => "daemon has not recorded a sync here yet".to_string(),
        };
        match peer {
            Some(want) if !channels.iter().any(|c| c == want) => {
                eprintln!("no inbox channel for '{want}'. {synced}.");
                if channels.is_empty() {
                    eprintln!(
                        "  no peers have messaged you yet — `wire dial <name> \"hi\"` to start a line, or `wire doctor` if you expected traffic."
                    );
                } else {
                    eprintln!("  channels you can tail: {}", channels.join(", "));
                }
            }
            _ => {
                let scope = peer.map(|p| format!(" from '{p}'")).unwrap_or_default();
                eprintln!("0 events{scope} ({total} matched). {synced}.");
                eprintln!("  expected a message? check sync: `wire doctor` / `wire status`.");
            }
        }
        return Ok(());
    }

    // D1: decrypt enc-bearing bodies for display (verify-gated). On-disk JSONL
    // stays verbatim ciphertext; this only shapes the rendered output.
    let seed = crate::enc::wire_x25519::self_seed_for_read();
    for (_, _, event) in window {
        let verified = crate::signing::verify_message_v31(event, &trust).is_ok();
        let ev_dec = match &seed {
            Some(s) => crate::enc::wire_x25519::decrypt_event_for_read(event, &trust, s),
            None => event.clone(),
        };
        let event = &ev_dec;
        if as_json {
            let mut event_with_meta = event.clone();
            if let Some(obj) = event_with_meta.as_object_mut() {
                obj.insert("verified".into(), json!(verified));
            }
            println!("{}", serde_json::to_string(&event_with_meta)?);
        } else {
            let ts = event
                .get("timestamp")
                .and_then(Value::as_str)
                .unwrap_or("?");
            let from = event.get("from").and_then(Value::as_str).unwrap_or("?");
            let kind = event.get("kind").and_then(Value::as_u64).unwrap_or(0);
            let kind_name = event.get("type").and_then(Value::as_str).unwrap_or("?");
            let summary = event
                .get("body")
                .map(|b| match b {
                    Value::String(s) => s.clone(),
                    _ => b.to_string(),
                })
                .unwrap_or_default();
            let mark = if verified { "✓" } else { "✗" };
            let deadline = event
                .get("time_sensitive_until")
                .and_then(Value::as_str)
                .map(|d| format!(" deadline: {d}"))
                .unwrap_or_default();
            println!("[{ts} {from} kind={kind} {kind_name}{deadline}] {summary} | sig {mark}");
        }
    }
    Ok(())
}

// ---------- monitor (live-tail across all peers, harness-friendly) ----------

/// Events filtered out of `wire monitor` by default — pair handshake +
/// liveness pings. Operators almost never want these surfaced; an explicit
/// `--include-handshake` brings them back.
fn monitor_is_noise_kind(kind: &str) -> bool {
    matches!(kind, "pair_drop" | "pair_drop_ack" | "heartbeat")
}

/// Resolve a pinned peer's persona (the DID-derived nickname + emoji,
/// respecting an advertised override on their card). `None` if the peer
/// isn't in trust or can't be resolved — callers fall back to the handle.
fn resolve_persona(peer_handle: &str) -> Option<crate::character::Character> {
    let trust = config::read_trust().ok()?;
    let agent = trust.get("agents").and_then(|a| a.get(peer_handle))?;
    if let Some(card) = agent.get("card") {
        Some(crate::character::Character::from_card(card))
    } else {
        let did = agent.get("did").and_then(Value::as_str)?;
        Some(crate::character::Character::from_did(did))
    }
}

/// "emoji nickname" label for a peer, falling back to the raw handle.
pub(super) fn persona_label(peer_handle: &str) -> String {
    match resolve_persona(peer_handle) {
        Some(ch) => format!("{} {}", ch.emoji, ch.nickname),
        None => peer_handle.to_string(),
    }
}

/// Render a single InboxEvent for `wire monitor` output. JSON form emits the
/// full structured event for tooling consumption; the plain form is a tight
/// one-line summary suitable as a harness stream-watcher notification.
///
/// Kept PURE (no trust I/O) so it stays deterministic and cheap per event.
/// Persona enrichment for `--json` belongs at InboxEvent construction in
/// `inbox_watch` (a follow-up), not here.
fn monitor_render(e: &crate::inbox_watch::InboxEvent, as_json: bool) -> Result<String> {
    if as_json {
        Ok(serde_json::to_string(e)?)
    } else {
        let eid_short: String = e.event_id.chars().take(12).collect();
        let body = e.body_preview.replace('\n', " ");
        let ts: String = e.timestamp.chars().take(19).collect();
        Ok(format!("[{ts}] {}/{} ({eid_short}) {body}", e.peer, e.kind))
    }
}

/// `wire monitor` — long-running line-per-event stream of new inbox events.
///
/// Built for agent harnesses that have an "every stdout line is a chat
/// notification" stream watcher (Claude Code Monitor tool, etc.). One
/// command, persistent, filtered. Replaces the manual `tail -F inbox/*.jsonl
/// | python parse | grep -v pair_drop` pipeline operators improvise on day
/// one of every wire session.
///
/// Default filter strips `pair_drop`, `pair_drop_ack`, and `heartbeat` —
/// pure handshake / liveness noise that operators almost never want
/// surfaced. Pass `--include-handshake` if you do.
///
/// Cursor: in-memory only. Starts from EOF (so a fresh `wire monitor`
/// doesn't drown the operator in replay), with optional `--replay N` to
/// emit the last N events first.
pub(super) fn cmd_monitor(
    peer_filter: Option<&str>,
    as_json: bool,
    include_handshake: bool,
    interval_ms: u64,
    replay: usize,
) -> Result<()> {
    let inbox_dir = config::inbox_dir()?;
    if !inbox_dir.exists() && !as_json {
        eprintln!("wire monitor: inbox dir {inbox_dir:?} missing — has the daemon ever run?");
    }
    // v0.13.x identity work: monitor owns the inbox cursor across the
    // long-running poll loop; collision with another wire process under
    // the same WIRE_HOME causes "I'm not seeing X's events" debugging
    // rabbit holes. Warn at startup so the operator catches it fast.
    crate::session::warn_on_identity_collision(std::process::id(), "monitor");
    // Still proceed — InboxWatcher::from_dir_head handles missing dir.

    // Optional replay — read existing files and emit the last `replay` events
    // (post-filter) before going live. Useful when the harness restarts and
    // wants recent context.
    if replay > 0 && inbox_dir.exists() {
        let mut all: Vec<crate::inbox_watch::InboxEvent> = Vec::new();
        for entry in std::fs::read_dir(&inbox_dir)?.flatten() {
            let path = entry.path();
            if path.extension().and_then(|x| x.to_str()) != Some("jsonl") {
                continue;
            }
            let peer = match path.file_stem().and_then(|s| s.to_str()) {
                Some(s) => s.to_string(),
                None => continue,
            };
            if let Some(filter) = peer_filter
                && peer != filter
            {
                continue;
            }
            let body = std::fs::read_to_string(&path).unwrap_or_default();
            for line in body.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let signed: Value = match serde_json::from_str(line) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let ev = crate::inbox_watch::InboxEvent::from_signed(
                    &peer, signed, /* verified */ true,
                );
                if !include_handshake && monitor_is_noise_kind(&ev.kind) {
                    continue;
                }
                all.push(ev);
            }
        }
        // Sort by timestamp string (RFC3339-ish — lexicographic order matches
        // chronological for same-zoned timestamps).
        all.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        let start = all.len().saturating_sub(replay);
        for ev in &all[start..] {
            println!("{}", monitor_render(ev, as_json)?);
        }
        use std::io::Write;
        std::io::stdout().flush().ok();
    }

    // Live loop. InboxWatcher::from_head() seeds cursors at current EOF, so
    // the first poll only returns events that arrived AFTER startup.
    let mut w = crate::inbox_watch::InboxWatcher::from_head()?;
    let sleep_dur = std::time::Duration::from_millis(interval_ms.max(50));

    loop {
        // Never die silently. wisp-blossom (Win10) saw `wire monitor` exit 1
        // with ZERO bytes on stdout+stderr when a cursor-block (untrusted
        // signer's pair event) tripped the watcher — a silent death looks
        // identical to "still watching" and breaks the sister-collab model.
        // Surface the reason and KEEP watching instead of propagating a fatal
        // `?` that some callers swallow.
        let events = match w.poll() {
            Ok(evs) => evs,
            Err(e) => {
                eprintln!("wire monitor: poll error (continuing to watch): {e:#}");
                std::thread::sleep(sleep_dur);
                continue;
            }
        };
        let mut wrote = false;
        for ev in events {
            if let Some(filter) = peer_filter
                && ev.peer != filter
            {
                continue;
            }
            if !include_handshake && monitor_is_noise_kind(&ev.kind) {
                continue;
            }
            println!("{}", monitor_render(&ev, as_json)?);
            wrote = true;
        }
        if wrote {
            use std::io::Write;
            std::io::stdout().flush().ok();
        }
        std::thread::sleep(sleep_dur);
    }
}

#[cfg(test)]
mod monitor_tests {
    use super::*;
    use crate::inbox_watch::InboxEvent;
    use serde_json::Value;

    fn ev(peer: &str, kind: &str, body: &str) -> InboxEvent {
        InboxEvent {
            peer: peer.to_string(),
            event_id: "abcd1234567890ef".to_string(),
            kind: kind.to_string(),
            body_preview: body.to_string(),
            verified: true,
            timestamp: "2026-05-15T23:14:07.123456Z".to_string(),
            raw: Value::Null,
        }
    }

    #[test]
    fn monitor_filter_drops_handshake_kinds_by_default() {
        // The whole point: pair_drop / pair_drop_ack / heartbeat are
        // protocol noise. If they leak into the operator's chat stream by
        // default, the recipe is useless ("wire monitor talks too much,
        // disabled it"). Burn this rule in.
        assert!(monitor_is_noise_kind("pair_drop"));
        assert!(monitor_is_noise_kind("pair_drop_ack"));
        assert!(monitor_is_noise_kind("heartbeat"));

        // Real-payload kinds — operator wants every one.
        assert!(!monitor_is_noise_kind("claim"));
        assert!(!monitor_is_noise_kind("decision"));
        assert!(!monitor_is_noise_kind("ack"));
        assert!(!monitor_is_noise_kind("request"));
        assert!(!monitor_is_noise_kind("note"));
        // Unknown future kinds shouldn't be filtered as noise either —
        // operator probably wants to see something they don't recognise,
        // not have it silently dropped (the P0.1 lesson at the UX layer).
        assert!(!monitor_is_noise_kind("future_kind_we_dont_know"));
    }

    #[test]
    fn monitor_render_plain_is_one_short_line() {
        let e = ev("willard", "claim", "real v8 train shipped 1350 steps");
        let line = monitor_render(&e, false).unwrap();
        // Must be single-line.
        assert!(!line.contains('\n'), "render must be one line: {line}");
        // Must include peer, kind, body fragment, short event_id.
        assert!(line.contains("willard"));
        assert!(line.contains("claim"));
        assert!(line.contains("real v8 train"));
        // Short event id (first 12 chars).
        assert!(line.contains("abcd12345678"));
        assert!(
            !line.contains("abcd1234567890ef"),
            "should truncate full id"
        );
        // RFC3339-ish second precision.
        assert!(line.contains("2026-05-15T23:14:07"));
    }

    #[test]
    fn monitor_render_strips_newlines_from_body() {
        // Multi-line bodies (markdown lists, code, etc.) must collapse to
        // one line — otherwise a single message produces multiple
        // notifications in the harness, ruining the "one event = one line"
        // contract the Monitor tool relies on.
        let e = ev("spark", "claim", "line one\nline two\nline three");
        let line = monitor_render(&e, false).unwrap();
        assert!(!line.contains('\n'), "newlines must be stripped: {line}");
        assert!(line.contains("line one line two line three"));
    }

    #[test]
    fn monitor_render_json_is_valid_jsonl() {
        let e = ev("spark", "claim", "hi");
        let line = monitor_render(&e, true).unwrap();
        assert!(!line.contains('\n'));
        let parsed: Value = serde_json::from_str(&line).expect("valid JSONL");
        assert_eq!(parsed["peer"], "spark");
        assert_eq!(parsed["kind"], "claim");
        assert_eq!(parsed["body_preview"], "hi");
    }

    #[test]
    fn monitor_does_not_drop_on_verified_null() {
        // Spark's bug confession on 2026-05-15: their monitor pipeline ran
        // `select(.verified == true)` against inbox JSONL. Daemon writes
        // events with verified=null (verification happens at tail-time, not
        // write-time), so the filter silently rejected everything — same
        // anti-pattern as P0.1 at the JSON-jq level. Cost: 4 of my events
        // never surfaced for ~30min.
        //
        // wire monitor's render path must NOT consult `.verified` for any
        // filter decision. Lock that in here so a future "be conservative,
        // only emit verified" patch can't quietly land.
        let mut e = ev("spark", "claim", "from disk with verified=null");
        e.verified = false; // worst case — even if disk says unverified, emit
        let line = monitor_render(&e, false).unwrap();
        assert!(line.contains("from disk with verified=null"));
        // Noise filter operates purely on kind, never on verified.
        assert!(!monitor_is_noise_kind("claim"));
    }
}

// ---------- verify ----------

pub(super) fn cmd_verify(path: &str, as_json: bool) -> Result<()> {
    let body = if path == "-" {
        let mut buf = String::new();
        use std::io::Read;
        std::io::stdin().read_to_string(&mut buf)?;
        buf
    } else {
        std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?
    };
    let event: Value = serde_json::from_str(&body)?;
    let trust = config::read_trust()?;
    match crate::signing::verify_message_v31(&event, &trust) {
        Ok(()) => {
            if as_json {
                println!("{}", serde_json::to_string(&json!({"verified": true}))?);
            } else {
                println!("verified ✓");
            }
            Ok(())
        }
        Err(e) => {
            let reason = e.to_string();
            if as_json {
                println!(
                    "{}",
                    serde_json::to_string(&json!({"verified": false, "reason": reason}))?
                );
            } else {
                eprintln!("FAILED: {reason}");
            }
            std::process::exit(1);
        }
    }
}

// ---------- notify (Goal 2) ----------

pub(super) fn cmd_notify(
    interval_secs: u64,
    peer_filter: Option<&str>,
    once: bool,
    as_json: bool,
) -> Result<()> {
    use crate::inbox_watch::InboxWatcher;
    let cursor_path = config::state_dir()?.join("notify.cursor");
    let mut watcher = InboxWatcher::from_cursor_file(&cursor_path)?;
    // v0.13.x identity work: a long-running notify loop racing another
    // wire process on the same inbox cursor silently drops toasts.
    // Skipped under `--once` (single sweep, no cursor ownership).
    if !once {
        crate::session::warn_on_identity_collision(std::process::id(), "notify");
    }

    let sweep = |watcher: &mut InboxWatcher| -> Result<()> {
        let events = watcher.poll()?;
        for ev in events {
            if let Some(p) = peer_filter
                && ev.peer != p
            {
                continue;
            }
            if as_json {
                println!("{}", serde_json::to_string(&ev)?);
            } else {
                os_notify_inbox_event(&ev);
            }
        }
        watcher.save_cursors(&cursor_path)?;
        Ok(())
    };

    if once {
        return sweep(&mut watcher);
    }

    let interval = std::time::Duration::from_secs(interval_secs.max(1));
    loop {
        if let Err(e) = sweep(&mut watcher) {
            eprintln!("wire notify: sweep error: {e}");
        }
        std::thread::sleep(interval);
    }
}

/// Poll the inbox for new verified events past `cursor_path` and advance the
/// persisted cursor. Pure mechanism — the caller decides what to do with the
/// returned events.
///
/// The daemon calls this every sync cycle and toasts the result (see
/// [`toast_inbox_events`]), folding `wire notify` into the always-on loop so
/// the default `wire up` path delivers inbound-message OS toasts. Previously
/// nothing ever started a notify sweep — `ensure_notify_running` had zero
/// callers — so an armed daemon toasted pair events but inbound *messages*
/// arrived silently. Shares `notify.cursor` with `wire notify`; running both
/// at once is the documented identity-collision case (each warns).
pub(super) fn notify_sweep_new_events(
    watcher: &mut crate::inbox_watch::InboxWatcher,
    cursor_path: &std::path::Path,
) -> Result<Vec<crate::inbox_watch::InboxEvent>> {
    let events = watcher.poll()?;
    watcher.save_cursors(cursor_path)?;
    Ok(events)
}

/// Toast a batch of inbox events (daemon-side). Thin wrapper so the daemon
/// loop body stays readable and the dedup/quiet machinery in
/// [`os_notify_inbox_event`] is reused verbatim.
pub(super) fn toast_inbox_events(events: &[crate::inbox_watch::InboxEvent]) {
    for ev in events {
        os_notify_inbox_event(ev);
    }
}

fn os_notify_inbox_event(ev: &crate::inbox_watch::InboxEvent) {
    let who = persona_label(&ev.peer);
    let title = if ev.verified {
        format!("wire ← {who}")
    } else {
        format!("wire ← {who} (UNVERIFIED)")
    };
    let body = format!("{}: {}", ev.kind, ev.body_preview);
    // Issue #81: dedup by (peer, event_id) so that overlapping monitor
    // sweeps / restarts with a torn cursor don't fire the same toast over
    // and over. `event_id` may be empty for pre-v0.5 legacy events; fall
    // back to the body preview in that case so the key still varies per
    // event rather than collapsing every keyless event into one entry.
    let id = if ev.event_id.is_empty() {
        ev.body_preview.as_str()
    } else {
        ev.event_id.as_str()
    };
    let dedup_key = format!("inbox:{}:{}", ev.peer, id);
    crate::os_notify::toast_dedup(&dedup_key, &title, &body);
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn os_toast(title: &str, body: &str) {
    eprintln!("[wire notify] {title}\n  {body}");
}

#[cfg(test)]
mod notify_sweep_tests {
    use super::*;
    use crate::inbox_watch::InboxWatcher;
    use std::io::Write;

    fn tmp_base(tag: &str) -> std::path::PathBuf {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        std::env::temp_dir().join(format!("wire-{tag}-{}-{n}", std::process::id()))
    }

    fn append_event(inbox: &std::path::Path, peer: &str, body: &str) {
        std::fs::create_dir_all(inbox).unwrap();
        let p = inbox.join(format!("{peer}.jsonl"));
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&p)
            .unwrap();
        let e = serde_json::json!({
            "event_id": format!("evt-{body}"),
            "from": format!("did:wire:{peer}"),
            "to": "did:wire:self",
            "type": "decision",
            "kind": 1,
            "timestamp": "2026-06-11T00:00:00Z",
            "body": body,
            "sig": "x",
        });
        writeln!(f, "{}", serde_json::to_string(&e).unwrap()).unwrap();
    }

    // The daemon's folded-in notify sweep must report each new inbox event
    // exactly once and persist the cursor — otherwise it either misses
    // inbound toasts (the original bug: nothing ever swept) or re-fires the
    // same toast every sync cycle (a torn/non-advancing cursor).
    #[test]
    fn notify_sweep_reports_new_events_once_and_persists_cursor() {
        let base = tmp_base("notifysweep");
        let inbox = base.join("inbox");
        let cursor = base.join("notify.cursor");

        append_event(&inbox, "paul", "first");
        let mut w = InboxWatcher::from_dir_and_cursor(inbox.clone(), &cursor).unwrap();
        let got = notify_sweep_new_events(&mut w, &cursor).unwrap();
        assert_eq!(got.len(), 1, "first sweep sees the one new event");
        assert!(got[0].body_preview.contains("first"));

        // Cursor was persisted: a brand-new watcher from the same cursor
        // file sees nothing — the event does NOT re-toast next cycle.
        let mut w2 = InboxWatcher::from_dir_and_cursor(inbox.clone(), &cursor).unwrap();
        assert!(
            notify_sweep_new_events(&mut w2, &cursor)
                .unwrap()
                .is_empty(),
            "persisted cursor prevents re-firing the same event"
        );

        // A later event past the cursor is picked up.
        append_event(&inbox, "paul", "second");
        let mut w3 = InboxWatcher::from_dir_and_cursor(inbox, &cursor).unwrap();
        let third = notify_sweep_new_events(&mut w3, &cursor).unwrap();
        assert_eq!(third.len(), 1);
        assert!(third[0].body_preview.contains("second"));

        let _ = std::fs::remove_dir_all(&base);
    }
}
