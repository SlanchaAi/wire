use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};

use crate::{
    config,
    signing::{sign_message_v31, verify_message_v31},
};

/// This agent's (did, handle) from its signed card.
/// This agent's signing identity for group ops: (did, handle, key_id, pk_b64).
fn group_self() -> Result<(String, String, String, String)> {
    let card = config::read_agent_card()?;
    let did = card
        .get("did")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("agent-card missing did — run `wire up` first"))?
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
    let key_id = crate::signing::make_key_id(&handle, &pk_bytes);
    Ok((did, handle, key_id, pk_b64))
}

/// Relay to host a group room on — prefer the federation endpoint (remote
/// members can reach it), fall back to LAN, then local, then any.
fn group_room_relay_url() -> Result<String> {
    use crate::endpoints::EndpointScope;
    let state = config::read_relay_state()?;
    let eps = crate::endpoints::self_endpoints(&state);
    let pick = eps
        .iter()
        .find(|e| e.scope == EndpointScope::Federation)
        .or_else(|| eps.iter().find(|e| e.scope == EndpointScope::Lan))
        .or_else(|| eps.iter().find(|e| e.scope == EndpointScope::Local))
        .or_else(|| eps.first());
    match pick {
        Some(e) if !e.relay_url.is_empty() => Ok(e.relay_url.clone()),
        _ => bail!("no relay endpoint on this identity — run `wire up --relay <url>` first"),
    }
}

/// Sign a `group_invite` (carrying the full creator-signed Group) and queue it
/// to every other member's outbox. The daemon/push delivers; the recipient's
/// `ingest_group_invites` materializes the room + introduce-pins members.
fn distribute_group_invite(group: &crate::group::Group, self_did: &str) -> Result<usize> {
    let (_, self_handle, _, pk_b64) = group_self()?;
    let sk_seed = config::read_private_key()?;
    let pk_bytes = crate::signing::b64decode(&pk_b64)?;
    let now_iso = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string());
    let group_json = serde_json::to_value(group)?;
    let mut delivered = 0usize;
    for handle in group.other_member_handles(self_did) {
        let event = json!({
            "schema_version": crate::signing::EVENT_SCHEMA_VERSION,
            "timestamp": now_iso,
            "from": self_did,
            "to": format!("did:wire:{handle}"),
            "type": "group_invite",
            "kind": super::parse_kind("group_invite")?,
            "body": group_json,
        });
        let signed = sign_message_v31(&event, &sk_seed, &pk_bytes, &self_handle)
            .map_err(|e| anyhow!("signing group_invite for `{handle}`: {e:?}"))?;
        let line = serde_json::to_vec(&signed)?;
        if config::append_outbox_record(&handle, &line).is_ok() {
            delivered += 1;
        }
    }
    Ok(delivered)
}

/// Introduce-pin a member's key on the creator's vouch: ensure
/// `trust.agents[handle]` carries this key so the member's group messages
/// verify, WITHOUT granting bilateral trust. Never lowers an existing tier
/// (a directly-VERIFIED peer stays VERIFIED); only adds the key if missing.
/// Returns `true` iff it actually changed `trust` (new entry or added key) —
/// callers use this to decide whether to persist.
fn introduce_pin(
    trust: &mut Value,
    handle: &str,
    did: &str,
    key_id: &str,
    key: &str,
    group_id: &str,
) -> bool {
    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    // Tolerate a corrupt trust.json whose root is valid JSON but not an
    // object (`[]`, `"x"`) — coerce instead of panicking mid-`group tail`.
    if !trust.is_object() {
        *trust = json!({});
    }
    let agents = trust
        .as_object_mut()
        .expect("trust root coerced to object above")
        .entry("agents")
        .or_insert_with(|| json!({}));
    let key_rec = json!({"key_id": key_id, "key": key, "added_at": now, "active": true});
    match agents.get_mut(handle) {
        Some(existing) => {
            // Already pinned (maybe at a higher bilateral tier) — just ensure
            // the key is present. Do NOT touch the tier.
            let keys = existing
                .as_object_mut()
                .and_then(|o| o.get_mut("public_keys"))
                .and_then(Value::as_array_mut);
            if let Some(keys) = keys {
                let have = keys
                    .iter()
                    .any(|k| k.get("key_id").and_then(Value::as_str) == Some(key_id));
                if !have {
                    keys.push(key_rec);
                    return true;
                }
            }
            false
        }
        None => {
            // First sight — pin at bilateral UNTRUSTED (disjoint from GroupTier).
            agents[handle] = json!({
                "tier": "UNTRUSTED",
                "did": did,
                "public_keys": [key_rec],
                "introduced_via": group_id,
                "pinned_at": now,
            });
            true
        }
    }
}

/// Scan the inbox for `group_invite` events from pinned creators, verify them
/// (event signature + roster `creator_sig`), materialize/refresh the local
/// group at its highest epoch, and introduce-pin every other member. Lazy:
/// runs at the top of group send/tail/list so a member just-pulled an invite
/// is immediately usable. Skips groups this agent created.
fn ingest_group_invites() -> Result<()> {
    let inbox = config::inbox_dir()?;
    if !inbox.exists() {
        return Ok(());
    }
    let (self_did, ..) = group_self()?;
    let trust_now = config::read_trust().unwrap_or_else(|_| json!({"agents": {}}));
    // group_id -> highest-epoch verified roster seen in the inbox.
    let mut best: std::collections::HashMap<String, crate::group::Group> =
        std::collections::HashMap::new();

    for entry in std::fs::read_dir(&inbox)?.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
            continue;
        }
        for line in std::fs::read_to_string(&path).unwrap_or_default().lines() {
            let event: Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if event.get("type").and_then(Value::as_str) != Some("group_invite") {
                continue;
            }
            // Event-level: the invite must be from a pinned peer (the creator)
            // with a valid signature.
            if verify_message_v31(&event, &trust_now).is_err() {
                continue;
            }
            let Some(body) = event.get("body") else {
                continue;
            };
            let group: crate::group::Group = match serde_json::from_value(body.clone()) {
                Ok(g) => g,
                Err(_) => continue,
            };
            if group.creator_did == self_did {
                continue; // never overwrite a group I created
            }
            // The invite's sender must be the group's creator.
            let from_did = event.get("from").and_then(Value::as_str).unwrap_or("");
            if from_did != group.creator_did {
                continue;
            }
            // Roster integrity: creator_sig must verify against the creator's
            // independently-pinned key (we paired with the creator → have it).
            let creator_handle = crate::agent_card::display_handle_from_did(&group.creator_did);
            let creator_key = trust_now
                .get("agents")
                .and_then(|a| a.get(creator_handle))
                .and_then(|a| a.get("public_keys"))
                .and_then(Value::as_array)
                .and_then(|ks| ks.first())
                .and_then(|k| k.get("key"))
                .and_then(Value::as_str)
                .and_then(|b| crate::signing::b64decode(b).ok());
            let Some(creator_key) = creator_key else {
                continue;
            };
            if !group.verify(&creator_key) {
                continue;
            }
            match best.get(&group.id) {
                Some(prev) if prev.epoch >= group.epoch => {}
                _ => {
                    best.insert(group.id.clone(), group);
                }
            }
        }
    }

    if best.is_empty() {
        return Ok(());
    }
    let mut trust = config::read_trust()?;
    for group in best.values() {
        // Don't regress a locally-known group to a stale epoch.
        if let Ok(local) = crate::group::load_group(&group.id)
            && local.epoch >= group.epoch
        {
            continue;
        }
        crate::group::save_group(group)?;
        for m in &group.members {
            if m.did == self_did || m.key.is_empty() {
                continue;
            }
            introduce_pin(&mut trust, &m.handle, &m.did, &m.key_id, &m.key, &group.id);
        }
    }
    config::write_trust(&trust)?;
    Ok(())
}

pub(crate) fn cmd_group_create(name: &str, as_json: bool) -> Result<()> {
    if !config::is_initialized()? {
        bail!("not initialized — run `wire up` first");
    }
    let (did, handle, key_id, pk_b64) = group_self()?;
    let relay_url = group_room_relay_url()?;
    // Allocate the shared group-room slot on the relay.
    let client = crate::relay_client::RelayClient::new(&relay_url);
    let room = client
        .allocate_slot(Some(&format!("group:{name}")))
        .with_context(|| format!("allocating group room on {relay_url}"))?;
    let id = format!("g{:016x}", rand::random::<u64>());
    let mut group = crate::group::Group::new(id.clone(), name.to_string(), handle, did.clone());
    group.set_room(relay_url, room.slot_id, room.slot_token);
    group.set_member_keys(&did, key_id, pk_b64)?;
    let sk = config::read_private_key()?;
    group.sign(&sk)?;
    crate::group::save_group(&group)?;
    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "id": id, "name": name, "members": 1, "relay_url": group.relay_url
            }))?
        );
    } else {
        println!(
            "created group `{name}` (id {id}) — room on {}. You are the creator.",
            group.relay_url
        );
        println!("  add peers: `wire group add {id} <peer>`   talk: `wire group send {id} \"hi\"`");
    }
    Ok(())
}

pub(crate) fn cmd_group_add(group_ref: &str, peer: &str, as_json: bool) -> Result<()> {
    let (self_did, ..) = group_self()?;
    let mut group = crate::group::resolve_group(group_ref)?;
    if group.creator_did != self_did {
        bail!("only the group creator can add members (the creator signs the roster)");
    }
    // T22 consent: a Member must be a peer you bilaterally VERIFIED.
    let bare = crate::agent_card::bare_handle(peer).to_string();
    let trust = config::read_trust()?;
    let agent = trust
        .get("agents")
        .and_then(|a| a.get(&bare))
        .ok_or_else(|| {
            anyhow!("`{bare}` is not a pinned peer — pair first (`wire dial {bare}@<relay>`)")
        })?;
    let tier = agent
        .get("tier")
        .and_then(Value::as_str)
        .unwrap_or("UNTRUSTED");
    if tier != "VERIFIED" {
        bail!(
            "`{bare}` is {tier}, not VERIFIED — only verified peers can be added as Members (T22 consent)"
        );
    }
    let peer_did = agent
        .get("did")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("trust entry for `{bare}` is missing a did"))?
        .to_string();
    // Capture the peer's signing key from trust so the creator can vouch for it
    // in the signed roster (members introduce-pin it to verify this peer).
    let key = agent
        .get("public_keys")
        .and_then(Value::as_array)
        .and_then(|ks| {
            ks.iter()
                .find(|k| k.get("active").and_then(Value::as_bool).unwrap_or(true))
        })
        .ok_or_else(|| anyhow!("no active pinned key for `{bare}` in trust"))?;
    let peer_key_id = key
        .get("key_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let peer_pk = key
        .get("key")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();

    group.add_member(
        bare.clone(),
        peer_did.clone(),
        crate::group::GroupTier::Member,
    )?;
    group.set_member_keys(&peer_did, peer_key_id, peer_pk)?;
    let sk = config::read_private_key()?;
    group.sign(&sk)?;
    crate::group::save_group(&group)?;
    // Distribute the refreshed signed roster (room coords + everyone's keys) to
    // ALL members so each can post + verify the others.
    let delivered = match distribute_group_invite(&group, &self_did) {
        Ok(n) => n,
        Err(e) => {
            // Non-fatal: the member IS added (group saved above); warn so the
            // operator knows no roster invites were queued instead of reading
            // "invites_queued: 0" as a successful no-op.
            eprintln!("wire group add: member added but roster distribution failed: {e:#}");
            0
        }
    };
    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "group": group.id, "added": bare, "epoch": group.epoch,
                "members": group.members.len(), "invites_queued": delivered
            }))?
        );
    } else {
        println!(
            "added `{bare}` to `{}` — now {} member(s), epoch {} ({delivered} invite(s) queued; run `wire push`)",
            group.name,
            group.members.len(),
            group.epoch
        );
    }
    Ok(())
}

pub(crate) fn cmd_group_send(group_ref: &str, message: &str, as_json: bool) -> Result<()> {
    if !config::is_initialized()? {
        bail!("not initialized — run `wire up` first");
    }
    ingest_group_invites()?;
    let (self_did, self_handle, _, pk_b64) = group_self()?;
    let group = crate::group::resolve_group(group_ref)?;
    // Membership for SEND is room-token possession: having the group locally
    // (with its slot_token) is the capability. The signed roster gates who you
    // can VERIFY, not whether you may post — a code-redeemed joiner isn't in the
    // creator-signed roster but legitimately holds the room key.
    if group.slot_id.is_empty() || group.relay_url.is_empty() {
        bail!(
            "group `{}` has no room slot (legacy/partial group)",
            group.name
        );
    }
    let sk_seed = config::read_private_key()?;
    let pk_bytes = crate::signing::b64decode(&pk_b64)?;
    let now_iso = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string());
    let event = json!({
        "schema_version": crate::signing::EVENT_SCHEMA_VERSION,
        "timestamp": now_iso,
        "from": self_did,
        "to": format!("did:wire:group:{}", group.id),
        "type": "group_msg",
        "kind": super::parse_kind("group_msg")?,
        "body": {
            "group_id": group.id,
            "group_name": group.name,
            "epoch": group.epoch,
            "text": message,
        },
    });
    let signed = sign_message_v31(&event, &sk_seed, &pk_bytes, &self_handle)
        .map_err(|e| anyhow!("signing group_msg: {e:?}"))?;
    // Post the one message to the shared group slot.
    let client = crate::relay_client::RelayClient::new(&group.relay_url);
    client
        .post_event(&group.slot_id, &group.slot_token, &signed)
        .with_context(|| {
            format!(
                "posting to group room {} on {}",
                group.slot_id, group.relay_url
            )
        })?;
    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "group": group.id, "epoch": group.epoch, "status": "posted",
                "members": group.members.len()
            }))?
        );
    } else {
        println!(
            "group `{}`: posted to the room ({} member(s))",
            group.name,
            group.members.len()
        );
    }
    Ok(())
}

pub(crate) fn cmd_group_tail(group_ref: &str, limit: usize, as_json: bool) -> Result<()> {
    ingest_group_invites()?;
    let group = crate::group::resolve_group(group_ref)?;
    if group.slot_id.is_empty() || group.relay_url.is_empty() {
        bail!(
            "group `{}` has no room slot (legacy/partial group)",
            group.name
        );
    }
    let mut trust = config::read_trust().unwrap_or_else(|_| json!({"agents": {}}));
    let client = crate::relay_client::RelayClient::new(&group.relay_url);
    // Pull the shared room; cap generously then show the last `limit`.
    let fetch = if limit == 0 {
        1000
    } else {
        (limit * 4).min(1000)
    };
    let events = client
        .list_events(&group.slot_id, &group.slot_token, None, Some(fetch))
        .with_context(|| {
            format!(
                "pulling group room {} on {}",
                group.slot_id, group.relay_url
            )
        })?;

    // Pass 1: introduce-pin anyone who announced a join. A `group_join` carries
    // the joiner's card and must self-consistently sign under it; posting to the
    // room requires the room token, so possession is the authorization (pinned
    // at bilateral UNTRUSTED, group tier Introduced). This lets their later
    // group messages verify even though they're not in the creator-signed roster.
    let mut trust_changed = false;
    for event in &events {
        if event.get("type").and_then(Value::as_str) != Some("group_join") {
            continue;
        }
        if let Some((h, did, kid, key)) = group_join_pin_material(event)
            && introduce_pin(&mut trust, &h, &did, &kid, &key, &group.id)
        {
            trust_changed = true;
        }
    }
    if trust_changed && let Err(e) = config::write_trust(&trust) {
        // Non-fatal: the in-memory trust still verifies this tail; warn so
        // the operator knows the introduced keys didn't persist for next run.
        eprintln!("wire group tail: failed to persist introduced member keys: {e:#}");
    }

    // Pass 2: build the timeline — group messages (verified against the
    // now-augmented trust) interleaved with join notices.
    enum Line {
        Msg {
            from: String,
            text: String,
            verified: bool,
        },
        Join {
            who: String,
        },
    }
    let mut timeline: Vec<(String, Line)> = Vec::new();
    for event in &events {
        let ty = event.get("type").and_then(Value::as_str).unwrap_or("");
        let body = match event.get("body") {
            Some(Value::String(s)) => serde_json::from_str::<Value>(s).ok(),
            Some(v) => Some(v.clone()),
            None => None,
        };
        let Some(body) = body else { continue };
        if body.get("group_id").and_then(Value::as_str) != Some(group.id.as_str()) {
            continue;
        }
        let ts = event
            .get("timestamp")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let from_did = event.get("from").and_then(Value::as_str).unwrap_or("");
        let from_handle = crate::agent_card::display_handle_from_did(from_did).to_string();
        match ty {
            "group_msg" => {
                let text = body
                    .get("text")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let verified = verify_message_v31(event, &trust).is_ok();
                timeline.push((
                    ts,
                    Line::Msg {
                        from: from_handle,
                        text,
                        verified,
                    },
                ));
            }
            "group_join" => timeline.push((ts, Line::Join { who: from_handle })),
            _ => {}
        }
    }
    timeline.sort_by(|a, b| a.0.cmp(&b.0));
    let start = if limit > 0 {
        timeline.len().saturating_sub(limit)
    } else {
        0
    };
    let recent = &timeline[start..];
    if as_json {
        let arr: Vec<Value> = recent
            .iter()
            .map(|(ts, l)| match l {
                Line::Msg {
                    from,
                    text,
                    verified,
                } => {
                    json!({"ts": ts, "type": "msg", "from": from, "text": text, "verified": verified})
                }
                Line::Join { who } => json!({"ts": ts, "type": "join", "from": who}),
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string(
                &json!({"group": group.id, "name": group.name, "messages": arr})
            )?
        );
    } else if recent.is_empty() {
        println!("group `{}`: no messages yet", group.name);
    } else {
        for (ts, l) in recent {
            let short_ts: String = ts.chars().take(19).collect();
            match l {
                Line::Msg {
                    from,
                    text,
                    verified,
                } => {
                    let mark = if *verified { "✓" } else { "✗" };
                    println!(
                        "[{short_ts}] {} {mark}: {text}",
                        super::comms::persona_label(from)
                    );
                }
                Line::Join { who } => {
                    println!("[{short_ts}] {} joined", super::comms::persona_label(who))
                }
            }
        }
    }
    Ok(())
}

/// Validate a `group_join` room event and extract the joiner's pin material:
/// (handle, did, key_id, key_b64). The event MUST self-consistently sign under
/// the key in the card it carries — so a forged join (card A, signed by key B)
/// is rejected. Authorization to be in the room is proven by the post itself
/// (it required the room token).
fn group_join_pin_material(event: &Value) -> Option<(String, String, String, String)> {
    let body = match event.get("body") {
        Some(Value::String(s)) => serde_json::from_str::<Value>(s).ok()?,
        Some(v) => v.clone(),
        None => return None,
    };
    let card = body.get("joiner_card")?;
    // Verify the event signs under the card it carries (one-entry trust).
    let mut tmp = json!({"agents": {}});
    // Empty tmp trust → no incumbent → the #245 collision guard never trips.
    let _ = crate::trust::add_agent_card_pin(&mut tmp, card, Some("UNTRUSTED"));
    if verify_message_v31(event, &tmp).is_err() {
        return None;
    }
    let did = card.get("did").and_then(Value::as_str)?.to_string();
    let handle = card
        .get("handle")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| crate::agent_card::display_handle_from_did(&did).to_string());
    let (kid_full, krec) = card
        .get("verify_keys")
        .and_then(Value::as_object)
        .and_then(|m| m.iter().next())?;
    let key_id = kid_full
        .strip_prefix("ed25519:")
        .unwrap_or(kid_full)
        .to_string();
    let key = krec.get("key").and_then(Value::as_str)?.to_string();
    Some((handle, did, key_id, key))
}

/// `wire group invite <group>` — mint a self-contained join code (the serialized
/// signed group: room coords + roster + member keys). The code IS the room key.
pub(crate) fn cmd_group_invite(group_ref: &str, as_json: bool) -> Result<()> {
    let group = crate::group::resolve_group(group_ref)?;
    if group.slot_id.is_empty() || group.relay_url.is_empty() {
        bail!(
            "group `{}` has no room slot — nothing to invite into",
            group.name
        );
    }
    if group.creator_sig.is_empty() {
        bail!(
            "group `{}` roster is unsigned — add a member or recreate before inviting",
            group.name
        );
    }
    let payload = serde_json::to_vec(&group)?;
    let code = format!("wire-group:{}", crate::signing::b64encode(&payload));
    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({"group": group.id, "name": group.name, "code": code}))?
        );
    } else {
        println!(
            "join code for `{}` — share ONLY with people you want in the room (it IS the room key):\n",
            group.name
        );
        println!("{code}\n");
        println!("they run:  wire group join <code>");
    }
    Ok(())
}

/// `wire group join <code>` — redeem a join code: verify the roster, materialize
/// the room locally, introduce-pin existing members, and announce ourselves to
/// the room so members verify our messages. Lands at group tier Introduced.
pub(crate) fn cmd_group_join(code: &str, as_json: bool) -> Result<()> {
    if !config::is_initialized()? {
        bail!("not initialized — run `wire up` first");
    }
    let raw = code.trim();
    let b64 = raw.strip_prefix("wire-group:").unwrap_or(raw);
    let payload =
        crate::signing::b64decode(b64).map_err(|_| anyhow!("invalid join code (not base64)"))?;
    let group: crate::group::Group = serde_json::from_slice(&payload)
        .map_err(|_| anyhow!("invalid join code (not a group payload)"))?;
    if group.slot_id.is_empty() || group.relay_url.is_empty() {
        bail!("join code carries no room coords");
    }
    // Verify the roster against the creator's key carried IN the roster (TOFU on
    // the code — you obtained it over a trusted channel). Rejects a tampered code.
    let creator_key = group
        .members
        .iter()
        .find(|m| m.did == group.creator_did)
        .map(|m| m.key.clone())
        .filter(|k| !k.is_empty())
        .and_then(|k| crate::signing::b64decode(&k).ok())
        .ok_or_else(|| anyhow!("join code is missing the creator's key"))?;
    if !group.verify(&creator_key) {
        bail!("join code failed its signature check (tampered or corrupt)");
    }
    let (self_did, self_handle, _, _) = group_self()?;
    if group.creator_did == self_did {
        bail!("you created group `{}` — you're already in it", group.name);
    }

    // Materialize locally + introduce-pin existing members so we can verify them.
    crate::group::save_group(&group)?;
    let mut trust = config::read_trust()?;
    for m in &group.members {
        if m.did == self_did || m.key.is_empty() {
            continue;
        }
        introduce_pin(&mut trust, &m.handle, &m.did, &m.key_id, &m.key, &group.id);
    }
    config::write_trust(&trust)?;

    // Announce ourselves to the room (carry our card) so members introduce-pin us.
    let card = config::read_agent_card()?;
    let sk_seed = config::read_private_key()?;
    let pk_b64 = card
        .get("verify_keys")
        .and_then(Value::as_object)
        .and_then(|m| m.values().next())
        .and_then(|v| v.get("key"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("agent-card missing verify_keys[*].key"))?;
    let pk_bytes = crate::signing::b64decode(pk_b64)?;
    let now_iso = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string());
    let event = json!({
        "schema_version": crate::signing::EVENT_SCHEMA_VERSION,
        "timestamp": now_iso,
        "from": self_did,
        "to": format!("did:wire:group:{}", group.id),
        "type": "group_join",
        "kind": super::parse_kind("group_join")?,
        "body": {
            "group_id": group.id,
            "group_name": group.name,
            "epoch": group.epoch,
            "joiner_card": card,
            "text": "joined",
        },
    });
    let signed = sign_message_v31(&event, &sk_seed, &pk_bytes, &self_handle)
        .map_err(|e| anyhow!("signing group_join: {e:?}"))?;
    let client = crate::relay_client::RelayClient::new(&group.relay_url);
    let announced = client
        .post_event(&group.slot_id, &group.slot_token, &signed)
        .is_ok();

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "group": group.id, "name": group.name, "joined": true,
                "members": group.members.len(), "announced": announced
            }))?
        );
    } else {
        println!(
            "joined group `{}` ({} member(s)) at Introduced tier.",
            group.name,
            group.members.len()
        );
        if announced {
            println!("  announced to the room — members will verify your messages.");
        } else {
            println!(
                "  ⚠ couldn't reach the room relay to announce; retry a `wire group send` so members can verify you."
            );
        }
        println!(
            "  read: `wire group tail {}`   talk: `wire group send {} \"hi\"`",
            group.id, group.id
        );
    }
    Ok(())
}

pub(crate) fn cmd_group_list(as_json: bool) -> Result<()> {
    let groups = crate::group::list_groups()?;
    if as_json {
        let arr: Vec<Value> = groups
            .iter()
            .map(|g| {
                json!({
                    "id": g.id,
                    "name": g.name,
                    "epoch": g.epoch,
                    "members": g.members.iter().map(|m| json!({"handle": m.handle, "tier": m.tier.as_str()})).collect::<Vec<_>>(),
                })
            })
            .collect();
        println!("{}", serde_json::to_string(&json!({"groups": arr}))?);
    } else if groups.is_empty() {
        println!("no groups yet — create one with `wire group create <name>`");
    } else {
        for g in &groups {
            println!(
                "{} ({}) — {} member(s), epoch {}",
                g.name,
                g.id,
                g.members.len(),
                g.epoch
            );
            for m in &g.members {
                println!("    {} [{}]", m.handle, m.tier.as_str());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod introduce_pin_tests {
    use super::*;

    #[test]
    fn pins_new_member_at_untrusted() {
        let mut trust = json!({"version": 1, "agents": {}});
        let changed = introduce_pin(&mut trust, "willard", "did:wire:willard", "k1", "PK", "g1");
        assert!(changed);
        let agent = &trust["agents"]["willard"];
        assert_eq!(agent["tier"], "UNTRUSTED");
        assert_eq!(agent["public_keys"][0]["key_id"], "k1");
    }

    #[test]
    fn never_touches_existing_tier() {
        let mut trust = json!({
            "agents": {"willard": {"tier": "VERIFIED", "public_keys": [
                {"key_id": "k1", "key": "PK", "active": true}
            ]}}
        });
        let changed = introduce_pin(&mut trust, "willard", "did:wire:willard", "k1", "PK", "g1");
        assert!(!changed);
        assert_eq!(trust["agents"]["willard"]["tier"], "VERIFIED");
    }

    #[test]
    fn non_object_trust_root_is_coerced_not_a_panic() {
        // Regression: a corrupt trust.json whose root is valid JSON but not an
        // object (`[]`, `"x"`) hit `.expect("trust is an object")` and panicked
        // in `wire group tail` / `wire group join`.
        for mut trust in [json!([]), json!("corrupt"), json!(42), Value::Null] {
            let changed =
                introduce_pin(&mut trust, "willard", "did:wire:willard", "k1", "PK", "g1");
            assert!(changed, "coerced root should accept the pin");
            assert_eq!(trust["agents"]["willard"]["tier"], "UNTRUSTED");
        }
    }
}
