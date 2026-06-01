//! Invite-URL pair flow (v0.4.0). Single-paste, zero-config pairing.
//!
//! Flow:
//!   A: `wire invite` → URL.
//!   A pastes URL into any channel (Discord, SMS, voice-read).
//!   B: `wire accept <URL>` → done. Both pinned.
//!
//! The invite URL is a self-contained bearer credential carrying A's signed
//! agent-card, relay coords, slot_token, and a single-use pair_nonce. B parses
//! it locally (no relay round-trip yet), pins A from the URL contents, then
//! POSTs a signed kind=1100 `pair_drop` event to A's slot using the slot_token
//! the URL granted. A's daemon (run_sync_pull) recognizes pair_drop events
//! that carry a matching pending_invite nonce, verifies the embedded card,
//! pins B, and consumes the nonce. Both sides paired.
//!
//! Trust model: pasting = trusting. Equivalent to Discord invite link, Zoom
//! join URL, Signal group invite. Operator's act of moving the URL between
//! channels IS the authentication ceremony. No SAS digits, no PAKE.
//!
//! The legacy SPAKE2 + SAS flow remains available via `wire pair --require-sas`
//! for operators who want the stronger MITM-resistance model.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::config;

pub const DEFAULT_RELAY: &str = "https://wireup.net";
pub const DEFAULT_TTL_SECS: u64 = 86_400; // 24 hours

/// P0.2 (0.5.11): write a structured rejection record for `wire doctor`
/// to surface later. Best-effort — if we can't even open the file, fall
/// back to stderr so the operator at least sees the failure mode in their
/// shell. Anything is better than silent.
///
/// Lives at `$WIRE_HOME/state/wire/pair-rejected.jsonl`. One JSON line per
/// rejected pair event. Append-only.
pub(crate) fn record_pair_rejection(peer_handle: &str, code: &str, detail: &str) {
    let line = json!({
        "ts": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        "peer": peer_handle,
        "code": code,
        "detail": detail,
    });
    let serialised = match serde_json::to_string(&line) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("wire: could not serialise pair-rejected entry: {e}");
            return;
        }
    };
    let path = match config::state_dir() {
        Ok(d) => d.join("pair-rejected.jsonl"),
        Err(e) => {
            eprintln!("wire: state_dir unresolved, dropping pair-rejected log: {e}");
            return;
        }
    };
    if let Some(parent) = path.parent()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        eprintln!("wire: could not create {parent:?}: {e}");
        return;
    }
    use std::io::Write;
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        Ok(mut f) => {
            if let Err(e) = writeln!(f, "{serialised}") {
                eprintln!("wire: could not append pair-rejected to {path:?}: {e}");
            }
        }
        Err(e) => {
            eprintln!("wire: could not open {path:?}: {e}");
        }
    }
}

/// Decoded contents of an invite URL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvitePayload {
    /// Schema version. Currently 1.
    pub v: u32,
    /// Issuer DID, e.g. `did:wire:paul`.
    pub did: String,
    /// Issuer's signed agent-card (full JSON).
    pub card: Value,
    /// Relay URL hosting the issuer's slot.
    pub relay_url: String,
    /// Issuer's slot id (32 hex chars).
    pub slot_id: String,
    /// Issuer's slot token (bearer auth for POSTing events to that slot).
    pub slot_token: String,
    /// Single-use nonce (32 random bytes hex).
    pub nonce: String,
    /// Unix timestamp after which this invite is invalid.
    pub exp: u64,
}

/// On-disk record for a minted invite, awaiting acceptance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingInvite {
    pub nonce: String,
    pub exp: u64,
    pub uses_remaining: u32,
    /// DIDs of peers who have already paired via this invite (for multi-use).
    pub accepted_by: Vec<String>,
    pub created_at: String,
}

/// Default-on policy: accept signed pair_drops from unknown peers (v0.5
/// zero-paste discovery). Operator can opt out by writing
/// `$WIRE_HOME/config/wire/policy.json` containing `{"accept_unknown_pair_drops": false}`.
fn open_mode_enabled() -> bool {
    let path = match config::config_dir() {
        Ok(p) => p.join("policy.json"),
        Err(_) => return true,
    };
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(_) => return true,
    };
    let v: Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => return true,
    };
    v.get("accept_unknown_pair_drops")
        .and_then(Value::as_bool)
        .unwrap_or(true)
}

pub fn pending_invites_dir() -> Result<PathBuf> {
    Ok(config::state_dir()?.join("pending-invites"))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Hostname-derived default handle for auto-init. Falls back to "wire-user"
/// if hostname is unavailable. Sanitized to ASCII alphanumeric / '-' / '_'.
fn default_handle() -> String {
    let raw = hostname::get()
        .ok()
        .and_then(|s| s.into_string().ok())
        .unwrap_or_else(|| "wire-user".into());
    let sanitized: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    if sanitized.is_empty() {
        "wire-user".into()
    } else {
        sanitized
    }
}

/// Ensure this node has an identity + relay slot. Idempotent.
/// Returns (did, relay_url, slot_id, slot_token).
pub fn ensure_self_with_relay(
    preferred_relay: Option<&str>,
) -> Result<(String, String, String, String)> {
    let relay = preferred_relay.unwrap_or(DEFAULT_RELAY);

    if !config::is_initialized()? {
        let handle = default_handle();
        crate::pair_session::init_self_idempotent(&handle, None, Some(relay))
            .with_context(|| format!("auto-init as did:wire:{handle}"))?;
    }

    let card = config::read_agent_card()?;
    let did = card
        .get("did")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("agent-card missing did"))?
        .to_string();

    let mut relay_state = config::read_relay_state()?;

    // v0.6.6: prefer an existing endpoint over allocating a new one.
    // `--local-only` sessions don't have legacy `self.slot_id` but DO
    // have `self.endpoints[]` with a local slot — those should be
    // honored, not stomped with a fresh federation allocation. Without
    // this guard, `wire pair-accept` on a local-only session would
    // auto-allocate a federation slot at DEFAULT_RELAY (wireup.net)
    // every time, silently turning local-only sessions into dual-slot.
    let existing = crate::endpoints::self_endpoints(&relay_state);
    if !existing.is_empty() {
        let ep = existing
            .iter()
            .find(|e| e.scope == crate::endpoints::EndpointScope::Federation)
            .cloned()
            .unwrap_or_else(|| existing[0].clone());
        return Ok((did, ep.relay_url, ep.slot_id, ep.slot_token));
    }

    let self_state = relay_state.get("self").cloned().unwrap_or(Value::Null);

    if self_state.is_null() || self_state.get("slot_id").and_then(Value::as_str).is_none() {
        let client = crate::relay_client::RelayClient::new(relay);
        client.check_healthz()?;
        let handle = crate::agent_card::display_handle_from_did(&did);
        let alloc = client.allocate_slot(Some(handle))?;
        relay_state["self"] = json!({
            "relay_url": relay,
            "slot_id": alloc.slot_id,
            "slot_token": alloc.slot_token,
        });
        config::write_relay_state(&relay_state)?;
    }

    let self_state = relay_state.get("self").cloned().unwrap_or(Value::Null);
    let relay_url = self_state["relay_url"].as_str().unwrap_or("").to_string();
    let slot_id = self_state["slot_id"].as_str().unwrap_or("").to_string();
    let slot_token = self_state["slot_token"].as_str().unwrap_or("").to_string();
    if relay_url.is_empty() || slot_id.is_empty() || slot_token.is_empty() {
        bail!("self relay state incomplete after auto-allocate");
    }
    Ok((did, relay_url, slot_id, slot_token))
}

/// Mint a fresh invite URL. Auto-inits + auto-allocates relay slot if needed.
pub fn mint_invite(
    ttl_secs: Option<u64>,
    uses: u32,
    preferred_relay: Option<&str>,
) -> Result<String> {
    let (did, relay_url, slot_id, slot_token) = ensure_self_with_relay(preferred_relay)?;

    let card = config::read_agent_card()?;
    let sk_seed = config::read_private_key()?;

    let mut nonce_bytes = [0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = hex::encode(nonce_bytes);

    let ttl = ttl_secs.unwrap_or(DEFAULT_TTL_SECS);
    let exp = now_unix() + ttl;

    let payload = InvitePayload {
        v: 1,
        did: did.clone(),
        card,
        relay_url,
        slot_id,
        slot_token,
        nonce: nonce.clone(),
        exp,
    };
    let payload_bytes = serde_json::to_vec(&payload)?;

    let mut sk_arr = [0u8; 32];
    sk_arr.copy_from_slice(&sk_seed[..32]);
    let sk = SigningKey::from_bytes(&sk_arr);
    let sig = sk.sign(&payload_bytes);

    let token = format!(
        "{}.{}",
        B64URL.encode(&payload_bytes),
        B64URL.encode(sig.to_bytes())
    );
    let url = format!("wire://pair?v=1&inv={token}");

    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    let pending = PendingInvite {
        nonce: nonce.clone(),
        exp,
        uses_remaining: uses.max(1),
        accepted_by: vec![],
        created_at: now,
    };
    let dir = pending_invites_dir()?;
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{nonce}.json"));
    std::fs::write(&path, serde_json::to_vec_pretty(&pending)?)?;

    Ok(url)
}

/// Parse an invite URL and verify the embedded signature against the embedded
/// card's first active verify key.
pub fn parse_invite(url: &str) -> Result<InvitePayload> {
    let rest = url
        .strip_prefix("wire://pair?")
        .ok_or_else(|| anyhow!("not a wire pair invite URL (must start with wire://pair?)"))?;
    let mut inv = None;
    for part in rest.split('&') {
        if let Some(v) = part.strip_prefix("inv=") {
            inv = Some(v);
        }
    }
    let token = inv.ok_or_else(|| anyhow!("invite URL missing `inv=` parameter"))?;
    let (payload_b64, sig_b64) = token
        .split_once('.')
        .ok_or_else(|| anyhow!("invite token missing `.` separator (payload.sig)"))?;
    let payload_bytes = B64URL
        .decode(payload_b64)
        .map_err(|e| anyhow!("invite payload b64 decode failed: {e}"))?;
    let sig_bytes = B64URL
        .decode(sig_b64)
        .map_err(|e| anyhow!("invite sig b64 decode failed: {e}"))?;

    let payload: InvitePayload = serde_json::from_slice(&payload_bytes)
        .map_err(|e| anyhow!("invite payload JSON decode failed: {e}"))?;

    if payload.v != 1 {
        bail!("invite schema version {} not supported", payload.v);
    }
    if now_unix() > payload.exp {
        bail!("invite expired (exp={}, now={})", payload.exp, now_unix());
    }

    // Verify the URL signature against the issuer's card key.
    crate::agent_card::verify_agent_card(&payload.card)
        .map_err(|e| anyhow!("invite issuer's card signature invalid: {e}"))?;

    let pk_b64 = payload
        .card
        .get("verify_keys")
        .and_then(Value::as_object)
        .and_then(|m| m.values().next())
        .and_then(|v| v.get("key"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("issuer card missing verify_keys[*].key"))?;
    let pk_bytes = crate::signing::b64decode(pk_b64)?;
    let mut pk_arr = [0u8; 32];
    if pk_bytes.len() != 32 {
        bail!("issuer pubkey wrong length");
    }
    pk_arr.copy_from_slice(&pk_bytes);
    let vk = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|e| anyhow!("issuer pubkey decode failed: {e}"))?;
    let mut sig_arr = [0u8; 64];
    if sig_bytes.len() != 64 {
        bail!("invite sig wrong length");
    }
    sig_arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify(&payload_bytes, &sig)
        .map_err(|_| anyhow!("invite URL signature did not verify"))?;

    Ok(payload)
}

/// Accept an invite URL. Auto-inits + auto-allocates if needed. Pins issuer
/// from URL contents, then POSTs a signed pair_drop event to issuer's slot.
pub fn accept_invite(url: &str) -> Result<Value> {
    let payload = parse_invite(url)?;

    // Auto-init self on the issuer's relay (or env-default if reachable).
    let (our_did, our_relay, our_slot_id, our_slot_token) =
        ensure_self_with_relay(Some(&payload.relay_url))?;

    if our_did == payload.did {
        bail!("refusing to accept own invite (issuer DID matches self)");
    }

    // Pin issuer in trust + relay-state.
    let mut trust = config::read_trust()?;
    crate::trust::add_agent_card_pin(&mut trust, &payload.card, Some("VERIFIED"));
    config::write_trust(&trust)?;

    let peer_handle = crate::agent_card::display_handle_from_did(&payload.did).to_string();
    let mut relay_state = config::read_relay_state()?;
    relay_state["peers"][&peer_handle] = json!({
        "relay_url": payload.relay_url,
        "slot_id": payload.slot_id,
        "slot_token": payload.slot_token,
    });
    config::write_relay_state(&relay_state)?;

    // Build signed pair_drop event carrying our own card + slot coords +
    // the issuer's pair_nonce. Issuer's daemon will look it up against
    // pending-invites and complete the bilateral pin.
    let our_card = config::read_agent_card()?;
    let sk_seed = config::read_private_key()?;
    let our_handle = crate::agent_card::display_handle_from_did(&our_did).to_string();
    let pk_b64 = our_card
        .get("verify_keys")
        .and_then(Value::as_object)
        .and_then(|m| m.values().next())
        .and_then(|v| v.get("key"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("our agent-card missing verify_keys[*].key"))?;
    let pk_bytes = crate::signing::b64decode(pk_b64)?;

    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    let event = json!({
        "schema_version": crate::signing::EVENT_SCHEMA_VERSION,
        "timestamp": now,
        "from": our_did,
        "to": payload.did,
        "type": "pair_drop",
        "kind": 1100u32,
        "body": {
            "card": our_card,
            "relay_url": our_relay,
            "slot_id": our_slot_id,
            "slot_token": our_slot_token,
            "pair_nonce": payload.nonce,
        },
    });
    let signed = crate::signing::sign_message_v31(&event, &sk_seed, &pk_bytes, &our_handle)?;
    let event_id = signed["event_id"].as_str().unwrap_or("").to_string();

    let client = crate::relay_client::RelayClient::new(&payload.relay_url);
    client
        .post_event(&payload.slot_id, &payload.slot_token, &signed)
        .with_context(|| {
            format!(
                "POST pair_drop to {} slot {}",
                payload.relay_url, payload.slot_id
            )
        })?;

    Ok(json!({
        "paired_with": payload.did,
        "peer_handle": peer_handle,
        "event_id": event_id,
        "status": "drop_sent",
    }))
}

/// Consume a pair_drop event during daemon pull. Returns `Ok(Some(peer_did))`
/// if the event matched a pending invite and the peer was pinned. Returns
/// `Ok(None)` if not a pair_drop or no matching invite. Errors only on real
/// problems (bad sig over event, IO failure).
pub fn maybe_consume_pair_drop(event: &Value) -> Result<Option<String>> {
    let kind = event.get("kind").and_then(Value::as_u64).unwrap_or(0);
    let type_str = event.get("type").and_then(Value::as_str).unwrap_or("");
    if kind != 1100 || type_str != "pair_drop" {
        return Ok(None);
    }
    let body = match event.get("body") {
        Some(b) => b,
        None => return Ok(None),
    };

    // v0.5: accept handle-initiated pair_drops too (no pair_nonce). These
    // come via `wire add <handle>` → POST /v1/handle/intro. Anchored only
    // by the embedded signed card. Gated by config `accept_unknown_pair_drops`
    // (default true). For nonce-bearing drops the existing v0.4 invite-URL
    // path stays in force.
    let nonce_opt = body
        .get("pair_nonce")
        .and_then(Value::as_str)
        .map(str::to_string);
    let mut pending: Option<PendingInvite> = None;
    let mut invite_path: Option<std::path::PathBuf> = None;
    if let Some(nonce) = nonce_opt.as_deref() {
        let dir = pending_invites_dir()?;
        let path = dir.join(format!("{nonce}.json"));
        if path.exists() {
            let p: PendingInvite = serde_json::from_slice(&std::fs::read(&path)?)
                .with_context(|| format!("reading pending invite {path:?}"))?;
            if now_unix() > p.exp {
                // P0.2: warn if cleanup fails — orphaned expired invites in
                // `pending-invites/` will pile up and confuse `wire doctor`.
                if let Err(e) = std::fs::remove_file(&path) {
                    eprintln!("wire: could not delete expired invite {path:?}: {e}");
                }
                return Ok(None);
            }
            pending = Some(p);
            invite_path = Some(path);
        } else if !open_mode_enabled() {
            // Nonce present but unknown locally, and open mode disabled →
            // refuse silently (the event will fall through to the normal
            // verify path which won't trust the sender yet).
            return Ok(None);
        }
    } else if !open_mode_enabled() {
        // No nonce + open mode disabled → ignore. Operator must opt in to
        // be discoverable via zero-paste `wire add`.
        return Ok(None);
    }

    let peer_card = body
        .get("card")
        .cloned()
        .ok_or_else(|| anyhow!("pair_drop body missing card"))?;
    crate::agent_card::verify_agent_card(&peer_card)
        .map_err(|e| anyhow!("pair_drop peer card sig invalid: {e}"))?;

    let peer_did = peer_card
        .get("did")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("peer card missing did"))?
        .to_string();
    let peer_handle = crate::agent_card::display_handle_from_did(&peer_did).to_string();

    // Verify the event signature against the peer's embedded pubkey. We need
    // a transient trust pin to drive the verifier, but for the handle path
    // (no nonce) this is the ONLY trust-write we'd make and we throw it away
    // immediately — see the bilateral-required branch below.
    let mut tmp_trust = config::read_trust()?;
    crate::trust::add_agent_card_pin(&mut tmp_trust, &peer_card, Some("VERIFIED"));
    crate::signing::verify_message_v31(event, &tmp_trust)
        .map_err(|e| anyhow!("pair_drop event sig verify failed: {e}"))?;

    let peer_relay = body.get("relay_url").and_then(Value::as_str).unwrap_or("");
    let peer_slot_id = body.get("slot_id").and_then(Value::as_str).unwrap_or("");
    let peer_slot_token = body.get("slot_token").and_then(Value::as_str).unwrap_or("");
    if peer_relay.is_empty() || peer_slot_id.is_empty() || peer_slot_token.is_empty() {
        bail!("pair_drop body missing relay_url/slot_id/slot_token");
    }

    // v0.5.17: peer may advertise multiple endpoints (federation +
    // optional local). Parse `body.endpoints[]` if present. Falls back
    // to a single federation endpoint from the legacy fields above for
    // v0.5.16-and-earlier senders.
    let peer_endpoints: Vec<crate::endpoints::Endpoint> = body
        .get("endpoints")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|e| {
                    serde_json::from_value::<crate::endpoints::Endpoint>(e.clone()).ok()
                })
                .collect()
        })
        .unwrap_or_else(|| {
            vec![crate::endpoints::Endpoint::federation(
                peer_relay.to_string(),
                peer_slot_id.to_string(),
                peer_slot_token.to_string(),
            )]
        });

    // ---------- v0.5.14 bilateral-required split ----------
    //
    // SPAKE2 invite-URL path (`pair_nonce` present): the operator already
    // gave the sender an invite-URL out-of-band; possession of the nonce IS
    // the consent gesture. Pin trust, write relay_state, send the ack —
    // unchanged from v0.5.13.
    //
    // Handle path (no nonce, zero-paste `wire add`): the sender knows
    // nothing more than the public phonebook entry. Receiver consent has
    // not been gestured. **Do NOT pin trust. Do NOT write our slot_token
    // back. Do NOT advertise relay coords.** Stash the request in pending-
    // inbound and prompt the operator. Bilateral pin completes only when
    // the operator runs `wire add <peer>@<their-relay>` to accept.
    //
    // This closes the v0.5.13 phonebook-scrape spam vector: an attacker
    // can deposit one entry in N victims' `wire pair-list --pending`, but
    // no slot_token leaks and no message-write capability accrues.
    if nonce_opt.is_some() {
        // ----- SPAKE2 invite-URL path (unchanged) -----
        config::write_trust(&tmp_trust)?;
        let mut relay_state = config::read_relay_state()?;
        // v0.5.17: pin all advertised endpoints (federation + optional
        // local). Top-level legacy fields still point at the federation
        // endpoint for back-compat readers.
        crate::endpoints::pin_peer_endpoints(&mut relay_state, &peer_handle, &peer_endpoints)?;
        config::write_relay_state(&relay_state)?;

        // Consume invite (single-use default; decrement uses for multi-use).
        if let (Some(pending), Some(invite_path)) = (pending, invite_path) {
            if pending.uses_remaining <= 1 {
                if let Err(e) = std::fs::remove_file(&invite_path) {
                    eprintln!("wire: could not delete consumed invite {invite_path:?}: {e}");
                }
            } else {
                let mut updated = pending.clone();
                updated.uses_remaining -= 1;
                updated.accepted_by.push(peer_did.clone());
                std::fs::write(&invite_path, serde_json::to_vec_pretty(&updated)?)?;
            }
        }
        crate::os_notify::toast(
            &format!("wire — paired with {peer_handle}"),
            "Invite accepted. Ready to send + receive.",
        );
        return Ok(Some(peer_did));
    }

    // ----- Handle path: stash in pending-inbound, no capability flows -----
    // RFC-001 Phase 1b (Option A): if the peer's card proves org membership the
    // operator opted into auto-pairing (org_policies.json `inbound=auto`), pin
    // ORG_VERIFIED + endpoints + ack now — the per-org opt-in IS the standing
    // consent (distinct from accepting an anonymous stranger). Safe-by-default:
    // no policy / no v3.2 org-claims → decide=Manual → falls through to the
    // normal pending-inbound flow below. Never reaches VERIFIED (that needs the
    // per-peer gesture/SAS path); ORG_VERIFIED < VERIFIED.
    if let Some(org_did) =
        org_auto_pin_decision(&peer_card, &crate::org_policy::FileOrgPolicy::load())
    {
        let mut trust = crate::config::read_trust()?;
        crate::trust::add_agent_card_pin(&mut trust, &peer_card, Some("ORG_VERIFIED"));
        crate::config::write_trust(&trust)?;

        let endpoints_to_pin = if peer_endpoints.is_empty() {
            vec![crate::endpoints::Endpoint::federation(
                peer_relay.to_string(),
                peer_slot_id.to_string(),
                peer_slot_token.to_string(),
            )]
        } else {
            peer_endpoints.clone()
        };
        let mut relay_state = crate::config::read_relay_state()?;
        crate::endpoints::pin_peer_endpoints(&mut relay_state, &peer_handle, &endpoints_to_pin)?;
        crate::config::write_relay_state(&relay_state)?;

        send_pair_drop_ack(&peer_handle, &endpoints_to_pin)
            .with_context(|| format!("org-auto pair_drop_ack send to {peer_handle} failed"))?;

        crate::os_notify::toast_dedup(
            &format!("org-pair:{peer_handle}"),
            &format!("wire — auto-paired {peer_handle}"),
            &format!(
                "org-verified member of {org_did}; pinned ORG_VERIFIED (your org_policies.json opt-in)"
            ),
        );
        return Ok(Some(peer_did));
    }

    let now_iso = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    let event_id = event
        .get("event_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let event_timestamp = event
        .get("timestamp")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let pending_inbound = crate::pending_inbound_pair::PendingInboundPair {
        peer_handle: peer_handle.clone(),
        peer_did: peer_did.clone(),
        peer_card: peer_card.clone(),
        peer_relay_url: peer_relay.to_string(),
        peer_slot_id: peer_slot_id.to_string(),
        peer_slot_token: peer_slot_token.to_string(),
        peer_endpoints: peer_endpoints.clone(),
        event_id,
        event_timestamp,
        received_at: now_iso,
    };
    crate::pending_inbound_pair::write_pending_inbound(&pending_inbound)?;

    // RFC-001 Phase 1b — Notify mode: default-deny pending stash above runs
    // unchanged (no auto-pin, no auto-ack), but we ENRICH the lock-screen
    // notification with org context when the peer's verified membership is in
    // an org the operator marked `notify`. Same `toast_dedup` keying pattern
    // the auto branch uses so a flurry of pair_drops doesn't spam the
    // notification center. Falls through to the generic toast otherwise.
    match org_notify_decision(&peer_card, &crate::org_policy::FileOrgPolicy::load()) {
        Some(org_did) => crate::os_notify::toast_dedup(
            &format!("notify-pair:{peer_handle}"),
            &format!("wire — org-verified pair request from {peer_handle}"),
            &format!(
                "verified member of {org_did} (your org_policies.json says `notify`). run `wire pair-accept {peer_handle}` to pin VERIFIED, or `wire pair-reject {peer_handle}`",
            ),
        ),
        None => crate::os_notify::toast(
            &format!("wire — pair request from {peer_handle}"),
            &format!(
                "run `wire pair-accept {peer_handle}` (or `wire add {peer_handle}@{peer_relay}`) to accept, or `wire pair-reject {peer_handle}` to refuse",
            ),
        ),
    }

    Ok(Some(peer_did))
}

/// RFC-001 Phase 1b — decide whether a received card's org membership earns an
/// auto-pin to `ORG_VERIFIED` under the receiver's policy. Returns the matched
/// `org_did` iff the membership verifies offline AND the policy opts that org
/// into auto (Option A). Pure over `policy`; never yields anything above
/// `ORG_VERIFIED`. Safe-by-default: an empty/absent policy → `None`.
fn org_auto_pin_decision(
    card: &Value,
    policy: &dyn crate::pair_decision::OrgPolicy,
) -> Option<String> {
    match crate::pair_decision::decide(
        &crate::org_membership::evaluate_card_membership(card),
        policy,
    ) {
        crate::pair_decision::PairAction::AutoOrgVerified { org_did } => Some(org_did),
        _ => None,
    }
}

/// RFC-001 Phase 1b — decide whether a received card's org membership is
/// **eligible** for a one-tap accept under the receiver's policy (Notify mode,
/// Option B in RFC-001 §"Default ease-of-pair mechanism"). Returns the matched
/// `org_did` iff the membership verifies offline AND the policy opts that org
/// into `notify`. The default-deny pending stash still fires; this decision
/// only enriches the toast with org context so the operator can recognize the
/// vouch on the lock-screen. Safe-by-default: empty/absent policy → `None`.
/// Auto mode wins over Notify when both apply (auto returns first; this is
/// only consulted on the non-auto path).
fn org_notify_decision(
    card: &Value,
    policy: &dyn crate::pair_decision::OrgPolicy,
) -> Option<String> {
    match crate::pair_decision::decide(
        &crate::org_membership::evaluate_card_membership(card),
        policy,
    ) {
        crate::pair_decision::PairAction::NotifyOrgEligible { org_did } => Some(org_did),
        _ => None,
    }
}

/// Send a `pair_drop_ack` event (kind=1101) carrying OUR slot_token to a peer
/// who just intro'd to us via `/v1/handle/intro/<nick>`. Completes the
/// zero-paste bidirectional pin. Best-effort: errors are logged but don't
/// propagate, since the inbound pair_drop pin already succeeded and the
/// operator can retry from either side.
/// Send a `pair_drop_ack` (kind=1101) carrying our slot_token to a peer.
/// Used by the SPAKE2 invite-URL path (auto-called) and by the bilateral
/// completion path in `cmd_add` (operator-driven). Failures propagate so
/// the caller can surface the failure loudly.
/// Send a pair_drop_ack to a peer. Iterates the peer's pinned endpoints
/// in priority order (UDS / Local / LAN / Federation), trying each on
/// failure — only errors if every endpoint fails. Fixes Bug 2: previously
/// took a single `peer_relay`/`peer_slot_id`/`peer_slot_token` triple and
/// gave up after the first POST, so a peer whose first endpoint 4xx'd
/// (e.g. the userinfo-malformed URL from Bug 1) was unreachable even when
/// they advertised a second, clean endpoint.
///
/// Back-compat: callers that only know a single endpoint (legacy v0.5.16-
/// era pending records without `endpoints[]`) can pass a one-element slice
/// built from the legacy fields — the helper handles list-of-one identically
/// to the pre-fix single-endpoint shape.
pub fn send_pair_drop_ack(
    peer_handle: &str,
    peer_endpoints: &[crate::endpoints::Endpoint],
) -> Result<()> {
    // Load our own card + relay coords.
    let our_card = config::read_agent_card()?;
    let our_did = our_card
        .get("did")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("our card missing did"))?
        .to_string();
    let our_handle = crate::agent_card::display_handle_from_did(&our_did).to_string();
    let relay_state = config::read_relay_state()?;
    let self_state = relay_state.get("self").cloned().unwrap_or(Value::Null);
    // v0.7.5 silent-fail fix: prefer top-level legacy fields (v0.5.16
    // and earlier writers), fall back to the first endpoint in
    // self.endpoints[] (v0.5.17+ dual-slot writers). Pre-v0.7.5 this
    // function ONLY read the legacy fields, so any session created
    // with `--with-local` / `--with-uds` / `--with-lan` (which only
    // populate endpoints[]) hit `self relay state incomplete; cannot
    // emit pair_drop_ack` and silently black-holed every pair attempt.
    // Logged as FM3 + the slancha-api ↔ source incident 2026-05-23.
    let mut our_relay = self_state
        .get("relay_url")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let mut our_slot_id = self_state
        .get("slot_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let mut our_slot_token = self_state
        .get("slot_token")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if our_relay.is_empty() || our_slot_id.is_empty() || our_slot_token.is_empty() {
        // Try v0.5.17+ endpoints[] form. Pick the first endpoint —
        // priority is preserved in self_endpoints() returned order
        // (UDS / Local / LAN / Federation, lowest-friction first), so
        // pair_drop_ack rides the same priority routing as send.
        let eps = crate::endpoints::self_endpoints(&relay_state);
        if let Some(ep) = eps.first() {
            our_relay = ep.relay_url.clone();
            our_slot_id = ep.slot_id.clone();
            our_slot_token = ep.slot_token.clone();
        }
    }
    if our_relay.is_empty() || our_slot_id.is_empty() || our_slot_token.is_empty() {
        // STILL empty after both readers — the session genuinely has
        // no inbound slot. This is the "agent without inbound mailbox"
        // footgun. Refuse loudly with the exact remediation rather
        // than the prior vague "self relay state incomplete" message.
        bail!(
            "this session has no inbound slot configured — peers cannot deliver to us.\n\
             Fix: `wire bind-relay http://127.0.0.1:8771 --migrate-pinned` \
             (allocates a slot and re-publishes our card to all pinned peers).\n\
             Then re-run the pair flow. See WIRE_PAIRING_INCIDENT_2026-05-23 for context."
        );
    }

    let sk_seed = config::read_private_key()?;
    let pk_b64 = our_card
        .get("verify_keys")
        .and_then(Value::as_object)
        .and_then(|m| m.values().next())
        .and_then(|v| v.get("key"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("our card missing verify_keys[*].key"))?;
    let pk_bytes = crate::signing::b64decode(pk_b64)?;

    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    // v0.5.17: also advertise our endpoints[] in the ack so the peer can
    // pin both our federation and local endpoints. Back-compat: top-level
    // legacy fields above stay populated for v0.5.16-and-earlier readers.
    let our_endpoints = crate::endpoints::self_endpoints(&relay_state);
    let mut body = json!({
        "relay_url": our_relay,
        "slot_id": our_slot_id,
        "slot_token": our_slot_token,
    });
    if !our_endpoints.is_empty() {
        body["endpoints"] = serde_json::to_value(&our_endpoints).unwrap_or(json!([]));
    }
    let event = json!({
        "schema_version": crate::signing::EVENT_SCHEMA_VERSION,
        "timestamp": now,
        "from": our_did,
        "to": format!("did:wire:{peer_handle}"),
        "type": "pair_drop_ack",
        "kind": 1101u32,
        "body": body,
    });
    let signed = crate::signing::sign_message_v31(&event, &sk_seed, &pk_bytes, &our_handle)?;

    // Bug 2 fix: try every advertised peer endpoint in priority order; only
    // error if all fail. Pre-fix this function POSTed once to a single
    // endpoint and gave up on the first 4xx — a peer with [bad, good]
    // endpoints (e.g. the userinfo-malformed first endpoint surfaced by
    // Bug 1) was unreachable even though a good endpoint sat behind it.
    let (delivered_ep, _resp) =
        crate::relay_client::try_post_event_with_failover(peer_endpoints, &signed, |ep, ev| {
            crate::relay_client::post_event_to_endpoint(ep, ev)
        })
        .with_context(|| {
            format!(
                "pair_drop_ack to {peer_handle} failed across {} endpoint(s)",
                peer_endpoints.len()
            )
        })?;
    let _ = delivered_ep; // delivered_ep is available for future logging.
    Ok(())
}

/// Consume a `pair_drop_ack` event during daemon pull. Updates
/// relay-state.peers[<peer>] with the ack's slot_token so we can `wire send`
/// to the peer. Returns `Ok(true)` if applied. Idempotent.
pub fn maybe_consume_pair_drop_ack(event: &Value) -> Result<bool> {
    let kind = event.get("kind").and_then(Value::as_u64).unwrap_or(0);
    let type_str = event.get("type").and_then(Value::as_str).unwrap_or("");
    if kind != 1101 || type_str != "pair_drop_ack" {
        return Ok(false);
    }
    let body = match event.get("body") {
        Some(b) => b,
        None => return Ok(false),
    };
    let from = event
        .get("from")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("ack missing 'from'"))?;
    let peer_handle = crate::agent_card::display_handle_from_did(from).to_string();
    let peer_relay = body.get("relay_url").and_then(Value::as_str).unwrap_or("");
    let peer_slot_id = body.get("slot_id").and_then(Value::as_str).unwrap_or("");
    let peer_slot_token = body.get("slot_token").and_then(Value::as_str).unwrap_or("");
    if peer_relay.is_empty() || peer_slot_id.is_empty() || peer_slot_token.is_empty() {
        bail!("pair_drop_ack body missing relay_url/slot_id/slot_token");
    }
    // v0.5.17: parse endpoints[] if present (peer ran v0.5.17+ and has
    // dual slots); fall back to a single federation entry synthesized
    // from the legacy fields for v0.5.16-and-earlier acks.
    let peer_endpoints: Vec<crate::endpoints::Endpoint> = body
        .get("endpoints")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|e| {
                    serde_json::from_value::<crate::endpoints::Endpoint>(e.clone()).ok()
                })
                .collect()
        })
        .unwrap_or_else(|| {
            vec![crate::endpoints::Endpoint::federation(
                peer_relay.to_string(),
                peer_slot_id.to_string(),
                peer_slot_token.to_string(),
            )]
        });
    let mut relay_state = config::read_relay_state()?;
    crate::endpoints::pin_peer_endpoints(&mut relay_state, &peer_handle, &peer_endpoints)?;
    // v0.14.2 (#162 fix #5): stamp the durable bilateral-completed marker
    // on receipt of pair_drop_ack — this is the moment the bilateral
    // handshake actually completes (we already have their slot_token
    // pinned from their pair_drop; they sent the ack carrying ours).
    // Monotonic: once set, NEVER cleared. `effective_peer_tier` reads
    // this instead of slot_token presence so a transient endpoint
    // re-pin can't flap the visible tier from VERIFIED → PENDING_ACK.
    // `pin_peer_endpoints` preserves the field across re-pin events.
    if let Some(peer_entry) = relay_state
        .get_mut("peers")
        .and_then(Value::as_object_mut)
        .and_then(|m| m.get_mut(&peer_handle))
        .and_then(Value::as_object_mut)
    {
        peer_entry
            .entry("bilateral_completed_at".to_string())
            .or_insert_with(|| {
                Value::String(
                    time::OffsetDateTime::now_utc()
                        .format(&time::format_description::well_known::Rfc3339)
                        .unwrap_or_default(),
                )
            });
    }
    config::write_relay_state(&relay_state)?;
    crate::os_notify::toast(
        &format!("wire — pair complete with {peer_handle}"),
        "Both sides bound. Ready to send + receive.",
    );
    Ok(true)
}

// Earlier note: "tests removed because of WIRE_HOME race." That's no longer
// true — `config::test_support::with_temp_home` serialises env-mutating
// tests behind a process-wide mutex, so unit tests here are safe again.
// Keep e2e coverage in `tests/e2e_invite_pair.rs` for full-flow paranoia.

#[cfg(test)]
mod tests {
    use super::*;

    // ---- RFC-001 Phase 1b: org-auto-pin decision gate ----

    struct AutoFor(String);
    impl crate::pair_decision::OrgPolicy for AutoFor {
        fn inbound_mode(&self, org_did: &str) -> Option<crate::pair_decision::InboundMode> {
            (org_did == self.0).then_some(crate::pair_decision::InboundMode::Auto)
        }
    }
    struct EmptyPolicy;
    impl crate::pair_decision::OrgPolicy for EmptyPolicy {
        fn inbound_mode(&self, _: &str) -> Option<crate::pair_decision::InboundMode> {
            None
        }
    }

    /// Build a signed v3.2 card for an operator enrolled in one org.
    fn org_verified_card() -> (Value, String) {
        let (op_sk, op_pk) = crate::signing::generate_keypair();
        let (org_sk, org_pk) = crate::signing::generate_keypair();
        let (sess_sk, sess_pk) = crate::signing::generate_keypair();
        let op_did = crate::agent_card::did_for_op("darby", &op_pk);
        let org_did = crate::agent_card::did_for_org("slanchaai", &org_pk);
        let member_cert = crate::enroll::issue_member_cert(&org_sk, &op_did).unwrap();
        let base = crate::agent_card::build_agent_card("vesper-valley", &sess_pk, None, None, None);
        let session_did = base
            .get("did")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();
        let claims = crate::enroll::build_member_claims(
            "darby",
            &op_sk,
            &op_pk,
            &session_did,
            &[crate::enroll::MemberOf {
                org_did: org_did.clone(),
                org_pubkey: org_pk,
                member_cert,
            }],
            None,
        )
        .unwrap();
        let card = crate::agent_card::sign_agent_card(
            &crate::agent_card::with_identity_claims(&base, &claims).unwrap(),
            &sess_sk,
        );
        (card, org_did)
    }

    #[test]
    fn org_auto_pin_decision_auto_only_when_policy_opts_in() {
        let (card, org_did) = org_verified_card();
        // Policy opts this org into auto → Some(org_did).
        assert_eq!(
            org_auto_pin_decision(&card, &AutoFor(org_did.clone())),
            Some(org_did.clone())
        );
        // Empty policy → None (safe-by-default: no opt-in, no auto-pin).
        assert_eq!(org_auto_pin_decision(&card, &EmptyPolicy), None);
    }

    #[test]
    fn org_auto_pin_decision_none_for_plain_card() {
        // A v3.1 card with no op/org claims never auto-pins, even with an
        // auto-everything policy — there's no verified membership to match.
        let plain = serde_json::json!({
            "schema_version": "v3.1", "did": "did:wire:plain-deadbeef", "handle": "plain"
        });
        assert_eq!(
            org_auto_pin_decision(&plain, &AutoFor("did:wire:org:x-1".into())),
            None
        );
    }

    // ---- RFC-001 Phase 1b: org-notify decision gate ----

    struct NotifyFor(String);
    impl crate::pair_decision::OrgPolicy for NotifyFor {
        fn inbound_mode(&self, org_did: &str) -> Option<crate::pair_decision::InboundMode> {
            (org_did == self.0).then_some(crate::pair_decision::InboundMode::Notify)
        }
    }

    #[test]
    fn org_notify_decision_notify_only_when_policy_opts_in() {
        let (card, org_did) = org_verified_card();
        // Policy opts this org into notify → Some(org_did).
        assert_eq!(
            org_notify_decision(&card, &NotifyFor(org_did.clone())),
            Some(org_did.clone())
        );
        // Empty policy → None.
        assert_eq!(org_notify_decision(&card, &EmptyPolicy), None);
    }

    #[test]
    fn org_notify_decision_returns_none_when_policy_is_auto() {
        // Auto and Notify are mutually exclusive PairActions — a card whose
        // org is in the policy as `auto` must NOT also surface via the notify
        // helper (auto wins; notify is only consulted on the non-auto path).
        let (card, org_did) = org_verified_card();
        assert_eq!(org_notify_decision(&card, &AutoFor(org_did)), None);
    }

    #[test]
    fn org_notify_decision_none_for_plain_card() {
        // A v3.1 card with no op/org claims never matches notify — no
        // verified membership to match against the policy.
        let plain = serde_json::json!({
            "schema_version": "v3.1", "did": "did:wire:plain-deadbeef", "handle": "plain"
        });
        assert_eq!(
            org_notify_decision(&plain, &NotifyFor("did:wire:org:x-1".into())),
            None
        );
    }
    use crate::config;

    #[test]
    fn record_pair_rejection_writes_jsonl_under_state_dir() {
        // P0.2: silent fails must leave a trace. This is what `wire doctor`
        // (P1.6) will surface. If the file isn't written, `wire doctor`
        // can't see the problem — same silent-fail class we're fixing.
        config::test_support::with_temp_home(|| {
            super::record_pair_rejection(
                "slancha-spark",
                "pair_drop_ack_send_failed",
                "POST returned 502",
            );
            let path = config::state_dir().unwrap().join("pair-rejected.jsonl");
            assert!(path.exists(), "record_pair_rejection must create {path:?}");
            let body = std::fs::read_to_string(&path).unwrap();
            let line = body.lines().last().expect("at least one line");
            let parsed: Value = serde_json::from_str(line).expect("valid JSON");
            assert_eq!(parsed["peer"], "slancha-spark");
            assert_eq!(parsed["code"], "pair_drop_ack_send_failed");
            assert_eq!(parsed["detail"], "POST returned 502");
            assert!(parsed["ts"].as_u64().unwrap_or(0) > 0);
        });
    }

    #[test]
    fn record_pair_rejection_appends_multiple_lines() {
        // Multiple silent fails in one session must each leave a record —
        // it's append-only, not a single most-recent slot.
        config::test_support::with_temp_home(|| {
            super::record_pair_rejection("a", "code_a", "detail_a");
            super::record_pair_rejection("b", "code_b", "detail_b");
            super::record_pair_rejection("c", "code_c", "detail_c");
            let path = config::state_dir().unwrap().join("pair-rejected.jsonl");
            let body = std::fs::read_to_string(&path).unwrap();
            let lines: Vec<&str> = body.lines().collect();
            assert_eq!(lines.len(), 3, "expected 3 entries, got {}", lines.len());
            for (i, peer) in ["a", "b", "c"].iter().enumerate() {
                let parsed: Value = serde_json::from_str(lines[i]).unwrap();
                assert_eq!(parsed["peer"], *peer);
            }
        });
    }
}
