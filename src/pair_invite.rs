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

pub const DEFAULT_RELAY: &str = "https://wire.laulpogan.com";
pub const DEFAULT_TTL_SECS: u64 = 86_400; // 24 hours

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
    let self_state = relay_state.get("self").cloned().unwrap_or(Value::Null);

    if self_state.is_null() || self_state.get("slot_id").and_then(Value::as_str).is_none() {
        let client = crate::relay_client::RelayClient::new(relay);
        if !client.healthz().unwrap_or(false) {
            bail!("relay healthz failed at {relay}");
        }
        let handle = did.strip_prefix("did:wire:").unwrap_or(&did);
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

    let peer_handle = payload
        .did
        .strip_prefix("did:wire:")
        .unwrap_or(&payload.did)
        .to_string();
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
    let our_handle = our_did
        .strip_prefix("did:wire:")
        .unwrap_or(&our_did)
        .to_string();
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
    let nonce = match body.get("pair_nonce").and_then(Value::as_str) {
        Some(n) => n.to_string(),
        None => return Ok(None),
    };

    let dir = pending_invites_dir()?;
    let invite_path = dir.join(format!("{nonce}.json"));
    if !invite_path.exists() {
        return Ok(None);
    }
    let pending: PendingInvite = serde_json::from_slice(&std::fs::read(&invite_path)?)
        .with_context(|| format!("reading pending invite {invite_path:?}"))?;
    if now_unix() > pending.exp {
        let _ = std::fs::remove_file(&invite_path);
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
    let peer_handle = peer_did
        .strip_prefix("did:wire:")
        .unwrap_or(&peer_did)
        .to_string();

    // Verify the event signature now that we have peer's pubkey.
    let mut tmp_trust = config::read_trust()?;
    crate::trust::add_agent_card_pin(&mut tmp_trust, &peer_card, Some("VERIFIED"));
    crate::signing::verify_message_v31(event, &tmp_trust)
        .map_err(|e| anyhow!("pair_drop event sig verify failed: {e}"))?;

    // Pin peer in trust + relay-state.
    config::write_trust(&tmp_trust)?;
    let peer_relay = body.get("relay_url").and_then(Value::as_str).unwrap_or("");
    let peer_slot_id = body.get("slot_id").and_then(Value::as_str).unwrap_or("");
    let peer_slot_token = body.get("slot_token").and_then(Value::as_str).unwrap_or("");
    if peer_relay.is_empty() || peer_slot_id.is_empty() || peer_slot_token.is_empty() {
        bail!("pair_drop body missing relay_url/slot_id/slot_token");
    }
    let mut relay_state = config::read_relay_state()?;
    relay_state["peers"][&peer_handle] = json!({
        "relay_url": peer_relay,
        "slot_id": peer_slot_id,
        "slot_token": peer_slot_token,
    });
    config::write_relay_state(&relay_state)?;

    // Consume invite (single-use default; decrement uses for multi-use).
    if pending.uses_remaining <= 1 {
        let _ = std::fs::remove_file(&invite_path);
    } else {
        let mut updated = pending.clone();
        updated.uses_remaining -= 1;
        updated.accepted_by.push(peer_did.clone());
        std::fs::write(&invite_path, serde_json::to_vec_pretty(&updated)?)?;
    }

    crate::os_notify::toast(
        &format!("wire — paired with {peer_handle}"),
        "Invite accepted. Ready to send + receive.",
    );

    Ok(Some(peer_did))
}

// Unit tests removed — they mutate WIRE_HOME and race with other env-mutating
// tests in the same binary. Coverage is provided by tests/e2e_invite_pair.rs
// which runs as a separate process with isolated WIRE_HOME per test.
