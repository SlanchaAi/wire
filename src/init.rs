//! Idempotent local-identity creation.
//!
//! `init_self_idempotent` is the single writeable identity-creation entry
//! point safe to expose to agents (via MCP `wire_init` / auto-init) and to the
//! invite-accept path: it can't change an operator's existing identity. It
//! lived in `pair_session` historically (the SAS pairing module) but is not
//! SAS-specific — it only ensures the local keypair + agent-card + relay slot
//! exist. Relocated here when the SAS flow was removed (RFC-005 follow-on).

use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

/// MCP-callable init: idempotent if already inited under the same handle,
/// errors on different-handle conflict, accepts optional --relay binding.
///
/// This is the only writeable identity-creation entry point safe to expose
/// to agents — it can't change the operator's existing identity.
pub fn init_self_idempotent(
    handle: &str,
    name: Option<&str>,
    relay: Option<&str>,
) -> Result<Value> {
    use crate::agent_card::{build_agent_card, sign_agent_card};
    use crate::signing::{fingerprint, generate_keypair, make_key_id};
    use crate::trust::{add_self_to_trust, empty_trust};

    if !handle
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        bail!("handle must be ASCII alphanumeric / '-' / '_' (got {handle:?})");
    }

    if crate::config::is_initialized()? {
        let card = crate::config::read_agent_card()?;
        let existing_did = card
            .get("did")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        // Prefer the explicit `handle` field on the card (v0.5.7+);
        // fall back to the DID prefix-and-pubkey-suffix strip for legacy.
        let existing_handle = card
            .get("handle")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| {
                crate::agent_card::display_handle_from_did(&existing_did).to_string()
            });
        // One-name rule: the on-disk identity is authoritative and the passed
        // `handle` is a vestigial seed (often the hostname from
        // default_handle()). Never re-key on re-init — adopt the existing
        // persona handle for all downstream fields. (Previously this bailed on
        // a handle mismatch, which broke claim / MCP / pairing on any session
        // whose persona handle differed from the hostname seed.)
        let handle: &str = &existing_handle;
        let pk_b64 = card
            .get("verify_keys")
            .and_then(Value::as_object)
            .and_then(|m| m.values().next())
            .and_then(|v| v.get("key"))
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("agent-card missing verify_keys[*].key"))?;
        let pk_bytes = crate::signing::b64decode(pk_b64)?;
        let mut out = json!({
            "did": existing_did,
            "handle": handle,
            "fingerprint": fingerprint(&pk_bytes),
            "key_id": make_key_id(handle, &pk_bytes),
            "config_dir": crate::config::config_dir()?.to_string_lossy(),
            "already_initialized": true,
        });
        let mut relay_state = crate::config::read_relay_state()?;
        if let Some(url) = relay {
            let url = url.trim_end_matches('/');
            // Bind iff we don't already hold a slot on THIS relay. Fixes
            // the v0.11 no-op where an already-initialized identity whose
            // `self` was non-null-but-unbound (e.g. `self relay: ?`) never
            // allocated the requested relay slot — `relay_state["self"]`
            // wasn't strictly null, so the old guard skipped binding and
            // wire_claim then failed with 404 unknown slot. Additive:
            // keeps any other slots (matches cmd_bind_relay).
            let already = crate::endpoints::self_endpoints(&relay_state)
                .into_iter()
                .find(|e| e.relay_url == url);
            if let Some(ep) = already {
                out["relay_url"] = json!(url);
                out["slot_id"] = json!(ep.slot_id);
            } else {
                let client = crate::relay_client::RelayClient::new(url);
                client.check_healthz()?;
                let alloc = client.allocate_slot(Some(handle))?;
                crate::endpoints::upsert_self_endpoint(
                    &mut relay_state,
                    crate::endpoints::Endpoint {
                        relay_url: url.to_string(),
                        slot_id: alloc.slot_id.clone(),
                        slot_token: alloc.slot_token,
                        scope: crate::endpoints::infer_scope_from_url(url),
                    },
                );
                crate::config::write_relay_state(&relay_state)?;
                out["relay_url"] = json!(url);
                out["slot_id"] = json!(alloc.slot_id);
            }
        }
        return Ok(out);
    }

    crate::config::ensure_dirs()?;
    let (sk_seed, pk_bytes) = generate_keypair();
    crate::config::write_private_key(&sk_seed)?;

    // One-name rule: derive the persona from the keypair fingerprint, not the
    // passed `handle` (a vestigial seed — often the hostname from
    // default_handle()). Deriving here means EVERY init path, including the
    // auto-init used by claim / MCP / pairing, yields a unique fp-derived
    // persona instead of a shared hostname. This was the root of "every new
    // session on a box shows the same handle".
    let synth_did = crate::agent_card::did_for_with_key(handle, &pk_bytes);
    let persona = crate::character::Character::from_did(&synth_did).nickname;
    let handle: &str = &persona;

    let card = build_agent_card(handle, &pk_bytes, name, None, None);
    // Card-emit (RFC-001 Phase 1b): attach operator/org claims if this machine
    // is enrolled. Fail-soft no-op when not enrolled — non-enrolled cards are
    // byte-identical. Signed below, so the self-signature covers the claims.
    let card = crate::enroll::with_op_claims_if_enrolled(card)?;
    // RFC-007 D3.1: attach the cross-signed Nostr transport binding if a
    // transport key is present. Additive + fail-soft (no-op when not keyed).
    let card = crate::nostr_key::with_nostr_binding_if_keyed(card)?;
    let signed = sign_agent_card(&card, &sk_seed);
    crate::config::write_agent_card(&signed)?;
    let mut trust = empty_trust();
    add_self_to_trust(&mut trust, handle, &pk_bytes);
    crate::config::write_trust(&trust)?;

    let mut out = json!({
        "did": crate::agent_card::did_for_with_key(handle, &pk_bytes),
        "handle": handle,
        "fingerprint": fingerprint(&pk_bytes),
        "key_id": make_key_id(handle, &pk_bytes),
        "config_dir": crate::config::config_dir()?.to_string_lossy(),
        "already_initialized": false,
    });

    if let Some(url) = relay {
        let client = crate::relay_client::RelayClient::new(url);
        client.check_healthz()?;
        let alloc = client.allocate_slot(Some(handle))?;
        let mut rs = crate::config::read_relay_state()?;
        rs["self"] = json!({
            "relay_url": url,
            "slot_id": alloc.slot_id.clone(),
            "slot_token": alloc.slot_token,
        });
        crate::config::write_relay_state(&rs)?;
        out["relay_url"] = json!(url);
        out["slot_id"] = json!(alloc.slot_id);
    }

    Ok(out)
}
