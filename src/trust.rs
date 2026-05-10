//! Trust state machine — v0.1 minimal subset.
//!
//! Tier semantics:
//!   - UNTRUSTED: card pinned, SAS not yet confirmed; messages ignored.
//!   - VERIFIED:  SAS confirmed bilateral; messages accepted.
//!   - ATTESTED:  reserved (v0.2+) — used today only for self-attest.
//!   - TRUSTED:   reserved (v0.2+).
//!
//! Promotion is one-way (UNTRUSTED → VERIFIED). Demotion would be
//! ambiguous in a bilateral setting and is deliberately not modeled.

use serde_json::{json, Value};
use std::collections::BTreeMap;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::signing::{b64encode, make_key_id};

/// Tier ranking — higher is more trusted. Useful for `>=` gating.
pub fn tier_order() -> BTreeMap<&'static str, u32> {
    [
        ("UNTRUSTED", 0u32),
        ("VERIFIED", 1),
        ("ATTESTED", 2),
        ("TRUSTED", 3),
    ]
    .into_iter()
    .collect()
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Tier {
    Untrusted,
    Verified,
    Attested,
    Trusted,
}

impl Tier {
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Untrusted => "UNTRUSTED",
            Tier::Verified => "VERIFIED",
            Tier::Attested => "ATTESTED",
            Tier::Trusted => "TRUSTED",
        }
    }
}

/// Trust state — kept as a free-form JSON Value so we can persist + read with
/// any conforming impl. v0.2+ may swap this for a typed struct.
pub type Trust = Value;

pub fn empty_trust() -> Trust {
    json!({"version": 1, "agents": {}})
}

pub fn get_tier(trust: &Trust, peer_handle: &str) -> String {
    trust
        .get("agents")
        .and_then(|a| a.get(peer_handle))
        .and_then(|a| a.get("tier"))
        .and_then(Value::as_str)
        .unwrap_or("UNTRUSTED")
        .to_string()
}

/// Pin a peer's card into our trust at the given tier (default UNTRUSTED).
///
/// The caller must independently run SAS confirmation (via `compute_sas`)
/// before calling `promote_to_verified`. Pinning alone DOES NOT verify.
pub fn add_agent_card_pin(trust: &mut Trust, card: &Value, tier: Option<&str>) {
    let did = card.get("did").and_then(Value::as_str).unwrap_or_default();
    let handle = did.strip_prefix("did:wire:").unwrap_or(did);
    if handle.is_empty() {
        panic!("card has no resolvable handle (did={did:?})");
    }
    let tier = tier.unwrap_or("UNTRUSTED");
    let now = now_iso();

    let mut public_keys = Vec::new();
    if let Some(vks) = card.get("verify_keys").and_then(Value::as_object) {
        for (key_id_full, key_record) in vks {
            // Strip the `ed25519:` algorithm prefix to match v3.1 trust.json shape.
            let key_id = key_id_full.strip_prefix("ed25519:").unwrap_or(key_id_full);
            public_keys.push(json!({
                "key_id": key_id,
                "key": key_record.get("key").cloned().unwrap_or(Value::Null),
                "added_at": now,
                "active": true,
            }));
        }
    }

    let agents = trust
        .as_object_mut()
        .expect("trust must be an object")
        .entry("agents")
        .or_insert_with(|| json!({}));

    agents[handle] = json!({
        "tier": tier,
        "did": did,
        "public_keys": public_keys,
        "card": card.clone(),
        "pinned_at": now,
    });
}

/// Promote UNTRUSTED → VERIFIED. Returns `Err(reason)` if not pinned or
/// already past UNTRUSTED (promotion is one-way).
pub fn promote_to_verified(trust: &mut Trust, peer_handle: &str) -> Result<(), String> {
    let agents = trust
        .as_object_mut()
        .ok_or("trust is not an object")?
        .get_mut("agents")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| format!("peer {peer_handle:?} not pinned"))?;

    let agent = agents
        .get_mut(peer_handle)
        .ok_or_else(|| format!("peer {peer_handle:?} not pinned"))?;

    let current = agent
        .get("tier")
        .and_then(Value::as_str)
        .unwrap_or("UNTRUSTED")
        .to_string();
    if current != "UNTRUSTED" {
        return Err(format!(
            "peer {peer_handle:?} already at tier {current:?} — promotion is one-way"
        ));
    }
    agent["tier"] = json!("VERIFIED");
    agent["verified_at"] = json!(now_iso());
    Ok(())
}

/// Self-pin our own keypair into trust at ATTESTED. Convenience for `wire init`.
pub fn add_self_to_trust(trust: &mut Trust, handle: &str, public_key: &[u8]) {
    let agents = trust
        .as_object_mut()
        .expect("trust must be an object")
        .entry("agents")
        .or_insert_with(|| json!({}));
    let key_id = make_key_id(handle, public_key);
    agents[handle] = json!({
        "tier": "ATTESTED",
        "did": format!("did:wire:{handle}"),
        "public_keys": [{
            "key_id": key_id,
            "key": b64encode(public_key),
            "added_at": now_iso(),
            "active": true,
        }],
    });
}

fn now_iso() -> String {
    let now = OffsetDateTime::now_utc();
    now.format(&Rfc3339).unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_card::{build_agent_card, sign_agent_card};
    use crate::signing::generate_keypair;

    #[test]
    fn empty_trust_shape() {
        let t = empty_trust();
        assert_eq!(t["version"], 1);
        assert!(t["agents"].is_object());
        assert_eq!(t["agents"].as_object().unwrap().len(), 0);
    }

    #[test]
    fn get_tier_unknown_returns_untrusted() {
        assert_eq!(get_tier(&empty_trust(), "ghost"), "UNTRUSTED");
    }

    #[test]
    fn add_agent_card_pin_defaults_untrusted() {
        let (sk, pk) = generate_keypair();
        let card = sign_agent_card(&build_agent_card("paul", &pk, None, None, None), &sk);
        let mut t = empty_trust();
        add_agent_card_pin(&mut t, &card, None);
        assert_eq!(get_tier(&t, "paul"), "UNTRUSTED");
        assert_eq!(t["agents"]["paul"]["did"], "did:wire:paul");
    }

    #[test]
    fn add_pin_strips_ed25519_prefix_from_key_id() {
        let (sk, pk) = generate_keypair();
        let card = sign_agent_card(&build_agent_card("paul", &pk, None, None, None), &sk);
        let mut t = empty_trust();
        add_agent_card_pin(&mut t, &card, None);
        let kid = t["agents"]["paul"]["public_keys"][0]["key_id"].as_str().unwrap();
        assert!(kid.contains(':'));
        assert!(!kid.starts_with("ed25519:"));
    }

    #[test]
    fn promote_to_verified_one_way() {
        let (sk, pk) = generate_keypair();
        let card = sign_agent_card(&build_agent_card("paul", &pk, None, None, None), &sk);
        let mut t = empty_trust();
        add_agent_card_pin(&mut t, &card, None);
        promote_to_verified(&mut t, "paul").unwrap();
        assert_eq!(get_tier(&t, "paul"), "VERIFIED");
        assert!(t["agents"]["paul"]["verified_at"].is_string());
    }

    #[test]
    fn promote_to_verified_idempotent_block() {
        let (sk, pk) = generate_keypair();
        let card = sign_agent_card(&build_agent_card("paul", &pk, None, None, None), &sk);
        let mut t = empty_trust();
        add_agent_card_pin(&mut t, &card, None);
        promote_to_verified(&mut t, "paul").unwrap();
        let err = promote_to_verified(&mut t, "paul").unwrap_err();
        assert!(err.contains("VERIFIED"), "got: {err}");
    }

    #[test]
    fn promote_unknown_peer_fails() {
        let mut t = empty_trust();
        let err = promote_to_verified(&mut t, "ghost").unwrap_err();
        assert!(err.contains("not pinned"), "got: {err}");
    }

    #[test]
    fn add_self_to_trust_attests() {
        let (_, pk) = generate_keypair();
        let mut t = empty_trust();
        add_self_to_trust(&mut t, "paul", &pk);
        assert_eq!(get_tier(&t, "paul"), "ATTESTED");
        assert_eq!(t["agents"]["paul"]["did"], "did:wire:paul");
    }

    #[test]
    fn tier_order_matches_promotion_semantics() {
        let order = tier_order();
        assert!(order["UNTRUSTED"] < order["VERIFIED"]);
        assert!(order["VERIFIED"] < order["ATTESTED"]);
        assert!(order["ATTESTED"] < order["TRUSTED"]);
    }
}
