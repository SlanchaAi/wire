//! Trust state machine — v0.1 minimal subset, extended in v3.2 (RFC-001).
//!
//! Tier semantics:
//!   - UNTRUSTED: card pinned, no claim verified yet; messages ignored.
//!   - ORG_VERIFIED: (v3.2 / RFC-001 §5) peer shares a verified `org_did`
//!     with us — *organisational* trust, NOT personal. Bilateral SAS is
//!     still required to cross into VERIFIED. Promotion from UNTRUSTED is
//!     one-way.
//!   - VERIFIED: SAS confirmed bilateral; messages accepted. Promotion
//!     accepts UNTRUSTED-or-ORG_VERIFIED as source (RFC-001 §5: "a
//!     SAS-paired peer that happens to share our org is recorded at
//!     VERIFIED, not downgraded").
//!   - ATTESTED: reserved (v0.2+) — used today only for self-attest.
//!   - TRUSTED: reserved (v0.2+).
//!
//! Promotion is one-way. Demotion would be ambiguous in a bilateral setting
//! and is deliberately not modeled. RFC-001 §5 invariant:
//!   "ORG_VERIFIED never satisfies a `>= VERIFIED` policy check."
//! That invariant is captured by `tier_order` (ORG_VERIFIED=1 < VERIFIED=2)
//! and by AC2 property test (tests/trust_ceiling_prop.rs) asserting no
//! claim-event walk reaches VERIFIED without a SasConfirmed step.

use serde_json::{Value, json};
use std::collections::BTreeMap;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::signing::{b64encode, make_key_id};

/// Tier ranking — higher is more trusted. Useful for `>=` gating.
///
/// RFC-001 §5 invariant: ORG_VERIFIED sits strictly between UNTRUSTED and
/// VERIFIED. A policy check of `tier >= VERIFIED` MUST NOT pass for an
/// ORG_VERIFIED peer — only an explicit SAS-confirmation can cross that line.
pub fn tier_order() -> BTreeMap<&'static str, u32> {
    [
        ("UNTRUSTED", 0u32),
        ("ORG_VERIFIED", 1),
        ("VERIFIED", 2),
        ("ATTESTED", 3),
        ("TRUSTED", 4),
    ]
    .into_iter()
    .collect()
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Tier {
    Untrusted,
    OrgVerified,
    Verified,
    Attested,
    Trusted,
}

impl Tier {
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Untrusted => "UNTRUSTED",
            Tier::OrgVerified => "ORG_VERIFIED",
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

/// Resolve a bare peer handle to the full DID stored in trust. Falls back
/// to `did:wire:<peer_handle>` (the bare-handle form) when the peer isn't
/// pinned — preserves pre-pair best-effort routing for unknown peers.
///
/// v0.14.2 (#162 fix #4): without this, send paths (`cmd_send` /
/// `tool_send`) built `to: did:wire:sunlit-aurora`, but pinned peers'
/// real DIDs carry the long fingerprint suffix
/// (`did:wire:sunlit-aurora-ec6f890d`). A bare-handle `to:` mismatches
/// the receiver's self-DID and risks rejection at canonical / cursor
/// check time (honey-pine's report observed this on the first queued
/// event). Use this helper at every send-build site to canonicalize
/// against the pinned peer's actual DID.
pub fn resolve_peer_did(trust: &Value, peer_handle: &str) -> String {
    trust
        .get("agents")
        .and_then(|a| a.get(peer_handle))
        .and_then(|p| p.get("did"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| format!("did:wire:{peer_handle}"))
}

/// Pin a peer's card into our trust at the given tier (default UNTRUSTED).
///
/// The caller must independently run SAS confirmation (via `compute_sas`)
/// before calling `promote_to_verified`. Pinning alone DOES NOT verify.
pub fn add_agent_card_pin(trust: &mut Trust, card: &Value, tier: Option<&str>) {
    let did = card.get("did").and_then(Value::as_str).unwrap_or_default();
    // v0.5.7+: prefer the explicit `handle` field on the card (display name).
    // Fall back to stripping the DID prefix for legacy cards. For v0.5.7+
    // pubkey-suffixed DIDs (`did:wire:paul-abc12345`), the display_handle
    // helper strips the pubkey suffix back off.
    let handle = card
        .get("handle")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| crate::agent_card::display_handle_from_did(did).to_string());
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

/// Promote UNTRUSTED or ORG_VERIFIED → VERIFIED. Returns `Err(reason)` if
/// not pinned or already past VERIFIED.
///
/// RFC-001 §5: a SAS-confirmed peer that happens to share our org is
/// recorded at VERIFIED, not downgraded — so ORG_VERIFIED is an accepted
/// source for VERIFIED promotion. ATTESTED and TRUSTED are above VERIFIED
/// and would be a downgrade; we refuse.
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
    if current != "UNTRUSTED" && current != "ORG_VERIFIED" {
        return Err(format!(
            "peer {peer_handle:?} already at tier {current:?} — promotion is one-way"
        ));
    }
    agent["tier"] = json!("VERIFIED");
    agent["verified_at"] = json!(now_iso());
    Ok(())
}

/// Promote UNTRUSTED → ORG_VERIFIED. Returns `Err(reason)` if not pinned or
/// already past UNTRUSTED.
///
/// RFC-001 §5: ORG_VERIFIED is granted on cryptographic + policy grounds
/// (the peer's `member_cert` for an org we accept verifies against that
/// org's pubkey) but DOES NOT satisfy the SAS-confirmation ceremony that
/// VERIFIED requires. It is a one-way intermediate step a peer may cross
/// before or after VERIFIED, but never *instead of* VERIFIED.
///
/// This function does NOT perform the cryptographic verification of
/// `member_cert` — that lives in [`crate::identity::verify_member_cert`]
/// and the caller must run it first. The trust mutation here is the policy
/// recording: "we accept this peer as ORG_VERIFIED under our active org
/// policy."
pub fn promote_to_org_verified(trust: &mut Trust, peer_handle: &str) -> Result<(), String> {
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
            "peer {peer_handle:?} already at tier {current:?} — \
             org_verified promotion fires from UNTRUSTED only"
        ));
    }
    agent["tier"] = json!("ORG_VERIFIED");
    agent["org_verified_at"] = json!(now_iso());
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
        "did": crate::agent_card::did_for_with_key(handle, public_key),
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
    now.format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
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
    fn resolve_peer_did_returns_pinned_did_with_full_suffix() {
        // v0.14.2 (#162 fix #4): a pinned peer's full DID includes the
        // long-fingerprint suffix; a bare-handle DID would mismatch the
        // receiver's self-DID and risk rejection at canonical/cursor
        // verification.
        let (sk, pk) = generate_keypair();
        let card = sign_agent_card(
            &build_agent_card("sunlit-aurora", &pk, None, None, None),
            &sk,
        );
        let pinned_did = card.get("did").and_then(Value::as_str).unwrap();
        assert!(
            pinned_did.starts_with("did:wire:sunlit-aurora-"),
            "test setup: card DID should carry long-hex suffix"
        );
        let mut t = empty_trust();
        add_agent_card_pin(&mut t, &card, Some("VERIFIED"));

        let resolved = resolve_peer_did(&t, "sunlit-aurora");
        assert_eq!(
            resolved, pinned_did,
            "pinned peer must resolve to its full DID, not the bare handle"
        );
    }

    #[test]
    fn resolve_peer_did_falls_back_to_bare_for_unknown_peer() {
        // Pre-pair best-effort: an unknown peer canonicalizes to the
        // bare-handle DID. cmd_send / tool_send keep working pre-pair;
        // post-pair the resolve path takes over.
        let t = empty_trust();
        assert_eq!(
            resolve_peer_did(&t, "ghost-peer"),
            "did:wire:ghost-peer",
            "unknown peer falls back to bare-handle DID"
        );
    }

    #[test]
    fn add_agent_card_pin_defaults_untrusted() {
        let (sk, pk) = generate_keypair();
        let card = sign_agent_card(&build_agent_card("paul", &pk, None, None, None), &sk);
        let mut t = empty_trust();
        add_agent_card_pin(&mut t, &card, None);
        assert_eq!(get_tier(&t, "paul"), "UNTRUSTED");
        // v0.5.7+: DID is pubkey-suffixed.
        let did = t["agents"]["paul"]["did"].as_str().unwrap();
        assert!(did.starts_with("did:wire:paul-"), "got: {did}");
    }

    #[test]
    fn add_pin_strips_ed25519_prefix_from_key_id() {
        let (sk, pk) = generate_keypair();
        let card = sign_agent_card(&build_agent_card("paul", &pk, None, None, None), &sk);
        let mut t = empty_trust();
        add_agent_card_pin(&mut t, &card, None);
        let kid = t["agents"]["paul"]["public_keys"][0]["key_id"]
            .as_str()
            .unwrap();
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
        let did = t["agents"]["paul"]["did"].as_str().unwrap();
        assert!(did.starts_with("did:wire:paul-"), "got: {did}");
    }

    #[test]
    fn tier_order_matches_promotion_semantics() {
        let order = tier_order();
        assert!(order["UNTRUSTED"] < order["ORG_VERIFIED"]);
        assert!(order["ORG_VERIFIED"] < order["VERIFIED"]);
        assert!(order["VERIFIED"] < order["ATTESTED"]);
        assert!(order["ATTESTED"] < order["TRUSTED"]);
    }

    // ─── RFC-001 §5: Tier::OrgVerified ────────────────────────────────────

    #[test]
    fn tier_as_str_covers_org_verified() {
        assert_eq!(Tier::OrgVerified.as_str(), "ORG_VERIFIED");
    }

    #[test]
    fn promote_to_org_verified_one_way() {
        let (sk, pk) = generate_keypair();
        let card = sign_agent_card(&build_agent_card("paul", &pk, None, None, None), &sk);
        let mut t = empty_trust();
        add_agent_card_pin(&mut t, &card, None);
        promote_to_org_verified(&mut t, "paul").unwrap();
        assert_eq!(get_tier(&t, "paul"), "ORG_VERIFIED");
        assert!(t["agents"]["paul"]["org_verified_at"].is_string());
    }

    #[test]
    fn promote_to_org_verified_refuses_already_verified() {
        // Once a peer is VERIFIED (bilateral SAS), regressing them to
        // ORG_VERIFIED would be a downgrade. Refuse.
        let (sk, pk) = generate_keypair();
        let card = sign_agent_card(&build_agent_card("paul", &pk, None, None, None), &sk);
        let mut t = empty_trust();
        add_agent_card_pin(&mut t, &card, None);
        promote_to_verified(&mut t, "paul").unwrap();
        let err = promote_to_org_verified(&mut t, "paul").unwrap_err();
        assert!(err.contains("VERIFIED"), "got: {err}");
        assert_eq!(get_tier(&t, "paul"), "VERIFIED");
    }

    #[test]
    fn promote_to_org_verified_refuses_self_idempotent() {
        // Twice-applied org promotion is a no-op error, not a silent reset
        // of `org_verified_at` — keeps the audit trail intact.
        let (sk, pk) = generate_keypair();
        let card = sign_agent_card(&build_agent_card("paul", &pk, None, None, None), &sk);
        let mut t = empty_trust();
        add_agent_card_pin(&mut t, &card, None);
        promote_to_org_verified(&mut t, "paul").unwrap();
        let err = promote_to_org_verified(&mut t, "paul").unwrap_err();
        assert!(err.contains("ORG_VERIFIED"), "got: {err}");
    }

    #[test]
    fn promote_to_verified_accepts_org_verified_source() {
        // RFC-001 §5: a peer can be ORG_VERIFIED then later cross the SAS
        // ceremony into VERIFIED — without losing the cryptographic
        // membership claim. We preserve `org_verified_at` for audit.
        let (sk, pk) = generate_keypair();
        let card = sign_agent_card(&build_agent_card("paul", &pk, None, None, None), &sk);
        let mut t = empty_trust();
        add_agent_card_pin(&mut t, &card, None);
        promote_to_org_verified(&mut t, "paul").unwrap();
        promote_to_verified(&mut t, "paul").unwrap();
        assert_eq!(get_tier(&t, "paul"), "VERIFIED");
        assert!(t["agents"]["paul"]["org_verified_at"].is_string());
        assert!(t["agents"]["paul"]["verified_at"].is_string());
    }

    #[test]
    fn promote_to_verified_refuses_attested_source() {
        // ATTESTED is reserved-but-above VERIFIED; a downgrade would lose
        // information. Refuse.
        let (_, pk) = generate_keypair();
        let mut t = empty_trust();
        add_self_to_trust(&mut t, "self", &pk);
        let err = promote_to_verified(&mut t, "self").unwrap_err();
        assert!(err.contains("ATTESTED"), "got: {err}");
    }

    #[test]
    fn org_verified_does_not_satisfy_verified_policy_check() {
        // The load-bearing RFC-001 invariant: a policy gate of
        // `tier >= VERIFIED` MUST refuse an ORG_VERIFIED peer.
        let order = tier_order();
        let verified_rank = order["VERIFIED"];
        let org_rank = order["ORG_VERIFIED"];
        assert!(
            org_rank < verified_rank,
            "ORG_VERIFIED ({org_rank}) must rank strictly below VERIFIED ({verified_rank})"
        );
    }
}
