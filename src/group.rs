//! Group chat (v0.13.3) — signed member-set model.
//!
//! A group is a named, creator-signed set of members. Group membership is a
//! SEPARATE axis from bilateral peer trust: a member's [`GroupTier`] is
//! group-scoped (Creator / Member / Introduced) and is NOT the bilateral
//! `trust.rs` `Tier`. A peer can be bilaterally UNTRUSTED yet a group Member,
//! or VERIFIED bilaterally but only INTRODUCED in a group — the two ladders
//! are intentionally disjoint, and group membership never auto-promotes
//! bilateral trust.
//!
//! The creator signs the canonical roster (`creator_sig`), so a member can pin
//! INTRODUCED peers on the creator's vouch even when the creator is offline.
//! `epoch` bumps on every roster mutation — it orders revocations (a kick at
//! epoch N invalidates anything stamped < N).
//!
//! Persistence: `<config>/groups/<id>.json`. Transport (group send/tail, the
//! join code, kick/secure-eject) lives in `cli.rs` and composes the existing
//! mesh-broadcast + invite primitives over the member set this module owns.

use anyhow::{Context, Result, bail};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::PathBuf;

use crate::signing::{b64decode, b64encode, canonical_event};

/// Group-scoped membership tier. Disjoint from the bilateral `trust.rs` Tier.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GroupTier {
    /// Owns the group; the only signer of the roster.
    Creator,
    /// Added by the creator from a bilaterally-VERIFIED peer (T22 consent).
    Member,
    /// Joined via a multi-use code — vouched-for, lower-privilege, visible,
    /// kickable. Never silently equivalent to a directly-verified Member.
    Introduced,
}

impl GroupTier {
    pub fn as_str(self) -> &'static str {
        match self {
            GroupTier::Creator => "creator",
            GroupTier::Member => "member",
            GroupTier::Introduced => "introduced",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    pub handle: String,
    /// Full DID — the identity anchor. Binding the member to its DID (not just
    /// the display handle) blocks a handle-spoof: two members can't collide on
    /// a handle, and a roster entry is pinned to one keypair.
    pub did: String,
    pub tier: GroupTier,
    /// Ed25519 key id (`<handle>:<fp>`). Part of the creator-signed roster so a
    /// member can introduce-pin this member's key on the creator's vouch.
    #[serde(default)]
    pub key_id: String,
    /// Base64 Ed25519 public key. The creator vouches for this binding via
    /// `creator_sig`; members pin it (at bilateral UNTRUSTED) to verify this
    /// member's group messages without a direct SAS handshake.
    #[serde(default)]
    pub key: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Group {
    pub id: String,
    pub name: String,
    pub creator_did: String,
    /// Bumped on every roster mutation (add/remove). Orders revocations (T17).
    pub epoch: u64,
    pub members: Vec<Member>,
    /// The shared group-room slot (I2). The creator allocates one relay slot;
    /// its token is the room key, distributed only to vouched members. Everyone
    /// posts + pulls this one slot. Empty until the room is allocated.
    #[serde(default)]
    pub relay_url: String,
    #[serde(default)]
    pub slot_id: String,
    /// Shared room key — read+write bearer credential for the group slot.
    /// SECRET: held only by vouched members; a leak compromises the room
    /// (revocation = rotate the slot, the I3 kick path).
    #[serde(default)]
    pub slot_token: String,
    /// Creator's Ed25519 signature (base64) over the canonical roster sans
    /// this field. Empty until signed.
    #[serde(default)]
    pub creator_sig: String,
}

impl Group {
    /// New group with the creator as the sole initial member. Unsigned — call
    /// [`Group::sign`] with the creator's private key.
    pub fn new(id: String, name: String, creator_handle: String, creator_did: String) -> Self {
        Group {
            members: vec![Member {
                handle: creator_handle,
                did: creator_did.clone(),
                tier: GroupTier::Creator,
                key_id: String::new(),
                key: String::new(),
            }],
            id,
            name,
            creator_did,
            epoch: 0,
            relay_url: String::new(),
            slot_id: String::new(),
            slot_token: String::new(),
            creator_sig: String::new(),
        }
    }

    /// Attach the relay-room coords (the shared group slot). Does NOT bump
    /// epoch — set as part of the create transaction, before signing.
    pub fn set_room(&mut self, relay_url: String, slot_id: String, slot_token: String) {
        self.relay_url = relay_url;
        self.slot_id = slot_id;
        self.slot_token = slot_token;
    }

    /// Attach a member's signing key by DID. Does NOT bump epoch — set as part
    /// of the add transaction, before signing. Errors if the DID isn't present.
    pub fn set_member_keys(&mut self, did: &str, key_id: String, key: String) -> Result<()> {
        let m = self
            .members
            .iter_mut()
            .find(|m| m.did == did)
            .with_context(|| format!("did {did} not in group {}", self.id))?;
        m.key_id = key_id;
        m.key = key;
        Ok(())
    }

    /// True if `did` is in the roster (any tier).
    pub fn contains_did(&self, did: &str) -> bool {
        self.members.iter().any(|m| m.did == did)
    }

    /// Member handles excluding self — the fan-out target for a group send.
    pub fn other_member_handles(&self, self_did: &str) -> Vec<String> {
        self.members
            .iter()
            .filter(|m| m.did != self_did)
            .map(|m| m.handle.clone())
            .collect()
    }

    /// Add a member at `tier`. Bumps `epoch` and INVALIDATES the signature
    /// (re-sign before persisting). Errors if the DID is already present.
    pub fn add_member(&mut self, handle: String, did: String, tier: GroupTier) -> Result<()> {
        if self.contains_did(&did) {
            bail!("did {did} already in group {}", self.id);
        }
        self.members.push(Member {
            handle,
            did,
            tier,
            key_id: String::new(),
            key: String::new(),
        });
        self.epoch += 1;
        self.creator_sig.clear();
        Ok(())
    }

    /// Remove a member by DID (kick). Bumps `epoch` (orders the revocation)
    /// and invalidates the signature. Refuses to remove the creator. Returns
    /// the removed member's handle.
    pub fn remove_member(&mut self, did: &str) -> Result<String> {
        if did == self.creator_did {
            bail!("cannot remove the group creator");
        }
        let idx = self
            .members
            .iter()
            .position(|m| m.did == did)
            .with_context(|| format!("did {did} not in group {}", self.id))?;
        let removed = self.members.remove(idx);
        self.epoch += 1;
        self.creator_sig.clear();
        Ok(removed.handle)
    }

    /// Canonical bytes signed by the creator — the group minus `creator_sig`.
    fn signing_bytes(&self) -> Vec<u8> {
        let payload = json!({
            "id": self.id,
            "name": self.name,
            "creator_did": self.creator_did,
            "epoch": self.epoch,
            "members": self.members,
            "relay_url": self.relay_url,
            "slot_id": self.slot_id,
            "slot_token": self.slot_token,
        });
        canonical_event(&payload, true)
    }

    /// Sign the roster with the creator's private key (32-byte seed).
    pub fn sign(&mut self, private_key: &[u8]) -> Result<()> {
        if private_key.len() < 32 {
            bail!("private key too short");
        }
        let mut sk_bytes = [0u8; 32];
        sk_bytes.copy_from_slice(&private_key[..32]);
        let sk = SigningKey::from_bytes(&sk_bytes);
        let sig = sk.sign(&self.signing_bytes());
        self.creator_sig = b64encode(&sig.to_bytes());
        Ok(())
    }

    /// Verify `creator_sig` against the creator's public key (32 bytes).
    pub fn verify(&self, creator_pubkey: &[u8]) -> bool {
        if self.creator_sig.is_empty() || creator_pubkey.len() != 32 {
            return false;
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(creator_pubkey);
        let vk = match VerifyingKey::from_bytes(&pk) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let sig_bytes = match b64decode(&self.creator_sig) {
            Ok(b) if b.len() == 64 => b,
            _ => return false,
        };
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        vk.verify(&self.signing_bytes(), &Signature::from_bytes(&sig_arr))
            .is_ok()
    }
}

/// `<config>/groups/`.
pub fn groups_dir() -> Result<PathBuf> {
    Ok(crate::config::config_dir()?.join("groups"))
}

/// Reject a group id that isn't a safe single filename component before it is
/// interpolated into a path. A group id arrives attacker-controlled inside a
/// join code (`cmd_group_join` deserializes the `Group` and TOFU-verifies it
/// against the creator key carried IN the roster — so the crafter signs their
/// own roster and `id` is fully attacker-chosen yet signature-valid). Without
/// this guard, `id = "../trust"` writes `<config>/wire/trust.json`, an
/// arbitrary-relative-path write / identity-store clobber. Legit ids are
/// `g<16hex>` (see `cmd_group_create`); allow `[A-Za-z0-9_-]{1,64}`, which
/// excludes `.`, `/`, `\`, and `..` by construction.
fn validate_group_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 64
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        bail!("invalid group id {id:?} (must be 1-64 chars of [A-Za-z0-9_-])");
    }
    Ok(())
}

fn group_path(id: &str) -> Result<PathBuf> {
    validate_group_id(id)?;
    Ok(groups_dir()?.join(format!("{id}.json")))
}

/// Persist a group (atomic tmp+rename).
pub fn save_group(group: &Group) -> Result<()> {
    let dir = groups_dir()?;
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {dir:?}"))?;
    let path = group_path(&group.id)?;
    let tmp = path.with_extension("json.tmp");
    let body = serde_json::to_vec_pretty(group)?;
    std::fs::write(&tmp, body).with_context(|| format!("writing {tmp:?}"))?;
    std::fs::rename(&tmp, &path).with_context(|| format!("atomic rename {tmp:?} → {path:?}"))?;
    Ok(())
}

/// Load a group by id.
pub fn load_group(id: &str) -> Result<Group> {
    let path = group_path(id)?;
    let bytes =
        std::fs::read(&path).with_context(|| format!("no such group {id:?} (at {path:?})"))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parsing group {id:?}"))
}

/// List all persisted groups (skips unparseable files).
pub fn list_groups() -> Result<Vec<Group>> {
    let dir = groups_dir()?;
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir)?.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        if let Ok(bytes) = std::fs::read(&path)
            && let Ok(g) = serde_json::from_slice::<Group>(&bytes)
        {
            out.push(g);
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// Resolve a group by id OR exact name. Errors if ambiguous/absent.
pub fn resolve_group(id_or_name: &str) -> Result<Group> {
    if let Ok(g) = load_group(id_or_name) {
        return Ok(g);
    }
    let matches: Vec<Group> = list_groups()?
        .into_iter()
        .filter(|g| g.name == id_or_name)
        .collect();
    match matches.len() {
        0 => bail!("no group with id or name {id_or_name:?}"),
        1 => Ok(matches.into_iter().next().unwrap()),
        n => bail!("{n} groups named {id_or_name:?} — use the group id"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::generate_keypair;

    fn mk() -> (Group, Vec<u8>, Vec<u8>) {
        let (sk, pk) = generate_keypair();
        let g = Group::new(
            "g1abc".into(),
            "test-group".into(),
            "creator-nick".into(),
            "did:wire:creator-aaaaaaaa".into(),
        );
        (g, sk.to_vec(), pk.to_vec())
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let (mut g, sk, pk) = mk();
        g.sign(&sk).unwrap();
        assert!(g.verify(&pk), "freshly-signed roster must verify");
        assert!(!g.creator_sig.is_empty());
    }

    #[test]
    fn tamper_breaks_signature() {
        let (mut g, sk, pk) = mk();
        g.sign(&sk).unwrap();
        // Inject a member WITHOUT re-signing → signature no longer covers the roster.
        g.members.push(Member {
            handle: "intruder".into(),
            did: "did:wire:intruder-bbbbbbbb".into(),
            tier: GroupTier::Member,
            key_id: String::new(),
            key: String::new(),
        });
        assert!(!g.verify(&pk), "tampered roster must NOT verify");
    }

    #[test]
    fn wrong_key_does_not_verify() {
        let (mut g, sk, _pk) = mk();
        g.sign(&sk).unwrap();
        let (_sk2, pk2) = generate_keypair();
        assert!(!g.verify(&pk2), "a different pubkey must not verify");
    }

    #[test]
    fn add_member_bumps_epoch_and_invalidates_sig() {
        let (mut g, sk, _pk) = mk();
        g.sign(&sk).unwrap();
        assert_eq!(g.epoch, 0);
        g.add_member(
            "bob".into(),
            "did:wire:bob-cccccccc".into(),
            GroupTier::Member,
        )
        .unwrap();
        assert_eq!(g.epoch, 1, "add bumps epoch");
        assert!(g.creator_sig.is_empty(), "add invalidates the signature");
    }

    #[test]
    fn add_duplicate_did_rejected() {
        let (mut g, _sk, _pk) = mk();
        g.add_member("x".into(), "did:wire:x-dddddddd".into(), GroupTier::Member)
            .unwrap();
        assert!(
            g.add_member("x2".into(), "did:wire:x-dddddddd".into(), GroupTier::Member)
                .is_err(),
            "duplicate DID must be rejected"
        );
    }

    #[test]
    fn remove_member_bumps_epoch_refuses_creator() {
        let (mut g, _sk, _pk) = mk();
        g.add_member(
            "bob".into(),
            "did:wire:bob-eeeeeeee".into(),
            GroupTier::Member,
        )
        .unwrap();
        let e = g.epoch;
        let h = g.remove_member("did:wire:bob-eeeeeeee").unwrap();
        assert_eq!(h, "bob");
        assert_eq!(g.epoch, e + 1, "remove bumps epoch (orders the revocation)");
        assert!(
            g.remove_member("did:wire:creator-aaaaaaaa").is_err(),
            "must refuse to remove the creator"
        );
    }

    #[test]
    fn group_tier_is_not_the_bilateral_tier() {
        // Doctrine guard: GroupTier is its own enum, serialized lowercase, and
        // must never be confused with trust.rs Tier (UPPERCASE). A member's
        // group standing says nothing about bilateral trust.
        assert_eq!(GroupTier::Introduced.as_str(), "introduced");
        let j = serde_json::to_string(&GroupTier::Member).unwrap();
        assert_eq!(j, "\"member\"");
        assert_ne!(
            GroupTier::Member.as_str(),
            crate::trust::Tier::Verified.as_str()
        );
    }

    #[test]
    fn room_coords_and_member_keys_are_covered_by_the_signature() {
        // The creator vouches for the room coords + each member's key binding,
        // so tampering with either after signing must invalidate creator_sig.
        let (mut g, sk, pk) = mk();
        g.set_room(
            "https://wireup.net".into(),
            "slot-abc".into(),
            "tok-secret".into(),
        );
        g.add_member(
            "bob".into(),
            "did:wire:bob-12345678".into(),
            GroupTier::Member,
        )
        .unwrap();
        g.set_member_keys(
            "did:wire:bob-12345678",
            "bob:12345678".into(),
            "BOBKEY".into(),
        )
        .unwrap();
        g.sign(&sk).unwrap();
        assert!(g.verify(&pk), "signed roster with room + keys must verify");

        // Tamper the room key → verify fails.
        let mut g2 = g.clone();
        g2.slot_token = "stolen".into();
        assert!(
            !g2.verify(&pk),
            "swapping the room token must break the vouch"
        );

        // Tamper a member's pinned key → verify fails (handle-spoof / key-swap).
        let mut g3 = g.clone();
        g3.members[1].key = "ATTACKERKEY".into();
        assert!(
            !g3.verify(&pk),
            "swapping a member key must break the vouch"
        );
    }

    #[test]
    fn other_member_handles_excludes_self() {
        let (mut g, _sk, _pk) = mk();
        g.add_member(
            "bob".into(),
            "did:wire:bob-ffffffff".into(),
            GroupTier::Member,
        )
        .unwrap();
        let targets = g.other_member_handles("did:wire:creator-aaaaaaaa");
        assert_eq!(targets, vec!["bob".to_string()], "fan-out excludes self");
    }

    #[test]
    fn group_id_path_traversal_is_rejected() {
        // A malicious join code carries an attacker-chosen `group.id` that is
        // signature-valid (self-signed roster). The path boundary MUST reject
        // anything that isn't a safe filename component, BEFORE any FS op — so
        // `id = "../trust"` can't clobber `<config>/wire/trust.json`.
        for bad in [
            "../trust",
            "../../config/wire/agent-card",
            "a/b",
            "a\\b",
            "..",
            ".",
            "a.b",
            "",
            &"x".repeat(65),
        ] {
            assert!(
                group_path(bad).is_err(),
                "path traversal not rejected: {bad:?}"
            );
            assert!(validate_group_id(bad).is_err(), "id not rejected: {bad:?}");
        }
        // Legit ids (the `g<16hex>` form from cmd_group_create) pass.
        for ok in ["g0123456789abcdef", "my-group_1", "G9"] {
            assert!(group_path(ok).is_ok(), "legit id rejected: {ok:?}");
        }
    }
}
