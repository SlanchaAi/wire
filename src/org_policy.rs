//! RFC-001 Phase 3 (minimal) — per-org pairing policy persistence.
//!
//! The receiver's trusted-org set + inbound mode, stored at
//! `config/wire/org_policies.json`. Implements the [`OrgPolicy`] trait
//! (`pair_decision`) that `decide()` consumes, so the live pairing wiring
//! (P1b) can look up "do I auto/notify-pair members of this org?".
//!
//! **Fail-closed.** A missing or malformed policy file loads as the empty
//! policy → every org is untrusted (`None`) → `decide()` returns `Manual`
//! (today's default-deny bilateral flow). A broken policy must never grant
//! eased pairing, so loading never errors.
//!
//! This is the minimal subset the wiring needs (org_did → inbound mode). The
//! full filtering surface from amendment #83 (first-match-wins table, the
//! `org_attestation`/`project` columns, the consent-gated `wire_org_set_policy`
//! MCP tool, AC-FILT) layers on top of this store.

use crate::pair_decision::{InboundMode, OrgPolicy};
use anyhow::Result;
use serde_json::json;
use std::collections::HashMap;
use std::path::Path;

const FILE: &str = "org_policies.json";

/// File-backed per-org policy. Maps `org_did` → inbound mode for the orgs the
/// receiver trusts; absence means untrusted (default-deny).
#[derive(Debug, Clone, Default)]
pub struct FileOrgPolicy {
    orgs: HashMap<String, InboundMode>,
}

impl FileOrgPolicy {
    /// Load from `config/wire/org_policies.json`. Missing or malformed → empty
    /// (default-deny). Never errors — a broken policy must not grant easing.
    pub fn load() -> Self {
        match crate::config::config_dir() {
            Ok(dir) => Self::load_path(&dir.join(FILE)),
            Err(_) => Self::default(),
        }
    }

    /// Load from an explicit path (testable). Fail-closed on any error.
    pub fn load_path(path: &Path) -> Self {
        let Ok(bytes) = std::fs::read(path) else {
            return Self::default();
        };
        let Ok(json) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            return Self::default();
        };
        let mut orgs = HashMap::new();
        if let Some(map) = json.get("orgs").and_then(|v| v.as_object()) {
            for (org_did, entry) in map {
                if let Some(mode) = entry
                    .get("inbound")
                    .and_then(|v| v.as_str())
                    .and_then(parse_mode)
                {
                    orgs.insert(org_did.clone(), mode);
                }
            }
        }
        Self { orgs }
    }

    /// Set/replace one org's inbound mode (in memory; call `save*` to persist).
    pub fn set(&mut self, org_did: &str, mode: InboundMode) {
        self.orgs.insert(org_did.to_string(), mode);
    }

    /// Drop an org from the trusted set.
    pub fn remove(&mut self, org_did: &str) {
        self.orgs.remove(org_did);
    }

    /// Number of trusted orgs (for `wire org policy list`).
    pub fn len(&self) -> usize {
        self.orgs.len()
    }

    /// Iterate `(org_did, mode)` for `wire org list`. Order is unspecified
    /// (HashMap); callers that need stable output should sort.
    pub fn entries(&self) -> impl Iterator<Item = (&String, &InboundMode)> {
        self.orgs.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.orgs.is_empty()
    }

    /// Persist to `config/wire/org_policies.json`.
    pub fn save(&self) -> Result<()> {
        let dir = crate::config::config_dir()?;
        std::fs::create_dir_all(&dir)?;
        self.save_path(&dir.join(FILE))?;
        Ok(())
    }

    /// Persist to an explicit path (testable).
    pub fn save_path(&self, path: &Path) -> std::io::Result<()> {
        std::fs::write(path, self.to_json())
    }

    fn to_json(&self) -> String {
        let orgs: serde_json::Map<String, serde_json::Value> = self
            .orgs
            .iter()
            .map(|(k, v)| (k.clone(), json!({ "inbound": mode_str(*v) })))
            .collect();
        serde_json::to_string_pretty(&json!({ "version": 1, "orgs": orgs }))
            .unwrap_or_else(|_| "{}".into())
    }
}

impl OrgPolicy for FileOrgPolicy {
    fn inbound_mode(&self, org_did: &str) -> Option<InboundMode> {
        self.orgs.get(org_did).copied()
    }
}

fn parse_mode(s: &str) -> Option<InboundMode> {
    match s {
        "auto" => Some(InboundMode::Auto),
        "notify" => Some(InboundMode::Notify),
        _ => None,
    }
}

fn mode_str(m: InboundMode) -> &'static str {
    match m {
        InboundMode::Auto => "auto",
        InboundMode::Notify => "notify",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("wire-orgpol-{}-{name}.json", std::process::id()))
    }

    #[test]
    fn missing_file_is_default_deny() {
        let p = tmp("missing");
        let _ = std::fs::remove_file(&p);
        let pol = FileOrgPolicy::load_path(&p);
        assert!(pol.is_empty());
        assert_eq!(pol.inbound_mode("did:wire:org:slanchaai-1"), None);
    }

    #[test]
    fn malformed_file_is_default_deny() {
        let p = tmp("malformed");
        std::fs::write(&p, b"not json {{{").unwrap();
        let pol = FileOrgPolicy::load_path(&p);
        assert!(pol.is_empty(), "malformed policy must fail closed to empty");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn set_save_load_roundtrip() {
        let p = tmp("roundtrip");
        let mut pol = FileOrgPolicy::default();
        pol.set("did:wire:org:slanchaai-1", InboundMode::Auto);
        pol.set("did:wire:org:contractor-2", InboundMode::Notify);
        pol.save_path(&p).unwrap();

        let loaded = FileOrgPolicy::load_path(&p);
        assert_eq!(
            loaded.inbound_mode("did:wire:org:slanchaai-1"),
            Some(InboundMode::Auto)
        );
        assert_eq!(
            loaded.inbound_mode("did:wire:org:contractor-2"),
            Some(InboundMode::Notify)
        );
        assert_eq!(loaded.inbound_mode("did:wire:org:unknown-9"), None);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn unknown_mode_string_is_skipped() {
        let p = tmp("badmode");
        std::fs::write(
            &p,
            br#"{"version":1,"orgs":{"did:wire:org:x-1":{"inbound":"superuser"}}}"#,
        )
        .unwrap();
        let pol = FileOrgPolicy::load_path(&p);
        assert_eq!(pol.inbound_mode("did:wire:org:x-1"), None);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn remove_drops_org() {
        let mut pol = FileOrgPolicy::default();
        pol.set("did:wire:org:x-1", InboundMode::Auto);
        pol.remove("did:wire:org:x-1");
        assert_eq!(pol.inbound_mode("did:wire:org:x-1"), None);
    }
}
