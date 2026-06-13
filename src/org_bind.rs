//! RFC-001 §2 / amendment-sso §A — DNS-TXT org binding (the domain-rooted
//! trust floor).
//!
//! An org proves control of a domain by publishing
//! `_wire-org.<domain> TXT "did=did:wire:org:<id>; v=1"`. A receiver who runs
//! `wire org bind <domain>` resolves that record, extracts the `org_did`, and
//! records a per-org pairing policy (`org_policies.json`). From then on, a
//! peer presenting a verified `member_cert` for that org reaches `ORG_VERIFIED`
//! under the receiver's chosen inbound mode — the org identity is now rooted in
//! a domain the org demonstrably controls, not just a bare keypair.
//!
//! This is **policy-setup-time** resolution, not a per-pairing dependency: the
//! pairing hot path stays fully offline (`org_membership::evaluate_card_membership`
//! verifies the inline cert chain). DNS is consulted once, here, to translate a
//! human domain into the `org_did` the offline chain already verifies against.
//!
//! Resolution is **DNS-over-HTTPS** (no extra DNS crate; works behind the
//! TLS-terminating proxies and split-horizon resolvers wire already tolerates
//! for federation). The resolver is a trait so the resolve→pin logic is
//! unit-testable without a network.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde_json::Value;

use crate::org_policy::FileOrgPolicy;
use crate::pair_decision::InboundMode;
use crate::relay_client::{WireOrgTxtDid, WireOrgTxtRecord, parse_wire_org_txt_record};

/// Default DNS-over-HTTPS endpoint. Cloudflare's resolver speaks the
/// `application/dns-json` shape this module parses. Override with `WIRE_DOH_URL`
/// (e.g. an internal resolver, or Google's `https://dns.google/resolve`).
pub const DEFAULT_DOH_URL: &str = "https://cloudflare-dns.com/dns-query";
pub const DOH_URL_ENV: &str = "WIRE_DOH_URL";

/// Resolver seam: return every TXT string at `fqdn` (already unquoted + chunk-
/// joined). Implemented over DoH in production, faked in tests.
pub trait TxtResolver {
    fn resolve_txt(&self, fqdn: &str) -> Result<Vec<String>>;
}

/// DNS-over-HTTPS resolver. No extra crate — reuses the `reqwest::blocking`
/// client wire already depends on.
pub struct DohResolver {
    endpoint: String,
}

impl DohResolver {
    pub fn new() -> Self {
        let endpoint = std::env::var(DOH_URL_ENV).unwrap_or_else(|_| DEFAULT_DOH_URL.to_string());
        Self { endpoint }
    }
}

impl Default for DohResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl TxtResolver for DohResolver {
    fn resolve_txt(&self, fqdn: &str) -> Result<Vec<String>> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .context("building DoH HTTP client")?;
        let resp = client
            .get(&self.endpoint)
            .query(&[("name", fqdn), ("type", "TXT")])
            .header("accept", "application/dns-json")
            .send()
            .with_context(|| format!("DoH query for {fqdn} via {}", self.endpoint))?;
        if !resp.status().is_success() {
            bail!("DoH resolver returned HTTP {} for {fqdn}", resp.status());
        }
        let body: Value = resp.json().context("parsing DoH JSON response")?;
        Ok(extract_txt_answers(&body))
    }
}

/// Pull TXT (`type == 16`) answers out of a DoH `application/dns-json` body,
/// unquoting + joining the per-string chunks DNS splits long records into.
fn extract_txt_answers(body: &Value) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(answers) = body.get("Answer").and_then(Value::as_array) {
        for a in answers {
            if a.get("type").and_then(Value::as_u64) != Some(16) {
                continue; // not a TXT record
            }
            if let Some(data) = a.get("data").and_then(Value::as_str) {
                out.push(unquote_txt(data));
            }
        }
    }
    out
}

/// DoH returns TXT `data` as the raw RDATA presentation form: one or more
/// double-quoted character-strings (DNS splits >255-byte records into chunks),
/// e.g. `"\"did=...; \" \"v=1\""`. Strip the quotes and concatenate the chunks.
fn unquote_txt(data: &str) -> String {
    let trimmed = data.trim();
    if !trimmed.contains('"') {
        return trimmed.to_string();
    }
    let mut out = String::new();
    let mut in_quote = false;
    let mut prev_backslash = false;
    for c in trimmed.chars() {
        match c {
            '"' if !prev_backslash => in_quote = !in_quote,
            _ if in_quote => out.push(c),
            _ => {}
        }
        prev_backslash = c == '\\' && !prev_backslash;
    }
    out
}

/// Resolve `_wire-org.<domain>` and return the first TXT record that parses as
/// a valid wire-org binding. Errors if none resolve or none parse.
pub fn org_record_for_domain(resolver: &dyn TxtResolver, domain: &str) -> Result<WireOrgTxtRecord> {
    let domain = domain.trim().trim_end_matches('.');
    if domain.is_empty() {
        bail!("empty domain");
    }
    let fqdn = format!("_wire-org.{domain}");
    let records = resolver.resolve_txt(&fqdn)?;
    let found = records.len();
    for r in records {
        if let Ok(parsed) = parse_wire_org_txt_record(&r) {
            return Ok(parsed);
        }
    }
    bail!(
        "no valid wire-org TXT record at {fqdn} ({found} TXT record(s) resolved, \
         none parseable as `did=did:wire:org:…; v=1`). Confirm the org published \
         `_wire-org.{domain}`."
    )
}

/// Resolve a domain's `org_did` and pin a per-org inbound policy for it
/// (RFC-001 §2 floor). Returns the bound `org_did` + the resolved record.
///
/// Rejects a record that binds a personal-tier operator DID (`did:wire:op:…`):
/// `wire org bind` is the *organization* floor; a personal domain is a
/// different (single-operator) relationship.
pub fn bind_org(
    resolver: &dyn TxtResolver,
    domain: &str,
    mode: InboundMode,
) -> Result<(String, WireOrgTxtRecord)> {
    let record = org_record_for_domain(resolver, domain)?;
    let org_did = match &record.did {
        WireOrgTxtDid::Org(did) => did.clone(),
        WireOrgTxtDid::Op(did) => bail!(
            "`_wire-org.{}` binds a personal operator DID ({did}), not an organization. \
             `wire org bind` trusts an org's members; it is not for personal-tier domains.",
            domain.trim().trim_end_matches('.')
        ),
    };
    let mut policy = FileOrgPolicy::load();
    policy.set(&org_did, mode);
    policy.save()?;
    Ok((org_did, record))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Canned resolver: fqdn → TXT strings.
    struct FakeResolver(HashMap<String, Vec<String>>);
    impl FakeResolver {
        fn with(fqdn: &str, records: &[&str]) -> Self {
            let mut m = HashMap::new();
            m.insert(
                fqdn.to_string(),
                records.iter().map(|s| s.to_string()).collect(),
            );
            Self(m)
        }
    }
    impl TxtResolver for FakeResolver {
        fn resolve_txt(&self, fqdn: &str) -> Result<Vec<String>> {
            Ok(self.0.get(fqdn).cloned().unwrap_or_default())
        }
    }

    // A well-formed org DID (did:wire:org:<handle>-<32 hex>).
    const ORG_DID: &str = "did:wire:org:acme-0123456789abcdef0123456789abcdef";
    const OP_DID: &str = "did:wire:op:darby-0123456789abcdef0123456789abcdef";

    #[test]
    fn unquote_joins_chunked_txt() {
        assert_eq!(unquote_txt("\"did=x; \" \"v=1\""), "did=x; v=1");
        assert_eq!(unquote_txt("\"plain\""), "plain");
        assert_eq!(unquote_txt("unquoted"), "unquoted");
    }

    #[test]
    fn extract_txt_answers_filters_non_txt() {
        let body = serde_json::json!({
            "Answer": [
                { "type": 5,  "data": "cname.example." },          // CNAME — ignored
                { "type": 16, "data": "\"did=hi; v=1\"" },
            ]
        });
        assert_eq!(extract_txt_answers(&body), vec!["did=hi; v=1".to_string()]);
    }

    #[test]
    fn org_record_for_domain_picks_the_wire_record() {
        let fqdn = "_wire-org.acme.com";
        let resolver = FakeResolver::with(
            fqdn,
            &[
                "v=spf1 include:_spf.google.com ~all", // unrelated TXT — skipped
                &format!("did={ORG_DID}; v=1"),
            ],
        );
        let rec = org_record_for_domain(&resolver, "acme.com").unwrap();
        assert_eq!(rec.did.as_str(), ORG_DID);
    }

    #[test]
    fn org_record_for_domain_errors_when_none_resolve() {
        let resolver = FakeResolver::with("_wire-org.empty.com", &[]);
        assert!(org_record_for_domain(&resolver, "empty.com").is_err());
    }

    #[test]
    fn bind_org_writes_policy_for_org_domain() {
        crate::config::test_support::with_temp_home(|| {
            let resolver =
                FakeResolver::with("_wire-org.acme.com", &[&format!("did={ORG_DID}; v=1")]);
            let (org_did, _rec) = bind_org(&resolver, "acme.com", InboundMode::Notify).unwrap();
            assert_eq!(org_did, ORG_DID);
            // The policy file now trusts that org_did at `notify`.
            let pol = FileOrgPolicy::load();
            assert_eq!(
                crate::pair_decision::OrgPolicy::inbound_mode(&pol, ORG_DID),
                Some(InboundMode::Notify)
            );
        });
    }

    #[test]
    fn bind_org_rejects_personal_operator_did() {
        crate::config::test_support::with_temp_home(|| {
            let resolver =
                FakeResolver::with("_wire-org.darby.dev", &[&format!("did={OP_DID}; v=1")]);
            let err = bind_org(&resolver, "darby.dev", InboundMode::Notify).unwrap_err();
            assert!(
                format!("{err:#}").contains("personal operator DID"),
                "got: {err:#}"
            );
            // And nothing was written to policy.
            assert!(FileOrgPolicy::load().is_empty());
        });
    }
}
