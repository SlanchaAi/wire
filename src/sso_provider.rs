//! Pluggable SSO / OIDC provider adapters — the seam from issue #92.
//!
//! Each IdP puts the organization "tenant" in a different OIDC claim: Google
//! Workspace uses `hd` (hosted domain), Azure AD uses `tid` (tenant id),
//! Keycloak encodes the realm in the issuer URL, etc. This trait normalizes a
//! verified token's claims to a provider-agnostic `(issuer, tenant, subject)`
//! so the SSO-attestation core (v0.15) never grows a `match provider { … }`:
//! adding an IdP is **one `impl SsoProvider` + one line in `builtins()`**.
//!
//! # SCOPE / SECURITY BOUNDARY
//! This is claim **normalization only** — pure, no network, no JWT signature
//! check. `extract()` assumes its `claims` came from a token whose signature
//! was already verified against the issuer's JWKS. It grants **no trust on its
//! own**; the live JWKS-fetch + signature verification + pinning is the v0.15
//! connector's job. Never feed `extract()` unverified claims and trust the
//! result.

use serde_json::Value;

/// Normalized identity extracted from a (verified) OIDC token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsoIdentity {
    /// The OIDC `iss` (issuer URL).
    pub issuer: String,
    /// The organization tenant, normalized across providers (Google `hd`,
    /// Azure `tid`, Keycloak realm, …). This is what an `org_did` binds to.
    pub tenant: String,
    /// The OIDC `sub`. Raw — the org-scoped pseudonym derivation
    /// (`blake2b(sub‖org_did‖…)`, RFC-001 §B.1) happens downstream; the raw
    /// subject must not cross the wire layer.
    pub subject: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SsoError {
    /// A required claim was absent or not a string.
    MissingClaim(&'static str),
}

/// A per-IdP adapter: select by issuer, then extract the normalized identity
/// from already-verified claims. Add an IdP by implementing this and appending
/// it to [`builtins`] (before [`Generic`], which is the catch-all fallback).
pub trait SsoProvider: Send + Sync {
    /// Stable provider id (`"google"`, `"azure"`, `"keycloak"`, `"generic"`, …).
    fn id(&self) -> &'static str;
    /// Whether this provider handles a token with issuer `iss`.
    fn matches_issuer(&self, iss: &str) -> bool;
    /// Extract `(issuer, tenant, subject)` from already-verified claims.
    fn extract(&self, claims: &Value) -> Result<SsoIdentity, SsoError>;
}

fn claim<'a>(claims: &'a Value, key: &'static str) -> Result<&'a str, SsoError> {
    claims
        .get(key)
        .and_then(Value::as_str)
        .ok_or(SsoError::MissingClaim(key))
}

/// Google Workspace — tenant is the `hd` (hosted-domain) claim. Personal Gmail
/// accounts carry no `hd`, so they correctly have no org tenant.
pub struct Google;
impl SsoProvider for Google {
    fn id(&self) -> &'static str {
        "google"
    }
    fn matches_issuer(&self, iss: &str) -> bool {
        iss == "https://accounts.google.com"
    }
    fn extract(&self, c: &Value) -> Result<SsoIdentity, SsoError> {
        Ok(SsoIdentity {
            issuer: claim(c, "iss")?.into(),
            tenant: claim(c, "hd")?.into(),
            subject: claim(c, "sub")?.into(),
        })
    }
}

/// Azure AD / Entra ID — tenant is the `tid` (directory GUID) claim. Issuer is
/// `https://login.microsoftonline.com/<tid>/v2.0`.
pub struct AzureAd;
impl SsoProvider for AzureAd {
    fn id(&self) -> &'static str {
        "azure"
    }
    fn matches_issuer(&self, iss: &str) -> bool {
        iss.starts_with("https://login.microsoftonline.com/")
    }
    fn extract(&self, c: &Value) -> Result<SsoIdentity, SsoError> {
        Ok(SsoIdentity {
            issuer: claim(c, "iss")?.into(),
            tenant: claim(c, "tid")?.into(),
            subject: claim(c, "sub")?.into(),
        })
    }
}

/// Keycloak — tenant is the realm, encoded in the issuer as
/// `https://<host>/realms/<realm>`.
pub struct Keycloak;
impl SsoProvider for Keycloak {
    fn id(&self) -> &'static str {
        "keycloak"
    }
    fn matches_issuer(&self, iss: &str) -> bool {
        iss.contains("/realms/")
    }
    fn extract(&self, c: &Value) -> Result<SsoIdentity, SsoError> {
        let iss = claim(c, "iss")?;
        let realm = iss
            .rsplit("/realms/")
            .next()
            .and_then(|s| s.split('/').next())
            .filter(|s| !s.is_empty())
            .ok_or(SsoError::MissingClaim("realm"))?;
        Ok(SsoIdentity {
            issuer: iss.into(),
            tenant: realm.into(),
            subject: claim(c, "sub")?.into(),
        })
    }
}

/// Generic OIDC fallback — no provider-specific tenant claim, so the tenant is
/// the issuer host. MUST stay last in [`builtins`] (its `matches_issuer` is
/// always true). Real deployments should prefer a specific provider.
pub struct Generic;
impl SsoProvider for Generic {
    fn id(&self) -> &'static str {
        "generic"
    }
    fn matches_issuer(&self, _iss: &str) -> bool {
        true
    }
    fn extract(&self, c: &Value) -> Result<SsoIdentity, SsoError> {
        let iss = claim(c, "iss")?;
        let host = iss
            .strip_prefix("https://")
            .or_else(|| iss.strip_prefix("http://"))
            .unwrap_or(iss)
            .split('/')
            .next()
            .unwrap_or(iss);
        Ok(SsoIdentity {
            issuer: iss.into(),
            tenant: host.into(),
            subject: claim(c, "sub")?.into(),
        })
    }
}

/// The built-in providers, tried in order; [`Generic`] is the catch-all and
/// MUST be last. Adding an IdP = `impl SsoProvider` + one entry here.
pub fn builtins() -> [&'static dyn SsoProvider; 4] {
    [&Google, &AzureAd, &Keycloak, &Generic]
}

/// Select the provider that handles `iss` (always returns one — `Generic` is
/// the fallback).
pub fn provider_for(iss: &str) -> &'static dyn SsoProvider {
    builtins()
        .into_iter()
        .find(|p| p.matches_issuer(iss))
        .expect("Generic matches all issuers")
}

/// Normalize a verified token's `claims` to `(identity, provider_id)`. The
/// caller is responsible for having verified the token's signature first.
pub fn normalize(claims: &Value) -> Result<(SsoIdentity, &'static str), SsoError> {
    let iss = claim(claims, "iss")?;
    let p = provider_for(iss);
    Ok((p.extract(claims)?, p.id()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn google_uses_hd_as_tenant() {
        let c = json!({"iss": "https://accounts.google.com", "hd": "slanchaai.com", "sub": "117"});
        let (id, prov) = normalize(&c).unwrap();
        assert_eq!(prov, "google");
        assert_eq!(id.tenant, "slanchaai.com");
        assert_eq!(id.subject, "117");
    }

    #[test]
    fn azure_uses_tid_as_tenant() {
        let c = json!({"iss": "https://login.microsoftonline.com/abc-123/v2.0", "tid": "abc-123", "sub": "u9"});
        let (id, prov) = normalize(&c).unwrap();
        assert_eq!(prov, "azure");
        assert_eq!(id.tenant, "abc-123");
    }

    #[test]
    fn keycloak_extracts_realm_from_issuer() {
        let c = json!({"iss": "https://id.example.com/realms/acme", "sub": "kc1"});
        let (id, prov) = normalize(&c).unwrap();
        assert_eq!(prov, "keycloak");
        assert_eq!(id.tenant, "acme");
    }

    #[test]
    fn generic_falls_back_to_issuer_host() {
        let c = json!({"iss": "https://idp.unknown.example/", "sub": "g1"});
        let (id, prov) = normalize(&c).unwrap();
        assert_eq!(prov, "generic");
        assert_eq!(id.tenant, "idp.unknown.example");
    }

    #[test]
    fn missing_tenant_claim_errors() {
        // Google issuer but no `hd` (personal account) → MissingClaim.
        let c = json!({"iss": "https://accounts.google.com", "sub": "117"});
        assert_eq!(normalize(&c), Err(SsoError::MissingClaim("hd")));
    }

    // Demonstrates the seam: adding an IdP is one impl, no core change.
    #[test]
    fn a_new_provider_is_one_impl() {
        struct Okta;
        impl SsoProvider for Okta {
            fn id(&self) -> &'static str {
                "okta"
            }
            fn matches_issuer(&self, iss: &str) -> bool {
                iss.ends_with(".okta.com")
            }
            fn extract(&self, c: &Value) -> Result<SsoIdentity, SsoError> {
                let iss = claim(c, "iss")?;
                let org = iss
                    .strip_prefix("https://")
                    .and_then(|h| h.split('.').next())
                    .ok_or(SsoError::MissingClaim("org"))?;
                Ok(SsoIdentity {
                    issuer: iss.into(),
                    tenant: org.into(),
                    subject: claim(c, "sub")?.into(),
                })
            }
        }
        let okta = Okta;
        assert!(okta.matches_issuer("https://slanchaai.okta.com"));
        let c = json!({"iss": "https://slanchaai.okta.com", "sub": "ok1"});
        assert_eq!(okta.extract(&c).unwrap().tenant, "slanchaai");
    }
}
