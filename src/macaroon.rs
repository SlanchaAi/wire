//! Speculative macaroon-style delegation scaffold.
//!
//! This module is deliberately not wired into CLI or relay paths. It proves the
//! consent-token shape can fit wire events if a future version chooses portable
//! scoped delegation over receiver-local policy.

use anyhow::{Result, anyhow, bail};
use base64::Engine as _;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Macaroon {
    pub root_key_id: String,
    pub identifier: String,
    pub caveats: Vec<Caveat>,
    pub signature: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum Caveat {
    Sender(String),
    Recipient(String),
    Kind(u32),
    Expiry(String),
    MaxRate { max: u32, window_secs: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyContext {
    pub sender: String,
    pub recipient: String,
    pub kind: u32,
    pub now: String,
    pub rate_count: Option<u32>,
}

impl Macaroon {
    pub fn mint(
        root_key_id: impl Into<String>,
        identifier: impl Into<String>,
        caveats: Vec<Caveat>,
        root_key: &[u8],
    ) -> Result<Self> {
        let root_key_id = root_key_id.into();
        let identifier = identifier.into();
        let signature = compute_signature(root_key, &identifier, &caveats)?;
        Ok(Self {
            root_key_id,
            identifier,
            caveats,
            signature,
        })
    }

    pub fn verify(&self, root_key: &[u8], context: &VerifyContext) -> Result<()> {
        let expected = compute_signature(root_key, &self.identifier, &self.caveats)?;
        if !constant_time_eq(self.signature.as_bytes(), expected.as_bytes()) {
            bail!("macaroon signature mismatch");
        }
        for caveat in &self.caveats {
            match caveat {
                Caveat::Sender(sender) if sender != &context.sender => {
                    bail!("sender caveat mismatch")
                }
                Caveat::Recipient(recipient) if recipient != &context.recipient => {
                    bail!("recipient caveat mismatch")
                }
                Caveat::Kind(kind) if kind != &context.kind => bail!("kind caveat mismatch"),
                Caveat::Expiry(expiry) => {
                    let expiry = parse_rfc3339(expiry)?;
                    let now = parse_rfc3339(&context.now)?;
                    if now > expiry {
                        bail!("expiry caveat elapsed");
                    }
                }
                Caveat::MaxRate { max, .. }
                    if context.rate_count.is_some_and(|count| count >= *max) =>
                {
                    bail!("max-rate caveat exceeded");
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub fn serialize(&self) -> Result<String> {
        let bytes = serde_json::to_vec(self)?;
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn deserialize(encoded: &str) -> Result<Self> {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|e| anyhow!("macaroon base64 decode failed: {e}"))?;
        Ok(serde_json::from_slice(&bytes)?)
    }
}

fn compute_signature(root_key: &[u8], identifier: &str, caveats: &[Caveat]) -> Result<String> {
    let mut sig = hmac_bytes(root_key, identifier.as_bytes())?;
    for caveat in caveats {
        let body = serde_json::to_vec(caveat)?;
        sig = hmac_bytes(&sig, &body)?;
    }
    Ok(hex::encode(sig))
}

fn hmac_bytes(key: &[u8], body: &[u8]) -> Result<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(key)?;
    mac.update(body);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn parse_rfc3339(s: &str) -> Result<time::OffsetDateTime> {
    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        .map_err(|e| anyhow!("invalid RFC3339 timestamp {s:?}: {e}"))
}

/// Constant-time comparison to avoid timing side-channels on signature checks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}
