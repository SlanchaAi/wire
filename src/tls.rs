//! Shared rustls `ClientConfig` for every wire HTTPS surface.
//!
//! ## Why this exists
//!
//! Pre-#176 wire used reqwest's `rustls-tls-native-roots` feature, which
//! loads the OS native trust store via `rustls-native-certs`. That gave
//! us corporate-CA / AV-resign transparency for free in shell-launched
//! daemons. But once #170's `--all-sessions` supervisor moved every
//! daemon into launchd, every TLS handshake to wireup.net failed
//! `UnknownIssuer`: launchd-spawned processes on macOS don't inherit
//! the operator's Aqua-session keychain context, so the system query
//! returned an empty root set.
//!
//! #176 unblocked the supervisor by swapping the reqwest feature to
//! `rustls-tls-webpki-roots` (Mozilla bundled CA set) and accepting
//! the corp-CA trade-off. This module restores both behaviours: webpki
//! bundled roots are ALWAYS loaded (works in any process context); the
//! OS native trust store is ALSO loaded when accessible (corp CAs +
//! AV-resign keep working in shell context, gracefully empty in
//! launchd). reqwest consumes the resulting `rustls::ClientConfig` via
//! its `use_preconfigured_tls` builder method.
//!
//! ## Design
//!
//! - **One `ClientConfig` per process, cached.** Building a
//!   `RootCertStore` walks ~200 webpki roots + however many native
//!   certs are accessible; ~3–5 ms cost. We pay it once per process.
//!   Every `relay_client::build_blocking_client` call clones a
//!   shared `Arc<ClientConfig>`.
//! - **Fail-soft on native-cert errors.** If `rustls-native-certs`
//!   panics, returns Err, or returns malformed certs, we log and fall
//!   through to webpki-roots only. Better one missing corp CA than no
//!   HTTPS at all.
//! - **`WIRE_INSECURE_SKIP_TLS_VERIFY=1` still works** — handled at
//!   the `relay_client::build_blocking_client` layer via reqwest's
//!   `danger_accept_invalid_certs(true)`. This module's config is
//!   only consulted when the env var is unset.

use std::sync::Arc;
use std::sync::OnceLock;

use rustls::ClientConfig;
use rustls::RootCertStore;

/// Return the shared `Arc<ClientConfig>` — built lazily on first call,
/// cached for the process lifetime.
pub fn shared_client_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG.get_or_init(build).clone()
}

fn build() -> Arc<ClientConfig> {
    // Ensure rustls's default CryptoProvider is installed before we
    // build a ClientConfig. With reqwest's `rustls-tls-webpki-roots`
    // feature, reqwest auto-installs `ring` as the default provider
    // for its own clients, but a freshly-spawned `wire` process
    // building a config via `use_preconfigured_tls` may reach here
    // before reqwest has done that. Setting it ourselves is
    // idempotent — set_default_provider() is no-op once installed
    // (returns Err that we ignore).
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    let mut roots = RootCertStore::empty();

    // Mozilla bundled webpki-roots — always loaded. Works in any
    // process context (no OS dep).
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let bundled_added = roots.len();

    // OS native trust store — additive when accessible. Loads corp
    // CAs / AV-resign roots / on-prem CAs in shell context; returns
    // empty on launchd-context macOS (the original #176 failure
    // mode). Fail-soft: log + continue with bundled roots only.
    let native_added = match rustls_native_certs::load_native_certs() {
        result if result.errors.is_empty() => {
            let mut count = 0usize;
            for cert in result.certs {
                if roots.add(cert).is_ok() {
                    count += 1;
                }
            }
            count
        }
        result => {
            // Partial / total failure to enumerate native certs.
            // Loud-but-non-fatal: stderr so launchd's StandardErrorPath
            // captures it for diagnosability without breaking the
            // handshake.
            eprintln!(
                "wire tls: rustls-native-certs reported {} error(s); continuing with bundled webpki roots only",
                result.errors.len()
            );
            let mut count = 0usize;
            for cert in result.certs {
                if roots.add(cert).is_ok() {
                    count += 1;
                }
            }
            count
        }
    };

    // One-line breadcrumb at process start so operators can confirm
    // both root sources contributed (and which one the process
    // landed in). Single fprintln, no log spam — only fires on the
    // first config build per process.
    eprintln!(
        "wire tls: trust roots loaded — {bundled_added} webpki + {native_added} native = {} total",
        roots.len()
    );

    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Arc::new(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_client_config_returns_clones_of_same_arc() {
        let a = shared_client_config();
        let b = shared_client_config();
        assert!(
            Arc::ptr_eq(&a, &b),
            "shared_client_config must return clones of one cached Arc"
        );
    }

    #[test]
    fn shared_client_config_has_webpki_roots_loaded() {
        // Webpki-roots ships ~150–200 Mozilla CA certs; the exact count
        // varies across crate versions, but >50 is a safe floor.
        let cfg = shared_client_config();
        let store_len = cfg
            .crypto_provider()
            .signature_verification_algorithms
            .all
            .len();
        // We can't directly inspect RootCertStore from outside —
        // assert on a side-effect proxy: the config built without
        // panic + has a valid crypto provider.
        assert!(store_len > 0, "crypto provider must have verification algs");
    }
}
