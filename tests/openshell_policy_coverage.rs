//! Drift guard: the OpenShell egress policy (`landing/openshell-policy.sh`)
//! must allow every relay route a sandboxed `wire` client actually calls.
//!
//! Why this exists: the policy is a hand-maintained allow-list of
//! `host:port:METHOD:/path` rules. When the client grows a new call (or changes
//! a method), the policy silently goes out of date and the new call is refused
//! *inside the sandbox only* — invisible to every test that runs against a local
//! relay with no egress firewall. This caught a real miss: the client calls
//! `DELETE /v1/handle/claim/:nick` (release a claimed handle, #247.1) but the
//! policy only allowed GET/POST, so handle-release was broken in-sandbox.
//!
//! Contract, not auto-derivation: `REQUIRED_ROUTES` is the set of *runtime*
//! relay routes the wire binary issues against the relay domain. These call
//! sites live across `src/relay_client.rs`, `src/daemon_stream.rs` (the SSE
//! stream), and `src/cli/pairing.rs` (invite register / short-URL resolve).
//! Parsing format!-built URLs out of Rust source would be brittler than an
//! explicit list (see the regex-discipline rule), so it is maintained by hand:
//! if you add a relay call in any of those files, add it here AND to the
//! `wire_runtime` rule in landing/openshell-policy.sh — this test is the
//! reminder. It asserts coverage (policy ⊇ required), not minimality, so extra
//! allows in the policy don't fail it.

/// The relay domain the runtime policy rule governs. Allows for OTHER hosts in
/// the script (the github.com / *.githubusercontent.com *install* rules) are
/// deliberately ignored: they are scoped to their own endpoints in the real
/// OpenShell engine, so they must not be allowed to "cover" a relay route here.
/// (Without this scoping, the github CDN's `GET:/*` allow would false-cover
/// `GET /healthz` — `glob_matches("/*", "/healthz") == true`; see sanity test.)
const RELAY_HOST: &str = "wireup.net";

/// (method, a concrete example path the wire binary hits at runtime against the
/// relay). Install-time routes (github.com / *.githubusercontent.com) are a
/// separate policy rule and out of scope — this is relay-runtime only.
const REQUIRED_ROUTES: &[(&str, &str)] = &[
    ("GET", "/healthz"),
    ("POST", "/v1/slot/allocate"),
    ("POST", "/v1/events/abc123"),
    ("GET", "/v1/events/abc123"),
    ("GET", "/v1/events/abc123/stream"), // src/daemon_stream.rs
    ("GET", "/v1/slot/abc123/state"),
    ("POST", "/v1/slot/abc123/responder-health"),
    ("POST", "/v1/pair"),
    ("POST", "/v1/pair/abandon"),
    ("GET", "/v1/pair/pid123"),
    ("POST", "/v1/pair/pid123/bootstrap"),
    ("POST", "/v1/handle/claim"),
    ("DELETE", "/v1/handle/claim/somenick"), // #247.1 — the route the miss broke
    ("POST", "/v1/handle/intro/somenick"),
    ("GET", "/.well-known/agent-card.json"),
    ("GET", "/.well-known/wire/agent"),
    ("POST", "/v1/invite/register"), // src/cli/pairing.rs
    ("GET", "/i/tok123?format=url"), // src/cli/pairing.rs cmd_accept resolves short URLs via ?format=url
                                     // NOTE: GET /v1/handles is intentionally NOT required — it's the web
                                     // phonebook listing (landing/*.html), not a call the wire binary makes. The
                                     // policy may still allow it for discovery parity, but it is not a hard
                                     // requirement, so omitting it here lets an operator tighten the policy
                                     // without this test false-failing.
];

/// Parsed `--add-allow 'host:port:METHOD:/path'` entry. `path` may end with `*`.
struct Allow {
    host: String,
    method: String,
    path: String,
}

fn parse_policy_allows(script: &str) -> Vec<Allow> {
    let mut out = Vec::new();
    for line in script.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("--add-allow '") else {
            continue;
        };
        let Some(rule) = rest
            .strip_suffix("' \\")
            .or_else(|| rest.strip_suffix('\''))
        else {
            continue;
        };
        // host:port:METHOD:/path  — path is the remainder (it has no ':').
        let parts: Vec<&str> = rule.splitn(4, ':').collect();
        if parts.len() != 4 {
            continue;
        }
        out.push(Allow {
            host: parts[0].to_string(),
            method: parts[2].to_string(),
            path: parts[3].to_string(),
        });
    }
    out
}

/// `*` in an allow path matches a single path segment (`[^/]*`), matching
/// OpenShell's glob semantics; the rest must match literally, fully anchored.
fn glob_matches(pattern: &str, path: &str) -> bool {
    fn rec(p: &[u8], s: &[u8]) -> bool {
        match p.first() {
            None => s.is_empty(),
            Some(b'*') => {
                // consume zero+ non-slash chars from s, then match the rest
                let mut i = 0;
                loop {
                    if rec(&p[1..], &s[i..]) {
                        return true;
                    }
                    if i < s.len() && s[i] != b'/' {
                        i += 1;
                    } else {
                        return false;
                    }
                }
            }
            Some(&c) => !s.is_empty() && s[0] == c && rec(&p[1..], &s[1..]),
        }
    }
    rec(pattern.as_bytes(), path.as_bytes())
}

#[test]
fn openshell_policy_covers_every_client_route() {
    let script = include_str!("../landing/openshell-policy.sh");
    let allows = parse_policy_allows(script);

    // Canary: a known relay-runtime allow must parse, or the parser silently
    // broke (a count floor would pass on already-parsed unrelated rules).
    assert!(
        allows
            .iter()
            .any(|a| a.host == RELAY_HOST && a.method == "GET" && a.path == "/healthz"),
        "parser found no `{RELAY_HOST}:GET:/healthz` allow — parse_policy_allows likely broke"
    );

    let mut uncovered = Vec::new();
    for (method, path) in REQUIRED_ROUTES {
        // Only allows scoped to the relay host can cover a relay route — an
        // allow for a different host is enforced against that host in OpenShell.
        let covered = allows
            .iter()
            .any(|a| a.host == RELAY_HOST && a.method == *method && glob_matches(&a.path, path));
        if !covered {
            uncovered.push(format!("{method} {path}"));
        }
    }

    assert!(
        uncovered.is_empty(),
        "openshell-policy.sh is missing allow rules for relay routes the client calls:\n  {}\n\
         Add the matching `--add-allow '{RELAY_HOST}:443:METHOD:/path'` line(s) to the wire_runtime rule.",
        uncovered.join("\n  ")
    );
}

#[test]
fn glob_matcher_sanity() {
    assert!(glob_matches("/v1/handle/claim/*", "/v1/handle/claim/bob"));
    assert!(glob_matches("/v1/slot/*/state", "/v1/slot/abc/state"));
    assert!(glob_matches("/healthz", "/healthz"));
    // zero-char `*` (trailing-star matches an empty final segment):
    assert!(glob_matches("abc*", "abc"));
    // single-segment `*` must NOT span a slash:
    assert!(!glob_matches("/v1/events/*", "/v1/events/abc/stream"));
    assert!(!glob_matches("/v1/pair/*", "/v1/pair/pid123/bootstrap"));
    assert!(!glob_matches("/v1/handle/claim/*", "/v1/handle/claim"));
    assert!(!glob_matches("/healthz", "/healthzz"));
    // empty-pattern base cases:
    assert!(glob_matches("", ""));
    assert!(!glob_matches("", "x"));
    // WHY the parser must filter by host: a `/*` allow DOES cover `/healthz`,
    // so a non-relay-host `GET:/*` rule would false-cover a relay route if the
    // coverage check didn't scope to RELAY_HOST.
    assert!(glob_matches("/*", "/healthz"));
}
