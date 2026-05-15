# Task [i] — Agent-aware root handler + /agent + /llms.txt

**Status:** queued post-v0.5.9. Not in the codex/v0.5.9-batch (that one
shipped + merged before this task was scoped). Pick up in v0.5.10 or
v0.6 batch.

**Branch:** new branch, name `codex/agent-aware-root` or similar.
**Target:** single commit.

## Why

When an agent (Claude Code, Cursor, curl/wget, python-requests, etc.)
fetches `https://wireup.net`, it gets the human landing HTML. Useless to
the agent. Want: agent sees the AGENT.md install + usage doc; human sees
the landing.

Also publishes wire's existence to the emerging `/llms.txt` discovery
convention (Jeremy Howard proposal; some AI tools auto-fetch).

## Scope

Three routes + one content-negotiation tweak:

| Route | Always serves | MIME |
|---|---|---|
| `/agent` | AGENT.md | `text/plain; charset=utf-8` |
| `/llms.txt` | AGENT.md | `text/plain; charset=utf-8` |
| `/llms-full.txt` | AGENT.md + README.md concatenated | `text/plain; charset=utf-8` |
| `/` | landing (human) OR AGENT.md (agent) | depends |

Root path content-negotiates based on `Accept` + `User-Agent` headers.

## Files to touch

### `src/relay_server.rs`

Add new handlers near the existing `landing_*` handlers (around line
625+):

```rust
const AGENT_MD: &[u8] = include_bytes!("../AGENT.md");
const README_MD: &[u8] = include_bytes!("../README.md");

async fn agent_md() -> impl IntoResponse {
    (
        StatusCode::OK,
        [
            (axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (axum::http::header::CACHE_CONTROL, "public, max-age=300"),
        ],
        AGENT_MD,
    )
}

async fn agent_md_full() -> impl IntoResponse {
    // AGENT.md + README.md back-to-back. Cheap to compute on each
    // request; both files are already in-binary.
    let mut buf = Vec::with_capacity(AGENT_MD.len() + README_MD.len() + 2);
    buf.extend_from_slice(AGENT_MD);
    buf.extend_from_slice(b"\n\n");
    buf.extend_from_slice(README_MD);
    (
        StatusCode::OK,
        [
            (axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (axum::http::header::CACHE_CONTROL, "public, max-age=300"),
        ],
        buf,
    )
}

/// Sniff request headers to decide if the caller is an agent (curl,
/// wget, python-requests, Claude Code, Cursor, any non-browser client)
/// vs a browser. Browsers always send Accept: text/html (mixed); agents
/// typically send Accept: */* or text/plain.
fn looks_like_agent(headers: &HeaderMap) -> bool {
    let accept = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let ua = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // 1. If Accept explicitly asks for HTML, treat as browser.
    if accept.contains("text/html") {
        return false;
    }

    // 2. Common non-browser UA prefixes.
    let agent_ua_markers = [
        "curl/", "Wget/", "python-requests", "reqwest", "Go-http-client",
        "okhttp", "node-fetch", "Claude", "Cursor", "Anthropic",
        "OpenAI", "GPTBot", "ChatGPT",
    ];
    if agent_ua_markers.iter().any(|m| ua.contains(m)) {
        return true;
    }

    // 3. Accept missing or */* with a non-browser-looking UA → agent.
    if accept.is_empty() || accept == "*/*" {
        return true;
    }

    false
}
```

Update the existing `landing_index` handler to accept the request
headers and content-negotiate:

```rust
async fn landing_index(headers: HeaderMap) -> axum::response::Response {
    static INDEX_HTML: &[u8] = include_bytes!("../landing/index.html");
    if looks_like_agent(&headers) {
        return agent_md().await.into_response();
    }
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
        INDEX_HTML,
    )
        .into_response()
}
```

Register the new routes in `Router::new()` (around line 346):

```rust
.route("/agent", get(agent_md))
.route("/llms.txt", get(agent_md))
.route("/llms-full.txt", get(agent_md_full))
```

### `.dockerignore`

Add `!AGENT.md` next to the existing `!README.md` exception so the
build context contains both files for `include_bytes!`:

```
*.md
!README.md
!AGENT.md
```

(Check whether README.md is currently in the build context — it
already needs to be for `include_bytes!("../README.md")` to compile.
If `!README.md` already lives in `.dockerignore`, add `!AGENT.md`
right beside it.)

## Tests

In `tests/relay.rs`, add:

```rust
#[tokio::test]
async fn root_serves_landing_html_to_browser_accept() {
    let dir = fresh_state_dir();
    let base = spawn_relay(dir).await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{base}/"))
        .header(reqwest::header::ACCEPT, "text/html,application/xhtml+xml")
        .header(reqwest::header::USER_AGENT, "Mozilla/5.0 (Macintosh)")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let ct = resp.headers().get("content-type").unwrap().to_str().unwrap();
    assert!(ct.starts_with("text/html"));
}

#[tokio::test]
async fn root_serves_agent_md_to_curl_ua() {
    let dir = fresh_state_dir();
    let base = spawn_relay(dir).await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{base}/"))
        .header(reqwest::header::USER_AGENT, "curl/8.4.0")
        .header(reqwest::header::ACCEPT, "*/*")
        .send()
        .await
        .unwrap();
    let ct = resp.headers().get("content-type").unwrap().to_str().unwrap();
    assert!(ct.starts_with("text/plain"));
    let body = resp.text().await.unwrap();
    assert!(body.contains("AGENT.md"), "expected AGENT.md preamble");
}

#[tokio::test]
async fn agent_route_always_serves_plain_text() {
    let dir = fresh_state_dir();
    let base = spawn_relay(dir).await;
    let resp = reqwest::get(format!("{base}/agent")).await.unwrap();
    assert!(resp.headers().get("content-type").unwrap().to_str().unwrap()
        .starts_with("text/plain"));
}

#[tokio::test]
async fn llms_txt_serves_agent_md() {
    let dir = fresh_state_dir();
    let base = spawn_relay(dir).await;
    let body = reqwest::get(format!("{base}/llms.txt"))
        .await.unwrap().text().await.unwrap();
    assert!(body.contains("AGENT.md") || body.contains("wire") );
}

#[tokio::test]
async fn llms_full_concatenates_agent_and_readme() {
    let dir = fresh_state_dir();
    let base = spawn_relay(dir).await;
    let body = reqwest::get(format!("{base}/llms-full.txt"))
        .await.unwrap().text().await.unwrap();
    // README always says "magic-wormhole" near the top
    assert!(body.contains("magic-wormhole"));
    // AGENT.md always says "read this first if you are an AI agent"
    assert!(body.contains("read this first if you are an AI agent"));
}
```

## Verification (manual smoke)

After Fly auto-deploys:

```bash
# Browser-like — gets landing
curl -s -H 'Accept: text/html' -H 'User-Agent: Mozilla/5.0' https://wireup.net/ | head -c 60
# expect: <!doctype html>... 

# Agent-like — gets AGENT.md
curl -s -H 'Accept: */*' -H 'User-Agent: curl/8.4.0' https://wireup.net/ | head -c 60
# expect: # AGENT.md — read this first...

# Explicit /agent — always AGENT.md
curl -s https://wireup.net/agent | head -c 60

# Explicit /llms.txt — always AGENT.md
curl -s https://wireup.net/llms.txt | head -c 60

# Explicit /llms-full.txt — AGENT.md + README.md
curl -s https://wireup.net/llms-full.txt | wc -c
# expect: bigger than AGENT.md alone
```

## Acceptance

- All 5 tests pass.
- All 5 manual smokes return expected output post-deploy.
- `cargo test --release` full suite still green.
- `cargo fmt --all --check` clean.
- `cargo clippy --release` clean.
- Docker image still builds (verify locally: `docker build -t wire-relay-test .`).
- Binary size grew by ~6 KB (AGENT.md + a small bit of code).

## Non-goals

- **Don't fingerprint specific AI agent UAs by company** beyond the generic
  list above. We're not trying to give different content to Claude vs
  GPT — just "agent vs browser."
- **Don't add a "machine-readable manifest" endpoint** (e.g. structured
  JSON describing wire). The protocol already has
  `/.well-known/agent-card.json` for A2A and `/.well-known/wire/agent`
  for wire-native. This task is about onboarding text, not structured
  capability discovery.
- **Don't move install instructions out of AGENT.md.** AGENT.md is the
  source of truth; the new routes serve it as-is.
- **Don't add a `?format=...` query param dispatcher** — too many ways
  to do the same thing. Three explicit routes + one content-negotiated
  root.
- **Don't change `/` behavior for ambiguous Accept headers** (e.g., bare
  `Accept: text/plain` from a browser test). Default = landing when
  truly ambiguous; agents should hit `/agent` explicitly if they want
  AGENT.md without sniff fragility.

## Commit message

```
[i] agent-aware root: serve AGENT.md to non-browser clients

Adds three explicit text/plain routes (/agent, /llms.txt,
/llms-full.txt) plus content negotiation on the root path. Agents
(curl, wget, python-requests, Claude/Cursor/GPT, etc.) fetching
https://wireup.net/ now receive the AGENT.md install + usage doc as
text/plain. Browsers still get the human landing HTML.

Routes:
- /agent          — always AGENT.md (text/plain)
- /llms.txt       — always AGENT.md (per Jeremy Howard's emerging
                    /llms.txt convention)
- /llms-full.txt  — AGENT.md + README.md concatenated
- /               — content-negotiates on Accept + User-Agent

Header sniff: Accept text/html → landing; UA matches a known non-
browser marker (curl, wget, python-requests, reqwest, Go-http-client,
okhttp, node-fetch, Claude, Cursor, Anthropic, OpenAI, GPTBot,
ChatGPT) → AGENT.md; ambiguous → landing (humans should still see
the human page on edge cases).

- src/relay_server.rs: agent_md handler, agent_md_full handler,
  looks_like_agent header sniff, /agent + /llms.txt + /llms-full.txt
  routes, content negotiation in landing_index
- .dockerignore: !AGENT.md to keep it in build context for
  include_bytes!
- tests/relay.rs: 5 new tests covering content negotiation +
  explicit-route behavior

No version bump on its own — fold into the next batch's [final]
commit (target v0.5.10 or v0.6.0).
```
