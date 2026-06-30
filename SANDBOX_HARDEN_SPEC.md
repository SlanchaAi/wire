# wire — sandbox hardening + validation (build-loop SPEC)

Branch: `sandbox-harden` · Tier: **HIGH** (security · secret-on-disk · cross-machine/sandbox · build-loop invoked)
Started: 2026-06-29 · Iteration: 1

Goal (operator): get wire **working, security-hardened, and validated** inside sandbox classes —
**Docker**, **OpenShell**, **Traceforce scanner**, (etc). Driven through the build-loop (research →
plan → gate#1 → develop → in-situ test → gate#2 → loop).

## Research ground truth (verified, 2026-06-29)

- **Docker**: two Dockerfiles. Root `Dockerfile` = `rust:1.88-bookworm`→`debian:bookworm-slim`
  (glibc) = the Fly **relay** image. `deploy/Dockerfile` = `rust:1.88-alpine` musl static →
  `gcr.io/distroless/static-debian12:nonroot` ~7MB = the **user kit** (all roles via CMD).
  `deploy/README.md` advertises hardening flags `--read-only --tmpfs /tmp --cap-drop=ALL
  --security-opt=no-new-privileges --pids-limit=200`. **Unvalidated**: does deploy image build?
  do client/`wire mcp` roles run under those flags? `deploy/Dockerfile` installs
  `openssl-dev openssl-libs-static` but wire is **rustls** (Cargo.toml L57–69) → dead build deps.
- **OpenShell**: `landing/openshell-policy.sh` (served at `wireup.net/openshell-policy.sh`) whitelists
  github (install) + wireup.net (runtime) egress for a named sandbox. Allow-list ≈ current relay
  routes. **Drift**: relay now has `DELETE /v1/handle/claim/:nick` (unclaim) — **no DELETE allow** in
  policy; stale unused GET allows (`/v1/handle/*`, `/v1/slot/*/responder-health` is POST-only now).
  Hard limit = **wireup.net-only pin** (documented "single-relay at v0.5"; cross-relay pairing blocked).
- **Traceforce**: wire **not in Atlas registry** (0/608) → scanner sees it as unknown/unvetted MCP.
  Atlas scores 13 attributes (higher=riskier). wire's defining traits land HIGH: relay egress
  (Connection Security scored, not NA), persistent daemon (Execution Mode 90), **unsanitized inbound
  peer text → agent context (I/O Sanitization 90)**, write-capable messaging. wire's clean dim:
  Unsafe Local Commands (messaging only). Top real residual matches `docs/THREAT_MODEL.md` +
  the retracted-worm note in `docs/V0_13_2_PLATFORM_HARDENING.md`: **inbound-peer-input hygiene**.

## Workstreams + falsifiable criteria (the runnable checks)

**W1 — Docker (autonomous, in-situ now)**
- C1: `docker build -f deploy/Dockerfile -t wire:sandbox-test .` exits 0; image ≤ ~15 MB.
- C2: client roles run under full hardening flags: `docker run --read-only --tmpfs /tmp
  --cap-drop=ALL --security-opt=no-new-privileges --pids-limit=200 -v st:/data wire ...` for
  `wire --version`, `wire mcp` (handshake), `wire init`/`up`. Any flag wire can't take → documented + relaxed minimally.
- C3: containerized 2-node round-trip (`compose.yml` relay+daemon, or two client containers + relay)
  lands a message A→B (the hello-world-validate analog, in containers).
- Fixes: dead openssl deps; read-only/tmp write failures; deploy/README ↔ image drift.

**W2 — OpenShell (audit + static-fix; in-situ iff host available)**
- C4: policy allow-list is an exact superset of the routes `relay_client.rs` actually calls
  (programmatic diff vs `relay_server.rs` `.route(`). Add `DELETE /v1/handle/claim/:nick`; prune or
  justify stale allows. A test asserts policy⊇client-routes so it can't silently drift again.
- C5: (host available) install→init→pair→send under the policy; (no host) static proof + the C4 test.

**W3 — Traceforce (gated on operator: create API client + approve scanner download)**
- C6: wire-only sandbox (clean container, only wire MCP) scanned; capture wire's Atlas/Actual score +
  the Issues raised. Feeds W4.

**W4 — Harden (the substantive security win; cross-cutting)**
- C7: inbound peer-message hygiene — peer text is untrusted **data**, never auto-executed; verify the
  MCP instruction doctrine + add a guard/affordance so an agent can't be driven to irreversible action
  by peer say-so. (The dimension Traceforce I/O-Sanitization + THREAT_MODEL both flag.)

## Constraints (don't-do)
- Never test externally-visible mutation at real blast radius (no real-peer pairing as a "test"; use
  local relay / self round-trip / sandbox).
- No secrets in tree. Branch only (never main). Commit atomic.
- Don't rebuild what exists — OpenShell + Docker kits already ship; fix/validate, don't replace.

## Results (2026-06-29, iteration 1)

- **W1 Docker — VALIDATED in-situ.** C1: `deploy/Dockerfile` builds, **12.8 MB**
  distroless musl. C2: `wire --version`/`whoami`/`status` run under full hardening
  (`--read-only --tmpfs /tmp --cap-drop=ALL --no-new-privileges --pids-limit=200`).
  C3: `wire up` mints identity + binds relay + claims + starts daemon under those
  flags (writes only `/data`); container-to-container invite-flow round-trip
  **delivered + decrypted + signature-verified** (`"dec":true,"verified":true`).
- **W1 cleanup** — `deploy/Dockerfile`: dropped dead `openssl-dev/openssl-libs-static/
  pkgconfig` (wire is rustls); rebuild re-verified. `deploy/README.md` size claim
  corrected 7→13 MB.
- **W2 OpenShell — FIXED + GUARDED.** Added missing `DELETE /v1/handle/claim/*`
  allow (client calls it #247.1; policy had no DELETE → handle-release broke
  in-sandbox). New `tests/openshell_policy_coverage.rs` asserts policy ⊇ the routes
  relay_client calls — TDD red (failed on the miss) → green.
- **W3 Traceforce — BLOCKED (documented, not faked).** API client created; scoring
  model + scanner mechanism (scout-lite, public CloudFront binary, enrolls from
  `~/.traceforce`) fully mapped. Live scan needs the dashboard scanner package,
  which the Chrome-MCP download can't retrieve headlessly (no OS Save-dialog), and
  the API-client creds are a different realm (api.traceforce.co 401). UNBLOCK:
  operator downloads the package once → hand over `~/.traceforce` → run scout-lite
  in the wire-only container. Analytical read stands.
- **W4 Harden** — docs/SANDBOXES.md (validated recipe + invite-flow + scanner posture),
  wired from deploy/README + INSTALL. **E4 validator relax DEFERRED to operator**
  (trust-path change, maintainer-tracked design; invite flow is the working
  sandbox-relay path, so not shipped blind).

## Findings for operator
- **E4 / federation-handle-no-port**: `is_valid_domain` (src/pair_profile.rs:163)
  rejects any `:port` suffix (the colon fails the per-label char check); a bare
  single-label host (`nick@relay`) *passes* but fails later at DNS. Net: a custom-port
  sandbox/loopback relay can't be named in a `wire dial nick@host:port` handle.
  Recommend relaxing for local scope (V0_13_2 E4). Workaround shipped in docs: invite flow.

## E4 — loopback handle port support (iteration 2, branch e4-local-relay, operator-authorized 2026-06-29)

Tier HIGH (trust-path: federation handle domain validation). Goal: `wire dial nick@127.0.0.1:8771`
reaches a loopback relay. Scope = **loopback only** (the clean boundary: loopback ⟹ http is certain;
internal-DNS-name ⟹ http/https is a guess → those keep using the invite flow).

Design:
1. `is_valid_domain` (pair_profile.rs:163): split optional `:port` (rsplit_once); if port present,
   accept ONLY when host is loopback (`localhost` / 127.0.0.0/8); validate port 1..=65535 + host labels.
   Non-loopback + port stays REJECTED (preserves port-less public-handle convention). No-port unchanged.
2. New `relay_url_for_domain(domain)` → `http://` for loopback host, else `https://`. Replaces the 3
   `format!("https://{}", domain)` fallback sites (pair_profile.rs:266, cli/pairing.rs:1176, mcp.rs:1730).
3. `is_known_relay_domain` (pairing.rs:685): loopback = implicitly-known (suppress spurious phishing warn).

TDD contract (runnable check):
- parse_handle Ok: `n@127.0.0.1:8771`, `n@localhost:8771`, `n@127.0.0.1` (already), `n@wireup.net` (unchanged).
- parse_handle Err: `n@evil.com:1337`, `n@wireup.net:8443` (non-loopback+port), `n@127.0.0.1:0`,
  `n@127.0.0.1:99999`, `n@:8771`, `n@127.0.0.1:abc`.
- relay_url_for_domain: `127.0.0.1:8771`→http, `localhost:9`→http, `wireup.net`→https (public unchanged).
- in-situ: `wire dial n@127.0.0.1:<port>` to a local relay → pairs + message lands.

Gate#1 (design persona review): security + protocol/compat — DISPATCHED. Key risk under review:
SSRF via `tool_add`/auto-dial on untrusted input hitting a loopback port (note: wire already GETs
well-known on any operator-chosen domain; loopback is the sensitive subset, response not returned to attacker).

## Gate ledger
- Gate#1 (plan): folded into gate#2 (de-scoped to MEDIUM — no trust-path code change).
- Gate#2 (built-thing review over diff): **PASS after fixes.** 3 parallel Sonnet reviewers
  (security · Rust+Dockerfile · docs-completeness). 0 BLOCKER, 0 MAJOR on code. Folded in:
  2 MAJOR doc overclaims (write-path /data; validator "single-label") → fixed; guard host-blind
  false-cover (github `/*` covering `/healthz`) → host-filtered; 2 dead policy allows pruned
  (GET /v1/handle/*, GET /v1/slot/*/responder-health); /v1/handles de-required; sanity cases +
  source-comment fixes. Reviewer conflict (false-pass: rev1 no / rev2 yes) resolved EMPIRICALLY
  — `glob('/*','/healthz')==true` ⇒ rev2 correct ⇒ host filter applied.
- fmt + clippy -D warnings + test gate: re-run after fixes (see below).
- Open BLOCKERs: none (W3 live-scan is operator-unblock, not a code blocker)
