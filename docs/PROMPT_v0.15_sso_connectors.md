# Hydrated prompt — build full SSO/identity **connectors** for wire v0.15

*Paste this into a fresh Claude session in `~/Source/wire` to drive the v0.15 SSO-connector buildout. Self-contained: assumes the agent has nothing in conversation context, only the repo + the references below.*

> **This supersedes the earlier "adapters" framing.** A *connector* is end-to-end (flow runner + token lifecycle + group/role enumeration + SCIM 2.0 ingest + deprovisioning hooks + verify); an *adapter* is just the verify half. Building only adapters leaves operators wedged: no refresh, no revoke, no ejection on departure, no live role data. This prompt builds the full thing.

---

## You are

A senior Rust engineer extending wire's RFC-001 identity layer with concrete end-to-end SSO/identity-provider **connectors**. v0.14.0 has shipped the offline-minimal identity loop (`op_did` + `org_memberships[]` with inline pubkeys, `Tier::OrgVerified`, `wire enroll` CLI, receive-side auto-pin under `org_policies.json`). #100 shipped only the *normalization* half of the SSO surface (`src/sso_provider.rs::SsoProvider::normalize`). **This prompt builds out the v0.15 full-connector surface: per-provider OIDC/SAML/SCIM integrations that reach `ORG_VERIFIED` without a wire-roster ceremony, by leaning on an IdP the org already runs — and that keep that trust live as roles change and members leave.**

Read these in order before touching code:

1. `docs/rfc/0001-identity-layer.md` — the ratified base + the "Implementation status (as-built, v0.14)" note (#106).
2. `docs/rfc/0001-identity-layer.amendment-sso.md` — the **normative spec for this work**. Everything below is implementation of §A (DNS-TXT issuer binding) + §B (session-signed OIDC attestation envelope) + §C (token-replay closure) + AC-SSO1–5, *extended* to the connector lifecycle (refresh / revoke / deprovision).
3. `src/sso_provider.rs` — the shipped trait + four normalizers (Google `hd`, Azure AD `tid`, Keycloak realm, Generic). Your connectors chain ONTO these.
4. `src/identity.rs` (`sign_did_cert` / `verify_op_cert` / `verify_member_cert`) — the offline cert primitives. Your SSO attestation must be verifiable the same way: a single Ed25519 sig over a canonical envelope, inline pubkey on the card, no resolver on the pairing hot path.
5. Memory notes: `feedback_heavy_e2e_subprocess_contention.md` (e2e gating pattern), `feedback_wire_send_shell_metachars.md` (`-F file` / `--body-file` only), `feedback_gate_exit_not_through_pipe.md` (real exit-code gates), `project_wire_event_kind_carrier_rule.md` (no new event kinds).

## Definitions (canon — read once)

- **Connector** — full integration with an IdP/SSO provider. Comprises: (1) auth-flow runner, (2) token lifecycle (issue / refresh / revoke / expire / rotate), (3) bind-time + receive-time verify, (4) group/role enumeration, (5) optional SCIM 2.0 user-lifecycle ingest, (6) deprovisioning hook, (7) CLI surface, (8) card-emit + receive-side decision branch. **Everything below the trait foundation is per-connector.**
- **Adapter** — just the verifier (a strict subset of a connector). #100 + the adapter-only framing covered this. Connectors absorb adapter functionality and add the rest.
- **Identity Provider (IdP)** — owns the user lifecycle (Microsoft Entra ID, Okta, Google Workspace, AWS Cognito, JumpCloud, OneLogin, GitHub Orgs, GitLab Groups). Connector MAY do SCIM ingest + group enum.
- **SSO frontend** — federates one or more IdPs (Auth0, Keycloak-as-broker, AWS IAM Identity Center). Connector proxies tenant + group claim through the frontend.
- **Hybrid** — both. Okta + OneLogin + JumpCloud sit here.
- **Deprovision-monotone-eject** — when an IdP signals "user gone" (SCIM 410 GONE, IdP-side revoke, refresh fail, OIDC `token_revoked`), the connector MUST eject the membership claim from the operator's card and re-republish. Receivers that pinned at `ORG_VERIFIED` via that membership see their trust ladder drop on next refresh. No retries-forever; idempotent best-effort + audit.

## Hard constraints (read twice, do not relax)

- **Offline-self-certifying on the pairing hot path.** Receivers MUST verify a peer's SSO attestation with material already inline on the card or pinned locally. No live JWKS fetch, no live OIDC discovery, no live DNS lookup during `maybe_consume_pair_drop`. The IdP signature verifies once at *bind time*; what travels in the card is a wire-native, replay-bound cert the receiver checks against a pinned issuer pubkey (the §A DNS-TXT-anchored `sso_iss_pubkey`).
- **`Tier::OrgVerified` ceiling holds.** SSO attestation *never* mints `VERIFIED`. Bilateral SAS (SPAKE2 invite path) or the `wire add` / `pair-accept` gesture remains the ONLY VERIFIED path. Property-tested in `tests/trust_ceiling_prop.rs` — extend it.
- **Replay closure (the O5/SSO splice).** Every per-session SSO attestation MUST bind `{receiver_did, nonce, iat, oidc_token_hash, issuer, tenant}` under the operator's session key. A hostile receiver MUST NOT be able to forward the attestation to a third org-mate. Test with `tests/sso_attestation_replay_prop.rs` (you create this).
- **No new event kinds.** All control-plane intents ride existing `kind=1001` with a body-discriminated `t` field (`t: "sso_attest"` / `"sso_attest_ack"` / `"sso_deprovision"`). See memory `project_wire_event_kind_carrier_rule.md`. Verify against `src/pull.rs::is_known_kind` and `src/signing.rs::kinds()`.
- **DNS-TXT floor is required.** Per §A, before any SSO attestation can be trusted, the receiver MUST have pinned `_wire-org.<domain> TXT "did=<org_did>; sso_iss=<issuer>; sso_tenant=<tenant>; sso_iss_pubkey=<base64>; v=1"`. If DNS-TXT pin is missing for the claimed org → fall through to default-deny pending. The DNS check happens at **bind/refresh time on a long cadence** (default 6h, min 1h, max 24h per AC3), never on the pairing hot path.
- **Token rotation is mandatory** for any refresh-token-bearing OIDC connector. Refresh tokens MUST be stored encrypted at rest (libsodium `secretbox` over the operator's session key); refresh failure → drop the binding to a new `Binding::PendingReauth` state, do NOT silently re-auth (IdP-side phish vector). Surface the dropped binding in `wire enroll sso status` and a lock-screen toast keyed `sso-reauth:<provider>:<tenant>`.
- **Deprovision is monotone-eject and idempotent.** SCIM 410 GONE / refresh-permanent-fail / OIDC `token_revoked` → eject membership claim → re-republish card → audit-log. On persistent eject failure (e.g. card write blocked), audit-log + alarm; do NOT loop. The eject signal also carries an outbound `kind=1001, t: "sso_deprovision"` body so paired peers can drop their pin proactively (operator MAY ignore; the receive-side trust-ladder drop happens on natural card refresh regardless).
- **Per-tenant rate limits.** OIDC discovery / JWKS / SCIM polling cached per-tenant with defaults: JWKS 1h, SCIM 15m (configurable up to 1h, below 15m → CI fails the connector-config test), OIDC discovery 6h. Token refresh on its own TTL schedule (typically refresh at TTL/2).
- **Group/role enumeration is bind-time + scheduled-refresh, never pairing-time.** The wire card carries the bound roles inline; refreshing the binding refreshes the roles.

## Providers to build (full-connector surface)

Each row below is **one full connector**. Acceptance criteria are the same per row (see "What 'done' looks like" below).

### Identity providers (own user lifecycle)

| Provider | Auth flow | Tenant claim | Tokens | Groups/roles | SCIM 2.0 | Deprovision signal |
|---|---|---|---|---|---|---|
| **Microsoft Entra ID** (Azure AD) | OIDC PKCE | `tid` (tenant GUID) | id+access+refresh | Graph `/me/memberOf` | yes (Entra → Wire SCIM) | SCIM 410 / refresh fail |
| **Okta** | OIDC PKCE | issuer URL or org URL | id+access+refresh | Groups API | yes | SCIM 410 / refresh fail |
| **Google Workspace** | OIDC PKCE | `hd` (hosted domain) | id+access+refresh | Admin SDK `/groups` | yes (via Cloud Identity) | Admin SDK suspension flag |
| **AWS Cognito User Pools** | OIDC PKCE | pool id (from `iss`) | id+access+refresh | `cognito:groups` claim | no (no SCIM) | `AdminDisableUser` event via EventBridge bind |
| **AWS IAM Identity Center** (ex AWS SSO) | OIDC PKCE | instance ARN | id+access | Identity Store API | yes (Identity Store SCIM) | SCIM 410 |
| **JumpCloud** | OIDC PKCE | org id | id+access+refresh | `/api/groups` | yes | SCIM 410 |
| **OneLogin** | OIDC PKCE | subdomain | id+access+refresh | `/api/2/groups` | yes | SCIM 410 |
| **Keycloak** (self-hosted IdP) | OIDC PKCE | realm in `iss` path | id+access+refresh | Admin REST `/groups` | yes | SCIM 410 |
| **Authentik** (self-hosted) | OIDC PKCE | `aud` or custom claim | id+access+refresh | `/api/v3/core/groups` | yes (v2023.10+) | SCIM 410 |
| **Ory Kratos + Hydra** (self-hosted) | OIDC PKCE (Hydra) | issuer URL | id+access+refresh | Kratos identity traits | no | Kratos identity delete webhook |

### SSO frontends (federate to other IdPs)

| Provider | Auth flow | Tenant claim | Tokens | Groups/roles | SCIM 2.0 | Deprovision signal |
|---|---|---|---|---|---|---|
| **Auth0** | OIDC PKCE | `aud` + namespaced claim | id+access+refresh | Mgmt API `/users/<id>/roles` | yes (Auth0 → Wire SCIM) | SCIM 410 / refresh fail |
| **Keycloak-as-broker** | OIDC PKCE | realm + upstream IdP id | id+access+refresh | Admin REST `/groups` | yes | SCIM 410 |

### Social / dev login (limited org tenancy)

| Provider | Auth flow | Org tenancy | Tokens | Groups/roles | SCIM | Deprovision signal |
|---|---|---|---|---|---|---|
| **GitHub** | OAuth + OIDC-shaped UserInfo | Org membership via Org-admin token | access+refresh | Org Membership API + Team API | no | Org-admin webhook `membership.removed` |
| **GitLab.com / self-hosted** | OIDC PKCE | `groups_direct` claim | id+access+refresh | `/api/v4/groups` | yes (premium+) | SCIM 410 |

### Enterprise SAML

| Provider | Auth flow | Tenant | Tokens | Groups/roles | SCIM | Deprovision |
|---|---|---|---|---|---|---|
| **Microsoft ADFS** | SAML 2.0 SP-init POST | issuer URI | SAML assertion (no refresh) | `Role` claim | no | Assertion no-renew |
| **PingFederate** | SAML 2.0 SP-init POST | issuer URI | SAML assertion | `memberOf` attr | no | Assertion no-renew |
| **Shibboleth** | SAML 2.0 SP-init POST | `Issuer` element | SAML assertion | `eduPersonScopedAffiliation` | no | Assertion no-renew |

### Catch-alls

- **Generic OIDC** — any RFC 6749 / OpenID Connect Core 1.0 provider with explicit `issuer`, `aud`, optional `tenant_claim`. Default fallback. Already partially normalized as `src/sso_provider.rs::Generic`.
- **Generic SAML** — any SAML 2.0 IdP with operator-configured tenant XPath / attribute mapping.
- **Generic SCIM 2.0** — RFC 7644 client that any of the above can compose into for user-lifecycle ingest where the operator gives a SCIM endpoint + bearer token.

**Out of scope (explicitly):** Discord / Slack / X-style social login. Those have no useful org-tenancy primitive that maps to `Tier::OrgVerified`; operators wanting "I'm in this Discord" should use the federation roster path, not SSO.

## What "done" looks like per connector

For each connector you MUST produce:

1. **Auth-flow runner** in `src/connectors/<provider>/runner.rs` implementing one of:
   - `OAuthRunner` (OIDC PKCE): launches `webbrowser`, loopback redirect on `http://127.0.0.1:<random-port>/sso/callback`, no public callback. Closes the tab on success.
   - `SamlRunner` (SAML SP-initiated POST): generates `AuthnRequest`, opens browser, receives the POSTed `SAMLResponse` on loopback.
2. **Token lifecycle** in `src/connectors/<provider>/tokens.rs` — `issue` (called from runner), `refresh` (with rotation), `revoke` (best-effort POST to revocation endpoint), `expire` (delete from disk + re-emit card without claim), `rotate` (scheduler-driven every TTL/2). Refresh tokens encrypted via libsodium `secretbox` keyed by the session key.
3. **Verifier impl** in `src/connectors/<provider>/verify.rs` implementing trait `SsoVerifier { fn verify_at_bind_time(token: &str, expected: &SsoBinding, ctx: &BindContext) -> Result<SsoIdentity, SsoError>; fn verify_at_receive_time(envelope: &SsoAttestation, pinned: &PinnedIssuer) -> Result<SsoIdentity, SsoError>; }`. Bind-time may do I/O via `BindContext`; receive-time MUST be pure-over-`pinned`.
4. **Group/role enumeration** in `src/connectors/<provider>/groups.rs` — calls the provider's groups API, maps to a normalized `wire::OrgRole { id: String, name: String }`. Cached per-tenant with 15m cadence.
5. **SCIM 2.0 ingest** in `src/connectors/<provider>/scim.rs` (where the provider supports it) — polls `/scim/v2/Users?filter=meta.lastModified gt <last_poll>` every 15m. On `meta.delete = true` or 410 GONE → fire the deprovision hook for the affected operator.
6. **Deprovisioning hook** registered with the scheduler:
   ```rust
   fn on_deprovision(&self, user_did: &Did, reason: DeprovisionReason) -> EjectAction;
   ```
   Default impl: drop the org membership claim from the operator's card, re-republish the card, emit `kind=1001, t: "sso_deprovision"` to paired peers, audit-log to `~/.config/wire/sso_audit.jsonl`. Idempotent.
7. **CLI** — extend the v0.15-adapter scaffold:
   - `wire enroll sso bind <provider> --org <org_did>` — runs the auth flow + binds.
   - `wire enroll sso refresh <provider> --org <org_did>` — force-refreshes tokens + roles.
   - `wire enroll sso revoke <provider> --org <org_did>` — operator-initiated revoke + eject.
   - `wire enroll sso status [--all]` — lists all bindings, their tier (`OK` / `PENDING_REAUTH` / `EXPIRED`), last refresh, next refresh, role count.
8. **Test fixtures**:
   - Mock IdP in `tests/fixtures/mock_<provider>.rs` (HTTPS-emulating, deterministic JWKS, deterministic SCIM responses). Runs in-process behind `tokio::net::TcpListener` on `127.0.0.1:0`. Mock survives CI's `--test-threads=1`.
   - Real-IdP nightly integration test gated `#[ignore = "needs-real-idp"]`. Operator runs with `WIRE_REAL_IDP_<PROVIDER>_{ISSUER,CLIENT_ID,CLIENT_SECRET,TENANT}=...` env vars. Document the env shape in `docs/connectors/<provider>.md`.
9. **At least 8 unit tests, 3 integration tests (against mock IdP), 1 replay-closure prop test** per connector. Required cases:
   - Happy bind (valid token + matching tenant → OK).
   - Expired token → rejected.
   - Tenant mismatch → rejected.
   - Missing tenant claim → rejected (default-deny).
   - Refresh happy (rotation succeeds, new refresh token stored encrypted).
   - Refresh rotation (server rotates RT, client persists new RT, old RT is wiped).
   - Refresh failure → binding moves to `PendingReauth` + toast fires.
   - Revoke happy (POST succeeds → eject membership → re-emit card).
   - Deprovision via SCIM 410 → eject within 1 poll interval + audit-log entry.
10. **Card-emit wiring + receive-side branch** — extend `OrgMembership` with `sso_attest: Option<String>` and `roles: Option<Vec<OrgRole>>` (schema bump to `v3.3`; v3.3 must stay backward-compatible with v3.2 readers via `#[serde(default, skip_serializing_if = "Option::is_none")]`). Receive-side: `pair_decision::PairAction::AutoOrgVerifiedViaSso { org_did, issuer, roles }`.
11. **Per-connector README** at `docs/connectors/<provider>.md` covering: required IdP-side setup (app registration, redirect URI, required scopes), operator env vars for the nightly test, gotchas. The implementing agent reads these when bringing up real-IdP tests; future operators read them when onboarding.

## Process

- **TDD.** Per connector: write the verifier test FIRST against the mock IdP, watch it fail, then write the impl. Then add lifecycle tests (refresh, revoke, deprovision) in the same TDD loop. Mirror `tests/e2e_identity.rs` for the offline-chain integration tests.
- **Persona critique BEFORE and AFTER every PR** (security / systems-design / SRE / DX / **deprovision-drill**). Surface BEFORE in the PR description; surface AFTER in a PR comment after CI green. The deprovision-drill persona walks: a member leaves the org → SCIM 410 → wire ejects → card re-emits → all receivers' trust ladders drop on next refresh. Show this in the PR description as a sequence diagram (ASCII is fine).
- **Gate REAL exit codes** (`fmt=$? clippy=$? lib=$? test=$?` — never pipe through `tail` then `&& echo OK`; see memory `feedback_gate_exit_not_through_pipe.md`).
- **One connector per PR.** Adapter-only verifier-only providers MAY share a PR for closely related ones, but full connectors (auth flow + scim + groups) get their own PR.
- **Use `-F file` / `--body-file` for ALL `git commit` messages and `gh` PR bodies.** Backticks / parens / `$()` get shell-evaluated otherwise; doc: `feedback_wire_send_shell_metachars.md`. Bites twice per session if you forget.
- **CI is `--test-threads=1`** since #111 — your heavy real-process tests can be regular (not `#[ignore]`d) as long as they're robust. Local detached-pair-style flake = environmental on busy boxes; verify isolated.
- **Real-IdP credentials NEVER touch CI secrets.** Operator runs nightly integration with `WIRE_REAL_IDP_<PROVIDER>_*` env. CI only runs the mock-IdP fixture tests.
- **Each PR is REVIEW-gated** (`@dthoma1` for RFC-001 semantics, `@WILLARDKLEIN` for the three-guarantee audit). Trust-adjacent; do not self-merge without explicit operator authorization per PR.

## Order to ship (suggested)

1. **PR #1 — Trait foundation** (`OAuthRunner` / `SamlRunner` / `SsoVerifier` / `ScimIngest` / `Deprovisioner`) + **Generic OIDC connector** + **Generic SAML connector** + mock IdP fixture + replay-closure property test + `wire enroll sso bind / refresh / revoke / status` CLI scaffold + `docs/connectors/_overview.md`. This is the spine. Everything else is per-provider.
2. PR #2 — Microsoft Entra ID (full connector + SCIM).
3. PR #3 — Google Workspace (full connector + Admin SDK groups; Cloud Identity SCIM if available).
4. PR #4 — Okta (full connector + SCIM).
5. PR #5 — Auth0 (full connector + Mgmt-API roles + SCIM).
6. PR #6 — Keycloak IdP + Keycloak-as-broker (full connectors; share Admin REST helper).
7. PR #7 — AWS Cognito + AWS IAM Identity Center (share AWS SDK helper).
8. PR #8 — JumpCloud + OneLogin (SCIM-heavy shapes; share helper).
9. PR #9 — GitHub + GitLab (hybrid: OAuth + org-membership / `groups_direct`).
10. PR #10 — Authentik + Ory (Hydra + Kratos) (self-hosted OIDC).
11. PR #11 — SAML enterprise: ADFS + PingFederate + Shibboleth + Generic SAML (XML-DSig).
12. PR #12 — Receive-side `AutoOrgVerifiedViaSso` wiring + v3.3 schema bump (carries inline `sso_attest` + `roles`) + cross-connector integration tests.

## Anti-patterns (instant-reject in review)

- **Live JWKS / OIDC-discovery / DNS / Graph / GitHub-API call inside `maybe_consume_pair_drop`** — breaks the offline invariant. Receiver MUST verify against pinned material.
- **A new top-level event `kind` for SSO traffic** — black-holes pre-v0.14 cursors. Use `kind=1001` + `t` discriminator (see `project_wire_event_kind_carrier_rule` for the carrier rule).
- **Promoting any SSO path to `Tier::Verified`** — bilateral SAS invariant. Re-read `tier_order`; never derive `Ord`.
- **Persisting `id_token` / `access_token` raw on disk** — store the *binding cert* (a wire-signed envelope) and discard the IdP token after bind. PII / replay-target reduction.
- **Storing refresh tokens unencrypted** — must be libsodium-`secretbox`'d under the operator session key. Encryption-at-rest is non-negotiable.
- **Silent re-auth on refresh failure** — IdP phish vector. On refresh fail, drop the binding to `PendingReauth`, surface in `wire enroll sso status` + lock-screen toast. Operator initiates re-auth.
- **SCIM polling at <15m cadence** — IdP rate-limit DOS vector. Default 15m, configurable up to 1h. Below 15m → CI fails the connector-config test.
- **Deprovisioning that retries forever** — on persistent eject failure, audit-log + alarm; do NOT loop. Idempotent best-effort.
- **Trusting `iss` alone as the org discriminator** — multi-tenant providers (Entra, Okta, Keycloak) require the tenant claim (`tid` / realm / org URL). Bind verifies BOTH.
- **Skipping the DNS-TXT pin** — §A floor is non-negotiable; without it any IdP-issued token claims any org.
- **Coupling connectors to a specific HTTP client / async runtime in trait surface** — the trait is pure-over-data; HTTP lives in the `BindContext` impl.
- **Mixing real-IdP credentials into CI secrets** — credentials live in the operator's `WIRE_REAL_IDP_<PROVIDER>_*` env, never repo-secrets.
- **A connector with no deprovisioning hook** — connector PR is incomplete without it. Operators that bind via Okta and have an employee leave MUST see the membership eject within one SCIM poll interval.

## Stop conditions / when to ask

- **Schema bump (v3.3)** — confirm shape with `@dthoma1` before defining card fields.
- **Adding the wireup-registry `/v1/sso/bind` endpoint** — out of scope for connectors; stub-and-defer.
- **Any decision that touches the receive-side trust ladder** — open as REVIEW PR (not self-merge); request `@WILLARDKLEIN`'s three-guarantee audit per #101 precedent.
- **Adding a new connector trait method** — coordinate before defining (trait surface affects every connector).
- **Long-running scheduler integration** — if you need a long-running scheduler service for SCIM polls / token rotation, open a discussion before coding; `wire monitor` is the candidate host but trust-adjacent.
- **A provider's tenant claim is genuinely ambiguous** (e.g. Auth0 with no standard org claim) → open a discussion comment on the v0.15 tracking issue before committing to a tenancy rule.

## What you start with

- `main` at the v0.14.x tail (see `git log`). The notify-mode PR #112 may or may not be merged; either is fine — your work is orthogonal.
- The shipped `SsoProvider` trait + four normalizers in `src/sso_provider.rs`. Extend, don't duplicate.
- `tests/e2e_identity.rs` for the offline-chain integration pattern. Mirror.
- A clean `cargo test -- --test-threads=1` baseline (post-#111). Keep it that way.
- `wire 0.14.0` binary self-reports correctly; you're building 0.15 features but do NOT bump Cargo until the full v0.15 surface is review-clean AND you have explicit operator authorization for the release.
- If a previous SSO-adapter prompt artifact exists in the repo, **this connector prompt supersedes it**. The adapter-only verifier framing under-delivers; build the connector surface end-to-end.

Start with PR #1: trait foundation + Generic OIDC + Generic SAML + mock IdP fixture + replay-closure property test + `wire enroll sso bind / refresh / revoke / status` CLI scaffold + `docs/connectors/_overview.md`. Persona-critique BEFORE (security + systems-design + SRE + DX + **deprovision-drill**). Write the trait tests first. Ship it.
