# RFC-001 Amendment: SSO-attestation channel (organization tier)

**Amends:** [RFC-001 v2](./0001-identity-layer.md) (merged as PR #76, squash `a6b4163`)
**Status:** Accepted — ratified by @laulpogan 2026-05-28 (direction blessed; AC-SSO1–5). **2026-06-16 (push-to-1.0):** the 90-day kill-criterion timer is **disarmed** and SSO is promoted to a **supported 1.0 feature** (it's the enterprise day-one hook). The wire-side contract — `ORG_VERIFIED` tier, `org_attestation.via` provenance, DNS-TXT floor (§A) — is **frozen**; the IdP-integration *config* (JWKS handling, OIDC claims→org mapping, tenant config) carries the normal deprecation window since it has external-dependency churn. See §H. <!-- Draft | Discussion | Accepted | Rejected | Implemented | Superseded -->
**Tracking:** [#73](https://github.com/SlanchaAi/wire/issues/73)
**Author:** swift-harbor (Copilot CLI agent, paired w/ @dthoma1)
**Date:** 2026-05-28
**Target:** v0.14 (rides RFC-001 v2; not a v0.13.x patch)
**Question this answers:** How does a wire peer prove it speaks for an organization without re-running SPAKE2+SAS for every operator-pair, when the organization already trusts an external OIDC/SSO identity provider?

---

## TL;DR

- Add an **SSO-attestation channel** to the bilateral tier ladder defined in RFC-001 v2 §3. Reaches `ORG_VERIFIED` without operator click-through when *both* the DNS-TXT issuer-binding (§A) and a session-key-signed OIDC attestation (§B) verify.
- DNS-TXT floor stays the offline-degrade baseline: `_wire-org.<org-domain> TXT "did=<org_did>; sso_iss=<oidc-issuer-url>; sso_tenant=<tenant-id>"`. SSO attestation *layers on top* — never substitutes for the DNS binding.
- **No new top-level `kind` values.** All SSO control-plane intents ride existing `kind=1001` (claim) with body-discriminated `t` field. Verified against `src/pull.rs::is_known_kind()` and `src/signing.rs::kinds()` — minting a new kind black-holes pre-v0.14 cursors. RFC-002's lesson, applied.
- **Token replay closed.** OIDC tokens travel wrapped in a session-key-signed envelope binding `{receiver_did, nonce, iat, oidc_token, issuer, tenant}`. A hostile receiver cannot forward to a third org-mate (the O5 splice, SSO flavor).
- **Bilateral SAS invariant preserved.** SSO never reaches `VERIFIED`. Promotion to `VERIFIED` still requires bilateral SPAKE2+SAS, exactly as in v2 §3.

---

## Motivation

RFC-001 v2 §3 defines `ORG_VERIFIED` as a tier reached when both peers' agent-cards carry mutually-verifying `org_did` + `member_cert` claims under a roster the receiver pins. That works for orgs that operate a wire-native roster signer. It does *not* answer: **what about orgs already running an OIDC/SSO IdP (Okta, Entra ID, Workspace, Auth0, Authentik) whose source of truth for "is this person an employee of this org" is the IdP, not a separate wire roster?**

Today such orgs face a choice: (a) stand up a parallel wire-roster ceremony, duplicating employee onboarding/offboarding plumbing they already run in the IdP; or (b) accept that every new operator session re-runs SPAKE2+SAS with every org-mate, defeating the friction-reduction goal of RFC-001 §1.

This amendment is choice (c): **let the IdP attest, on a per-session basis, that the operator behind a wire session is the IdP's known principal at a known org/tenant.** Wire still pins the org's DNS binding, still preserves the bilateral SAS invariant for `VERIFIED`, still runs its own roster epochs — SSO only collapses the *first-contact* friction inside an already-trusted org.

---

## Design

### §A. DNS-TXT issuer + tenant binding (offline floor)

The org publishes:

```
_wire-org.<org-domain> TXT "did=did:wire:org:<32hex>; sso_iss=https://login.acme.com/realms/wire; sso_tenant=acme-prod; v=1"
```

A personal-tier operator (`0003-per-company-relays.amendment-deployment-tiers.md` — single human across N sessions, wire-rooted signing-key-first identity) publishes the SAME record name with their `op_did` instead. SSO and tenant fields are optional for personal-tier:

```
_wire-org.<personal-domain> TXT "did=did:wire:op:operator-<32hex>; v=1"
```

- `did=` — wire DID anchor (Ed25519). Accepts both `did:wire:org:<32hex>` (organizational anchor, RFC-001 v2 §1) and `did:wire:op:operator-<32hex>` (personal-tier operator anchor, deployment-tiers amendment). **Parsers MUST dispatch on the `did:wire:op:` vs `did:wire:org:` prefix** to select the verification path: `org_did` resolves against the receiver's per-org membership-cert chain (`identity::verify_member_cert`); `op_did` resolves directly against the inline `op_pubkey` on the peer's card (`identity::verify_op_cert`). Both paths verify fully offline against pinned material — no resolver, no registry on the pairing hot path. **Record name `_wire-org.<domain>` is used for both DID kinds** (no per-DID record-name split); the org-vs-op semantic lives entirely in the `did=` field value.
- `sso_iss=` — OIDC issuer URL. Receiver fetches `<iss>/.well-known/openid-configuration` exactly once per onboarding, caches the JWKS URI + alg list. **Optional for personal-tier** (SSO is additive convenience, never the identity root — see deployment-tiers amendment §"Identity — most-secure default").
- `sso_tenant=` — IdP tenant/realm identifier. Required when `sso_iss=` is present because most IdPs serve multiple tenants from one issuer. Omit both `sso_iss=` and `sso_tenant=` for non-SSO operators / orgs.
- `v=` — version tag; receivers MUST reject unknown `v` (value-level rule).

**Field-additive evolution clarification (back-ported from RFC-003 §2, #130-comment-by-dthoma1).** Parsers MUST ignore fields they don't understand at a known `v` (field-level rule, distinct from the value-level rule above). `v` bumps ONLY when an existing field's semantics change OR a field is dropped. Adding a new field (e.g. RFC-003's `relay=` for per-company-relay binding; hypothetical future `sso_iss_kid=` for IdP key pinning) does NOT require a `v` bump. This makes `v=1` field-additive evolvable — receivers tolerate forward-compatible field additions; senders MAY use a higher `v` only when receivers would mis-verify under v=1 rules.

**Why DNS-TXT under the operator's domain (not Anthropic's discovery doc, not a wire registry):** the DNS record is the operator's *unilateral declaration* of "I own this domain, and the SSO IdP at `sso_iss` speaks for this org on wire". It's the same trust root operators already use for DKIM, DMARC, SPF. No third party (including wireup.net) gains the ability to silently rebind an org's SSO.

**Cache semantics:** receiver pins the TXT record + JWKS on first sight. Subsequent JWKS rotations are reconciled via §C. A TXT-record change (different `sso_iss` or `sso_tenant`) is an alarm-grade event — receiver MUST drop to `UNTRUSTED` and require operator re-confirmation.

### §B. OIDC token → ORG_VERIFIED mapping (with replay binding)

When a wire peer wants to assert `ORG_VERIFIED` to another peer via the SSO channel, it:

1. Acquires a fresh OIDC ID token from its IdP for the operator's session (interactive on first login; refresh-token thereafter).
2. Wraps the token in a **session-key-signed envelope**:

```json
{
  "t": "sso_attest",
  "receiver_did": "did:wire:<peer-session-did>",
  "nonce": "<32 byte random, b64>",
  "iat":   1716938400,
  "oidc_token": "<the JWT>",
  "issuer":  "https://login.acme.com/realms/wire",
  "tenant":  "acme-prod"
}
```

3. Signs the envelope with its wire **session key** (the same key used for every other wire event) and ships it as a `kind=1001` claim with body `t: "sso_attest"`.

**Receiver verification order (any failure = silent drop, no fingerprintable event):**

1. Envelope signature valid under sender's session public key.
2. `receiver_did` equals receiver's own session DID. (Closes O5 splice — a hostile receiver who forwards the envelope to a third org-mate fails this check.)
3. `nonce` not seen before for this sender (small bounded cache, e.g. 1k entries with LRU); `iat` within ±60s of receiver's clock.
4. JWT signature valid under JWKS pinned at §A onboarding (or via §C refresh).
5. JWT `iss` matches the `sso_iss` from the §A DNS-TXT record for the sender's claimed `org_did`. **Comparison is byte-equal against the pinned `sso_iss` value (case-sensitive, no trailing-slash normalization, no URL-canonicalization).** Prefix-match (e.g. accepting `https://login.acme.com/realms/wire/sub-realm` because `https://login.acme.com/realms/wire` is pinned) is non-conformant and MUST fail this check. Case-insensitive comparison is non-conformant. Trailing-slash normalization is non-conformant. The IdP-adapter trait surface in v0.15 (`Verifier::verify_iss(&JwtClaims, &PinnedSsoIss)` or equivalent named method per the adapter shape settled in #92) MUST implement byte-equal comparison; any normalization happens at *pin* time (when `sso_iss=` is written into the §A DNS-TXT record), never at *verify* time. (AC-SSO-strict-iss per #137 + paul directive on #92.)
6. JWT tenant claim matches `sso_tenant` from §A.
7. JWT `exp` > now; `iat` not in future.

If all pass: receiver upgrades the sender's tier to `ORG_VERIFIED` and adds an entry to the peer's card surface: `org_attestation: { via: "sso", iss, exp }`.

**What's deliberately NOT in the envelope:** the operator's IdP `sub`, name, email, or any PII. The receiver-visible record is `(org_did, op_pseudonym, exp)`. See §B.1 for `op_pseudonym`.

#### §B.1. Operator pseudonym (privacy)

`op_pseudonym = blake2b(sub || org_did || "wire-op-pseudo-v1")` truncated to 32 hex.

- Stable per `(operator, org)` pair across all the operator's wire sessions inside that org — this is **the filtering payoff** (receivers can implement per-operator policy like "auto-pair Alice from acme-prod, manual-confirm everyone else"). Intra-org session correlation IS the feature.
- Different operator OR different org → different pseudonym. No cross-org linkage.
- For orgs with low-entropy `sub` (e.g. small employee count, sequential numeric IDs), the org MAY publish `sso_secret_hint` in a separately-signed `org.json` and receivers compute `op_pseudonym = HMAC(org_secret, sub || org_did)` instead. Opt-in.
- High-privacy operators may opt into per-receiver pseudonyms (folds into O7 from RFC-001 v2). Default is single per-org pseudonym; the privacy/filter tradeoff is the org's call, not wire's.

### §C. JWKS pinning + offline degrade

JWKS is fetched once at §A onboarding and cached. Refresh policy:

- **Soft refresh:** if a §B verification fails on signature with a `kid` not in the cache, *and* `cache.last_refresh < now - 5min`, fetch `<iss>/.well-known/openid-configuration` and JWKS. Retry verification.
- **Soft refresh failure (network unreachable, IdP 5xx):** receiver enters **offline degrade**. SSO attestations that *only* the unrefreshed JWKS would have verified are *not* accepted. But the peer's previously-acquired `ORG_VERIFIED` state from a valid prior attestation **persists** as long as the DNS-TXT record at §A still resolves and its `did=` still matches. New peers in the same offline window cannot reach `ORG_VERIFIED` via SSO until JWKS is reachable again; they fall back to manual SAS or the wire-native roster path (RFC-001 v2 §3).
- **Hard refresh:** triggered by an §E alarm event. Bypasses the soft-refresh rate limit. Receiver drops cached JWKS, fetches fresh, and re-verifies all currently-pinned `ORG_VERIFIED`-via-SSO peers; any that no longer verify under the new JWKS drop to the DNS-TXT floor.

**Why this shape:** offline degrade preserves the live mesh during transient IdP outages (common) without permitting *new* SSO trust to be minted against a stale JWKS (the IdP-rotated-out-a-compromised-key case). The hard-refresh trigger from §E is the recovery path for legitimately fast key rotations.

### §D. Token expiry vs roster epoch reconciliation (folds O6)

OIDC tokens have short `exp` (typically minutes to hours). Wire's roster epoch advances on org-side membership changes (operator added/removed). These two clocks need not align.

**Body-discriminated intent on `kind=1001` (claim):**

```json
{
  "t": "sso_epoch_advance",
  "org_did":   "did:wire:org:<32hex>",
  "epoch":     17,
  "iat":       1716938400,
  "expires":   1716942000
}
```

Semantics:

- The org's wire-native roster signer emits `sso_epoch_advance` events at most once per epoch change. Receivers caching prior SSO-attested peers MUST re-check those peers' attestations against the new epoch within `expires - iat` (typically 1h).
- If a peer's last `sso_attest` was issued *before* the epoch advance, the receiver MUST require a fresh attestation before the peer re-asserts on a new operation; until then the peer stays at `ORG_VERIFIED` but is marked `attestation_stale: true` on the card surface.
- A peer who fails to produce a fresh attestation within the grace window (org-configurable, default 24h) drops to the DNS-TXT floor.

**`kind=1001` carrier rationale:** kind=1001 (`claim`) already exists in `src/signing.rs::kinds()` and has no semantic conflict with the SSO control-plane meaning. Body intents the receiver doesn't recognize (e.g., a v0.15 peer emitting `t: "sso_epoch_revoke"` to a v0.14 peer that only knows `sso_epoch_advance`) are cursor-PAST gracefully with a warning logged — they do NOT cause `TRANSIENT_REJECT`. This is the architectural lesson RFC-002 documents and `tests/pull_unknown_kind.rs` pins (for the *unknown kind* failure mode that body-discrimination avoids).

### §E. JWKS-rotation alarm + compromised-IdP threat (T21)

When a wire peer detects an *unexpected* JWKS state change for a pinned issuer — specifically:

1. A previously-pinned `kid` disappears from the JWKS endpoint without a prior `sso_epoch_advance` precedent, OR
2. JWKS endpoint TLS thumbprint changes (only checked if the operator pinned `sso_root_thumbprint` in their §A onboarding), OR
3. JWKS publishes a `kid` that contradicts the operator's locally-pinned `kid_thumbprint` for that issuer (opt-in defense-in-depth).

…it emits a **body-discriminated intent on the same `kind=1001` carrier** as §D:

```json
{
  "t": "sso_jwks_alarm",
  "org_did": "did:wire:org:<32hex>",
  "issuer": "https://login.acme.com/realms/wire",
  "kid_change": { "removed": ["kid-old-1"], "added": ["kid-new-1"] },
  "iat": 1716938400,
  "evidence": { ... }
}
```

Semantics:

- **Receivers do NOT auto-promote the alarm to a trust mutation.** It's an *advisory*. Receivers MUST hard-refresh JWKS (§C) and log the alarm for the operator's review.
- The operator's UI surface MAY show "your org's SSO key rotated unexpectedly" with a single click to (a) accept and re-pin, or (b) drop all SSO-attested peers to `UNTRUSTED` pending manual reverification.
- An adversarial peer emitting forged `sso_jwks_alarm` events causes at most a JWKS hard-refresh on receivers; it cannot cause silent demotion or promotion. The cost ceiling is "extra HTTPS request to the IdP".

**Why kind=1001 (NOT kind=1102):** kind=1102 (`trust_revoke_key`) is reserved for trust *mutation*. No 1102 handler exists today, but the moment a real `trust_revoke_key` handler lands and parses kind=1102 bodies, an unknown body intent (`t: "sso_jwks_alarm"`) on that kind would land in a code path with trust-mutating authority. One generic carrier (`kind=1001`) for the *whole* SSO control plane keeps the blast radius bounded to claim-handler semantics, never trust-mutation semantics. (Per @coral-weasel's review of issue #73, 2026-05-28.)

**Compromised-IdP threat (T21, new):** if the IdP itself is compromised — adversary controls JWKS, mints valid tokens for any `sub` — the SSO channel is structurally bypassable. The mitigation is *not* in wire (we can't defeat a compromised root of trust); it's:

1. **Detection:** the alarm channel surfaces unexpected rotations to operators promptly. Time-to-detect is the key metric, not time-to-prevent.
2. **Containment:** SSO attestation NEVER reaches `VERIFIED`. An adversary who fully owns the IdP can mint `ORG_VERIFIED` for arbitrary peers, but cannot reach the bilateral-SAS-required `VERIFIED` tier. The blast radius of a compromised IdP is "anything an ORG_VERIFIED peer can do," not "anything a VERIFIED peer can do."
3. **Recovery:** operator response to a confirmed compromised IdP is to publish a new DNS-TXT with a new `sso_iss` (or remove the `sso_iss=` field entirely and revert to wire-native roster). Receivers detect the TXT change and drop all SSO-attested peers under the old issuer to `UNTRUSTED`.

This is consistent with how SPIFFE/SPIRE, GitHub OIDC, and Sigstore treat compromised IdP roots: detect-and-rotate, never silent-recovery.

---

## §F. Acceptance criteria

**Architectural invariants (MUST hold across all of §A–§E):**

- **No new top-level `kind` values are minted for SSO control plane.** All SSO control intents (epoch_advance, jwks_alarm) ride `kind=1001` (claim) with body-discriminated `t` field. Verified against `src/signing.rs::kinds()` and `src/pull.rs::is_known_kind()`. Body intents the receiver doesn't know are cursor-PAST gracefully (warning logged), NOT `TRANSIENT_REJECT`.
- **No SSO body intents ride `kind=1102`** (`trust_revoke_key`). 1102 stays reserved for its eventual trust-mutating handler. Reviewed and pinned by @coral-weasel.
- **Bilateral SPAKE2+SAS invariant unchanged.** SSO reaches `ORG_VERIFIED`; the `VERIFIED` tier still requires SAS. No code path promotes SSO-attested peers to `VERIFIED`.
- **DNS-TXT floor is the offline anchor.** A peer with a valid DNS-TXT but unreachable IdP retains its prior `ORG_VERIFIED` state; new SSO-mediated `ORG_VERIFIED` is gated on JWKS reachability.

**Falsifiable acceptance tests (each MUST have a test that fails before the implementation lands and passes after):**

- **AC-SSO1:** A peer with valid DNS-TXT + valid OIDC envelope reaches `ORG_VERIFIED` on first contact without any operator click-through. The local operator's per-org auto-pair opt-in (RFC-001 v2 §3) still gates user consent.
- **AC-SSO2:** A peer with valid DNS-TXT but expired-cache JWKS (offline window) retains `ORG_VERIFIED` via DNS-TXT floor; SSO attestation is dropped from the card surface; the bilateral pair persists.
- **AC-SSO3:** A forged OIDC token (invalid JWKS signature) is silently rejected; receiver's prior trust state for that peer is unchanged; no event is emitted that could be used as a side-channel fingerprint.
- **AC-SSO4:** A `sso_jwks_alarm` event (`kind=1001` with body intent `t: "sso_jwks_alarm"`) emitted by a v0.14 peer to a pre-v0.14 peer does NOT block the receiver's cursor. (Pinned by an integration test that boots a pre-v0.14 binary against a v0.14 emitter.)
- **AC-SSO5:** Token replay by a hostile receiver — receiver A forwards a valid envelope from sender X to a third org-mate B — fails envelope verification at receiver B on the `receiver_did` mismatch. (Pinned by a unit test.)

## §G. Open coordination questions (handed to slate-lotus)

Three questions for slate-lotus's owning side of #73 (filtering surface + project A/B fork). Coral has relayed these with her leanings; this records the canonical version:

1. **Tier name in filter DSL:** keep `ORG_VERIFIED` as a single tier with a `peer.org_attestation` provenance subfield (`{ via: "sso" | "dns" | "roster", … }`), versus splitting into `ORG_VERIFIED_VIA_SSO` / `ORG_VERIFIED_VIA_DNS` as separate tier values. Recommendation: keep the tier, separate provenance. Filtering can still discriminate via `peer.org_attestation.via == "sso"`.
2. **T21 alarm-window policy hook location:** global config, per-org config, or per-filter-rule. Affects where the §C grace-window + §E alarm-debounce timers are configured.
3. **Filter-expression shape for "fan-out project:X to same-tenant ORG_VERIFIED":** the filter DSL needs to express both project-tag selectors and org-attestation predicates; the §C JWKS hard-refresh + grace-window mechanics produce cache-invalidation events that the filter compiler should subscribe to. Need slate's preferred event shape so §C degrade announcements are emitted as compatible cache-invalidations.

## §H. Kill criterion → superseded: SSO is a supported 1.0 feature

**Resolved for 1.0 (2026-06-16, "push to 1.0" pass).** The original criterion auto-reverted the OIDC channel in v0.15 if it produced zero `ORG_VERIFIED` mediations within 90 days of v0.14. That armed version-pinned self-destruct can't cross a 1.0 freeze (`ROAD_TO_1.0.md` §5) — but the *fix is not to scope SSO out*. Org-verification is the **enterprise day-one hook** (it leads the enterprise pitch); enterprises must be able to build on a stable contract, so SSO is **promoted into the supported 1.0 surface**, split by stability:

- **Frozen in 1.0 (no-break guarantee):** the DNS-TXT floor (§A), the **`ORG_VERIFIED` tier**, and the **`org_attestation.via` provenance** subfield. A consumer can program against these.
- **Supported, but evolves under the deprecation policy:** the **IdP-integration config** — JWKS endpoint handling, OIDC claims→`org` mapping, tenant/issuer config shape (§B–§E). This carries external-dependency churn (IdP quirks, claim conventions), so its *shape* may change across 1.x **through a deprecation window** (announce → warn → ≥1 MINOR & ≥90 days), never a silent break. The *capability* (SSO-mediated `ORG_VERIFIED`) is a 1.0 feature, not experimental.
- **Removed:** the 90-day auto-revert timer. Keep/cut is now an ordinary evidence-gated deprecation decision, not a one-shot armed version gate.

Net effect: 1.0 ships SSO as a real, supported feature with a frozen wire-side contract; only the inherently-churny IdP plumbing is iterable, and even that only via the documented deprecation window. No surprise revert, no experimental asterisk on the enterprise hook.

## References

- **RFC-001 v2** (this amendment's parent): `docs/rfc/0001-identity-layer.md`, merged as PR #76 (squash `a6b4163`).
- **RFC-002** (architectural lesson on body-discriminated intents): `docs/rfc/0002-token-efficient-comms.md`.
- **Issue #73** (SSO design discussion): https://github.com/SlanchaAi/wire/issues/73 — first-cut comment `#issuecomment-4561182957`, correction comment `#issuecomment-4561227125`.
- **Kind registry**: `src/signing.rs::kinds()` (canonical list); `src/pull.rs::is_known_kind()` (the cursor-blocking gate); `tests/pull_unknown_kind.rs` (the adversarial pin).
- **Reviewer:** @coral-weasel — flagged the 1102→1001 carrier collision risk; resolved Q1 (pseudonym design) and Q2 (project A/B fork: stays §6 unsigned routing for v0.14).
