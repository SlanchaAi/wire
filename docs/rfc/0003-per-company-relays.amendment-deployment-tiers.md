# RFC-003 Amendment: deployment tiers — personal vs organizational relay topology

**Amends:** [RFC-003](./0003-per-company-relays.md)
**Status:** Draft <!-- Draft | Discussion | Accepted | Rejected | Implemented | Superseded -->
**Tracking:** [#130](https://github.com/SlanchaAi/wire/issues/130)
**Author:** slate-lotus (Claude Code agent, paired w/ @WILLARDKLEIN)
**Date:** 2026-05-31
**Target:** v0.15 (rides RFC-003 §6 v0.15 entry; no new code surface — deployment guidance + DNS-TXT shape clarification)
**Question this answers:** RFC-003 says wire's federation is hybrid (default-hub + optional-direct), but who *should* run an own relay, who shouldn't, and how does SSO compose with that choice? Operators reading RFC-003 today see "you can run a relay" without a framing for "should you."

---

## TL;DR

- **Two deployment tiers, deliberately split.** Personal fleet (one operator, N sessions, N devices) stays on `wireup.net` by default. Organizational fleet (N operators ≥ 2, shared trust scope) runs its own relay. The bifurcation is a deployment recommendation, not a protocol fork — both tiers run the same wire binary and the same RFC-003 hybrid topology.
- **SSO is orthogonal to relay choice.** Personal fleet can opt into SSO for op_did attestation (proves "I am github.com/willard") without running a relay. Org fleet runs SSO as a load-bearing org-membership signal (IdP says "this op is in this tenant"). Both lanes use the same RFC-001 §A DNS-TXT shape and the same RFC-001-amendment-sso §B envelope.
- **Trigger for personal → org promotion** is operator count ≥ 2, not size or compliance. The moment two distinct humans share a `org_did`, transport-layer sovereignty becomes load-bearing (audit trail, slot-binding gate, data residency). One human across N sessions does NOT trigger it.
- **No new fields, no new kinds.** This amendment is deployment guidance + a TXT-record example matrix. Code-side it's a no-op on top of RFC-003 v0.15.

---

## Motivation

RFC-003 establishes that any operator CAN run an own relay. It does not answer when they SHOULD. The result observed in pre-amendment wire traffic (paul ↔ willard, 2026-05-31):

> paul: "I think the next natural step for the org level stuff is to do org level relays Like Slancha.ai"
>
> willard: "willard-fleet would make more sense to use the public because I'm an individual and they're theoretically all my own sessions on my devices but really could be optional so personal would have public relay + SSO but for organizations it's crucial to have their own relay with SSO"

The framing willard surfaced is sharper than the RFC-003 default: per-company relays are **crucial for orgs** (multi-operator trust scopes) but **optional QoL for personal fleets**. The implicit answer is in RFC-003 §1's hybrid topology, but reading the RFC end-to-end an operator currently can't quickly tell whether their fleet should self-host. This amendment makes the bifurcation explicit + provides the decision matrix.

Why now (v0.15 target, not deferred to v0.16):

- v0.15 ships the DNS-TXT `relay=` field as part of the SSO connector PR foundation (RFC-003 §6 v0.15 entry).
- Onboarding docs that ship alongside the v0.15 release need to answer "which tier am I" *before* they answer "how do I bind a relay."
- Without this guidance, the personal-fleet operator faces unnecessary infra cost; the org operator may stay on shared `wireup.net` past the point where own-relay would have prevented a metadata leak. Both failure modes are silent.

## Deployment tier matrix

| Axis | Personal fleet | Organizational fleet |
|---|---|---|
| **# operators** | 1 | ≥ 2 |
| **`org_did` purpose** | Group N sessions of one human under one anchor (optional) | Express "this group of humans trusts each other" (load-bearing) |
| **Relay** | `wireup.net` (default) | Own relay (default), e.g. `relay.company.com` |
| **DNS-TXT pin** | Optional — only needed if SSO opt-in | **Required** — pins org_did + relay + (typically) sso_iss |
| **SSO** | Optional QoL — proves op_did = github.com/willard or similar | Load-bearing — IdP attests "operator ∈ org tenant" |
| **Slot-binding gate** | None (public phonebook) | Member-only (relay refuses bind unless presenter's card carries verifying org_membership) |
| **Transport boundary** | Shared public infra | In-org transport stays in-org |
| **Compliance posture** | Operator's personal stance | Often externally driven (data residency, audit logs, etc.) |
| **Cost** | $0 (public-good shared infra) | < $5/mo recurring per RFC-003 AC4 (Cloudflare Tunnel free + Spark/fly baseline) |
| **Onboarding time** | None (works out of `wire up`) | < 30 min per RFC-003 AC4 |
| **Failure mode if mis-tiered** | Operator runs infra they don't need (sunk cost) | Operator leaks org-internal metadata to shared phonebook (silent until audited) |

The matrix is intentionally binary at the operator-count axis. Edge cases:

- **One human with a corporate identity** (e.g., willard operating under `willard@company.com`): the human's *personal* fleet stays personal-tier; if the company has an `org_did`, willard's sessions can ALSO carry a `company` org_membership in addition to a personal `willard-fleet` membership. RFC-001 §1 already supports `org_memberships[]` as a list; the two memberships compose without conflict.
- **Solo founder running a company** (one human today, planning ≥ 2 soon): start personal-tier; promote to org-tier when the second operator joins. The DNS-TXT update + relay spin-up are reversible and atomic on the receiver side (next bind refresh, ≤ 24h per RFC-003 §2).
- **Family / friend group sharing a trust scope**: org-tier by operator count, even if the group isn't a legal entity. The "organization" framing is a wire-tier descriptor, not a corporate one.

## Personal fleet — recommended shape

**Relay:** `wireup.net` (default).

**Identity — most-secure default = wire-rooted signing key, ALWAYS.**

Personal-tier identity is **always anchored at the wire-native Ed25519 signing key (`op_did`)**, regardless of whether the operator opts into any third-party IdP. The op_did + op_cert chain verifying against the inline `op_pubkey` on the card IS the cryptographic identity; this is the offline-self-certifying invariant from RFC-001 §"Implementation status (as-built, v0.14)" applied to the personal case. Third-party SSO (Google / Okta / Workspace / Auth0 / Authentik / GitHub-OAuth) is **purely additive attestation** that proves "this op_did is also `github.com/<user>`" for peer-side recognition; it never replaces or substitutes for the wire-rooted signing key.

Why most-secure by default: a personal-tier user whose ONLY identity was third-party-rooted (SSO-only) would inherit that third party's trust + recovery semantics + outage surface (Google account suspended → wire identity gone; Okta tenant rotated → wire identity unverifiable). Wire-rooting the signing key by default keeps the operator sovereign over their own identity. SSO becomes a recognition + bootstrap convenience, never the trust root. **An operator who uses no IdP at all still has a fully-functional, peer-verifiable, cryptographically-anchored personal-tier identity.**

Concretely:
- `wire enroll op --handle <yourname>` → op_did + Ed25519 keypair minted, key saved 0600 under `config/wire/op.key`. **This step is required, not optional.** The keypair IS the personal-tier identity anchor.
- Optional: `wire enroll op --sso github` (v0.15) → op_did carries an attestation envelope (`sso_attest` per RFC-001-amendment-sso §B) provable to peers. Consumer OAuth flow; no IdP infra required. **Additive on top of the signing key; the op_cert chain still verifies offline.**
- No `wire enroll org-create` unless the operator wants to express a self-claimed `personal-fleet` org for filtering (legitimate use: `org_policies.json` row `willard-fleet → auto` lets willard's own sessions auto-ORG_VERIFIED at each other without per-session SAS).

**Failure-mode framing:** if the consumer-OAuth IdP rotates / suspends / deprecates (e.g., GitHub's OAuth surface changes), the SSO attestation drops but the op_did's signing key + op_cert chain remain verifiable against the inline `op_pubkey` on every peer's pinned card. Identity continuity is preserved; only the third-party recognition layer degrades. This is the security property that demands signing-key-first as the default, not optional-SSO-first.

**DNS-TXT pin:** Optional. Only needed if the operator wants `nick@personaldomain.com` discovery (e.g. `willard@willardk.com`). Shape:

```
_wire-org.willardk.com. IN TXT "did=did:wire:op:operator-<32hex>; v=1"
```

Note: `relay=` is absent (default-to-wireup), `sso_iss=` is absent unless the operator wants peer-side IdP-verifiable op_did. The TXT carries `op_did` rather than `org_did` for the personal case (one human anchor). Schema is field-additive per RFC-003 §2 — receivers that only know how to look up `did=did:wire:org:*` parsers MUST tolerate `did=did:wire:op:*` and treat it as "no org binding declared at this domain" (operator-tier identity is a §A use-case the SSO amendment §A point 4 implicitly permits but does not document).

**Recommended addition to RFC-001 §A and RFC-003 §2:** clarify that `did=` accepts both `did:wire:org:*` and `did:wire:op:*` prefixes, with parsers dispatching on prefix. This is editorial — the §A grammar already says "Ed25519 anchor" without restricting to org_did, but example records always show org. Personal-tier deployment surfaces the gap.

**Cost:** $0. Onboarding: ≤ 5 min (`wire up`, `wire enroll op`, optionally drop DNS-TXT).

**When to promote to org-tier:** the moment a second human (distinct op_did) joins the trust scope. Promotion is one-way in practice: once an `org_did` carries multiple operators, demoting back to personal-tier loses the auto-pair lane between the two humans.

## Organizational fleet — recommended shape

**Relay:** own, bound to the company apex via DNS-TXT.

**Recommended deploy** (per RFC-003 §3 subdomain-split):
- HTTP relay: `https://relay.company.com` (Cloudflare Tunnel → home Spark / VPS / fly.io).
- DNS-TXT pin at apex: `_wire-org.company.com TXT "did=...; relay=https://relay.company.com; sso_iss=...; sso_tenant=...; v=1"`.
- Apex `company.com` serves the company website unchanged.
- Federation handle: `<nick>@company.com` (apex-as-email pattern per RFC-003 §3).

**Identity:**
- `wire enroll op` per operator (each human gets their own op_did).
- `wire enroll org-create --handle <company>` on the org-admin's session → mints `org_did` + org root key. **The org root key is the single load-bearing secret of org-tier deployment**; treat as a sealed credential (offline storage, hardware-bound where possible, rotation plan documented).
- `wire enroll org-add-member` issues member_cert per operator; distribute via secure channel (Note: F-INGEST means recipients hand-edit `memberships.json` until [#127](https://github.com/SlanchaAi/wire/issues/127) lands).

**SSO (load-bearing):**
- DNS-TXT carries `sso_iss=` + `sso_tenant=` pointing at the company IdP (Okta, Entra, Workspace, Auth0, Authentik).
- Operators authenticate via the IdP at session start (PR #92 adapter trait surfaces the IdP-specific OAuth flow).
- Each pair_drop carries an `sso_attest` envelope (RFC-001 §B) — receivers verify the JWT, map IdP tenant claim to `sso_tenant`, upgrade peer to `ORG_VERIFIED`.
- Member onboarding/offboarding tracks the IdP (the source of truth), not a separate wire roster. Removing an operator from the IdP's org membership → next `sso_epoch_advance` (RFC-001 §D) flushes their cached attestation → demotion to DNS-TXT floor → next pair fails verification → demotion to `UNTRUSTED`.

**Slot-binding gate** (NEW capability surface for v0.15+):
- An org-tier relay refuses `wire bind-relay` from a session whose card does not carry `org_memberships[*].org_did` matching the relay's anchor org.
- Verification: relay's `/v1/handle/bind` reads the presenter's signed card, verifies the inline `member_cert` against the org_pubkey pinned in the relay's local config, allows or refuses bind.
- This is **transport-layer enforcement** of org membership — the design parity with RFC-001 §3's "wire-native roster" claim. Without the gate, the relay is "your relay" only in branding; with the gate, it's "your relay" in trust topology.

**Acceptance criterion (NEW — AC-DT1 below):** an org-tier relay MUST refuse slot bind from a non-member session. Test: spin up a relay anchored at `org_did = did:wire:org:test-fleet-*`; attempt `wire bind-relay` from a fresh session with no `test-fleet` membership; expect 403 + structured error `{ "error": "org_membership_required", "anchor_org": "<did>" }`. Owner: per-RFC-003-§6 v0.15 entry.

**Cost:** < $5/mo per RFC-003 AC4. **Onboarding:** < 30 min per RFC-003 AC4.

## SSO composability — same envelope, both tiers

Whether the operator runs a personal or org fleet, the SSO mechanic is identical:

```
DNS-TXT at <domain>  ─→  sso_iss + sso_tenant pinned
                              │
                              ▼
op_did session  ─→  acquires OIDC JWT  ─→  wraps in session-key-signed envelope
                                                 │
                                                 ▼  (RFC-001 §B sso_attest, kind=1001)
                                              receiver verifies:
                                                  envelope sig ∧ receiver_did ∧ nonce ∧
                                                  JWT sig (JWKS) ∧ iss == TXT.sso_iss ∧
                                                  tenant claim == TXT.sso_tenant ∧ exp
                                                 │
                                                 ▼
                                            tier upgrade: ORG_VERIFIED
```

Difference between tiers is **what the receiver does with the attestation**, not how it's computed:

- **Personal fleet receiver:** treats `op_pseudonym` as "this is the same human's other session" → optionally auto-pair under a self-claimed `willard-fleet` `org_policies.json` row.
- **Org fleet receiver:** treats `op_pseudonym` as "this is an authenticated employee of `acme-prod`" → auto-pair per the org's RFC-001-amendment-filtering policy table.

The IdP adapter trait (PR #92) handles both lanes identically. Consumer OAuth (GitHub Personal, Google Personal) is registered as just another adapter alongside Okta / Entra / Workspace / Auth0 / Authentik. The TXT format does not distinguish — `sso_iss=https://github.com/login/oauth` is as valid as `sso_iss=https://login.acme.com/realms/wire`.

## Migration path: personal → organizational

A solo operator becoming an org (second operator joins):

1. **Stand up the org_did** (if not yet present): `wire enroll org-create --handle <company>` on the founding operator's session. Mints `org_did` + org root key.
2. **Spin up own relay** at `relay.company.com` (Cloudflare Tunnel + Spark / VPS / fly). RFC-003 §6 v0.14.x entry says this works today.
3. **Publish DNS-TXT pin**: `_wire-org.company.com TXT "did=<org_did>; relay=https://relay.company.com; v=1"`. SSO fields optional initially; can be added when IdP is procured.
4. **Issue member_certs** for both operators (founder + newcomer). Both add their bundle to local `memberships.json`. Both run `wire enroll republish`.
5. **Both operators run** `wire bind-relay https://relay.company.com`. Their cards now publish on the company relay; wireup.net publishing optional (kept for cross-fleet discoverability per RFC-003 hybrid topology).
6. **Receivers re-resolve**: peers pinned to the founder before promotion will pick up the new relay endpoint on next DNS-TXT refresh (≤ 24h per RFC-003 §2 read cadence). No manual re-pair.

Reverse migration (org → personal, last operator drops out leaving only one): possible but loses the auto-pair lane and ORG_VERIFIED tier between sessions. Recommended: keep the org_did anchored even at N=1 — costs nothing, preserves the upgrade path if the org regrows.

## Out of scope

- **The org root key rotation problem.** Inherited from RFC-001 §"Key rotation" + RFC-003 §"Out of scope". Org-tier deployment makes the root key MORE load-bearing, not less; this amendment does not solve key rotation. v0.16+ key-rotation work is the right venue.
- **Personal-tier SSO mandatory.** Personal fleets MAY opt in; this amendment does not propose making it required. Forcing SSO on personal-tier would block operators without persistent OAuth/IdP accounts (an anti-feature for the solo-operator UX).
- **Cross-org operator memberships across tiers.** RFC-001 §1's `org_memberships[]` already supports multiple memberships per card; this amendment does not modify that surface. An operator carrying both a personal `willard-fleet` membership and a company `acme-prod` membership works under existing wire semantics.
- **Multi-relay org topology.** An org running multiple relays (e.g., geo-distributed) is a v0.16 cross-relay-discovery concern per RFC-003 §6; this amendment treats "own relay" as a singular endpoint.

## Acceptance criteria

Two falsifiable additions; both ride on RFC-003 §6 v0.15:

- **AC-DT1: org-tier relay refuses non-member slot binds.** Spin up a relay anchored at a test `org_did`; attempt `wire bind-relay` from a session with no matching `org_memberships[]` entry; expect 403 + structured error `{ "error": "org_membership_required", "anchor_org": "<did>" }`. Personal-tier relays (anchored at op_did or unanchored) MUST NOT carry this gate (`wireup.net` is a personal-tier-by-construction reference). Owner: RFC-003 §6 v0.15 implementer.
- **AC-DT2: deployment-tier doc ships with v0.15.** A reachable `docs/deployment-tiers.md` (or this amendment promoted to ratified status) ships in the v0.15 release notes. The personal-tier walkthrough and org-tier walkthrough each fit on one screen of the operator's terminal. Owner: docs-lead at v0.15 cut.

These are deliberately small. The amendment's load-bearing work is the framing + matrix; the protocol-level acceptance is AC-DT1 (slot-binding gate).

## Kill criterion

If a personal-tier operator running `wireup.net` + opt-in SSO + a self-claimed `willard-fleet` `org_did` can NOT reach `ORG_VERIFIED` between their own sessions without standing up their own relay — i.e., if the slot-binding gate (AC-DT1) bleeds into wireup.net's behavior and forces personal fleets onto own-relay — abandon this amendment. The bifurcation only works if personal-tier stays cost-free.

## Open questions

- **Q1: Does `wire enroll org-create` need a `--tier personal | organizational` flag?** Probably no — the tier is determined by deployment topology (where the relay lives), not by an enroll-time declaration. The same `org_did` can be anchored at a personal-tier relay (wireup) on Monday and migrated to an org-tier relay (own infra) on Friday with no key changes.
- **Q2: Should personal-tier SSO be exposed via `wire enroll op --sso github` as a one-shot convenience?** Yes — this amendment recommends it as the canonical personal-tier SSO entry point (consumer OAuth, no IdP infra), but the implementation is a v0.15 PR-92-adjacent concern, not a protocol-layer question.
- **Q3: Cross-tier visibility — can an org-tier peer see a personal-tier peer's op_pseudonym?** Yes, by RFC-001 §B.1 semantics: `op_pseudonym` is stable per (sub, org_did, salt) pair regardless of where either peer's relay lives. Cross-tier pairs land in the receiver's filtering surface (RFC-001-amendment-filtering) at whatever tier the DNS-TXT + SSO chain validates to.

## References

- `docs/rfc/0001-identity-layer.md` — RFC-001 (ratified, implemented v0.14).
- `docs/rfc/0001-identity-layer.amendment-sso.md` — §A DNS-TXT + §B OIDC envelope + §B.1 op_pseudonym (ratified, v0.15 build).
- `docs/rfc/0001-identity-layer.amendment-filtering.md` — per-org receiver-side policy table (ratified).
- `docs/rfc/0003-per-company-relays.md` — hybrid topology, DNS-TXT `relay=`, A2A parity, phasing (Discussion → v0.15+ target).
- [Issue #127](https://github.com/SlanchaAi/wire/issues/127) — F-INGEST: peer-side `add-membership` CLI verb (load-bearing for org-tier onboarding UX).
- [PR #92](https://github.com/SlanchaAi/wire/pull/92) — SSO adapter trait, pluggable IdPs.
