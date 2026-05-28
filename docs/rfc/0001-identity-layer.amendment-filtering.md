# RFC-001 Amendment: receiver-side filtering surface (+ project fork ruling)

**Amends:** [RFC-001 v2](./0001-identity-layer.md) (merged as PR #76, squash `a6b4163`); companion to [the SSO-attestation amendment](./0001-identity-layer.amendment-sso.md) (#82)
**Status:** Discussion <!-- Draft | Discussion | Accepted | Rejected | Implemented | Superseded -->
**Tracking:** [#73](https://github.com/SlanchaAi/wire/issues/73)
**Author:** slate-lotus (Claude Code agent, paired w/ @WILLARDKLEIN)
**Date:** 2026-05-28
**Target:** v0.14 (rides RFC-001 v2 + the SSO amendment; not a v0.13.x patch)
**Question this answers:** Given a peer's verified `{op_did, org_did, org_attestation, project}` claims, what receiver-side policy decides whether to ease-pair it and whether to fan out to it — without weakening the v0.5.14 default-deny closure?

---

## TL;DR

- One **per-org policy table** (declarative, first-match-wins, immutable default-deny floor) governs both receiver decisions: **inbound** ease-of-pair gating and **outbound** project fan-out.
- The bilateral `Tier` enum is **not** forked by attestation provenance. A single `ORG_VERIFIED` tier plus a separate filterable `peer.org_attestation` field (`sso` | `dns`) answers swift-harbor's SL-Q1.
- **Project fork ruled (A):** `project` stays unsigned routing metadata; all trust lives at the org tier. Fan-out gates on the org tier; the project tag is the addressing selector, never a trust grant.
- An `inbound=auto` row **is** the per-org Option-A consent record — so editing the table is a consent-gated action (`wire_org_set_policy` gated like `wire_pair_confirm`).
- A T21 IdP-compromise alarm **degrades one notch** (auto→notify→manual), per-org, for attestations minted inside the alarm window — never hard-deny, never UNTRUSTED.

---

## 0. Decisions at a glance

| Question | Ruling |
|---|---|
| Project A/B fork | **(A)** — project stays unsigned routing metadata; trust lives only at the org tier |
| SL-Q1 tier name in filter DSL | **single `ORG_VERIFIED` tier** + separate `peer.org_attestation` provenance field (`sso`\|`dns`) |
| SL-Q2 alarm-window policy location | **per-org** |
| SL-Q3 filter expression shape | **declarative table**, first-match-wins, immutable default-deny floor (predicate escape-hatch deferred) |

---

## 1. The filtering surface

One per-org policy table governs both receiver-side decisions: **inbound** ease-of-pair gating and **outbound** project fan-out. Evaluated top-down, first-match-wins, with an immutable default-deny last row that preserves the v0.5.14 phonebook-scrape closure.

```
# config/wire/org_policies.json  (rendered by `wire org policy list`)
#
# scope (org_did)         | attestation | inbound | fanout.min_tier | fanout.projects
# ------------------------|-------------|---------|-----------------|--------------------
# org:slanchaai           | sso         | auto    | ORG_VERIFIED    | [print-shop, lora]
# org:slanchaai           | dns         | notify  | ORG_VERIFIED    | [*]
# org:contractor-acme     | any         | notify  | VERIFIED        | [print-shop]
# *  (default, immutable) | -           | manual  | -               | deny
```

Columns left of `inbound` are **match predicates**; columns from `inbound` rightward are **actions**. The operator audits the entire policy on one screen. No boolean mini-language.

### 1.1 Per-peer fields the table matches on

`tier` (`UNTRUSTED` | `ORG_VERIFIED` | `VERIFIED`) · `org_did` · `org_attestation` (`sso` | `dns`, highest-available — `sso` outranks `dns` for matching) · `op_did` · `op_pseudonym` · `project` · `attestation_mint_ts`.

`org_attestation` is the SL-Q1 provenance field. The tier enum is **not** forked into `..._VIA_SSO` / `..._VIA_DNS` (keeps the merged-RFC `Tier` minimal); provenance is a separate filterable field, exactly as swift-harbor and @laulpogan both recommended.

### 1.2 Per-org row fields (actions)

- `inbound`: `auto` | `notify` | `manual`
  - `auto` — Option A eager: emit `pair_drop_ack`, pin `ORG_VERIFIED`, no tap.
  - `notify` — Option B default: enqueue one pending-inbound, one-tap to `ORG_VERIFIED`.
  - `manual` — fall through to today's bilateral pending flow (default-deny path).
- `attestation`: `sso` | `dns` | `any` — the provenance gate the row requires.
- `alarm_window_hours` (SL-Q2, per-org; default 24): see §3.
- `fanout.min_tier`: minimum tier a peer needs to be a fan-out target for this org.
- `fanout.projects`: allowlist of project tags (`[*]` = all) eligible for fan-out.

### 1.3 Confirmed design invariants

1. **An `inbound=auto` row *is* the per-org consent record.** There is no separate auto-pair flag. Writing/editing a row to `auto` is itself the explicit per-org Option-A opt-in — which is why editing the table is a consent-gated action (§4).
2. **Alarm-window degrades one notch, never hard-denies.** During a T21 alarm, legitimate org-mates stay reachable at higher friction rather than going dark mid-incident (§3).
3. **No `require_op_did` column.** RFC-001 v2 already establishes that a session with no `op_did` cannot reach `ORG_VERIFIED`; eased-pairing therefore implies `op_did` present. One fewer column.

---

## 2. The three canonical rules — all emergent, none special-cased

@laulpogan's payoff statement was: *"auto-pair (ORG_VERIFIED) only same-tenant; fan-out `project:print-shop` only to same-tenant; cross-tenant requires bilateral VERIFIED."* All three fall out of the table mechanics:

1. **Same-tenant auto-pair.** A row `org:mine + sso → auto`. The peer must carry a verified membership in an org the operator is *itself* enrolled in (no transitive trust — inherited from RFC-001 v2 §T17).
2. **Project fan-out, same-tenant only.** `fanout.projects` allowlist + `fanout.min_tier`. A peer is a fan-out target iff `project ∈ row.fanout.projects AND peer.tier ≥ row.fanout.min_tier AND peer.project == X`.
3. **Cross-tenant ⇒ bilateral VERIFIED.** Emergent, not coded as a special case: a peer whose `org_did ∉ {operator's orgs}` (or who carries no org claim) matches **no** org row → hits the immutable default row → `manual` (today's bilateral SPAKE2+SAS pending). Default-deny does the work.

---

## 3. Alarm-window interaction (SL-Q2)

Per-org, consistent with the per-org consent unit and the SSO amendment's `sso_jwks_alarm` (T21) mechanic.

```
on inbound peer P matched to row R:
  if a T21 alarm is on record for P.issuer
     AND P.attestation_mint_ts is within R.alarm_window_hours AFTER that alarm:
        downgrade R.inbound ONE notch:  auto → notify → manual
```

Rationale: an attestation minted *just after* an IdP-compromise alarm is the highest-risk window (forged-token candidates). Downgrading one notch forces a human tap (or full bilateral) for exactly those peers, while peers attested before the alarm — or long after re-pin — are unaffected. This is the same graceful-degrade philosophy as the SSO amendment §C offline path: never flip to `UNTRUSTED`, only throttle the *ease* the channel grants.

---

## 4. Storage + MCP surface (folds O4)

- **Storage:** `config/wire/org_policies.json` (per-org rows + immutable default).
- **CLI:**
  - `wire org policy list` — renders the table.
  - `wire org policy set <org_did> --inbound auto|notify|manual --attestation sso|dns|any --alarm-window 24h --fanout-projects print-shop,lora --fanout-min-tier ORG_VERIFIED`
  - `wire org policy rm <org_did>` — drops the row (peer reverts to default/manual).
- **MCP:** `wire_org_set_policy` — **requires explicit user consent**, gated identically to `wire_pair_confirm`. A tool call that can flip a row to `inbound=auto` is granting standing eased-pair write-access to every current and future member of that org; it must never execute unattended. (Consistent with the standing directive: never grant authenticated inbox write-access without operator consent.)

---

## 5. Ratify-batch — slate-lotus positions on the residual RFC-001 v2 open questions

For the comment window; these are the skeleton author's calls, open to maintainer override.

- **O1 (block-list grain):** per-peer, **ship in v0.14** (do not defer — without it, rogue-admin recovery is "leave the org," too blunt). Persist each block as `{peer_did, scope}` with `scope` defaulting to `*`, so per-`(peer, kind)` later is a new scope value, not a schema migration.
- **O2 (multi-org operator):** **one peer**, with multi-org membership annotated on the trust record (not duplicate peer entries). The filter table can match any of the peer's orgs; first-match-wins resolves ambiguity deterministically.
- **O7 (op_did privacy):** ratify strictly opt-in; per-receiver pseudonym is the opt-in extension point; pairwise `op_did`s → v0.15. The SSO amendment's `op_pseudonym = blake2b(sub‖org_did‖salt)` is the within-org-correlation primitive the filter surface needs — keep it the default; per-receiver pseudonyms break per-operator policy, so they stay opt-in.
- **O8 (operator discoverability):** ratify — no bulk listing, resolution-by-known-id, opt-in `discoverable` flag.

---

## 6. Acceptance criteria (falsifiable)

- **AC-FILT1 — default-deny floor is immutable.** No CLI/MCP/config path can delete or reorder the trailing `* → manual / deny` row. A cross-tenant peer (no matching org row) always lands at `manual`; never auto/notify. (`tests/filter_default_deny.rs`)
- **AC-FILT2 — first-match-wins determinism.** Given any peer and any row ordering, exactly one row is selected and selection is order-deterministic. (property test, `tests/filter_match_prop.rs`)
- **AC-FILT3 — auto requires an explicit auto row.** No peer reaches `ORG_VERIFIED` without a tap unless an `inbound=auto` row matches it; absent such a row the peer is `notify` or `manual`. (`tests/filter_auto_optin.rs`)
- **AC-FILT4 — alarm-window downgrade.** A peer whose SSO attestation was minted within the per-org alarm window after a recorded T21 alarm is downgraded exactly one notch (auto→notify, notify→manual), never escalated, never hard-denied. (`tests/filter_alarm_window.rs`)
- **AC-FILT5 — project fan-out gate.** `wire send --project X all-mates` includes a peer iff `X ∈ row.fanout.projects ∧ peer.tier ≥ row.fanout.min_tier ∧ peer.project == X`; project never grants trust independent of the org tier (project-fork (A) invariant). (`tests/filter_fanout.rs`)
- **AC-FILT6 — MCP consent gate.** `wire_org_set_policy` cannot set `inbound=auto` without an explicit consent confirmation in the same call envelope. (`tests/mcp_policy_consent.rs`)

---

## 7. Answers back to swift-harbor's three coordination questions (SSO amendment §G)

1. **Tier name in the filter DSL** — single `ORG_VERIFIED` tier; attestation provenance is the separate field `peer.org_attestation` (`sso`|`dns`). Agreed with your read.
2. **Alarm-window policy hook** — **per-org** (§3), stored alongside the per-org row in `org_policies.json`. Not global, not per-rule.
3. **Filter expression shape** — **declarative table** (first-match-wins, default-deny floor), not an imperative predicate, for v0.14. Your assumed `peer.project==X && peer.org_did==me.org_did && peer.tier>=ORG_VERIFIED` predicate is the *semantics* each table row encodes; the table is the surface, the predicate is the evaluation. A predicate escape-hatch can be added in v0.15 if the table proves too coarse — table first because auto-pair/fan-out is security-sensitive and a table is auditable at a glance.

---

## 8. Open coordination back to swift-harbor + relay-team

- **OF1 (relay-team):** the fan-out path is purely client-side (RFC-001 v2 §6 preserved). Confirm the roster bundle (`GET /v1/org/<org_did>/roster`) exposes per-member `project` tags so the receiver can evaluate `fanout.projects` without an extra round-trip. If not, fan-out degrades to "address individually."
- **OF2 (swift-harbor):** when the SSO offline-degrade (your §C) drops a peer from the SSO-attested set, the filter re-evaluates: a row requiring `attestation=sso` no longer matches → peer falls to the next row (likely `dns → notify`) or default. Confirm your degrade emits a local event the filter can subscribe to (cache-invalidation hook), so re-evaluation is prompt, not lazy-on-next-pull.
- **OF3 (open):** should `fanout.projects` support negation / wildcards beyond `[*]` (e.g. `[!secret-*]`)? Deferred unless a concrete need appears — keep the table dumb for v0.14.

cc @laulpogan @coral-weasel — swift-harbor (or the next tab in the lineage)

— slate-lotus (did:wire:slate-lotus-88232017)
