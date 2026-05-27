# RFC-001: Operator / Organization / Project identity layer

**Status:** Discussion <!-- direction blessed; full v2 in development -->
**Tracking:** [#73](https://github.com/SlanchaAi/wire/issues/73)
**Author:** slate-lotus (Willard via Claude Code) — skeleton; **v2 by swift-harbor** (wire peer agent)
**Date:** 2026-05-27
**Target:** v0.14 (invasive — not a v0.13.x patch)
**Question this answers:** How should wire express operator / organization / project identity to reduce pairing friction inside trust scopes?

---

> **This is a stub.** The full design lives in tracking issue [#73](https://github.com/SlanchaAi/wire/issues/73) and is being developed in depth by swift-harbor; the v2 doc will replace this file when ready. This stub records the proposal summary and the **maintainer's direction-bless + guardrails** so the v2 doesn't go down a redirected path.

## Summary

A 3-layer identity model — **operator** (one human, N sessions/machines), **organization** (mutually-trusting operators), **project** (routing tag) — layered on wire's existing per-session DIDs, to reduce the N² SAS-pairing friction inside an established trust scope. Strawman adds `op_did` / `org_did` / `project` claims to the agent-card and inserts an `ORG_VERIFIED` tier between `INTRODUCED` and `VERIFIED`.

## Maintainer direction (2026-05-27)

**Direction consented.** The "no agent-platform positioning" constraint is **relaxed** — wire can build coordination layers people want; this is identity/pairing infrastructure, not mission creep, as long as it stays at the identity/transport layer. Proceed to v2 along these lines, holding these guardrails:

- **`ORG_VERIFIED` < `VERIFIED`, always.** Org membership *eases* pairing; it never substitutes for bilateral SAS. This is what dodges the transitive-trust trap and preserves the v0.5.14 phonebook-scrape closure. Non-negotiable.
- **Eased-pair lifts the consent *unit*, never abolishes consent.** Per-org one-shot opt-in is the right grain.
- **New claims are orthogonal axes, not alternate names.** `op_did`/`org_did` must not reintroduce a free-choice name that diverges from the DID-derived session handle — the one-name invariant still holds for the session's own identity.
- **Express orgs as a flavor of `wire group`** (v0.13.3 creator-signed roster + introduce-pinning), not a new trust primitive — reuse the known machinery and threat surface.
- **Org claims are non-FCFS / attested.** DNS-TXT floor; `did:web` optional; defer GitHub-org verification.
- **Lazy auto-pair** (pair on first send), not eager — the eager 100×10 = 1000-pair_drop balloon is real.

## Open questions

Carried in [#73](https://github.com/SlanchaAi/wire/issues/73) (attestation channel, consent unit, tier ladder, reuse-vs-new, liveness/GC, traffic shape). Owner of the v2 design: swift-harbor; ratification: @laulpogan.

## Sources

Threat-model grounding: `docs/THREAT_MODEL.md` (T-tiers, phonebook-scrape closure). Group substrate: v0.13.3 `wire group`.
