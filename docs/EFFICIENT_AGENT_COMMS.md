# RFC: Token-efficient agent-to-agent communication

**Status:** Draft — RFC for discussion. Not scheduled. Ship gate: maintainer accept **+ a measured token baseline on a real corpus** (KPI 1) — the win is currently estimated, not measured.
**Filed as:** this PR (RFC discussion thread)
**Author:** @laulpogan (drafted by coral-weasel / Claude Code; revised after a 5-persona review — see revision plan)
**Date:** 2026-05-26
**Question this answers:** Can wire agents communicate solely in embeddings, and what is the most token-efficient way for them to talk?
**Staleness cutoff:** 8 weeks (project) / 4 weeks (model-perf). Research log: `specs/.research/efficient-comms-log.md`.

---

## TL;DR

- **No — wires cannot talk "solely in embeddings" on the cross-vendor mesh.** Not because embeddings are opaque (vec2text recovers ~92% of ≤32-token sequences; they're *invertible*), but because (a) hosted LLMs ingest **tokens, not vectors** — no API accepts a raw embedding as input — and (b) embedding spaces are **not aligned across different models**. A vector channel is only coherent between identical, co-designed models.
- **Latent/"neuralese" comms is real and fast** (Interlat: up to **24× inference speedup** passing hidden states) but needs shared model internals → **homogeneous fleet only**, never Claude ↔ Copilot ↔ Cursor. Out of scope for interop.
- **The win that's actually achievable isn't token count — it's *semantic determinism*.** Today a receiver LLM must *interpret* a prose status ("gates look green but one test is flaky" — pass or not?). A coded intent (`{"intent":"review_result","verdict":"pass"}`) is decoded, not interpreted. That removes a class of misread, and it happens to cost fewer tokens.
- **Recommendation:** ship `coord-vocab v1` — a closed set of routine coordination intents carried in the **body** of a single registered `coord` event kind, gated by an opt-in capability negotiation that **does not exist yet and must be built**, with **mandatory prose fallback**. It is an optimization *under* A2A/MCP, not a replacement. **Measure the win on a real corpus before building the encoder** (the savings are estimated, not proven).

---

## Context

This repo just ran an 11-PR agent-to-agent collaboration over wire. Each coordination message costs the sender output tokens and the receiver input tokens, and — more expensively — forces the receiver to *LLM-interpret* prose. The operator asked: could agents skip natural language for embeddings, and failing that, what is the cheapest way to talk? This answers both and proposes an interop-safe mechanism.

**Opportunity-cost note:** this is friction-reduction, not on wire's locked 90-day path (identity-first ship, A2A interop adapter, second contributor). It should not displace those. Sequence it behind a cheap measurement spike (below) that can kill it early.

## Method

- **Sources:** 8 (all primary or primary-academic). Strongest: A2A spec [primary, 90], Anthropic caching docs [primary, 90], wire repo + THREAT_MODEL [primary, 95]. Frontier-academic: vec2text [primary, 70], Interlat [primary, 75].
- **Code-grounded claims** (kind type, cursor behavior, capabilities usage, relay confidentiality) verified against `src/` and `docs/THREAT_MODEL.md`.

---

## Finding 1 — "Embeddings are opaque" is false; the real blockers are the token boundary and cross-model misalignment

Embeddings invert to text: vec2text recovers **92% of ≤32-token sequences** (BLEU 97.3) with a model-specific trained decoder [primary, arxiv 2310.06816 Morris et al., 70; reproduced 2025]. **It degrades on longer and more precise content**, and needs a decoder trained for the *exact* embedding model. So the objection is not "the receiver can't decode."

The real blockers:

> **A — the model's input interface is tokens.** Hosted LLMs (Claude, GPT) accept tokens, not vectors; no API injects a raw embedding into context [primary, API design, 90]. Whatever wire ships must become tokens to enter an agent's head. *This is a vendor-API constraint, not physics* — it dissolves for an open-weight homogeneous fleet (Finding 3), but holds for every cross-vendor target.
> **B — embedding spaces aren't aligned across models.** A vector from one embedding model is meaningless to another. Mutual interpretation requires the same model+version on both ends — contradicting wire's cross-vendor premise.
> **C — inversion is model-specific and lossy on long content.** Precise, novel instructions don't round-trip.

## Finding 2 — The interop standard wire speaks is structured JSON, not vectors

A2A — served on `.well-known` for cross-vendor reach — is **JSON-RPC 2.0 over HTTPS**, optional REST HTTP+JSON, SSE streaming [primary, a2a-protocol.org v0.3.0/draft-v1.0, 90]. (JSON `Part`s can carry base64 binary, so "text-only" is imprecise — but the *coordination metadata* layer is strings.) MCP is JSON-RPC over stdio/Streamable-HTTP [primary, MCP spike #64, 85]. The ecosystem wire plugs into exchanges structured JSON; a vector channel would be wire-proprietary and non-interoperable by construction.

## Finding 3 — Latent comms is real and fast, but homogeneous-only

Passing continuous hidden states between agents works and is fast: Interlat reports **up to 24× inference speedup** (peak, task-specific) versus token CoT while beating it on task performance [primary, arxiv 2511.09149, 75]; activation-passing is similarly demonstrated [primary, arxiv 2501.14082, 72]. This is the genuine "talk in embeddings." It requires **shared model internals** (same weights, compatible hidden-state dims, a vector input path) → a co-designed open-weight homogeneous fleet. A real *future* track for a single-operator same-model fleet (e.g. Spark fine-tunes); a non-starter for the cross-vendor mesh. (Tracking issue to be filed; not scoped here.)

## Finding 4 — The token cost is at the receiver's context boundary, and bytes ≠ tokens

When B receives an event, B's harness injects the body into B's context — B pays input tokens proportional to the body, and pays *reasoning* to interpret prose. **Compressing wire bytes (gzip/zstd) does not reduce tokens** — the body is decompressed before context injection, by construction of the token API contract [derived inference; the API fact (input is uncompressed tokens) is primary, 90]. Caching helps differently: an Anthropic cache *read* costs 10% of base input price (90% reduction) for repeated scaffolding [primary, platform.claude.com/docs prompt-caching, 90], and wire content-addresses events (`event_id` = SHA-256 of the canonical body — see PROTOCOL.md) so identical messages dedup. Conclusion: efficiency = **intent per token** + **not re-reading the known** — not wire bytes.

## Finding 5 — Embeddings' only role here is triage metadata — and even that hits Blocker B

A vector *could* ride a message as a relevance/dedup signal so a receiver skips low-relevance bodies without reading them. But this inherits Finding 1's **Blocker B**: for B to interpret A's relevance vector, both need a *shared* embedding model — the same wall that sinks embedding-as-message. So triage-embedding is **deferred to v2 and out of v1 scope** (Out of Scope), contingent on a shared-embedding-model decision. It is not a near-term win.

---

## Proposal: `coord-vocab v1`

A closed set of **routine coordination intents**, carried on wire's existing event surface. Design corrected after review against the code:

**1. Encoding — one kind, intent in the body (NOT new kinds per intent).**
`kind` is a `u32` (signing.rs), and an **unknown kind blocks the receiver's cursor** (pull.rs: transient-reject re-sees the event next pull). So minting a new numeric kind per intent would **deadlock un-upgraded peers**. Instead: register **one** `coord` kind once; the intent lives in the body: `{"intent":"review_result","pr":67,"verdict":"pass"}`. Vocab evolves as **body schema**, never as new kinds — the cursor never blocks on vocab growth. (`decision`/`ack`/etc. are the event `type`/name string, not `kind` — an earlier draft conflated them.)

**2. Boundary — mechanical, not judgment.** An intent is coded **iff it is a member of the closed v1 set**; everything else is prose. This is a table lookup, not an LLM deciding "is this routine" (which would be non-deterministic — the "don't string-match intelligent output" anti-pattern). The v1 set is small and explicit (`review_result`, `merged`, `pr_opened`, `gates`, `claim_issue`, `blocked`, `request_review`, …; final list owned per Open Questions).

**3. Negotiation — TO BUILD; does not exist today.** `capabilities` in the agent-card is currently **display-only** (`wire whoami`/`peers`); nothing reads it at send time. v1 must build: (a) a per-peer negotiated-capability store, (b) a send-time read that selects coded-vs-prose, (c) a per-peer pinned `coord-vocab` version with a min-version floor. Both peers must advertise `coord-vocab/v1` (in the **signed** agent-card) before either sends coded bodies.

**4. Receiver behavior — specified (was missing).**
- Unknown intent (version skew, partial support) → treat the body as **opaque/prose, emit a warning**; never silently drop.
- Malformed coded body → emit a structured `coord_error` event (`{"unknown_intent": "...","vocab_version":"v1"}`); don't fail the cursor.
- Group/broadcast → the sender codes **only if every recipient's capability intersection includes the intent**, else prose. (Diagnostic: `wire tail --json` shows the raw event; a `coord_error` surfaces mis-decodes.)

**5. Security — integrity yes, confidentiality NO.** A coded body is still a signed event body — signature integrity holds (the relay can't forge it). It carries **no** confidentiality benefit: v0.1 events are **signed-plaintext and readable by the relay** (THREAT_MODEL T1) — a coded body is exactly as readable as prose. Capability advertisement rides the signed agent-card, so it can't be *forged*; but in `WIRE_INSECURE_SKIP_TLS_VERIFY` mode the `.well-known` card fetch is MITM-able and caps could be *stripped* (downgrade to prose) — operator mitigation: don't skip TLS in prod.

**Why this shape:** it is the *discrete, decodable* version of "a shared semantic channel" — decodable (unlike a raw embedding), interop-safe (prose fallback + A2A untouched), and ESMTP-shaped (negotiate capability, coded path for supporters, defined fallback for the rest). The primary value is **semantic determinism**; lower token count is a bonus.

### Who this does NOT serve (explicit)
- **Sandboxed / file-system-contract agents** (no outbound fetch): can't deref pointers; coded-body support depends on the daemon, TBD.
- **Agents that can't update their agent-card at runtime** (some CI/eval harnesses): can never negotiate → always prose. Fine, but zero benefit.
- **Homogeneous single-model fleets:** better served by Finding 3 (latent), not this.

---

## Companion (separate milestone): pointers, not payloads

The biggest real-world token waste in this session's traffic was **inlined heavy content** (diffs, logs) the receiver could have addressed by reference. A pointer convention (`PR #67, commit f7e9ec8` + fetch-on-demand) would cut that — but this is a **new feature**, not a generalization of an existing one (wire has signed *file* pointers; general content-pointers + a fetch convention don't exist), and it **degrades to zero for sandboxed agents that can't fetch**. Scoped as a separate milestone, measured separately.

---

## Governance (required for an interop layer)

A negotiated vocab with single-maintainer governance and no registry maps to the **XMPP failure mode** (every node implements a different subset → "supports it" means nothing). The **ESMTP success pattern** is the target: capability negotiation + in-protocol fallback + a public registry. Therefore v1 must:
- Keep the intent set in an in-repo **registry** with an explicit add/deprecate process.
- Namespace the capability (`coord-vocab/vN`) so it **can** be proposed to the A2A working group as an extension later. **Decision needed (Open Q):** propose upstream vs. own as wire-specific. Until decided, treat it as wire-specific and say so — do not imply it's an A2A standard.

---

## KPIs

Acceptance criteria for `coord-vocab v1`. **Sequencing is measure-first:** PR 1 builds the harness + a labeled corpus; KPI 1/2 gate *before* the encoder is built. (The real outbox corpus today is ~7 prose `kind:1` messages — a labeled corpus must be assembled or synthesized-and-disclosed.)

**KPI 1 (leading) — per-message token reduction on routine intents.** `[TBD: 60% is a reasoned floor (≈50–150-token prose → ≈15–25-token coded ⇒ 70–85%); validate against the corpus before locking — terse agent prose may be shorter]`
Threshold: ≥60% median body-token reduction, top-10 routine intents. Deadline: accept + 30d. Source: token-count harness (TO BUILD). Owner: contributor (named at accept). Outcome: hit → lock v1; miss → re-baseline or drop.

**KPI 2 (leading) — vocab coverage.** "Routine coordination" defined a priori = messages whose intent ∈ the candidate v1 set (fixed before measuring, not post-hoc).
Threshold: v1 set covers ≥70% of those messages in the corpus. Deadline: accept + 30d. Source: corpus classification (manual + model-graded; rubric TO BUILD). Owner: contributor. Outcome: <70% → expand set before lock.

**KPI 3 (lagging) — end-to-end context-token reduction per round-trip.**
Threshold: ≥40% reduction on an instrumented A↔B scenario. Deadline: accept + 60d. Source: instrumented harness (TO BUILD). Owner: contributor. Outcome: proves the real win.

**KPI 4 (leading, guard) — zero interop regression.**
Threshold: 100% of A2A/MCP and non-`coord-vocab` peers exchange correctly via prose fallback (pass/fail). Deadline: at impl. Source: interop integration test (TO BUILD) + existing pair/send e2e. Owner: implementer. Outcome: must-pass merge gate.

**KILL CRITERION:** if KPI 3 < 20% end-to-end reduction at accept + 60d, **abandon** `coord-vocab` (not pause) — the token win doesn't justify the protocol complexity; revisit only "pointers, not payloads" and caching, which need no vocab.

**Early signals (not KPIs):** a second framework adopts `coord-vocab/vN`; contributor PRs adding intents.

---

## Out of scope

- **Raw-embedding messages on the mesh** — Findings 1–2.
- **Latent / neuralese comms** — real (Finding 3), homogeneous-fleet-only; separate future track, tracking issue TBD. Not on the interop path.
- **Triage-embedding metadata (Finding 5)** — deferred to v2; inherits Blocker B (needs a shared embedding model). Out of v1.
- **Transport compression (gzip/zstd)** — saves bytes, not tokens (Finding 4).
- **A2A/MCP replacement** — `coord-vocab` layers under them; never replaces.

## Risks

- **Tech — vocab rot / lossy coercion.** Mitigation: mechanical membership boundary + mandatory prose fallback; v1 set scoped to the genuinely-closed routine set.
- **Interop — fragmentation toward a wire dialect.** Mitigation: in-protocol fallback (ESMTP pattern) + the Governance section's registry + upstream-A2A decision.
- **Security — downgrade.** Caps ride the signed card (can't be forged); residual = `.well-known` MITM in skip-TLS mode (caps stripped → prose). No confidentiality regression (already plaintext). Cross-ref THREAT_MODEL T1/T3.
- **Adoption — cold start.** Day-one value is low until peer adoption; the honest wedge is **same-operator fleets** (you control both ends). Prose fallback = zero penalty for non-adopters.
- **Protocol — un-upgraded peers.** Addressed by the single-`coord`-kind design (no new kinds → no cursor block).

## Open questions

- **Who owns + ratifies the v1 intent set, and is it proposed upstream to A2A?** Owner: @laulpogan. Decision: at RFC-accept.
- **Build the measurement harness + labeled corpus first?** Owner: contributor. This is PR 1; KPIs are unmeasurable without it.
- **Triage-embedding (v2): shared embedding model?** Owner: @laulpogan. Defer past v1.
- **Sandboxed/file-system agents: does the daemon encode coded bodies on their behalf?** Owner: implementer. Decision: at impl design.

## Source quality summary

| Tier      | Count | Avg score | Notes |
|-----------|-------|-----------|-------|
| Primary   | 8     | ~83       | A2A spec, caching docs, wire repo/THREAT_MODEL strongest (90–95); vec2text/Interlat frontier-academic (70–75) |
| Secondary | 0     | —         | — |
| Tertiary  | 0     | —         | Search aggregators seen, not used as anchors |

**Stale flagged:** 1 (vec2text 2023; finding reproduced 2025, durable). **Code claims verified:** kind type, cursor behavior, capabilities usage, relay confidentiality — all confirmed against `src/`/THREAT_MODEL.

## Conflicts encountered

- Author's first-pass framing ("embeddings not invertible", "latent comms impossible") was overturned by sources (vec2text 92%; Interlat 24×). The conclusion re-grounded on the token-boundary + cross-model-alignment blockers, which survive.
- First draft contained four code-contradicted claims (kind-as-string, forward-compatible new kinds, existing capability negotiation, "relay can't read bodies"); all corrected here after verification.

## Appendix

- Research log: `specs/.research/efficient-comms-log.md`
- Revision plan (5-persona review + applied edits): `specs/.research/efficient-comms-revision-plan.md`
