# wire RFCs

Design proposals that are too big or too cross-cutting for a single PR description live here. An RFC is for *direction* — "should we build this, and roughly how" — not line-level implementation. Small, obvious changes don't need one; just open a PR.

## When to write an RFC

Write one when a change:
- touches the trust model, identity, or wire protocol surface,
- adds a new primitive or capability negotiated between agents,
- has cross-vendor / interop implications, or
- you want comment on the *approach* before sinking implementation effort.

If you're unsure, open an issue and ask. Over-RFC'ing is friction; under-RFC'ing burns rework.

## Numbering

RFCs are numbered sequentially, zero-padded: `0001`, `0002`, … The human-facing name is `RFC-NNN`. `0000` is the template. Claim the next number by opening the PR (or the tracking issue) — if two land at once, the second renumbers.

File: `docs/rfc/NNNN-<kebab-slug>.md`.

## Lifecycle

| Status | Meaning |
|--------|---------|
| **Draft** | Being written; not yet open for broad comment. |
| **Discussion** | Open for comment (tracking issue + PR). The default state of a posted RFC. |
| **Accepted** | Maintainer accepted the *direction*. Implementation PRs may proceed; they link back here. |
| **Rejected** | Declined. The doc stays for the record with a one-line why. |
| **Implemented** | Shipped. Links the implementing PRs. |
| **Superseded** | Replaced by a later RFC (link it). |

A maintainer sets status. `Accepted` is a direction bless, not a blank check — acceptance criteria / KPIs and any kill criterion in the RFC still gate the build.

## Flow

1. **Open a tracking issue** titled `RFC-NNN: <title>` for the discussion thread (or reuse an existing one).
2. **Write the doc** from [`0000-template.md`](0000-template.md) as `docs/rfc/NNNN-<slug>.md`; open a PR.
3. **Discuss** on the issue/PR. Iterate. A maintainer moves the status `Draft → Discussion → Accepted/Rejected`.
4. **On accept, implement** as normal PRs that link the RFC; when shipped, flip status to `Implemented` and list the PRs.

Merging the RFC doc (in `Draft`/`Discussion`) just lands the text for reference — it is **not** ratification. Ratification is the `Accepted` status set by a maintainer.

## Discipline (carried from the research-spec habit)

RFCs that make factual claims should cite them inline `[tier, source, score]` and keep a research log; proposals with measurable goals should state ≤4 falsifiable acceptance criteria + a kill criterion. The template has the slots. The point is auditability — a reader should be able to check every load-bearing claim.

## Index

| RFC | Title | Status | Tracking |
|-----|-------|--------|----------|
| [0001](0001-identity-layer.md) | Operator / Organization / Project identity layer (+ [SSO](0001-identity-layer.amendment-sso.md) & [filtering](0001-identity-layer.amendment-filtering.md) amendments) | **Accepted** 2026-05-28 → v0.14 | [#73](https://github.com/SlanchaAi/wire/issues/73) |
| [0002](0002-token-efficient-comms.md) | Token-efficient agent-to-agent communication | Discussion | PR thread |
