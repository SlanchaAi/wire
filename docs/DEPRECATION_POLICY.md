# wire deprecation policy

> Status: in force from 1.0. Pre-1.0 (0.x) wire shipped fast and broke surfaces
> freely (see README "Status & API stability"); this policy is the promise that
> replaces that freedom **at 1.0**.

## What this covers

1.0 freezes five surfaces (see `ROAD_TO_1.0.md` §1). This document says how any of
them may *change* after 1.0 — the contract is **a deprecation window, never a
silent break**:

1. **Identities & pairings** — a DID/pairing that worked in 1.0 keeps working.
2. **On-disk state** — `sessions/`, `trust.json`, `relay.json`, pidfile schema.
3. **The wire protocol** — event kinds, the agent-card schema (`v3.x`), the
   signing/canonicalization rules, the relay HTTP surface.
4. **The operator/agent surface** — CLI verbs, `--json` output shapes, the MCP
   tool catalog (names + input schemas), the file-system contract.
5. **Security posture honesty** — the threat model matches the code.

## Versioning

wire is semver-ish from 1.0:

- **MAJOR** (`2.0`) — may *remove* anything previously deprecated, and may make
  breaking on-disk/protocol changes (with a migration). A removal can only land
  in a MAJOR, and only after the deprecation window below.
- **MINOR** (`1.x`) — additive only. New CLI verbs, new `--json` *fields* (never
  removed/renamed ones), new MCP tools, new optional agent-card fields. Existing
  consumers keep working unchanged. This is where almost everything lands —
  the `v3.x` agent card is additive/forward-compatible by design, so the
  org/identity layer can grow across 1.x without a major.
- **PATCH** (`1.0.x`) — bug/security fixes only, no surface change.

## The deprecation window

To remove or break a frozen surface element (a CLI verb, a `--json` field, an
MCP tool or one of its params, an on-disk field):

1. **Announce** in the release that first deprecates it: a `### Deprecated`
   CHANGELOG entry naming the element, the replacement, and the earliest version
   it may be removed.
2. **Warn at runtime** where feasible — a deprecated CLI verb/flag prints a
   one-line stderr deprecation notice (not an error); a deprecated `--json`
   field stays present and gains a sibling `*_deprecated: true` marker where it
   matters; a deprecated MCP tool keeps responding and its description is
   prefixed `DEPRECATED:`.
3. **Wait at least one MINOR release _and_ ≥ 90 days**, whichever is longer,
   with the deprecation live. (Security-forced removals may compress this — see
   below — but must still announce + provide a migration.)
4. **Remove only in the next MAJOR**, listing it under `### Removed` with the
   migration.

A consumer that pins a `1.x` version and ignores deprecation warnings will still
work until they choose to move to `2.0`.

## What is explicitly NOT frozen by 1.0

These may change in a MINOR without a deprecation window, because 1.0 never
promised them — they are documented as out-of-scope/experimental:

- Anything in `BACKLOG.md` marked deferred (MLS group confidentiality, forward
  secrecy, multi-relay redundancy, file-share, registry).
- Internal-only output behind a documented `--unstable`/experimental flag.
- Human-facing prose: `--help` wording, log lines, stderr phrasing (the *machine*
  surface — `--json`, exit codes — is frozen; the prose around it is not).

**Note — org-SSO is supported, not windowless.** The OIDC/SSO channel
(RFC-001 amendment §B–§E) is a supported 1.0 feature, *not* an exception above:
its wire-side contract (`ORG_VERIFIED` tier + `org_attestation.via` provenance +
the DNS-TXT floor) is **frozen**, and its IdP-integration *config* (JWKS, claims
mapping, tenant/issuer shape) changes only **through the deprecation window** —
the external-dependency churn is real, so the config is iterable, but never
silently.

## Enforcement

- The MCP tool catalog (names + input-schema props + required) is golden-locked
  by `mcp_catalog_schema_is_frozen` (`src/mcp.rs` tests) — a diff there fails CI
  and forces an explicit, reviewed surface change + this policy's window.
- `--json` shapes for the load-bearing builders are schema-locked in unit tests
  (e.g. `send::delivery_json`). Extending that lock to every `--json` surface is
  ongoing 1.0-hardening work.
- Doc/tool drift (PLUGIN.md vs `tool_defs()`) is guarded by
  `agent_docs_match_advertised_tools` (#255).

## Exceptions

- **Security.** A vulnerability may force a faster removal/break than the window
  allows. Even then: announce in the release, document the migration, and prefer
  a compatibility shim over a hard break where one exists.
- **Pre-1.0 state.** Nothing here applies retroactively to 0.x; the 0.x→1.0 step
  may require a one-time `wire nuke` + re-pair (RFC-005/006), called out in the
  1.0 release notes.
