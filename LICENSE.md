# License — Trio Split

The `wire` project uses three licenses corresponding to three audiences. This file is the human-readable explanation; the canonical legal texts live in `LICENSES/AGPL-3.0-or-later.txt`, `LICENSES/Apache-2.0.txt`, and `LICENSES/MIT.txt`, and the machine-readable per-file mapping lives in [`REUSE.toml`](REUSE.toml) (the [REUSE 3.3](https://reuse.software) spec).

The model follows [atuin](https://atuin.sh/)'s pattern of separating server/spec/client by license, except our server is AGPL (not closed-source).

## Server — AGPL-3.0

Files: `src/relay_server.rs`, and any future server-side daemon code it grows into.

Why AGPL: forks that host the relay as a SaaS must share their changes back. This prevents the Elasticsearch / MongoDB / Redis-style relicensing, where a vendor takes the OSS code and offers a closed-source SaaS.

If you self-host the relay for your own use (including for friends/customers/colleagues), AGPL imposes no extra burden — only "share modifications back if you make them publicly available as a service."

## Spec — Apache-2.0

Files: `docs/PROTOCOL.md`, and the protocol surface in `src/signing.rs`, `src/agent_card.rs`, and `src/canonical.rs` (the parts that define event schemas, kind ranges, canonical bytes, and the signature algorithm).

Why Apache: the protocol should be implementable in any language by anyone, including in commercial closed-source products. We want the wire protocol to be MORE compatible than competitors, not less.

## Client — MIT

Files: `src/cli.rs`, `src/sas.rs`, `src/relay_client.rs`, `src/config.rs`, `src/trust.rs`, the `wire` CLI binary, and everything else under `src/` not named above.

Why MIT: the client is meant to be embedded everywhere — claude-agent-sdk plugins, MCP server wrappers, custom integrations. MIT removes friction from this embedding.

## How we determine which license applies

The authoritative, machine-readable mapping is [`REUSE.toml`](REUSE.toml). In prose, treat the license as scoped per-file by role:

- `src/relay_server.rs` (and future server-side daemon code) = AGPL effective scope
- `docs/PROTOCOL.md` + the protocol-surface files (`src/signing.rs`, `src/agent_card.rs`, `src/canonical.rs`) = Apache effective scope
- Everything else (the CLI + protocol-supporting code) = MIT

Run `reuse lint` to verify the mapping is complete and consistent.

## If you want to use this code

- **Embedding the CLI in your tool:** MIT license applies. Take, modify, ship closed-source if you want.
- **Implementing the protocol from scratch in another language:** Apache license applies. Take the spec, implement in Rust/Go/JS/whatever.
- **Hosting the relay as a SaaS service:** AGPL applies. Your modifications to the server code must be made available to your service users.
- **Any combination of the above:** apply the most-restrictive license to the union of the parts you used.

## Why not single-license?

Single AGPL would chill CLI embedding. Single Apache would let a vendor close-fork the relay as SaaS. Single MIT would do both badly. The trio split mirrors the actual three audiences (client embedders, protocol implementers, hosted-service operators) with appropriate trade-offs for each.

This decision is locked. See [`ANTI_FEATURES.md`](ANTI_FEATURES.md) for the analysis that produced it.
