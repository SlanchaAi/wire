# License — Trio Split

The `wire` project uses three licenses corresponding to three audiences. This file is the explanation; the canonical legal text lives in `LICENSE-AGPL`, `LICENSE-APACHE`, and `LICENSE-MIT`.

The model follows [atuin](https://atuin.sh/)'s pattern of separating server/spec/client by license, except our server is AGPL (not closed-source).

## Server — AGPL-3.0

Files: `wire/relay_server.py`, any future server-side daemon code.

Why AGPL: forks that host the relay as a SaaS must share their changes back. This prevents the elastic-search / MongoDB / redis-style relicensing, where a vendor takes the OSS code and offers a closed-source SaaS.

If you self-host the relay for your own use (including for friends/customers/colleagues), AGPL imposes no extra burden — only "share modifications back if you make them publicly available as a service."

## Spec — Apache-2.0

Files: `docs/PROTOCOL.md`, the protocol surface in `wire/signing.py`, `wire/agent_card.py` (the parts that define event schemas, kind ranges, canonical bytes, sig algorithm).

Why Apache: the protocol should be implementable in any language by anyone, including in commercial closed-source products. We want the wire protocol to be MORE compatible than competitors, not less.

## Client — MIT

Files: `wire/cli.py`, `wire/sas.py`, `wire/relay_client.py`, `wire/config.py`, `wire/trust.py`, the `wire` CLI binary.

Why MIT: the client is meant to be embedded everywhere — claude-agent-sdk plugins, MCP server wrappers, custom integrations. MIT removes friction from this embedding.

## How we determine which license applies

For now, treat the license as scoped per-file based on the directory + role:
- Anything under `wire/` that the relay-server imports + serves = AGPL effective scope
- Anything under `docs/PROTOCOL.md` = Apache effective scope
- Everything else (CLI + protocol-supporting code) = MIT

Per-file SPDX headers will be added at v0.1.1; treat this `LICENSE.md` as the authoritative interpretation until then.

## If you want to use this code

- **Embedding the CLI in your tool:** MIT license applies. Take, modify, ship closed-source if you want.
- **Implementing the protocol from scratch in another language:** Apache license applies. Take the spec, implement in Rust/Go/JS/whatever.
- **Hosting the relay as a SaaS service:** AGPL applies. Your modifications to the server code must be made available to your service users.
- **Any combination of the above:** apply the most-restrictive license to the union of the parts you used.

## Why not single-license?

Single AGPL would chill CLI embedding. Single Apache would let a vendor close-fork the relay as SaaS. Single MIT would do both badly. The trio split mirrors the actual three audiences (client embedders, protocol implementers, hosted-service operators) with appropriate trade-offs for each.

This decision is locked. See `ANTI_FEATURES.md` and the upstream R&D `R3_OSS_VERDICT.md` for the analysis that produced it.
