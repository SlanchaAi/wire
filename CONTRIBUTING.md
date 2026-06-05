# Contributing to wire

Thanks for your interest. wire is early and largely solo-maintained, but contributions — bug reports, fixes, docs, protocol implementations — are welcome.

## Ground rules

- **Open an issue first** for anything non-trivial, so we can agree on the approach before you write code.
- **Keep PRs focused.** One logical change per PR; small, reviewable diffs land fastest.
- Be excellent to each other. Assume good faith.

## Development setup

wire is Rust (edition 2024, MSRV **1.88**). The relay is part of the same crate; there is no separate server repo.

```bash
git clone https://github.com/SlanchaAi/wire
cd wire
cargo build              # debug binary at target/debug/wire
cargo test               # the suite is hermetic — runs clean in parallel
```

## The gates (CI enforces all three)

Run these locally before pushing — CI will reject a PR that fails any of them:

```bash
cargo fmt --check                          # formatting
cargo clippy --all-targets -- -D warnings  # lints, warnings are errors
cargo test                                 # full suite
```

Tests are isolated (no shared global state) — if you add a test that touches process env or the wire state dir, route it through `config::test_support::with_temp_home` so it holds the shared `ENV_LOCK` and doesn't race other tests.

## Pull request flow

1. Branch off `main` (`fix/…`, `feat/…`, `docs/…`, `chore/…`).
2. Make atomic commits with a real "why" in the body.
3. Run the three gates locally — green or don't push.
4. Open the PR; describe what changed, why, and how you verified it.
5. CI must be fully green (incl. the demo + docs-lint jobs) before merge.

## Sign your commits (DCO)

We use the [Developer Certificate of Origin](https://developercertificate.org/) — a lightweight, no-paperwork way to certify you wrote (or have the right to submit) your contribution. Add a `Signed-off-by` line to every commit:

```bash
git commit -s -m "fix: …"
```

This appends `Signed-off-by: Your Name <you@example.com>` using your `git config user.name/user.email`. PRs without sign-off will be asked to amend.

## Licensing of contributions

wire is **multi-licensed by component** (the "trio split") — see [`LICENSE.md`](LICENSE.md) and the machine-readable [`REUSE.toml`](REUSE.toml):

- relay/server code → **AGPL-3.0**
- protocol spec surface → **Apache-2.0**
- client / CLI / everything else → **MIT**

By submitting a contribution, you agree it is licensed under the license that already applies to the file(s) you touch, as defined by `REUSE.toml`. If your change adds a new file, it inherits the license of its directory/role per the same rules — call it out in your PR if you're unsure which applies.

## Good first issues

Look for [`good first issue`](https://github.com/SlanchaAi/wire/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) and [`help wanted`](https://github.com/SlanchaAi/wire/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22).

## Pointers

- Protocol / on-wire format: [`docs/PROTOCOL.md`](docs/PROTOCOL.md)
- Security model: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)
- Release history: [`CHANGELOG.md`](CHANGELOG.md)

## Questions

Ask in [Discord](https://discord.gg/dv2Cd3xzPh) or open a discussion/issue.
