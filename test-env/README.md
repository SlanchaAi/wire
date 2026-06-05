# test-env — reproducible Rust gate for wire

A throwaway container with the pinned Rust toolchain (1.88) that runs wire's
CI gate against a mounted checkout, isolated from your host's wire state dir.
Use it to validate a change locally exactly the way CI will — handy between
steps of a refactor or dead-code sweep.

## Usage

```bash
test-env/run.sh                  # full gate: fmt + clippy + test (mirrors CI)
test-env/run.sh cargo test pull  # run a specific cargo command
test-env/run.sh bash             # interactive shell in the container
```

First run builds the image (`wire-testenv`) and warms the build cache; later
runs reuse the cached `target/` and cargo registry (named Docker volumes), so
they're fast and never touch your host `target/`.

## What it mirrors

The default command is exactly the CI gate from `.github/workflows/ci.yml`:

```
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets -- --test-threads=1
```

(CI pins `--test-threads=1` for the heavy real-process e2e binaries; this
container does the same so local and CI behavior match.)

## Not the stock-Claude sandbox

This is a wire-specific build/test environment. It is **not** the
naive-first-run Claude sandbox in `dotfiles-claude/test-env` (which has no
Rust toolchain and doesn't mount the repo). Different tool, same nickname.

## Related CI

The `install-smoke` job in `.github/workflows/ci.yml` covers the
complementary angle — a fresh user's first run of the built binary (clean
PATH, no repo, offline identity creation) — so a change that compiles and
passes tests but breaks the out-of-the-box experience still gets caught.
