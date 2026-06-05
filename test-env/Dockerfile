# Reproducible Rust dev/test container for wire.
#
# Runs the exact gate CI runs (.github/workflows/ci.yml) — fmt, clippy,
# and the test suite — against a mounted checkout, in a clean environment
# isolated from the host's wire state dir. Use it to validate a change
# locally the same way CI will, e.g. between steps of a refactor.
#
#   Build:  docker build -t wire-testenv test-env
#   Gate:   test-env/run.sh                 # fmt + clippy + test (mirrors CI)
#   Ad-hoc: test-env/run.sh cargo test pull # any cargo command
#
# Not to be confused with the stock-Claude UX sandbox in dotfiles-claude;
# this one has the Rust toolchain and mounts the repo.
FROM rust:1.88-bookworm

# clippy + rustfmt components, and jq for the demo scripts / smoke checks.
RUN rustup component add clippy rustfmt \
    && apt-get update \
    && apt-get install -y --no-install-recommends jq \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /wire
ENV CARGO_TERM_COLOR=always

# Default command = the full CI gate. Overridden by any args passed to
# `docker run` (see run.sh).
# Non-login shell (`-c`, not `-lc`): a login shell sources /etc/profile,
# which resets PATH and drops the rust image's /usr/local/cargo/bin —
# `cargo: command not found`. `-c` inherits the image's ENV PATH.
CMD ["bash", "-c", "cargo fmt --all -- --check && cargo clippy --all-targets -- -D warnings && cargo test --all-targets -- --test-threads=1"]
