# Reproducible Rust dev/test container for wire.
#
# Runs CI's behavior gate (.github/workflows/ci.yml) against a mounted
# checkout, in a clean environment isolated from the host's wire state dir:
# fmt, clippy, the test suite, AND the three demo jobs (demo-invite,
# demo-hotline, `wire demo`). The demos are shell-script integration tests
# that `cargo test` does NOT cover — they exercise the real CLI surface, so a
# removed flag / changed arg shape that compiles fine still gets caught here
# the way CI catches it. (NOT covered locally: install-smoke, docs-lint, and
# the windows build — those need a different runner.)
#
#   Build:  docker build -t wire-testenv test-env
#   Gate:   test-env/run.sh                 # fmt + clippy + test + demos
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
CMD ["bash", "-c", "cargo fmt --all -- --check && cargo clippy --all-targets -- -D warnings && cargo test --all-targets -- --test-threads=1 && cargo build --release --bin wire && WIRE=./target/release/wire bash demo-invite.sh && WIRE=./target/release/wire bash demo-hotline.sh && ./target/release/wire demo --json | grep -q '\"ok\":true' && WIRE=./target/release/wire tests/it/run-all.sh"]
