#!/usr/bin/env bash
# Run wire's gate (or any cargo command) in the reproducible Rust container.
#
# Mirrors CI (.github/workflows/ci.yml). The repo is mounted read-write; the
# build cache (target/) and the cargo registry live in named Docker volumes,
# so the host's target/ is never clobbered and rebuilds stay warm between
# runs.
#
#   test-env/run.sh                  # full gate: fmt + clippy + test
#   test-env/run.sh cargo test pull  # ad-hoc: run a specific cargo command
#   test-env/run.sh bash             # drop into a shell in the container
#
set -euo pipefail

IMAGE=wire-testenv
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

command -v docker >/dev/null 2>&1 || { echo "docker not found on PATH" >&2; exit 1; }

# Always (re)build so Dockerfile / entrypoint / CMD changes are actually picked
# up — docker's layer cache makes an unchanged build near-instant. The previous
# "only build if the image is missing" check silently ran a STALE image after a
# Dockerfile edit (a newly-added gate step never executed, yet the gate still
# reported green).
docker build -t "$IMAGE" "$ROOT/test-env"

# Allocate a TTY only when attached to one (so CI / pipes don't break).
tty_flag=()
[ -t 0 ] && [ -t 1 ] && tty_flag=(-it)

exec docker run --rm "${tty_flag[@]}" \
  -v "$ROOT:/wire" \
  -v wire-testenv-target:/wire/target \
  -v wire-testenv-cargo-registry:/usr/local/cargo/registry \
  -w /wire \
  "$IMAGE" "$@"
