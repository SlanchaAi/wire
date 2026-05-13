# wire-relay-server — container image for Fly.io (or any OCI host).
#
# Two-stage build:
#   1. rust:bookworm builds a release binary with all deps statically except
#      libc (glibc, dynamic). Linking dynamic is fine inside debian:slim.
#   2. debian:bookworm-slim runtime, minimal surface, just ca-certificates
#      for outbound HTTPS (we don't make any, but reqwest is in the binary
#      and pulls in TLS roots transitively — harmless to keep).
#
# Build:   docker build -t wire-relay .
# Run:     docker run -p 8770:8770 -v $(pwd)/data:/data wire-relay
# Healthz: curl http://localhost:8770/healthz   # → ok

FROM rust:1.88-bookworm AS build

WORKDIR /src

# Cache deps separately from source so cargo only rebuilds the workspace
# crate on source-only changes.
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tests ./tests
COPY landing ./landing

RUN cargo build --release --bin wire

FROM debian:bookworm-slim

# ca-certificates: TLS root bundle for any outbound HTTPS the relay does
#   (currently none, but reqwest is linked in).
# tini: PID 1 reaper so SIGTERM from Fly's proxy cleanly drains in-flight
#   SSE streams instead of orphaning them.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tini \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/target/release/wire /usr/local/bin/wire

# Relay state lives on the volume Fly mounts to /data.
ENV WIRE_HOME=/data

EXPOSE 8770

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["wire", "relay-server", "--bind", "0.0.0.0:8770"]
