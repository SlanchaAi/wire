# Multi-stage build → tiny static-linked single-binary image.
# Same image runs every wire subcommand (relay-server, daemon, mcp, init, pair-host, ...)
# Pick the role at runtime via CMD.

# ---- build stage ----
FROM rust:1.88-alpine AS build

# Static-linked binary via musl. ~14 deps need build tools.
RUN apk add --no-cache musl-dev pkgconfig openssl-dev openssl-libs-static

WORKDIR /build
# Cache deps separately from source for faster rebuilds.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs && \
    cargo build --release --target $(rustc -vV | grep '^host:' | awk '{print $2}') --bin wire 2>/dev/null || true

# Now the real source.
COPY . .
RUN cargo build --release --locked --bin wire && \
    strip target/release/wire

# ---- runtime stage ----
# Distroless static — no shell, no package manager, no /tmp by default.
# Keeps attack surface near zero. Image is ~7MB total.
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /home/nonroot
COPY --from=build /build/target/release/wire /usr/local/bin/wire

# State dirs — bind-mount or volume here for persistence.
# WIRE_HOME governs both config + state paths (see src/config.rs).
ENV WIRE_HOME=/data
VOLUME ["/data"]

# Default port for relay-server. Container caller maps it to the host port
# they want; cloudflared / nginx / Caddy / k8s ingress in front handles TLS.
EXPOSE 8770

# Default = relay-server. Override CMD for client / daemon / MCP roles:
#   docker run wire daemon
#   docker run wire mcp
#   docker run -it wire init paul --relay https://relay.slancha.ai
CMD ["wire", "relay-server", "--bind", "0.0.0.0:8770"]
