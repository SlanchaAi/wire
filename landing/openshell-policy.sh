#!/usr/bin/env bash
# wire — OpenShell policy bootstrap
#
# Run on the OpenShell HOST (not inside the sandbox) to grant a sandbox the
# minimum network surface wire needs to install + run against wireup.net.
#
# Usage:  curl -fsSL https://wireup.net/openshell-policy.sh | bash -s <sandbox>
#         (defaults to sandbox name "my-assistant" when no arg given)
#
# After this runs, the sandbox can:
#   curl -fsSL https://wireup.net/install.sh | sh
#   wire init <handle> --relay https://wireup.net
#   wire claim <handle>
#   wire add <peer>@wireup.net
#   wire send / wire tail / wire daemon — all single-relay, no other egress.
#
# Source + audit:  https://github.com/SlanchaAi/wire/blob/main/landing/openshell-policy.sh

set -euo pipefail

SANDBOX_NAME="${1:-my-assistant}"

if ! command -v openshell >/dev/null 2>&1; then
  echo "openshell executable not found on PATH; nothing to do." >&2
  exit 0
fi

echo "→ updating OpenShell policy for sandbox: ${SANDBOX_NAME}"

# ── Install path ────────────────────────────────────────────────────────────
# install.sh resolves /releases/latest/download/<asset> on github.com, which
# 302-redirects to one of two CDN domains for the actual binary payload.
# No api.github.com — install.sh skips the rate-limited Releases API.

openshell policy update "${SANDBOX_NAME}" --wait \
  --rule-name wire_install_github_release \
  --add-endpoint github.com:443::rest:enforce \
  --add-allow 'github.com:443:GET:/SlanchaAi/wire/releases/latest/download/*' \
  --add-allow 'github.com:443:GET:/SlanchaAi/wire/releases/download/*' \
  --binary /usr/bin/curl \
  --binary /usr/bin/wget \
  --binary /usr/local/bin/curl

openshell policy update "${SANDBOX_NAME}" --wait \
  --rule-name wire_install_github_objects \
  --add-endpoint objects.githubusercontent.com:443::rest:enforce \
  --add-endpoint release-assets.githubusercontent.com:443::rest:enforce \
  --add-allow 'objects.githubusercontent.com:443:GET:/*' \
  --add-allow 'release-assets.githubusercontent.com:443:GET:/*' \
  --binary /usr/bin/curl \
  --binary /usr/bin/wget \
  --binary /usr/local/bin/curl

# ── Runtime path — wireup.net only (single-relay at v0.5) ───────────────────
# Expand --add-endpoint if/when you start pairing against handles on other
# relay domains. Single-quote every --add-allow so the shell can't expand the
# `*` against pwd silently.

openshell policy update "${SANDBOX_NAME}" --wait \
  --rule-name wire_runtime \
  --add-endpoint wireup.net:443::rest:enforce \
  --add-allow 'wireup.net:443:GET:/install.sh' \
  --add-allow 'wireup.net:443:GET:/install' \
  --add-allow 'wireup.net:443:GET:/healthz' \
  --add-allow 'wireup.net:443:GET:/.well-known/wire/agent' \
  --add-allow 'wireup.net:443:GET:/.well-known/agent-card.json' \
  --add-allow 'wireup.net:443:GET:/v1/handles' \
  --add-allow 'wireup.net:443:GET:/v1/slot/*/state' \
  --add-allow 'wireup.net:443:GET:/v1/events/*' \
  --add-allow 'wireup.net:443:GET:/v1/events/*/stream' \
  --add-allow 'wireup.net:443:GET:/v1/pair/*' \
  --add-allow 'wireup.net:443:GET:/i/*' \
  --add-allow 'wireup.net:443:POST:/v1/slot/allocate' \
  --add-allow 'wireup.net:443:POST:/v1/handle/claim' \
  --add-allow 'wireup.net:443:DELETE:/v1/handle/claim/*' \
  --add-allow 'wireup.net:443:POST:/v1/handle/intro/*' \
  --add-allow 'wireup.net:443:POST:/v1/slot/*/responder-health' \
  --add-allow 'wireup.net:443:POST:/v1/events/*' \
  --add-allow 'wireup.net:443:POST:/v1/pair' \
  --add-allow 'wireup.net:443:POST:/v1/pair/*/bootstrap' \
  --add-allow 'wireup.net:443:POST:/v1/pair/abandon' \
  --add-allow 'wireup.net:443:POST:/v1/invite/register' \
  --binary /usr/bin/curl \
  --binary /usr/bin/wget \
  --binary /usr/local/bin/curl \
  --binary /usr/local/bin/wire \
  --binary "${HOME}/.local/bin/wire"

echo "✓ wire OpenShell policy applied to ${SANDBOX_NAME}"
echo ""
echo "next step (inside the sandbox):"
echo "  curl -fsSL https://wireup.net/install.sh | sh"
echo "  wire init <handle> --relay https://wireup.net"
