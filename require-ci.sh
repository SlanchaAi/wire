#!/usr/bin/env bash
# Require all CI checks to pass before anything merges to main.
# Run once (needs repo admin). Re-run to update the required-check list.
set -euo pipefail
gh api -X PUT repos/SlanchaAi/wire/branches/main/protection --input - <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "checks": [
      {"context": "test"},
      {"context": "fmt"},
      {"context": "clippy"},
      {"context": "docs-lint"},
      {"context": "demo-command"},
      {"context": "demo-invite"},
      {"context": "demo-hotline"},
      {"context": "install-smoke"},
      {"context": "install-smoke-windows"},
      {"context": "install-script-smoke"},
      {"context": "integration-tests"}
    ]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": null,
  "restrictions": null
}
JSON
echo "✓ main now requires all CI checks green (and up-to-date) before merge."
