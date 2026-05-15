#!/bin/sh
# wire — one-line installer
# Usage:   curl -fsSL https://wireup.net/install.sh | sh
# Source:  https://github.com/SlanchaAi/wire/blob/main/landing/install.sh
#
# What this does:
#   1. Detect your OS + arch.
#   2. Find the latest wire release on GitHub.
#   3. Download the matching binary + SHA-256 sidecar.
#   4. Verify the checksum.
#   5. Install to ~/.local/bin/wire (or /usr/local/bin/wire if you can write
#      there). chmod +x.
#   6. Print where it landed + a "next step" hint.
#
# Honesty:
#   - This script trusts GitHub's HTTPS + the SHA-256s in the release.
#     If you'd rather build from source: `cargo install --git
#     https://github.com/SlanchaAi/wire wire`.
#   - It WILL NOT modify your shell rc files. If ~/.local/bin isn't on
#     your PATH, the script will tell you the export line to add.

set -eu

REPO="SlanchaAi/wire"
BIN_NAME="wire"

# ───── platform detection ─────
uname_s=$(uname -s 2>/dev/null || echo unknown)
uname_m=$(uname -m 2>/dev/null || echo unknown)

case "$uname_s" in
    Linux)
        case "$uname_m" in
            x86_64|amd64)  TARGET="x86_64-unknown-linux-gnu" ;;
            aarch64|arm64) TARGET="aarch64-unknown-linux-gnu" ;;
            *) echo "unsupported Linux arch: $uname_m" >&2; exit 1 ;;
        esac
        ;;
    Darwin)
        case "$uname_m" in
            arm64|aarch64) TARGET="aarch64-apple-darwin" ;;
            x86_64)
                echo "Intel Mac binary not published in v0.5 (queue-time issue on" >&2
                echo "GitHub macos-13 runners). Fall back to:" >&2
                echo "  cargo install --git https://github.com/${REPO} wire" >&2
                exit 1
                ;;
            *) echo "unsupported macOS arch: $uname_m" >&2; exit 1 ;;
        esac
        ;;
    MINGW*|MSYS*|CYGWIN*)
        echo "use the .exe from https://github.com/${REPO}/releases/latest" >&2
        exit 1
        ;;
    *)
        echo "unsupported OS: $uname_s" >&2
        echo "fall back: cargo install --git https://github.com/${REPO} wire" >&2
        exit 1
        ;;
esac

# ───── pick install dir ─────
if [ -n "${WIRE_INSTALL_DIR:-}" ]; then
    INSTALL_DIR="$WIRE_INSTALL_DIR"
elif [ -w "/usr/local/bin" ] 2>/dev/null; then
    INSTALL_DIR="/usr/local/bin"
else
    INSTALL_DIR="$HOME/.local/bin"
fi
mkdir -p "$INSTALL_DIR"

# ───── direct download URLs ─────
# Use GitHub's /releases/latest/download/<asset> alias — it 302-redirects to
# the current tag's asset without consuming the anonymous API rate limit (60
# req/hr/IP). Anonymous clients on shared NATs were 403ing during install.
echo "→ resolving latest wire release..."
DL_BIN="https://github.com/${REPO}/releases/latest/download/wire-${TARGET}"
DL_SHA="${DL_BIN}.sha256"

# ───── download + verify ─────
TMPDIR=$(mktemp -d -t wire-install.XXXXXX)
trap 'rm -rf "$TMPDIR"' EXIT

echo "→ downloading $DL_BIN"
curl -fsSL "$DL_BIN" -o "$TMPDIR/wire" || {
    echo "download failed. release artifact may not exist for $TARGET." >&2
    echo "browse: https://github.com/${REPO}/releases/tag/${TAG}" >&2
    exit 1
}

echo "→ downloading $DL_SHA"
curl -fsSL "$DL_SHA" -o "$TMPDIR/wire.sha256" || {
    echo "warning: no sha256 sidecar — skipping verification" >&2
}

if [ -f "$TMPDIR/wire.sha256" ]; then
    echo "→ verifying sha256"
    # sha256 file looks like:  "<hex>  wire-<target>"
    EXPECTED=$(awk '{print $1}' "$TMPDIR/wire.sha256")
    if command -v shasum >/dev/null 2>&1; then
        ACTUAL=$(shasum -a 256 "$TMPDIR/wire" | awk '{print $1}')
    elif command -v sha256sum >/dev/null 2>&1; then
        ACTUAL=$(sha256sum "$TMPDIR/wire" | awk '{print $1}')
    else
        echo "no shasum / sha256sum on PATH — skipping verification" >&2
        ACTUAL="$EXPECTED"
    fi
    if [ "$EXPECTED" != "$ACTUAL" ]; then
        echo "sha256 mismatch!" >&2
        echo "  expected: $EXPECTED" >&2
        echo "  actual:   $ACTUAL" >&2
        exit 1
    fi
    echo "  ok"
fi

# ───── install ─────
echo "→ installing to $INSTALL_DIR/$BIN_NAME"
chmod +x "$TMPDIR/wire"
mv "$TMPDIR/wire" "$INSTALL_DIR/$BIN_NAME"

# ───── PATH hint ─────
case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *)
        echo
        echo "$INSTALL_DIR is not on your PATH. Add it:"
        echo "  echo 'export PATH=\"$INSTALL_DIR:\$PATH\"' >> ~/.bashrc   # or ~/.zshrc"
        echo
        ;;
esac

echo
VERSION_LINE=$("$INSTALL_DIR/$BIN_NAME" --version 2>/dev/null || echo "wire")
echo "${VERSION_LINE} installed at $INSTALL_DIR/$BIN_NAME"
echo
echo "next step:"
echo "  wire init <handle> --relay https://wireup.net"
echo "  wire claim <handle>"
echo "  wire add <friend>@wireup.net"
echo
echo "source: https://github.com/${REPO}"
echo "discord: https://discord.gg/dv2Cd3xzPh"
