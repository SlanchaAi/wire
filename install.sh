#!/usr/bin/env sh
# install.sh — single-binary installer for `wire`.
#
# Usage:
#   curl -fsSL https://wire.example.com/install.sh | sh
#   curl -fsSL https://wire.example.com/install.sh | sh -s -- --prefix ~/bin
#
# What it does:
#   1. Detects platform (linux-x86_64, linux-arm64, darwin-x86_64, darwin-arm64).
#   2. Downloads the matching pre-built `wire` binary from $WIRE_DIST_URL
#      (default: https://wire.example.com/dist/<platform>/wire).
#   3. Verifies SHA-256 if a sibling .sha256 file exists at the dist URL.
#   4. Installs to $PREFIX/wire (default: $HOME/.local/bin/wire if it exists
#      and is on $PATH, else /usr/local/bin/wire — with sudo if needed).
#   5. If pre-built binary unavailable AND `cargo` is on $PATH, falls back
#      to `cargo install --git <repo>`. (Source-build path; takes ~2 min.)
#
# What it does NOT do:
#   - install systemd / launchd units (use `wire daemonize` opt-in)
#   - install gh, cloudflared, or any other system service
#   - require root unless writing to /usr/local/bin

set -eu

REPO_URL="${WIRE_REPO_URL:-https://github.com/laulpogan/wire}"
# Default release-asset URL — points at GitHub Releases produced by .github/workflows/release.yml.
# Override via WIRE_DIST_URL for testing or alternate hosts.
DIST_URL="${WIRE_DIST_URL:-${REPO_URL}/releases/latest/download}"
PREFIX="${PREFIX:-}"

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix) PREFIX="$2"; shift 2 ;;
        --prefix=*) PREFIX="${1#*=}"; shift ;;
        -h|--help)
            sed -n '/^# Usage:/,/^[^#]/p' "$0" | sed 's/^# \{0,1\}//' | head -n -1
            exit 0
            ;;
        *) echo "unknown flag: $1" >&2; exit 2 ;;
    esac
done

uname_s="$(uname -s)"
uname_m="$(uname -m)"
# Resolve target triple for a release asset matching .github/workflows/release.yml.
# Binary suffix is `.exe` on Windows shells (Git Bash / MSYS / Cygwin), empty elsewhere.
binsuffix=""
case "$uname_s" in
    Linux)
        # Prefer musl static for max-portability if available; fall back to gnu otherwise.
        case "$uname_m" in
            x86_64|amd64)  triple="x86_64-unknown-linux-musl" ;;
            aarch64|arm64) triple="aarch64-unknown-linux-musl" ;;
            *) echo "unsupported Linux arch: $uname_m" >&2; exit 1 ;;
        esac
        ;;
    Darwin)
        case "$uname_m" in
            x86_64|amd64)  triple="x86_64-apple-darwin" ;;
            aarch64|arm64) triple="aarch64-apple-darwin" ;;
            *) echo "unsupported Darwin arch: $uname_m" >&2; exit 1 ;;
        esac
        ;;
    MINGW*|MSYS*|CYGWIN*|Windows_NT)
        # Git Bash / MSYS2 / Cygwin on Windows. uname -m returns "x86_64" or "i686".
        case "$uname_m" in
            x86_64|amd64) triple="x86_64-pc-windows-msvc"; binsuffix=".exe" ;;
            *) echo "unsupported Windows arch: $uname_m (need x86_64)" >&2; exit 1 ;;
        esac
        ;;
    *) echo "unsupported OS: $uname_s" >&2; exit 1 ;;
esac

# Choose install dir.
if [ -z "$PREFIX" ]; then
    if [ -d "$HOME/.local/bin" ] && case ":$PATH:" in *":$HOME/.local/bin:"*) true ;; *) false ;; esac; then
        PREFIX="$HOME/.local/bin"
    else
        PREFIX="/usr/local/bin"
    fi
fi
mkdir -p "$PREFIX"
target="$PREFIX/wire${binsuffix}"

binary_url="$DIST_URL/wire-${triple}${binsuffix}"
echo "fetching $binary_url ..."
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

if curl -fsSL "$binary_url" -o "$tmp"; then
    # Optional SHA-256 sibling.
    if curl -fsSL "$binary_url.sha256" -o "$tmp.sha256" 2>/dev/null; then
        expected="$(awk '{print $1}' "$tmp.sha256")"
        if command -v sha256sum >/dev/null 2>&1; then
            actual="$(sha256sum "$tmp" | awk '{print $1}')"
        elif command -v shasum >/dev/null 2>&1; then
            actual="$(shasum -a 256 "$tmp" | awk '{print $1}')"
        else
            echo "warn: no sha256sum/shasum tool — skipping integrity check" >&2
            actual="$expected"
        fi
        if [ "$expected" != "$actual" ]; then
            echo "FATAL: SHA-256 mismatch — expected $expected, got $actual" >&2
            exit 1
        fi
    fi
    chmod +x "$tmp"
    if ! mv "$tmp" "$target" 2>/dev/null; then
        echo "elevating to write $target ..." >&2
        sudo mv "$tmp" "$target"
    fi
elif command -v cargo >/dev/null 2>&1; then
    echo "pre-built binary unavailable — building from source via cargo (this takes ~2 min)" >&2
    cargo install --git "$REPO_URL" --root "$(dirname "$PREFIX")" --bin wire
else
    echo "FATAL: pre-built binary unavailable and cargo not found." >&2
    echo "Install Rust from https://rustup.rs/ and re-run this script, or" >&2
    echo "git clone $REPO_URL && cd wire && cargo build --release" >&2
    exit 1
fi

if [ -x "$target" ]; then
    echo "wire installed at $target"
    echo
    "$target" --version
    echo
    echo "next steps:"
    echo "  wire init <handle>"
    echo "  wire pair-host --relay <relay-url>   # pair with a friend"
    echo
    echo "see 'wire --help' or https://github.com/laulpogan/wire for more."
fi
