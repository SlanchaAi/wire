#!/usr/bin/env sh
# install.sh — single-binary installer for `wire`.
#
# Usage:
#   curl -fsSL https://wireup.net/install.sh | sh
#   curl -fsSL https://wireup.net/install.sh | sh -s -- --prefix ~/bin
#
# What it does:
#   1. Detects platform (linux x86_64/arm64, darwin arm64, windows x86_64 via Git Bash/MSYS).
#   2. Downloads the matching pre-built `wire` binary from $WIRE_DIST_URL
#      (default: GitHub Releases — $REPO_URL/releases/latest/download/wire-<triple>).
#   3. Verifies SHA-256 if a sibling .sha256 file exists at the dist URL.
#   4. Installs to $PREFIX/wire (default: $HOME/.local/bin/wire if it exists
#      and is on $PATH, else /usr/local/bin/wire — with sudo if needed).
#   5. If pre-built binary unavailable AND `cargo` is on $PATH, falls back
#      to `cargo install slancha-wire` from crates.io. (Source-build path;
#      takes ~2 min. The package is named `slancha-wire` on crates.io
#      because the bare `wire` name is squatted by an unrelated 2014 crate;
#      the installed binary is still `wire`.)
#
# What it does NOT do:
#   - install systemd / launchd units (use `wire daemonize` opt-in)
#   - install gh, cloudflared, or any other system service
#   - require root unless writing to /usr/local/bin

set -eu

REPO_URL="${WIRE_REPO_URL:-https://github.com/SlanchaAi/wire}"
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
#
# Default precedence:
#   1. Explicit `--prefix <dir>` (or PREFIX env) — always wins.
#   2. Running as root → /usr/local/bin (no sudo needed, system-wide).
#   3. Else → $HOME/.local/bin (XDG-standard, no sudo prompt). We CREATE the
#      directory if it doesn't exist and warn at the end if it isn't on $PATH
#      so the operator knows the one-line fix to make `wire` discoverable.
#
# Why not default to /usr/local/bin? Hitting sudo on `curl | sh` interactively
# is friction (and breaks in non-interactive `sh -c` / CI / Docker contexts);
# leaving a binary at a path that isn't on $PATH is a worse silent failure than
# either of the alternatives. Matches what `rustup` / `uv` / `ollama` /
# `cargo install` all do.
if [ -z "$PREFIX" ]; then
    if [ "$(id -u 2>/dev/null || echo 1000)" = "0" ]; then
        PREFIX="/usr/local/bin"
    else
        PREFIX="$HOME/.local/bin"
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
    echo "pre-built binary unavailable — building from source via cargo install slancha-wire (~2 min)" >&2
    # Prefer crates.io (slancha-wire) over git pin so users get pinned-version semantics.
    # If that fails (offline / mirror down), fall back to the git path.
    if ! cargo install slancha-wire --root "$(dirname "$PREFIX")"; then
        echo "crates.io install failed — falling back to git source build" >&2
        cargo install --git "$REPO_URL" --root "$(dirname "$PREFIX")" --bin wire
    fi
else
    echo "FATAL: pre-built binary unavailable and cargo not found." >&2
    echo "Install Rust from https://rustup.rs/ and re-run this script, or" >&2
    echo "  cargo install slancha-wire    (after rustup)" >&2
    echo "  git clone $REPO_URL && cd wire && cargo build --release" >&2
    exit 1
fi

if [ -x "$target" ]; then
    echo "wire installed at $target"
    echo
    "$target" --version
    echo

    # PATH check: warn if $PREFIX isn't on $PATH so the operator gets the
    # exact one-line fix instead of an opaque "command not found: wire" on
    # the next invocation. Default install dir ($HOME/.local/bin) ISN'T on
    # $PATH on many shells out-of-the-box (notably zsh + bash on macOS
    # before Sequoia, and minimal Linux distros). Without this nudge, the
    # user runs the install and then can't find `wire`.
    on_path="no"
    case ":$PATH:" in *":$PREFIX:"*) on_path="yes" ;; esac
    if [ "$on_path" = "no" ]; then
        # Detect the operator's interactive shell so we name the right rc
        # file. SHELL env is set by login shells everywhere we care about
        # (macOS, Linux, WSL, Git Bash); fall back to the binary basename
        # of $SHELL, then to "your shell" if even that fails.
        shell_name=""
        if [ -n "${SHELL:-}" ]; then
            shell_name="$(basename "$SHELL" 2>/dev/null || echo "")"
        fi
        case "$shell_name" in
            zsh)  rc="$HOME/.zshrc" ;;
            bash)
                # bash reads ~/.bashrc on interactive non-login shells; on
                # macOS login shells (Terminal.app default) read .bash_profile.
                # Recommend .bashrc but mention .bash_profile for macOS users.
                rc="$HOME/.bashrc"
                ;;
            fish) rc="$HOME/.config/fish/config.fish" ;;
            *)    rc="" ;;
        esac
        echo "WARNING: $PREFIX is NOT on your \$PATH — running 'wire' will fail" >&2
        echo "         until you add it. One-line fix:" >&2
        echo >&2
        if [ "$shell_name" = "fish" ]; then
            echo "  fish_add_path $PREFIX" >&2
            if [ -n "$rc" ]; then
                echo "  # (or append to $rc:)" >&2
                echo "  echo 'fish_add_path $PREFIX' >> $rc" >&2
            fi
        elif [ -n "$rc" ]; then
            echo "  echo 'export PATH=\"$PREFIX:\$PATH\"' >> $rc" >&2
            echo "  source $rc                          # reload current shell" >&2
            if [ "$shell_name" = "bash" ] && [ "$uname_s" = "Darwin" ]; then
                echo "  # macOS Terminal.app reads ~/.bash_profile for login shells;" >&2
                echo "  # add the same line there if 'wire' still isn't found after relogin." >&2
            fi
        else
            echo "  # Add this line to your shell's startup file (~/.zshrc, ~/.bashrc, etc.):" >&2
            echo "  export PATH=\"$PREFIX:\$PATH\"" >&2
        fi
        echo >&2
        echo "         Or run wire directly via its absolute path: $target" >&2
        echo
    fi

    # v0.6.8: stale-cleanup pass. After replacing the binary in place,
    # old daemons may still be running (with the previous binary text
    # loaded in memory) and old pidfiles may point at processes that
    # have just been clobbered. Running `wire upgrade` here:
    #   - kills any wire daemon still alive from the old binary,
    #   - wipes stale pidfiles across every session,
    #   - respawns session daemons under the new binary,
    #   - warns if multiple wire binaries are on $PATH (the most common
    #     "I updated but it's still broken" cause).
    # Best effort: silent skip on older binaries that lack `upgrade`.
    if "$target" upgrade --check >/dev/null 2>&1; then
        echo "running stale-cleanup pass (wire upgrade)..."
        "$target" upgrade || echo "warn: wire upgrade returned non-zero; running daemons may need a manual restart" >&2
        echo
    fi

    echo "next steps:"
    # If wire isn't on $PATH, the next-steps need the absolute path so
    # operators can copy-paste them and have them actually run.
    if [ "$on_path" = "yes" ]; then
        wire_cmd="wire"
    else
        wire_cmd="$target"
        echo "  # NOTE: \$PATH doesn't include $PREFIX (see warning above);"
        echo "  # commands below use the absolute path. After fixing \$PATH"
        echo "  # you can drop the path and just say 'wire <verb>'."
    fi
    echo "  $wire_cmd up                              # one-shot: identity + relay + claim your persona + daemon"
    echo "  $wire_cmd here                            # see your persona (handle == DID-derived name) + who's around"
    echo "  $wire_cmd dial <peer>@wireup.net          # pair a peer, then: $wire_cmd send <peer> \"hi\""
    echo "  $wire_cmd session new --local-only        # per-project isolated identity (multi-agent box)"
    echo "  $wire_cmd session pair-all-local          # mesh-pair every sister"
    echo
    echo "see '$wire_cmd --help' or https://github.com/SlanchaAi/wire for more."
fi
