<#
install.ps1 — single-binary installer for `wire` (native PowerShell).

Usage:
  iex (irm https://wireup.net/install.ps1)
  iex (irm https://wireup.net/install.ps1) -Prefix C:\Tools

What it does:
  1. Detects platform (Windows x86_64 / ARM64).
  2. Downloads the matching pre-built `wire.exe` binary from $WIRE_DIST_URL
     (default: GitHub Releases — $WIRE_REPO_URL/releases/latest/download/wire-<triple>.exe).
  3. Verifies SHA-256 if a sibling .sha256 file exists at the dist URL.
  4. Installs to $Prefix\wire.exe (default: $env:LOCALAPPDATA\Programs\wire\wire.exe,
     XDG-style user-local; no admin elevation required).
  5. Adds the install dir to the User PATH if not already present.
  6. If pre-built binary unavailable AND `cargo` is on $PATH, falls back to
     `cargo install slancha-wire` from crates.io. (Source-build path; ~2 min.)
  7. Runs `wire upgrade --check` for stale-daemon cleanup (best-effort).

What it does NOT do:
  - install Windows services (use `wire service install` opt-in)
  - install Scoop, winget, or any other package manager
  - require admin elevation unless writing outside $env:LOCALAPPDATA

Override defaults via PowerShell parameters:
  iex (& { (irm https://wireup.net/install.ps1) } -Prefix C:\bin)
  $env:WIRE_REPO_URL = "https://github.com/your-fork/wire"; iex (irm ...)
  $env:WIRE_DIST_URL = "https://your-host/dist";            iex (irm ...)
#>

[CmdletBinding()]
param(
    [string]$Prefix
)

$ErrorActionPreference = 'Stop'

$RepoUrl = if ($env:WIRE_REPO_URL) { $env:WIRE_REPO_URL } else { 'https://github.com/SlanchaAi/wire' }
$DistUrl = if ($env:WIRE_DIST_URL) { $env:WIRE_DIST_URL } else { "$RepoUrl/releases/latest/download" }

# 1. Detect arch.
$arch = $env:PROCESSOR_ARCHITECTURE
$triple = switch ($arch) {
    'AMD64' { 'x86_64-pc-windows-msvc' }
    'ARM64' { 'aarch64-pc-windows-msvc' }
    default { throw "unsupported Windows arch: $arch (need AMD64 or ARM64)" }
}

# 2. Choose install dir.
#
# Default precedence:
#   1. Explicit `-Prefix <dir>` (or PREFIX env) — always wins.
#   2. $env:LOCALAPPDATA\Programs\wire — user-local, no admin needed, XDG-equivalent.
#
# Why not $env:ProgramFiles by default? Hitting UAC on `irm | iex` interactively is
# friction (and breaks in non-interactive scripted contexts); leaving a binary at a
# path that isn't on PATH is a worse silent failure than either alternative.
# Matches what rustup-init.exe, ollama, gh, and uv all do on Windows.
if (-not $Prefix) {
    if ($env:PREFIX) {
        $Prefix = $env:PREFIX
    } else {
        $Prefix = Join-Path $env:LOCALAPPDATA 'Programs\wire'
    }
}
if (-not (Test-Path $Prefix)) {
    New-Item -ItemType Directory -Path $Prefix -Force | Out-Null
}
$target = Join-Path $Prefix 'wire.exe'

$binaryUrl = "$DistUrl/wire-$triple.exe"
Write-Host "fetching $binaryUrl ..."

$tmp = [System.IO.Path]::GetTempFileName()
$tmpExe = "$tmp.exe"
$tmpSha = "$tmp.sha256"

$downloaded = $false
try {
    Invoke-WebRequest -UseBasicParsing -Uri $binaryUrl -OutFile $tmpExe
    $downloaded = $true
} catch {
    Write-Warning "pre-built binary unavailable at $binaryUrl"
}

if ($downloaded) {
    # 3. Optional SHA-256 sibling.
    try {
        Invoke-WebRequest -UseBasicParsing -Uri "$binaryUrl.sha256" -OutFile $tmpSha
        $expected = (Get-Content $tmpSha -Raw).Trim().Split()[0]
        $actual = (Get-FileHash -Path $tmpExe -Algorithm SHA256).Hash.ToLower()
        if ($expected.ToLower() -ne $actual) {
            throw "SHA-256 mismatch — expected $expected, got $actual"
        }
    } catch [System.Net.WebException] {
        Write-Warning "no .sha256 sibling at $binaryUrl.sha256 — skipping integrity check"
    }

    # 4. Move into place. If target is currently running (the running-exe
    # rename-aside trick `wire update` uses), we fall back to renaming the
    # existing target so the move can land.
    try {
        Move-Item -Path $tmpExe -Destination $target -Force
    } catch {
        $aside = "$target.old-$(Get-Random)"
        Write-Warning "$target is in use; renaming to $aside and moving the new binary into place."
        Move-Item -Path $target -Destination $aside -Force
        Move-Item -Path $tmpExe -Destination $target
    }
} else {
    # 5. Cargo fallback.
    $cargo = Get-Command cargo -ErrorAction SilentlyContinue
    if ($cargo) {
        Write-Host 'pre-built binary unavailable — building from source via cargo install slancha-wire (~2 min)'
        $parentPrefix = Split-Path -Parent $Prefix
        try {
            & cargo install slancha-wire --root $parentPrefix
        } catch {
            Write-Warning 'crates.io install failed — falling back to git source build'
            & cargo install --git $RepoUrl --root $parentPrefix --bin wire
        }
    } else {
        Write-Error @"
pre-built binary unavailable and cargo not found.
Install Rust from https://rustup.rs/ and re-run this script, or:
  cargo install slancha-wire    (after rustup)
  git clone $RepoUrl; cd wire; cargo build --release
"@
        exit 1
    }
}

# Cleanup temp.
Remove-Item -Path $tmp, $tmpSha -ErrorAction SilentlyContinue

if (Test-Path $target) {
    Write-Host "wire installed at $target"
    Write-Host ''
    & $target --version
    Write-Host ''

    # 6. PATH check: add $Prefix to user PATH if not already present.
    # Matches install.sh's $HOME/.local/bin nudge — without the install
    # dir on PATH the user runs the install and then `wire` returns
    # "command not found".
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $pathSegs = if ($userPath) { $userPath.Split(';') } else { @() }
    $onPath = $pathSegs -contains $Prefix
    if (-not $onPath) {
        Write-Host "adding $Prefix to user PATH ..."
        $newPath = if ($userPath) { "$Prefix;$userPath" } else { $Prefix }
        [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
        # Make the change visible in THIS session too (the User PATH edit
        # only takes effect in NEW processes).
        $env:Path = "$Prefix;$env:Path"
        Write-Host "PATH updated. Open a new terminal to inherit the change."
        Write-Host ''
    }

    # 7. Stale-cleanup pass (best-effort; silently skipped on older binaries
    # that lack `upgrade --check`).
    try {
        & $target upgrade --check 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host 'running stale-cleanup pass (wire upgrade)...'
            & $target upgrade
            if ($LASTEXITCODE -ne 0) {
                Write-Warning 'wire upgrade returned non-zero; running daemons may need a manual restart'
            }
            Write-Host ''
        }
    } catch {
        # Older binaries without `upgrade --check` — silent skip.
    }

    Write-Host 'next steps:'
    Write-Host "  wire up                              # one-shot: identity + relay + claim your persona + daemon"
    Write-Host "  wire here                            # see your persona (handle == DID-derived name) + who's around"
    Write-Host "  wire dial <peer>@wireup.net          # pair a peer, then: wire send <peer> ""hi"""
    Write-Host "  wire session new --local-only        # per-project isolated identity (multi-agent box)"
    Write-Host "  wire session pair-all-local          # mesh-pair every sister"
    Write-Host ''
    Write-Host "see 'wire --help' or https://github.com/SlanchaAi/wire for more."
}
