# Scoop manifest for wire

`wire.json` here is the [Scoop](https://scoop.sh/) manifest for installing wire on Windows.

## How to publish this manifest

The manifest needs to live in a Scoop **bucket** (a separate git repo Scoop reads from). Two paths to publish it:

### Path A — Submit to the `extras` bucket (community-curated)

```powershell
# Operator workflow:
# 1. Fork https://github.com/ScoopInstaller/Extras
# 2. Copy scoop/wire.json from this repo to bucket/wire.json in the fork
# 3. Open a PR; once merged: `scoop install extras/wire` works for everyone
```

### Path B — Stand up `SlanchaAi/scoop-bucket` (Slancha-controlled)

```powershell
# Operator workflow:
# 1. Create empty repo: SlanchaAi/scoop-bucket
# 2. Copy scoop/wire.json from this repo to wire.json (at the repo root)
# 3. End-user UX:
#    scoop bucket add slancha https://github.com/SlanchaAi/scoop-bucket
#    scoop install slancha/wire
```

Path B keeps the manifest under Slancha control and is the recommended starting point until wire's release cadence stabilizes.

## Auto-update

`wire.json` includes a `checkver` + `autoupdate` block that points at the GitHub releases page. Scoop's `scoop checkver` / `scoop bucket auto-update` will pick up new wire releases automatically — no manual hash maintenance after a release ships.

After every wire release:

```powershell
scoop bot                              # in the bucket repo
# or manually:
.\bin\checkver.ps1 wire -update
```

The hash placeholders (`0000…`) in this initial manifest will be overwritten on the first `checkver -update` run; intentional, since the live release hashes haven't been minted yet.

## Verifying the manifest locally (no bucket needed)

```powershell
scoop install .\scoop\wire.json
```

Scoop will install directly from the local file, useful for dry-running the manifest before publishing.

## Architecture coverage

The manifest currently ships **Windows x86_64 only**. Windows ARM64 is intentionally omitted because `.github/workflows/release.yml` does not yet build the `aarch64-pc-windows-msvc` target — pointing at a 404 URL would hard-fail Scoop installs on ARM64 boxes. When release.yml adds the ARM64 target, restore the `arm64` block:

```json
"arm64": {
    "url": "https://github.com/SlanchaAi/wire/releases/latest/download/wire-aarch64-pc-windows-msvc.exe#/wire.exe",
    "hash": "sha256:..."
}
```

ARM64 PowerShell users in the meantime get a clean fallback via `install.ps1`: the script falls through to `cargo install slancha-wire` from source when no prebuilt binary exists for their triple.

## References

- Scoop docs: https://scoop.sh/
- App manifests reference: https://github.com/ScoopInstaller/Scoop/wiki/App-Manifests
- Tracking issue: [#149](https://github.com/SlanchaAi/wire/issues/149)
