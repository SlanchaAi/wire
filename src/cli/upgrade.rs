use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};

use super::ServiceAction;

// ---------- service (install / uninstall / status) ----------

pub(crate) fn cmd_service(action: ServiceAction) -> Result<()> {
    let kind = |local_relay: bool| {
        if local_relay {
            crate::service::ServiceKind::LocalRelay
        } else {
            crate::service::ServiceKind::Daemon
        }
    };
    let (report, as_json) = match action {
        ServiceAction::Install { local_relay, json } => {
            (crate::service::install_kind(kind(local_relay))?, json)
        }
        ServiceAction::Uninstall { local_relay, json } => {
            (crate::service::uninstall_kind(kind(local_relay))?, json)
        }
        ServiceAction::Status { local_relay, json } => {
            (crate::service::status_kind(kind(local_relay))?, json)
        }
    };
    if as_json {
        println!("{}", serde_json::to_string(&report)?);
    } else {
        println!("wire service {}", report.action);
        println!("  platform:  {}", report.platform);
        println!("  unit:      {}", report.unit_path);
        println!("  status:    {}", report.status);
        println!("  detail:    {}", report.detail);
    }
    Ok(())
}

// ---------- update (self-update from crates.io / prebuilt release) ----------

const CRATE_NAME: &str = "slancha-wire";

/// (target-triple, binary-extension) of the GitHub release asset for THIS
/// platform — names mirror `.github/workflows/release.yml`. `None` if no
/// prebuilt is published for this target.
fn release_asset_triple() -> Option<(&'static str, &'static str)> {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        return Some(("x86_64-pc-windows-msvc", ".exe"));
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        return Some(("aarch64-apple-darwin", ""));
    }
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    {
        return Some(("x86_64-apple-darwin", ""));
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        return Some(("x86_64-unknown-linux-musl", ""));
    }
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    {
        return Some(("aarch64-unknown-linux-musl", ""));
    }
    #[allow(unreachable_code)]
    None
}

/// Latest stable version published on crates.io.
fn fetch_latest_published_version() -> Result<String> {
    let url = format!("https://crates.io/api/v1/crates/{CRATE_NAME}");
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()?;
    let resp = client
        .get(&url)
        // crates.io rejects requests without a descriptive User-Agent (403).
        .header(
            "User-Agent",
            format!("wire/{} (self-update)", env!("CARGO_PKG_VERSION")),
        )
        .send()?;
    if !resp.status().is_success() {
        bail!("crates.io returned {} for {CRATE_NAME}", resp.status());
    }
    let v: Value = resp.json()?;
    v.get("crate")
        .and_then(|c| {
            c.get("max_stable_version")
                .or_else(|| c.get("newest_version"))
        })
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| anyhow!("crates.io response missing crate.max_stable_version"))
}

/// True iff `latest` is strictly newer than `current` (numeric major.minor.patch;
/// pre-release suffixes ignored).
fn version_is_newer(latest: &str, current: &str) -> bool {
    let parse = |s: &str| -> (u64, u64, u64) {
        let core = s.split('-').next().unwrap_or(s);
        let mut it = core.split('.').map(|p| p.parse::<u64>().unwrap_or(0));
        (
            it.next().unwrap_or(0),
            it.next().unwrap_or(0),
            it.next().unwrap_or(0),
        )
    };
    parse(latest) > parse(current)
}

fn cargo_on_path() -> bool {
    std::process::Command::new("cargo")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Download the prebuilt release binary for `latest` and replace THIS binary
/// in place — the toolchain-free update path (for boxes with no `cargo`).
fn self_update_from_release(latest: &str) -> Result<()> {
    let (triple, ext) = release_asset_triple().ok_or_else(|| {
        anyhow!(
            "no prebuilt release binary for this platform — install a Rust toolchain and re-run, \
             or `cargo install {CRATE_NAME}`"
        )
    })?;
    let base =
        format!("https://github.com/SlanchaAi/wire/releases/download/v{latest}/wire-{triple}{ext}");
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()?;
    let resp = client
        .get(&base)
        .header("User-Agent", "wire-self-update")
        .send()?;
    if !resp.status().is_success() {
        bail!("downloading {base} returned {}", resp.status());
    }
    let bytes = resp.bytes()?;

    // Verify the SHA-256 sidecar if present (best-effort; absence is non-fatal).
    if let Ok(sha) = client
        .get(format!("{base}.sha256"))
        .header("User-Agent", "wire-self-update")
        .send()
        && sha.status().is_success()
    {
        let expected = sha
            .text()?
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_string();
        if !expected.is_empty() {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(&bytes);
            let actual = hex::encode(h.finalize());
            if expected != actual {
                bail!(
                    "SHA-256 mismatch — expected {expected}, got {actual} (aborting, binary NOT replaced)"
                );
            }
        }
    }

    let exe = std::env::current_exe().context("locating current exe")?;
    let dir = exe
        .parent()
        .ok_or_else(|| anyhow!("current exe has no parent dir"))?;
    let tmp = dir.join(format!(".wire-update-{}", std::process::id()));
    std::fs::write(&tmp, &bytes).with_context(|| format!("writing {tmp:?}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755));
        // Unix: rename over the running binary — the running process keeps the
        // old inode; the new file takes the path for the next invocation.
        std::fs::rename(&tmp, &exe).with_context(|| format!("replacing {exe:?}"))?;
    }
    #[cfg(windows)]
    {
        // Windows can't overwrite a running .exe — rename it aside first
        // (allowed even while running), then move the new one into place.
        let old = exe.with_extension("old");
        let _ = std::fs::remove_file(&old);
        std::fs::rename(&exe, &old)
            .with_context(|| format!("renaming running exe {exe:?} aside"))?;
        std::fs::rename(&tmp, &exe).with_context(|| format!("installing new exe at {exe:?}"))?;
    }
    Ok(())
}

/// Outcome of the crates.io self-update step (the front half of `wire upgrade`).
struct UpdateOutcome {
    current: String,
    latest: String,
    /// A newer stable version is published.
    available: bool,
    /// We actually installed it this run.
    installed: bool,
    /// How it was installed ("cargo install" / "prebuilt release binary").
    via: Option<&'static str>,
}

/// Check crates.io for a newer published wire and, when `install` is true,
/// self-install it (cargo if a toolchain is on PATH, else the prebuilt release
/// binary). The front half of `wire upgrade`; `install=false` is check-only.
fn self_update_step(install: bool) -> Result<UpdateOutcome> {
    let current = env!("CARGO_PKG_VERSION").to_string();
    let latest = fetch_latest_published_version().context("checking crates.io for latest wire")?;
    let available = version_is_newer(&latest, &current);
    if !install || !available {
        return Ok(UpdateOutcome {
            current,
            latest,
            available,
            installed: false,
            via: None,
        });
    }
    let via = if cargo_on_path() {
        eprintln!(
            "wire upgrade: {current} → {latest} — installing via `cargo install {CRATE_NAME}` …"
        );
        let status = std::process::Command::new("cargo")
            .args([
                "install",
                CRATE_NAME,
                "--version",
                &latest,
                "--force",
                "--locked",
            ])
            .status()
            .context("running cargo install")?;
        if !status.success() {
            bail!("`cargo install {CRATE_NAME}` failed");
        }
        "cargo install"
    } else {
        eprintln!(
            "wire upgrade: {current} → {latest} — no `cargo` on PATH, downloading the prebuilt release binary …"
        );
        self_update_from_release(&latest)?;
        "prebuilt release binary"
    };
    Ok(UpdateOutcome {
        current,
        latest,
        available,
        installed: true,
        via: Some(via),
    })
}

// ---------- upgrade (atomic daemon swap) ----------

/// `wire upgrade` — kill all running `wire daemon` processes, spawn a
/// fresh one from the currently-installed binary, write a new versioned
/// pidfile. The fix for today's exact failure mode: a daemon process that
/// kept running OLD binary text in memory under a symlink that had since
/// been repointed at a NEW binary on disk.
///
/// Idempotent. If no stale daemon is running, just starts a fresh one
/// (same as `wire daemon &` but with the wait-until-alive guard from
/// ensure_up::ensure_daemon_running).
///
/// `--check` mode reports drift without acting — lists the processes
/// that WOULD be killed and the binary version of each.
///
/// Session-scoped upgrade kill set (v0.13.2, B fix): THIS session's own daemon
/// (`my_pid`, from its pidfile — reliable even when the OS process scan can't
/// see it, as on Windows) plus TRUE orphans (found `wire daemon` pids owned by
/// no session), EXCLUDING sibling sessions' daemons. Pure + unit-tested so the
/// session-scoping is locked — the box-wide predecessor accumulated daemons.
pub(crate) fn upgrade_kill_set(
    my_pid: Option<u32>,
    found_daemon_pids: &[u32],
    owned_session_pids: &std::collections::HashSet<u32>,
) -> Vec<u32> {
    let mut k: Vec<u32> = Vec::new();
    if let Some(p) = my_pid {
        k.push(p);
    }
    for &p in found_daemon_pids {
        if !owned_session_pids.contains(&p) && Some(p) != my_pid {
            k.push(p); // true orphan — owned by no session
        }
    }
    k.sort_unstable();
    k.dedup();
    k
}

/// One distinct `wire` binary discovered on `$PATH`, with enrichment used by
/// the `wire upgrade` PATH-shadowing diagnostic (issue #80).
///
/// "Distinct" = unique canonical path; symlink chains collapse to a single
/// entry at the FIRST PATH position that surfaced them. This is what
/// `which -a` would show modulo symlink dedup.
#[derive(Debug, Clone)]
struct PathWireBinary {
    /// PATH entry under which this binary was discovered (NOT canonicalized,
    /// so the operator sees the path they wrote in their shell config).
    path: std::path::PathBuf,
    /// Canonical filesystem path (symlinks resolved). Used for dedup so a
    /// symlink that points at the real binary doesn't show up as a second
    /// "distinct" entry.
    canonical: std::path::PathBuf,
    /// SHA-256 hex of the binary contents. `None` if unreadable (rare; would
    /// require a race or perms change after the existence check).
    sha256: Option<String>,
    /// Last-modified time of the binary. `None` if metadata unreadable.
    mtime: Option<std::time::SystemTime>,
    /// Zero-based PATH position (after dedup). `0` = the binary bare `wire`
    /// resolves to (the winner of PATH precedence).
    path_index: usize,
    /// True iff this is the binary currently executing the running `wire
    /// upgrade` process (i.e. `std::env::current_exe()` canonicalized matches).
    /// When this is NOT the `path_index == 0` entry, the operator just ran
    /// `wire upgrade` against a SHADOWED binary and bare `wire` will continue
    /// to use the active one — the central footgun #80 exists to catch.
    is_current_exe: bool,
}

impl PathWireBinary {
    /// True iff bare `wire` resolves here (the PATH-precedence winner).
    fn is_active(&self) -> bool {
        self.path_index == 0
    }
    /// Short sha256 (first 8 hex chars) for compact display; `?` filler when
    /// the hash couldn't be computed.
    fn sha256_short(&self) -> String {
        self.sha256
            .as_deref()
            .map(|s| s[..s.len().min(8)].to_string())
            .unwrap_or_else(|| "????????".to_string())
    }
    /// Pretty mtime in UTC RFC3339 seconds; `?` when missing or unrepresentable.
    fn mtime_display(&self) -> String {
        let Some(ts) = self.mtime else {
            return "?".to_string();
        };
        let secs = match ts.duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => d.as_secs() as i64,
            Err(_) => return "?".to_string(),
        };
        time::OffsetDateTime::from_unix_timestamp(secs)
            .ok()
            .and_then(|dt| {
                dt.format(&time::format_description::well_known::Rfc3339)
                    .ok()
            })
            .unwrap_or_else(|| "?".to_string())
    }
}

/// SHA-256 hex of a file's contents (streamed; safe for any size).
fn sha256_file(p: &std::path::Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut f = std::fs::File::open(p).with_context(|| format!("opening {}", p.display()))?;
    let mut h = Sha256::new();
    std::io::copy(&mut f, &mut h).with_context(|| format!("hashing {}", p.display()))?;
    Ok(hex::encode(h.finalize()))
}

/// Walk `$PATH` left-to-right, find all distinct files named `wire` (plus
/// `wire.exe` on Windows), and return them in PATH order with sha256+mtime
/// enrichment. Issue #80.
///
/// Invariants:
/// - First entry (`path_index == 0`) is what bare `wire` resolves to.
/// - Symlink chains collapse: only the first PATH position surfaces; later
///   entries pointing at the same canonical file are dropped (NOT counted
///   as a "shadow").
/// - Best-effort: I/O errors degrade to `None` on per-binary fields,
///   never abort the whole walk.
/// - Empty / missing PATH → empty Vec (NOT an error; the caller is already
///   running, so SOMETHING resolved this binary, just not via PATH).
fn enumerate_path_wire_binaries() -> Vec<PathWireBinary> {
    let path = std::env::var("PATH").unwrap_or_default();
    // Resolve the ` (deleted)` kernel marker BEFORE canonicalize: after a
    // `cargo install` in-place replace, `current_exe()` is `…/wire (deleted)`,
    // which can't canonicalize → is_current_exe never matches → a false
    // "off-PATH / old binary" warning even when the active PATH entry is a
    // symlink to the freshly-upgraded binary (issue #276). Stripping the marker
    // first lets the recreated install path canonicalize and match.
    let current_exe_canon: Option<std::path::PathBuf> = crate::platform::current_exe_resolved()
        .ok()
        .and_then(|p| p.canonicalize().ok());
    enumerate_path_wire_binaries_from(&path, current_exe_canon.as_deref())
}

/// Pure (testable) inner of [`enumerate_path_wire_binaries`]: takes the PATH
/// string and an optional already-canonicalized `current_exe` so tests don't
/// have to mutate process-wide environment (which would race with any other
/// test that reads PATH).
fn enumerate_path_wire_binaries_from(
    path: &str,
    current_exe_canon: Option<&std::path::Path>,
) -> Vec<PathWireBinary> {
    if path.is_empty() {
        return Vec::new();
    }
    // Unix splits PATH on ':', Windows on ';'. We don't use
    // `std::env::split_paths` because we want to be explicit and consistent
    // with the existing v0.6.8 detection that this helper replaces (which
    // used `.split(':')` unconditionally — a Unix-only bug; fixed here).
    let separator = if cfg!(windows) { ';' } else { ':' };
    let names: &[&str] = if cfg!(windows) {
        // Try .exe first — that's what CreateProcess resolves bare `wire` to
        // under PATHEXT. A plain `wire` script (e.g. msys) only wins if
        // there's no wire.exe in the same directory.
        &["wire.exe", "wire"]
    } else {
        &["wire"]
    };

    let mut seen: std::collections::HashSet<std::path::PathBuf> = std::collections::HashSet::new();
    let mut out: Vec<PathWireBinary> = Vec::new();
    for dir in path.split(separator) {
        if dir.is_empty() {
            continue;
        }
        for name in names {
            let candidate = std::path::PathBuf::from(dir).join(name);
            // `is_file()` (not `.exists()`) so a directory named `wire`
            // doesn't false-positive — `.exists()` returns true for dirs.
            if !candidate.is_file() {
                continue;
            }
            let canon = candidate
                .canonicalize()
                .unwrap_or_else(|_| candidate.clone());
            if !seen.insert(canon.clone()) {
                // An earlier PATH entry already surfaced this canonical file
                // (symlink chain). Don't double-count as a shadow.
                break;
            }
            let meta = std::fs::metadata(&canon).ok();
            let mtime = meta.as_ref().and_then(|m| m.modified().ok());
            let sha256 = sha256_file(&canon).ok();
            let is_current_exe = current_exe_canon
                .map(|c| c == canon.as_path())
                .unwrap_or(false);
            let path_index = out.len();
            out.push(PathWireBinary {
                path: candidate,
                canonical: canon,
                sha256,
                mtime,
                path_index,
                is_current_exe,
            });
            // One entry per PATH dir — don't surface both wire AND wire.exe
            // from the same directory.
            break;
        }
    }
    out
}

/// Render a multi-line WARN message for the PATH-shadow case, or `None` if
/// there's nothing to warn about. Issue #80.
///
/// Triggers (any one fires the warning):
/// - `>= 2 distinct wire binaries` on PATH (classic shadow case).
/// - Exactly 1 binary on PATH AND that binary isn't the one currently
///   running this `wire upgrade` (operator ran an off-PATH binary; bare
///   `wire` would resolve to a DIFFERENT binary that this upgrade just
///   bypassed).
/// - `0 binaries` on PATH at all (this `wire upgrade` ran via an absolute
///   path; bare `wire` would fail in any future shell).
fn path_shadow_warning(bins: &[PathWireBinary]) -> Option<String> {
    let any_current = bins.iter().any(|b| b.is_current_exe);
    let multi = bins.len() >= 2;
    let off_path = !bins.is_empty() && !any_current;
    let none_on_path = bins.is_empty();
    if !multi && !off_path && !none_on_path {
        return None;
    }
    let mut out = String::new();
    if multi {
        out.push_str(&format!(
            "WARN: {} distinct `wire` binaries on PATH — older entries can shadow your fresh install:\n",
            bins.len()
        ));
        for b in bins {
            let mut tags: Vec<&str> = Vec::new();
            if b.is_active() {
                tags.push("ACTIVE (bare `wire` resolves here)");
            }
            if b.is_current_exe {
                tags.push("THIS upgrade ran against this binary");
            }
            let tag_str = if tags.is_empty() {
                String::new()
            } else {
                format!("  ← {}", tags.join("; "))
            };
            out.push_str(&format!(
                "  [{}] {}  (sha256:{}  mtime:{}){}\n",
                b.path_index,
                b.path.display(),
                b.sha256_short(),
                b.mtime_display(),
                tag_str,
            ));
        }
        if !any_current {
            out.push_str(
                "  NOTE: none of the PATH-resident binaries is the one running this `wire upgrade`.\n",
            );
            out.push_str(
                "        Your upgrade will NOT affect bare `wire` calls in shells, scripts, or peer agents.\n",
            );
        } else if !bins[0].is_current_exe {
            out.push_str(
                "  Bare `wire` calls (shells, scripts, daemons, peer agents) will use the\n",
            );
            out.push_str(
                "  ACTIVE binary [0], NOT the one you just upgraded. Recommended fixes:\n",
            );
            out.push_str(&format!(
                "    - rm {}  (or symlink it to the upgraded binary)\n",
                bins[0].path.display(),
            ));
            out.push_str(
                "    - or reorder PATH so the upgraded binary's directory precedes the active one\n",
            );
            out.push_str("  Verify with: which -a wire\n");
        }
    } else if off_path {
        // Single PATH binary, but THIS upgrade ran against a different file.
        let active = &bins[0];
        out.push_str("WARN: this `wire upgrade` is running against an off-PATH binary;\n");
        out.push_str(&format!(
            "      bare `wire` resolves to {} (sha256:{}),\n",
            active.path.display(),
            active.sha256_short(),
        ));
        out.push_str(
            "      which was NOT touched by this upgrade. Shells, scripts, and peer agents\n",
        );
        out.push_str("      will continue to invoke the old binary.\n");
    } else if none_on_path {
        out.push_str("WARN: no `wire` binary on PATH; bare `wire` will fail in future shells.\n");
        out.push_str("      This upgrade ran against an absolute-path invocation only.\n");
    }
    Some(out.trim_end().to_string())
}

pub(crate) fn cmd_upgrade(
    check_only: bool,
    local: bool,
    restart_mcp: bool,
    refresh_stale_children: bool,
    as_json: bool,
) -> Result<()> {
    // 0. (v0.13.3 — merged `update`) ALWAYS check crates.io first and, unless
    // this is a --check or --local run, self-install a newer release BEFORE the
    // daemon swap below — the respawn then picks up the new on-disk binary. A
    // crates.io/network failure must NOT block the restart, so it degrades to a
    // warning. `--local` skips it entirely (offline / local dev build).
    let update: Option<UpdateOutcome> = if local {
        None
    } else {
        match self_update_step(!check_only) {
            Ok(o) => Some(o),
            Err(e) => {
                if !check_only {
                    eprintln!("wire upgrade: update check skipped — {e:#}");
                }
                None
            }
        }
    };
    if let Some(o) = &update
        && o.installed
    {
        eprintln!(
            "wire upgrade: installed {} (was {}, via {}); restarting the daemon on the new binary.",
            o.latest,
            o.current,
            o.via.unwrap_or("self-update")
        );
    }

    // 1. Identify all running wire processes. v0.7.3: walks `pgrep -f`
    // on unix / `Get-CimInstance Win32_Process` on Windows via the
    // shared `platform::find_processes_by_cmdline`. Covers both the
    // long-lived sync `wire daemon` *and* the `wire relay-server`
    // local-only loopback — the pre-v0.7.3 upgrade only swept daemons
    // and left stale relay-server children pinned on the old binary,
    // forcing operators to `pkill -f relay-server` manually after
    // every version bump.
    let daemon_pids: Vec<u32> = crate::platform::find_processes_by_cmdline("wire daemon");
    let relay_pids: Vec<u32> = crate::platform::find_processes_by_cmdline("wire relay-server");
    // v0.14.x: also enumerate `wire mcp` server subprocesses. These are
    // pinned by their MCP host (Claude Code / Claude.app desktop), NOT
    // in wire's pidfile registry. We do NOT kill them — that would
    // disconnect every Claude tab's wire MCP toolset until each session
    // explicitly `/mcp` reconnects — but we surface their count so the
    // operator knows their sister sessions still run pre-upgrade code
    // until they reconnect. See `feedback_wire_upgrade_skips_mcp_servers`.
    let mcp_pids: Vec<u32> = crate::platform::find_processes_by_cmdline("wire mcp");
    let running_pids: Vec<u32> = daemon_pids
        .iter()
        .chain(relay_pids.iter())
        .copied()
        .collect();

    // 2. Read pidfile to surface what the daemon THINKS it is.
    let record = crate::ensure_up::read_pid_record("daemon");
    let recorded_version: Option<String> = match &record {
        crate::ensure_up::PidRecord::Json(d) => Some(d.version.clone()),
        _ => None,
    };
    let cli_version = env!("CARGO_PKG_VERSION").to_string();

    // 2b. v0.13.2 (B fix — session-scoped upgrade). `wire upgrade` now
    // refreshes THIS session's daemon, not the whole box. The old box-wide
    // design (kill every `wire daemon` process, wipe every session's pidfile,
    // respawn every session) was wrong for a multi-session / shared-relay box
    // AND broke on Windows: the CIM scan can't match the quoted
    // `"...\wire.exe" daemon` command line (no contiguous `wire daemon`), so it
    // found nothing to kill, then the respawn loop ACCUMULATED daemons
    // (glossy-magnolia: 2->5->8->11). The kill set is now:
    //   (a) THIS session's own daemon, via its pidfile pid — reliable and
    //       CIM-independent; plus
    //   (b) TRUE orphans: `wire daemon` pids owned by NO session.
    // It SPARES sibling sessions' daemons AND the shared loopback relay-server
    // (killing it would break every same-box session's routing).
    let my_daemon_pid = record.pid();
    let owned_session_pids: std::collections::HashSet<u32> = crate::session::list_sessions()
        .unwrap_or_default()
        .iter()
        .filter_map(|s| crate::session::session_daemon_pid(&s.home_dir))
        .collect();
    let mut kill_set = upgrade_kill_set(my_daemon_pid, &daemon_pids, &owned_session_pids);
    // relay_pids are intentionally NOT killed — the local relay is shared.
    //
    // v0.14.3 (closes the #198 follow-up): when `--refresh-stale-children`
    // is set, extend the kill set with the daemons of supervisor-reported
    // `stale_binary_sessions` so the supervisor respawns them on the new
    // binary on its next 10s poll. The supervisor's existing-pidfile check
    // is what made those daemons stick around in the first place — only an
    // explicit opt-in upgrade flag should override that policy, because
    // killing a daemon interrupts any in-flight sync for that session.
    // Errors reading supervisor state are non-fatal (no-op).
    let stale_children_killed: Vec<serde_json::Value> = if refresh_stale_children {
        match crate::daemon_supervisor::read_supervisor_state() {
            Ok(sv) => {
                let mut killed: Vec<serde_json::Value> = Vec::new();
                let cli_v = env!("CARGO_PKG_VERSION");
                for s in &sv.sessions {
                    if !sv.stale_binary_sessions.contains(&s.name) {
                        continue;
                    }
                    if let Some(pid) = s.daemon_pid {
                        // Don't double-add if it's already in the kill
                        // set (paranoia: shouldn't happen since stale
                        // children are sister sessions by definition).
                        if !kill_set.contains(&pid) {
                            kill_set.push(pid);
                        }
                        killed.push(json!({
                            "session": s.name,
                            "pid": pid,
                            "prev_version": s.daemon_version,
                            "cli_version": cli_v,
                        }));
                    }
                }
                if !killed.is_empty() && !as_json {
                    eprintln!(
                        "wire upgrade: --refresh-stale-children will kill {} stale-binary session daemon(s); supervisor respawns each on next 10s poll.",
                        killed.len()
                    );
                }
                killed
            }
            Err(e) => {
                if !as_json {
                    eprintln!(
                        "wire upgrade: --refresh-stale-children skipped — could not read supervisor state ({e:#}). \
                         The flag is a no-op when no `wire daemon --all-sessions` supervisor is running."
                    );
                }
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };

    if check_only {
        // v0.6.8: also surface session-level state + PATH dupes in --check.
        let sessions_with_daemons: Vec<String> = crate::session::list_sessions()
            .unwrap_or_default()
            .iter()
            .filter(|s| s.daemon_running)
            .map(|s| s.name.clone())
            .collect();
        let path_bins = enumerate_path_wire_binaries();
        let path_dupes: Vec<String> = path_bins
            .iter()
            .map(|b| b.canonical.to_string_lossy().into_owned())
            .collect();
        let path_binaries_detail: Vec<serde_json::Value> = path_bins
            .iter()
            .map(|b| {
                json!({
                    "path": b.path.to_string_lossy(),
                    "canonical": b.canonical.to_string_lossy(),
                    "sha256": b.sha256,
                    "mtime_rfc3339": b.mtime.map(|_| b.mtime_display()),
                    "path_index": b.path_index,
                    "is_active": b.is_active(),
                    "is_current_exe": b.is_current_exe,
                })
            })
            .collect();
        let path_warning_check = path_shadow_warning(&path_bins);
        // v0.7.3: enumerate which service units WOULD be refreshed.
        // Read-only — `status_kind` doesn't touch anything.
        let installed_service_kinds: Vec<&'static str> = [
            (crate::service::ServiceKind::Daemon, "daemon"),
            (crate::service::ServiceKind::LocalRelay, "local-relay"),
        ]
        .into_iter()
        .filter_map(|(k, label)| {
            crate::service::status_kind(k)
                .ok()
                .filter(|r| r.status != "absent")
                .map(|_| label)
        })
        .collect();
        let (update_latest, update_available) = match &update {
            Some(o) => (Some(o.latest.clone()), o.available),
            None => (None, false),
        };
        let report = json!({
            "running_pids": running_pids,
            "running_daemons": daemon_pids,
            "running_relay_servers": relay_pids,
            // v0.14.x: surface stale `wire mcp` host-pinned server count
            // so JSON consumers can drive their own /mcp-reconnect UX.
            // `would_warn_stale_mcp_servers` is true iff there ARE any
            // AND --restart-mcp was NOT passed. `would_restart_mcp_servers`
            // is true iff --restart-mcp WAS passed (v0.14.2) — kills the
            // MCP procs so the host respawns them on the new binary.
            "running_mcp_servers": mcp_pids,
            "would_warn_stale_mcp_servers": !mcp_pids.is_empty() && !restart_mcp,
            "would_restart_mcp_servers": restart_mcp && !mcp_pids.is_empty(),
            "restart_mcp_requested": restart_mcp,
            "pidfile_version": recorded_version,
            "cli_version": cli_version,
            "latest_published": update_latest,
            "update_available": update_available,
            "would_kill": kill_set,
            "would_refresh_services": installed_service_kinds,
            "session_daemons_running": sessions_with_daemons,
            "path_binaries": path_dupes,
            "path_binaries_detail": path_binaries_detail,
            "path_duplicate_warning": path_dupes.len() > 1,
            "path_warning": path_warning_check,
        });
        if as_json {
            println!("{}", serde_json::to_string(&report)?);
        } else {
            println!("wire upgrade --check");
            println!("  cli version:      {cli_version}");
            match (&update_latest, update_available) {
                (Some(l), true) => println!("  latest published: {l}  (UPDATE AVAILABLE)"),
                (Some(l), false) => println!("  latest published: {l}  (up to date)"),
                (None, _) => println!("  latest published: (crates.io check skipped)"),
            }
            println!(
                "  pidfile version:  {}",
                recorded_version.as_deref().unwrap_or("(missing)")
            );
            if running_pids.is_empty() {
                println!("  running daemons:  none");
                println!("  running relays:   none");
            } else {
                if daemon_pids.is_empty() {
                    println!("  running daemons:  none");
                } else {
                    let p: Vec<String> = daemon_pids.iter().map(|p| p.to_string()).collect();
                    println!("  running daemons:  pids {}", p.join(", "));
                }
                if relay_pids.is_empty() {
                    println!("  running relays:   none");
                } else {
                    let p: Vec<String> = relay_pids.iter().map(|p| p.to_string()).collect();
                    println!("  running relays:   pids {}", p.join(", "));
                }
                println!("  would kill all + spawn fresh");
            }
            // v0.14.x: surface the MCP-server pin gotcha in `--check` too
            // so an operator probing "what will this do?" sees the full
            // story BEFORE running the actual upgrade. v0.14.2: line
            // adapts to --restart-mcp.
            if !mcp_pids.is_empty() {
                let p: Vec<String> = mcp_pids.iter().map(|p| p.to_string()).collect();
                if restart_mcp {
                    println!(
                        "  wire mcp servers: pids {} (would be killed via --restart-mcp; host respawns on new binary)",
                        p.join(", ")
                    );
                } else {
                    println!(
                        "  wire mcp servers: pids {} (NOT killed; each Claude tab must `/mcp` reconnect, or re-run with --restart-mcp to signal them now)",
                        p.join(", ")
                    );
                }
            }
            if !installed_service_kinds.is_empty() {
                println!(
                    "  would refresh:    {} installed service unit(s) → new binary path",
                    installed_service_kinds.join(", ")
                );
            }
            if !sessions_with_daemons.is_empty() {
                println!(
                    "  session daemons:  {} (would respawn under new binary)",
                    sessions_with_daemons.join(", ")
                );
            }
            // v0.14.3: preview the --refresh-stale-children effect in
            // --check too so operators can dry-run "what would the
            // flag do?" before committing.
            if let Ok(sv) = crate::daemon_supervisor::read_supervisor_state()
                && !sv.stale_binary_sessions.is_empty()
            {
                let cli_v = env!("CARGO_PKG_VERSION");
                if refresh_stale_children {
                    println!(
                        "  stale children:   {} session(s) on old binary; --refresh-stale-children WOULD kill each so supervisor respawns on v{cli_v}",
                        sv.stale_binary_sessions.len()
                    );
                } else {
                    println!(
                        "  stale children:   {} session(s) on old binary (v{cli_v} is current); rerun with --refresh-stale-children to refresh them",
                        sv.stale_binary_sessions.len()
                    );
                }
                for name in &sv.stale_binary_sessions {
                    let ver = sv
                        .sessions
                        .iter()
                        .find(|s| &s.name == name)
                        .and_then(|s| s.daemon_version.clone())
                        .unwrap_or_else(|| "?".to_string());
                    println!("                    - {name} running v{ver}");
                }
            }
            if let Some(w) = &path_warning_check {
                println!("  PATH check:");
                for line in w.lines() {
                    println!("    {line}");
                }
            }
        }
        return Ok(());
    }

    // 3. Terminate the kill set. Graceful first, then FORCE-kill any survivor.
    //
    // v0.13.2 (B fix #2): the force-kill must NOT be gated on graceful having
    // "succeeded". On Windows, `taskkill /PID /T` WITHOUT `/F` is a no-op for a
    // windowless daemon (it returns failure), so the rc9 logic — which only
    // force-killed pids that graceful had reported killing — force-killed
    // NOTHING, and the daemon survived every `wire upgrade` (glossy: pidfile
    // pids 3676/25236/24660 all survived → accumulation). Now we attempt
    // graceful best-effort, grace-wait, then force-kill EVERY pid still alive
    // regardless of the graceful result. Force-kill (`taskkill /F /T` /
    // SIGKILL) is the load-bearing step.
    for pid in &kill_set {
        let _ = crate::platform::kill_process(*pid, false); // best-effort graceful
    }
    if !kill_set.is_empty() {
        // Brief grace for platforms where graceful works (Unix SIGTERM).
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(800);
        while std::time::Instant::now() < deadline
            && kill_set.iter().any(|p| super::process_alive_pid(*p))
        {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        // Force-kill every survivor — this is what actually kills the
        // windowless daemon on Windows.
        for pid in &kill_set {
            if super::process_alive_pid(*pid) {
                let _ = crate::platform::kill_process(*pid, true);
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(200)); // settle
    }
    // Report what's actually gone (drives the "no stale" message + JSON).
    let killed: Vec<u32> = kill_set
        .iter()
        .copied()
        .filter(|p| !super::process_alive_pid(*p))
        .collect();

    // 4. Remove stale pidfile so ensure_daemon_running doesn't think the
    //    old daemon is still owning it.
    let pidfile = crate::config::state_dir()?.join("daemon.pid");
    if pidfile.exists() {
        let _ = std::fs::remove_file(&pidfile);
    }

    // 4b. v0.13.2: session-scoped — only THIS session's pidfile is wiped
    // (already removed at step 4 above). We deliberately DO NOT touch sibling
    // sessions' pidfiles: their daemons were spared, so wiping their pidfiles
    // would make them look down and the old box-wide respawn would spawn
    // duplicates (the accumulation bug). Each sibling refreshes itself on its
    // own `wire upgrade`.

    // 4c. v0.6.8 PATH duplicate-binary detection. If `wire` resolves to
    // multiple distinct files on $PATH, surface the conflict — operators
    // get bitten when an old binary at /usr/local/bin shadows a fresh
    // ~/.local/bin install (or vice versa). Warning only; no auto-fix.
    let path_bins = enumerate_path_wire_binaries();
    let path_dupes: Vec<String> = path_bins
        .iter()
        .map(|b| b.canonical.to_string_lossy().into_owned())
        .collect();
    let path_binaries_detail: Vec<Value> = path_bins
        .iter()
        .map(|b| {
            json!({
                "path": b.path.to_string_lossy(),
                "canonical": b.canonical.to_string_lossy(),
                "sha256": b.sha256,
                "mtime_rfc3339": b.mtime.map(|_| b.mtime_display()),
                "path_index": b.path_index,
                "is_active": b.is_active(),
                "is_current_exe": b.is_current_exe,
            })
        })
        .collect();
    let path_warning = path_shadow_warning(&path_bins);

    // 4d. v0.7.3 NEW: refresh installed service units so they point at
    // the freshly-installed binary path. Without this step, an upgrade
    // would: kill the old daemon, leave the launchd plist /
    // systemd unit / Windows scheduled task pointing at the OLD
    // binary path (or, worse, an old binary location that's been
    // unlinked), and then the OS's auto-respawn would either fail or
    // bring the OLD binary back from the dead. Reinstalling rewrites
    // the unit with `std::env::current_exe()` (the freshly-resolved
    // path of the running upgrade-driver process) and re-bootstraps /
    // re-enables / re-registers so the next OS-driven start uses it.
    //
    // Only refreshes units that are already installed — does NOT
    // install services the operator never opted into.
    let mut service_refreshes: Vec<Value> = Vec::new();
    for kind in [
        crate::service::ServiceKind::Daemon,
        crate::service::ServiceKind::LocalRelay,
    ] {
        let already_installed = crate::service::status_kind(kind)
            .map(|r| r.status != "absent")
            .unwrap_or(false);
        if !already_installed {
            continue;
        }
        match crate::service::install_kind(kind) {
            Ok(rep) => service_refreshes.push(json!({
                "kind": rep.kind,
                "platform": rep.platform,
                "status": rep.status,
                "unit_path": rep.unit_path,
                "action": "refreshed",
            })),
            Err(e) => service_refreshes.push(json!({
                "kind": format!("{kind:?}"),
                "action": "refresh_failed",
                "error": format!("{e:#}"),
            })),
        }
    }

    // 5. Spawn fresh daemon via ensure_up — atomically waits for
    //    process_alive + writes the versioned pidfile.
    //
    // v0.14.2 (#170 supervisor follow-up): when the Daemon service
    // was successfully refreshed AND its launchd / systemd / Task
    // Scheduler bootstrap succeeded, the OS will (re)start the
    // `wire daemon --all-sessions` supervisor on the new binary
    // within seconds, and the supervisor will spawn this session's
    // child within its 10s registry poll. ensure_daemon_running()'s
    // single-session foreground spawn is redundant in that path —
    // it would create a transient daemon that the supervisor's
    // singleton-guard subsequently no-ops, AND the
    // "wire upgrade: spawned fresh daemon (pid N)" line in the
    // output misleads operators into thinking pid N is the
    // long-lived owner.
    //
    // Skip the redundant spawn only when BOTH conditions hold:
    //   1. The Daemon service refresh succeeded (entry present,
    //      action=="refreshed").
    //   2. The bootstrap step itself returned a "loaded" / "enabled"
    //      / "registered" status (per platform). This is what
    //      `install_kind` reports in its `status` field when
    //      launchctl bootstrap / systemctl enable --now / schtasks
    //      Create succeeded. Anything else (status=="written")
    //      means the OS bootstrap failed — fall back to the
    //      foreground spawn so this session still has a daemon.
    let supervisor_will_spawn = service_refreshes.iter().any(|r| {
        let kind = r.get("kind").and_then(Value::as_str).unwrap_or("");
        let action = r.get("action").and_then(Value::as_str).unwrap_or("");
        let status = r.get("status").and_then(Value::as_str).unwrap_or("");
        kind == "daemon"
            && action == "refreshed"
            && matches!(
                status,
                "loaded" | "enabled" | "active" | "registered" | "running"
            )
    });
    let spawned = if supervisor_will_spawn {
        // Defer to launchd / systemd / Task Scheduler. Pidfile reads
        // below still report the eventual supervisor child's state.
        None
    } else {
        Some(crate::ensure_up::ensure_daemon_running()?)
    };

    // 5b. v0.13.2: session-scoped — no sibling respawn. `ensure_daemon_running`
    // above already respawned THIS session's daemon; sibling sessions were
    // spared (never killed), so there is nothing to respawn for them. Each
    // refreshes itself on its own `wire upgrade`.
    let session_respawns: Vec<Value> = Vec::new();

    let new_record = crate::ensure_up::read_pid_record("daemon");
    let new_pid = new_record.pid();
    let new_version: Option<String> = if let crate::ensure_up::PidRecord::Json(d) = &new_record {
        Some(d.version.clone())
    } else {
        None
    };

    // 5c. v0.14.2: --restart-mcp also signals host-pinned `wire mcp` server
    // subprocesses to restart on the new binary. Per
    // `feedback_wire_upgrade_skips_mcp_servers`: macOS mmap + harness-pinned
    // MCP subprocesses mean sister Claude / Copilot CLI sessions stay on
    // pre-upgrade MCP code until each session explicitly `/mcp` reconnects.
    // Killing the MCP child closes its stdio; the MCP host (Claude Code /
    // Claude.app / Copilot CLI) auto-respawns it via its own restart
    // logic — picking up the new on-disk binary.
    //
    // Cross-session impact: kills EVERY `wire mcp` subprocess found, not
    // just this session's. There is no per-session MCP pidfile registry
    // (these procs are host-spawned). Operators opting in via the flag
    // accept the brief MCP-tool-unavailable window while hosts respawn.
    //
    // Same graceful-then-force-kill pattern as the daemon kill loop above —
    // taskkill /F is load-bearing on Windows for windowless subprocs.
    let killed_mcp: Vec<u32> = if restart_mcp && !mcp_pids.is_empty() {
        for pid in &mcp_pids {
            let _ = crate::platform::kill_process(*pid, false);
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(800);
        while std::time::Instant::now() < deadline
            && mcp_pids.iter().any(|p| super::process_alive_pid(*p))
        {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        for pid in &mcp_pids {
            if super::process_alive_pid(*pid) {
                let _ = crate::platform::kill_process(*pid, true);
            }
        }
        mcp_pids
            .iter()
            .copied()
            .filter(|p| !super::process_alive_pid(*p))
            .collect()
    } else {
        Vec::new()
    };

    if as_json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "killed": killed,
                "found_daemons": daemon_pids,
                "spared_relay_servers": relay_pids,
                // v0.14.x: same surface as `--check` — JSON consumers
                // get the stale-MCP-server pid list so they can drive
                // operator UX (e.g., a tab-restart prompt). With
                // --restart-mcp (v0.14.2), `killed_mcp_server_pids`
                // carries what the upgrade itself signaled; the host
                // (Claude Code / Claude.app / Copilot CLI) respawns
                // them on the new binary. Without the flag, the procs
                // were NEVER candidates for the kill set and the
                // `stale_mcp_warning` is the human-readable nudge.
                "stale_mcp_server_pids": mcp_pids,
                "killed_mcp_server_pids": killed_mcp,
                "restart_mcp_requested": restart_mcp,
                "stale_mcp_warning": if mcp_pids.is_empty() || restart_mcp {
                    Value::Null
                } else {
                    json!(format!(
                        "{} `wire mcp` server subprocess(es) still on pre-upgrade code; each Claude tab must `/mcp` reconnect to pick up the new binary (or re-run with `wire upgrade --restart-mcp` to signal them now)",
                        mcp_pids.len()
                    ))
                },
                "service_refreshes": service_refreshes,
                "spawned_fresh_daemon": spawned,
                "new_pid": new_pid,
                "new_version": new_version,
                "cli_version": cli_version,
                "session_respawns": session_respawns,
                "stale_children_killed": stale_children_killed,
                "path_binaries": path_dupes,
                "path_binaries_detail": path_binaries_detail,
                "path_warning": path_warning,
            }))?
        );
    } else {
        if killed.is_empty() {
            println!("wire upgrade: no stale wire processes running");
        } else {
            let killed_list = killed
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            // Session-scoped: report what was actually killed, and that the
            // shared relay-server was SPARED (not killed) — the old wording
            // lumped the spared relay into the killed count and read like it
            // had been terminated (glossy-magnolia nit).
            if relay_pids.is_empty() {
                println!(
                    "wire upgrade: killed {} daemon(s) [{killed_list}]",
                    killed.len()
                );
            } else {
                let relay_list = relay_pids
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                println!(
                    "wire upgrade: killed {} daemon(s) [{killed_list}]; spared {} shared relay-server(s) [{relay_list}]",
                    killed.len(),
                    relay_pids.len()
                );
            }
        }
        if !stale_children_killed.is_empty() {
            let cli_v = env!("CARGO_PKG_VERSION");
            println!(
                "wire upgrade: refreshed {} stale-binary session daemon(s) (supervisor respawns on v{cli_v} on next 10s poll):",
                stale_children_killed.len()
            );
            for entry in &stale_children_killed {
                let name = entry.get("session").and_then(Value::as_str).unwrap_or("?");
                let pid = entry.get("pid").and_then(Value::as_u64).unwrap_or(0);
                let prev = entry
                    .get("prev_version")
                    .and_then(Value::as_str)
                    .unwrap_or("?");
                println!("                    - {name} (pid {pid}, was v{prev})");
            }
        }
        if !service_refreshes.is_empty() {
            println!(
                "wire upgrade: refreshed {} installed service unit(s) to point at the new binary:",
                service_refreshes.len()
            );
            for r in &service_refreshes {
                let kind = r.get("kind").and_then(Value::as_str).unwrap_or("?");
                let action = r.get("action").and_then(Value::as_str).unwrap_or("?");
                let status = r.get("status").and_then(Value::as_str).unwrap_or("");
                let platform = r.get("platform").and_then(Value::as_str).unwrap_or("");
                if action == "refreshed" {
                    println!("                    - {kind}: {action} ({status}, {platform})");
                } else {
                    let err = r.get("error").and_then(Value::as_str).unwrap_or("");
                    println!("                    - {kind}: {action} ({err})");
                }
            }
        }
        match spawned {
            Some(true) => println!(
                "wire upgrade: spawned fresh daemon (pid {} v{})",
                new_pid
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "?".to_string()),
                new_version.as_deref().unwrap_or(&cli_version),
            ),
            Some(false) => {
                println!("wire upgrade: daemon was already running on current binary");
            }
            // v0.14.2 (#170 follow-up): Daemon service refresh
            // succeeded → launchd / systemd / Task Scheduler will
            // (re)start the `--all-sessions` supervisor on the new
            // binary, which spawns this session's child within its
            // next registry poll (default 10s). No foreground spawn
            // needed.
            None => println!(
                "wire upgrade: daemon refresh deferred to {} supervisor (will spawn within 10s)",
                if cfg!(target_os = "macos") {
                    "launchd"
                } else if cfg!(target_os = "linux") {
                    "systemd"
                } else if cfg!(target_os = "windows") {
                    "Task Scheduler"
                } else {
                    "OS"
                }
            ),
        }
        if !session_respawns.is_empty() {
            println!(
                "wire upgrade: refreshed {} session daemon(s):",
                session_respawns.len()
            );
            for r in &session_respawns {
                let h = r["session_home"].as_str().unwrap_or("?");
                let s = r["status"].as_str().unwrap_or("?");
                let label = std::path::Path::new(h)
                    .file_name()
                    .map(|f| f.to_string_lossy().into_owned())
                    .unwrap_or_else(|| h.to_string());
                println!("  {label:<24} {s}");
            }
        }
        if let Some(msg) = &path_warning {
            eprintln!("wire upgrade: {msg}");
        }
        // v0.14.x: surface MCP-server subprocess status. Without
        // --restart-mcp, warn the operator that sister Claude tabs
        // keep running pre-upgrade code until each one explicitly
        // `/mcp` reconnects — the "fix shipped but my sister session
        // still shows the old behavior" support-ping pattern that
        // surfaced this gap. With --restart-mcp (v0.14.2), report
        // what we signaled so the operator sees the brief
        // MCP-tool-unavailable window is by design.
        if restart_mcp {
            if !killed_mcp.is_empty() {
                let p: Vec<String> = killed_mcp.iter().map(|p| p.to_string()).collect();
                println!(
                    "wire upgrade: killed {} `wire mcp` server subprocess(es) [{}]; host (Claude Code / Claude.app / Copilot CLI) will respawn on the new binary.",
                    killed_mcp.len(),
                    p.join(", ")
                );
            } else if mcp_pids.is_empty() {
                // --restart-mcp was set but no MCP servers were running.
                // Common when the operator runs `wire upgrade` from a
                // shell with no Claude / Copilot session attached.
                println!(
                    "wire upgrade: --restart-mcp set, but no `wire mcp` server subprocesses were running."
                );
            } else {
                // Asked to restart but none of them actually died — the
                // operator should investigate (likely a permission
                // issue or a sibling-user pid that wire can't signal).
                let p: Vec<String> = mcp_pids.iter().map(|p| p.to_string()).collect();
                eprintln!(
                    "wire upgrade: WARNING — --restart-mcp requested but {} `wire mcp` subprocess(es) [{}] survived signaling. Check process ownership / OS permissions.",
                    mcp_pids.len(),
                    p.join(", ")
                );
            }
        } else if !mcp_pids.is_empty() {
            let p: Vec<String> = mcp_pids.iter().map(|p| p.to_string()).collect();
            eprintln!(
                "wire upgrade: NOTE — {} `wire mcp` server subprocess(es) [{}] still on pre-upgrade code (Claude Code / Claude.app pin these at session start). Each Claude tab must `/mcp` reconnect (or restart the host app) to pick up the new binary. Run `wire upgrade --restart-mcp` to signal them now.",
                mcp_pids.len(),
                p.join(", ")
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod upgrade_tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn upgrade_kill_set_is_session_scoped() {
        // owned: my daemon 100, sibling session daemon 200.
        let owned: HashSet<u32> = [100, 200].into_iter().collect();
        // found by the process scan: mine (100), sibling (200), a true orphan (999).
        let k = upgrade_kill_set(Some(100), &[100, 200, 999], &owned);
        assert!(k.contains(&100), "must kill my own daemon (to replace it)");
        assert!(k.contains(&999), "must sweep a true orphan");
        assert!(!k.contains(&200), "must SPARE a sibling session's daemon");

        // CRITICAL: even when the process scan returns EMPTY (Windows CIM can't
        // match the quoted command line), my own daemon is still killed via its
        // pidfile pid — this is the B-accumulation fix.
        assert_eq!(
            upgrade_kill_set(Some(100), &[], &owned),
            vec![100],
            "own daemon killed even when the process scan is empty"
        );

        // Uninitialized session (no own daemon): only true orphans.
        assert_eq!(upgrade_kill_set(None, &[999], &HashSet::new()), vec![999]);
    }

    // ----- issue #80: PATH-shadow detection -----
    //
    // We test the pure inner `enumerate_path_wire_binaries_from(path, cur)`
    // so we never mutate the process-wide PATH — that would race with any
    // other test in the binary that reads PATH (e.g. `process_alive_self`
    // resolving the test binary via PATH).

    fn write_fake_wire(dir: &std::path::Path, body: &[u8]) -> std::path::PathBuf {
        use std::io::Write;
        let p = dir.join("wire");
        let mut f = std::fs::File::create(&p).expect("create fake wire");
        f.write_all(body).expect("write fake wire");
        drop(f);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perm = std::fs::metadata(&p).unwrap().permissions();
            perm.set_mode(0o755);
            std::fs::set_permissions(&p, perm).unwrap();
        }
        p
    }

    #[test]
    #[cfg_attr(windows, ignore = "PATH separator + .exe semantics differ")]
    fn enumerate_finds_no_binaries_when_path_empty() {
        let bins = enumerate_path_wire_binaries_from("", None);
        assert!(
            bins.is_empty(),
            "empty PATH yields no binaries, got {bins:?}"
        );
    }

    #[test]
    #[cfg_attr(windows, ignore = "PATH separator + .exe semantics differ")]
    fn enumerate_detects_two_distinct_binaries_in_path_order() {
        let d1 = tempfile::tempdir().unwrap();
        let d2 = tempfile::tempdir().unwrap();
        let p1 = write_fake_wire(d1.path(), b"#!/bin/sh\necho A\n");
        let p2 = write_fake_wire(d2.path(), b"#!/bin/sh\necho B\n");
        let path = format!("{}:{}", d1.path().display(), d2.path().display());

        let bins = enumerate_path_wire_binaries_from(&path, None);
        assert_eq!(bins.len(), 2, "expected two distinct binaries: {bins:?}");
        assert_eq!(bins[0].path_index, 0);
        assert_eq!(bins[1].path_index, 1);
        assert!(bins[0].is_active(), "first PATH entry is active");
        assert!(!bins[1].is_active(), "second PATH entry is not active");
        // sha256 differs because contents differ.
        assert_ne!(
            bins[0].sha256, bins[1].sha256,
            "distinct contents must hash differently"
        );
        // path field is the un-canonicalized PATH-relative shape.
        assert_eq!(bins[0].path, p1);
        assert_eq!(bins[1].path, p2);
    }

    #[test]
    #[cfg_attr(windows, ignore = "PATH separator + symlink semantics differ")]
    fn enumerate_collapses_symlink_chains_to_one_entry() {
        let real_dir = tempfile::tempdir().unwrap();
        let link_dir = tempfile::tempdir().unwrap();
        let real = write_fake_wire(real_dir.path(), b"#!/bin/sh\necho real\n");
        let link = link_dir.path().join("wire");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real, &link).unwrap();

        // Put the SYMLINK first in PATH; the real binary second. Both
        // resolve to the same canonical file — should collapse to ONE entry
        // at the first PATH position.
        let path = format!(
            "{}:{}",
            link_dir.path().display(),
            real_dir.path().display()
        );
        let bins = enumerate_path_wire_binaries_from(&path, None);
        assert_eq!(
            bins.len(),
            1,
            "symlink chain must collapse to a single entry: {bins:?}"
        );
        assert!(bins[0].is_active());
        // path is the symlink (what the operator wrote), canonical is the real file.
        assert_eq!(bins[0].path, link);
        assert_eq!(bins[0].canonical, real.canonicalize().unwrap());
    }

    #[test]
    #[cfg_attr(windows, ignore = "PATH separator + symlink semantics differ")]
    fn no_shadow_warning_when_active_symlink_resolves_to_current_exe() {
        // Issue #276: ~/.local/bin/wire is a symlink → ~/.cargo/bin/wire (the
        // upgraded binary), and current_exe canonicalizes to that same real
        // file. Both PATH entries are the SAME upgraded binary — there is no
        // shadow, so no warning. (In production the caller first strips the
        // ` (deleted)` marker so current_exe CAN canonicalize; here we pass the
        // resolved canonical path directly, which is what that strip yields.)
        let real_dir = tempfile::tempdir().unwrap();
        let link_dir = tempfile::tempdir().unwrap();
        let real = write_fake_wire(real_dir.path(), b"#!/bin/sh\necho upgraded\n");
        let link = link_dir.path().join("wire");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let real_canon = real.canonicalize().unwrap();

        // Symlink dir precedes the real dir on PATH (the #276 layout).
        let path = format!(
            "{}:{}",
            link_dir.path().display(),
            real_dir.path().display()
        );
        let bins = enumerate_path_wire_binaries_from(&path, Some(&real_canon));
        assert_eq!(bins.len(), 1, "symlink chain collapses: {bins:?}");
        assert!(
            bins[0].is_current_exe,
            "active symlink resolving to current_exe must count as current_exe"
        );
        assert!(
            path_shadow_warning(&bins).is_none(),
            "no warning when the active PATH entry resolves to the upgraded binary; got: {:?}",
            path_shadow_warning(&bins)
        );
    }

    #[test]
    #[cfg_attr(windows, ignore = "PATH separator + .exe semantics differ")]
    fn shadow_warning_off_path_when_current_exe_not_on_path() {
        // One binary on PATH, but current_exe points somewhere else.
        // The off-PATH branch fires.
        let d = tempfile::tempdir().unwrap();
        write_fake_wire(d.path(), b"#!/bin/sh\necho only\n");
        let elsewhere = tempfile::tempdir().unwrap();
        let cur = elsewhere.path().join("not-on-path-wire");
        let bins = enumerate_path_wire_binaries_from(&d.path().display().to_string(), Some(&cur));
        assert_eq!(bins.len(), 1);
        assert!(!bins[0].is_current_exe);
        let warn = path_shadow_warning(&bins).expect("off-path single bin must warn");
        assert!(
            warn.contains("off-PATH binary"),
            "off-path WARN must mention off-PATH; got: {warn}"
        );
    }

    #[test]
    fn shadow_warning_fires_when_no_binaries_at_all() {
        let bins: Vec<PathWireBinary> = Vec::new();
        let warn = path_shadow_warning(&bins).expect("empty must warn");
        assert!(warn.contains("no `wire` binary on PATH"), "got: {warn}");
    }

    #[test]
    #[cfg_attr(windows, ignore = "PATH separator differs")]
    fn shadow_warning_multi_binaries_names_active_and_recommends_fix() {
        let d1 = tempfile::tempdir().unwrap();
        let d2 = tempfile::tempdir().unwrap();
        write_fake_wire(d1.path(), b"published\n");
        write_fake_wire(d2.path(), b"head\n");
        let path = format!("{}:{}", d1.path().display(), d2.path().display());
        let bins = enumerate_path_wire_binaries_from(&path, None);
        let warn = path_shadow_warning(&bins).expect("two distinct bins must warn");
        assert!(warn.contains("2 distinct"), "got: {warn}");
        assert!(warn.contains("ACTIVE"), "must mark the active binary");
        assert!(
            warn.contains("which -a wire") || warn.contains("none of the PATH-resident"),
            "must guide the operator to a fix; got: {warn}"
        );
    }
}
