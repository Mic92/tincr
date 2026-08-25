//! `Sandbox = none|normal|high` — Landlock path allowlist on Linux.
//!
//! Same shape as C tinc's OpenBSD pledge+unveil sandbox, on Linux
//! via Landlock (kernel ≥5.13). The path-allowlist maps
//! 1:1; the syscall-filter half (pledge) we skip — Landlock does
//! paths only. seccomp would be a separate feature.
//!
//! ## Ordering
//!
//! `enter()` is called from `main()` after `drop_privs` (chroot+
//! setuid), before the epoll loop. By that point `tinc-up` has
//! already run with root (`Daemon::setup` fires
//! it), the device is open, listeners are bound. Landlock is the
//! last gate before steady-state.
//!
//! ## `normal` vs `high`
//!
//! - `normal`: confbase gets `rx`, hosts gets `rwxc`. Scripts work.
//!   Kernel-too-old → silently no-op (defense-in-depth, not load-
//!   bearing). The OpenBSD default with `HAVE_SANDBOX`; we keep
//!   `none` as default to match the non-OpenBSD C behavior.
//! - `high`: drops exec. `can(StartProcesses)` returns false →
//!   `script::execute` short-circuits. Kernel-too-old → HARD FAIL
//!   (`high` is a security promise; silently downgrading is a
//!   confused-deputy waiting to happen).
//!
//! ## chroot interaction
//!
//! "chroot is used. Disabling path sandbox." If `-R` is set, every
//! path is already
//! under confbase-as-root; Landlock `PathBeneath` rules would be
//! both redundant and confused (they resolve at ruleset-build time
//! against the post-chroot view). We mirror: `enter()` no-ops on
//! `chrooted=true`, but still records the level so `can()` gates
//! work (a chrooted `Sandbox=high` daemon still skips scripts).
//!
//! ## What we DON'T port
//!
//! `open_exec_paths` (`/bin`, `/sbin`, etc). At `normal`, C grants
//! exec to the standard PATH so scripts can call `ip`, `route`, etc.
//! On Linux+Landlock that's a distro-specific guess. We grant
//! `Execute` per-file on the fixed hook-script paths under confbase
//! (so `confbase/tinc-up` itself can be exec'd); a `#!/bin/sh`
//! shebang will EACCES — `tests/netns/sandbox.rs::sandbox_normal_
//! ping` pins that as intentional.

#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
use landlock::{
    ABI, Access, AccessFs, BitFlags, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
    path_beneath_rules,
};
#[cfg(target_os = "linux")]
use std::env;
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::fs::OpenOptions;
#[cfg(target_os = "linux")]
use std::iter;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, Ordering};

/// `repr(u8)` for the atomic store. `None` is 0 so the static
/// default (`AtomicU8::new(0)`) reads as `None` before `enter()`.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// No sandbox. C default outside OpenBSD; ours too. The
    /// Landlock syscall is never made.
    None = 0,
    /// Path allowlist, exec preserved on confbase. Best-effort:
    /// kernel-too-old logs a warning and continues.
    Normal = 1,
    /// Path allowlist, exec dropped. `can(StartProcesses)` →
    /// false. Hard fail if Landlock unavailable.
    High = 2,
}

impl Level {
    /// Accepts `off` for `none` (the variable name vs the enum
    /// constant). Case-insensitive like every other tinc enum
    /// config (`Mode`, `Forwarding`, `ProcessPriority`).
    ///
    /// # Errors
    /// `Err(value)` for unrecognized strings; caller formats the
    /// error message (matches the daemon's other enum-parse sites).
    pub fn parse(s: &str) -> Result<Self, &str> {
        match s.to_ascii_lowercase().as_str() {
            "off" | "none" => Ok(Self::None),
            "normal" => Ok(Self::Normal),
            "high" => Ok(Self::High),
            _ => Err(s),
        }
    }
}

/// Only `START_PROCESSES` is wired; `USE_NEW_PATHS` exists for parity but the only caller
/// (`ScriptsInterpreter` reload guard) is commented out — we re-read
/// the interpreter unconditionally
/// because Landlock at `normal` grants `Execute` on confbase, so a
/// reloaded interpreter under confbase still works.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// fork+exec for scripts and exec proxies. False at `High`.
    StartProcesses,
    /// Access paths not in the build-time ruleset. False at
    /// `Normal` and `High` once entered. C uses this to refuse
    /// reloading `Proxy = exec /new/path` mid-run.
    UseNewPaths,
}

/// Paths the daemon needs after `enter()`; `Option` where a path may be unset
/// (stderr logging, dummy device). Built in `main()`, which already has
/// confbase/pidfile/socket/logfile; the device is `/dev/net/tun` on Linux.
/// `path_beneath_rules` resolves relative paths against cwd (confbase by then),
/// so we pass absolutes and only chroot changes path semantics.
#[derive(Debug, Clone)]
pub struct Paths {
    /// `/etc/tinc/<net>/`. `r` at high, `rx` at normal. Subdirs
    /// (`cache`, `hosts`, `invitations`) get `rwc` separately.
    pub confbase: PathBuf,
    /// `/dev/net/tun` on Linux. `rw`. `None` for `DeviceType=
    /// dummy` (no device fd).
    pub device: Option<PathBuf>,
    /// `--logfile PATH`. `rwc`. `None` when logging to stderr (the
    /// fd is already open; Landlock doesn't gate fd I/O, only
    /// path-based open).
    pub logfile: Option<PathBuf>,
    /// `--pidfile PATH`. `rwc`. Already written at this point but
    /// `Daemon::Drop` unlinks it.
    pub pidfile: PathBuf,
    /// Unix control socket path. `rwc`. Already bound but
    /// `ControlSocket::Drop` unlinks it.
    pub unixsocket: PathBuf,
}

/// Process-global sandbox state. `enter()` writes once; `can()`
/// reads. The C uses three `static` globals (`current_level`,
/// `entered`, `can_use_new_paths`). We pack into one atomic byte:
/// bits 0-1 = level, bit 2 = entered. `Relaxed` is fine: `enter()`
/// runs single-threaded on the main thread before the event loop
/// starts, and `can()` callers are all on that same thread.
static STATE: AtomicU8 = AtomicU8::new(0);

const ENTERED_BIT: u8 = 0b100;

/// `sandbox_can`. We always answer `RIGHT_NOW` because the only
/// caller is `script::execute` which runs after `enter()`. Before
/// `enter()`: always true.
#[must_use]
pub fn can(action: Action) -> bool {
    let s = STATE.load(Ordering::Relaxed);
    if s & ENTERED_BIT == 0 {
        return true;
    }
    let level = s & 0b11;
    match action {
        Action::StartProcesses => level < Level::High as u8,
        // false after `enter()` at any non-None level
        Action::UseNewPaths => level == Level::None as u8,
    }
}

/// Enter the sandbox; one-shot. `chrooted` (`-R`) skips the Landlock
/// ruleset (its absolute paths don't exist in the jail) but records the
/// level so `can(StartProcesses)` gates.
///
/// # Errors
/// At `Level::High` when Landlock is unavailable (`Normal` only warns),
/// or if called twice.
pub fn enter(level: Level, paths: &Paths, chrooted: bool) -> Result<(), String> {
    let prev = STATE.swap(level as u8 | ENTERED_BIT, Ordering::Relaxed);
    if prev & ENTERED_BIT != 0 {
        return Err("sandbox::enter called twice".into());
    }

    if level == Level::None {
        log::debug!(target: "tincd", "Sandbox is disabled");
        return Ok(());
    }

    if chrooted {
        log::debug!(target: "tincd",
            "chroot is used. Disabling path sandbox.");
        return Ok(());
    }

    enter_impl(level, paths)
}

/// Which paths get which Landlock access bits, in the order `restrict_self`
/// consumes them (rules merge in addition order, which matters for partial
/// fallback on older kernels). Computed by `discover_paths`, applied by
/// `build_and_apply_ruleset`; split so the path set is unit-testable without
/// the syscall.
#[cfg(target_os = "linux")]
struct SandboxPaths {
    /// `confbase` root: `rd` only, never exec (see hosts/ leak note).
    confbase: PathBuf,
    /// Per-file `Execute|ReadFile` on fixed hook-script names. Empty
    /// at `High` (exec dropped). `path_beneath_rules` silently skips
    /// nonexistent entries — scripts created post-`enter()` are
    /// intentionally inert (`UseNewPaths`).
    scripts: Vec<PathBuf>,
    /// `confbase/hosts`: `rd | rwc`. Per-node `hosts/{node}-up`
    /// scripts deliberately don't get `Execute` here.
    hosts: PathBuf,
    /// `rd | rwc`: addrcache, invitations, optional `$STATE_DIRECTORY`
    /// fallback, and the tun device.
    rwc: Vec<PathBuf>,
    /// `pidfile` + `unixsocket` + optional `logfile`: `ReadFile|WriteFile`
    /// on the file inodes themselves (parent dirs may be /var/run
    /// etc., which we don't grant). Logfile, when present, is
    /// always the last entry — `build_and_apply_ruleset` touches
    /// it pre-ruleset.
    runtime_files: Vec<PathBuf>,
    /// Whether `runtime_files` ends with a logfile entry that
    /// needs touching before ruleset build (so `path_beneath_rules`
    /// can open it).
    has_logfile: bool,
    /// Parent dirs of pidfile/unixsocket: `RemoveFile` only, for the
    /// `Daemon::Drop` / `ControlSocket::Drop` unlink path.
    unlink_parents: Vec<PathBuf>,
    /// `/dev/{,u}random`: `ReadFile`. urandom is `rand_core`'s libc
    /// fallback; bwrap netns harness binds it.
    random: Vec<&'static str>,
}

/// Pure: compute the path set for a given `level` and `paths`. No
/// I/O, no syscalls. The apply half pre-creates dirs and touches
/// the logfile before handing the set to Landlock.
#[cfg(target_os = "linux")]
fn discover_paths(level: Level, paths: &Paths) -> SandboxPaths {
    let can_exec = level < Level::High;

    let scripts: Vec<PathBuf> = if can_exec {
        const SCRIPT_NAMES: &[&str] = &[
            "tinc-up",
            "tinc-down",
            "host-up",
            "host-down",
            "subnet-up",
            "subnet-down",
            "invitation-accepted",
        ];
        SCRIPT_NAMES
            .iter()
            .map(|n| paths.confbase.join(n))
            .collect()
    } else {
        Vec::new()
    };

    let mut rwc: Vec<PathBuf> = vec![
        paths.confbase.join("addrcache"),
        paths.confbase.join("invitations"),
    ];
    // addrcache falls back to `$STATE_DIRECTORY/addrcache`
    // when confbase is read-only (NixOS store). Allow it so the
    // fallback survives Landlock too.
    if let Some(sd) = env::var_os("STATE_DIRECTORY") {
        rwc.push(PathBuf::from(sd).join("addrcache"));
    }
    if let Some(dev) = &paths.device {
        rwc.push(dev.clone());
    }

    let mut runtime_files: Vec<PathBuf> = vec![paths.pidfile.clone(), paths.unixsocket.clone()];
    let has_logfile = paths.logfile.is_some();
    if let Some(lf) = &paths.logfile {
        runtime_files.push(lf.clone());
    }

    let mut unlink_parents: Vec<PathBuf> = Vec::new();
    if let Some(p) = paths.pidfile.parent() {
        unlink_parents.push(p.to_owned());
    }
    if let Some(p) = paths.unixsocket.parent() {
        unlink_parents.push(p.to_owned());
    }

    SandboxPaths {
        confbase: paths.confbase.clone(),
        scripts,
        hosts: paths.confbase.join("hosts"),
        rwc,
        runtime_files,
        unlink_parents,
        random: vec!["/dev/random", "/dev/urandom"],
        has_logfile,
    }
}

/// Pre-create dirs / touch logfile (so `path_beneath_rules` can
/// open the path), then build and commit the Landlock ruleset.
///
/// `add_rules` order is load-bearing: on partial-rule fallback the
/// kernel applies the prefix it understood. Keep in sync with the
/// pre-split body.
#[cfg(target_os = "linux")]
fn build_and_apply_ruleset(p: SandboxPaths, level: Level) -> Result<(), String> {
    // ABI V1 (kernel 5.13) has everything we need. V3 adds Truncate, which
    // `addrcache.rs::save` uses; `from_all(V1)` doesn't handle it so it stays
    // unrestricted on V1/V2. `Ruleset::default()` is best-effort: too old a kernel
    // yields `NotEnforced`, not an error.
    let abi = ABI::V1;
    let access_all = AccessFs::from_all(abi);
    // Read-only without Execute (`from_read` would include it).
    let access_rd: BitFlags<AccessFs> = AccessFs::ReadFile | AccessFs::ReadDir;
    // unveil "rwc" → write + create-file + create-dir + remove-*.
    // Not `from_write(abi)` — that includes MakeChar/MakeBlock/
    // MakeFifo which the daemon never needs. MakeSock is needed:
    // ControlSocket re-bind on restart unlinks+binds the socket
    // path, but that happened before enter(). Daemon::Drop
    // unlinks pidfile and ControlSocket::Drop unlinks the socket
    // — RemoveFile covers both.
    let access_rwc: BitFlags<AccessFs> = AccessFs::WriteFile
        | AccessFs::MakeReg
        | AccessFs::MakeDir
        | AccessFs::RemoveFile
        | AccessFs::RemoveDir;

    // `path_beneath_rules` silently skips paths it can't open, so pre-create the
    // confbase subdirs and `$STATE_DIRECTORY/addrcache` now; creating them lazily
    // later would need MakeDir on confbase, which isn't granted. `/dev/*` entries
    // are char devices and skipped.
    let dirs_to_create =
        iter::once(&p.hosts).chain(p.rwc.iter().filter(|d| !d.starts_with("/dev/")));
    for d in dirs_to_create {
        if let Err(e) = fs::create_dir_all(d) {
            // Non-fatal: hosts/ existing is required by setup()
            // already. cache/ and invitations/ are optional. If
            // mkdir fails, path_beneath_rules skips the entry and
            // the daemon hits EACCES later. Warn so operator knows.
            log::warn!(target: "tincd",
                "Sandbox: mkdir {}: {e}", d.display());
        }
    }

    // Touch logfile so PathBeneath can open it (init_logging
    // already created it; belt-and-braces).
    if p.has_logfile {
        let lf = p.runtime_files.last().expect("has_logfile invariant");
        if let Err(e) = OpenOptions::new().append(true).create(true).open(lf) {
            log::warn!(target: "tincd",
                "Sandbox: touch {}: {e}", lf.display());
        }
    }

    // confbase + subdirs are NO EXEC. Landlock rules are additive,
    // so Execute on confbase would leak into hosts/ — which also
    // has WriteFile|MakeReg — giving a compromised event loop a
    // write-then-exec primitive via `run_host_script("hosts/{node}-
    // up")`. Execute is granted per-file on the fixed hook-script
    // names instead.
    let confbase_access = access_rd;
    let hosts_access = access_rd | access_rwc;

    let status = Ruleset::default()
        .handle_access(access_all)
        .map_err(|e| format!("Landlock handle_access: {e}"))?
        .create()
        .map_err(|e| format!("Landlock create: {e}"))?
        .add_rules(path_beneath_rules(&[&p.confbase], confbase_access))
        .map_err(|e| format!("Landlock add confbase: {e}"))?
        .add_rules(path_beneath_rules(
            &p.scripts,
            AccessFs::Execute | AccessFs::ReadFile,
        ))
        .map_err(|e| format!("Landlock add scripts: {e}"))?
        .add_rules(path_beneath_rules(&[&p.hosts], hosts_access))
        .map_err(|e| format!("Landlock add hosts: {e}"))?
        .add_rules(path_beneath_rules(&p.rwc, access_rd | access_rwc))
        .map_err(|e| format!("Landlock add rwc: {e}"))?
        .add_rules(path_beneath_rules(
            &p.runtime_files,
            AccessFs::ReadFile | AccessFs::WriteFile,
        ))
        .map_err(|e| format!("Landlock add runtime files: {e}"))?
        .add_rules(path_beneath_rules(
            &p.unlink_parents,
            BitFlags::from(AccessFs::RemoveFile),
        ))
        .map_err(|e| format!("Landlock add unlink parents: {e}"))?
        .add_rules(path_beneath_rules(p.random, AccessFs::ReadFile))
        .map_err(|e| format!("Landlock add random: {e}"))?
        .restrict_self()
        .map_err(|e| format!("Landlock restrict_self: {e}"))?;

    match status.ruleset {
        RulesetStatus::FullyEnforced | RulesetStatus::PartiallyEnforced => {
            log::info!(target: "tincd",
                "Entered sandbox at level {level:?} ({:?})",
                status.ruleset);
            Ok(())
        }
        RulesetStatus::NotEnforced => {
            // Kernel doesn't support Landlock (or the LSM is
            // disabled at boot). At normal: defense-in-depth, log
            // and carry on. At high: refuse — the operator asked
            // for a security guarantee we can't provide.
            if level == Level::High {
                Err("Sandbox=high requested but Landlock is not \
                     available (kernel <5.13 or landlock LSM not \
                     enabled). Set Sandbox=normal or off."
                    .into())
            } else {
                log::warn!(target: "tincd",
                    "Sandbox=normal: Landlock not available, \
                     running without path restrictions");
                Ok(())
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn enter_impl(level: Level, paths: &Paths) -> Result<(), String> {
    build_and_apply_ruleset(discover_paths(level, paths), level)
}

#[cfg(not(target_os = "linux"))]
fn enter_impl(level: Level, _paths: &Paths) -> Result<(), String> {
    // Upstream HARD-FAILS at any level >none on non-OpenBSD. We mirror at
    // high (security promise); at normal warn and continue — same
    // best-effort stance as the Landlock arm on a too-old kernel.
    if level == Level::High {
        Err("Sandbox=high requested but Landlock is Linux-only. \
             Set Sandbox=normal or off."
            .into())
    } else {
        log::warn!(target: "tincd",
            "Sandbox={level:?} requested but Landlock is Linux-only; \
             running unrestricted");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_parse_case_insensitive() {
        assert_eq!(Level::parse("off"), Ok(Level::None));
        assert_eq!(Level::parse("OFF"), Ok(Level::None));
        assert_eq!(Level::parse("none"), Ok(Level::None));
        assert_eq!(Level::parse("Normal"), Ok(Level::Normal));
        assert_eq!(Level::parse("HIGH"), Ok(Level::High));
        assert_eq!(Level::parse("garbage"), Err("garbage"));
    }

    /// `can()` before `enter()` is always true: tinc-up and subnet-up run from
    /// `Daemon::setup` before `main()` enters the sandbox. STATE is per-process,
    /// fresh under nextest. The discovery half is pure; pin its field-by-field
    /// shape so dropping `$STATE_DIRECTORY` or reordering scripts fails a test
    /// rather than EACCES at runtime.
    #[cfg(target_os = "linux")]
    #[test]
    fn discover_paths_normal_shape() {
        let paths = Paths {
            confbase: PathBuf::from("/etc/tinc/net"),
            device: Some(PathBuf::from("/dev/net/tun")),
            logfile: Some(PathBuf::from("/var/log/tinc.log")),
            pidfile: PathBuf::from("/run/tinc.pid"),
            unixsocket: PathBuf::from("/run/tinc.sock"),
        };
        let p = discover_paths(Level::Normal, &paths);
        assert_eq!(p.confbase, PathBuf::from("/etc/tinc/net"));
        assert_eq!(p.hosts, PathBuf::from("/etc/tinc/net/hosts"));
        assert_eq!(p.scripts.len(), 7, "7 hook-script names");
        assert!(p.scripts[0].ends_with("tinc-up"));
        // Don't depend on host $STATE_DIRECTORY: assert membership.
        assert!(p.rwc.contains(&PathBuf::from("/etc/tinc/net/addrcache")));
        assert!(p.rwc.contains(&PathBuf::from("/etc/tinc/net/invitations")));
        assert!(p.rwc.contains(&PathBuf::from("/dev/net/tun")));
        assert_eq!(p.runtime_files.len(), 3);
        assert!(p.has_logfile);
        assert_eq!(
            p.unlink_parents,
            vec![PathBuf::from("/run"), PathBuf::from("/run")]
        );
        assert_eq!(p.random, vec!["/dev/random", "/dev/urandom"]);
    }

    /// `High` drops Execute: scripts list is empty so
    /// `path_beneath_rules` adds no Execute grants.
    #[cfg(target_os = "linux")]
    #[test]
    fn discover_paths_high_drops_scripts() {
        let paths = Paths {
            confbase: PathBuf::from("/c"),
            device: None,
            logfile: None,
            pidfile: PathBuf::from("/run/p"),
            unixsocket: PathBuf::from("/run/s"),
        };
        let p = discover_paths(Level::High, &paths);
        assert!(p.scripts.is_empty());
        assert!(!p.has_logfile);
        assert_eq!(p.runtime_files.len(), 2);
    }

    #[test]
    fn can_before_enter_is_always_true() {
        assert!(can(Action::StartProcesses));
        assert!(can(Action::UseNewPaths));
        assert_eq!(STATE.load(Ordering::Relaxed) & 0b11, 0);
    }
}
