//! `Sandbox = none|normal|high` — Landlock path allowlist on Linux.
//!
//! Spec: `src/bsd/openbsd/tincd.c` (pledge+unveil). Linux gets the
//! same shape via Landlock (kernel ≥5.13). The path-allowlist maps
//! 1:1; the syscall-filter half (pledge) we skip — Landlock does
//! paths only. seccomp would be a separate feature.
//!
//! ## Ordering
//!
//! `enter()` is called from `main()` AFTER `drop_privs` (chroot+
//! setuid), BEFORE the epoll loop. By that point `tinc-up` has
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

use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, Ordering};

/// `sandbox_level_t` (`sandbox.h:7-10`).
///
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

/// `sandbox_action_t` (`sandbox.h:12-15`). Only `START_PROCESSES`
/// is wired; `USE_NEW_PATHS` exists for parity but the only caller
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

/// Paths the daemon needs after `enter()`. `Option<_>` for paths
/// that may be unset (logfile when logging to stderr; device
/// when `DeviceType=dummy`).
///
/// Constructed in `main()` because that's where confbase/pidfile/
/// socket/logfile already live (`Args`). Device path is
/// hard-coded `/dev/net/tun` on Linux — `tinc-device::DEFAULT_
/// DEVICE` is a private const but every Linux backend opens that
/// one path.
///
/// Relative paths are resolved by `path_beneath_rules` against the
/// daemon's cwd at ruleset-build time. `main()` chdir'd to confbase
/// (`main.rs:983`); confbase as a relative path
/// would resolve to itself. We pass absolutes anyway (`main()` has
/// them) so the chroot interaction is the only path-semantics gotcha.
#[derive(Debug, Clone)]
pub struct Paths {
    /// `/etc/tinc/<net>/`. `r` at high, `rx` at normal. Subdirs
    /// (`cache`, `hosts`, `invitations`) get `rwc` separately.
    pub confbase: PathBuf,
    /// `/dev/net/tun` on Linux. `rw`. `None` for `DeviceType=
    /// dummy` (no device fd; the C skips it via `strcasecmp(device,
    /// DEVICE_DUMMY)`).
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

/// For tests/asserts. C exposes `current_level` as a static; we
/// don't, but the netns test wants to verify the daemon ACTUALLY
/// entered (a level > None on a kernel without Landlock at `normal`
/// would still record `Normal` here — that's correct, `can()` gates
/// are about INTENT, the path restriction is best-effort).
#[must_use]
pub fn entered_level() -> Level {
    match STATE.load(Ordering::Relaxed) & 0b11 {
        2 => Level::High,
        1 => Level::Normal,
        _ => Level::None,
    }
}

/// `sandbox_enter`. One-shot.
///
/// `chrooted`: upstream's `chrooted()` checks `!confbase`; we
/// take it as a flag because `main()` knows whether `-R` was set.
/// When chrooted: skip the Landlock ruleset (paths inside the jail
/// don't match the build-time absolute paths) but still record the
/// level so `can(StartProcesses)` gates correctly.
///
/// # Errors
///
/// At `Level::High` when Landlock is unavailable (kernel <5.13,
/// LSM not enabled, or non-Linux target). At `Normal` and `None`,
/// never fails — `Normal` on a too-old kernel
/// logs a warning and degrades to no-op.
///
/// # Panics
///
/// Called twice. C asserts `!entered` (`:137`). The state machine
/// is one-shot; a second call is a bug in `main()`.
pub fn enter(level: Level, paths: &Paths, chrooted: bool) -> Result<(), String> {
    let prev = STATE.swap(level as u8 | ENTERED_BIT, Ordering::Relaxed);
    assert_eq!(prev & ENTERED_BIT, 0, "sandbox::enter called twice");

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

#[cfg(target_os = "linux")]
fn enter_impl(level: Level, paths: &Paths) -> Result<(), String> {
    use landlock::{
        ABI, Access, AccessFs, BitFlags, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
        path_beneath_rules,
    };

    // ABI V1 = kernel 5.13 (June 2021). Everything we need
    // (Execute, ReadFile, WriteFile, ReadDir, Make*, Remove*) is
    // V1. V3 adds Truncate which `addrcache.rs::save` (`fs::write`
    // → `O_TRUNC`) needs, but `from_all(V1)` doesn't HANDLE
    // Truncate so it stays unrestricted on V1/V2 kernels —
    // best-effort is the right shape. The crate's `Ruleset::
    // default()` does best-effort compat: kernel-too-old →
    // `RulesetStatus::NotEnforced`, no error.
    let abi = ABI::V1;
    let access_all = AccessFs::from_all(abi);
    // Read-only without Execute (`from_read` would include it).
    let access_rd: BitFlags<AccessFs> = AccessFs::ReadFile | AccessFs::ReadDir;

    // unveil "rwc" → write + create-file + create-dir + remove-*.
    // Not `from_write(abi)` — that includes MakeChar/MakeBlock/
    // MakeFifo which the daemon never needs. MakeSock IS needed:
    // ControlSocket re-bind on restart unlinks+binds the socket
    // path, but that happened before enter(). Daemon::Drop
    // unlinks pidfile and ControlSocket::Drop unlinks the socket
    // — RemoveFile covers both.
    let access_rwc: BitFlags<AccessFs> = AccessFs::WriteFile
        | AccessFs::MakeReg
        | AccessFs::MakeDir
        | AccessFs::RemoveFile
        | AccessFs::RemoveDir;

    let can_exec = level < Level::High;

    // path_beneath_rules SILENTLY SKIPS paths it can't open
    // (`fs.rs:613` `Err(_) => None`). This is what we want for
    // logfile (parent dir might not exist yet; the file itself
    // is already open as an fd). We pre-create the confbase
    // subdirs so the rules apply.
    let addrcache = paths.confbase.join("addrcache");
    let hosts = paths.confbase.join("hosts");
    let invitations = paths.confbase.join("invitations");
    // `makedirs(DIR_CACHE | DIR_HOSTS | DIR_INVITATIONS)`. main.rs
    // comment said "Daemon::setup already creates what it needs
    // ... Skip." That was
    // true for non-sandboxed runs (addrcache lazily mkdirs cache/).
    // With Landlock, lazy mkdir AFTER restrict_self needs
    // MakeDir on confbase itself, which we don't grant. Pre-create
    // here so the PathBeneath fd-open succeeds.
    for d in [&addrcache, &hosts, &invitations] {
        if let Err(e) = std::fs::create_dir_all(d) {
            // Non-fatal: hosts/ existing is required by setup()
            // already. cache/ and invitations/ are optional. If
            // mkdir fails, path_beneath_rules will skip the entry
            // (see above) and the daemon hits EACCES later when
            // it tries to use the dir. Warn so the operator knows.
            log::warn!(target: "tincd",
                "Sandbox: mkdir {}: {e}", d.display());
        }
    }

    // confbase + subdirs are NO EXEC. Landlock rules are additive,
    // so Execute on confbase would leak into hosts/ — which also
    // has WriteFile|MakeReg — giving a compromised event loop a
    // write-then-exec primitive via `run_host_script("hosts/{node}-
    // up")`. Execute is granted per-file on the fixed hook-script
    // names below instead. Per-node `hosts/{node}-up` therefore
    // won't run under Sandbox; use `host-up` + $NODE.
    let confbase_access = access_rd;
    let hosts_access = access_rd | access_rwc;

    // path_beneath_rules skips nonexistent paths; scripts created
    // after enter() are intentionally not exec'able (UseNewPaths).
    let script_names: &[&str] = &[
        "tinc-up",
        "tinc-down",
        "host-up",
        "host-down",
        "subnet-up",
        "subnet-down",
        "invitation-accepted",
    ];
    let script_paths: Vec<PathBuf> = if can_exec {
        script_names
            .iter()
            .map(|n| paths.confbase.join(n))
            .collect()
    } else {
        Vec::new()
    };

    // Paths granted r+w+c (no exec). cache/ and invitations/ are
    // pure data dirs; the device is a char dev (MakeReg meaningless
    // on it but harmless, and one access-set means one add_rules).
    let mut rwc_paths: Vec<PathBuf> = vec![addrcache, invitations];
    // addrcache + dht_nodes fall back to `$STATE_DIRECTORY/addrcache`
    // when confbase is read-only (NixOS store). Pre-create + allow it
    // so the fallback survives Landlock too.
    if let Some(sd) = std::env::var_os("STATE_DIRECTORY") {
        let sd_cache = PathBuf::from(sd).join("addrcache");
        let _ = std::fs::create_dir_all(&sd_cache);
        rwc_paths.push(sd_cache);
    }
    if let Some(dev) = &paths.device {
        rwc_paths.push(dev.clone());
    }

    // pidfile / unixsocket / logfile: grant Read|Write on the FILE
    // inodes (all exist by enter() time), not their parent dirs —
    // those default to /var/run, /var/log. unlink is a directory op,
    // so the parent dirs get RemoveFile ONLY for Drop cleanup.
    let mut runtime_files: Vec<PathBuf> = vec![paths.pidfile.clone(), paths.unixsocket.clone()];
    let mut unlink_parents: Vec<PathBuf> = Vec::new();
    if let Some(p) = paths.pidfile.parent() {
        unlink_parents.push(p.to_owned());
    }
    if let Some(p) = paths.unixsocket.parent() {
        unlink_parents.push(p.to_owned());
    }
    if let Some(lf) = &paths.logfile {
        // Touch so PathBeneath can open it (init_logging already did).
        if let Err(e) = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(lf)
        {
            log::warn!(target: "tincd",
                "Sandbox: touch {}: {e}", lf.display());
        }
        runtime_files.push(lf.clone());
    }

    // /dev/{u,}random "r". On Linux getrandom(2) is
    // the primary; the urandom fd is rand_core's libc fallback
    // for ancient kernels. Harmless to grant. The bwrap netns
    // harness dev-binds /dev/urandom; without the rule that
    // bind would be inaccessible.
    let random_paths = ["/dev/random", "/dev/urandom"];

    let status = Ruleset::default()
        .handle_access(access_all)
        .map_err(|e| format!("Landlock handle_access: {e}"))?
        .create()
        .map_err(|e| format!("Landlock create: {e}"))?
        .add_rules(path_beneath_rules(&[&paths.confbase], confbase_access))
        .map_err(|e| format!("Landlock add confbase: {e}"))?
        .add_rules(path_beneath_rules(
            &script_paths,
            AccessFs::Execute | AccessFs::ReadFile,
        ))
        .map_err(|e| format!("Landlock add scripts: {e}"))?
        .add_rules(path_beneath_rules(&[&hosts], hosts_access))
        .map_err(|e| format!("Landlock add hosts: {e}"))?
        .add_rules(path_beneath_rules(&rwc_paths, access_rd | access_rwc))
        .map_err(|e| format!("Landlock add rwc: {e}"))?
        .add_rules(path_beneath_rules(
            &runtime_files,
            AccessFs::ReadFile | AccessFs::WriteFile,
        ))
        .map_err(|e| format!("Landlock add runtime files: {e}"))?
        .add_rules(path_beneath_rules(
            &unlink_parents,
            BitFlags::from(AccessFs::RemoveFile),
        ))
        .map_err(|e| format!("Landlock add unlink parents: {e}"))?
        .add_rules(path_beneath_rules(random_paths, AccessFs::ReadFile))
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

    /// `can()` before `enter()` always returns true. tinc-up and
    /// the subnet-up loop in `Daemon::setup` run BEFORE `main()`
    /// calls `enter()`; they must not be gated.
    ///
    /// nextest per-process model means each #[test] is its own
    /// process, so STATE is fresh. (cargo test without nextest
    /// runs tests in threads of one process — STATE would leak.
    /// AGENTS.md mandates nextest.)
    #[test]
    fn can_before_enter_is_always_true() {
        assert!(can(Action::StartProcesses));
        assert!(can(Action::UseNewPaths));
        assert_eq!(entered_level(), Level::None);
    }
}
