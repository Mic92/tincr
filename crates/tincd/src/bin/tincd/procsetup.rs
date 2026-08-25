//! Process bring-up: detach, privilege drop, priority, hardening.

use nix::fcntl::{FcntlArg, FdFlag, fcntl};
use std::ffi::CString;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::path::Path;
use std::{env, process};
use tinc_conf::Config;
use tincd::sandbox;

/// `tinc start` umbilical handshake: write a nul byte and close so
/// the spawning `tinc start` exits 0. We don't tee log output
/// through the umbilical (`env_logger` has no hook); the
/// detach-without-logfile warning in `init_logging` covers that gap.
/// No-op when `TINC_UMBILICAL` is unset.
pub(crate) fn cut_umbilical() {
    let Ok(spec) = env::var("TINC_UMBILICAL") else {
        return;
    };
    // First token is the fd; second (`colorize`) is ignored — we don't tee.
    let Some(fd) = spec
        .split_whitespace()
        .next()
        .and_then(|s| s.parse::<RawFd>().ok())
    else {
        return;
    };
    // Reject stdio: taking ownership of 0/1/2 would close it and
    // let the next open() reuse the slot. `tinc start` always
    // passes a socketpair half (≥3).
    if fd <= 2 {
        log::warn!(target: "tincd",
            "TINC_UMBILICAL={spec}: fd {fd} is stdio/invalid, ignoring");
        return;
    }
    // SAFETY: fd > 2 checked above. The TINC_UMBILICAL env var is
    // the ownership transfer protocol — spawner set it, no one else
    // in this process knows the number. Stale fd → F_GETFL fails →
    // we drop (close) harmlessly.
    #[expect(unsafe_code)]
    let f = unsafe { OwnedFd::from_raw_fd(fd) };
    if fcntl(&f, FcntlArg::F_GETFL).is_err() {
        return; // drop closes the fd
    }
    let _ = fcntl(&f, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC));
    let _ = nix::unistd::write(&f, b"\0");
    // Drop closes. snip!
}

pub(crate) fn detach() -> Result<(), String> {
    // Single-threaded here (logger not yet initialised), so the
    // single-fork `daemon(3)` is safe; SIGPIPE is already SIG_IGN
    // via Rust's runtime, and USR1/USR2/WINCH get masked later in
    // `register_signals`.
    tincd::daemonize()
}

/// `getpwnam → initgroups → setgid → [chroot] → setuid`. chroot must
/// run after initgroups (which reads `/etc/group`, outside the jail)
/// and before setuid (chroot needs root); setuid is last so it can't
/// be undone.
pub(crate) fn drop_privs(
    switchuser: Option<&str>,
    do_chroot: bool,
    confbase: &Path,
) -> Result<(), String> {
    let uid_gid = if let Some(user) = switchuser {
        let pw = nix::unistd::User::from_name(user)
            .map_err(|e| format!("getpwnam_r `{user}': {e}"))?
            .ok_or_else(|| format!("unknown user `{user}'"))?;

        // initgroups: supplementary groups from /etc/group.
        // Single-threaded here (event loop not started).
        let cuser = CString::new(user).map_err(|_| "username contains NUL".to_string())?;
        tincd::initgroups(&cuser, pw.gid)
            .map_err(|e| format!("System call `initgroups' failed: {e}"))?;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        nix::unistd::setresgid(pw.gid, pw.gid, pw.gid)
            .map_err(|e| format!("System call `setresgid' failed: {e}"))?;
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        nix::unistd::setgid(pw.gid).map_err(|e| format!("System call `setgid' failed: {e}"))?;

        Some((pw.uid, pw.gid))
    } else {
        None
    };

    if do_chroot {
        // tzset before chroot: load /etc/localtime so log timestamps
        // stay in local tz inside the jail.
        // SAFETY: tzset is non-reentrant; single-threaded here.
        #[expect(unsafe_code)]
        {
            unsafe extern "C" {
                fn tzset();
            }
            unsafe { tzset() };
        }

        nix::unistd::chroot(confbase).map_err(|e| format!("System call `chroot' failed: {e}"))?;
        // Don't leave a cwd handle pointing outside the jail.
        env::set_current_dir("/").map_err(|e| format!("chdir / after chroot: {e}"))?;
    }

    // setresuid last (real/effective/saved); after this we can't undo.
    if let Some((uid, gid)) = uid_gid {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            nix::unistd::setresuid(uid, uid, uid)
                .map_err(|e| format!("System call `setresuid' failed: {e}"))?;

            // Verify the kernel applied the drop to all three of each.
            let ru = nix::unistd::getresuid().map_err(|e| format!("getresuid: {e}"))?;
            let rg = nix::unistd::getresgid().map_err(|e| format!("getresgid: {e}"))?;
            if ru.real != uid || ru.effective != uid || ru.saved != uid {
                return Err(format!("setresuid did not stick: got {ru:?}, want {uid}"));
            }
            if rg.real != gid || rg.effective != gid || rg.saved != gid {
                return Err(format!("setresgid did not stick: got {rg:?}, want {gid}"));
            }
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            let _ = gid; // gid already set via setgid above
            nix::unistd::setuid(uid).map_err(|e| format!("System call `setuid' failed: {e}"))?;
        }
    }

    // PR_SET_NO_NEW_PRIVS: future execve can't grant setuid/file caps.
    // Set unconditionally; the sandbox path sets it again harmlessly.
    #[cfg(target_os = "linux")]
    if let Err(e) = nix::sys::prctl::set_no_new_privs() {
        log::warn!(target: "tincd", "prctl(PR_SET_NO_NEW_PRIVS): {e}");
    }

    Ok(())
}

/// `ProcessPriority` config key. Best-effort: a daemon that can't
/// nice itself can still tunnel packets. Re-reads tinc.conf rather
/// than threading the merged config out of `Daemon::setup`.
pub(crate) fn apply_process_priority(confbase: &Path, cmdline: &Config) {
    let mut config = match tinc_conf::read_server_config(confbase) {
        Ok(c) => c,
        // Daemon::setup already validated this read; failure here is
        // a race. Priority is a hint, skip.
        Err(e) => {
            log::warn!(target: "tincd", "ProcessPriority: re-read tinc.conf failed: {e}");
            return;
        }
    };
    config.merge(cmdline.entries().iter().cloned());

    let Some(e) = config.lookup("ProcessPriority").next() else {
        return; // not set, default scheduling
    };
    let prio_str = e.get_str();

    // Unix nice mapping of C's Windows priority-class names.
    let nice: i32 = match prio_str.to_ascii_lowercase().as_str() {
        "normal" => 0,
        "low" => 10,
        "high" => -10,
        other => {
            log::error!(target: "tincd", "Invalid priority `{other}`!");
            return;
        }
    };

    // SAFETY: setpriority(PRIO_PROCESS, 0, nice); who=0 = current process.
    // PRIO_PROCESS type varies (c_uint on gnu, c_int on musl/bsd) —
    // rely on the libc const's own type via `as _`.
    #[expect(unsafe_code)]
    let r = unsafe { libc::setpriority(libc::PRIO_PROCESS as _, 0, nice) };
    if r != 0 {
        log::warn!(
            target: "tincd",
            "System call `setpriority' failed: {}",
            std::io::Error::last_os_error()
        );
    }
}

/// `Sandbox` config key; `-o` overrides tinc.conf. Default `none`
/// (Landlock is always compiled in but unconfigured daemons keep
/// pre-sandbox behaviour).
pub(crate) fn resolve_sandbox_level(
    confbase: &Path,
    cmdline: &Config,
) -> Result<sandbox::Level, String> {
    fn lookup(c: &Config) -> Option<Result<sandbox::Level, String>> {
        c.lookup("Sandbox").next().map(|e| {
            sandbox::Level::parse(e.get_str()).map_err(|v| format!("Bad sandbox value {v}!"))
        })
    }
    if let Some(r) = lookup(cmdline) {
        return r;
    }
    // Read failure silent; Daemon::setup reports it.
    if let Ok(c) = tinc_conf::read_server_config(confbase)
        && let Some(r) = lookup(&c)
    {
        return r;
    }
    Ok(sandbox::Level::None)
}

/// systemd socket activation env parse: `Some(n)` only if `LISTEN_PID` is our
/// pid and `LISTEN_FDS` is a positive count. The pid check stops a stale
/// `LISTEN_FDS` inherited through a wrapper from making us adopt random fds as
/// listeners. Values are passed in so tests avoid `set_var`.
pub(crate) fn check_socket_activation(
    listen_pid: Option<String>,
    listen_fds: Option<String>,
) -> Option<usize> {
    let pid_ok = listen_pid.and_then(|s| s.parse::<u32>().ok()) == Some(process::id());
    if !pid_ok {
        return None;
    }
    listen_fds
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| n > 0)
}

/// Disable core dumps before any key load: a core file would leak
/// the Ed25519 private key and every live SPTPS key. `RLIMIT_CORE=0`
/// covers on-disk dumps; Linux `PR_SET_DUMPABLE=0` additionally
/// blocks same-uid ptrace and systemd-coredump pipe handlers (which
/// ignore `RLIMIT_CORE`).
pub(crate) fn harden_process(allow_coredump: bool) {
    if allow_coredump {
        return;
    }
    if let Err(e) = nix::sys::resource::setrlimit(nix::sys::resource::Resource::RLIMIT_CORE, 0, 0) {
        // pre-init_logging → eprintln
        eprintln!("tincd: setrlimit(RLIMIT_CORE, 0): {e} (continuing)");
    }
    #[cfg(target_os = "linux")]
    if let Err(e) = nix::sys::prctl::set_dumpable(false) {
        eprintln!("tincd: prctl(PR_SET_DUMPABLE, 0): {e} (continuing)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PID matching ours + `LISTEN_FDS=2` → Some(2). The happy path.
    #[test]
    fn socket_activation_our_pid_with_fds() {
        let our = process::id().to_string();
        assert_eq!(
            check_socket_activation(Some(our), Some("2".into())),
            Some(2)
        );
    }

    /// Wrong PID → None even with valid `LISTEN_FDS`. THE security
    /// gate — inheritance from a wrapper that happened to have the
    /// vars set must not make us adopt random fds.
    #[test]
    fn socket_activation_wrong_pid_ignored() {
        // Our PID + 1 is guaranteed not-us (PIDs are unique).
        let wrong = (process::id() + 1).to_string();
        assert_eq!(check_socket_activation(Some(wrong), Some("2".into())), None);
    }

    /// Right PID but no `LISTEN_FDS` → None. Upstream
    /// gates on `listen_fds` non-null too.
    #[test]
    fn socket_activation_no_fds() {
        let our = process::id().to_string();
        assert_eq!(check_socket_activation(Some(our), None), None);
    }

    /// `LISTEN_FDS=0` → None. Zero sockets is not activation.
    #[test]
    fn socket_activation_zero_fds() {
        let our = process::id().to_string();
        assert_eq!(check_socket_activation(Some(our), Some("0".into())), None);
    }

    /// Garbage in either var → None. C uses `atoi` (returns 0 on
    /// garbage); 0 != `getpid()` and 0 fds is filtered. Same outcome.
    #[test]
    fn socket_activation_garbage() {
        let our = process::id().to_string();
        assert_eq!(
            check_socket_activation(Some("garbage".into()), Some("2".into())),
            None
        );
        assert_eq!(
            check_socket_activation(Some(our), Some("garbage".into())),
            None
        );
    }

    /// Neither var set → None. The common case (not socket-activated).
    #[test]
    fn socket_activation_absent() {
        assert_eq!(check_socket_activation(None, None), None);
    }
}
