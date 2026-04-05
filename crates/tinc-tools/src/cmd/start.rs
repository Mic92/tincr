//! `cmd_start` and `cmd_restart`.
//!
//! ## The umbilical
//!
//! `tinc start` is not just `exec(tincd)` — it's spawn tincd, then
//! *wait for it to be ready*. The wait is the whole point: `tinc
//! start && tinc pid` should work, with the daemon actually accepting
//! control connections by the time `&&` runs.
//!
//! The signalling channel is a `socketpair(AF_UNIX, SOCK_STREAM)`.
//! Parent keeps one end; child gets the other end's fd number in
//! `TINC_UMBILICAL` env. The daemon (`crates/tincd/src/main.rs::
//! cut_umbilical`) writes a single nul byte after `Daemon::setup`
//! returns Ok, then closes. Parent reads until EOF; if the last
//! byte before EOF was nul, success.
//!
//! Why socketpair not pipe: upstream tees early-startup log lines
//! through the umbilical too, so `tinc start` shows you what went
//! wrong if setup fails. Our daemon doesn't tee logs (env_logger
//! has no hook), so we just get the nul byte. The drain loop here
//! still passes any bytes it gets to stderr — forward-compat if
//! log teeing lands, and cross-compat with the upstream tincd.
//!
//! ## `Command::spawn` not raw `fork`
//!
//! The fd number is decided pre-fork (it's the socketpair fd in
//! *our* process), exec preserves non-CLOEXEC fds at the same
//! number, so `Command::env("TINC_UMBILICAL", "<fd> ...")` set in
//! the parent works fine. Clear CLOEXEC on the child end, format
//! its fd number into the env, spawn, drop our copy of the child
//! end. No manual fork, no post-fork-libc-only discipline.
//!
//! The one thing `Command` doesn't give us is `signal(SIGINT,
//! SIG_IGN)` during the wait. Dropped: nix's `signal()` is `unsafe`
//! (mutates global signal disposition), and tincd detaches by
//! default (the wait is sub-second; the SIGINT window is tiny).
//! `tinc start -D` users who want Ctrl-C to reach the foreground
//! daemon: it does anyway — both processes are in the same process
//! group, the terminal sends SIGINT to the whole group. We just
//! *also* exit on it instead of ignoring. Harmless.
//!
//! ## Finding tincd
//!
//! `dirname(current_exe) + "tincd"`, falling back to bare `"tincd"`
//! (PATH lookup). The `tinc` and `tincd` binaries live next to each
//! other under `target/` and under `$prefix/bin/`. Tests can
//! override with `TINCD_PATH` env (our addition for `cargo nextest`,
//! where the tincd binary lives in a different `target/` subdir).

#![allow(clippy::doc_markdown)]
#![cfg(unix)]

use std::io::{IsTerminal, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::Command;

use nix::fcntl::{FcntlArg, FdFlag, fcntl};

use crate::cmd::CmdError;
use crate::ctl::CtlSocket;
use crate::names::Paths;

/// `cmd_start`. Spawn tincd, wait for the umbilical nul-byte ready
/// signal.
///
/// `paths` must have had `resolve_runtime()` called — we pass
/// `--pidfile` and `--socket` explicitly to the spawned daemon
/// (the daemon's argv parser requires them).
///
/// `extra_args` are passed through to tincd: everything after
/// `start` becomes a tincd arg, so `tinc start -d 5` runs
/// `tincd -d 5`.
///
/// # Errors
/// - Socketpair / spawn / fcntl failure: `BadInput` wrapping the
///   `io::Error`.
/// - Daemon didn't send the nul byte before closing the umbilical
///   (setup failed; whatever it logged to stderr is the diagnostic):
///   `BadInput("Error starting <path>")`.
///
/// "Already running" is **not** an error: prints a message, returns
/// Ok. Idempotent start.
pub fn start(paths: &Paths, extra_args: &[String]) -> Result<(), CmdError> {
    // ─── already running?
    // Any connect error means "not running, proceed". PidfileMissing,
    // PidfileMalformed, DaemonDead, SocketConnect — all mean "go".
    if let Ok(ctl) = CtlSocket::connect(paths) {
        eprintln!("A tincd is already running with pid {}.", ctl.pid);
        return Ok(());
    }

    let tincd = find_tincd();

    // ─── socketpair
    // `UnixStream::pair` wraps `socketpair(AF_UNIX, SOCK_STREAM, 0)`.
    // The catch: std sets CLOEXEC on both fds (sane default for
    // everything *except* deliberate inheritance). We clear it on
    // `theirs` so it survives exec.
    let (mut ours, theirs) = UnixStream::pair()
        .map_err(|e| CmdError::BadInput(format!("Could not create umbilical socket: {e}")))?;

    let theirs_fd = theirs.as_raw_fd();
    // F_SETFD with empty FdFlag clears all fd flags, i.e. unsets
    // CLOEXEC. nix 0.29 takes RawFd here (it's a probe-style call,
    // not ownership-claiming).
    fcntl(theirs_fd, FcntlArg::F_SETFD(FdFlag::empty()))
        .map_err(|e| CmdError::BadInput(format!("Could not clear CLOEXEC on umbilical: {e}")))?;

    // ─── TINC_UMBILICAL value
    // "{fd} {colorize}". The fd number is stable across spawn —
    // exec preserves non-CLOEXEC fds at their current numbers. We
    // can format it here, in the parent, pre-spawn.
    //
    // colorize: used for teed log lines. Our daemon ignores it (no
    // teeing). Still set, for forward-compat and for cross-impl
    // with the upstream tincd (`TINCD_PATH` pointed at it).
    let colorize = i32::from(use_ansi_escapes_stderr());
    let umbilical_val = format!("{theirs_fd} {colorize}");

    // ─── spawn
    // We don't replay our `-c`/`-n` — instead pass the *resolved*
    // paths as explicit `--pidfile`/`--socket`/`-c`. This is what
    // every test in `crates/tincd/tests/` does already.
    //
    // `Command` does fork+exec internally. The child inherits our
    // env (including `TINC_UMBILICAL` via `.env()`) and our open
    // fds (including `theirs_fd`, now non-CLOEXEC).
    let mut child = Command::new(&tincd)
        .arg("-c")
        .arg(&paths.confbase)
        .arg("--pidfile")
        .arg(paths.pidfile())
        .arg("--socket")
        .arg(paths.unix_socket())
        .args(extra_args)
        .env("TINC_UMBILICAL", &umbilical_val)
        .spawn()
        .map_err(|e| CmdError::BadInput(format!("Error starting {}: {e}", tincd.display())))?;

    // ─── close our copy of the child end
    // Critical: if we kept it open, the read loop below would never
    // see EOF (we'd be holding the write end open ourselves).
    drop(theirs);

    // ─── drain the umbilical
    // Everything before the final nul byte is teed to stderr (the
    // daemon's startup logs; in our case empty until log teeing
    // lands, but the loop works against the upstream tincd too).
    //
    // `failure` tracks: did we see a nul byte as the *last* byte
    // before EOF? Nul is 0 (false → success). If the daemon died
    // without writing anything, the loop body never runs, failure
    // stays at its `true` initializer.
    let mut failure = true;
    let mut buf = [0u8; 1024];
    loop {
        match ours.read(&mut buf) {
            Ok(0) => break, // EOF
            Ok(mut n) => {
                // The nul byte itself isn't log output — strip it
                // before the stderr write.
                failure = buf[n - 1] != 0;
                if !failure {
                    n -= 1;
                }
                let _ = std::io::stderr().write_all(&buf[..n]);
            }
            Err(_) => {
                failure = true;
                break;
            }
        }
    }

    // ─── reap the child
    // The daemon detaches by default — its `daemon(3)` call exits
    // the original child with status 0 immediately. So wait returns
    // fast and `status.success()`. The *grandchild* (the actual
    // daemon) keeps running.
    //
    // If the daemon was started with `-D` in extra_args, this blocks
    // until the daemon exits. That's correct for `tinc start -D`
    // (you asked for foreground; `tinc start` waits with you).
    let status = child
        .wait()
        .map_err(|e| CmdError::BadInput(format!("Error waiting for {}: {e}", tincd.display())))?;

    if failure || !status.success() {
        return Err(CmdError::BadInput(format!(
            "Error starting {}",
            tincd.display()
        )));
    }
    Ok(())
}

/// `cmd_restart`. Stop (best-effort), then start. Stop failing
/// (daemon wasn't running) is fine; start proceeds.
///
/// # Errors
/// Only from `start`. A failed stop is not an error.
pub fn restart(paths: &Paths, extra_args: &[String]) -> Result<(), CmdError> {
    // Best-effort stop. `ctl_simple::stop` errors if the daemon
    // isn't running (connect fails); that's the no-op case.
    let _ = super::ctl_simple::stop(paths);
    start(paths, extra_args)
}

/// Find the tincd binary.
///
/// Precedence:
///   1. `TINCD_PATH` env (our addition; for tests)
///   2. Sibling of the `tinc` binary (`dirname(current_exe)/tincd`)
///   3. Bare `tincd` (Command searches PATH)
///
/// `current_exe()` is the absolute resolved path on Linux
/// (`/proc/self/exe` readlink) and macOS (`_NSGetExecutablePath`).
/// More reliable than argv[0].
fn find_tincd() -> PathBuf {
    if let Ok(p) = std::env::var("TINCD_PATH") {
        return PathBuf::from(p);
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let sibling = dir.join("tincd");
        if sibling.exists() {
            return sibling;
        }
    }
    // Bare name. Command::spawn searches PATH for non-slash names.
    PathBuf::from("tincd")
}

/// Same three-check as `cmd::stream::use_ansi_escapes_stdout` but
/// on fd 2. The umbilical's teed log lines go to *our* stderr, so
/// colorize iff our stderr is a colour-capable tty.
fn use_ansi_escapes_stderr() -> bool {
    if !std::io::stderr().is_terminal() {
        return false;
    }
    match std::env::var("TERM") {
        Ok(term) => term != "dumb",
        Err(_) => false,
    }
}

// ═══════════════════════════ tests ═════════════════════════════════
//
// `start()` is mostly process plumbing; the unit-testable parts are
// `find_tincd` and the negative-path drain (no nul byte → error).
// The positive path (real tincd writes the nul) is the integration
// test in `crates/tincd/tests/stop.rs::umbilical_ready_signal` —
// that's where CARGO_BIN_EXE_tincd is available.

#[cfg(test)]
// set_var/remove_var are unsafe in edition 2024 (multi-threaded
// env-mutation race). nextest runs each test in its own process so
// the race doesn't apply, but the lint doesn't know that. The
// `unsafe` is purely for env mutation — `start()` itself is
// unsafe-free.
#[allow(unsafe_code)]
mod tests {
    use super::*;

    /// `TINCD_PATH` env wins.
    #[test]
    fn find_tincd_env_override() {
        // SAFETY: nextest runs each test in its own process; no
        // env-mutation race with parallel tests.
        unsafe {
            std::env::set_var("TINCD_PATH", "/custom/tincd");
        }
        assert_eq!(find_tincd(), PathBuf::from("/custom/tincd"));
        unsafe {
            std::env::remove_var("TINCD_PATH");
        }
    }

    /// Daemon-not-running → proceed past the connect check, attempt
    /// spawn. With `TINCD_PATH=/bin/true`, spawn+wait succeed but
    /// `/bin/true` doesn't write the nul byte → `failure` stays true
    /// → "Error starting". Proves: (a) PidfileMissing doesn't block
    /// start, (b) the drain loop's last-byte logic works for the
    /// "no bytes at all" case.
    #[test]
    fn start_proceeds_past_missing_pidfile() {
        let dir = tempfile::tempdir().unwrap();
        let mut paths = crate::names::Paths::for_cli(&crate::names::PathsInput {
            confbase: Some(dir.path().to_owned()),
            ..Default::default()
        });
        paths.resolve_runtime(&crate::names::PathsInput {
            confbase: Some(dir.path().to_owned()),
            pidfile: Some(dir.path().join("nope.pid")),
            ..Default::default()
        });

        // /bin/true: exits 0 without writing to the umbilical →
        // EOF immediately → failure stays at its true initializer.
        // SAFETY: nextest runs each test in its own process.
        unsafe {
            std::env::set_var("TINCD_PATH", "/bin/true");
        }
        let r = start(&paths, &[]);
        unsafe {
            std::env::remove_var("TINCD_PATH");
        }

        let err = r.unwrap_err();
        assert!(err.to_string().contains("Error starting"), "got: {err}");
    }

    /// Any `CtlError` → discard, proceed. A malformed pidfile
    /// (daemon crashed mid-write, say) shouldn't block start.
    #[test]
    fn start_proceeds_past_malformed_pidfile() {
        let dir = tempfile::tempdir().unwrap();
        let pf = dir.path().join("tinc.pid");
        // Garbage. Pidfile::read returns CtlError::PidfileMalformed.
        std::fs::write(&pf, "not a pidfile\n").unwrap();

        let mut paths = crate::names::Paths::for_cli(&crate::names::PathsInput {
            confbase: Some(dir.path().to_owned()),
            ..Default::default()
        });
        paths.resolve_runtime(&crate::names::PathsInput {
            confbase: Some(dir.path().to_owned()),
            pidfile: Some(pf),
            ..Default::default()
        });

        // SAFETY: nextest runs each test in its own process.
        unsafe {
            std::env::set_var("TINCD_PATH", "/bin/true");
        }
        let r = start(&paths, &[]);
        unsafe {
            std::env::remove_var("TINCD_PATH");
        }

        // Got past the connect check (didn't early-return Ok), and
        // the error is from the umbilical drain, not a CtlError.
        assert!(r.unwrap_err().to_string().contains("Error starting"));
    }
}
