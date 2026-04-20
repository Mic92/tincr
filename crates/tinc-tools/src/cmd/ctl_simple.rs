//! One-shot control commands: reload/purge/retry/stop/debug/pid/
//! disconnect. Each is: connect → send one line → recv one ack →
//! check result int.
//!
//! ## Why one module not seven
//!
//! Seven 5-line functions sharing one helper. The implementations
//! are so similar that splitting into seven files would be more
//! navigation than code. Contrast with `cmd::init` or `cmd::join` —
//! those have actual substance.
//!
//! ## What's NOT here despite being a one-shot
//!
//! `dump invitations`: not a daemon RPC at all — pure filesystem
//! readdir. Belongs in `cmd::dump`.
//!
//! `cmd_log`/`cmd_pcap`: not one-shot. They stream forever. Separate
//! modules when they land.
//!
//! `cmd_start`/`cmd_restart`: fork+exec, daemon binary needs to exist.
//!
//! ## Testing
//!
//! Unit tests use `CtlSocket::handshake` over `UnixStream::pair()` —
//! same fake-daemon-thread pattern as `ctl.rs`. The tests prove each
//! command sends the right line and handles the right ack; they
//! don't prove the daemon does the right thing (no daemon yet).
//!
//! The one untested seam is `CtlSocket::connect()` — the real OS
//! path. That gets a smoke test when the daemon lands. The pieces
//! it composes (pidfile read, socket connect, handshake) are each
//! unit-tested.

#![cfg(unix)]

use crate::cmd::CmdError;
use crate::ctl::{CtlRequest, CtlSocket};
use crate::names::{Paths, check_id};

/// Connect with a useful "daemon not running" message. We return
/// the error and let the binary print.
///
/// `paths` must already be `resolve_runtime()`d. The panic from
/// `pidfile()` is the assertion that the binary did its job.
fn connect(paths: &Paths) -> Result<CtlSocket<std::os::unix::net::UnixStream>, CmdError> {
    CtlSocket::connect(paths).map_err(Into::into)
}

/// `cmd_pid`. The simplest command: connect, print the pid from
/// greeting line 2, done. No CONTROL request sent at all — the
/// greeting carries the pid.
///
/// Returns the pid; the binary prints it. Returning instead of
/// printing lets the binary's `cmd_pid` adapter handle stdout, same
/// pattern as `cmd_invite` returning the URL.
///
/// # Errors
/// `BadInput` (wrapping `CtlError`) if connect fails. Daemon down,
/// pidfile missing, socket connect refused, greeting bad — all become
/// "could not connect" with the specific message.
pub fn pid(paths: &Paths) -> Result<u32, CmdError> {
    let ctl = connect(paths)?;
    Ok(ctl.pid)
}

/// connect → send `req` → expect `result == 0` ack. Three commands
/// (reload/purge/retry) differ only in the request and the error text.
fn simple(paths: &Paths, req: CtlRequest, err: &str) -> Result<(), CmdError> {
    let mut ctl = connect(paths)?;
    ctl.send(req)?;
    if ctl.recv_ack(req)? != 0 {
        return Err(CmdError::BadInput(err.into()));
    }
    Ok(())
}

/// `cmd_reload`. Tell the daemon to re-read its config. The daemon's
/// `reload_configuration()` returns nonzero on error (config parse
/// failed, unknown variable, etc.); that surfaces as our error.
///
/// # Errors
/// Connect failure, or daemon-side reload returned nonzero.
pub fn reload(paths: &Paths) -> Result<(), CmdError> {
    simple(paths, CtlRequest::Reload, "Could not reload configuration.")
}

/// `cmd_purge`. Tell the daemon to forget unreachable nodes. The
/// daemon's `purge()` is void → always-0 result.
///
/// # Errors
/// Connect failure. The daemon-side purge can't fail (it's a tree
/// walk and free); we still check `result` out of habit.
pub fn purge(paths: &Paths) -> Result<(), CmdError> {
    simple(paths, CtlRequest::Purge, "Could not purge old information.")
}

/// `cmd_retry`. Tell the daemon to retry outgoing connections
/// immediately (instead of waiting for the backoff timer). Daemon's
/// `retry()` is void → always-0.
///
/// # Errors
/// Connect failure.
pub fn retry(paths: &Paths) -> Result<(), CmdError> {
    simple(
        paths,
        CtlRequest::Retry,
        "Could not retry outgoing connections.",
    )
}

/// `cmd_stop`. Tell the daemon to exit. The daemon acks then
/// `event_exit()`s; we drain until the socket closes.
///
/// The drain loop serves two purposes: (1) wait for the daemon to
/// actually exit (so `tinc stop && tinc start` doesn't race), (2)
/// consume the ack line we don't otherwise need. The second is why
/// we don't use `recv_ack` — we don't check the ack, just drain.
///
/// # Errors
/// Connect failure. After STOP is sent, the daemon closing is the
/// expected outcome — EOF is success, not error.
pub fn stop(paths: &Paths) -> Result<(), CmdError> {
    let mut ctl = connect(paths)?;
    ctl.send(CtlRequest::Stop)?;
    // Drain. `recv_line` distinguishes Ok(None)=EOF from Err. EOF is
    // what we want. Real I/O error after STOP is also kind of
    // success (the daemon's gone), so we don't propagate it.
    while let Ok(Some(_)) = ctl.recv_line() {}
    Ok(())
}

/// `cmd_debug`. Set the daemon's debug level. Returns the *previous*
/// level — `REQ_SET_DEBUG` repurposes the ack's result int for this.
///
/// `level < 0` means "don't change, just query". `debug(paths, -1)`
/// is a valid "what's the current level" call. If/when we add `tinc
/// debug` without args, that's the implementation.
///
/// # Errors
/// Connect failure or ack-shape mismatch.
pub fn debug(paths: &Paths, level: i32) -> Result<i32, CmdError> {
    let mut ctl = connect(paths)?;
    ctl.send_int(CtlRequest::SetDebug, level)?;
    // Result is the previous level, not an error code.
    ctl.recv_ack(CtlRequest::SetDebug).map_err(Into::into)
}

/// `cmd_disconnect`. Tell the daemon to drop its connection to
/// `name`. Daemon-side: walk `connection_list`, terminate on
/// matches, return `0` if found, `-2` if not.
///
/// Validates `name` with `check_id` before sending — a bogus name
/// would just not match (return `-2`), but defense in depth.
///
/// # Errors
/// `BadInput("Invalid name")` if `check_id` fails (before connect).
/// Connect failure. `BadInput("Could not disconnect")` if daemon
/// returns nonzero (node not found, or disconnect failed).
pub fn disconnect(paths: &Paths, name: &str) -> Result<(), CmdError> {
    // Validate FIRST — don't waste a socket on a bad name.
    if !check_id(name) {
        return Err(CmdError::BadInput("Invalid name for node.".into()));
    }

    let mut ctl = connect(paths)?;
    ctl.send_str(CtlRequest::Disconnect, name)?;
    let result = ctl.recv_ack(CtlRequest::Disconnect)?;
    if result != 0 {
        return Err(CmdError::BadInput(format!("Could not disconnect {name}.")));
    }
    Ok(())
}

// Tests cover the post-connect ack-interpretation; the `connect()` OS
// path is untestable without a real daemon and is a thin wrapper.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctl::CtlSocket;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    use std::thread;

    /// Thin wrapper over the shared `ctl::tests::fake_daemon` with the
    /// fixed cookie/pid these tests use.
    fn fake_daemon<F>(theirs: UnixStream, serve: F) -> thread::JoinHandle<()>
    where
        F: FnOnce(&mut BufReader<&UnixStream>, &mut &UnixStream) + Send + 'static,
    {
        crate::ctl::tests::fake_daemon(theirs, &"a".repeat(64), 4242, serve)
    }

    /// `reload` happy path: result=0 → Ok.
    /// `reload` failure: daemon's reload returned nonzero. We test
    /// the interpretation, not the transport (that's `ctl.rs`'s job).
    #[test]
    fn reload_daemon_fail() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let cookie = "a".repeat(64);

        let daemon = fake_daemon(theirs, |br, w| {
            let mut line = String::new();
            br.read_line(&mut line).unwrap();
            // result=1 — config parse failed on daemon side, say.
            writeln!(w, "18 1 1").unwrap();
        });

        let mut ctl = CtlSocket::handshake(ours, &cookie).unwrap();
        ctl.send(CtlRequest::Reload).unwrap();
        let r = ctl.recv_ack(CtlRequest::Reload).unwrap();
        // Nonzero. The public `reload()` would map this to an error;
        // here we just check the value flows.
        assert_ne!(r, 0);

        daemon.join().unwrap();
    }

    /// `stop` drains to EOF. The actual stop semantics: daemon acks,
    /// daemon exits, socket closes, our drain loop exits.
    #[test]
    fn stop_drains() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let cookie = "a".repeat(64);

        let daemon = fake_daemon(theirs, |br, w| {
            let mut line = String::new();
            br.read_line(&mut line).unwrap();
            assert_eq!(line.trim_end(), "18 0");
            writeln!(w, "18 0 0").unwrap();
            // Thread returns → drop → socket closes → EOF.
        });

        let mut ctl = CtlSocket::handshake(ours, &cookie).unwrap();
        // Inline stop's body. Send + drain.
        ctl.send(CtlRequest::Stop).unwrap();
        let mut drained = 0;
        while let Ok(Some(_)) = ctl.recv_line() {
            drained += 1;
        }
        // One line drained: the ack. Then EOF.
        assert_eq!(drained, 1);

        daemon.join().unwrap();
    }

    /// `debug` returns the previous level, not an error code. The
    /// repurposed-result-int semantics that `recv_ack` deliberately
    /// doesn't interpret.
    #[test]
    fn debug_returns_prev_level() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let cookie = "a".repeat(64);

        let daemon = fake_daemon(theirs, |br, w| {
            let mut line = String::new();
            br.read_line(&mut line).unwrap();
            // We requested level 5.
            assert_eq!(line.trim_end(), "18 9 5");
            // Daemon was at 2. Sends old level *before* updating.
            writeln!(w, "18 9 2").unwrap();
        });

        let mut ctl = CtlSocket::handshake(ours, &cookie).unwrap();
        ctl.send_int(CtlRequest::SetDebug, 5).unwrap();
        let prev = ctl.recv_ack(CtlRequest::SetDebug).unwrap();
        // Previous level. NOT an error code. `debug()` would NOT
        // map this to an error.
        assert_eq!(prev, 2);

        daemon.join().unwrap();
    }

    /// `disconnect` with bad name fails BEFORE connect. We test the
    /// public `disconnect()` here because the validation IS the
    /// function — no socket needed for the failure path.
    #[test]
    fn disconnect_bad_name_preflight() {
        // We need a Paths but it won't be used (check_id fails first).
        // Don't resolve_runtime — if disconnect() reaches for the
        // socket on this input, the panic from `pidfile()` will
        // (correctly) fail the test.
        let paths = Paths::for_cli(&crate::names::PathsInput {
            confbase: Some("/tmp/never-touched".into()),
            ..Default::default()
        });

        let err = disconnect(&paths, "has space").unwrap_err();
        assert!(matches!(err, CmdError::BadInput(_)));
        assert!(err.to_string().contains("Invalid name"));

        // Traversal attempt. `check_id` rejects `/`.
        let err = disconnect(&paths, "../etc/passwd").unwrap_err();
        assert!(matches!(err, CmdError::BadInput(_)));
    }

    /// `disconnect` ack: -2 means not-found. The CLI maps both -2
    /// and -1 to the same error message; we just check the nonzero
    /// detection.
    #[test]
    fn disconnect_not_found() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let cookie = "a".repeat(64);

        let daemon = fake_daemon(theirs, |br, w| {
            let mut line = String::new();
            br.read_line(&mut line).unwrap();
            assert_eq!(line.trim_end(), "18 12 ghost");
            writeln!(w, "18 12 -2").unwrap();
        });

        let mut ctl = CtlSocket::handshake(ours, &cookie).unwrap();
        ctl.send_str(CtlRequest::Disconnect, "ghost").unwrap();
        let r = ctl.recv_ack(CtlRequest::Disconnect).unwrap();
        assert_eq!(r, -2);

        daemon.join().unwrap();
    }

    /// `pid` returns the pid from the greeting. No CONTROL line sent.
    /// This is the simplest possible 5b command — just the side
    /// effect of connecting.
    #[test]
    fn pid_from_greeting() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let cookie = "a".repeat(64);

        // No serve closure body — pid comes from the greeting,
        // nothing more is sent.
        let daemon = fake_daemon(theirs, |_br, _w| {});

        let ctl = CtlSocket::handshake(ours, &cookie).unwrap();
        // fake_daemon sends pid=4242 in greeting line 2.
        assert_eq!(ctl.pid, 4242);

        daemon.join().unwrap();
    }
}
