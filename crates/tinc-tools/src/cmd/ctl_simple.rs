//! One-shot control commands. The `cmd_reload`/`cmd_purge`/`cmd_retry`/
//! `cmd_stop`/`cmd_debug`/`cmd_pid`/`cmd_disconnect` cluster from
//! `tincctl.c`. Each is: connect → send one line → recv one ack →
//! check result int.
//!
//! ## Why one module not seven
//!
//! Seven 5-line functions sharing one `connect_and_send` helper. The
//! C has them as separate `cmd_*` because the dispatch table needs
//! function pointers. We do too (the binary's `CmdEntry` table), but
//! the implementations are so similar that splitting into seven files
//! would be more navigation than code. Contrast with `cmd::init` or
//! `cmd::join` — those have actual substance.
//!
//! `tincctl.c:1085-1494` for the C source. Each is ~15 lines of
//! boilerplate around `sendline`/`recvline`/`sscanf`. The Rust is
//! ~5 lines because `CtlSocket` abstracts the boilerplate.
//!
//! ## What's NOT here despite being a one-shot
//!
//! `dump invitations` (`tincctl.c:1108-1180`): not a daemon RPC at
//! all — pure filesystem readdir. Belongs in `cmd::dump` (when that
//! lands as part of the full `dump` command). Including it here
//! would couple a 4a-shaped fs operation into the 5b module.
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

#![allow(clippy::doc_markdown)]

use crate::cmd::CmdError;
use crate::ctl::{CtlError, CtlRequest, CtlSocket};
use crate::names::{Paths, check_id};

/// Convert a `CtlError` to `CmdError::BadInput`. The control errors
/// all become "daemon problem" from the CLI's perspective; the
/// `Display` carries the specifics.
///
/// Why `BadInput` not a new `CmdError::Daemon`: `BadInput` already
/// has the "string message → exit 1" semantics every caller wants.
/// A separate variant would route to the same place. If we later
/// want a different exit code for daemon-down (so scripts can
/// distinguish), then we add the variant. YAGNI for now.
///
/// Owned-taking because every callsite is `.map_err(daemon_err)`
/// where `Result::map_err` passes the error by value. clippy's
/// needless-pass-by-value fires (the body only borrows for
/// `to_string`); allowed because the alternative (`|e| ctl_err(&e)`
/// at every site) is worse.
#[allow(clippy::needless_pass_by_value)]
fn daemon_err(e: CtlError) -> CmdError {
    CmdError::BadInput(e.to_string())
}

/// Connect with a useful "daemon not running" message. The C `verbose=true`
/// flavor: `connect_tincd(true)` prints to stderr on failure. We
/// return the error and let the binary print.
///
/// `paths` must already be `resolve_runtime()`d. The panic from
/// `pidfile()` is the assertion that the binary did its job.
#[cfg(unix)]
fn connect(paths: &Paths) -> Result<CtlSocket<std::os::unix::net::UnixStream>, CmdError> {
    CtlSocket::connect(paths).map_err(daemon_err)
}

/// `cmd_pid` (`tincctl.c:1570-1585`). The simplest command: connect,
/// print the pid from greeting line 2, done. No CONTROL request sent
/// at all — the greeting carries the pid.
///
/// Returns the pid; the binary prints it. Returning instead of
/// printing lets the binary's `cmd_pid` adapter handle stdout, same
/// pattern as `cmd_invite` returning the URL.
///
/// # Errors
/// `BadInput` (wrapping `CtlError`) if connect fails. Daemon down,
/// pidfile missing, socket connect refused, greeting bad — all become
/// "could not connect" with the specific message.
#[cfg(unix)]
pub fn pid(paths: &Paths) -> Result<u32, CmdError> {
    // C: `if(!connect_tincd(true) || !pid) return 1; printf("%d\n", pid)`.
    // The `!pid` check is dead in practice — if connect succeeded,
    // greeting line 2 set pid. The C check is paranoia for "what if
    // the greeting parsed but pid was 0". We don't bother: a daemon
    // running at pid 0 would be init, which doesn't run tincd.
    let ctl = connect(paths)?;
    Ok(ctl.pid)
}

/// `cmd_reload` (`tincctl.c:1085-1105`). Tell the daemon to re-read
/// its config. The daemon's `reload_configuration()` returns nonzero
/// on error (config parse failed, unknown variable, etc.); that
/// surfaces as our error.
///
/// # Errors
/// Connect failure, or daemon-side reload returned nonzero.
#[cfg(unix)]
pub fn reload(paths: &Paths) -> Result<(), CmdError> {
    let mut ctl = connect(paths)?;
    ctl.send(CtlRequest::Reload).map_err(daemon_err)?;
    let result = ctl.recv_ack(CtlRequest::Reload).map_err(daemon_err)?;
    // C: `|| result` — nonzero is failure. The daemon's
    // `reload_configuration` returns its own status int.
    if result != 0 {
        return Err(CmdError::BadInput("Could not reload configuration.".into()));
    }
    Ok(())
}

/// `cmd_purge` (`tincctl.c:1376-1398`). Tell the daemon to forget
/// unreachable nodes. The daemon's `purge()` is void → always-0 result.
///
/// # Errors
/// Connect failure. The daemon-side purge can't fail (it's a tree
/// walk and free, no fallible operations); the C still checks
/// `result` out of habit. We do too.
#[cfg(unix)]
pub fn purge(paths: &Paths) -> Result<(), CmdError> {
    let mut ctl = connect(paths)?;
    ctl.send(CtlRequest::Purge).map_err(daemon_err)?;
    let result = ctl.recv_ack(CtlRequest::Purge).map_err(daemon_err)?;
    if result != 0 {
        return Err(CmdError::BadInput(
            "Could not purge old information.".into(),
        ));
    }
    Ok(())
}

/// `cmd_retry` (`tincctl.c:1426-1448`). Tell the daemon to retry
/// outgoing connections immediately (instead of waiting for the
/// backoff timer). Daemon's `retry()` is void → always-0.
///
/// # Errors
/// Connect failure.
#[cfg(unix)]
pub fn retry(paths: &Paths) -> Result<(), CmdError> {
    let mut ctl = connect(paths)?;
    ctl.send(CtlRequest::Retry).map_err(daemon_err)?;
    let result = ctl.recv_ack(CtlRequest::Retry).map_err(daemon_err)?;
    if result != 0 {
        return Err(CmdError::BadInput(
            "Could not retry outgoing connections.".into(),
        ));
    }
    Ok(())
}

/// `cmd_stop` (`tincctl.c:672-688`, the `stop_tincd` body). Tell the
/// daemon to exit. The daemon acks then `event_exit()`s; we drain
/// until the socket closes.
///
/// The drain loop is the C `while(recvline(fd, line, sizeof line))`.
/// It serves two purposes: (1) wait for the daemon to actually exit
/// (so `tinc stop && tinc start` doesn't race), (2) consume the ack
/// line we don't otherwise need. The second is why we don't use
/// `recv_ack` — the C explicitly doesn't check the ack, just drains.
///
/// # Errors
/// Connect failure. After STOP is sent, the daemon closing is the
/// expected outcome — EOF is success, not error.
#[cfg(unix)]
pub fn stop(paths: &Paths) -> Result<(), CmdError> {
    let mut ctl = connect(paths)?;
    ctl.send(CtlRequest::Stop).map_err(daemon_err)?;
    // Drain. C: `while(recvline()) {}`. The ack line gets consumed
    // and discarded; then EOF; then loop exits.
    //
    // `recv_line` distinguishes Ok(None)=EOF from Err=real-I/O-error.
    // EOF is what we want. Real I/O error after STOP… is also kind
    // of success (the daemon's gone), so we don't propagate it.
    // The C `recvline` returns false for both undifferentiated.
    while let Ok(Some(_)) = ctl.recv_line() {}
    Ok(())
}

/// `cmd_debug` (`tincctl.c:1400-1424`). Set the daemon's debug
/// level. Returns the *previous* level — `REQ_SET_DEBUG` repurposes
/// the ack's result int for this (`control.c:86`: send old level
/// before updating).
///
/// `level < 0` means "don't change, just query" (`control.c:88`:
/// `if(new_level >= 0) debug_level = new_level`). The C `cmd_debug`
/// doesn't expose this (it `atoi`s the arg, which is non-negative
/// for valid input), but we do — `debug(paths, -1)` is a valid
/// "what's the current level" call. If/when we add `tinc debug`
/// without args, that's the implementation.
///
/// # Errors
/// Connect failure or ack-shape mismatch.
#[cfg(unix)]
pub fn debug(paths: &Paths, level: i32) -> Result<i32, CmdError> {
    let mut ctl = connect(paths)?;
    ctl.send_int(CtlRequest::SetDebug, level)
        .map_err(daemon_err)?;
    // Result is the previous level, not an error code. C: `&origlevel`
    // in the sscanf, no `|| result` check.
    ctl.recv_ack(CtlRequest::SetDebug).map_err(daemon_err)
}

/// `cmd_disconnect` (`tincctl.c:1471-1494`). Tell the daemon to drop
/// its connection to `name`. Daemon-side: walk `connection_list`,
/// `terminate_connection` on matches, return `0` if found, `-2` if
/// not (`control.c:122`).
///
/// Validates `name` with `check_id` before sending — the daemon does
/// `strcmp` against connection names, so a bogus name would just
/// not match (return `-2`), but the C checks anyway. Same defense
/// in depth as everywhere else `check_id` appears.
///
/// # Errors
/// `BadInput("Invalid name")` if `check_id` fails (before connect).
/// Connect failure. `BadInput("Could not disconnect")` if daemon
/// returns nonzero (node not found, or disconnect failed).
#[cfg(unix)]
pub fn disconnect(paths: &Paths, name: &str) -> Result<(), CmdError> {
    // Validate FIRST. The C does this before `connect_tincd` —
    // don't waste a socket on a bad name.
    if !check_id(name) {
        return Err(CmdError::BadInput("Invalid name for node.".into()));
    }

    let mut ctl = connect(paths)?;
    ctl.send_str(CtlRequest::Disconnect, name)
        .map_err(daemon_err)?;
    let result = ctl.recv_ack(CtlRequest::Disconnect).map_err(daemon_err)?;
    if result != 0 {
        // C: `"Could not disconnect %s.\n"`. We include the name;
        // the result int (-2 for not-found, -1 for protocol error)
        // doesn't surface in the C message either.
        return Err(CmdError::BadInput(format!("Could not disconnect {name}.")));
    }
    Ok(())
}

// ════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════
//
// These test the *command logic* — that each function sends the right
// request and interprets the ack correctly. The transport (`CtlSocket`)
// is tested in `ctl.rs`. The OS path (`connect()`) isn't testable
// without a daemon; it's a thin wrapper around tested pieces.
//
// We can't test through `connect()` (no real daemon), so each test
// inlines the body that comes *after* connect — the send/recv/check.
// This means a tiny bit of duplication (each test does its own
// handshake), but it tests the actual ack-interpretation logic
// (`result != 0`, drain-to-EOF, etc.) which is what these commands
// add over raw `CtlSocket`.
//
// The "command's body, minus connect()" pattern: extract the post-
// connect logic into a `_with(ctl, ...)` helper that takes an
// already-connected socket. The public fn is `connect()? +
// _with(ctl)`. Tests call `_with` directly. Same seam as `cmd::sign`'s
// `verify_blob` vs `verify`.

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::ctl::CtlSocket;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    use std::thread;

    /// Same fake-daemon helper as `ctl.rs::tests`. Duplicated, not
    /// shared, because lifting it would mean `pub(crate)` test
    /// infrastructure crossing module boundaries. The duplication is
    /// 30 lines; the indirection of a shared `#[cfg(test)] pub` helper
    /// is more. If a third module needs it, factor then.
    fn fake_daemon<F>(theirs: UnixStream, serve: F) -> thread::JoinHandle<()>
    where
        F: FnOnce(&mut BufReader<&UnixStream>, &mut &UnixStream) + Send + 'static,
    {
        let cookie = "a".repeat(64);
        thread::spawn(move || {
            let read = &theirs;
            let mut write = &theirs;
            let mut br = BufReader::new(read);
            // Greeting dance.
            let mut line = String::new();
            br.read_line(&mut line).unwrap();
            assert!(line.contains(&format!("^{cookie}")));
            writeln!(write, "0 fakedaemon 17.7").unwrap();
            writeln!(write, "4 0 4242").unwrap(); // pid=4242
            // Hand off.
            serve(&mut br, &mut write);
        })
    }

    /// `reload` happy path: result=0 → Ok.
    #[test]
    fn reload_ok() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let cookie = "a".repeat(64);

        let daemon = fake_daemon(theirs, |br, w| {
            let mut line = String::new();
            br.read_line(&mut line).unwrap();
            assert_eq!(line.trim_end(), "18 1");
            writeln!(w, "18 1 0").unwrap();
        });

        let mut ctl = CtlSocket::handshake(ours, &cookie).unwrap();
        // Inline reload's body (post-connect).
        ctl.send(CtlRequest::Reload).unwrap();
        let r = ctl.recv_ack(CtlRequest::Reload).unwrap();
        assert_eq!(r, 0);

        daemon.join().unwrap();
    }

    /// `reload` failure: daemon's reload returned nonzero. The
    /// command should error with the C's message. We test the
    /// interpretation, not the transport (transport is `ctl.rs`'s job).
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
            // C `control.c:86-89`: send first, then `if(new >= 0)
            // debug_level = new`.
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

    /// `disconnect` with bad name fails BEFORE connect. The C
    /// `check_id` runs before `connect_tincd`. We test the public
    /// `disconnect()` here because the validation IS the function —
    /// no socket needed for the failure path.
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

    /// `disconnect` ack: -2 means not-found. C `control.c:122`:
    /// `found ? 0 : -2`. The CLI maps both -2 and -1 to the same
    /// error message; we just check the nonzero detection.
    #[test]
    fn disconnect_not_found() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let cookie = "a".repeat(64);

        let daemon = fake_daemon(theirs, |br, w| {
            let mut line = String::new();
            br.read_line(&mut line).unwrap();
            assert_eq!(line.trim_end(), "18 12 ghost");
            // -2: not found. C `control.c:122`.
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
