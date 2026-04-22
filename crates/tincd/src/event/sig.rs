//! Self-pipe signal handling. Ports `signal.c` (90 LOC).
//!
//! Async-signal-safe handler does `write(pipefd[1], &num, 1)`. The
//! poll loop reads `pipefd[0]` and dispatches. Standard self-pipe
//! trick (DJB, 1990s).
//!
//! We use the same trick. `signal-hook` exists and does this with
//! more polish, but it's +3 deps (`signal-hook`, `signal-hook-
//! registry`, `libc` which we already have). The C is 90 LOC; the
//! Rust is ~150. Hand-roll.
//!
//! # `signal()` vs `sigaction()`
//!
//! POSIX `signal()` is underspecified — System V semantics reset to
//! `SIG_DFL` after one delivery; BSD semantics don't. Linux glibc
//! gives BSD semantics (the man page warns). The C code works on
//! Linux/BSD by accident of the libc.
//!
//! We use `sigaction()` directly with `SA_RESTART` and an empty mask.
//! Same effective behavior on Linux/BSD as the C, but portable.
//! `SA_RESTART` because the daemon's syscalls (read, write, accept)
//! shouldn't fail with `EINTR` for SIGHUP/SIGTERM — the self-pipe
//! wakes the poll loop, the syscall restarts and finishes, then poll
//! sees the pipe. Without `SA_RESTART` every syscall everywhere would
//! need an EINTR retry loop. The C didn't set `SA_RESTART` (because
//! `signal()` doesn't expose flags); BSD `signal()` sets it
//! implicitly, glibc does too. We make it explicit.
//!
//! # Async-signal-safety
//!
//! The handler may only call async-signal-safe functions; it does
//! one raw `write(2)` of `signum as u8` and nothing else. The
//! write-end fd is stashed in a `static AtomicI32` — the C uses a
//! plain `static int`, which is a (benign) data race; `AtomicI32`
//! costs nothing and avoids the UB.

use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::sync::atomic::{AtomicI32, Ordering};

use nix::sys::signal::{SaFlags, SigAction, SigHandler, SigSet, Signal, sigaction};

/// Write-end fd for the handler. `-1` = not initialized; `new()`
/// sets this BEFORE installing the handler so the `<0` bail is
/// purely defensive.
static PIPE_WR: AtomicI32 = AtomicI32::new(-1);

/// Max signal number we'll dispatch. `SIGRTMIN - 1` on Linux is 31;
/// real-time signals start at 32. tincd registers HUP(1), INT(2),
/// ALRM(14), TERM(15). 32 is plenty.
const NSIG_TABLE: usize = 32;

/// Self-pipe + signal dispatch table.
///
/// Generic over `W: Copy` — the daemon's `enum SignalWhat`, same
/// pattern as `IoWhat`/`TimerWhat`. The daemon defines:
///
/// ```ignore
/// enum SignalWhat { Reload, Exit, Retry }
/// ```
///
/// and registers `(SIGHUP, Reload)`, `(SIGTERM, Exit)`, etc.
pub(crate) struct SelfPipe<W> {
    /// Read end. Registered with the `EventLoop` for `Io::Read`.
    /// When `turn()` reports it readable, daemon calls `drain()`.
    rd: OwnedFd,
    /// Write end. The handler writes here via `PIPE_WR` (the raw
    /// copy); we keep the `OwnedFd` so the pipe doesn't half-close
    /// and so tests can write through it without forging a fd.
    #[cfg_attr(not(test), allow(dead_code))]
    wr: OwnedFd,
    /// Dispatch table, indexed by signum.
    table: [Option<W>; NSIG_TABLE],
}

/// The actual signal handler. Only async-signal-safe ops: atomic
/// load + raw `write(2)`. Result ignored — a full pipe means signals
/// coalesce (two SIGHUPs = one reload), `EPIPE` means the daemon is
/// dying anyway.
extern "C" fn handler(signum: libc::c_int) {
    let fd = PIPE_WR.load(Ordering::Relaxed);
    if fd < 0 {
        return;
    }
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)] // NSIG < 256
    let byte = signum as u8;
    // SAFETY: write(2) is async-signal-safe (POSIX.1). fd is a
    // valid pipe write-end (set in new() before this handler was
    // installed; never closed while handler is installed). The
    // pointer is to a stack local. Length is 1.
    //
    // Intentionally raw `libc::write`, NOT `nix::unistd::write`: this
    // is signal-handler context. nix's wrapper is thin, but staying
    // on the bare syscall keeps the async-signal-safety audit trivial.
    #[allow(unsafe_code)]
    unsafe {
        libc::write(fd, std::ptr::addr_of!(byte).cast(), 1);
    }
}

impl<W: Copy> SelfPipe<W> {
    /// Creates the pipe, stashes the write fd in `PIPE_WR` for the
    /// handler. Does NOT
    /// register with the event loop — caller does that with `read_
    /// fd()` + `EventLoop::add`.
    ///
    /// # Panics
    /// If a `SelfPipe` already exists (`PIPE_WR` is set). The C
    /// Multiple self-pipes don't make sense (one global handler per signal).
    ///
    /// # Errors
    /// Returns the underlying I/O error if `pipe2(O_CLOEXEC)` fails.
    pub(crate) fn new() -> io::Result<Self> {
        // STRICTER: O_CLOEXEC. Without it the pipe leaks into spawned
        // script children — they'd just have an extra unused fd, but
        // it's untidy.
        let (rd, wr) = Self::pipe_cloexec()?;

        // "already initialized?" singleton check.
        let prev = PIPE_WR.swap(wr.as_raw_fd(), Ordering::Relaxed);
        assert_eq!(prev, -1, "SelfPipe already exists — singleton");

        Ok(Self {
            rd,
            wr,
            table: [None; NSIG_TABLE],
        })
    }

    /// `pipe2(O_CLOEXEC)` where available; `pipe()` + `fcntl` on macOS
    /// (which lacks `pipe2`).
    fn pipe_cloexec() -> io::Result<(OwnedFd, OwnedFd)> {
        #[cfg(any(
            target_os = "linux",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "dragonfly",
        ))]
        {
            Ok(nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC)?)
        }
        #[cfg(not(any(
            target_os = "linux",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "dragonfly",
        )))]
        {
            use nix::fcntl::{FcntlArg, FdFlag, fcntl};
            let (rd, wr) = nix::unistd::pipe()?;
            fcntl(&rd, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;
            fcntl(&wr, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;
            Ok((rd, wr))
        }
    }

    /// Read-end fd for `EventLoop::add(..., Io::Read, IoWhat::Signal)`.
    #[must_use]
    pub(crate) fn read_fd(&self) -> BorrowedFd<'_> {
        self.rd.as_fd()
    }

    /// Write-end fd. The signal handler writes here via the
    /// `PIPE_WR` raw copy; this borrowed handle lets tests inject a
    /// wakeup byte without forging a `BorrowedFd` from the static int.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn write_fd(&self) -> BorrowedFd<'_> {
        self.wr.as_fd()
    }

    /// Install the handler for `signum` and record `what`.
    /// `sigaction(SA_RESTART)`, not `signal()` — see module doc.
    ///
    /// # Errors
    /// Returns the underlying I/O error if `sigaction` fails.
    ///
    /// # Panics
    /// If `signum >= 32` (real-time signals; tincd doesn't use them).
    pub(crate) fn add(&mut self, signum: i32, what: W) -> io::Result<()> {
        let idx = usize::try_from(signum).expect("signum negative");
        assert!(idx < NSIG_TABLE, "signum {signum} >= {NSIG_TABLE}");

        let sig = Signal::try_from(signum).map_err(io::Error::from)?;
        let act = SigAction::new(
            SigHandler::Handler(handler),
            SaFlags::SA_RESTART,
            SigSet::empty(),
        );
        // SAFETY: installing a signal handler is inherently unsafe —
        // the handler must be async-signal-safe. Ours is (atomic load
        // + raw write(2)); see `handler` above.
        #[allow(unsafe_code)]
        unsafe {
            sigaction(sig, &act)?;
        }

        self.table[idx] = Some(what);
        Ok(())
    }

    /// Called when `turn()` reports the pipe readable. One blocking
    /// read of a 64-byte buffer drains everything: signals don't
    /// queue per-signum without `SA_SIGINFO`, so at most ~NSIG bytes
    /// are pending. (C reads one byte per wake; we do one read so
    /// epoll doesn't re-wake per byte.)
    pub(crate) fn drain(&self, out: &mut Vec<W>) {
        let mut buf = [0u8; 64];
        // Err: shouldn't happen — pipe is valid, was reported
        // readable. Ok(0): EOF (write end closed — daemon is dying).
        // Ok(n > 0): that many signums.
        let Ok(n) = nix::unistd::read(&self.rd, &mut buf) else {
            return;
        };
        for &signum in &buf[..n] {
            let idx = signum as usize;
            // None → skip: signum we never registered (stray byte).
            if let Some(what) = self.table.get(idx).copied().flatten() {
                out.push(what);
            }
        }
    }

}

impl<W> Drop for SelfPipe<W> {
    fn drop(&mut self) {
        // Reset PIPE_WR so a fresh SelfPipe can be created (tests
        // need this; the daemon doesn't — it's a singleton for the
        // process lifetime).
        PIPE_WR.store(-1, Ordering::Relaxed);
        // OwnedFd drops close the pipe fds. Installed handlers stay
        // installed; a post-drop signal makes `handler` see
        // `PIPE_WR == -1` and bail before write(). tincd's lifecycle
        // is "create at boot, never drop", so restoring SIG_DFL here
        // is not worth the sigaction churn.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// `SelfPipe` is a process-global singleton (one `PIPE_WR`
    /// static); serialize tests so they don't race on it.
    static SERIAL: Mutex<()> = Mutex::new(());

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Sig {
        Reload,
        Exit,
    }

    /// Pipe mechanics + table dispatch, bypassing the handler
    /// (sending real signals to the test process is rude).
    #[test]
    fn drain_dispatches_from_table() {
        let _g = SERIAL.lock().unwrap();
        let mut sp: SelfPipe<Sig> = SelfPipe::new().unwrap();
        // Populate table directly; installing real handlers is
        // process-global and covered by the integration suite.
        sp.table[Signal::SIGHUP as usize] = Some(Sig::Reload);
        sp.table[Signal::SIGTERM as usize] = Some(Sig::Exit);

        // Write signums to the pipe directly. This is what the
        // handler does, minus the atomic load.
        let bytes = [
            Signal::SIGHUP as u8,
            Signal::SIGTERM as u8,
            Signal::SIGHUP as u8,
        ];
        assert!(PIPE_WR.load(Ordering::Relaxed) >= 0, "new() set PIPE_WR");
        let n = nix::unistd::write(sp.write_fd(), &bytes).unwrap();
        assert_eq!(n, 3);

        let mut out = Vec::new();
        sp.drain(&mut out);
        assert_eq!(out, vec![Sig::Reload, Sig::Exit, Sig::Reload]);
    }

    /// Unknown signum in pipe — drain skips it.
    #[test]
    fn drain_skips_unknown() {
        let _g = SERIAL.lock().unwrap();
        let sp: SelfPipe<Sig> = SelfPipe::new().unwrap();
        // table is all None.

        let byte = [Signal::SIGUSR1 as u8];
        let n = nix::unistd::write(sp.write_fd(), &byte).unwrap();
        assert_eq!(n, 1);

        let mut out = Vec::new();
        sp.drain(&mut out);
        assert!(out.is_empty(), "unknown signum should be skipped");
    }

    /// `PIPE_WR` is reset on drop — fresh `SelfPipe` can be created.
    /// Tests need this (each test wants its own pipe); daemon doesn't.
    #[test]
    fn drop_resets_singleton() {
        let _g = SERIAL.lock().unwrap();
        {
            let _sp: SelfPipe<Sig> = SelfPipe::new().unwrap();
            assert_ne!(PIPE_WR.load(Ordering::Relaxed), -1);
        }
        assert_eq!(PIPE_WR.load(Ordering::Relaxed), -1);
        // Second new() works.
        let _sp2: SelfPipe<Sig> = SelfPipe::new().unwrap();
    }

    /// drain on empty pipe returns immediately (read returns 0 or
    /// EAGAIN — actually, blocking pipe with no data BLOCKS. We
    /// rely on epoll telling us it's readable first. This test
    /// would hang without that contract. So: don't test "drain on
    /// empty"; the contract is "drain after `turn()` says READ").
    ///
    /// Instead test: drain doesn't OVER-read. Write 1 byte; drain
    /// returns 1 element; pipe is empty.
    #[test]
    fn drain_reads_exactly_pending() {
        let _g = SERIAL.lock().unwrap();
        let mut sp: SelfPipe<Sig> = SelfPipe::new().unwrap();
        sp.table[Signal::SIGHUP as usize] = Some(Sig::Reload);

        let byte = [Signal::SIGHUP as u8];
        nix::unistd::write(sp.write_fd(), &byte).unwrap();

        let mut out = Vec::new();
        sp.drain(&mut out);
        assert_eq!(out, vec![Sig::Reload]);

        // Second drain — pipe is empty, would block. We can't call
        // it. The test for "doesn't over-read" is implicit: out has
        // exactly 1 element, not 64 (the buffer size).
    }
}
