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
//! The handler can ONLY call async-signal-safe functions. `write(2)`
//! is on the list (POSIX.1-2001). `eprintln!` is NOT (it locks).
//! Neither is anything that allocates. The handler is:
//!
//! ```c
//! write(fd, &signum_as_u8, 1);  // ignore the result
//! ```
//!
//! That's it. The Rust equivalent:
//!
//! ```ignore
//! libc::write(fd, &signum_as_u8 as *const u8 as *const _, 1);
//! ```
//!
//! Same. The fd is stashed in a `static AtomicI32` (atomic load is
//! async-signal-safe; the C uses a plain `static int` which is a
//! data race in theory but works in practice because `int` writes
//! are atomic on every platform tinc runs on. We use `AtomicI32`
//! because it costs nothing and the data race is technically UB).
//!
//! # `NSIG` and the dispatch table
//!
//! Dispatch table indexed by signum. The handler writes `signum` as
//! a `u8`; `signum` fits because real-time signals top out around
//! 64. The poll-side reads the byte and
//! indexes the table.
//!
//! `tincd.c` registers exactly 4 signals: HUP (reload), TERM (exit),
//! INT (exit), ALRM (retry). We don't need a 65-entry dispatch table.
//! `[Option<W>; 32]` is plenty (`SIGRTMIN` is 32 on Linux, 33 on BSD;
//! tinc doesn't use real-time signals).

use std::io;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicI32, Ordering};

/// The write-end fd for the handler. `-1` means "not initialized" — the handler reads this and bails
/// if so (defensive; shouldn't happen because `SelfPipe::new`
/// installs the handler AFTER setting the fd).
///
/// `AtomicI32` not `static mut` — the handler reads, `new()` writes.
/// The C uses a plain `static int`; that's a data race. Works in
/// practice (int stores are atomic on every arch tinc runs on); UB
/// in theory. `AtomicI32` is free.
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
pub struct SelfPipe<W> {
    /// Read end. Registered with the `EventLoop` for `Io::Read`.
    /// When `turn()` reports it readable, daemon calls `drain()`.
    rd: OwnedFd,
    /// Write end. The handler writes here. Kept alive so the pipe
    /// doesn't half-close. `_` prefix because we never read it
    /// directly — `PIPE_WR` is the handler's copy.
    _wr: OwnedFd,
    /// Dispatch table, indexed by signum.
    table: [Option<W>; NSIG_TABLE],
}

/// The actual signal handler. Must be `extern "C"` for `sigaction`.
///
/// Only async-signal-safe operations: atomic load, raw write.
///
/// `write(pipefd[1], &num, 1)`; result ignored — pipe full or broken,
/// nothing we can do. If the pipe is full (64KB of pending signals), losing
/// one is fine — they coalesce semantically (two SIGHUPs = one
/// reload). If the pipe is broken (`EPIPE`), the daemon is dying
/// anyway.
extern "C" fn handler(signum: libc::c_int) {
    let fd = PIPE_WR.load(Ordering::Relaxed);
    if fd < 0 {
        // Not initialized. Shouldn't happen — new() sets PIPE_WR
        // before installing the handler. Defensive.
        return;
    }
    // signum fits in u8 (NSIG < 256 everywhere). Cast is safe.
    // The C does the same: `unsigned char num = signum;` at :34.
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    let byte = signum as u8;
    // SAFETY: write(2) is async-signal-safe (POSIX.1). fd is a
    // valid pipe write-end (set in new() before this handler was
    // installed; never closed while handler is installed). The
    // pointer is to a stack local. Length is 1.
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
    pub fn new() -> io::Result<Self> {
        // STRICTER: O_CLOEXEC. Without it the pipe leaks into spawned
        // script children — they'd just have an extra unused fd, but
        // it's untidy.
        let mut fds = [0i32; 2];
        // SAFETY: pipe2 writes two valid fds on success.
        #[allow(unsafe_code)]
        let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: pipe2 returned 0; both fds are valid and ours.
        // OwnedFd::drop closes them.
        #[allow(unsafe_code)]
        let (rd, wr) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };

        // "already initialized?" singleton check.
        let prev = PIPE_WR.swap(fds[1], Ordering::Relaxed);
        assert_eq!(prev, -1, "SelfPipe already exists — singleton");

        Ok(Self {
            rd,
            _wr: wr,
            table: [None; NSIG_TABLE],
        })
    }

    /// Read-end fd for `EventLoop::add(..., Io::Read, IoWhat::Signal)`.
    #[must_use]
    pub fn read_fd(&self) -> RawFd {
        use std::os::fd::AsRawFd;
        self.rd.as_raw_fd()
    }

    /// Installs the handler for `signum` and stores `what` in the
    /// dispatch table.
    ///
    /// `sigaction()` not `signal()` — see module doc. `SA_RESTART`
    /// so syscalls auto-retry on EINTR (the C gets this implicitly
    /// from glibc/BSD `signal()` semantics).
    ///
    /// # Errors
    /// Returns the underlying I/O error if `sigaction` fails.
    ///
    /// # Panics
    /// If `signum >= 32` (real-time signals; tincd doesn't use them).
    pub fn add(&mut self, signum: i32, what: W) -> io::Result<()> {
        let idx = usize::try_from(signum).expect("signum negative");
        assert!(idx < NSIG_TABLE, "signum {signum} >= {NSIG_TABLE}");

        // sigaction with SA_RESTART. sa_mask empty (don't block
        // anything during the handler — it's just a write()).
        // SAFETY: libc::sigaction is the standard syscall wrapper.
        // `act` is fully initialized (zeroed sigset_t is the empty
        // set; sa_sigaction is set; sa_flags is set). `old` we
        // don't care about (NULL).
        #[allow(unsafe_code)]
        unsafe {
            let mut act: libc::sigaction = std::mem::zeroed();
            // sighandler_t is `usize` on Linux/BSD (it's the type of
            // the `sa_handler` union variant that takes a fn ptr).
            // fn-item → usize is the rustc lint `function_casts_as_
            // integer`; the *const () intermediary states the intent.
            act.sa_sigaction = handler as *const () as libc::sighandler_t;
            act.sa_flags = libc::SA_RESTART;
            if libc::sigaction(signum, &raw const act, std::ptr::null_mut()) < 0 {
                return Err(io::Error::last_os_error());
            }
        }

        self.table[idx] = Some(what);
        Ok(())
    }

    /// Called when `turn()` reports the pipe readable. Reads ALL
    /// pending bytes
    /// (signals can coalesce in the pipe) and pushes their `what`s
    /// into `out`.
    ///
    /// The C reads ONE byte per call (`read(pipefd[0], &signum, 1)`
    /// at `:46`). The pipe is level-triggered, so if there are 3
    /// pending bytes, epoll wakes 3 times. That works but is silly.
    /// We drain in a loop with `O_NONBLOCK` on the read end —
    /// actually wait, we didn't set `O_NONBLOCK` on the read end.
    /// `pipe2(O_CLOEXEC)` doesn't set it. We need `O_NONBLOCK` so the
    /// drain loop terminates with EAGAIN instead of blocking.
    ///
    /// Fix: set `O_NONBLOCK` in `new()`. Or: read exactly as many bytes
    /// as fit in a buffer, once. The pipe has at most NSIG bytes
    /// pending (signals don't queue per-signum without `SA_SIGINFO`).
    /// One read of a 64-byte buffer drains everything.
    pub fn drain(&self, out: &mut Vec<W>) {
        let mut buf = [0u8; 64];
        // SAFETY: read(2) on a valid fd. buf is 64 bytes; we ask
        // for 64. read returns how many it actually gave us (>=0)
        // or -1 on error.
        #[allow(unsafe_code)]
        let n = unsafe {
            use std::os::fd::AsRawFd;
            libc::read(self.rd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len())
        };
        // n < 0: error (shouldn't happen — pipe is valid, was
        // reported readable). n == 0: EOF (write end closed —
        // daemon is dying). n > 0: that many signums.
        if n <= 0 {
            return;
        }
        #[allow(clippy::cast_sign_loss)] // n > 0 checked above
        let n = n as usize;
        for &signum in &buf[..n] {
            let idx = signum as usize;
            // Unknown signum (table[idx] is None) — silently skipped.
            // Can happen if a signal
            // was del'd between handler write and drain read.
            if let Some(what) = self.table.get(idx).copied().flatten() {
                out.push(what);
            }
        }
    }

    /// Restores `SIG_DFL`, clears the table entry.
    ///
    /// Idempotent. C checks `!sig->cb` at `:84`.
    pub fn del(&mut self, signum: i32) {
        let Ok(idx) = usize::try_from(signum) else {
            return;
        };
        let Some(slot) = self.table.get_mut(idx) else {
            return;
        };
        if slot.is_none() {
            return; // already del'd / never added
        }
        // SAFETY: same as `add` — sigaction with SIG_DFL.
        #[allow(unsafe_code)]
        unsafe {
            let mut act: libc::sigaction = std::mem::zeroed();
            act.sa_sigaction = libc::SIG_DFL;
            // No SA_RESTART here — SIG_DFL doesn't return.
            let _ = libc::sigaction(signum, &raw const act, std::ptr::null_mut());
        }
        *slot = None;
    }
}

impl<W> Drop for SelfPipe<W> {
    fn drop(&mut self) {
        // Reset PIPE_WR so a fresh SelfPipe can be created (tests
        // need this; the daemon doesn't — it's a singleton for the
        // process lifetime).
        PIPE_WR.store(-1, Ordering::Relaxed);
        // OwnedFd drops close the pipe fds. Any installed handlers
        // are still installed — calling drop without calling del
        // first means a future signal will write() to a closed fd
        // (EBADF, ignored). That's a caller bug. We could iterate
        // `table` and `del` each one, but tincd's lifecycle is
        // "create at boot, never drop", so don't bother.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// `SelfPipe` is a process-global singleton (one `PIPE_WR`
    /// static, one signal handler per signum). Tests run on parallel
    /// threads. Serialize. Each test takes the lock for its full
    /// scope; `SelfPipe::drop` resets `PIPE_WR` before unlock.
    ///
    /// Poison: if a test panics holding the lock, the next test
    /// would get `PoisonError`. We `unwrap()` — panic propagates,
    /// the suite fails, that's correct.
    static SERIAL: Mutex<()> = Mutex::new(());

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Sig {
        Reload,
        Exit,
    }

    /// Can't easily test the actual signal delivery without a
    /// subprocess (sending SIGTERM to the test process is rude).
    /// What we CAN test: the pipe mechanics. Write a byte to the
    /// pipe directly (bypassing the handler), drain reads it.
    ///
    /// This proves the table dispatch and the read-loop work. The
    /// handler itself is 3 lines of obviously-correct code (atomic
    /// load + write); the integration test (daemon sends SIGHUP to
    /// itself) is the proof for that.
    #[test]
    fn drain_dispatches_from_table() {
        let _g = SERIAL.lock().unwrap();
        let mut sp: SelfPipe<Sig> = SelfPipe::new().unwrap();
        // Don't actually install handlers — populate table directly.
        // Tests run in parallel; installing SIGHUP/TERM handlers is
        // process-global and races. The handler installation IS
        // tested, but in the integration suite.
        sp.table[libc::SIGHUP as usize] = Some(Sig::Reload);
        sp.table[libc::SIGTERM as usize] = Some(Sig::Exit);

        // Write signums to the pipe directly. This is what the
        // handler does, minus the atomic load.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let bytes = [libc::SIGHUP as u8, libc::SIGTERM as u8, libc::SIGHUP as u8];
        let wr_fd = PIPE_WR.load(Ordering::Relaxed);
        assert!(wr_fd >= 0, "new() set PIPE_WR");
        #[allow(unsafe_code)]
        let n = unsafe { libc::write(wr_fd, bytes.as_ptr().cast(), bytes.len()) };
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

        let wr_fd = PIPE_WR.load(Ordering::Relaxed);
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let byte = [libc::SIGUSR1 as u8];
        #[allow(unsafe_code)]
        let n = unsafe { libc::write(wr_fd, byte.as_ptr().cast(), 1) };
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

    /// Table size. SIGHUP=1, SIGINT=2, SIGALRM=14, SIGTERM=15. All
    /// fit in 32.
    #[test]
    fn tincd_signals_fit() {
        // The 4 signals tincd.c registers. All are small positive
        // ints (POSIX guarantees SIGHUP=1, SIGINT=2, SIGTERM=15;
        // SIGALRM is 14 on Linux/BSD). The cast is safe because we
        // check `> 0` first — but clippy can't see across asserts,
        // so try_from.
        for &s in &[libc::SIGHUP, libc::SIGINT, libc::SIGALRM, libc::SIGTERM] {
            let idx = usize::try_from(s).expect("signum positive");
            assert!(
                idx < NSIG_TABLE,
                "signal {s} doesn't fit in {NSIG_TABLE}-entry table"
            );
            // And fits in u8 (the pipe protocol).
            assert!(idx < 256);
        }
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
        sp.table[libc::SIGHUP as usize] = Some(Sig::Reload);

        let wr_fd = PIPE_WR.load(Ordering::Relaxed);
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let byte = [libc::SIGHUP as u8];
        #[allow(unsafe_code)]
        unsafe {
            libc::write(wr_fd, byte.as_ptr().cast(), 1);
        }

        let mut out = Vec::new();
        sp.drain(&mut out);
        assert_eq!(out, vec![Sig::Reload]);

        // Second drain — pipe is empty, would block. We can't call
        // it. The test for "doesn't over-read" is implicit: out has
        // exactly 1 element, not 64 (the buffer size).
    }
}
