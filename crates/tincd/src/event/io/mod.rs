//! I/O readiness loop. Ports `linux/event.c` (`io_add`/`_set`/`_del`/
//! `event_loop`) and the per-platform splay-tree bookkeeping.
//!
//! The platform syscall surface lives in `epoll.rs` (and a future
//! `kqueue.rs`). The `OwnedFd` is the `epollset` static; the slot
//! index is `epoll_event.data.u64`.
//!
//! # The loop doesn't own fds
//!
//! `linux/event.c` does `epoll_ctl(epollset, ..., io->fd, ...)` — the
//! event loop never owns fds. The `connection_t` does, via
//! `c->socket`. The loop just tells the kernel "wake me when this fd
//! is readable."
//!
//! This means `EventLoop` stores `RawFd` per slot (so it can
//! reregister/deregister later), but doesn't `close()` on drop.
//! Closing is the `connection_t` equivalent's job.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};
use std::time::Duration;

#[cfg(target_os = "linux")]
mod epoll;
#[cfg(target_os = "linux")]
use epoll::{
    Poller, RawEvent, add, create, del, empty_event, ev_readable, ev_token, ev_writable, modify,
    wait,
};

#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]
mod kqueue;
#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]
use kqueue::{
    Poller, RawEvent, add, create, del, empty_event, ev_readable, ev_token, ev_writable, modify,
    wait,
};

use crate::event::MAX_EVENTS_PER_TURN;

/// Read/write interest. Ports `IO_READ`/`IO_WRITE` from `event.h`.
/// No zero-interest state — the daemon only ever toggles between
/// `Read` and `ReadWrite`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Io {
    Read,
    // tincd registers `Read` or `ReadWrite`; bare `Write` exists for
    // symmetry in `wants()` and the backend match arms. Tests cover it.
    #[allow(dead_code)]
    Write,
    ReadWrite,
}

impl Io {
    /// Does this interest include the given readiness? The
    /// generation-guard substitute — see `dispatch` below.
    const fn wants(self, ready: Ready) -> bool {
        matches!(
            (self, ready),
            (Self::Read | Self::ReadWrite, Ready::Read)
                | (Self::Write | Self::ReadWrite, Ready::Write)
        )
    }
}

/// What kind of readiness fired. The `IO_READ`/`IO_WRITE` arg passed
/// to the callback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ready {
    Read,
    Write,
}

/// Opaque io handle. The epoll token (`epoll_event.u64`) IS this
/// (same `usize`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct IoId(usize);

struct Slot<W> {
    // non-owning: the EventLoop never closes registered fds (see
    // module doc "The loop doesn't own fds"). Kept only as the
    // epoll_ctl key for later MOD/DEL.
    fd: RawFd,
    interest: Io,
    what: W,
}

/// The event loop. Owns the epoll fd, the events buffer, and the
/// slot slab. Does NOT own fds.
///
/// Generic over `W: Copy` — the daemon's `enum IoWhat`. See lib.rs.
pub(crate) struct EventLoop<W> {
    ep: Poller,
    events: Box<[RawEvent; MAX_EVENTS_PER_TURN]>,
    /// Hand-rolled slab; `None` = freed. The epoll token indexes this
    /// directly so `get(token).is_none()` is the cheap stale check.
    slots: Vec<Option<Slot<W>>>,
    free: Vec<usize>,
    /// Count of `Some` entries in `slots`. Test-only invariant
    /// accounting (slot leak / double-free detection).
    live: usize,
}

impl<W: Copy> EventLoop<W> {
    /// Create the poll instance + `Events` buffer.
    ///
    /// # Errors
    /// Returns the underlying I/O error if epoll/kqueue creation fails.
    pub(crate) fn new() -> io::Result<Self> {
        Ok(Self {
            ep: create()?,
            events: Box::new([empty_event(); MAX_EVENTS_PER_TURN]),
            slots: Vec::new(),
            free: Vec::new(),
            live: 0,
        })
    }

    /// Register an fd. The loop stores the raw fd only as a
    /// reregister/deregister key — it never closes it (see module
    /// doc).
    ///
    /// # Errors
    /// Propagates `epoll_ctl(ADD)` failures — `EEXIST` if the fd is
    /// already registered (caller bug), `EBADF`/`ENOMEM` from the
    /// kernel.
    pub(crate) fn add(&mut self, fd: BorrowedFd<'_>, interest: Io, what: W) -> io::Result<IoId> {
        let raw = fd.as_raw_fd();
        let idx = self.free.pop().unwrap_or_else(|| {
            self.slots.push(None);
            self.slots.len() - 1
        });
        // Register first so a kernel reject (EEXIST/EBADF) leaves
        // the slot None and the index goes back to the freelist.
        if let Err(e) = add(&self.ep, fd, idx, interest) {
            self.free.push(idx);
            return Err(e);
        }
        self.slots[idx] = Some(Slot {
            fd: raw,
            interest,
            what,
        });
        self.live += 1;
        Ok(IoId(idx))
    }

    /// Change interest on an already-registered fd. No-op if
    /// unchanged — skips the `epoll_ctl(MOD)` syscall.
    ///
    /// # Errors
    /// Propagates `epoll_ctl(MOD)` failures.
    ///
    /// # Panics
    /// If `id` is dangling. C dereferences caller-owned `io_t*` —
    /// would be UAF.
    pub(crate) fn set(&mut self, id: IoId, interest: Io) -> io::Result<()> {
        let slot = self.slots[id.0].as_mut().expect("dangling IoId");
        if slot.interest == interest {
            return Ok(());
        }
        modify(&self.ep, slot.fd, id.0, interest)?;
        slot.interest = interest;
        Ok(())
    }

    /// Deregister and free the slot. Idempotent. Deregister errors
    /// are swallowed: `ENOENT` is normal (closing an fd auto-removes
    /// it from epoll); `EBADF` is tripwired in debug below.
    pub(crate) fn del(&mut self, id: IoId) {
        let Some(slot) = self.slots.get_mut(id.0).and_then(Option::take) else {
            return; // already del'd
        };
        // Best-effort. ENOENT is fine (fd closed → kernel auto-
        // removed). EBADF is NOT: caller closed BEFORE ev.del();
        // a surviving dup would busy-loop ERR|HUP into a freed
        // slot. Tripwire in debug.
        if let Err(e) = del(&self.ep, slot.fd) {
            debug_assert_ne!(
                e.raw_os_error(),
                Some(nix::Error::EBADF as i32),
                "ev.del(fd={}) after fd closed — deregister BEFORE drop",
                slot.fd
            );
        }
        self.free.push(id.0);
        self.live -= 1;
    }

    /// ONE iteration of the event loop. The `while(running)` outer
    /// loop is the daemon's job.
    ///
    /// Blocks for at most `timeout` (or forever if `None`). Drains
    /// readiness into `out` as `(what, ready)` pairs. The daemon's
    /// loop matches on `what`.
    ///
    /// `Ok(())` even if no events fired (timeout expired).
    ///
    /// # The generation-guard substitute
    ///
    /// Generation tracking: instead of bailing the whole dispatch
    /// loop when a cb removes/alters another slot, we check per-event:
    /// `slots.get(token)` returns `None` if removed; `interest.wants
    /// (ready)` is false if reregistered to a non-overlapping
    /// interest. Stale events are dropped silently. Level-triggered:
    /// anything still actually ready re-fires next turn.
    ///
    /// This processes more events per wake than C (C bails at first
    /// change; we keep going). That's correct: the C bail is
    /// conservative because it can't tell WHICH slot changed.
    ///
    /// `out` is borrowed not returned — same hot-loop reasoning as
    /// `Timers::tick`.
    ///
    /// # WRITE before READ
    ///
    /// WRITE is dispatched before READ. The reason: the meta
    /// connection's WRITE cb can drain the outbuf and call
    /// `io_set(READ)`, which means the READ that follows is for a slot
    /// that just changed. C's generation bail handles that. We check
    /// `interest.wants` between WRITE and READ dispatch for the same
    /// slot. Same effect.
    ///
    /// # Errors
    /// Returns the underlying I/O error from `epoll_wait` / `kqueue`.
    /// `EINTR` is *not* an error — it returns `Ok(())` with `out`
    /// empty so the caller's `while running` loop re-checks its flag.
    pub(crate) fn turn(
        &mut self,
        timeout: Option<Duration>,
        out: &mut Vec<(W, Ready)>,
    ) -> io::Result<()> {
        out.clear();

        // EINTR: `SA_RESTART` does NOT auto-retry epoll_wait (man 7
        // signal "never restart" list), so every signal during the
        // wait surfaces here. Return `Ok` empty rather than looping
        // so the caller re-ticks timers before re-polling — the
        // self-pipe byte is readable next turn.
        let n_events = match wait(&self.ep, &mut self.events[..], timeout) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                return Ok(());
            }
            Err(e) => return Err(e),
        };

        for ev in &self.events[..n_events] {
            let idx = ev_token(ev);
            // Generation-guard substitute, part 1: slot still exists.
            let Some(slot) = self.slots.get(idx).and_then(Option::as_ref) else {
                continue; // del'd by an earlier event in this batch
            };
            let what = slot.what;
            let interest = slot.interest;

            // WRITE first. Part 2: interest still includes WRITE.
            if ev_writable(ev) && interest.wants(Ready::Write) {
                out.push((what, Ready::Write));
            }

            // No re-lookup of interest between WRITE and READ: we
            // collect into `out`, not fire inline, so nothing could
            // have changed it yet.
            if ev_readable(ev) && interest.wants(Ready::Read) {
                out.push((what, Ready::Read));
            }
        }
        Ok(())
    }

    /// Look up the `what` for an id. `None` if dangling.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn what(&self, id: IoId) -> Option<W> {
        self.slots.get(id.0)?.as_ref().map(|s| s.what)
    }

    /// Number of live slots.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.live
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::fd::AsFd;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum What {
        Device,
        Conn(u32),
    }

    /// `pipe()` pair — read end registered for READABLE.
    fn mkpipe() -> (std::fs::File, std::fs::File) {
        let (r, w) = nix::unistd::pipe().expect("pipe()");
        (std::fs::File::from(r), std::fs::File::from(w))
    }

    /// `io_add` + `event_loop` happy path. Write to pipe, `turn()`
    /// reports READ on the read end.
    #[test]
    fn add_and_turn_reads() {
        let mut ev = EventLoop::new().unwrap();
        let (rd, mut wr) = mkpipe();
        let id = ev.add(rd.as_fd(), Io::Read, What::Device).unwrap();

        // Nothing ready yet — short timeout, expect empty.
        let mut out = Vec::new();
        ev.turn(Some(Duration::from_millis(1)), &mut out).unwrap();
        assert!(out.is_empty());

        // Write a byte. Now the read end is readable.
        wr.write_all(b"x").unwrap();
        ev.turn(Some(Duration::from_millis(100)), &mut out).unwrap();
        assert_eq!(out, vec![(What::Device, Ready::Read)]);

        // Drain it. The id is what we got.
        assert_eq!(ev.what(id), Some(What::Device));
        // Deregister BEFORE close — the order the EBADF tripwire in
        // `del()` enforces.
        ev.del(id);
        drop((rd, wr));
    }

    /// `io_set` with same flags is a no-op (no error, slot unchanged).
    #[test]
    fn set_same_interest_noop() {
        let mut ev = EventLoop::new().unwrap();
        let (rd, _wr) = mkpipe();
        let id = ev.add(rd.as_fd(), Io::Read, What::Device).unwrap();

        // Same interest, repeatedly.
        ev.set(id, Io::Read).unwrap();
        ev.set(id, Io::Read).unwrap();

        // Slot unchanged.
        let slot = ev.slots[id.0].as_ref().unwrap();
        assert_eq!(slot.interest, Io::Read);
        ev.del(id);
    }

    /// The READ ↔︎ READ|WRITE dance. Adding WRITE interest, getting
    /// WRITE readiness, then
    /// dropping WRITE interest, NOT getting WRITE readiness anymore.
    #[test]
    fn set_changes_interest() {
        let mut ev = EventLoop::new().unwrap();
        let (rd, wr) = mkpipe();
        // Register the WRITE end for WRITE interest. Pipes are
        // immediately writable (until the buffer fills).
        let id = ev.add(wr.as_fd(), Io::Write, What::Conn(1)).unwrap();

        let mut out = Vec::new();
        ev.turn(Some(Duration::from_millis(100)), &mut out).unwrap();
        assert_eq!(out, vec![(What::Conn(1), Ready::Write)]);

        // Switch to READ only. The write end of a pipe is never
        // readable; turn() should report nothing.
        ev.set(id, Io::Read).unwrap();
        out.clear();
        ev.turn(Some(Duration::from_millis(10)), &mut out).unwrap();
        assert!(out.is_empty(), "got stale WRITE after reregister to READ");

        drop(rd);
        // del BEFORE wr drops to avoid the EBADF tripwire.
        ev.del(id);
        drop(wr);
    }

    /// del is idempotent.
    #[test]
    fn del_idempotent() {
        let mut ev = EventLoop::new().unwrap();
        let (rd, _wr) = mkpipe();
        let id = ev.add(rd.as_fd(), Io::Read, What::Device).unwrap();
        assert_eq!(ev.len(), 1);

        ev.del(id);
        assert_eq!(ev.len(), 0);
        ev.del(id); // second del — no panic
        assert_eq!(ev.len(), 0);
    }

    /// del'd slot's `what()` returns None; `turn()` doesn't crash on
    /// a freed slot. (The full mid-batch stale-token scenario isn't
    /// reproducible without a daemon bug; the slab guard covers it.)
    #[test]
    fn del_makes_what_none() {
        let mut ev = EventLoop::new().unwrap();
        let (rd, _wr) = mkpipe();
        let id = ev.add(rd.as_fd(), Io::Read, What::Device).unwrap();
        assert_eq!(ev.what(id), Some(What::Device));
        ev.del(id);
        assert_eq!(ev.what(id), None);
    }

    /// Freelist reuse: del then add gets the same slot index. The
    /// `Token` is reused. Same as the timer freelist test.
    #[test]
    fn freelist_reuses_slot() {
        let mut ev = EventLoop::new().unwrap();
        let (rd1, _wr1) = mkpipe();
        let (rd2, _wr2) = mkpipe();

        let id1 = ev.add(rd1.as_fd(), Io::Read, What::Conn(1)).unwrap();
        ev.del(id1);
        let id2 = ev.add(rd2.as_fd(), Io::Read, What::Conn(2)).unwrap();

        assert_eq!(id1.0, id2.0, "freelist reused slot");
        // But the what is the new one.
        assert_eq!(ev.what(id2), Some(What::Conn(2)));
        ev.del(id2);
    }

    /// One fd both readable and writable → WRITE dispatched first.
    /// Socketpair, not pipe — a pipe fd is never both.
    #[test]
    fn write_before_read_same_fd() {
        let (mut a, b) = std::os::unix::net::UnixStream::pair().expect("socketpair");

        let mut ev = EventLoop::new().unwrap();
        // Register `b` for both. It's immediately writable (empty
        // sendbuf). Make it readable too by writing to `a`.
        let id = ev.add(b.as_fd(), Io::ReadWrite, What::Conn(7)).unwrap();
        a.write_all(b"hello").unwrap();

        let mut out = Vec::new();
        ev.turn(Some(Duration::from_millis(100)), &mut out).unwrap();

        // Both fired, WRITE first (C dispatch order).
        assert_eq!(
            out,
            vec![(What::Conn(7), Ready::Write), (What::Conn(7), Ready::Read)]
        );

        // Drain so the next turn isn't noisy.
        let mut buf = [0u8; 16];
        let n = {
            let mut bf = &b;
            bf.read(&mut buf).unwrap()
        };
        assert_eq!(&buf[..n], b"hello");

        ev.del(id);
        drop((a, b));
    }

    /// `add` failure rolls back the slot allocation. EEXIST: register
    /// the same fd twice (epoll rejects). kqueue silently replaces
    /// with `EV_ADD`, so this test is Linux-only.
    #[test]
    #[cfg(target_os = "linux")]
    fn add_failure_frees_slot() {
        let mut ev = EventLoop::new().unwrap();
        let (rd, _wr) = mkpipe();

        let id1 = ev.add(rd.as_fd(), Io::Read, What::Device).unwrap();
        assert_eq!(ev.len(), 1);

        // Same fd again — epoll EEXIST.
        let err = ev.add(rd.as_fd(), Io::Read, What::Conn(99)).unwrap_err();
        // Linux: EEXIST. Don't pin the exact errno, just that it
        // failed and didn't leak a slot.
        let _ = err;
        assert_eq!(ev.len(), 1, "failed add must not leak slot");

        ev.del(id1);
    }

    /// `Io::wants` truth table. Unit-level — no syscalls.
    #[test]
    fn io_wants_table() {
        for (io, ready, want) in [
            (Io::Read, Ready::Read, true),
            (Io::Read, Ready::Write, false),
            (Io::Write, Ready::Read, false),
            (Io::Write, Ready::Write, true),
            (Io::ReadWrite, Ready::Read, true),
            (Io::ReadWrite, Ready::Write, true),
        ] {
            assert_eq!(io.wants(ready), want, "{io:?}.wants({ready:?})");
        }
    }

    /// `out` is cleared at top of turn — caller reuses one Vec.
    #[test]
    fn turn_clears_out() {
        let mut ev: EventLoop<What> = EventLoop::new().unwrap();
        let mut out = vec![(What::Device, Ready::Read)]; // stale
        ev.turn(Some(Duration::from_millis(1)), &mut out).unwrap();
        assert!(out.is_empty());
    }
}
