//! Kqueue syscall surface via `nix::sys::event`. The shared slab +
//! dispatch lives in `mod.rs`; this is just the platform layer so it
//! slots in alongside `epoll.rs`.
//!
//! Uses `EV_CLEAR` (edge-triggered) for performance — the kernel
//! skips re-checking readiness each `kevent()` call. The tinc event
//! loop fully drains ready fds each turn, so edge-triggered is safe.
//!
//! kqueue uses separate filter registrations for READ and WRITE
//! (unlike epoll's single interest mask). `add`/`modify` register
//! both filters with `EV_ADD` for the wanted ones and `EV_DELETE`
//! for the unwanted ones. `del` deletes both.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};
use std::time::Duration;

use nix::sys::event::{EvFlags, EventFilter, FilterFlag, KEvent, Kqueue};
use nix::sys::time::TimeSpec;

/// The kqueue fd.
pub(super) type Poller = Kqueue;
pub(super) type RawEvent = KEvent;

/// Zero-init for the events array.
#[inline]
pub(super) fn empty_event() -> RawEvent {
    KEvent::new(
        0,
        EventFilter::EVFILT_READ,
        EvFlags::empty(),
        FilterFlag::empty(),
        0,
        0,
    )
}

pub(super) fn create() -> io::Result<Poller> {
    Kqueue::new().map_err(Into::into)
}

/// fd → kevent ident. fds are non-negative; the kqueue ABI takes
/// `uintptr_t` (nix exposes it as `usize`).
#[inline]
#[expect(clippy::cast_sign_loss)]
fn fd_ident(fd: RawFd) -> usize {
    fd as usize
}

/// token → kevent udata. nix wraps `udata` as `isize`; tokens are
/// slab indices well under `isize::MAX`.
#[inline]
fn token_udata(token: usize) -> isize {
    token.cast_signed()
}

/// Shorthand `KEvent` constructor — the only fields that vary across
/// our changelists are filter and flags.
#[inline]
fn kev(fd: RawFd, filter: EventFilter, flags: EvFlags, token: usize) -> KEvent {
    KEvent::new(
        fd_ident(fd),
        filter,
        flags,
        FilterFlag::empty(),
        0,
        token_udata(token),
    )
}

/// Build a READ+WRITE changelist for `i`. Wanted filters get
/// `EV_ADD | EV_CLEAR`; unwanted get `EV_DELETE` when
/// `delete_unwanted`, else they're packed at the tail and the
/// returned `n` excludes them (so `add()` never submits an
/// `EV_DELETE` for a filter that was never registered — kqueue would
/// ENOENT).
fn changes(fd: RawFd, token: usize, i: super::Io, delete_unwanted: bool) -> ([KEvent; 2], usize) {
    const ADD: EvFlags = EvFlags::EV_ADD.union(EvFlags::EV_CLEAR);
    let want_read = matches!(i, super::Io::Read | super::Io::ReadWrite);
    let want_write = matches!(i, super::Io::Write | super::Io::ReadWrite);
    let flag = |w| if w { ADD } else { EvFlags::EV_DELETE };
    let read_ev = kev(fd, EventFilter::EVFILT_READ, flag(want_read), token);
    let write_ev = kev(fd, EventFilter::EVFILT_WRITE, flag(want_write), token);
    if delete_unwanted {
        ([read_ev, write_ev], 2)
    } else {
        // Wanted first; n counts only wanted.
        match i {
            super::Io::Read => ([read_ev, write_ev], 1),
            super::Io::Write => ([write_ev, read_ev], 1),
            super::Io::ReadWrite => ([read_ev, write_ev], 2),
        }
    }
}

pub(super) fn add(kq: &Poller, fd: BorrowedFd<'_>, token: usize, i: super::Io) -> io::Result<()> {
    let (ch, n) = changes(fd.as_raw_fd(), token, i, false);
    kq.kevent(&ch[..n], &mut [], None)
        .map(|_| ())
        .map_err(Into::into)
}

pub(super) fn modify(kq: &Poller, fd: RawFd, token: usize, i: super::Io) -> io::Result<()> {
    // kqueue: EV_ADD on an existing filter replaces it (no EEXIST).
    // EV_DELETE on a non-existing filter returns ENOENT — tolerate it
    // by submitting changes one at a time.
    let (ch, n) = changes(fd, token, i, true);
    for ch in &ch[..n] {
        match kq.kevent(std::slice::from_ref(ch), &mut [], None) {
            Ok(_) | Err(nix::errno::Errno::ENOENT) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

pub(super) fn del(kq: &Poller, fd: RawFd) -> io::Result<()> {
    let changes = [
        kev(fd, EventFilter::EVFILT_READ, EvFlags::EV_DELETE, 0),
        kev(fd, EventFilter::EVFILT_WRITE, EvFlags::EV_DELETE, 0),
    ];
    // Ignore ENOENT — filter might not have been registered.
    match kq.kevent(&changes, &mut [], None) {
        Ok(_) | Err(nix::errno::Errno::ENOENT) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

pub(super) fn wait(
    kq: &Poller,
    events: &mut [RawEvent],
    timeout: Option<Duration>,
) -> io::Result<usize> {
    // `Kqueue::kevent` takes nix's `timespec` re-export; build via
    // `TimeSpec` so the field types/widths stay nix's problem.
    let ts = timeout.map(|d| *TimeSpec::from_duration(d).as_ref());
    kq.kevent(&[], events, ts).map_err(Into::into)
}

// Event accessors.

#[inline]
pub(super) fn ev_token(e: &RawEvent) -> usize {
    e.udata().cast_unsigned()
}

#[inline]
pub(super) fn ev_readable(e: &RawEvent) -> bool {
    matches!(e.filter(), Ok(EventFilter::EVFILT_READ))
}

#[inline]
pub(super) fn ev_writable(e: &RawEvent) -> bool {
    matches!(e.filter(), Ok(EventFilter::EVFILT_WRITE))
}
