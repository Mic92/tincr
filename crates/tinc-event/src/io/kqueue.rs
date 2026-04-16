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
use std::os::fd::{AsRawFd, BorrowedFd};
use std::time::Duration;

use nix::sys::event::{EventFilter, EventFlag, FilterFlag, KEvent, Kqueue};

/// The kqueue fd.
pub(super) type Poller = Kqueue;

/// Wrapper around `KEvent` so we can add an `empty()` constructor.
/// `repr(transparent)` so the array layout is identical.
#[repr(transparent)]
#[derive(Clone, Copy, Debug)]
pub(super) struct RawEvent(KEvent);

impl RawEvent {
    /// Zero-init for the events array.
    #[inline]
    pub(super) fn empty() -> Self {
        Self(KEvent::new(
            0,
            EventFilter::EVFILT_READ,
            EventFlag::empty(),
            FilterFlag::empty(),
            0,
            0,
        ))
    }
}

pub(super) fn create() -> io::Result<Poller> {
    Kqueue::new().map_err(Into::into)
}

/// Build a changelist that only ADDs wanted filters (for initial registration).
fn add_changes(fd: BorrowedFd<'_>, token: usize, i: super::Io) -> [KEvent; 2] {
    let ident = fd.as_raw_fd() as usize;
    let udata = token as isize;
    let flags = EventFlag::EV_ADD | EventFlag::EV_CLEAR;
    let read_ev = KEvent::new(ident, EventFilter::EVFILT_READ, flags, FilterFlag::empty(), 0, udata);
    let write_ev = KEvent::new(ident, EventFilter::EVFILT_WRITE, flags, FilterFlag::empty(), 0, udata);
    match i {
        super::Io::Read => [read_ev, write_ev],       // only [0] used
        super::Io::Write => [write_ev, read_ev],      // only [0] used
        super::Io::ReadWrite => [read_ev, write_ev],  // both used
    }
}

fn add_count(i: super::Io) -> usize {
    match i {
        super::Io::ReadWrite => 2,
        _ => 1,
    }
}

/// Build the changelist for modify. Wanted filters get
/// `EV_ADD | EV_CLEAR`; unwanted get `EV_DELETE`.
fn interest_changes(fd: BorrowedFd<'_>, token: usize, i: super::Io) -> [KEvent; 2] {
    let ident = fd.as_raw_fd() as usize;
    let udata = token as isize;
    let want_read = matches!(i, super::Io::Read | super::Io::ReadWrite);
    let want_write = matches!(i, super::Io::Write | super::Io::ReadWrite);

    let read_ev = KEvent::new(
        ident,
        EventFilter::EVFILT_READ,
        if want_read {
            EventFlag::EV_ADD | EventFlag::EV_CLEAR
        } else {
            EventFlag::EV_DELETE
        },
        FilterFlag::empty(),
        0,
        udata,
    );
    let write_ev = KEvent::new(
        ident,
        EventFilter::EVFILT_WRITE,
        if want_write {
            EventFlag::EV_ADD | EventFlag::EV_CLEAR
        } else {
            EventFlag::EV_DELETE
        },
        FilterFlag::empty(),
        0,
        udata,
    );
    [read_ev, write_ev]
}

pub(super) fn add(kq: &Poller, fd: BorrowedFd<'_>, token: usize, i: super::Io) -> io::Result<()> {
    // On add, only register wanted filters — don't EV_DELETE filters
    // that were never registered (kqueue returns ENOENT for that).
    let changes = add_changes(fd, token, i);
    kq.kevent(&changes[..add_count(i)], &mut [], None).map(|_| ()).map_err(Into::into)
}

pub(super) fn modify(
    kq: &Poller,
    fd: BorrowedFd<'_>,
    token: usize,
    i: super::Io,
) -> io::Result<()> {
    // kqueue: EV_ADD on an existing filter replaces it (no EEXIST).
    // EV_DELETE on a non-existing filter returns ENOENT — tolerate it
    // by submitting changes one at a time.
    let changes = interest_changes(fd, token, i);
    for ch in &changes {
        match kq.kevent(std::slice::from_ref(ch), &mut [], None) {
            Ok(_) | Err(nix::errno::Errno::ENOENT) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

pub(super) fn del(kq: &Poller, fd: BorrowedFd<'_>) -> io::Result<()> {
    let ident = fd.as_raw_fd() as usize;
    let changes = [
        KEvent::new(
            ident,
            EventFilter::EVFILT_READ,
            EventFlag::EV_DELETE,
            FilterFlag::empty(),
            0,
            0,
        ),
        KEvent::new(
            ident,
            EventFilter::EVFILT_WRITE,
            EventFlag::EV_DELETE,
            FilterFlag::empty(),
            0,
            0,
        ),
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
    let ts = timeout.map(|d| libc::timespec {
        tv_sec: d.as_secs() as libc::time_t,
        tv_nsec: d.subsec_nanos() as libc::c_long,
    });
    // SAFETY: RawEvent is repr(transparent) over KEvent.
    #[allow(unsafe_code)]
    let kevents = unsafe {
        std::slice::from_raw_parts_mut(events.as_mut_ptr().cast::<KEvent>(), events.len())
    };
    kq.kevent(&[], kevents, ts).map_err(Into::into)
}

// Event accessors.

#[inline]
pub(super) fn ev_token(e: &RawEvent) -> usize {
    e.0.udata() as usize
}

#[inline]
pub(super) fn ev_readable(e: &RawEvent) -> bool {
    matches!(e.0.filter(), Ok(EventFilter::EVFILT_READ))
}

#[inline]
pub(super) fn ev_writable(e: &RawEvent) -> bool {
    matches!(e.0.filter(), Ok(EventFilter::EVFILT_WRITE))
}
