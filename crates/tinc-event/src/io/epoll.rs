//! Epoll syscall surface via `nix::sys::epoll`. The shared slab +
//! dispatch lives in `mod.rs`; this is just the platform layer so a
//! future `kqueue.rs` can slot in.
//!
//! We don't register `EPOLLPRI`/`EPOLLRDHUP`/oneshot — peer-close is
//! detected via `read() → 0`, same as C tinc.

use std::io;
use std::os::fd::{BorrowedFd, RawFd};
use std::time::Duration;

use nix::sys::epoll::{Epoll, EpollCreateFlags, EpollEvent, EpollFlags, EpollTimeout};

pub(super) type RawEvent = EpollEvent;
pub(super) type Poller = Epoll;

const FLAGS_BASE: EpollFlags = EpollFlags::empty(); // level-triggered, matches src/linux/event.c:97

pub(super) fn create() -> io::Result<Poller> {
    Ok(Epoll::new(EpollCreateFlags::EPOLL_CLOEXEC)?)
}

fn interest_to_flags(i: super::Io) -> EpollFlags {
    FLAGS_BASE
        | match i {
            super::Io::Read => EpollFlags::EPOLLIN,
            super::Io::Write => EpollFlags::EPOLLOUT,
            super::Io::ReadWrite => EpollFlags::EPOLLIN | EpollFlags::EPOLLOUT,
        }
}

/// Borrow a `RawFd` for the duration of an `epoll_ctl` call.
///
/// The event loop stores `RawFd` per slot by design (see `mod.rs`
/// module doc "The loop doesn't own fds") — the fds belong to
/// `connection_t` etc. nix's `Epoll` methods want `AsFd`, so we wrap
/// at this boundary. The caller contract is: `fd` is open for the
/// duration of this call (`mod.rs` only ever passes fds it was just
/// handed via `add`/`set`, or that it's deregistering in `del`).
#[inline]
fn borrow(fd: RawFd) -> BorrowedFd<'static> {
    // SAFETY: caller contract above. nix only uses the fd for one
    // `epoll_ctl` syscall and does not retain it.
    #[allow(unsafe_code)]
    unsafe {
        BorrowedFd::borrow_raw(fd)
    }
}

pub(super) fn add(ep: &Poller, fd: RawFd, token: usize, i: super::Io) -> io::Result<()> {
    let ev = EpollEvent::new(interest_to_flags(i), token as u64);
    Ok(ep.add(borrow(fd), ev)?)
}

pub(super) fn modify(ep: &Poller, fd: RawFd, token: usize, i: super::Io) -> io::Result<()> {
    let mut ev = EpollEvent::new(interest_to_flags(i), token as u64);
    Ok(ep.modify(borrow(fd), &mut ev)?)
}

pub(super) fn del(ep: &Poller, fd: RawFd) -> io::Result<()> {
    // nix passes NULL for DEL; kernel ≥2.6.9 ignores it. We don't
    // support pre-2.6.9 kernels (no epoll_create1 there anyway).
    Ok(ep.delete(borrow(fd))?)
}

pub(super) fn wait(
    ep: &Poller,
    events: &mut [RawEvent],
    timeout: Option<Duration>,
) -> io::Result<usize> {
    // Clamp to i32 range. Our timer wheel caps at ~pingtimeout so
    // this never triggers in practice, but saturating is free.
    let to = timeout.map_or(EpollTimeout::NONE, |d| {
        EpollTimeout::try_from(d).unwrap_or(EpollTimeout::MAX)
    });
    Ok(ep.wait(events, to)?)
}

// Event accessors. Only EPOLLIN/EPOLLOUT — see module doc.

#[inline]
#[allow(clippy::cast_possible_truncation)] // tokens are slot indices, fit usize on any platform
pub(super) fn ev_token(e: &RawEvent) -> usize {
    e.data() as usize
}

#[inline]
pub(super) fn ev_readable(e: &RawEvent) -> bool {
    e.events().contains(EpollFlags::EPOLLIN)
}

#[inline]
pub(super) fn ev_writable(e: &RawEvent) -> bool {
    e.events().contains(EpollFlags::EPOLLOUT)
}
