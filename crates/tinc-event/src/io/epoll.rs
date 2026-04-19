//! Epoll syscall surface via `nix::sys::epoll`. The shared slab +
//! dispatch lives in `mod.rs`; this is just the platform layer so a
//! future `kqueue.rs` can slot in.
//!
//! We don't register `EPOLLPRI`/`EPOLLRDHUP`/oneshot — peer-close is
//! detected via `read() → 0`, same as C tinc.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};
use std::time::Duration;

#[allow(deprecated)] // epoll_ctl(RawFd) — see `epoll_ctl_raw` below.
use nix::sys::epoll::epoll_ctl;
use nix::sys::epoll::{Epoll, EpollCreateFlags, EpollEvent, EpollFlags, EpollOp, EpollTimeout};

pub(super) type RawEvent = EpollEvent;
pub(super) type Poller = Epoll;

#[inline]
pub(super) fn empty_event() -> RawEvent {
    EpollEvent::empty()
}

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

pub(super) fn add(ep: &Poller, fd: BorrowedFd<'_>, token: usize, i: super::Io) -> io::Result<()> {
    let ev = EpollEvent::new(interest_to_flags(i), token as u64);
    Ok(ep.add(fd, ev)?)
}

/// `epoll_ctl(MOD/DEL)` taking `RawFd` directly.
///
/// nix's `Epoll::modify`/`delete` want `impl AsFd`, but the loop
/// stores fds non-owningly (see module doc) and only the caller can
/// vouch for liveness. Forging a `BorrowedFd` here would assert an
/// open-for-'a invariant the loop cannot guarantee — if the caller
/// closed the fd first, that is the *caller's* bug (the EBADF
/// tripwire in `EventLoop::del` catches it), not a soundness hole
/// in this crate. So use nix's deprecated free-function `epoll_ctl`,
/// which still takes `RawFd` and keeps the `unsafe` inside nix.
#[allow(deprecated)]
fn epoll_ctl_raw(
    ep: &Poller,
    op: EpollOp,
    fd: RawFd,
    ev: Option<&mut EpollEvent>,
) -> io::Result<()> {
    Ok(epoll_ctl(ep.0.as_raw_fd(), op, fd, ev)?)
}

pub(super) fn modify(ep: &Poller, fd: RawFd, token: usize, i: super::Io) -> io::Result<()> {
    let mut ev = EpollEvent::new(interest_to_flags(i), token as u64);
    epoll_ctl_raw(ep, EpollOp::EpollCtlMod, fd, Some(&mut ev))
}

pub(super) fn del(ep: &Poller, fd: RawFd) -> io::Result<()> {
    epoll_ctl_raw(ep, EpollOp::EpollCtlDel, fd, None)
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
