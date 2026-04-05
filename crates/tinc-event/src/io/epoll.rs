//! Raw epoll syscalls. No mio. The shared slab + dispatch lives in
//! `mod.rs`; this is just the platform syscall surface so a future
//! `kqueue.rs` can slot in.
//!
//! mio used to do this for us. mio's `epoll.rs` is ~200 LOC because
//! it abstracts over flags we don't use (`EPOLLPRI`, `EPOLLRDHUP`,
//! one-shot mode). We need ~90.

use std::io;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::time::Duration;

pub(super) type RawEvent = libc::epoll_event;

// EPOLLET is i32 in libc (0x8000_0000 sign-extends); cast is the bit pattern.
#[allow(clippy::cast_sign_loss)]
const FLAGS_BASE: u32 = libc::EPOLLET as u32; // matches mio today; commit 2 drops this

pub(super) fn create() -> io::Result<OwnedFd> {
    // SAFETY: epoll_create1 returns a fresh fd or -1. No invariants
    // beyond "the kernel works".
    #[allow(unsafe_code)]
    let fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is fresh, valid, exclusively ours; OwnedFd drop
    // closes it.
    #[allow(unsafe_code)]
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn interest_to_flags(i: super::Io) -> u32 {
    FLAGS_BASE
        | match i {
            super::Io::Read => libc::EPOLLIN as u32,
            super::Io::Write => libc::EPOLLOUT as u32,
            super::Io::ReadWrite => (libc::EPOLLIN | libc::EPOLLOUT) as u32,
        }
}

pub(super) fn ctl(
    ep: RawFd,
    op: libc::c_int,
    fd: RawFd,
    token: usize,
    i: super::Io,
) -> io::Result<()> {
    let mut ev = libc::epoll_event {
        events: interest_to_flags(i),
        u64: token as u64,
    };
    // SAFETY: ep and fd are valid by caller contract (see io/mod.rs
    // — ep is `self.ep.as_raw_fd()`, fd came from `add()`); ev is a
    // local that outlives the call.
    #[allow(unsafe_code)]
    let r = unsafe { libc::epoll_ctl(ep, op, fd, &raw mut ev) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(super) fn del(ep: RawFd, fd: RawFd) -> io::Result<()> {
    // Kernel ≥2.6.9 ignores the event ptr for DEL. We pass a real
    // one anyway — older kernels NULL-deref'd. Belt-and-suspenders.
    let mut ev = libc::epoll_event { events: 0, u64: 0 };
    // SAFETY: same as ctl()
    #[allow(unsafe_code)]
    let r = unsafe { libc::epoll_ctl(ep, libc::EPOLL_CTL_DEL, fd, &raw mut ev) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(super) fn wait(
    ep: RawFd,
    events: &mut Vec<RawEvent>,
    timeout: Option<Duration>,
) -> io::Result<()> {
    // Same clamp mio does internally. Our timer wheel caps at
    // ~pingtimeout so this never triggers in practice, but
    // saturating arithmetic is free.
    #[allow(clippy::cast_possible_truncation)] // c_int::MAX = 24.8 days; we min() to it
    let ms: libc::c_int = timeout.map_or(-1, |d| {
        d.as_millis().min(libc::c_int::MAX as u128) as libc::c_int
    });
    events.clear();
    // SAFETY: events.as_mut_ptr() is valid for capacity() writes;
    // capacity is set by Vec::with_capacity in EventLoop::new and
    // never shrunk. epoll_wait fills [0..n) and returns n.
    #[allow(unsafe_code)]
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    // EVENT_CAP is 64, fits c_int
    let n = unsafe {
        libc::epoll_wait(
            ep,
            events.as_mut_ptr(),
            events.capacity() as libc::c_int,
            ms,
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: kernel wrote exactly n entries into events[0..n).
    // n ≥ 0 was just checked. n ≤ capacity by epoll_wait's contract
    // (maxevents arg).
    #[allow(unsafe_code)]
    #[allow(clippy::cast_sign_loss)] // n ≥ 0 checked above
    unsafe {
        events.set_len(n as usize);
    }
    Ok(())
}

// Event accessors. mio's Event::is_* covered EPOLLPRI/EPOLLRDHUP
// too — we never asked. Peer-close is detected via read() → 0
// (same as C).

#[inline]
#[allow(clippy::cast_possible_truncation)] // tokens are slot indices, fit usize on any platform
pub(super) fn ev_token(e: &RawEvent) -> usize {
    e.u64 as usize
}

#[inline]
pub(super) fn ev_readable(e: &RawEvent) -> bool {
    e.events & libc::EPOLLIN as u32 != 0
}

#[inline]
pub(super) fn ev_writable(e: &RawEvent) -> bool {
    e.events & libc::EPOLLOUT as u32 != 0
}
