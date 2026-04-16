//! Platform compatibility shims for Linux-specific APIs.

use nix::sys::socket::SockFlag;

/// `SOCK_CLOEXEC` on Linux, empty on macOS (caller should
/// `fcntl(FD_CLOEXEC)` separately if needed, but for
/// short-lived sockets it's acceptable to skip).
#[inline]
pub fn sock_cloexec_flag() -> SockFlag {
    #[cfg(target_os = "linux")]
    {
        SockFlag::SOCK_CLOEXEC
    }
    #[cfg(not(target_os = "linux"))]
    {
        SockFlag::empty()
    }
}

/// Set `SO_NOSIGPIPE` on macOS so `send()` returns `EPIPE` instead
/// of raising `SIGPIPE` on broken TCP connections. Linux uses
/// `MSG_NOSIGNAL` per-send instead.
#[cfg(not(target_os = "linux"))]
pub fn set_nosigpipe(fd: std::os::fd::RawFd) {
    // nix 0.29 doesn't wrap SO_NOSIGPIPE; use raw libc.
    let val: libc::c_int = 1;
    #[allow(unsafe_code)]
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_NOSIGPIPE,
            std::ptr::from_ref(&val).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

#[cfg(target_os = "linux")]
#[inline]
pub fn set_nosigpipe(_fd: std::os::fd::RawFd) {}

/// Set `FD_CLOEXEC` via `fcntl`. Use after socket/socketpair on
/// platforms without `SOCK_CLOEXEC`.
#[cfg(not(target_os = "linux"))]
pub fn set_cloexec(fd: impl std::os::fd::AsFd) {
    use nix::fcntl::{FdFlag, fcntl, FcntlArg};
    let _ = fcntl(fd, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC));
}

#[cfg(target_os = "linux")]
#[inline]
pub fn set_cloexec(_fd: impl std::os::fd::AsFd) {}

/// `MSG_NOSIGNAL` on Linux, empty on macOS (macOS uses
/// `SO_NOSIGPIPE` on the socket instead).
#[inline]
pub fn msg_nosignal() -> nix::sys::socket::MsgFlags {
    #[cfg(target_os = "linux")]
    {
        nix::sys::socket::MsgFlags::MSG_NOSIGNAL
    }
    #[cfg(not(target_os = "linux"))]
    {
        nix::sys::socket::MsgFlags::empty()
    }
}
