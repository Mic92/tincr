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
