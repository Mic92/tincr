//! Platform compatibility shims for Linux-specific APIs.
//!
//! Anything that needs `#[cfg(target_os = ...)]` around a raw
//! `libc::` call belongs here, so call sites stay cfg-free with a
//! single signature. The cfg split lives INSIDE each function body
//! (or as twin cfg-gated definitions with identical signatures).

use std::ffi::CStr;
use std::io;
use std::os::fd::{AsFd, AsRawFd};

use nix::sys::socket::SockFlag;
use socket2::Socket;

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
pub fn set_nosigpipe(fd: impl AsFd) {
    // nix 0.29 doesn't wrap SO_NOSIGPIPE; use raw libc.
    let val: libc::c_int = 1;
    #[allow(unsafe_code)]
    unsafe {
        libc::setsockopt(
            fd.as_fd().as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_NOSIGPIPE,
            std::ptr::from_ref(&val).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

#[cfg(target_os = "linux")]
#[inline]
pub fn set_nosigpipe(_fd: impl AsFd) {}

/// Set `FD_CLOEXEC` via `fcntl`. Use after socket/socketpair on
/// platforms without `SOCK_CLOEXEC`.
#[cfg(not(target_os = "linux"))]
pub fn set_cloexec(fd: impl AsFd) {
    use nix::fcntl::{FcntlArg, FdFlag, fcntl};
    let _ = fcntl(fd, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC));
}

#[cfg(target_os = "linux")]
#[inline]
pub fn set_cloexec(_fd: impl AsFd) {}

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

/// Raw `setsockopt` for `c_int`-valued options that nix 0.29 doesn't
/// wrap (`IP_MTU_DISCOVER`/`IPV6_MTU_DISCOVER`, `IP_BOUND_IF`, …).
/// Single unsafe site shared by the platform shims below.
pub fn set_int_sockopt(
    fd: impl AsFd,
    level: libc::c_int,
    optname: libc::c_int,
    val: libc::c_int,
) -> io::Result<()> {
    // SAFETY: fd is borrowed (caller owns it); val is a stack c_int
    // whose address+len we pass for the duration of the call. The
    // syscall copies out before return.
    // truncation: size_of::<c_int>() == 4, fits socklen_t.
    #[allow(unsafe_code, clippy::cast_possible_truncation)]
    let rc = unsafe {
        libc::setsockopt(
            fd.as_fd().as_raw_fd(),
            level,
            optname,
            (&raw const val).cast::<libc::c_void>(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// setsockopt `IP_TOS`/`IPV6_TCLASS`. Sets the DSCP for OUTGOING
/// UDP datagrams. `is_ipv6`: family of the dest sockaddr.
///
/// Log-on-error at debug, never fail — a busy system flipping TOS
/// per-packet would spam if the kernel ever started rejecting these.
pub fn set_udp_tos(fd: impl AsFd, is_ipv6: bool, prio: u8) {
    #[cfg(target_os = "linux")]
    {
        use nix::sys::socket::{setsockopt, sockopt};
        let val = libc::c_int::from(prio);
        let (label, res) = if is_ipv6 {
            (
                "IPV6_TCLASS",
                setsockopt(&fd.as_fd(), sockopt::Ipv6TClass, &val),
            )
        } else {
            ("IP_TOS", setsockopt(&fd.as_fd(), sockopt::IpTos, &val))
        };
        log::debug!(target: "tincd::net",
                    "Setting outgoing packet priority to {prio} ({label})");
        if let Err(e) = res {
            log::debug!(target: "tincd::net",
                        "setsockopt {label} failed: {}",
                        io::Error::from(e));
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        // nix 0.29 only wraps IpTos/Ipv6TClass on Linux. macOS supports
        // these via raw setsockopt.
        let (level, optname, label) = if is_ipv6 {
            (libc::IPPROTO_IPV6, libc::IPV6_TCLASS, "IPV6_TCLASS")
        } else {
            (libc::IPPROTO_IP, libc::IP_TOS, "IP_TOS")
        };
        log::debug!(target: "tincd::net",
                    "Setting outgoing packet priority to {prio} ({label})");
        if let Err(e) = set_int_sockopt(fd, level, optname, libc::c_int::from(prio)) {
            log::debug!(target: "tincd::net",
                        "setsockopt {label} failed: {e}");
        }
    }
}

/// `bind_to_interface`. Linux: `SO_BINDTODEVICE` (by name). macOS:
/// `IP_BOUND_IF`/`IPV6_BOUND_IF` (by index, resolved via
/// `if_nametoindex`). Returns `Err` on failure (caller closes the
/// socket) — unlike the other sockopts, this is intentional: see
/// `SockOpts.bind_to_interface`.
#[cfg(target_os = "linux")]
pub fn bind_to_interface(s: &Socket, iface: &str) -> io::Result<()> {
    use nix::sys::socket::{setsockopt, sockopt};
    let name = std::ffi::OsString::from(iface);
    setsockopt(&s.as_fd(), sockopt::BindToDevice, &name)
        .map_err(|e| io::Error::other(format!("Can't bind to interface {iface}: {e}")))
}

#[cfg(not(target_os = "linux"))]
pub fn bind_to_interface(s: &Socket, iface: &str) -> io::Result<()> {
    // macOS equivalent of SO_BINDTODEVICE: IP_BOUND_IF binds a
    // socket to a specific interface index.
    let cname = std::ffi::CString::new(iface)
        .map_err(|_| io::Error::other(format!("interface name {iface} contains NUL")))?;
    #[allow(unsafe_code)]
    let ifindex = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if ifindex == 0 {
        return Err(io::Error::other(format!("Unknown interface {iface}")));
    }
    let val = ifindex as libc::c_int;
    // IP_BOUND_IF for IPv4, IPV6_BOUND_IF for IPv6.
    let is_v6 = s.local_addr().map_or(false, |a| a.is_ipv6());
    let (level, optname) = if is_v6 {
        (libc::IPPROTO_IPV6, libc::IPV6_BOUND_IF)
    } else {
        (libc::IPPROTO_IP, libc::IP_BOUND_IF)
    };
    set_int_sockopt(s, level, optname, val)
        .map_err(|e| io::Error::other(format!("Can't bind to interface {iface}: {e}")))
}

/// `daemon(3)`: fork, parent `_exit(0)`, child `setsid()` and
/// redirects stdio to `/dev/null`. (nochdir=true, noclose=false):
/// keep cwd (paths already resolved), close stdio.
///
/// nix wraps this on Linux only; macOS deprecates `daemon(3)` (it
/// wants launchd) but the libc symbol still works.
pub fn daemonize() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        nix::unistd::daemon(true, false).map_err(|e| format!("Couldn't detach from terminal: {e}"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        // nix::unistd::daemon is Linux-only in nix 0.29.
        // Use libc::daemon directly.
        #[allow(unsafe_code, deprecated)]
        let rc = unsafe { libc::daemon(1, 0) };
        if rc < 0 {
            Err(format!(
                "Couldn't detach from terminal: {}",
                io::Error::last_os_error()
            ))
        } else {
            Ok(())
        }
    }
}

/// `initgroups(3)`: set the supplementary group list for `user` from
/// `/etc/group`, plus `gid`. nix gates `unistd::initgroups` out on
/// Apple targets (the libc signature differs: gid is `c_int` there,
/// `gid_t` elsewhere); a single raw libc call with an `as _` cast
/// covers both.
pub fn initgroups(user: &CStr, gid: nix::unistd::Gid) -> io::Result<()> {
    #[allow(unsafe_code, clippy::cast_possible_wrap)]
    let rc = unsafe { libc::initgroups(user.as_ptr(), gid.as_raw() as _) };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
