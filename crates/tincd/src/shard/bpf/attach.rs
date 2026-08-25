//! `TUNSETSTEERINGEBPF` — defensive detach only.
//!
//! With the eBPF design dropped, the only reason this ioctl ships is
//! belt-and-suspenders: if a previous tincd crashed with an eBPF
//! steering prog attached (impossible with this codebase, but the
//! TUN device may be persistent and shared), `tun_automq_select_queue`
//! never runs (`tun.c:483` checks `tun->steering_prog` first). Passing
//! `prog_fd = -1` detaches (`tun_set_ebpf` → `__tun_set_ebpf(NULL)`),
//! restoring automq. No-op if nothing was attached.
//!
//! Never EPERM: the ioctl path is gated by the same `CAP_NET_ADMIN`
//! check as `TUNSETIFF` (`tun.c:3257` `tun_chr_ioctl` switch). If
//! we got past `open_mq`, we can call this.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};

/// `_IOR('T', 224, int)` — `tun.c:3293`. `_IOR` encoding is honest:
/// the kernel `copy_from_user`s 4 bytes from the user pointer and
/// writes nothing back. Not in libc.
pub const TUNSETSTEERINGEBPF: libc::c_ulong = 0x8004_54e0;

/// Attach (`prog_fd >= 0`) or detach (`-1`) a TUN steering prog; automq only
/// ever detaches, but any `i32` is accepted so the test can probe the ioctl
/// with garbage fds. Detaching with nothing attached succeeds
/// (`__tun_set_ebpf(NULL)` is idempotent).
///
/// # Errors
/// `EBADF` (not an open fd), `EINVAL` (not a `SOCKET_FILTER` prog).
#[expect(unsafe_code)]
pub fn tunsetsteeringebpf(tun_fd: BorrowedFd<'_>, prog_fd: i32) -> io::Result<()> {
    let mut prog_fd = prog_fd; // kernel reads via copy_from_user
    // SAFETY: TUNSETSTEERINGEBPF takes `int *` (4 bytes); kernel
    // `copy_from_user`s it (`tun.c:2978` `tun_set_ebpf`). `&raw mut
    // prog_fd` is a valid aligned `*mut i32` on our stack. Kernel
    // writes nothing back.
    let ret = unsafe { libc::ioctl(tun_fd.as_raw_fd(), TUNSETSTEERINGEBPF, &raw mut prog_fd) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
