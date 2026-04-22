//! Darwin `sendmsg_x`/`recvmsg_x` FFI shared between
//! [`egress::macos`](crate::egress) (UDP send) and
//! [`daemon::net`](crate::daemon) (UDP recv). The utun side has its
//! own copy in `tinc-device` to keep the dep graph acyclic.
//!
//! Both syscalls are private (`socket_private.h`, "the API is subject
//! to change") but have been ABI-stable since macOS 10.10 and are
//! used in production by WireGuard-go, quinn, and shadowsocks. The
//! symbols are exported unconditionally from libSystem (verified via
//! `libSystem.B.tbd`), so no `dlsym` dance.

#![allow(unsafe_code)]
#![cfg(target_os = "macos")]

/// `struct msghdr_x` (xnu `bsd/sys/socket_private.h`). Layout matches
/// the LP64 user struct exactly. Field names verbatim from C for
/// greppability.
#[repr(C)]
#[allow(clippy::struct_field_names)]
pub(crate) struct MsghdrX {
    pub msg_name: *mut libc::c_void,
    pub msg_namelen: libc::socklen_t,
    pub msg_iov: *mut libc::iovec,
    pub msg_iovlen: libc::c_int,
    pub msg_control: *mut libc::c_void,
    pub msg_controllen: libc::socklen_t,
    pub msg_flags: libc::c_int,
    /// `recvmsg_x`: bytes received in this slot. `sendmsg_x`: must be
    /// zero on input.
    pub msg_datalen: libc::size_t,
}

// SAFETY: declarations match `bsd/sys/socket_private.h` exactly.
unsafe extern "C" {
    /// Returns datagrams sent, or -1/errno. Only `MSG_DONTWAIT`
    /// accepted in `flags`.
    pub(crate) fn sendmsg_x(
        s: libc::c_int,
        msgp: *const MsghdrX,
        cnt: libc::c_uint,
        flags: libc::c_int,
    ) -> libc::ssize_t;

    /// Returns datagrams received, or -1/errno. Only
    /// `MSG_DONTWAIT|MSG_NBIO` accepted in `flags`.
    pub(crate) fn recvmsg_x(
        s: libc::c_int,
        msgp: *mut MsghdrX,
        cnt: libc::c_uint,
        flags: libc::c_int,
    ) -> libc::ssize_t;
}

/// Heap-allocate a zeroed `Box<[T; N]>` without building the array on
/// the stack first.
///
/// # Safety
/// `T` must be valid when zero-initialised (true for `MsghdrX`,
/// `libc::iovec`, `libc::sockaddr_storage`).
pub(crate) unsafe fn zeroed_boxed_array<T, const N: usize>() -> Box<[T; N]> {
    // SAFETY: caller guarantees zeroed `T` is valid.
    let v: Box<[T]> = (0..N).map(|_| unsafe { std::mem::zeroed::<T>() }).collect();
    // map_err: raw-pointer `T` isn't `Debug`.
    v.try_into().map_err(|_| ()).expect("collected N elements")
}
