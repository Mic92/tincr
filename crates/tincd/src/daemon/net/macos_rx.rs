//! Darwin `recvmsg_x` UDP ingress: one syscall for up to
//! [`UDP_RX_BATCH`] datagrams on the unconnected listener socket.
//! The Linux path uses `recvmmsg(2)`; this is the Darwin analogue.
//!
//! Unlike the utun kctl socket, an unconnected UDP socket *does*
//! carry per-datagram source addresses through `recvmsg_x`
//! (`uipc_syscalls.c:2872` copies `msg_name` per message). We don't
//! request cmsgs at all, which sidesteps the macOS 10.15 quirk where
//! `msg_controllen` isn't overwritten on output (quinn-udp #1148).
//!
//! Falls back to the per-datagram `recvfrom` loop on `ENOSYS`; never
//! observed on 10.10+ but the header says "subject to change".

#![allow(unsafe_code)]

use std::net::SocketAddr;

use super::{UDP_RX_BATCH, UDP_RX_BUFSZ, UdpRxBatch};
use crate::darwin_x::{MsghdrX, recvmsg_x, zeroed_boxed_array};
use crate::listen::unmap;

/// Persistent `msghdr_x` / iovec / `sockaddr_storage` arrays. Same
/// shape as `egress::macos::Fast` but with per-slot address storage.
pub(in crate::daemon) struct Scratch {
    disabled: bool,
    hdrs: Box<[MsghdrX; UDP_RX_BATCH]>,
    iovs: Box<[libc::iovec; UDP_RX_BATCH]>,
    addrs: Box<[libc::sockaddr_storage; UDP_RX_BATCH]>,
}

// SAFETY: raw pointers in `hdrs`/`iovs` are scratch, fully overwritten
// before every `recvmsg_x` call and never read by Rust code; they
// alias only `bufs`/`addrs`, both exclusively borrowed at call time.
// The daemon is single-threaded; `Send` is for the `Option<UdpRxBatch>`
// `mem::take` dance only.
unsafe impl Send for Scratch {}

impl Scratch {
    pub(super) fn new() -> Self {
        // SAFETY: zeroed `msghdr_x`/`iovec`/`sockaddr_storage` are
        // valid (null pointers, zero lengths, AF_UNSPEC).
        unsafe {
            Self {
                disabled: false,
                hdrs: zeroed_boxed_array(),
                iovs: zeroed_boxed_array(),
                addrs: zeroed_boxed_array(),
            }
        }
    }
}

/// `recvmsg_x` phase-1: fill `batch.bufs` and `meta` exactly as the
/// Linux `recvmmsg` path does. Returns `None` to signal "fall back to
/// `recvfrom` loop" (latched `ENOSYS`); the caller then runs the
/// portable phase-1 so behaviour is byte-identical.
pub(super) fn phase1(
    fd: std::os::fd::RawFd,
    batch: &mut UdpRxBatch,
    meta: &mut [(u16, Option<SocketAddr>); UDP_RX_BATCH],
) -> Option<usize> {
    let x = &mut batch.x;
    if x.disabled {
        return None;
    }
    let bufs = batch.bufs.as_mut_ptr();
    for i in 0..UDP_RX_BATCH {
        // SAFETY: `i < UDP_RX_BATCH`; `bufs`/`addrs` are exclusively
        // borrowed via `&mut batch`. The kernel writes at most
        // `iov_len`/`msg_namelen` bytes respectively.
        x.iovs[i] = libc::iovec {
            iov_base: unsafe { bufs.add(i) }.cast(),
            iov_len: UDP_RX_BUFSZ,
        };
        x.hdrs[i] = MsghdrX {
            msg_name: (&raw mut x.addrs[i]).cast(),
            #[allow(clippy::cast_possible_truncation)] // 128 fits socklen_t
            msg_namelen: size_of::<libc::sockaddr_storage>() as libc::socklen_t,
            msg_iov: &raw mut x.iovs[i],
            msg_iovlen: 1,
            // No cmsgs: avoids the 10.15 `msg_controllen` quirk and
            // we don't need pktinfo on the listener.
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
            msg_datalen: 0,
        };
    }

    // UDP_RX_BATCH = 64; fits c_uint.
    #[allow(clippy::cast_possible_truncation)]
    let cnt = UDP_RX_BATCH as libc::c_uint;
    // SAFETY: `hdrs[..UDP_RX_BATCH]` fully initialised above; each
    // iovec/msg_name points into exclusively-borrowed `batch` memory.
    // `MSG_DONTWAIT` is one of the two flags `recvmsg_x` accepts.
    let ret = unsafe { recvmsg_x(fd, x.hdrs.as_mut_ptr(), cnt, libc::MSG_DONTWAIT) };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        return match err.raw_os_error() {
            Some(libc::EAGAIN) => Some(0),
            Some(libc::ENOSYS) => {
                x.disabled = true;
                None
            }
            _ => {
                log::error!(target: "tincd::net", "Receiving packet failed: {err}");
                Some(0)
            }
        };
    }
    // `ret` ∈ [0, UDP_RX_BATCH]; non-negative checked above.
    #[allow(clippy::cast_sign_loss)]
    let n = ret as usize;
    for (i, m) in meta.iter_mut().enumerate().take(n) {
        #[allow(clippy::cast_possible_truncation)] // ≤ UDP_RX_BUFSZ = 2048
        let len = x.hdrs[i].msg_datalen.min(UDP_RX_BUFSZ) as u16;
        let peer = ss_to_socketaddr(&x.addrs[i], x.hdrs[i].msg_namelen);
        *m = (len, peer.map(unmap));
    }
    Some(n)
}

/// `sockaddr_storage` → std `SocketAddr`. socket2 0.6 wraps storage
/// in its own opaque type and nix wants its own `SockaddrStorage`;
/// neither can be built from a raw `libc::sockaddr_storage` without
/// a transmute, so decode by hand. UDP only ever yields v4/v6.
fn ss_to_socketaddr(ss: &libc::sockaddr_storage, len: libc::socklen_t) -> Option<SocketAddr> {
    // SAFETY: `sockaddr_storage` is sized/aligned to hold any
    // `sockaddr_*`; once `ss_family` says AF_INET{,6} the
    // corresponding-sized prefix is a valid `sockaddr_in{,6}`
    // written by the kernel. `len` is checked so a short write
    // (never observed on Darwin UDP) can't read uninitialised
    // bytes. `read_unaligned` is belt-only — `sockaddr_storage` is
    // already max-aligned.
    unsafe {
        match libc::c_int::from(ss.ss_family) {
            libc::AF_INET if len as usize >= size_of::<libc::sockaddr_in>() => {
                let sin = std::ptr::from_ref(ss)
                    .cast::<libc::sockaddr_in>()
                    .read_unaligned();
                Some(SocketAddr::new(
                    std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)).into(),
                    u16::from_be(sin.sin_port),
                ))
            }
            libc::AF_INET6 if len as usize >= size_of::<libc::sockaddr_in6>() => {
                let sin6 = std::ptr::from_ref(ss)
                    .cast::<libc::sockaddr_in6>()
                    .read_unaligned();
                Some(SocketAddr::V6(std::net::SocketAddrV6::new(
                    std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr),
                    u16::from_be(sin6.sin6_port),
                    sin6.sin6_flowinfo,
                    sin6.sin6_scope_id,
                )))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::os::fd::AsRawFd;

    /// `phase1` over a real loopback UDP socket: same `(len, peer)`
    /// per slot as the `recvfrom` loop would have produced, in one
    /// syscall. Covers the per-datagram `msg_name` extraction (the
    /// utun batch path doesn't exercise that — kctl has no `PR_ADDR`).
    #[test]
    fn recvmsg_x_udp_phase1() {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        rx.set_nonblocking(true).unwrap();
        let dst = rx.local_addr().unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer = tx.local_addr().unwrap();

        let payloads: [&[u8]; 3] = [b"alpha", b"bravo-bravo", b"c"];
        for p in &payloads {
            tx.send_to(p, dst).unwrap();
        }

        let mut batch = UdpRxBatch::new();
        let mut meta = [(0u16, None); UDP_RX_BATCH];
        let n = phase1(rx.as_raw_fd(), &mut batch, &mut meta).expect("recvmsg_x available");
        assert_eq!(n, payloads.len());
        for (i, p) in payloads.iter().enumerate() {
            assert_eq!(usize::from(meta[i].0), p.len(), "slot {i} len");
            assert_eq!(meta[i].1, Some(peer), "slot {i} peer");
            assert_eq!(&batch.bufs[i][..p.len()], *p, "slot {i} bytes");
        }

        // Drained: next call sees EAGAIN → 0.
        assert_eq!(phase1(rx.as_raw_fd(), &mut batch, &mut meta), Some(0));
    }
}
