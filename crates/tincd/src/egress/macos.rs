//! `macos::Fast` — batch UDP send via `sendmsg_x(2)`.
//!
//! `sendmsg_x` is the Darwin analogue of Linux `sendmmsg`: one syscall
//! ships N datagrams. It's a private syscall (`socket_private.h`, "the
//! API is subject to change") but has been ABI-stable since macOS 10.10
//! and is used in production by WireGuard-go, quinn, and shadowsocks.
//! We `dlsym` nothing — it's exported from libSystem unconditionally
//! (verified via `libSystem.B.tbd`). On the off-chance the kernel ever
//! returns `ENOSYS` we latch a fallback flag and degrade to per-frame
//! `sendto`.
//!
//! ## Per-datagram address vs. connected socket
//!
//! `socket_private.h` says "Address … not supported … `msg_name` must
//! be set to zero", but the implementation in `bsd/kern/
//! uipc_syscalls.c::sendmsg_x` only takes the connected-socket fast
//! path (`sendit_x`) when `SS_ISCONNECTED`; on an *unconnected* UDP
//! socket it falls through to a per-message `sendit()` loop — the
//! same kernel internal as `sendmsg(2)` — which honours `msg_name`.
//! That still saves N−1 syscall transitions per batch.
//!
//! We deliberately stay on the unconnected path: a `connect()`-ed dup
//! cannot share the listener's bound port without `SO_REUSEPORT`, and
//! on Darwin a connected socket bound to the same 4-tuple *steals
//! inbound* datagrams from the listener (best-match wins), which
//! would starve the daemon's recv loop. Giving up the `sendit_x` mbuf-
//! list fast path is the price of not breaking receive.

// `sendmsg_x` is not in libc/nix; raw FFI is unavoidable. Parent
// module is `deny(unsafe_code)`; scope the allow to this file.
#![allow(unsafe_code)]

use std::io;
use std::os::fd::AsRawFd;

use socket2::Socket;

use super::{EgressBatch, Portable, UdpEgress};

/// `struct msghdr_x` (xnu `bsd/sys/socket_private.h`). Layout matches
/// the LP64 user struct exactly; checked against shadowsocks-rust and
/// the xnu source. Field names kept verbatim from C for greppability.
#[repr(C)]
#[allow(clippy::struct_field_names)]
struct MsghdrX {
    msg_name: *mut libc::c_void,
    msg_namelen: libc::socklen_t,
    msg_iov: *mut libc::iovec,
    msg_iovlen: libc::c_int,
    msg_control: *mut libc::c_void,
    msg_controllen: libc::socklen_t,
    msg_flags: libc::c_int,
    /// Output for `recvmsg_x`; must be zero on input to `sendmsg_x`.
    msg_datalen: libc::size_t,
}

// SAFETY: the raw pointers in `MsghdrX`/`iovec` are scratch slots
// fully overwritten before every `sendmsg_x` call and never read by
// Rust code; they don't alias any shared state. `UdpEgress: Send` is
// the bound; the daemon is single-threaded so this is belt-only.
unsafe impl Send for Fast {}

unsafe extern "C" {
    /// Returns number of datagrams sent, or -1/errno. `flags` accepts
    /// only `MSG_DONTWAIT`.
    fn sendmsg_x(
        s: libc::c_int,
        msgp: *const MsghdrX,
        cnt: libc::c_uint,
        flags: libc::c_int,
    ) -> libc::ssize_t;
}

/// Max datagrams per `sendmsg_x` call. The daemon caps a `TxBatch` run
/// at `UDP_MAX_SEGMENTS = 128`; we size the header/iov scratch arrays
/// to match so they're allocated once and never grow.
const HDR_CAP: usize = super::UDP_MAX_SEGMENTS as usize;

/// macOS batch UDP egress. Falls back to [`Portable`] for `count == 1`
/// (no batching win) and on `ENOSYS`.
pub(crate) struct Fast {
    /// Per-frame `sendto` fallback; also owns the fd we send on.
    fallback: Portable,
    /// Latched after the first `ENOSYS` so we stop trying. Per-egress
    /// not global: cheap, and avoids a `static AtomicBool` for what is
    /// in practice a never-taken branch.
    disabled: bool,
    /// Reused per-batch header/iov scratch. One iovec per datagram
    /// (the `EgressBatch` buffer is already contiguous, so each iovec
    /// is just `(ptr+off, len)`). Heap-once, reused warm.
    hdrs: Box<[MsghdrX; HDR_CAP]>,
    iovs: Box<[libc::iovec; HDR_CAP]>,
}

impl Fast {
    /// Dup the listener UDP socket. Same construction as [`Portable`].
    ///
    /// # Errors
    /// `io::Error` from `dup(2)`.
    pub(crate) fn new(udp: &Socket) -> io::Result<Self> {
        // SAFETY: zeroed `msghdr_x`/`iovec` are valid (all-null
        // pointers, zero lengths) and are fully overwritten before
        // each `sendmsg_x` call. `Box::<[T; N]>::new_zeroed()` is
        // unstable; go via collect→boxed-slice→try_into so the
        // ~7 KiB scratch lands on the heap, not the stack.
        let hdrs: Box<[MsghdrX]> = (0..HDR_CAP)
            .map(|_| unsafe { std::mem::zeroed::<MsghdrX>() })
            .collect();
        let iovs: Box<[libc::iovec]> = (0..HDR_CAP)
            .map(|_| unsafe { std::mem::zeroed::<libc::iovec>() })
            .collect();
        // `try_into` fails only on length mismatch; we just collected
        // exactly `HDR_CAP` elements. Setup-time, never hot-path.
        // `map_err` because `Box<[MsghdrX]>` (raw ptrs) isn't `Debug`.
        Ok(Self {
            fallback: Portable::new(udp)?,
            disabled: false,
            hdrs: hdrs.try_into().map_err(|_| ()).expect("HDR_CAP elements"),
            iovs: iovs.try_into().map_err(|_| ()).expect("HDR_CAP elements"),
        })
    }
}

impl UdpEgress for Fast {
    fn send_batch(&mut self, b: &EgressBatch<'_>) -> io::Result<()> {
        // Single frame: `sendmsg_x` saves nothing over `sendto`.
        if self.disabled || b.count <= 1 || usize::from(b.count) > HDR_CAP {
            return self.fallback.send_batch(b);
        }

        let sock = self.fallback.sock().as_raw_fd();
        let stride = usize::from(b.stride);
        let base = b.frames.as_ptr();
        for i in 0..usize::from(b.count) {
            let off = i * stride;
            let len = if i + 1 == usize::from(b.count) {
                usize::from(b.last_len)
            } else {
                stride
            };
            // SAFETY: `EgressBatch::frames` is `&[u8]` of length
            // `(count-1)*stride + last_len`; `off+len` is in bounds
            // for every `i < count` by construction (`TxBatch::stage`
            // packed it). The iovec is read-only by the kernel.
            self.iovs[i] = libc::iovec {
                iov_base: unsafe { base.add(off) } as *mut libc::c_void,
                iov_len: len,
            };
            self.hdrs[i] = MsghdrX {
                // Unconnected-socket path: `sendit()` honours this
                // exactly like `sendmsg(2)` would. `as_ptr()` returns
                // `*const sockaddr_storage`; the syscall reads only
                // `msg_namelen` bytes and never writes through it, so
                // the const→mut cast is sound.
                msg_name: b.dst.as_ptr() as *mut libc::c_void,
                msg_namelen: b.dst.len(),
                msg_iov: &raw mut self.iovs[i],
                msg_iovlen: 1,
                msg_control: std::ptr::null_mut(),
                msg_controllen: 0,
                msg_flags: 0,
                msg_datalen: 0,
            };
        }

        // SAFETY: `hdrs[..count]` fully initialized above; `sock` is
        // the listener dup we own. `MSG_DONTWAIT` is belt-and-
        // suspenders: the dup shares `O_NONBLOCK` with the listener.
        let ret = unsafe {
            sendmsg_x(
                sock,
                self.hdrs.as_ptr(),
                libc::c_uint::from(b.count),
                libc::MSG_DONTWAIT,
            )
        };
        if ret >= 0 {
            // Partial send (`ret < count`) means sndbuf filled mid-
            // batch. The unsent tail is dropped — same semantics as
            // `Portable` hitting `WouldBlock` per-frame, and as
            // `linux::Fast`'s all-or-nothing GSO send. UDP is
            // unreliable; inner-TCP retransmits.
            return Ok(());
        }
        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            // Kernel doesn't implement it (never observed on 10.10+
            // for UDP, but the header says "subject to change").
            // Latch off and replay this batch via the portable path
            // so no frames are lost.
            Some(libc::ENOSYS) => {
                self.disabled = true;
                self.fallback.send_batch(b)
            }
            _ => Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use socket2::SockAddr;
    use std::net::UdpSocket;

    /// Wire-equivalence: `Fast::send_batch` produces the same
    /// datagrams a loop of `sendto` would. Same fixture as
    /// `egress::tests::portable_batch_splits_at_stride` but through
    /// the `sendmsg_x` path (count > 1 forces it).
    #[test]
    fn macos_fast_splits_at_stride() {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let dst = SockAddr::from(rx.local_addr().unwrap());
        let tx: Socket = UdpSocket::bind("127.0.0.1:0").unwrap().into();
        let mut p = Fast::new(&tx).unwrap();

        let mut frames = [0u8; 27];
        frames[0..10].copy_from_slice(b"AAAAAAAAAA");
        frames[10..20].copy_from_slice(b"BBBBBBBBBB");
        frames[20..27].copy_from_slice(b"CCCCCCC");
        let batch = EgressBatch {
            dst: &dst,
            frames: &frames,
            stride: 10,
            count: 3,
            last_len: 7,
        };
        p.send_batch(&batch).unwrap();

        let mut buf = [0u8; 64];
        let (n, _) = rx.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"AAAAAAAAAA");
        let (n, _) = rx.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"BBBBBBBBBB");
        let (n, _) = rx.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"CCCCCCC");

        // Second batch reuses the same scratch arrays; different
        // bytes prove no stale state leaks between calls.
        let frames2 = *b"xxxxxxxxxxyyyyyyyyyy";
        p.send_batch(&EgressBatch {
            dst: &dst,
            frames: &frames2,
            stride: 10,
            count: 2,
            last_len: 10,
        })
        .unwrap();
        let (n, _) = rx.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"xxxxxxxxxx");
        let (n, _) = rx.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"yyyyyyyyyy");
    }

    /// `count == 1` takes the portable `sendto` fallback, not
    /// `sendmsg_x`. Proves the immediate-send path still works.
    #[test]
    fn macos_fast_count_1_is_sendto() {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let dst = SockAddr::from(rx.local_addr().unwrap());
        let tx: Socket = UdpSocket::bind("127.0.0.1:0").unwrap().into();
        let mut p = Fast::new(&tx).unwrap();

        p.send_batch(&EgressBatch {
            dst: &dst,
            frames: b"single",
            stride: 6,
            count: 1,
            last_len: 6,
        })
        .unwrap();

        let mut buf = [0u8; 64];
        let (n, _) = rx.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"single");
    }
}
