//! `UdpEgress` — the send-side seam for the 10G datapath.
//!
//! `RUST_REWRITE_10G.md` Phase 0. The trait is the contract: ship
//! `count` UDP datagrams to `dst`. HOW depends on what the kernel
//! offers. The daemon builds an `EgressBatch` and doesn't care.
//!
//! Phase 0 (this commit): one impl, `Portable`. `count` × `sendto`.
//! Same wire output as the `slot.listener.udp.send_to` it replaces
//! (`net.rs:1930`). Works on every POSIX.
//!
//! Phase 1 swaps `linux::Fast`: one `sendmsg(MSG_ZEROCOPY)` with
//! `cmsg UDP_SEGMENT=stride`, kernel splits at egress. Same `count`
//! datagrams hit the wire; the receiver can't tell the difference.
//!
//! ## Why `Box<dyn>` not generics
//!
//! The daemon's `egress: Vec<Box<dyn UdpEgress>>` is parallel to
//! `listeners` (same `sock` index). One vtable indirect per BATCH.
//! At 10G with 63KB super-packets that's ~20k batches/s × ~2ns
//! ≈ 0.004% of cycles. The alternative is a `cfg`-selected type
//! alias plumbed through every signature that touches `egress`.
//! The vtable is cheaper than the maintenance.
//!
//! ## Why `try_clone` not borrow
//!
//! `Portable` holds a `socket2::Socket`. The `Listener.udp` it dups
//! from stays where it is (the `recvmmsg` path needs it). `try_clone`
//! is `dup(2)` — same file description, separate fd, no ownership
//! puzzle, no self-referential daemon struct. The kernel doesn't
//! care which fd `sendto` lands on.

#![forbid(unsafe_code)]

use std::io;

use socket2::{SockAddr, Socket};

/// A run of encrypted frames to one destination. Daemon builds these
/// from par-encrypt output (Phase 3) or one-at-a-time today.
///
/// `frames` is a contiguous slice into `DeviceArena` (Phase 1+) or
/// `tx_scratch` (Phase 0, `count=1`). The egress impl decides how
/// to ship; the wire result is `count` UDP datagrams either way.
pub struct EgressBatch<'a> {
    /// Destination. `SockAddr` not `SocketAddr` — `socket2::send_to`
    /// takes `&SockAddr` and the daemon already has one cached
    /// (`udp_addr_cached`, the hot path; cold path builds with
    /// `SockAddr::from(SocketAddr)` once per send anyway).
    pub dst: &'a SockAddr,
    /// Contiguous: `count` chunks at `stride` each, last possibly
    /// shorter. For `UDP_SEGMENT` this is exactly the buffer the
    /// kernel reads in one `copy_from_iter`.
    pub frames: &'a [u8],
    /// `gso_size`. All chunks except possibly the last are this size.
    /// `u16`: kernel `UDP_MAX_SEGMENTS=128` × any sane stride fits
    /// in `frames.len()` without `stride` needing more than 16 bits
    /// (PMTU caps it anyway — `EMSGSIZE` if `stride > PMTU - 28`).
    pub stride: u16,
    /// Number of datagrams. `≤ UDP_MAX_SEGMENTS = 128`
    /// (`include/linux/udp.h:124`). The daemon caps at
    /// `DEVICE_DRAIN_CAP=64` today, well under.
    pub count: u16,
    /// `≤ stride`. The kernel allows a shorter trailing segment
    /// (Willem's `bec1f6f69736` commit msg: "If not an exact multiple
    /// of segment size, the last segment will be shorter"). The
    /// trailing-ACK case in a TCP burst.
    pub last_len: u16,
}

/// Ship batches. The Phase-0 contract; Phase 1/4 add fast impls.
pub trait UdpEgress: Send {
    /// Ship a batch: `count` UDP datagrams to `dst`. Same wire
    /// result on every impl; the kernel-side mechanism differs.
    ///
    /// # Errors
    /// `io::Error` from `sendto`/`sendmsg`. `WouldBlock` (UDP
    /// sndbuf full) and `EMSGSIZE` (stride > PMTU) are the daemon's
    /// concern — `Portable` surfaces them per-chunk; `linux::Fast`
    /// surfaces them per-batch. The daemon's PMTU machinery handles
    /// `EMSGSIZE` either way (`net.rs:1934`).
    fn send_batch(&mut self, b: &EgressBatch<'_>) -> io::Result<()>;

    /// ZC completion poll. Default no-op (Portable doesn't ZC).
    /// Called from the event loop on errqueue `EPOLLIN`. Returns
    /// the count of arena slots now reusable (the buffer the kernel
    /// pinned is released). Phase 4 wires this; until then, the
    /// daemon never registers an errqueue fd, never calls this.
    ///
    /// # Errors
    /// `io::Error` from `recvmsg(MSG_ERRQUEUE)` (Phase 4). Default
    /// impl never errs.
    fn poll_completions(&mut self) -> io::Result<usize> {
        Ok(0)
    }
}

/// The floor. `count` × `sendto`. Works on macOS, BSD, anything
/// POSIX. Produces wire output identical to today's `net.rs:1930`
/// `send_to` — `Portable::send_batch` with `count=1` IS one `sendto`.
pub struct Portable {
    /// `dup(2)` of `Listener.udp`. Same file description, so
    /// `SO_BINDTODEVICE`/`IP_TOS`/etc. set on the listener apply
    /// here. Separate fd, so dropping `Portable` (daemon teardown)
    /// doesn't close the listener's fd.
    sock: Socket,
}

impl Portable {
    /// Build from a dup of the listener's UDP socket.
    ///
    /// # Errors
    /// `io::Error` from `dup(2)` (fd exhaustion — same failure mode
    /// as opening one more listener).
    pub fn new(udp: &Socket) -> io::Result<Self> {
        Ok(Self {
            sock: udp.try_clone()?,
        })
    }
}

impl UdpEgress for Portable {
    fn send_batch(&mut self, b: &EgressBatch<'_>) -> io::Result<()> {
        // Phase 0: count is always 1 (the daemon hasn't batched
        // yet). The loop is here so Phase 1's daemon-side batching
        // works on Portable too — BSD/macOS get the per-frame
        // sendto, Linux gets `linux::Fast`.
        let stride = usize::from(b.stride);
        for i in 0..b.count {
            let off = usize::from(i) * stride;
            let len = if i + 1 == b.count {
                usize::from(b.last_len)
            } else {
                stride
            };
            self.sock.send_to(&b.frames[off..off + len], b.dst)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{SocketAddr, UdpSocket};

    /// `Portable::send_batch` with `count=1` produces the same bytes
    /// on the wire as a direct `send_to`. This is the Phase-0
    /// invariant: the seam is transparent. If this fails, the
    /// abstraction changed semantics and all 1210 tests are suspect.
    ///
    /// Uses a real loopback UDP pair — same kernel path as
    /// production, no mock. The `recv_from` on the other end sees
    /// exactly what `net.rs:1930` would have sent.
    #[test]
    fn portable_count_1_is_one_sendto() {
        // Receiver: bind ephemeral, learn the port.
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let rx_addr = rx.local_addr().unwrap();
        rx.set_nonblocking(false).unwrap();

        // Sender: socket2::Socket so we exercise the same `send_to`
        // signature as production. Bind to ephemeral (the daemon
        // binds to the listener port; here we just need a source).
        let tx_std = UdpSocket::bind("127.0.0.1:0").unwrap();
        let tx: Socket = tx_std.into();
        let mut p = Portable::new(&tx).unwrap();

        let payload = b"exactly what net.rs:1930 sends";
        let dst = SockAddr::from(rx_addr);
        #[allow(clippy::cast_possible_truncation)] // 30 bytes
        let len = payload.len() as u16;
        let batch = EgressBatch {
            dst: &dst,
            frames: payload,
            stride: len,
            count: 1,
            last_len: len,
        };
        p.send_batch(&batch).unwrap();

        let mut buf = [0u8; 256];
        let (n, from) = rx.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], payload);
        // The source is the dup'd socket — same fd table entry,
        // same bound address as `tx`.
        assert_eq!(from, tx.local_addr().unwrap().as_socket().unwrap());
    }

    /// `count > 1` produces `count` datagrams in order, each `stride`
    /// bytes except the last (`last_len`). Phase 0 doesn't exercise
    /// this (daemon always builds `count=1`), but the loop is here
    /// for Phase 1 — and it must be right NOW so we don't debug the
    /// portable fallback while debugging UDP_SEGMENT.
    #[test]
    fn portable_batch_splits_at_stride() {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let rx_addr: SocketAddr = rx.local_addr().unwrap();
        let tx: Socket = UdpSocket::bind("127.0.0.1:0").unwrap().into();
        let mut p = Portable::new(&tx).unwrap();

        // 3 chunks of 10, last is 7. Contiguous in memory like the
        // arena will lay them out.
        let mut frames = [0u8; 30];
        frames[0..10].copy_from_slice(b"AAAAAAAAAA");
        frames[10..20].copy_from_slice(b"BBBBBBBBBB");
        frames[20..27].copy_from_slice(b"CCCCCCC");
        let dst = SockAddr::from(rx_addr);
        let batch = EgressBatch {
            dst: &dst,
            frames: &frames,
            stride: 10,
            count: 3,
            last_len: 7,
        };
        p.send_batch(&batch).unwrap();

        // Three datagrams arrive, in order (loopback preserves it).
        let mut buf = [0u8; 64];
        let (n, _) = rx.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"AAAAAAAAAA");
        let (n, _) = rx.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"BBBBBBBBBB");
        let (n, _) = rx.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"CCCCCCC");
    }

    /// `try_clone` produces a working dup. Dropping `Portable` does
    /// not close the original fd (the listener's `recvmmsg` path
    /// still needs it). This is the "no ownership puzzle" claim.
    #[test]
    fn portable_dup_survives_drop() {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let rx_addr = rx.local_addr().unwrap();
        let tx: Socket = UdpSocket::bind("127.0.0.1:0").unwrap().into();

        {
            let _p = Portable::new(&tx).unwrap();
            // _p drops here, closing the dup'd fd
        }

        // Original `tx` still works.
        let dst = SockAddr::from(rx_addr);
        tx.send_to(b"still alive", &dst).unwrap();
        let mut buf = [0u8; 64];
        let (n, _) = rx.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"still alive");
    }

    /// `poll_completions` default is a no-op returning 0. Phase 4
    /// overrides it; until then the daemon never calls it (no
    /// errqueue fd registered). This test pins the default so a
    /// stray refactor that makes it `unimplemented!()` fails CI
    /// before it hits a Phase-4 caller.
    #[test]
    fn poll_completions_default_noop() {
        let tx: Socket = UdpSocket::bind("127.0.0.1:0").unwrap().into();
        let mut p = Portable::new(&tx).unwrap();
        assert_eq!(p.poll_completions().unwrap(), 0);
    }
}
