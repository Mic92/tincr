//! `linux::Fast` — `UDP_SEGMENT` cmsg egress.
//!
//! One `sendmsg` with `cmsg{SOL_UDP, UDP_SEGMENT, gso_size: u16}`; the
//! kernel splits at `gso_size` boundaries. Wire-identical to `Portable`'s
//! `count × sendto`.
//!
//! Implemented via `nix::sys::socket::sendmsg` +
//! `ControlMessage::UdpGsoSegments`, which builds the ~24-byte cmsg
//! buffer per call. The earlier hand-rolled `libc::sendmsg` path
//! pre-built the cmsghdr once and patched the 2-byte `gso_size`
//! in-place to avoid that work; the `sendmsg` syscall itself dwarfs
//! the encode, so we trade the micro-optimization for zero `unsafe`.
//! Re-check `rust_vs_c_throughput` if this is ever suspect.
//!
//! No fallback: kernel ≥4.18 floor. `ENOPROTOOPT` panics rather than
//! silently degrading to per-frame sendto.

#![forbid(unsafe_code)]

use std::io;
use std::io::IoSlice;
use std::os::fd::AsRawFd;

use nix::errno::Errno;
use nix::sys::socket::{ControlMessage, MsgFlags, SockaddrStorage, sendmsg};
use socket2::Socket;

use super::{EgressBatch, UdpEgress};

/// `UDP_SEGMENT` egress. Linux ≥4.18 (`bec1f6f69736`).
pub(crate) struct Fast {
    /// `dup(2)` of the listener's UDP socket. Same file description
    /// as the `recvmmsg` side — same bound addr, same `SO_BINDTODEVICE`,
    /// same `IP_TOS` (the daemon's `set_udp_tos` sets it on the
    /// listener fd, which is the same FILE DESCRIPTION).
    sock: Socket,
}

impl Fast {
    /// Dup the listener's UDP fd.
    ///
    /// # Errors
    /// `io::Error` from `dup(2)` (fd exhaustion).
    pub(crate) fn new(udp: &Socket) -> io::Result<Self> {
        Ok(Self {
            sock: udp.try_clone()?,
        })
    }
}

impl UdpEgress for Fast {
    fn send_batch(&mut self, b: &EgressBatch<'_>) -> io::Result<()> {
        // count=1: skip the cmsg entirely. Two reasons:
        //
        // (a) Kernel's `udp_send_skb` GSO branch only fires when
        //     `datalen > gso_size`. With `count=1` and `last_len ≤
        //     stride`, `datalen ≤ gso_size` — the kernel skips GSO
        //     and does a plain send anyway. The cmsg parse is pure
        //     overhead.
        //
        // (b) The common case. `on_device_read` only arms the batch
        //     for `drain count > 1`. A single ICMP, ARP, control
        //     frame falls through to immediate-send with `count=1`.
        //     Don't tax the mundane case for the iperf3 case.
        //
        // socket2's `send_to` is one `sendto` syscall, no allocs.
        // `frames[..last_len]`: `count=1` means `frames.len() ==
        // last_len` for a properly built batch, but slicing makes
        // the invariant local.
        if b.count == 1 {
            return self
                .sock
                .send_to(&b.frames[..usize::from(b.last_len)], b.dst)
                .map(|_| ());
        }

        // The GSO path. One iovec spanning the whole dense-packed
        // run; kernel reads it in one `copy_from_iter`, splits at
        // `b.stride`. Last segment may be shorter (Willem's commit
        // msg explicitly allows it).
        //
        // `b.frames` is exactly `(count-1)*stride + last_len` bytes
        // — the daemon's `TxBatch::stage` packed them densely. NO
        // gaps, no padding; the kernel's split-at-stride math
        // depends on this.
        //
        // Hard limits the daemon already respects:
        //   - `gso_size + iphdr + udphdr ≤ PMTU` else `EMSGSIZE`.
        //     `stride` is `body+33` where body ≤ `relay.minmtu`; the
        //     PMTU machinery set `minmtu` from probe replies, so
        //     `stride` fits. EMSGSIZE here means PMTU shrank mid-
        //     flight (rare; the daemon's `on_emsgsize` shrinks
        //     `maxmtu` and the next batch is smaller).
        //   - `count ≤ UDP_MAX_SEGMENTS = 128` else `EINVAL`.
        //     `DEVICE_DRAIN_CAP = 64` caps it; the daemon never
        //     builds a batch wider than one drain pass.
        //   - `sk_no_check_tx == 0`. We never set `SO_NO_CHECK`.

        // `EgressBatch::dst` is a `socket2::SockAddr` (cached on the
        // hot path). nix wants a `SockaddrLike`; round-trip via
        // `std::net::SocketAddr` — UDP egress is always IP, so
        // `as_socket()` is `Some`. Stack-only, no alloc.
        let dst = SockaddrStorage::from(
            b.dst
                .as_socket()
                .expect("UDP egress destination is always an IP socket address"),
        );

        let iov = [IoSlice::new(b.frames)];
        let cmsg = [ControlMessage::UdpGsoSegments(&b.stride)];

        // `flags=0`: the socket is already non-blocking; EWOULDBLOCK
        // surfaces as `Errno::EAGAIN`.
        if let Err(e) = sendmsg(
            self.sock.as_raw_fd(),
            &iov,
            &cmsg,
            MsgFlags::empty(),
            Some(&dst),
        ) {
            // ENOPROTOOPT: kernel <4.18, doesn't recognize
            // UDP_SEGMENT. Deployment policy excludes this; panic
            // with a clear message rather than silently dropping.
            // The throughput gate would eventually flag it but the
            // failure is loud enough to halt on.
            assert_ne!(
                e,
                Errno::ENOPROTOOPT,
                "kernel rejects UDP_SEGMENT cmsg (requires Linux ≥4.18; \
                 no Linux fallback ladder)"
            );
            return Err(e.into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use socket2::SockAddr;
    use std::net::UdpSocket;

    /// `Fast::send_batch` with `count=1` is one plain `sendto` (no
    /// cmsg). Same wire bytes as `Portable`. The seam is transparent
    /// at `count=1` — the `linux::Fast` swap doesn't change ICMP/ARP/
    /// control-frame behaviour.
    #[test]
    fn fast_count_1_is_plain_sendto() {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let rx_addr = rx.local_addr().unwrap();
        let tx: Socket = UdpSocket::bind("127.0.0.1:0").unwrap().into();
        let mut f = Fast::new(&tx).unwrap();

        let payload = b"one frame, no GSO";
        let dst = SockAddr::from(rx_addr);
        #[expect(clippy::cast_possible_truncation)] // test payload is 17 bytes
        let len = payload.len() as u16;
        f.send_batch(&EgressBatch {
            dst: &dst,
            frames: payload,
            stride: len,
            count: 1,
            last_len: len,
        })
        .unwrap();

        let mut buf = [0u8; 64];
        let (n, _) = rx.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], payload);
    }

    /// One `sendmsg` with `UDP_SEGMENT` cmsg produces N datagrams.
    /// Hits the real kernel GSO path
    /// (`udp_send_skb` → `__udp_gso_segment`); loopback has no NIC
    /// USO so this exercises the SOFTWARE split, which is the path
    /// most deployments hit anyway.
    ///
    /// Asserts: 3 datagrams arrive, in order, with correct payloads.
    /// The kernel split at `stride` boundaries, so each datagram is
    /// exactly the slice we packed.
    #[test]
    fn fast_gso_splits_at_stride() {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let rx_addr = rx.local_addr().unwrap();
        let tx: Socket = UdpSocket::bind("127.0.0.1:0").unwrap().into();
        let mut f = Fast::new(&tx).unwrap();

        // Dense-packed: 3 frames at stride=10, last is full-size
        // (the simple case; short-tail tested separately).
        let mut frames = [0u8; 30];
        frames[0..10].copy_from_slice(b"AAAAAAAAAA");
        frames[10..20].copy_from_slice(b"BBBBBBBBBB");
        frames[20..30].copy_from_slice(b"CCCCCCCCCC");

        let dst = SockAddr::from(rx_addr);
        f.send_batch(&EgressBatch {
            dst: &dst,
            frames: &frames,
            stride: 10,
            count: 3,
            last_len: 10,
        })
        .unwrap();

        // Loopback preserves order. Three datagrams, each the slice
        // the kernel cut.
        let mut buf = [0u8; 64];
        let (n, _) = rx.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"AAAAAAAAAA");
        let (n, _) = rx.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"BBBBBBBBBB");
        let (n, _) = rx.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"CCCCCCCCCC");
    }

    /// Short trailing segment (`last_len < stride`). Willem's commit
    /// msg (`bec1f6f69736`): "If not an exact multiple of segment
    /// size, the last segment will be shorter." The TCP-ACK-after-
    /// burst case.
    #[test]
    fn fast_gso_short_tail() {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let rx_addr = rx.local_addr().unwrap();
        let tx: Socket = UdpSocket::bind("127.0.0.1:0").unwrap().into();
        let mut f = Fast::new(&tx).unwrap();

        // 2 full frames at stride=10, 1 short at 7. Dense: 27 bytes.
        let mut frames = [0u8; 27];
        frames[0..10].copy_from_slice(b"0123456789");
        frames[10..20].copy_from_slice(b"abcdefghij");
        frames[20..27].copy_from_slice(b"SHORT!!");

        let dst = SockAddr::from(rx_addr);
        f.send_batch(&EgressBatch {
            dst: &dst,
            frames: &frames,
            stride: 10,
            count: 3,
            last_len: 7,
        })
        .unwrap();

        let mut buf = [0u8; 64];
        let (n, _) = rx.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"0123456789");
        let (n, _) = rx.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"abcdefghij");
        let (n, _) = rx.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"SHORT!!");
    }

    /// `Fast` → `Portable` wire equivalence. Same `EgressBatch`, two
    /// impls, two listeners, byte-identical results. This is the
    /// wire-equivalence invariant: the receiver can't tell which
    /// egress sent the batch. If this fails, `linux::Fast` changed
    /// semantics
    /// and the netns integration tests are suspect.
    #[test]
    fn fast_matches_portable_on_wire() {
        let rx_f = UdpSocket::bind("127.0.0.1:0").unwrap();
        let rx_p = UdpSocket::bind("127.0.0.1:0").unwrap();
        let tx: Socket = UdpSocket::bind("127.0.0.1:0").unwrap().into();
        let mut fast = Fast::new(&tx).unwrap();
        let mut portable = super::super::Portable::new(&tx).unwrap();

        // 4 frames, stride=13, last short at 5. Non-power-of-2
        // stride to catch any alignment assumption.
        let mut frames = [0u8; 13 * 3 + 5];
        for (i, b) in frames.iter_mut().enumerate() {
            #[expect(clippy::cast_possible_truncation)] // i < frames.len()=44, fits u8
            {
                *b = i as u8;
            }
        }

        let dst_f = SockAddr::from(rx_f.local_addr().unwrap());
        let dst_p = SockAddr::from(rx_p.local_addr().unwrap());
        for (egress, dst) in [
            (&mut fast as &mut dyn UdpEgress, &dst_f),
            (&mut portable as &mut dyn UdpEgress, &dst_p),
        ] {
            egress
                .send_batch(&EgressBatch {
                    dst,
                    frames: &frames,
                    stride: 13,
                    count: 4,
                    last_len: 5,
                })
                .unwrap();
        }

        // Both listeners see the same 4 datagrams in the same order
        // with the same bytes.
        let mut bf = [0u8; 64];
        let mut bp = [0u8; 64];
        for _ in 0..4 {
            let (nf, _) = rx_f.recv_from(&mut bf).unwrap();
            let (np, _) = rx_p.recv_from(&mut bp).unwrap();
            assert_eq!(&bf[..nf], &bp[..np]);
        }
    }

    /// Stride changes between batches: ship batch A at stride=8,
    /// then batch B at stride=12; both split correctly. Guards
    /// against any per-`Fast` state accidentally carrying `gso_size`
    /// across calls.
    #[test]
    fn fast_gso_stride_changes() {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let dst = SockAddr::from(rx.local_addr().unwrap());
        let tx: Socket = UdpSocket::bind("127.0.0.1:0").unwrap().into();
        let mut f = Fast::new(&tx).unwrap();

        // Batch A: 2 × 8 bytes.
        f.send_batch(&EgressBatch {
            dst: &dst,
            frames: b"AAAAAAAAaaaaaaaa",
            stride: 8,
            count: 2,
            last_len: 8,
        })
        .unwrap();
        // Batch B: 2 × 12 bytes. If the cmsg still says gso_size=8,
        // the kernel splits this into 3 datagrams (12+12 / 8 = 3),
        // not 2, and the third is 8 bytes of the second frame's tail.
        f.send_batch(&EgressBatch {
            dst: &dst,
            frames: b"BBBBBBBBBBBBbbbbbbbbbbbb",
            stride: 12,
            count: 2,
            last_len: 12,
        })
        .unwrap();

        let mut buf = [0u8; 64];
        let (n, _) = rx.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"AAAAAAAA");
        let (n, _) = rx.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"aaaaaaaa");
        let (n, _) = rx.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"BBBBBBBBBBBB"); // 12, not 8
        let (n, _) = rx.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"bbbbbbbbbbbb");
        // No fifth datagram (would be the wrong-stride symptom).
        rx.set_nonblocking(true).unwrap();
        assert_eq!(
            rx.recv_from(&mut buf).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
}
