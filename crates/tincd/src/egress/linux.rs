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
//! The kernel rejects GSO with `EIO` on xfrm routes and, before 6.11, on
//! devices without TX checksum offload, and with `ENOPROTOOPT` before
//! 4.18. Either latches this egress to per-frame sendto.

#![forbid(unsafe_code)]

use std::io;
use std::io::IoSlice;
use std::os::fd::{AsRawFd, RawFd};

use nix::errno::Errno;
use nix::sys::socket::{ControlMessage, MsgFlags, SockaddrStorage, sendmsg};
use socket2::Socket;

use super::{EgressBatch, Portable, UdpEgress};

/// `UDP_SEGMENT` egress. Linux ≥4.18 (`bec1f6f69736`).
pub(crate) struct Fast {
    /// Per-frame sender over a dup of the listener's UDP socket, which
    /// shares its bound addr, `SO_BINDTODEVICE` and `IP_TOS`.
    fallback: Portable,
    gso_off: bool,
}

impl Fast {
    /// Dup the listener's UDP fd.
    ///
    /// # Errors
    /// `io::Error` from `dup(2)` (fd exhaustion).
    pub(crate) fn new(udp: &Socket) -> io::Result<Self> {
        Ok(Self {
            fallback: Portable::new(udp)?,
            gso_off: false,
        })
    }
}

impl UdpEgress for Fast {
    fn send_batch(&mut self, b: &EgressBatch<'_>) -> io::Result<()> {
        self.send_batch_with(b, |fd, iov, cmsg, dst| {
            sendmsg(fd, iov, cmsg, MsgFlags::empty(), Some(dst)).map(|_| ())
        })
    }
}

impl Fast {
    fn send_batch_with<F>(&mut self, b: &EgressBatch<'_>, submit: F) -> io::Result<()>
    where
        F: FnOnce(
            RawFd,
            &[IoSlice<'_>],
            &[ControlMessage<'_>],
            &SockaddrStorage,
        ) -> nix::Result<()>,
    {
        // count=1: the kernel's GSO branch only fires for `datalen > gso_size`
        // anyway, and this is the common case.
        if b.count == 1 || self.gso_off {
            return self.fallback.send_batch(b);
        }

        // One iovec over the dense run, split by the kernel at `b.stride`.
        // `b.frames` is exactly `(count-1)*stride + last_len` with no gaps.
        // EMSGSIZE means the PMTU shrank mid-flight and `on_emsgsize` handles it.
        let dst = SockaddrStorage::from(
            b.dst
                .as_socket()
                .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?,
        );
        let iov = [IoSlice::new(b.frames)];
        let cmsg = [ControlMessage::UdpGsoSegments(&b.stride)];
        match submit(self.fallback.sock().as_raw_fd(), &iov, &cmsg, &dst) {
            Ok(()) => Ok(()),
            Err(Errno::EIO | Errno::ENOPROTOOPT) => {
                log::info!(target: "tincd::net", "UDP GSO unsupported here, sending per frame");
                self.gso_off = true;
                self.fallback.send_batch(b)
            }
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::Portable;
    use super::*;
    use socket2::SockAddr;
    use std::net::UdpSocket;
    use std::time::Duration;

    /// GSO `EIO` resends the run per frame and latches GSO off.
    #[test]
    fn gso_eio_latches_per_frame() {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        rx.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let tx: Socket = UdpSocket::bind("127.0.0.1:0").unwrap().into();
        let mut f = Fast::new(&tx).unwrap();
        let dst = SockAddr::from(rx.local_addr().unwrap());
        let b = EgressBatch {
            dst: &dst,
            frames: b"aaaabb",
            stride: 4,
            count: 2,
            last_len: 2,
        };
        f.send_batch_with(&b, |_, _, _, _| Err(Errno::EIO)).unwrap();
        f.send_batch_with(&b, |_, _, _, _| panic!("GSO retried"))
            .unwrap();
        let mut buf = [0u8; 64];
        for want in [&b"aaaa"[..], b"bb", b"aaaa", b"bb"] {
            let (n, _) = rx.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..n], want);
        }
    }

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

    /// One `sendmsg` with `UDP_SEGMENT` yields N datagrams via the kernel's
    /// software split (`__udp_gso_segment`; loopback has no USO, like most
    /// deployments). Asserts 3 arrive in order, each exactly the slice packed.
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
        let mut portable = Portable::new(&tx).unwrap();

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
