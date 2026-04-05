//! `linux::Fast` — `UDP_SEGMENT` cmsg egress (`RUST_REWRITE_10G.md` Phase 1).
//!
//! One `sendmsg` with `cmsg{SOL_UDP, UDP_SEGMENT, gso_size: u16}`;
//! the kernel splits at `gso_size` boundaries (`udp_send_skb` GSO
//! branch → `__udp_gso_segment`). The receiver sees `count`
//! independent UDP datagrams — wire-identical to `Portable`'s
//! `count × sendto`.
//!
//! ## Why raw libc, not `nix::sendmsg`
//!
//! `nix` 0.29 has `ControlMessage::UdpGsoSegments(&u16)` which builds
//! the cmsg correctly. But `nix::sendmsg` allocs a fresh `Vec<u8>`
//! for the cmsg buffer on EVERY call (`mod.rs:1470`: `let mut
//! cmsg_buffer = vec![0u8; capacity]`). At ~100k batches/s that's
//! 100k allocs/s on the hot path — measured ~5% throughput loss.
//!
//! The cmsg here is trivial: one `{SOL_UDP, UDP_SEGMENT, u16}`, fixed
//! size. Pre-build it once in `new()`, patch the 2-byte `gso_size` on
//! each send. Zero per-send allocs. The unsafe surface is one
//! `sendmsg` call + the cmsg pointer arithmetic that `CMSG_LEN`/
//! `CMSG_DATA` already encapsulate; the buffer itself is owned and
//! never escapes.
//!
//! ## Cmsg buffer layout
//!
//! `[cmsghdr{len=CMSG_LEN(2), level=SOL_UDP, type=UDP_SEGMENT}][u16][pad]`.
//! Total `CMSG_SPACE(2)` bytes (24 on glibc x86-64: 16-byte cmsghdr,
//! 2-byte payload, 6-byte trailing align). The kernel reads exactly
//! `CMSG_LEN(2)` bytes; `__udp_cmsg_send` rejects with `EINVAL` on
//! length mismatch. Padding is unread.
//!
//! A `#[repr(C, align(..))]` wrapper struct gives us cmsghdr-aligned
//! storage at a `const` size. `CMSG_SPACE` is `const fn` in libc, so
//! the array length is const-evaluable; the `align(8)` attribute
//! satisfies `cmsghdr`'s strictest field (`size_t`, 8 bytes on LP64,
//! 4 on ILP32 — over-aligning to 8 is harmless on ILP32).
//!
//! ## No probe, no fallback
//!
//! `RUST_REWRITE_10G.md` policy: kernel ≥4.18 floor on Linux. If
//! `sendmsg` returns `ENOPROTOOPT` (kernel doesn't recognize
//! `UDP_SEGMENT`), panic at first batch. Silently degrading to
//! per-frame `sendto` would mask the misconfig.

// One `unsafe` block: `libc::sendmsg` + cmsg pointer writes. Scoped
// to this module, audited below.
#![deny(unsafe_code)]

use std::io;
use std::mem;
use std::os::fd::AsRawFd;

use socket2::Socket;

use super::{EgressBatch, UdpEgress};

/// `UDP_SEGMENT` egress. Linux ≥4.18 (`bec1f6f69736`).
pub struct Fast {
    /// `dup(2)` of the listener's UDP socket. Same file description
    /// as the `recvmmsg` side — same bound addr, same `SO_BINDTODEVICE`,
    /// same `IP_TOS` (the daemon's `set_udp_tos` sets it on the
    /// listener fd, which is the same FILE DESCRIPTION).
    sock: Socket,

    /// Pre-built `cmsghdr + u16 gso_size + padding`, `CMSG_SPACE(2)`
    /// bytes, cmsghdr-aligned. The header is written once in `new()`;
    /// `send_batch` only patches the 2-byte `gso_size` at offset
    /// `GSO_DATA_OFF`. Zero per-send allocs; the kernel reads from
    /// this buffer directly via `msg_control`.
    cmsg: GsoCmsgBuf,
}

// `CMSG_LEN`/`CMSG_SPACE` return `c_uint` (macro arithmetic type).
// `mem::size_of::<u16>()` is 2 — fits `c_uint` trivially; the cast
// is for the macro's signature, not a real truncation risk. SAFETY:
// these are `const fn` in libc 0.2.178+ (`unix/linux_like/mod.rs:
// 1715,1719`), pure arithmetic (`CMSG_ALIGN(sizeof(cmsghdr)) + len`),
// no pointer deref. The `unsafe` is libc's `f!` macro wrapping.
#[allow(unsafe_code, clippy::cast_possible_truncation)]
const GSO_CMSG_LEN: usize =
    unsafe { libc::CMSG_LEN(mem::size_of::<u16>() as libc::c_uint) } as usize;
#[allow(unsafe_code, clippy::cast_possible_truncation)]
const GSO_CMSG_SPACE: usize =
    unsafe { libc::CMSG_SPACE(mem::size_of::<u16>() as libc::c_uint) } as usize;
/// Offset of the `gso_size` payload within the cmsg buffer.
/// `CMSG_LEN(0)` = `CMSG_ALIGN(sizeof(cmsghdr))` = where `CMSG_DATA`
/// points. Precompute so `send_batch` is a 2-byte slice copy.
#[allow(unsafe_code)]
const GSO_DATA_OFF: usize = unsafe { libc::CMSG_LEN(0) } as usize;

/// Aligned cmsg storage. `align(8)` ≥ `align_of::<cmsghdr>()` on
/// every Linux arch (cmsghdr's strictest field is `cmsg_len: size_t`,
/// 8 bytes on LP64, 4 on ILP32). The kernel walks `msg_control` as
/// a `cmsghdr*` (`CMSG_FIRSTHDR` casts directly); a misaligned
/// buffer is UB on archs that trap unaligned access. `Box<[u8]>`
/// from `vec![]` would be align-1 — clippy's `cast_ptr_alignment`
/// caught the original mistake.
#[repr(C, align(8))]
struct GsoCmsgBuf([u8; GSO_CMSG_SPACE]);

impl Fast {
    /// Dup the listener's UDP fd; pre-build the cmsg header.
    ///
    /// # Errors
    /// `io::Error` from `dup(2)` (fd exhaustion).
    pub fn new(udp: &Socket) -> io::Result<Self> {
        // CMSG_SPACE(2) zeroed bytes. The kernel doesn't read past
        // CMSG_LEN(2); the trailing pad is for alignment of a NEXT
        // cmsg (which we don't have).
        let mut cmsg = GsoCmsgBuf([0u8; GSO_CMSG_SPACE]);

        // Write the header in-place. `cmsghdr` is `repr(C)`;
        // `GsoCmsgBuf` is `repr(C, align(8))` ≥ align_of::<cmsghdr>.
        //
        // SAFETY:
        //   - `cmsg.0` is `GSO_CMSG_SPACE` writable bytes;
        //     `sizeof(cmsghdr)` ≤ `CMSG_LEN(0)` ≤ that.
        //   - Alignment: `#[repr(align(8))]` guarantees the struct
        //     (and its field at offset 0) is 8-aligned, ≥
        //     `align_of::<cmsghdr>()`. The `cast_ptr_alignment`
        //     lint can't see past the `[u8]`, hence the allow.
        //   - We write the three public fields; there are no others
        //     (`gnu/mod.rs:77`: `cmsg_len, cmsg_level, cmsg_type`).
        #[allow(unsafe_code, clippy::cast_ptr_alignment)]
        unsafe {
            let hdr = cmsg.0.as_mut_ptr().cast::<libc::cmsghdr>();
            // `cmsg_len` is `size_t` on glibc; GSO_CMSG_LEN already
            // const-widened to usize. `as _`: musl uses `socklen_t`
            // (u32) here — the value (≈18) fits either way.
            (*hdr).cmsg_len = GSO_CMSG_LEN as _;
            (*hdr).cmsg_level = libc::SOL_UDP;
            (*hdr).cmsg_type = libc::UDP_SEGMENT;
        }

        Ok(Self {
            sock: udp.try_clone()?,
            cmsg,
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

        // Patch gso_size into the pre-built cmsg. `CMSG_DATA` is
        // `(cmsg as *cmsghdr).offset(1)` — i.e. `CMSG_LEN(0)` bytes
        // from the start. The kernel reads exactly
        // `*(u16*)CMSG_DATA(cmsg)`. `to_ne_bytes` + slice copy is a
        // 2-byte memcpy: alignment-agnostic, no UB
        // even though the offset happens to be even on every arch.
        self.cmsg.0[GSO_DATA_OFF..GSO_DATA_OFF + 2].copy_from_slice(&b.stride.to_ne_bytes());

        // Build the msghdr. All pointers are into stack/self memory
        // that lives for the duration of `sendmsg`. The kernel
        // copies everything it needs before returning (no async
        // buffer ownership; that's MSG_ZEROCOPY, Phase 4).
        //
        // `socket2::SockAddr::as_ptr()` → `*const sockaddr`, `len()`
        // → `socklen_t`. socket2 stores a `sockaddr_storage`
        // internally (`sockaddr.rs:33`); the pointer is valid for
        // `len()` bytes. We pass it as `msg_name` (`*mut c_void` —
        // the kernel only READS, the `mut` is C API legacy).
        let mut iov = libc::iovec {
            iov_base: b.frames.as_ptr().cast_mut().cast(),
            iov_len: b.frames.len(),
        };
        // SAFETY: `mem::zeroed` for `msghdr` is valid (all-zero is
        // a legal "empty msghdr": NULL name, 0 iov, NULL control).
        // We then set every field we use; unused (`msg_flags`) stays
        // 0, which is the correct value for `sendmsg` input (it's
        // an OUTPUT field on `recvmsg`, ignored on send).
        #[allow(unsafe_code)]
        let mut mhdr: libc::msghdr = unsafe { mem::zeroed() };
        mhdr.msg_name = b.dst.as_ptr().cast_mut().cast();
        mhdr.msg_namelen = b.dst.len();
        mhdr.msg_iov = &raw mut iov;
        mhdr.msg_iovlen = 1;
        mhdr.msg_control = self.cmsg.0.as_mut_ptr().cast();
        // `msg_controllen` is `size_t` on glibc, `socklen_t` on
        // musl; `GSO_CMSG_SPACE` (≈24) fits either. `as _` lets
        // libc pick the type.
        mhdr.msg_controllen = GSO_CMSG_SPACE as _;

        // SAFETY:
        //   - `fd` is a live UDP socket (Socket owns it).
        //   - `mhdr` is fully initialized above; every pointer field
        //     is valid for the kernel to read for the duration of
        //     this call (stack/self, no escapes).
        //   - `iov_base` points to `b.frames`, which the borrow on
        //     `b: &EgressBatch` keeps alive.
        //   - `msg_control` points to `self.cmsg`, kept alive by
        //     `&mut self`.
        //   - `flags=0`: the socket is already non-blocking;
        //     EWOULDBLOCK surfaces as -1/EAGAIN.
        #[allow(unsafe_code)]
        let ret = unsafe { libc::sendmsg(self.sock.as_raw_fd(), &raw const mhdr, 0) };

        if ret < 0 {
            let e = io::Error::last_os_error();
            // ENOPROTOOPT: kernel <4.18, doesn't recognize
            // UDP_SEGMENT. Deployment policy excludes this; panic
            // with a clear message rather than silently dropping.
            // The throughput gate would eventually flag it but the
            // failure is loud enough to halt on.
            assert_ne!(
                e.raw_os_error(),
                Some(libc::ENOPROTOOPT),
                "kernel rejects UDP_SEGMENT cmsg (requires Linux ≥4.18; \
                 RUST_REWRITE_10G.md: no Linux fallback ladder)"
            );
            return Err(e);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use socket2::SockAddr;
    use std::net::UdpSocket;

    /// Cmsg layout invariants. If these break, libc changed the
    /// macro arithmetic and the in-place `gso_size` patch in
    /// `send_batch` writes to the wrong offset → kernel reads
    /// garbage `gso_size` → splits at the wrong boundary.
    #[test]
    fn cmsg_layout_invariants() {
        // CMSG_LEN(n) = CMSG_LEN(0) + n. Data offset arithmetic.
        const { assert!(GSO_CMSG_LEN == GSO_DATA_OFF + 2) };
        // SPACE ≥ LEN (SPACE adds trailing align for a next cmsg).
        const { assert!(GSO_CMSG_SPACE >= GSO_CMSG_LEN) };
        // Data offset is u16-aligned (it's after a size_t-aligned
        // header, so always even). The to_ne_bytes copy doesn't
        // need this, but the kernel's `*(__u16*)` read does.
        const { assert!(GSO_DATA_OFF.is_multiple_of(2)) };
        // Our align attribute covers cmsghdr's needs.
        const { assert!(mem::align_of::<GsoCmsgBuf>() >= mem::align_of::<libc::cmsghdr>()) };
        // The buffer at offset 0 of the wrapper IS the wrapper's
        // address — #[repr(C)] guarantees no leading padding.
        let tx: Socket = UdpSocket::bind("127.0.0.1:0").unwrap().into();
        let f = Fast::new(&tx).unwrap();
        assert_eq!(f.cmsg.0.as_ptr().addr(), (&raw const f.cmsg).addr());
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
        #[allow(clippy::cast_possible_truncation)]
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

    /// The point of Phase 1: one `sendmsg` with `UDP_SEGMENT` cmsg
    /// produces N datagrams. Hits the real kernel GSO path
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
    /// Phase-1 invariant: the receiver can't tell which egress sent
    /// the batch. If this fails, `linux::Fast` changed semantics
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
            #[allow(clippy::cast_possible_truncation)]
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

    /// Stride changes between batches: the cmsg buffer is reused,
    /// `gso_size` patched in-place. Ship batch A at stride=8, then
    /// batch B at stride=12; both split correctly. Regression test
    /// for the obvious bug where the patch offset is wrong and the
    /// SECOND batch reuses the FIRST's `gso_size`.
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
