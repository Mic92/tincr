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

// Not `forbid`: the `linux` submodule needs one `unsafe` block for
// `libc::sendmsg` + cmsg pointer writes (nix::sendmsg allocs a Vec
// per call, ~5% throughput loss on the hot path). The `Portable`
// impl and `TxBatch` below are still pure-safe; the `deny` makes
// any new unsafe a compile error unless `#[allow]`'d at the site.
#![deny(unsafe_code)]

use std::io;

use socket2::{SockAddr, Socket};

#[cfg(target_os = "linux")]
pub mod linux;

/// `UDP_MAX_SEGMENTS` (`include/linux/udp.h:124`). The kernel rejects
/// `UDP_SEGMENT` sends with more segments than this (`EINVAL`).
/// The daemon's `DEVICE_DRAIN_CAP=64` is well under;
/// this is here for the `can_coalesce` check so a future cap bump
/// doesn't silently overflow the kernel limit.
pub const UDP_MAX_SEGMENTS: u16 = 128;

/// `udp_sendmsg` rejects `len > 0xFFFF` with `EMSGSIZE` BEFORE the
/// GSO branch even runs — this is the UDP datagram-length field cap, not a path-MTU thing. The cmsg parse
/// happens AFTER, so the kernel never learns we wanted GSO; it just
/// sees a too-big plain send. The daemon's `EMSGSIZE` handler then
/// shrinks PMTU thinking it's a path-MTU failure → death spiral.
/// `can_coalesce` must cap below this. Conservative: leave headroom
/// for the outer UDP+IP headers (28 bytes IPv4, 48 IPv6) the kernel
/// adds to `len` before the comparison. (Willem's `UDP_SEGMENT` design
/// expects ~64 KB super-packets; the practical cap is here, not the
/// 128-segment one.)
const BATCH_MAX_BYTES: usize = 0xFFFF - 48;

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

/// TX batch accumulator. Phase 1: the daemon stages encrypted frames
/// here during the `on_device_read` drain loop, then ships the run
/// in one `EgressBatch` after the loop. The "no TX batch exists
/// today" problem from `mt-crypto-findings.md` Finding 1 — this is
/// CREATING the batch.
///
/// ## Dense packing, not arena slots
///
/// Frames are appended at `[count*stride .. count*stride + len]`,
/// NOT at fixed STRIDE-sized slots. `UDP_SEGMENT` splits at
/// `gso_size` boundaries; a gap between frames
/// would land in the previous datagram's tail. The buffer IS the
/// wire layout.
///
/// `stride` is the encrypted-frame size of the FIRST frame in the
/// run. Subsequent frames must match (`can_coalesce` checks). The
/// SPTPS overhead is fixed (+33: `mt-kernel-findings.md`), so a TCP
/// burst at one MSS produces same-size encrypted frames.
///
/// ## One run at a time
///
/// Tailscale's `coalesceMessages` builds a `Vec<run>`; we keep ONE
/// run and flush on mismatch. Simpler, and the common case (iperf3
/// TCP burst to one peer) is one run anyway. Multi-peer interleave
/// degrades to per-change flushes — still fewer syscalls than per-
/// frame, never worse than Phase 0.
pub struct TxBatch {
    /// Dense-packed encrypted frames. Capacity sized for one drain
    /// pass at MTU+overhead; never reallocs after warmup.
    buf: Vec<u8>,
    /// Encrypted-frame size for THIS run. All frames except possibly
    /// the last are exactly this size. Set on first stage; checked
    /// on subsequent stages.
    stride: u16,
    /// Length of the most-recently-staged frame. ≤ `stride`. The
    /// kernel allows a short tail; we allow a short tail to be
    /// followed by a flush (a same-stride frame after a short one
    /// can't coalesce — it would land mid-stride).
    last_len: u16,
    /// Frames in `buf`. ≤ `UDP_MAX_SEGMENTS`.
    count: u16,
    /// Destination of this run. `None` when empty. `SockAddr` is
    /// `Clone` (`derive`, socket2 `sockaddr.rs:20`); cloning the
    /// tunnel's `udp_addr_cached` once per RUN (not per frame) is
    /// fine. We can't borrow it: the daemon mutates `tunnels`
    /// between stage calls.
    dst: Option<SockAddr>,
    /// Listener index (`ListenerSlot`). Paired with `dst`: same
    /// destination on a different listener (different bound addr)
    /// is a different run.
    sock: u8,
    /// The relay node whose `pmtu` shrinks on `EMSGSIZE`. Stored
    /// per-run so `flush` can call `on_emsgsize` without re-
    /// resolving the route. `tinc_graph::NodeId` is `Copy`.
    relay: tinc_graph::NodeId,
    /// Plaintext body length of the LARGEST frame in the run.
    /// `on_emsgsize` shrinks `maxmtu` to this (the kernel rejected
    /// at the OUTER size, but PMTU is tracked at the inner-body
    /// layer). All same-stride frames have the same body length
    /// (stride = body+33, fixed overhead) so this is just the
    /// first frame's body.
    origlen: u16,
}

impl TxBatch {
    /// New, empty. `cap_bytes` should be `DEVICE_DRAIN_CAP ×
    /// (MTU + overhead)` so the buffer never reallocs after the
    /// first batch.
    #[must_use]
    pub fn new(cap_bytes: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap_bytes),
            stride: 0,
            last_len: 0,
            count: 0,
            dst: None,
            sock: 0,
            relay: tinc_graph::NodeId(0),
            origlen: 0,
        }
    }

    /// True if `frame` (encrypted, with the 12-byte ID prefix) can
    /// extend the current run. Same dst, same sock, same stride,
    /// previous frame was full-stride (a short tail ends the run —
    /// the kernel's split-at-stride math expects only the LAST
    /// segment short), and under the kernel cap.
    #[must_use]
    pub fn can_coalesce(&self, dst: &SockAddr, sock: u8, frame_len: usize) -> bool {
        // Empty run coalesces with anything (it BECOMES the run).
        if self.count == 0 {
            return true;
        }
        // u16: frame_len ≤ MTU+33 < 65535. Checked by caller.
        let Ok(frame_len) = u16::try_from(frame_len) else {
            return false; // > 64KB can't be a single UDP datagram
        };
        self.sock == sock
            && self.count < UDP_MAX_SEGMENTS
            // Total bytes after this stage ≤ the UDP datagram cap.
            // `udp_sendmsg` rejects `len > 0xFFFF` BEFORE the GSO
            // cmsg parse — it sees the whole iovec as
            // one too-big plain send. At MTU≈1500 + 33 overhead this
            // caps batches at ~43 frames; the "43 same-MSS segments"
            // from `mt-kernel-findings.md` fit exactly (not a
            // coincidence: 64KB / MSS ≈ 43 is HOW the inner-TCP
            // burst was sized in the first place).
            && self.buf.len() + usize::from(frame_len) <= BATCH_MAX_BYTES
            // Short tail already staged: run is closed. The kernel
            // splits at stride; a short frame followed by a full
            // one would put the full one's head in the short one's
            // datagram.
            && self.last_len == self.stride
            // Same encrypted size OR smaller (becomes the new tail).
            // Larger can't coalesce: it would span two stride slots.
            && frame_len <= self.stride
            // SockAddr PartialEq compares storage bytes (socket2
            // `sockaddr.rs:379`). Same peer, same family, same port
            // → same bytes.
            && self.dst.as_ref() == Some(dst)
    }

    /// Append `frame` to the run. Caller MUST have checked
    /// `can_coalesce` (or this is the first frame). Stores the
    /// per-run metadata (`dst`/`sock`/`relay`/`origlen`) on first
    /// stage; subsequent stages only append.
    ///
    /// # Panics
    /// Debug-asserts the `can_coalesce` precondition.
    pub fn stage(
        &mut self,
        dst: &SockAddr,
        sock: u8,
        relay: tinc_graph::NodeId,
        origlen: u16,
        frame: &[u8],
    ) {
        debug_assert!(self.can_coalesce(dst, sock, frame.len()));
        #[allow(clippy::cast_possible_truncation)] // ≤ MTU+33
        let frame_len = frame.len() as u16;
        if self.count == 0 {
            // First frame defines the run.
            self.buf.clear();
            self.stride = frame_len;
            self.dst = Some(dst.clone());
            self.sock = sock;
            self.relay = relay;
            self.origlen = origlen;
        }
        self.buf.extend_from_slice(frame);
        self.last_len = frame_len;
        self.count += 1;
    }

    /// Consume the run as an `EgressBatch`. `None` if empty.
    /// Resets to empty (next `stage` starts a fresh run).
    ///
    /// Returns `(batch, sock, relay, origlen)` — the egress sends
    /// `batch`; the daemon's error handler needs the rest for
    /// `EMSGSIZE` → `pmtu.on_emsgsize(origlen)`.
    #[must_use]
    pub fn take(&mut self) -> Option<(EgressBatch<'_>, u8, tinc_graph::NodeId, u16)> {
        if self.count == 0 {
            return None;
        }
        let dst = self.dst.as_ref()?; // Some by construction
        let batch = EgressBatch {
            dst,
            frames: &self.buf,
            stride: self.stride,
            count: self.count,
            last_len: self.last_len,
        };
        let sock = self.sock;
        let relay = self.relay;
        let origlen = self.origlen;
        // Reset BEFORE returning the borrow would conflict; but the
        // batch borrows `self.buf` and `self.dst`. So: caller drops
        // the batch, THEN calls `reset`. Two-step.
        Some((batch, sock, relay, origlen))
    }

    /// Reset to empty. Call after `take()`'s borrow is dropped.
    /// Keeps `buf` capacity (the whole point: warm reuse).
    pub const fn reset(&mut self) {
        self.count = 0;
        self.dst = None;
        // buf cleared on next stage's count==0 branch; no need here.
    }

    /// Count of staged frames. For the daemon's "did anything
    /// stage?" check.
    #[must_use]
    pub const fn count(&self) -> u16 {
        self.count
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
    /// portable fallback while debugging `UDP_SEGMENT`.
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

    /// `TxBatch::can_coalesce`: empty batch accepts anything;
    /// same-dst-same-stride extends; mismatch on any of dst/sock/
    /// stride/short-tail closes the run. This is the grouping
    /// invariant the GSO send depends on — if `can_coalesce` says
    /// yes when it shouldn't, the kernel splits at the wrong
    /// boundary and the wire is garbage.
    #[test]
    fn txbatch_coalesce_gates() {
        use tinc_graph::NodeId;
        let dst1 = SockAddr::from("127.0.0.1:1111".parse::<SocketAddr>().unwrap());
        let dst2 = SockAddr::from("127.0.0.1:2222".parse::<SocketAddr>().unwrap());
        let mut b = TxBatch::new(4096);

        // Empty: accepts anything.
        assert!(b.can_coalesce(&dst1, 0, 100));
        assert!(b.can_coalesce(&dst2, 7, 9999));

        // Stage one frame at stride=100.
        b.stage(&dst1, 0, NodeId(1), 67, &[0xAA; 100]);
        assert_eq!(b.count(), 1);

        // Same dst, same sock, same size: extends.
        assert!(b.can_coalesce(&dst1, 0, 100));
        // Different dst: closes.
        assert!(!b.can_coalesce(&dst2, 0, 100));
        // Different sock: closes.
        assert!(!b.can_coalesce(&dst1, 1, 100));
        // Larger frame: closes (would span two stride slots).
        assert!(!b.can_coalesce(&dst1, 0, 101));
        // Smaller frame: extends as the short tail.
        assert!(b.can_coalesce(&dst1, 0, 50));

        // Stage the short tail.
        b.stage(&dst1, 0, NodeId(1), 17, &[0xBB; 50]);
        assert_eq!(b.count(), 2);
        // After a short tail, NOTHING coalesces — even same-stride.
        // The kernel's split-at-stride math expects only the LAST
        // segment short.
        assert!(!b.can_coalesce(&dst1, 0, 100));
        assert!(!b.can_coalesce(&dst1, 0, 50));
    }

    /// `TxBatch::take` produces a dense-packed `EgressBatch`. The
    /// `frames` slice is exactly `(count-1)*stride + last_len` bytes,
    /// no gaps. Ship it through `Portable` to a real listener; the
    /// datagrams that arrive are byte-identical to what staged. This
    /// is the end-to-end "batch construction → wire" check.
    #[test]
    fn txbatch_dense_packing_roundtrip() {
        use tinc_graph::NodeId;
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let dst = SockAddr::from(rx.local_addr().unwrap());
        let tx: Socket = UdpSocket::bind("127.0.0.1:0").unwrap().into();
        let mut p = Portable::new(&tx).unwrap();

        let mut b = TxBatch::new(4096);
        // 3 frames: two at stride=12, one short at 5. Distinct
        // bytes per-frame so we can match them on the rx side.
        b.stage(&dst, 0, NodeId(1), 0, b"frame_one_12");
        b.stage(&dst, 0, NodeId(1), 0, b"frame_two_12");
        b.stage(&dst, 0, NodeId(1), 0, b"short");

        let (batch, sock, relay, _origlen) = b.take().unwrap();
        assert_eq!(sock, 0);
        assert_eq!(relay, NodeId(1));
        assert_eq!(batch.count, 3);
        assert_eq!(batch.stride, 12);
        assert_eq!(batch.last_len, 5);
        // Dense: 12 + 12 + 5 = 29, NOT 3×12.
        assert_eq!(batch.frames.len(), 29);

        p.send_batch(&batch).unwrap();
        // batch borrows b.buf; let it fall out of scope before reset.
        let _ = batch;
        b.reset();
        assert_eq!(b.count(), 0);

        let mut buf = [0u8; 64];
        let (n, _) = rx.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"frame_one_12");
        let (n, _) = rx.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"frame_two_12");
        let (n, _) = rx.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"short");
    }

    /// `BATCH_MAX_BYTES` cap: a 44th frame at stride=1519 (MTU+33,
    /// the SPTPS on-wire size for a full-MSS inner-TCP segment) does
    /// NOT coalesce — 43×1519 = 65317 fits the UDP datagram cap,
    /// 44×1519 = 66836 doesn't. The kernel rejects
    /// the latter with `EMSGSIZE` BEFORE the GSO cmsg parse, the
    /// daemon's PMTU machinery shrinks `maxmtu` thinking it's a
    /// path-MTU failure, and the next batch goes TCP. Regression
    /// test for the death-spiral the throughput gate caught.
    #[test]
    fn txbatch_caps_at_udp_datagram_limit() {
        use tinc_graph::NodeId;
        let dst = SockAddr::from("127.0.0.1:1".parse::<SocketAddr>().unwrap());
        let mut b = TxBatch::new(70_000);
        let frame = [0u8; 1519]; // body+33 for body=1486 (MSS-ish)

        // 43 fit (65317 ≤ 65487).
        for _ in 0..43 {
            assert!(b.can_coalesce(&dst, 0, frame.len()));
            b.stage(&dst, 0, NodeId(1), 1486, &frame);
        }
        assert_eq!(b.count(), 43);
        // 44th doesn't (66836 > 65487).
        assert!(!b.can_coalesce(&dst, 0, frame.len()));

        // The batch as built fits the cap.
        let (batch, ..) = b.take().unwrap();
        assert!(batch.frames.len() <= BATCH_MAX_BYTES);
    }

    /// `take` on empty returns None; `reset` is idempotent. The
    /// drain loop's final `flush_tx_batch` may see an empty batch
    /// (every frame went TCP, or got dropped pre-encrypt).
    #[test]
    fn txbatch_empty_take_is_none() {
        let mut b = TxBatch::new(64);
        assert!(b.take().is_none());
        b.reset();
        assert!(b.take().is_none());
        assert_eq!(b.count(), 0);
    }
}
