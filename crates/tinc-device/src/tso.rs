//! Userspace TSO split — `RUST_REWRITE_10G.md` Phase 2a.
//!
//! When `IFF_VNET_HDR + TUNSETOFFLOAD(TUN_F_TSO4|TUN_F_TSO6)` is set,
//! the kernel TCP stack stops segmenting at the TUN MTU. It hands us
//! one ≤64KB skb prefixed by a `virtio_net_hdr` describing the GSO
//! state. We split it back into MTU-sized TCP segments here.
//!
//! ## Reference: wireguard-go `tun/offload_linux.go:901` `gsoSplit`
//!
//! Ported carefully. The TCP seqno arithmetic, IPv4 ID++, and csum
//! recompute are byte-for-byte the same operations. Differences:
//!
//! - wg-go uses `IFF_NO_PI` and gets raw IP packets. We **also** use
//!   `IFF_NO_PI` on the `vnet_hdr` path (the kernel writes
//!   `[vnet_hdr][IP packet]` — no `tun_pi`, no eth header). But the
//!   *daemon* speaks ethernet frames internally (`route_packet` reads
//!   ethertype at byte 12). So `tso_split` writes a synthetic eth
//!   header into each output chunk, same as `fd.rs`/`bsd.rs` do for
//!   their no-PI paths. The IP-layer arithmetic is unchanged; we just
//!   prepend 14 bytes per chunk.
//!
//! - wg-go's checksum is unrolled 128-byte adc. We use a simpler
//!   2-byte loop. The bottleneck is `ChaCha20` (4.6µs/pkt), not the
//!   checksum (~0.02µs for a 20-byte IP header). Don't optimize what
//!   isn't hot.
//!
//! ## Why this lives in `tinc-device`, not `tincd`
//!
//! `RUST_REWRITE_10G.md` §"Design implication": same `virtio_net_hdr`
//! wire format on FreeBSD `TAPSVNETHDR`. Same input on Windows NDIS
//! LSO. One ~200 LOC function, three platforms.
//! Keep it next to `DrainResult::Super` (its consumer) and `ether.rs`
//! (its dependency for the synthetic header).
//!
//! ## What's NOT here
//!
//! - `VIRTIO_NET_HDR_GSO_UDP_L4` (USO, kernel 6.2+): we don't set
//!   `TUN_F_USO4/6`, so the kernel never hands it to us. The split
//!   itself is simpler than TCP (no seqno, just UDP length per chunk
//!   — wg-go `:965` is 3 lines). What's missing is the use case:
//!   inner-QUIC over tinc is a tunnel-in-tunnel scenario the project
//!   hasn't seen yet. The kernel-6.2 floor also rules out half the
//!   deploy targets. The hooks are here (`gso_type` enum has the
//!   slot, `tso_split` would gain a `proto == UDP` branch); ~+30 LOC
//!   when someone files the issue.
//! - `VIRTIO_NET_HDR_GSO_ECN`: we don't set `TUN_F_TSO_ECN`. wg-go
//!   doesn't either ("TODO: support TSO with ECN bits"). The kernel
//!   software-segments ECN flows; we just see them as `GSO_NONE`.

use crate::arena::GsoType;
use crate::ether::{ETH_HLEN, ETH_P_IP, ETH_P_IPV6, set_etherheader};

// ── virtio_net_hdr ─────────────────────────────────────────────────

/// `struct virtio_net_hdr` — `include/uapi/linux/virtio_net.h:222`.
/// 10 bytes. Prepended by `tun_put_user` (`tun.c:2064`) when
/// `IFF_VNET_HDR` is set.
///
/// ## Endianness
///
/// `__virtio16` fields use legacy virtio endianness: HOST-endian
/// (`tun_vnet.h:50` `tun_vnet_legacy_is_little_endian` =
/// `virtio_legacy_is_little_endian()` = the host's native order).
/// On LE hosts (x86_64, aarch64, riscv64 — every Linux target tinc
/// builds for) that's LE, so `from_le_bytes` reads correctly.
///
/// BE Linux targets that the kernel still supports: s390x, ppc64
/// (BE variant), and some embedded MIPS. On those, the kernel writes
/// BE u16s here AND `from_le_bytes` byte-swaps them → garbage. The
/// fix would be `from_ne_bytes` (matching the kernel's host-native
/// behavior), but that's untested and we don't have a BE CI runner.
/// Better to fail loudly than silently corrupt.
#[cfg(target_endian = "big")]
compile_error!("virtio_net_hdr endianness needs TUNSETVNETLE on BE hosts");

/// `sizeof(struct virtio_net_hdr)`. The kernel default `vnet_hdr_sz`
/// (`tun.c:2791`: `tun->vnet_hdr_sz = sizeof(struct virtio_net_hdr)`).
/// Can be raised via `TUNSETVNETHDRSZ` to 12 (`_mrg_rxbuf` variant,
/// for v1+hash); we don't.
pub const VNET_HDR_LEN: usize = 10;

/// `VIRTIO_NET_HDR_F_NEEDS_CSUM` — `virtio_net.h:153`. `flags` bit:
/// "the kernel left the L4 checksum partial (`CHECKSUM_PARTIAL` skb
/// state); compute it from `csum_start` and place at `csum_start +
/// csum_offset`". Set on every TSO frame (TSO implies csum offload).
/// Also set on `GSO_NONE` frames when the kernel TX path has csum
/// offload enabled — those need [`gso_none_checksum`].
const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 1;

/// `VIRTIO_NET_HDR_GSO_*` — `virtio_net.h:158-161`. `gso_type` values.
const VIRTIO_NET_HDR_GSO_NONE: u8 = 0;
const VIRTIO_NET_HDR_GSO_TCPV4: u8 = 1;
const VIRTIO_NET_HDR_GSO_TCPV6: u8 = 4;

/// Parsed `virtio_net_hdr`. The raw 10-byte struct, fields decoded
/// from LE. wg-go `virtioNetHdr` (`offload_linux.go:29`).
#[derive(Debug, Clone, Copy)]
pub struct VirtioNetHdr {
    /// `VIRTIO_NET_HDR_F_*` flags. We only act on `NEEDS_CSUM`.
    pub flags: u8,
    /// `VIRTIO_NET_HDR_GSO_*`. Mapped to [`GsoType`] by [`Self::gso`].
    pub gso_type: u8,
    /// IP header + TCP header length. **DON'T TRUST IT** — wg-go
    /// `tun_linux.go:417`: "can be equal to the length of the entire
    /// first packet when the kernel is handling it as part of a
    /// FORWARD path". Recompute from `csum_start` + parsed TCP hlen.
    /// We carry it for the `GSO_NONE` case (where it's correct).
    pub hdr_len: u16,
    /// MSS. Payload bytes per output segment.
    pub gso_size: u16,
    /// IP header length (offset of TCP/UDP header from start of IP
    /// packet). The kernel sets this from `skb->csum_start -
    /// skb_headroom` — it's the L4 header offset, which for TUN
    /// (no L2) equals IPHL.
    pub csum_start: u16,
    /// Offset WITHIN the L4 header where the checksum field sits.
    /// 16 for TCP (`tcphdr.th_sum`), 6 for UDP (`udphdr.uh_sum`).
    pub csum_offset: u16,
}

impl VirtioNetHdr {
    /// Decode the 10-byte header. wg-go `decode` (`:38`) does an
    /// `unsafe.Slice` memcpy; we read fields explicitly so the LE
    /// conversion is documented at the boundary.
    ///
    /// Returns `None` if `raw.len() < 10` — short read on a `vnet_hdr`
    /// device means the device is misconfigured (kernel always writes
    /// the full header). Caller drops the frame.
    #[must_use]
    pub fn decode(raw: &[u8]) -> Option<Self> {
        Self::decode_at(raw)
    }

    #[inline]
    fn decode_at(raw: &[u8]) -> Option<Self> {
        if raw.len() < VNET_HDR_LEN {
            return None;
        }
        Some(Self {
            flags: raw[0],
            gso_type: raw[1],
            hdr_len: u16::from_le_bytes([raw[2], raw[3]]),
            gso_size: u16::from_le_bytes([raw[4], raw[5]]),
            csum_start: u16::from_le_bytes([raw[6], raw[7]]),
            csum_offset: u16::from_le_bytes([raw[8], raw[9]]),
        })
    }

    /// Encode into a 10-byte buffer. wg-go `encode` (`:45`): an
    /// `unsafe.Slice` memcpy. We write fields explicitly so the LE
    /// encoding is documented at the boundary, mirroring [`decode`].
    /// Phase 2b GRO write path: this fills the slot that `1da3d1d7`
    /// left zeroed.
    ///
    /// # Panics
    /// Debug-asserts `buf.len() >= 10`. Callers slice the GRO
    /// scratch at a known offset; a short slice is a bug.
    pub fn encode(&self, buf: &mut [u8]) {
        debug_assert!(buf.len() >= VNET_HDR_LEN);
        buf[0] = self.flags;
        buf[1] = self.gso_type;
        buf[2..4].copy_from_slice(&self.hdr_len.to_le_bytes());
        buf[4..6].copy_from_slice(&self.gso_size.to_le_bytes());
        buf[6..8].copy_from_slice(&self.csum_start.to_le_bytes());
        buf[8..10].copy_from_slice(&self.csum_offset.to_le_bytes());
    }

    /// `gso_type` → our enum. `None` for unknown types (we only
    /// advertise TSO4/6, so the kernel should never hand us `UDP_L4`
    /// or ECN — but if it does, the caller falls back to `Frames`
    /// with one frame and lets `route_packet` deal with it).
    #[must_use]
    pub const fn gso(&self) -> Option<GsoType> {
        match self.gso_type {
            VIRTIO_NET_HDR_GSO_NONE => Some(GsoType::None),
            VIRTIO_NET_HDR_GSO_TCPV4 => Some(GsoType::TcpV4),
            VIRTIO_NET_HDR_GSO_TCPV6 => Some(GsoType::TcpV6),
            _ => None,
        }
    }

    /// `NEEDS_CSUM` flag check. Even `GSO_NONE` frames can have a
    /// partial checksum (the kernel's TX csum offload, separate from
    /// segmentation). [`gso_none_checksum`] completes it.
    #[must_use]
    pub const fn needs_csum(&self) -> bool {
        self.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM != 0
    }
}

// ── checksum ───────────────────────────────────────────────────────

/// RFC 1071 internet checksum, no fold. wg-go `checksumNoFold`
/// (`checksum.go:9`) — but without the 128-byte adc unroll.
///
/// At 20-byte IP headers and ~1500-byte TCP payloads, the simple
/// loop is ~0.5µs/pkt. Crypto is 4.6µs. The wg-go unroll uses
/// `bits.Add64` for explicit carry propagation — in Rust that's
/// `u64::carrying_add` (nightly) or manual `(sum, carry)` tuple
/// threading. The 8-byte-per-iteration loop with `u64::from_be_
/// bytes` reads + `wrapping_add` + post-hoc carry count would gain
/// ~0.3µs. Not nothing at 10G; not the bottleneck at 3G. Phase 3
/// par-encrypt amortizes crypto first; revisit checksum after.
///
/// `initial` is BIG-endian-interpreted (wg-go does a
/// `NativeEndian → BigEndian` swap on entry). We accumulate in BE
/// space throughout — `from_be_bytes` on each chunk, return value is
/// the BE-interpreted sum. The fold-and-complement in [`checksum`]
/// produces a host-order u16 that, when written via `to_be_bytes`,
/// puts the correct bytes on the wire.
#[inline]
fn checksum_nofold(data: &[u8], initial: u64) -> u64 {
    let mut sum = initial;
    let mut chunks = data.chunks_exact(2);
    for pair in &mut chunks {
        sum += u64::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    if let [tail] = chunks.remainder() {
        // RFC 1071 §4.1: tail byte is the HIGH byte of a zero-padded
        // 16-bit word. wg-go: `binary.NativeEndian.Uint16([b[0], 0])`
        // then byteswap → `b[0] << 8` in BE space.
        sum += u64::from(*tail) << 8;
    }
    sum
}

/// Fold 64→16 + complement. wg-go `checksum` (`checksum.go:86`).
/// Four folds is enough for `u64` (each fold halves the bit width
/// of the carry). The complement is the RFC 1071 one's-complement
/// final step.
#[inline]
fn checksum(data: &[u8], initial: u64) -> u16 {
    let mut ac = checksum_nofold(data, initial);
    ac = (ac >> 16) + (ac & 0xffff);
    ac = (ac >> 16) + (ac & 0xffff);
    ac = (ac >> 16) + (ac & 0xffff);
    ac = (ac >> 16) + (ac & 0xffff);
    #[allow(clippy::cast_possible_truncation)] // folded to 16 bits
    {
        !(ac as u16)
    }
}

/// TCP/UDP pseudo-header checksum. wg-go `pseudoHeaderChecksumNoFold`
/// (`checksum.go:95`). RFC 793 §3.1 / RFC 8200 §8.1: sum over
/// `src_addr ‖ dst_addr ‖ [0, protocol] ‖ tcp_length_BE`.
///
/// `addr_len`: 4 (IPv4) or 16 (IPv6). The slice `addrs` is `src_addr
/// ‖ dst_addr` straight from the IP header (they're adjacent in both
/// v4 and v6 — `ip_src`/`ip_dst` at bytes 12..20, `ip6_src`/`ip6_dst`
/// at bytes 8..40).
#[inline]
fn pseudo_header_checksum_nofold(proto: u8, addrs: &[u8], tcp_len: u16) -> u64 {
    let sum = checksum_nofold(addrs, 0);
    let sum = sum + u64::from(proto);
    sum + u64::from(tcp_len)
}

// ── tso_split ──────────────────────────────────────────────────────

// IP header field offsets. Same as `tincd::packet::Ipv4Hdr` layout
// but we work on raw byte slices here (no zerocopy dependency in
// tinc-device, and `tso_split` needs `&mut` access while iterating
// which the `#[repr(packed)]` accessor pattern doesn't give).

const IPV4_TOTLEN_OFF: usize = 2;
const IPV4_ID_OFF: usize = 4;
const IPV4_CSUM_OFF: usize = 10;
const IPV4_SRCADDR_OFF: usize = 12; // src+dst = 8 bytes

const IPV6_PLEN_OFF: usize = 4;
const IPV6_SRCADDR_OFF: usize = 8; // src+dst = 32 bytes

const TCP_SEQ_OFF: usize = 4;
const TCP_DATAOFF_OFF: usize = 12; // high nibble × 4 = header length
const TCP_FLAGS_OFF: usize = 13;
const TCP_CSUM_OFF: usize = 16;

const TCP_FLAG_FIN: u8 = 0x01;
const TCP_FLAG_PSH: u8 = 0x08;
const TCP_FLAG_ACK: u8 = 0x10;

const IPPROTO_TCP: u8 = 6;

/// What went wrong. All of these are kernel-contract violations
/// (the `vnet_hdr` describes a packet shape that doesn't match the
/// actual bytes) — log + drop, don't panic. wg-go returns `error`;
/// we map to a unit-per-variant enum so the daemon can log which one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TsoError {
    /// Packet shorter than `csum_start + 13` (can't read TCP hlen).
    /// wg-go: `"packet is too short"`.
    TooShort,
    /// TCP data offset < 5 or > 15 words. wg-go: `"tcp header len
    /// is invalid"`. Kernel never sets this (the TCP stack validates),
    /// but we don't trust the wire.
    BadTcpHlen,
    /// `csum_start + csum_offset` past end of packet. wg-go: `"end
    /// of checksum offset exceeds packet length"`.
    BadCsumOffset,
    /// IP version nibble doesn't match `gso_type`. wg-go: `"ip
    /// header version: %d, GSO type: %d"`. Shouldn't happen (the
    /// kernel knows what it's segmenting).
    IpVersionMismatch,
    /// Output scratch too small. With `DEVICE_DRAIN_CAP=64` slots
    /// at 1600 stride, 64KB / 1400 ≈ 47 segments fit. If `gso_size`
    /// is tiny (kernel can do 88-byte MSS for some PMTU edge cases),
    /// 64KB / 88 = 745 segments — we drop. wg-go: `ErrTooManySegments`.
    /// Mitigated: tinc's PMTU probe never returns < 590.
    TooManySegments,
}

/// `gsoNoneChecksum` (wg-go `offload_linux.go:985`). For `GSO_NONE`
/// frames with `NEEDS_CSUM` set: the kernel left the L4 checksum
/// half-done (it wrote the pseudo-header sum into the checksum field
/// as the "initial value", expecting hardware to finish). We finish.
///
/// `pkt` is the IP packet (NO eth header — this is called by `drain`
/// before the eth header is synthesized). Mutates in place.
pub fn gso_none_checksum(pkt: &mut [u8], csum_start: u16, csum_offset: u16) {
    let csum_at = usize::from(csum_start) + usize::from(csum_offset);
    if csum_at + 2 > pkt.len() {
        // Kernel-contract violation. Silently skip — the inner TCP
        // will see a bad checksum and retransmit. Better than
        // panicking the daemon on a malformed frame.
        return;
    }
    // The kernel wrote the pseudo-header checksum here as initial.
    let initial = u16::from_be_bytes([pkt[csum_at], pkt[csum_at + 1]]);
    pkt[csum_at] = 0;
    pkt[csum_at + 1] = 0;
    let sum = checksum(&pkt[usize::from(csum_start)..], u64::from(initial));
    pkt[csum_at..csum_at + 2].copy_from_slice(&sum.to_be_bytes());
}

/// Split a TCP super-segment. wg-go `gsoSplit` (`offload_linux.go:901`).
///
/// `pkt`: the IP packet from the device read, AFTER stripping the
/// 10-byte `vnet_hdr`. `[IP header][TCP header][≤64KB payload]`. NO
/// eth header (`vnet_hdr` device uses `IFF_NO_PI` and L3 mode).
///
/// `hdr`: the decoded `vnet_hdr`. `gso_type` MUST be `TcpV4` or `TcpV6`
/// (caller checks; we `debug_assert`).
///
/// `out`: scratch buffer for the segments. Each segment is written
/// at `out_stride * i`, length `ETH_HLEN + iphlen + tcphlen +
/// chunk_len`. `out_stride` MUST be ≥ `ETH_HLEN + hdr_len + gso_size`
/// (the largest segment). With `DeviceArena::STRIDE = 1600`, that's
/// `1600 - 14 - 60 = 1526` bytes of payload room — fine for any
/// `gso_size ≤ 1500`.
///
/// `lens`: per-segment length output. `lens[i]` is `out[i*stride..]`'s
/// valid length.
///
/// Returns the number of segments written.
///
/// # Errors
/// See [`TsoError`]. All variants indicate a malformed input or
/// undersized scratch — log + drop the super-segment.
#[allow(clippy::too_many_lines)] // wg-go's gsoSplit is ~90 LOC; this
// adds eth-header synthesis and the validation that wg-go does in
// `handleVirtioRead` before the call. Factoring would obscure the
// 1:1 port mapping that lets you diff against upstream for bugs.
pub fn tso_split(
    pkt: &[u8],
    hdr: &VirtioNetHdr,
    gso_type: GsoType,
    out: &mut [u8],
    out_stride: usize,
    lens: &mut [usize],
) -> Result<usize, TsoError> {
    let is_v6 = match gso_type {
        GsoType::TcpV4 => false,
        GsoType::TcpV6 => true,
        GsoType::None => {
            debug_assert!(false, "tso_split called with GsoType::None");
            return Err(TsoError::IpVersionMismatch);
        }
    };

    // ─── Validate IP version against gso_type ──────────────────
    // wg-go `tun_linux.go:404-414`. Kernel should never violate
    // this (it set gso_type FROM the IP version), but check anyway.
    if pkt.is_empty() {
        return Err(TsoError::TooShort);
    }
    let ip_ver = pkt[0] >> 4;
    if (is_v6 && ip_ver != 6) || (!is_v6 && ip_ver != 4) {
        return Err(TsoError::IpVersionMismatch);
    }

    // ─── Recompute hdr_len from TCP data offset ────────────────
    // wg-go `tun_linux.go:417-433`: don't trust hdr.hdr_len.
    // `csum_start` is the IP header length (the L4 header offset).
    let iphlen = usize::from(hdr.csum_start);
    if pkt.len() <= iphlen + TCP_DATAOFF_OFF {
        return Err(TsoError::TooShort);
    }
    let tcp_hlen = usize::from(pkt[iphlen + TCP_DATAOFF_OFF] >> 4) * 4;
    // RFC 793: data offset is 5..=15 words → 20..=60 bytes.
    if !(20..=60).contains(&tcp_hlen) {
        return Err(TsoError::BadTcpHlen);
    }
    let hdr_len = iphlen + tcp_hlen;
    if pkt.len() < hdr_len {
        return Err(TsoError::TooShort);
    }

    // wg-go `:443-446`: csum_offset bounds. `csum_offset` is 16 for
    // TCP (`tcphdr.th_sum` offset) — pin it. The kernel always sets
    // it correctly but a wrong value would write to a random offset.
    let csum_at = iphlen + usize::from(hdr.csum_offset);
    if csum_at + 2 > pkt.len() {
        return Err(TsoError::BadCsumOffset);
    }

    // ─── Read invariants from the input ────────────────────────
    // wg-go `:912-915`: clear input csum fields BEFORE reading
    // anything else (so we don't have to track which output bytes
    // came from the cleared input). We CAN'T mutate `pkt` (it's
    // `&[u8]`, and it's a slice into the device arena which the
    // daemon may want to inspect for debugging). Instead: copy the
    // header into a stack buffer, clear THAT, copy from there.
    let mut hdr_buf = [0u8; 60 + 60]; // max IPv6 hdr + max TCP hdr
    hdr_buf[..hdr_len].copy_from_slice(&pkt[..hdr_len]);
    if !is_v6 {
        // wg-go `:906`: zero IPv4 header checksum. It's recomputed
        // per-segment (totlen + ID change).
        hdr_buf[IPV4_CSUM_OFF] = 0;
        hdr_buf[IPV4_CSUM_OFF + 1] = 0;
    }
    // wg-go `:911`: zero TCP checksum. Recomputed per-segment.
    hdr_buf[csum_at] = 0;
    hdr_buf[csum_at + 1] = 0;

    // wg-go `:916`: first segment's TCP sequence number. Each
    // subsequent segment adds `gso_size`. RFC 793 §3.3: seqno
    // counts payload bytes.
    let first_seq = u32::from_be_bytes([
        pkt[iphlen + TCP_SEQ_OFF],
        pkt[iphlen + TCP_SEQ_OFF + 1],
        pkt[iphlen + TCP_SEQ_OFF + 2],
        pkt[iphlen + TCP_SEQ_OFF + 3],
    ]);

    // wg-go `:903-904`: src+dst addr slice for pseudo-header.
    let (addr_off, addr_len) = if is_v6 {
        (IPV6_SRCADDR_OFF, 32)
    } else {
        (IPV4_SRCADDR_OFF, 8)
    };
    let addrs = &pkt[addr_off..addr_off + addr_len];

    // wg-go `:936`: IPv4 ID from the FIRST segment, increment for
    // each subsequent. RFC 6864: ID need not be unique for atomic
    // datagrams (DF set, no frag), but the kernel still increments
    // and receivers may use it for diagnostics. Match wg-go.
    let first_id = if is_v6 {
        0
    } else {
        u16::from_be_bytes([pkt[IPV4_ID_OFF], pkt[IPV4_ID_OFF + 1]])
    };

    let ethertype = if is_v6 { ETH_P_IPV6 } else { ETH_P_IP };
    let gso_size = usize::from(hdr.gso_size);
    let max_slots = out.len() / out_stride;

    // ─── The split loop ────────────────────────────────────────
    // wg-go `:921-981`.
    let mut next_data = hdr_len;
    let mut i = 0usize;
    while next_data < pkt.len() {
        if i >= max_slots || i >= lens.len() {
            return Err(TsoError::TooManySegments);
        }

        let seg_end = (next_data + gso_size).min(pkt.len());
        let seg_data_len = seg_end - next_data;
        let total_len = hdr_len + seg_data_len; // IP-layer total
        let frame_len = ETH_HLEN + total_len;

        if frame_len > out_stride {
            // gso_size > MTU. Kernel shouldn't do this (gso_size is
            // the MSS, MSS < MTU - 40), but check anyway. Same
            // failure mode as TooManySegments from the daemon's
            // perspective.
            return Err(TsoError::TooManySegments);
        }

        let slot = &mut out[i * out_stride..i * out_stride + frame_len];

        // ─── synthetic eth header ──────────────────────────────
        // The vnet_hdr device speaks raw IP (no PI, no eth). The
        // daemon speaks eth (`route_packet` reads ethertype at
        // byte 12). Same synth as `fd.rs::FdTun::read`.
        set_etherheader(slot, ethertype);

        let ip = &mut slot[ETH_HLEN..];

        // ─── IP header ─────────────────────────────────────────
        // wg-go `:933`: copy IP header. From our cleared hdr_buf.
        ip[..iphlen].copy_from_slice(&hdr_buf[..iphlen]);

        if is_v6 {
            // wg-go `:949`: IPv6 payload length = TCP hdr + payload.
            // RFC 8200 §3: "Length of the IPv6 payload, i.e., the
            // rest of the packet following this IPv6 header".
            // total_len - iphlen = tcp_hlen + seg_data_len.
            #[allow(clippy::cast_possible_truncation)] // ≤ 65535
            let plen = (total_len - iphlen) as u16;
            ip[IPV6_PLEN_OFF..IPV6_PLEN_OFF + 2].copy_from_slice(&plen.to_be_bytes());
            // No IP checksum in v6. No ID. Ext headers: copied
            // verbatim above (they're part of `iphlen` since
            // `csum_start` points past them). RFC 8200 §4: ext
            // headers are immutable in transit anyway.
        } else {
            // wg-go `:937-943`: ID++, total_len, recompute csum.
            #[allow(clippy::cast_possible_truncation)] // i ≤ 47 in practice
            let id = first_id.wrapping_add(i as u16);
            ip[IPV4_ID_OFF..IPV4_ID_OFF + 2].copy_from_slice(&id.to_be_bytes());
            #[allow(clippy::cast_possible_truncation)] // total_len ≤ hdr+gso_size ≤ MTU < 65536
            let totlen = total_len as u16;
            ip[IPV4_TOTLEN_OFF..IPV4_TOTLEN_OFF + 2].copy_from_slice(&totlen.to_be_bytes());
            // Csum field already zeroed (from hdr_buf). Compute over
            // the IP header only (RFC 791: "covers the header only").
            let csum = checksum(&ip[..iphlen], 0);
            ip[IPV4_CSUM_OFF..IPV4_CSUM_OFF + 2].copy_from_slice(&csum.to_be_bytes());
        }

        // ─── TCP header ────────────────────────────────────────
        // wg-go `:952`: copy from cleared hdr_buf.
        ip[iphlen..hdr_len].copy_from_slice(&hdr_buf[iphlen..hdr_len]);

        // wg-go `:956`: seqno = first + gso_size * i. Wrapping is
        // correct (TCP seqno is mod 2^32, RFC 793 §3.3).
        #[allow(clippy::cast_possible_truncation)] // TCP seqno is mod 2^32 (RFC 793 §3.3)
        let seq = first_seq.wrapping_add((gso_size * i) as u32);
        ip[iphlen + TCP_SEQ_OFF..iphlen + TCP_SEQ_OFF + 4].copy_from_slice(&seq.to_be_bytes());

        // wg-go `:958-961`: FIN + PSH only on the LAST segment.
        // RFC 793: FIN consumes a seqno → must be on the final
        // segment of the burst. PSH means "deliver now" → only
        // meaningful on the last (the receiver buffers the others).
        // The original super-packet has the right flags; we CLEAR
        // them on non-last segments. Other flags (ACK, URG, RST,
        // SYN) are preserved — ACK is on every segment of an
        // established flow.
        if seg_end != pkt.len() {
            ip[iphlen + TCP_FLAGS_OFF] &= !(TCP_FLAG_FIN | TCP_FLAG_PSH);
        }

        // ─── payload ───────────────────────────────────────────
        ip[hdr_len..total_len].copy_from_slice(&pkt[next_data..seg_end]);

        // ─── TCP checksum ──────────────────────────────────────
        // wg-go `:973-977`. Pseudo-header + TCP header + payload.
        // RFC 793 §3.1. The pseudo-header `tcp_len` is "TCP header
        // + data" — same as what we sum over.
        #[allow(clippy::cast_possible_truncation)] // tcp_hlen+seg_data_len ≤ MTU < 65536
        let len_for_pseudo = (tcp_hlen + seg_data_len) as u16;
        let pseudo = pseudo_header_checksum_nofold(IPPROTO_TCP, addrs, len_for_pseudo);
        let tcp_csum = checksum(&ip[iphlen..total_len], pseudo);
        ip[csum_at..csum_at + 2].copy_from_slice(&tcp_csum.to_be_bytes());

        lens[i] = frame_len;
        next_data = seg_end;
        i += 1;
    }

    Ok(i)
}

// ── GRO coalesce (Phase 2b) ────────────────────────────────────────

/// Max coalesced IP packet size. The kernel's `tun_get_user` accepts
/// up to `IP_MAX_MTU` (65535) for `gso_type != NONE` skbs. We cap
/// just under so the `u16` totlen never overflows.
const GRO_MAX_IP_LEN: usize = 65535;

/// Outcome of [`GroBucket::offer`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroVerdict {
    /// Packet merged into the bucket. Caller must NOT write it
    /// individually — it's absorbed.
    Coalesced,
    /// Packet is a valid GRO candidate but doesn't fit the current
    /// bucket (different flow, non-adjacent seq, post-PSH). Caller
    /// should `flush()` then `offer()` again — it'll seed a new
    /// bucket.
    FlushFirst,
    /// Packet is not a GRO candidate (non-TCP, IP options,
    /// fragmented, FIN/SYN/RST, zero-payload pure-ACK). Caller
    /// writes it individually via `Device::write`.
    NotCandidate,
}

/// Single-slot TCP GRO accumulator. The Phase-2b inverse of
/// [`tso_split`]: collect same-flow packets back into a super-
/// segment + `virtio_net_hdr`, write once.
///
/// **Single-slot, append-only.** wg-go's `tcpGROTable` is a full
/// flow hashmap with prepend support. We don't need either: the
/// receiving daemon under iperf3 sees ONE flow's data packets in
/// seq order (per recvmmsg batch). Mismatch → flush → restart
/// handles the rare interleaved-flow case correctly (just doesn't
/// coalesce across the gap). The iperf3-is-one-flow assumption
/// matches `RUST_REWRITE_10G.md` Phase 2b's profiling target.
///
/// **No csum verification.** wg-go's `checksumValid` gate
/// (`offload_linux.go:389`) protects against an inner packet with
/// a corrupt csum polluting the coalesced result (kernel only
/// re-verifies the SUPER's csum, which we recompute). But our
/// inner packets are SPTPS-AEAD-authenticated bytes from a peer's
/// `tso_split` (or kernel TCP for non-GSO peers) — a bad csum
/// here is a sender-side bug, not tampering. The `netns::
/// tso_ingest_stream_integrity` sha256 catches it end-to-end.
///
/// Buffer layout: `[vnet_hdr(10)][IP super-packet]`. The slice
/// returned by [`flush`] is fed directly to `Device::write_super`
/// (raw TUN fd write, no eth munging).
pub struct GroBucket {
    /// `[vnet_hdr(10)][IP ≤65535]`.
    buf: Box<[u8]>,
    /// Valid length of `buf`. `0` = empty bucket.
    len: usize,

    // ─── coalesce key (wg-go `tcpFlowKey` shape) ────────────────
    is_v6: bool,
    iphlen: u8,
    tcphlen: u8,
    /// `[src_addr ‖ dst_addr]` straight from the IP header. Same
    /// slice shape as `tso_split`'s `addrs` (8 bytes v4, 32 bytes
    /// v6), padded into a fixed array for cheap compare.
    addrs: [u8; 32],
    sport: u16,
    dport: u16,
    /// wg-go `tcpFlowKey.rxAck`: "varying ack values should not be
    /// coalesced" — the kernel's GRO does the same (`tcp_gro_
    /// receive` in `net/ipv4/tcp_offload.c:268` flushes on ack
    /// mismatch). Under heavy unidirectional flow, data-direction
    /// segments share the same ack (it only moves when the SENDER
    /// has new data, which iperf3-receiver-side rarely does).
    ack: u32,
    /// `tos`/`ttl` (v4) or `tclass`/`hlim` (v6). wg-go
    /// `ipHeadersCanCoalesce`: kernel GRO flushes on these too.
    /// Stored together: low byte = ttl/hlim, high = tos/tclass.
    ip_meta: u16,

    // ─── coalesce state (wg-go `tcpGROItem`) ───────────────────
    /// Expected seq of the NEXT packet to append. `first_seq +
    /// total_payload_appended`.
    next_seq: u32,
    /// Payload size of the FIRST packet. wg-go: subsequent packets'
    /// payload must be ≤ this (a smaller packet may end the run; a
    /// larger one would put a small packet mid-run, which the
    /// kernel's GSO can't represent).
    gso_size: u16,
    /// PSH was seen on the last appended packet. Nothing may append
    /// after PSH — "deliver now" must be the LAST segment.
    psh_set: bool,
    /// A smaller-than-gso_size packet was appended. wg-go: "a
    /// smaller packet on the end" terminates the run — GSO emits
    /// fixed-size segments + one short tail.
    short_tail: bool,
    /// Number of packets merged (including the first). 1 = single
    /// packet, no GSO needed (zero `vnet_hdr` on flush).
    num_merged: u16,
}

impl GroBucket {
    #[must_use]
    pub fn new() -> Self {
        Self {
            buf: vec![0u8; VNET_HDR_LEN + GRO_MAX_IP_LEN].into_boxed_slice(),
            len: 0,
            is_v6: false,
            iphlen: 0,
            tcphlen: 0,
            addrs: [0; 32],
            sport: 0,
            dport: 0,
            ack: 0,
            ip_meta: 0,
            next_seq: 0,
            gso_size: 0,
            psh_set: false,
            short_tail: false,
            num_merged: 0,
        }
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Try to coalesce `ip` into the bucket.
    ///
    /// `ip` is the raw IP packet (NO eth header, NO `vnet_hdr`) —
    /// the daemon strips its synthetic eth before calling. wg-go
    /// `tcpGRO` (`offload_linux.go:531`) shape, minus the table
    /// machinery.
    ///
    /// `Coalesced`: packet absorbed, caller drops it. `FlushFirst`:
    /// flush + retry. `NotCandidate`: write individually.
    #[allow(clippy::too_many_lines)] // wg-go tcpGRO is 90 LOC; this is the linear unroll
    pub fn offer(&mut self, ip: &[u8]) -> GroVerdict {
        // ─── candidate check (wg-go `packetIsGROCandidate` :751) ───
        if ip.len() < 40 {
            // 20 (min IPv4) + 20 (min TCP). v6 is 60; checked below.
            return GroVerdict::NotCandidate;
        }
        let is_v6 = match ip[0] >> 4 {
            4 => {
                // wg-go `:757`: "IPv4 packets w/IP options do not
                // coalesce" — IHL must be exactly 5 words.
                if ip[0] & 0x0F != 5 || ip[9] != IPPROTO_TCP {
                    return GroVerdict::NotCandidate;
                }
                // wg-go `:561`: no fragmented segments. MF flag,
                // or any fragment-offset bits.
                if ip[6] & 0x20 != 0 || ip[6] & 0x1F != 0 || ip[7] != 0 {
                    return GroVerdict::NotCandidate;
                }
                // wg-go `:546`: totlen sanity. A trailing pad (eth
                // minimum-frame) would mismatch here.
                if usize::from(u16::from_be_bytes([ip[2], ip[3]])) != ip.len() {
                    return GroVerdict::NotCandidate;
                }
                false
            }
            6 => {
                if ip.len() < 60 || ip[6] != IPPROTO_TCP {
                    return GroVerdict::NotCandidate;
                }
                // wg-go `:541`: payload-len sanity. v6 has no
                // header csum, so this is the only consistency
                // check available.
                if usize::from(u16::from_be_bytes([ip[4], ip[5]])) != ip.len() - 40 {
                    return GroVerdict::NotCandidate;
                }
                true
            }
            _ => return GroVerdict::NotCandidate,
        };
        let iphlen: usize = if is_v6 { 40 } else { 20 };

        let tcphlen = usize::from(ip[iphlen + TCP_DATAOFF_OFF] >> 4) * 4;
        if !(20..=60).contains(&tcphlen) || ip.len() < iphlen + tcphlen {
            return GroVerdict::NotCandidate;
        }

        // wg-go `:566-574`: only ACK or ACK|PSH. FIN/SYN/RST/URG
        // → noop. Pure ACK (zero payload) → also noop — the kernel
        // GRO doesn't coalesce them either (`:577`).
        let flags = ip[iphlen + TCP_FLAGS_OFF];
        let psh_set = flags & TCP_FLAG_PSH != 0;
        if flags & !TCP_FLAG_PSH != TCP_FLAG_ACK {
            return GroVerdict::NotCandidate;
        }
        let payload_len = ip.len() - iphlen - tcphlen;
        if payload_len == 0 {
            return GroVerdict::NotCandidate;
        }

        let seq = u32::from_be_bytes([
            ip[iphlen + TCP_SEQ_OFF],
            ip[iphlen + TCP_SEQ_OFF + 1],
            ip[iphlen + TCP_SEQ_OFF + 2],
            ip[iphlen + TCP_SEQ_OFF + 3],
        ]);
        let ack = u32::from_be_bytes([
            ip[iphlen + 8],
            ip[iphlen + 9],
            ip[iphlen + 10],
            ip[iphlen + 11],
        ]);
        let sport = u16::from_be_bytes([ip[iphlen], ip[iphlen + 1]]);
        let dport = u16::from_be_bytes([ip[iphlen + 2], ip[iphlen + 3]]);
        let (addr_off, addr_len) = if is_v6 {
            (IPV6_SRCADDR_OFF, 32)
        } else {
            (IPV4_SRCADDR_OFF, 8)
        };
        // wg-go `ipHeadersCanCoalesce` `:279-307`. v4: tos at [1],
        // ttl at [8], DF at [6]>>5. v6: tclass split across [0..2]
        // (we store the [0] high nibble + [1] high nibble), hlim
        // at [7]. Packed into one u16 so the compare below stays
        // a single branch.
        let ip_meta = if is_v6 {
            u16::from(ip[0] & 0x0F) << 12 | u16::from(ip[1] & 0xF0) << 4 | u16::from(ip[7])
        } else {
            u16::from(ip[1]) << 8 | u16::from(ip[6] >> 5) << 7 | u16::from(ip[8])
        };

        #[allow(clippy::cast_possible_truncation)] // payload_len < 65535
        let gso_size = payload_len as u16;

        // ─── empty bucket: seed it ──────────────────────────────────
        if self.len == 0 {
            self.buf[VNET_HDR_LEN..VNET_HDR_LEN + ip.len()].copy_from_slice(ip);
            self.len = VNET_HDR_LEN + ip.len();
            self.is_v6 = is_v6;
            #[allow(clippy::cast_possible_truncation)] // 20 or 40
            {
                self.iphlen = iphlen as u8;
                self.tcphlen = tcphlen as u8;
            }
            self.addrs = [0; 32];
            self.addrs[..addr_len].copy_from_slice(&ip[addr_off..addr_off + addr_len]);
            self.sport = sport;
            self.dport = dport;
            self.ack = ack;
            self.ip_meta = ip_meta;
            self.next_seq = seq.wrapping_add(u32::from(gso_size));
            self.gso_size = gso_size;
            self.psh_set = psh_set;
            self.short_tail = false;
            self.num_merged = 1;
            return GroVerdict::Coalesced;
        }

        // ─── flow key match (wg-go `tcpPacketsCanCoalesce` :334) ───
        // wg-go's lookup is a hashmap miss; our single-slot is a
        // linear compare. Same effect for the one-flow case.
        if is_v6 != self.is_v6
            || iphlen != usize::from(self.iphlen)
            || tcphlen != usize::from(self.tcphlen)
            || sport != self.sport
            || dport != self.dport
            || ack != self.ack
            || ip_meta != self.ip_meta
            || ip[addr_off..addr_off + addr_len] != self.addrs[..addr_len]
        {
            return GroVerdict::FlushFirst;
        }
        // wg-go `:340-345`: TCP options bytes must match exactly
        // (timestamps with monotonic values would be safe to
        // coalesce, but wg-go doesn't bother and neither do we —
        // the kernel re-splits with the SUPER's timestamp anyway).
        if tcphlen > 20 {
            let pkt_head = &self.buf[VNET_HDR_LEN..];
            if ip[iphlen + 20..iphlen + tcphlen] != pkt_head[iphlen + 20..iphlen + tcphlen] {
                return GroVerdict::FlushFirst;
            }
        }
        // wg-go `:352`: seq adjacency. Append-only: pkt must be
        // exactly at `next_seq`. (wg-go also tries prepend at
        // `:368`; we don't — reordered packets just flush.)
        if seq != self.next_seq {
            return GroVerdict::FlushFirst;
        }
        // wg-go `:354-357`: can't append after PSH; can't append
        // after a short tail (GSO is fixed-size + one trailer).
        if self.psh_set || self.short_tail {
            return GroVerdict::FlushFirst;
        }
        // wg-go `:363`: larger packet can't follow smaller.
        if gso_size > self.gso_size {
            return GroVerdict::FlushFirst;
        }
        // 65535 cap.
        if self.len - VNET_HDR_LEN + payload_len > GRO_MAX_IP_LEN {
            return GroVerdict::FlushFirst;
        }

        // ─── append payload ─────────────────────────────────────────
        // wg-go `coalesceTCPPackets` `:494-496`: just the bytes;
        // headers stay from the FIRST packet. PSH propagates to
        // the head's flags so the kernel sees it on the super.
        self.buf[self.len..self.len + payload_len].copy_from_slice(&ip[iphlen + tcphlen..]);
        self.len += payload_len;
        self.next_seq = self.next_seq.wrapping_add(u32::from(gso_size));
        if psh_set {
            self.psh_set = true;
            self.buf[VNET_HDR_LEN + iphlen + TCP_FLAGS_OFF] |= TCP_FLAG_PSH;
        }
        if gso_size < self.gso_size {
            self.short_tail = true;
        }
        self.num_merged += 1;
        GroVerdict::Coalesced
    }

    /// Finalize the bucket. Fixes up IP totlen/csum, writes the
    /// `virtio_net_hdr`, returns the wire-ready `[vnet_hdr][IP]`
    /// slice. wg-go `applyTCPCoalesceAccounting` (`:624`).
    ///
    /// `None` if empty. The bucket is reset on return.
    pub fn flush(&mut self) -> Option<&[u8]> {
        if self.len == 0 {
            return None;
        }
        let len = self.len;
        let iphlen = usize::from(self.iphlen);
        let tcphlen = usize::from(self.tcphlen);
        let pkt = &mut self.buf[VNET_HDR_LEN..len];

        if self.num_merged > 1 {
            // ─── fix up the super-packet's IP header ──────────────
            // wg-go `:640-649`.
            #[allow(clippy::cast_possible_truncation)] // capped at GRO_MAX_IP_LEN
            let totlen = pkt.len() as u16;
            if self.is_v6 {
                pkt[IPV6_PLEN_OFF..IPV6_PLEN_OFF + 2].copy_from_slice(&(totlen - 40).to_be_bytes());
            } else {
                pkt[IPV4_TOTLEN_OFF..IPV4_TOTLEN_OFF + 2].copy_from_slice(&totlen.to_be_bytes());
                pkt[IPV4_CSUM_OFF] = 0;
                pkt[IPV4_CSUM_OFF + 1] = 0;
                let csum = checksum(&pkt[..iphlen], 0);
                pkt[IPV4_CSUM_OFF..IPV4_CSUM_OFF + 2].copy_from_slice(&csum.to_be_bytes());
            }

            // ─── pseudo-header partial into TCP csum field ─────────
            // wg-go `:658-664`. `NEEDS_CSUM` tells the kernel "L4
            // csum is partial; finish from `csum_start`". We write
            // the folded-but-NOT-complemented pseudo — the kernel
            // chains it (RFC 1071) with the TCP-hdr+payload sum.
            // Same shape `gso_none_checksum` reads on ingest.
            let (addr_off, addr_len) = if self.is_v6 {
                (IPV6_SRCADDR_OFF, 32)
            } else {
                (IPV4_SRCADDR_OFF, 8)
            };
            #[allow(clippy::cast_possible_truncation)] // ≤ 65535-iphlen
            let l4_len = (pkt.len() - iphlen) as u16;
            let pseudo = pseudo_header_checksum_nofold(
                IPPROTO_TCP,
                &pkt[addr_off..addr_off + addr_len],
                l4_len,
            );
            // Fold-no-complement. wg-go does `checksum([]byte{},
            // psum)` — their `checksum` doesn't complement (`:92`
            // returns the raw fold). Ours does, so fold by hand.
            let mut p = pseudo;
            p = (p >> 16) + (p & 0xffff);
            p = (p >> 16) + (p & 0xffff);
            #[allow(clippy::cast_possible_truncation)] // 32-bit one's-complement fold to 16-bit
            let p = p as u16;
            pkt[iphlen + TCP_CSUM_OFF..iphlen + TCP_CSUM_OFF + 2].copy_from_slice(&p.to_be_bytes());

            // ─── vnet_hdr ─────────────────────────────────────────────
            // wg-go `:629-636`. The kernel's `virtio_net_hdr_to_skb`
            // (`virtio_net.h:83`) maps NEEDS_CSUM → CHECKSUM_PARTIAL
            // and gso_type → SKB_GSO_TCPV4/6; `napi_gro_receive`
            // does the rest.
            #[allow(clippy::cast_possible_truncation)] // iphlen+tcphlen ≤ 100
            let hdr = VirtioNetHdr {
                flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
                gso_type: if self.is_v6 {
                    VIRTIO_NET_HDR_GSO_TCPV6
                } else {
                    VIRTIO_NET_HDR_GSO_TCPV4
                },
                hdr_len: (iphlen + tcphlen) as u16,
                gso_size: self.gso_size,
                csum_start: iphlen as u16,
                csum_offset: TCP_CSUM_OFF as u16,
            };
            hdr.encode(&mut self.buf[..VNET_HDR_LEN]);
        } else {
            // num_merged == 1: single packet went through the
            // bucket but nothing joined. wg-go `:667-672`: zero
            // vnet_hdr (gso_type=NONE, no csum offload). The IP
            // packet is verbatim from the first `offer` — csum
            // already valid (sender's tso_split or kernel TCP).
            self.buf[..VNET_HDR_LEN].fill(0);
        }

        self.len = 0; // reset for next batch
        Some(&self.buf[..len])
    }
}

impl Default for GroBucket {
    fn default() -> Self {
        Self::new()
    }
}

// ── tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
