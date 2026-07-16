//! Userspace TSO split.
//!
//! With `IFF_VNET_HDR + TUNSETOFFLOAD(TUN_F_TSO4|TUN_F_TSO6)` the kernel
//! hands us one ≤64KB skb prefixed by `virtio_net_hdr`. We split it back
//! into MTU-sized TCP segments.
//!
//! Each chunk gets a synthetic eth header prepended because
//! `forward_packet` reads the ethertype at byte 12.
//!
//! Lives in `tinc-device` because the same `virtio_net_hdr` format
//! appears on FreeBSD `TAPSVNETHDR` and Windows NDIS LSO.
//!
//! Not handled: USO (`GSO_UDP_L4`, kernel 6.2+) and `GSO_ECN` — we
//! don't enable those `TUN_F_*` flags, so the kernel never sends them.

use crate::arena::GsoType;
use crate::ether::{ETH_HLEN, ETH_P_IP, ETH_P_IPV6, set_etherheader};

/// `struct virtio_net_hdr` endianness: `__virtio16` fields use legacy
/// virtio (host-native) byte order. We decode with `from_le_bytes`,
/// which is only correct on little-endian hosts. On big-endian hosts
/// that would silently corrupt the header; fail the build loudly
/// instead (no BE CI runner to validate a `from_ne_bytes` fix).
#[cfg(target_endian = "big")]
compile_error!("virtio_net_hdr endianness needs TUNSETVNETLE on BE hosts");

/// `sizeof(struct virtio_net_hdr)`, the kernel's default `vnet_hdr_sz`.
/// `TUNSETVNETHDRSZ` could raise it to 12 (`_mrg_rxbuf` variant); we
/// keep the default.
pub const VNET_HDR_LEN: usize = 10;

/// `VIRTIO_NET_HDR_F_NEEDS_CSUM`: the kernel left the L4 checksum
/// partial; compute it from `csum_start` and place it at
/// `csum_start + csum_offset`. Set on every TSO frame, and also on
/// `GSO_NONE` frames when TX csum offload is enabled — those need
/// [`gso_none_checksum`].
const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 1;

/// `VIRTIO_NET_HDR_GSO_*` values for `gso_type`.
const VIRTIO_NET_HDR_GSO_NONE: u8 = 0;
const VIRTIO_NET_HDR_GSO_TCPV4: u8 = 1;
const VIRTIO_NET_HDR_GSO_TCPV6: u8 = 4;

/// Parsed `virtio_net_hdr`: the raw 10-byte struct, fields decoded
/// from LE.
#[derive(Debug, Clone, Copy)]
pub struct VirtioNetHdr {
    /// `VIRTIO_NET_HDR_F_*` flags. We only act on `NEEDS_CSUM`.
    pub flags: u8,
    /// `VIRTIO_NET_HDR_GSO_*`. Mapped to [`GsoType`] by [`Self::gso`].
    pub gso_type: u8,
    /// IP header + TCP header length. **DON'T TRUST IT** — on the
    /// kernel FORWARD path it can equal the length of the entire
    /// first packet. Recompute from `csum_start` + parsed TCP hlen.
    /// Carried for the `GSO_NONE` case (where it's correct).
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
    /// Decode the 10-byte header.
    ///
    /// Returns `None` if `raw.len() < 10` — a short read on a `vnet_hdr`
    /// device means the device is misconfigured (the kernel always
    /// writes the full header). Caller drops the frame.
    #[must_use]
    #[inline]
    pub fn decode(raw: &[u8]) -> Option<Self> {
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

    /// Encode into a 10-byte buffer.
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
    /// with one frame and lets `forward_packet` deal with it).
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

/// RFC 1071 internet checksum, no fold.
///
/// Deliberately unoptimized: the simple loop costs ~0.5µs/pkt while
/// crypto costs ~4.6µs, so an unrolled carry-propagating variant would
/// not move the bottleneck. Revisit if crypto ever stops dominating.
///
/// `initial` is BIG-endian-interpreted; we accumulate in BE space
/// throughout, so the fold-and-complement in [`checksum`] yields a
/// value that `to_be_bytes` puts correctly on the wire.
#[inline]
fn checksum_nofold(data: &[u8], initial: u64) -> u64 {
    let mut sum = initial;
    let (chunks, rem) = data.as_chunks::<2>();
    for pair in chunks {
        sum += u64::from(u16::from_be_bytes(*pair));
    }
    if let [tail] = rem {
        // RFC 1071 §4.1: tail byte is the HIGH byte of a zero-padded
        // 16-bit word.
        sum += u64::from(*tail) << 8;
    }
    sum
}

/// Fold 64→16 + complement (RFC 1071 one's-complement final step).
#[inline]
fn checksum(data: &[u8], initial: u64) -> u16 {
    !fold16(checksum_nofold(data, initial))
}

/// Fold a 64-bit one's-complement accumulator to 16 bits (no
/// complement). Four folds is enough for `u64` (each fold halves the
/// bit width of the carry).
#[inline]
#[expect(clippy::cast_possible_truncation)] // folded to 16 bits
fn fold16(mut ac: u64) -> u16 {
    ac = (ac >> 16) + (ac & 0xffff);
    ac = (ac >> 16) + (ac & 0xffff);
    ac = (ac >> 16) + (ac & 0xffff);
    ac = (ac >> 16) + (ac & 0xffff);
    ac as u16
}

/// `(offset, len)` of `[src_addr ‖ dst_addr]` inside the IP header.
#[inline]
const fn ip_addr_span(is_v6: bool) -> (usize, usize) {
    if is_v6 {
        (IPV6_SRCADDR_OFF, 32)
    } else {
        (IPV4_SRCADDR_OFF, 8)
    }
}

/// Big-endian u16 at `b[o..o+2]`. Panics on OOB — callers have
/// already length-checked the header.
#[inline]
fn be16(b: &[u8], o: usize) -> u16 {
    u16::from_be_bytes(b[o..o + 2].try_into().unwrap())
}

/// Big-endian u32 at `b[o..o+4]`.
#[inline]
fn be32(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes(b[o..o + 4].try_into().unwrap())
}

/// TCP/UDP pseudo-header checksum. RFC 793 §3.1 / RFC 8200 §8.1: sum over
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

// IP header field offsets. We work on raw byte slices here: no
// zerocopy dependency in tinc-device, and `tso_split` needs `&mut`
// access while iterating which a `#[repr(packed)]` accessor pattern
// doesn't give.

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
/// actual bytes) — log + drop, don't panic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TsoError {
    /// Packet shorter than `csum_start + 13` (can't read TCP hlen).
    TooShort,
    /// TCP data offset < 5 or > 15 words. Kernel never sets this
    /// (the TCP stack validates), but we don't trust the wire.
    BadTcpHlen,
    /// `csum_start + csum_offset` past end of packet.
    BadCsumOffset,
    /// IP version nibble doesn't match `gso_type`. Shouldn't happen
    /// (the kernel knows what it's segmenting).
    IpVersionMismatch,
    /// Output scratch too small. With `DEVICE_DRAIN_CAP=64` slots
    /// at 1600 stride, 64KB / 1400 ≈ 47 segments fit; a tiny
    /// `gso_size` (the kernel can emit 88-byte MSS in PMTU edge
    /// cases) could need far more, in which case we drop. Mitigated:
    /// tinc's PMTU probe never returns < 590.
    TooManySegments,
}

/// For `GSO_NONE` frames with `NEEDS_CSUM` set: the kernel left the L4 checksum
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

/// Split a TCP super-segment into MTU-sized frames.
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

    // Validate IP version against gso_type. Kernel should never
    // violate this (it set gso_type FROM the IP version), but check anyway.
    if pkt.is_empty() {
        return Err(TsoError::TooShort);
    }
    let ip_ver = pkt[0] >> 4;
    if (is_v6 && ip_ver != 6) || (!is_v6 && ip_ver != 4) {
        return Err(TsoError::IpVersionMismatch);
    }

    // Recompute hdr_len from the TCP data offset — don't trust
    // hdr.hdr_len. `csum_start` is the IP header length (the L4 header offset).
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

    // csum_offset bounds: it's 16 for TCP (`tcphdr.th_sum` offset).
    // The kernel always sets it correctly but a wrong value would
    // write to a random offset.
    let csum_at = iphlen + usize::from(hdr.csum_offset);
    if csum_at + 2 > pkt.len() {
        return Err(TsoError::BadCsumOffset);
    }

    // Csum fields must be cleared before checksumming, but `pkt` is
    // a shared slice into the device arena which the daemon may still
    // inspect. Copy the header into a stack buffer, clear that, and
    // copy from there.
    let mut hdr_buf = [0u8; 60 + 60]; // max IPv6 hdr + max TCP hdr
    if hdr_len > hdr_buf.len() || csum_at + 2 > hdr_buf.len() {
        return Err(TsoError::TooShort);
    }
    hdr_buf[..hdr_len].copy_from_slice(&pkt[..hdr_len]);
    if !is_v6 {
        // Zero IPv4 header checksum; it's recomputed per-segment
        // (totlen + ID change).
        hdr_buf[IPV4_CSUM_OFF] = 0;
        hdr_buf[IPV4_CSUM_OFF + 1] = 0;
    }
    // Zero TCP checksum. Recomputed per-segment.
    hdr_buf[csum_at] = 0;
    hdr_buf[csum_at + 1] = 0;

    // First segment's TCP sequence number; each subsequent segment
    // adds `gso_size` (RFC 793 §3.3: seqno counts payload bytes).
    let first_seq = be32(pkt, iphlen + TCP_SEQ_OFF);

    // src+dst addr slice for the pseudo-header.
    let (addr_off, addr_len) = ip_addr_span(is_v6);
    let addrs = &pkt[addr_off..addr_off + addr_len];

    // IPv4 ID from the FIRST segment, incremented per segment.
    // RFC 6864: ID need not be unique for atomic datagrams (DF set,
    // no frag), but the kernel still increments and receivers may
    // use it for diagnostics.
    let first_id = if is_v6 { 0 } else { be16(pkt, IPV4_ID_OFF) };

    let ethertype = if is_v6 { ETH_P_IPV6 } else { ETH_P_IP };
    let gso_size = usize::from(hdr.gso_size);
    let max_slots = out.len() / out_stride;

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

        // Synthetic eth header: the vnet_hdr device speaks raw IP (no PI, no eth). The
        // daemon speaks eth (`forward_packet` reads ethertype at
        // byte 12). Same synth as `fd.rs::FdTun::read`.
        set_etherheader(slot, ethertype);

        let ip = &mut slot[ETH_HLEN..];

        // IP header, from the cleared hdr_buf.
        ip[..iphlen].copy_from_slice(&hdr_buf[..iphlen]);

        if is_v6 {
            // IPv6 payload length = TCP hdr + payload.
            // RFC 8200 §3: "Length of the IPv6 payload, i.e., the
            // rest of the packet following this IPv6 header".
            // total_len - iphlen = tcp_hlen + seg_data_len.
            #[expect(clippy::cast_possible_truncation)] // ≤ 65535
            let plen = (total_len - iphlen) as u16;
            ip[IPV6_PLEN_OFF..IPV6_PLEN_OFF + 2].copy_from_slice(&plen.to_be_bytes());
            // No IP checksum in v6. No ID. Ext headers: copied
            // verbatim above (they're part of `iphlen` since
            // `csum_start` points past them). RFC 8200 §4: ext
            // headers are immutable in transit anyway.
        } else {
            // ID++, total_len, recompute csum.
            #[expect(clippy::cast_possible_truncation)] // i ≤ 47 in practice
            let id = first_id.wrapping_add(i as u16);
            ip[IPV4_ID_OFF..IPV4_ID_OFF + 2].copy_from_slice(&id.to_be_bytes());
            #[expect(clippy::cast_possible_truncation)] // total_len ≤ hdr+gso_size ≤ MTU < 65536
            let totlen = total_len as u16;
            ip[IPV4_TOTLEN_OFF..IPV4_TOTLEN_OFF + 2].copy_from_slice(&totlen.to_be_bytes());
            // Csum field already zeroed (from hdr_buf). Compute over
            // the IP header only (RFC 791: "covers the header only").
            let csum = checksum(&ip[..iphlen], 0);
            ip[IPV4_CSUM_OFF..IPV4_CSUM_OFF + 2].copy_from_slice(&csum.to_be_bytes());
        }

        // TCP header, from the cleared hdr_buf.
        ip[iphlen..hdr_len].copy_from_slice(&hdr_buf[iphlen..hdr_len]);

        // seqno = first + gso_size * i. Wrapping is correct
        // (TCP seqno is mod 2^32, RFC 793 §3.3).
        #[expect(clippy::cast_possible_truncation)] // TCP seqno is mod 2^32 (RFC 793 §3.3)
        let seq = first_seq.wrapping_add((gso_size * i) as u32);
        ip[iphlen + TCP_SEQ_OFF..iphlen + TCP_SEQ_OFF + 4].copy_from_slice(&seq.to_be_bytes());

        // FIN + PSH only on the LAST segment.
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

        ip[hdr_len..total_len].copy_from_slice(&pkt[next_data..seg_end]);

        // TCP checksum: pseudo-header + TCP header + payload.
        // RFC 793 §3.1. The pseudo-header `tcp_len` is "TCP header
        // + data" — same as what we sum over.
        #[expect(clippy::cast_possible_truncation)] // tcp_hlen+seg_data_len ≤ MTU < 65536
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

/// Single-slot TCP GRO accumulator. The inverse of [`tso_split`]:
/// collect same-flow packets back into a super-
/// segment + `virtio_net_hdr`, write once.
///
/// **Single-slot, append-only.** No flow hashmap or prepend support:
/// under a bulk transfer the receiving daemon sees ONE flow's data
/// packets in seq order per batch. A mismatch → flush → restart
/// handles the rare interleaved-flow case correctly (it just doesn't
/// coalesce across the gap).
///
/// **No csum verification.** A corrupt inner checksum could pollute
/// the coalesced result (the kernel only re-verifies the SUPER's
/// csum, which we recompute). But our inner packets are
/// SPTPS-AEAD-authenticated bytes from a peer's `tso_split` (or
/// kernel TCP for non-GSO peers) — a bad csum here is a sender-side
/// bug, not tampering. The `netns::tso_ingest_stream_integrity`
/// sha256 test catches it end-to-end.
///
/// Buffer layout: `[vnet_hdr(10)][IP super-packet]`. The slice
/// returned by [`flush`] is fed directly to `Device::write_super`
/// (raw TUN fd write, no eth munging).
pub struct GroBucket {
    /// `[vnet_hdr(10)][IP ≤65535]`.
    buf: Box<[u8]>,
    /// Valid length of `buf`. `0` = empty bucket.
    len: usize,

    // coalesce key
    is_v6: bool,
    iphlen: u8,
    tcphlen: u8,
    /// `[src_addr ‖ dst_addr]` straight from the IP header. Same
    /// slice shape as `tso_split`'s `addrs` (8 bytes v4, 32 bytes
    /// v6), padded into a fixed array for cheap compare.
    addrs: [u8; 32],
    sport: u16,
    dport: u16,
    /// Varying ack values must not be coalesced (the kernel's GRO
    /// flushes on ack mismatch too). Under heavy unidirectional flow,
    /// data-direction segments share the same ack.
    ack: u32,
    /// `tos`/`ttl` (v4) or `tclass`/`hlim` (v6). Kernel GRO flushes
    /// on these too. Stored together: low byte = ttl/hlim, high =
    /// tos/tclass.
    ip_meta: u16,

    // coalesce state
    /// Expected seq of the NEXT packet to append. `first_seq +
    /// total_payload_appended`.
    next_seq: u32,
    /// Payload size of the FIRST packet. Subsequent packets' payload
    /// must be ≤ this (a smaller packet may end the run; a larger one
    /// would put a small packet mid-run, which the kernel's GSO can't
    /// represent).
    gso_size: u16,
    /// PSH was seen on the last appended packet. Nothing may append
    /// after PSH — "deliver now" must be the LAST segment.
    psh_set: bool,
    /// A smaller-than-gso_size packet was appended, terminating the
    /// run — GSO emits fixed-size segments + one short tail.
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
    /// the daemon strips its synthetic eth before calling.
    ///
    /// `Coalesced`: packet absorbed, caller drops it. `FlushFirst`:
    /// flush + retry. `NotCandidate`: write individually.
    pub fn offer(&mut self, ip: &[u8]) -> GroVerdict {
        if ip.len() < 40 {
            // 20 (min IPv4) + 20 (min TCP). v6 is 60; checked below.
            return GroVerdict::NotCandidate;
        }
        let is_v6 = match ip[0] >> 4 {
            4 => {
                // IPv4 packets with IP options do not coalesce —
                // IHL must be exactly 5 words.
                if ip[0] & 0x0F != 5 || ip[9] != IPPROTO_TCP {
                    return GroVerdict::NotCandidate;
                }
                // No fragmented segments: MF flag or any
                // fragment-offset bits.
                if ip[6] & 0x20 != 0 || ip[6] & 0x1F != 0 || ip[7] != 0 {
                    return GroVerdict::NotCandidate;
                }
                // totlen sanity. A trailing pad (eth minimum-frame)
                // would mismatch here.
                if usize::from(be16(ip, 2)) != ip.len() {
                    return GroVerdict::NotCandidate;
                }
                false
            }
            6 => {
                if ip.len() < 60 || ip[6] != IPPROTO_TCP {
                    return GroVerdict::NotCandidate;
                }
                // Payload-len sanity. v6 has no header csum, so this
                // is the only consistency check available.
                if usize::from(be16(ip, 4)) != ip.len() - 40 {
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

        // Only ACK or ACK|PSH coalesce. FIN/SYN/RST/URG → noop.
        // Pure ACK (zero payload) → also noop — the kernel GRO
        // doesn't coalesce them either.
        let flags = ip[iphlen + TCP_FLAGS_OFF];
        let psh_set = flags & TCP_FLAG_PSH != 0;
        if flags & !TCP_FLAG_PSH != TCP_FLAG_ACK {
            return GroVerdict::NotCandidate;
        }
        let payload_len = ip.len() - iphlen - tcphlen;
        if payload_len == 0 {
            return GroVerdict::NotCandidate;
        }

        let seq = be32(ip, iphlen + TCP_SEQ_OFF);
        let ack = be32(ip, iphlen + 8);
        let sport = be16(ip, iphlen);
        let dport = be16(ip, iphlen + 2);
        let (addr_off, addr_len) = ip_addr_span(is_v6);
        // v4: tos at [1], ttl at [8], DF at [6]>>5. v6: tclass split
        // across [0..2] (we store the [0] high nibble + [1] high
        // nibble), hlim at [7]. Packed into one u16 so the compare
        // below stays a single branch.
        let ip_meta = if is_v6 {
            u16::from(ip[0] & 0x0F) << 12 | u16::from(ip[1] & 0xF0) << 4 | u16::from(ip[7])
        } else {
            u16::from(ip[1]) << 8 | u16::from(ip[6] >> 5) << 7 | u16::from(ip[8])
        };

        #[expect(clippy::cast_possible_truncation)] // payload_len < 65535
        let gso_size = payload_len as u16;

        // Empty bucket: seed it.
        if self.len == 0 {
            self.buf[VNET_HDR_LEN..VNET_HDR_LEN + ip.len()].copy_from_slice(ip);
            self.len = VNET_HDR_LEN + ip.len();
            self.is_v6 = is_v6;
            #[expect(clippy::cast_possible_truncation)] // 20 or 40
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

        // Flow key match.
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
        // TCP options bytes must match exactly (timestamps with
        // monotonic values would be safe to coalesce, but the kernel
        // re-splits with the SUPER's timestamp anyway).
        if tcphlen > 20 {
            let pkt_head = &self.buf[VNET_HDR_LEN..];
            if ip[iphlen + 20..iphlen + tcphlen] != pkt_head[iphlen + 20..iphlen + tcphlen] {
                return GroVerdict::FlushFirst;
            }
        }
        // Seq adjacency. Append-only: pkt must be exactly at
        // `next_seq`; reordered packets just flush.
        if seq != self.next_seq {
            return GroVerdict::FlushFirst;
        }
        // Can't append after PSH; can't append after a short tail
        // (GSO is fixed-size + one trailer).
        if self.psh_set || self.short_tail {
            return GroVerdict::FlushFirst;
        }
        // Larger packet can't follow smaller.
        if gso_size > self.gso_size {
            return GroVerdict::FlushFirst;
        }
        // 65535 cap.
        if self.len - VNET_HDR_LEN + payload_len > GRO_MAX_IP_LEN {
            return GroVerdict::FlushFirst;
        }

        // Append payload bytes only; headers stay from the FIRST
        // packet. PSH propagates to the head's flags so the kernel
        // sees it on the super.
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
    /// slice.
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
            // Fix up the super-packet's IP header.
            #[expect(clippy::cast_possible_truncation)] // capped at GRO_MAX_IP_LEN
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

            // Pseudo-header partial into the TCP csum field.
            // `NEEDS_CSUM` tells the kernel "L4 csum is partial;
            // finish from `csum_start`". We write the
            // folded-but-NOT-complemented pseudo — the kernel chains
            // it (RFC 1071) with the TCP-hdr+payload sum. Same shape
            // `gso_none_checksum` reads on ingest.
            let (addr_off, addr_len) = ip_addr_span(self.is_v6);
            #[expect(clippy::cast_possible_truncation)] // ≤ 65535-iphlen
            let l4_len = (pkt.len() - iphlen) as u16;
            let pseudo = pseudo_header_checksum_nofold(
                IPPROTO_TCP,
                &pkt[addr_off..addr_off + addr_len],
                l4_len,
            );
            // Fold without complement — [`checksum`] complements, so
            // fold separately here.
            let p = fold16(pseudo);
            pkt[iphlen + TCP_CSUM_OFF..iphlen + TCP_CSUM_OFF + 2].copy_from_slice(&p.to_be_bytes());

            // The kernel's `virtio_net_hdr_to_skb` maps NEEDS_CSUM →
            // CHECKSUM_PARTIAL and gso_type → SKB_GSO_TCPV4/6;
            // `napi_gro_receive` does the rest.
            #[expect(clippy::cast_possible_truncation)] // iphlen+tcphlen ≤ 100
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
            // num_merged == 1: single packet went through the bucket
            // but nothing joined. Zero vnet_hdr (gso_type=NONE, no
            // csum offload). The IP packet is verbatim from the first
            // `offer` — csum already valid.
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

#[cfg(test)]
mod tests;
