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
//!   `IFF_NO_PI` on the vnet_hdr path (the kernel writes
//!   `[vnet_hdr][IP packet]` — no `tun_pi`, no eth header). But the
//!   *daemon* speaks ethernet frames internally (`route_packet` reads
//!   ethertype at byte 12). So `tso_split` writes a synthetic eth
//!   header into each output chunk, same as `fd.rs`/`bsd.rs` do for
//!   their no-PI paths. The IP-layer arithmetic is unchanged; we just
//!   prepend 14 bytes per chunk.
//!
//! - wg-go's checksum is unrolled 128-byte adc. We use a simpler
//!   2-byte loop. The bottleneck is ChaCha20 (4.6µs/pkt), not the
//!   checksum (~0.02µs for a 20-byte IP header). Don't optimize what
//!   isn't hot.
//!
//! ## Why this lives in `tinc-device`, not `tincd`
//!
//! `RUST_REWRITE_10G.md` §"Design implication": same `virtio_net_hdr`
//! wire format on FreeBSD `TAPSVNETHDR` (`if_tuntap.c:168`). Same
//! input on Windows NDIS LSO. One ~200 LOC function, three platforms.
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
/// "the kernel left the L4 checksum partial (CHECKSUM_PARTIAL skb
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
    /// Returns `None` if `raw.len() < 10` — short read on a vnet_hdr
    /// device means the device is misconfigured (kernel always writes
    /// the full header). Caller drops the frame.
    #[must_use]
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

    /// `gso_type` → our enum. `None` for unknown types (we only
    /// advertise TSO4/6, so the kernel should never hand us UDP_L4
    /// or ECN — but if it does, the caller falls back to `Frames`
    /// with one frame and lets `route_packet` deal with it).
    #[must_use]
    pub fn gso(&self) -> Option<GsoType> {
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
    pub fn needs_csum(&self) -> bool {
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
#[cfg(test)]
const TCP_CSUM_OFF: usize = 16;

const TCP_FLAG_FIN: u8 = 0x01;
const TCP_FLAG_PSH: u8 = 0x08;

const IPPROTO_TCP: u8 = 6;

/// What went wrong. All of these are kernel-contract violations
/// (the vnet_hdr describes a packet shape that doesn't match the
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
/// 10-byte vnet_hdr. `[IP header][TCP header][≤64KB payload]`. NO
/// eth header (vnet_hdr device uses `IFF_NO_PI` and L3 mode).
///
/// `hdr`: the decoded vnet_hdr. `gso_type` MUST be `TcpV4` or `TcpV6`
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
            #[allow(clippy::cast_possible_truncation)]
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
        #[allow(clippy::cast_possible_truncation)]
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
        #[allow(clippy::cast_possible_truncation)]
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

// ── tests ──────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)] // test packets are <64KB
mod tests {
    use super::*;

    /// `virtio_net_hdr` constants match the kernel UAPI. `gcc -E
    /// include/uapi/linux/virtio_net.h | grep VIRTIO_NET_HDR_GSO`.
    ///
    /// Why test constants that "can't change": the test pins OUR
    /// COPY of them. The kernel's are stable; ours could drift if
    /// someone refactors and typos `TCPV6 = 6` (it's 4, not 6 —
    /// the obvious value is wrong). This is the same pattern as
    /// `linux.rs::tunsetiff_value`: kernel ABI is the source of
    /// truth; we hand-copied it; the test catches the hand-copy
    /// going wrong. If `libc` ever adds these constants, switch to
    /// `assert_eq!(OUR, libc::VIRTIO_...)` and the test becomes a
    /// dependency-upgrade canary instead.
    #[test]
    fn virtio_constants_match_kernel() {
        assert_eq!(VIRTIO_NET_HDR_GSO_NONE, 0);
        assert_eq!(VIRTIO_NET_HDR_GSO_TCPV4, 1);
        assert_eq!(VIRTIO_NET_HDR_GSO_TCPV6, 4);
        assert_eq!(VIRTIO_NET_HDR_F_NEEDS_CSUM, 1);
        assert_eq!(VNET_HDR_LEN, 10);
    }

    /// Decode the wg-go test vectors' header shapes. wg-go
    /// `offload_linux_test.go:179` "tcp4" case: csum_start=20
    /// (IPv4 hdr), csum_offset=16 (TCP th_sum), gso_size=100.
    #[test]
    fn vnet_hdr_decode() {
        // flags=NEEDS_CSUM(1), gso=TCPV4(1), hdr_len=40, gso_size=100,
        // csum_start=20, csum_offset=16. All u16 LE.
        let raw = [1u8, 1, 40, 0, 100, 0, 20, 0, 16, 0];
        let h = VirtioNetHdr::decode(&raw).unwrap();
        assert_eq!(h.flags, 1);
        assert_eq!(h.gso_type, 1);
        assert_eq!(h.hdr_len, 40);
        assert_eq!(h.gso_size, 100);
        assert_eq!(h.csum_start, 20);
        assert_eq!(h.csum_offset, 16);
        assert_eq!(h.gso(), Some(GsoType::TcpV4));
        assert!(h.needs_csum());

        // Short → None.
        assert!(VirtioNetHdr::decode(&[0; 9]).is_none());
    }

    /// RFC 1071 reference vector. From the RFC's example: sum over
    /// `00 01 f2 03 f4 f5 f6 f7` = `0xddf2`, complement = `0x220d`.
    #[test]
    fn checksum_rfc1071_reference() {
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        // RFC: sum = 0001 + f203 + f4f5 + f6f7 = 2ddf0, fold = ddf2.
        assert_eq!(checksum(&data, 0), 0x220d);
    }

    /// Odd-length tail. RFC 1071 §4.1: pad with zero in the LOW byte
    /// (= high byte of the BE-interpreted word).
    #[test]
    fn checksum_odd_tail() {
        // `00 01 f2` → 0001 + f200 = f201, ~f201 = 0dfe.
        assert_eq!(checksum(&[0x00, 0x01, 0xf2], 0), 0x0dfe);
    }

    /// Chaining: `checksum(A‖B, 0)` = fold(nofold(A) + nofold(B)).
    /// This is what makes pseudo-header chaining work.
    #[test]
    fn checksum_chains() {
        let a = [0x12, 0x34, 0x56, 0x78];
        let b = [0xab, 0xcd];
        let mut ab = a.to_vec();
        ab.extend_from_slice(&b);
        let direct = checksum(&ab, 0);
        let chained = checksum(&b, checksum_nofold(&a, 0));
        assert_eq!(direct, chained);
    }

    // ─── packet builders for tso_split tests ───────────────────

    /// IPv4 + TCP + `payload_len` bytes of `0xAA`. Minimal headers
    /// (20 + 20). seq=1000, ACK+PSH set. Checksums valid.
    fn build_v4_tcp(payload_len: usize) -> Vec<u8> {
        let total = 20 + 20 + payload_len;
        let mut p = vec![0u8; total];
        // IPv4 header: ver=4, ihl=5, tos=0, totlen, id=0x1234, off=DF,
        // ttl=64, proto=TCP, csum=0, src=10.0.0.1, dst=10.0.0.2.
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
        p[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
        p[8] = 64;
        p[9] = IPPROTO_TCP;
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[10, 0, 0, 2]);
        let csum = checksum(&p[..20], 0);
        p[10..12].copy_from_slice(&csum.to_be_bytes());
        // TCP: sport=1000, dport=2000, seq=1000, ack=0, doff=5<<4,
        // flags=ACK|PSH, win=65535, csum=0, urp=0.
        p[20..22].copy_from_slice(&1000u16.to_be_bytes());
        p[22..24].copy_from_slice(&2000u16.to_be_bytes());
        p[24..28].copy_from_slice(&1000u32.to_be_bytes());
        p[32] = 5 << 4;
        p[33] = 0x10 | TCP_FLAG_PSH; // ACK | PSH
        p[34..36].copy_from_slice(&65535u16.to_be_bytes());
        // Payload.
        for b in &mut p[40..] {
            *b = 0xAA;
        }
        // TCP csum: pseudo + tcp.
        let pseudo =
            pseudo_header_checksum_nofold(IPPROTO_TCP, &p[12..20], (20 + payload_len) as u16);
        let csum = checksum(&p[20..], pseudo);
        p[36..38].copy_from_slice(&csum.to_be_bytes());
        p
    }

    /// IPv6 + TCP. Same as v4 but 40-byte IP header.
    fn build_v6_tcp(payload_len: usize) -> Vec<u8> {
        let total = 40 + 20 + payload_len;
        let mut p = vec![0u8; total];
        // IPv6: ver=6/tc=0/flow=0, plen=20+payload, nh=TCP, hlim=64,
        // src=fe80::1, dst=fe80::2.
        p[0] = 0x60;
        p[4..6].copy_from_slice(&((20 + payload_len) as u16).to_be_bytes());
        p[6] = IPPROTO_TCP;
        p[7] = 64;
        p[8..24].copy_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        p[24..40].copy_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        // TCP at 40..60, same as v4.
        p[40..42].copy_from_slice(&1000u16.to_be_bytes());
        p[42..44].copy_from_slice(&2000u16.to_be_bytes());
        p[44..48].copy_from_slice(&1000u32.to_be_bytes());
        p[52] = 5 << 4;
        p[53] = 0x10 | TCP_FLAG_PSH;
        p[54..56].copy_from_slice(&65535u16.to_be_bytes());
        for b in &mut p[60..] {
            *b = 0xBB;
        }
        let pseudo =
            pseudo_header_checksum_nofold(IPPROTO_TCP, &p[8..40], (20 + payload_len) as u16);
        let csum = checksum(&p[40..], pseudo);
        p[56..58].copy_from_slice(&csum.to_be_bytes());
        p
    }

    fn hdr_v4(gso_size: u16) -> VirtioNetHdr {
        VirtioNetHdr {
            flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
            gso_type: VIRTIO_NET_HDR_GSO_TCPV4,
            hdr_len: 40,
            gso_size,
            csum_start: 20,
            csum_offset: TCP_CSUM_OFF as u16,
        }
    }

    fn hdr_v6(gso_size: u16) -> VirtioNetHdr {
        VirtioNetHdr {
            flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
            gso_type: VIRTIO_NET_HDR_GSO_TCPV6,
            hdr_len: 60,
            gso_size,
            csum_start: 40,
            csum_offset: TCP_CSUM_OFF as u16,
        }
    }

    /// Verify a v4 TCP segment: IP csum valid, TCP csum valid,
    /// totlen matches frame, ID = expected, seq = expected.
    fn verify_v4_seg(frame: &[u8], expect_id: u16, expect_seq: u32, expect_payload_len: usize) {
        // eth header
        assert_eq!(&frame[12..14], &ETH_P_IP.to_be_bytes());
        let ip = &frame[ETH_HLEN..];
        // IP version + IHL
        assert_eq!(ip[0], 0x45);
        // total len = frame len - eth
        let totlen = u16::from_be_bytes([ip[2], ip[3]]);
        assert_eq!(usize::from(totlen), ip.len());
        assert_eq!(usize::from(totlen), 20 + 20 + expect_payload_len);
        // ID
        assert_eq!(u16::from_be_bytes([ip[4], ip[5]]), expect_id);
        // IP csum: re-verify by re-summing (must be 0 over a valid header).
        // RFC 1071: checksum of a valid header (csum field included) is 0.
        let mut hdr = ip[..20].to_vec();
        let stored = [hdr[10], hdr[11]];
        hdr[10] = 0;
        hdr[11] = 0;
        let recomputed = checksum(&hdr, 0);
        assert_eq!(recomputed.to_be_bytes(), stored, "IPv4 hdr csum");
        // seq
        let seq = u32::from_be_bytes([ip[24], ip[25], ip[26], ip[27]]);
        assert_eq!(seq, expect_seq);
        // TCP csum: pseudo + zero-csum-field-then-sum.
        let mut tcp = ip[20..].to_vec();
        let stored = [tcp[16], tcp[17]];
        tcp[16] = 0;
        tcp[17] = 0;
        let pseudo = pseudo_header_checksum_nofold(IPPROTO_TCP, &ip[12..20], tcp.len() as u16);
        let recomputed = checksum(&tcp, pseudo);
        assert_eq!(recomputed.to_be_bytes(), stored, "TCP csum");
    }

    // ─── tso_split: the main cases ─────────────────────────────

    /// IPv4, 200 bytes payload, gso_size=100 → 2 segments of 100.
    /// wg-go `offload_linux_test.go:179` "tcp4" case shape.
    #[test]
    fn split_v4_even() {
        let pkt = build_v4_tcp(200);
        let hdr = hdr_v4(100);
        let mut out = vec![0u8; 4 * 1600];
        let mut lens = [0usize; 4];

        let n = tso_split(&pkt, &hdr, GsoType::TcpV4, &mut out, 1600, &mut lens).unwrap();
        assert_eq!(n, 2);
        assert_eq!(lens[0], ETH_HLEN + 40 + 100);
        assert_eq!(lens[1], ETH_HLEN + 40 + 100);

        // Seg 0: ID=0x1234, seq=1000, 100 bytes, PSH cleared (not last).
        verify_v4_seg(&out[..lens[0]], 0x1234, 1000, 100);
        assert_eq!(out[ETH_HLEN + 33] & TCP_FLAG_PSH, 0, "PSH cleared seg0");
        assert_eq!(out[ETH_HLEN + 33] & 0x10, 0x10, "ACK kept seg0");

        // Seg 1: ID=0x1235, seq=1100, 100 bytes, PSH KEPT (last).
        verify_v4_seg(&out[1600..1600 + lens[1]], 0x1235, 1100, 100);
        assert_eq!(
            out[1600 + ETH_HLEN + 33] & TCP_FLAG_PSH,
            TCP_FLAG_PSH,
            "PSH kept seg1"
        );

        // Payload bytes intact.
        assert_eq!(out[ETH_HLEN + 40], 0xAA);
        assert_eq!(out[1600 + ETH_HLEN + 40], 0xAA);
    }

    /// IPv4, 250 bytes, gso_size=100 → 3 segments: 100, 100, 50.
    /// Last segment shorter — the iperf3 trailing-ACK case.
    #[test]
    fn split_v4_short_tail() {
        let pkt = build_v4_tcp(250);
        let hdr = hdr_v4(100);
        let mut out = vec![0u8; 4 * 1600];
        let mut lens = [0usize; 4];

        let n = tso_split(&pkt, &hdr, GsoType::TcpV4, &mut out, 1600, &mut lens).unwrap();
        assert_eq!(n, 3);
        assert_eq!(lens[0], ETH_HLEN + 40 + 100);
        assert_eq!(lens[1], ETH_HLEN + 40 + 100);
        assert_eq!(lens[2], ETH_HLEN + 40 + 50);

        verify_v4_seg(&out[..lens[0]], 0x1234, 1000, 100);
        verify_v4_seg(&out[1600..1600 + lens[1]], 0x1235, 1100, 100);
        verify_v4_seg(&out[3200..3200 + lens[2]], 0x1236, 1200, 50);

        // PSH only on last.
        assert_eq!(out[ETH_HLEN + 33] & TCP_FLAG_PSH, 0);
        assert_eq!(out[1600 + ETH_HLEN + 33] & TCP_FLAG_PSH, 0);
        assert_eq!(out[3200 + ETH_HLEN + 33] & TCP_FLAG_PSH, TCP_FLAG_PSH);
    }

    /// Single chunk: payload ≤ gso_size → 1 segment, identical to
    /// input (modulo eth header). The "kernel handed us a small
    /// packet anyway" case.
    #[test]
    fn split_v4_single_chunk() {
        let pkt = build_v4_tcp(50);
        let hdr = hdr_v4(100);
        let mut out = vec![0u8; 1600];
        let mut lens = [0usize; 1];

        let n = tso_split(&pkt, &hdr, GsoType::TcpV4, &mut out, 1600, &mut lens).unwrap();
        assert_eq!(n, 1);
        assert_eq!(lens[0], ETH_HLEN + 40 + 50);
        verify_v4_seg(&out[..lens[0]], 0x1234, 1000, 50);
        // PSH kept (only/last segment).
        assert_eq!(out[ETH_HLEN + 33] & TCP_FLAG_PSH, TCP_FLAG_PSH);
    }

    /// IPv6: no IP csum, no ID, payload_len field instead of totlen.
    #[test]
    fn split_v6_even() {
        let pkt = build_v6_tcp(200);
        let hdr = hdr_v6(100);
        let mut out = vec![0u8; 4 * 1600];
        let mut lens = [0usize; 4];

        let n = tso_split(&pkt, &hdr, GsoType::TcpV6, &mut out, 1600, &mut lens).unwrap();
        assert_eq!(n, 2);
        assert_eq!(lens[0], ETH_HLEN + 60 + 100);

        // Ethertype = IPv6.
        assert_eq!(&out[12..14], &ETH_P_IPV6.to_be_bytes());
        let ip = &out[ETH_HLEN..ETH_HLEN + 60 + 100];
        // ver=6.
        assert_eq!(ip[0] >> 4, 6);
        // plen = TCP hdr + payload chunk = 20 + 100.
        assert_eq!(u16::from_be_bytes([ip[4], ip[5]]), 120);
        // seq = 1000.
        assert_eq!(u32::from_be_bytes([ip[44], ip[45], ip[46], ip[47]]), 1000);
        // TCP csum: verify against pseudo-header.
        let mut tcp = ip[40..].to_vec();
        let stored = [tcp[16], tcp[17]];
        tcp[16] = 0;
        tcp[17] = 0;
        let pseudo = pseudo_header_checksum_nofold(IPPROTO_TCP, &ip[8..40], 120);
        assert_eq!(checksum(&tcp, pseudo).to_be_bytes(), stored);

        // Seg 1: seq = 1100, plen = 120.
        let ip1 = &out[1600 + ETH_HLEN..1600 + ETH_HLEN + 60 + 100];
        assert_eq!(u16::from_be_bytes([ip1[4], ip1[5]]), 120);
        assert_eq!(
            u32::from_be_bytes([ip1[44], ip1[45], ip1[46], ip1[47]]),
            1100
        );
    }

    /// Seqno wrap. RFC 793: seqno is mod 2^32. A long-lived flow
    /// near the wrap point must not break.
    #[test]
    fn split_seq_wraps() {
        let mut pkt = build_v4_tcp(200);
        // Set seq to 0xFFFF_FF80 (128 below wrap).
        pkt[24..28].copy_from_slice(&0xFFFF_FF80u32.to_be_bytes());
        let hdr = hdr_v4(100);
        let mut out = vec![0u8; 4 * 1600];
        let mut lens = [0usize; 4];

        let n = tso_split(&pkt, &hdr, GsoType::TcpV4, &mut out, 1600, &mut lens).unwrap();
        assert_eq!(n, 2);
        // Seg 0: 0xFFFF_FF80.
        let s0 = u32::from_be_bytes([
            out[ETH_HLEN + 24],
            out[ETH_HLEN + 25],
            out[ETH_HLEN + 26],
            out[ETH_HLEN + 27],
        ]);
        assert_eq!(s0, 0xFFFF_FF80);
        // Seg 1: 0xFFFF_FF80 + 100 = 0xFFFF_FFE4.
        let s1 = u32::from_be_bytes([
            out[1600 + ETH_HLEN + 24],
            out[1600 + ETH_HLEN + 25],
            out[1600 + ETH_HLEN + 26],
            out[1600 + ETH_HLEN + 27],
        ]);
        assert_eq!(s1, 0xFFFF_FFE4);
    }

    // ─── tso_split: error paths ────────────────────────────────

    #[test]
    fn split_err_too_short() {
        let hdr = hdr_v4(100);
        let mut out = [0u8; 1600];
        let mut lens = [0usize; 1];
        // Can't even read TCP data offset.
        assert_eq!(
            tso_split(&[0x45; 30], &hdr, GsoType::TcpV4, &mut out, 1600, &mut lens),
            Err(TsoError::TooShort)
        );
    }

    #[test]
    fn split_err_bad_tcp_hlen() {
        let mut pkt = build_v4_tcp(100);
        pkt[32] = 3 << 4; // doff=3 → 12 bytes, < 20.
        let hdr = hdr_v4(100);
        let mut out = [0u8; 1600];
        let mut lens = [0usize; 1];
        assert_eq!(
            tso_split(&pkt, &hdr, GsoType::TcpV4, &mut out, 1600, &mut lens),
            Err(TsoError::BadTcpHlen)
        );
    }

    #[test]
    fn split_err_ip_mismatch() {
        let pkt = build_v4_tcp(100);
        let hdr = hdr_v6(100); // says v6, packet is v4.
        let mut out = [0u8; 1600];
        let mut lens = [0usize; 1];
        assert_eq!(
            tso_split(&pkt, &hdr, GsoType::TcpV6, &mut out, 1600, &mut lens),
            Err(TsoError::IpVersionMismatch)
        );
    }

    #[test]
    fn split_err_too_many_segments() {
        // 1000 bytes / 100 gso = 10 segments, but only 2 slots.
        let pkt = build_v4_tcp(1000);
        let hdr = hdr_v4(100);
        let mut out = vec![0u8; 2 * 1600];
        let mut lens = [0usize; 2];
        assert_eq!(
            tso_split(&pkt, &hdr, GsoType::TcpV4, &mut out, 1600, &mut lens),
            Err(TsoError::TooManySegments)
        );
    }

    /// `gso_none_checksum`: the partial-csum completion. Build a
    /// packet with the pseudo-header sum stuffed into the csum field
    /// (what the kernel does), call gso_none_checksum, verify the
    /// resulting csum is valid.
    #[test]
    fn gso_none_completes_partial_csum() {
        let mut pkt = build_v4_tcp(100);
        // Replace the valid TCP csum with the pseudo-header sum
        // (what the kernel writes for CHECKSUM_PARTIAL).
        let pseudo = pseudo_header_checksum_nofold(IPPROTO_TCP, &pkt[12..20], 120);
        // Fold pseudo to 16 bits, NO complement (the kernel writes
        // the un-complemented partial — RFC 1071 chaining).
        let mut p = pseudo;
        p = (p >> 16) + (p & 0xffff);
        p = (p >> 16) + (p & 0xffff);
        pkt[36..38].copy_from_slice(&(p as u16).to_be_bytes());

        gso_none_checksum(&mut pkt, 20, 16);

        // Now the TCP csum should be valid: re-verify.
        let mut tcp = pkt[20..].to_vec();
        let stored = [tcp[16], tcp[17]];
        tcp[16] = 0;
        tcp[17] = 0;
        let pseudo = pseudo_header_checksum_nofold(IPPROTO_TCP, &pkt[12..20], 120);
        assert_eq!(checksum(&tcp, pseudo).to_be_bytes(), stored);
    }
}
