//! Packet header structs + RFC 1071 checksum (`route.c` prep).
//!
//! `route.c` SYNTHESIZES packets — ICMP unreachable, ARP replies,
//! NDP NA — with hand-computed checksums. `etherparse` is read-only.
//! These are the `#[repr(C, packed)]` structs and the `inet_checksum`
//! function the builders will use (chunk 7, when `vpn_packet_t`
//! lands).
//!
//! ## `#[repr(C, packed)]` + zerocopy
//!
//! Every struct here is packed, no padding (the `const _: () =
//! assert!(size_of == N)` checks prove it). Serialization is just
//! a transmute; `zerocopy::{FromBytes, IntoBytes}` derive that.
//!
//! Packed → fields may be unaligned → Rust REFUSES `&self.field`.
//! Read with `let x = self.field;` (copy to local). The accessors
//! below all copy out; setters write back.
//!
//! ## Endianness
//!
//! Fields are stored RAW — network-order bytes as they sit on the
//! wire. Getters do `u16::from_be(raw)`. Setters take host-order
//! and write `to_be()`. We push the `htons`/`ntohs` into accessors
//! so the caller never sees a wrong-endian number.
//!
//! ## No bitfields
//!
//! `struct ip` has `ip_hl:4` and `ip_v:4`. C bitfield order is
//! implementation-defined, which is why `ipv4.h:67-72` flips the
//! definition under `__BYTE_ORDER == __LITTLE_ENDIAN`. The C is
//! FIGHTING the compiler. The wire byte is always `(v<<4)|hl`. We
//! store one `u8` and shift/mask. No fight, no `bitfield` crate.

// Field names mirror the C structs (`ip_ttl`, `icmp6_cksum`, ...) so
// cross-referencing `route.c` line-by-line stays mechanical.
#![allow(clippy::struct_field_names)]
#![forbid(unsafe_code)]

use std::mem::size_of;

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

// ── inet_checksum ──────────────────────────────────────────────────

/// `inet_checksum`. RFC 1071 one's-complement sum.
///
/// Chainable: pass `0xFFFF` for the first call, then feed the
/// previous return value as `prevsum` to fold in more data (e.g.
/// ICMP header, then chain the payload).
///
/// **Endianness**: `memcpy(&word, data, 2)` is a NATIVE-
/// endian load. We use `from_ne_bytes`. RFC 1071 §2(B) proves the
/// sum is byte-order independent on the wire (the byte-swapped sum
/// equals the swap of the sum), but the *numeric* `u16` we return
/// is host-order. Doesn't matter: it's always written back into a
/// raw checksum field via `memcpy`/`to_ne_bytes`, so the bytes on
/// the wire are correct on either endianness.
///
/// **Odd tail**: `checksum += *data` puts the last byte in the LOW
/// half of the u32, NOT high. Easy to get wrong if you "fix" it to
/// look like a big-endian high-byte pad.
#[must_use]
pub(crate) fn inet_checksum(data: &[u8], prevsum: u16) -> u16 {
    let mut checksum: u32 = u32::from(prevsum ^ 0xFFFF);

    let (chunks, rem) = data.as_chunks::<2>();
    for pair in chunks {
        // memcpy(&word, data, 2) — NATIVE-endian, not BE.
        checksum += u32::from(u16::from_ne_bytes(*pair));
    }
    // Tail byte goes in the LOW half. RFC 1071 §4.1.
    if let [tail] = rem {
        checksum += u32::from(*tail);
    }

    // Fold carries until the high half is zero.
    while checksum >> 16 != 0 {
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
    }

    #[expect(clippy::cast_possible_truncation)] // fold loop above zeroes high half
    {
        !(checksum as u16)
    }
}

// ── IPv4 header ────────────────────────────────────────────────────

/// `struct ip` (`ipv4.h:74-85`). 20 bytes, no options.
///
/// `ip_vhl` is the bitfield byte: `(version << 4) | ihl`. The C
/// uses `:4` bitfields with `__BYTE_ORDER` gymnastics (`ipv4.h
/// :67-72`); we use a `u8` and getters. Wire byte for normal IPv4
/// is `0x45` (v=4, ihl=5 words = 20 bytes).
#[repr(C, packed)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub(crate) struct Ipv4Hdr {
    /// `(ip_v << 4) | ip_hl`. Bitfield in C; one byte here.
    pub ip_vhl: u8,
    pub ip_tos: u8,
    /// Total length, network order. Use [`Self::total_len`]/[`Self::set_total_len`].
    ip_len: u16,
    ip_id: u16,
    ip_off: u16,
    pub ip_ttl: u8,
    pub ip_p: u8,
    /// Checksum, raw. NOT byte-swapped: `inet_checksum` returns
    /// host-order which `memcpy`'s back as-is.
    pub ip_sum: u16,
    /// `struct in_addr ip_src`. Raw bytes, network order.
    pub ip_src: [u8; 4],
    pub ip_dst: [u8; 4],
}

const _: () = assert!(size_of::<Ipv4Hdr>() == 20);

const _: () = assert!(size_of::<IcmpHdr>() == 8);

const _: () = assert!(size_of::<Ipv6Hdr>() == 40);

const _: () = assert!(size_of::<Icmp6Hdr>() == 8);

const _: () = assert!(size_of::<ArpHdr>() == 8);

const _: () = assert!(size_of::<EtherArp>() == 28);

const _: () = assert!(size_of::<Ipv6Pseudo>() == 40);

const _: () = assert!(size_of::<Ipv4Pseudo>() == 12);

/// `IP_OFFMASK` (`ipv4.h:96`). Low 13 bits of `ip_off`.
pub(crate) const IP_OFFMASK: u16 = 0x1fff;
/// `IP_DF` (`ipv4.h:90`). Don't Fragment.
#[cfg(test)]
pub(crate) const IP_DF: u16 = 0x4000;
/// `IP_MF` (`ipv4.h:91`). More Fragments.
pub(crate) const IP_MF: u16 = 0x2000;

impl Ipv4Hdr {
    /// `ip_v` — high nibble. 4 for IPv4.
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn version(self) -> u8 {
        self.ip_vhl >> 4
    }
    /// `ip_hl` — low nibble. Header length in 32-bit words.
    #[must_use]
    pub(crate) const fn ihl(self) -> u8 {
        self.ip_vhl & 0x0F
    }
    /// Set version + IHL.
    pub(crate) const fn set_vhl(&mut self, version: u8, ihl: u8) {
        self.ip_vhl = (version << 4) | (ihl & 0x0F);
    }

    /// `ntohs(ip_len)`. Named `total_len` not `len`: this is the
    /// IPv4 total-length field, not a collection length.
    #[must_use]
    pub(crate) const fn total_len(self) -> u16 {
        // packed: copy out before swap.
        let raw = self.ip_len;
        u16::from_be(raw)
    }
    /// `ip_len = htons(v)`.
    pub(crate) const fn set_total_len(&mut self, v: u16) {
        self.ip_len = v.to_be();
    }

    /// `ntohs(ip_off)`. Compare against `IP_OFFMASK`/`IP_MF`.
    #[must_use]
    pub(crate) const fn off(self) -> u16 {
        let raw = self.ip_off;
        u16::from_be(raw)
    }
    pub(crate) const fn set_off(&mut self, v: u16) {
        self.ip_off = v.to_be();
    }

    /// `ntohs(ip_id)`.
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn id(self) -> u16 {
        let raw = self.ip_id;
        u16::from_be(raw)
    }
    pub(crate) const fn set_id(&mut self, v: u16) {
        self.ip_id = v.to_be();
    }
}

// ── ICMP header (short) ────────────────────────────────────────────

/// `struct icmp`, FIRST 8 BYTES ONLY. The full C struct (`ipv4.h
/// :100-148`) is 28 bytes with a variant tail union. `route.c` only
/// touches type/code/cksum/nextmtu and uses `icmp_size = 8`. We
/// model just that.
///
/// `icmp.icmp_nextmtu = htons(...)` is `icmp_hun.ih_pmtu.ipm_nextmtu`
/// — bytes 6-7 of the struct (the
/// SECOND `u16` of the 4-byte union). Bytes 4-5 are `ipm_void`
/// (unused, zero).
#[repr(C, packed)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub(crate) struct IcmpHdr {
    pub icmp_type: u8,
    pub icmp_code: u8,
    /// Raw, like `Ipv4Hdr::ip_sum`. `inet_checksum` output.
    pub icmp_cksum: u16,
    /// `ipm_void` (`ipv4.h:116`). Always zero in `route.c`.
    pub icmp_void: u16,
    /// `ipm_nextmtu` (`ipv4.h:117`). Network order.
    icmp_nextmtu: u16,
}

impl IcmpHdr {
    /// `icmp.icmp_nextmtu = htons(v)`.
    pub(crate) const fn set_nextmtu(&mut self, v: u16) {
        self.icmp_nextmtu = v.to_be();
    }
}

// ── IPv6 header ────────────────────────────────────────────────────

/// `struct ip6_hdr` (`ipv6.h:42-53`). 40 bytes.
///
/// `ip6_flow` is `(v<<28)|(tc<<20)|flow`. `htonl(0x60000000)` is
/// version 6, tc 0, flow 0.
#[repr(C, packed)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub(crate) struct Ipv6Hdr {
    /// `ip6_un1_flow`. Network order. `(v<<28)|(tc<<20)|flow`.
    ip6_flow: u32,
    /// Payload length, network order.
    ip6_plen: u16,
    pub ip6_nxt: u8,
    pub ip6_hlim: u8,
    pub ip6_src: [u8; 16],
    pub ip6_dst: [u8; 16],
}

impl Ipv6Hdr {
    /// `ip6.ip6_flow = htonl(v)`.
    pub(crate) const fn set_flow(&mut self, v: u32) {
        self.ip6_flow = v.to_be();
    }
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn flow(self) -> u32 {
        let raw = self.ip6_flow;
        u32::from_be(raw)
    }
    /// Version nibble. High 4 bits of byte 0. 6 for IPv6.
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn version(self) -> u8 {
        // High byte of BE u32, high nibble.
        let raw = self.ip6_flow;
        (u32::from_be(raw) >> 28) as u8
    }

    /// `ip6.ip6_plen = htons(v)`.
    pub(crate) const fn set_plen(&mut self, v: u16) {
        self.ip6_plen = v.to_be();
    }
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn plen(self) -> u16 {
        let raw = self.ip6_plen;
        u16::from_be(raw)
    }
}

// ── ICMPv6 header ──────────────────────────────────────────────────

/// `struct icmp6_hdr` (`ipv6.h:66-75`). 8 bytes.
///
/// `icmp6_data32[0]` aliases `icmp6_mtu` (`ipv6.h:89`). `route.c
/// :281`: `icmp6.icmp6_mtu = htonl(len)` for `ICMP6_PACKET_TOO_BIG`.
#[repr(C, packed)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub(crate) struct Icmp6Hdr {
    pub icmp6_type: u8,
    pub icmp6_code: u8,
    /// Raw checksum. `inet_checksum` output.
    pub icmp6_cksum: u16,
    /// `icmp6_un_data32[0]` / `icmp6_mtu`. Network order.
    icmp6_data32: u32,
}

impl Icmp6Hdr {
    /// `icmp6.icmp6_mtu = htonl(v)`.
    pub(crate) const fn set_mtu(&mut self, v: u32) {
        self.icmp6_data32 = v.to_be();
    }
}

// ── ARP ────────────────────────────────────────────────────────────

/// `struct arphdr` (`ethernet.h:75-81`). Fixed 8-byte ARP header.
#[repr(C, packed)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub(crate) struct ArpHdr {
    /// Hardware type. Network order. `ARPHRD_ETHER` = 1.
    ar_hrd: u16,
    /// Protocol type. Network order. `ETH_P_IP` = 0x0800.
    ar_pro: u16,
    pub ar_hln: u8,
    pub ar_pln: u8,
    /// Opcode. Network order. `ARPOP_REQUEST`=1, `ARPOP_REPLY`=2.
    ar_op: u16,
}

/// `ARPOP_REQUEST` (`ethernet.h:82`).
pub(crate) const ARPOP_REQUEST: u16 = 1;
/// `ARPOP_REPLY` (`ethernet.h:83`).
pub(crate) const ARPOP_REPLY: u16 = 2;
/// `ARPHRD_ETHER` (`ethernet.h:40`).
pub(crate) const ARPHRD_ETHER: u16 = 1;

// `ETH_P_IP`/`ETH_P_IPV6` live in `tinc-device/src/ether.rs` (the
// source of truth) but they're `pub(crate)` there. Re-declared here
// with a pointer back. RFC constants; can't drift.
/// `ETH_P_IP` — see `tinc-device/src/ether.rs:32`.
pub(crate) const ETH_P_IP: u16 = 0x0800;
/// `ETH_P_ARP` (`ethernet.h:48`). NOT in `tinc-device`.
pub(crate) const ETH_P_ARP: u16 = 0x0806;

impl ArpHdr {
    #[must_use]
    pub(crate) const fn hrd(self) -> u16 {
        let raw = self.ar_hrd;
        u16::from_be(raw)
    }
    #[cfg(test)]
    pub(crate) const fn set_hrd(&mut self, v: u16) {
        self.ar_hrd = v.to_be();
    }
    #[must_use]
    pub(crate) const fn pro(self) -> u16 {
        let raw = self.ar_pro;
        u16::from_be(raw)
    }
    #[cfg(test)]
    pub(crate) const fn set_pro(&mut self, v: u16) {
        self.ar_pro = v.to_be();
    }
    #[must_use]
    pub(crate) const fn op(self) -> u16 {
        let raw = self.ar_op;
        u16::from_be(raw)
    }
    pub(crate) const fn set_op(&mut self, v: u16) {
        self.ar_op = v.to_be();
    }
}

/// `struct ether_arp` (`ethernet.h:93-99`). 28 bytes: `arphdr` +
/// sender/target HA(6)/PA(4) for Ethernet/IPv4. The C nests
/// `struct arphdr ea_hdr` and uses `#define arp_op ea_hdr.ar_op`
/// to flatten access; we just embed.
#[repr(C, packed)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub(crate) struct EtherArp {
    pub ea_hdr: ArpHdr,
    pub arp_sha: [u8; 6],
    pub arp_spa: [u8; 4],
    pub arp_tha: [u8; 6],
    pub arp_tpa: [u8; 4],
}

// ── Pseudo-headers (checksum only) ─────────────────────────────────

/// IPv6 pseudo-header for upper-layer checksum (RFC 2460 §8.1). 40
/// bytes. NOT a wire header — never transmitted; checksum input
/// only. `length` and `next` are `uint32_t`, written with `htonl`.
#[repr(C, packed)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub(crate) struct Ipv6Pseudo {
    pub ip6_src: [u8; 16],
    pub ip6_dst: [u8; 16],
    /// Upper-layer length, network order.
    length: u32,
    /// Next header (`IPPROTO_ICMPV6`), network order.
    next: u32,
}

impl Ipv6Pseudo {
    pub(crate) const fn set_length(&mut self, v: u32) {
        self.length = v.to_be();
    }
    pub(crate) const fn set_next(&mut self, v: u32) {
        self.next = v.to_be();
    }
}

/// IPv4 pseudo-header for TCP/UDP checksum (RFC 793 §3.1). 12 bytes.
/// `route.c`'s MSS clamping uses this (chunk 7). Same shape as the
/// kernel's `struct tcp_pseudo_hdr`.
#[repr(C, packed)]
#[derive(Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub(crate) struct Ipv4Pseudo {
    pub ip_src: [u8; 4],
    pub ip_dst: [u8; 4],
    pub zero: u8,
    pub proto: u8,
    /// TCP/UDP length, network order.
    length: u16,
}

impl Ipv4Pseudo {
    pub(crate) const fn set_length(&mut self, v: u16) {
        self.length = v.to_be();
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use zerocopy::IntoBytes;

    // ─── Struct sizes — pin layout

    /// `STATIC_ASSERT(sizeof(struct ip) == 20)` (`ipv4.h:93`).
    /// Already const-asserted at module level; this test exists so
    /// `cargo test packet` shows it in the count.
    #[test]
    fn struct_sizes_match_c_static_asserts() {
        assert_eq!(size_of::<Ipv4Hdr>(), 20); // ipv4.h:93
        assert_eq!(size_of::<IcmpHdr>(), 8); // icmp_size
        assert_eq!(size_of::<Ipv6Hdr>(), 40); // ipv6.h:63
        assert_eq!(size_of::<Icmp6Hdr>(), 8); // ipv6.h:91
        assert_eq!(size_of::<ArpHdr>(), 8); // ethernet.h:90
        assert_eq!(size_of::<EtherArp>(), 28); // ethernet.h:107
        assert_eq!(size_of::<Ipv6Pseudo>(), 40);
        assert_eq!(size_of::<Ipv4Pseudo>(), 12);
    }

    // ─── Bitfield byte ordering

    /// THE bitfield test. `ipv4.h:67-72` flips `ip_hl`/`ip_v`
    /// nibble order under `__LITTLE_ENDIAN` because GCC packs
    /// bitfields LSB-first on LE. The wire byte is ALWAYS
    /// `(v<<4)|hl`: v=4, hl=5 → `0x45`. Not `0x54`. Ever.
    #[test]
    fn ipv4_ihl_v_packing() {
        let mut h = Ipv4Hdr::default();
        h.set_vhl(4, 5);
        // Wire byte 0 is 0x45. This is what tcpdump shows.
        assert_eq!(h.ip_vhl, 0x45);
        assert_eq!(h.version(), 4);
        assert_eq!(h.ihl(), 5);
        // Round-trip via wire.
        assert_eq!(h.as_bytes()[0], 0x45);
    }

    /// IPv6: `ip6.ip6_flow = htonl(0x60000000)`. Byte 0 on the wire
    /// is `0x60` (v=6, tc high nibble = 0).
    #[test]
    fn ipv6_flow_version_packing() {
        let mut h = Ipv6Hdr::default();
        h.set_flow(0x6000_0000);
        assert_eq!(h.as_bytes()[0], 0x60);
        assert_eq!(h.version(), 6);
    }

    // ─── Endianness in accessors

    /// `set_total_len(115)` → bytes `[0x00, 0x73]` on the wire. The
    /// stored `u16` is whatever `to_be()` produces on the host;
    /// `to_bytes()` writes it via `to_ne_bytes()` so the bytes are
    /// always BE regardless of host. This is the `htons`.
    #[test]
    fn ipv4hdr_len_is_be_on_wire() {
        let mut h = Ipv4Hdr::default();
        h.set_total_len(115);
        assert_eq!(h.total_len(), 115);
        assert_eq!(&h.as_bytes()[2..4], &[0x00, 0x73]);
    }

    // ─── Round-trip

    /// Build, serialize, parse, eq.
    #[test]
    fn ipv4hdr_roundtrip() {
        let mut h = Ipv4Hdr::default();
        h.set_vhl(4, 5);
        h.ip_tos = 0;
        h.set_total_len(115);
        h.set_id(0);
        h.set_off(IP_DF);
        h.ip_ttl = 64;
        h.ip_p = 17; // UDP
        h.ip_sum = 0;
        h.ip_src = [192, 168, 0, 1];
        h.ip_dst = [192, 168, 0, 199];

        let b = h.as_bytes();
        // This is the same header as kat/gen_checksum.c case 5.
        let expect: [u8; 20] = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        assert_eq!(b, expect);

        let back = Ipv4Hdr::read_from_bytes(b).unwrap();
        assert_eq!(back.version(), 4);
        assert_eq!(back.ihl(), 5);
        assert_eq!(back.total_len(), 115);
        assert_eq!(back.off(), IP_DF);
        assert_eq!(back.ip_ttl, 64);
        assert_eq!(back.ip_src, [192, 168, 0, 1]);
        assert_eq!(back.ip_dst, [192, 168, 0, 199]);
    }

    #[test]
    fn ipv6hdr_roundtrip() {
        let mut h = Ipv6Hdr::default();
        h.set_flow(0x6000_0000);
        h.set_plen(32);
        h.ip6_nxt = 58; // IPPROTO_ICMPV6
        h.ip6_hlim = 255;
        h.ip6_src = *b"\xfe\x80\0\0\0\0\0\0\0\0\0\0\0\0\0\x01";
        h.ip6_dst = *b"\xfe\x80\0\0\0\0\0\0\0\0\0\0\0\0\0\x02";

        let b = h.as_bytes();
        assert_eq!(b[0], 0x60);
        assert_eq!(&b[4..6], &[0x00, 0x20]); // plen=32 BE
        assert_eq!(b[6], 58);
        assert_eq!(b[7], 255);
        assert_eq!(&b[8..24], &h.ip6_src);

        let back = Ipv6Hdr::read_from_bytes(b).unwrap();
        assert_eq!(back.flow(), 0x6000_0000);
        assert_eq!(back.plen(), 32);
        assert_eq!(back.ip6_nxt, 58);
        assert_eq!(back.ip6_src, h.ip6_src);
    }

    #[test]
    fn ether_arp_roundtrip() {
        let mut a = EtherArp::default();
        a.ea_hdr.set_hrd(ARPHRD_ETHER);
        a.ea_hdr.set_pro(ETH_P_IP);
        a.ea_hdr.ar_hln = 6;
        a.ea_hdr.ar_pln = 4;
        a.ea_hdr.set_op(ARPOP_REPLY);
        a.arp_sha = [0xaa; 6];
        a.arp_spa = [10, 0, 0, 1];
        a.arp_tha = [0xbb; 6];
        a.arp_tpa = [10, 0, 0, 2];

        let b = a.as_bytes();
        assert_eq!(&b[0..2], &[0x00, 0x01]); // ARPHRD_ETHER BE
        assert_eq!(&b[2..4], &[0x08, 0x00]); // ETH_P_IP BE
        assert_eq!(&b[6..8], &[0x00, 0x02]); // ARPOP_REPLY BE
        assert_eq!(&b[8..14], &[0xaa; 6]);
        assert_eq!(&b[14..18], &[10, 0, 0, 1]);

        let back = EtherArp::read_from_bytes(b).unwrap();
        assert_eq!(back.ea_hdr.op(), ARPOP_REPLY);
        assert_eq!(back.arp_spa, [10, 0, 0, 1]);
    }

    // ─── inet_checksum KAT

    /// KAT vectors from `kat/gen_checksum.c`. Proves bit-for-bit
    /// match including the native-endian `memcpy` load and the
    /// low-half tail byte.
    #[test]
    fn inet_checksum_kat() {
        // Embedded vectors. Regenerate: nix build .#kat-checksum
        // Format: (name, hex_data, prevsum, expected_checksum)
        #[rustfmt::skip]
        let cases: &[(&str, &str, u16, u16)] = &[
            ("empty",                  "",                                         0xFFFF, 65535),
            ("rfc1071_example",        "0001f203f4f5f6f7",                         0xFFFF,  3362),
            ("single_byte",            "ab",                                       0xFFFF, 65364),
            ("odd_length_3",           "123456",                                   0xFFFF, 52119),
            ("ipv4_header_zeroed_sum", "450000730000400040110000c0a80001c0a800c7", 0xFFFF, 25016),
            ("chain_first_half",       "0001f203",                                 0xFFFF, 64269),
            ("chain_second_half",      "f4f5f6f7",                                  64269,  3362),
            ("all_ones_8",             "ffffffffffffffff",                         0xFFFF,     0),
        ];

        for (name, hex, prevsum, expect) in cases {
            let data = decode_hex(hex);
            let got = inet_checksum(&data, *prevsum);
            assert_eq!(
                got, *expect,
                "case {name}: got {got:#06x} want {expect:#06x}"
            );
        }
    }

    /// Separate test: chain == single. The chained-checksum pattern
    /// (ICMP header, then payload) relies on this property: result
    /// MUST equal checksumming both at once.
    #[test]
    fn inet_checksum_is_chainable() {
        let data = decode_hex("0001f203f4f5f6f7");
        let single = inet_checksum(&data, 0xFFFF);
        let mid = inet_checksum(&data[..4], 0xFFFF);
        let chain = inet_checksum(&data[4..], mid);
        assert_eq!(single, chain);
        assert_eq!(single, 0x0d22); // RFC 1071 §3 worked example.
    }

    /// Feeding the checksum back over the same data → 0. This is how
    /// receivers verify: include the checksum field, sum, expect 0.
    #[test]
    fn inet_checksum_verifies_to_zero() {
        // Real IPv4 header with sum filled in.
        let mut hdr: [u8; 20] = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        let sum = inet_checksum(&hdr, 0xFFFF);
        // Write it back into the checksum field, native order
        // (this is what `memcpy(&ip.ip_sum, ...)` does in C).
        hdr[10..12].copy_from_slice(&sum.to_ne_bytes());
        // Re-checksum: must be 0 (or 0xFFFF in one's-complement,
        // but the C returns 0 here because ~0xFFFF == 0).
        assert_eq!(inet_checksum(&hdr, 0xFFFF), 0);
    }

    // tiny hex decoder for the KAT table — no serde needed for 8 cases
    fn decode_hex(s: &str) -> Vec<u8> {
        assert_eq!(s.len() % 2, 0);
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
