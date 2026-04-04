//! ARP/NDP reply synthesis (`route.c:793-1035`).
//!
//! The fake-MAC trick (`route.c:1015-1016`, `:899-900`): answer the
//! kernel's ARP/NS with its OWN eth-src MAC, last byte XOR `0xFF`.
//! Kernel caches it, sends to it; daemon reads everything off TUN
//! regardless of dst MAC. The XOR is cosmetic ("for consistency").
//!
//! C inlines subnet-lookup; we split: `parse_*` returns target IP,
//! daemon looks up, `build_*` synthesizes.
//!
//! `overwrite-mac` (`:970-973`, `:830-832`) and `source != myself`
//! (`:964-967`, `:814-817`): handled at the daemon callsite
//! (`handle_arp`/`handle_ndp`); this module stays pure.

#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)] // header-size constants, max 32

use std::net::{Ipv4Addr, Ipv6Addr};

use zerocopy::{FromBytes, IntoBytes};

use crate::packet::{
    ARPHRD_ETHER, ARPOP_REPLY, ARPOP_REQUEST, ETH_P_IP, EtherArp, Ipv6Hdr, Ipv6Pseudo,
    inet_checksum,
};

// ── Sizes (`route.c:50-56`) ────────────────────────────────────────

const ETHER_SIZE: usize = 14;
const ETH_ALEN: usize = 6;
const ARP_SIZE: usize = 28;
const IP6_SIZE: usize = 40;
const NS_SIZE: usize = 24; // icmp6_hdr(8) + in6_addr(16). ipv6.h:106
const OPT_SIZE: usize = 2; // {type, len}. ipv6.h:115
const IPPROTO_ICMPV6: u8 = 58;

// ── NDP constants (RFC 4861) ───────────────────────────────────────

pub const ND_NEIGHBOR_SOLICIT: u8 = 135;
pub const ND_NEIGHBOR_ADVERT: u8 = 136;
pub const ND_OPT_SOURCE_LINKADDR: u8 = 1;
pub const ND_OPT_TARGET_LINKADDR: u8 = 2;

// ── ARP ────────────────────────────────────────────────────────────

/// `route.c:960,977-984`. Returns `arp_tpa` iff `frame` is a valid
/// Ethernet/IP ARP who-has. Caller does subnet lookup (`:988-1002`).
#[must_use]
pub fn parse_arp_req(frame: &[u8]) -> Option<Ipv4Addr> {
    // route.c:960 checklength
    if frame.len() < ETHER_SIZE + ARP_SIZE {
        return None;
    }
    // route.c:977
    let arp_bytes: &[u8; ARP_SIZE] = frame[ETHER_SIZE..ETHER_SIZE + ARP_SIZE].try_into().ok()?;
    let arp = EtherArp::read_from_bytes(arp_bytes).ok()?;

    // route.c:980-984
    if arp.ea_hdr.hrd() != ARPHRD_ETHER
        || arp.ea_hdr.pro() != ETH_P_IP
        || arp.ea_hdr.ar_hln != ETH_ALEN as u8
        || arp.ea_hdr.ar_pln != 4
        || arp.ea_hdr.op() != ARPOP_REQUEST
    {
        return None;
    }

    Some(Ipv4Addr::from(arp.arp_tpa))
}

/// `route.c:1011-1022`. `arp_sha` = orig eth-src XOR `0xFF` on last
/// byte (the fake-MAC trick).
///
/// # Panics
/// If `original.len() < 42`. Caller validates with [`parse_arp_req`].
#[must_use]
pub fn build_arp_reply(original: &[u8]) -> Vec<u8> {
    debug_assert!(original.len() >= ETHER_SIZE + ARP_SIZE);

    let mut out = original[..ETHER_SIZE + ARP_SIZE].to_vec();

    // C does NOT touch the eth header (only :1022 copies arp back).
    // Eth-dst is ignored on a tap read.

    let arp_bytes: &[u8; ARP_SIZE] = original[ETHER_SIZE..ETHER_SIZE + ARP_SIZE]
        .try_into()
        .expect("validated");
    let mut arp = EtherArp::read_from_bytes(arp_bytes).expect("28 bytes");

    std::mem::swap(&mut arp.arp_tpa, &mut arp.arp_spa); // :1011-1013
    arp.arp_tha = arp.arp_sha; // :1014

    // :1015-1016 fake-MAC: orig eth-src, last byte flipped
    let eth_src: [u8; ETH_ALEN] = original[ETH_ALEN..ETH_ALEN * 2]
        .try_into()
        .expect("validated");
    arp.arp_sha = eth_src;
    arp.arp_sha[ETH_ALEN - 1] ^= 0xFF;

    arp.ea_hdr.set_op(ARPOP_REPLY); // :1017
    out[ETHER_SIZE..ETHER_SIZE + ARP_SIZE].copy_from_slice(arp.as_bytes()); // :1022
    out
}

// ── NDP ────────────────────────────────────────────────────────────

/// `route.c:808-861`. Returns `nd_ns_target` iff: long enough,
/// `ip6_nxt == ICMPV6`, type 135, opt-type ok (`:835-836`), and
/// **ICMPv6 checksum verifies** (`:847-861`). Hop-limit (RFC 4861
/// §7.1.1) is the kernel's job. We add the `ip6_nxt` check (C gets
/// it from route dispatch; we're freestanding).
#[must_use]
pub fn parse_ndp_solicit(frame: &[u8]) -> Option<Ipv6Addr> {
    // route.c:808 checklength
    if frame.len() < ETHER_SIZE + IP6_SIZE + NS_SIZE {
        return None;
    }
    // route.c:812
    let has_opt = frame.len() >= ETHER_SIZE + IP6_SIZE + NS_SIZE + OPT_SIZE + ETH_ALEN;

    // route.c:821-822
    let ip6_bytes: &[u8; IP6_SIZE] = frame[ETHER_SIZE..ETHER_SIZE + IP6_SIZE].try_into().ok()?;
    let ip6 = Ipv6Hdr::read_from_bytes(ip6_bytes).ok()?;

    // Not in C (route dispatch already branched); we're freestanding.
    if ip6.ip6_nxt != IPPROTO_ICMPV6 {
        return None;
    }

    let ns_off = ETHER_SIZE + IP6_SIZE;
    let ns = &frame[ns_off..ns_off + NS_SIZE];

    // :835-838
    if ns[0] != ND_NEIGHBOR_SOLICIT {
        return None;
    }
    if has_opt {
        let opt_type = frame[ns_off + NS_SIZE];
        if opt_type != ND_OPT_SOURCE_LINKADDR {
            return None;
        }
    }

    // :843-861 checksum verify
    let icmp_len = if has_opt {
        NS_SIZE + OPT_SIZE + ETH_ALEN
    } else {
        NS_SIZE
    };
    let mut pseudo = Ipv6Pseudo::default();
    pseudo.ip6_src = ip6.ip6_src;
    pseudo.ip6_dst = ip6.ip6_dst;
    pseudo.set_length(icmp_len as u32);
    pseudo.set_next(u32::from(IPPROTO_ICMPV6));

    // C feeds 4 separate calls (stack structs); we have contiguous bytes.
    let mut ck = inet_checksum(pseudo.as_bytes(), 0xFFFF);
    ck = inet_checksum(&frame[ns_off..ns_off + icmp_len], ck);
    if ck != 0 {
        return None;
    }

    let target: [u8; 16] = ns[8..24].try_into().ok()?;
    Some(Ipv6Addr::from(target))
}

/// `route.c:890-948`. Eth: dst←orig-src, src←orig-src⊕FF (`:899`).
/// Ip6: dst←orig-src, src←target (hlim untouched; kernel set 255,
/// RFC 4861 §7.2.2). Icmp6: type←ADVERT, reserved←Solicited (`:910`).
/// Opt: type←TARGET_LLADDR, lladdr←fake MAC (`:904`).
///
/// `:895` decrement_ttl: gated at the daemon callsite (`handle_ndp`)
/// before this fn is called — keeps this module pure.
#[must_use]
pub fn build_ndp_advert(original: &[u8]) -> Option<Vec<u8>> {
    if original.len() < ETHER_SIZE + IP6_SIZE + NS_SIZE {
        return None;
    }
    let has_opt = original.len() >= ETHER_SIZE + IP6_SIZE + NS_SIZE + OPT_SIZE + ETH_ALEN;
    let icmp_len = if has_opt {
        NS_SIZE + OPT_SIZE + ETH_ALEN
    } else {
        NS_SIZE
    };
    let total = ETHER_SIZE + IP6_SIZE + icmp_len;

    let mut out = original[..total].to_vec();

    // ── Ethernet (route.c:899-900) ───────────────────────────────
    // memcpy leaves dst=src=orig-src, then XOR hits the src half.
    let eth_src: [u8; ETH_ALEN] = original[ETH_ALEN..ETH_ALEN * 2].try_into().ok()?;
    out[..ETH_ALEN].copy_from_slice(&eth_src);
    out[ETH_ALEN..ETH_ALEN * 2].copy_from_slice(&eth_src);
    out[ETH_ALEN * 2 - 1] ^= 0xFF;
    let fake_mac: [u8; ETH_ALEN] = out[ETH_ALEN..ETH_ALEN * 2].try_into().ok()?;

    // ── IPv6 (route.c:902-903) ───────────────────────────────────
    let ip6_off = ETHER_SIZE;
    let ip6_bytes: &[u8; IP6_SIZE] = original[ip6_off..ip6_off + IP6_SIZE].try_into().ok()?;
    let mut ip6 = Ipv6Hdr::read_from_bytes(ip6_bytes).ok()?;

    let ns_off = ETHER_SIZE + IP6_SIZE;
    let target: [u8; 16] = original[ns_off + 8..ns_off + 24].try_into().ok()?;

    ip6.ip6_dst = ip6.ip6_src; // :902
    ip6.ip6_src = target; //       :903
    out[ip6_off..ip6_off + IP6_SIZE].copy_from_slice(ip6.as_bytes());

    // ── ICMPv6 / NS (route.c:909-911) ────────────────────────────
    // [type][code][cksum:2][reserved:4][target:16]
    out[ns_off] = ND_NEIGHBOR_ADVERT; // :910
    out[ns_off + 2] = 0; // :909
    out[ns_off + 3] = 0;
    // :911 Solicited flag (spec says R|S|O for proxy; tinc sets S only).
    out[ns_off + 4..ns_off + 8].copy_from_slice(&0x4000_0000u32.to_be_bytes());

    // ── Option (route.c:904-907,912) ─────────────────────────────
    if has_opt {
        let opt_off = ns_off + NS_SIZE;
        out[opt_off] = ND_OPT_TARGET_LINKADDR; // :912
        out[opt_off + OPT_SIZE..opt_off + OPT_SIZE + ETH_ALEN].copy_from_slice(&fake_mac); // :905-907
    }

    // ── Checksum (route.c:916-936) ───────────────────────────────
    let mut pseudo = Ipv6Pseudo::default();
    pseudo.ip6_src = ip6.ip6_src;
    pseudo.ip6_dst = ip6.ip6_dst;
    pseudo.set_length(icmp_len as u32);
    pseudo.set_next(u32::from(IPPROTO_ICMPV6));

    let mut ck = inet_checksum(pseudo.as_bytes(), 0xFFFF);
    ck = inet_checksum(&out[ns_off..ns_off + icmp_len], ck);
    out[ns_off + 2..ns_off + 4].copy_from_slice(&ck.to_ne_bytes()); // ne-order (packet.rs)

    Some(out)
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Eth+ARP "who has `tpa`? tell `spa`". eth-src locally administered.
    fn mk_arp_req(spa: [u8; 4], tpa: [u8; 4]) -> Vec<u8> {
        let mut f = Vec::with_capacity(ETHER_SIZE + ARP_SIZE);
        f.extend_from_slice(&[0xff; 6]);
        f.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
        f.extend_from_slice(&crate::packet::ETH_P_ARP.to_be_bytes());
        let mut a = EtherArp::default();
        a.ea_hdr.set_hrd(ARPHRD_ETHER);
        a.ea_hdr.set_pro(ETH_P_IP);
        a.ea_hdr.ar_hln = 6;
        a.ea_hdr.ar_pln = 4;
        a.ea_hdr.set_op(ARPOP_REQUEST);
        a.arp_sha = [0x02, 0, 0, 0, 0, 0x01];
        a.arp_spa = spa;
        a.arp_tha = [0; 6];
        a.arp_tpa = tpa;
        f.extend_from_slice(a.as_bytes());
        f
    }

    #[test]
    fn parse_arp_valid_request() {
        let f = mk_arp_req([10, 42, 0, 1], [10, 42, 0, 2]);
        assert_eq!(parse_arp_req(&f), Some(Ipv4Addr::new(10, 42, 0, 2)));
    }

    #[test]
    fn parse_arp_reply_is_none() {
        let mut f = mk_arp_req([10, 42, 0, 1], [10, 42, 0, 2]);
        f[ETHER_SIZE + 6..ETHER_SIZE + 8].copy_from_slice(&ARPOP_REPLY.to_be_bytes());
        assert_eq!(parse_arp_req(&f), None);
    }

    #[test]
    fn parse_arp_non_ethernet_hw() {
        let mut f = mk_arp_req([10, 42, 0, 1], [10, 42, 0, 2]);
        f[ETHER_SIZE..ETHER_SIZE + 2].copy_from_slice(&6u16.to_be_bytes()); // ARPHRD_IEEE802
        assert_eq!(parse_arp_req(&f), None);
    }

    #[test]
    fn parse_arp_too_short() {
        assert_eq!(parse_arp_req(&[0u8; 20]), None);
        assert_eq!(parse_arp_req(&[]), None);
        assert_eq!(parse_arp_req(&[0u8; 41]), None);
    }

    #[test]
    fn build_arp_reply_swaps() {
        let f = mk_arp_req([10, 42, 0, 1], [10, 42, 0, 2]);
        let r = build_arp_reply(&f);
        assert_eq!(r.len(), ETHER_SIZE + ARP_SIZE);

        let arp_bytes: &[u8; ARP_SIZE] = r[ETHER_SIZE..].try_into().unwrap();
        let arp = EtherArp::read_from_bytes(arp_bytes).unwrap();

        assert_eq!(arp.arp_spa, [10, 42, 0, 2]); // swapped
        assert_eq!(arp.arp_tpa, [10, 42, 0, 1]);
        assert_eq!(arp.ea_hdr.op(), ARPOP_REPLY);
        assert_eq!(arp.arp_tha, [0x02, 0, 0, 0, 0, 0x01]); // orig sha
        assert_eq!(arp.arp_sha, [0x02, 0, 0, 0, 0, 0x01 ^ 0xFF]); // fake MAC
        assert_eq!(&r[..ETHER_SIZE], &f[..ETHER_SIZE]); // eth unchanged
    }

    /// `route.c:971` snatch + `net_packet.c:1557-1562` stamp.
    /// neighbor.rs is pure (no daemon access); the daemon does the
    /// 4-line snatch+stamp at the callsite. This test checks the
    /// byte arithmetic is right.
    #[test]
    fn overwrite_mac_snatch_then_stamp() {
        // ARP from kernel, eth-src = the kernel's interface MAC.
        let mut req = mk_arp_req([10, 0, 0, 1], [10, 0, 0, 2]);
        let kernel_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        req[6..12].copy_from_slice(&kernel_mac);

        // C `route.c:971`: memcpy(mymac.x, DATA(packet)+ETH_ALEN, ETH_ALEN)
        // Daemon snatches AFTER parse_arp_req validates.
        assert!(parse_arp_req(&req).is_some());
        let mut mymac = [0u8; 6];
        mymac.copy_from_slice(&req[6..12]);
        assert_eq!(mymac, kernel_mac);

        // C `net_packet.c:1557-1562`: stamp on a frame headed TO the device.
        let mut frame = [0u8; 60];
        frame[0..6].copy_from_slice(&mymac);
        frame[6..12].copy_from_slice(&mymac);
        frame[11] ^= 0xFF;

        assert_eq!(&frame[0..6], &kernel_mac); // dst = kernel's own
        assert_eq!(&frame[6..11], &kernel_mac[..5]); // src = kernel's...
        assert_eq!(frame[11], 0x00); // ...XOR 0xFF on last byte
    }

    #[test]
    fn arp_roundtrip() {
        let f = mk_arp_req([192, 168, 1, 100], [192, 168, 1, 200]);
        assert_eq!(parse_arp_req(&f), Some(Ipv4Addr::new(192, 168, 1, 200)));
        let r = build_arp_reply(&f);
        assert_eq!(parse_arp_req(&r), None); // reply, not request
        let arp_bytes: &[u8; ARP_SIZE] = r[ETHER_SIZE..].try_into().unwrap();
        let arp = EtherArp::read_from_bytes(arp_bytes).unwrap();
        assert_eq!(arp.ea_hdr.hrd(), ARPHRD_ETHER);
        assert_eq!(arp.ea_hdr.pro(), ETH_P_IP);
    }

    // ── NDP fixtures ──────────────────────────────────────────────

    /// Valid NS with SOURCE_LLADDR opt + correct checksum.
    fn mk_ndp_solicit(target: Ipv6Addr) -> Vec<u8> {
        let eth_src = [0x02, 0, 0, 0, 0, 0x01];
        let ip_src: Ipv6Addr = "fe80::1".parse().unwrap();
        let ip_dst: Ipv6Addr = "ff02::1".parse().unwrap(); // tinc doesn't check dst

        let icmp_len = NS_SIZE + OPT_SIZE + ETH_ALEN;
        let mut f = Vec::with_capacity(ETHER_SIZE + IP6_SIZE + icmp_len);

        f.extend_from_slice(&[0x33, 0x33, 0, 0, 0, 0x01]);
        f.extend_from_slice(&eth_src);
        f.extend_from_slice(&0x86DDu16.to_be_bytes());

        let mut ip6 = Ipv6Hdr::default();
        ip6.set_flow(0x6000_0000);
        ip6.set_plen(icmp_len as u16);
        ip6.ip6_nxt = IPPROTO_ICMPV6;
        ip6.ip6_hlim = 255;
        ip6.ip6_src = ip_src.octets();
        ip6.ip6_dst = ip_dst.octets();
        f.extend_from_slice(ip6.as_bytes());

        let ns_off = f.len();
        f.push(ND_NEIGHBOR_SOLICIT);
        f.push(0);
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(&[0; 4]);
        f.extend_from_slice(&target.octets());

        f.push(ND_OPT_SOURCE_LINKADDR);
        f.push(1); // len in 8-byte units: 2+6 = 8 → 1
        f.extend_from_slice(&eth_src);

        let mut pseudo = Ipv6Pseudo::default();
        pseudo.ip6_src = ip_src.octets();
        pseudo.ip6_dst = ip_dst.octets();
        pseudo.set_length(icmp_len as u32);
        pseudo.set_next(u32::from(IPPROTO_ICMPV6));
        let mut ck = inet_checksum(pseudo.as_bytes(), 0xFFFF);
        ck = inet_checksum(&f[ns_off..], ck);
        f[ns_off + 2..ns_off + 4].copy_from_slice(&ck.to_ne_bytes());

        f
    }

    #[test]
    fn parse_ndp_valid_solicit() {
        let target: Ipv6Addr = "fe80::42".parse().unwrap();
        let f = mk_ndp_solicit(target);
        assert_eq!(parse_ndp_solicit(&f), Some(target));
    }

    #[test]
    fn parse_ndp_bad_checksum() {
        let target: Ipv6Addr = "fe80::42".parse().unwrap();
        let mut f = mk_ndp_solicit(target);
        let last = f.len() - 10;
        f[last] ^= 0x01;
        assert_eq!(parse_ndp_solicit(&f), None);
    }

    #[test]
    fn parse_ndp_wrong_type() {
        let target: Ipv6Addr = "fe80::42".parse().unwrap();
        let mut f = mk_ndp_solicit(target);
        // Type gate (:835) fires before checksum verify.
        f[ETHER_SIZE + IP6_SIZE] = ND_NEIGHBOR_ADVERT;
        assert_eq!(parse_ndp_solicit(&f), None);
    }

    #[test]
    fn parse_ndp_too_short() {
        assert_eq!(parse_ndp_solicit(&[0u8; 50]), None);
        assert_eq!(parse_ndp_solicit(&[]), None);
    }

    #[test]
    fn parse_ndp_wrong_nexthdr() {
        let target: Ipv6Addr = "fe80::42".parse().unwrap();
        let mut f = mk_ndp_solicit(target);
        f[ETHER_SIZE + 6] = 6; // ip6_nxt = TCP
        assert_eq!(parse_ndp_solicit(&f), None);
    }

    #[test]
    fn build_ndp_advert_hlim_255() {
        // RFC 4861 §7.2.2. C relies on solicit having hlim=255 (§7.1.1).
        let target: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let f = mk_ndp_solicit(target);
        let r = build_ndp_advert(&f).expect("valid");
        assert_eq!(r[ETHER_SIZE + 7], 255);
    }

    #[test]
    fn build_ndp_advert_checksum_valid() {
        let target: Ipv6Addr = "2001:db8::dead:beef".parse().unwrap();
        let f = mk_ndp_solicit(target);
        let r = build_ndp_advert(&f).expect("valid");

        // Reverify independently (parse can't accept ADVERT, but checksum is shared).
        let ip6_bytes: &[u8; IP6_SIZE] = r[ETHER_SIZE..ETHER_SIZE + IP6_SIZE].try_into().unwrap();
        let ip6 = Ipv6Hdr::read_from_bytes(ip6_bytes).unwrap();
        let icmp_len = NS_SIZE + OPT_SIZE + ETH_ALEN;
        let mut pseudo = Ipv6Pseudo::default();
        pseudo.ip6_src = ip6.ip6_src;
        pseudo.ip6_dst = ip6.ip6_dst;
        pseudo.set_length(icmp_len as u32);
        pseudo.set_next(u32::from(IPPROTO_ICMPV6));
        let mut ck = inet_checksum(pseudo.as_bytes(), 0xFFFF);
        ck = inet_checksum(&r[ETHER_SIZE + IP6_SIZE..], ck);
        assert_eq!(ck, 0, "advert checksum must verify");
    }

    #[test]
    fn build_ndp_advert_fields() {
        let target: Ipv6Addr = "2001:db8::cafe".parse().unwrap();
        let f = mk_ndp_solicit(target);
        let r = build_ndp_advert(&f).expect("valid");

        assert_eq!(&r[..6], &[0x02, 0, 0, 0, 0, 0x01]); // dst = orig-src
        assert_eq!(&r[6..12], &[0x02, 0, 0, 0, 0, 0x01 ^ 0xFF]); // src = fake

        let ip6_bytes: &[u8; IP6_SIZE] = r[ETHER_SIZE..ETHER_SIZE + IP6_SIZE].try_into().unwrap();
        let ip6 = Ipv6Hdr::read_from_bytes(ip6_bytes).unwrap();
        assert_eq!(ip6.ip6_src, target.octets());
        let orig_src: Ipv6Addr = "fe80::1".parse().unwrap();
        assert_eq!(ip6.ip6_dst, orig_src.octets());

        let ns_off = ETHER_SIZE + IP6_SIZE;
        assert_eq!(r[ns_off], ND_NEIGHBOR_ADVERT);
        assert_eq!(&r[ns_off + 4..ns_off + 8], &0x4000_0000u32.to_be_bytes());
        assert_eq!(&r[ns_off + 8..ns_off + 24], &target.octets());

        let opt_off = ns_off + NS_SIZE;
        assert_eq!(r[opt_off], ND_OPT_TARGET_LINKADDR);
        assert_eq!(
            &r[opt_off + 2..opt_off + 8],
            &[0x02, 0, 0, 0, 0, 0x01 ^ 0xFF]
        );
    }

    #[test]
    fn build_ndp_advert_no_opt() {
        // DAD-style (RFC 4861 §7.2.2: unspec src → no opt). C has_opt branch.
        let target: Ipv6Addr = "fe80::99".parse().unwrap();
        let ip_src: Ipv6Addr = "fe80::1".parse().unwrap();
        let ip_dst: Ipv6Addr = "ff02::1".parse().unwrap();

        let mut f = Vec::new();
        f.extend_from_slice(&[0x33, 0x33, 0, 0, 0, 0x01]);
        f.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
        f.extend_from_slice(&0x86DDu16.to_be_bytes());
        let mut ip6 = Ipv6Hdr::default();
        ip6.set_flow(0x6000_0000);
        ip6.set_plen(NS_SIZE as u16);
        ip6.ip6_nxt = IPPROTO_ICMPV6;
        ip6.ip6_hlim = 255;
        ip6.ip6_src = ip_src.octets();
        ip6.ip6_dst = ip_dst.octets();
        f.extend_from_slice(ip6.as_bytes());
        let ns_off = f.len();
        f.push(ND_NEIGHBOR_SOLICIT);
        f.push(0);
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(&[0; 4]);
        f.extend_from_slice(&target.octets());
        let mut pseudo = Ipv6Pseudo::default();
        pseudo.ip6_src = ip_src.octets();
        pseudo.ip6_dst = ip_dst.octets();
        pseudo.set_length(NS_SIZE as u32);
        pseudo.set_next(u32::from(IPPROTO_ICMPV6));
        let mut ck = inet_checksum(pseudo.as_bytes(), 0xFFFF);
        ck = inet_checksum(&f[ns_off..], ck);
        f[ns_off + 2..ns_off + 4].copy_from_slice(&ck.to_ne_bytes());

        assert_eq!(parse_ndp_solicit(&f), Some(target));

        let r = build_ndp_advert(&f).expect("valid");
        assert_eq!(r.len(), ETHER_SIZE + IP6_SIZE + NS_SIZE);
        assert_eq!(r[ETHER_SIZE + IP6_SIZE], ND_NEIGHBOR_ADVERT);

        let ip6_bytes: &[u8; IP6_SIZE] = r[ETHER_SIZE..ETHER_SIZE + IP6_SIZE].try_into().unwrap();
        let ip6r = Ipv6Hdr::read_from_bytes(ip6_bytes).unwrap();
        let mut pseudo = Ipv6Pseudo::default();
        pseudo.ip6_src = ip6r.ip6_src;
        pseudo.ip6_dst = ip6r.ip6_dst;
        pseudo.set_length(NS_SIZE as u32);
        pseudo.set_next(u32::from(IPPROTO_ICMPV6));
        let mut ck = inet_checksum(pseudo.as_bytes(), 0xFFFF);
        ck = inet_checksum(&r[ETHER_SIZE + IP6_SIZE..], ck);
        assert_eq!(ck, 0);
    }
}
