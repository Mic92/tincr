//! ARP/NDP reply synthesis.
//!
//! The fake-MAC trick: answer the kernel's ARP/NS with its OWN
//! eth-src MAC, last byte XOR `0xFF`.
//! Kernel caches it, sends to it; daemon reads everything off TUN
//! regardless of dst MAC. The XOR is cosmetic ("for consistency").
//!
//! C inlines subnet-lookup; we split: `parse_*` returns target IP,
//! daemon looks up, `build_*` synthesizes.
//!
//! `overwrite-mac` and `source != myself`: handled at the daemon
//! callsite
//! (`handle_arp`/`handle_ndp`); this module stays pure.

#![forbid(unsafe_code)]
#![expect(clippy::cast_possible_truncation)] // header-size constants, max 32

use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr};

use zerocopy::{FromBytes, IntoBytes};

use crate::packet::{
    ARPHRD_ETHER, ARPOP_REPLY, ARPOP_REQUEST, ETH_P_IP, EtherArp, Ipv6Hdr, Ipv6Pseudo,
    inet_checksum,
};
use crate::wire::array;

const ETHER_SIZE: usize = 14;
const ETH_ALEN: usize = 6;
const ARP_SIZE: usize = 28;
const IP6_SIZE: usize = 40;
const NS_SIZE: usize = 24; // icmp6_hdr(8) + in6_addr(16).
const OPT_SIZE: usize = 2; // {type, len}.
const IPPROTO_ICMPV6: u8 = 58;

// NDP constants (RFC 4861).

pub(crate) const ND_NEIGHBOR_SOLICIT: u8 = 135;
pub(crate) const ND_NEIGHBOR_ADVERT: u8 = 136;
pub(crate) const ND_OPT_SOURCE_LINKADDR: u8 = 1;
pub(crate) const ND_OPT_TARGET_LINKADDR: u8 = 2;

/// The kernel's MAC with the last byte flipped.
fn fake_mac(frame: &[u8]) -> Option<[u8; ETH_ALEN]> {
    let mut mac = *array::<ETH_ALEN>(frame, ETH_ALEN)?;
    mac[ETH_ALEN - 1] ^= 0xFF;
    Some(mac)
}

fn arp(frame: &[u8]) -> Option<EtherArp> {
    EtherArp::read_from_bytes(array::<ARP_SIZE>(frame, ETHER_SIZE)?).ok()
}

/// Returns `arp_tpa` iff `frame` is a valid Ethernet/IP ARP
/// who-has. Caller does subnet lookup.
#[must_use]
pub(crate) fn parse_arp_req(frame: &[u8]) -> Option<Ipv4Addr> {
    let arp = arp(frame)?;
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

/// Reply to an ARP request. The eth header is copied unchanged, as in C.
#[must_use]
pub(crate) fn build_arp_reply(original: &[u8]) -> Option<Vec<u8>> {
    let mut arp = arp(original)?;
    mem::swap(&mut arp.arp_tpa, &mut arp.arp_spa);
    arp.arp_tha = arp.arp_sha;
    arp.arp_sha = fake_mac(original)?;
    arp.ea_hdr.set_op(ARPOP_REPLY);

    let mut out = original.get(..ETHER_SIZE)?.to_vec();
    out.extend_from_slice(arp.as_bytes());
    Some(out)
}

/// `ICMPv6` length of a solicit/advert: with the link-layer option iff
/// the frame has room for it.
fn ndp_icmp_len(frame: &[u8]) -> Option<usize> {
    let avail = frame.len().checked_sub(ETHER_SIZE + IP6_SIZE)?;
    if avail >= NS_SIZE + OPT_SIZE + ETH_ALEN {
        Some(NS_SIZE + OPT_SIZE + ETH_ALEN)
    } else if avail >= NS_SIZE {
        Some(NS_SIZE)
    } else {
        None
    }
}

fn icmp6_checksum(ip6: &Ipv6Hdr, icmp: &[u8]) -> u16 {
    let mut pseudo = Ipv6Pseudo::default();
    pseudo.ip6_src = ip6.ip6_src;
    pseudo.ip6_dst = ip6.ip6_dst;
    pseudo.set_length(icmp.len() as u32);
    pseudo.set_next(u32::from(IPPROTO_ICMPV6));
    inet_checksum(icmp, inet_checksum(pseudo.as_bytes(), 0xFFFF))
}

/// Returns `nd_ns_target` iff: long enough, `ip6_nxt == ICMPV6`,
/// type 135, opt-type ok, and the `ICMPv6` checksum verifies.
/// Hop limit (RFC 4861 §7.1.1) is the kernel's job.
#[must_use]
pub(crate) fn parse_ndp_solicit(frame: &[u8]) -> Option<Ipv6Addr> {
    let icmp_len = ndp_icmp_len(frame)?;
    let ip6 = Ipv6Hdr::read_from_bytes(array::<IP6_SIZE>(frame, ETHER_SIZE)?).ok()?;
    if ip6.ip6_nxt != IPPROTO_ICMPV6 {
        return None;
    }
    let icmp = frame.get(ETHER_SIZE + IP6_SIZE..)?.get(..icmp_len)?;
    if icmp.first() != Some(&ND_NEIGHBOR_SOLICIT) {
        return None;
    }
    if icmp
        .get(NS_SIZE)
        .is_some_and(|&t| t != ND_OPT_SOURCE_LINKADDR)
    {
        return None;
    }
    if icmp6_checksum(&ip6, icmp) != 0 {
        return None;
    }
    Some(Ipv6Addr::from(*array::<16>(icmp, 8)?))
}

/// Advert for a solicit. Eth: both MACs ← orig src, src's last byte
/// flipped. Ip6: dst ← orig src, src ← target, hlim 255 (RFC 4861
/// §7.1.2). Icmp6: ADVERT with the Solicited flag. The option carries
/// the fake MAC.
#[must_use]
pub(crate) fn build_ndp_advert(original: &[u8]) -> Option<Vec<u8>> {
    let icmp_len = ndp_icmp_len(original)?;
    let fake = fake_mac(original)?;
    let src = *array::<ETH_ALEN>(original, ETH_ALEN)?;

    let mut ip6 = Ipv6Hdr::read_from_bytes(array::<IP6_SIZE>(original, ETHER_SIZE)?).ok()?;
    let ns = original.get(ETHER_SIZE + IP6_SIZE..)?.get(..icmp_len)?;
    ip6.ip6_dst = ip6.ip6_src;
    ip6.ip6_src = *array::<16>(ns, 8)?;
    ip6.ip6_hlim = 255;

    let mut icmp = ns.to_vec();
    // [type][code][cksum:2][flags:4]: tinc sets only Solicited.
    icmp.get_mut(..8)?
        .copy_from_slice(&[ND_NEIGHBOR_ADVERT, 0, 0, 0, 0x40, 0, 0, 0]);
    if let Some((kind, mac)) = icmp.get_mut(NS_SIZE..).and_then(<[u8]>::split_first_mut) {
        *kind = ND_OPT_TARGET_LINKADDR;
        mac.get_mut(1..)?.copy_from_slice(&fake);
    }
    let ck = icmp6_checksum(&ip6, &icmp);
    icmp.get_mut(2..4)?.copy_from_slice(&ck.to_ne_bytes()); // ne-order (packet.rs)

    let mut out = Vec::with_capacity(ETHER_SIZE + IP6_SIZE + icmp_len);
    out.extend_from_slice(&src);
    out.extend_from_slice(&fake);
    out.extend_from_slice(original.get(12..14)?);
    out.extend_from_slice(ip6.as_bytes());
    out.extend_from_slice(&icmp);
    Some(out)
}

// Tests.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::ETH_P_ARP;

    /// Eth+ARP "who has `tpa`? tell `spa`". eth-src locally administered.
    fn mk_arp_req(spa: [u8; 4], tpa: [u8; 4]) -> Vec<u8> {
        let mut f = Vec::with_capacity(ETHER_SIZE + ARP_SIZE);
        f.extend_from_slice(&[0xff; 6]);
        f.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
        f.extend_from_slice(&ETH_P_ARP.to_be_bytes());
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
        let r = build_arp_reply(&f).unwrap();
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

    /// Snatch + stamp. neighbor.rs is pure (no daemon access);
    /// the daemon does the
    /// 4-line snatch+stamp at the callsite. This test checks the
    /// byte arithmetic is right.
    #[test]
    fn overwrite_mac_snatch_then_stamp() {
        // ARP from kernel, eth-src = the kernel's interface MAC.
        let mut req = mk_arp_req([10, 0, 0, 1], [10, 0, 0, 2]);
        let kernel_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        req[6..12].copy_from_slice(&kernel_mac);

        // Daemon snatches after parse_arp_req validates.
        assert!(parse_arp_req(&req).is_some());
        let mut mymac = [0u8; 6];
        mymac.copy_from_slice(&req[6..12]);
        assert_eq!(mymac, kernel_mac);

        // Stamp on a frame headed TO the device.
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
        let r = build_arp_reply(&f).unwrap();
        assert_eq!(parse_arp_req(&r), None); // reply, not request
        let arp_bytes: &[u8; ARP_SIZE] = r[ETHER_SIZE..].try_into().unwrap();
        let arp = EtherArp::read_from_bytes(arp_bytes).unwrap();
        assert_eq!(arp.ea_hdr.hrd(), ARPHRD_ETHER);
        assert_eq!(arp.ea_hdr.pro(), ETH_P_IP);
    }

    // NDP fixtures.

    /// Valid NS with `SOURCE_LLADDR` opt + correct checksum.
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
        // RFC 4861 §7.1.2, even if the solicit was already decremented.
        let target: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let mut f = mk_ndp_solicit(target);
        f[ETHER_SIZE + 7] = 254;
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
