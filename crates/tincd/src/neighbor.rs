//! ARP/NDP reply synthesis (`route.c:793-1035`).
//!
//! Router mode: the daemon strips ethernet headers and routes by
//! IP. But the kernel doesn't know that — it ARPs (v4) or sends
//! Neighbor Solicits (v6) for the next-hop MAC before sending. We
//! answer with a **fake** MAC. The kernel caches it, traffic flows,
//! we ignore the eth header.
//!
//! ## The fake-MAC trick
//!
//! `route.c:1015-1016` builds the reply's "this is the neighbor's
//! MAC" answer by taking the **kernel's own MAC** (the eth source
//! of the request frame, `DATA(packet)+ETH_ALEN`) and XOR'ing the
//! last byte with `0xFF`. So when the kernel asks "who has
//! 10.42.0.2?", we answer "10.42.0.2 is at <your-mac-but-last-byte-
//! flipped>". The kernel happily caches that, sends to it, and the
//! daemon — which reads everything off the TUN regardless of dst
//! MAC — sees the traffic. The XOR mangling is purely cosmetic
//! ("for consistency with route_packet()", `route.c:1016`): it just
//! makes the source look like Not Us in case anything inspects the
//! cache. NDP does the same dance at `route.c:899-900`.
//!
//! ## Decomposition
//!
//! The C inlines subnet-lookup into `route_arp`/`route_neighborsol`.
//! We split: [`parse_arp_req`] / [`parse_ndp_solicit`] return the
//! target IP if the packet is a valid request; the daemon does the
//! subnet lookup; [`build_arp_reply`] / [`build_ndp_advert`]
//! synthesize given the original frame. Pure functions, no state.
//!
//! `STUB(chunk-9-switch)`: `overwrite_mac` snatching (`:970-973`,
//! `:830-832`) and `source != myself` (`:964-967`, `:814-817`) are
//! switch-mode concerns; default-off / router-mode-only here.

#![forbid(unsafe_code)]
// All `as u32`/`as u16` casts in this module are header-size constants
// (max NS_SIZE+OPT_SIZE+ETH_ALEN = 32). Never truncate.
#![allow(clippy::cast_possible_truncation)]

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::packet::{
    ARPHRD_ETHER, ARPOP_REPLY, ARPOP_REQUEST, ETH_P_IP, EtherArp, Ipv6Hdr, Ipv6Pseudo,
    inet_checksum,
};

// ── Sizes (`route.c:50-56`) ────────────────────────────────────────

const ETHER_SIZE: usize = 14;
const ETH_ALEN: usize = 6;
/// `sizeof(struct ether_arp)` — `route.c:52`.
const ARP_SIZE: usize = 28;
/// `sizeof(struct ip6_hdr)` — `route.c:54`.
const IP6_SIZE: usize = 40;
/// `sizeof(struct nd_neighbor_solicit)` — `ipv6.h:106`. The struct
/// is `icmp6_hdr` (8) + `in6_addr nd_ns_target` (16) = 24.
const NS_SIZE: usize = 24;
/// `sizeof(struct nd_opt_hdr)` — `ipv6.h:115`. `{type, len}`.
const OPT_SIZE: usize = 2;

const IPPROTO_ICMPV6: u8 = 58;

// ── NDP constants (RFC 4861) ───────────────────────────────────────

/// `ND_NEIGHBOR_SOLICIT` (RFC 4861 §4.3). ICMPv6 type 135.
pub const ND_NEIGHBOR_SOLICIT: u8 = 135;
/// `ND_NEIGHBOR_ADVERT` (RFC 4861 §4.4). ICMPv6 type 136.
pub const ND_NEIGHBOR_ADVERT: u8 = 136;
/// `ND_OPT_SOURCE_LINKADDR` (RFC 4861 §4.6.1). Option type 1.
pub const ND_OPT_SOURCE_LINKADDR: u8 = 1;
/// `ND_OPT_TARGET_LINKADDR` (RFC 4861 §4.6.1). Option type 2.
pub const ND_OPT_TARGET_LINKADDR: u8 = 2;

// ── ARP ────────────────────────────────────────────────────────────

/// Parse + validate an ARP request (`route.c:960,977-984`).
///
/// Returns the target IPv4 (`arp_tpa`) if and only if `frame` is a
/// well-formed Ethernet/IP ARP `who-has`: `arp_hrd == ARPHRD_ETHER`,
/// `arp_pro == ETH_P_IP`, `arp_hln == 6`, `arp_pln == 4`, `arp_op ==
/// ARPOP_REQUEST`. Anything else (replies, non-Ethernet HW, wrong
/// protocol, malformed, short) → `None`.
///
/// The caller does the subnet lookup (`route.c:988-1002`).
#[must_use]
pub fn parse_arp_req(frame: &[u8]) -> Option<Ipv4Addr> {
    // route.c:960 checklength
    if frame.len() < ETHER_SIZE + ARP_SIZE {
        return None;
    }
    // route.c:977
    let arp_bytes: &[u8; ARP_SIZE] = frame[ETHER_SIZE..ETHER_SIZE + ARP_SIZE].try_into().ok()?;
    let arp = EtherArp::from_bytes(arp_bytes);

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

/// Build an ARP reply (`route.c:1011-1022`).
///
/// `original` is the request frame; we reuse most of it. The reply's
/// `arp_sha` (the answer: "the neighbor's MAC is THIS") is the
/// original frame's eth-source MAC with the last byte XOR `0xFF` —
/// see the module-level [fake-MAC trick](self) commentary.
///
/// # Panics
///
/// If `original.len() < 42`. The caller MUST have validated
/// `original` with [`parse_arp_req`]; we don't re-validate.
///
/// Returns a fresh `Vec`. `ETHER_SIZE + ARP_SIZE` = 42 bytes; any
/// trailing padding on `original` is dropped (the C mutates in place
/// and keeps `packet->len` as-is, but the trailing bytes are junk —
/// `send_packet` reads only 42 effective bytes from a tap-mode TUN
/// in router mode).
#[must_use]
pub fn build_arp_reply(original: &[u8]) -> Vec<u8> {
    debug_assert!(original.len() >= ETHER_SIZE + ARP_SIZE);

    let mut out = original[..ETHER_SIZE + ARP_SIZE].to_vec();

    // The C does NOT touch the ethernet header here (route.c only
    // copies the arp struct back at :1022). The eth header still has
    // dst=broadcast, src=kernel-mac. That's fine: the daemon writes
    // this back to the TUN; the kernel reads it; eth-dst is ignored
    // on a tap read.

    let arp_bytes: &[u8; ARP_SIZE] = original[ETHER_SIZE..ETHER_SIZE + ARP_SIZE]
        .try_into()
        .expect("validated");
    let mut arp = EtherArp::from_bytes(arp_bytes);

    // route.c:1011-1013 — swap protocol addresses.
    std::mem::swap(&mut arp.arp_tpa, &mut arp.arp_spa);

    // route.c:1014 — set target HW addr = original sender HW addr.
    arp.arp_tha = arp.arp_sha;

    // route.c:1015-1016 — set sender HW addr = original eth-src
    // with last byte flipped. The fake-MAC trick.
    let eth_src: [u8; ETH_ALEN] = original[ETH_ALEN..ETH_ALEN * 2]
        .try_into()
        .expect("validated");
    arp.arp_sha = eth_src;
    arp.arp_sha[ETH_ALEN - 1] ^= 0xFF;

    // route.c:1017
    arp.ea_hdr.set_op(ARPOP_REPLY);

    // route.c:1022
    out[ETHER_SIZE..ETHER_SIZE + ARP_SIZE].copy_from_slice(&arp.to_bytes());
    out
}

// ── NDP ────────────────────────────────────────────────────────────

/// Parse + validate an NDP Neighbor Solicit (`route.c:808-861`).
///
/// Returns `nd_ns_target` if and only if:
/// - frame is long enough for eth + ip6 + ns (`:808-810`)
/// - `ip6.ip6_nxt == IPPROTO_ICMPV6`
/// - `ns.type == ND_NEIGHBOR_SOLICIT` (`:835`)
/// - if a SOURCE_LLADDR option is present, its type is correct (`:836`)
/// - the **ICMPv6 checksum verifies** over pseudo-hdr + ns [+ opt
///   + lladdr] (`:847-861`)
///
/// NDP packets carry no signature; the only integrity guarantees
/// are hop-limit=255 (link-local scoping, RFC 4861 §7.1.1) and the
/// ICMPv6 checksum. We verify the checksum here; hop-limit is the
/// kernel's job (it generated this packet).
///
/// The C does NOT check `ip6_nxt`; it gets there via the route
/// dispatch which already branched on next-header. We add the check
/// because [`parse_ndp_solicit`] is a freestanding parser.
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
    let ip6 = Ipv6Hdr::from_bytes(ip6_bytes);

    // Not in C (see doc-comment): the route dispatch already
    // branched on this. We're freestanding.
    if ip6.ip6_nxt != IPPROTO_ICMPV6 {
        return None;
    }

    let ns_off = ETHER_SIZE + IP6_SIZE;
    let ns = &frame[ns_off..ns_off + NS_SIZE];

    // route.c:835-838 — type check + opt-type check.
    // ns[0] = icmp6_type (nd_ns_type via #define).
    if ns[0] != ND_NEIGHBOR_SOLICIT {
        return None;
    }
    if has_opt {
        let opt_type = frame[ns_off + NS_SIZE];
        if opt_type != ND_OPT_SOURCE_LINKADDR {
            return None;
        }
    }

    // route.c:843-861 — checksum verify.
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

    // The C feeds (pseudo, ns, opt, lladdr) as four separate
    // inet_checksum calls because they're stack structs. We have
    // the contiguous wire bytes; one call suffices.
    let mut ck = inet_checksum(&pseudo.to_bytes(), 0xFFFF);
    ck = inet_checksum(&frame[ns_off..ns_off + icmp_len], ck);
    if ck != 0 {
        return None;
    }

    // ns[8..24] = nd_ns_target.
    let target: [u8; 16] = ns[8..24].try_into().ok()?;
    Some(Ipv6Addr::from(target))
}

/// Build an NDP Neighbor Advert (`route.c:890-948`).
///
/// The involved one. Rebuilds:
/// - eth: dst ← orig-src, src ← orig-src ⊕ `0xFF` on last byte
///   (`:899-900`)
/// - ip6: dst ← orig-src, src ← `nd_ns_target`, hlim stays as-is
///   (the C doesn't touch hlim here; the kernel set it to 255 in
///   the solicit and we mirror it back — RFC 4861 §7.2.2 mandates
///   255 for adverts)
/// - icmp6: type ← `ND_NEIGHBOR_ADVERT`, reserved ← Solicited flag
///   (`htonl(0x40000000)`, `:910`), checksum recomputed
/// - opt (if present): type ← `ND_OPT_TARGET_LINKADDR`, lladdr ←
///   the fake MAC (`:904-905`)
///
/// `STUB(chunk-9-relay)`: `decrement_ttl` (`:895`) is daemon-side.
///
/// Returns `None` only if `original` is too short; the caller
/// SHOULD have validated with [`parse_ndp_solicit`] already so this
/// is defensive.
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
    // memcpy(DATA, DATA+ETH_ALEN, ETH_ALEN): dst ← orig-src.
    // DATA[ETH_ALEN*2-1] ^= 0xFF: mangle src last byte.
    // Net effect: eth-dst = orig-eth-src; eth-src = orig-eth-src
    // with last byte flipped (because the memcpy left both halves
    // identical, then XOR hits the src half).
    let eth_src: [u8; ETH_ALEN] = original[ETH_ALEN..ETH_ALEN * 2].try_into().ok()?;
    out[..ETH_ALEN].copy_from_slice(&eth_src);
    out[ETH_ALEN..ETH_ALEN * 2].copy_from_slice(&eth_src);
    out[ETH_ALEN * 2 - 1] ^= 0xFF;
    // The same mangled-src is the fake MAC we hand out below.
    let fake_mac: [u8; ETH_ALEN] = out[ETH_ALEN..ETH_ALEN * 2].try_into().ok()?;

    // ── IPv6 (route.c:902-903) ───────────────────────────────────
    let ip6_off = ETHER_SIZE;
    let ip6_bytes: &[u8; IP6_SIZE] = original[ip6_off..ip6_off + IP6_SIZE].try_into().ok()?;
    let mut ip6 = Ipv6Hdr::from_bytes(ip6_bytes);

    let ns_off = ETHER_SIZE + IP6_SIZE;
    let target: [u8; 16] = original[ns_off + 8..ns_off + 24].try_into().ok()?;

    ip6.ip6_dst = ip6.ip6_src; // :902
    ip6.ip6_src = target; //       :903
    out[ip6_off..ip6_off + IP6_SIZE].copy_from_slice(&ip6.to_bytes());

    // ── ICMPv6 / NS (route.c:909-911) ────────────────────────────
    // We work in `out` directly: it's just byte poking.
    // ns layout: [type][code][cksum:2][reserved:4][target:16]
    out[ns_off] = ND_NEIGHBOR_ADVERT; // :910 nd_ns_type
    // :909 nd_ns_cksum = 0
    out[ns_off + 2] = 0;
    out[ns_off + 3] = 0;
    // :911 nd_ns_reserved = htonl(0x40000000) — Solicited flag.
    // (Spec says R|S|O for proxy NA but tinc sets S only; mirror C.)
    out[ns_off + 4..ns_off + 8].copy_from_slice(&0x4000_0000u32.to_be_bytes());
    // target stays as-is (already in `out` from the copy).

    // ── Option (route.c:904-907,912) ─────────────────────────────
    if has_opt {
        let opt_off = ns_off + NS_SIZE;
        out[opt_off] = ND_OPT_TARGET_LINKADDR; // :912
        // opt_len stays (1 = 8 bytes, already correct from solicit).
        // :905-907: the lladdr field gets our fake MAC.
        out[opt_off + OPT_SIZE..opt_off + OPT_SIZE + ETH_ALEN].copy_from_slice(&fake_mac);
    }

    // ── Checksum (route.c:916-936) ───────────────────────────────
    let mut pseudo = Ipv6Pseudo::default();
    pseudo.ip6_src = ip6.ip6_src;
    pseudo.ip6_dst = ip6.ip6_dst;
    pseudo.set_length(icmp_len as u32);
    pseudo.set_next(u32::from(IPPROTO_ICMPV6));

    let mut ck = inet_checksum(&pseudo.to_bytes(), 0xFFFF);
    ck = inet_checksum(&out[ns_off..ns_off + icmp_len], ck);
    // Write back raw — inet_checksum returns ne-order (see packet.rs).
    out[ns_off + 2..ns_off + 4].copy_from_slice(&ck.to_ne_bytes());

    Some(out)
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-build an Ethernet+ARP request frame: "who has `tpa`?
    /// tell `spa`". eth-src = `02:00:00:00:00:01` (locally
    /// administered), eth-dst = broadcast.
    fn mk_arp_req(spa: [u8; 4], tpa: [u8; 4]) -> Vec<u8> {
        let mut f = Vec::with_capacity(ETHER_SIZE + ARP_SIZE);
        // eth: dst broadcast, src 02:00:00:00:00:01, ethertype ARP
        f.extend_from_slice(&[0xff; 6]);
        f.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
        f.extend_from_slice(&crate::packet::ETH_P_ARP.to_be_bytes());
        // arp
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
        f.extend_from_slice(&a.to_bytes());
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
        // arp_op is at ETHER_SIZE + 6..8
        f[ETHER_SIZE + 6..ETHER_SIZE + 8].copy_from_slice(&ARPOP_REPLY.to_be_bytes());
        assert_eq!(parse_arp_req(&f), None);
    }

    #[test]
    fn parse_arp_non_ethernet_hw() {
        let mut f = mk_arp_req([10, 42, 0, 1], [10, 42, 0, 2]);
        // arp_hrd at ETHER_SIZE + 0..2: set to ARPHRD_IEEE802 = 6
        f[ETHER_SIZE..ETHER_SIZE + 2].copy_from_slice(&6u16.to_be_bytes());
        assert_eq!(parse_arp_req(&f), None);
    }

    #[test]
    fn parse_arp_too_short() {
        assert_eq!(parse_arp_req(&[0u8; 20]), None);
        assert_eq!(parse_arp_req(&[]), None);
        // exactly ETHER_SIZE + ARP_SIZE - 1
        assert_eq!(parse_arp_req(&[0u8; 41]), None);
    }

    #[test]
    fn build_arp_reply_swaps() {
        let f = mk_arp_req([10, 42, 0, 1], [10, 42, 0, 2]);
        let r = build_arp_reply(&f);
        assert_eq!(r.len(), ETHER_SIZE + ARP_SIZE);

        let arp_bytes: &[u8; ARP_SIZE] = r[ETHER_SIZE..].try_into().unwrap();
        let arp = EtherArp::from_bytes(arp_bytes);

        // protocol addrs swapped
        assert_eq!(arp.arp_spa, [10, 42, 0, 2]);
        assert_eq!(arp.arp_tpa, [10, 42, 0, 1]);
        // op = REPLY
        assert_eq!(arp.ea_hdr.op(), ARPOP_REPLY);
        // tha = orig sha
        assert_eq!(arp.arp_tha, [0x02, 0, 0, 0, 0, 0x01]);
        // sha = orig eth-src with last byte XOR 0xFF
        assert_eq!(arp.arp_sha, [0x02, 0, 0, 0, 0, 0x01 ^ 0xFF]);
        // eth header unchanged (C doesn't touch it)
        assert_eq!(&r[..ETHER_SIZE], &f[..ETHER_SIZE]);
    }

    #[test]
    fn arp_roundtrip() {
        let f = mk_arp_req([192, 168, 1, 100], [192, 168, 1, 200]);
        // Parse the request.
        assert_eq!(parse_arp_req(&f), Some(Ipv4Addr::new(192, 168, 1, 200)));
        // Build the reply.
        let r = build_arp_reply(&f);
        // The reply is NOT a request — it should not parse as one.
        assert_eq!(parse_arp_req(&r), None);
        // But it IS a well-formed ARP frame.
        let arp_bytes: &[u8; ARP_SIZE] = r[ETHER_SIZE..].try_into().unwrap();
        let arp = EtherArp::from_bytes(arp_bytes);
        assert_eq!(arp.ea_hdr.hrd(), ARPHRD_ETHER);
        assert_eq!(arp.ea_hdr.pro(), ETH_P_IP);
    }

    // ── NDP fixtures ──────────────────────────────────────────────

    /// Build a valid NDP Neighbor Solicit for `target`, with a
    /// SOURCE_LLADDR option, and a correct ICMPv6 checksum. Mirrors
    /// what a real Linux kernel emits when ARPing-v6 for a TUN
    /// next-hop.
    fn mk_ndp_solicit(target: Ipv6Addr) -> Vec<u8> {
        let eth_src = [0x02, 0, 0, 0, 0, 0x01];
        let ip_src: Ipv6Addr = "fe80::1".parse().unwrap();
        // RFC 4861: NS goes to solicited-node multicast, but tinc
        // doesn't check the dst — use the all-nodes for simplicity.
        let ip_dst: Ipv6Addr = "ff02::1".parse().unwrap();

        let icmp_len = NS_SIZE + OPT_SIZE + ETH_ALEN;
        let mut f = Vec::with_capacity(ETHER_SIZE + IP6_SIZE + icmp_len);

        // eth
        f.extend_from_slice(&[0x33, 0x33, 0, 0, 0, 0x01]); // multicast
        f.extend_from_slice(&eth_src);
        f.extend_from_slice(&0x86DDu16.to_be_bytes()); // ETH_P_IPV6

        // ip6
        let mut ip6 = Ipv6Hdr::default();
        ip6.set_flow(0x6000_0000);
        ip6.set_plen(icmp_len as u16);
        ip6.ip6_nxt = IPPROTO_ICMPV6;
        ip6.ip6_hlim = 255;
        ip6.ip6_src = ip_src.octets();
        ip6.ip6_dst = ip_dst.octets();
        f.extend_from_slice(&ip6.to_bytes());

        // ns: [type][code][cksum:2][reserved:4][target:16]
        let ns_off = f.len();
        f.push(ND_NEIGHBOR_SOLICIT);
        f.push(0); // code
        f.extend_from_slice(&[0, 0]); // cksum placeholder
        f.extend_from_slice(&[0; 4]); // reserved
        f.extend_from_slice(&target.octets());

        // opt: [type][len][lladdr:6]
        f.push(ND_OPT_SOURCE_LINKADDR);
        f.push(1); // len in 8-byte units: 2+6 = 8 → 1
        f.extend_from_slice(&eth_src);

        // checksum
        let mut pseudo = Ipv6Pseudo::default();
        pseudo.ip6_src = ip_src.octets();
        pseudo.ip6_dst = ip_dst.octets();
        pseudo.set_length(icmp_len as u32);
        pseudo.set_next(u32::from(IPPROTO_ICMPV6));
        let mut ck = inet_checksum(&pseudo.to_bytes(), 0xFFFF);
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
        // Flip a byte in the target — checksum no longer matches.
        let last = f.len() - 10;
        f[last] ^= 0x01;
        assert_eq!(parse_ndp_solicit(&f), None);
    }

    #[test]
    fn parse_ndp_wrong_type() {
        let target: Ipv6Addr = "fe80::42".parse().unwrap();
        let mut f = mk_ndp_solicit(target);
        // Change type to ADVERT (and don't fix checksum — type
        // gate fires before checksum verify, route.c:835).
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
        // ip6_nxt at ETHER_SIZE + 6
        f[ETHER_SIZE + 6] = 6; // TCP
        assert_eq!(parse_ndp_solicit(&f), None);
    }

    #[test]
    fn build_ndp_advert_hlim_255() {
        // RFC 4861 §7.2.2: NA MUST have hop-limit 255. The C
        // doesn't explicitly set this — it relies on the solicit
        // having had hlim=255 (which it must, §7.1.1). Our fixture
        // sets 255; verify it propagates.
        let target: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let f = mk_ndp_solicit(target);
        let r = build_ndp_advert(&f).expect("valid");
        // ip6_hlim at ETHER_SIZE + 7
        assert_eq!(r[ETHER_SIZE + 7], 255);
    }

    #[test]
    fn build_ndp_advert_checksum_valid() {
        let target: Ipv6Addr = "2001:db8::dead:beef".parse().unwrap();
        let f = mk_ndp_solicit(target);
        let r = build_ndp_advert(&f).expect("valid");

        // Reverify the checksum independently. This is the
        // strongest test: parse_ndp_solicit can't accept what
        // build_ndp_advert emits (wrong type) but the checksum
        // logic is shared.
        let ip6_bytes: &[u8; IP6_SIZE] = r[ETHER_SIZE..ETHER_SIZE + IP6_SIZE].try_into().unwrap();
        let ip6 = Ipv6Hdr::from_bytes(ip6_bytes);
        let icmp_len = NS_SIZE + OPT_SIZE + ETH_ALEN;
        let mut pseudo = Ipv6Pseudo::default();
        pseudo.ip6_src = ip6.ip6_src;
        pseudo.ip6_dst = ip6.ip6_dst;
        pseudo.set_length(icmp_len as u32);
        pseudo.set_next(u32::from(IPPROTO_ICMPV6));
        let mut ck = inet_checksum(&pseudo.to_bytes(), 0xFFFF);
        ck = inet_checksum(&r[ETHER_SIZE + IP6_SIZE..], ck);
        assert_eq!(ck, 0, "advert checksum must verify");
    }

    #[test]
    fn build_ndp_advert_fields() {
        let target: Ipv6Addr = "2001:db8::cafe".parse().unwrap();
        let f = mk_ndp_solicit(target);
        let r = build_ndp_advert(&f).expect("valid");

        // eth: dst = orig-src, src = orig-src with last byte ^0xFF
        assert_eq!(&r[..6], &[0x02, 0, 0, 0, 0, 0x01]);
        assert_eq!(&r[6..12], &[0x02, 0, 0, 0, 0, 0x01 ^ 0xFF]);

        // ip6: src = target, dst = orig-ip6-src
        let ip6_bytes: &[u8; IP6_SIZE] = r[ETHER_SIZE..ETHER_SIZE + IP6_SIZE].try_into().unwrap();
        let ip6 = Ipv6Hdr::from_bytes(ip6_bytes);
        assert_eq!(ip6.ip6_src, target.octets());
        let orig_src: Ipv6Addr = "fe80::1".parse().unwrap();
        assert_eq!(ip6.ip6_dst, orig_src.octets());

        // icmp: type=ADVERT, reserved=Solicited flag
        let ns_off = ETHER_SIZE + IP6_SIZE;
        assert_eq!(r[ns_off], ND_NEIGHBOR_ADVERT);
        assert_eq!(&r[ns_off + 4..ns_off + 8], &0x4000_0000u32.to_be_bytes());
        // target unchanged
        assert_eq!(&r[ns_off + 8..ns_off + 24], &target.octets());

        // opt: type=TARGET_LLADDR, lladdr = fake mac
        let opt_off = ns_off + NS_SIZE;
        assert_eq!(r[opt_off], ND_OPT_TARGET_LINKADDR);
        assert_eq!(
            &r[opt_off + 2..opt_off + 8],
            &[0x02, 0, 0, 0, 0, 0x01 ^ 0xFF]
        );
    }

    #[test]
    fn build_ndp_advert_no_opt() {
        // Solicit without SOURCE_LLADDR option (DAD-style, RFC
        // 4861 §7.2.2: unspecified source → no opt). The C handles
        // both paths (has_opt branch); so do we.
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
        f.extend_from_slice(&ip6.to_bytes());
        let ns_off = f.len();
        f.push(ND_NEIGHBOR_SOLICIT);
        f.push(0);
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(&[0; 4]);
        f.extend_from_slice(&target.octets());
        // checksum (no opt)
        let mut pseudo = Ipv6Pseudo::default();
        pseudo.ip6_src = ip_src.octets();
        pseudo.ip6_dst = ip_dst.octets();
        pseudo.set_length(NS_SIZE as u32);
        pseudo.set_next(u32::from(IPPROTO_ICMPV6));
        let mut ck = inet_checksum(&pseudo.to_bytes(), 0xFFFF);
        ck = inet_checksum(&f[ns_off..], ck);
        f[ns_off + 2..ns_off + 4].copy_from_slice(&ck.to_ne_bytes());

        // Parses.
        assert_eq!(parse_ndp_solicit(&f), Some(target));

        // Builds, with no opt in output, checksum valid.
        let r = build_ndp_advert(&f).expect("valid");
        assert_eq!(r.len(), ETHER_SIZE + IP6_SIZE + NS_SIZE);
        assert_eq!(r[ETHER_SIZE + IP6_SIZE], ND_NEIGHBOR_ADVERT);

        let ip6_bytes: &[u8; IP6_SIZE] = r[ETHER_SIZE..ETHER_SIZE + IP6_SIZE].try_into().unwrap();
        let ip6r = Ipv6Hdr::from_bytes(ip6_bytes);
        let mut pseudo = Ipv6Pseudo::default();
        pseudo.ip6_src = ip6r.ip6_src;
        pseudo.ip6_dst = ip6r.ip6_dst;
        pseudo.set_length(NS_SIZE as u32);
        pseudo.set_next(u32::from(IPPROTO_ICMPV6));
        let mut ck = inet_checksum(&pseudo.to_bytes(), 0xFFFF);
        ck = inet_checksum(&r[ETHER_SIZE + IP6_SIZE..], ck);
        assert_eq!(ck, 0);
    }
}
