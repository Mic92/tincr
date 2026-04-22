//! `route.c`: the forwarding decision.
//!
//! `route_ipv4`/`route_ipv6` call `send_packet()`/`route_..._
//! unreachable()` directly upstream. We return [`RouteResult`] and
//! the daemon
//! dispatches — pure function of `(bytes, subnets, resolve)`.
//! Config-gated post-route mutations live daemon-side.

#![forbid(unsafe_code)]

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::packet::{ETH_P_ARP, ETH_P_IP};
use crate::subnet_tree::SubnetTree;

// ── Wire constants ─────────────────────────────────────────────────

const ETHER_SIZE: usize = 14;
const IP_SIZE: usize = 20;
const IP6_SIZE: usize = 40;
const ICMP6_SIZE: usize = 8;
const ETH_P_IPV6: u16 = 0x86DD;
const ETH_P_8021Q: u16 = 0x8100;

// ICMPv4 (RFC 792, RFC 1122). `ipv4.h:35-63`.
pub(crate) const ICMP_DEST_UNREACH: u8 = 3;
pub(crate) const ICMP_NET_UNKNOWN: u8 = 6;
/// Code 9 (admin prohibited). Used for `directonly` and `FMODE_OFF`:
/// route exists, we refuse to forward.
pub(crate) const ICMP_NET_ANO: u8 = 9;
pub(crate) const ICMP_NET_UNREACH: u8 = 0;
pub(crate) const ICMP_FRAG_NEEDED: u8 = 4;
pub(crate) const ICMP_TIME_EXCEEDED: u8 = 11;
pub(crate) const ICMP_EXC_TTL: u8 = 0;

// ICMPv6 (RFC 4443).
pub(crate) const ICMP6_DST_UNREACH: u8 = 1;
pub(crate) const ICMP6_DST_UNREACH_NOROUTE: u8 = 0;
pub(crate) const ICMP6_DST_UNREACH_ADMIN: u8 = 1;
pub(crate) const ICMP6_DST_UNREACH_ADDR: u8 = 3;
/// RFC 4443 type 2. `len > MAX(via->mtu, 1294)` — 1294 = 1280 (v6
/// min MTU, RFC 8200) + 14 eth.
pub(crate) const ICMP6_PACKET_TOO_BIG: u8 = 2;
pub(crate) const ICMP6_TIME_EXCEEDED: u8 = 3;
pub(crate) const ICMP6_TIME_EXCEED_TRANSIT: u8 = 0;

/// RFC 4861 §4.3. Diverts to `route_neighborsol`.
const ND_NEIGHBOR_SOLICIT: u8 = 135;

const IPPROTO_ICMP: u8 = 1;
const IPPROTO_ICMPV6: u8 = 58;

// ────────────────────────────────────────────────────────────────────
// RouteResult

/// What to do with a packet. `route.c`'s side-effect calls, reified.
///
/// `T` is the resolved destination type — daemon uses `NodeId`, tests
/// use `String`. `resolve: FnMut(&str) -> Option<T>` maps owner name
/// to `T`; `None` = unreachable.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RouteResult<T> {
    /// `send_packet(owner, ...)`. `to == myself` → daemon writes to
    /// TUN (`send_packet` special-cases same).
    Forward { to: T },

    /// `route_ipv4_unreachable(...)`. Daemon synthesises ICMP error.
    Unreachable { icmp_type: u8, icmp_code: u8 },

    /// Daemon logs + drops.
    Unsupported { reason: &'static str },

    /// `ICMPv6` type 135. Daemon synthesises Neighbor Advert
    /// (`route_neighborsol`).
    NeighborSolicit,

    /// `route_mac`: unknown dest MAC. `RMODE_SWITCH` only (router
    /// uses `Unreachable` instead). Daemon → `broadcast_packet`.
    Broadcast,

    /// `checklength` failed.
    TooShort { need: usize, have: usize },
}

// ────────────────────────────────────────────────────────────────────
// route_ipv4

/// Reads `ip_dst`, looks up in `subnets`, returns the owner.
/// `resolve` returns `None` for unreachable; `myself` is always
/// reachable so the remote-only check falls out.
pub(crate) fn route_ipv4<T>(
    data: &[u8],
    subnets: &SubnetTree,
    mut resolve: impl FnMut(&str) -> Option<T>,
) -> RouteResult<T> {
    let need = ETHER_SIZE + IP_SIZE;
    if data.len() < need {
        return RouteResult::TooShort {
            need,
            have: data.len(),
        };
    }

    // DATA[30] = ETHER_SIZE + offsetof(ip, ip_dst) = 14+16
    let dst_off = ETHER_SIZE + 16;
    let dest = Ipv4Addr::new(
        data[dst_off],
        data[dst_off + 1],
        data[dst_off + 2],
        data[dst_off + 3],
    );

    let Some((_subnet, owner)) = subnets.lookup_ipv4(dest, |n| resolve(n).is_some()) else {
        // no covering subnet
        return RouteResult::Unreachable {
            icmp_type: ICMP_DEST_UNREACH,
            icmp_code: ICMP_NET_UNKNOWN,
        };
    };

    // `if(!subnet->owner) route_broadcast()`. Ownerless = broadcast
    // subnet (224/4, 255.255.255.255, plus
    // BroadcastSubnet config). Daemon → broadcast_packet.
    let Some(owner) = owner else {
        return RouteResult::Broadcast;
    };

    // owner==source loop check: daemon-side.

    // lookup_ipv4 may return an unreachable owner (last-hit
    // fallback, subnet_tree.rs). Re-check. owner==myself →
    // Forward{to:myself}, daemon → TUN.
    let Some(to) = resolve(owner) else {
        return RouteResult::Unreachable {
            icmp_type: ICMP_DEST_UNREACH,
            icmp_code: ICMP_NET_UNREACH,
        };
    };

    // decrement_ttl, priorityinheritance, via=, directonly,
    // MTU/fragment, clamp_mss: all daemon-side, in
    // dispatch_route_result. They need tunnels/last_routes/settings.

    RouteResult::Forward { to }
}

// ────────────────────────────────────────────────────────────────────
// route_ipv6

/// Same shape as [`route_ipv4`]; differences: dst at offset 38,
/// `ICMPv6` codes, NDP divert, MTU check
/// uses `MAX(via->mtu, 1294)` (v6 forbids in-net frag, RFC 8200 §5).
pub(crate) fn route_ipv6<T>(
    data: &[u8],
    subnets: &SubnetTree,
    mut resolve: impl FnMut(&str) -> Option<T>,
) -> RouteResult<T> {
    let need = ETHER_SIZE + IP6_SIZE;
    if data.len() < need {
        return RouteResult::TooShort {
            need,
            have: data.len(),
        };
    }

    // NDP divert. [20]=ip6_nxt (14+6), [54]=icmp6_type (14+40).
    if data[20] == IPPROTO_ICMPV6
        && data.len() >= ETHER_SIZE + IP6_SIZE + ICMP6_SIZE
        && data[54] == ND_NEIGHBOR_SOLICIT
    {
        return RouteResult::NeighborSolicit;
    }

    // DATA[38] = ETHER_SIZE + offsetof(ip6_hdr, ip6_dst) = 14+24
    let dst_off = ETHER_SIZE + 24;
    #[allow(clippy::missing_panics_doc)] // unreachable: ip6 hdr len-checked above
    let dest: [u8; 16] = data[dst_off..dst_off + 16]
        .try_into()
        .expect("len-checked above");
    let dest = Ipv6Addr::from(dest);

    let Some((_subnet, owner)) = subnets.lookup_ipv6(&dest, |n| resolve(n).is_some()) else {
        return RouteResult::Unreachable {
            icmp_type: ICMP6_DST_UNREACH,
            icmp_code: ICMP6_DST_UNREACH_ADDR,
        };
    };

    // `if(!subnet->owner) route_broadcast()`. Ownerless = broadcast
    // subnet (ff00::/8 plus config).
    let Some(owner) = owner else {
        return RouteResult::Broadcast;
    };

    // owner==source: daemon-side.

    // Same fallback re-check as route_ipv4.
    let Some(to) = resolve(owner) else {
        return RouteResult::Unreachable {
            icmp_type: ICMP6_DST_UNREACH,
            icmp_code: ICMP6_DST_UNREACH_NOROUTE,
        };
    };

    // decrement_ttl, priorityinheritance, via=, directonly, MTU →
    // PACKET_TOO_BIG, clamp_mss: daemon-side.

    RouteResult::Forward { to }
}

// ────────────────────────────────────────────────────────────────────
// decrement_ttl

/// `do_decrement_ttl` outcome. Upstream returns bool + side-effects;
/// we reify the four exits.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TtlResult {
    /// `:365,384,386`: TTL>1 decremented (or unknown ethertype).
    Decremented,
    /// `:344-347,376-379`: TTL≤1 AND already ICMP-time-exceeded.
    /// Silent drop (storm guard).
    DropSilent,
    /// `:345,377`: TTL≤1, not already time-exceeded. Daemon bounces.
    SendIcmp { icmp_type: u8, icmp_code: u8 },
    /// `:339-341,368-370`: checklength failed.
    TooShort,
}

/// `do_decrement_ttl`. In-place TTL/hop-limit decrement + IPv4
/// checksum adjust (RFC 1624 incremental: `csum +=
/// old + ~new` then fold — `:354-360`). v6 has no IP checksum.
pub(crate) fn decrement_ttl(data: &mut [u8]) -> TtlResult {
    // Read ethertype, skip 8021Q tag if present.
    if data.len() < ETHER_SIZE {
        return TtlResult::TooShort;
    }
    let mut ethertype = u16::from_be_bytes([data[12], data[13]]);
    let mut ethlen = ETHER_SIZE;
    if ethertype == ETH_P_8021Q {
        if data.len() < ETHER_SIZE + 4 {
            return TtlResult::TooShort;
        }
        ethertype = u16::from_be_bytes([data[16], data[17]]);
        ethlen += 4;
    }

    match ethertype {
        ETH_P_IP => {
            // :339-341 checklength
            if data.len() < ethlen + IP_SIZE {
                return TtlResult::TooShort;
            }

            // :343-349. TTL at [ethlen+8]. C bug (since 2012): the
            // storm-guard reads proto at [ethlen+11] (ip_sum low byte;
            // should be +9) and ICMP type at [ethlen+32] (wrong too).
            // The check almost never matches. Ported AS-IS; `.get()`
            // for the +32 read (checklength only guarantees +20).
            if data[ethlen + 8] <= 1 {
                if data[ethlen + 11] != IPPROTO_ICMP
                    || data.get(ethlen + 32).copied() != Some(ICMP_TIME_EXCEEDED)
                {
                    return TtlResult::SendIcmp {
                        icmp_type: ICMP_TIME_EXCEEDED,
                        icmp_code: ICMP_EXC_TTL,
                    };
                }
                return TtlResult::DropSilent;
            }

            // :351-353: TTL+proto as one 16-bit word (checksum unit).
            let old = u16::from_be_bytes([data[ethlen + 8], data[ethlen + 9]]);
            data[ethlen + 8] -= 1;
            let new = u16::from_be_bytes([data[ethlen + 8], data[ethlen + 9]]);

            // :355-363 RFC 1624 incremental adjust
            let mut csum = u32::from(u16::from_be_bytes([data[ethlen + 10], data[ethlen + 11]]));
            csum += u32::from(old) + u32::from(!new);
            while csum >> 16 != 0 {
                csum = (csum & 0xFFFF) + (csum >> 16);
            }
            #[allow(clippy::cast_possible_truncation)] // fold guarantees <0x10000
            {
                data[ethlen + 10] = (csum >> 8) as u8;
                data[ethlen + 11] = csum as u8;
            }

            TtlResult::Decremented
        }

        ETH_P_IPV6 => {
            // :368-370 checklength
            if data.len() < ethlen + IP6_SIZE {
                return TtlResult::TooShort;
            }

            // :372-381. hlim at [ethlen+7], nxt at [+6], ICMP type
            // at [+40] (correct this time — v6 hdr is fixed 40B).
            // `.get()`: checklength only guarantees +40.
            if data[ethlen + 7] <= 1 {
                if data[ethlen + 6] != IPPROTO_ICMPV6
                    || data.get(ethlen + 40).copied() != Some(ICMP6_TIME_EXCEEDED)
                {
                    return TtlResult::SendIcmp {
                        icmp_type: ICMP6_TIME_EXCEEDED,
                        icmp_code: ICMP6_TIME_EXCEED_TRANSIT,
                    };
                }
                return TtlResult::DropSilent;
            }

            // :383. No IP checksum in v6 (RFC 8200 §3).
            data[ethlen + 7] -= 1;

            TtlResult::Decremented
        }

        // :386: unknown ethertype — no TTL, forward as-is.
        _ => TtlResult::Decremented,
    }
}

// ────────────────────────────────────────────────────────────────────
// extract_tos

/// Read the inner packet's TOS/TC byte for `PriorityInheritance`.
///
/// v4: `DATA[15]` — 14 (eth) + 1 (ver/ihl) = byte 15 is the TOS
/// field (RFC 791 §3.1). v6: traffic class straddles bytes 14/15:
/// `(DATA[14] & 0x0f) << 4 | DATA[15] >> 4` (RFC 8200 §3, the
/// 4-bit version field eats the high nibble of byte 14).
///
/// `None` for non-IP ethertype or short frame — caller leaves
/// priority at 0. Only set `packet->priority` when ethertype+length
/// both pass.
#[must_use]
pub(crate) fn extract_tos(data: &[u8]) -> Option<u8> {
    if data.len() < ETHER_SIZE {
        return None;
    }
    let ethertype = u16::from_be_bytes([data[12], data[13]]);
    match ethertype {
        ETH_P_IP if data.len() >= ETHER_SIZE + IP_SIZE => Some(data[15]),
        ETH_P_IPV6 if data.len() >= ETHER_SIZE + IP6_SIZE => {
            Some((data[14] & 0x0f) << 4 | data[15] >> 4)
        }
        _ => None,
    }
}

// ────────────────────────────────────────────────────────────────────
// route — top-level dispatch

/// Ethertype dispatch (`RMODE_ROUTER` only).
/// `data` is full eth frame; TUN synthesises the header in router mode.
pub(crate) fn route<T>(
    data: &[u8],
    subnets: &SubnetTree,
    resolve: impl FnMut(&str) -> Option<T>,
) -> RouteResult<T> {
    // DEFERRED(chunk-9): pcap; FMODE_KERNEL.

    if data.len() < ETHER_SIZE {
        return RouteResult::TooShort {
            need: ETHER_SIZE,
            have: data.len(),
        };
    }

    let ethertype = u16::from_be_bytes([data[12], data[13]]);

    // DEFERRED(chunk-9): RMODE_SWITCH/RMODE_HUB.
    match ethertype {
        ETH_P_IP => route_ipv4(data, subnets, resolve),
        ETH_P_IPV6 => route_ipv6(data, subnets, resolve),
        ETH_P_ARP => RouteResult::Unsupported {
            reason: "arp: chunk 9",
        },
        // Upstream strips 4-byte tag before the switch. Deferred.
        ETH_P_8021Q => RouteResult::Unsupported {
            reason: "vlan: chunk 9",
        },
        _ => RouteResult::Unsupported {
            reason: "unknown ethertype",
        },
    }
}

// ════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use tinc_proto::Subnet;

    /// 34-byte eth+IPv4; only ethertype and `ip_dst` set.
    fn ipv4_packet(dst: Ipv4Addr) -> Vec<u8> {
        let mut p = vec![0u8; ETHER_SIZE + IP_SIZE];
        p[12..14].copy_from_slice(&ETH_P_IP.to_be_bytes());
        p[ETHER_SIZE + 16..ETHER_SIZE + 20].copy_from_slice(&dst.octets());
        p
    }

    fn sn(s: &str) -> Subnet {
        s.parse().unwrap()
    }

    #[allow(clippy::unnecessary_wraps)] // signature must match `resolve`
    fn always(n: &str) -> Option<String> {
        Some(n.to_owned())
    }
    fn never(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn route_ipv4_forwards_to_owner() {
        let mut t = SubnetTree::new();
        t.add(sn("10.0.0.0/24"), "bob".into());

        let p = ipv4_packet(Ipv4Addr::new(10, 0, 0, 5));
        let r = route_ipv4(&p, &t, always);

        assert_eq!(r, RouteResult::Forward { to: "bob".into() });
    }

    /// owner==myself → still Forward.
    #[test]
    fn route_ipv4_forwards_to_self() {
        let mut t = SubnetTree::new();
        t.add(sn("10.0.0.0/24"), "alice".into());

        let p = ipv4_packet(Ipv4Addr::new(10, 0, 0, 5));
        let r = route_ipv4(&p, &t, |n| (n == "alice").then(|| n.to_owned()));

        assert_eq!(r, RouteResult::Forward { to: "alice".into() });
    }

    /// no subnet → type 3 code 6.
    #[test]
    fn route_ipv4_unknown_net() {
        let t = SubnetTree::new();

        let p = ipv4_packet(Ipv4Addr::new(10, 0, 0, 5));
        let r = route_ipv4(&p, &t, always);

        assert_eq!(
            r,
            RouteResult::Unreachable {
                icmp_type: ICMP_DEST_UNREACH,
                icmp_code: ICMP_NET_UNKNOWN,
            }
        );
    }

    /// ownerless subnet → Broadcast. mDNS to
    /// 224.0.0.251, DHCP to 255.255.255.255. Before this fix, these
    /// hit `Unreachable{NET_UNKNOWN`} — daemon ICMP-bounced its own
    /// kernel's multicast. Silent (mDNS doesn't surface ICMP).
    #[test]
    fn route_ipv4_broadcast_subnet() {
        let mut t = SubnetTree::new();
        t.add_broadcast(sn("224.0.0.0/4"));
        t.add_broadcast(sn("255.255.255.255"));

        let p = ipv4_packet(Ipv4Addr::new(224, 0, 0, 251)); // mDNS
        assert_eq!(route_ipv4(&p, &t, always), RouteResult::Broadcast);

        let p = ipv4_packet(Ipv4Addr::BROADCAST); // DHCP
        assert_eq!(route_ipv4(&p, &t, always), RouteResult::Broadcast);

        // 10.0.0.5 doesn't match — falls through to NET_UNKNOWN.
        let p = ipv4_packet(Ipv4Addr::new(10, 0, 0, 5));
        assert_eq!(
            route_ipv4(&p, &t, always),
            RouteResult::Unreachable {
                icmp_type: ICMP_DEST_UNREACH,
                icmp_code: ICMP_NET_UNKNOWN,
            }
        );
    }

    /// unreachable owner → type 3 code 0.
    #[test]
    fn route_ipv4_unreachable_owner() {
        let mut t = SubnetTree::new();
        t.add(sn("10.0.0.0/24"), "bob".into());

        let p = ipv4_packet(Ipv4Addr::new(10, 0, 0, 5));
        let r = route_ipv4(&p, &t, never);

        assert_eq!(
            r,
            RouteResult::Unreachable {
                icmp_type: ICMP_DEST_UNREACH,
                icmp_code: ICMP_NET_UNREACH,
            }
        );
    }

    #[test]
    fn route_too_short() {
        let p = vec![0u8; 30];
        let t = SubnetTree::new();
        let r = route_ipv4(&p, &t, always);

        assert_eq!(r, RouteResult::TooShort { need: 34, have: 30 });
    }

    /// ethertype dispatch.
    #[test]
    fn route_ethertype_dispatch() {
        let t = SubnetTree::new();
        let mut p = vec![0u8; ETHER_SIZE];

        for (et, want) in [
            (ETH_P_ARP, "arp: chunk 9"),
            (ETH_P_8021Q, "vlan: chunk 9"),
            (0x1234, "unknown ethertype"),
        ] {
            p[12..14].copy_from_slice(&et.to_be_bytes());
            let r = route(&p, &t, always);
            assert_eq!(r, RouteResult::Unsupported { reason: want });
        }

        // IP ethertypes dispatch then bounce on length.
        p[12..14].copy_from_slice(&ETH_P_IP.to_be_bytes());
        let r = route(&p, &t, always);
        assert_eq!(r, RouteResult::TooShort { need: 34, have: 14 });

        p[12..14].copy_from_slice(&ETH_P_IPV6.to_be_bytes());
        let r = route(&p, &t, always);
        assert_eq!(r, RouteResult::TooShort { need: 54, have: 14 });
    }

    #[test]
    fn route_too_short_for_ethertype() {
        let p = vec![0u8; 10];
        let t = SubnetTree::new();
        let r = route(&p, &t, always);

        assert_eq!(r, RouteResult::TooShort { need: 14, have: 10 });
    }

    // ────────────────────────────────────────────────────────────────
    // route_ipv6

    fn ipv6_packet(dst: Ipv6Addr) -> Vec<u8> {
        let mut p = vec![0u8; ETHER_SIZE + IP6_SIZE];
        p[12..14].copy_from_slice(&ETH_P_IPV6.to_be_bytes());
        p[ETHER_SIZE + 24..ETHER_SIZE + 40].copy_from_slice(&dst.octets());
        p
    }

    #[test]
    fn route_ipv6_forwards_to_owner() {
        let mut t = SubnetTree::new();
        t.add(sn("2001:db8::/32"), "bob".into());

        let p = ipv6_packet("2001:db8::5".parse().unwrap());
        let r = route_ipv6(&p, &t, always);

        assert_eq!(r, RouteResult::Forward { to: "bob".into() });
    }

    #[test]
    fn route_ipv6_unknown_is_unreachable_addr() {
        let t = SubnetTree::new();

        let p = ipv6_packet("2001:db8::5".parse().unwrap());
        let r = route_ipv6(&p, &t, always);

        assert_eq!(
            r,
            RouteResult::Unreachable {
                icmp_type: ICMP6_DST_UNREACH,
                icmp_code: ICMP6_DST_UNREACH_ADDR,
            }
        );
    }

    /// ownerless → Broadcast. NDP to `ff02::1`,
    /// mDNS to `ff02::fb`. Before: `Unreachable{DST_UNREACH_ADDR`}.
    #[test]
    fn route_ipv6_broadcast_subnet() {
        let mut t = SubnetTree::new();
        t.add_broadcast(sn("ff00::/8"));

        let p = ipv6_packet("ff02::1".parse().unwrap()); // all-nodes
        assert_eq!(route_ipv6(&p, &t, always), RouteResult::Broadcast);

        let p = ipv6_packet("ff02::fb".parse().unwrap()); // mDNS
        assert_eq!(route_ipv6(&p, &t, always), RouteResult::Broadcast);
    }

    /// unreachable → NOROUTE not ADDR.
    #[test]
    fn route_ipv6_unreachable_owner_is_noroute() {
        let mut t = SubnetTree::new();
        t.add(sn("2001:db8::/32"), "bob".into());

        let p = ipv6_packet("2001:db8::5".parse().unwrap());
        let r = route_ipv6(&p, &t, never);

        assert_eq!(
            r,
            RouteResult::Unreachable {
                icmp_type: ICMP6_DST_UNREACH,
                icmp_code: ICMP6_DST_UNREACH_NOROUTE,
            }
        );
    }

    #[test]
    fn route_ipv6_too_short() {
        let mut p = vec![0u8; 50];
        p[12..14].copy_from_slice(&ETH_P_IPV6.to_be_bytes());
        let t = SubnetTree::new();
        let r = route_ipv6(&p, &t, always);

        assert_eq!(r, RouteResult::TooShort { need: 54, have: 50 });
    }

    /// NDP divert needs eth+ip6+icmp6 (62 bytes).
    #[test]
    fn route_ipv6_ndp_divert() {
        let mut p = vec![0u8; ETHER_SIZE + IP6_SIZE + ICMP6_SIZE];
        p[12..14].copy_from_slice(&ETH_P_IPV6.to_be_bytes());
        p[20] = IPPROTO_ICMPV6; // ip6_nxt
        p[54] = ND_NEIGHBOR_SOLICIT; // icmp6_type

        let t = SubnetTree::new();
        let r = route_ipv6(&p, &t, always);

        assert_eq!(r, RouteResult::NeighborSolicit);

        // Too short for icmp6 hdr → divert does NOT fire, falls
        // through to subnet lookup. Proves length-guard ordering.
        let p = &p[..ETHER_SIZE + IP6_SIZE];
        let r = route_ipv6(p, &t, always);
        assert!(matches!(r, RouteResult::Unreachable { .. }));
    }

    // ────────────────────────────────────────────────────────────────
    // decrement_ttl

    use crate::packet::inet_checksum;

    fn ipv4_ttl_packet(ttl: u8, proto: u8) -> Vec<u8> {
        let mut p = vec![0u8; ETHER_SIZE + IP_SIZE];
        p[12..14].copy_from_slice(&ETH_P_IP.to_be_bytes());
        p[ETHER_SIZE] = 0x45; // vhl: v4, ihl=5
        p[ETHER_SIZE + 8] = ttl;
        p[ETHER_SIZE + 9] = proto;
        // Real checksum so RFC-1624 adjust has a valid start.
        // inet_checksum returns native-order; write back ne_bytes.
        let csum = inet_checksum(&p[ETHER_SIZE..ETHER_SIZE + IP_SIZE], 0);
        p[ETHER_SIZE + 10..ETHER_SIZE + 12].copy_from_slice(&csum.to_ne_bytes());
        p
    }

    /// RFC-1624: incremental adjust == recompute.
    #[test]
    fn decrement_ttl_v4_decrements_and_adjusts_checksum() {
        let mut p = ipv4_ttl_packet(64, 6); // TCP, TTL 64

        let r = decrement_ttl(&mut p);
        assert_eq!(r, TtlResult::Decremented);
        assert_eq!(p[ETHER_SIZE + 8], 63);

        let adjusted = [p[ETHER_SIZE + 10], p[ETHER_SIZE + 11]];
        p[ETHER_SIZE + 10] = 0;
        p[ETHER_SIZE + 11] = 0;
        let fresh = inet_checksum(&p[ETHER_SIZE..ETHER_SIZE + IP_SIZE], 0);
        assert_eq!(adjusted, fresh.to_ne_bytes());
    }

    #[test]
    fn decrement_ttl_v4_at_1_sends_icmp() {
        let mut p = ipv4_ttl_packet(1, 6); // TCP

        let r = decrement_ttl(&mut p);
        assert_eq!(
            r,
            TtlResult::SendIcmp {
                icmp_type: ICMP_TIME_EXCEEDED,
                icmp_code: ICMP_EXC_TTL,
            }
        );
        assert_eq!(p[ETHER_SIZE + 8], 1); // untouched on bounce
    }

    /// Storm guard. Tests upstream's actual (buggy) offsets: [+11]
    /// is `ip_sum` low byte not `ip_p`, but ported as-is.
    #[test]
    fn decrement_ttl_v4_at_1_but_is_timeexceeded() {
        let mut p = vec![0u8; ETHER_SIZE + 33]; // need [ethlen+32]
        p[12..14].copy_from_slice(&ETH_P_IP.to_be_bytes());
        p[ETHER_SIZE + 8] = 1; // TTL
        p[ETHER_SIZE + 11] = IPPROTO_ICMP; // C reads here for proto
        p[ETHER_SIZE + 32] = ICMP_TIME_EXCEEDED; // C reads here for type

        let r = decrement_ttl(&mut p);
        assert_eq!(r, TtlResult::DropSilent);
    }

    #[test]
    fn decrement_ttl_v6_decrements() {
        let mut p = vec![0u8; ETHER_SIZE + IP6_SIZE];
        p[12..14].copy_from_slice(&ETH_P_IPV6.to_be_bytes());
        p[ETHER_SIZE + 7] = 64; // ip6_hlim

        let r = decrement_ttl(&mut p);
        assert_eq!(r, TtlResult::Decremented);
        assert_eq!(p[ETHER_SIZE + 7], 63);
    }

    #[test]
    fn decrement_ttl_v6_at_1_sends_icmp() {
        let mut p = vec![0u8; ETHER_SIZE + IP6_SIZE + 1];
        p[12..14].copy_from_slice(&ETH_P_IPV6.to_be_bytes());
        p[ETHER_SIZE + 7] = 1; // hlim
        p[ETHER_SIZE + 6] = 6; // nxt: TCP, not ICMPv6

        let r = decrement_ttl(&mut p);
        assert_eq!(
            r,
            TtlResult::SendIcmp {
                icmp_type: ICMP6_TIME_EXCEEDED,
                icmp_code: ICMP6_TIME_EXCEED_TRANSIT,
            }
        );
    }

    #[test]
    fn decrement_ttl_unknown_ethertype_noop() {
        let mut p = vec![0u8; ETHER_SIZE];
        p[12..14].copy_from_slice(&0x1234u16.to_be_bytes());

        let r = decrement_ttl(&mut p);
        assert_eq!(r, TtlResult::Decremented);
    }

    #[test]
    fn decrement_ttl_8021q_skip() {
        let mut p = vec![0u8; ETHER_SIZE + 4 + IP_SIZE];
        p[12..14].copy_from_slice(&ETH_P_8021Q.to_be_bytes());
        p[16..18].copy_from_slice(&ETH_P_IP.to_be_bytes()); // inner
        p[ETHER_SIZE + 4 + 8] = 64; // TTL at ethlen+8

        let r = decrement_ttl(&mut p);
        assert_eq!(r, TtlResult::Decremented);
        assert_eq!(p[ETHER_SIZE + 4 + 8], 63);
    }

    // ────────────────────────────────────────────────────────────────
    // extract_tos

    /// v4 TOS at byte 15.
    #[test]
    fn extract_tos_v4() {
        let mut p = ipv4_packet(Ipv4Addr::new(10, 0, 0, 1));
        p[15] = 0xb8; // DSCP EF (Expedited Forwarding), RFC 3246
        assert_eq!(extract_tos(&p), Some(0xb8));
    }

    /// v6 TC straddles bytes 14/15.
    /// `0x6b` `0x80` → ver=6, TC = (0xb<<4)|(0x8) = 0xb8.
    #[test]
    fn extract_tos_v6() {
        let mut p = ipv6_packet("2001:db8::1".parse().unwrap());
        p[14] = 0x6b; // ver=6, TC high nibble = 0xb
        p[15] = 0x80; // TC low nibble = 0x8, flow label high = 0
        assert_eq!(extract_tos(&p), Some(0xb8));
    }

    /// short / non-IP → None (priority stays 0).
    #[test]
    fn extract_tos_gates() {
        // Too short for ethertype.
        assert_eq!(extract_tos(&[0u8; 10]), None);
        // ARP: non-IP.
        let mut p = vec![0u8; ETHER_SIZE];
        p[12..14].copy_from_slice(&ETH_P_ARP.to_be_bytes());
        assert_eq!(extract_tos(&p), None);
        // v4 ethertype but short body (<34): MAC mode could see this.
        let mut p = vec![0u8; ETHER_SIZE + 10];
        p[12..14].copy_from_slice(&ETH_P_IP.to_be_bytes());
        assert_eq!(extract_tos(&p), None);
    }

    #[test]
    fn decrement_ttl_v4_minimal_frame_ttl_expired() {
        // 34B = eth(14)+ip(20); TTL=1; [+11]=ICMP so storm-guard reads [+32] (past end)
        let mut p = vec![0u8; ETHER_SIZE + IP_SIZE];
        p[12..14].copy_from_slice(&ETH_P_IP.to_be_bytes());
        p[ETHER_SIZE + 8] = 1;
        p[ETHER_SIZE + 11] = IPPROTO_ICMP;
        assert_eq!(
            decrement_ttl(&mut p),
            TtlResult::SendIcmp {
                icmp_type: ICMP_TIME_EXCEEDED,
                icmp_code: ICMP_EXC_TTL,
            }
        );
    }

    #[test]
    fn decrement_ttl_v6_minimal_frame_hlim_expired() {
        // 54B = eth(14)+ip6(40); hlim=1; nxt=ICMPv6 so storm-guard reads [+40] (== len)
        let mut p = vec![0u8; ETHER_SIZE + IP6_SIZE];
        p[12..14].copy_from_slice(&ETH_P_IPV6.to_be_bytes());
        p[ETHER_SIZE + 7] = 1;
        p[ETHER_SIZE + 6] = IPPROTO_ICMPV6;
        assert_eq!(
            decrement_ttl(&mut p),
            TtlResult::SendIcmp {
                icmp_type: ICMP6_TIME_EXCEEDED,
                icmp_code: ICMP6_TIME_EXCEED_TRANSIT,
            }
        );
    }
}
