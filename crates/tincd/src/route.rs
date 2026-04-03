//! `route.c`: the forwarding decision.
//!
//! When a packet arrives — from the TUN device or from a peer — the
//! daemon calls `route()` to figure out where it goes next. The C
//! `route.c:1130` reads the ethertype, dispatches by family,
//! `route_ipv4` reads the dst address out of the IP header, hits
//! the subnet tree, and calls `send_packet(subnet->owner, packet)`
//! directly.
//!
//! ## Decisions, not effects
//!
//! C `route_ipv4` is a 90-line procedure with eight exit points,
//! each one a side effect: `send_packet()`, `route_ipv4_unreachable()`,
//! `fragment_ipv4_packet()`, plain `return`. Testing it means standing
//! up the whole node graph + a fake TUN.
//!
//! Same pattern as `graph_glue::Transition`: this module returns a
//! `RouteResult` enum and the daemon loop dispatches it. The routing
//! logic is then a pure function of `(packet bytes, subnet tree,
//! reachability oracle)` → `RouteResult`. Six tests, no I/O.
//!
//! ## What's NOT here yet
//!
//! Chunk 7 wires the happy path. The C `route_ipv4` has another ~50
//! LOC of MTU/TTL/MSS/broadcast handling that all gate on config
//! flags or per-node MTU state. Those are `// DEFERRED(chunk-9)`
//! markers below, each with the C line ref.

#![forbid(unsafe_code)]

use std::net::Ipv4Addr;

use crate::packet::{ETH_P_ARP, ETH_P_IP};
use crate::subnet_tree::SubnetTree;

// ────────────────────────────────────────────────────────────────────
// Wire constants
//
// `route.c:56-59`: `ether_size = sizeof(struct ether_header)` etc.
// `Ipv4Hdr` is 20 bytes (`packet.rs:114` static-asserts it). We don't
// pull in `Ipv4Hdr` here — `route_ipv4` only needs offset 16 (`ip_dst`),
// and the manual slice is what the C does anyway (`memcpy(&dest,
// &DATA(packet)[30], ...)` — `30 == 14 + 16`).

/// `sizeof(struct ether_header)`. `ethernet.h:36`.
const ETHER_SIZE: usize = 14;

/// `sizeof(struct ip)`. `ipv4.h:93`. Minimum — no options.
const IP_SIZE: usize = 20;

/// `ETH_P_IPV6` — `ethernet.h:52`. `tinc-device::ether` has it but
/// it's `pub(crate)`; one duplicated `u16` beats a re-export commit.
const ETH_P_IPV6: u16 = 0x86DD;

/// `ETH_P_8021Q` — `ethernet.h:56`. VLAN tag. `route.c:1145` strips
/// the 4-byte tag and re-dispatches; deferred.
const ETH_P_8021Q: u16 = 0x8100;

// `ipv4.h:35,43,55`. ICMP type 3 (destination unreachable) and the
// two codes `route_ipv4` actually emits on the happy path. The full
// set (NET_ANO, FRAG_NEEDED, …) lands with chunk-9's ICMP synthesis.

/// `ICMP_DEST_UNREACH` — `ipv4.h:35`. RFC 792 type 3.
pub const ICMP_DEST_UNREACH: u8 = 3;
/// `ICMP_NET_UNKNOWN` — `ipv4.h:43`. RFC 1122 code 6: no route.
pub const ICMP_NET_UNKNOWN: u8 = 6;
/// `ICMP_NET_UNREACH` — `ipv4.h:55`. RFC 792 code 0: route exists,
/// next hop is down.
pub const ICMP_NET_UNREACH: u8 = 0;

// ────────────────────────────────────────────────────────────────────
// RouteResult

/// What to do with a packet. `route.c`'s side-effect calls, reified.
///
/// The lifetime `'a` ties `Forward::to` back into the `SubnetTree`
/// — same shape as `lookup_ipv4`'s return. Daemon resolves the name
/// to a `NodeId` before the next subnet-tree mutation.
#[derive(Debug, PartialEq, Eq)]
pub enum RouteResult<'a> {
    /// `route.c:706`: `send_packet(subnet->owner, packet)`.
    ///
    /// `to == myself` is the "destined for us" case — C
    /// `send_packet` special-cases that into `write_packet()` (TUN
    /// write). The daemon does the same on this variant.
    Forward { to: &'a str },

    /// `route.c:640,655,660,681,690`: `route_ipv4_unreachable(...)`.
    ///
    /// Chunk 7: daemon logs `(type, code)` and drops. Chunk 9: daemon
    /// synthesises the ICMP error packet (`route.c:121-215`) and
    /// sends it back to `source`.
    Unreachable { icmp_type: u8, icmp_code: u8 },

    /// `route.c:1149,1154,1163` and the `RMODE_SWITCH` branch.
    /// Ethertypes / modes we don't handle yet. Daemon logs + drops.
    Unsupported { reason: &'static str },

    /// `route.c:103-108`: `checklength` failed. Packet truncated
    /// somewhere upstream. C logs "Got too short packet from %s"
    /// at `DEBUG_TRAFFIC` and drops; daemon does the same.
    TooShort { need: usize, have: usize },
}

// ────────────────────────────────────────────────────────────────────
// route_ipv4

/// `route.c:620-710`. The IPv4 routing decision.
///
/// Reads the destination address from the IP header at
/// `data[ETHER_SIZE..]`, looks it up in `subnets`, returns the owner.
///
/// `is_reachable`: the daemon passes a closure that reads
/// `graph.node(nid).reachable`. This is the same shape as
/// `SubnetTree::lookup_ipv4`'s callback — and we forward to it
/// (with `myself` always considered up; a node never marks itself
/// unreachable).
///
/// `myself`: our own node name. C compares `subnet->owner == myself`
/// by pointer; we compare by string.
///
/// What's NOT here from the C: every branch that needs config flags
/// or `node_t` fields beyond `reachable`. See the `DEFERRED` markers.
pub fn route_ipv4<'a>(
    data: &[u8],
    subnets: &'a SubnetTree,
    myself: &str,
    mut is_reachable: impl FnMut(&str) -> bool,
) -> RouteResult<'a> {
    // `route.c:621`: `if(!checklength(source, packet, ether_size +
    // ip_size)) return;`. The C logs the source name; we hand back
    // the lengths and let the daemon (which HAS the source) log.
    let need = ETHER_SIZE + IP_SIZE;
    if data.len() < need {
        return RouteResult::TooShort {
            need,
            have: data.len(),
        };
    }

    // `route.c:629`: `memcpy(&dest, &DATA(packet)[30], sizeof(dest))`.
    // 30 == ETHER_SIZE + offsetof(struct ip, ip_dst) == 14 + 16.
    // `Ipv4Hdr` has `ip_dst: [u8; 4]` at that offset (`packet.rs:111`)
    // but we'd have to copy the full 20-byte header to use the getter;
    // the C reads four bytes, so do we.
    let dst_off = ETHER_SIZE + 16;
    let dest = Ipv4Addr::new(
        data[dst_off],
        data[dst_off + 1],
        data[dst_off + 2],
        data[dst_off + 3],
    );

    // `route.c:630`: `subnet = lookup_subnet_ipv4(&dest)`.
    //
    // `lookup_ipv4` walks the tree longest-prefix-first and breaks on
    // the first owner the closure says is reachable. We treat `myself`
    // as always reachable here: if WE own the most-specific covering
    // subnet, that's the answer regardless of what the graph says
    // about us (`route.c:655` only checks `subnet->owner->status.
    // reachable` for REMOTE owners; `myself->status.reachable` is
    // never consulted on this path).
    let Some((_subnet, owner)) = subnets.lookup_ipv4(&dest, |n| n == myself || is_reachable(n))
    else {
        // `route.c:632-641`: no covering subnet → ICMP net-unknown.
        // C also logs the dotted-quad at DEBUG_TRAFFIC; daemon's job.
        return RouteResult::Unreachable {
            icmp_type: ICMP_DEST_UNREACH,
            icmp_code: ICMP_NET_UNKNOWN,
        };
    };

    // DEFERRED(chunk-9): `route.c:644-646` `if(!subnet->owner)` —
    // ownerless subnets are broadcast. `SubnetTree` doesn't model
    // ownerless entries yet (every `add()` takes a `String` owner).

    // DEFERRED(chunk-7-daemon): `route.c:648-651` `if(subnet->owner
    // == source)` — loop detection. Needs `source`, which is daemon
    // state (which connection did this packet arrive on?). The
    // daemon checks before calling us.

    // `route.c:706`: `send_packet(subnet->owner, packet)`. C reaches
    // this for `owner == myself` too — `send_packet` itself branches
    // on that into `write_packet` (TUN). We collapse: same variant,
    // daemon checks `to == myself`.
    if owner == myself {
        return RouteResult::Forward { to: owner };
    }

    // `route.c:653-656`: `if(!subnet->owner->status.reachable)`.
    //
    // `lookup_ipv4` may return an UNREACHABLE owner: it remembers
    // the last `maskcmp` hit even if the closure never said yes
    // (`subnet_tree.rs:310` "We return Some for that fallback too").
    // C `route_ipv4` then turns that into ICMP net-unreach. So we
    // must re-check.
    if !is_reachable(owner) {
        return RouteResult::Unreachable {
            icmp_type: ICMP_DEST_UNREACH,
            icmp_code: ICMP_NET_UNREACH,
        };
    }

    // DEFERRED(chunk-9): `route.c:658-661` `forwarding_mode ==
    // FMODE_OFF && source != myself && owner != myself` → NET_ANO.
    // Config-gated; default is FMODE_INTERNAL.

    // DEFERRED(chunk-9): `route.c:663-666` `decrement_ttl` →
    // `do_decrement_ttl()`. Mutates the packet (TTL field + checksum
    // fixup). Config-gated; default off.

    // DEFERRED(chunk-9): `route.c:668-670` `priorityinheritance` —
    // copies the IP TOS byte into `packet->priority`. Config-gated.

    // DEFERRED(chunk-7-daemon): `route.c:672` `via = (owner->via ==
    // myself) ? owner->nexthop : owner->via`. The indirect/relay
    // path. Needs `nodes` access (graph state, not subnet tree).
    // `route.c:674-677` then re-checks `via == source` for loops.

    // DEFERRED(chunk-9): `route.c:679-682` `directonly && owner !=
    // via` → NET_ANO. Config-gated.

    // DEFERRED(chunk-9): `route.c:684-696` MTU check. `packet->len >
    // via->mtu` → either FRAG_NEEDED (DF bit set) or fragment. Needs
    // per-node MTU from PMTU discovery (chunk 8).

    // DEFERRED(chunk-9): `route.c:698` `clamp_mss(source, via,
    // packet)`. TCP MSS rewriting for the via-node's MTU.

    RouteResult::Forward { to: owner }
}

// ────────────────────────────────────────────────────────────────────
// route — top-level dispatch

/// `route.c:1130-1180`. Ethertype dispatch.
///
/// C reads `routing_mode` first (`RMODE_ROUTER` / `_SWITCH` /
/// `_HUB`). We only do `RMODE_ROUTER` — switch mode is TAP-device
/// territory (chunk 9+). The ethertype switch under it is what's
/// here.
///
/// `data` is the full ethernet frame: 14-byte header, then payload.
/// The TUN device (`tinc-device`) synthesises the ethernet header
/// for us in router mode, so this works for both TUN-read and
/// peer-received packets.
pub fn route<'a>(
    data: &[u8],
    subnets: &'a SubnetTree,
    myself: &str,
    is_reachable: impl FnMut(&str) -> bool,
) -> RouteResult<'a> {
    // DEFERRED(chunk-9): `route.c:1131-1133` `if(pcap) send_pcap()`.
    // Debug tap into the control socket.

    // DEFERRED(chunk-9): `route.c:1135-1138` `forwarding_mode ==
    // FMODE_KERNEL` — punt everything to the OS routing table.
    // Config-gated; default is FMODE_INTERNAL.

    // `route.c:1140`: `if(!checklength(source, packet, ether_size))`.
    // We need bytes [12..14] for the ethertype.
    if data.len() < ETHER_SIZE {
        return RouteResult::TooShort {
            need: ETHER_SIZE,
            have: data.len(),
        };
    }

    // `route.c:1144`: `type = DATA(packet)[12] << 8 | DATA(packet)[13]`.
    // Big-endian ethertype. Same as `EtherHdr::type` would be if we
    // had one in `packet.rs`; we don't, two bytes don't need a struct.
    let ethertype = u16::from_be_bytes([data[12], data[13]]);

    // `route.c:1146`: `switch(routing_mode)`. Only RMODE_ROUTER.
    // DEFERRED(chunk-9): RMODE_SWITCH → `route_mac` (TAP bridge
    // learning). RMODE_HUB → `route_broadcast` (flood everything).

    // `route.c:1148`: `switch(type)`.
    match ethertype {
        ETH_P_IP => route_ipv4(data, subnets, myself, is_reachable),
        ETH_P_IPV6 => RouteResult::Unsupported {
            reason: "ipv6: chunk 9",
        },
        ETH_P_ARP => RouteResult::Unsupported {
            reason: "arp: chunk 9",
        },
        ETH_P_8021Q => {
            // `route.c:1145` (the C handles this BEFORE the type
            // switch, by bumping `ether_size += 4` and re-reading
            // the inner ethertype at `[16..18]`). We defer.
            RouteResult::Unsupported {
                reason: "vlan: chunk 9",
            }
        }
        _ => {
            // `route.c:1163`: "Cannot route packet … unknown type
            // %hx". The C logs the hex value; we'd have to leak a
            // formatted string to put it in `&'static str`. Daemon
            // can log `data[12..14]` itself.
            RouteResult::Unsupported {
                reason: "unknown ethertype",
            }
        }
    }
}

// ════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use tinc_proto::Subnet;

    /// Build a minimal 34-byte ethernet+IPv4 frame with `dst` in the
    /// IP header's `ip_dst` field. Everything else is zero — `route`
    /// only reads ethertype `[12..14]` and dst `[30..34]`.
    fn ipv4_packet(dst: Ipv4Addr) -> Vec<u8> {
        let mut p = vec![0u8; ETHER_SIZE + IP_SIZE];
        // Ethertype at [12..14], big-endian.
        p[12..14].copy_from_slice(&ETH_P_IP.to_be_bytes());
        // `ip_dst` at offset 16 in the IP header → [30..34] absolute.
        p[ETHER_SIZE + 16..ETHER_SIZE + 20].copy_from_slice(&dst.octets());
        p
    }

    fn sn(s: &str) -> Subnet {
        s.parse().unwrap()
    }

    /// `route.c:706` happy path: subnet exists, owner is up,
    /// `send_packet(owner, ...)`.
    #[test]
    fn route_ipv4_forwards_to_owner() {
        let mut t = SubnetTree::new();
        t.add(sn("10.0.0.0/24"), "bob".into());

        let p = ipv4_packet(Ipv4Addr::new(10, 0, 0, 5));
        let r = route_ipv4(&p, &t, "alice", |_| true);

        assert_eq!(r, RouteResult::Forward { to: "bob" });
    }

    /// `route.c:706` with `owner == myself`: still `Forward`, daemon
    /// special-cases the TUN write. Reachability of self is never
    /// consulted — pass a closure that says everything is DOWN to
    /// prove the `myself` short-circuit fires first.
    #[test]
    fn route_ipv4_forwards_to_self() {
        let mut t = SubnetTree::new();
        t.add(sn("10.0.0.0/24"), "alice".into());

        let p = ipv4_packet(Ipv4Addr::new(10, 0, 0, 5));
        let r = route_ipv4(&p, &t, "alice", |_| false);

        assert_eq!(r, RouteResult::Forward { to: "alice" });
    }

    /// `route.c:632-641`: `lookup_subnet_ipv4` returned NULL.
    /// Type 3 code 6 — RFC 1122 "destination network unknown".
    #[test]
    fn route_ipv4_unknown_net() {
        let t = SubnetTree::new();

        let p = ipv4_packet(Ipv4Addr::new(10, 0, 0, 5));
        let r = route_ipv4(&p, &t, "alice", |_| true);

        assert_eq!(
            r,
            RouteResult::Unreachable {
                icmp_type: ICMP_DEST_UNREACH,
                icmp_code: ICMP_NET_UNKNOWN,
            }
        );
    }

    /// `route.c:653-656`: subnet exists but `owner->status.reachable`
    /// is false. `lookup_ipv4` returns the unreachable owner anyway
    /// (the "last hit" fallback); we turn it into type 3 code 0.
    #[test]
    fn route_ipv4_unreachable_owner() {
        let mut t = SubnetTree::new();
        t.add(sn("10.0.0.0/24"), "bob".into());

        let p = ipv4_packet(Ipv4Addr::new(10, 0, 0, 5));
        let r = route_ipv4(&p, &t, "alice", |_| false);

        assert_eq!(
            r,
            RouteResult::Unreachable {
                icmp_type: ICMP_DEST_UNREACH,
                icmp_code: ICMP_NET_UNREACH,
            }
        );
    }

    /// `route.c:621` `checklength`: 30 bytes < 14+20.
    #[test]
    fn route_too_short() {
        let p = vec![0u8; 30];
        let t = SubnetTree::new();
        let r = route_ipv4(&p, &t, "alice", |_| true);

        assert_eq!(r, RouteResult::TooShort { need: 34, have: 30 });
    }

    /// `route.c:1148` ethertype dispatch. IPv6 / ARP / VLAN are
    /// chunk-9; unknown types fall through to the C `default` log.
    #[test]
    fn route_ethertype_dispatch() {
        let t = SubnetTree::new();
        let mut p = vec![0u8; ETHER_SIZE];

        for (et, want) in [
            (ETH_P_IPV6, "ipv6: chunk 9"),
            (ETH_P_ARP, "arp: chunk 9"),
            (ETH_P_8021Q, "vlan: chunk 9"),
            (0x1234, "unknown ethertype"),
        ] {
            p[12..14].copy_from_slice(&et.to_be_bytes());
            let r = route(&p, &t, "alice", |_| true);
            assert_eq!(r, RouteResult::Unsupported { reason: want });
        }

        // And ETH_P_IP actually dispatches into route_ipv4 (which
        // then bounces on length: 14 bytes < 34).
        p[12..14].copy_from_slice(&ETH_P_IP.to_be_bytes());
        let r = route(&p, &t, "alice", |_| true);
        assert_eq!(r, RouteResult::TooShort { need: 34, have: 14 });
    }

    /// `route.c:1140`: top-level `checklength(ether_size)`. Can't
    /// read the ethertype from a 10-byte frame.
    #[test]
    fn route_too_short_for_ethertype() {
        let p = vec![0u8; 10];
        let t = SubnetTree::new();
        let r = route(&p, &t, "alice", |_| true);

        assert_eq!(r, RouteResult::TooShort { need: 14, have: 10 });
    }
}
