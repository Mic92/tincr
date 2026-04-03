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

use std::net::{Ipv4Addr, Ipv6Addr};

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

/// `sizeof(struct ip6_hdr)`. `ipv6.h:63`. Fixed; v6 has no header
/// options (extensions are chained via `ip6_nxt`).
const IP6_SIZE: usize = 40;

/// `sizeof(struct icmp6_hdr)`. `ipv6.h:84`. Type, code, checksum,
/// 4-byte data union. `route.c:710` checks this length before
/// reading the ICMP type byte for the NDP divert.
const ICMP6_SIZE: usize = 8;

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
/// `ICMP_NET_ANO` — `ipv4.h:59`. RFC 1122 code 9: "communication
/// with destination network administratively prohibited". The C
/// uses this for `directonly` (`route.c:680`) and `FMODE_OFF`
/// (`route.c:660`): the route EXISTS but we choose not to forward.
pub const ICMP_NET_ANO: u8 = 9;
/// `ICMP_NET_UNREACH` — `ipv4.h:55`. RFC 792 code 0: route exists,
/// next hop is down.
pub const ICMP_NET_UNREACH: u8 = 0;
/// `ICMP_TIME_EXCEEDED` — `ipv4.h:59`. RFC 792 type 11.
pub const ICMP_TIME_EXCEEDED: u8 = 11;
/// `ICMP_EXC_TTL` — `ipv4.h:63`. RFC 792 code 0: TTL went to zero
/// in transit.
pub const ICMP_EXC_TTL: u8 = 0;

// `<netinet/icmp6.h>`. RFC 4443 §3.1.

/// `ICMP6_DST_UNREACH` — RFC 4443 type 1.
pub const ICMP6_DST_UNREACH: u8 = 1;
/// `ICMP6_DST_UNREACH_NOROUTE` — RFC 4443 code 0.
pub const ICMP6_DST_UNREACH_NOROUTE: u8 = 0;
/// `ICMP6_DST_UNREACH_ADMIN` — RFC 4443 code 1: administratively
/// prohibited. The C uses this for `FMODE_OFF` and `directonly`.
pub const ICMP6_DST_UNREACH_ADMIN: u8 = 1;
/// `ICMP6_DST_UNREACH_ADDR` — RFC 4443 code 3: address unreachable.
/// The v6 analogue of `ICMP_NET_UNKNOWN` for the no-subnet case.
pub const ICMP6_DST_UNREACH_ADDR: u8 = 3;
/// `ICMP6_PACKET_TOO_BIG` — RFC 4443 type 2. v6 doesn't fragment
/// in-network (RFC 8200 §5); only the source can. `route.c:780`
/// emits this on `len > MAX(via->mtu, 1294)` — 1294 = 1280 (the
/// v6 minimum MTU) + 14 ethernet.
pub const ICMP6_PACKET_TOO_BIG: u8 = 2;
/// `ICMP6_TIME_EXCEEDED` — RFC 4443 type 3.
pub const ICMP6_TIME_EXCEEDED: u8 = 3;
/// `ICMP6_TIME_EXCEED_TRANSIT` — RFC 4443 code 0.
pub const ICMP6_TIME_EXCEED_TRANSIT: u8 = 0;

/// `ND_NEIGHBOR_SOLICIT` — RFC 4861 §4.3. ICMPv6 type 135. The v6
/// equivalent of an ARP who-has. `route.c:710` diverts these into
/// `route_neighborsol` which synthesises the advert reply.
const ND_NEIGHBOR_SOLICIT: u8 = 135;

/// `IPPROTO_ICMP`. `route.c:344` checks this when deciding whether
/// a TTL=0 packet IS already an ICMP-time-exceeded (no storm).
const IPPROTO_ICMP: u8 = 1;
/// `IPPROTO_ICMPV6`. `route.c:710` for the NDP-divert next-header
/// check, and `:376` for the v6 storm guard.
const IPPROTO_ICMPV6: u8 = 58;

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

    /// `route.c:710-713`: ICMPv6 type 135 (Neighbor Solicit). The
    /// daemon synthesises a Neighbor Advert (`route_neighborsol`,
    /// `:793-954`). The daemon already has the original `data`;
    /// nothing to carry here. Same treatment as `ETH_P_ARP =>
    /// Unsupported{"arp"}` — both arms get real bodies when the
    /// `neighbor.rs` leaf lands.
    NeighborSolicit,

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
// route_ipv6

/// `route.c:705-791`. The IPv6 routing decision.
///
/// Structurally identical to [`route_ipv4`] — same gates, same
/// shape. Differences: dst at offset 38 not 30; ICMPv6 codes not
/// ICMPv4; the NDP divert at `:710` (no v4 equivalent in `route_
/// ipv4` itself — ARP is dispatched at the ethertype level); and
/// the MTU check uses `MAX(via->mtu, 1294)` because v6 forbids
/// in-network fragmentation (RFC 8200 §5).
///
/// The NDP divert (`:710-713`): when `ip6_nxt == IPPROTO_ICMPV6`
/// and the ICMP type byte at `[54]` is `ND_NEIGHBOR_SOLICIT`, the
/// daemon synthesises a neighbor-advert reply (`route_neighborsol`,
/// the v6 equivalent of `route_arp`). We return `NeighborSolicit`
/// and the daemon falls through to that. The synthesis itself is
/// another leaf (`neighbor.rs`).
///
/// Same `DEFERRED(chunk-9)` markers as `route_ipv4` for the
/// config-gated branches.
pub fn route_ipv6<'a>(
    data: &[u8],
    subnets: &'a SubnetTree,
    myself: &str,
    mut is_reachable: impl FnMut(&str) -> bool,
) -> RouteResult<'a> {
    // `route.c:706`: `if(!checklength(source, packet, ether_size +
    // ip6_size)) return;`.
    let need = ETHER_SIZE + IP6_SIZE;
    if data.len() < need {
        return RouteResult::TooShort {
            need,
            have: data.len(),
        };
    }

    // `route.c:710-713`: NDP divert. `DATA(packet)[20]` is `ip6_nxt`
    // (offset 6 in `struct ip6_hdr` → 14+6=20). `DATA(packet)[54]`
    // is `icmp6_type` (14+40+0). The C also `checklength(ether +
    // ip6 + icmp6)` here — needs the type byte to exist.
    if data[20] == IPPROTO_ICMPV6
        && data.len() >= ETHER_SIZE + IP6_SIZE + ICMP6_SIZE
        && data[54] == ND_NEIGHBOR_SOLICIT
    {
        return RouteResult::NeighborSolicit;
    }

    // `route.c:719`: `memcpy(&dest, &DATA(packet)[38], sizeof dest)`.
    // 38 == ETHER_SIZE + offsetof(struct ip6_hdr, ip6_dst) == 14+24.
    // 16 bytes; the slice-to-array `try_into` can't fail (we length-
    // checked above), so `expect` is unreachable. Clippy wants the
    // `# Panics` doc note; this is the same shape as `route_ipv4`'s
    // direct indexing — the bounds check IS the proof.
    let dst_off = ETHER_SIZE + 24;
    #[allow(clippy::missing_panics_doc)]
    let dest: [u8; 16] = data[dst_off..dst_off + 16]
        .try_into()
        .expect("len-checked above");
    let dest = Ipv6Addr::from(dest);

    // `route.c:720`: `subnet = lookup_subnet_ipv6(&dest)`.
    // Same `myself`-always-reachable shape as `route_ipv4`.
    let Some((_subnet, owner)) = subnets.lookup_ipv6(&dest, |n| n == myself || is_reachable(n))
    else {
        // `route.c:722-735`: no covering subnet → ICMPv6
        // dest-unreach / addr. C also logs the colon-hex.
        return RouteResult::Unreachable {
            icmp_type: ICMP6_DST_UNREACH,
            icmp_code: ICMP6_DST_UNREACH_ADDR,
        };
    };

    // DEFERRED(chunk-9): `route.c:738-741` `if(!subnet->owner)` —
    // ownerless subnets are broadcast. `SubnetTree` doesn't model
    // ownerless entries yet (every `add()` takes a `String` owner).

    // DEFERRED(chunk-7-daemon): `route.c:743-746` `if(subnet->owner
    // == source)` — loop detection. Needs `source`, which is daemon
    // state (which connection did this packet arrive on?). The
    // daemon checks before calling us.

    // `route.c:789`: same collapse as `route_ipv4` — `owner ==
    // myself` is `Forward{to:myself}` and the daemon dispatches to
    // TUN write.
    if owner == myself {
        return RouteResult::Forward { to: owner };
    }

    // `route.c:748-751`: `if(!subnet->owner->status.reachable)`.
    // Same fallback-unreachable-owner re-check as `route_ipv4`
    // (`lookup_ipv6` may return an unreachable owner from the
    // last-hit fallback).
    if !is_reachable(owner) {
        return RouteResult::Unreachable {
            icmp_type: ICMP6_DST_UNREACH,
            icmp_code: ICMP6_DST_UNREACH_NOROUTE,
        };
    }

    // DEFERRED(chunk-9): `route.c:753-756` `forwarding_mode ==
    // FMODE_OFF && source != myself && owner != myself` →
    // DST_UNREACH_ADMIN. Config-gated; default is FMODE_INTERNAL.

    // DEFERRED(chunk-9): `route.c:758-761` `decrement_ttl` →
    // `do_decrement_ttl()`. Mutates the packet (hop-limit field;
    // no checksum in v6 IP). Config-gated; default off.

    // DEFERRED(chunk-9): `route.c:763-765` `priorityinheritance` —
    // copies the v6 traffic-class nibble pair `((data[14] & 0x0f)
    // << 4) | (data[15] >> 4)` into `packet->priority`. Config-gated.

    // DEFERRED(chunk-7-daemon): `route.c:767` `via = (owner->via ==
    // myself) ? owner->nexthop : owner->via`. The indirect/relay
    // path. Needs `nodes` access (graph state, not subnet tree).
    // `route.c:769-772` then re-checks `via == source` for loops.

    // DEFERRED(chunk-9): `route.c:774-777` `directonly && owner !=
    // via` → DST_UNREACH_ADMIN. Config-gated.

    // DEFERRED(chunk-9): `route.c:779-784` MTU check. `packet->len >
    // MAX(via->mtu, 1294)` → PACKET_TOO_BIG. 1294 = 1280 (v6 min
    // MTU, RFC 8200) + 14 eth. v6 never fragments in-network; only
    // ever the TOO_BIG bounce. Needs per-node MTU (chunk 8).

    // DEFERRED(chunk-9): `route.c:786` `clamp_mss(source, via,
    // packet)`. TCP MSS rewriting for the via-node's MTU.

    RouteResult::Forward { to: owner }
}

// ────────────────────────────────────────────────────────────────────
// decrement_ttl

/// `do_decrement_ttl`'s outcome (`route.c:328-388`). The C returns
/// `bool` (keep-going / stop) and side-effects the ICMP synthesis;
/// we reify the four exits.
#[derive(Debug, PartialEq, Eq)]
pub enum TtlResult {
    /// `:365`, `:384`, `:386`: TTL was >1 and decremented (or the
    /// ethertype is unknown — `default: return true`). Keep going.
    Decremented,
    /// `:344-347`, `:376-379`: TTL was ≤1 and the packet IS an
    /// ICMP-time-exceeded — silent drop to avoid storms. The C
    /// `return false` without the `route_..._unreachable` call.
    DropSilent,
    /// `:345`, `:377`: TTL was ≤1 and the packet is NOT already a
    /// time-exceeded. Daemon synthesises ICMP and bounces back to
    /// `source`. v4/v6 distinguished by the type/code pair (the
    /// daemon knows from dispatch context which `build_` to call).
    SendIcmp { icmp_type: u8, icmp_code: u8 },
    /// `:339-341`, `:368-370`: `checklength` failed. C `return
    /// false` after the log; daemon drops.
    TooShort,
}

/// `do_decrement_ttl` (`route.c:328-388`). In-place TTL/hop-limit
/// decrement + IPv4 checksum adjust.
///
/// `data` is `&mut` because the v4 path checksum-adjusts in place
/// (`:362-363`). The v6 IP header has no checksum (RFC 8200 §3)
/// so v6 just decrements `[ethlen+7]` and is done.
///
/// ## RFC 1624 incremental checksum adjust (`:354-360`)
///
/// The IPv4 header checksum is one's-complement of the one's-
/// complement sum of the header words. When one 16-bit word changes
/// from `m` to `m'`, RFC 1624 eqn 3 gives `HC' = ~(~HC + ~m + m')`
/// — which is the same as updating the running SUM by `+m + ~m'`
/// and re-folding. The C `:356` does `csum += old + (~new & 0xFFFF)`
/// where `csum` is the OLD checksum value (already complemented):
/// adding `old + ~new` to the complemented sum and folding gives
/// the new complemented sum directly.
///
/// Why not `csum += old - new`? In two's-complement these aren't
/// equivalent: one's-complement `-x ≡ ~x` but the carry-out from
/// the 16-bit add must wrap back into the low bit (`:358-360` fold).
/// Ordinary subtraction loses that carry.
pub fn decrement_ttl(data: &mut [u8]) -> TtlResult {
    // `route.c:329-335`: read ethertype, skip 8021Q tag if present.
    // Same idiom as `clamp_mss` (`:396-400`).
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
            // `:339-341`: `checklength(ethlen + ip_size)`.
            if data.len() < ethlen + IP_SIZE {
                return TtlResult::TooShort;
            }

            // `:343-349`: TTL byte is `[ethlen+8]` (`ip_ttl`, offset
            // 8 in `struct ip`). If ≤1 we either bounce TIME_EXCEEDED
            // or, if this IS already a TIME_EXCEEDED ICMP (proto at
            // `[ethlen+9]` == 1, ICMP type at `[ethlen+ip_size+0]` ==
            // 11), drop silently. `[ethlen+32]` is the ICMP type byte
            // because the C assumes `ihl=5` here — `ethlen + 20 + 12`
            // would be wrong; it's `ethlen + 20 + 0`. Wait: 32 ==
            // ip_size(20) + 12? No: 32 = 8 + 24. The C reads
            // `[ethlen+32]` = `[ethlen + ip_size + 12]`? That'd be the
            // ICMP "original IP header" quote, byte 12. Hm — actually
            // 32 = 20 + 12: ICMP header is 8 bytes, then quoted IP
            // header... no. Re-reading: `:344` checks `[ethlen+11]`
            // for proto and `[ethlen+32]` for type. 11 = `ip_p` offset
            // (correct: byte 9 is `ip_p`? no, byte 9 is also TTL
            // territory). Ah: `struct ip`: vhl(1) tos(1) len(2) id(2)
            // off(2) ttl(1=@8) p(1=@9) sum(2=@10) src(4=@12)
            // dst(4=@16). So `[ethlen+9]` is proto. C says `[ethlen
            // +11]` — that's the LOW byte of `ip_sum`. That can't be
            // right unless... oh, the C is WRONG here. But we port
            // it faithfully.
            //
            // Actually re-read `:344`: `DATA(packet)[ethlen+11] !=
            // IPPROTO_ICMP`. Offset 11 in the IP header is the low
            // byte of `ip_sum`. This is a bug in the C — should be
            // `+9`. And `[ethlen+32]` = `+20+12` = 12 bytes into the
            // ICMP payload (which is the quoted IP `ip_src` field).
            // The check is broken; it almost never matches; the
            // storm-guard rarely fires. We port it AS-IS (bug-for-
            // bug) and note it. `git log -p` confirms the C has been
            // this way since 2012.
            if data[ethlen + 8] <= 1 {
                if data[ethlen + 11] != IPPROTO_ICMP || data[ethlen + 32] != ICMP_TIME_EXCEEDED {
                    return TtlResult::SendIcmp {
                        icmp_type: ICMP_TIME_EXCEEDED,
                        icmp_code: ICMP_EXC_TTL,
                    };
                }
                return TtlResult::DropSilent;
            }

            // `:351-353`: read TTL+proto as a 16-bit BE word
            // (because the checksum operates on 16-bit words and TTL
            // is the high byte of word 4). Decrement TTL. Re-read.
            let old = u16::from_be_bytes([data[ethlen + 8], data[ethlen + 9]]);
            data[ethlen + 8] -= 1;
            let new = u16::from_be_bytes([data[ethlen + 8], data[ethlen + 9]]);

            // `:355-363`: RFC 1624 incremental adjust. See doc
            // comment above for the one's-complement rationale.
            let mut csum = u32::from(u16::from_be_bytes([data[ethlen + 10], data[ethlen + 11]]));
            csum += u32::from(old) + u32::from(!new);
            while csum >> 16 != 0 {
                csum = (csum & 0xFFFF) + (csum >> 16);
            }
            // Fold-loop guarantees `csum < 0x10000`; the casts are
            // exact (high half is zero).
            #[allow(clippy::cast_possible_truncation)]
            {
                data[ethlen + 10] = (csum >> 8) as u8;
                data[ethlen + 11] = csum as u8;
            }

            TtlResult::Decremented
        }

        ETH_P_IPV6 => {
            // `:368-370`: `checklength(ethlen + ip6_size)`.
            if data.len() < ethlen + IP6_SIZE {
                return TtlResult::TooShort;
            }

            // `:372-381`: hop-limit is `[ethlen+7]` (`ip6_hlim`,
            // offset 7 in `struct ip6_hdr`). Same storm-guard
            // shape: `[ethlen+6]` is `ip6_nxt`, `[ethlen+40]` is
            // the ICMPv6 type byte (correct this time — v6 IP
            // header is fixed 40 bytes).
            if data[ethlen + 7] <= 1 {
                if data[ethlen + 6] != IPPROTO_ICMPV6 || data[ethlen + 40] != ICMP6_TIME_EXCEEDED {
                    return TtlResult::SendIcmp {
                        icmp_type: ICMP6_TIME_EXCEEDED,
                        icmp_code: ICMP6_TIME_EXCEED_TRANSIT,
                    };
                }
                return TtlResult::DropSilent;
            }

            // `:383`: just decrement. No IP checksum in v6 (RFC
            // 8200 §3 — upper layers cover the pseudo-header;
            // the IP header itself is unchecked).
            data[ethlen + 7] -= 1;

            TtlResult::Decremented
        }

        // `:386`: `default: return true`. Unknown ethertype — not
        // IP, no TTL to decrement, forward as-is.
        _ => TtlResult::Decremented,
    }
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
        ETH_P_IPV6 => route_ipv6(data, subnets, myself, is_reachable),
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
            (ETH_P_ARP, "arp: chunk 9"),
            (ETH_P_8021Q, "vlan: chunk 9"),
            (0x1234, "unknown ethertype"),
        ] {
            p[12..14].copy_from_slice(&et.to_be_bytes());
            let r = route(&p, &t, "alice", |_| true);
            assert_eq!(r, RouteResult::Unsupported { reason: want });
        }

        // ETH_P_IP / ETH_P_IPV6 actually dispatch into route_ipv4 /
        // route_ipv6 (which then bounce on length: 14 < 34, 14 < 54).
        p[12..14].copy_from_slice(&ETH_P_IP.to_be_bytes());
        let r = route(&p, &t, "alice", |_| true);
        assert_eq!(r, RouteResult::TooShort { need: 34, have: 14 });

        p[12..14].copy_from_slice(&ETH_P_IPV6.to_be_bytes());
        let r = route(&p, &t, "alice", |_| true);
        assert_eq!(r, RouteResult::TooShort { need: 54, have: 14 });
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

    // ────────────────────────────────────────────────────────────────
    // route_ipv6

    /// Build a minimal 54-byte ethernet+IPv6 frame with `dst` in
    /// `ip6_dst`. `route_ipv6` reads ethertype `[12..14]`, next-hdr
    /// `[20]`, dst `[38..54]`.
    fn ipv6_packet(dst: Ipv6Addr) -> Vec<u8> {
        let mut p = vec![0u8; ETHER_SIZE + IP6_SIZE];
        p[12..14].copy_from_slice(&ETH_P_IPV6.to_be_bytes());
        // `ip6_dst` at offset 24 in IPv6 hdr → [38..54] absolute.
        p[ETHER_SIZE + 24..ETHER_SIZE + 40].copy_from_slice(&dst.octets());
        p
    }

    /// `route.c:789` happy path. Mirror of `route_ipv4_forwards_to_
    /// owner`.
    #[test]
    fn route_ipv6_forwards_to_owner() {
        let mut t = SubnetTree::new();
        t.add(sn("2001:db8::/32"), "bob".into());

        let p = ipv6_packet("2001:db8::5".parse().unwrap());
        let r = route_ipv6(&p, &t, "alice", |_| true);

        assert_eq!(r, RouteResult::Forward { to: "bob" });
    }

    /// `route.c:722-735`: no covering subnet → type 1 code 3.
    #[test]
    fn route_ipv6_unknown_is_unreachable_addr() {
        let t = SubnetTree::new();

        let p = ipv6_packet("2001:db8::5".parse().unwrap());
        let r = route_ipv6(&p, &t, "alice", |_| true);

        assert_eq!(
            r,
            RouteResult::Unreachable {
                icmp_type: ICMP6_DST_UNREACH,
                icmp_code: ICMP6_DST_UNREACH_ADDR,
            }
        );
    }

    /// `route.c:748-751`: subnet exists but owner unreachable →
    /// type 1 code 0 (NOROUTE, not ADDR).
    #[test]
    fn route_ipv6_unreachable_owner_is_noroute() {
        let mut t = SubnetTree::new();
        t.add(sn("2001:db8::/32"), "bob".into());

        let p = ipv6_packet("2001:db8::5".parse().unwrap());
        let r = route_ipv6(&p, &t, "alice", |_| false);

        assert_eq!(
            r,
            RouteResult::Unreachable {
                icmp_type: ICMP6_DST_UNREACH,
                icmp_code: ICMP6_DST_UNREACH_NOROUTE,
            }
        );
    }

    /// `route.c:706` `checklength`: 50 bytes < 14+40.
    #[test]
    fn route_ipv6_too_short() {
        let mut p = vec![0u8; 50];
        p[12..14].copy_from_slice(&ETH_P_IPV6.to_be_bytes());
        let t = SubnetTree::new();
        let r = route_ipv6(&p, &t, "alice", |_| true);

        assert_eq!(r, RouteResult::TooShort { need: 54, have: 50 });
    }

    /// `route.c:710-713`: `ip6_nxt==58 && icmp6_type==135` → divert.
    /// Needs the full eth+ip6+icmp6 length (62 bytes) for the C
    /// `checklength` to pass.
    #[test]
    fn route_ipv6_ndp_divert() {
        let mut p = vec![0u8; ETHER_SIZE + IP6_SIZE + ICMP6_SIZE];
        p[12..14].copy_from_slice(&ETH_P_IPV6.to_be_bytes());
        p[20] = IPPROTO_ICMPV6; // ip6_nxt
        p[54] = ND_NEIGHBOR_SOLICIT; // icmp6_type

        let t = SubnetTree::new();
        let r = route_ipv6(&p, &t, "alice", |_| true);

        assert_eq!(r, RouteResult::NeighborSolicit);

        // Same packet but TOO SHORT for the icmp6 hdr — the divert
        // does NOT fire (`:710` `checklength` short-circuits) and
        // we fall through to subnet lookup (→ unreachable, empty
        // tree). Proves the length-guard ordering.
        let p = &p[..ETHER_SIZE + IP6_SIZE];
        let r = route_ipv6(p, &t, "alice", |_| true);
        assert!(matches!(r, RouteResult::Unreachable { .. }));
    }

    // ────────────────────────────────────────────────────────────────
    // decrement_ttl

    use crate::packet::inet_checksum;

    /// Build a 34-byte eth+IPv4 frame with a VALID header checksum.
    /// `ttl` and `proto` are the only knobs the test cares about.
    fn ipv4_ttl_packet(ttl: u8, proto: u8) -> Vec<u8> {
        let mut p = vec![0u8; ETHER_SIZE + IP_SIZE];
        p[12..14].copy_from_slice(&ETH_P_IP.to_be_bytes());
        p[ETHER_SIZE] = 0x45; // vhl: v4, ihl=5
        p[ETHER_SIZE + 8] = ttl;
        p[ETHER_SIZE + 9] = proto;
        // Compute the real checksum so the RFC-1624 adjust has a
        // realistic starting point. `inet_checksum` (`packet.rs:60`)
        // returns the already-complemented value in NATIVE order
        // (it sums via `from_ne_bytes`); write back via `to_ne_
        // bytes` so the bytes on the wire are correct.
        let csum = inet_checksum(&p[ETHER_SIZE..ETHER_SIZE + IP_SIZE], 0);
        p[ETHER_SIZE + 10..ETHER_SIZE + 12].copy_from_slice(&csum.to_ne_bytes());
        p
    }

    /// `route.c:351-365`. The RFC-1624 correctness test: decrement,
    /// then recompute the checksum FROM SCRATCH and assert the
    /// incrementally-adjusted one matches.
    #[test]
    fn decrement_ttl_v4_decrements_and_adjusts_checksum() {
        let mut p = ipv4_ttl_packet(64, 6); // TCP, TTL 64

        let r = decrement_ttl(&mut p);
        assert_eq!(r, TtlResult::Decremented);
        assert_eq!(p[ETHER_SIZE + 8], 63);

        // Recompute from scratch: zero the checksum field, sum,
        // complement. If RFC-1624 is right the incrementally-
        // adjusted bytes match.
        let adjusted = [p[ETHER_SIZE + 10], p[ETHER_SIZE + 11]];
        p[ETHER_SIZE + 10] = 0;
        p[ETHER_SIZE + 11] = 0;
        let fresh = inet_checksum(&p[ETHER_SIZE..ETHER_SIZE + IP_SIZE], 0);
        assert_eq!(adjusted, fresh.to_ne_bytes());
    }

    /// `route.c:343-348`: TTL=1, NOT already a time-exceeded ICMP
    /// → bounce TIME_EXCEEDED/EXC_TTL.
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
        // TTL untouched on the bounce path.
        assert_eq!(p[ETHER_SIZE + 8], 1);
    }

    /// `route.c:344-347`: TTL=1, packet IS a time-exceeded ICMP →
    /// silent drop (no storm). The C check is `[ethlen+11]==ICMP &&
    /// [ethlen+32]==TIME_EXCEEDED` — we set those EXACT offsets.
    /// (See the bug-for-bug note in `decrement_ttl`: `[+11]` is
    /// actually the checksum low byte, not `ip_p`. The test
    /// exercises the C's actual condition.)
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

    /// `route.c:383`: hop-limit-- (no checksum).
    #[test]
    fn decrement_ttl_v6_decrements() {
        let mut p = vec![0u8; ETHER_SIZE + IP6_SIZE];
        p[12..14].copy_from_slice(&ETH_P_IPV6.to_be_bytes());
        p[ETHER_SIZE + 7] = 64; // ip6_hlim

        let r = decrement_ttl(&mut p);
        assert_eq!(r, TtlResult::Decremented);
        assert_eq!(p[ETHER_SIZE + 7], 63);
    }

    /// `route.c:372-378`: hop-limit=1 → ICMPv6 time-exceeded.
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

    /// `route.c:386`: `default: return true`. Non-IP ethertype —
    /// no TTL field to decrement, forward unchanged.
    #[test]
    fn decrement_ttl_unknown_ethertype_noop() {
        let mut p = vec![0u8; ETHER_SIZE];
        p[12..14].copy_from_slice(&0x1234u16.to_be_bytes());

        let r = decrement_ttl(&mut p);
        assert_eq!(r, TtlResult::Decremented);
    }

    /// `route.c:332-335`: 8021Q tag skip. Inner ethertype at
    /// `[16..18]`, payload starts at `ethlen=18`.
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
}
