//! MAC-layer routing for `RMODE_SWITCH` (`route.c:1025-1100`).
//!
//! TAP-mode routing. The IP-layer router (`route.rs`) sees the
//! destination IP and looks up the longest-prefix subnet. This sees
//! the destination MAC and does an exact-match lookup in a flat
//! table. Unknown MAC → broadcast (the switch-learning pattern:
//! flood until you learn where everyone is).
//!
//! ## MAC learning (`route.c:524-556`)
//!
//! When a frame enters via OUR device (`source == myself`, `:1031`),
//! the source-MAC tells us which VM/container/host behind our TAP
//! sent it. The C records that as a transient subnet (`SUBNET_MAC`,
//! expires `now + macexpire`, default 600s), broadcasts `ADD_SUBNET`
//! so peers route REPLIES to that MAC back to us, and arms a 10s
//! `age_subnets` timer.
//!
//! The C does this synchronously inside `route_mac`. We split:
//! [`route_mac`] returns the routing decision PLUS a [`LearnAction`]
//! annotation. The daemon owns the subnet table and the gossip
//! channel; we're a pure leaf.
//!
//! ## MAC lookup (`subnet.c:lookup_subnet_mac`)
//!
//! C uses a hash table keyed by the 6-byte MAC — exact match only,
//! no prefix length (unlike `SUBNET_IPV4`/`SUBNET_IPV6` which need
//! the trie). We take a `&HashMap<Mac, String>` directly. The daemon
//! builds it from the `tinc_proto::Subnet::Mac` entries it already
//! gossips on the meta-connection.
//!
//! ## What's NOT here
//!
//! - `age_subnets` (`route.c:491-521`): the 10s timer that prunes
//!   expired MAC entries and broadcasts `DEL_SUBNET` for each.
//!   Daemon-owned (`on_age_subnets` in `daemon/periodic.rs`).
//! - `route_broadcast` (`route.c:559-565`): we return
//!   [`RouteResult::Broadcast`]; the daemon dispatches to
//!   `broadcast_packet` (`net_packet.c:1438`).
//! - `do_decrement_ttl` (`route.c:1056-1059`): config-gated (default
//!   off), mutates the frame. The C calls it on the eth payload's
//!   IP-layer TTL — `do_decrement_ttl` is eth-aware (it skips the
//!   first 14 bytes, `route.c:327`). DEFERRED(chunk-9).
//! - `priorityinheritance` (`route.c:1063-1069`): config-gated
//!   (default off). Reads the IP TOS byte out of the eth payload.
//!   DEFERRED(chunk-9).
//! - PMTU clamp (`route.c:1073-1100`): needs `via->mtu` from PMTU
//!   discovery. DEFERRED(chunk-9).

#![forbid(unsafe_code)]

use std::collections::HashMap;

use crate::route::RouteResult;

/// `sizeof(struct ether_header)`. `ethernet.h:36`. The minimum
/// frame for MAC routing — we need `dst[0..6]`, `src[6..12]`,
/// `ethertype[12..14]`.
///
/// `route.c:1028`: the C does NOT actually check this. The
/// `memcpy(&src, &DATA[6], 6)` at `:1033` happily reads off the
/// end of a short packet. The top-level `route()` at `:1132` does
/// `checklength(ether_size)` before dispatching to `route_mac`, so
/// in practice the C never UB's — but `route_mac` itself is
/// unguarded. We check.
pub const ETH_HDR_LEN: usize = 14;

/// 6-byte MAC. C `mac_t` (`net.h:92`): `struct { uint8_t x[6]; }`.
pub type Mac = [u8; 6];

/// `learn_mac` extraction (`route.c:524-556`). Returned alongside
/// the route result; the daemon does the actual subnet-add and
/// `ADD_SUBNET` broadcast.
///
/// The C `learn_mac` either:
/// - finds no subnet for `src` (`:528 if(!subnet)`): allocates one,
///   `subnet_add(myself, ...)`, broadcasts `ADD_SUBNET`, arms the
///   `age_subnets` timer → [`LearnAction::New`].
/// - finds one (`:551-555 else`): `if(subnet->expires) subnet->
///   expires = now + macexpire`. Just refresh the lease →
///   [`LearnAction::Refresh`]. (The `if(expires)` guard skips
///   subnets without an expiry — i.e. statically-configured ones
///   from `tinc.conf`. Those never refresh; they're permanent.)
///
/// We don't decide New-vs-Refresh here — that needs the daemon's
/// authoritative subnet table (the `mac_table` passed to
/// [`route_mac`] is a routing snapshot of ALL nodes' MACs, not just
/// `myself`'s learned set). The daemon checks its own table on
/// receipt of either variant. We surface both so the daemon can
/// short-circuit the table walk when the source MAC is already in
/// the routing snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LearnAction {
    /// `:1031` `source != myself`. Nothing to learn — the sender
    /// is a peer, not our local TAP.
    NotOurs,

    /// `:1031-1035` + `:528` `if(!subnet)`. From our TAP, and the
    /// source MAC is NOT in the routing snapshot. Daemon: allocate
    /// `Subnet::Mac`, add to `myself`, broadcast `ADD_SUBNET`, arm
    /// the `age_subnets` timer.
    New(Mac),

    /// `:1031-1035` + `:551-555 else`. From our TAP, and the source
    /// MAC IS in the routing snapshot. The C refreshes `subnet->
    /// expires`. Daemon: bump the lease in its learned-MAC table
    /// (no gossip — peers already know).
    ///
    /// Note: this fires even when the snapshot says the MAC belongs
    /// to a REMOTE node. That's a topology change (a VM migrated to
    /// us). The C handles this by `lookup_subnet_mac(myself, &src)`
    /// at `:525` — it scopes the lookup to `myself`, so a remotely-
    /// owned MAC reads as "not found" → `New`. We surface `Refresh`
    /// here and let the daemon do the scoped check (it has the
    /// owner already; the snapshot value is the owner string).
    Refresh(Mac),
}

/// `route_mac` (`route.c:1025-1100`). The RMODE_SWITCH routing
/// decision.
///
/// Same shape as [`route_ipv4`](crate::route::route_ipv4): pure
/// function of `(frame bytes, lookup table, source identity)` →
/// [`RouteResult`]. Differences:
///
/// - `frame` includes the 14-byte ethernet header. TAP preserves
///   it; TUN strips it. (In RMODE_ROUTER the C glues a fake eth
///   header on; in RMODE_SWITCH it's the real one off the wire.)
/// - dest is `frame[0..6]`, src is `frame[6..12]`. No IP parsing.
/// - `mac_table` is exact-match (`HashMap`, not the subnet trie).
///   `subnet.c:lookup_subnet_mac` is a hash lookup; MAC subnets
///   have no prefix length.
/// - Unknown dest → [`RouteResult::Broadcast`], not `Unreachable`
///   (`:1042-1045`). A switch floods unknown unicast; a router
///   returns ICMP no-route. This is the WHOLE POINT of switch
///   mode: you don't pre-configure subnets, you learn them.
///
/// `from_myself`: `source == myself` (`:1031`). The CALLER knows
/// this (it's daemon state — which connection did this frame
/// arrive on?). Determines whether we learn the source MAC.
///
/// `source`: the source node's name, for the loop check at `:1047`.
/// `route_ipv4` defers this to the daemon (`DEFERRED(chunk-7-
/// daemon)`), but `route_mac` has the lookup table RIGHT HERE and
/// the check is one string compare. We do it.
///
/// `myself`: our own node name. C compares `subnet->owner ==
/// myself` by pointer at `:1052`; we compare by string. Gates the
/// `FMODE_OFF` and `decrement_ttl` deferrals (both fire only when
/// `source != myself && owner != myself`, i.e. pure transit).
///
/// # Returns
///
/// `(route_result, learn_action)`. Daemon dispatches both.
///
/// `resolve`: maps the looked-up owner name to the caller's `T`.
/// `None` = treat as not-found (→ `Broadcast`). Daemon passes a
/// `&str -> Option<NodeId>` that hits `node_ids`; `mac_table` is
/// gossip-populated so the owner is always in `node_ids`, but the
/// fallback to `Broadcast` is the safe default for stale entries.
///
/// # Panics
///
/// Never. The `try_into` calls are length-checked above; clippy
/// wants the doc note anyway.
#[must_use]
pub fn route_mac<T, S: std::hash::BuildHasher>(
    frame: &[u8],
    from_myself: bool,
    source: &str,
    myself: &str,
    mac_table: &HashMap<Mac, String, S>,
    resolve: impl FnOnce(&str) -> Option<T>,
) -> (RouteResult<T>, LearnAction) {
    // `route.c:1132` `checklength(ether_size)` — the C does this
    // at the dispatch level, not inside `route_mac`. We check
    // anyway; `route_mac` is `pub` and the daemon may call it
    // directly in chunk-12 wire-up.
    if frame.len() < ETH_HDR_LEN {
        return (
            RouteResult::TooShort {
                need: ETH_HDR_LEN,
                have: frame.len(),
            },
            LearnAction::NotOurs,
        );
    }

    // `:1033`: `memcpy(&src, &DATA[6], 6)`. Only read when
    // `source == myself` in the C; we read unconditionally
    // (it's two array indexes, and we need it for the learn
    // annotation either way).
    #[allow(clippy::missing_panics_doc)]
    let src: Mac = frame[6..12].try_into().expect("len-checked above");
    // `:1039`: `memcpy(&dest, &DATA[0], 6)`.
    #[allow(clippy::missing_panics_doc)]
    let dst: Mac = frame[0..6].try_into().expect("len-checked above");

    // `:1031-1035`: `if(source == myself) { learn_mac(&src); }`.
    // The actual learn (subnet_add, ADD_SUBNET broadcast, timer)
    // is the daemon's job. We annotate New-vs-Refresh based on
    // the routing snapshot — see `LearnAction` doc for the
    // `myself`-scoping caveat.
    let learn = if from_myself {
        if mac_table.contains_key(&src) {
            LearnAction::Refresh(src)
        } else {
            LearnAction::New(src)
        }
    } else {
        LearnAction::NotOurs
    };

    // `:1040-1041`: `subnet = lookup_subnet_mac(NULL, &dest)`.
    // The `NULL` first arg means "any owner" — the C
    // `lookup_subnet_mac` filters by owner when non-NULL.
    let Some(owner) = mac_table.get(&dst) else {
        // `:1042-1045`: `if(!subnet || !subnet->owner) {
        // route_broadcast(source, packet); return; }`.
        //
        // `route_broadcast` (`route.c:559-565`) does the
        // `decrement_ttl` gate then `broadcast_packet`. We
        // return the variant; daemon does both.
        //
        // This is the ff:ff:ff:ff:ff:ff path too — the broadcast
        // MAC is never in anyone's subnet table, so it falls
        // through here. Same for multicast (33:33:..., 01:00:5e:
        // ...). The C makes no special case; neither do we.
        return (RouteResult::Broadcast, learn);
    };
    // `:1047-1050`: `if(subnet->owner == source) { logger(...
    // "Packet looping back to %s"); return; }`. Loop detection:
    // a peer sent us a frame whose dest-MAC routes BACK to that
    // peer. The C logs at WARNING and silently drops (no ICMP —
    // there's no ICMP at the MAC layer). We surface as
    // `Unsupported` so the daemon logs; the reason string is the
    // log line.
    //
    // `route_ipv4` defers this check to the daemon. We don't:
    // the lookup is one HashMap probe and we have everything we
    // need. Different layering trade-off, same effect.
    if owner.as_str() == source {
        return (
            RouteResult::Unsupported {
                reason: "MAC routing loop (owner == source)",
            },
            learn,
        );
    }

    // DEFERRED(chunk-9): `:1052-1054` `forwarding_mode == FMODE_OFF
    // && source != myself && subnet->owner != myself` → silent
    // drop (no ICMP at MAC layer; the C just `return`s).
    // Config-gated; default is FMODE_INTERNAL.
    //
    // The `_ = myself` here documents the deferral: when chunk-9
    // wires FMODE_OFF, this is where the `owner != myself` check
    // goes. Clippy would otherwise flag the param dead.
    let _ = myself;

    // DEFERRED(chunk-9): `:1056-1059` `decrement_ttl && source !=
    // myself && subnet->owner != myself` → `do_decrement_ttl()`.
    // Mutates the frame. The C `do_decrement_ttl` is eth-aware
    // (`route.c:327`: it reads `DATA[14]` as the IP version nibble,
    // i.e. it KNOWS about the eth header). So in switch mode it
    // does the right thing: peeks past the eth, decrements the
    // payload's IP-layer TTL. Config-gated; default off.

    // DEFERRED(chunk-9): `:1063-1069` `priorityinheritance` —
    // reads `DATA[15]` (IPv4 TOS) or `DATA[14..16]` (IPv6 traffic
    // class) into `packet->priority`. Config-gated; default off.

    // DEFERRED(chunk-9): `:1073` `via = (owner->via == myself) ?
    // owner->nexthop : owner->via`. The relay path. Needs
    // `nodes` access (graph state). Then `:1075-1077` `directonly
    // && owner != via` → silent drop.

    // DEFERRED(chunk-9): `:1079-1100` PMTU clamp. `packet->len >
    // via->mtu` → either FRAG_NEEDED (DF set, IPv4) or
    // PACKET_TOO_BIG (IPv6) or fragment (IPv4, DF clear). The
    // C peeks into the eth payload to dispatch by ethertype
    // (including the VLAN-unwrap at `:1083-1086`). Needs
    // per-node MTU from chunk-8's PMTU discovery.

    // DEFERRED(chunk-9): `:1102` `clamp_mss(source, via, packet)`.
    // TCP MSS rewrite for the via-node's MTU.

    // `:1104`: `send_packet(subnet->owner, packet)`. Same collapse
    // as `route_ipv4` — `owner == myself` is `Forward{to:myself}`
    // and the daemon dispatches to TAP write. `resolve` maps the
    // owner name to the caller's `T` (NodeId in the daemon). If
    // `None` (owner not in `node_ids` — stale gossip entry), fall
    // through to Broadcast: a switch floods unknown destinations.
    match resolve(owner) {
        Some(to) => (RouteResult::Forward { to }, learn),
        None => (RouteResult::Broadcast, learn),
    }
}

// ────────────────────────────────────────────────────────────────────
// Tests

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-rolled 14-byte ethernet header. `dst[0..6]`,
    /// `src[6..12]`, `ethertype[12..14]`. We don't care about the
    /// ethertype for MAC routing (the C reads it at `:1061` only
    /// for `priorityinheritance`, deferred), so it's fixed at
    /// 0x0800 (IPv4) for plausibility.
    fn frame(dst: Mac, src: Mac) -> Vec<u8> {
        let mut f = Vec::with_capacity(ETH_HDR_LEN);
        f.extend_from_slice(&dst);
        f.extend_from_slice(&src);
        f.extend_from_slice(&[0x08, 0x00]);
        f
    }

    /// Test resolver: `T = String`, identity map. The daemon's
    /// `node_ids` lookup never fails for `mac_table` entries (gossip
    /// only adds known nodes); model that as always-`Some`.
    #[allow(clippy::unnecessary_wraps)] // signature must match `resolve`
    fn id(n: &str) -> Option<String> {
        Some(n.to_owned())
    }

    /// Three-node table: alice owns `aa:...`, bob owns `bb:...`,
    /// charlie owns `cc:...`. Mirrors the IP-layer test fixtures.
    fn table() -> HashMap<Mac, String> {
        let mut t = HashMap::new();
        t.insert([0xaa; 6], "alice".into());
        t.insert([0xbb; 6], "bob".into());
        t.insert([0xcc; 6], "charlie".into());
        t
    }

    /// `route.c:1104` happy path. Dest MAC is in the table,
    /// owner != source → `Forward{to: owner}`.
    #[test]
    fn route_mac_forwards_known_dest() {
        let t = table();
        let f = frame([0xbb; 6], [0xaa; 6]);

        let (r, learn) = route_mac(&f, false, "alice", "myself", &t, id);

        assert_eq!(r, RouteResult::Forward { to: "bob".into() });
        assert_eq!(learn, LearnAction::NotOurs);
    }

    /// `route.c:1042-1045`: dest MAC unknown → `Broadcast`.
    /// The whole point of switch mode: flood until you learn.
    #[test]
    fn route_mac_broadcasts_unknown_dest() {
        let t = table();
        let f = frame([0xdd; 6], [0xaa; 6]);

        let (r, learn) = route_mac(&f, false, "alice", "myself", &t, id);

        assert_eq!(r, RouteResult::Broadcast);
        assert_eq!(learn, LearnAction::NotOurs);
    }

    /// `route.c:1031-1035`: `source == myself` and the source
    /// MAC is new. Learn-action says `New`; routing decision
    /// is independent (here: dest unknown → `Broadcast`).
    #[test]
    fn route_mac_learns_new_src_when_from_myself() {
        let t = table();
        // src `ee:...` is NOT in the table.
        let f = frame([0xdd; 6], [0xee; 6]);

        let (r, learn) = route_mac(&f, true, "myself", "myself", &t, id);

        assert_eq!(r, RouteResult::Broadcast);
        assert_eq!(learn, LearnAction::New([0xee; 6]));
    }

    /// `route.c:551-555`: `source == myself` and the source MAC
    /// is already in the table → `Refresh`. The C bumps
    /// `subnet->expires`; daemon does the same.
    #[test]
    fn route_mac_refreshes_known_src_when_from_myself() {
        let t = table();
        // src `aa:...` IS in the table (owned by alice).
        let f = frame([0xbb; 6], [0xaa; 6]);

        let (r, learn) = route_mac(&f, true, "myself", "myself", &t, id);

        assert_eq!(r, RouteResult::Forward { to: "bob".into() });
        assert_eq!(learn, LearnAction::Refresh([0xaa; 6]));
    }

    /// `route.c:1031` `source != myself` → no learning regardless
    /// of whether the source MAC is known. A peer sent this; THEY
    /// learn their own TAP's MACs, not us.
    #[test]
    fn route_mac_does_not_learn_when_not_from_myself() {
        let t = table();
        // src `ee:...` is unknown — would be `New` if from_myself.
        let f = frame([0xbb; 6], [0xee; 6]);

        let (r, learn) = route_mac(&f, false, "charlie", "myself", &t, id);

        assert_eq!(r, RouteResult::Forward { to: "bob".into() });
        assert_eq!(learn, LearnAction::NotOurs);
    }

    /// `route.c:1132` `checklength(ether_size)`. 13-byte frame
    /// is one short of the eth header. The C checks this at the
    /// `route()` dispatch level; we check inside `route_mac`.
    #[test]
    fn route_mac_too_short() {
        let t = table();
        let f = vec![0u8; 13];

        let (r, learn) = route_mac(&f, true, "myself", "myself", &t, id);

        assert_eq!(
            r,
            RouteResult::TooShort {
                need: ETH_HDR_LEN,
                have: 13,
            }
        );
        // No learning on a short frame — we never read src.
        assert_eq!(learn, LearnAction::NotOurs);
    }

    /// Exactly 14 bytes — the minimum. Dst+src parse, no payload.
    /// The C would route this fine (it never reads past `[13]`
    /// on the happy path).
    #[test]
    fn route_mac_exactly_eth_hdr() {
        let t = table();
        let f = frame([0xbb; 6], [0xaa; 6]);
        assert_eq!(f.len(), ETH_HDR_LEN);

        let (r, _) = route_mac(&f, false, "alice", "myself", &t, id);

        assert_eq!(r, RouteResult::Forward { to: "bob".into() });
    }

    /// `route.c:1047-1050`: `subnet->owner == source` → loop.
    /// A peer sent us a frame whose dest-MAC routes back to that
    /// peer. C logs WARNING + silent drop. We surface `Unsupported`
    /// so the daemon logs.
    #[test]
    fn route_mac_loop_detection() {
        let t = table();
        // Dest `bb:...` is owned by bob; bob sent this frame.
        let f = frame([0xbb; 6], [0xee; 6]);

        let (r, learn) = route_mac(&f, false, "bob", "myself", &t, id);

        assert_eq!(
            r,
            RouteResult::Unsupported {
                reason: "MAC routing loop (owner == source)",
            }
        );
        assert_eq!(learn, LearnAction::NotOurs);
    }

    /// The all-ones broadcast MAC. Never in anyone's subnet table
    /// (the C `lookup_subnet_mac` would miss). → `Broadcast`. No
    /// special case in the C; falls out of the unknown-dest path.
    #[test]
    fn route_mac_broadcast_mac() {
        let t = table();
        let f = frame([0xff; 6], [0xaa; 6]);

        let (r, _) = route_mac(&f, false, "alice", "myself", &t, id);

        assert_eq!(r, RouteResult::Broadcast);
    }

    /// IPv6 multicast MAC (33:33:xx:xx:xx:xx, RFC 2464 §7). Same
    /// as broadcast — not in the table, → `Broadcast`. The C makes
    /// no special case for multicast; neither do we.
    #[test]
    fn route_mac_multicast_mac_v6() {
        let t = table();
        let f = frame([0x33, 0x33, 0x00, 0x00, 0x00, 0x01], [0xaa; 6]);

        let (r, _) = route_mac(&f, false, "alice", "myself", &t, id);

        assert_eq!(r, RouteResult::Broadcast);
    }

    /// IPv4 multicast MAC (01:00:5e:xx:xx:xx, RFC 1112 §6.4).
    /// Same shape as v6 multicast.
    #[test]
    fn route_mac_multicast_mac_v4() {
        let t = table();
        let f = frame([0x01, 0x00, 0x5e, 0x00, 0x00, 0x01], [0xaa; 6]);

        let (r, _) = route_mac(&f, false, "alice", "myself", &t, id);

        assert_eq!(r, RouteResult::Broadcast);
    }

    /// Dest is OUR MAC. `Forward{to: myself}` — same collapse as
    /// `route_ipv4`: the daemon special-cases `to == myself` into
    /// a TAP write.
    #[test]
    fn route_mac_forwards_to_self() {
        let mut t = HashMap::new();
        t.insert([0xaa; 6], "myself".into());
        t.insert([0xbb; 6], "bob".into());

        let f = frame([0xaa; 6], [0xbb; 6]);

        let (r, _) = route_mac(&f, false, "bob", "myself", &t, id);

        assert_eq!(
            r,
            RouteResult::Forward {
                to: "myself".into()
            }
        );
    }

    /// Learn + route are independent: from_myself with a NEW
    /// source AND a KNOWN dest. Learn says `New`, route says
    /// `Forward`. Both channels populated.
    #[test]
    fn route_mac_learns_and_forwards() {
        let t = table();
        // src `ee:...` is new; dst `cc:...` is charlie's.
        let f = frame([0xcc; 6], [0xee; 6]);

        let (r, learn) = route_mac(&f, true, "myself", "myself", &t, id);

        assert_eq!(
            r,
            RouteResult::Forward {
                to: "charlie".into()
            }
        );
        assert_eq!(learn, LearnAction::New([0xee; 6]));
    }

    /// KAT: a real ethernet frame with a payload, and verify the
    /// parsed src/dst match what we encoded. This is the
    /// `memcpy(&src, &DATA[6], 6)` / `memcpy(&dest, &DATA[0], 6)`
    /// offset check — easy to fat-finger when porting from C.
    #[test]
    fn route_mac_kat_real_frame() {
        // A 60-byte frame (the eth minimum without FCS):
        // dst=02:00:00:00:00:01, src=02:00:00:00:00:02,
        // ethertype=0x0800, then 46 bytes of zeros (IP payload).
        // Locally-administered (bit 1 of byte 0 set) so no
        // collision with real OUIs in test logs.
        let dst: Mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let src: Mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
        let mut f = Vec::with_capacity(60);
        f.extend_from_slice(&dst);
        f.extend_from_slice(&src);
        f.extend_from_slice(&[0x08, 0x00]);
        f.resize(60, 0);

        let mut t = HashMap::new();
        t.insert(dst, "destnode".into());
        // src is NOT in the table.

        let (r, learn) = route_mac(&f, true, "myself", "myself", &t, id);

        // Dst lookup hit:
        assert_eq!(
            r,
            RouteResult::Forward {
                to: "destnode".into()
            }
        );
        // Src was unknown → New, with the exact src bytes:
        assert_eq!(learn, LearnAction::New(src));
    }

    /// Empty mac_table. Everything broadcasts. This is the cold-
    /// start state of a switch-mode mesh: nobody's learned anything
    /// yet, everything floods until ADD_SUBNET gossip propagates.
    #[test]
    fn route_mac_empty_table_broadcasts() {
        let t = HashMap::new();
        let f = frame([0xbb; 6], [0xaa; 6]);

        let (r, learn) = route_mac(&f, true, "myself", "myself", &t, id);

        assert_eq!(r, RouteResult::Broadcast);
        // And we learn our own src:
        assert_eq!(learn, LearnAction::New([0xaa; 6]));
    }
}
