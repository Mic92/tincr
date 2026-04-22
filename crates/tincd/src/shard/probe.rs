//! TX fast-path eligibility probe.
//!
//! `tx_probe(&TxSnapshot, chunk0, count)` walks the same gate chain
//! `route_packet` → `send_sptps_packet` → `send_sptps_data_relay`
//! would walk, returning `Some(TxTarget)` only if the WHOLE super
//! can take the direct-UDP path with no per-chunk side effects. No
//! `&mut Daemon` reborrow: the `Arc<AtomicU64>` outseqno IS the seqno
//! allocator now.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use super::{TunnelHandles, TxSnapshot};
use crate::graph::NodeId;
use crate::route::{RouteResult, route};

/// Per-super seal-send target. Everything is a COPY — no borrows into
/// snapshot state. ~120 bytes, copied once per super (~33 chunks).
pub(crate) struct TxTarget {
    /// The `Arc` from `snap.tunnels.get()`. Seal loop reads `outkey`.
    /// Holding the `Arc` directly instead of unpacking key/sock: the
    /// seal loop derefs `handles.outkey` once into `ChaPoly::new`;
    /// no point copying 64 bytes when the `Arc` clone is one refcount
    /// bump.
    pub handles: Arc<TunnelHandles>,
    /// `handles.udp_addr.lock().clone()`. Cloned once per super so
    /// the seal loop's `sendto` isn't holding the mutex.
    pub dst: socket2::SockAddr,
    /// `handles.outseqno.fetch_add(count, Relaxed) as u32`. Producer
    /// indexes `seqno_base.wrapping_add(i)`.
    pub seqno_base: u32,
    /// `[NULL_dst‖myself_src]`. Setup-time const; same for every
    /// direct-send packet from this node.
    pub prefix: [u8; 12],
    /// For the EMSGSIZE → `on_emsgsize` path. Direct: `to == relay`.
    pub to_nid: NodeId,
    /// Daemon's listener index from `udp_addr.1`. Egress is per-
    /// listener; `seal_super` is handed `listeners[sock].egress`.
    pub sock: u8,
}

/// Probe whether THIS super can take the fast path. Runs `route()` on
/// `chunk0`, walks the gate chain WITHOUT side effects (except seqno
/// alloc), returns the copies the seal loop needs. `None` ⇒ slow path.
///
/// Gates (any ⇒ `None`):
///   - `slowpath_all` (setup-time fold of `dns | !Router |
///     priorityinheritance`; `any_pcap` checked live at call site)
///   - ARP ethertype (`handle_arp` writes device, reads subnets diff)
///   - `route()` returns `Forward` (not Unreachable/Broadcast/etc)
///   - `to != myself` (loopback writes TUN directly)
///   - `route.via == to && route.nexthop == to` (DIRECT: no relay-MTU
///     frag, no PACKET 17 short-circuit, no `via_mtu` floor)
///   - `!TCPONLY` (we're sending UDP)
///   - `tunnels.get(to)` exists, `validkey`, `outcompression == 0`
///   - `minmtu > 0 && body_len <= minmtu` (PMTU converged; pre-PMTU
///     ~3.3s on the slow path is fine)
///   - `udp_addr` set (cold `choose_udp_address` builds stack-local)
///
/// Non-gates (dead on TX, `from=None` semantics):
///   - `forwarding_mode == Kernel` (gated `&& from.is_some()`)
///   - `decrement_ttl`, `forwarding_mode == Off` (same)
///   - `via_mtu` floor (gated `via != myself`, but `via == to` here)
///   - `CLAMP_MSS`: walks TCP options, only present in SYN/SYN-ACK.
///     SYN arrives as `Frames{1}` with `gso_type=0` — the `Frames`
///     arm, not `Super`. The Super arm structurally cannot see a SYN.
///     Gating on it would reject every default-config peer (the bit
///     is default-on). Slow path's Frames arm still clamps.
///
/// `count`: seqnos to reserve. The `fetch_add` is the ONE side effect:
/// burns seqnos even when the result is discarded. Gaps are valid
/// (SPTPS replay window is a sliding bitmap, REJECTS reused seqnos,
/// doesn't accept-twice).
#[must_use]
pub(crate) fn tx_probe(snap: &TxSnapshot, chunk0: &[u8], count: u32) -> Option<TxTarget> {
    // Setup-time fold of every "this packet must go through control"
    // gate. Cheapest possible early-out: one bool.
    if snap.slowpath_all {
        return None;
    }

    // ARP gate (`route_packet:1009`). `route()` returns `Unsupported`
    // for ARP anyway, but checking it explicitly skips the trie probe.
    // `chunk0.len() < 14` falls through `route()`'s `TooShort`.
    if chunk0.len() >= 14
        && u16::from_be_bytes([chunk0[12], chunk0[13]]) == crate::packet::ETH_P_ARP
    {
        return None;
    }

    // `route()`. Same closure as `route_packet:1031` — but `NodeView::
    // resolve` packages `node_ids.get + graph.node().reachable` so the
    // closure body is one method call instead of two struct probes.
    // The trie lookup is the expensive half; we do it ONCE per super.
    let RouteResult::Forward { to: to_nid } =
        route(chunk0, &snap.subnets, |name| snap.ns.resolve(name))
    else {
        return None; // Unreachable / Broadcast / TooShort / Unsupported
    };
    if to_nid == snap.myself {
        return None; // dispatch_route_result:1377 — loopback to TUN
    }

    // `last_routes` lookup. DIRECT gate: target IS the relay AND IS
    // the nexthop. Covers (a) distance-1 neighbor (`via=nexthop=to`
    // by tinc-graph:632 — `via = if indirect {n_via} else {e.to}`)
    // and (b) what the slow path actually checks: sptps.rs's
    // relay-pick collapses to `to == relay_nid` for from=myself +
    // non-indirect (via!=myself ⇒ relay=via, then direct = to==via).
    // `via == myself` only ever holds for myself itself (graph:547),
    // already excluded above.
    let route = snap.route_of(to_nid)?;
    if route.via != to_nid || route.nexthop != to_nid {
        return None;
    }
    // TCPONLY. Direct ⇒ relay==to ⇒ relay_options == route.options.
    if (snap.myself_options | route.options) & crate::proto::OPTION_TCPONLY != 0 {
        return None;
    }

    // Tunnel state. `get` not `entry`: don't insert just to fail.
    let handles = snap.tunnels.get(&to_nid)?;
    if !handles.validkey.load(Ordering::Relaxed) {
        return None; // send_sptps_packet:1727 → send_req_key
    }
    if handles.outcompression != 0 {
        return None; // send_sptps_packet:1751 mutates body
    }
    // PMTU gate. `minmtu == 0` ⇒ PMTU not converged (~3.3s) ⇒ PACKET 17
    // territory. `tso_split` chunks are uniform (gso_size) except the
    // tail (≤gso_size), so chunk0 fitting ⇒ all fit. `chunk0` arrives
    // WITH the synthetic eth header (tso.rs:479 frame_len=ETH_HLEN+...);
    // the slow path strips at the seal site (sptps.rs:24 offset=14) and
    // measures minmtu against the BODY. Compare body length here too.
    let minmtu = handles.minmtu.load(Ordering::Relaxed);
    let body_len = chunk0.len().saturating_sub(14);
    if minmtu == 0 || body_len > usize::from(minmtu) {
        return None;
    }
    // `udp_addr` set ⇔ `udp_confirmed` flipped. Cold `choose_udp_
    // address` builds a stack-local; can't copy what isn't cached.
    let (dst, sock) = handles.udp_addr.lock().unwrap().clone()?;

    // ─── ALL GATES PASSED. The one side effect: burn `count` seqnos. ──
    // The `Arc<AtomicU64>` is shared with the control-side `Sptps`;
    // both see the same counter. `Relaxed`: uniqueness is the only
    // requirement; the peer's replay window does the ordering.
    // Intentional truncation: SPTPS wire seqno IS 32-bit; the
    // AtomicU64 is just headroom for the wrap math. `wrapping_add` on
    // the producer side, sliding-bitmap on the consumer side; the
    // `as u32` here is exactly what `seal_data_into` does.
    #[expect(clippy::cast_possible_truncation)]
    let seqno_base = handles
        .outseqno
        .fetch_add(u64::from(count), Ordering::Relaxed) as u32;

    Some(TxTarget {
        handles: Arc::clone(handles),
        dst,
        seqno_base,
        prefix: snap.id6_prefix,
        to_nid,
        sock,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::Route;
    use crate::inthash::IntHashMap;
    use crate::shard::NodeView;
    use crate::subnet_tree::SubnetTree;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64};
    use tinc_sptps::ReplayWindow;

    /// 100-byte eth+v4 frame: eth(14) + ip(20) + 66 payload.
    /// Ethertype at [12..14], `ip_dst` at [14+16..14+20] = [30..34].
    fn v4_frame(dst: [u8; 4]) -> Vec<u8> {
        let mut frame = vec![0u8; 100];
        frame[12..14].copy_from_slice(&crate::packet::ETH_P_IP.to_be_bytes());
        frame[30..34].copy_from_slice(&dst);
        frame
    }

    /// Two-node topology: alice (myself) ↔ bob, distance 1, non-indirect
    /// edge. `run_graph_and_log` would produce `via=nexthop=bob` for
    /// this (tinc-graph:632 — `via = if indirect {n_via} else {e.to}`).
    /// bob owns 10.0.0.0/24, has `TunnelHandles` with PMTU converged.
    ///
    /// `options` lets tests vary the route options (TCPONLY etc).
    fn fixture(options: u32) -> (TxSnapshot, NodeId) {
        let alice = NodeId(0);
        let bob = NodeId(1);

        let routes: Arc<Vec<Option<Route>>> = Arc::new(vec![
            None, // alice (myself; route_of returns None)
            Some(Route {
                indirect: false,
                distance: 1,
                weighted_distance: 10,
                nexthop: bob,
                via: bob,
                prevedge: None,
                options,
            }),
        ]);

        let mut st = SubnetTree::new();
        st.add("10.0.0.0/24".parse().unwrap(), "bob".into());

        // NodeView: route()'s resolve closure does name→nid +
        // reachability gate. add_node defaults reachable=true.
        let ns = {
            let mut g = crate::graph::Graph::new();
            let _a = g.add_node("alice");
            let _b = g.add_node("bob");
            let mut ni = std::collections::HashMap::new();
            ni.insert("alice".to_owned(), alice);
            ni.insert("bob".to_owned(), bob);
            Arc::new(NodeView::build(&g, &ni, &IntHashMap::default(), 2))
        };

        // TunnelHandles for bob: validkey=true, minmtu=1400 (PMTU
        // converged), outcompression=0, udp_addr cached. The outseqno
        // Arc here is NOT shared with a real Sptps (no Sptps exists
        // in this test); the gate logic is what we're proving.
        let handles = Arc::new(TunnelHandles {
            outseqno: Arc::new(AtomicU64::new(0)),
            replay: Arc::new(Mutex::new(ReplayWindow::default())),
            outkey: [0u8; 64],
            inkey: [0u8; 64],
            udp_addr: Mutex::new(Some((
                socket2::SockAddr::from("10.0.0.2:655".parse::<std::net::SocketAddr>().unwrap()),
                0,
            ))),
            validkey: AtomicBool::new(true),
            minmtu: AtomicU16::new(1400),
            outcompression: 0,
            stats: Arc::default(),
        });
        let mut tunnels = IntHashMap::default();
        tunnels.insert(bob, handles);

        let snap = TxSnapshot {
            slowpath_all: false,
            myself: alice,
            myself_options: 0,
            id6_prefix: [0u8; 12],
            myself_name: "alice".into(),
            id6: Arc::default(),
            routes,
            subnets: Arc::new(st),
            ns,
            tunnels,
        };
        (snap, bob)
    }

    /// Positive case: the probe MUST return `Some` for a direct peer
    /// with default-on options (`CLAMP_MSS|PMTU_DISCOVERY`). Regression
    /// for two former bugs: `via == myself` (structurally unreachable)
    /// and `CLAMP_MSS` gate (default-on, blocks every real peer).
    #[test]
    fn direct_peer_default_options_is_some() {
        let (snap, bob) = fixture(crate::proto::OPTION_CLAMP_MSS | 0x0004);
        let frame = v4_frame([10, 0, 0, 5]);

        let target = tx_probe(&snap, &frame, 4).expect("direct peer must pass");
        assert_eq!(target.to_nid, bob);
        assert_eq!(target.seqno_base, 0);
        // The one side effect: 4 seqnos burned.
        assert_eq!(snap.tunnels[&bob].outseqno.load(Ordering::Relaxed), 4);
    }

    /// Negative: TCPONLY rejects (we're sending UDP).
    #[test]
    fn tcponly_is_none() {
        let (snap, bob) = fixture(crate::proto::OPTION_TCPONLY);
        let frame = v4_frame([10, 0, 0, 5]);

        assert!(tx_probe(&snap, &frame, 1).is_none());
        // No side effect on the seqno (gate fails before fetch_add).
        assert_eq!(snap.tunnels[&bob].outseqno.load(Ordering::Relaxed), 0);
    }

    /// Negative: indirect route (`via != to`) — relay/frag territory.
    #[test]
    fn indirect_route_is_none() {
        let (mut snap, _bob) = fixture(0);
        // Make bob reachable only via charlie (NodeId(2)).
        let charlie = NodeId(2);
        Arc::make_mut(&mut snap.routes)[1] = Some(Route {
            indirect: true,
            distance: 2,
            weighted_distance: 20,
            nexthop: charlie,
            via: charlie,
            prevedge: None,
            options: 0,
        });
        let frame = v4_frame([10, 0, 0, 5]);
        assert!(tx_probe(&snap, &frame, 1).is_none());
    }

    /// Negative: minmtu=0 (PMTU not converged). Body length
    /// (100-14=86) compared against zero fails.
    #[test]
    fn minmtu_zero_is_none() {
        let (snap, bob) = fixture(0);
        snap.tunnels[&bob].minmtu.store(0, Ordering::Relaxed);
        let frame = v4_frame([10, 0, 0, 5]);
        assert!(tx_probe(&snap, &frame, 1).is_none());
    }

    /// Edge: `body_len` exactly equals minmtu — must pass. The gate is
    /// `>`, not `>=`. minmtu IS the maximum body that fits.
    #[test]
    fn body_len_eq_minmtu_is_some() {
        let (snap, bob) = fixture(0);
        // 100-byte frame → 86-byte body. Set minmtu=86.
        snap.tunnels[&bob].minmtu.store(86, Ordering::Relaxed);
        let frame = v4_frame([10, 0, 0, 5]);
        assert!(tx_probe(&snap, &frame, 1).is_some());
        // 87-byte body should fail.
        snap.tunnels[&bob].minmtu.store(85, Ordering::Relaxed);
        assert!(tx_probe(&snap, &frame, 1).is_none());
    }

    /// Negative: `slowpath_all` = true → immediate bail, no other
    /// reads. Pcap/DNS/non-Router/priorityinheritance.
    #[test]
    fn slowpath_all_is_none() {
        let (mut snap, _bob) = fixture(0);
        snap.slowpath_all = true;
        let frame = v4_frame([10, 0, 0, 5]);
        assert!(tx_probe(&snap, &frame, 1).is_none());
    }
}
