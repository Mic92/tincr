//! `NodeView` — read-only snapshot of `graph`/`node_ids`/`nodes` for the
//! TX fast-path's route resolve closure.
//!
//! The hot path reads control-side state at many sites: `node_ids.get(name)`
//! for the route resolve closure, `graph.node(nid).reachable` for the gate,
//! `graph.node(nid).name` for log lines. None are *mutated* on the hot path
//! — they're written by `on_ack`/`terminate`/`run_graph_and_log` and read
//! per-packet.
//!
//! Same publication strategy as `last_routes`: control rebuilds a fresh
//! `NodeView` after each event that changes the inputs, wraps it in
//! `Arc::new`. Reads are a plain `Arc` deref — pointer chase, no fence.
//! Staleness is one rebuild interval; nodes change on edge events, not
//! packets.
//!
//! Node names + reachability + direct-conn presence + edge-addr all change
//! *together*: `on_ack` writes `nodes.insert` + `graph.add_edge` →
//! `run_graph_and_log` flips `reachable`. One fat snapshot built once at
//! the END of `run_graph_and_log` (after all transitions applied) keeps
//! these fields self-consistent.
//!   See the new `Reply` variants.
//!
//! ## Rebuild cost
//!
//! `build()` is one walk over `graph.node_ids()` + one walk over
//! `daemon.nodes` (the direct-neighbor map, ~5 entries in a small mesh).
//! `node_ids` is a `HashMap<String, NodeId>` clone — O(n) string clones.
//! For a 100-node mesh: ~100 String clones (~2KB total) + 100×4B per dense
//! vec = ~3KB allocated, ~5µs cold. Called once per `run_graph_and_log`,
//! which fires on edge events — seconds to minutes apart in steady state,
//! per-second during a reconnect storm. Either way, off the hot path.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::graph::NodeId;

/// Per-nid dense entry. Indexed by `NodeId.0` (slab index, never deleted in
/// tincd, so dead slots stay `None`). Same layout discipline as `last_routes`.
///
/// 32 bytes: `name` (16 bytes inline `Arc<str>`, see below) + `edge_addr`
/// (28 bytes `Option<SocketAddr>`) + bools packed into a u8. ...except
/// `Option<SocketAddr>` is large (~28B) and 100 nodes × 28B = ~3KB which
/// is fine but the cache footprint matters on the hot path read.
///
/// Hot-path access pattern:
///   - `name`: log strings only (`node_log_name`, 9 sites). Debug-level
///     mostly; cold when traffic flows. `Arc<str>` over `String`: the same
///     name appears in `node_ids` (the resolve map's key) — share the alloc.
///   - `reachable`: `handle_relay_receive` gate (1 site, rare branch).
///   - `has_direct_conn`: `try_tx` `TCPOnly` gate + `send_sptps_packet`
///     PACKET-17 short-circuit (2 sites, every packet that goes via TCP
///     fallback — rare in steady state, common during PMTU discovery).
///   - `edge_addr`: `choose_udp_address` cold path only (cached path
///     bypasses it). One read per peer per session typically.
///
/// So the hot read is `has_direct_conn`. Put it first.
#[derive(Debug, Clone)]
pub(crate) struct NodeViewEntry {
    /// `nodes.get(nid).conn.is_some()`. The `TCPOnly` / PACKET-17 gate.
    /// Shard can't read `ConnId` (control owns conns), but it doesn't need
    /// to — the hot path only asks "is there one."
    #[allow(dead_code)] // read via NodeView accessors once shard tx-path lands
    pub has_direct_conn: bool,
    /// `graph.node(nid).reachable`. NOT redundant with `routes[nid].is_some()`:
    /// the route exists for `myself` too (`distance: 0`), and the relay-recv
    /// gate (`rx.rs:468`) wants "is the *destination* up", which for
    /// `myself` is trivially yes. Carrying it explicitly avoids the
    /// `nid == myself` special case at every read site.
    pub reachable: bool,
    /// `nodes.get(nid).edge_addr`. The peer-ACK addr (TCP addr, port
    /// rewritten to UDP). `choose_udp_address` cold-path fallback when
    /// `tunnel.udp_addr` isn't set yet. Also seeded into `tunnel.udp_addr`
    /// at `BecameReachable`.
    ///
    /// `None` for transitives (no `NodeState` entry; only direct neighbors
    /// get one) — `choose_udp_address` returns `None` and the caller drops
    /// the packet, same as today. `None` for `myself`.
    #[allow(dead_code)] // read via NodeView::edge_addr once shard tx-path lands
    pub edge_addr: Option<SocketAddr>,
    /// `graph.node(nid).name`. `node_log_name`. `Arc<str>` so cloning
    /// `NodeView` (fanout to N shards) doesn't clone N×100 Strings.
    /// The `Arc::from(&str)` at build time is one alloc; `Arc::clone` at
    /// fanout is a refcount bump.
    #[allow(dead_code)] // read via NodeView::name_of once shard tx-path lands
    pub name: Arc<str>,
}

/// The snapshot. Dense `Vec<Option<NodeViewEntry>>` indexed by `NodeId.0`,
/// plus the `name → NodeId` resolve map for the route closure.
///
/// `Clone`: O(1) refcount bumps (every field is `Arc`).
///
/// `Default`: empty snapshot. Reads safe: `entries.get(nid)` → `None`
/// → `<gone>` for log names, `false` for `has_direct_conn` — matches
/// a node-not-yet-learned state.
#[derive(Debug, Clone, Default)]
pub(crate) struct NodeView {
    /// Indexed by `NodeId.0`. `None` for freed slots (never happens in
    /// tincd — nodes are monotonic — but `Graph` is a generic slab and
    /// `node_ids()` skips freed slots).
    entries: Arc<Vec<Option<NodeViewEntry>>>,
    /// `Daemon::node_ids` clone. The route resolve closure
    /// (`route.rs:73-77`) does `node_ids.get(name)? → reachable check`.
    /// `Arc<HashMap>` so the snapshot clone is a refcount bump; the
    /// `HashMap` itself is rebuilt only when a new node name appears
    /// (`lookup_or_add_node`), which is the same event that triggers
    /// `id6_table` rebuild — rare.
    ///
    /// `Arc<str>` keys: shared with `NodeViewEntry::name`. One alloc per
    /// node name, total. The route closure does `&str` key lookups via
    /// `Borrow<str>`, no temporary `Arc` constructed per lookup.
    name_to_nid: Arc<HashMap<Arc<str>, NodeId>>,
}

impl NodeView {
    /// `node_log_name` shard-side. `<gone>` matches the daemon's helper
    /// (the graph crate's `Option` is for freed slots, which tincd never
    /// hits — but the snapshot has the same shape).
    #[inline]
    #[must_use]
    #[allow(dead_code)] // shard tx-path consumer not yet landed
    pub(crate) fn name_of(&self, nid: NodeId) -> &str {
        self.entries
            .get(nid.0 as usize)
            .and_then(Option::as_ref)
            .map_or("<gone>", |e| &*e.name)
    }

    /// The route resolve closure body. `daemon/net/route.rs:73-77` does:
    /// ```ignore
    /// let nid = *node_ids.get(name)?;
    /// graph.node(nid).filter(|n| n.reachable).map(|_| nid)
    /// ```
    /// Same shape here, reading the snapshot. The `&str` lookup goes
    /// through `Borrow<str> for Arc<str>` — no temporary alloc.
    ///
    /// `route()` calls this once per packet (the LPM lookup returns an
    /// owner *name*, this maps name → nid + reachability gate). On the
    /// hot path. The `HashMap` probe is the cost; same as today (the daemon
    /// does the same probe against `self.node_ids`).
    #[inline]
    #[must_use]
    pub(crate) fn resolve(&self, name: &str) -> Option<NodeId> {
        let &nid = self.name_to_nid.get(name)?;
        // `entries[nid]` should always be `Some` for a nid we got from
        // `name_to_nid` (built together, same pass). The `?` is
        // belt-and-suspenders against build-order bugs.
        let e = self.entries.get(nid.0 as usize)?.as_ref()?;
        e.reachable.then_some(nid)
    }

    /// `nodes.get(nid).conn.is_some()`. The `TCPOnly` / PACKET-17 gate.
    /// `false` for nids not in the snapshot — same as the daemon's
    /// `self.nodes.get(&nid).is_some_and(|ns| ns.conn.is_some())`.
    #[inline]
    #[must_use]
    #[allow(dead_code)] // shard tx-path consumer not yet landed
    pub(crate) fn has_direct_conn(&self, nid: NodeId) -> bool {
        self.entries
            .get(nid.0 as usize)
            .and_then(Option::as_ref)
            .is_some_and(|e| e.has_direct_conn)
    }

    /// `graph.node(nid).reachable`. The relay-receive gate (`rx.rs:468`).
    #[inline]
    #[must_use]
    #[allow(dead_code)] // shard tx-path consumer not yet landed
    pub(crate) fn reachable(&self, nid: NodeId) -> bool {
        self.entries
            .get(nid.0 as usize)
            .and_then(Option::as_ref)
            .is_some_and(|e| e.reachable)
    }

    /// `nodes.get(nid).edge_addr`. `choose_udp_address` cold-path fallback.
    #[inline]
    #[must_use]
    #[allow(dead_code)] // shard tx-path consumer not yet landed
    pub(crate) fn edge_addr(&self, nid: NodeId) -> Option<SocketAddr> {
        self.entries
            .get(nid.0 as usize)
            .and_then(Option::as_ref)?
            .edge_addr
    }

    /// Daemon-side builder. Called from `run_graph_and_log` AFTER the
    /// transition loop (so `reachable` reflects the *post*-BFS state) and
    /// from `on_ack` / `terminate` (when `nodes.insert`/`conn = None`
    /// flips `has_direct_conn`).
    ///
    /// Takes `&Graph` + `&HashMap<String, NodeId>` (the `node_ids` map) +
    /// `&IntHashMap<NodeId, NodeState>` separately rather than `&Daemon`
    /// — keeps this module decoupled from the daemon struct, and lets the
    /// tests below build snapshots from minimal inputs.
    ///
    /// `n_nodes` is `graph.nodes.len()` (slab length, including holes).
    /// `last_routes.len()` is the same; `Graph` doesn't expose `.len()`
    /// directly but `sssp()` returns a vec of that length, so the daemon
    /// passes `last_routes.len()` here. Dense vec sizing: same indexing
    /// invariant as `last_routes`.
    #[must_use]
    pub(crate) fn build(
        graph: &crate::graph::Graph,
        node_ids: &HashMap<String, NodeId>,
        nodes: &crate::inthash::IntHashMap<NodeId, crate::daemon::NodeState>,
        n_nodes: usize,
    ) -> Self {
        // One alloc for the name interning. `node_ids` is the source of
        // truth for "which names exist" — every nid the hot path can see
        // came from here (via `lookup_or_add_node`). Walk it once,
        // intern, populate `name_to_nid` + the entry's `name` field.
        let mut entries: Vec<Option<NodeViewEntry>> = vec![None; n_nodes];
        let mut name_to_nid: HashMap<Arc<str>, NodeId> = HashMap::with_capacity(node_ids.len());

        for (name, &nid) in node_ids {
            let name: Arc<str> = Arc::from(name.as_str());
            // `graph.node(nid)` is `Some` for every nid in `node_ids`
            // (`lookup_or_add_node` writes both together). The `else`
            // is unreachable in practice; keep the entry `None` if it
            // ever fires (the read side handles `None` gracefully).
            let reachable = graph.node(nid).is_some_and(|n| n.reachable);
            // `nodes` is sparse (direct neighbors only). `None` means
            // transitive — no direct conn, no edge addr. Correct.
            let ns = nodes.get(&nid);
            let idx = nid.0 as usize;
            // `n_nodes` is the slab len; `nid.0` is a slab index.
            // `idx < n_nodes` holds by construction (`Graph::add_node`
            // never hands out an index ≥ len). Debug-assert documents;
            // the `get_mut` below would silently skip on a violation
            // (entry stays `None`, reads see `<gone>` — degraded but
            // not unsound).
            debug_assert!(idx < n_nodes, "nid {nid:?} >= slab len {n_nodes}");
            if let Some(slot) = entries.get_mut(idx) {
                *slot = Some(NodeViewEntry {
                    has_direct_conn: ns.is_some_and(|s| s.conn.is_some()),
                    reachable,
                    edge_addr: ns.and_then(|s| s.edge_addr),
                    name: Arc::clone(&name),
                });
            }
            name_to_nid.insert(name, nid);
        }

        Self {
            entries: Arc::new(entries),
            name_to_nid: Arc::new(name_to_nid),
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// Compile-time `Send + Sync` checks
//
// `Arc<NodeView>` crosses the channel. `Send` to move; `Sync` so
// the shard can read through `&Arc<NodeView>` (which it does:
// `self.ns.name_of(nid)` derefs `Arc` → `&NodeView`). All fields
// are `Arc<T>` where `T: Send + Sync` (`Vec`, `HashMap` of `Send+Sync`
// elements). `SocketAddr` is `Copy`. `Arc<str>` is `Send + Sync`.

const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    let _ = assert_send_sync::<NodeView>;
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::NodeState;
    use crate::inthash::IntHashMap;
    use crate::graph::Graph;

    /// Minimal builder. Sets up a 3-node graph (a-b-c chain), `b` directly
    /// connected (has `NodeState`), `c` transitive. `a` is myself.
    fn fixture() -> (
        Graph,
        HashMap<String, NodeId>,
        IntHashMap<NodeId, NodeState>,
    ) {
        let mut g = Graph::new();
        let a = g.add_node("a");
        let b = g.add_node("b");
        let c = g.add_node("c");
        // a-b bidi, b-c bidi. `sssp` needs the reverse to visit.
        g.add_edge(a, b, 1, 0);
        g.add_edge(b, a, 1, 0);
        g.add_edge(b, c, 1, 0);
        g.add_edge(c, b, 1, 0);
        // `add_node` defaults `reachable: true` — don't fight it; the
        // test cares about the snapshot read, not the BFS logic.

        let mut node_ids = HashMap::new();
        node_ids.insert("a".to_owned(), a);
        node_ids.insert("b".to_owned(), b);
        node_ids.insert("c".to_owned(), c);

        let mut nodes = IntHashMap::default();
        // Only `b` is a direct neighbor. `conn: Some` would need a
        // real `ConnId` (slotmap key) — the daemon constructs those
        // via `conns.insert`. For the snapshot, all that matters is
        // `is_some()`. Cheat: `NodeState::edge_addr` IS what we read,
        // and `conn` we test as `None` (transitive) — the
        // `has_direct_conn: true` case is covered in the daemon's
        // integration tests where a real ConnId exists.
        nodes.insert(
            b,
            NodeState {
                edge: None,
                conn: None,
                edge_addr: Some("10.0.0.2:655".parse().unwrap()),
                edge_weight: 0,
                edge_options: crate::proto::ConnOptions::empty(),
            },
        );

        (g, node_ids, nodes)
    }

    #[test]
    fn build_populates_entries_dense() {
        let (g, node_ids, nodes) = fixture();
        // n_nodes = 3 (slab len, no holes in this fixture).
        let ns = NodeView::build(&g, &node_ids, &nodes, 3);

        // All three slots filled (no holes).
        assert_eq!(ns.name_of(NodeId(0)), "a");
        assert_eq!(ns.name_of(NodeId(1)), "b");
        assert_eq!(ns.name_of(NodeId(2)), "c");
        // Out of bounds → `<gone>`.
        assert_eq!(ns.name_of(NodeId(99)), "<gone>");
    }

    #[test]
    fn resolve_mirrors_daemon_route_closure() {
        let (g, node_ids, nodes) = fixture();
        let ns = NodeView::build(&g, &node_ids, &nodes, 3);

        // Same body as `daemon/net/route.rs:73-77`. All reachable
        // (Graph::add_node defaults true).
        assert_eq!(ns.resolve("a"), Some(NodeId(0)));
        assert_eq!(ns.resolve("b"), Some(NodeId(1)));
        assert_eq!(ns.resolve("c"), Some(NodeId(2)));
        // Unknown name → None (daemon: `node_ids.get(name)?` fails).
        assert_eq!(ns.resolve("nobody"), None);
    }

    #[test]
    fn resolve_gates_on_reachability() {
        let (mut g, node_ids, nodes) = fixture();
        // Flip `c` unreachable. The daemon does this in `run_graph`
        // when sssp doesn't visit; here we set directly.
        g.set_reachable(NodeId(2), false);
        let ns = NodeView::build(&g, &node_ids, &nodes, 3);

        assert_eq!(ns.resolve("a"), Some(NodeId(0)));
        assert_eq!(ns.resolve("c"), None); // unreachable → filtered
        // `name_of` still works (it doesn't gate on reachable; log
        // strings for unreachable nodes are valid).
        assert_eq!(ns.name_of(NodeId(2)), "c");
        assert!(!ns.reachable(NodeId(2)));
        assert!(ns.reachable(NodeId(1)));
    }

    #[test]
    fn edge_addr_only_for_direct_neighbors() {
        let (g, node_ids, nodes) = fixture();
        let ns = NodeView::build(&g, &node_ids, &nodes, 3);

        // `b` has a NodeState entry with edge_addr.
        assert_eq!(ns.edge_addr(NodeId(1)), "10.0.0.2:655".parse().ok());
        // `a` (myself) and `c` (transitive) don't.
        assert_eq!(ns.edge_addr(NodeId(0)), None);
        assert_eq!(ns.edge_addr(NodeId(2)), None);
        // `has_direct_conn`: `b`'s `conn` is `None` in the fixture
        // (can't fake a ConnId here). The daemon's integration tests
        // cover the `Some` case.
        assert!(!ns.has_direct_conn(NodeId(1)));
    }

    #[test]
    fn clone_is_refcount_bump() {
        let (g, node_ids, nodes) = fixture();
        let ns = NodeView::build(&g, &node_ids, &nodes, 3);

        let entries_ptr = Arc::as_ptr(&ns.entries);
        let names_ptr = Arc::as_ptr(&ns.name_to_nid);

        let ns2 = ns.clone();

        // Same heap allocation. The fanout to N shards is N × this.
        assert_eq!(Arc::as_ptr(&ns2.entries), entries_ptr);
        assert_eq!(Arc::as_ptr(&ns2.name_to_nid), names_ptr);
        // Functionally identical.
        assert_eq!(ns2.resolve("b"), Some(NodeId(1)));
    }

    #[test]
    fn default_is_empty_safe() {
        let ns = NodeView::default();
        // Shard starts with this. Everything reads as "not yet learned".
        assert_eq!(ns.name_of(NodeId(0)), "<gone>");
        assert_eq!(ns.resolve("anyone"), None);
        assert!(!ns.has_direct_conn(NodeId(0)));
        assert!(!ns.reachable(NodeId(0)));
        assert_eq!(ns.edge_addr(NodeId(0)), None);
    }
}
