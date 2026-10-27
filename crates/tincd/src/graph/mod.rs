//! Mesh graph: a slab of nodes and edges with typed `NodeId`/`EdgeId`
//! handles, plus the two routing algorithms that run over it —
//! Kruskal's MST and a BFS-based single-source shortest path producing
//! per-node distance, `via` relay, and indirect/direct status.
//!
//! Edges and nodes are stored in `Vec<Option<_>>` slabs with a LIFO
//! free-list, so churn from TCP reconnects is O(1) and stale IDs
//! harmlessly read `None`. Per-node edge lists are kept sorted by
//! destination name and Kruskal walks a `BTreeMap` keyed by
//! `(weight, from-name, to-name)`, which makes equal-cost tie-breaks
//! deterministic. SSSP additionally upgrades a node from indirect to
//! direct whenever a direct path appears, even at a worse distance, so
//! the `via` hint used for UDP hole-punching always points at the last
//! real relay.

use crate::dispatch::ConnOptions;
use std::collections::{BTreeMap, VecDeque};

// IDs

/// Index into [`Graph`]'s node slab.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(pub u32);

/// Index into [`Graph`]'s edge slab.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EdgeId(pub u32);

/// The one option bit BFS reads. Sourced from [`crate::dispatch::ConnOptions::INDIRECT`] so the bit
/// value lives in exactly one place.
pub const OPTION_INDIRECT: u32 = ConnOptions::INDIRECT.bits();

/// Stickiness band for [`Graph::sssp_sticky`]: keep the previous
/// nexthop if its path cost is within this percent of the new best.
/// 133 ≡ "new must be ≥33 % cheaper to win" — Tailscale's DERP-home
/// hysteresis (`netcheck.go:1453`).
pub const STICKY_THRESHOLD_PCT: i32 = 133;

/// Stickiness post-pass for [`Graph::sssp_sticky`]. `sticky_wdist[n]` is
/// `Some(w)` iff the BFS found an equal-hop path to `n` through
/// `prev[n].nexthop` with weight `w` — the only safe stickiness, since it
/// proves the old nexthop still reaches `n` at that hop count. "Old nexthop is
/// still a neighbour" is not enough; the far edge may be gone.
fn sticky_post_pass(
    route: &mut [Option<Route>],
    prev: &[Option<Route>],
    sticky_wdist: &[Option<i32>],
) {
    for (slot, r) in route.iter_mut().enumerate() {
        let Some(new) = r else { continue };
        let Some(Some(old)) = prev.get(slot) else {
            continue;
        };
        if old.nexthop == new.nexthop {
            continue;
        }
        let Some(sticky_w) = sticky_wdist.get(slot).copied().flatten() else {
            // BFS never saw an equal-hop path via old.nexthop → it no
            // longer reaches `n` at this distance. Real reroute.
            continue;
        };
        // Metric gate: `sticky ≤ best × STICKY_THRESHOLD_PCT / 100`.
        // i64 so ×133 can't overflow on pathological weights; both
        // sides non-negative (`parse_add_edge` clamps weight at 0).
        let sticky_w64 = i64::from(sticky_w);
        let best_w = i64::from(new.weighted_distance);
        if sticky_w64 * 100 <= best_w * i64::from(STICKY_THRESHOLD_PCT) {
            new.nexthop = old.nexthop;
            new.weighted_distance = sticky_w;
        }
    }
}

// Slab payloads. Minimal — just what the algorithms read.

/// One node. This is the graph-relevant slice of the daemon's node
/// state. The daemon keeps the rest (SPTPS state, MTU probe, address
/// cache)
/// in a parallel table keyed by `NodeId`.
#[derive(Debug, Clone)]
pub struct Node {
    /// Node name; also the tie-break key (matches C tinc's
    /// name-ordered trees so route tie-breaks agree across the mesh).
    pub name: String,

    /// Outgoing edges, sorted by destination name. A sorted `Vec`
    /// instead of a tree (typical degree is small enough that linear
    /// insert beats
    /// `BTreeSet` overhead).
    edges: Vec<EdgeId>,

    /// `n->status.reachable` — *input* to the algorithms. Kruskal uses
    /// it to pick a starting point; SSSP uses it to gate the
    /// `update_node_udp` call (which we don't fire here, but the gate
    /// affects whether the call *would* fire — the daemon diffs old vs
    /// new). Set by the *previous* SSSP via `check_reachability`.
    pub reachable: bool,
}

/// One directed edge. `a→b` and `b→a` are two `Edge`s linked via
/// `reverse`.
#[derive(Debug, Clone)]
pub struct Edge {
    pub from: NodeId,
    pub to: NodeId,
    /// Signed because the wire format is `%d` and never range-checked.
    pub weight: i32,
    /// Full bitfield. Only `OPTION_INDIRECT` is read here; the daemon
    /// reads the rest.
    pub options: u32,
    /// `e->reverse`. `None` for one-way edges (transient: one half of
    /// an `ADD_EDGE` pair has arrived but not its twin). SSSP and
    /// Kruskal both skip them.
    pub reverse: Option<EdgeId>,

    /// `to->name`, cached. Per-node edge lists must be sorted by
    /// destination name to match `splay_each` order, but the comparator
    /// can't index into `nodes` while we hold `&mut from_node.edges`.
    /// One cloned string per edge beats the borrow gymnastics.
    to_name: String,
}

/// SSSP routing for one node, or `None` if the BFS never visited it
/// (unreachable; `check_reachability` then syncs `reachable`). `Copy` (32
/// bytes): the daemon keeps the routes behind `Arc`, and by-value lookup avoids
/// a borrow chain at every read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    /// `n->status.indirect`. Reached only through `OPTION_INDIRECT`
    /// edges. UDP can't reach this node directly; relay through `via`.
    pub indirect: bool,
    /// `n->distance`. Hop count.
    pub distance: i32,
    /// `n->weighted_distance`. Sum of edge weights along the chosen
    /// path. Not necessarily minimal — the indirect→direct upgrade can
    /// pick a heavier path. See module doc.
    pub weighted_distance: i32,
    /// `n->nexthop`. First hop from `myself`. Unicast packets go here.
    pub nexthop: NodeId,
    /// `n->via`. Last *direct* node on the path. Equals self if direct;
    /// equals predecessor's `via` if indirect. UDP hole-punching target.
    pub via: NodeId,
    /// `n->prevedge`. The edge BFS arrived through. Daemon uses it for
    /// `update_node_udp` (the edge carries the source address). `None`
    /// only for `myself`.
    pub prevedge: Option<EdgeId>,
    /// `n->options` — copied from `prevedge->options`. The daemon
    /// checks `OPTION_TCPONLY` here.
    pub options: u32,
}

// The graph

/// Node + edge slabs, plus the weight-ordered edge index Kruskal walks.
///
/// Slabs are `Vec<Option<_>>` with free-lists — see module doc,
/// "Deletion".
#[derive(Debug, Default)]
pub struct Graph {
    nodes: Vec<Option<Node>>,
    edges: Vec<Option<Edge>>,
    /// LIFO recycle stack: indices of `None` slots in `nodes`.
    node_free: Vec<u32>,
    /// LIFO recycle stack: indices of `None` slots in `edges`.
    edge_free: Vec<u32>,
    /// `edge_weight_tree`: `(weight, from_name, to_name) → EdgeId`.
    /// `BTreeMap` for sorted iteration + `O(log n)` remove. Names
    /// cloned into the key — cheap (a few hundred bytes for typical
    /// meshes), avoids borrowing `nodes` while iterating `weight_order`.
    weight_order: BTreeMap<(i32, String, String), EdgeId>,
}

/// Store `v` in a recycled slot (LIFO) or a new one, return its index.
fn alloc_slot<T>(slab: &mut Vec<Option<T>>, free: &mut Vec<u32>, v: T) -> u32 {
    while let Some(idx) = free.pop() {
        if let Some(s) = slab.get_mut(idx as usize)
            && s.is_none()
        {
            *s = Some(v);
            return idx;
        }
    }
    slab.push(Some(v));
    #[expect(clippy::cast_possible_truncation)] // a mesh never nears u32::MAX slots
    let idx = (slab.len() - 1) as u32;
    idx
}

/// `to_name` of a slab edge, `""` for a freed slot.
fn edge_to_name(edges: &[Option<Edge>], e: EdgeId) -> &str {
    edges
        .get(e.0 as usize)
        .and_then(Option::as_ref)
        .map_or("", |e| e.to_name.as_str())
}

/// Slot indices zipped with live payloads.
fn live<T>(slab: &[Option<T>]) -> impl Iterator<Item = (u32, &T)> {
    (0u32..)
        .zip(slab)
        .filter_map(|(i, s)| s.as_ref().map(|v| (i, v)))
}

impl Graph {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn node_mut(&mut self, n: NodeId) -> Option<&mut Node> {
        self.nodes.get_mut(n.0 as usize)?.as_mut()
    }

    fn edge_mut(&mut self, e: EdgeId) -> Option<&mut Edge> {
        self.edges.get_mut(e.0 as usize)?.as_mut()
    }

    fn name(&self, n: NodeId) -> String {
        self.node(n).map(|n| n.name.clone()).unwrap_or_default()
    }

    /// `node_tree.insert`. `reachable` defaults true (steady state).
    /// Recycles a freed slot if one exists (LIFO).
    pub fn add_node(&mut self, name: impl Into<String>) -> NodeId {
        let node = Node {
            name: name.into(),
            edges: Vec::new(),
            reachable: true,
        };
        NodeId(alloc_slot(&mut self.nodes, &mut self.node_free, node))
    }

    /// `edge_add`: insert into `from.edge_tree` and `edge_weight_tree`,
    /// link `reverse` if the twin already exists. Both nodes must be live.
    pub fn add_edge(&mut self, from: NodeId, to: NodeId, weight: i32, options: u32) -> EdgeId {
        // Daemon discipline holds (on_add_edge does lookup_edge first,
        // on_ack does terminate→del_edge first); this is a tripwire.
        debug_assert!(
            self.lookup_edge(from, to).is_none(),
            "duplicate edge {from:?}→{to:?}"
        );
        let reverse = self
            .node_edges(to)
            .iter()
            .copied()
            .find(|&eid| self.edge(eid).is_some_and(|e| e.to == from));
        let to_name = self.name(to);
        let from_name = self.name(from);
        let edge = Edge {
            from,
            to,
            weight,
            options,
            reverse,
            to_name: to_name.clone(),
        };
        let id = EdgeId(alloc_slot(&mut self.edges, &mut self.edge_free, edge));
        if let Some(r) = reverse.and_then(|r| self.edge_mut(r)) {
            r.reverse = Some(id);
        }

        // Per-node edge list, sorted by `to_name`. The cache in `Edge`
        // is what makes this comparator work without borrowing `nodes`.
        let edges = &self.edges;
        if let Some(from_node) = self.nodes.get_mut(from.0 as usize).and_then(Option::as_mut) {
            let pos = from_node
                .edges
                .partition_point(|&eid| edge_to_name(edges, eid) < to_name.as_str());
            from_node.edges.insert(pos, id);
        }

        self.weight_order.insert((weight, from_name, to_name), id);
        id
    }

    /// Delete an edge: unlink the twin's `reverse`, remove from the per-node list
    /// and `weight_order`, free the slot. `None` if already freed, since conn close
    /// and `DEL_EDGE` can race during teardown and a no-op is the safe answer.
    pub fn del_edge(&mut self, e: EdgeId) -> Option<()> {
        // The per-node list comparator reads `e`'s slot, so `take()` comes last.
        let (from, to_name, weight, reverse) = {
            let edge = self.edge(e)?;
            (edge.from, edge.to_name.clone(), edge.weight, edge.reverse)
        };

        if let Some(r) = reverse.and_then(|r| self.edge_mut(r)) {
            r.reverse = None;
        }

        let edges = &self.edges;
        if let Some(from_node) = self.nodes.get_mut(from.0 as usize).and_then(Option::as_mut)
            && let Ok(pos) = from_node
                .edges
                .binary_search_by(|&eid| edge_to_name(edges, eid).cmp(&to_name))
        {
            from_node.edges.remove(pos);
        }

        let from_name = self.name(from);
        self.weight_order.remove(&(weight, from_name, to_name));

        if let Some(s) = self.edges.get_mut(e.0 as usize) {
            *s = None;
            self.edge_free.push(e.0);
        }
        Some(())
    }

    /// Delete a node: cascade-delete its outgoing edges (their twins become
    /// reverseless, which `sssp`/`mst` skip), then free the slot. Incoming edges
    /// are not hunted down; the protocol layer deletes both halves before purging a
    /// node. `None` if already freed, as [`Self::del_edge`]. Subnets are
    /// daemon-side.
    pub fn del_node(&mut self, n: NodeId) -> Option<()> {
        // `del_edge` needs the node live, so drain a snapshot before the take.
        let outgoing: Vec<EdgeId> = self.node(n)?.edges.clone();
        for e in outgoing {
            self.del_edge(e);
        }
        if let Some(s) = self.nodes.get_mut(n.0 as usize) {
            *s = None;
            self.node_free.push(n.0);
        }
        Some(())
    }

    /// In-place edge update: write `options`, re-key `weight_order` only if
    /// the weight changed, leave the per-node index alone. Exists alongside
    /// del+add for `EdgeId` stability, so side tables keyed on the id see one
    /// write. `None` for a stale id.
    pub fn update_edge(&mut self, e: EdgeId, weight: i32, options: u32) -> Option<()> {
        let edge = self.edge_mut(e)?;
        edge.options = options;
        if edge.weight == weight {
            return Some(());
        }
        let old_weight = edge.weight;
        edge.weight = weight;
        let to_name = edge.to_name.clone();
        let from = edge.from;
        let from_name = self.name(from);
        self.weight_order
            .remove(&(old_weight, from_name.clone(), to_name.clone()));
        self.weight_order.insert((weight, from_name, to_name), e);
        Some(())
    }

    /// Find the edge `from → to` if it exists. Searches the per-node
    /// list keyed on `to_name`.
    #[must_use]
    pub fn lookup_edge(&self, from: NodeId, to: NodeId) -> Option<EdgeId> {
        let to_name = self.node(to)?.name.as_str();
        let from_edges = &self.node(from)?.edges;
        let i = from_edges
            .binary_search_by(|&eid| edge_to_name(&self.edges, eid).cmp(to_name))
            .ok()?;
        from_edges.get(i).copied()
    }

    /// Daemon calls after diffing SSSP results. No-op on a freed slot.
    pub fn set_reachable(&mut self, n: NodeId, r: bool) {
        if let Some(n) = self.node_mut(n) {
            n.reachable = r;
        }
    }

    /// `None` if the slot was freed (stale `NodeId`).
    #[must_use]
    pub fn node(&self, n: NodeId) -> Option<&Node> {
        self.nodes.get(n.0 as usize)?.as_ref()
    }

    /// Slab length (incl. freed holes). Every `NodeId.0 < slab_len()`;
    /// same length `sssp()` returns. Use to size dense per-node tables.
    #[must_use]
    pub fn slab_len(&self) -> usize {
        self.nodes.len()
    }

    /// Live edge count (slab len minus freed slots).
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.edges.len() - self.edge_free.len()
    }

    /// `None` if the slot was freed (stale `EdgeId`).
    #[must_use]
    pub fn edge(&self, e: EdgeId) -> Option<&Edge> {
        self.edges.get(e.0 as usize)?.as_ref()
    }

    /// Live node IDs, slot order. **Not** `ExactSizeIterator`: with a
    /// free-list, `nodes.len()` counts holes too.
    pub fn node_ids(&self) -> impl Iterator<Item = NodeId> + '_ {
        live(&self.nodes).map(|(i, _)| NodeId(i))
    }

    /// All edges in slab order. A bidi link is two `Edge`s and yields two
    /// items, matching the dump's per-direction rows.
    pub fn edge_iter(&self) -> impl Iterator<Item = (EdgeId, &Edge)> + '_ {
        live(&self.edges).map(|(i, e)| (EdgeId(i), e))
    }

    /// Outgoing edges of `n`, sorted by destination name. Empty slice
    /// for freed slots.
    #[must_use]
    pub fn node_edges(&self, n: NodeId) -> &[EdgeId] {
        self.node(n).map_or(&[], |node| node.edges.as_slice())
    }

    /// BFS from `myself`; one `Option<Route>` per node indexed by `NodeId.0`,
    /// `None` = unreachable. The revisit rule is the subtle part: an
    /// already-visited node is revisited only when the new path upgrades
    /// indirect→direct, or has the same hop count and lower weight.
    #[must_use]
    pub fn sssp(&self, myself: NodeId) -> Vec<Option<Route>> {
        self.sssp_sticky(myself, &[])
    }

    /// [`sssp`](Self::sssp) with nexthop stickiness: where `nexthop` would change
    /// versus `prev` but the previous route is still valid (same hop count, same
    /// `indirect`) and within [`STICKY_THRESHOLD_PCT`] % of the new best weight,
    /// keep it. Local damping of weight jitter, no re-gossip; topology changes
    /// still win. `prev` is the last result; uncovered slots get the plain BFS
    /// answer.
    #[must_use]
    pub fn sssp_sticky(&self, myself: NodeId, prev: &[Option<Route>]) -> Vec<Option<Route>> {
        let prev_nh = |n: NodeId| {
            prev.get(n.0 as usize)
                .and_then(Option::as_ref)
                .map(|r| r.nexthop)
        };
        // Indexed by raw slot number, freed slots stay `None`.
        let n_nodes = self.nodes.len();
        let mut route: Vec<Option<Route>> = vec![None; n_nodes];
        // Per-node: cheapest equal-hop wdist via the previous nexthop,
        // if the BFS encounters one. Consumed by `sticky_post_pass`.
        let mut sticky_wdist: Vec<Option<i32>> = vec![None; n_nodes];

        if let Some(r) = route.get_mut(myself.0 as usize) {
            *r = Some(Route {
                indirect: false,
                distance: 0,
                weighted_distance: 0,
                nexthop: myself,
                via: myself,
                prevedge: None,
                options: 0, // never meaningful for myself
            });
        }

        let mut todo = VecDeque::new();
        todo.push_back(myself);

        while let Some(n) = todo.pop_front() {
            let Some(Some(r)) = route.get(n.0 as usize).copied() else {
                continue;
            };

            for &eid in self.node_edges(n) {
                let Some(e) = self.edge(eid) else { continue };

                // Skip half-edges and edges back to ourselves.
                if e.reverse.is_none() || e.to == myself {
                    continue;
                }
                let to = e.to.0 as usize;
                let Some(&old) = route.get(to) else { continue };

                // Indirect propagates; OPTION_INDIRECT adds.
                let indirect = r.indirect || (e.options & OPTION_INDIRECT) != 0;

                let cand_hops = r.distance + 1;
                // Peer-supplied weight: saturate so a chain of i32::MAX
                // hops can't wrap negative and win the tie-break.
                let cand_wdist = r.weighted_distance.saturating_add(e.weight);
                let cand_nexthop = if r.nexthop == myself { e.to } else { r.nexthop };

                // Stickiness bookkeeping: record the cheapest wdist of any candidate arriving
                // via this node's previous nexthop at the hop count the BFS will settle on.
                // Recorded before the skip so the heavier equal-hop alternative isn't lost.
                if Some(cand_nexthop) == prev_nh(e.to)
                    && old.is_none_or(|p| p.distance == cand_hops)
                    && let Some(slot) = sticky_wdist.get_mut(to)
                {
                    *slot = Some(slot.map_or(cand_wdist, |w| w.min(cand_wdist)));
                }

                // nexthop and weighted_distance update only on first visit or same-hop lighter
                // weight. The indirect→direct upgrade keeps nexthop but updates
                // distance/prevedge/via/options, so distance can rise while nexthop stays;
                // matching C exactly keeps routing consistent mesh-wide (KAT-pinned).
                let (nexthop, weighted_distance) = match old {
                    None => (cand_nexthop, cand_wdist),
                    Some(p) => {
                        let directness_unchanged = !p.indirect || indirect;
                        let lighter = p.distance == cand_hops && p.weighted_distance > cand_wdist;
                        if directness_unchanged && !lighter {
                            continue;
                        }
                        if lighter {
                            (cand_nexthop, cand_wdist)
                        } else {
                            (p.nexthop, p.weighted_distance)
                        }
                    }
                };

                if let Some(slot) = route.get_mut(to) {
                    *slot = Some(Route {
                        indirect,
                        distance: cand_hops,
                        weighted_distance,
                        nexthop,
                        via: if indirect { r.via } else { e.to },
                        prevedge: Some(eid),
                        options: e.options,
                    });
                }

                // Can enqueue a node twice (indirect→direct upgrade); the
                // second visit mostly hits the skip branch.
                todo.push_back(e.to);
            }
        }

        if !prev.is_empty() {
            sticky_post_pass(&mut route, prev, &sticky_wdist);
        }

        route
    }

    /// Kruskal without union-find, as C tinc: walk edges by weight, take each one
    /// joining an unvisited node to a visited one, and rewind to the start after
    /// progress following a skip (so a light edge between two unvisited nodes is
    /// picked up once one end is connected). Starts from the first reachable `from`
    /// in weight order. Returns both directions' `EdgeId`s.
    #[must_use]
    pub fn mst(&self) -> Vec<EdgeId> {
        let mut visited = vec![false; self.nodes.len()];
        let is_visited = |v: &[bool], n: NodeId| v.get(n.0 as usize).copied().unwrap_or(false);
        let visit = |v: &mut [bool], n: NodeId| {
            if let Some(b) = v.get_mut(n.0 as usize) {
                *b = true;
            }
        };
        let mut mst_edges = Vec::new();

        let order: Vec<(EdgeId, &Edge)> = self
            .weight_order
            .values()
            .filter_map(|&eid| Some((eid, self.edge(eid)?)))
            .collect();
        if let Some((_, e)) = order
            .iter()
            .find(|(_, e)| self.node(e.from).is_some_and(|n| n.reachable))
        {
            visit(&mut visited, e.from);
        }

        let mut i = 0;
        let mut skipped = false;
        while let Some(&(eid, e)) = order.get(i) {
            let joins = is_visited(&visited, e.from) != is_visited(&visited, e.to);
            let Some(rev) = e.reverse.filter(|_| joins) else {
                skipped = true;
                i += 1;
                continue;
            };
            visit(&mut visited, e.from);
            visit(&mut visited, e.to);
            mst_edges.push(eid);
            mst_edges.push(rev);

            if skipped {
                skipped = false;
                i = 0;
            } else {
                i += 1;
            }
        }

        mst_edges
    }
}

// Unit tests for invariants. KAT differential tests live in
// tests/kat.rs.

#[cfg(test)]
#[expect(clippy::many_single_char_names)] // graph node labels: a/b/c is clearest
mod tests {
    use super::*;

    #[test]
    fn edge_order_by_to_name() {
        let mut g = Graph::new();
        let a = g.add_node("a");
        let _z = g.add_node("z");
        let _b = g.add_node("b");
        // Insert out of name order; verify the per-node edge list is sorted.
        g.add_edge(a, NodeId(1), 0, 0); // a→z
        g.add_edge(a, NodeId(2), 0, 0); // a→b
        let names: Vec<_> = g
            .node(a)
            .unwrap()
            .edges
            .iter()
            .map(|&e| g.edge(e).unwrap().to_name.as_str())
            .collect();
        assert_eq!(names, ["b", "z"]);
    }

    #[test]
    fn reverse_auto_links() {
        let mut g = Graph::new();
        let a = g.add_node("a");
        let b = g.add_node("b");
        let e1 = g.add_edge(a, b, 1, 0);
        assert!(g.edge(e1).unwrap().reverse.is_none()); // twin not yet present
        let e2 = g.add_edge(b, a, 1, 0);
        assert_eq!(g.edge(e2).unwrap().reverse, Some(e1));
        assert_eq!(g.edge(e1).unwrap().reverse, Some(e2)); // back-linked
    }

    #[test]
    fn sssp_singleton() {
        let mut g = Graph::new();
        let a = g.add_node("a");
        let r = g.sssp(a);
        assert_eq!(r.len(), 1);
        let me = r[0].as_ref().unwrap();
        assert_eq!(me.distance, 0);
        assert_eq!(me.nexthop, a);
        assert_eq!(me.via, a);
        assert!(!me.indirect);
        assert!(me.prevedge.is_none());
    }

    #[test]
    fn sssp_skips_reverseless() {
        let mut g = Graph::new();
        let a = g.add_node("a");
        let b = g.add_node("b");
        g.add_edge(a, b, 1, 0); // one-way, no reverse
        let r = g.sssp(a);
        assert!(r[1].is_none()); // b unreachable
    }

    // Deletion

    /// Triangle a-b-c, all bidi. Handy for delete tests.
    fn triangle() -> (Graph, [NodeId; 3], [EdgeId; 6]) {
        let mut g = Graph::new();
        let a = g.add_node("a");
        let b = g.add_node("b");
        let c = g.add_node("c");
        let ab = g.add_edge(a, b, 10, 0);
        let ba = g.add_edge(b, a, 10, 0);
        let bc = g.add_edge(b, c, 20, 0);
        let cb = g.add_edge(c, b, 20, 0);
        let ac = g.add_edge(a, c, 30, 0);
        let ca = g.add_edge(c, a, 30, 0);
        (g, [a, b, c], [ab, ba, bc, cb, ac, ca])
    }

    /// Postconditions of a single `del_edge(ab)` on the triangle:
    /// reverse-unlink, per-node list removal, and free-list slot
    /// recycling.
    #[test]
    fn del_edge_postconditions() {
        let (mut g, [a, b, c], [ab, ba, ..]) = triangle();
        assert_eq!(g.edge(ba).unwrap().reverse, Some(ab));

        g.del_edge(ab).unwrap();

        assert!(g.edge(ab).is_none(), "slot freed");
        assert_eq!(g.edge(ba).unwrap().reverse, None, "twin orphaned");

        // a had edges to b and c; now only c, list stays sorted.
        assert_eq!(g.lookup_edge(a, b), None, "gone from node list");
        assert!(g.lookup_edge(a, c).is_some(), "a→c still there");
        assert_eq!(g.node(a).unwrap().edges.len(), 1, "node list shrunk");

        // Free-list LIFO: deleted slot is the next one handed out.
        // (Replace with the same a→b pair; triangle's c→a still
        // exists, so a fresh c→a would trip the duplicate assert.)
        let new = g.add_edge(a, b, 99, 0);
        assert_eq!(new, ab, "freed slot recycled");
        assert_eq!(
            g.edge(new).unwrap().weight,
            99,
            "recycled slot has new payload"
        );
    }

    #[test]
    fn del_edge_removes_from_weight_order() {
        // After deleting both halves of a-c, MST should be the a-b-c
        // path (4 edges) and never see weight=30.
        let (mut g, _, [_, _, _, _, ac, ca]) = triangle();
        g.del_edge(ac).unwrap();
        g.del_edge(ca).unwrap();
        let mst = g.mst();
        assert_eq!(mst.len(), 4); // ab+ba+bc+cb
        for e in &mst {
            assert_ne!(g.edge(*e).unwrap().weight, 30);
        }
    }

    #[test]
    fn sssp_after_del_unreachable() {
        // Chain a-b-c. Cut b-c. c becomes unreachable from a.
        let mut g = Graph::new();
        let a = g.add_node("a");
        let b = g.add_node("b");
        let c = g.add_node("c");
        g.add_edge(a, b, 1, 0);
        g.add_edge(b, a, 1, 0);
        let bc = g.add_edge(b, c, 1, 0);
        g.add_edge(c, b, 1, 0);

        let before = g.sssp(a);
        assert!(before[c.0 as usize].is_some());

        // Delete one half: b→c. c→b is now reverseless → sssp skips.
        g.del_edge(bc).unwrap();
        let after = g.sssp(a);
        assert!(after[b.0 as usize].is_some()); // b still reachable
        assert!(after[c.0 as usize].is_none()); // c isn't
    }

    #[test]
    fn del_edge_on_freed_slot_is_noop() {
        // Rationale in `del_edge` doc: teardown races make panic
        // unhelpful.
        let (mut g, _, [ab, ..]) = triangle();
        assert_eq!(g.del_edge(ab), Some(()));
        assert_eq!(g.del_edge(ab), None); // double-delete: no-op
    }

    #[test]
    fn del_both_halves_either_order() {
        // Deleting a→b then b→a: second delete sees `reverse = None`
        // (first delete unlinked it) so the back-unlink is a no-op,
        // not a freed-slot deref.
        let (mut g, _, [ab, ba, ..]) = triangle();
        g.del_edge(ab).unwrap();
        // ba.reverse is now None — the unlink branch shouldn't try to
        // touch ab's freed slot.
        g.del_edge(ba).unwrap();
        assert!(g.edge(ab).is_none());
        assert!(g.edge(ba).is_none());
    }

    #[test]
    fn del_node_cascades_outgoing() {
        // Cascade: only outgoing; incoming become reverseless.
        let (mut g, [a, b, c], [ab, ba, bc, cb, ac, ca]) = triangle();
        g.del_node(b).unwrap();

        assert!(g.node(b).is_none());
        // b's outgoing edges (ba, bc) are gone:
        assert!(g.edge(ba).is_none());
        assert!(g.edge(bc).is_none());
        // Incoming edges (ab, cb) still exist but reverseless:
        assert_eq!(g.edge(ab).unwrap().reverse, None);
        assert_eq!(g.edge(cb).unwrap().reverse, None);
        // Unrelated edges untouched:
        assert_eq!(g.edge(ac).unwrap().reverse, Some(ca));

        // sssp from a: c reachable via a-c (the surviving bidi link),
        // b's slot is dead → None route. The dangling ab edge with
        // `to = b` (freed) is skipped because reverseless.
        let r = g.sssp(a);
        assert!(r[b.0 as usize].is_none());
        assert!(r[c.0 as usize].is_some());
    }

    #[test]
    fn del_node_recycles_slot() {
        let (mut g, [_, b, _], _) = triangle();
        g.del_node(b).unwrap();
        let d = g.add_node("d");
        assert_eq!(d, b, "freed node slot recycled");
        assert_eq!(g.node(d).unwrap().name, "d");
        assert!(g.node(d).unwrap().edges.is_empty()); // fresh, not stale
    }

    #[test]
    fn node_ids_skips_freed() {
        let (mut g, [a, b, c], _) = triangle();
        g.del_node(b).unwrap();
        let live: Vec<_> = g.node_ids().collect();
        assert_eq!(live, vec![a, c]);
    }

    // edge_iter + update_edge

    #[test]
    fn edge_iter_skips_freed_slots() {
        let (mut g, _, [_, _, bc, ..]) = triangle();
        assert_eq!(g.edge_iter().count(), 6);
        g.del_edge(bc).unwrap();
        let live: Vec<_> = g.edge_iter().map(|(id, _)| id).collect();
        assert_eq!(live.len(), 5);
        assert!(!live.contains(&bc));
    }

    #[test]
    fn edge_iter_yields_recycled_slot() {
        // Slot order, not insertion order: a recycled slot reappears
        // at its original index, not at the end.
        let (mut g, [a, _, c], [_, _, bc, ..]) = triangle();
        g.del_edge(bc).unwrap();
        assert_eq!(g.edge_iter().count(), 5);
        let _ = a;
        let new = g.add_edge(c, c, 99, 0); // recycles bc's slot (self-loop: never collides with triangle)
        assert_eq!(new, bc);
        assert_eq!(g.edge_iter().count(), 6);
        // Slot 2 is back, with the new payload.
        let (_, e) = g.edge_iter().find(|&(id, _)| id == bc).unwrap();
        assert_eq!(e.weight, 99);
    }

    #[test]
    fn update_edge_preserves_id() {
        // The whole point: same EdgeId handle before and after.
        // Contrast with del+add which recycles (same index, but
        // semantically a delete-then-insert).
        let (mut g, [a, b, _], [ab, ..]) = triangle();
        assert_eq!(g.lookup_edge(a, b), Some(ab));
        g.update_edge(ab, 999, OPTION_INDIRECT).unwrap();
        // Same ID still resolves via the per-node index (which is
        // keyed on to_name, not weight).
        assert_eq!(g.lookup_edge(a, b), Some(ab));
        let e = g.edge(ab).unwrap();
        assert_eq!(e.weight, 999);
        assert_eq!(e.options, OPTION_INDIRECT);
    }

    #[test]
    fn update_edge_on_deleted_is_none() {
        let (mut g, _, [ab, ..]) = triangle();
        g.del_edge(ab).unwrap();
        assert_eq!(g.update_edge(ab, 1, 0), None);
    }

    #[test]
    fn update_edge_same_weight_is_noop_on_weight_order() {
        // The unlink/reinsert is gated on `weight != new_weight`.
        // Options-only update mustn't churn weight_order. Observable
        // via mst (which walks weight_order).
        let (mut g, _, [ab, ..]) = triangle();
        let before = g.mst();
        g.update_edge(ab, 10, OPTION_INDIRECT).unwrap(); // same weight
        assert_eq!(g.edge(ab).unwrap().options, OPTION_INDIRECT);
        assert_eq!(g.mst(), before);
    }

    #[test]
    fn update_edge_changes_mst_result() {
        // Triangle: ab=10, bc=20, ac=30. MST = {ab, bc} (cheapest two).
        // Bump ab to 100 → now ab is the most expensive. MST flips to
        // {bc, ac}. This proves weight_order was re-keyed, not just
        // the slot mutated.
        let (mut g, _, [ab, ba, bc, cb, ac, ca]) = triangle();

        let mst: Vec<_> = g.mst();
        assert!(mst.contains(&ab) && mst.contains(&ba));
        assert!(mst.contains(&bc) && mst.contains(&cb));
        assert!(!mst.contains(&ac));

        g.update_edge(ab, 100, 0).unwrap();
        g.update_edge(ba, 100, 0).unwrap();

        let mst: Vec<_> = g.mst();
        assert!(mst.contains(&bc) && mst.contains(&cb));
        assert!(mst.contains(&ac) && mst.contains(&ca));
        assert!(!mst.contains(&ab));
    }

    // sssp_sticky

    /// Diamond src─r1─dst / src─r2─dst. Both paths 2 hops; weight
    /// tie-break decides nexthop. The shape the edge-weight bench
    /// uses (src=a, r1=b, r2=c, dst=d).
    fn diamond(w_r1: i32, w_r2: i32) -> (Graph, [NodeId; 4]) {
        let mut g = Graph::new();
        let src = g.add_node("src");
        let r1 = g.add_node("r1");
        let r2 = g.add_node("r2");
        let dst = g.add_node("dst");
        for (a, b, w) in [
            (src, r1, w_r1),
            (src, r2, w_r2),
            // Far-side legs equal so only the src-side weight matters.
            (r1, dst, 10),
            (r2, dst, 10),
        ] {
            g.add_edge(a, b, w, 0);
            g.add_edge(b, a, w, 0);
        }
        (g, [src, r1, r2, dst])
    }

    #[test]
    fn sticky_keeps_prev_within_band() {
        // t0: r1=15 r2=35 → nexthop r1. t1: r1=40 r2=35 — r2 now
        // best (45 vs 50) but 50 ≤ 45×1.33=59.85 → STICK to r1.
        let (g0, [src, r1, _r2, dst]) = diamond(15, 35);
        let prev = g0.sssp(src);
        assert_eq!(prev[dst.0 as usize].unwrap().nexthop, r1);

        let (g1, _) = diamond(40, 35);
        let plain = g1.sssp(src);
        assert_ne!(
            plain[dst.0 as usize].unwrap().nexthop,
            r1,
            "BFS alone flips"
        );

        let sticky = g1.sssp_sticky(src, &prev);
        let r = sticky[dst.0 as usize].unwrap();
        assert_eq!(r.nexthop, r1, "within 33% band → keep old nexthop");
        assert_eq!(r.weighted_distance, 50, "carry old wdist for next compare");
    }

    #[test]
    fn sticky_switches_when_clearly_better() {
        // The connect-outlier case: r1 mis-measured at 197, true 15
        // on r2. 207 > 25×1.33 → must switch. Proves sssp-sticky
        // alone does not fix the SYN-retransmit bug (control variant).
        let (g0, [src, r1, r2, dst]) = diamond(197, 200);
        let prev = g0.sssp(src);
        assert_eq!(prev[dst.0 as usize].unwrap().nexthop, r1);

        let (g1, _) = diamond(197, 15);
        let sticky = g1.sssp_sticky(src, &prev);
        assert_eq!(
            sticky[dst.0 as usize].unwrap().nexthop,
            r2,
            ">33% improvement beats stickiness"
        );
    }

    #[test]
    fn sticky_ignored_when_old_nexthop_gone() {
        // Old nexthop r1 loses its meta-conn (src↔r1 edge deleted).
        // Stickiness must not pin a dead first hop.
        let (g0, [src, r1, r2, dst]) = diamond(15, 16);
        let prev = g0.sssp(src);
        assert_eq!(prev[dst.0 as usize].unwrap().nexthop, r1);

        let mut g1 = g0;
        let e = g1.lookup_edge(src, r1).unwrap();
        g1.del_edge(e).unwrap();
        let e = g1.lookup_edge(r1, src).unwrap();
        g1.del_edge(e).unwrap();

        let sticky = g1.sssp_sticky(src, &prev);
        assert_eq!(sticky[dst.0 as usize].unwrap().nexthop, r2);
    }

    #[test]
    fn sticky_ignored_on_hop_change() {
        // r1 path becomes 3 hops (insert mid). Different distance →
        // topology change → no stickiness even though weights close.
        let (g0, [src, r1, r2, dst]) = diamond(15, 16);
        let prev = g0.sssp(src);
        assert_eq!(prev[dst.0 as usize].unwrap().nexthop, r1);

        // New graph: src─r2─dst only at 2 hops; r1 reachable but
        // dst-via-r1 now 3 hops. BFS picks r2 at distance 2; old
        // route had distance 2 via r1 — but r1 is no longer a
        // first-hop neighbour of equal-hop dst path. Simplest model:
        // drop r1→dst so dst only via r2.
        let mut g1 = Graph::new();
        let s = g1.add_node("src");
        let b = g1.add_node("r1");
        let c = g1.add_node("r2");
        let d = g1.add_node("dst");
        assert_eq!((s, b, c, d), (src, r1, r2, dst)); // slot order stable
        for (a, bb, w) in [(s, b, 15), (s, c, 16), (c, d, 10)] {
            g1.add_edge(a, bb, w, 0);
            g1.add_edge(bb, a, w, 0);
        }
        let sticky = g1.sssp_sticky(src, &prev);
        assert_eq!(sticky[dst.0 as usize].unwrap().nexthop, r2);
    }

    #[test]
    fn sticky_empty_prev_is_plain_sssp() {
        let (g, [src, ..]) = diamond(15, 35);
        assert_eq!(g.sssp(src), g.sssp_sticky(src, &[]));
    }

    #[test]
    fn lookup_edge_finds_by_names() {
        let (g, [a, b, c], [ab, _, _, _, ac, _]) = triangle();
        assert_eq!(g.lookup_edge(a, b), Some(ab));
        assert_eq!(g.lookup_edge(a, c), Some(ac));
        assert_eq!(
            g.lookup_edge(b, c).map(|e| g.edge(e).unwrap().weight),
            Some(20)
        );
    }
}

// SSSP result → reachability transitions. `sssp` says visited or not; diffing
// against each node's previous `reachable` bit yields transitions the daemon
// turns into logs, host-up/down scripts, subnet updates, SPTPS resets and MTU
// timers (returned like `tinc_sptps::Output`). The one side effect kept here
// is writing `reachable` back, since the next `sssp` and `mst` read it.

/// One reachability transition for the daemon to act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Transition {
    /// `n->status.reachable` went false→true. Log `"Node %s became
    /// reachable"`, fire `host-up` script. The `via` is from the
    /// new `Route` — log line is actually
    /// `"became reachable"` without via, but `via` is what the
    /// daemon needs for the UDP-addr cache update later.
    BecameReachable { node: NodeId, via: NodeId },
    /// went true→false. Log `"became unreachable"`, fire
    /// `host-down`, `sptps_stop(&n->sptps)`, reset `n->mtuprobes`/
    /// `n->minmtu`/`n->maxmtu`, kill the MTU
    /// probe timer. No `via` — the route is `None`.
    BecameUnreachable { node: NodeId },
}

/// Diff old vs new reachability per node (skipping `myself`), write the new
/// bit back via [`Graph::set_reachable`] for the next sssp/mst, and return
/// the transitions. `new_routes` is slot-indexed like `sssp`'s output.
///
/// # Panics
/// If `new_routes` is shorter than the node slab; never for a fresh `sssp()`.
pub(crate) fn diff_reachability(
    graph: &mut Graph,
    myself: NodeId,
    new_routes: &[Option<Route>],
) -> Vec<Transition> {
    let mut out = Vec::new();

    // `node_ids()` yields only live slots. Collect first: the loop
    // body calls `set_reachable` (`&mut Graph`), can't hold the
    // iterator's `&Graph` borrow across it.
    let nodes: Vec<NodeId> = graph.node_ids().collect();

    for n in nodes {
        if n == myself {
            continue;
        }

        let route = new_routes.get(n.0 as usize).copied().flatten();
        let visited = route.is_some();
        let was_reachable = graph.node(n).is_some_and(|n| n.reachable);

        if visited == was_reachable {
            continue;
        }

        // Write-back before emitting — `mst()` in `run_graph` reads
        // this.
        graph.set_reachable(n, visited);

        if let Some(r) = route {
            out.push(Transition::BecameReachable {
                node: n,
                via: r.via,
            });
        } else {
            out.push(Transition::BecameUnreachable { node: n });
        }
    }

    out
}

/// Convenience: `sssp` + `diff` + `mst`. Returns (transitions,
/// mst-edges). The mst result feeds chunk
/// 5's `connection_t.status.mst` bit (broadcast tree).
///
/// Order matters: `sssp_bfs()` then `check_reachability()` then
/// `mst_kruskal()`. `mst` reads `reachable` to pick a starting
/// node, so the diff's write-back must land first.
#[must_use]
pub(crate) fn run_graph(
    graph: &mut Graph,
    myself: NodeId,
    prev_routes: &[Option<Route>],
) -> (Vec<Transition>, Vec<EdgeId>, Vec<Option<Route>>) {
    let routes = graph.sssp_sticky(myself, prev_routes);
    let transitions = diff_reachability(graph, myself, &routes);
    let mst = graph.mst();
    (transitions, mst, routes)
}

#[cfg(test)]
#[expect(clippy::many_single_char_names)] // graph node labels
mod glue_tests {
    use super::*;

    /// Chain a-b-c-d, all bidi. `a` is `myself`. All start
    /// `reachable=true` (the `add_node` default = steady state).
    fn chain() -> (Graph, [NodeId; 4]) {
        let mut g = Graph::new();
        let a = g.add_node("a");
        let b = g.add_node("b");
        let c = g.add_node("c");
        let d = g.add_node("d");
        g.add_edge(a, b, 1, 0);
        g.add_edge(b, a, 1, 0);
        g.add_edge(b, c, 1, 0);
        g.add_edge(c, b, 1, 0);
        g.add_edge(c, d, 1, 0);
        g.add_edge(d, c, 1, 0);
        (g, [a, b, c, d])
    }

    #[test]
    fn no_change_empty() {
        // Steady state: all reachable before, all reachable after.
        let (mut g, [a, ..]) = chain();
        let routes = g.sssp(a);
        let t = diff_reachability(&mut g, a, &routes);
        assert!(t.is_empty());
    }

    #[test]
    fn single_reachable() {
        // b starts unreachable (cold boot for that node). sssp
        // visits it → one BecameReachable transition.
        let (mut g, [a, b, ..]) = chain();
        g.set_reachable(b, false);
        let routes = g.sssp(a);
        let t = diff_reachability(&mut g, a, &routes);
        assert_eq!(
            t,
            vec![Transition::BecameReachable {
                node: b,
                // b is one hop, direct: via is b itself
                // (`via = indirect ? n->via : e->to`).
                via: b,
            }]
        );
    }

    #[test]
    fn single_unreachable() {
        // d was reachable; cut c-d, d goes None → BecameUnreachable.
        let (mut g, [a, _, c, d]) = chain();
        let cd = g.lookup_edge(c, d).unwrap();
        g.del_edge(cd).unwrap();
        let routes = g.sssp(a);
        assert!(routes[d.0 as usize].is_none());
        let t = diff_reachability(&mut g, a, &routes);
        assert_eq!(t, vec![Transition::BecameUnreachable { node: d }]);
    }

    #[test]
    fn myself_excluded() {
        // Even if myself's reachable bit somehow started false, no
        // transition is emitted and the bit is not written back
        // (`continue`s before the diff).
        let (mut g, [a, ..]) = chain();
        g.set_reachable(a, false);
        let routes = g.sssp(a);
        let t = diff_reachability(&mut g, a, &routes);
        assert!(t.is_empty());
        // Untouched — the `continue` skips the update.
        assert!(!g.node(a).unwrap().reachable);
    }

    #[test]
    fn set_reachable_persisted() {
        // Write-back happens inside the diff. After diff,
        // `graph.node(n).reachable` reflects new state.
        let (mut g, [a, b, c, d]) = chain();
        // b,c,d cold.
        g.set_reachable(b, false);
        g.set_reachable(c, false);
        g.set_reachable(d, false);
        let routes = g.sssp(a);
        diff_reachability(&mut g, a, &routes);
        assert!(g.node(b).unwrap().reachable);
        assert!(g.node(c).unwrap().reachable);
        assert!(g.node(d).unwrap().reachable);
    }

    #[test]
    fn cascade() {
        // Chain a-b-c-d, cut b-c. c and d both go unreachable in
        // one `run_graph` call. Tests that the diff walk emits
        // multiple transitions, not just the first.
        let (mut g, [a, b, c, d]) = chain();
        let bc = g.lookup_edge(b, c).unwrap();
        g.del_edge(bc).unwrap();

        let (t, mst, _routes) = run_graph(&mut g, a, &[]);

        // Order is `node_ids()` order (slot order = insertion order
        // here); nothing depends on transition order.
        assert_eq!(
            t,
            vec![
                Transition::BecameUnreachable { node: c },
                Transition::BecameUnreachable { node: d },
            ]
        );
        // b still reachable, untouched.
        assert!(g.node(b).unwrap().reachable);
        assert!(!g.node(c).unwrap().reachable);
        assert!(!g.node(d).unwrap().reachable);

        // MST after the cut: only a-b survives (c,d are now
        // `reachable=false`, so mst's starting-point search picks
        // a or b; the only spanning edge is a↔b). Both halves.
        assert_eq!(mst.len(), 2);
    }

    #[test]
    fn run_graph_mst_sees_writeback() {
        // Order: sssp, check_reachability, mst. mst reads
        // `reachable` to pick a start. If diff didn't write back,
        // mst on a cold-boot graph would
        // see `reachable=false` everywhere and pick wrong / nothing.
        let (mut g, [a, b, c, d]) = chain();
        // Cold boot: nobody reachable yet.
        for n in [a, b, c, d] {
            g.set_reachable(n, false);
        }
        let (t, mst, _routes) = run_graph(&mut g, a, &[]);
        // 3 transitions (b,c,d all came up; a is myself, excluded).
        assert_eq!(t.len(), 3);
        // 3 spanning edges × 2 halves = 6. Only works if mst saw
        // the written-back `reachable=true` bits.
        assert_eq!(mst.len(), 6);
    }
}
