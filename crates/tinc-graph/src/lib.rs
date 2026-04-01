//! `graph.c`: Kruskal's MST + BFS-based SSSP.
//!
//! ## What's here, what's not
//!
//! `graph.c` has three functions: `mst_kruskal`, `sssp_bfs`, and
//! `check_reachability`. The first two are graph algorithms with one
//! stray side-effect each (Kruskal sets `connection_t.status.mst`; BFS
//! calls `update_node_udp` under a gate). The third is *all*
//! side-effects: diffs `visited` against `reachable`, fires up/down
//! scripts, resets SPTPS sessions, kicks the MTU probe.
//!
//! Here we port the two algorithms. They produce per-node routing
//! results plus a list of MST edge IDs. `check_reachability` is daemon
//! territory — Phase 5.
//!
//! ## The arena
//!
//! `node_t` ↔ `edge_t` ↔ `connection_t` is a pointer rats' nest in C.
//! We use a slab + `u32` IDs — same shape, no borrow drama, no `Rc`
//! cycle headaches.
//!
//! `NodeId` / `EdgeId` are typed wrappers, not bare `u32`, so swapping
//! them is a compile error.
//!
//! ## Iteration order matters
//!
//! Two paths with equal `(distance, weighted_distance, indirect)` are
//! tie-broken by which edge was visited first. The C iterates a node's
//! edges via `splay_each` over a tree keyed on `to->name`. So the
//! tiebreak is alphabetical by destination. We sort the per-node edge
//! lists the same way.
//!
//! Kruskal walks `edge_weight_tree`, sorted by `(weight, from->name,
//! to->name)`. Same deal — `BTreeMap` with that key.
//!
//! ## The indirect→direct upgrade quirk
//!
//! `sssp_bfs` line 180:
//! ```c
//! if (e->to->status.visited && (!e->to->status.indirect || indirect)
//!     && (... distance/weight check ...)) continue;
//! ```
//!
//! That `!e->to->status.indirect || indirect` clause means: if the
//! target was previously reached *indirectly* and we now have a
//! *direct* path, *always* take the new path — even if the new
//! distance is worse. Directness trumps hop count. The KAT
//! `diamond_indirect` case verifies this: a node can end up with
//! `distance=3` after first being visited at `distance=1` indirectly.
//!
//! Subtle but load-bearing for UDP hole-punching: `via` (the last
//! direct relay) must be correct, and it's set from the path. A short
//! indirect path gives a wrong `via`.

#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]

use std::collections::{BTreeMap, VecDeque};

// ────────────────────────────────────────────────────────────────────
// IDs

/// Index into [`Graph`]'s node slab.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(pub u32);

/// Index into [`Graph`]'s edge slab.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EdgeId(pub u32);

/// `OPTION_INDIRECT` from `connection.h`. The one option bit BFS reads.
pub const OPTION_INDIRECT: u32 = 0x0001;

// ────────────────────────────────────────────────────────────────────
// Slab payloads. Minimal — just what the algorithms read.

/// One node. The C `node_t` is huge; this is the graph-relevant slice.
/// The daemon keeps the rest (SPTPS state, MTU probe, address cache)
/// in a parallel table keyed by `NodeId`.
#[derive(Debug, Clone)]
pub struct Node {
    /// Tie-break key. The C splay trees sort on `strcmp(name)`.
    pub name: String,

    /// Outgoing edges, sorted by destination name. C `node_t.edge_tree`
    /// is a splay tree keyed on `to->name`; we keep a sorted `Vec`
    /// (typical degree is small enough that linear insert beats
    /// `BTreeSet` overhead).
    edges: Vec<EdgeId>,

    /// `n->status.reachable` — *input* to the algorithms. Kruskal uses
    /// it to pick a starting point; SSSP uses it to gate the
    /// `update_node_udp` call (which we don't fire here, but the gate
    /// affects whether the call *would* fire — Phase 5's diff).
    /// Set by the *previous* SSSP via `check_reachability`.
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

// ────────────────────────────────────────────────────────────────────
// SSSP output. Side table — the C writes into `node_t` directly.

/// SSSP routing for one node, or `None` if unreachable from `myself`.
///
/// "Unreachable" maps to C `n->status.visited == false` after the BFS.
/// (`check_reachability` then flips `reachable` to match `visited`.)
#[derive(Debug, Clone, PartialEq, Eq)]
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

// ────────────────────────────────────────────────────────────────────
// The graph

/// Node + edge slabs, plus the weight-ordered edge index Kruskal walks.
#[derive(Debug, Default)]
pub struct Graph {
    nodes: Vec<Node>,
    edges: Vec<Edge>,
    /// `edge_weight_tree`: `(weight, from_name, to_name) → EdgeId`.
    /// `BTreeMap` for sorted iteration + `O(log n)` remove. Names
    /// cloned into the key — cheap (a few hundred bytes for typical
    /// meshes), avoids borrowing `nodes` while iterating `weight_order`.
    weight_order: BTreeMap<(i32, String, String), EdgeId>,
}

impl Graph {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// `node_tree.insert`. `reachable` defaults true (steady state).
    ///
    /// # Panics
    /// On more than `u32::MAX` nodes — not a realistic limit; tinc
    /// meshes are tens to hundreds.
    pub fn add_node(&mut self, name: impl Into<String>) -> NodeId {
        let id = NodeId(u32::try_from(self.nodes.len()).expect("u32 nodes"));
        self.nodes.push(Node {
            name: name.into(),
            edges: Vec::new(),
            reachable: true,
        });
        id
    }

    /// `edge_add`: insert into `from.edge_tree` and `edge_weight_tree`,
    /// link `reverse` if the twin already exists.
    ///
    /// # Panics
    /// On more than `u32::MAX` edges. Not a realistic concern; tinc
    /// meshes are tens to hundreds of nodes.
    pub fn add_edge(&mut self, from: NodeId, to: NodeId, weight: i32, options: u32) -> EdgeId {
        let id = EdgeId(u32::try_from(self.edges.len()).expect("u32 edges"));

        // Find reverse: an edge from `to` whose destination is `from`.
        // C does `lookup_edge(to, from)` via `to.edge_tree`.
        let reverse = self.nodes[to.0 as usize]
            .edges
            .iter()
            .copied()
            .find(|&eid| self.edges[eid.0 as usize].to == from);
        if let Some(r) = reverse {
            self.edges[r.0 as usize].reverse = Some(id);
        }

        let to_name = self.nodes[to.0 as usize].name.clone();
        let from_name = self.nodes[from.0 as usize].name.clone();

        self.edges.push(Edge {
            from,
            to,
            weight,
            options,
            reverse,
            to_name: to_name.clone(),
        });

        // Per-node edge list, sorted by `to_name`. The cache in `Edge`
        // is what makes this comparator work without borrowing `nodes`.
        let from_edges = &mut self.nodes[from.0 as usize].edges;
        let edges = &self.edges;
        let pos = from_edges.partition_point(|&eid| edges[eid.0 as usize].to_name < to_name);
        from_edges.insert(pos, id);

        // Global weight-ordered index.
        self.weight_order.insert((weight, from_name, to_name), id);

        id
    }

    /// `n->status.reachable = r`. Daemon calls after diffing SSSP results.
    pub fn set_reachable(&mut self, n: NodeId, r: bool) {
        self.nodes[n.0 as usize].reachable = r;
    }

    #[must_use]
    pub fn node(&self, n: NodeId) -> &Node {
        &self.nodes[n.0 as usize]
    }

    #[must_use]
    pub fn edge(&self, e: EdgeId) -> &Edge {
        &self.edges[e.0 as usize]
    }

    /// All node IDs, stable (insertion) order. Safe by construction —
    /// [`Self::add_node`] enforces the `u32` bound.
    #[allow(clippy::missing_panics_doc)]
    pub fn node_ids(&self) -> impl ExactSizeIterator<Item = NodeId> + '_ {
        (0..u32::try_from(self.nodes.len()).unwrap()).map(NodeId)
    }

    // ────────────────────────────────────────────────────────────────
    // sssp_bfs

    /// `sssp_bfs`. Returns one `Option<Route>` per node, indexed by
    /// `NodeId.0`. `None` = unreachable from `myself`.
    ///
    /// Port is line-by-line from `graph.c:125-211`. The revisit
    /// condition (lines 180-183) is the part that needs care:
    ///
    /// ```c
    /// if (e->to->status.visited
    ///     && (!e->to->status.indirect || indirect)
    ///     && (e->to->distance != n->distance + 1
    ///         || e->to->weighted_distance <= n->weighted_distance + e->weight))
    ///     continue;
    /// ```
    ///
    /// In English: skip if already visited **and** (already direct, or
    /// new path is also indirect) **and** (different hop count, or new
    /// path isn't lighter). I.e. revisit when (1) indirect→direct, or
    /// (2) same hop count, lighter weight.
    #[must_use]
    #[allow(clippy::missing_panics_doc)] // unwraps are on enqueued (⇒ visited) IDs
    pub fn sssp(&self, myself: NodeId) -> Vec<Option<Route>> {
        let n_nodes = self.nodes.len();
        let mut route: Vec<Option<Route>> = vec![None; n_nodes];

        // `myself`'s entry. C lines 138-145.
        route[myself.0 as usize] = Some(Route {
            indirect: false,
            distance: 0,
            weighted_distance: 0,
            nexthop: myself,
            via: myself,
            prevedge: None,
            options: 0, // C never writes myself->options in sssp; reads stale
        });

        // The C uses a `list_t` and the `list_each` macro that
        // re-reads `node->next` after the body — so `list_insert_tail`
        // mid-iteration works. `VecDeque` push_back during pop_front
        // is the same.
        let mut todo = VecDeque::new();
        todo.push_back(myself);

        while let Some(n) = todo.pop_front() {
            // The body needs `route[n]` immutable while writing
            // `route[e.to]` mutable. Snapshot the bits we read.
            // (C just deref's pointers; we have to convince borrowck.)
            let (n_distance, n_wdist, n_indirect, n_nexthop, n_via) = {
                let r = route[n.0 as usize].as_ref().unwrap();
                (
                    r.distance,
                    r.weighted_distance,
                    r.indirect,
                    r.nexthop,
                    r.via,
                )
            };

            for &eid in &self.nodes[n.0 as usize].edges {
                let e = &self.edges[eid.0 as usize];

                // C line 159: `if(!e->reverse || e->to == myself) continue;`
                if e.reverse.is_none() || e.to == myself {
                    continue;
                }

                // C line 178: indirect propagates, OPTION_INDIRECT adds.
                let indirect = n_indirect || (e.options & OPTION_INDIRECT) != 0;

                let cand_hops = n_distance + 1;
                let cand_wdist = n_wdist.wrapping_add(e.weight);

                // The revisit condition. C lines 180-184.
                if let Some(prev) = &route[e.to.0 as usize] {
                    // visited. Skip if (already direct OR new indirect)
                    // AND (different hop OR not lighter).
                    let directness_unchanged = !prev.indirect || indirect;
                    let not_lighter =
                        prev.distance != cand_hops || prev.weighted_distance <= cand_wdist;
                    if directness_unchanged && not_lighter {
                        continue;
                    }
                }

                // C lines 188-191: nexthop and weighted_distance update
                // only if first visit OR (same hop, lighter weight).
                // The indirect→direct upgrade case *doesn't* update
                // nexthop — it keeps the old one. But it *does* update
                // distance, prevedge, via, options. Yes, this means
                // distance can go *up* and nexthop stays. The KAT pins it.
                let prev = route[e.to.0 as usize].as_ref();
                let update_nexthop = prev.is_none()
                    || (prev.unwrap().distance == cand_hops
                        && prev.unwrap().weighted_distance > cand_wdist);

                let (nexthop, weighted_distance) = if update_nexthop {
                    (
                        // C: `(n->nexthop == myself) ? e->to : n->nexthop`
                        if n_nexthop == myself { e.to } else { n_nexthop },
                        cand_wdist,
                    )
                } else {
                    let p = prev.unwrap();
                    (p.nexthop, p.weighted_distance)
                };

                // C lines 193-198: unconditional. `distance` is
                // *always* set to `n->distance + 1` here, even if the
                // old one was smaller. `via` is propagated or fresh
                // depending on `indirect`.
                route[e.to.0 as usize] = Some(Route {
                    indirect,
                    distance: cand_hops,
                    weighted_distance,
                    nexthop,
                    via: if indirect { n_via } else { e.to },
                    prevedge: Some(eid),
                    options: e.options,
                });

                // C line 200-202: the `update_node_udp` gate.
                // Suppressed here — daemon side-effect. The condition
                // is `!reachable || (target had AF_UNSPEC and edge has
                // a real address)`. We don't track addresses; the
                // daemon checks against its own table.
                //
                // (We could emit `(NodeId, EdgeId)` pairs for the
                // daemon to act on. Not yet — no consumer.)

                // C line 204: re-enqueue. `list_insert_tail` — the
                // `list_each` macro picks it up because it re-reads
                // `next` after the body. We get the same with
                // `push_back` into a deque drained from the front.
                //
                // This *can* enqueue a node multiple times (e.g. on
                // indirect→direct upgrade, after it's already been
                // dequeued once). The C does the same; the second
                // visit's edge loop will mostly hit the skip branch.
                todo.push_back(e.to);
            }
        }

        route
    }

    // ────────────────────────────────────────────────────────────────
    // mst_kruskal

    /// `mst_kruskal`. Returns the set of edges whose `connection_t`
    /// would have `status.mst = true`.
    ///
    /// The C is Kruskal without union-find — it walks edges in weight
    /// order, takes each edge that connects an unvisited node to a
    /// visited one (a "safe edge" in the textbook sense), and *rewinds
    /// to the start* whenever it makes progress after a skip. That
    /// rewind is the key trick: a light edge between two unvisited
    /// nodes gets skipped on the first pass, then picked up after a
    /// heavier edge connects one of them.
    ///
    /// The starting point is the `from` node of the first edge in
    /// weight order whose `from` is `reachable`. (Uses `reachable` as
    /// set by the previous `check_reachability`, i.e. last SSSP's
    /// `visited`.)
    ///
    /// Both the edge *and* its reverse get their connection's `mst`
    /// bit set. We return both `EdgeId`s.
    #[must_use]
    #[allow(clippy::missing_panics_doc)] // reverse.unwrap() guarded two lines up
    pub fn mst(&self) -> Vec<EdgeId> {
        let mut visited = vec![false; self.nodes.len()];
        let mut mst_edges = Vec::new();

        // C: walk edge_weight_tree, find first reachable `from`, mark.
        for &eid in self.weight_order.values() {
            let from = self.edges[eid.0 as usize].from;
            if self.nodes[from.0 as usize].reachable {
                visited[from.0 as usize] = true;
                break;
            }
        }

        // C: linear walk with `next = head` rewind on
        // skipped→progress. We use an index and reset it.
        //
        // The C `splay_each` macro reads `next = node->next` *before*
        // the body, then after the body does `node = next`. The rewind
        // assigns `next = edge_weight_tree.head`, so the next iteration
        // starts from the head. We collect the order once (it doesn't
        // change mid-walk) and index.
        let order: Vec<EdgeId> = self.weight_order.values().copied().collect();
        let mut i = 0;
        let mut skipped = false;

        while i < order.len() {
            let eid = order[i];
            let e = &self.edges[eid.0 as usize];

            let v_from = visited[e.from.0 as usize];
            let v_to = visited[e.to.0 as usize];

            // C: `if(!e->reverse || (e->from->status.visited == e->to->status.visited))`
            if e.reverse.is_none() || v_from == v_to {
                skipped = true;
                i += 1;
                continue;
            }

            visited[e.from.0 as usize] = true;
            visited[e.to.0 as usize] = true;

            // Both directions get the mst bit. Reverse exists (checked above).
            mst_edges.push(eid);
            mst_edges.push(e.reverse.unwrap());

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

// ────────────────────────────────────────────────────────────────────
// Unit tests for invariants. KAT differential tests live in
// tests/kat.rs.

#[cfg(test)]
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
        let names: Vec<_> = g.nodes[0]
            .edges
            .iter()
            .map(|&e| g.edges[e.0 as usize].to_name.as_str())
            .collect();
        assert_eq!(names, ["b", "z"]);
    }

    #[test]
    fn reverse_auto_links() {
        let mut g = Graph::new();
        let a = g.add_node("a");
        let b = g.add_node("b");
        let e1 = g.add_edge(a, b, 1, 0);
        assert!(g.edge(e1).reverse.is_none()); // twin not yet present
        let e2 = g.add_edge(b, a, 1, 0);
        assert_eq!(g.edge(e2).reverse, Some(e1));
        assert_eq!(g.edge(e1).reverse, Some(e2)); // back-linked
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
}
