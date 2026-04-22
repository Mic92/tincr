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
/// Sourced from [`crate::dispatch::ConnOptions::INDIRECT`] so the bit
/// value lives in exactly one place.
pub const OPTION_INDIRECT: u32 = crate::dispatch::ConnOptions::INDIRECT.bits();

/// Stickiness band for [`Graph::sssp_sticky`]: keep the previous
/// nexthop if its path cost is within this percent of the new best.
/// 133 ≡ "new must be ≥33 % cheaper to win" — Tailscale's DERP-home
/// hysteresis (`netcheck.go:1453`).
pub const STICKY_THRESHOLD_PCT: i32 = 133;

/// Stickiness post-pass for [`Graph::sssp_sticky`].
///
/// `sticky_wdist[n]` is `Some(w)` iff the BFS discovered an equal-hop
/// path to `n` whose first hop is `prev[n].nexthop`, with cumulative
/// weight `w`. That is the ONLY safe stickiness: the old nexthop
/// provably still reaches `n` at the same hop count in the current
/// graph. Checking merely "old nexthop is still a neighbour" is not
/// enough — the far-side edge may be gone, and pinning it would loop.
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
        let Some(sticky_w) = sticky_wdist[slot] else {
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

// ────────────────────────────────────────────────────────────────────
// Slab payloads. Minimal — just what the algorithms read.

/// One node. This is the graph-relevant slice of the daemon's node
/// state. The daemon keeps the rest (SPTPS state, MTU probe, address
/// cache)
/// in a parallel table keyed by `NodeId`.
#[derive(Debug, Clone)]
pub struct Node {
    /// Tie-break key. The C splay trees sort on `strcmp(name)`.
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

// ────────────────────────────────────────────────────────────────────
// SSSP output. Side table — the C writes into `node_t` directly.

/// SSSP routing for one node, or `None` if unreachable from `myself`.
///
/// "Unreachable" means the BFS never visited the node.
/// (`check_reachability` then flips `reachable` to match `visited`.)
///
/// `Copy`: 32 bytes, all-Copy fields. The daemon snapshots the routes
/// vector behind `Arc`; by-value lookup avoids a borrow chain through
/// the `Arc` deref at every read site.
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

// ────────────────────────────────────────────────────────────────────
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

/// Index into the slabs. Slot may be `None` (freed) — hence the
/// `Option` indirection. Macro because we'd otherwise repeat
/// `self.edges[e.0 as usize].as_ref().unwrap()` two dozen times, and
/// half the time it's `as_mut`, and `.expect("live")` everywhere is
/// noise. Live-slot expectation is documented at each call site by
/// the surrounding logic (e.g. "just got this ID off the BFS queue").
macro_rules! slot {
    ($slab:expr_2021, $id:expr_2021) => {
        $slab[$id.0 as usize].as_ref().expect("live slot")
    };
    (mut $slab:expr_2021, $id:expr_2021) => {
        $slab[$id.0 as usize].as_mut().expect("live slot")
    };
}

/// Reserve a slot in a slab: recycle from `free` (LIFO) or push a new
/// `None`. Returns the index; caller writes the value.
fn alloc_slot<T>(slab: &mut Vec<Option<T>>, free: &mut Vec<u32>) -> u32 {
    if let Some(idx) = free.pop() {
        debug_assert!(slab[idx as usize].is_none());
        idx
    } else {
        let idx = u32::try_from(slab.len()).expect("u32 slots");
        slab.push(None);
        idx
    }
}

impl Graph {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// `node_tree.insert`. `reachable` defaults true (steady state).
    /// Recycles a freed slot if one exists (LIFO).
    ///
    /// # Panics
    /// On more than `u32::MAX` nodes — not a realistic limit; tinc
    /// meshes are tens to hundreds.
    pub fn add_node(&mut self, name: impl Into<String>) -> NodeId {
        let idx = alloc_slot(&mut self.nodes, &mut self.node_free);
        self.nodes[idx as usize] = Some(Node {
            name: name.into(),
            edges: Vec::new(),
            reachable: true,
        });
        NodeId(idx)
    }

    /// `edge_add`: insert into `from.edge_tree` and `edge_weight_tree`,
    /// link `reverse` if the twin already exists.
    ///
    /// # Panics
    /// On more than `u32::MAX` edges. Not a realistic concern; tinc
    /// meshes are tens to hundreds of nodes.
    pub fn add_edge(&mut self, from: NodeId, to: NodeId, weight: i32, options: u32) -> EdgeId {
        // We don't dedup; per-node list would get two
        // entries with same `to_name` (binary_search_by → unspecified
        // match), and weight_order would silently drop the old EdgeId.
        // Daemon discipline holds (on_add_edge does lookup_edge first,
        // on_ack does terminate→del_edge first); this is a tripwire.
        debug_assert!(
            self.lookup_edge(from, to).is_none(),
            "duplicate edge {from:?}→{to:?}"
        );
        let id = EdgeId(alloc_slot(&mut self.edges, &mut self.edge_free));

        // Find reverse: an edge from `to` whose destination is `from`.
        // C does `lookup_edge(to, from)` via `to.edge_tree`.
        let reverse = slot!(self.nodes, to)
            .edges
            .iter()
            .copied()
            .find(|&eid| slot!(self.edges, eid).to == from);
        if let Some(r) = reverse {
            slot!(mut self.edges, r).reverse = Some(id);
        }

        let to_name = slot!(self.nodes, to).name.clone();
        let from_name = slot!(self.nodes, from).name.clone();

        self.edges[id.0 as usize] = Some(Edge {
            from,
            to,
            weight,
            options,
            reverse,
            to_name: to_name.clone(),
        });

        // Per-node edge list, sorted by `to_name`. The cache in `Edge`
        // is what makes this comparator work without borrowing `nodes`.
        let edges = &self.edges;
        let from_edges = &mut slot!(mut self.nodes, from).edges;
        let pos = from_edges.partition_point(|&eid| slot!(edges, eid).to_name < to_name);
        from_edges.insert(pos, id);

        // Global weight-ordered index.
        self.weight_order.insert((weight, from_name, to_name), id);

        id
    }

    /// Delete an edge. Unlinks the twin's `reverse`, removes from the
    /// per-node sorted list and `weight_order`, frees the slot.
    ///
    /// Returns `None` if the slot was already freed. The C would
    /// dereference a dangling pointer (UB); we no-op. Chosen over
    /// panic because daemon teardown can hit double-delete races
    /// (connection close + `del_edge_h` arriving close together) and
    /// a no-op is the conservative choice. Callers that care can
    /// check the return.
    ///
    /// # Panics
    /// If the edge is live but its `from` node is freed, or its
    /// per-node-list / `weight_order` entry is missing. Both are arena
    /// invariants this module maintains; a panic means a bug here, not
    /// in the caller.
    pub fn del_edge(&mut self, e: EdgeId) -> Option<()> {
        // Read what we need *before* mutating the slab. The per-node
        // edge list still contains `e` itself; the binary-search
        // comparator below will deref `e`'s slot, so it must stay live
        // until after the list-remove. `take()` comes last.
        let (from, to_name, weight, reverse) = {
            let edge = self.edges[e.0 as usize].as_ref()?;
            (edge.from, edge.to_name.clone(), edge.weight, edge.reverse)
        };

        // Unlink twin's back-pointer.
        if let Some(r) = reverse {
            slot!(mut self.edges, r).reverse = None;
        }

        // Per-node list is sorted by `to_name`; binary-search the slot
        // out. The `from` node must be live — deleting an edge whose
        // origin is gone is a caller bug (and the C would crash too).
        let edges = &self.edges;
        let from_edges = &mut slot!(mut self.nodes, from).edges;
        let pos = from_edges
            .binary_search_by(|&eid| slot!(edges, eid).to_name.as_str().cmp(&to_name))
            .expect("edge in from's list");
        from_edges.remove(pos);

        // Recompute the weight-order key. `from_name` we don't cache
        // (only `to_name`
        // is needed for the sort comparator); look it up. Cheaper than
        // a third name clone on every edge.
        let from_name = slot!(self.nodes, from).name.clone();
        self.weight_order.remove(&(weight, from_name, to_name));

        self.edges[e.0 as usize] = None;
        self.edge_free.push(e.0);
        Some(())
    }

    /// Delete a node. Cascades: deletes all the node's outgoing edges
    /// first (their twins become reverseless), then frees the slot.
    ///
    /// Does **not** hunt down *incoming* edges. The C doesn't either:
    /// `node_del` walks `n->edge_tree` only. Any edge with `to ==`
    /// this node becomes a dangling reference; the protocol layer
    /// (`del_edge_h`) is responsible for deleting both halves of a
    /// pair before the node itself is purged. That said, the cascade
    /// nulls the twin's `reverse`, and `sssp`/`mst` skip reverseless
    /// edges — so a dangling `to` is invisible to the algorithms.
    ///
    /// Returns `None` if already freed (same rationale as
    /// [`Self::del_edge`]).
    ///
    /// Subnet cascade is not here — subnets are daemon-side, not in
    /// this crate.
    pub fn del_node(&mut self, n: NodeId) -> Option<()> {
        // Can't `take` yet — `del_edge` needs the node live to look
        // up `from_name` and edit `from_edges`. Check liveness, drain
        // edges, *then* take. Drain a snapshot to avoid iterator
        // invalidation during `del_edge`.
        let outgoing: Vec<EdgeId> = self.nodes[n.0 as usize].as_ref()?.edges.clone();
        for e in outgoing {
            self.del_edge(e);
        }

        self.nodes[n.0 as usize] = None;
        self.node_free.push(n.0);
        Some(())
    }

    /// In-place edge update. Mutates `options` directly; re-keys
    /// `weight_order` only if weight changed (weight is the sort key
    /// there). Does *not* touch the per-node index — that's keyed on
    /// `to_name` alone, so a weight change doesn't break it. Mutate
    /// the slot, re-key
    /// `weight_order` if weight moved, leave `from.edges` untouched.
    ///
    /// Returns `None` if the slot is freed (stale `EdgeId`).
    ///
    /// **Why this exists** when del+add already works (`gossip::on_add_edge`):
    /// `EdgeId` stability. del+add recycles the slot — same index, but
    /// any parallel table keyed on `EdgeId` (e.g. `Daemon::edge_addrs`
    /// for `e->address`)
    /// would see a delete+insert. `update_edge` is one slot write; the
    /// ID is the same handle before and after.
    ///
    /// # Panics
    /// If the edge is live but its `from` node is freed, or its
    /// `weight_order` entry is missing. Arena invariants.
    pub fn update_edge(&mut self, e: EdgeId, weight: i32, options: u32) -> Option<()> {
        let edge = self.edges[e.0 as usize].as_mut()?;
        edge.options = options;
        if edge.weight == weight {
            return Some(());
        }
        // Weight changed: re-key `weight_order` (unlink, reinsert).
        let old_weight = edge.weight;
        edge.weight = weight;
        let to_name = edge.to_name.clone();
        let from_name = slot!(self.nodes, edge.from).name.clone();
        self.weight_order
            .remove(&(old_weight, from_name.clone(), to_name.clone()))
            .expect("edge in weight_order");
        self.weight_order.insert((weight, from_name, to_name), e);
        Some(())
    }

    /// Find the edge `from → to` if it exists. Searches the per-node
    /// list keyed on `to_name`.
    #[must_use]
    pub fn lookup_edge(&self, from: NodeId, to: NodeId) -> Option<EdgeId> {
        let to_name = self.nodes[to.0 as usize].as_ref()?.name.as_str();
        let from_edges = &self.nodes[from.0 as usize].as_ref()?.edges;
        let edges = &self.edges;
        from_edges
            .binary_search_by(|&eid| slot!(edges, eid).to_name.as_str().cmp(to_name))
            .ok()
            .map(|i| from_edges[i])
    }

    /// `n->status.reachable = r`. Daemon calls after diffing SSSP results.
    ///
    /// # Panics
    /// If `n` is a freed slot. The daemon walks `sssp` results indexed
    /// by live `NodeId`; a freed ID here is a bug.
    pub fn set_reachable(&mut self, n: NodeId, r: bool) {
        slot!(mut self.nodes, n).reachable = r;
    }

    /// `None` if the slot was freed (stale `NodeId`).
    #[must_use]
    pub fn node(&self, n: NodeId) -> Option<&Node> {
        self.nodes.get(n.0 as usize)?.as_ref()
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
    /// free-list, `nodes.len()` counts holes too. The daemon's `sssp`
    /// result vector is still `nodes.len()` long (indexed by raw slot,
    /// dead slots get `None` routes); use `.len()` on that if you need
    /// a count.
    #[expect(clippy::missing_panics_doc)] // u32::try_from on a u32-bounded len
    pub fn node_ids(&self) -> impl Iterator<Item = NodeId> + '_ {
        (0..u32::try_from(self.nodes.len()).unwrap())
            .filter(|&i| self.nodes[i as usize].is_some())
            .map(NodeId)
    }

    /// Dump all edges. Nested walk — outer over nodes (alphabetical
    /// by node name), inner over each node's edges (alphabetical by
    /// `to_name`). We
    /// have a flat slab; this yields slot order (insertion-then-recycle).
    ///
    /// **Order divergence is intentional**: `tincctl.c` reads dump rows
    /// into an unordered set and the CLI sorts client-side before
    /// display. The wire format is one edge per line, no inter-row
    /// dependency. Slab order is one pass over `Vec<Option<Edge>>`,
    /// no per-node indirection.
    ///
    /// Each direction is its own `Edge` (the C has separate `edge_t`s
    /// for `a→b` and `b→a`), so a bidi link yields two items here —
    /// matches `dump_edges`' per-direction `send_request`.
    pub fn edge_iter(&self) -> impl Iterator<Item = (EdgeId, &Edge)> + '_ {
        self.edges.iter().enumerate().filter_map(|(i, slot)| {
            #[expect(clippy::cast_possible_truncation)] // slab is u32-bounded
            slot.as_ref().map(|e| (EdgeId(i as u32), e))
        })
    }

    /// Outgoing edges of `n`, sorted by destination name. Empty slice
    /// for freed slots.
    #[must_use]
    pub fn node_edges(&self, n: NodeId) -> &[EdgeId] {
        self.nodes
            .get(n.0 as usize)
            .and_then(Option::as_ref)
            .map_or(&[], |node| node.edges.as_slice())
    }

    // ────────────────────────────────────────────────────────────────
    // sssp_bfs

    /// `sssp_bfs`. Returns one `Option<Route>` per node, indexed by
    /// `NodeId.0`. `None` = unreachable from `myself`.
    ///
    /// The revisit condition is the part that needs care:
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
    pub fn sssp(&self, myself: NodeId) -> Vec<Option<Route>> {
        self.sssp_sticky(myself, &[])
    }

    /// [`sssp`](Self::sssp) with Tailscale-style nexthop stickiness.
    ///
    /// After the BFS, for every node whose `nexthop` would change
    /// versus `prev`: if the previous route is still valid (same hop
    /// count, same `indirect`) and its `weighted_distance` is within
    /// [`STICKY_THRESHOLD_PCT`] % of the freshly-computed best, keep
    /// the previous `nexthop`/`weighted_distance` instead of
    /// switching. Pure local damping — absorbs weight jitter without
    /// any re-gossip. Does NOT override hop-count or indirect→direct
    /// changes (those are topology, not metric noise).
    ///
    /// `prev` is the last `sssp` result (slot-indexed, same shape).
    /// Shorter/empty `prev` (first run, or graph grew) means no
    /// stickiness for the uncovered slots — plain BFS result.
    ///
    /// Analogue: Tailscale `netcheck.go:1453` (DERP home sticky
    /// unless new region beats old by ≥33 %).
    #[must_use]
    #[expect(clippy::missing_panics_doc)] // unwraps are on enqueued (⇒ visited) IDs
    pub fn sssp_sticky(&self, myself: NodeId, prev: &[Option<Route>]) -> Vec<Option<Route>> {
        // Helper: previous nexthop for slot `n`, if any.
        let prev_nh = |n: NodeId| {
            prev.get(n.0 as usize)
                .and_then(Option::as_ref)
                .map(|r| r.nexthop)
        };
        // Result is indexed by raw slot number, including freed slots
        // (they stay `None`). The daemon zips this against `node_ids()`
        // and never reads dead slots.
        let n_nodes = self.nodes.len();
        let mut route: Vec<Option<Route>> = vec![None; n_nodes];
        // Per-node: cheapest equal-hop wdist via the PREVIOUS nexthop,
        // if the BFS encounters one. Consumed by `sticky_post_pass`.
        let mut sticky_wdist: Vec<Option<i32>> = vec![None; n_nodes];

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

            for &eid in &slot!(self.nodes, n).edges {
                let e = slot!(self.edges, eid);

                // C line 159: `if(!e->reverse || e->to == myself) continue;`
                if e.reverse.is_none() || e.to == myself {
                    continue;
                }

                // C line 178: indirect propagates, OPTION_INDIRECT adds.
                let indirect = n_indirect || (e.options & OPTION_INDIRECT) != 0;

                let cand_hops = n_distance + 1;
                let cand_wdist = n_wdist.wrapping_add(e.weight);
                let cand_nexthop = if n_nexthop == myself { e.to } else { n_nexthop };

                // Stickiness bookkeeping: record the cheapest wdist of
                // any candidate that (a) arrives via this node's
                // PREVIOUS nexthop and (b) is at the same hop count as
                // whatever the BFS ultimately picks. (b) is enforced
                // by only recording when first-visit OR same-hop
                // revisit — BFS never lowers `distance` after first
                // visit, and the indirect→direct upgrade (which CAN
                // raise it) doesn't touch nexthop so stickiness is
                // moot there. Recorded BEFORE the skip so the
                // "heavier equal-hop alternative" case (the whole
                // point) isn't lost.
                if Some(cand_nexthop) == prev_nh(e.to) {
                    let same_hop = route[e.to.0 as usize]
                        .as_ref()
                        .is_none_or(|p| p.distance == cand_hops);
                    if same_hop {
                        let slot = &mut sticky_wdist[e.to.0 as usize];
                        *slot = Some(slot.map_or(cand_wdist, |w| w.min(cand_wdist)));
                    }
                }

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
                    (cand_nexthop, cand_wdist)
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

                // C line 200-202 (`update_node_udp`): daemon side-effect,
                // suppressed here — we don't track addresses.

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

        if !prev.is_empty() {
            sticky_post_pass(&mut route, prev, &sticky_wdist);
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
    #[expect(clippy::missing_panics_doc)] // reverse.unwrap() guarded two lines up
    pub fn mst(&self) -> Vec<EdgeId> {
        let mut visited = vec![false; self.nodes.len()];
        let mut mst_edges = Vec::new();

        // Walk weight order, find first reachable `from`, mark.
        // `weight_order` only holds live edges (`del_edge` removes),
        // so `slot!` is safe here.
        for &eid in self.weight_order.values() {
            let from = slot!(self.edges, eid).from;
            if slot!(self.nodes, from).reachable {
                visited[from.0 as usize] = true;
                break;
            }
        }

        // Linear walk with rewind-to-head on skipped→progress. We use
        // an index and reset it.
        //
        // The rewind assigns the index back to 0, so the next iteration
        // starts from the head. We collect the order once (it doesn't
        // change mid-walk) and index.
        let order: Vec<EdgeId> = self.weight_order.values().copied().collect();
        let mut i = 0;
        let mut skipped = false;

        while i < order.len() {
            let eid = order[i];
            let e = slot!(self.edges, eid);

            let v_from = visited[e.from.0 as usize];
            let v_to = visited[e.to.0 as usize];

            // Skip if no reverse twin, or both endpoints have the same
            // visited state (already in tree, or both unreachable).
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

    // ────────────────────────────────────────────────────────────────
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
        // The C would deref a dangling pointer here. We return None.
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

    // ────────────────────────────────────────────────────────────────
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

    // ────────────────────────────────────────────────────────────────
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
        // alone does NOT fix the SYN-retransmit bug (control variant).
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
        // Stickiness must NOT pin a dead first hop.
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

// ────────────────────────────────────────────────────────────────────
// `graph()` glue: SSSP result → reachability transitions.
//
// `sssp` runs the BFS and returns `Vec<Option<Route>>` — `Some` =
// `n->status.visited`, `None` = unvisited. The C then walks
// `node_tree` and diffs `visited` against the *previous* `reachable`
// bit. A flip in either direction is a transition: log line,
// host-up/host-down script, subnet-up/down, SPTPS reset, MTU probe
// timer reset.
//
// All of those touch daemon state outside the graph (`process.c`
// script spawn, per-node SPTPS sessions, timer wheel). Same pattern
// as `tinc_sptps::Output`: return a `Vec<Transition>`, daemon match-
// arms grow as later chunks land.
//
// The one side-effect that *does* belong here: writing the new
// `reachable` bit back into the `Graph`. The next `sssp` reads it
// (gates `update_node_udp` on `!n->status.reachable`), and `mst`
// picks its starting point from it. So [`diff_reachability`]
// persists before returning.

/// One reachability transition. The daemon turns these into log
/// lines + script spawns + per-node-SPTPS resets.
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

/// `check_reachability`. Diffs old vs new reachability per node.
/// WRITES BACK [`Graph::set_reachable`] so the next sssp's
/// `update_node_udp` gate reads the updated bit. Returns
/// transitions for the daemon to act on.
///
/// `myself` is excluded. `myself` always has a route (sssp seeds
/// it) so its `reachable` never flips, but we skip it before the
/// diff anyway — never
/// emit a transition for it, never touch its bit.
///
/// `new_routes` is indexed by raw slot number (same as `sssp`'s
/// return). Dead slots are `None` and are skipped via `node_ids()`.
///
/// # Panics
/// If `new_routes` is shorter than the graph's node slab, or if a
/// `NodeId` from `node_ids()` reads a freed slot. Neither happens
/// when `new_routes` is a fresh `sssp()` result on the same graph.
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

        // `visited` ⇔ `new_routes[n].is_some()`.
        let visited = new_routes[n.0 as usize].is_some();
        // `node()` is `Some` — `n` came from `node_ids()`.
        let was_reachable = graph.node(n).expect("live").reachable;

        if visited == was_reachable {
            continue;
        }

        // Write-back BEFORE emitting — `mst()` in `run_graph` reads
        // this.
        graph.set_reachable(n, visited);

        if visited {
            // Route is `Some` (just checked).
            let via = new_routes[n.0 as usize].as_ref().expect("visited").via;
            out.push(Transition::BecameReachable { node: n, via });
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
        // transition is emitted and the bit is NOT written back
        // (`continue`s before the diff).
        let (mut g, [a, ..]) = chain();
        g.set_reachable(a, false);
        let routes = g.sssp(a);
        let t = diff_reachability(&mut g, a, &routes);
        assert!(t.is_empty());
        // Untouched — the `continue` is before `:251`.
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
        // Chain a-b-c-d, cut b-c. c AND d both go unreachable in
        // one `run_graph` call. Tests that the diff walk emits
        // multiple transitions, not just the first.
        let (mut g, [a, b, c, d]) = chain();
        let bc = g.lookup_edge(b, c).unwrap();
        g.del_edge(bc).unwrap();

        let (t, mst, _routes) = run_graph(&mut g, a, &[]);

        // Order is `node_ids()` order (slot order = insertion order
        // here). C order is splay-tree-on-name; both are stable, but
        // the C doesn't depend on transition order so neither do we.
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
