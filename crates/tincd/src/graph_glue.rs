//! `graph()` glue: SSSP result → reachability transitions.
//!
//! `tinc-graph::sssp` runs the BFS and returns `Vec<Option<Route>>` —
//! `Some` = `n->status.visited`, `None` = unvisited. The C then walks
//! `node_tree` and diffs `visited` against the *previous*
//! `reachable` bit. A flip in either direction is a transition:
//! log line, host-up/host-down script, subnet-up/down, SPTPS reset,
//! MTU probe timer reset.
//!
//! All of those touch daemon state outside the graph (`process.c`
//! script spawn, per-node SPTPS sessions, timer wheel). Same pattern
//! as `tinc_sptps::Output`: return a `Vec<Transition>`, daemon match-
//! arms grow as later chunks land. The script spawn is chunk 8;
//! `update_node_udp` is chunk 7.
//!
//! The one side-effect that *does* belong here: writing the new
//! `reachable` bit back into the `Graph`. The next `sssp` reads it
//! (gates `update_node_udp` on `!n->status.reachable`), and `mst`
//! picks its starting point from it. So [`diff_reachability`]
//! persists before returning.

#![forbid(unsafe_code)]

use tinc_graph::{EdgeId, Graph, NodeId, Route};

/// One reachability transition. The daemon turns these into log
/// lines + script spawns + per-node-SPTPS resets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transition {
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
pub fn diff_reachability(
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
pub fn run_graph(
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
#[allow(clippy::many_single_char_names)] // graph node labels
mod tests {
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
