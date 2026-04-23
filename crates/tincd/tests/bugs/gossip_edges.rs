//! Regression tests for `ADD_EDGE`/`DEL_EDGE` handling and graph SSSP.

use tincd::graph::Graph;

/// A peer can advertise edge weights up to `i32::MAX` on the wire
/// (`AddEdge::parse` only clamps `>= 0`). `sssp` accumulates
/// `weighted_distance` with `wrapping_add`, so two `i32::MAX` hops
/// sum to `-2`. The same-hop "lighter weight" tie-break then prefers
/// the wrapped path over a genuinely cheap one, letting a hostile
/// (but authenticated) mesh member steer relayed traffic through
/// itself by advertising the *worst* possible weight.
#[test]
#[ignore = "bug: sssp weighted_distance i32 wrap lets MAX-weight path win tie-break"]
fn sssp_weight_overflow_hijacks_nexthop() {
    let mut g = Graph::new();
    let src = g.add_node("src");
    let evil = g.add_node("evil"); // sorts before "good" → BFS visits first
    let good = g.add_node("good");
    let dst = g.add_node("dst");

    // Hostile path: src—evil—dst, weight i32::MAX on both hops.
    // i32::MAX.wrapping_add(i32::MAX) == -2.
    for (a, b) in [(src, evil), (evil, dst)] {
        g.add_edge(a, b, i32::MAX, 0);
        g.add_edge(b, a, i32::MAX, 0);
    }
    // Legit path: src—good—dst, weight 10 each → wdist 20.
    for (a, b) in [(src, good), (good, dst)] {
        g.add_edge(a, b, 10, 0);
        g.add_edge(b, a, 10, 0);
    }

    let routes = g.sssp(src);
    let r = routes[dst.0 as usize].expect("dst reachable");

    assert!(
        r.weighted_distance >= 0,
        "weighted_distance wrapped negative: {}",
        r.weighted_distance
    );
    assert_eq!(
        r.nexthop, good,
        "overflow let i32::MAX-weight path beat weight-20 path \
         (got nexthop={:?}, wdist={})",
        r.nexthop, r.weighted_distance
    );
}
