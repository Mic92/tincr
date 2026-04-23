//! Regression tests for `ADD_EDGE`/`DEL_EDGE` handling and graph SSSP.

use tincd::graph::Graph;

/// `i32::MAX`-weight hops must not wrap negative and beat a cheap path on the tie-break.
#[test]
fn sssp_weight_overflow_hijacks_nexthop() {
    let mut g = Graph::new();
    let src = g.add_node("src");
    let evil = g.add_node("evil");
    let good = g.add_node("good");
    let dst = g.add_node("dst");

    // Hostile path: i32::MAX on both hops.
    for (a, b) in [(src, evil), (evil, dst)] {
        g.add_edge(a, b, i32::MAX, 0);
        g.add_edge(b, a, i32::MAX, 0);
    }
    // Legit path: weight 10 each.
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
