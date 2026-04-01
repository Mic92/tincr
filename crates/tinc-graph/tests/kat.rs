//! Differential test vs `kat_graph/gen_graph.c`.
//!
//! Same shape as `tinc-crypto/tests/kat.rs`: load a JSON file produced
//! by a C generator, build the same graph in Rust, run the same
//! algorithms, diff outputs field-by-field. The C generator includes
//! the real `splay_tree.c` and `list.c` and copies the bodies of
//! `mst_kruskal` and `sssp_bfs` verbatim from `graph.c`, so any drift
//! between the copies and `graph.c` shows up as a build break (cc finds
//! the same symbols) or a KAT failure here.
//!
//! What we *don't* test: `update_node_udp` (gated off by seeding all
//! nodes `reachable=true`), `check_reachability` (90% script
//! execution). Both are daemon territory.

use serde::Deserialize;
use std::collections::HashSet;
use tinc_graph::{EdgeId, Graph, NodeId};

#[derive(Deserialize)]
struct Kat {
    name: String,
    nodes: Vec<String>,
    edges: Vec<KatEdge>,
    myself: u32,
    sssp: Vec<KatRoute>,
    mst: Vec<u32>,
}

#[derive(Deserialize)]
struct KatEdge {
    from: u32,
    to: u32,
    weight: i32,
    opts: u32,
    reverse: i32, // -1 sentinel
}

#[derive(Deserialize)]
struct KatRoute {
    reachable: bool,
    indirect: bool,
    distance: i32,
    weighted_distance: i32,
    nexthop: i32, // -1 if unreachable
    via: i32,
    prevedge: i32,
    options: u32,
}

fn build(k: &Kat) -> Graph {
    let mut g = Graph::new();
    for n in &k.nodes {
        g.add_node(n.clone());
    }
    // Our `add_edge` auto-links `reverse`; the KAT file has explicit
    // reverse indices because the C generator hand-wires them. Verify
    // the auto-link agrees with what the C built.
    for (i, e) in k.edges.iter().enumerate() {
        let id = g.add_edge(NodeId(e.from), NodeId(e.to), e.weight, e.opts);
        assert_eq!(id.0, u32::try_from(i).unwrap(), "edge id sequential");
    }
    for (i, e) in k.edges.iter().enumerate() {
        let got = g.edge(EdgeId(u32::try_from(i).unwrap())).reverse;
        let want = (e.reverse >= 0).then(|| EdgeId(u32::try_from(e.reverse).unwrap()));
        assert_eq!(
            got, want,
            "{}: edge {} reverse mismatch (auto-link disagrees with C)",
            k.name, i
        );
    }
    g
}

#[test]
fn sssp_kat() {
    let cases: Vec<Kat> = serde_json::from_str(include_str!("kat/graph.json")).unwrap();
    assert!(cases.len() >= 18, "expected ≥18 KAT cases");

    for k in &cases {
        let g = build(k);
        let routes = g.sssp(NodeId(k.myself));

        for (i, want) in k.sssp.iter().enumerate() {
            let got = &routes[i];
            let ctx = format!("{}: node {} ({})", k.name, i, k.nodes[i]);

            if !want.reachable {
                assert!(got.is_none(), "{ctx}: should be unreachable, got {got:?}");
                continue;
            }
            let got = got
                .as_ref()
                .unwrap_or_else(|| panic!("{ctx}: should be reachable"));

            // Field-by-field for legible failures. The order here is
            // roughly "cause → effect": indirect determines via;
            // distance + weighted_distance determine nexthop; prevedge
            // is the trace.
            assert_eq!(got.indirect, want.indirect, "{ctx}: indirect");
            assert_eq!(got.distance, want.distance, "{ctx}: distance");
            assert_eq!(
                got.weighted_distance, want.weighted_distance,
                "{ctx}: weighted_distance"
            );
            assert_eq!(
                got.nexthop.0,
                u32::try_from(want.nexthop).unwrap(),
                "{ctx}: nexthop"
            );
            assert_eq!(got.via.0, u32::try_from(want.via).unwrap(), "{ctx}: via");
            assert_eq!(got.options, want.options, "{ctx}: options");

            // prevedge: -1 means None (only for myself).
            match want.prevedge {
                -1 => assert!(got.prevedge.is_none(), "{ctx}: prevedge"),
                e => assert_eq!(
                    got.prevedge,
                    Some(EdgeId(u32::try_from(e).unwrap())),
                    "{ctx}: prevedge"
                ),
            }
        }
    }
}

#[test]
fn mst_kat() {
    let cases: Vec<Kat> = serde_json::from_str(include_str!("kat/graph.json")).unwrap();

    for k in &cases {
        let mut g = build(k);

        // The C generator runs SSSP first, snapshots `visited`, then
        // assigns `reachable := visited` before MST. Mirror that — MST
        // uses `reachable` to pick its starting node.
        let routes = g.sssp(NodeId(k.myself));
        for (i, r) in routes.iter().enumerate() {
            g.set_reachable(NodeId(u32::try_from(i).unwrap()), r.is_some());
        }

        let got: HashSet<u32> = g.mst().iter().map(|e| e.0).collect();
        let want: HashSet<u32> = k.mst.iter().copied().collect();

        // MST output order is implementation-defined (we push edge then
        // reverse, C sets bits on connections we read in edge order).
        // Compare as sets.
        assert_eq!(got, want, "{}: mst edges", k.name);
    }
}

/// Sanity: the `diamond_indirect` case is the indirect→direct upgrade.
/// Hand-check the surprising property: a node's `distance` *increases*
/// after revisit. If this test starts failing, either the KAT JSON
/// changed (regen?) or someone "fixed" the BFS to not do this — which
/// would break `via` correctness.
#[test]
fn indirect_upgrade_can_increase_distance() {
    let cases: Vec<Kat> = serde_json::from_str(include_str!("kat/graph.json")).unwrap();
    let k = cases.iter().find(|c| c.name == "diamond_indirect").unwrap();

    // n1 has the indirect edge from n0. It's reached at distance=1
    // indirect, then upgraded to direct via n3 → n1 at distance=3.
    // (n0 →[indirect] n1 doesn't count; n0 → n2 → n3 → n1 is direct.)
    let n1 = &k.sssp[1];
    assert!(n1.reachable);
    assert!(!n1.indirect, "n1 should end up direct (the upgrade)");
    assert_eq!(n1.distance, 3, "distance went *up* from 1 to 3");

    // And n3 stayed at distance=2, direct. Its weighted_distance is 10
    // (5+5, the indirect path) — *not* 100 (50+50, the direct path).
    // That's the other half of the quirk: nexthop+weighted_distance
    // are *not* updated on indirect→direct, only the rest is.
    let n3 = &k.sssp[3];
    assert_eq!(n3.distance, 2);
    assert!(!n3.indirect);
    assert_eq!(
        n3.weighted_distance, 10,
        "weighted_distance is from the OLD (indirect) path's nexthop update"
    );
}
