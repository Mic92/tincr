//! `broadcast_packet` target selection.
//!
//! Broadcast = packet goes to ALL nodes. Two strategies:
//!
//! - **MST** (`BMODE_MST`, default): walk the minimum spanning tree.
//!   Each node forwards over MST edges except the one it arrived on.
//!   Loop-free, every node sees the packet once, sending load
//!   distributes across all nodes.
//!
//! - **Direct** (`BMODE_DIRECT`): the originator sends one copy per
//!   directly-reachable node. No forwarding. Only useful for
//!   small/flat meshes.
//!
//! - **None**: no broadcast. The `RMODE_SWITCH` unknown-MAC fallback
//!   then can't flood; switch learning still works for known MACs.
//!
//! C also checks `tunnelserver` (`:1622`) — MST might be invalid in
//! tunnelserver mode (filtered `ADD_EDGE`). Daemon-side gate.
//!
//! ## What's NOT here
//!
//! - `c->status.mst` — daemon stores `Vec<EdgeId>` from `run_graph`
//!   in `last_mst` (gossip.rs `run_graph_and_log`).
//! - The actual `send_packet` calls — daemon iterates the targets we
//!   return in `broadcast_packet` (`daemon/net.rs`).
//! - `RouteResult::Broadcast` match arm — `dispatch_route_result`.
#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::hash::Hash;

/// Broadcast strategy. Default MST.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BroadcastMode {
    None,
    #[default]
    Mst,
    Direct,
}

/// MST broadcast: filter active conns to those whose edge is in the
/// MST, EXCEPT the one the packet arrived
/// on (`c != from->nexthop->connection`).
///
/// Generic over `(ConnId, EdgeId)` pairs — daemon builds from its
/// `nodes` map (`NodeState{conn, edge}`).
///
/// `mst` is the `Vec<EdgeId>` from `crate::graph::mst()`. Convert to a
/// set for O(1) membership; ≤ conn count elements so `HashSet` is fine.
///
/// `from_conn`: the connection the packet ARRIVED on
/// (`from->nexthop->connection`). `None` for locally-originated
/// broadcasts (`from == myself`; `:1616` `if(from != myself)` already
/// gave us a copy).
pub(crate) fn mst_targets<C, E>(
    active_conns: impl Iterator<Item = (C, E)>,
    mst: &[E],
    from_conn: Option<C>,
) -> Vec<C>
where
    C: Copy + Eq,
    E: Copy + Eq + Hash,
{
    let mst_set: HashSet<E> = mst.iter().copied().collect();
    active_conns
        .filter(|(c, e)| {
            // c->edge — caller only feeds active conns (already implied
            //           by having an EdgeId)
            // c->status.mst — edge is in the MST
            // c != from->nexthop->connection — don't echo back
            mst_set.contains(e) && Some(*c) != from_conn
        })
        .map(|(c, _)| c)
        .collect()
}

/// Direct broadcast. The condition: `(n->via == myself && n->nexthop
/// == n) || n->via == n`. In English: nodes we can reach in one hop (either directly UDP-dialable, or
/// `via` themselves = self-relay = direct).
///
/// `:1644-1646` `if(from != myself) break` — direct mode ONLY
/// broadcasts when WE originated. We take a `from_is_self: bool` and
/// return empty if false.
///
/// Generic over a node-view tuple `(NodeId, via, nexthop)`. Daemon
/// builds from `last_routes`.
///
/// `:1650` `n != myself` — we never include ourselves in the targets;
/// the `send_packet(myself, ..)` at `:1617` already happened.
pub(crate) fn direct_targets<N>(
    nodes: impl Iterator<Item = (N, Option<N>, Option<N>)>,
    myself: N,
    from_is_self: bool,
) -> Vec<N>
where
    N: Copy + Eq,
{
    // :1644-1646 — direct mode only broadcasts locally-originated.
    if !from_is_self {
        return Vec::new();
    }
    nodes
        .filter(|&(n, via, nexthop)| {
            // n != myself
            if n == myself {
                return false;
            }
            // (n->via == myself && n->nexthop == n) || n->via == n
            // C also gates on n->status.reachable; daemon only feeds
            // reachable nodes (unreachable have no via/nexthop).
            let via_self_nexthop_n = via == Some(myself) && nexthop == Some(n);
            let via_is_n = via == Some(n);
            via_self_nexthop_n || via_is_n
        })
        .map(|(n, _, _)| n)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Use plain u32 for both conn-id and edge-id stand-ins.

    #[test]
    fn mst_filters_non_mst() {
        // 4 conns A=1,B=2,C=3,D=4 with edges e1..e4; mst=[e1,e3]
        let conns = [(1u32, 10u32), (2, 20), (3, 30), (4, 40)];
        let mst = [10u32, 30];
        let mut got = mst_targets(conns.into_iter(), &mst, None);
        got.sort_unstable();
        assert_eq!(got, vec![1, 3]);
    }

    #[test]
    fn mst_excludes_from_conn() {
        let conns = [(1u32, 10u32), (2, 20)];
        let mst = [10u32, 20];
        let got = mst_targets(conns.into_iter(), &mst, Some(1));
        assert_eq!(got, vec![2]);
    }

    #[test]
    fn mst_from_none() {
        // locally-originated: all MST conns in targets
        let conns = [(1u32, 10u32), (2, 20), (3, 30)];
        let mst = [10u32, 20, 30];
        let mut got = mst_targets(conns.into_iter(), &mst, None);
        got.sort_unstable();
        assert_eq!(got, vec![1, 2, 3]);
    }

    #[test]
    fn mst_empty_mst() {
        let conns = [(1u32, 10u32), (2, 20)];
        let mst: [u32; 0] = [];
        let got = mst_targets(conns.into_iter(), &mst, None);
        assert!(got.is_empty());
    }

    #[test]
    fn direct_via_self_nexthop_self() {
        // node X=1 with via=myself(0), nexthop=X(1) → in targets
        let nodes = [(1u32, Some(0u32), Some(1u32))];
        let got = direct_targets(nodes.into_iter(), 0, true);
        assert_eq!(got, vec![1]);
    }

    #[test]
    fn direct_via_is_node() {
        // n->via == n arm: via=X(1) → in targets
        let nodes = [(1u32, Some(1u32), Some(99u32))];
        let got = direct_targets(nodes.into_iter(), 0, true);
        assert_eq!(got, vec![1]);
    }

    #[test]
    fn direct_via_someone_else() {
        // via=Z(2) (relay) → NOT in targets
        let nodes = [(1u32, Some(2u32), Some(2u32))];
        let got = direct_targets(nodes.into_iter(), 0, true);
        assert!(got.is_empty());
    }

    #[test]
    fn direct_from_not_self() {
        // :1644-1646 — direct only broadcasts when WE originated.
        // node would otherwise qualify (via=self, nexthop=self).
        let nodes = [(1u32, Some(0u32), Some(1u32))];
        let got = direct_targets(nodes.into_iter(), 0, false);
        assert!(got.is_empty());
    }

    #[test]
    fn direct_excludes_self() {
        // :1650 `n != myself` — myself shouldn't appear even if it
        // satisfies the filter (via==myself && nexthop==myself, or
        // via==myself which IS the n->via==n arm when n==myself).
        let nodes = [
            (0u32, Some(0u32), Some(0u32)), // myself, satisfies via==n
            (1, Some(0), Some(1)),          // direct neighbor
        ];
        let got = direct_targets(nodes.into_iter(), 0, true);
        assert_eq!(got, vec![1]);
    }
}
