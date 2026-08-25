#![forbid(unsafe_code)]
//! Node GC for unreachable peers.
//!
//! Without this, nodes accumulate forever: every reconnect under a
//! new edge, every churn cycle, every transitive node ever gossiped
//! stays in `graph` + `node_ids` + `id6_table`. The walks in
//! `dump_nodes_rows`, `send_everything`, `decide_autoconnect`,
//! `on_periodic_tick` grow O(nodes-ever-seen). After a few weeks of
//! moderate churn that's thousands of dead slots.
//!
//! ## Two passes
//!
//! **Pass 1**: for each unreachable node, gossip DEL for its subnets
//! and outgoing edges, then delete them locally. After this the
//! unreachable node owns nothing and originates no edges.
//!
//! **Pass 2**: for each still-unreachable node, check if ANY edge
//! anywhere points TO it. If not — and `!autoconnect &&
//! (!strictsubnets || no subnets)` — delete the node itself.
//!
//! The early return in pass 2 is the subtle bit: a SINGLE incoming
//! edge to a SINGLE unreachable node aborts ALL pass-2 deletions this
//! round. Intentional — that edge's owner is also unreachable (else
//! `to` would be reachable via it), and pass 1 just deleted *its*
//! outgoing edges, including this one. Pass-1 deletions are visible
//! to pass-2 (we re-snapshot edges between passes). The early return
//! only fires when a *reachable* node still claims an edge to a dead
//! one — gossip hasn't caught up yet, wait for next purge.
//!
//! ## Side-table cleanup
//!
//! `Graph::del_node` recycles the `NodeId` slot (free list). Any
//! daemon-side table keyed on `NodeId` would dangle. We sweep:
//! `node_ids`, `id6_table`, `nodes`, `tunnels`. `last_routes` is
//! slot-indexed but the deleted slot was already `None` (unreachable
//! ⇒ no route) and `run_graph_and_log` rewrites the whole vec on the
//! next `graph()` call. `last_mst` can't reference dead edges (MST
//! only spans reachable nodes). `edge_addrs` swept per-edge in pass 1.

use super::Daemon;

use std::collections::HashSet;

use crate::graph::{EdgeId, NodeId};
use tinc_proto::msg::{DelEdge, SubnetMsg};
use tinc_proto::{Request, Subnet};

impl Daemon {
    /// See module doc. Only from the `REQ_PURGE` ctl arm: auto-purging from
    /// `on_del_edge` broadcast `DEL_EDGE`s for transiently unreachable nodes, their
    /// owners contradicted, and mixed meshes oscillated (issue #4). Returns pass
    /// 1's `needs_write` so the caller sets write interest once.
    pub(super) fn purge(&mut self) -> bool {
        log::debug!(target: "tincd::proto", "Purging unreachable nodes");

        // pass 1: gossip DEL + delete subnets/edges.
        // Collect first: `graph.node_ids()` borrows `&self.graph`,
        // the deletes need `&mut self.graph`.
        let unreachable: Vec<(NodeId, String)> = self
            .graph
            .node_ids()
            .filter_map(|nid| {
                let n = self.graph.node(nid)?;
                // Never myself (sssp visits it as the root).
                (!n.reachable).then(|| (nid, n.name.clone()))
            })
            .collect();

        let mut nw = false;
        for (nid, name) in &unreachable {
            log::debug!(target: "tincd::proto", "Purging node {name}");

            // Subnets. `owned_by` already collects (the iterator
            // self-borrows through `del`).
            for s in self.subnets.owned_by(name) {
                let line = SubnetMsg {
                    owner: name.clone(),
                    subnet: s,
                }
                .format(Request::DelSubnet, Self::nonce());
                nw |= self.broadcast_line(&line);

                // subnet-down already ran at BecameUnreachable
                // (via `run_graph_and_log`); this is just the
                // tree delete.
                if !self.settings.strictsubnets {
                    self.subnets.del(&s, name);
                    // mac_table sync. Same defensive owner-match as
                    // `on_del_subnet`.
                    if let Subnet::Mac { addr, .. } = s
                        && self.mac_table.get(&addr).map(String::as_str) == Some(name.as_str())
                    {
                        self.mac_table.remove(&addr);
                    }
                }
            }

            // Edges (outgoing only). Clone the slice; `del_edge`
            // mutates the same vec.
            let edges: Vec<EdgeId> = self.graph.node_edges(*nid).to_vec();
            for eid in edges {
                let Some(e) = self.graph.edge(eid) else {
                    continue;
                };
                let to_name = self.node_log_name(e.to).to_owned();

                if !self.settings.tunnelserver {
                    let line = DelEdge {
                        from: name.clone(),
                        to: to_name,
                    }
                    .format(Self::nonce());
                    nw |= self.broadcast_line(&line);
                }

                self.graph.del_edge(eid);
                self.edge_addrs.remove(&eid);
            }
        }

        // Pass 2: delete orphan nodes. Reachability is re-snapshotted although pass 1
        // can't have changed it. The early return aborts all deletions on purpose
        // (module doc). The set of edge targets is built once: O(edges + unreachable).
        let edge_targets: HashSet<NodeId> = self.graph.edge_iter().map(|(_, e)| e.to).collect();

        for (nid, name) in unreachable {
            // Defensive re-check; can't have flipped.
            if self.graph.node(nid).is_some_and(|n| n.reachable) {
                continue;
            }
            if edge_targets.contains(&nid) {
                return nw;
            }

            // After pass 1: if `!strictsubnets`, we deleted all
            // subnets, so the subnet check is always true; if
            // `strictsubnets`, they're still there (preloaded by
            // `load_all_nodes`). The condition reduces to: never
            // delete under autoconnect (it wants to dial dead-but-
            // addressed nodes); under strictsubnets, only delete if
            // the operator's hosts/ file had no Subnet= lines.
            if !self.settings.autoconnect
                && (!self.settings.strictsubnets || self.subnets.owned_by(&name).is_empty())
            {
                // Daemon-side sweep first, then the graph slot.
                // Pass 1 already emptied subnets+edges.
                log::debug!(target: "tincd::proto",
                            "Deleting node {name} (no edges, no subnets)");
                self.node_ids.remove(&name);
                self.id6_table.remove(nid);
                // Unreachable nodes shouldn't have a NodeState (only
                // direct peers do, via `on_ack`) or a live tunnel
                // (`reset_unreachable` cleared it), but sweep anyway:
                // cheap, and a recycled NodeId pointing at stale
                // state is a debugging nightmare.
                self.nodes.remove(&nid);
                self.dp.tunnels.remove(&nid);
                self.graph.del_node(nid);
            }
        }

        // `node_ids.remove` + `graph.del_node` invalidates NodeView:
        // the slot is freed, the next `lookup_or_add_node` recycles
        // it, and a stale snapshot would map the new nid to the OLD
        // name's reachable bit. `purge` is the only path that doesn't
        // follow with `run_graph_and_log` (purged nodes were already
        // unreachable; no BFS change). Subnets/handles also mutated
        // in the loop; one refresh covers all.
        self.tx_snap_refresh_graph();
        self.tx_snap_refresh_subnets();
        if let Some(s) = self.tx_snap.as_mut() {
            // Purged nids were unreachable so BecameUnreachable
            // already cleared their handles, but be defensive.
            s.tunnels
                .retain(|nid, _| self.tunnel_handles.contains_key(nid));
        }
        self.publish_shard_snap();

        nw
    }
}
