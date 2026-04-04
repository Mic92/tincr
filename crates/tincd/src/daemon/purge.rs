#![forbid(unsafe_code)]
//! `purge()` — `net.c:50-93`. Node GC for unreachable peers.
//!
//! Without this, nodes accumulate forever: every reconnect under a
//! new edge, every churn cycle, every transitive node ever gossiped
//! stays in `graph` + `node_ids` + `id6_table`. The walks in
//! `dump_nodes_rows`, `send_everything`, `decide_autoconnect`,
//! `on_periodic_tick` grow O(nodes-ever-seen). After a few weeks of
//! moderate churn that's thousands of dead slots.
//!
//! ## Two passes (C `:55-93`)
//!
//! **Pass 1** (`:55-74`): for each unreachable node, gossip DEL for
//! its subnets and outgoing edges, then delete them locally. After
//! this the unreachable node owns nothing and originates no edges.
//!
//! **Pass 2** (`:78-92`): for each still-unreachable node, check if
//! ANY edge anywhere points TO it. If not — and `!autoconnect &&
//! (!strictsubnets || no subnets)` — delete the node itself.
//!
//! The `:83 return` is the subtle bit: a SINGLE incoming edge to a
//! SINGLE unreachable node aborts ALL pass-2 deletions this round.
//! Intentional — that edge's owner is also unreachable (else `to`
//! would be reachable via it), and pass 1 just deleted *its*
//! outgoing edges, including this one. But the C walks `edge_weight_
//! tree` BETWEEN the two `splay_each(node_tree)` loops, so the
//! pass-1 deletions are visible to pass-2. The early return only
//! fires when a *reachable* node still claims an edge to a dead one
//! — gossip hasn't caught up yet, wait for next purge.
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

#[allow(clippy::wildcard_imports)]
use super::*;

impl Daemon {
    /// `purge()` (`net.c:50-93`). See module doc.
    ///
    /// Called from:
    /// - REQ_PURGE ctl arm (`control.c:75-77`)
    /// - `on_del_edge` after a DEL_EDGE makes `to` unreachable —
    ///   our addition, not in C; see `gossip.rs` callsite comment.
    ///
    /// Returns `needs_write` from the gossip broadcasts (pass 1).
    /// C is `void` (`send_del_*` writes synchronously); we bubble it
    /// so the metaconn arm can `maybe_set_write_any` once.
    #[allow(clippy::too_many_lines)] // C purge is 43 LOC; side-table sweep doubles it
    pub(super) fn purge(&mut self) -> bool {
        log::debug!(target: "tincd::proto", "Purging unreachable nodes");

        // ─── pass 1: gossip DEL + delete subnets/edges ──────────
        // C `:55-75`. Collect first: `graph.node_ids()` borrows
        // `&self.graph`, the deletes need `&mut self.graph`.
        let unreachable: Vec<(NodeId, String)> = self
            .graph
            .node_ids()
            .filter_map(|nid| {
                let n = self.graph.node(nid)?;
                // C `:56` `if(!n->status.reachable)`. Never myself
                // (`net_setup.c:1050` sets myself reachable; sssp
                // visits it as the root).
                (!n.reachable).then(|| (nid, n.name.clone()))
            })
            .collect();

        let mut nw = false;
        for (nid, name) in &unreachable {
            log::debug!(target: "tincd::proto", "Purging node {name}");

            // C `:59-65`: subnets. `n->subnet_tree` ≡ `owned_by(name)`.
            // `owned_by` already collects (the iterator self-borrows
            // through `del`).
            for s in self.subnets.owned_by(name) {
                // C `:60` `send_del_subnet(everyone, s)`.
                let line = SubnetMsg {
                    owner: name.clone(),
                    subnet: s,
                }
                .format(Request::DelSubnet, Self::nonce());
                nw |= self.broadcast_line(&line);

                // C `:62-64` `if(!strictsubnets) subnet_del(n, s)`.
                // C `subnet_del` (`subnet.c:231`) is just the tree
                // delete; subnet-down ran at BecameUnreachable
                // (`graph.c:294` → our `run_graph_and_log`).
                if !self.settings.strictsubnets {
                    self.subnets.del(&s, name);
                    // mac_table sync. Same defensive owner-match as
                    // `on_del_subnet` (`gossip.rs:1179`).
                    if let Subnet::Mac { addr, .. } = s
                        && self.mac_table.get(&addr).map(String::as_str) == Some(name.as_str())
                    {
                        self.mac_table.remove(&addr);
                    }
                }
            }

            // C `:67-73`: edges. `n->edge_tree` ≡ `node_edges(nid)`
            // (outgoing only — same as C, see `edge.c:53-55`
            // `edge_compare` keyed on `to->name`). Clone the slice;
            // `del_edge` mutates the same vec.
            let edges: Vec<EdgeId> = self.graph.node_edges(*nid).to_vec();
            for eid in edges {
                let Some(e) = self.graph.edge(eid) else {
                    continue;
                };
                let to_name = self.node_log_name(e.to).to_owned();

                // C `:68-70` `if(!tunnelserver) send_del_edge(everyone, e)`.
                if !self.settings.tunnelserver {
                    let line = DelEdge {
                        from: name.clone(),
                        to: to_name,
                    }
                    .format(Self::nonce());
                    nw |= self.broadcast_line(&line);
                }

                // C `:72` `edge_del(e)`.
                self.graph.del_edge(eid);
                self.edge_addrs.remove(&eid);
            }
        }

        // ─── pass 2: delete orphan nodes ────────────────────────
        // C `:79-92`. Re-snapshot unreachables: pass 1 didn't change
        // reachability (it only deleted edges FROM unreachable nodes,
        // which by definition weren't on any path from myself), but
        // re-check anyway — matches C's separate `splay_each` walk.
        //
        // C `:81-84`: walk `edge_weight_tree`, return-from-function
        // if ANY edge's `to` is the node under inspection. Our
        // `edge_iter()` is the equivalent global walk. The early
        // return aborts ALL deletions, not just this node's — see
        // module doc for why that's intentional.
        //
        // Hoist the edge-target scan out of the per-node loop: build
        // the set of all `e.to` values once. Same observable behavior
        // (C's nested loop is O(unreachable × edges); set is
        // O(edges + unreachable)).
        let edge_targets: HashSet<NodeId> = self.graph.edge_iter().map(|(_, e)| e.to).collect();

        for (nid, name) in unreachable {
            // C `:80` re-check. Defensive; can't have flipped.
            if self.graph.node(nid).is_some_and(|n| n.reachable) {
                continue;
            }
            // C `:81-84`: `for splay_each(edge_t, e, &edge_weight_
            // tree) if(e->to == n) return;`
            if edge_targets.contains(&nid) {
                return nw;
            }

            // C `:86-90` gate. `!n->subnet_tree.head` ≡ node owns no
            // subnets. After pass 1: if `!strictsubnets`, we deleted
            // them all, so this is always true; if `strictsubnets`,
            // they're still there (preloaded by `load_all_nodes`).
            // The condition reduces to: never delete under
            // autoconnect (it wants to dial dead-but-addressed
            // nodes); under strictsubnets, only delete if the
            // operator's hosts/ file had no Subnet= lines.
            if !self.settings.autoconnect
                && (!self.settings.strictsubnets || self.subnets.owned_by(&name).is_empty())
            {
                // C `:89` `node_del(n)`. C cascades subnet_del +
                // edge_del (`node.c:137-143`); pass 1 already
                // emptied both, so the cascade is a no-op. We do
                // the daemon-side sweep first, then the graph slot.
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
                self.tunnels.remove(&nid);
                self.graph.del_node(nid);
            }
        }

        nw
    }
}
