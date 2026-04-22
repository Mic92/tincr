//! `run_graph_and_log` / `flush_graph_dirty` — SSSP + reachability
//! transition handling driven by gossip-mutated topology.

use crate::daemon::Daemon;

use crate::graph_glue::{Transition, run_graph};
use crate::local_addr;

impl Daemon {
    /// sssp + diff + mst.
    pub(in crate::daemon) fn run_graph_and_log(&mut self) {
        // Covers any pending `on_add_edge` deferrals from the same
        // batch when called directly (on_del_edge/on_ack/terminate).
        self.graph_dirty = false;
        let (transitions, mst, routes) = run_graph(&mut self.graph, self.myself, &self.last_routes);
        // Side-table for dump_nodes. Swap-whole: sssp built a fresh Vec.
        // Old Arc drops here (refcount 1, single-thread).
        self.last_routes = std::sync::Arc::new(routes);
        // Snapshot refresh: must happen BEFORE the transition loop's
        // BecameUnreachable arm clears tunnel_handles, but AFTER the
        // BFS so routes are post-sssp. The transition loop only
        // touches dp.tunnels, not the graph/node_ids that NodeView
        // reads. Refresh once here; the post-transition state is the
        // same as far as routes/ns are concerned.
        // Keep edge IDs and map at broadcast time.
        self.last_mst = mst;
        for t in transitions {
            match t {
                Transition::BecameReachable { node, via: via_nid } => {
                    // `device_enable` is idempotent so we just call
                    // on every BecameReachable; the flag inside
                    // dedups. Gated on standby: when !standby,
                    // setup() already fired tinc-up.
                    if self.settings.device_standby {
                        self.device_enable();
                    }
                    let name = self
                        .graph
                        .node(node)
                        .map_or("<unknown>", |n| n.name.as_str());
                    let via_name = self
                        .graph
                        .node(via_nid)
                        .map_or("<unknown>", |n| n.name.as_str());
                    log::info!(target: "tincd::graph",
                               "Node {name} became reachable (via {via_name})");

                    // Seed `udp_addr`. Direct neighbors:
                    // `NodeState.edge_addr` (set in on_ack). Transitive
                    // nodes: prevedge's wire addr from `edge_addrs`.
                    // Without this, `choose_udp_address` for a
                    // transitive non-INDIRECT node returns None and
                    // direct UDP probes are silently dropped.
                    // We key incoming UDP on [dst_id6][src_id6]
                    // prefix - no tree to re-index.
                    let name_owned = name.to_owned();
                    let addr = self
                        .nodes
                        .get(&node)
                        .and_then(|ns| ns.edge_addr)
                        .or_else(|| {
                            let prev = self.route_of(node)?.prevedge?;
                            let (a, p, _, _) = self.edge_addrs.get(&prev)?;
                            local_addr::parse_addr_port(a.as_str(), p.as_str())
                        });
                    if let Some(addr) = addr {
                        let tunnel = self.dp.tunnels.entry(node).or_default();
                        tunnel.udp_addr = Some(addr);
                        tunnel.udp_addr_cached = None;
                    }

                    // host-up AFTER addr known.
                    self.run_host_script(true, &name_owned, addr);

                    // subnet-up for every owned subnet.
                    for s in &self.subnets.owned_by(&name_owned) {
                        self.run_subnet_script(true, &name_owned, s);
                    }
                    // Always true (no legacy); set for dump.
                    self.dp.tunnels.entry(node).or_default().status.sptps = true;
                }
                Transition::BecameUnreachable { node } => {
                    let name = self
                        .graph
                        .node(node)
                        .map_or("<unknown>", |n| n.name.as_str());
                    log::info!(target: "tincd::graph",
                               "Node {name} became unreachable");

                    let name_owned = name.to_owned();
                    // Read addr BEFORE reset clears it.
                    let addr = self
                        .dp
                        .tunnels
                        .get(&node)
                        .and_then(|t| t.udp_addr)
                        .or_else(|| self.nodes.get(&node).and_then(|ns| ns.edge_addr));

                    self.run_host_script(false, &name_owned, addr);

                    // subnet-down for every owned subnet.
                    for s in &self.subnets.owned_by(&name_owned) {
                        self.run_subnet_script(false, &name_owned, s);
                    }

                    // reset_unreachable: sptps_stop + mtu reset +
                    // clear UDP addr.
                    if let Some(tunnel) = self.dp.tunnels.get_mut(&node) {
                        tunnel.reset_unreachable();
                    }
                    // Drop the fast-path handles. The snapshot's
                    // `tunnels.get(&nid)` returns None next probe;
                    // packet falls to slow path.
                    self.tunnel_handles.remove(&node);
                    if let Some(s) = self.tx_snap.as_mut() {
                        s.tunnels.remove(&node);
                    }
                }
            }
        }
        // device_disable: check post-loop reachable count.
        if self.settings.device_standby && self.device_enabled {
            let any_reachable = self
                .graph
                .node_ids()
                .filter(|&n| n != self.myself)
                .any(|n| self.graph.node(n).is_some_and(|n| n.reachable));
            if !any_reachable {
                self.device_disable();
            }
        }
        // Refresh AFTER the transition loop: `reachable` is post-BFS,
        // and `nodes`/`node_ids` reflect any `on_ack`/`terminate`
        // mutation that triggered this call (both call sites do the
        // mutation FIRST, then `run_graph_and_log`).
        self.tx_snap_refresh_graph();
    }

    /// One BFS per dispatch batch. See [`Daemon::graph_dirty`].
    pub(in crate::daemon) fn flush_graph_dirty(&mut self) {
        if self.graph_dirty {
            self.run_graph_and_log();
        }
    }
}
