//! `run_graph_and_log` / `flush_graph_dirty` — SSSP + reachability
//! transition handling driven by gossip-mutated topology.

use crate::daemon::Daemon;

use crate::graph::{NodeId, Transition, run_graph};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// A BFS owed after deferred topology changes. Only this module reads
/// or clears it, so a stale read must go through `flush_graph_dirty`.
#[derive(Default)]
pub(crate) struct GraphDirty(bool);

impl GraphDirty {
    pub(crate) fn mark(&mut self) {
        self.0 = true;
    }
}

impl Daemon {
    /// sssp + diff + mst.
    pub(in crate::daemon) fn run_graph_and_log(&mut self) {
        // Covers any pending `on_add_edge` deferrals from the same
        // batch when called directly (on_del_edge/on_ack/terminate).
        self.graph_dirty = GraphDirty::default();
        let (transitions, mst, routes) = run_graph(&mut self.graph, self.myself, &self.last_routes);
        // Side-table for dump_nodes. Swap-whole: sssp built a fresh Vec.
        // Old Arc drops here (refcount 1, single-thread).
        self.last_routes = Arc::new(routes);
        // Snapshot refresh: must happen before the transition loop's
        // BecameUnreachable arm clears tunnel_handles, but after the
        // BFS so routes are post-sssp. The transition loop only
        // touches dp.tunnels, not the graph/node_ids that NodeView
        // reads. Refresh once here; the post-transition state is the
        // same as far as routes/ns are concerned.
        // Keep edge IDs and map at broadcast time.
        self.last_mst = mst;
        let unix_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        for t in transitions {
            let (Transition::BecameReachable { node, .. } | Transition::BecameUnreachable { node }) =
                t;
            self.state_changed.insert(node, unix_now);
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

                    // Seed `udp_addr`: direct neighbours from `NodeState.edge_addr` (set in
                    // on_ack), transitive nodes from prevedge's wire addr. Without it
                    // `choose_udp_address` returns None for transitive non-INDIRECT nodes and
                    // direct probes are silently dropped. Incoming UDP is keyed on the id6 prefix,
                    // so nothing to re-index.
                    let name_owned = name.to_owned();
                    let addr = self
                        .nodes
                        .get(&node)
                        .and_then(|ns| ns.edge_addr)
                        .or_else(|| {
                            let prev = self.route_of(node)?.prevedge?;
                            self.edge_wire_addr(prev)
                        });
                    if let Some(addr) = addr {
                        self.learn_udp_addr(node, addr, "reachable via edge");
                    }

                    // host-up after addr known.
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

                    // Before reset clears the address.
                    self.run_node_down_scripts(node);

                    // reset_unreachable: sptps_stop + mtu reset +
                    // clear UDP addr.
                    if let Some(tunnel) = self.dp.tunnels.get_mut(&node) {
                        tunnel.reset_unreachable();
                    }
                    self.tunnel_handles.remove(&node);
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
        // Refresh after the transition loop: `reachable` is post-BFS,
        // and `nodes`/`node_ids` reflect any `on_ack`/`terminate`
        // mutation that triggered this call (both call sites do the
        // mutation first, then `run_graph_and_log`).
        self.tx_snap_refresh_graph();
    }

    /// Queue `host-down`, `hosts/NAME-down` and `subnet-down` for `node`.
    pub(in crate::daemon) fn run_node_down_scripts(&self, node: NodeId) {
        let Some(name) = self.graph.node(node).map(|n| n.name.clone()) else {
            return;
        };
        let addr = self
            .dp
            .tunnels
            .get(&node)
            .and_then(|t| t.path.addr())
            .or_else(|| self.nodes.get(&node).and_then(|ns| ns.edge_addr));
        self.run_host_script(false, &name, addr);
        for s in &self.subnets.owned_by(&name) {
            self.run_subnet_script(false, &name, s);
        }
    }

    /// One BFS per dispatch batch. See [`Daemon::graph_dirty`].
    pub(in crate::daemon) fn flush_graph_dirty(&mut self) {
        if self.graph_dirty.0 {
            self.run_graph_and_log();
        }
    }
}
