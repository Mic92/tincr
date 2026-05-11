//! Network-level gossip simulation proving that removing
//! purge-on-del-edge (the fix for
//! <https://github.com/Mic92/tincr/issues/4>) eliminates the
//! contradiction storm that caused reachability oscillation in
//! mixed tincr / tinc-1.1pre18 meshes.
//!
//! Each simulated node maintains its own [`Graph`], runs SSSP.
//! Gossip is flooded over meta connections (broadcast to all TCP
//! peers, each peer forwards). A node unreachable in SSSP can
//! still RECEIVE gossip via meta-connection flooding.
//!
//! The key scenario: a `DEL_EDGE` arrives at a node before the
//! `ADD_EDGE` that provides an alternative path. During the gap,
//! SSSP says the target is unreachable. Previously, tincr called
//! `purge()` here, broadcasting `DEL_EDGE` for the target's
//! outgoing edges. Those flooded to the owning node, which
//! contradicted. With the fix (no purge-on-del-edge), zero
//! contradictions.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use tincd::graph::{Graph, NodeId};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Msg {
    AddEdge { from: String, to: String },
    DelEdge { from: String, to: String },
}

#[derive(Debug, Clone)]
struct Envelope {
    arrive_tick: u64,
    sender: String,
    dest: String,
    msg: Msg,
    nonce: u64,
}

struct SimNode {
    graph: Graph,
    myself: NodeId,
    node_ids: HashMap<String, NodeId>,
    meta_peers: Vec<String>,
    seen: BTreeSet<u64>,
    oscillations: HashMap<String, u64>,
    contradictions: u64,
}

impl SimNode {
    fn new(name: &str) -> Self {
        let mut graph = Graph::new();
        let myself = graph.add_node(name);
        graph.set_reachable(myself, true);
        let mut node_ids = HashMap::new();
        node_ids.insert(name.to_string(), myself);
        SimNode {
            graph,
            myself,
            node_ids,
            meta_peers: Vec::new(),
            seen: BTreeSet::new(),
            oscillations: HashMap::new(),
            contradictions: 0,
        }
    }

    fn lookup_or_add(&mut self, name: &str) -> NodeId {
        if let Some(&nid) = self.node_ids.get(name) {
            nid
        } else {
            let nid = self.graph.add_node(name);
            self.node_ids.insert(name.to_string(), nid);
            nid
        }
    }

    fn run_sssp(&mut self) {
        let routes = self.graph.sssp(self.myself);
        let ids: Vec<(NodeId, String)> = self
            .node_ids
            .iter()
            .filter(|&(_, &nid)| nid != self.myself)
            .map(|(name, &nid)| (nid, name.clone()))
            .collect();
        for (nid, name) in ids {
            let visited = routes.get(nid.0 as usize).is_some_and(Option::is_some);
            let was = self.graph.node(nid).is_some_and(|n| n.reachable);
            if visited != was {
                self.graph.set_reachable(nid, visited);
                *self.oscillations.entry(name).or_default() += 1;
            }
        }
    }

    fn nid_to_name(&self, nid: NodeId) -> String {
        self.node_ids
            .iter()
            .find(|&(_, &v)| v == nid)
            .map_or_else(|| format!("?{}", nid.0), |(k, _)| k.clone())
    }
}

struct Simulation {
    nodes: BTreeMap<String, SimNode>,
    queue: VecDeque<Envelope>,
    tick: u64,
    hop_delay: u64,
    nonce_counter: u64,
    msg_count: u64,
}

impl Simulation {
    fn new(hop_delay: u64) -> Self {
        Simulation {
            nodes: BTreeMap::new(),
            queue: VecDeque::new(),
            tick: 0,
            hop_delay,
            nonce_counter: 0,
            msg_count: 0,
        }
    }

    fn add_node(&mut self, name: &str) {
        self.nodes.insert(name.to_string(), SimNode::new(name));
    }

    fn next_nonce(&mut self) -> u64 {
        self.nonce_counter += 1;
        self.nonce_counter
    }

    fn connect(&mut self, a: &str, b: &str) {
        self.nodes
            .get_mut(a)
            .unwrap()
            .meta_peers
            .push(b.to_string());
        self.nodes
            .get_mut(b)
            .unwrap()
            .meta_peers
            .push(a.to_string());

        for node_name in [a, b] {
            let node = self.nodes.get_mut(node_name).unwrap();
            let aid = node.lookup_or_add(a);
            let bid = node.lookup_or_add(b);
            if node.graph.lookup_edge(aid, bid).is_none() {
                node.graph.add_edge(aid, bid, 0, 0);
            }
            if node.graph.lookup_edge(bid, aid).is_none() {
                node.graph.add_edge(bid, aid, 0, 0);
            }
        }

        self.nodes.get_mut(a).unwrap().run_sssp();
        self.nodes.get_mut(b).unwrap().run_sssp();

        self.broadcast_all_edges(a);
        self.broadcast_all_edges(b);
    }

    fn broadcast_all_edges(&mut self, node_name: &str) {
        let node = &self.nodes[node_name];
        let mut msgs = Vec::new();
        for (_, e) in node.graph.edge_iter() {
            msgs.push(Msg::AddEdge {
                from: node.nid_to_name(e.from),
                to: node.nid_to_name(e.to),
            });
        }
        let peers: Vec<String> = node.meta_peers.clone();
        for peer in &peers {
            for msg in &msgs {
                let nonce = self.next_nonce();
                self.queue.push_back(Envelope {
                    arrive_tick: self.tick + self.hop_delay,
                    sender: node_name.to_string(),
                    dest: peer.clone(),
                    msg: msg.clone(),
                    nonce,
                });
            }
        }
    }

    fn send_msg(&mut self, sender: &str, dest: &str, msg: Msg, nonce: u64) {
        self.queue.push_back(Envelope {
            arrive_tick: self.tick + self.hop_delay,
            sender: sender.to_string(),
            dest: dest.to_string(),
            msg,
            nonce,
        });
    }

    fn disconnect(&mut self, a: &str, b: &str) {
        for (local, remote) in [(a, b), (b, a)] {
            let node = self.nodes.get_mut(local).unwrap();
            let local_id = node.node_ids[local];
            let remote_id = node.node_ids[remote];
            if let Some(eid) = node.graph.lookup_edge(local_id, remote_id) {
                node.graph.del_edge(eid);
            }
            if let Some(eid) = node.graph.lookup_edge(remote_id, local_id) {
                node.graph.del_edge(eid);
            }
            node.run_sssp();
            node.meta_peers.retain(|p| p != remote);
        }

        for (local, remote) in [(a, b), (b, a)] {
            for (from, to) in [(local, remote), (remote, local)] {
                let nonce = self.next_nonce();
                let msg = Msg::DelEdge {
                    from: from.to_string(),
                    to: to.to_string(),
                };
                let peers: Vec<String> = self.nodes[local].meta_peers.clone();
                for peer in &peers {
                    self.queue.push_back(Envelope {
                        arrive_tick: self.tick + self.hop_delay,
                        sender: local.to_string(),
                        dest: peer.clone(),
                        msg: msg.clone(),
                        nonce,
                    });
                }
            }
        }
    }

    fn run(&mut self, max_ticks: u64) {
        let end = self.tick + max_ticks;
        while self.tick < end {
            self.tick += 1;
            let mut ready: Vec<Envelope> = Vec::new();
            let mut i = 0;
            while i < self.queue.len() {
                if self.queue[i].arrive_tick <= self.tick {
                    ready.push(self.queue.remove(i).unwrap());
                } else {
                    i += 1;
                }
            }
            if ready.is_empty() && self.queue.is_empty() {
                break;
            }
            for env in &ready {
                self.process_message(env);
            }
        }
    }

    fn process_message(&mut self, env: &Envelope) {
        let dest_name = env.dest.clone();
        let sender = env.sender.clone();
        let nonce = env.nonce;

        let mut nonce_used = 0u64;
        let nonce_base = self.nonce_counter + 1;
        let mut alloc_nonce = || -> u64 {
            nonce_used += 1;
            nonce_base + nonce_used - 1
        };

        let Some(peer) = self.nodes.get_mut(&dest_name) else {
            return;
        };

        if peer.seen.contains(&nonce) {
            return;
        }
        peer.seen.insert(nonce);

        let mut outgoing: Vec<(String, String, Msg, u64)> = Vec::new();

        match &env.msg {
            Msg::AddEdge { from, to } => {
                let from_id = peer.lookup_or_add(from);
                let to_id = peer.lookup_or_add(to);

                if peer.graph.lookup_edge(from_id, to_id).is_some() {
                    self.msg_count += 1;
                    return;
                }

                if from_id == peer.myself {
                    // Contradiction: peer claims we have an edge we
                    // don't. Send `DEL_EDGE` back.
                    let n = alloc_nonce();
                    outgoing.push((
                        dest_name.clone(),
                        sender.clone(),
                        Msg::DelEdge {
                            from: from.clone(),
                            to: to.clone(),
                        },
                        n,
                    ));
                } else {
                    peer.graph.add_edge(from_id, to_id, 0, 0);
                    peer.run_sssp();
                    let peers: Vec<String> = peer.meta_peers.clone();
                    for p in &peers {
                        if *p == sender {
                            continue;
                        }
                        outgoing.push((dest_name.clone(), p.clone(), env.msg.clone(), nonce));
                    }
                }
            }
            Msg::DelEdge { from, to } => {
                let Some(&from_id) = peer.node_ids.get(from.as_str()) else {
                    self.msg_count += 1;
                    return;
                };
                let Some(&to_id) = peer.node_ids.get(to.as_str()) else {
                    self.msg_count += 1;
                    return;
                };

                if from_id == peer.myself {
                    // Contradiction: someone says our edge doesn't
                    // exist, but it does. Send `ADD_EDGE` back.
                    if peer.graph.lookup_edge(from_id, to_id).is_some() {
                        peer.contradictions += 1;
                        let n = alloc_nonce();
                        outgoing.push((
                            dest_name.clone(),
                            sender.clone(),
                            Msg::AddEdge {
                                from: from.clone(),
                                to: to.clone(),
                            },
                            n,
                        ));
                    }
                } else {
                    let Some(eid) = peer.graph.lookup_edge(from_id, to_id) else {
                        self.msg_count += 1;
                        return;
                    };

                    peer.graph.del_edge(eid);

                    let fwd_peers: Vec<String> = peer.meta_peers.clone();
                    for p in &fwd_peers {
                        if *p == sender {
                            continue;
                        }
                        outgoing.push((dest_name.clone(), p.clone(), env.msg.clone(), nonce));
                    }

                    peer.run_sssp();

                    // No purge-on-del-edge. This is the fix for
                    // issue #4: C tinc never auto-purges here, and
                    // doing so caused a contradiction storm that
                    // made the mesh oscillate. Purge is only
                    // triggered by explicit `tinc purge` (REQ_PURGE).
                }
            }
        }

        self.msg_count += 1;
        self.nonce_counter += nonce_used;

        for (s, d, m, n) in outgoing {
            self.send_msg(&s, &d, m, n);
        }
    }

    fn total_contradictions(&self) -> u64 {
        self.nodes.values().map(|n| n.contradictions).sum()
    }
}

// ──────────────────────────── tests ─────────────────────────────

/// Timing-gap scenario that triggered issue #4.
///
/// ```text
///           ┌── hub2 ──────────────┐
///  node1 ───┤                      carol ── dave
///           └── hub1 ── hub3 ──────┘
/// ```
///
/// `hub2` disconnects from carol; carol reconnects to `hub3` 1 tick
/// later. The `DEL_EDGE hub2→carol` reaches `node1` before the
/// `ADD_EDGE hub3→carol`. During the gap, SSSP says carol is
/// unreachable. Previously tincr called `purge()` here, broadcasting
/// `DEL_EDGE` for carol's outgoing edges; carol contradicted. With
/// the fix: zero contradictions.
#[test]
fn timing_gap_zero_contradictions() {
    let mut sim = Simulation::new(1);

    for name in ["node1", "hub1", "hub2", "hub3", "carol", "dave"] {
        sim.add_node(name);
    }

    sim.connect("node1", "hub1");
    sim.connect("node1", "hub2");
    sim.connect("hub1", "hub3");
    sim.connect("hub2", "carol");
    sim.connect("carol", "dave");

    sim.run(50);

    // Verify full reachability.
    {
        let t = &sim.nodes["node1"];
        for name in ["hub1", "hub2", "hub3", "carol", "dave"] {
            let nid = t.node_ids[name];
            assert!(
                t.graph.node(nid).unwrap().reachable,
                "pre: node1 should see {name} reachable"
            );
        }
    }

    // Timing gap: disconnect first, then reconnect via different hub.
    sim.disconnect("hub2", "carol");
    sim.run(1);
    sim.connect("carol", "hub3");
    sim.run(100);

    assert_eq!(sim.total_contradictions(), 0, "no contradictions after fix");

    let t = &sim.nodes["node1"];
    assert!(
        t.graph.node(t.node_ids["carol"]).unwrap().reachable,
        "carol reachable via hub3 after convergence"
    );
    assert!(
        t.graph.node(t.node_ids["dave"]).unwrap().reachable,
        "dave reachable via hub3→carol after convergence"
    );
}

/// Larger mesh: 3 observer nodes + 5 backbone + 2 edge nodes.
/// A single non-critical disconnect must not cause any contradictions.
#[test]
fn multi_node_zero_contradictions() {
    let mut sim = Simulation::new(1);

    for name in ["n1", "n2", "n3", "h1", "h2", "h3", "carol", "dave"] {
        sim.add_node(name);
    }

    sim.connect("n1", "h1");
    sim.connect("n1", "h2");
    sim.connect("n2", "h2");
    sim.connect("n2", "h3");
    sim.connect("n3", "h1");
    sim.connect("n3", "h3");
    sim.connect("h1", "h2");
    sim.connect("h2", "h3");
    sim.connect("h2", "carol");
    sim.connect("carol", "dave");

    sim.run(50);

    sim.disconnect("h2", "carol");
    sim.run(1);
    sim.connect("carol", "h3");
    sim.run(200);

    assert_eq!(
        sim.total_contradictions(),
        0,
        "no contradictions in larger mesh"
    );

    // All nodes converge to full reachability.
    for obs in ["n1", "n2", "n3"] {
        let n = &sim.nodes[obs];
        assert!(
            n.graph.node(n.node_ids["carol"]).unwrap().reachable,
            "{obs}: carol should be reachable"
        );
    }
}
