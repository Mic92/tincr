//! `ADD_EDGE` / `DEL_EDGE` — flooded topology gossip.

use super::{MAX_EDGES, MAX_NODES};
use crate::daemon::{ConnId, Daemon};

use crate::proto::{DispatchError, parse_add_edge, parse_del_edge};

use tinc_proto::AddrStr;
use tinc_proto::msg::DelEdge;

impl Daemon {
    /// Edge exists with different params ⇒ update in place (`Graph::`
    /// `update_edge` keeps `EdgeId` slot stable; `edge_addrs` is keyed on
    /// it).
    pub(in crate::daemon) fn on_add_edge(
        &mut self,
        from_conn: ConnId,
        body: &[u8],
    ) -> Result<bool, DispatchError> {
        let edge = parse_add_edge(body)?;

        let Some(conn_name) = self.flooded_prologue(
            from_conn,
            body,
            "ADD_EDGE",
            &[&edge.from, &edge.to],
            format_args!("({} → {})", edge.from, edge.to),
        ) else {
            return Ok(false);
        };

        // Reject before `lookup_or_add_node` so neither name lands.
        let new_names = usize::from(!self.node_ids.contains_key(&edge.from))
            + usize::from(!self.node_ids.contains_key(&edge.to));
        if new_names > 0 && self.node_ids.len() + new_names > MAX_NODES {
            log::warn!(target: "tincd::proto",
                       "Dropping ADD_EDGE {} → {}: node table full ({MAX_NODES})",
                       edge.from, edge.to);
            return Ok(false);
        }
        let from_id = self.lookup_or_add_node(&edge.from);
        let to_id = self.lookup_or_add_node(&edge.to);

        if self.graph.lookup_edge(from_id, to_id).is_none() && self.graph.edge_count() >= MAX_EDGES
        {
            log::warn!(target: "tincd::proto",
                       "Dropping ADD_EDGE {} → {}: edge table full ({MAX_EDGES})",
                       edge.from, edge.to);
            return Ok(false);
        }

        let eid = if let Some(existing) = self.graph.lookup_edge(from_id, to_id) {
            // Idempotent only if weight+options+ADDRESS all match.
            // The address compare matters: synthesized reverse from
            // on_ack has no edge_addrs entry; when peer's real
            // ADD_EDGE arrives (same weight/options, real addr), it
            // must fall through to update+forward. Weight-only check
            // early-returned and broke hub-spoke (three_daemon_relay
            // regression). Check edge_addrs too.
            let e = self.graph.edge(existing).expect("just looked up");
            let same_addr = self
                .edge_addrs
                .get(&existing)
                .is_some_and(|(a, p, la, lp)| {
                    // A changed local_address counts as "not same":
                    // dropping local-only updates leaves
                    // LocalDiscovery probing a stale LAN address. An
                    // absent/unspec incoming local (6-token form,
                    // older peers) is NOT a change.
                    let addr_same = a == &edge.addr && p == &edge.port;
                    let local_same = match &edge.local {
                        None => true,
                        Some((nla, _)) if nla.as_str() == AddrStr::UNSPEC => true,
                        Some((nla, nlp)) => nla == la && nlp == lp,
                    };
                    addr_same && local_same
                });
            if e.weight == edge.weight && e.options == edge.options && same_addr {
                return Ok(false); // no forward, no graph()
            }

            // Peer's view of OUR edge is wrong.
            if from_id == self.myself {
                log::debug!(target: "tincd::proto",
                            "Got ADD_EDGE from {conn_name} for ourself \
                             which does not match existing entry");
                // Send back what WE know (existing, not wire body).
                let nw = self.send_add_edge(from_conn, existing);
                return Ok(nw);
            }

            // In-place update. NOT del+add: edge_addrs is keyed on
            // EdgeId; del+add recycles same slot only by
            // LIFO-freelist accident. update_edge makes it explicit.
            log::debug!(target: "tincd::proto",
                        "Got ADD_EDGE from {conn_name} which does not \
                         match existing entry");
            self.graph
                .update_edge(existing, edge.weight, edge.options)
                .expect("lookup_edge just returned this EdgeId; no await, no free");
            existing
        } else if from_id == self.myself {
            // Contradiction - peer says we have an edge we don't.
            // Counter read by on_periodic_tick.
            log::debug!(target: "tincd::proto",
                        "Got ADD_EDGE from {conn_name} for ourself \
                         which does not exist");
            self.contradicting_add_edge += 1;
            // Send DEL with the wire body's names.
            let nw = self.send_del_edge(from_conn, &edge.from, &edge.to);
            return Ok(nw);
        } else {
            self.graph
                .add_edge(from_id, to_id, edge.weight, edge.options)
        };
        // local optional (pre-1.0.24); default to "unspec".
        let (la, lp) = edge
            .local
            .unwrap_or_else(|| (AddrStr::unspec(), AddrStr::unspec()));
        self.edge_addrs.insert(eid, (edge.addr, edge.port, la, lp));

        let nw = if self.settings.tunnelserver {
            false
        } else {
            self.forward_request(from_conn, body)
        };

        // Defer BFS to end of dispatch batch; see `graph_dirty`.
        self.graph_dirty = true;

        Ok(nw)
    }

    /// Missing node/edge is warn-and-drop (NOT `lookup_or_add`).
    pub(in crate::daemon) fn on_del_edge(
        &mut self,
        from_conn: ConnId,
        body: &[u8],
    ) -> Result<bool, DispatchError> {
        let edge = parse_del_edge(body)?;

        let Some(conn_name) = self.flooded_prologue(
            from_conn,
            body,
            "DEL_EDGE",
            &[&edge.from, &edge.to],
            format_args!("({} → {})", edge.from, edge.to),
        ) else {
            return Ok(false);
        };

        // missing → warn-and-drop (view already consistent).
        let Some(&from_id) = self.node_ids.get(&edge.from) else {
            log::debug!(target: "tincd::proto",
                        "Got DEL_EDGE from {conn_name} which does not \
                         appear in the edge tree (unknown from: {})", edge.from);
            return Ok(false);
        };
        let Some(&to_id) = self.node_ids.get(&edge.to) else {
            log::debug!(target: "tincd::proto",
                        "Got DEL_EDGE from {conn_name} which does not \
                         appear in the edge tree (unknown to: {})", edge.to);
            return Ok(false);
        };

        let Some(eid) = self.graph.lookup_edge(from_id, to_id) else {
            log::debug!(target: "tincd::proto",
                        "Got DEL_EDGE from {conn_name} which does not \
                         appear in the edge tree");
            return Ok(false);
        };

        // Peer says we DON'T have an edge we DO have.
        if from_id == self.myself {
            log::debug!(target: "tincd::proto",
                        "Got DEL_EDGE from {conn_name} for ourself");
            self.contradicting_del_edge += 1;
            // Edge exists (just looked up); send what we know.
            let nw = self.send_add_edge(from_conn, eid);
            return Ok(nw);
        }

        let mut nw = if self.settings.tunnelserver {
            false
        } else {
            self.forward_request(from_conn, body)
        };

        self.graph.del_edge(eid);
        self.edge_addrs.remove(&eid);

        self.run_graph_and_log();

        // If `to` became unreachable AND has edge back to us (the
        // synthesized reverse from on_ack), delete + broadcast.
        if !self.graph.node(to_id).is_some_and(|n| n.reachable)
            && let Some(rev) = self.graph.lookup_edge(to_id, self.myself)
        {
            if !self.settings.tunnelserver {
                let line = DelEdge {
                    from: edge.to,
                    to: self.name.clone(),
                }
                .format(Self::nonce());
                // `97ef5af0` bug class: this DEL_EDGE was queued but
                // never armed WRITE. `purge()` below CAN cover it (same
                // conns, broadcast = all active) - but only if purge has
                // anything to broadcast. After `del_edge(rev)` below,
                // `to` has zero outgoing edges; if it also owns no
                // subnets, purge pass-1 emits nothing, `nw_purge=false`,
                // and this line sits for up to pinginterval. OR it in.
                nw |= self.broadcast_line(&line);
            }
            self.graph.del_edge(rev);
            self.edge_addrs.remove(&rev);
        }

        // If the deleted edge disconnected `to` from the mesh, GC it
        // now. Without this, a node that disconnects and has its
        // edges gossiped away stays in `graph` forever - the only
        // other purge triggers are REQ_PURGE (operator-manual) and
        // the contradiction storm (rare). Our slotmap walks are
        // O(slots) for `dump_nodes`/`send_everything`. The check is
        // cheap (one `reachable` read); the actual purge runs only on
        // the unreachability transition.
        if !self.graph.node(to_id).is_some_and(|n| n.reachable) {
            let nw_purge = self.purge();
            return Ok(nw | nw_purge);
        }

        Ok(nw)
    }
}
