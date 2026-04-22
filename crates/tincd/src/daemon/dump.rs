//! Control-socket `DUMP_*` row formatters. Not gossip — moved out of
//! `gossip.rs` so "where does message X get handled" stays grep-free.

use super::Daemon;

use crate::listen::fmt_addr;
use crate::node_id::NodeId6;

use tinc_proto::Request;

impl Daemon {
    /// 21 fields per row; CLI parses 22 (`" port "` re-split).
    /// Placeholders: cipher/digest/maclength=0 (legacy-only);
    /// `last_state_change=0` (deferred). status bitfield: bit 4
    /// reachable feeds CLI's filter.
    pub(super) fn dump_nodes_rows(&self) -> Vec<String> {
        let mut rows = Vec::new();
        for nid in self.graph.node_ids() {
            let Some(node) = self.graph.node(nid) else {
                continue; // freed slot (concurrent del; defensive)
            };
            let name = node.name.as_str();

            // myself = "MYSELF port <tcp>". Direct peers: address
            // rewritten to UDP in on_ack. Transitives: literal.
            let hostname = if nid == self.myself {
                format!("MYSELF port {}", self.my_udp_port)
            } else if let Some(ea) = self.nodes.get(&nid).and_then(|ns| ns.edge_addr.as_ref()) {
                fmt_addr(ea) // "%s port %s", no v6 brackets
            } else if let Some(addr) = self.dp.tunnels.get(&nid).and_then(|t| t.udp_addr) {
                // Indirect node: address learned via UDP (hole-punch /
                // UDP_INFO), not meta-conn ACK. C: update_node_udp().
                // IpAddr Display has no v6 brackets, matches "%s port %s".
                format!("{} port {}", addr.ip(), addr.port())
            } else {
                "unknown port unknown".to_string()
            };

            // options: written by sssp from incoming edge. myself: 0.
            // Unreachable: 0.
            let route = self.route_of(nid);
            let options = route.map_or(0, |r| r.options);

            // status. myself: just reachable.
            let tunnel = self.dp.tunnels.get(&nid);
            let status = tunnel.map_or_else(
                || {
                    if node.reachable { 1 << 4 } else { 0 }
                },
                |t| t.status.as_u32(node.reachable),
            );

            // Unreachable → "-".
            let (nexthop, via, distance) = match route {
                Some(r) => {
                    let nh = self.graph.node(r.nexthop).map_or("-", |n| n.name.as_str());
                    let via = self.graph.node(r.via).map_or("-", |n| n.name.as_str());
                    (nh, via, r.distance)
                }
                None => ("-", "-", 0),
            };

            // udp_ping_rtt=-1 is the unmeasured sentinel.
            rows.push(format!(
                "{} {} {} {} {} {} {} {} {} {:x} {:x} {} {} {} {} {} {} {} {} {} {} {} {}",
                Request::Control,                                   // %d CONTROL
                crate::proto::REQ_DUMP_NODES,                       // %d
                name,                                               // %s
                self.id6_table.id_of(nid).unwrap_or(NodeId6::NULL), // %s id
                hostname,                                           // %s ("HOST port PORT")
                0,                                                  // %d cipher (DISABLE_LEGACY)
                0,                                                  // %d digest
                0,                                                  // %lu maclength
                tunnel.map_or(0, |t| t.outcompression),             // %d compression
                options,                                            // %x
                status,                                             // %x
                nexthop,                                            // %s
                via,                                                // %s
                distance,                                           // %d
                tunnel.and_then(|t| t.pmtu.as_ref()).map_or(0, |p| p.mtu), // %d mtu
                tunnel.and_then(|t| t.pmtu.as_ref()).map_or(0, |p| p.minmtu), // %d minmtu
                tunnel.and_then(|t| t.pmtu.as_ref()).map_or(0, |p| p.maxmtu), // %d maxmtu
                0,                                                  // %ld last_state_change
                tunnel
                    .and_then(|t| t.pmtu.as_ref())
                    .and_then(|p| p.udp_ping_rtt)
                    .map_or(-1_i32, u32::cast_signed), // %d
                tunnel.map_or(0, |t| t.stats.in_packets()),         // %PRIu64
                tunnel.map_or(0, |t| t.stats.in_bytes()),
                tunnel.map_or(0, |t| t.stats.out_packets()),
                tunnel.map_or(0, |t| t.stats.out_bytes()),
            ));
        }
        rows
    }

    /// 6 body fields; CLI parses 8 (two `" port "` re-splits).
    /// `edge_addrs` stores raw `AddrStr` tokens; format as `"%s port %s"`.
    pub(super) fn dump_edges_rows(&self) -> Vec<String> {
        let mut rows = Vec::new();
        // Order differs from a tree walk; tincctl sorts client-side
        // anyway.
        for (eid, e) in self.graph.edge_iter() {
            let from = self.node_log_name(e.from);
            let to = self.node_log_name(e.to);

            let (addr, local) = match self.edge_addrs.get(&eid) {
                Some((a, p, la, lp)) => (format!("{a} port {p}"), format!("{la} port {lp}")),
                // Synthesized reverse (see on_ack).
                None => (
                    "unknown port unknown".to_string(),
                    "unknown port unknown".to_string(),
                ),
            };

            rows.push(format!(
                "{} {} {} {} {} {} {:x} {}",
                Request::Control,
                crate::proto::REQ_DUMP_EDGES,
                from,
                to,
                addr,
                local,
                e.options,
                e.weight,
            ));
        }
        rows
    }

    /// Walk all known nodes (not just tunnels): includes myself +
    /// unreachables. Nodes without a `TunnelState` emit zeros.
    pub(super) fn dump_traffic_rows(&self) -> Vec<String> {
        let mut rows = Vec::new();
        for nid in self.graph.node_ids() {
            let Some(node) = self.graph.node(nid) else {
                continue;
            };
            let t = self.dp.tunnels.get(&nid);
            rows.push(format!(
                "{} {} {} {} {} {} {}",
                Request::Control,
                crate::proto::REQ_DUMP_TRAFFIC,
                node.name.as_str(),
                t.map_or(0, |t| t.stats.in_packets()),
                t.map_or(0, |t| t.stats.in_bytes()),
                t.map_or(0, |t| t.stats.out_packets()),
                t.map_or(0, |t| t.stats.out_bytes()),
            ));
        }
        rows
    }
}
