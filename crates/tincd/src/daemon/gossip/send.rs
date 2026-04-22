//! Outbound gossip formatters: `fmt_add_edge`, `send_everything`, …

use crate::daemon::{ConnId, Daemon};

use tinc_graph::EdgeId;
use tinc_proto::msg::{AddEdge, DelEdge, SubnetMsg};
use tinc_proto::{AddrStr, Request, Subnet};

impl Daemon {
    /// Returns `None` if edge or addr entry missing - the
    /// synthesized reverse from `on_ack` has no addr; skip rather
    /// than emit `"unknown port unknown"` (peers would parse to
    /// `AF_UNKNOWN`, never connect).
    pub(in crate::daemon) fn fmt_add_edge(&self, eid: EdgeId, nonce: u32) -> Option<String> {
        let e = self.graph.edge(eid)?;
        let (addr, port, la, lp) = self.edge_addrs.get(&eid)?;
        let from = self.graph.node(e.from)?.name.clone();
        let to = self.graph.node(e.to)?.name.clone();
        // Our sentinel is "unspec" string.
        let local = if la.as_str() == AddrStr::UNSPEC {
            None
        } else {
            Some((la.clone(), lp.clone()))
        };
        let msg = AddEdge {
            from,
            to,
            addr: addr.clone(),
            port: port.clone(),
            options: e.options,
            weight: e.weight,
            local,
        };
        Some(msg.format(nonce))
    }

    /// Correction path: send back what WE know about an edge.
    pub(in crate::daemon) fn send_add_edge(&mut self, to: ConnId, eid: EdgeId) -> bool {
        let Some(line) = self.fmt_add_edge(eid, Self::nonce()) else {
            log::warn!(target: "tincd::proto",
                       "send_add_edge: edge {eid:?} has no addr entry, skipping");
            return false;
        };
        self.conns
            .get_mut(to)
            .is_some_and(|c| c.send(format_args!("{line}")))
    }

    /// Contradiction reply: take names directly.
    pub(in crate::daemon) fn send_del_edge(
        &mut self,
        to: ConnId,
        from_name: &str,
        to_name: &str,
    ) -> bool {
        let msg = DelEdge {
            from: from_name.to_owned(),
            to: to_name.to_owned(),
        };
        let line = msg.format(Self::nonce());
        self.conns
            .get_mut(to)
            .is_some_and(|c| c.send(format_args!("{line}")))
    }

    pub(in crate::daemon) fn send_subnet(
        &mut self,
        to: ConnId,
        which: Request,
        owner: &str,
        subnet: &Subnet,
    ) -> bool {
        let msg = SubnetMsg {
            owner: owner.to_owned(),
            subnet: *subnet,
        };
        let line = msg.format(which, Self::nonce());
        self.conns
            .get_mut(to)
            .is_some_and(|c| c.send(format_args!("{line}")))
    }

    /// Called from `on_ack`. Flatten over global trees - same wire
    /// output, order irrelevant.
    pub(in crate::daemon) fn send_everything(&mut self, to: ConnId) -> bool {
        if self.settings.tunnelserver {
            // ONLY myself's subnets, NO edges. Peer's edge to us
            // comes from on_ack's send_add_edge.
            let mut lines: Vec<String> = Vec::new();
            for (subnet, owner) in self.subnets.iter() {
                if owner == self.name.as_str() {
                    let msg = SubnetMsg {
                        owner: owner.to_owned(),
                        subnet: *subnet,
                    };
                    lines.push(msg.format(Request::AddSubnet, Self::nonce()));
                }
            }
            let Some(conn) = self.conns.get_mut(to) else {
                return false;
            };
            let mut nw = false;
            for line in lines {
                nw |= conn.send(format_args!("{line}"));
            }
            log::debug!(target: "tincd::proto",
                        "send_everything (tunnelserver) to {}: own subnets only",
                        conn.name);
            return nw;
        }
        // Pre-format: subnets.iter() borrows &self; conn.send() needs &mut.
        let mut lines: Vec<String> = Vec::new();

        for (subnet, owner) in self.subnets.iter() {
            let msg = SubnetMsg {
                owner: owner.to_owned(),
                subnet: *subnet,
            };
            lines.push(msg.format(Request::AddSubnet, Self::nonce()));
        }

        // Addr-less edges (synthesized reverse) skipped by
        // fmt_add_edge; peer learns them from the other endpoint.
        let eids: Vec<EdgeId> = self.graph.edge_iter().map(|(id, _)| id).collect();
        for eid in eids {
            if let Some(line) = self.fmt_add_edge(eid, Self::nonce()) {
                lines.push(line);
            }
        }

        let Some(conn) = self.conns.get_mut(to) else {
            return false;
        };
        let mut nw = false;
        for line in lines {
            nw |= conn.send(format_args!("{line}"));
        }
        log::debug!(target: "tincd::proto",
                    "send_everything to {}: {} subnets, {} edges sent",
                    conn.name, self.subnets.len(),
                    self.edge_addrs.len());
        nw
    }
}
