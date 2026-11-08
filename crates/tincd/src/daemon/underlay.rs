//! Where wire input becomes [`UnderlayAddr`]s.

use std::net::SocketAddr;

use tinc_proto::Subnet;

use crate::daemon::Daemon;
use crate::graph::{EdgeId, NodeId};
use crate::local_addr;
use crate::subnet_tree;
use crate::underlay::UnderlayAddr;

impl Daemon {
    #[must_use]
    pub(crate) fn underlay(&self, addr: SocketAddr) -> Option<UnderlayAddr> {
        UnderlayAddr::check(&self.subnets, addr)
    }

    /// Where `e.from` saw `e.to`.
    #[must_use]
    pub(crate) fn edge_addr(&self, eid: EdgeId) -> Option<UnderlayAddr> {
        let (a, p, _, _) = self.edge_addrs.get(&eid)?;
        self.underlay(local_addr::parse_addr_port(a.as_str(), p.as_str())?)
    }

    /// `e.from`'s own end of the connection (`getsockname`).
    #[must_use]
    pub(crate) fn edge_local_addr(&self, eid: EdgeId) -> Option<UnderlayAddr> {
        let (_, _, la, lp) = self.edge_addrs.get(&eid)?;
        self.underlay(local_addr::parse_addr_port(la.as_str(), lp.as_str())?)
    }

    /// Offer `addr`, learnt from `source`, as `nid`'s UDP address.
    pub(crate) fn learn_udp_hint(&mut self, nid: NodeId, addr: SocketAddr, source: &str) {
        let Some(addr) = self.underlay(addr) else {
            log::debug!(target: "tincd::net",
                        "Ignoring UDP address {addr} for {} from {source}: inside the VPN",
                        self.node_log_name(nid));
            return;
        };
        if self
            .dp
            .tunnels
            .entry(nid)
            .or_default()
            .path
            .on_addr_hint(addr)
        {
            self.publish_path(nid);
        }
    }

    /// Install `subnet`. Endpoints inside it are tunnel addresses from
    /// now on and are forgotten.
    pub(crate) fn add_subnet(&mut self, subnet: Subnet, owner: String) {
        self.subnets.add(subnet, owner);
        let inside: Vec<NodeId> = self
            .dp
            .tunnels
            .iter()
            .filter(|(_, t)| {
                t.path
                    .addr()
                    .is_some_and(|a| subnet_tree::covers(&subnet, a.ip()))
            })
            .map(|(&nid, _)| nid)
            .collect();
        for nid in inside {
            if let Some(t) = self.dp.tunnels.get_mut(&nid) {
                t.path.forget_endpoint();
            }
            self.publish_path(nid);
        }
    }
}
