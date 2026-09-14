//! One gate for every place a peer endpoint is learnt, chosen or
//! accepted: an address inside a Subnet the mesh advertises is a
//! *tunnel* address. Reaching it means going through the VPN, and a
//! meta connection or UDP path that rides inside the tunnel it is
//! supposed to carry is a loop: it works exactly as long as some
//! other path keeps the tunnel up, then wedges ("Timeout during
//! authentication" on the accept side, silent UDP blackhole on the
//! send side).
//!
//! Without this gate such an address, once seeded anywhere, is
//! self-perpetuating: dialling it succeeds, the ACK persists it into
//! the `addrcache` "recent" tier, the accepting side republishes it
//! as the edge's address (and its own tun address as
//! `local_address`), and every node that walks that edge learns it.
//!
//! Sites, all funnelled through [`Daemon::is_tunnel_addr`]:
//! - TCP accept (`on_tcp_accept`): refused before `ID`.
//! - Outgoing dial (`do_outgoing_connection`): every tier, including
//!   operator `Address =` lines and the persisted recent tier.
//! - Edge gossip consumers ([`Daemon::edge_wire_addr`],
//!   [`Daemon::edge_local_addr`]): the outgoing edge-walk, UDP
//!   candidate choice, `LocalDiscovery`, `BecameReachable` seeding.
//! - Reflexive/relay-observed UDP addresses ([`Daemon::learn_udp_addr`]):
//!   `REQ_KEY`/`ANS_KEY` appendix, `UDP_INFO`, and the source address
//!   of authenticated UDP (`net::helpers::confirm_udp_addr`).
//! - What we publish: `on_ack` sends `local_address = unspec` when
//!   `getsockname` returned a tunnel address.

use std::net::{IpAddr, SocketAddr};

use crate::daemon::Daemon;
use crate::graph::{EdgeId, NodeId};
use crate::local_addr;

impl Daemon {
    /// `ip` lies inside a Subnet somebody advertises (ours included;
    /// see [`crate::subnet_tree::SubnetTree::covers`] for the
    /// default-route carve-out).
    #[must_use]
    pub(crate) fn is_tunnel_addr(&self, ip: IpAddr) -> bool {
        self.subnets.covers(ip)
    }

    /// The edge's wire address (`e.to` as seen by `e.from`), unless
    /// it is a tunnel address or unparseable.
    #[must_use]
    pub(crate) fn edge_wire_addr(&self, eid: EdgeId) -> Option<SocketAddr> {
        let (a, p, _, _) = self.edge_addrs.get(&eid)?;
        local_addr::parse_addr_port(a.as_str(), p.as_str())
            .filter(|sa| !self.is_tunnel_addr(sa.ip()))
    }

    /// The edge's `local_address` (`e.from`'s `getsockname`), unless
    /// it is `unspec` or a tunnel address.
    #[must_use]
    pub(crate) fn edge_local_addr(&self, eid: EdgeId) -> Option<SocketAddr> {
        let (_, _, la, lp) = self.edge_addrs.get(&eid)?;
        local_addr::parse_addr_port(la.as_str(), lp.as_str())
            .filter(|sa| !self.is_tunnel_addr(sa.ip()))
    }

    /// Stash `addr` as `nid`'s UDP endpoint (unconfirmed; the next
    /// probe decides). Refused, with a debug line naming `source`,
    /// when it is a tunnel address. Returns whether it was taken.
    pub(crate) fn learn_udp_addr(&mut self, nid: NodeId, addr: SocketAddr, source: &str) -> bool {
        if self.is_tunnel_addr(addr.ip()) {
            let name = self.graph.node(nid).map_or("<gone>", |n| n.name.as_str());
            log::debug!(target: "tincd::net",
                        "Ignoring UDP address {addr} for {name} ({source}): inside the VPN");
            return false;
        }
        let t = self.dp.tunnels.entry(nid).or_default();
        t.udp_addr = Some(addr);
        t.udp_addr_cached = None; // stale: new candidate supersedes
        true
    }
}
