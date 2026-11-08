//! Peer addresses outside the VPN.
//!
//! An address inside a Subnet the mesh advertises is reached through
//! the tunnel. A meta connection or UDP path using one rides inside the
//! tunnel it carries: it works while some other path keeps the tunnel
//! up, then wedges. Once seeded such an address spreads (persisted as a
//! recent dial address, republished in edges), so every address we
//! dial, accept, send UDP to or publish is an [`UnderlayAddr`], and the
//! only way to get one is [`UnderlayAddr::check`].

use std::fmt;
use std::net::SocketAddr;

use crate::subnet_tree::SubnetTree;

/// A peer address outside every advertised Subnet, as of when it was
/// checked.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) struct UnderlayAddr(SocketAddr);

impl UnderlayAddr {
    /// `None` if `addr` is inside the VPN.
    #[must_use]
    pub(crate) fn check(subnets: &SubnetTree, addr: SocketAddr) -> Option<Self> {
        (!subnets.covers(addr.ip())).then_some(Self(addr))
    }

    #[must_use]
    pub(crate) const fn get(self) -> SocketAddr {
        self.0
    }

    #[cfg(test)]
    pub(crate) const fn unchecked(addr: SocketAddr) -> Self {
        Self(addr)
    }
}

impl fmt::Display for UnderlayAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
