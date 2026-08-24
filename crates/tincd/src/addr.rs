//! Address-class filter for peer-supplied dial targets.
//!
//! The `connect.rs` edge-walk feeds gossiped `ADD_EDGE` addresses
//! straight into the outgoing `addr_cache`. Without a class filter a
//! peer could make us `connect()` to `127.0.0.1:22`, `0.0.0.0:port`,
//! multicast, or a link-local address. The handshake won't
//! authenticate, but the TCP SYN does land — a port-scan oracle.
//!
//! RFC1918 / ULA are deliberately kept: a flat-LAN mesh is a supported
//! topology and those are the only addresses such peers have.

#![forbid(unsafe_code)]

use std::net::{IpAddr, SocketAddr};

/// `true` if dialling `ip` from peer-supplied data is never sensible:
/// loopback, unspecified, multicast, v4 link-local / broadcast, v6
/// link-local. Everything else — including RFC1918 and `fc00::/7` —
/// passes.
#[must_use]
pub(crate) fn is_unwanted_dial_target(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_link_local()
                || v4.is_broadcast()
        }
        IpAddr::V6(v6) => {
            // std's v6 predicates all return `false` for the
            // `::ffff:0:0/96` mapped range; re-check as v4.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_unwanted_dial_target(IpAddr::V4(v4));
            }
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || v6.is_unicast_link_local()
        }
    }
}

#[must_use]
pub(crate) fn is_unwanted_dial_addr(sa: &SocketAddr) -> bool {
    is_unwanted_dial_target(sa.ip())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes() {
        let drop = |s: &str| is_unwanted_dial_target(s.parse().unwrap());
        assert!(drop("127.0.0.1"));
        assert!(drop("0.0.0.0"));
        assert!(drop("224.0.0.1"));
        assert!(drop("169.254.1.1"));
        assert!(drop("::1"));
        assert!(drop("fe80::1"));
        // v4-mapped must re-check as v4.
        assert!(drop("::ffff:127.0.0.1"));
        assert!(drop("::ffff:0.0.0.0"));
        assert!(drop("::ffff:169.254.1.1"));
        // RFC1918 / ULA kept.
        assert!(!drop("10.0.0.1"));
        assert!(!drop("::ffff:192.168.1.1"));
        assert!(!drop("fd00::1"));
        assert!(!drop("2001:db8::1"));
    }
}
