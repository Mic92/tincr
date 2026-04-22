//! Address-class predicates shared by the discovery and outgoing-dial
//! paths.
//!
//! Both `discovery::parse_record` (DHT-published self-report) and the
//! `connect.rs` edge-walk (gossiped `ADD_EDGE` addresses) take peer-
//! supplied `SocketAddr`s and feed them straight into the outgoing
//! `addr_cache`. Without a class filter that's a blind-SSRF dial: a
//! peer (or, pre-D1-fix, *any* node on the DHT query path) could make
//! us `connect()` to `127.0.0.1:22`, `0.0.0.0:port`, multicast, or a
//! link-local address. The handshake won't authenticate, but the TCP
//! SYN does land — port-scan oracle, and on some services a tinc ID
//! line is enough to log/crash.
//!
//! RFC1918 / ULA are deliberately **kept**: a flat-LAN mesh is a
//! supported topology and those are the only addresses such peers
//! *have*. Gating private ranges belongs behind a future config knob,
//! not a hard filter.

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
            // `::ffff:0:0/96` — std's v6 predicates all return
            // `false` for the mapped range, so `[::ffff:127.0.0.1]`
            // would sail past. Re-check as v4.
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

/// Convenience: `is_unwanted_dial_target` on a `SocketAddr`.
#[must_use]
pub(crate) fn is_unwanted_dial_addr(sa: &SocketAddr) -> bool {
    is_unwanted_dial_target(sa.ip())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only the non-obvious edges: v4-mapped v6 must re-check as v4
    /// (std's `Ipv6Addr::is_loopback` is `false` for
    /// `::ffff:127.0.0.1`); RFC1918/ULA must pass. The plain
    /// loopback/link-local cases are covered end-to-end by
    /// `discovery::tests::parse_record_filters_unwanted_addr_classes`.
    #[test]
    fn v4_mapped_and_private_ranges() {
        let drop = |s: &str| is_unwanted_dial_target(s.parse().unwrap());
        // v4-mapped bypass closed.
        assert!(drop("::ffff:127.0.0.1"));
        assert!(drop("::ffff:0.0.0.0"));
        assert!(drop("::ffff:169.254.1.1"));
        // RFC1918 / ULA kept (incl. via the mapped path).
        assert!(!drop("10.0.0.1"));
        assert!(!drop("::ffff:192.168.1.1"));
        assert!(!drop("fd00::1"));
    }
}
