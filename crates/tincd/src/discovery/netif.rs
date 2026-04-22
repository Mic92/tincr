//! Local interface enumeration. v6-only: Mainline is a v4 island, and
//! v6 doesn't NAT, so the interface address *is* the reachable address.

use std::net::Ipv6Addr;

/// `getifaddrs()` filtered to v6 global unicast (`2000::/3`). Stable
/// `Ipv6Addr::is_unicast_global` is feature-gated; `(s0 & 0xe000) ==
/// 0x2000` is the same predicate. RFC 4941 temp addrs aren't skipped
/// (`IFA_F_TEMPORARY` not surfaced) — they rotate daily, the 5-min
/// republish catches it.
pub(super) fn enumerate_v6() -> Vec<Ipv6Addr> {
    let Ok(ifaces) = if_addrs::get_if_addrs() else {
        return Vec::new();
    };
    ifaces
        .into_iter()
        .filter_map(|iface| match iface.addr {
            if_addrs::IfAddr::V6(v6) => {
                let ip = v6.ip;
                let s0 = ip.segments()[0];
                ((s0 & 0xe000) == 0x2000).then_some(ip)
            }
            if_addrs::IfAddr::V4(_) => None,
        })
        .collect()
}
