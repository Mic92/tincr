//! Shared helpers for the net layer.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::graph::{Graph, NodeId};
use socket2::SockAddr;
use tinc_device::{Device, GroBucket, GroVerdict};

use crate::inthash::IntHashMap;
use crate::local_addr;
use crate::shard::TunnelHandles;
use crate::subnet_tree::SubnetTree;
use crate::tunnel::TunnelState;

use super::ListenerSlot;
use crate::daemon::Daemon;
use std::io;

/// Re-warn cadence for [`handle_udp_unreachable`].
const UDP_UNREACHABLE_WARN_INTERVAL: Duration = Duration::from_mins(1);

/// Confirm a peer's UDP address: flip `udp_confirmed`, cache the
/// `SockAddr` + sock index, mirror into the lock-free fast-path handle.
/// Gates on `cached.is_none() OR addr changed` — not just addr-change —
/// because gossip seeds `udp_addr` while clearing `udp_addr_cached`.
/// A source inside the mesh's own Subnets came through the tunnel (see
/// `daemon::endpoint`): processed, but never becomes the endpoint.
/// Checked after the steady-state early return, so per-packet cost is nil.
pub(super) fn confirm_udp_addr(
    tunnels: &mut IntHashMap<NodeId, TunnelState>,
    listeners: &[ListenerSlot],
    tunnel_handles: &IntHashMap<NodeId, Arc<TunnelHandles>>,
    subnets: &SubnetTree,
    nid: NodeId,
    from_name: &str,
    peer_addr: SocketAddr,
) {
    let tunnel = tunnels.entry(nid).or_default();
    if tunnel.udp_addr_cached.is_some() && tunnel.udp_addr == Some(peer_addr) {
        return;
    }
    if subnets.covers(peer_addr.ip()) {
        log::debug!(target: "tincd::net",
                    "Ignoring UDP address {peer_addr} for {from_name} (datagram source): inside the VPN");
        return;
    }
    let listener_addrs: Vec<SocketAddr> = listeners.iter().map(|s| s.listener.local).collect();
    let sock = local_addr::adapt_socket(&peer_addr, 0, &listener_addrs);
    if !tunnel.status.udp_confirmed {
        log::debug!(target: "tincd::net",
                    "UDP address of {from_name} confirmed: {peer_addr}");
        tunnel.status.udp_confirmed = true;
    }
    tunnel.udp_addr = Some(peer_addr);
    let cached = (SockAddr::from(peer_addr), sock);
    tunnel.udp_addr_cached = Some(cached.clone());
    if let Some(h) = tunnel_handles.get(&nid) {
        *h.udp_addr.lock().unwrap() = Some(cached);
    }
}

/// `sendmsg` errnos meaning "this destination cannot be sent to from
/// here": routing (`ENETUNREACH`, `EHOSTUNREACH`, `ENETDOWN`), family/
/// source (`EAFNOSUPPORT`, `EADDRNOTAVAIL`) and policy (`EPERM`:
/// firewall; `EIO`: Android refusing a VPN-protected socket a destination
/// that routes back into the VPN). Same reaction for all: forget the
/// address so the next send goes cold path or TCP relay. `EMSGSIZE`/
/// `EAGAIN` are handled elsewhere and are not "this address is wrong".
pub(super) fn is_udp_unreachable_errno(e: &io::Error) -> bool {
    let Some(raw) = e.raw_os_error() else {
        return false;
    };
    matches!(
        raw,
        libc::ENETUNREACH
            | libc::EHOSTUNREACH
            | libc::ENETDOWN
            | libc::EAFNOSUPPORT
            | libc::EADDRNOTAVAIL
            | libc::EPERM
            | libc::EIO
    )
}

/// Handle "destination unreachable" on UDP send: clear cached
/// `udp_addr` so `choose_udp_address` picks a different candidate.
/// Rate-limits the warn log to once per [`UDP_UNREACHABLE_WARN_INTERVAL`]
/// per peer. Does not tear down SPTPS or pmtu — this is a routing event.
pub(super) fn handle_udp_unreachable(
    tunnels: &mut IntHashMap<NodeId, TunnelState>,
    tunnel_handles: &IntHashMap<NodeId, Arc<TunnelHandles>>,
    relay_nid: NodeId,
    relay_name: &str,
    err: &io::Error,
    now: Instant,
) {
    let warn_now = if let Some(tunnel) = tunnels.get_mut(&relay_nid) {
        let warn_now = tunnel
            .udp_send_failed_at
            .is_none_or(|t| now.saturating_duration_since(t) >= UDP_UNREACHABLE_WARN_INTERVAL);
        tunnel.udp_send_failed_at = Some(now);
        tunnel.udp_addr = None;
        tunnel.udp_addr_cached = None;
        tunnel.status.udp_confirmed = false;
        if let Some(p) = tunnel.pmtu.as_mut() {
            p.udp_confirmed = false;
        }
        warn_now
    } else {
        true
    };

    if let Some(h) = tunnel_handles.get(&relay_nid)
        && let Ok(mut g) = h.udp_addr.lock()
    {
        *g = None;
    }

    if warn_now {
        log::warn!(target: "tincd::net",
                   "UDP send to {relay_name} failed: {err}; \
                    clearing cached address, will retry via cold path");
    }
}

/// `EMSGSIZE` on UDP send: shrink relay's `maxmtu` so the next
/// batch fits. Current frames are lost; inner-TCP retransmits.
pub(super) fn handle_udp_emsgsize(
    tunnels: &mut IntHashMap<NodeId, TunnelState>,
    graph: &Graph,
    relay_nid: NodeId,
    origlen: u16,
) {
    let Some(p) = tunnels.get_mut(&relay_nid).and_then(|t| t.pmtu.as_mut()) else {
        return;
    };
    let relay_name = graph.node(relay_nid).map_or("<gone>", |n| n.name.as_str());
    for a in p.on_emsgsize(origlen) {
        Daemon::log_pmtu_action(relay_name, &a);
    }
}

/// Offer raw IP `data` to GRO bucket, flushing as needed; falls
/// through to direct device write on `NotCandidate`.
pub(crate) fn gro_offer_or_write(
    device: &mut dyn Device,
    gro: &mut Option<GroBucket>,
    data: &mut [u8],
) {
    const ETH_HLEN: usize = 14;
    let flush = |device: &mut dyn Device, b: &mut GroBucket| {
        if let Some(buf) = b.flush()
            && let Err(e) = device.write_super(buf)
        {
            log::warn!(target: "tincd::net",
                       "GRO super write failed: {e} — \
                        gro_enabled gate let a non-vnet device through?");
        }
    };
    if let Some(bucket) = gro.as_mut()
        && data.len() > ETH_HLEN
    {
        match bucket.offer(&data[ETH_HLEN..]) {
            GroVerdict::Coalesced => return,
            GroVerdict::FlushFirst => {
                flush(device, bucket);
                let v = bucket.offer(&data[ETH_HLEN..]);
                debug_assert_ne!(v, GroVerdict::FlushFirst);
                if v == GroVerdict::Coalesced {
                    return;
                }
            }
            GroVerdict::NotCandidate => {
                // Flush first to preserve ordering.
                flush(device, bucket);
            }
        }
    }
    if let Err(e) = device.write(data) {
        log::debug!(target: "tincd::net", "Error writing to device: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::TunnelState;
    use std::io;

    #[test]
    fn is_udp_unreachable_errno_matches_routing_failures() {
        for raw in [
            libc::ENETUNREACH,
            libc::EHOSTUNREACH,
            libc::ENETDOWN,
            libc::EAFNOSUPPORT,
            libc::EADDRNOTAVAIL,
            libc::EPERM,
            libc::EIO,
        ] {
            let e = io::Error::from_raw_os_error(raw);
            assert!(
                is_udp_unreachable_errno(&e),
                "errno {raw} should be classified as udp-unreachable"
            );
        }
        for raw in [libc::EMSGSIZE, libc::EAGAIN] {
            let e = io::Error::from_raw_os_error(raw);
            assert!(
                !is_udp_unreachable_errno(&e),
                "errno {raw} should NOT be classified as udp-unreachable"
            );
        }
        let e = io::Error::other("synthetic");
        assert!(!is_udp_unreachable_errno(&e));
    }

    /// A datagram whose source is a tunnel address never becomes the
    /// peer's endpoint, even on the first (uncached) packet; a LAN
    /// source does.
    #[test]
    fn confirm_udp_addr_ignores_tunnel_sources() {
        let mut tunnels: IntHashMap<NodeId, TunnelState> = IntHashMap::default();
        let tunnel_handles: IntHashMap<NodeId, Arc<TunnelHandles>> = IntHashMap::default();
        let mut subnets = SubnetTree::new();
        subnets.add("42:0:ce16::113/128".parse().unwrap(), "bob".into());
        let nid = NodeId(7);

        let tun_src: SocketAddr = "[42:0:ce16::113]:35710".parse().unwrap();
        confirm_udp_addr(
            &mut tunnels,
            &[],
            &tunnel_handles,
            &subnets,
            nid,
            "bob",
            tun_src,
        );
        let t = tunnels.get(&nid).expect("entry created");
        assert!(t.udp_addr.is_none(), "tunnel source must not be learnt");
        assert!(!t.status.udp_confirmed);

        let lan_src: SocketAddr = "10.79.131.61:40483".parse().unwrap();
        confirm_udp_addr(
            &mut tunnels,
            &[],
            &tunnel_handles,
            &subnets,
            nid,
            "bob",
            lan_src,
        );
        let t = tunnels.get(&nid).unwrap();
        assert_eq!(t.udp_addr, Some(lan_src));
        assert!(t.status.udp_confirmed);
    }

    #[test]
    fn handle_udp_unreachable_clears_state_and_rate_limits() {
        let mut tunnels: IntHashMap<NodeId, TunnelState> = IntHashMap::default();
        let tunnel_handles: IntHashMap<NodeId, Arc<TunnelHandles>> = IntHashMap::default();
        let nid = NodeId(42);
        let mut t = TunnelState {
            udp_addr: Some("10.0.0.1:655".parse().unwrap()),
            ..TunnelState::default()
        };
        let lo: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        t.udp_addr_cached = Some((SockAddr::from(lo), 0));
        t.status.udp_confirmed = true;
        tunnels.insert(nid, t);

        let now = Instant::now();
        let err = io::Error::from_raw_os_error(101);
        handle_udp_unreachable(&mut tunnels, &tunnel_handles, nid, "peer", &err, now);

        let t = tunnels.get(&nid).expect("tunnel still present");
        assert!(t.udp_addr.is_none(), "udp_addr cleared");
        assert!(t.udp_addr_cached.is_none(), "udp_addr_cached cleared");
        assert!(!t.status.udp_confirmed, "udp_confirmed cleared");
        assert_eq!(
            t.udp_send_failed_at,
            Some(now),
            "failed-at timestamp stamped"
        );

        // Idempotent: second call on same timestamp suppresses warn.
        handle_udp_unreachable(&mut tunnels, &tunnel_handles, nid, "peer", &err, now);
        let t = tunnels.get(&nid).unwrap();
        assert_eq!(
            t.udp_send_failed_at,
            Some(now),
            "still stamped, not regressed"
        );

        let missing = NodeId(99);
        handle_udp_unreachable(&mut tunnels, &tunnel_handles, missing, "ghost", &err, now);
    }
}
