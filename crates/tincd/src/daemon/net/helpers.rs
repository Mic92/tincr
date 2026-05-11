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
use crate::tunnel::TunnelState;

use super::ListenerSlot;

/// Re-warn cadence for [`handle_udp_unreachable`].
const UDP_UNREACHABLE_WARN_INTERVAL: Duration = Duration::from_secs(60);

/// Confirm a peer's UDP address: flip `udp_confirmed`, cache the
/// `SockAddr` + sock index, mirror into the lock-free fast-path handle.
///
/// Gates on `cached.is_none() OR addr changed` — not just addr-change —
/// because gossip seeds `udp_addr` while clearing `udp_addr_cached`.
pub(super) fn confirm_udp_addr(
    tunnels: &mut IntHashMap<NodeId, TunnelState>,
    listeners: &[ListenerSlot],
    tunnel_handles: &IntHashMap<NodeId, Arc<TunnelHandles>>,
    nid: NodeId,
    from_name: &str,
    peer_addr: SocketAddr,
) {
    let tunnel = tunnels.entry(nid).or_default();
    if tunnel.udp_addr_cached.is_some() && tunnel.udp_addr == Some(peer_addr) {
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

/// Returns `true` for `sendmsg` errnos meaning "destination not
/// locally routable" (`ENETUNREACH`, `EHOSTUNREACH`, `EAFNOSUPPORT`,
/// `EADDRNOTAVAIL`).
pub(super) fn is_udp_unreachable_errno(e: &std::io::Error) -> bool {
    let Some(raw) = e.raw_os_error() else {
        return false;
    };
    matches!(
        raw,
        // Stable Linux ABI values.
        101 // ENETUNREACH
        | 113 // EHOSTUNREACH
        | 97  // EAFNOSUPPORT
        | 99  // EADDRNOTAVAIL
    )
}

/// Handle "destination unreachable" on UDP send: clear cached
/// `udp_addr` so `choose_udp_address` picks a different candidate.
/// Rate-limits the warn log to once per [`UDP_UNREACHABLE_WARN_INTERVAL`]
/// per peer. Does NOT tear down SPTPS or pmtu — this is a routing event.
pub(super) fn handle_udp_unreachable(
    tunnels: &mut IntHashMap<NodeId, TunnelState>,
    tunnel_handles: &IntHashMap<NodeId, Arc<TunnelHandles>>,
    relay_nid: NodeId,
    relay_name: &str,
    err: &std::io::Error,
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
        crate::daemon::Daemon::log_pmtu_action(relay_name, &a);
    }
}

/// Offer raw IP `data` to GRO bucket, flushing as needed; falls
/// through to direct device write on `NotCandidate`.
pub(super) fn gro_offer_or_write(
    device: &mut Box<dyn Device>,
    gro: &mut Option<GroBucket>,
    data: &mut [u8],
) {
    const ETH_HLEN: usize = 14;
    let flush = |device: &mut Box<dyn Device>, b: &mut GroBucket| {
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
    use std::io;

    #[test]
    fn is_udp_unreachable_errno_matches_routing_failures() {
        for raw in [101, 113, 97, 99] {
            let e = io::Error::from_raw_os_error(raw);
            assert!(
                is_udp_unreachable_errno(&e),
                "errno {raw} should be classified as udp-unreachable"
            );
        }
        for raw in [90, 11] {
            let e = io::Error::from_raw_os_error(raw);
            assert!(
                !is_udp_unreachable_errno(&e),
                "errno {raw} should NOT be classified as udp-unreachable"
            );
        }
        let e = io::Error::new(io::ErrorKind::Other, "synthetic");
        assert!(!is_udp_unreachable_errno(&e));
    }

    #[test]
    fn handle_udp_unreachable_clears_state_and_rate_limits() {
        use crate::tunnel::TunnelState;
        let mut tunnels: IntHashMap<NodeId, TunnelState> = IntHashMap::default();
        let tunnel_handles: IntHashMap<NodeId, Arc<TunnelHandles>> = IntHashMap::default();
        let nid = NodeId(42);
        let mut t = TunnelState::default();
        t.udp_addr = Some("10.0.0.1:655".parse().unwrap());
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
