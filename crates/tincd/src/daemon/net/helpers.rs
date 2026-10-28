//! Shared helpers for the net layer.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::PoisonError;
use std::time::{Duration, Instant};

use crate::graph::{Graph, NodeId};
use tinc_device::{Device, GroBucket, GroVerdict};

use crate::inthash::IntHashMap;
use crate::shard::TunnelHandles;
use crate::tunnel::TunnelState;

use super::ListenerSlot;
use crate::daemon::Daemon;
use std::io;
use std::sync::atomic;

/// Re-warn cadence for [`handle_udp_unreachable`].
const UDP_UNREACHABLE_WARN_INTERVAL: Duration = Duration::from_mins(1);

/// Listener index for sending to `addr`: `hint` (where the peer reached
/// us) if its family fits, else the first of the family.
pub(super) fn listener_for(listeners: &[ListenerSlot], addr: &SocketAddr, hint: u8) -> u8 {
    let fits = |s: &ListenerSlot| s.listener.local.is_ipv4() == addr.is_ipv4();
    if listeners.get(usize::from(hint)).is_some_and(fits) {
        return hint;
    }
    listeners
        .iter()
        .position(fits)
        .and_then(|i| u8::try_from(i).ok())
        .unwrap_or(0)
}

/// Every `UdpPath` transition ends here.
pub(super) fn publish_path(
    tunnels: &mut IntHashMap<NodeId, TunnelState>,
    listeners: &[ListenerSlot],
    tunnel_handles: &IntHashMap<NodeId, Arc<TunnelHandles>>,
    nid: NodeId,
) {
    let Some(t) = tunnels.get_mut(&nid) else {
        return;
    };
    let moved = t.path.refresh_target(|a, h| listener_for(listeners, a, h));
    if let Some(h) = tunnel_handles.get(&nid) {
        if moved {
            *h.udp_addr.lock().unwrap_or_else(PoisonError::into_inner) = t.path.target().cloned();
        }
        h.minmtu.store(t.path.minmtu(), atomic::Ordering::Relaxed);
    }
}

impl Daemon {
    pub(in crate::daemon) fn debug_check_paths(&self) {
        if !cfg!(debug_assertions) {
            return;
        }
        for (nid, t) in &self.dp.tunnels {
            let derived = t
                .path
                .derive_target(|a, h| listener_for(&self.listeners, a, h));
            debug_assert!(t.path.target() == derived.as_ref(), "{nid:?}: stale target");
            if let Some(h) = self.tunnel_handles.get(nid) {
                debug_assert!(t.status.validkey, "{nid:?}: fast path outlived its session");
                let published = h.udp_addr.lock().unwrap_or_else(PoisonError::into_inner);
                debug_assert!(*published == derived, "{nid:?}: stale fast-path addr");
                debug_assert_eq!(
                    h.minmtu.load(atomic::Ordering::Relaxed),
                    t.path.minmtu(),
                    "{nid:?}: stale fast-path minmtu"
                );
            }
        }
    }

    pub(in crate::daemon) fn publish_path(&mut self, nid: NodeId) {
        publish_path(
            &mut self.dp.tunnels,
            &self.listeners,
            &self.tunnel_handles,
            nid,
        );
    }
}

/// `sendmsg` errnos meaning the destination address is unusable from
/// here, so it should be forgotten. `EPERM` is a firewall reject; `EIO`
/// is what Android returns when a protected socket targets an address
/// routed back into the VPN.
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

/// "Destination unreachable" on UDP send. A routing event: SPTPS stays.
pub(super) fn handle_udp_unreachable(
    tunnels: &mut IntHashMap<NodeId, TunnelState>,
    listeners: &[ListenerSlot],
    tunnel_handles: &IntHashMap<NodeId, Arc<TunnelHandles>>,
    relay_nid: NodeId,
    relay_name: &str,
    err: &io::Error,
    now: Instant,
) -> bool {
    let warn = tunnels
        .get_mut(&relay_nid)
        .is_none_or(|t| t.path.on_unreachable(now, UDP_UNREACHABLE_WARN_INTERVAL));
    publish_path(tunnels, listeners, tunnel_handles, relay_nid);

    if warn {
        log::warn!(target: "tincd::net",
                   "UDP send to {relay_name} failed: {err}; \
                    clearing cached address, will retry via cold path");
    }
    warn
}

/// `EMSGSIZE` on UDP send. The frames are the caller's to re-route or drop.
pub(super) fn handle_udp_emsgsize(
    tunnels: &mut IntHashMap<NodeId, TunnelState>,
    listeners: &[ListenerSlot],
    graph: &Graph,
    tunnel_handles: &IntHashMap<NodeId, Arc<TunnelHandles>>,
    relay_nid: NodeId,
    origlen: u16,
) {
    let Some(t) = tunnels.get_mut(&relay_nid) else {
        return;
    };
    let relay_name = graph.node(relay_nid).map_or("<gone>", |n| n.name.as_str());
    for a in t.path.on_emsgsize(origlen) {
        Daemon::log_pmtu_action(relay_name, &a);
    }
    publish_path(tunnels, listeners, tunnel_handles, relay_nid);
}

/// Offer raw IP `data` to GRO bucket, flushing as needed; falls
/// through to direct device write on `NotCandidate`.
pub(crate) fn gro_offer_or_write(
    device: &mut dyn Device,
    gro: &mut Option<GroBucket>,
    data: &[u8],
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
        && let Some(ip) = data.get(ETH_HLEN..).filter(|ip| !ip.is_empty())
    {
        match bucket.offer(ip) {
            GroVerdict::Coalesced => return,
            GroVerdict::FlushFirst => {
                flush(device, bucket);
                let v = bucket.offer(ip);
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

    #[test]
    fn handle_udp_unreachable_clears_state_and_rate_limits() {
        let mut tunnels: IntHashMap<NodeId, TunnelState> = IntHashMap::default();
        let tunnel_handles: IntHashMap<NodeId, Arc<TunnelHandles>> = IntHashMap::default();
        let nid = NodeId(42);
        let now = Instant::now();
        let mut t = TunnelState::default();
        t.path
            .on_authenticated_rx("10.0.0.1:655".parse().unwrap(), 0);
        let _ = t.path.on_probe_reply(1400, now);
        assert!(t.path.refresh_target(|_, _| 0));
        tunnels.insert(nid, t);

        let err = io::Error::from_raw_os_error(101);
        let mut fail = |nid, secs| {
            let at = now + Duration::from_secs(secs);
            handle_udp_unreachable(&mut tunnels, &[], &tunnel_handles, nid, "peer", &err, at)
        };
        let warned: Vec<bool> = [0, 30, 61, 90].map(|s| fail(nid, s)).into();
        assert_eq!(warned, [true, false, true, false]);
        assert!(fail(NodeId(99), 0));

        let t = tunnels.get(&nid).expect("tunnel still present");
        assert!(t.path.addr().is_none());
        assert!(t.path.target().is_none());
        assert!(!t.path.confirmed());
        assert_eq!(t.path.minmtu(), 0);
    }
}
