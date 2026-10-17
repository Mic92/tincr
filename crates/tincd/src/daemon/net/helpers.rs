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
use crate::daemon::Daemon;
use std::io;
use std::sync::atomic;

/// Re-warn cadence for [`handle_udp_unreachable`].
const UDP_UNREACHABLE_WARN_INTERVAL: Duration = Duration::from_mins(1);

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

/// Handle "destination unreachable" on UDP send: clear cached
/// `udp_addr` so `choose_udp_address` picks a different candidate, and
/// treat it as a UDP timeout (`minmtu = 0`, rediscover) so data falls
/// back to TCP until UDP is confirmed again; every other `minmtu`
/// reset is gated on `udp_confirmed`. Rate-limits the warn log to once
/// per [`UDP_UNREACHABLE_WARN_INTERVAL`] per peer. SPTPS is kept.
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
        if warn_now {
            tunnel.udp_send_failed_at = Some(now);
        }
        tunnel.udp_addr = None;
        tunnel.udp_addr_cached = None;
        tunnel.status.udp_confirmed = false;
        if let Some(p) = tunnel.pmtu.as_mut() {
            p.on_udp_timeout();
        }
        warn_now
    } else {
        true
    };

    if let Some(h) = tunnel_handles.get(&relay_nid) {
        if let Ok(mut g) = h.udp_addr.lock() {
            *g = None;
        }
        h.minmtu.store(0, atomic::Ordering::Relaxed);
    }

    if warn_now {
        log::warn!(target: "tincd::net",
                   "UDP send to {relay_name} failed: {err}; \
                    clearing cached address, will retry via cold path");
    }
}

/// `EMSGSIZE` on UDP send: clamp the relay's PMTU bounds below
/// `origlen` and publish the new `minmtu` to the shard fast path so
/// larger bodies go TCP. The triggering frame(s) are the caller's to
/// re-route or drop.
pub(super) fn handle_udp_emsgsize(
    tunnels: &mut IntHashMap<NodeId, TunnelState>,
    graph: &Graph,
    tunnel_handles: &IntHashMap<NodeId, Arc<TunnelHandles>>,
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
    if let Some(h) = tunnel_handles.get(&relay_nid) {
        h.minmtu.store(p.minmtu, atomic::Ordering::Relaxed);
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
    use crate::pmtu::{MTU, PmtuPhase, PmtuState};
    use crate::tunnel::TunnelState;
    use std::io;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64};

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
        // Continuous failure re-warns once per interval instead of
        // pushing the deadline out on every send.
        let later = now + Duration::from_secs(30);
        handle_udp_unreachable(&mut tunnels, &tunnel_handles, nid, "peer", &err, later);
        assert_eq!(tunnels[&nid].udp_send_failed_at, Some(now));
        let later = now + UDP_UNREACHABLE_WARN_INTERVAL;
        handle_udp_unreachable(&mut tunnels, &tunnel_handles, nid, "peer", &err, later);
        assert_eq!(tunnels[&nid].udp_send_failed_at, Some(later));

        let missing = NodeId(99);
        handle_udp_unreachable(&mut tunnels, &tunnel_handles, missing, "ghost", &err, now);
    }

    /// Regression (retiolum radio→styx): only `udp_confirmed` was
    /// cleared, so `minmtu` kept data on UDP to a dead address and no
    /// `udp_confirmed`-gated path ever reset it. Must end where a UDP
    /// timeout does: `minmtu` 0 in both copies, discovery restarted.
    #[test]
    fn handle_udp_unreachable_drops_minmtu() {
        let now = Instant::now();
        let nid = NodeId(42);
        let mut p = PmtuState::new(now, MTU);
        (p.mtu, p.minmtu, p.maxmtu) = (1400, 1400, 1400);
        p.phase = PmtuPhase::Steady;
        p.udp_confirmed = true;
        let mut tunnels: IntHashMap<NodeId, TunnelState> = IntHashMap::default();
        tunnels.insert(
            nid,
            TunnelState {
                udp_addr: Some("[2001:db8::1]:655".parse().unwrap()),
                pmtu: Some(p),
                ..TunnelState::default()
            },
        );
        let cipher =
            || tinc_crypto::aead::SptpsCipher::new(tinc_sptps::SptpsAead::default(), &[0u8; 64]);
        let addr: SocketAddr = "[2001:db8::1]:655".parse().unwrap();
        let h = Arc::new(TunnelHandles {
            outseqno: Arc::new(AtomicU64::new(0)),
            out_key_base: 0,
            replay: Arc::default(),
            outcipher: cipher(),
            incipher: cipher(),
            udp_addr: Mutex::new(Some((SockAddr::from(addr), 0))),
            validkey: AtomicBool::new(true),
            minmtu: AtomicU16::new(1400),
            outcompression: 0,
            stats: Arc::default(),
        });
        let mut tunnel_handles: IntHashMap<NodeId, Arc<TunnelHandles>> = IntHashMap::default();
        tunnel_handles.insert(nid, Arc::clone(&h));

        let err = io::Error::from_raw_os_error(libc::ENETUNREACH);
        handle_udp_unreachable(&mut tunnels, &tunnel_handles, nid, "styx", &err, now);

        let t = &tunnels[&nid];
        assert_eq!(t.minmtu(), 0, "data must take the TCP gate");
        let p = t.pmtu.as_ref().unwrap();
        assert!(!p.udp_confirmed);
        assert!(p.phase.is_discovery_start());
        assert_eq!((p.mtu, p.maxmtu), (1400, MTU));
        assert_eq!(h.minmtu.load(atomic::Ordering::Relaxed), 0);
        assert!(h.udp_addr.lock().unwrap().is_none());
    }
}
