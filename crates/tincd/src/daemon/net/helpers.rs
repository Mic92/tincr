//! Small cross-path helpers for the net layer. All three bodies
//! used to be duplicated at 2–3 call sites each; keep the logic
//! here so drift can't reintroduce the bugs the audits caught.

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

/// Re-warn cadence for [`handle_udp_unreachable`]. First failure logs
/// at `warn`; further failures within this window are suppressed
/// (the helper still clears the cached addr each time so the next
/// packet retries the slow path).
const UDP_UNREACHABLE_WARN_INTERVAL: Duration = Duration::from_secs(60);

/// Flip `udp_confirmed`, cache the pre-converted `SockAddr` + sock
/// index, mirror into the lock-free fast-path handle.
///
/// Gate is `cached.is_none() OR addr changed`, not just addr-change:
/// `gossip::BecameReachable` / `tx_control::UDP_INFO` seed `udp_addr`
/// from `edge_addr` while clearing `udp_addr_cached`. If the peer then
/// sends from that same addr the old `udp_addr != peer_addr` gate
/// would stay false forever and every send fell through to
/// `choose_udp_address` (the 2.18% self-time cold path).
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

/// `sendmsg` errno classifier: is this "destination not locally
/// routable"? `ENETUNREACH` (e.g. peer's IPv6 with no v6 default
/// route), `EHOSTUNREACH` (peer-specific blackhole), `EAFNOSUPPORT`
/// (kernel built without v6), `EADDRNOTAVAIL` (e.g. our v6 source
/// disappeared between bind and send). All four mean the same thing
/// to us: the chosen `udp_addr` is not usable; drop it and let
/// `choose_udp_address` pick a different candidate next time.
pub(super) fn is_udp_unreachable_errno(e: &std::io::Error) -> bool {
    let Some(raw) = e.raw_os_error() else {
        return false;
    };
    matches!(
        raw,
        // libc errnos. Spelled-out so this compiles without pulling
        // libc in just for this site; values are stable Linux ABI.
        101 // ENETUNREACH
        | 113 // EHOSTUNREACH
        | 97  // EAFNOSUPPORT
        | 99  // EADDRNOTAVAIL
    )
}

/// `ENETUNREACH` / `EHOSTUNREACH` / `EAFNOSUPPORT` / `EADDRNOTAVAIL`
/// on a UDP send: the chosen `udp_addr` is not locally routable
/// (typical: peer advertised an IPv6 address but our host has no
/// public IPv6 path). Without this handler, every subsequent send
/// retries the same broken cached address forever — visible as a
/// per-packet warn spam and a peer that never establishes direct
/// UDP even when its `ADD_EDGE` also carries a routable IPv4
/// address.
///
/// Effect: clear `udp_addr`, `udp_addr_cached`, and the
/// `udp_confirmed` mirror so the next packet falls through to
/// `choose_udp_address`'s cold edge-walk. `pmtu` and the SPTPS
/// session are NOT touched — this is a routing event, not a peer
/// teardown. Stamps `udp_send_failed_at` so:
///   - the warn log is emitted at most once per minute per peer
///     (avoids the per-packet flood when the cold path keeps
///     re-picking the same broken address);
///   - the cold path can deprioritise the reflexive arm while a
///     recent failure is in effect (handled in
///     `choose_udp_address`).
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
        // No TunnelState: log once and bail; nothing else to clear.
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

/// `EMSGSIZE` on a UDP send: LOCAL kernel rejected at interface MTU.
/// Shrink the relay's `maxmtu` so the NEXT batch's stride fits. The
/// frames in THIS send are lost — inner-TCP retransmits. This IS the
/// discovery mechanism; don't warn.
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

/// Offer `data` (raw IP — caller strips the synth eth header) to
/// the GRO bucket, flushing as needed; writes through to the device
/// on `NotCandidate` / flushed-and-didn't-fit. Shared between
/// `send_packet_myself` and `rx_fast_sink`.
pub(super) fn gro_offer_or_write(
    device: &mut Box<dyn Device>,
    gro: &mut Option<GroBucket>,
    data: &mut [u8],
) {
    const ETH_HLEN: usize = 14;
    // `gro_enabled` setup gate makes the write_super Unsupported
    // path unreachable in practice; warn (not debug) if we hit it.
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
                // Ordering: anything in the bucket goes out first.
                // A same-flow non-candidate (FIN) mustn't reorder
                // past lower-seq data.
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
        // EMSGSIZE, EWOULDBLOCK, EAGAIN — handled by other arms.
        for raw in [90, 11] {
            let e = io::Error::from_raw_os_error(raw);
            assert!(
                !is_udp_unreachable_errno(&e),
                "errno {raw} should NOT be classified as udp-unreachable"
            );
        }
        // No raw os error (e.g. synthetic kind).
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

        // The handler is idempotent and safe to call again on an
        // already-cleared tunnel; the rate-limit gate just keeps
        // the warn from firing every packet.
        handle_udp_unreachable(&mut tunnels, &tunnel_handles, nid, "peer", &err, now);
        let t = tunnels.get(&nid).unwrap();
        assert_eq!(
            t.udp_send_failed_at,
            Some(now),
            "still stamped, not regressed"
        );

        // No TunnelState: don't panic.
        let missing = NodeId(99);
        handle_udp_unreachable(&mut tunnels, &tunnel_handles, missing, "ghost", &err, now);
    }
}
