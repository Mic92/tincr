//! Small cross-path helpers for the net layer. All three bodies
//! used to be duplicated at 2–3 call sites each; keep the logic
//! here so drift can't reintroduce the bugs the audits caught.

use std::net::SocketAddr;
use std::sync::Arc;

use crate::graph::{Graph, NodeId};
use socket2::SockAddr;
use tinc_device::{Device, GroBucket, GroVerdict};

use crate::inthash::IntHashMap;
use crate::local_addr;
use crate::shard::TunnelHandles;
use crate::tunnel::TunnelState;

use super::ListenerSlot;

/// Flip `udp_confirmed`, cache the pre-converted `SockAddr` + sock
/// index, mirror into the lock-free fast-path handle.
///
/// Gate is `cached.is_none() OR addr changed`, not just addr-change:
/// `gossip::BecameReachable` / `txpath::UDP_INFO` seed `udp_addr`
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
