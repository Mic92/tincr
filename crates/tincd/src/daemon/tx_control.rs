//! Per-peer UDP tunnel improvement: probe send/receive, PMTU ticks,
//! UDP address selection. State machines live in `crate::pmtu`; this
//! is the daemon-side I/O around them.

#![forbid(unsafe_code)]

use super::net::TunnelSendOutcome;
use super::{ConnId, Daemon, PKT_PROBE};

use std::net::SocketAddr;
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

use crate::dispatch::ConnOptions;
use crate::graph::{NodeId, Route};
use crate::pmtu::{PmtuAction, PmtuState};
use crate::tunnel::{MTU, TunnelState};
use crate::{local_addr, pmtu};
use rand_core::Rng;
use tinc_crypto::os_rng;
use tinc_proto::msg::MtuInfo;

#[cfg(any(target_os = "linux", target_os = "android"))]
use nix::sys::socket::{
    AddressFamily, SockFlag, SockType, SockaddrStorage, connect, getsockopt, socket, sockopt,
};

/// Ask the kernel for its PMTU cache entry to this peer; subtract
/// our encapsulation overhead to get the tinc-layer MTU. Makes PMTU
/// converge in 1 RTT instead of ~10 probes × 333ms — the very first
/// probe is sent at the (likely correct) maxmtu, the reply confirms
/// it, `try_fix_mtu` fires immediately.
///
/// Without this the ~3.3s convergence window leaves `via.mtu == 0`,
/// during which the frag-needed check fires at MTU 576. The kernel
/// caches that per-dst for 10 minutes; any TCP flow that starts in
/// that window is stuck at MSS 536.
///
/// Falls back to `MTU` on every error.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn choose_initial_maxmtu(_peer: SocketAddr) -> u16 {
    // macOS has no IP_MTU sockopt to query the kernel's PMTU cache.
    // Fall back to default MTU; the PMTU probing loop in pmtu.rs will
    // converge to the real path MTU within ~10 probes × 333ms. This
    // costs one extra RTT vs Linux where we seed from the kernel cache.
    MTU
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn choose_initial_maxmtu(peer: SocketAddr) -> u16 {
    // Ephemeral DGRAM socket, only for the kernel's route+PMTU
    // lookup. Never sends.
    let af = match peer {
        SocketAddr::V4(_) => AddressFamily::Inet,
        SocketAddr::V6(_) => AddressFamily::Inet6,
    };
    let Ok(sock) = socket(af, SockType::Datagram, SockFlag::SOCK_CLOEXEC, None) else {
        return MTU;
    };
    // connect() makes the kernel resolve the route. UDP connect is
    // just a route lookup + dst association — no packets.
    let ss = SockaddrStorage::from(peer);
    if connect(sock.as_raw_fd(), &ss).is_err() {
        return MTU;
    }
    // IP_MTU is the kernel's PMTU cache for this route. On lo it's
    // 65536 (clamped below). On real interfaces it's the link MTU
    // minus any cached PMTUD reductions.
    let Ok(ip_mtu) = getsockopt(&sock, sockopt::IpMtu) else {
        return MTU;
    };
    // Sanity floor. Kernel returns i32; <0 is impossible from a
    // successful getsockopt but the type allows it.
    if ip_mtu < i32::from(pmtu::MINMTU) {
        return MTU;
    }
    // On lo IP_MTU is 65536 — doesn't fit u16. We're going to clamp
    // to MTU=1518 anyway so saturate at u16::MAX; the min() catches it.
    let ip_mtu = u16::try_from(ip_mtu).unwrap_or(u16::MAX);
    // Peel off encapsulation layers. We're SPTPS-only, protocol
    // minor ≥4 always.
    //   IP header: 20 (v4) or 40 (v6)
    //   UDP header: 8
    //   [dst_id6][src_id6]: 12
    //   SPTPS datagram overhead: 21 (seqno+type+tag)
    let ip_hdr: u16 = if peer.is_ipv6() { 40 } else { 20 };
    debug_assert_eq!(tinc_sptps::DATAGRAM_OVERHEAD, 21);
    let tinc_mtu = ip_mtu.saturating_sub(ip_hdr + 8 + 12 + 21);
    tinc_mtu.min(MTU)
}

impl Daemon {
    /// One probe record arrived: byte[0] == 0 is a request (echo it),
    /// otherwise a type 1/2 reply for `pmtu.on_probe_reply`.
    pub(super) fn udp_probe_h(&mut self, peer: NodeId, peer_name: &str, body: &[u8]) -> bool {
        if body.is_empty() {
            return false;
        }
        if body[0] == 0 {
            log::debug!(target: "tincd::net",
                        "Got UDP probe request {} from {peer_name}",
                        body.len());
            #[expect(clippy::cast_possible_truncation)] // body ≤ MTU
            let body_len = body.len() as u16;
            // Asymmetric-UDP meta-ack: remember the largest probe
            // request we've seen so `try_udp` can tell `peer` over
            // the meta connection. If `peer`'s inbound UDP is
            // filtered, the type-2 reply we send next never arrives;
            // the meta-ack is the only way they learn their outbound
            // leg works. Hot path: 1 max() + store, no I/O here.
            let t = self.dp.tunnels.entry(peer).or_default();
            t.udp_rx_maxlen = t.udp_rx_maxlen.max(body_len);
            return self.send_udp_probe_reply(peer, peer_name, body_len);
        }

        // reply (type 1 or 2).
        // type-2 carries probed length in bytes [1..3] (reply itself
        // is MIN_PROBE_SIZE on wire — saves bandwidth).
        #[expect(clippy::cast_possible_truncation)] // body ≤ MTU
        let len: u16 = if body[0] == 2 && body.len() >= 3 {
            u16::from_be_bytes([body[1], body[2]])
        } else {
            body.len() as u16
        };
        log::debug!(target: "tincd::net",
                    "Got type {} UDP probe reply {len} from {peer_name}",
                    body[0]);

        // Fresh Instant::now() — RTT measurement needs sub-ms accuracy;
        // self.timers.now() is cached once per event-loop turn and can be
        // a full epoll batch stale (yielding rtt=0 when probe-send and an
        // unrelated reply land in the same batch).
        let now = Instant::now();
        let actions = if let Some(p) = self.dp.tunnels.get_mut(&peer).and_then(|t| t.pmtu.as_mut())
        {
            p.on_probe_reply(len, now)
        } else {
            // No pmtu state yet — seed now to record the floor.
            let tunnel = self.dp.tunnels.entry(peer).or_default();
            let mut p = PmtuState::new(now, MTU);
            let actions = p.on_probe_reply(len, now);
            tunnel.pmtu = Some(p);
            actions
        };
        // `status.udp_confirmed` is what dump_nodes reports; pmtu is authoritative.
        if let Some(t) = self.dp.tunnels.get_mut(&peer) {
            t.status.udp_confirmed = true;
        }
        for a in &actions {
            Self::log_pmtu_action(peer_name, a);
        }
        // Publish minmtu to the fast path (probe replies are seconds
        // apart, so this isn't per-packet). Unconditional store: may
        // have raised, capped (LogFixed clamps), or stayed put;
        // reading the post-action value covers all three. None until
        // first HandshakeDone (probes start after the SPTPS dance).
        if let Some(h) = self.tunnel_handles.get(&peer) {
            let m = self.dp.tunnels.get(&peer).map_or(0, TunnelState::minmtu);
            h.minmtu.store(m, std::sync::atomic::Ordering::Relaxed);
        }
        false
    }

    /// Type-2 reply: length in bytes [1..3], wire packet is
    /// `MIN_PROBE_SIZE`. The receive path stashed `udp_addr` already, so
    /// `choose_udp_address` sends the reply back the way it came.
    pub(super) fn send_udp_probe_reply(&mut self, peer: NodeId, peer_name: &str, len: u16) -> bool {
        let mut body = vec![0u8; usize::from(pmtu::MIN_PROBE_SIZE)];
        body[0] = 2;
        body[1..3].copy_from_slice(&len.to_be_bytes());
        // recipient only reads [0..3], zero is fine.

        log::debug!(target: "tincd::net",
                    "Sending type 2 probe reply length {len} to {peer_name}");

        self.send_probe_record(peer, peer_name, &body).needs_write
    }

    /// Build and send a probe request of `len` bytes. byte[0]=0
    /// (request), bytes[1..14]=zero, bytes[14..len]=random.
    fn send_udp_probe(&mut self, peer: NodeId, peer_name: &str, len: u16) -> TunnelSendOutcome {
        let len = len.max(pmtu::MIN_PROBE_SIZE);
        let mut body = vec![0u8; usize::from(len)];
        // zero[0..14], random[14..]. The 14-byte zero prefix is
        // convention only.
        if body.len() > 14 {
            os_rng().fill_bytes(&mut body[14..]);
        }
        // body[0] = 0 (request marker) from vec init.

        log::debug!(target: "tincd::net",
                    "Sending UDP probe length {len} to {peer_name}");
        self.send_probe_record(peer, peer_name, &body)
    }

    /// Shared path for probe requests and replies.
    pub(super) fn send_probe_record(
        &mut self,
        peer: NodeId,
        peer_name: &str,
        body: &[u8],
    ) -> TunnelSendOutcome {
        let tunnel = self.dp.tunnels.entry(peer).or_default();
        if !tunnel.status.validkey {
            return TunnelSendOutcome::default();
        }
        let Some(sptps) = tunnel.sptps.as_deref_mut() else {
            return TunnelSendOutcome::default();
        };
        let outs = match sptps.send_record(PKT_PROBE, body) {
            Ok(outs) => outs,
            Err(e) => {
                log::debug!(target: "tincd::net",
                            "Probe send_record for {peer_name}: {e:?}");
                return TunnelSendOutcome::default();
            }
        };
        // relay decision always prefers `via` for PKT_PROBE.
        self.dispatch_tunnel_outputs(peer, peer_name, outs)
    }

    /// The "improve the tunnel" tick. Called from two places:
    ///
    /// 1. `on_ping_tick`: once per active conn, `mtu=false`. Keeps
    ///    UDP alive (NAT timeouts).
    /// 2. `forward_packet` Forward arm: once per forwarded packet,
    ///    `mtu=true`. Drives PMTU discovery.
    ///
    /// Chain: `REQ_KEY` if needed → via deref → `try_udp` (probe send)
    /// → `try_mtu` (PMTU tick).
    ///
    /// Via-recursion: recurse on relay if `via != target`. Finite:
    /// via-chain is the sssp tree (acyclic).
    pub(super) fn try_tx(&mut self, target: NodeId, mtu: bool) -> bool {
        // TCPONLY + direct meta conn ⇒ skip UDP.
        {
            let target_options = self.route_of(target).map_or(ConnOptions::empty(), |r| {
                ConnOptions::from_bits_retain(r.options)
            });
            let tcponly = (self.myself_options | target_options).contains(ConnOptions::TCPONLY);
            if tcponly {
                let has_direct_conn = self.nodes.get(&target).is_some_and(|ns| ns.conn.is_some());
                if has_direct_conn {
                    return true;
                }
            }
        }

        // send_sptps_packet sends the first REQ_KEY; this catches the
        // 10-second restart.
        let now = self.timers.now();
        {
            let tunnel = self.dp.tunnels.entry(target).or_default();
            if !tunnel.status.validkey {
                if !tunnel.status.waitingforkey {
                    return self.send_req_key(target);
                }
                // REQ_KEY_RETRY debounce.
                if tunnel
                    .last_req_key
                    .is_some_and(|l| now.duration_since(l) >= super::intervals::REQ_KEY_RETRY)
                {
                    log::debug!(target: "tincd::net",
                                "No key after 10 seconds, restarting SPTPS");
                    tunnel.sptps = None;
                    tunnel.status.waitingforkey = false;
                    return self.send_req_key(target);
                }
                return false;
            }
        }

        // Static-relay recursion. Two-phase borrow: copy NodeId,
        // drop, recurse.
        {
            let route = self.route_of(target);
            // Unreachable: pretend direct.
            let via_nid = route.map_or(target, |r| {
                if r.via == self.myself {
                    r.nexthop
                } else {
                    r.via
                }
            });
            if via_nid != target {
                // minor <4 lacks relay support. Our default is
                // 7<<24; gate matters for old-C interop.
                let via_options = self.route_of(via_nid).map_or(0, |r| r.options);
                if (via_options >> 24) < 4 {
                    return false;
                }
                return self.try_tx(via_nid, mtu);
            }
        }

        // `target` from caller; nodes never deleted in tincd.
        let target_name = self.node_log_name(target).to_owned();

        let mut nw = self.try_udp(target, &target_name, now);

        // Don't probe MTU until UDP confirmed.
        if mtu {
            // Re-seed maxmtu just before discovery starts. The peer
            // addr lookup goes through `choose_udp_address` (the
            // same path the actual probe send will use). If there's
            // no UDP addr yet the probe wouldn't go anywhere either
            // — fall back to MTU and let the next try_tx pick it up.
            let needs_seed = self
                .dp
                .tunnels
                .get(&target)
                .and_then(|t| t.pmtu.as_ref())
                .is_none_or(|p| p.phase.is_discovery_start());
            let initial_maxmtu = if needs_seed {
                self.choose_udp_address(target)
                    .map_or(MTU, |(addr, _)| choose_initial_maxmtu(addr))
            } else {
                MTU
            };

            let tunnel = self.dp.tunnels.entry(target).or_default();
            let p = tunnel
                .pmtu
                .get_or_insert_with(|| PmtuState::new(now, initial_maxmtu));
            // Re-seed even if pmtu state already exists (UDP timeout
            // restarted discovery). Our get_or_insert only seeds on
            // first construction.
            if p.phase.is_discovery_start() {
                p.maxmtu = initial_maxmtu;
            }
            if p.udp_confirmed {
                let pinginterval = Duration::from_secs(u64::from(self.settings.pinginterval));
                let actions = p.tick(now, pinginterval);
                for a in &actions {
                    Self::log_pmtu_action(&target_name, a);
                }
                for a in actions {
                    if let PmtuAction::SendProbe { len, counts_miss } = a {
                        let outcome = self.send_udp_probe(target, &target_name, len);
                        nw |= outcome.needs_write;
                        if counts_miss
                            && outcome.udp_sent
                            && let Some(pmtu) = self
                                .dp
                                .tunnels
                                .get_mut(&target)
                                .and_then(|t| t.pmtu.as_mut())
                        {
                            pmtu.on_counted_probe_sent();
                        }
                    }
                }
            }
        }

        // Nexthop dynamic-relay recursion. Warm the relay's tunnel
        // while trying direct UDP, so send_sptps_data's b64-TCP
        // fallback can reach.
        let udp_confirmed = self
            .dp
            .tunnels
            .get(&target)
            .and_then(|t| t.pmtu.as_ref())
            .is_some_and(|p| p.udp_confirmed);
        if !udp_confirmed {
            let nexthop = self.route_of(target).map(|r| r.nexthop);
            if let Some(nh) = nexthop
                && nh != target
            {
                let nh_options = self.route_of(nh).map_or(0, |r| r.options);
                if (nh_options >> 24) >= 4 {
                    nw |= self.try_tx(nh, mtu);
                }
            }
        }

        nw
    }

    /// Probe-request send + gratuitous-reply keepalive. New and
    /// timed-out paths probe immediately; retries use 2s when not
    /// confirmed and 10s when confirmed (NAT keepalive).
    pub(super) fn try_udp(&mut self, target: NodeId, target_name: &str, now: Instant) -> bool {
        if !self.settings.udp_discovery {
            return false;
        }

        let tunnel = self.dp.tunnels.entry(target).or_default();

        // Revalidate before carrying data when either an outstanding
        // keepalive timed out or the last authenticated UDP evidence
        // predates one timeout window. The latter catches a stale NAT
        // mapping on the first packet after a data-driven idle gap.
        let timeout = Duration::from_secs(u64::from(self.settings.udp_discovery_timeout));
        let (timed_out, cold_stale) = tunnel.pmtu.as_ref().map_or((false, false), |p| {
            (
                p.udp_timed_out(now, timeout),
                p.udp_needs_cold_revalidation(now, timeout),
            )
        });
        if timed_out || cold_stale {
            if cold_stale {
                log::info!(target: "tincd::net",
                           "UDP path to {target_name} is idle; revalidating before data");
            } else {
                log::info!(target: "tincd::net",
                           "Too much time has elapsed since last UDP ping response from {target_name}, stopping UDP communication");
            }
            if let Some(p) = tunnel.pmtu.as_mut() {
                p.on_udp_timeout();
            }
            tunnel.status.udp_confirmed = false;
            tunnel.udp_addr_cached = None;
            if let Some(h) = self.tunnel_handles.get(&target) {
                h.minmtu.store(0, std::sync::atomic::Ordering::Relaxed);
            }
            // Fall through: discovery starts immediately, while data
            // uses the existing TCP path until UDP is authenticated.
        }

        let udp_confirmed = tunnel.pmtu.as_ref().is_some_and(|p| p.udp_confirmed);

        // Gratuitous keepalive: a type-2 reply at the largest
        // recently-seen size tells the peer their PMTU still holds
        // (rewinds their revalidation to Steady).
        let mut nw = false;
        if udp_confirmed {
            let keepalive =
                Duration::from_secs(u64::from(self.settings.udp_discovery_keepalive_interval));
            let due = tunnel
                .udp_reply_sent
                .is_none_or(|last| now.duration_since(last) >= keepalive);
            if due {
                tunnel.udp_reply_sent = Some(now);
                let maxrecentlen = tunnel
                    .pmtu
                    .as_mut()
                    .map_or(0, |p| std::mem::take(&mut p.maxrecentlen));
                if maxrecentlen > 0 {
                    nw |= self.send_udp_probe_reply(target, target_name, maxrecentlen);
                }
            }
        }

        // Drain `udp_rx_maxlen` into an MTU_INFO 4th-field ack.
        // Deferred from `udp_probe_h` (no meta-send on the UDP rx
        // path). Separate from `send_mtu_info`: that gates on
        // `!to_directly_connected`, but the asymmetric-filter case
        // is precisely a direct peer whose UDP reply can't reach us
        // — so we need a path that does send to direct peers.
        nw |= self.send_udp_rx_ack(target, target_name, now);

        // Probe request. Seed pmtu if needed (we read udp_ping_sent).
        let tunnel = self.dp.tunnels.entry(target).or_default();
        let p = tunnel.pmtu.get_or_insert_with(|| PmtuState::new(now, MTU));
        let interval = if p.udp_confirmed {
            self.settings.udp_discovery_keepalive_interval
        } else {
            self.settings.udp_discovery_interval
        };
        if p.udp_probe_due(now, Duration::from_secs(u64::from(interval))) {
            // Fresh clock only for a submitted probe's RTT stamp; the
            // cadence gate uses the cached loop clock.
            let attempted_at = Instant::now();
            let outcome = self.send_udp_probe(target, target_name, pmtu::MIN_PROBE_SIZE);
            nw |= outcome.needs_write;
            let mut sent = outcome.udp_sent;

            // send_locally is a side-channel to choose_udp_address;
            // no early-return between set/clear.
            if self.settings.local_discovery {
                let confirmed = self
                    .dp
                    .tunnels
                    .get(&target)
                    .is_some_and(|t| t.status.udp_confirmed);
                let has_prevedge = self.route_of(target).and_then(|r| r.prevedge).is_some();
                if !confirmed && has_prevedge {
                    if let Some(t) = self.dp.tunnels.get_mut(&target) {
                        t.status.send_locally = true;
                    }
                    let local = self.send_udp_probe(target, target_name, pmtu::MIN_PROBE_SIZE);
                    nw |= local.needs_write;
                    sent |= local.udp_sent;
                    if let Some(t) = self.dp.tunnels.get_mut(&target) {
                        t.status.send_locally = false;
                    }
                }
            }
            if let Some(p) = self
                .dp
                .tunnels
                .get_mut(&target)
                .and_then(|t| t.pmtu.as_mut())
            {
                p.on_udp_probe_attempt(attempted_at, sent);
            }
        }

        nw
    }

    /// Drain `udp_rx_maxlen` into an `MTU_INFO` 4th-field ack toward
    /// `target`. Debounced by `mtu_info_sent` (shared with
    /// `send_mtu_info`: same payload plus one field). Bypasses the
    /// `to_directly_connected` gate on purpose: the asymmetric-filter
    /// peer is directly connected.
    fn send_udp_rx_ack(&mut self, target: NodeId, target_name: &str, now: Instant) -> bool {
        let interval = Duration::from_secs(u64::from(self.settings.mtu_info_interval));
        let Some(tunnel) = self.dp.tunnels.get_mut(&target) else {
            return false;
        };
        if tunnel.udp_rx_maxlen == 0 {
            return false;
        }
        if tunnel
            .mtu_info_sent
            .is_some_and(|l| now.saturating_duration_since(l) < interval)
        {
            return false;
        }
        let udp_rx_len = std::mem::take(&mut tunnel.udp_rx_maxlen);
        tunnel.mtu_info_sent = Some(now);

        let Some(conn_id) = self.conn_for_nexthop(target) else {
            return false;
        };
        let Some(conn) = self.conns.get_mut(conn_id) else {
            return false;
        };
        let msg = MtuInfo {
            from: self.name.clone(),
            to: target_name.to_owned(),
            mtu: i32::from(MTU),
            udp_rx_len,
        };
        log::debug!(target: "tincd::net",
                    "meta-ack UDP rx {udp_rx_len} to {target_name}");
        conn.send(format_args!("{}", msg.format()))
    }

    /// Dispatch the `Log*` PMTU actions. The `SendProbe` actions
    /// are dispatched by the caller (they need `&mut self`).
    pub(super) fn log_pmtu_action(name: &str, a: &PmtuAction) {
        match a {
            PmtuAction::SendProbe { .. } => {} // caller dispatches
            PmtuAction::LogFixed { mtu, probes } => {
                log::info!(target: "tincd::net",
                           "Fixing MTU of {name} to {mtu} after {probes} probes");
            }
            PmtuAction::LogReset => {
                log::info!(target: "tincd::net",
                           "Decrease in PMTU to {name} detected, restarting discovery");
            }
            PmtuAction::LogIncrease => {
                log::info!(target: "tincd::net",
                           "Increase in PMTU to {name} detected, restarting discovery");
            }
        }
    }

    /// Meta conn for routing toward `to`.
    pub(super) fn conn_for_nexthop(&self, to_nid: NodeId) -> Option<ConnId> {
        let nexthop = self.route_of(to_nid)?.nexthop;
        self.nodes.get(&nexthop)?.conn
    }

    /// `Route` lookup. Reads cached `last_routes` (not a fresh sssp).
    ///
    /// By-value: `Route` is `Copy` (32 bytes, all-Copy fields). The
    /// `Arc` deref is transparent — same codegen as `&Vec`.
    #[inline]
    pub(super) fn route_of(&self, nid: NodeId) -> Option<Route> {
        *self.last_routes.get(nid.0 as usize)?
    }

    /// Three modes: `send_locally` → `choose_local` from `edge_addrs`
    /// [2,3]; `udp_confirmed` → stashed addr; otherwise 1-in-3 cycle:
    /// 2 of 3 calls explore an edge addr, 3rd uses reflexive — probes
    /// both even when `udp_addr` is set but unconfirmed (NAT hairpin).
    ///
    /// `adapt_socket` folded in (dual-stack: v6 target needs v6 socket).
    /// `&mut self` for the cycle counter.
    pub(super) fn choose_udp_address(&mut self, to_nid: NodeId) -> Option<(SocketAddr, u8)> {
        let listener_addrs: Vec<SocketAddr> =
            self.listeners.iter().map(|s| s.listener.local).collect();

        let send_locally = self
            .dp
            .tunnels
            .get(&to_nid)
            .is_some_and(|t| t.status.send_locally);
        if send_locally {
            // Edge local addrs (positions 2,3); filter_map skips "unspec".
            let candidates: Vec<SocketAddr> = self
                .graph
                .node_edges(to_nid)
                .iter()
                .filter_map(|eid| {
                    let (_, _, la, lp) = self.edge_addrs.get(eid)?;
                    local_addr::parse_addr_port(la.as_str(), lp.as_str())
                })
                .collect();
            if let Some((addr, sock)) =
                local_addr::choose_local(&candidates, &mut os_rng(), &listener_addrs)
            {
                return Some((addr, sock));
            }
            // Fall through if no local address found.
        }

        // Reflexive (stashed udp_addr).
        if let Some(t) = self.dp.tunnels.get(&to_nid)
            && let Some(addr) = t.udp_addr
        {
            if t.status.udp_confirmed {
                let sock = local_addr::adapt_socket(&addr, 0, &listener_addrs);
                return Some((addr, sock));
            }
            // 1-of-3 returns early with stashed addr; other 2 fall
            // through to edge exploration.
            self.dp.choose_udp_x = self.dp.choose_udp_x.wrapping_add(1);
            if self.dp.choose_udp_x >= 3 {
                self.dp.choose_udp_x = 0;
                let sock = local_addr::adapt_socket(&addr, 0, &listener_addrs);
                return Some((addr, sock));
            }
        }

        // Direct-neighbor fast path first (NodeState.edge_addr is
        // the peer-ACK addr); else walk node_edges → reverse →
        // edge_addrs. Without the walk a transitive non-indirect
        // node (`via == target` in try_tx, so no relay recursion)
        // returns None and the probe is silently dropped.
        let addr = self
            .nodes
            .get(&to_nid)
            .and_then(|ns| ns.edge_addr)
            .or_else(|| {
                let mut cands: Vec<SocketAddr> = self
                    .graph
                    .node_edges(to_nid)
                    .iter()
                    .filter_map(|&eid| self.graph.edge(eid)?.reverse)
                    .filter_map(|rev| {
                        let (a, p, _, _) = self.edge_addrs.get(&rev)?;
                        local_addr::parse_addr_port(a.as_str(), p.as_str())
                    })
                    .collect();
                if cands.is_empty() {
                    return None;
                }
                // Spread probes when multiple neighbors report
                // different addrs (NAT).
                let i = (os_rng().next_u32() as usize) % cands.len();
                Some(cands.swap_remove(i))
            })?;
        let sock = local_addr::adapt_socket(&addr, 0, &listener_addrs);
        Some((addr, sock))
    }
}
