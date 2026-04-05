#![forbid(unsafe_code)]

use super::{ConnId, Daemon, PKT_PROBE, TimerWhat, parse_subnets_from_config};

use std::collections::HashSet;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

use crate::autoconnect::{AutoAction, NodeSnapshot};
use crate::outgoing::{Outgoing, OutgoingId, resolve_config_addrs};
use crate::pmtu::{PmtuAction, PmtuState};
use crate::proto::{ConnOptions, DispatchError};
use crate::tunnel::{MTU, TunnelState};
use crate::udp_info::{FromMtuState, FromState, MtuInfoAction, PmtuSnapshot, UdpInfoAction};
use crate::{autoconnect, local_addr, pmtu, udp_info};

use rand_core::{OsRng, RngCore};
use tinc_event::Io;
use tinc_graph::{NodeId, Route};
use tinc_proto::AddrStr;
use tinc_proto::msg::{MtuInfo, UdpInfo};

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
    /// One PROBE record arrived. byte[0] == 0 ⇒ request → echo back.
    /// byte[0] != 0 ⇒ reply (type 1 or 2) → feed `pmtu.on_probe_reply`.
    pub(super) fn udp_probe_h(&mut self, peer: NodeId, peer_name: &str, body: &[u8]) -> bool {
        if body.is_empty() {
            return false;
        }
        // byte[0]==0 marks a REQUEST.
        if body[0] == 0 {
            log::debug!(target: "tincd::net",
                        "Got UDP probe request {} from {peer_name}",
                        body.len());
            #[allow(clippy::cast_possible_truncation)] // body ≤ MTU
            return self.send_udp_probe_reply(peer, peer_name, body.len() as u16);
        }

        // ─── reply (type 1 or 2) ────────────────────────────────
        // type-2 carries probed length in bytes [1..3] (reply itself
        // is MIN_PROBE_SIZE on wire — saves bandwidth).
        #[allow(clippy::cast_possible_truncation)] // body ≤ MTU
        let len: u16 = if body[0] == 2 && body.len() >= 3 {
            u16::from_be_bytes([body[1], body[2]])
        } else {
            body.len() as u16
        };
        log::debug!(target: "tincd::net",
                    "Got type {} UDP probe reply {len} from {peer_name}",
                    body[0]);

        // udp_confirmed lives in BOTH `status` (dump_nodes packing)
        // and `pmtu` (authoritative).
        let now = self.timers.now();
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
        // Mirror udp_confirmed into status.
        if let Some(t) = self.dp.tunnels.get_mut(&peer) {
            t.status.udp_confirmed = true;
        }
        for a in &actions {
            Self::log_pmtu_action(peer_name, a);
        }
        // Publish minmtu to the fast path. NOT a per-packet write —
        // probe replies are seconds apart. Unconditional store: may
        // have raised, capped (LogFixed clamps), or stayed put;
        // reading the post-action value covers all three. None until
        // first HandshakeDone (probes start after the SPTPS dance).
        if let Some(h) = self.tunnel_handles.get(&peer) {
            let m = self.dp.tunnels.get(&peer).map_or(0, TunnelState::minmtu);
            h.minmtu.store(m, std::sync::atomic::Ordering::Relaxed);
        }
        // No per-node UDP-timeout timer (PMTU is driven inline by
        // try_tx/pmtu.tick()).
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

        self.send_probe_record(peer, peer_name, &body)
    }

    /// Build and send a PROBE request of `len` bytes. byte[0]=0
    /// (request), bytes[1..14]=zero, bytes[14..len]=random.
    pub(super) fn send_udp_probe(&mut self, peer: NodeId, peer_name: &str, len: u16) -> bool {
        let len = len.max(pmtu::MIN_PROBE_SIZE);
        let mut body = vec![0u8; usize::from(len)];
        // zero[0..14], random[14..]. The 14-byte zero prefix is
        // convention only.
        if body.len() > 14 {
            OsRng.fill_bytes(&mut body[14..]);
        }
        // body[0] = 0 (request marker) from vec init.

        log::debug!(target: "tincd::net",
                    "Sending UDP probe length {len} to {peer_name}");
        self.send_probe_record(peer, peer_name, &body)
    }

    /// Shared path for probe requests and replies.
    pub(super) fn send_probe_record(&mut self, peer: NodeId, peer_name: &str, body: &[u8]) -> bool {
        let tunnel = self.dp.tunnels.entry(peer).or_default();
        if !tunnel.status.validkey {
            return false;
        }
        let Some(sptps) = tunnel.sptps.as_deref_mut() else {
            return false;
        };
        let outs = match sptps.send_record(PKT_PROBE, body) {
            Ok(outs) => outs,
            Err(e) => {
                log::debug!(target: "tincd::net",
                            "Probe send_record for {peer_name}: {e:?}");
                return false;
            }
        };
        // relay decision always prefers `via` for PKT_PROBE.
        self.dispatch_tunnel_outputs(peer, peer_name, outs)
    }

    /// The "improve the tunnel" tick. Called from TWO places:
    ///
    /// 1. `on_ping_tick`: once per active conn, `mtu=false`. Keeps
    ///    UDP alive (NAT timeouts).
    /// 2. `route_packet` Forward arm: once per forwarded packet,
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

        // ─── try_sptps ──────────────────────────────────────────
        // send_sptps_packet does the FIRST REQ_KEY; this catches the
        // 10-second restart.
        let now = self.timers.now();
        {
            let tunnel = self.dp.tunnels.entry(target).or_default();
            if !tunnel.status.validkey {
                if !tunnel.status.waitingforkey {
                    return self.send_req_key(target);
                }
                // 10s debounce.
                if tunnel
                    .last_req_key
                    .is_some_and(|l| now.duration_since(l).as_secs() >= 10)
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

        // ─── via deref ───────────────────────────────────────────
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

        // ─── try_udp ────────────────────────────────────────────
        let mut nw = self.try_udp(target, &target_name, now);

        // ─── try_mtu ────────────────────────────────────────────
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
            // reset mtuprobes to 0). Our get_or_insert only seeds on
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
                    if let PmtuAction::SendProbe { len } = a {
                        nw |= self.send_udp_probe(target, &target_name, len);
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

    /// Probe-request send + gratuitous-reply keepalive. Gated on
    /// `udp_ping_sent` elapsed: 2s when not confirmed (aggressive
    /// discovery), 10s when confirmed (NAT keepalive).
    pub(super) fn try_udp(&mut self, target: NodeId, target_name: &str, now: Instant) -> bool {
        if !self.settings.udp_discovery {
            return false;
        }

        let tunnel = self.dp.tunnels.entry(target).or_default();
        let udp_confirmed = tunnel.pmtu.as_ref().is_some_and(|p| p.udp_confirmed);

        // ─── gratuitous reply keepalive ──────────────────────────
        // Type-2 reply at largest recently-seen size tells PEER
        // their PMTU is still good (their on_probe_reply rewinds
        // mtuprobes to -1).
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

        // ─── probe request ──────────────────────────────────────
        // Seed pmtu if needed (we read udp_ping_sent).
        let tunnel = self.dp.tunnels.entry(target).or_default();
        let p = tunnel.pmtu.get_or_insert_with(|| PmtuState::new(now, MTU));
        let interval = if p.udp_confirmed {
            self.settings.udp_discovery_keepalive_interval
        } else {
            self.settings.udp_discovery_interval
        };
        let elapsed = now.duration_since(p.udp_ping_sent);
        if elapsed >= Duration::from_secs(u64::from(interval)) {
            p.udp_ping_sent = now;
            p.ping_sent = true;
            nw |= self.send_udp_probe(target, target_name, pmtu::MIN_PROBE_SIZE);
            // localdiscovery && !udp_confirmed && has_prevedge.
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
                    nw |= self.send_udp_probe(target, target_name, pmtu::MIN_PROBE_SIZE);
                    if let Some(t) = self.dp.tunnels.get_mut(&target) {
                        t.status.send_locally = false;
                    }
                }
            }
        }

        nw
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

    /// `to->nexthop->connection`. Meta conn for routing toward `to`.
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

    /// `n->{min,max}mtu` snapshot for `adjust_mtu_for_send`.
    pub(super) fn pmtu_snapshot(&self, nid: NodeId) -> Option<PmtuSnapshot> {
        self.dp
            .tunnels
            .get(&nid)?
            .pmtu
            .as_ref()
            .map(|p| PmtuSnapshot {
                minmtu: p.minmtu,
                maxmtu: p.maxmtu,
            })
    }

    // ─── load_all_nodes ─────────────────────────────────────────

    /// Walk `confbase/hosts/`, add every valid-named file to the
    /// graph, populate `has_address`.
    ///
    /// EVERY hosts/-file name goes into the graph even with no edge
    /// to us — a `has_address && !reachable` node is exactly
    /// autoconnect's eligible-to-dial set. Without the graph add it'd
    /// be invisible to `decide()`.
    ///
    /// strictsubnets: preload Subnet= lines so the lookup-first gate
    /// in `on_add_subnet` finds them; only unauthorized subnets fall
    /// through.
    ///
    /// `TODO(strictsubnets-reload)`: we only do cold-start preload.
    /// Diff old/new authorized sets, broadcast deltas.
    pub(super) fn load_all_nodes(&mut self) {
        let hosts_dir = self.confbase.join("hosts");
        let dir = match std::fs::read_dir(&hosts_dir) {
            Ok(d) => d,
            Err(e) => {
                // non-fatal.
                log::error!(target: "tincd",
                            "Could not open {}: {e}", hosts_dir.display());
                return;
            }
        };

        // Clear on reload — a removed Address= would otherwise keep
        // the stale bit until restart. Only autoconnect reads it, and
        // dialing a no-Address node is harmless (addr-cache-empty →
        // backoff).
        self.has_address.clear();

        for ent in dir.flatten() {
            let Some(fname) = ent.file_name().to_str().map(str::to_owned) else {
                continue; // non-UTF-8 filename — can't be a node name
            };
            // also filters `.` `..` and swap files.
            if !tinc_proto::check_id(&fname) {
                continue;
            }

            self.lookup_or_add_node(&fname);

            // Only need the hosts/ file (Address is HOST-tagged).
            let Ok(entries) = tinc_conf::parse_file(ent.path()) else {
                continue; // unreadable file — skip silently
            };
            let mut cfg = tinc_conf::Config::default();
            cfg.merge(entries);

            if cfg.lookup("Address").next().is_some() {
                self.has_address.insert(fname.clone());
            }

            // Preload authorized subnets. Skip our own name (setup()
            // already added them; add is idempotent but skipping
            // saves a parse).
            if self.settings.strictsubnets && fname != self.name {
                for s in parse_subnets_from_config(&cfg, &fname) {
                    self.subnets.add(s, fname.clone());
                }
            }
        }
    }

    // ─── autoconnect ────────────────────────────────────────────

    /// Build snapshot, call `autoconnect::decide`. Nodes sorted by
    /// name: `decide()` indexes by position (`prng(count)` then walk-
    /// to-index).
    pub(super) fn decide_autoconnect(&self) -> AutoAction {
        let mut names: Vec<&str> = self.node_ids.keys().map(String::as_str).collect();
        names.sort_unstable();

        let nodes: Vec<NodeSnapshot> = names
            .iter()
            .filter_map(|&name| {
                let &nid = self.node_ids.get(name)?;
                let gnode = self.graph.node(nid)?;
                // outgoing only.
                let edge_count = self.graph.node_edges(nid).len();
                // NodeState.conn (set in on_ack, cleared in terminate).
                let directly_connected = self
                    .nodes
                    .get(&nid)
                    .and_then(|ns| ns.conn)
                    .and_then(|cid| self.conns.get(cid))
                    .is_some();
                Some(NodeSnapshot {
                    name: name.to_owned(),
                    reachable: gnode.reachable,
                    has_address: self.has_address.contains(name),
                    directly_connected,
                    edge_count,
                })
            })
            .collect();

        // Past-ACK + initiated.
        let active_outgoing_conns: Vec<String> = self
            .conns
            .values()
            .filter(|c| c.active && c.outgoing.is_some())
            .map(|c| c.name.clone())
            .collect();

        // pending = Outgoing slots with no live conn. Pre-ACK conns
        // DO count as serving.
        let served: HashSet<OutgoingId> = self
            .conns
            .values()
            .filter_map(|c| c.outgoing.map(OutgoingId::from))
            .collect();
        let pending_outgoings: Vec<String> = self
            .outgoings
            .iter()
            .filter(|(oid, _)| !served.contains(oid))
            .map(|(_, o)| o.node_name.clone())
            .collect();

        autoconnect::decide(
            &self.name,
            &nodes,
            &active_outgoing_conns,
            &pending_outgoings,
            &mut OsRng,
        )
    }

    /// Execute one `AutoAction`. The daemon-side I/O for `decide()`'s
    /// pure decision.
    pub(super) fn execute_auto_action(&mut self, action: AutoAction) {
        match action {
            AutoAction::Noop => {}
            AutoAction::Connect { name } => {
                // Same path as setup()'s ConnectTo loop.
                log::info!(target: "tincd",
                           "Autoconnecting to {name}");
                self.lookup_or_add_node(&name);
                let config_addrs = resolve_config_addrs(&self.confbase, &name);
                let addr_cache =
                    crate::addrcache::AddressCache::open(&self.confbase, &name, config_addrs);
                let oid = self.outgoings.insert(Outgoing {
                    node_name: name,
                    timeout: 0,
                    addr_cache,
                });
                let tid = self.timers.add(TimerWhat::RetryOutgoing(oid));
                self.outgoing_timers.insert(oid, tid);
                self.setup_outgoing_connection(oid);
            }
            AutoAction::Disconnect { name } => {
                // Order matters: clear conn.outgoing BEFORE terminate
                // so its retry path doesn't fire (we're CHOOSING to
                // drop this).
                log::info!(target: "tincd",
                           "Autodisconnecting from {name}");
                // Find ConnId by name (active + outgoing).
                let cid = self
                    .conns
                    .iter()
                    .find(|(_, c)| c.active && c.outgoing.is_some() && c.name == name)
                    .map(|(id, _)| id);
                if let Some(cid) = cid {
                    let oid = self
                        .conns
                        .get_mut(cid)
                        .and_then(|c| c.outgoing.take())
                        .map(OutgoingId::from);
                    if let Some(oid) = oid {
                        if let Some(tid) = self.outgoing_timers.remove(oid) {
                            self.timers.del(tid);
                        }
                        self.outgoings.remove(oid);
                    }
                    self.terminate(cid);
                }
            }
            AutoAction::CancelPending { name } => {
                // drop slot, no conn to kill.
                log::info!(target: "tincd",
                           "Cancelled outgoing connection to {name}");
                let oid = self
                    .outgoings
                    .iter()
                    .find(|(_, o)| o.node_name == name)
                    .map(|(id, _)| id);
                if let Some(oid) = oid {
                    if let Some(tid) = self.outgoing_timers.remove(oid) {
                        self.timers.del(tid);
                    }
                    self.outgoings.remove(oid);
                }
            }
        }
    }

    // ─── UDP_INFO / MTU_INFO send ───────────────────────────────

    /// Gates in `udp_info::should_send_udp_info`; this gathers state,
    /// builds wire, queues on nexthop conn. `from_is_myself` is true
    /// at all daemon call sites; forwarding goes via
    /// `send_udp_info_forward`.
    pub(super) fn send_udp_info(
        &mut self,
        to_nid: NodeId,
        to_name: &str,
        from_is_myself: bool,
    ) -> bool {
        // Static-relay deref. UDP_INFO terminates at the relay (last
        // node seeing from's UDP directly). Original to's options
        // feed to_options; dereffed to's route feeds the rest.
        let Some(orig_route) = self.route_of(to_nid) else {
            // Our callers are opportunistic hints, just skip.
            return false;
        };
        let to_options_orig = ConnOptions::from_bits_retain(orig_route.options);
        let dereffed = if orig_route.via == self.myself {
            orig_route.nexthop
        } else {
            orig_route.via
        };

        // checked against DEREFFED to.
        let to_is_myself = dereffed == self.myself;
        let to_reachable = self.graph.node(dereffed).is_some_and(|n| n.reachable);
        let to_directly_connected = self.nodes.get(&dereffed).and_then(|ns| ns.conn).is_some();
        let nexthop_options = self.route_of(dereffed).map_or(ConnOptions::empty(), |r| {
            self.route_of(r.nexthop).map_or(ConnOptions::empty(), |nr| {
                ConnOptions::from_bits_retain(nr.options)
            })
        });

        let from_options = if from_is_myself {
            self.myself_options
        } else {
            self.route_of(to_nid).map_or(ConnOptions::empty(), |r| {
                ConnOptions::from_bits_retain(r.options)
            })
        };

        let now = self.timers.now();
        let last_sent = self.dp.tunnels.get(&dereffed).and_then(|t| t.udp_info_sent);
        let interval = Duration::from_secs(u64::from(self.settings.udp_info_interval));

        if !udp_info::should_send_udp_info(
            to_is_myself,
            to_reachable,
            to_directly_connected,
            from_is_myself,
            from_options,
            to_options_orig,
            self.myself_options,
            nexthop_options,
            last_sent,
            now,
            interval,
        ) {
            return false;
        }

        // When from==myself, the first hop ignores whatever address
        // we send (replaces with what they observe). Send unspec.
        // The from!=myself case goes via send_udp_info_forward.
        let (addr, port) = (AddrStr::unspec(), AddrStr::unspec());

        let Some(conn_id) = self.conn_for_nexthop(dereffed) else {
            return false;
        };
        let Some(conn) = self.conns.get_mut(conn_id) else {
            return false;
        };
        let from_name: &str = if from_is_myself { &self.name } else { to_name };
        let msg = UdpInfo {
            from: from_name.to_owned(),
            to: self
                .graph
                .node(dereffed)
                .map_or_else(|| to_name.to_owned(), |n| n.name.clone()),
            addr,
            port,
        };
        let nw = conn.send(format_args!("{}", msg.format()));

        if from_is_myself {
            self.dp.tunnels.entry(dereffed).or_default().udp_info_sent = Some(now);
        }
        nw
    }

    /// `send_udp_info(from, to)` forward path. Called from
    /// `on_udp_info` after the action decision. Unlike the originate
    /// path, this carries `from`'s OBSERVED address (which may have
    /// just been updated by `UpdateAndForward`).
    pub(super) fn send_udp_info_forward(&mut self, from_nid: NodeId, to_nid: NodeId) -> bool {
        let Some(from_name) = self.graph.node(from_nid).map(|n| n.name.clone()) else {
            return false;
        };
        let Some(to_name) = self.graph.node(to_nid).map(|n| n.name.clone()) else {
            return false;
        };

        // Same static-relay deref as the originate path.
        let Some(orig_route) = self.route_of(to_nid) else {
            return false;
        };
        let to_options_orig = ConnOptions::from_bits_retain(orig_route.options);
        let dereffed = if orig_route.via == self.myself {
            orig_route.nexthop
        } else {
            orig_route.via
        };

        let to_is_myself = dereffed == self.myself;
        let to_reachable = self.graph.node(dereffed).is_some_and(|n| n.reachable);
        // to->connection check only fires when from==myself.
        let from_options = self.route_of(from_nid).map_or(ConnOptions::empty(), |r| {
            ConnOptions::from_bits_retain(r.options)
        });
        let nexthop_options = self.route_of(dereffed).map_or(ConnOptions::empty(), |r| {
            self.route_of(r.nexthop).map_or(ConnOptions::empty(), |nr| {
                ConnOptions::from_bits_retain(nr.options)
            })
        });

        if !udp_info::should_send_udp_info(
            to_is_myself,
            to_reachable,
            false, // to_directly_connected — only checked when from==myself
            false, // from_is_myself
            from_options,
            to_options_orig,
            self.myself_options,
            nexthop_options,
            None, // last_sent — only checked when from==myself
            self.timers.now(),
            Duration::ZERO,
        ) {
            return false;
        }

        // Our observation of from's UDP address (or unspec).
        let (addr, port) = self
            .dp
            .tunnels
            .get(&from_nid)
            .and_then(|t| t.udp_addr)
            .map_or_else(
                || (AddrStr::unspec(), AddrStr::unspec()),
                |a| {
                    (
                        AddrStr::new(a.ip().to_string()).expect("ip is valid token"),
                        AddrStr::new(a.port().to_string()).expect("port is valid token"),
                    )
                },
            );

        let Some(conn_id) = self.conn_for_nexthop(dereffed) else {
            return false;
        };
        let Some(conn) = self.conns.get_mut(conn_id) else {
            return false;
        };
        let msg = UdpInfo {
            from: from_name,
            to: to_name,
            addr,
            port,
        };
        conn.send(format_args!("{}", msg.format()))
    }

    /// No static-relay deref unlike `UDP_INFO`.
    pub(super) fn send_mtu_info(
        &mut self,
        to_nid: NodeId,
        to_name: &str,
        mtu: i32,
        from_is_myself: bool,
    ) -> bool {
        self.send_mtu_info_from(self.myself, to_nid, to_name, mtu, from_is_myself)
    }

    /// `send_mtu_info` with explicit `from`. `from_is_myself` separate
    /// from `from_nid`: gate logic keys on it independently (debounce).
    pub(super) fn send_mtu_info_from(
        &mut self,
        from_nid: NodeId,
        to_nid: NodeId,
        to_name: &str,
        mtu: i32,
        from_is_myself: bool,
    ) -> bool {
        let to_is_myself = to_nid == self.myself;
        let to_reachable = self.graph.node(to_nid).is_some_and(|n| n.reachable);
        let to_directly_connected = self.nodes.get(&to_nid).and_then(|ns| ns.conn).is_some();
        let nexthop_options = self.route_of(to_nid).map_or(ConnOptions::empty(), |r| {
            self.route_of(r.nexthop).map_or(ConnOptions::empty(), |nr| {
                ConnOptions::from_bits_retain(nr.options)
            })
        });

        let now = self.timers.now();
        let last_sent = self.dp.tunnels.get(&to_nid).and_then(|t| t.mtu_info_sent);
        let interval = Duration::from_secs(u64::from(self.settings.mtu_info_interval));

        if !udp_info::should_send_mtu_info(
            to_is_myself,
            to_reachable,
            to_directly_connected,
            from_is_myself,
            last_sent,
            now,
            interval,
            nexthop_options,
        ) {
            return false;
        }

        // Adjust MTU based on our knowledge of the path to `from`.
        let from_route = self.route_of(from_nid);
        let from_via_is_myself = from_route.is_some_and(|r| r.via == self.myself);
        let via_nid = from_route.map(|r| {
            if r.via == self.myself {
                r.nexthop
            } else {
                r.via
            }
        });
        let via_nexthop_nid = via_nid.and_then(|v| self.route_of(v).map(|r| r.nexthop));

        let mtu = udp_info::adjust_mtu_for_send(
            mtu,
            from_via_is_myself,
            self.pmtu_snapshot(from_nid),
            via_nid.and_then(|v| self.pmtu_snapshot(v)),
            via_nexthop_nid.and_then(|v| self.pmtu_snapshot(v)),
        );

        if from_is_myself {
            self.dp.tunnels.entry(to_nid).or_default().mtu_info_sent = Some(now);
        }

        let Some(conn_id) = self.conn_for_nexthop(to_nid) else {
            return false;
        };
        let Some(conn) = self.conns.get_mut(conn_id) else {
            return false;
        };
        let from_name = self
            .graph
            .node(from_nid)
            .map_or_else(|| self.name.clone(), |n| n.name.clone());
        let msg = MtuInfo {
            from: from_name,
            to: to_name.to_owned(),
            mtu,
        };
        conn.send(format_args!("{}", msg.format()))
    }

    // ─── UDP_INFO / MTU_INFO receive ────────────────────────────

    /// Err only on parse failure (→ teardown); semantic drops are
    /// Ok(false).
    pub(super) fn on_udp_info(
        &mut self,
        from_conn: ConnId,
        body: &[u8],
    ) -> Result<bool, DispatchError> {
        let body_str = std::str::from_utf8(body)
            .map_err(|_| DispatchError::BadKey("non-UTF-8 UDP_INFO".into()))?;
        let parsed = UdpInfo::parse(body_str)
            .map_err(|_| DispatchError::BadKey("UDP_INFO parse failed".into()))?;

        // `from_conn` came from dispatch THIS turn; live.
        let conn_name = self
            .conns
            .get(from_conn)
            .expect("dispatched from live conn")
            .name
            .clone();

        let from = self.node_ids.get(&parsed.from).copied().map(|nid| {
            let directly_connected = self.nodes.get(&nid).and_then(|ns| ns.conn).is_some();
            let udp_confirmed = self
                .dp
                .tunnels
                .get(&nid)
                .is_some_and(|t| t.status.udp_confirmed);
            // `from->via == from`: false means "wandered past static relay".
            let via_is_self = self.route_of(nid).is_some_and(|r| r.via == nid);
            (
                nid,
                FromState {
                    directly_connected,
                    udp_confirmed,
                    via_is_self,
                },
            )
        });
        let to = self.node_ids.get(&parsed.to).copied();
        let current_from_addr =
            from.and_then(|(nid, _)| self.dp.tunnels.get(&nid).and_then(|t| t.udp_addr));

        match udp_info::on_receive_udp_info(&parsed, from, to, current_from_addr) {
            UdpInfoAction::UnknownNode => {
                log::error!(target: "tincd::proto",
                            "Got UDP_INFO from {conn_name} for unknown node \
                             {} → {}", parsed.from, parsed.to);
                Ok(false)
            }
            UdpInfoAction::DroppedPastRelay => {
                log::warn!(target: "tincd::proto",
                           "Got UDP_INFO from {conn_name} for {} which we \
                            can't reach directly", parsed.from);
                Ok(false)
            }
            UdpInfoAction::UpdateAndForward { from, to, new_addr } => {
                log::debug!(target: "tincd::proto",
                            "UDP_INFO from {conn_name}: learned {} at {new_addr}",
                            parsed.from);
                let t = self.dp.tunnels.entry(from).or_default();
                t.udp_addr = Some(new_addr);
                t.udp_addr_cached = None; // stale
                Ok(self.send_udp_info_forward(from, to))
            }
            UdpInfoAction::Forward { from, to } => Ok(self.send_udp_info_forward(from, to)),
        }
    }

    /// Malformed (mtu<512) is Err → teardown; everything else Ok.
    pub(super) fn on_mtu_info(
        &mut self,
        from_conn: ConnId,
        body: &[u8],
    ) -> Result<bool, DispatchError> {
        let body_str = std::str::from_utf8(body)
            .map_err(|_| DispatchError::BadKey("non-UTF-8 MTU_INFO".into()))?;
        let parsed = MtuInfo::parse(body_str)
            .map_err(|_| DispatchError::BadKey("MTU_INFO parse failed".into()))?;

        // `from_conn` came from dispatch THIS turn; live.
        let conn_name = self
            .conns
            .get(from_conn)
            .expect("dispatched from live conn")
            .name
            .clone();

        let from = self.node_ids.get(&parsed.from).copied().map(|nid| {
            // Supply zero defaults for missing tunnel state.
            let t = self.dp.tunnels.get(&nid);
            (
                nid,
                FromMtuState {
                    mtu: t.map_or(0, TunnelState::mtu),
                    minmtu: t.map_or(0, TunnelState::minmtu),
                    maxmtu: t.map_or(MTU, TunnelState::maxmtu),
                },
            )
        });
        let to = self.node_ids.get(&parsed.to).copied();

        match udp_info::on_receive_mtu_info(&parsed, from, to) {
            MtuInfoAction::Malformed => {
                // conn-fatal.
                Err(DispatchError::BadKey(format!(
                    "MTU_INFO from {conn_name}: invalid MTU {}",
                    parsed.mtu
                )))
            }
            MtuInfoAction::UnknownNode => {
                log::error!(target: "tincd::proto",
                            "Got MTU_INFO from {conn_name} for unknown node \
                             {} → {}", parsed.from, parsed.to);
                Ok(false)
            }
            MtuInfoAction::ClampAndForward { from, to, new_mtu } => {
                // Provisional mtu (probing will overwrite). Only
                // matters if pmtu seeded; unseeded reads MTU anyway.
                log::debug!(target: "tincd::proto",
                            "Using provisional MTU {new_mtu} for {}", parsed.from);
                if let Some(p) = self.dp.tunnels.get_mut(&from).and_then(|t| t.pmtu.as_mut()) {
                    p.mtu = new_mtu;
                }
                Ok(self.send_mtu_info_from(from, to, &parsed.to, i32::from(new_mtu), false))
            }
            MtuInfoAction::Forward { from, to } => {
                // adjust_mtu_for_send may tighten further with our knowledge.
                let mtu = parsed.mtu.min(udp_info::MTU_MAX);
                Ok(self.send_mtu_info_from(from, to, &parsed.to, mtu, false))
            }
        }
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

        // ─── send_locally override ───────────────────────────────
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
                local_addr::choose_local(&candidates, &mut OsRng, &listener_addrs)
            {
                return Some((addr, sock));
            }
            // Fall through if no local address found.
        }

        // ─── reflexive (stashed udp_addr) ────────────────────────
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

        // ─── edge's reverse->address ─────────────────────────────
        // Direct-neighbor shortcut: NodeState.edge_addr is the
        // peer-ACK addr. Transitives go via relay (try_tx
        // via-recursion) anyway.
        let addr = self.nodes.get(&to_nid)?.edge_addr?;
        let sock = local_addr::adapt_socket(&addr, 0, &listener_addrs);
        Some((addr, sock))
    }

    /// `io_set` `ReadWrite` for any conn with nonempty outbuf. Device-read
    /// / udp-recv paths queue on meta-conns without a `ConnId` in scope.
    /// STUB(chunk-11-perf): track touched `ConnIds` instead of sweeping.
    pub(super) fn maybe_set_write_any(&mut self) {
        let dirty: Vec<ConnId> = self
            .conns
            .iter()
            .filter(|(_, c)| !c.outbuf.is_empty())
            .map(|(id, _)| id)
            .collect();
        for id in dirty {
            if let Some(&io_id) = self.conn_io.get(id)
                && let Err(e) = self.ev.set(io_id, Io::ReadWrite)
            {
                log::error!(target: "tincd::conn",
                                "io_set failed for {id:?}: {e}");
                self.terminate(id);
            }
        }
    }

    /// Walk conns with `log_level`, send each log line. We drain the
    /// thread-local tap buffer once per event-loop turn.
    ///
    /// Wire shape: newline-terminated header `"18 15 <len>"`, then
    /// RAW body bytes (no `\n`). CLI does `recvline()` for the
    /// header, `recvdata(len)` for the body.
    ///
    /// Per-conn level filter. Our `log::Level` ordering is INVERTED
    /// (Error=1 < Trace=5 in the enum, but Error is "higher"
    /// priority). `<=` is "this level or more important":
    /// `Level::Info <= Level::Debug` is true (Info passes a
    /// Debug-level filter).
    pub(super) fn flush_log_tap(&mut self) {
        let drained = crate::log_tap::drain();
        if drained.is_empty() {
            return;
        }
        // Snapshot log-conn ids: send() borrows `&mut conn`.
        let log_conns: Vec<_> = self
            .conns
            .iter()
            .filter_map(|(id, c)| c.log_level.map(|lv| (id, lv)))
            .collect();
        if log_conns.is_empty() {
            // Gate is open but no log conns (race: REQ_LOG arrived
            // and the conn died in the same turn). Drop on the floor.
            return;
        }
        let mut nw = false;
        for (level, msg) in &drained {
            for &(id, conn_level) in &log_conns {
                // `Level` ordering: Error < Warn < Info < Debug <
                // Trace. `*level <= conn_level` = "at least as
                // important as the conn wants".
                if *level > conn_level {
                    continue;
                }
                let Some(conn) = self.conns.get_mut(id) else {
                    continue;
                };
                // Header line; send() appends `\n`. Then raw body,
                // no newline.
                nw |= conn.send(format_args!(
                    "{} {} {}",
                    tinc_proto::Request::Control as u8,
                    crate::proto::REQ_LOG,
                    msg.len()
                ));
                nw |= conn.send_raw(msg.as_bytes());
            }
        }
        if nw {
            self.maybe_set_write_any();
        }
    }
}
