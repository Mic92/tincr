use super::super::{ConnId, Daemon, ForwardingMode, RoutingMode, TimerWhat};

use std::time::Duration;

use crate::route_decide::{self, RouteResult, TtlResult, route};
use crate::tunnel::{MTU, TunnelState};
use crate::{broadcast, mss, route_mac};

use super::icmp::IcmpKind;
use crate::daemon::intervals::HOUSEKEEP_SWEEP;
use crate::dispatch::OPTION_CLAMP_MSS;
use crate::dns;
use crate::fragment;
use crate::graph::{EdgeId, NodeId};
use crate::packet::ETH_P_ARP;
use crate::packet::ETH_P_IP;
use tinc_proto::{Request, Subnet};

/// Cap on locally-learned MAC subnets (switch mode).
pub(in crate::daemon) const MAX_MAC_LEASES: usize = 4096;

impl Daemon {
    /// `from`: `None` = device read; `Some` = peer. Returns the
    /// `io_set` signal.
    pub(in crate::daemon) fn forward_packet(
        &mut self,
        data: &mut [u8],
        from: Option<NodeId>,
    ) -> bool {
        // pcap is first — a tap, sees everything (incl. kernel-mode
        // forward, runt frames, ARP). The cheap-gate is the field
        // load; `send_pcap` walks conns only when armed (debugging).
        let mut nw = false;
        if self.any_pcap {
            nw |= self.send_pcap(data);
        }

        // Kernel-mode shortcut — peer traffic straight to TUN, OS
        // forwarding table decides. Packets from our device still
        // route (we're the originator). before the length check
        // (device.write rejects short).
        if self.settings.forwarding_mode == ForwardingMode::Kernel && from.is_some() {
            self.send_packet_myself(data);
            return nw;
        }

        match self.settings.routing_mode {
            RoutingMode::Switch => {
                return nw | self.route_packet_mac(data, from);
            }
            RoutingMode::Hub => {
                // Always broadcast, no learning.
                return nw | self.dispatch_route_result(RouteResult::Broadcast, data, from);
            }
            RoutingMode::Router => {}
        }

        // ARP intercept. ROUTER-only (Switch treats ARP as opaque
        // eth, returned above). `handle_arp` does its own subnet
        // lookup so handle it before `route()` (which would return
        // `Unsupported{"arp"}`).
        if data.len() >= 14 && u16::from_be_bytes([data[12], data[13]]) == ETH_P_ARP {
            return nw | self.handle_arp(data, from);
        }

        // DNS stub intercept (Rust-only): match `dst == magic && dport == 53` on TUN
        // ingress, no socket bind (as Tailscale's netstack does). Router mode, device
        // reads only; a peer sending us DNS is misconfig and takes the normal route.
        // Feature off costs one `is_some()` branch.
        if from.is_none() && self.dns.is_some() && self.try_dns_intercept(data) {
            return nw;
        }

        // Close over node_ids+graph and gate on reachability.
        // `myself` is always reachable, so the "only check reachable
        // for REMOTE owners" falls out without an explicit string
        // compare.
        let node_ids = &self.node_ids;
        let graph = &self.graph;
        let result = route(data, &self.subnets, |name| {
            let nid = *node_ids.get(name)?;
            graph.node(nid).filter(|n| n.reachable).map(|_| nid)
        });

        nw | self.dispatch_route_result(result, data, from)
    }

    /// Emit `18 14 LEN\n` plus the full eth frame to each pcap subscriber
    /// (plaintext control conns; the CLI reads the line, then exactly LEN bytes, so
    /// embedded newlines are fine). `any_pcap` is recomputed during the walk, so a
    /// dropped subscriber clears the gate on the next packet without `terminate()`
    /// knowing. Debug-only hot path; unarmed cost is one branch.
    fn send_pcap(&mut self, data: &[u8]) -> bool {
        let now = self.timers.now();
        let mut nw = false;
        let mut still_armed = false;
        for (_, conn) in &mut self.conns {
            if !conn.pcap {
                continue;
            }
            still_armed = true;
            // Refresh idle-reap window while we're actively streaming.
            conn.last_ping_time = now + Duration::from_hours(1);

            // snaplen=0 → no clip.
            let snap = usize::from(conn.pcap_snaplen);
            let len = if snap != 0 && snap < data.len() {
                snap
            } else {
                data.len()
            };

            // Control conns are plaintext (`conn.sptps` is None), so
            // `send` formats straight to outbuf.
            nw |= conn.send(format_args!(
                "{} {} {len}",
                tinc_proto::Request::Control,
                crate::dispatch::REQ_PCAP
            ));
            // Raw body, no `\n`. `send` is infallible (queues to
            // outbuf, write errors surface at `flush()`).
            nw |= conn.send_raw(&data[..len]);
        }
        self.any_pcap = still_armed;
        nw
    }

    /// Switch-mode dispatch.
    fn route_packet_mac(&mut self, data: &mut [u8], from: Option<NodeId>) -> bool {
        let from_myself = from.is_none();
        let source_name = match from {
            None => self.name.clone(),
            Some(nid) => self
                .graph
                .node(nid)
                .map_or_else(|| "<unknown>".to_owned(), |n| n.name.clone()),
        };

        let node_ids = &self.node_ids;
        let (result, learn) = route_mac::route_mac(
            data,
            from_myself,
            &source_name,
            &self.name,
            &self.mac_table,
            |name| node_ids.get(name).copied(),
        );

        // LearnAction and routing are independent.
        let mut nw = false;
        match learn {
            route_mac::LearnAction::NotOurs => {}
            route_mac::LearnAction::New(mac) => {
                nw |= self.learn_mac(mac);
            }
            route_mac::LearnAction::Refresh(mac) => {
                // route_mac's snapshot isn't myself-scoped — check.
                if self.mac_table.get(&mac).map(String::as_str) == Some(self.name.as_str()) {
                    let now = self.timers.now();
                    self.mac_leases.refresh(mac, now, self.settings.macexpire);
                } else {
                    // Remotely owned → VM migrated to us.
                    nw |= self.learn_mac(mac);
                }
            }
        }

        nw |= self.dispatch_route_result(result, data, from);
        nw
    }

    /// New source MAC on TAP → `Subnet::Mac` + broadcast `ADD_SUBNET` +
    /// arm `age_subnets` timer.
    fn learn_mac(&mut self, mac: route_mac::Mac) -> bool {
        if self.mac_leases.len() >= MAX_MAC_LEASES {
            if !self.mac_cap_warned {
                self.mac_cap_warned = true;
                log::warn!(target: "tincd::net",
                           "Learned MAC table full ({MAX_MAC_LEASES}); \
                            dropping new MACs until some expire");
            }
            return false;
        }
        log::info!(target: "tincd::net",
                   "Learned new MAC address \
                    {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

        let subnet = Subnet::Mac {
            addr: mac,
            weight: 10,
        };
        let myname = self.name.clone();
        self.subnets.add(subnet, myname.clone());
        self.tx_snap_refresh_subnets();
        self.mac_table.insert(mac, myname.clone());
        self.run_subnet_script(true, &myname, &subnet);

        // learn() returns true if table was empty.
        let now = self.timers.now();
        let arm_timer = self.mac_leases.learn(mac, now, self.settings.macexpire);

        let mut nw = false;
        let targets = self.broadcast_targets(None);
        for cid in targets {
            nw |= self.send_subnet(cid, Request::AddSubnet, &myname, &subnet);
        }

        // Arm only when learn() says table was empty and no slot
        // (defensive).
        if arm_timer && self.age_subnets_timer.is_none() {
            let tid = self.timers.add(TimerWhat::AgeSubnets);
            self.timers.set(tid, HOUSEKEEP_SWEEP);
            self.age_subnets_timer = Some(tid);
        }

        nw
    }

    fn broadcast_packet(&mut self, data: &mut [u8], from: Option<NodeId>) -> bool {
        // Echo a forwarded broadcast to local kernel.
        if from.is_some() {
            self.send_packet_myself(data);
        }

        // Tunnelserver: MST might be invalid (filtered ADD_EDGE →
        // loops). BMODE_NONE: opted out.
        if self.settings.tunnelserver
            || self.settings.broadcast_mode == broadcast::BroadcastMode::None
        {
            return false;
        }

        let from_is_self = from.is_none();
        log::debug!(target: "tincd::net",
                    "Broadcasting packet of {} bytes from {}",
                    data.len(),
                    if from_is_self { "MYSELF" } else { "peer" });

        let target_nids: Vec<NodeId> = match self.settings.broadcast_mode {
            broadcast::BroadcastMode::None => unreachable!("checked above"),
            broadcast::BroadcastMode::Mst => {
                let from_conn: Option<ConnId> = from.and_then(|nid| {
                    let route = self.route_of(nid)?;
                    self.nodes.get(&route.nexthop)?.conn
                });

                let active: Vec<(ConnId, EdgeId)> = self
                    .conns
                    .iter()
                    .filter(|&(_, c)| c.active)
                    .filter_map(|(cid, c)| {
                        let nid = self.node_ids.get(&c.name)?;
                        let eid = self.nodes.get(nid)?.edge?;
                        Some((cid, eid))
                    })
                    .collect();

                let target_conns =
                    broadcast::mst_targets(active.into_iter(), &self.last_mst, from_conn);

                target_conns
                    .into_iter()
                    .filter_map(|cid| {
                        let cname = &self.conns.get(cid)?.name;
                        self.node_ids.get(cname).copied()
                    })
                    .collect()
            }
            broadcast::BroadcastMode::Direct => {
                // Walk reachable nodes, filter to one-hop.
                // last_routes[nid] None for unreachable.
                let routes = &self.last_routes;
                let nodes_iter = self.node_ids.values().filter_map(|&nid| {
                    let r = (*routes.get(nid.0 as usize)?)?;
                    Some((nid, Some(r.via), Some(r.nexthop)))
                });
                broadcast::direct_targets(nodes_iter, self.myself, from_is_self)
            }
        };

        // No clamp_mss/directonly/decrement_ttl — route()-level
        // concerns; broadcast bypasses route().
        let mut nw = false;
        for nid in target_nids {
            let len = data.len();
            let tunnel = self.dp.tunnels.entry(nid).or_default();
            tunnel.stats.add_out(1, len as u64);
            nw |= self.send_sptps_packet(nid, data);
            nw |= self.try_tx(nid, true);
        }
        nw
    }

    /// `RouteResult` dispatch. Shared by Router and Switch paths.
    #[expect(clippy::needless_pass_by_value)] // consumed by match (moves out NodeId from variants)
    fn dispatch_route_result(
        &mut self,
        result: RouteResult<NodeId>,
        data: &mut [u8],
        from: Option<NodeId>,
    ) -> bool {
        match result {
            RouteResult::Forward { to } if to == self.myself => {
                self.send_packet_myself(data);
                false
            }
            RouteResult::Forward { to: to_nid } => self.dispatch_forward(to_nid, data, from),
            RouteResult::Unreachable {
                icmp_type,
                icmp_code,
            } => self.emit_icmp(
                data,
                IcmpKind::Unreach {
                    t: icmp_type,
                    c: icmp_code,
                    discover_src: false,
                },
                from,
            ),
            RouteResult::NeighborSolicit => {
                self.handle_ndp(data, from);
                false
            }
            RouteResult::Unsupported { reason } => {
                log::debug!(target: "tincd::net",
                            "route: dropping packet ({reason})");
                false
            }
            RouteResult::Broadcast => {
                // decrement_ttl() passes ARP via TooShort.
                if self.settings.decrement_ttl && from.is_some() {
                    match route_decide::decrement_ttl(data) {
                        TtlResult::Decremented | TtlResult::TooShort => {}
                        TtlResult::DropSilent | TtlResult::SendIcmp { .. } => {
                            // No ICMP synth.
                            return false;
                        }
                    }
                }
                self.broadcast_packet(data, from)
            }
            RouteResult::TooShort { need, have } => {
                log::debug!(target: "tincd::net",
                            "route: too short (need {need}, have {have})");
                false
            }
        }
    }

    /// The Forward-to-peer arm: 5 gates (loop check, `FMODE_OFF`,
    /// directonly, PMTU, TTL) all derived from the route table entry
    /// for `to_nid`. Gates share `via_nid`/`via_mtu` so they live
    /// together.
    fn dispatch_forward(&mut self, to_nid: NodeId, data: &mut [u8], from: Option<NodeId>) -> bool {
        let to = self
            .graph
            .node(to_nid)
            .map_or_else(|| "<gone>".to_owned(), |n| n.name.clone());

        // Dest subnet OWNED by sender — overlapping subnets,
        // misconfig.
        if Some(to_nid) == from {
            log::warn!(target: "tincd::net",
                       "Packet looping back to {to}");
            return false;
        }

        // FMODE_OFF: we are an endpoint, not a relay. `from.is_some()` is `source !=
        // myself`; this arm is `owner != myself`. v4 → NET_ANO, v6 → ADMIN, MAC →
        // silent drop. The setting used to be parsed and never read (`bcc5c3e3`).
        if self.settings.forwarding_mode == ForwardingMode::Off && from.is_some() {
            log::debug!(target: "tincd::net",
                        "Forwarding=off: dropping transit packet \
                         to {to} (we are not a relay)");
            if self.settings.routing_mode == RoutingMode::Router {
                let ethertype = u16::from_be_bytes([data[12], data[13]]);
                let (t, c) = if ethertype == ETH_P_IP {
                    (route_decide::ICMP_DEST_UNREACH, route_decide::ICMP_NET_ANO)
                } else {
                    (
                        route_decide::ICMP6_DST_UNREACH,
                        route_decide::ICMP6_DST_UNREACH_ADMIN,
                    )
                };
                return self.emit_icmp(
                    data,
                    IcmpKind::Unreach {
                        t,
                        c,
                        discover_src: false,
                    },
                    from,
                );
            }
            return false;
        }

        // clamp_mss before send, after routing. last_routes
        // is current for any Forward target (route() only
        // returns Forward for reachable owners).
        let route = self.route_of(to_nid);
        let via_options = route.map_or(0, |r| r.options);
        let via_nid = route.map_or(to_nid, |r| {
            if r.via == self.myself {
                r.nexthop
            } else {
                r.via
            }
        });

        // Next hop is the sender — bounce loop (stale graph
        // data, DEL_EDGE arrived but run_graph hasn't
        // recomputed via).
        if Some(via_nid) == from {
            let from_name = from
                .and_then(|nid| self.graph.node(nid))
                .map_or("?", |n| n.name.as_str());
            log::error!(target: "tincd::net",
                        "Routing loop for packet from {from_name}");
            return false;
        }

        // TunnelState::default() inits to MTU (not 0); until
        // PMTU runs: 1518 ceiling.
        let via_mtu = self.dp.tunnels.get(&via_nid).map_or(MTU, TunnelState::mtu);

        // directonly — operator opts out of relay.
        if self.settings.directonly && to_nid != via_nid {
            let ethertype = u16::from_be_bytes([data[12], data[13]]);
            let (t, c) = if ethertype == ETH_P_IP {
                (route_decide::ICMP_DEST_UNREACH, route_decide::ICMP_NET_ANO)
            } else {
                (
                    route_decide::ICMP6_DST_UNREACH,
                    route_decide::ICMP6_DST_UNREACH_ADMIN,
                )
            };
            return self.emit_icmp(
                data,
                IcmpKind::Unreach {
                    t,
                    c,
                    discover_src: false,
                },
                from,
            );
        }
        // Too big for the next hop's PMTU, relaying only (clamp_mss and kernel PMTU
        // cover our own traffic). Floors 590/1294 = RFC 791/8200 minimum + 14. Skip
        // while `via_mtu == 0`: before discovery finishes `mtu` is 0, we'd claim 576,
        // and the kernel caches that per destination for 10 minutes, pinning every TCP
        // flow in that window to MSS 536.
        if via_nid != self.myself && via_mtu != 0 {
            let ethertype = u16::from_be_bytes([data[12], data[13]]);
            let floor: u16 = if ethertype == ETH_P_IP { 590 } else { 1294 };
            let limit = via_mtu.max(floor);
            if data.len() > usize::from(limit) {
                if ethertype == ETH_P_IP {
                    // DF flag (data.len()>590 ⇒ [20] in bounds).
                    let df_set = data[20] & 0x40 != 0;
                    if df_set {
                        // limit-14 = IP-layer MTU. limit≥590
                        // so sub never wraps.
                        return self.emit_icmp(
                            data,
                            IcmpKind::FragNeeded { mtu: limit - 14 },
                            from,
                        );
                    }
                    // RFC 791 §2.3: routers must fragment.
                    // Rare path (modern OS sets DF on TCP)
                    // but UDP without DF through narrow-
                    // MTU relay needs this.
                    let Some(frags) = fragment::fragment_v4(data, limit) else {
                        log::debug!(target: "tincd::net",
                            "fragment_v4: malformed input, dropping");
                        return false;
                    };
                    // Mirror the normal send path below: preflight
                    // the transport before choosing TCP or UDP.
                    let n = frags.len();
                    log::debug!(target: "tincd::net",
                        "Fragmenting packet of {} bytes into \
                         {n} pieces for {to}", data.len());
                    {
                        let tunnel = self.dp.tunnels.entry(to_nid).or_default();
                        for frag in &frags {
                            tunnel.stats.add_out(1, frag.len() as u64);
                        }
                    }
                    let mut nw = self.try_tx(to_nid, true);
                    for frag in &frags {
                        nw |= self.send_sptps_packet(to_nid, frag);
                    }
                    return nw;
                }
                // v6: no in-transit frag (RFC 8200 §5).
                return self.emit_icmp(
                    data,
                    IcmpKind::TooBigV6 {
                        mtu: u32::from(limit - 14),
                    },
                    from,
                );
            }
        }

        if via_options & OPTION_CLAMP_MSS != 0 {
            let mtu = via_mtu.min(MTU);
            let _ = mss::clamp(data, mtu);
        }

        // `source != myself` gate: don't decrement on
        // TUN-origin (we are the first hop).
        if self.settings.decrement_ttl && from.is_some() {
            match route_decide::decrement_ttl(data) {
                TtlResult::Decremented => {}
                TtlResult::TooShort | TtlResult::DropSilent => {
                    return false;
                }
                TtlResult::SendIcmp {
                    icmp_type,
                    icmp_code,
                } => {
                    return self.emit_icmp(
                        data,
                        IcmpKind::Unreach {
                            t: icmp_type,
                            c: icmp_code,
                            discover_src: true,
                        },
                        from,
                    );
                }
            }
        }

        // Read inner TOS for the outer UDP socket. Threaded
        // via Daemon.tx_priority. Reset to 0 each packet —
        // priority only ever flows from data through to UDP
        // send. Done here, not at forward_packet entry, to stay
        // clear of the dump-traffic agent's route boundary.
        self.dp.tx_priority = if self.settings.priorityinheritance {
            route_decide::extract_tos(data).unwrap_or(0)
        } else {
            0
        };

        let len = data.len();
        log::debug!(target: "tincd::net",
                    "Sending packet of {len} bytes to {to}");
        // Counts attempts, not deliveries.
        let tunnel = self.dp.tunnels.entry(to_nid).or_default();
        tunnel.stats.add_out(1, len as u64);

        // Preflight may demote stale UDP before transport choice;
        // every forwarded packet still drives PMTU discovery once.
        let mut nw = self.try_tx(to_nid, true);
        nw |= self.send_sptps_packet(to_nid, data);
        nw
    }

    /// DNS stub TUN intercept (Rust-only): `true` if `data` was a DNS query to the
    /// magic IP and a reply was written, so the caller skips `route()`; `false`
    /// after ~5 byte compares otherwise. The caller has checked
    /// `self.dns.is_some()`; the take/put-back avoids the borrow conflict with
    /// `device.write(&mut self)` and moves only two `Option<IpAddr>` and a
    /// `String`.
    fn try_dns_intercept(&mut self, data: &[u8]) -> bool {
        let cfg = self.dns.take().expect("caller gated on is_some()");
        // v4 path. `match_v4` does the full eth+IP+UDP+port check;
        // None means "not for us" — fall through to v6 then route().
        let hit = if let Some(dns_ip) = cfg.dns_addr4
            && let Some((src, sport, dns)) = dns::match_v4(data, dns_ip)
        {
            let Some(reply) = dns::answer(dns, &cfg, &self.subnets, &self.name) else {
                // Malformed past header recovery (truncated ID, or
                // QR bit set = reflection attempt). Drop silently.
                // not route() — it'd Forward{to:myself} (the magic IP
                // is on the TUN), and the kernel would ICMP port-
                // unreachable, leaking that something's there.
                self.dns = Some(cfg);
                return true;
            };
            let mut frame = dns::wrap_v4(data, &reply, dns_ip, src, sport);
            log::debug!(target: "tincd::dns",
                        "reply {} bytes to {src}:{sport}", reply.len());
            if let Err(e) = self.device.write(&mut frame) {
                log::debug!(target: "tincd::dns",
                            "device write failed: {e}");
            }
            true
        }
        // v6 path. Same shape; UDP checksum is mandatory here
        // (RFC 8200 §8.1) — wrap_v6 always computes it.
        else if let Some(dns_ip) = cfg.dns_addr6
            && let Some((src, sport, dns)) = dns::match_v6(data, &dns_ip)
        {
            let Some(reply) = dns::answer(dns, &cfg, &self.subnets, &self.name) else {
                self.dns = Some(cfg);
                return true;
            };
            let mut frame = dns::wrap_v6(data, &reply, &dns_ip, &src, sport);
            log::debug!(target: "tincd::dns",
                        "reply {} bytes to [{src}]:{sport}", reply.len());
            if let Err(e) = self.device.write(&mut frame) {
                log::debug!(target: "tincd::dns",
                            "device write failed: {e}");
            }
            true
        } else {
            false
        };
        self.dns = Some(cfg);
        hit
    }
}
