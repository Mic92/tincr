use super::super::{ConnId, Daemon, ForwardingMode, RoutingMode, TimerWhat};

use std::time::Duration;

use crate::route::{self, RouteResult, TtlResult, route};
use crate::tunnel::{MTU, TunnelState};
use crate::{broadcast, icmp, mss, route_mac};

use tinc_graph::{EdgeId, NodeId};
use tinc_proto::{Request, Subnet};

impl Daemon {
    /// `from`: `None` = device read; `Some` = peer. Returns the
    /// `io_set` signal.
    pub(in crate::daemon) fn route_packet(
        &mut self,
        data: &mut [u8],
        from: Option<NodeId>,
    ) -> bool {
        // pcap is FIRST — a tap, sees everything (incl. kernel-mode
        // forward, runt frames, ARP). The cheap-gate is the field
        // load; `send_pcap` walks conns only when armed (debugging).
        let mut nw = false;
        if self.any_pcap {
            nw |= self.send_pcap(data);
        }

        // Kernel-mode shortcut — peer traffic straight to TUN, OS
        // forwarding table decides. Packets from our device still
        // route (we're the originator). BEFORE the length check
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

        // ARP intercept. ROUTER-ONLY (Switch treats ARP as opaque
        // eth, returned above). `handle_arp` does its own subnet
        // lookup so handle it before `route()` (which would return
        // `Unsupported{"arp"}`).
        if data.len() >= 14 && u16::from_be_bytes([data[12], data[13]]) == crate::packet::ETH_P_ARP
        {
            return nw | self.handle_arp(data, from);
        }

        // DNS stub intercept (Rust-only). Tailscale's trick: no
        // socket bind, just match `dst==magic && dport==53` on TUN
        // ingress (`wgengine/netstack/netstack.go:847-858`). ROUTER-
        // mode + device-read only — `from.is_some()` means a peer
        // sent us a DNS query, which is either misconfig (their
        // resolved is pointed at OUR magic IP) or weird; let it hit
        // route() and Forward/Unreachable normally. The `is_some()`
        // gate is the cheap path: feature off = one branch.
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

    /// Walk pcap subscribers, emit `"18 14 LEN\n"` + raw packet
    /// body to each. The body is the FULL eth frame.
    ///
    /// Recomputes `any_pcap` as it walks: clears the flag at the
    /// top, then sets it for each live subscriber. If a subscriber
    /// dropped, the NEXT packet's walk finds zero and clears the
    /// gate — `terminate()` stays ignorant. One wasted walk per
    /// disconnect; cheap (conns is ~5).
    ///
    /// Wire shape (control conns are plaintext, no SPTPS):
    ///   `send_request`: `"18 14 LEN\n"` (`send` appends `\n`)
    ///   `send_meta`:    raw `data[..LEN]` bytes, no terminator
    /// The CLI's `recv_line()` reads to `\n`, then `recv_data(LEN)`
    /// reads exactly LEN bytes (`stream.rs:556-571`). The packet body
    /// MAY contain `\n`; the length-prefixed framing makes that safe.
    ///
    /// Hot path WHEN armed (which is rare — debugging only). The
    /// `any_pcap` gate keeps the unarmed cost at one branch.
    fn send_pcap(&mut self, data: &[u8]) -> bool {
        let mut nw = false;
        let mut still_armed = false;
        for (_, conn) in &mut self.conns {
            if !conn.pcap {
                continue;
            }
            still_armed = true;

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
                tinc_proto::Request::Control as u8,
                crate::proto::REQ_PCAP
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

        // Arm only when learn() says table was empty AND no slot
        // (defensive).
        if arm_timer && self.age_subnets_timer.is_none() {
            let tid = self.timers.add(TimerWhat::AgeSubnets);
            self.timers.set(tid, Duration::from_secs(10));
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
                    let route = self.last_routes.get(nid.0 as usize)?.as_ref()?;
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
                let nodes_iter = self.node_ids.values().filter_map(|&nid| {
                    let r = self.last_routes.get(nid.0 as usize)?.as_ref()?;
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
            let tunnel = self.tunnels.entry(nid).or_default();
            tunnel.out_packets += 1;
            tunnel.out_bytes += len as u64;
            nw |= self.send_sptps_packet(nid, data);
            nw |= self.try_tx(nid, true);
        }
        nw
    }

    /// `RouteResult` dispatch. Shared by Router and Switch paths.
    #[allow(clippy::too_many_lines)] // Forward arm ~100 LOC: 5 gates share via_nid/via_mtu
    #[allow(clippy::needless_pass_by_value)] // RouteResult<NodeId>: Copy
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
            RouteResult::Forward { to: to_nid } => {
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

                // FMODE_OFF — operator says "I am an endpoint, not a
                // relay". Gate is `source != myself && owner !=
                // myself`: `from.is_some()` is the first; this match
                // arm (NOT the `to == self.myself` arm above) is the
                // second. v4 → NET_ANO, v6 → ADMIN; MAC (Switch) →
                // silent drop. Gap audit `bcc5c3e3`: parsed in
                // `parse_settings`, never read — the security knob
                // silently no-op'd.
                if self.settings.forwarding_mode == ForwardingMode::Off && from.is_some() {
                    log::debug!(target: "tincd::net",
                                "Forwarding=off: dropping transit packet \
                                 to {to} (we are not a relay)");
                    if self.settings.routing_mode == RoutingMode::Router {
                        let ethertype = u16::from_be_bytes([data[12], data[13]]);
                        let (t, c) = if ethertype == crate::packet::ETH_P_IP {
                            (route::ICMP_DEST_UNREACH, route::ICMP_NET_ANO)
                        } else {
                            (route::ICMP6_DST_UNREACH, route::ICMP6_DST_UNREACH_ADMIN)
                        };
                        self.write_icmp_to_device(data, t, c);
                    }
                    return false;
                }

                // clamp_mss BEFORE send, AFTER routing. last_routes
                // is current for any Forward target (route() only
                // returns Forward for reachable owners).
                let route = self
                    .last_routes
                    .get(to_nid.0 as usize)
                    .and_then(Option::as_ref);
                let via_options = route.map_or(0, |r| r.options);
                let via_nid = route.map_or(to_nid, |r| {
                    if r.via == self.myself {
                        r.nexthop
                    } else {
                        r.via
                    }
                });

                // Next hop IS the sender — bounce loop (stale graph
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
                let via_mtu = self.tunnels.get(&via_nid).map_or(MTU, TunnelState::mtu);

                // directonly — operator opts out of relay.
                if self.settings.directonly && to_nid != via_nid {
                    let ethertype = u16::from_be_bytes([data[12], data[13]]);
                    let (t, c) = if ethertype == crate::packet::ETH_P_IP {
                        (route::ICMP_DEST_UNREACH, route::ICMP_NET_ANO)
                    } else {
                        (route::ICMP6_DST_UNREACH, route::ICMP6_DST_UNREACH_ADMIN)
                    };
                    self.write_icmp_to_device(data, t, c);
                    return false;
                }
                // Packet too big for next hop's PMTU. Only when
                // relaying (clamp_mss + kernel PMTU handle our own
                // outbound). Floors: 590=576+14 (RFC 791),
                // 1294=1280+14 (RFC 8200) — don't claim MTU < 576
                // even if discovery hasn't run.
                //
                // `via_mtu != 0`: don't claim a path MTU before
                // discovery has measured one. `try_fix_mtu` only
                // sets `mtu` once `minmtu >= maxmtu`; until then
                // it's 0, `MAX(0,590)` claims 576, and the kernel
                // caches that per-dst for 10 minutes — any TCP flow
                // in that window is stuck at MSS 536 forever. 3×
                // packets/crypto/syscalls for the same bytes.
                if via_nid != self.myself && via_mtu != 0 {
                    let ethertype = u16::from_be_bytes([data[12], data[13]]);
                    let floor: u16 = if ethertype == crate::packet::ETH_P_IP {
                        590
                    } else {
                        1294
                    };
                    let limit = via_mtu.max(floor);
                    if data.len() > usize::from(limit) {
                        if ethertype == crate::packet::ETH_P_IP {
                            // DF flag (data.len()>590 ⇒ [20] in bounds).
                            let df_set = data[20] & 0x40 != 0;
                            if df_set {
                                // limit-14 = IP-layer MTU. limit≥590
                                // so sub never wraps.
                                self.write_icmp_frag_needed(data, limit - 14);
                            } else {
                                // RFC 791 §2.3: routers MUST fragment.
                                // Rare path (modern OS sets DF on TCP)
                                // but UDP without DF through narrow-
                                // MTU relay needs this.
                                let Some(frags) = crate::fragment::fragment_v4(data, limit) else {
                                    log::debug!(target: "tincd::net",
                                        "fragment_v4: malformed input, dropping");
                                    return false;
                                };
                                // Mirror the normal send path below:
                                // send_sptps_packet + try_tx for PMTU
                                // drive.
                                let n = frags.len();
                                log::debug!(target: "tincd::net",
                                    "Fragmenting packet of {} bytes into \
                                     {n} pieces for {to}", data.len());
                                {
                                    let tunnel = self.tunnels.entry(to_nid).or_default();
                                    for frag in &frags {
                                        tunnel.out_packets += 1;
                                        tunnel.out_bytes += frag.len() as u64;
                                    }
                                }
                                let mut nw = false;
                                for frag in &frags {
                                    nw |= self.send_sptps_packet(to_nid, frag);
                                }
                                nw |= self.try_tx(to_nid, true);
                                return nw;
                            }
                        } else {
                            // v6: no in-transit frag (RFC 8200 §5).
                            self.write_icmp_pkt_too_big(data, u32::from(limit - 14));
                        }
                        return false;
                    }
                }

                if via_options & crate::proto::OPTION_CLAMP_MSS != 0 {
                    let mtu = via_mtu.min(MTU);
                    let _ = mss::clamp(data, mtu);
                }

                // `source != myself` gate: don't decrement on
                // TUN-origin (we ARE the first hop).
                if self.settings.decrement_ttl && from.is_some() {
                    match route::decrement_ttl(data) {
                        TtlResult::Decremented => {}
                        TtlResult::TooShort | TtlResult::DropSilent => {
                            return false;
                        }
                        TtlResult::SendIcmp {
                            icmp_type,
                            icmp_code,
                        } => {
                            self.write_icmp_to_device(data, icmp_type, icmp_code);
                            return false;
                        }
                    }
                }

                // Read inner TOS for the outer UDP socket. Threaded
                // via Daemon.tx_priority. Reset to 0 each packet —
                // priority only ever flows from data through to UDP
                // send. Done here, not at route_packet entry, to stay
                // clear of the dump-traffic agent's route boundary.
                self.tx_priority = if self.settings.priorityinheritance {
                    route::extract_tos(data).unwrap_or(0)
                } else {
                    0
                };

                let len = data.len();
                log::debug!(target: "tincd::net",
                            "Sending packet of {len} bytes to {to}");
                // Counts attempts, not deliveries.
                let tunnel = self.tunnels.entry(to_nid).or_default();
                tunnel.out_packets += 1;
                tunnel.out_bytes += len as u64;

                // try_tx: every forwarded packet drives PMTU
                // discovery one step.
                let mut nw = self.send_sptps_packet(to_nid, data);
                nw |= self.try_tx(to_nid, true);
                nw
            }
            RouteResult::Unreachable {
                icmp_type,
                icmp_code,
            } => {
                // ratelimit(3), keyed on same-second.
                let now_sec = self.timers.now().duration_since(self.started_at).as_secs();
                if self.icmp_ratelimit.should_drop(now_sec, 3) {
                    log::debug!(target: "tincd::net",
                                "route: unreachable (type={icmp_type} \
                                 code={icmp_code}), rate-limited");
                    return false;
                }
                // v4/v6 dispatch on ethertype here (bug audit
                // `deef1268`). data.len() ≥ 14 guaranteed: route()
                // returns TooShort for shorter.
                let ethertype = u16::from_be_bytes([data[12], data[13]]);
                let reply = if ethertype == 0x86DD {
                    // ETH_P_IPV6
                    icmp::build_v6_unreachable(data, icmp_type, icmp_code, None, None)
                } else {
                    icmp::build_v4_unreachable(data, icmp_type, icmp_code, None, None)
                };
                let Some(reply) = reply else {
                    log::debug!(target: "tincd::net",
                                "route: unreachable, ICMP synth failed (short input)");
                    return false;
                };
                log::debug!(target: "tincd::net",
                            "route: unreachable, sending ICMP type={icmp_type} \
                             code={icmp_code} ({} bytes)", reply.len());
                self.write_icmp_reply(reply);
                false
            }
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
                    match route::decrement_ttl(data) {
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

    /// DNS stub TUN intercept (Rust-only). Returns `true` if `data`
    /// was a DNS query for the magic IP and we wrote a reply; the
    /// caller skips `route()` entirely. `false` for non-match (wrong
    /// dst, wrong port, not UDP, ihl!=5) — packet falls through to
    /// normal routing. Ownership stays with the borrow; we read
    /// `data` and write a fresh reply frame.
    ///
    /// Hot-path cost: when the feature is on but the packet isn't
    /// for us, this is ~5 byte compares (`match_v4` early-outs on
    /// the first non-matching field). When off (`self.dns == None`),
    /// the caller's `is_some()` gate skips this call entirely.
    ///
    /// Caller pre-checks `self.dns.is_some()`; the `take()` here
    /// always succeeds. The take/put-back dance avoids the borrow
    /// conflict between `&self.dns` and `device.write(&mut self)`
    /// — same pattern as `device_arena` in `on_device_read`.
    /// `DnsConfig` is two `Option<IpAddr>` + a `String`; the move
    /// is cheap (no realloc, the String's heap buffer stays put).
    fn try_dns_intercept(&mut self, data: &[u8]) -> bool {
        let cfg = self.dns.take().expect("caller gated on is_some()");
        // v4 path. `match_v4` does the full eth+IP+UDP+port check;
        // None means "not for us" — fall through to v6 then route().
        let hit = if let Some(dns_ip) = cfg.dns_addr4
            && let Some((src, sport, dns)) = crate::dns::match_v4(data, &dns_ip)
        {
            let Some(reply) = crate::dns::answer(dns, &cfg, &self.subnets, &self.name) else {
                // Malformed past header recovery (truncated ID, or
                // QR bit set = reflection attempt). Drop silently.
                // NOT route() — it'd Forward{to:myself} (the magic IP
                // is on the TUN), and the kernel would ICMP port-
                // unreachable, leaking that something's there.
                self.dns = Some(cfg);
                return true;
            };
            let mut frame = crate::dns::wrap_v4(data, &reply, &dns_ip, &src, sport);
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
            && let Some((src, sport, dns)) = crate::dns::match_v6(data, &dns_ip)
        {
            let Some(reply) = crate::dns::answer(dns, &cfg, &self.subnets, &self.name) else {
                self.dns = Some(cfg);
                return true;
            };
            let mut frame = crate::dns::wrap_v6(data, &reply, &dns_ip, &src, sport);
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
