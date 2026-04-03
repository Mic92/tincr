#![forbid(unsafe_code)]

#[allow(clippy::wildcard_imports)]
use super::*;

impl Daemon {
    /// `udp_probe_h` (`net_packet.c:170-238`). One PROBE record
    /// arrived. byte[0] == 0 ⇒ request → echo back. byte[0] != 0
    /// ⇒ reply (type 1 or 2) → feed `pmtu.on_probe_reply`.
    pub(super) fn udp_probe_h(&mut self, peer: NodeId, peer_name: &str, body: &[u8]) -> bool {
        if body.is_empty() {
            return false;
        }
        // C `:172-175`: `if(!DATA[0]) { send_udp_probe_reply;
        // return; }`. byte[0]==0 marks a REQUEST.
        if body[0] == 0 {
            log::debug!(target: "tincd::net",
                        "Got UDP probe request {} from {peer_name}",
                        body.len());
            #[allow(clippy::cast_possible_truncation)] // body ≤ MTU
            return self.send_udp_probe_reply(peer, peer_name, body.len() as u16);
        }

        // ─── reply (type 1 or 2) ────────────────────────────────
        // C `:177-182`: type-2 carries the length INSIDE the packet
        // at bytes [1..3]. Type-2 replies are MIN_PROBE_SIZE bytes
        // on the wire regardless of the probed length (saves
        // bandwidth: "yes, your 1400-byte probe arrived" doesn't
        // need a 1400-byte reply).
        #[allow(clippy::cast_possible_truncation)] // body ≤ MTU
        let len: u16 = if body[0] == 2 && body.len() >= 3 {
            u16::from_be_bytes([body[1], body[2]])
        } else {
            body.len() as u16
        };
        log::debug!(target: "tincd::net",
                    "Got type {} UDP probe reply {len} from {peer_name}",
                    body[0]);

        // C `:199-238` is `pmtu.on_probe_reply`. The udp_confirmed
        // bit lives in BOTH `status` (for `dump_nodes` packing)
        // and `pmtu` (the authoritative state machine bit). Mirror.
        let now = self.timers.now();
        let actions = if let Some(p) = self.tunnels.get_mut(&peer).and_then(|t| t.pmtu.as_mut()) {
            p.on_probe_reply(len, now)
        } else {
            // No pmtu state yet (first probe was a request from
            // them, we replied, they replied to OUR keepalive...).
            // Seed it now so we have somewhere to record the floor.
            let tunnel = self.tunnels.entry(peer).or_default();
            let mut p = PmtuState::new(now, MTU);
            let actions = p.on_probe_reply(len, now);
            tunnel.pmtu = Some(p);
            actions
        };
        // Mirror udp_confirmed into status.
        if let Some(t) = self.tunnels.get_mut(&peer) {
            t.status.udp_confirmed = true;
        }
        for a in &actions {
            Self::log_pmtu_action(peer_name, a);
        }
        // C `:213-217` `timeout_del + timeout_add(udp_ping_
        // timeout)`: the per-node UDP-timeout timer. We don't arm
        // it (PMTU is driven inline by `try_tx`/`pmtu.tick()`, not
        // a separate timer); see the BecameUnreachable comment.
        // Nothing to reset.
        false
    }

    /// `send_udp_probe_reply` (`net_packet.c:140-168`). Echo a
    /// probe request back. Type-2 reply (proto ≥17.3): the LENGTH
    /// goes in bytes [1..3]; the wire packet is MIN_PROBE_SIZE.
    /// We're SPTPS-only so peers are always ≥17.3 (`options >> 24
    /// >= 3` is the gate; ours is 7).
    ///
    /// C `:163-165`: `udp_confirmed = true` temporarily so the
    /// reply goes back "the same way it came in" (via
    /// `choose_udp_address` which prefers `udp_addr` when
    /// confirmed). We already stash `udp_addr` from the receive
    /// path BEFORE this is called; `choose_udp_address` reads it
    /// regardless of the bit.
    pub(super) fn send_udp_probe_reply(&mut self, peer: NodeId, peer_name: &str, len: u16) -> bool {
        // C `:148-152`: type-2 = byte[0]=2, bytes[1..3]=htons(len),
        // packet.len = MIN_PROBE_SIZE.
        let mut body = vec![0u8; usize::from(pmtu::MIN_PROBE_SIZE)];
        body[0] = 2;
        body[1..3].copy_from_slice(&len.to_be_bytes());
        // bytes[3..14] stay zero; bytes[14..] would be random in C
        // but with MIN_PROBE_SIZE=18 that's just 4 bytes. Zero is
        // fine — the recipient only reads [0..3].

        log::debug!(target: "tincd::net",
                    "Sending type 2 probe reply length {len} to {peer_name}");

        // C `:165`: `send_udppacket(n, packet)`. The C path goes
        // `send_udppacket` → `send_sptps_packet` (the SPTPS branch
        // at `:817`) → `:691-694` PKT_PROBE detect (zero-ethertype
        // marker) → `sptps_send_record(PKT_PROBE)`. We shortcut
        // straight to the SPTPS send.
        self.send_probe_record(peer, peer_name, &body)
    }

    /// `send_udp_probe_packet` (`net_packet.c:1177-1195`). Build
    /// and send a PROBE request of `len` bytes. byte[0]=0 (request),
    /// bytes[1..14]=zero, bytes[14..len]=random.
    pub(super) fn send_udp_probe(&mut self, peer: NodeId, peer_name: &str, len: u16) -> bool {
        // C `:1185`: `len = MAX(len, MIN_PROBE_SIZE)`. The pmtu
        // module already clamps but be defensive.
        let len = len.max(pmtu::MIN_PROBE_SIZE);
        let mut body = vec![0u8; usize::from(len)];
        // C `:1187-1188`: `memset(DATA, 0, 14); randomize(DATA+14,
        // len-14)`. The first 14 are the synthetic ethernet header
        // slot (probes go through `send_udppacket` which expects
        // a full vpn_packet_t). Our `send_probe_record` sends the
        // body directly; the zero-prefix is just convention.
        if body.len() > 14 {
            OsRng.fill_bytes(&mut body[14..]);
        }
        // body[0] = 0 (request marker) — already zero from vec init.

        log::debug!(target: "tincd::net",
                    "Sending UDP probe length {len} to {peer_name}");
        self.send_probe_record(peer, peer_name, &body)
    }

    /// `sptps_send_record(&n->sptps, PKT_PROBE, data, len)`. The
    /// shared SPTPS-send for both probe requests and replies. The
    /// C `:691-694` zero-ethertype detect is a vestige of the
    /// `vpn_packet_t` shape; we just send the record directly.
    pub(super) fn send_probe_record(&mut self, peer: NodeId, peer_name: &str, body: &[u8]) -> bool {
        let tunnel = self.tunnels.entry(peer).or_default();
        if !tunnel.status.validkey {
            // Can't probe without keys. C `:685` gate.
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
        // Dispatch: one Wire output. Goes via `send_sptps_data`
        // with `record_type = PKT_PROBE`. The relay decision at
        // `:967` always prefers `via` for PROBE (the `type ==
        // PKT_PROBE` term).
        self.dispatch_tunnel_outputs(peer, peer_name, outs)
    }

    /// `try_tx_sptps` (`net_packet.c:1473-1513`). The "improve
    /// the tunnel" tick. Called from TWO places:
    ///
    /// 1. `on_ping_tick` (`net.c:250`): once per active conn,
    ///    `mtu=false`. Keeps UDP alive (NAT timeouts).
    /// 2. `route_packet` Forward arm (`net_packet.c:1590`): once
    ///    per forwarded packet, `mtu=true`. Drives PMTU discovery.
    ///
    /// Chain: `try_sptps` (REQ_KEY if needed) → via deref →
    /// `try_udp` (probe send) → `try_mtu` (PMTU tick).
    ///
    /// Via-recursion (`:1490-1497`): if `via != target`, recurse on
    /// the relay instead. Finite: graph is acyclic in the via-chain
    /// sense (sssp tree); max depth = graph diameter (≤5 in
    /// practice).
    #[allow(clippy::too_many_lines)] // C `try_tx_sptps` is 41 LOC
    // but inlines via try_sptps/try_udp/try_mtu callbacks; we
    // unfold them. The match arms are the C call chain.
    pub(super) fn try_tx(&mut self, target: NodeId, mtu: bool) -> bool {
        // C `:1477-1479`: `if(n->connection && (myself|n)->options
        // & OPTION_TCPONLY) return`. The `n->connection` check
        // means "we have a DIRECT meta connection to this node"
        // (not just graph-reachable). Map: `nodes[name].conn` is
        // Some. The options-OR is the same shape as `send_sptps_
        // data`'s tcponly check. Early-return true: TCP is fine,
        // don't bother trying UDP.
        {
            let target_options = self
                .last_routes
                .get(target.0 as usize)
                .and_then(Option::as_ref)
                .map_or(0, |r| r.options);
            let tcponly =
                (self.myself_options | target_options) & crate::proto::OPTION_TCPONLY != 0;
            if tcponly {
                let has_direct_conn = self
                    .graph
                    .node(target)
                    .and_then(|n| self.nodes.get(n.name.as_str()))
                    .is_some_and(|ns| ns.conn.is_some());
                if has_direct_conn {
                    return true;
                }
            }
        }

        // ─── try_sptps (`:1483` → `:1156-1173`) ──────────────────
        // `if(!validkey) { if(!waitingforkey) send_req_key; else
        // if(last_req_key+10 < now) restart }`. The `send_sptps_
        // packet` path already does the FIRST send; this catches
        // the 10-second-timeout restart.
        let now = self.timers.now();
        {
            let tunnel = self.tunnels.entry(target).or_default();
            if !tunnel.status.validkey {
                // Can't UDP without keys. Kick the handshake if
                // needed; nothing more to do.
                if !tunnel.status.waitingforkey {
                    return self.send_req_key(target);
                }
                // C `:1167-1173`: 10-second debounce.
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

        // ─── via deref (`:1487-1498`) ────────────────────────────
        // `via = (n->via == myself) ? n->nexthop : n->via; if(via
        // != n) { try_tx(via, mtu); return; }`. The static-relay
        // recursion. Read `last_routes`, copy out the NodeId, drop
        // the borrow, THEN recurse (same two-phase as `forward_
        // request`). Invariant: `last_routes` is current for any
        // reachable target (sssp populates it; we only call try_tx
        // on reachable nodes).
        {
            let route = self
                .last_routes
                .get(target.0 as usize)
                .and_then(Option::as_ref);
            // Unreachable target: pretend direct (no recursion).
            // The C would deref a NULL `n->via`; we're safer.
            let via_nid = route.map_or(target, |r| {
                if r.via == self.myself {
                    r.nexthop
                } else {
                    r.via
                }
            });
            if via_nid != target {
                // C `:1491-1497`: `if((via->options >> 24) < 4)
                // return; try_tx(via, mtu); return`. The `< 4`
                // gate: protocol minor 4 introduced relay support.
                // Our `myself_options_default` is `7 << 24` so
                // Rust↔Rust is always ≥4; gate matters for old-C-
                // tincd interop.
                let via_options = self
                    .last_routes
                    .get(via_nid.0 as usize)
                    .and_then(Option::as_ref)
                    .map_or(0, |r| r.options);
                if (via_options >> 24) < 4 {
                    return false;
                }
                // RECURSE. Finite: sssp tree (via-chain is acyclic).
                return self.try_tx(via_nid, mtu);
            }
        }

        let target_name = self
            .graph
            .node(target)
            .map_or("<gone>", |n| n.name.as_str())
            .to_owned();

        // ─── try_udp (`:1502` → `:1200-1246`) ────────────────────
        let mut nw = self.try_udp(target, &target_name, now);

        // ─── try_mtu (`:1505-1509`) ──────────────────────────────
        // C `:1358-1364`: `if(udp_discovery && !udp_confirmed) {
        // reset; return }`. Don't probe MTU until UDP works.
        // C `:1348-1356`: `if(!(options & OPTION_PMTU_DISCOVERY))`
        // gate. Default-on (`myself_options_default`).
        if mtu {
            let tunnel = self.tunnels.entry(target).or_default();
            // Seed pmtu state on first call. C `node.c` xzalloc;
            // our `PmtuState::new` needs `now`.
            // STUB(chunk-9c): `choose_initial_maxmtu` getsockopt.
            // The `MTU` fallback works (the C does too on platforms
            // without `IP_MTU`); getsockopt is an optimization
            // (skips the first few too-big probes).
            let p = tunnel.pmtu.get_or_insert_with(|| PmtuState::new(now, MTU));
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

        // C `:1511-1513`: nexthop dynamic-relay recursion. `if(
        // !udp_confirmed && n != nexthop && (nexthop->options >> 24)
        // >= 4) try_tx(nexthop, mtu)`. While we try direct UDP, also
        // warm the relay's tunnel so the b64-TCP fallback in
        // `send_sptps_data` can reach. Same two-phase borrow shape.
        let udp_confirmed = self
            .tunnels
            .get(&target)
            .and_then(|t| t.pmtu.as_ref())
            .is_some_and(|p| p.udp_confirmed);
        if !udp_confirmed {
            let nexthop = self
                .last_routes
                .get(target.0 as usize)
                .and_then(Option::as_ref)
                .map(|r| r.nexthop);
            if let Some(nh) = nexthop {
                if nh != target {
                    let nh_options = self
                        .last_routes
                        .get(nh.0 as usize)
                        .and_then(Option::as_ref)
                        .map_or(0, |r| r.options);
                    if (nh_options >> 24) >= 4 {
                        nw |= self.try_tx(nh, mtu);
                    }
                }
            }
        }

        nw
    }

    /// `try_udp` (`net_packet.c:1200-1246`). Probe-request send
    /// + gratuitous-reply keepalive. Gated on `udp_ping_sent`
    ///   elapsed: 2s when not confirmed (aggressive discovery), 10s
    ///   when confirmed (NAT keepalive).
    pub(super) fn try_udp(&mut self, target: NodeId, target_name: &str, now: Instant) -> bool {
        // C `:1202`: `if(!udp_discovery) return`. We don't have
        // the config knob yet; default-on.

        let tunnel = self.tunnels.entry(target).or_default();
        let udp_confirmed = tunnel.pmtu.as_ref().is_some_and(|p| p.udp_confirmed);

        // ─── :1207-1223: gratuitous reply keepalive ─────────────
        // C `:1207`: `if((options >> 24) >= 3 && udp_confirmed)`.
        // SPTPS-only ⇒ always ≥3. Send a type-2 reply at the
        // largest recently-seen size; it tells the PEER "your
        // PMTU is still good" (their `on_probe_reply` rewinds
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

        // ─── :1227-1245: probe request ───────────────────────────
        // C `:1231-1233`: `interval = udp_confirmed ? keepalive
        // : interval`. Seed pmtu if needed (we read `udp_ping_sent`
        // from it).
        let tunnel = self.tunnels.entry(target).or_default();
        let p = tunnel.pmtu.get_or_insert_with(|| PmtuState::new(now, MTU));
        let interval = if p.udp_confirmed {
            self.settings.udp_discovery_keepalive_interval
        } else {
            self.settings.udp_discovery_interval
        };
        let elapsed = now.duration_since(p.udp_ping_sent);
        if elapsed >= Duration::from_secs(u64::from(interval)) {
            // C `:1236-1238`: `udp_ping_sent = now; ping_sent =
            // true; send_udp_probe_packet(n, MIN_PROBE_SIZE)`.
            p.udp_ping_sent = now;
            p.ping_sent = true;
            nw |= self.send_udp_probe(target, target_name, pmtu::MIN_PROBE_SIZE);
            // STUB(chunk-10-local): `:1240-1245` `if(localdiscovery
            // && !udp_confirmed)` send_locally probe.
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

    /// `to->nexthop->connection`. The meta connection for routing
    /// REQ_KEY/ANS_KEY toward `to`. With direct neighbors, `nexthop
    /// == to` so it's just `nodes[to_name].conn`. Transitives go
    /// via the first hop's connection.
    pub(super) fn conn_for_nexthop(&self, to_nid: NodeId) -> Option<ConnId> {
        // `last_routes[to_nid]` has `nexthop`. If unreachable
        // (`None`), no path.
        let nexthop = self
            .last_routes
            .get(to_nid.0 as usize)
            .and_then(Option::as_ref)?
            .nexthop;
        // Reverse-lookup nexthop's name (graph slot → name string).
        let nexthop_name = self.graph.node(nexthop)?.name.as_str();
        // `NodeState.conn` for the nexthop.
        self.nodes.get(nexthop_name)?.conn
    }

    /// `Route` lookup with bounds + `Option::as_ref` flatten.
    /// `None` for unreachable / never-routed. Reads the cached
    /// `last_routes` (NOT a fresh sssp).
    pub(super) fn route_of(&self, nid: NodeId) -> Option<&Route> {
        self.last_routes.get(nid.0 as usize)?.as_ref()
    }

    /// `n->{min,max}mtu` snapshot for `udp_info::adjust_mtu_for_
    /// send`. `None` if no PMTU state seeded yet.
    pub(super) fn pmtu_snapshot(&self, nid: NodeId) -> Option<PmtuSnapshot> {
        self.tunnels.get(&nid)?.pmtu.as_ref().map(|p| PmtuSnapshot {
            minmtu: p.minmtu,
            maxmtu: p.maxmtu,
        })
    }

    // ─── load_all_nodes (`net_setup.c:161-217`) ─────────────────

    /// Walk `confbase/hosts/`, add every valid-named file to the
    /// graph, populate `has_address` for files with `Address =`.
    /// C `net_setup.c:161-217`. Called from `setup()` (`:1057`) and
    /// `reload_configuration()` (`net.c:370`).
    ///
    /// **The `lookup_or_add_node` decision** (`:186-189`): the C
    /// adds EVERY hosts/-file name to `node_tree`, even ones with
    /// no edge to us. We match: a node with `has_address && !
    /// reachable` is exactly autoconnect's eligible-to-dial set
    /// (`autoconnect.c:34`). Without the graph add, the node would
    /// be invisible to `decide()` (which walks `node_ids`, not
    /// `has_address`). The cost is graph entries that stay
    /// `reachable=false` until SOMETHING connects them — harmless,
    /// `dump nodes` shows them as unreachable which is correct.
    ///
    /// `strictsubnets` branch (`:192-208`): STUB(chunk-12-switch).
    /// Reads each file's `Subnet =` lines into the subnet tree.
    /// We don't have strictsubnets yet.
    pub(super) fn load_all_nodes(&mut self) {
        let hosts_dir = self.confbase.join("hosts");
        let dir = match std::fs::read_dir(&hosts_dir) {
            Ok(d) => d,
            Err(e) => {
                // C `:170-172`: `"Could not open %s: %s"`. Non-fatal.
                log::error!(target: "tincd",
                            "Could not open {}: {e}", hosts_dir.display());
                return;
            }
        };

        // Reload re-walks; clear so removed-Address files lose the
        // bit. The C doesn't clear (it only sets, `:211`), so a
        // file that HAD `Address` and then had it removed keeps
        // the bit until restart. We diverge: clearing is the
        // less-surprising behavior on SIGHUP, and there's no
        // observable C contract for the stale-bit case (nothing
        // reads has_address EXCEPT autoconnect, and autoconnect
        // dialing a node with no Address just hits the addr-cache-
        // empty path → retry_outgoing → harmless backoff).
        self.has_address.clear();

        for ent in dir.flatten() {
            let Some(fname) = ent.file_name().to_str().map(str::to_owned) else {
                continue; // non-UTF-8 filename — can't be a node name
            };
            // C `:176`: `if(!check_id(ent->d_name)) continue`.
            // Filters `.` `..` and editor swap files for free.
            if !tinc_proto::check_id(&fname) {
                continue;
            }

            // C `:186-189`: `n = lookup_node; if(!n) { new_node;
            // node_add; }`. Our fused helper.
            self.lookup_or_add_node(&fname);

            // C `:183-184`: `read_config_options(..., d_name);
            // read_host_config(..., d_name)`. The C reads BOTH the
            // tinc.conf-tagged options for this node AND its hosts/
            // file. We only need the latter (the only thing read
            // is `Address`, which is HOST-tagged).
            let Ok(entries) = tinc_conf::parse_file(ent.path()) else {
                continue; // unreadable file — skip silently (C does too)
            };
            let mut cfg = tinc_conf::Config::default();
            cfg.merge(entries);

            // C `:210-212`: `if(lookup_config("Address")) n->
            // status.has_address = true`.
            if cfg.lookup("Address").next().is_some() {
                self.has_address.insert(fname);
            }
        }
    }

    // ─── autoconnect (`autoconnect.c`) ──────────────────────────

    /// Build the snapshot, call `autoconnect::decide`. Three-phase
    /// borrow: read `&self` to build snapshots, call `decide` (no
    /// borrow), caller does `&mut self` to execute.
    ///
    /// `nodes` ordering: sorted by name. C walks `node_tree` (splay,
    /// strcmp-ordered). `connect_to_unreachable` indexes by position
    /// (`autoconnect.c:86`: `prng(count)` then walk to that index);
    /// matching the C's iteration order makes the per-tick random
    /// pick reproducible against C with the same RNG seed. Our RNG
    /// is OsRng so this doesn't matter for production, but it's the
    /// least-surprising shape.
    pub(super) fn decide_autoconnect(&self) -> AutoAction {
        // Sort node names so iteration order matches the C splay
        // (strcmp). `node_ids` HashMap iteration is random.
        let mut names: Vec<&str> = self.node_ids.keys().map(String::as_str).collect();
        names.sort_unstable();

        let nodes: Vec<NodeSnapshot> = names
            .iter()
            .filter_map(|&name| {
                let &nid = self.node_ids.get(name)?;
                let gnode = self.graph.node(nid)?;
                // C `n->edge_tree.count`: outgoing edges only (each
                // direction is a separate `edge_t`). `node_edges()`
                // returns the outgoing-edge slice.
                let edge_count = self.graph.node_edges(nid).len();
                // C `n->connection != NULL`: directly connected via
                // ANY meta conn (in or out). `NodeState.conn` is
                // exactly that — set in `on_ack`, cleared in
                // `terminate`. Nodes without a NodeState (transitive,
                // hosts/-only) are not directly connected.
                let directly_connected = self
                    .nodes
                    .get(name)
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

        // C `:121-122`: `c->edge && c->outgoing`. Past-ACK
        // (`active`) AND we initiated. Names of nodes, not ConnIds:
        // `decide` matches by name.
        let active_outgoing_conns: Vec<String> = self
            .conns
            .values()
            .filter(|c| c.active && c.outgoing.is_some())
            .map(|c| c.name.clone())
            .collect();

        // C `:152-163`: walk `outgoing_list`, skip ones with a
        // matching `c->outgoing` (i.e. ones with a live conn). The
        // pending set is "Outgoing slot exists, no conn serves it
        // — the retry timer is waiting". Match by `c.outgoing` →
        // `OutgoingId`. A conn that's STILL connecting (pre-ACK,
        // not active yet) DOES count as serving the outgoing — the
        // C `:155` check is just `c->outgoing == outgoing`, no
        // `c->edge` gate.
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
    /// pure decision. C `autoconnect.c`: each branch's tail.
    pub(super) fn execute_auto_action(&mut self, action: AutoAction) {
        match action {
            AutoAction::Noop => {}
            AutoAction::Connect { name } => {
                // C `autoconnect.c:67-71` (and `:106-110`): build
                // `outgoing_t`, `setup_outgoing_connection`. Same
                // path as setup()'s ConnectTo loop and reload's
                // to_add loop. Copy-paste because the field set is
                // small (3 lines) and factoring would obscure the
                // C correspondence at each site.
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
                // C `:143-146`: `list_delete(&outgoing_list,
                // c->outgoing); c->outgoing = NULL; terminate_
                // connection(c, c->edge)`. Order matters: clear
                // `c->outgoing` BEFORE terminate so terminate's
                // retry-on-disconnect path doesn't fire (we're
                // CHOOSING to drop this; don't reconnect).
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
                    // C `:143`: `list_delete`. Drop slot + timer.
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
                // C `:165-166`: `list_delete(&outgoing_list,
                // outgoing)`. Just drop the slot; no conn to kill
                // (that's the definition of "pending").
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

    // ─── UDP_INFO / MTU_INFO send (`protocol_misc.c:155-330`) ───

    /// `send_udp_info(myself, to)` (`protocol_misc.c:155-215`). The
    /// gates live in `udp_info::should_send_udp_info`; this gathers
    /// the daemon state, calls the gate, builds the wire message,
    /// queues it on `to->nexthop->connection`.
    ///
    /// `from_is_myself`: ALWAYS true for the daemon's call sites
    /// (every C `send_udp_info` call is `(myself, ...)`). The
    /// forwarding case (`from != myself`) is handled by
    /// `on_udp_info` re-calling this with the parsed `from`/`to`.
    /// We pass it explicitly so the forward path can share the
    /// gate logic.
    ///
    /// Returns the io_set signal (queued bytes on a meta conn).
    pub(super) fn send_udp_info(
        &mut self,
        to_nid: NodeId,
        to_name: &str,
        from_is_myself: bool,
    ) -> bool {
        // C `:158`: `to = (to->via == myself) ? to->nexthop :
        // to->via`. Static-relay deref: UDP_INFO terminates at
        // the static relay (it's the last node that sees `from`'s
        // UDP traffic directly). `should_send_udp_info` doesn't
        // do this deref (it's pure); we do it here. The ORIGINAL
        // `to`'s options feed `to_options`; the DEREFFED `to`'s
        // route feeds `nexthop_options` and `to_is_myself`.
        let Some(orig_route) = self.route_of(to_nid) else {
            // C `:160-163`: `if(to == NULL)`. Can happen if `to`
            // is unreachable (no route). C logs ERR and returns
            // false (terminates conn); we just skip — the call
            // sites are all opportunistic hints, not protocol-
            // mandatory sends.
            return false;
        };
        let to_options_orig = orig_route.options;
        let dereffed = if orig_route.via == self.myself {
            orig_route.nexthop
        } else {
            orig_route.via
        };

        // C `:170`: `if(to == myself) return true`. Now checked
        // against the DEREFFED to. Chain terminates here.
        let to_is_myself = dereffed == self.myself;
        let to_reachable = self.graph.node(dereffed).is_some_and(|n| n.reachable);
        let to_directly_connected = self
            .graph
            .node(dereffed)
            .and_then(|n| self.nodes.get(&n.name))
            .and_then(|ns| ns.conn)
            .is_some();
        // `to->nexthop->options`: the dereffed-to's nexthop. With
        // direct neighbors, `dereffed.nexthop == dereffed` so
        // these are the same. Read from `last_routes`.
        let nexthop_options = self
            .route_of(dereffed)
            .map_or(0, |r| self.route_of(r.nexthop).map_or(0, |nr| nr.options));

        // `from`'s options: when `from == myself`, it's our own.
        // When forwarding, the `from` node's route options.
        let from_options = if from_is_myself {
            self.myself_options
        } else {
            self.route_of(to_nid).map_or(0, |r| r.options)
        };

        let now = self.timers.now();
        let last_sent = self.tunnels.get(&dereffed).and_then(|t| t.udp_info_sent);
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

        // C `:199-204`: build the address. When `from == myself`,
        // the C uses `to->nexthop->connection->edge->local_address`
        // — "our local address as seen by the next hop". The first
        // hop IGNORES this (the address is replaced with what THEY
        // observe), so the C comment says "the address we use is
        // irrelevant". We send `unspec`: simpler, same semantics.
        // When forwarding, we send `to`'s currently-known addr
        // (`tunnel.udp_addr`) — that's the relay's observation.
        let (addr, port) = if from_is_myself {
            (
                AddrStr::new(AddrStr::UNSPEC).expect("unspec is valid"),
                AddrStr::new(AddrStr::UNSPEC).expect("unspec is valid"),
            )
        } else {
            // Forward case: `from->address` (the C `:203`
            // `&from->address`). Our `tunnel.udp_addr` for the
            // FROM node (NOT `to`!). The caller (`on_udp_info`)
            // passes the from-nid via `to_nid` … wait, no. The
            // forward case calls `send_udp_info_forward` below.
            // THIS function's non-myself case is dead — keep it
            // unspec for safety, the forward path is separate.
            (
                AddrStr::new(AddrStr::UNSPEC).expect("unspec is valid"),
                AddrStr::new(AddrStr::UNSPEC).expect("unspec is valid"),
            )
        };

        // C `:206`: `send_request(to->nexthop->connection, ...)`.
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

        // C `:211`: `if(from == myself) to->udp_info_sent = now`.
        if from_is_myself {
            self.tunnels.entry(dereffed).or_default().udp_info_sent = Some(now);
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

        // Same `:158` deref as the originate path.
        let Some(orig_route) = self.route_of(to_nid) else {
            return false;
        };
        let to_options_orig = orig_route.options;
        let dereffed = if orig_route.via == self.myself {
            orig_route.nexthop
        } else {
            orig_route.via
        };

        let to_is_myself = dereffed == self.myself;
        let to_reachable = self.graph.node(dereffed).is_some_and(|n| n.reachable);
        // `:179` `to->connection` check is gated on `from ==
        // myself`. Forwarding skips it. Pass false (irrelevant).
        let from_options = self.route_of(from_nid).map_or(0, |r| r.options);
        let nexthop_options = self
            .route_of(dereffed)
            .map_or(0, |r| self.route_of(r.nexthop).map_or(0, |nr| nr.options));

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

        // C `:203`: `&from->address`. Our observation of `from`'s
        // UDP address. If we don't have one, send unspec (same as
        // C `AF_UNSPEC` → `sockaddr2str` → `"unspec"`).
        let (addr, port) = self
            .tunnels
            .get(&from_nid)
            .and_then(|t| t.udp_addr)
            .map_or_else(
                || {
                    (
                        AddrStr::new(AddrStr::UNSPEC).expect("const"),
                        AddrStr::new(AddrStr::UNSPEC).expect("const"),
                    )
                },
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

    /// `send_mtu_info(from, to, mtu)` (`protocol_misc.c:272-330`).
    /// Gates → adjust_mtu_for_send → queue on nexthop conn.
    ///
    /// Unlike UDP_INFO, there's no `:158` static-relay deref — `to`
    /// is `to`. The nexthop is `to->nexthop` directly.
    pub(super) fn send_mtu_info(
        &mut self,
        to_nid: NodeId,
        to_name: &str,
        mtu: i32,
        from_is_myself: bool,
    ) -> bool {
        self.send_mtu_info_from(self.myself, to_nid, to_name, mtu, from_is_myself)
    }

    /// `send_mtu_info` with explicit `from` for the forward path.
    /// `from_is_myself` is still passed separately because the gate
    /// logic keys on it independently of `from_nid` (debounce +
    /// directly-connected checks).
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
        let to_directly_connected = self.nodes.get(to_name).and_then(|ns| ns.conn).is_some();
        // `to->nexthop->options`: read via the route.
        let nexthop_options = self
            .route_of(to_nid)
            .map_or(0, |r| self.route_of(r.nexthop).map_or(0, |nr| nr.options));

        let now = self.timers.now();
        let last_sent = self.tunnels.get(&to_nid).and_then(|t| t.mtu_info_sent);
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

        // C `:305-320`: adjust the MTU based on what we know about
        // the path to `from`. `from->via == myself`: route to
        // `from` has no static relay (we ARE direct or there's only
        // dynamic relays). `via`: the C derefs `(from->via ==
        // myself) ? from->nexthop : from->via` at `:305`.
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

        // C `:323`: `if(from == myself) to->mtu_info_sent = now`.
        if from_is_myself {
            self.tunnels.entry(to_nid).or_default().mtu_info_sent = Some(now);
        }

        // C `:328`: `send_request(to->nexthop->connection, ...)`.
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

    // ─── UDP_INFO / MTU_INFO receive (`protocol_misc.c:217-376`) ─

    /// `udp_info_h` (`protocol_misc.c:217-268`). Parse, build the
    /// `FromState` snapshot, call `udp_info::on_receive_udp_info`,
    /// dispatch the action.
    ///
    /// Returns `Err` only on parse failure (C `:226` `return false`
    /// → conn teardown). All semantic drops (`UnknownNode`,
    /// `DroppedPastRelay`) are `Ok(false)` (C `return true`).
    pub(super) fn on_udp_info(
        &mut self,
        from_conn: ConnId,
        body: &[u8],
    ) -> Result<bool, DispatchError> {
        let body_str = std::str::from_utf8(body)
            .map_err(|_| DispatchError::BadKey("non-UTF-8 UDP_INFO".into()))?;
        let parsed = UdpInfo::parse(body_str)
            .map_err(|_| DispatchError::BadKey("UDP_INFO parse failed".into()))?;

        let conn_name = self
            .conns
            .get(from_conn)
            .map_or("<gone>", |c| c.name.as_str())
            .to_owned();

        // Build `FromState`. `None` → `lookup_node(from)` failed.
        let from_nid = self.node_ids.get(&parsed.from).copied();
        let from_state = from_nid.map(|nid| {
            let directly_connected = self
                .nodes
                .get(&parsed.from)
                .and_then(|ns| ns.conn)
                .is_some();
            let udp_confirmed = self
                .tunnels
                .get(&nid)
                .is_some_and(|t| t.status.udp_confirmed);
            // `from->via == from`: route to `from` has `via ==
            // from`. With direct routes, `via == from` always. The
            // "wandered past static relay" case has `via !=` from.
            let via_is_self = self.route_of(nid).is_some_and(|r| r.via == nid);
            FromState {
                directly_connected,
                udp_confirmed,
                via_is_self,
            }
        });
        let to_nid = self.node_ids.get(&parsed.to).copied();
        let current_from_addr =
            from_nid.and_then(|nid| self.tunnels.get(&nid).and_then(|t| t.udp_addr));

        match udp_info::on_receive_udp_info(
            &parsed,
            from_state,
            to_nid.is_some(),
            current_from_addr,
        ) {
            UdpInfoAction::UnknownNode => {
                // C `:238-240` / `:261-263`: log, return true.
                log::error!(target: "tincd::proto",
                            "Got UDP_INFO from {conn_name} for unknown node \
                             {} → {}", parsed.from, parsed.to);
                Ok(false)
            }
            UdpInfoAction::DroppedPastRelay => {
                // C `:247-249`: warning, return true.
                log::warn!(target: "tincd::proto",
                           "Got UDP_INFO from {conn_name} for {} which we \
                            can't reach directly", parsed.from);
                Ok(false)
            }
            UdpInfoAction::UpdateAndForward { new_addr } => {
                // C `:255`: `update_node_udp(from, &from_addr)`.
                // For us that's just `tunnel.udp_addr = Some(addr)`
                // — see the BecameReachable comment for why we
                // don't have `node_udp_tree`.
                let from_nid = from_nid.expect("UpdateAndForward implies from exists");
                log::debug!(target: "tincd::proto",
                            "UDP_INFO from {conn_name}: learned {} at {new_addr}",
                            parsed.from);
                self.tunnels.entry(from_nid).or_default().udp_addr = Some(new_addr);
                // C `:265`: `return send_udp_info(from, to)`.
                let to_nid = to_nid.expect("UpdateAndForward implies to exists");
                Ok(self.send_udp_info_forward(from_nid, to_nid))
            }
            UdpInfoAction::Forward => {
                // C `:265` without `:255`. No update; just forward.
                let from_nid = from_nid.expect("Forward implies from exists");
                let to_nid = to_nid.expect("Forward implies to exists");
                Ok(self.send_udp_info_forward(from_nid, to_nid))
            }
        }
    }

    /// `mtu_info_h` (`protocol_misc.c:332-376`). Parse, snapshot,
    /// `udp_info::on_receive_mtu_info`, dispatch.
    ///
    /// `Malformed` (`:345` `mtu < 512`) returns `Err` → conn
    /// teardown. Everything else is `Ok`.
    pub(super) fn on_mtu_info(
        &mut self,
        from_conn: ConnId,
        body: &[u8],
    ) -> Result<bool, DispatchError> {
        let body_str = std::str::from_utf8(body)
            .map_err(|_| DispatchError::BadKey("non-UTF-8 MTU_INFO".into()))?;
        let parsed = MtuInfo::parse(body_str)
            .map_err(|_| DispatchError::BadKey("MTU_INFO parse failed".into()))?;

        let conn_name = self
            .conns
            .get(from_conn)
            .map_or("<gone>", |c| c.name.as_str())
            .to_owned();

        let from_nid = self.node_ids.get(&parsed.from).copied();
        let from_mtu = from_nid.map(|nid| {
            // `None` if no tunnel — the C reads `from->mtu` etc.
            // which are xzalloc'd to 0. Our helpers return the
            // same defaults; supply them.
            let t = self.tunnels.get(&nid);
            FromMtuState {
                mtu: t.map_or(0, TunnelState::mtu),
                minmtu: t.map_or(0, TunnelState::minmtu),
                maxmtu: t.map_or(MTU, TunnelState::maxmtu),
            }
        });
        let to_nid = self.node_ids.get(&parsed.to).copied();

        match udp_info::on_receive_mtu_info(&parsed, from_mtu, to_nid.is_some()) {
            MtuInfoAction::Malformed => {
                // C `:345-348`: `return false`. Conn-fatal.
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
            MtuInfoAction::ClampAndForward { new_mtu } => {
                // C `:369`: `from->mtu = mtu`. Set the PROVISIONAL
                // mtu (the discovered one will overwrite when
                // probing converges). Write to `pmtu.mtu` if
                // seeded; otherwise the helper-default (`MTU`) is
                // what `dump_nodes` reads, and the next `try_tx`
                // seed will start from `MTU` regardless. We write
                // it anyway for the seeded case.
                let from_nid = from_nid.expect("ClampAndForward implies from exists");
                log::debug!(target: "tincd::proto",
                            "Using provisional MTU {new_mtu} for {}", parsed.from);
                if let Some(p) = self
                    .tunnels
                    .get_mut(&from_nid)
                    .and_then(|t| t.pmtu.as_mut())
                {
                    p.mtu = new_mtu;
                }
                // C `:375`: `return send_mtu_info(from, to, mtu)`.
                let to_nid = to_nid.expect("ClampAndForward implies to exists");
                Ok(
                    self.send_mtu_info_from(
                        from_nid,
                        to_nid,
                        &parsed.to,
                        i32::from(new_mtu),
                        false,
                    ),
                )
            }
            MtuInfoAction::Forward => {
                let from_nid = from_nid.expect("Forward implies from exists");
                let to_nid = to_nid.expect("Forward implies to exists");
                // Forward with the (clamped) received mtu. The
                // `adjust_mtu_for_send` in `send_mtu_info_from`
                // may tighten it further based on OUR knowledge.
                let mtu = parsed.mtu.min(udp_info::MTU_MAX);
                Ok(self.send_mtu_info_from(from_nid, to_nid, &parsed.to, mtu, false))
            }
        }
    }

    /// `choose_udp_address` (`net_packet.c:744-800`), abridged.
    /// Prefer the confirmed address; fall back to the edge address
    /// from `on_ack` (the meta-conn peer addr with port rewritten
    /// to their UDP port).
    pub(super) fn choose_udp_address(&self, to_nid: NodeId, to_name: &str) -> Option<SocketAddr> {
        // C `:746-751`: `*sa = &n->address; if(udp_confirmed)
        // return`. Our `udp_addr` is `n->address`.
        if let Some(t) = self.tunnels.get(&to_nid) {
            if let Some(addr) = t.udp_addr {
                return Some(addr);
            }
        }
        // C `:765-781`: pick a random edge's `reverse->address`.
        // For chunk 7: just use `NodeState.edge_addr` (which IS
        // the same thing for direct neighbors — the addr from the
        // peer's ACK with port set to their UDP port).
        self.nodes.get(to_name)?.edge_addr
    }

    /// io_set ReadWrite for ANY connection that has a nonempty
    /// outbuf. Device-read / udp-recv paths can queue handshake
    /// records on a meta-conn but don't have a `ConnId` in scope
    /// to set io_set on. Sweep all conns. Per-packet hot path…
    /// but `conns.len()` is tiny (one per direct peer + control).
    /// STUB(chunk-11-perf): track which ConnIds were touched, set those.
    pub(super) fn maybe_set_write_any(&mut self) {
        let dirty: Vec<ConnId> = self
            .conns
            .iter()
            .filter(|(_, c)| !c.outbuf.is_empty())
            .map(|(id, _)| id)
            .collect();
        for id in dirty {
            if let Some(&io_id) = self.conn_io.get(id) {
                if let Err(e) = self.ev.set(io_id, Io::ReadWrite) {
                    log::error!(target: "tincd::conn",
                                "io_set failed for {id:?}: {e}");
                    self.terminate(id);
                }
            }
        }
    }
}
