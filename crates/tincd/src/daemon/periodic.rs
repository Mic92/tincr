#![forbid(unsafe_code)]

#[allow(clippy::wildcard_imports)]
use super::*;

impl Daemon {
    /// `timeout_handler` (`net.c:180-266`). Dead-conn sweep + ping.
    ///
    /// Per-conn cases: `:219` skip control; `:236-247` pre-ACK
    /// timeout (handshake stalled); `:253-257` PING sent but no
    /// PONG; `:260-262` idle → send PING.
    ///
    /// Laptop-suspend detector (`:189-213`): timer skipped >1min →
    /// daemon was asleep → peers dropped us → force-close all
    /// (sending into stale SPTPS contexts is just noise).
    #[allow(clippy::too_many_lines)] // C `timeout_handler` is 86 LOC
    pub(super) fn on_ping_tick(&mut self) {
        let now = self.timers.now();

        // :189-213 laptop-suspend detection. Saturating sub:
        // clock-goes-backwards (NTP) reads as zero (safe).
        let sleep_time = now.saturating_duration_since(self.last_periodic_run_time);
        let threshold = Duration::from_secs(u64::from(self.settings.udp_discovery_timeout) * 2);
        let close_all_connections = sleep_time > threshold;
        if close_all_connections {
            log::error!(target: "tincd",
                        "Awaking from dead after {} seconds of sleep",
                        sleep_time.as_secs());
        }
        self.last_periodic_run_time = now; // :215

        let pingtimeout = Duration::from_secs(u64::from(self.settings.pingtimeout));
        let pinginterval = Duration::from_secs(u64::from(self.settings.pinginterval));

        // terminate() mutates conns; collect ids first.
        let ids: Vec<ConnId> = self.conns.keys().collect();
        let mut nw = false;
        for id in ids {
            let Some(conn) = self.conns.get(id) else {
                continue; // earlier terminate in this sweep
            };

            // :219-221
            if conn.control {
                continue;
            }

            // :224-228
            if close_all_connections {
                log::error!(target: "tincd",
                            "Forcing connection close after sleep time {} ({})",
                            conn.name, conn.hostname);
                // C: terminate_connection(c, c->edge). c->edge!=NULL
                // ≡ conn.active; terminate() keys DEL_EDGE on it.
                self.terminate(id);
                continue;
            }

            // :231-233: not yet stale
            let stale = now.saturating_duration_since(conn.last_ping_time);
            if stale <= pingtimeout {
                continue;
            }

            // :236-247: pre-ACK timeout
            if !conn.active {
                if conn.connecting {
                    log::warn!(target: "tincd::conn",
                               "Timeout while connecting to {} ({})",
                               conn.name, conn.hostname);
                } else {
                    // C :240-241 also sets c->status.tarpit. Our
                    // Tarpit is accept-side only; harmless (auth-
                    // timeout is benign, accept-side covers spam).
                    log::warn!(target: "tincd::conn",
                               "Timeout from {} ({}) during authentication",
                               conn.name, conn.hostname);
                }
                self.terminate(id);
                continue;
            }

            // :250 try_tx(c->node, false). UDP keepalive (no PMTU).
            //
            // Gate on validkey: C try_tx fires for ALL direct
            // neighbors here, but unconditional REQ_KEY races with
            // gossip during mesh formation. Per-packet try_tx (in
            // route_packet) handles the initial handshake instead.
            let try_nid = self
                .node_ids
                .get(&conn.name)
                .copied()
                .filter(|nid| self.tunnels.get(nid).is_some_and(|t| t.status.validkey));
            let pinged = conn.pinged;
            let conn_name = conn.name.clone();
            let conn_hostname = conn.hostname.clone();

            if let Some(nid) = try_nid {
                nw |= self.try_tx(nid, false);
            }

            // :253-257: PING sent, no PONG
            if pinged {
                log::info!(target: "tincd::conn",
                           "{conn_name} ({conn_hostname}) didn't respond \
                            to PING in {} seconds", stale.as_secs());
                self.terminate(id);
                continue;
            }

            // :260-262 send_ping (protocol_misc.c:47-52)
            if stale >= pinginterval {
                let conn = self.conns.get_mut(id).expect("just checked");
                conn.pinged = true;
                conn.last_ping_time = now;
                nw |= conn.send(format_args!("{}", Request::Ping as u8));
            }
        }
        if nw {
            self.maybe_set_write_any();
        }

        // :263-265 re-arm +1s (jitter() not ported)
        self.timers.set(self.pingtimer, Duration::from_secs(1));
    }

    /// `periodic_handler` (`net.c:268-303`). Contradicting-edge
    /// storm detection + autoconnect.
    ///
    /// `:274-291`: both counters >100 → two daemons same Name. Fix
    /// is **synchronous sleep** — blocking the loop IS the point
    /// (stop sending corrections). Doubled per trigger (cap 3600s),
    /// halved per clean period (floor 10s).
    ///
    /// Returns would-sleep duration for the unit test only.
    pub(super) fn on_periodic_tick(&mut self) -> Duration {
        // :274
        let slept = if self.contradicting_del_edge > 100 && self.contradicting_add_edge > 100 {
            log::warn!(target: "tincd",
                       "Possible node with same Name as us! Sleeping {} seconds.",
                       self.sleeptime);
            let d = Duration::from_secs(u64::from(self.sleeptime));
            // :276. Blocking sleep is intentional — see doc.
            #[cfg(not(test))]
            std::thread::sleep(d);
            // :277-281. C `< 0` catches signed overflow; u32 cap explicit.
            self.sleeptime = self.sleeptime.saturating_mul(2).min(3600);
            d
        } else {
            // :282-289
            self.sleeptime = (self.sleeptime / 2).max(10);
            Duration::ZERO
        };

        // :290-291
        self.contradicting_add_edge = 0;
        self.contradicting_del_edge = 0;

        // :294-296. node_tree.count > 1 ≡ node_ids.len() > 1.
        if self.settings.autoconnect && self.node_ids.len() > 1 {
            let action = self.decide_autoconnect();
            self.execute_auto_action(action);
        }

        // :298-300
        self.timers.set(self.periodictimer, Duration::from_secs(5));

        slept
    }

    /// `execute_script` (`script.c:144-253`). C callers all ignore
    /// the return; a failing script never aborts the daemon.
    /// `DEVICE`/`NETNAME`/`DEBUG`: not threaded through yet (None).
    pub(super) fn run_script(&self, name: &str) {
        let env = ScriptEnv::base(None, &self.name, None, Some(&self.iface), None);
        Self::log_script(name, script::execute(&self.confbase, name, &env, None));
    }

    /// `subnet_update` single-subnet (`subnet.c:376-390`). The
    /// loop-all path (`:352-372`) is inlined in BecameReachable.
    ///
    /// C `:360-366` strips `#weight` and passes `""` for default;
    /// we always pass the integer (more useful, scripts guard anyway).
    pub(super) fn run_subnet_script(&self, up: bool, owner: &str, subnet: &Subnet) {
        let mut env = ScriptEnv::base(None, &self.name, None, Some(&self.iface), None);
        env.add("NODE", owner.to_owned()); // :337
        // :339-345: REMOTEADDRESS/REMOTEPORT only if owner != myself
        if owner != self.name
            && let Some(addr) = self
                .node_ids
                .get(owner)
                .and_then(|nid| self.nodes.get(nid))
                .and_then(|ns| ns.edge_addr)
        {
            env.add("REMOTEADDRESS", addr.ip().to_string());
            env.add("REMOTEPORT", addr.port().to_string());
        }
        // :359-368: strip #weight if present
        let netstr = subnet.to_string();
        let netstr = netstr.split_once('#').map_or(netstr.as_str(), |(s, _)| s);
        env.add("SUBNET", netstr.to_owned());
        env.add("WEIGHT", subnet.weight().to_string());

        let name = if up { "subnet-up" } else { "subnet-down" };
        Self::log_script(name, script::execute(&self.confbase, name, &env, None));
    }

    /// `graph.c:273-289`: host-up/down AND hosts/NAME-up/down.
    /// `addr` None → REMOTEADDRESS omitted (C would pass "unknown").
    pub(super) fn run_host_script(&self, up: bool, node: &str, addr: Option<SocketAddr>) {
        let mut env = ScriptEnv::base(None, &self.name, None, Some(&self.iface), None);
        env.add("NODE", node.to_owned()); // :279
        if let Some(a) = addr {
            env.add("REMOTEADDRESS", a.ip().to_string());
            env.add("REMOTEPORT", a.port().to_string());
        }

        // :284
        let name = if up { "host-up" } else { "host-down" };
        Self::log_script(name, script::execute(&self.confbase, name, &env, None));

        // :286-287 per-node hook, same env
        let per = format!("hosts/{node}-{}", if up { "up" } else { "down" });
        Self::log_script(&per, script::execute(&self.confbase, &per, &env, None));
    }

    /// `script.c:228-250` outcome logging.
    pub(super) fn log_script(name: &str, r: io::Result<ScriptResult>) {
        match r {
            // :203 NotFound silent; :230 Ok silent
            Ok(ScriptResult::NotFound | ScriptResult::Ok) => {}
            // :231-238
            Ok(ScriptResult::Failed(st)) => {
                log::warn!(target: "tincd", "Script {name}: {st}");
            }
            // :249-250 spawn fail
            Err(e) => {
                log::error!(target: "tincd", "Script {name} spawn failed: {e}");
            }
        }
    }

    /// `age_past_requests` (`protocol.c:213-228`). Evict entries
    /// older than `pinginterval`. `:226`: skip log if 0/0.
    pub(super) fn on_age_past_requests(&mut self) {
        let now = self.timers.now();
        let max_age = Duration::from_secs(u64::from(self.settings.pinginterval));
        let (deleted, left) = self.seen.age(now, max_age);
        if deleted > 0 || left > 0 {
            log::debug!(target: "tincd::proto",
                        "Aging past requests: deleted {deleted}, left {left}");
        }
        self.timers.set(self.age_timer, Duration::from_secs(10)); // :228
    }

    /// `age_subnets` (`route.c:491-521`). Lazy-armed by learn_mac.
    /// 10s = sweep frequency; macexpire (600s) = lease duration.
    pub(super) fn on_age_subnets(&mut self) {
        let now = self.timers.now();
        let (expired, any_left) = self.mac_leases.age(now);

        let myname = self.name.clone();
        for mac in &expired {
            // learn_mac:538: weight=10. del compares full Subnet incl weight.
            let subnet = Subnet::Mac {
                addr: *mac,
                weight: 10,
            };
            log::info!(target: "tincd::net", "Subnet {subnet} expired");

            // :506-509
            let targets = self.broadcast_targets(None);
            for cid in targets {
                let _ = self.send_subnet(cid, Request::DelSubnet, &myname, &subnet);
            }

            // :511. C does NOT fire subnet_update here — originator's
            // expiry doesn't run subnet-down (only receiver's del_subnet_h).
            self.subnets.del(&subnet, &myname);
            self.mac_table.remove(mac);
        }

        // :518-521: re-arm only if leases remain. Else clear slot;
        // next learn_mac re-creates (learn() returns true on empty).
        if any_left {
            if let Some(tid) = self.age_subnets_timer {
                self.timers.set(tid, Duration::from_secs(10));
            }
        } else if let Some(tid) = self.age_subnets_timer.take() {
            self.timers.del(tid);
        }
    }

    // ─── signal handlers

    /// `net.c:316-333` sigterm/sighup/sigalrm handlers.
    pub(super) fn on_signal(&mut self, s: SignalWhat) {
        match s {
            SignalWhat::Exit => {
                log::info!(target: "tincd", "Got signal, exiting");
                self.running = false;
            }
            SignalWhat::Reload => {
                // :321-328. No log file to reopen (env_logger → stderr).
                // C continues either way; so do we.
                log::info!(target: "tincd", "Got SIGHUP, reloading");
                if !self.reload_configuration() {
                    log::error!(target: "tincd",
                                "Unable to reload configuration");
                }
            }
            SignalWhat::Retry => {
                // C retry() (net.c:460-485). Not yet implemented.
                log::info!(target: "tincd", "Got SIGALRM, retry not implemented");
            }
        }
    }

    /// `reload_configuration` (`net.c:336-458`). False if config
    /// re-read failed (`:343`); daemon continues either way.
    ///
    /// NOT reloadable: Port, AddressFamily, DeviceType (need re-bind/
    /// re-open; C same). Not-yet: Compression, Forwarding.
    #[allow(clippy::too_many_lines)] // C is 122 lines; shared state
    pub(super) fn reload_configuration(&mut self) -> bool {
        // :340-354
        let config = match tinc_conf::read_server_config(&self.confbase) {
            Ok(c) => c,
            Err(e) => {
                log::error!(target: "tincd",
                            "Unable to reread configuration file: {e}");
                return false;
            }
        };
        // :350-351 read_host_config
        let mut config = config;
        let host_file = self.confbase.join("hosts").join(&self.name);
        if let Ok(entries) = tinc_conf::parse_file(&host_file) {
            config.merge(entries);
        }

        // :355 setup_myself_reloadable
        apply_reloadable_settings(&config, &mut self.settings);

        // net_setup.c:570: operator may have run `tinc invite` since boot.
        match invitation_serve::read_invitation_key(&self.confbase) {
            Ok(k) => {
                if k.is_some() && self.invitation_key.is_none() {
                    log::info!(target: "tincd", "Invitation key loaded");
                }
                self.invitation_key = k;
            }
            Err(e) => {
                log::warn!(target: "tincd",
                            "Failed to read invitation key: {e}");
            }
        }

        // :396-428 subnet diff (non-strictsubnets branch)
        let current_subnets: HashSet<Subnet> =
            self.subnets.owned_by(&self.name).into_iter().collect();
        let new_subnets = parse_subnets_from_config(&config, &self.name);
        let diff = reload::diff_subnets(&current_subnets, &new_subnets);

        // :423-427 removed → send DEL, subnet-down, del
        let myname = self.name.clone();
        for s in diff.removed {
            let line = SubnetMsg {
                owner: myname.clone(),
                subnet: s,
            }
            .format(Request::DelSubnet, Self::nonce());
            self.broadcast_line(&line);
            self.run_subnet_script(false, &myname, &s); // :425
            self.subnets.del(&s, &myname); // :427
            // mac_table sync (rare in practice; matches C semantics)
            if let Subnet::Mac { addr, .. } = s {
                self.mac_table.remove(&addr);
            }
        }
        // :415-419 added → add, send ADD, subnet-up (C order matched)
        for s in diff.added {
            self.subnets.add(s, myname.clone()); // :415
            let line = SubnetMsg {
                owner: myname.clone(),
                subnet: s,
            }
            .format(Request::AddSubnet, Self::nonce());
            self.broadcast_line(&line);
            self.run_subnet_script(true, &myname, &s); // :419
            if let Subnet::Mac { addr, .. } = s {
                self.mac_table.insert(addr, myname.clone());
            }
        }

        // :432 try_outgoing_connections. C mark-sweeps; we diff.
        let current_ct: BTreeSet<String> = self
            .outgoings
            .iter()
            .map(|(_, o)| o.node_name.clone())
            .collect();
        let new_ct: BTreeSet<String> = parse_connect_to_from_config(&config, &myname)
            .into_iter()
            .collect();
        let (to_add, to_remove) = reload::diff_connect_to(&current_ct, &new_ct);

        // Remove: terminate conn, drop slot+timer. C net_socket.c:870-883.
        for name in to_remove {
            let oid = self
                .outgoings
                .iter()
                .find(|(_, o)| o.node_name == name)
                .map(|(id, _)| id);
            if let Some(oid) = oid {
                let to_terminate: Vec<ConnId> = self
                    .conns
                    .iter()
                    .filter(|(_, c)| c.outgoing.map(OutgoingId::from) == Some(oid))
                    .map(|(id, _)| id)
                    .collect();
                for cid in to_terminate {
                    // Clear outgoing first so terminate doesn't retry.
                    if let Some(c) = self.conns.get_mut(cid) {
                        c.outgoing = None;
                    }
                    self.terminate(cid);
                }
                if let Some(tid) = self.outgoing_timers.remove(oid) {
                    self.timers.del(tid);
                }
                self.outgoings.remove(oid);
                log::info!(target: "tincd",
                            "Removed outgoing connection to {name}");
            }
        }
        // Add: same path as setup()
        for peer in to_add {
            self.lookup_or_add_node(&peer);
            let config_addrs = resolve_config_addrs(&self.confbase, &peer);
            let addr_cache =
                crate::addrcache::AddressCache::open(&self.confbase, &peer, config_addrs);
            let oid = self.outgoings.insert(Outgoing {
                node_name: peer,
                timeout: 0,
                addr_cache,
            });
            let tid = self.timers.add(TimerWhat::RetryOutgoing(oid));
            self.outgoing_timers.insert(oid, tid);
            self.setup_outgoing_connection(oid);
        }

        // :438-455 mtime check
        let conn_names: Vec<String> = self
            .conns
            .values()
            .filter(|c| !c.control)
            .map(|c| c.name.clone())
            .collect();
        let host_mtimes: Vec<(String, SystemTime)> = conn_names
            .iter()
            .filter_map(|name| {
                let path = self.confbase.join("hosts").join(name);
                std::fs::metadata(&path)
                    .and_then(|m| m.modified())
                    .ok()
                    .map(|mt| (name.clone(), mt))
            })
            .collect();
        let to_terminate =
            reload::conns_to_terminate(&conn_names, &host_mtimes, self.last_config_check);
        for name in to_terminate {
            log::info!(target: "tincd::conn",
                        "Host config file of {name} has been changed");
            let to_term: Vec<ConnId> = self
                .conns
                .iter()
                .filter(|(_, c)| !c.control && c.name == name)
                .map(|(id, _)| id)
                .collect();
            for cid in to_term {
                self.terminate(cid);
            }
        }

        // net.c:370. C does this BEFORE try_outgoing_connections;
        // ConnectTo diff above doesn't read has_address, so order ok.
        self.load_all_nodes();

        self.last_config_check = SystemTime::now(); // :455

        self.maybe_set_write_any();

        true
    }

    /// `keyexpire_handler` + `regenerate_key` + `send_key_changed`
    /// (SPTPS-only branch). C `net_setup.c:144-160`, `protocol_
    /// key.c:38-62`.
    ///
    /// C `regenerate_key` clears `validkey_in` for every node and
    /// calls `send_key_changed`. Under `#ifdef DISABLE_LEGACY`
    /// `send_key_changed` reduces to: walk every reachable+validkey
    /// SPTPS tunnel, call `sptps_force_kex`. The `validkey_in` clear
    /// is legacy-receive bookkeeping (gates `receive_udppacket`
    /// `:437`); the SPTPS state machine handles the rekey transcript
    /// independently.
    ///
    /// C-nolegacy NEVER ARMS this timer (`timeout_add` at `net_
    /// setup.c:1049` is inside `#ifndef DISABLE_LEGACY`). That's a
    /// C bug: `outseqno` is the ChaCha20-Poly1305 nonce, wraps at
    /// u32::MAX with no check (`sptps.c:116,141`). We arm.
    pub(super) fn on_keyexpire(&mut self) {
        log::info!(target: "tincd", "Expiring symmetric keys");

        // C `protocol_key.c:55-60`: `for splay_each(node_t, n,
        // &node_tree) if(reachable && validkey && sptps)
        // sptps_force_kex(&n->sptps)`.
        //
        // Borrow dance: collect (nid, name, outs) first; dispatch_
        // tunnel_outputs needs `&mut self`. force_kex's RNG is
        // OsRng — same as the receive paths in metaconn.rs/gossip.rs.
        let mut pending: Vec<(NodeId, String, Vec<tinc_sptps::Output>)> = Vec::new();
        for (&nid, tunnel) in &mut self.tunnels {
            if !tunnel.status.validkey {
                continue;
            }
            // C also checks `reachable`; our `validkey` is cleared on
            // BecameUnreachable (tunnel.reset_unreachable, gossip.rs:
            // 830-ish), so validkey ⇒ reachable here.
            let Some(sptps) = tunnel.sptps.as_deref_mut() else {
                continue;
            };
            match sptps.force_kex(&mut OsRng) {
                Ok(outs) => {
                    let name = self
                        .graph
                        .node(nid)
                        .map_or_else(|| "<unknown>".to_owned(), |n| n.name.clone());
                    pending.push((nid, name, outs));
                }
                Err(_) => {
                    // InvalidState: rekey already in flight (state !=
                    // SecondaryKex). C `sptps_force_kex` returns false;
                    // C ignores it. Same.
                    log::debug!(target: "tincd",
                                "force_kex skipped (rekey already in flight)");
                }
            }
        }

        let mut nw = false;
        for (nid, name, outs) in pending {
            nw |= self.dispatch_tunnel_outputs(nid, &name, outs);
        }
        if nw {
            self.maybe_set_write_any();
        }

        // C `net_setup.c:148-149`: re-arm +keylifetime.
        self.timers.set(
            self.keyexpire_timer,
            Duration::from_secs(u64::from(self.settings.keylifetime)),
        );
    }

    // ─── io handlers
}
