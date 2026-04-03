#![forbid(unsafe_code)]

#[allow(clippy::wildcard_imports)]
use super::*;

impl Daemon {
    /// `timeout_handler` (`net.c:180-266`). The dead-connection
    /// sweep + ping sender.
    ///
    /// ## Four cases per connection
    ///
    /// `:219-221` Control conn → skip. Control conns also get a
    ///   1-hour `last_ping_time` bump in `handle_id` so the timeout
    ///   check would skip them anyway; the explicit `continue` saves
    ///   the comparison.
    ///
    /// `:236-247` **Pre-edge timeout** (handshake stalled). The conn
    ///   passed `pingtimeout` seconds without reaching ACK. Either
    ///   the async-connect never finished (`:238` "Timeout while
    ///   connecting") OR `id_h`/SPTPS stalled (`:240` "Timeout
    ///   during authentication", + tarpit bit in C — we don't track
    ///   per-conn tarpit yet). Terminate. THIS reaps the half-open
    ///   conn `tests/security.rs::id_timeout_half_open` plants.
    ///
    /// `:253-257` **Pinged but no PONG** (peer died). We sent PING,
    ///   `pingtimeout` elapsed, no PONG cleared the bit. Terminate.
    ///   The TCP keepalive case: peer rebooted, our socket is fine
    ///   (no RST yet), the only way we KNOW is the silence.
    ///
    /// `:260-262` **Send PING** (idle keepalive). `pinginterval`
    ///   elapsed since `last_ping_time`. Set the `pinged` bit, send
    ///   `"8"`. The peer's `ping_h` replies `"9"` → our `pong_h`
    ///   clears the bit → the conn survives the next sweep.
    ///
    /// ## Laptop-suspend detector (`:189-213`)
    ///
    /// `now - last_periodic_run_time > 2 * udp_discovery_timeout`
    /// → the timer hasn't fired for over a minute → the daemon
    /// was asleep (laptop lid). Every peer has timed US out and
    /// dropped the connection; OUR sockets still look alive. Sending
    /// into them produces "failed signature" noise on the peer side
    /// (stale SPTPS context). Force-close everything; outgoings
    /// retry with fresh contexts.
    #[allow(clippy::too_many_lines)] // C `timeout_handler` is 86 LOC
    pub(super) fn on_ping_tick(&mut self) {
        let now = self.timers.now();

        // ─── laptop-suspend detection (`:189-213`)
        // C `:189`: `now.tv_sec - last_periodic_run_time.tv_sec`.
        // `Instant` saturating sub: a clock-goes-backwards (NTP
        // jump) reads as zero, which is the safe answer.
        let sleep_time = now.saturating_duration_since(self.last_periodic_run_time);
        let threshold = Duration::from_secs(u64::from(self.settings.udp_discovery_timeout) * 2);
        let close_all_connections = sleep_time > threshold;
        if close_all_connections {
            log::error!(target: "tincd",
                        "Awaking from dead after {} seconds of sleep",
                        sleep_time.as_secs());
        }
        // C `:215`: `last_periodic_run_time = now`.
        self.last_periodic_run_time = now;

        let pingtimeout = Duration::from_secs(u64::from(self.settings.pingtimeout));
        let pinginterval = Duration::from_secs(u64::from(self.settings.pinginterval));

        // `terminate()` mutates `conns`; collect ids first. The
        // connection set is small (one per direct peer + control).
        let ids: Vec<ConnId> = self.conns.keys().collect();
        let mut nw = false;
        for id in ids {
            let Some(conn) = self.conns.get(id) else {
                // Can happen if a previous terminate in THIS sweep
                // tore down a conn that's still in `ids`. Defensive.
                continue;
            };

            // C `:219-221`: control conns have no timeout.
            if conn.control {
                continue;
            }

            // C `:224-228`: laptop-suspend force-close.
            if close_all_connections {
                log::error!(target: "tincd",
                            "Forcing connection close after sleep time {} ({})",
                            conn.name, conn.hostname);
                // C: `terminate_connection(c, c->edge)`. The second
                // arg is `report` = broadcast DEL_EDGE; `c->edge !=
                // NULL` ≡ our `conn.active`. `terminate()` already
                // keys its DEL_EDGE on `was_active` — same effect.
                self.terminate(id);
                continue;
            }

            // C `:231-233`: `if(c->last_ping_time + pingtimeout >
            // now.tv_sec) continue`. Not yet stale; skip.
            let stale = now.saturating_duration_since(conn.last_ping_time);
            if stale <= pingtimeout {
                continue;
            }

            // C `:236-247`: `if(!c->edge)`. Pre-ACK timeout. The
            // handshake (or even the async-connect) didn't finish
            // in `pingtimeout` seconds.
            if !conn.active {
                if conn.connecting {
                    log::warn!(target: "tincd::conn",
                               "Timeout while connecting to {} ({})",
                               conn.name, conn.hostname);
                } else {
                    // C `:240-241`: also sets `c->status.tarpit =
                    // true` so `terminate` queues the fd in the
                    // tarpit ring instead of closing immediately.
                    // Our `Tarpit` is accept-side only; the per-
                    // conn tarpit bit isn't tracked. The terminate
                    // closes immediately. Harmless: the auth-
                    // timeout case is benign (slow peer) not hostile
                    // — the tarpit was for INBOUND auth-spam, and
                    // that's covered by the accept-side rate limit.
                    log::warn!(target: "tincd::conn",
                               "Timeout from {} ({}) during authentication",
                               conn.name, conn.hostname);
                }
                self.terminate(id);
                continue;
            }

            // C `:250`: `try_tx(c->node, false)`. UDP holepunch
            // keepalive. The `false` is `mtu = false`: ping-tick
            // keeps the UDP path warm but doesn't drive PMTU
            // (PMTU is per-packet, not per-tick).
            //
            // IMPORTANT: only `try_tx` if `validkey` is already
            // set. The C `try_sptps` would `send_req_key` here,
            // but for direct neighbors that's WRONG — they're our
            // META connection, not a data target. The C `try_tx`
            // is gated on `c->node` actually being a forwarding
            // target (something tries to send to them); the ping
            // tick keepalive is a degenerate trigger that fires
            // for ALL direct neighbors. With `try_sptps`
            // unconditionally REQ_KEY-ing here, every direct
            // neighbor gets a per-tunnel handshake even if no data
            // ever flows to them. That's correct (keeps UDP warm)
            // but races with gossip during initial mesh formation.
            // Gate on `validkey` to skip the noisy first phase.
            // The per-packet `try_tx` (in `route_packet`) does the
            // initial handshake when data actually flows.
            let try_nid = self
                .node_ids
                .get(&conn.name)
                .copied()
                .filter(|nid| self.tunnels.get(nid).is_some_and(|t| t.status.validkey));
            // Read `pinged` before releasing the `conn` borrow.
            let pinged = conn.pinged;
            let conn_name = conn.name.clone();
            let conn_hostname = conn.hostname.clone();
            // ─── conn borrow ends here ───

            if let Some(nid) = try_nid {
                nw |= self.try_tx(nid, false);
            }

            // C `:253-257`: `if(c->status.pinged)`. Sent PING,
            // `pingtimeout` elapsed, no PONG cleared the bit.
            if pinged {
                log::info!(target: "tincd::conn",
                           "{conn_name} ({conn_hostname}) didn't respond \
                            to PING in {} seconds", stale.as_secs());
                self.terminate(id);
                continue;
            }

            // C `:260-262`: `if(c->last_ping_time + pinginterval
            // <= now.tv_sec) send_ping(c)`. Idle for `pinginterval`
            // — send a keepalive. `send_ping` (`protocol_misc.c:
            // 47-52`): set bit, stamp time, `"%d", PING`.
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

        // C `net.c:263-265`: `timeout_set(data, &(struct timeval) {
        // 1, jitter() })`. Re-arm +1s. jitter() not ported.
        self.timers.set(self.pingtimer, Duration::from_secs(1));
    }

    /// `periodic_handler` (`net.c:268-303`). Contradicting-edge
    /// storm detection + autoconnect. Re-arms +5s.
    ///
    /// `:274-291`: when both `contradicting_add_edge > 100` AND
    /// `contradicting_del_edge > 100`, two daemons are fighting
    /// over the same Name — each rejects the other's edges ("I
    /// don't have that"), correction-floods, gossip won't converge.
    /// The fix is **synchronous sleep**: blocking the event loop
    /// IS the point (stop sending corrections, let the other side
    /// win). Doubled each trigger (cap 3600s); halved each clean
    /// period (floor 10s).
    ///
    /// Returns the would-sleep duration so the unit test can check
    /// the backoff arithmetic without actually sleeping. The `run()`
    /// loop calls this; nobody reads the return outside tests.
    pub(super) fn on_periodic_tick(&mut self) -> Duration {
        // C `:274`: `if(contradicting_del_edge > 100 &&
        // contradicting_add_edge > 100)`.
        let slept = if self.contradicting_del_edge > 100 && self.contradicting_add_edge > 100 {
            log::warn!(target: "tincd",
                       "Possible node with same Name as us! Sleeping {} seconds.",
                       self.sleeptime);
            let d = Duration::from_secs(u64::from(self.sleeptime));
            // C `:276`: `sleep_millis(sleeptime * 1000)`. Blocks.
            // The daemon is single-threaded; this stops EVERYTHING.
            // Intentional — see doc comment.
            #[cfg(not(test))]
            std::thread::sleep(d);
            // C `:277-281`: `sleeptime *= 2; if < 0 → 3600`. The
            // C's `< 0` check catches signed-int overflow. u32
            // doesn't overflow at 3600*2; cap explicitly.
            self.sleeptime = self.sleeptime.saturating_mul(2).min(3600);
            d
        } else {
            // C `:282-289`: halve, floor at 10. Integer divide.
            self.sleeptime = (self.sleeptime / 2).max(10);
            Duration::ZERO
        };

        // C `:290-291`: reset both counters.
        self.contradicting_add_edge = 0;
        self.contradicting_del_edge = 0;

        // C `:294-296`: `if(autoconnect && node_tree.count > 1)
        // do_autoconnect()`. `node_tree.count` is the total number
        // of NodeIds (incl. myself); `> 1` means "we know of at
        // least one other node". `node_ids.len()` is exactly that.
        if self.settings.autoconnect && self.node_ids.len() > 1 {
            let action = self.decide_autoconnect();
            self.execute_auto_action(action);
        }

        // C `:298-300`: `timeout_set(data, { 5, jitter() })`.
        self.timers.set(self.periodictimer, Duration::from_secs(5));

        slept
    }

    /// `execute_script` wrapper (`script.c:144-253`). Builds the
    /// base env from daemon state, invokes, logs the outcome
    /// matching C `:231-247`. The C callers all ignore the return
    /// (`net_setup.c:752`, `graph.c:287`, `subnet.c:393`); a failing
    /// script never aborts the daemon. We log and move on.
    ///
    /// `DEVICE` env var: C reads the `device` global (path like
    /// `/dev/net/tun`). We don't keep that path post-open (the
    /// trait doesn't expose it; `Dummy` has no path). Pass `None`.
    /// The standard tinc-up scripts use `INTERFACE`, not `DEVICE`.
    ///
    /// `NETNAME`/`DEBUG`: not threaded through the daemon yet (the
    /// `-n` flag and `-d N` are main.rs concerns). `None` for now.
    pub(super) fn run_script(&self, name: &str) {
        let env = ScriptEnv::base(
            None,       // netname: not threaded through yet
            &self.name, // myname
            None,       // device path: not retained post-open
            Some(&self.iface),
            None, // debug_level: not threaded through yet
        );
        Self::log_script(name, script::execute(&self.confbase, name, &env, None));
    }

    /// `subnet_update` single-subnet path (`subnet.c:323-393`, the
    /// `else` branch at `:376-390`). Called from `on_add_subnet`/
    /// `on_del_subnet`. The `subnet=NULL` loop-all-subnets path
    /// (`:352-372`, called from `graph.c:294`) is inlined in
    /// `BecameReachable`/`BecameUnreachable`.
    ///
    /// C `:360-366` strips `#weight` from `net2str` output and puts
    /// it in `WEIGHT` separately. Our `Subnet::Display` already
    /// omits `#weight` when it's the default (10); we always pass
    /// the integer in `WEIGHT` (the C passes `""` for default —
    /// `:364` `weight = empty`). The integer is more useful; the C
    /// scripts that read `$WEIGHT` typically `[ -z "$WEIGHT" ]`
    /// guard anyway.
    pub(super) fn run_subnet_script(&self, up: bool, owner: &str, subnet: &Subnet) {
        let mut env = ScriptEnv::base(None, &self.name, None, Some(&self.iface), None);
        // C `:337`: `"NODE=%s", owner->name`.
        env.add("NODE", owner.to_owned());
        // C `:339-345`: REMOTEADDRESS/REMOTEPORT only `if owner !=
        // myself`. The owner's UDP address — from `n->address`
        // (which is `update_node_udp`-written; for direct peers
        // it's `NodeState.edge_addr`).
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
        // C `:359-368`: `net2str` then `strchr('#')` split. Our
        // `Display` may include `#weight` (non-default); strip it.
        let netstr = subnet.to_string();
        let netstr = netstr.split_once('#').map_or(netstr.as_str(), |(s, _)| s);
        env.add("SUBNET", netstr.to_owned());
        env.add("WEIGHT", subnet.weight().to_string());

        let name = if up { "subnet-up" } else { "subnet-down" };
        Self::log_script(name, script::execute(&self.confbase, name, &env, None));
    }

    /// `graph.c:273-289` script firing for one node transition.
    /// Fires `host-up`/`host-down` AND `hosts/NAME-up`/`hosts/
    /// NAME-down` (the per-node script). Same env for both.
    ///
    /// `addr` is `n->address` — the SSSP-derived UDP address. For
    /// direct peers it's `NodeState.edge_addr`; for transitives we
    /// don't have it yet (chunk 9's `update_node_udp` walk). `None`
    /// → REMOTEADDRESS/REMOTEPORT omitted (the C would pass
    /// `"unknown"` from `sockaddr2str` of an `AF_UNKNOWN` — less
    /// useful than not setting the var at all).
    pub(super) fn run_host_script(&self, up: bool, node: &str, addr: Option<SocketAddr>) {
        let mut env = ScriptEnv::base(None, &self.name, None, Some(&self.iface), None);
        // C `:279`: `"NODE=%s", n->name`.
        env.add("NODE", node.to_owned());
        // C `:280-282`: `sockaddr2str(&n->address, &address, &port)`.
        if let Some(a) = addr {
            env.add("REMOTEADDRESS", a.ip().to_string());
            env.add("REMOTEPORT", a.port().to_string());
        }

        // C `:284`: `execute_script(reachable ? "host-up" :
        // "host-down", &env)`.
        let name = if up { "host-up" } else { "host-down" };
        Self::log_script(name, script::execute(&self.confbase, name, &env, None));

        // C `:286-287`: `snprintf(name, "hosts/%s-%s", n->name,
        // up?"up":"down"); execute_script(name, &env)`. Per-node
        // hook. Same env.
        let per = format!("hosts/{node}-{}", if up { "up" } else { "down" });
        Self::log_script(&per, script::execute(&self.confbase, &per, &env, None));
    }

    /// C `script.c:228-250` outcome logging. Associated fn (not
    /// method): the script call sites borrow `&self` for env
    /// building; this needs no daemon state.
    pub(super) fn log_script(name: &str, r: io::Result<ScriptResult>) {
        match r {
            // C `:203`: NotFound is silent (script optional).
            // C `:230`: Ok is silent (success is the boring case).
            Ok(ScriptResult::NotFound | ScriptResult::Ok) => {}
            Ok(ScriptResult::Failed(st)) => {
                // C `:231-238`: `"Script %s exited with non-zero
                // status %d"` or `"...terminated by signal %d"`.
                // `ExitStatus::Display` covers both.
                log::warn!(target: "tincd", "Script {name}: {st}");
            }
            Err(e) => {
                // C `:249-250`: `system() == -1` → `"...exited
                // abnormally"`. Our spawn-fail (ENOEXEC etc).
                log::error!(target: "tincd", "Script {name} spawn failed: {e}");
            }
        }
    }

    /// `age_past_requests` (`protocol.c:213-228`). Evict seen-
    /// request entries older than `pinginterval` seconds, log the
    /// counts at DEBUG, re-arm +10s.
    ///
    /// C `:219` condition: `p->firstseen + pinginterval <=
    /// now.tv_sec`. The `<=` boundary is preserved by `seen.age`.
    /// C `:226` log: `"Aging past requests: deleted %d, left %d"`
    /// only when `left || deleted` (don't log 0/0 every 10s).
    pub(super) fn on_age_past_requests(&mut self) {
        let now = self.timers.now();
        let max_age = Duration::from_secs(u64::from(self.settings.pinginterval));
        let (deleted, left) = self.seen.age(now, max_age);
        // C `:225-227`: gate the log on non-empty.
        if deleted > 0 || left > 0 {
            log::debug!(target: "tincd::proto",
                        "Aging past requests: deleted {deleted}, left {left}");
        }
        // C `:228`: `timeout_set(..., {10, jitter()})`. Re-arm.
        self.timers.set(self.age_timer, Duration::from_secs(10));
    }

    /// `age_subnets` (`route.c:491-521`). Timer handler. Walk our
    /// learned-MAC leases, expire the dead ones (broadcast
    /// DEL_SUBNET for each), re-arm if any remain.
    ///
    /// Only fires in switch mode (lazy-armed by `learn_mac`). The
    /// 10s interval is the SWEEP frequency; `settings.macexpire`
    /// (default 600s) is the LEASE duration.
    pub(super) fn on_age_subnets(&mut self) {
        let now = self.timers.now();
        let (expired, any_left) = self.mac_leases.age(now);

        let myname = self.name.clone();
        for mac in &expired {
            // C `learn_mac:538`: `weight = 10`. We always learn at
            // weight 10, so the matching del key is also weight 10
            // (SubnetTree::del compares the full Subnet incl weight).
            let subnet = Subnet::Mac {
                addr: *mac,
                weight: 10,
            };
            log::info!(target: "tincd::net", "Subnet {subnet} expired");

            // C `:506-509`: `for(c) if(c->edge) send_del_subnet(c, s)`.
            let targets = self.broadcast_targets(None);
            for cid in targets {
                let _ = self.send_subnet(cid, Request::DelSubnet, &myname, &subnet);
            }

            // C `:511`: `subnet_del(myself, s)`. The C does NOT
            // fire `subnet_update(.., false)` here — the
            // originator's expiry doesn't run subnet-down (only
            // the receiving side's `del_subnet_h` does). Match.
            self.subnets.del(&subnet, &myname);
            self.mac_table.remove(mac);
        }

        // C `:518-521`: `if(left) timeout_set(..., {10, jitter()})`.
        // Re-arm only if leases remain. Otherwise let the timer
        // lapse and clear the slot so the next `learn_mac` re-
        // creates it (`mac_leases.learn()` returns true when the
        // table is empty, which it will be after this).
        if any_left {
            if let Some(tid) = self.age_subnets_timer {
                self.timers.set(tid, Duration::from_secs(10));
            }
        } else if let Some(tid) = self.age_subnets_timer.take() {
            self.timers.del(tid);
        }
    }

    // ─── signal handlers

    /// `sigterm_handler` (`net.c:316-319`) for `Exit`;
    /// `sighup_handler` (`:321-328`) for `Reload`;
    /// `sigalrm_handler` (`:330-333`) for `Retry`.
    pub(super) fn on_signal(&mut self, s: SignalWhat) {
        match s {
            SignalWhat::Exit => {
                // C: `logger(..., LOG_NOTICE, "Got %s signal");
                // event_exit()`. event_exit sets `running = false`.
                log::info!(target: "tincd", "Got signal, exiting");
                self.running = false;
            }
            SignalWhat::Reload => {
                // C `net.c:321-328`: `reopenlogger(); reload_
                // configuration()`. We don't have a log file to
                // reopen (env_logger writes stderr); just reload.
                // C `:325` checks the return value but only logs
                // (`if(reload_configuration()) ERR`); the daemon
                // continues either way.
                log::info!(target: "tincd", "Got SIGHUP, reloading");
                if !self.reload_configuration() {
                    log::error!(target: "tincd",
                                "Unable to reload configuration");
                }
            }
            SignalWhat::Retry => {
                // C: retry() (`net.c:460-485`). Walks outgoing_list,
                // sets each timeout to fire NOW. Skeleton has no
                // outgoings.
                log::info!(target: "tincd", "Got SIGALRM, retry not implemented");
            }
        }
    }

    /// `reload_configuration` (`net.c:336-458`). Re-read tinc.conf +
    /// hosts/NAME, re-apply reloadable settings, diff subnets +
    /// ConnectTo, terminate conns whose hosts/ file changed.
    ///
    /// Returns `true` on success, `false` if `read_server_config`
    /// failed (`net.c:343`: `return EINVAL`). Either way the daemon
    /// continues — the SIGHUP handler logs and moves on.
    ///
    /// What's reloadable vs not (`net_setup.c:391-575`):
    /// - YES: pinginterval, pingtimeout, maxtimeout, the bool gates
    ///   (decrement_ttl, tunnelserver, directonly), invitation_
    ///   lifetime, invitation_key.
    /// - NO: Port, AddressFamily, DeviceType. These need re-bind /
    ///   re-open. The C doesn't reload them either.
    /// - NO (yet): Compression, Forwarding. The C re-applies them
    ///   in `setup_myself_reloadable`; we don't yet (cosmetic — a
    ///   restart picks them up).
    #[allow(clippy::too_many_lines)] // C reload_configuration is
    // 122 lines. The diff/broadcast/script sequence shares too
    // much state to split cleanly.
    pub(super) fn reload_configuration(&mut self) -> bool {
        // ─── re-read config (C `:340-354`)
        let config = match tinc_conf::read_server_config(&self.confbase) {
            Ok(c) => c,
            Err(e) => {
                // C `:343-345`: `return EINVAL`. The CALLER logs;
                // we log here too (the SIGHUP path doesn't see the
                // error, only the false return).
                log::error!(target: "tincd",
                            "Unable to reread configuration file: {e}");
                return false;
            }
        };
        // C `:350-351`: read_host_config. Same two-liner as setup().
        let mut config = config;
        let host_file = self.confbase.join("hosts").join(&self.name);
        if let Ok(entries) = tinc_conf::parse_file(&host_file) {
            config.merge(entries);
        }

        // ─── setup_myself_reloadable (C `:355`)
        apply_reloadable_settings(&config, &mut self.settings);

        // ─── read_invitation_key (C `net_setup.c:570`, inside
        // setup_myself_reloadable). The operator may have run
        // `tinc invite` since boot, creating the key.
        match invitation_serve::read_invitation_key(&self.confbase) {
            Ok(k) => {
                if k.is_some() && self.invitation_key.is_none() {
                    log::info!(target: "tincd", "Invitation key loaded");
                }
                self.invitation_key = k;
            }
            Err(e) => {
                // Corrupt key file. Log, leave the old key in place.
                log::warn!(target: "tincd",
                            "Failed to read invitation key: {e}");
            }
        }

        // ─── subnet diff (C `:396-428`, the non-strictsubnets
        // branch — our `diff_subnets`).
        // Current: every subnet we own (filtered by owner == us).
        // From config: re-parse `Subnet =` lines.
        let current_subnets: HashSet<Subnet> = self
            .subnets
            .iter()
            .filter(|(_, owner)| *owner == self.name)
            .map(|(s, _)| *s)
            .collect();
        let new_subnets = parse_subnets_from_config(&config, &self.name);
        let diff = reload::diff_subnets(&current_subnets, &new_subnets);

        // C `:423-427`: removed → send DEL, fire subnet-down, del.
        // Clone our name once (used in 4 places below; the borrow
        // checker doesn't like &self.name across &mut self calls).
        let myname = self.name.clone();
        for s in diff.removed {
            // C `:423`: `send_del_subnet(everyone, subnet)`.
            let line = SubnetMsg {
                owner: myname.clone(),
                subnet: s,
            }
            .format(Request::DelSubnet, Self::nonce());
            self.broadcast_line(&line);
            // C `:425`: `subnet_update(myself, subnet, false)`.
            self.run_subnet_script(false, &myname, &s);
            // C `:427`: `subnet_del(myself, subnet)`.
            self.subnets.del(&s, &myname);
            // mac_table sync. In practice never fires (own-subnets
            // from hosts/NAME are IP in router mode; switch learns
            // dynamically). Completeness + matches C semantics.
            if let Subnet::Mac { addr, .. } = s {
                self.mac_table.remove(&addr);
            }
        }
        // C `:415-419`: added → add, send ADD, fire subnet-up.
        // (C order is add-send-update; we match.)
        for s in diff.added {
            // C `:415`: `subnet_add(myself, subnet)`.
            self.subnets.add(s, myname.clone());
            // C `:417`: `send_add_subnet(everyone, subnet)`.
            let line = SubnetMsg {
                owner: myname.clone(),
                subnet: s,
            }
            .format(Request::AddSubnet, Self::nonce());
            self.broadcast_line(&line);
            // C `:419`: `subnet_update(myself, subnet, true)`.
            self.run_subnet_script(true, &myname, &s);
            // mac_table sync (see removed-loop note).
            if let Subnet::Mac { addr, .. } = s {
                self.mac_table.insert(addr, myname.clone());
            }
        }

        // ─── ConnectTo diff (C `:432`: try_outgoing_connections).
        // The C re-runs the WHOLE walk (which mark-sweeps via the
        // `outgoing->aip = NULL` trick). Our diff is explicit.
        let current_ct: BTreeSet<String> = self
            .outgoings
            .iter()
            .map(|(_, o)| o.node_name.clone())
            .collect();
        let new_ct: BTreeSet<String> = parse_connect_to_from_config(&config, &myname)
            .into_iter()
            .collect();
        let (to_add, to_remove) = reload::diff_connect_to(&current_ct, &new_ct);

        // Remove: find the Outgoing slot, terminate its conn (if
        // any), drop the slot + timer. C `net_socket.c:870-883`
        // mark-sweep does the same.
        for name in to_remove {
            // Find the OutgoingId by name (linear scan; outgoings
            // are few — single digits).
            let oid = self
                .outgoings
                .iter()
                .find(|(_, o)| o.node_name == name)
                .map(|(id, _)| id);
            if let Some(oid) = oid {
                // Terminate the conn serving this outgoing (if
                // connected). C: `terminate_connection(c, c->edge)`.
                let to_terminate: Vec<ConnId> = self
                    .conns
                    .iter()
                    .filter(|(_, c)| c.outgoing.map(OutgoingId::from) == Some(oid))
                    .map(|(id, _)| id)
                    .collect();
                for cid in to_terminate {
                    // Clear `outgoing` first so terminate's retry
                    // path doesn't fire (the slot is going away).
                    if let Some(c) = self.conns.get_mut(cid) {
                        c.outgoing = None;
                    }
                    self.terminate(cid);
                }
                // Drop the slot + its timer.
                if let Some(tid) = self.outgoing_timers.remove(oid) {
                    self.timers.del(tid);
                }
                self.outgoings.remove(oid);
                log::info!(target: "tincd",
                            "Removed outgoing connection to {name}");
            }
        }
        // Add: same path as setup() — lookup_or_add_node,
        // build Outgoing, setup_outgoing_connection.
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

        // ─── mtime check (C `:438-455`).
        // Conn names: every non-control conn. Daemon does the
        // stat() (I/O); reload module decides.
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
            // C `:450`: `"Host config file of %s has been changed"`.
            log::info!(target: "tincd::conn",
                        "Host config file of {name} has been changed");
            // Find ConnId by name. Same linear scan; conns are few.
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

        // C `net.c:370`: `load_all_nodes()`. Re-walk hosts/ — a
        // newly-added file with `Address =` becomes eligible for
        // autoconnect on the next periodic tick. C does this AFTER
        // `setup_myself_reloadable` and BEFORE `try_outgoing_
        // connections`; we already did the ConnectTo diff above
        // (it doesn't read `has_address`), so order is harmless.
        self.load_all_nodes();

        // C `:455`: `last_config_check = now.tv_sec`.
        self.last_config_check = SystemTime::now();

        // The broadcast_line calls above queued to active conns.
        // Sweep IO_WRITE.
        self.maybe_set_write_any();

        true
    }

    // ─── io handlers
}
