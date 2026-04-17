#![forbid(unsafe_code)]

use super::{
    ConnId, Daemon, SignalWhat, TimerWhat, apply_reloadable_settings, parse_connect_to_from_config,
    parse_subnets_from_config,
};

use std::collections::{BTreeSet, HashSet};
use std::io;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime};

use crate::outgoing::{Outgoing, OutgoingId, resolve_config_addrs};
use crate::script::{ScriptEnv, ScriptResult};
use crate::{invitation_serve, reload, script};

use rand_core::OsRng;
use tinc_graph::NodeId;
use tinc_proto::msg::SubnetMsg;
use tinc_proto::{Request, Subnet};

impl Daemon {
    /// Dead-conn sweep + ping.
    ///
    /// Per-conn cases: skip control; pre-ACK timeout (handshake
    /// stalled); PING sent but no PONG; idle → send PING.
    ///
    /// Laptop-suspend detector: timer skipped >1min → daemon was
    /// asleep → peers dropped us → force-close all (sending into
    /// stale SPTPS contexts is just noise).
    pub(super) fn on_ping_tick(&mut self) {
        let now = self.timers.now();

        // Laptop-suspend detection. Saturating sub: clock-goes-
        // backwards (NTP) reads as zero (safe).
        let sleep_time = now.saturating_duration_since(self.last_periodic_run_time);
        let threshold = Duration::from_secs(u64::from(self.settings.udp_discovery_timeout) * 2);
        let close_all_connections = sleep_time > threshold;
        if close_all_connections {
            log::error!(target: "tincd",
                        "Awaking from dead after {} seconds of sleep",
                        sleep_time.as_secs());
        }
        self.last_periodic_run_time = now;

        let pingtimeout = Duration::from_secs(u64::from(self.settings.pingtimeout));
        let pinginterval = Duration::from_secs(u64::from(self.settings.pinginterval));

        // terminate() mutates conns; collect ids first.
        let ids: Vec<ConnId> = self.conns.keys().collect();
        let mut nw = false;
        for id in ids {
            let Some(conn) = self.conns.get(id) else {
                continue; // earlier terminate in this sweep
            };

            let stale = now.saturating_duration_since(conn.last_ping_time);

            // Outbuf cap. Control conns: unconditional (their `stale` is
            // pinned at 0 by the +1h window). Meta conns: only once stale.
            if (conn.control || stale > pingtimeout)
                && conn.outbuf.live_len() > self.settings.maxoutbufsize
            {
                log::warn!(target: "tincd::conn",
                           "{} ({}) could not flush for {} seconds ({} bytes pending)",
                           conn.name, conn.hostname, stale.as_secs(),
                           conn.outbuf.live_len());
                self.terminate(id);
                continue;
            }

            if conn.control {
                // `id_control` sets last_ping_time = now+1h; pcap/log writes
                // refresh it. Past that window the client is gone — reap.
                if stale > pingtimeout {
                    self.terminate(id);
                }
                continue;
            }

            if close_all_connections {
                log::error!(target: "tincd",
                            "Forcing connection close after sleep time {} ({})",
                            conn.name, conn.hostname);
                // terminate() keys DEL_EDGE on conn.active.
                self.terminate(id);
                continue;
            }

            // not yet stale
            if stale <= pingtimeout {
                continue;
            }

            // pre-ACK timeout
            if !conn.active {
                if conn.connecting {
                    log::warn!(target: "tincd::conn",
                               "Timeout while connecting to {} ({})",
                               conn.name, conn.hostname);
                } else {
                    // Our Tarpit is accept-side only; harmless
                    // (auth-timeout is benign, accept-side covers
                    // spam).
                    log::warn!(target: "tincd::conn",
                               "Timeout from {} ({}) during authentication",
                               conn.name, conn.hostname);
                }
                self.terminate(id);
                continue;
            }

            // UDP keepalive (no PMTU). Gate on validkey:
            // unconditional REQ_KEY races with gossip during mesh
            // formation. The simultaneous-init race itself (both
            // ends `send_req_key` from `try_tx` before either's
            // REQ_KEY lands) is broken by the name tie-break in
            // `gossip.rs::on_req_key`; this gate just avoids adding
            // a third initiator to the mix every PingInterval.
            // Regression: `tests/reqkey_simultaneous.rs`. Per-packet try_tx (in route_packet) handles
            // the initial handshake instead.
            let try_nid = self
                .node_ids
                .get(&conn.name)
                .copied()
                .filter(|nid| self.dp.tunnels.get(nid).is_some_and(|t| t.status.validkey));
            let pinged = conn.pinged;
            let conn_name = conn.name.clone();
            let conn_hostname = conn.hostname.clone();

            if let Some(nid) = try_nid {
                nw |= self.try_tx(nid, false);
            }

            // PING sent, no PONG
            if pinged {
                log::info!(target: "tincd::conn",
                           "{conn_name} ({conn_hostname}) didn't respond \
                            to PING in {} seconds", stale.as_secs());
                self.terminate(id);
                continue;
            }

            if stale >= pinginterval {
                let conn = self.conn_mut(id);
                conn.pinged = true;
                conn.last_ping_time = now;
                nw |= conn.send(format_args!("{}", Request::Ping));
            }
        }
        if nw {
            self.maybe_set_write_any();
        }

        // collect any exited detached hook scripts (script::spawn)
        script::reap_children();

        // re-arm +1s
        self.timers.set(self.pingtimer, Duration::from_secs(1));
    }

    /// Contradicting-edge storm detection + autoconnect.
    ///
    /// Both counters >100 → two daemons same Name. C tinc does a
    /// blocking `nanosleep`; we instead defer all outgoing retries
    /// and the next periodic tick by `sleeptime` (peer can drive the
    /// counters; blocking the loop is a DoS). Doubled per trigger
    /// (cap 3600s), halved per clean period (floor 10s).
    ///
    /// Returns the deferral duration for the unit test only.
    pub(super) fn on_periodic_tick(&mut self) -> Duration {
        let slept = if self.contradicting_del_edge > 100 && self.contradicting_add_edge > 100 {
            log::warn!(target: "tincd",
                       "Possible node with same Name as us! Sleeping {} seconds.",
                       self.sleeptime);
            let d = Duration::from_secs(u64::from(self.sleeptime));
            for (oid, outgoing) in &mut self.outgoings {
                outgoing.timeout = outgoing.timeout.max(self.sleeptime);
                if let Some(&tid) = self.outgoing_timers.get(oid) {
                    self.timers.set(tid, d);
                }
            }
            self.sleeptime = self.sleeptime.saturating_mul(2).min(3600);
            d
        } else {
            self.sleeptime = (self.sleeptime / 2).max(10);
            Duration::ZERO
        };

        self.contradicting_add_edge = 0;
        self.contradicting_del_edge = 0;

        if self.settings.autoconnect && self.node_ids.len() > 1 {
            let action = self.decide_autoconnect();
            self.execute_auto_action(action);
        }

        // ─── DHT discovery poll (Rust extension). tick() may block on
        // put_mutable (~hundreds of ms); same blocking-is-fine precedent
        // as the contradicting-edge sleep above.
        if self.settings.dht_discovery
            && let Some(d) = self.discovery.as_mut()
        {
            for (name, addrs) in d.drain_resolved() {
                if addrs.is_empty() {
                    log::debug!(target: "tincd::discovery",
                                "DHT resolve {name}: no record");
                } else {
                    log::info!(target: "tincd::discovery",
                               "DHT resolved {name}: {addrs:?}");
                    self.dht_hints.insert(name, addrs);
                }
            }

            let r = d.tick(self.timers.now());
            for ev in r.events {
                match ev {
                    crate::discovery::DiscoveryEvent::PublicV4 { ip, firewalled } => {
                        log::info!(target: "tincd::discovery",
                                   "DHT voted public v4: {ip} \
                                    (firewalled={firewalled})");
                    }
                    crate::discovery::DiscoveryEvent::Published { seq, value } => {
                        log::debug!(target: "tincd::discovery",
                                    "published seq={seq}: {value}");
                    }
                }
            }

            // Port-probe from tincd's *own* socket so the BEP 42 echo
            // carries the NAT mapping for the correct port. Doubles as
            // a keepalive (25s cadence vs 30–180s conntrack timeouts).
            // mainline is v4-only → first v4 listener; no v4 → skip.
            if r.wants_port_probe
                && let targets = d.probe_targets()
                && !targets.is_empty()
                && let Some(slot) = self.listeners.iter().find(|s| s.listener.local.is_ipv4())
            {
                self.dht_probe_sent.clear();
                for tgt in &targets {
                    let dst = socket2::SockAddr::from(SocketAddr::V4(*tgt));
                    let _ = slot
                        .listener
                        .udp
                        .send_to(crate::discovery::PORT_PROBE_PING, &dst);
                    self.dht_probe_sent.insert(SocketAddr::V4(*tgt));
                }
                d.probe_sent(self.timers.now());
            }
        }

        self.timers
            .set(self.periodictimer, Duration::from_secs(5).max(slept));

        slept
    }

    /// A failing script never aborts the daemon. `DEVICE`/`NETNAME`/
    /// `DEBUG`: not threaded through yet (None).
    pub(super) fn run_script(&self, name: &str) {
        let mut env = ScriptEnv::base(None, &self.name, None, Some(&self.iface), None);
        // Rust-only: thread DNS config through to tinc-up so the
        // script can `resolvectl dns "$INTERFACE" "$DNS_ADDR"`
        // without hardcoding the magic IP. Only set when the stub
        // is on; scripts can `[ -n "$DNS_ADDR" ] && resolvectl ...`.
        // Separate v4/v6 vars (resolvectl takes both in one call,
        // but the script may want to gate on which is present).
        if let Some(cfg) = &self.dns {
            if let Some(a) = cfg.dns_addr4 {
                env.add("DNS_ADDR", a.to_string());
            }
            if let Some(a) = cfg.dns_addr6 {
                env.add("DNS_ADDR6", a.to_string());
            }
            env.add("DNS_SUFFIX", cfg.suffix.clone());
        }
        let interp = self.settings.scripts_interpreter.as_deref();
        Self::log_script(name, script::execute(&self.confbase, name, &env, interp));
    }

    /// Fires `tinc-up`. Idempotent via `device_enabled`: called on
    /// every graph run where `reachable_count` went 0→>0; the flag
    /// dedups.
    pub(super) fn device_enable(&mut self) {
        if self.device_enabled {
            return;
        }
        self.device_enabled = true;
        self.run_script("tinc-up");
    }

    /// Fires `tinc-down`. Mirror of `device_enable`. Called when the
    /// last peer becomes unreachable (`DeviceStandby` mode).
    pub(super) fn device_disable(&mut self) {
        if !self.device_enabled {
            return;
        }
        self.device_enabled = false;
        self.run_script("tinc-down");
    }

    /// Single-subnet script. The loop-all path is inlined in
    /// `BecameReachable`. We always pass the weight integer (more
    /// useful than an empty string; scripts guard anyway).
    pub(super) fn run_subnet_script(&self, up: bool, owner: &str, subnet: &Subnet) {
        self.run_subnet_script_impl(up, owner, subnet, false);
    }

    /// [`run_subnet_script`] without waiting; for gossip-driven bulk fires.
    pub(super) fn run_subnet_script_async(&self, up: bool, owner: &str, subnet: &Subnet) {
        self.run_subnet_script_impl(up, owner, subnet, true);
    }

    fn run_subnet_script_impl(&self, up: bool, owner: &str, subnet: &Subnet, detach: bool) {
        let mut env = ScriptEnv::base(None, &self.name, None, Some(&self.iface), None);
        env.add("NODE", owner.to_owned());
        // REMOTEADDRESS/REMOTEPORT only if owner != myself
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
        // strip #weight if present
        let netstr = subnet.to_string();
        let netstr = netstr.split_once('#').map_or(netstr.as_str(), |(s, _)| s);
        env.add("SUBNET", netstr.to_owned());
        env.add("WEIGHT", subnet.weight().to_string());

        let name = if up { "subnet-up" } else { "subnet-down" };
        let interp = self.settings.scripts_interpreter.as_deref();
        let run = if detach {
            script::spawn
        } else {
            script::execute
        };
        Self::log_script(name, run(&self.confbase, name, &env, interp));
    }

    /// host-up/down AND hosts/NAME-up/down. `addr` None →
    /// REMOTEADDRESS omitted.
    pub(super) fn run_host_script(&self, up: bool, node: &str, addr: Option<SocketAddr>) {
        let mut env = ScriptEnv::base(None, &self.name, None, Some(&self.iface), None);
        env.add("NODE", node.to_owned());
        if let Some(a) = addr {
            env.add("REMOTEADDRESS", a.ip().to_string());
            env.add("REMOTEPORT", a.port().to_string());
        }

        let name = if up { "host-up" } else { "host-down" };
        let interp = self.settings.scripts_interpreter.as_deref();
        Self::log_script(name, script::execute(&self.confbase, name, &env, interp));

        // per-node hook, same env
        let per = format!("hosts/{node}-{}", if up { "up" } else { "down" });
        Self::log_script(&per, script::execute(&self.confbase, &per, &env, interp));
    }

    /// Script outcome logging.
    pub(super) fn log_script(name: &str, r: io::Result<ScriptResult>) {
        match r {
            Ok(ScriptResult::NotFound | ScriptResult::Ok | ScriptResult::Spawned) => {}
            // Log Sandboxed at debug so an operator who wonders why
            // their host-up didn't fire under Sandbox=high can find
            // out without reading the source.
            Ok(ScriptResult::Sandboxed) => {
                log::debug!(target: "tincd",
                    "Script {name}: skipped (Sandbox=high)");
            }
            Ok(ScriptResult::Failed(st)) => {
                // error!, not warn!: a failing tinc-up usually means
                // the interface never got an address — the tunnel is
                // effectively dead and the operator needs to see it
                // at default log level.
                log::error!(target: "tincd",
                    "Script {name} exited with status: {st}");
            }
            Err(e) => {
                log::error!(target: "tincd", "Script {name} spawn failed: {e}");
            }
        }
    }

    /// Evict seen-request entries older than `pinginterval`.
    pub(super) fn on_age_past_requests(&mut self) {
        let now = self.timers.now();
        let max_age = Duration::from_secs(u64::from(self.settings.pinginterval));
        let (deleted, left) = self.seen.age(now, max_age);
        if deleted > 0 || left > 0 {
            log::debug!(target: "tincd::proto",
                        "Aging past requests: deleted {deleted}, left {left}");
        }
        self.timers.set(self.age_timer, Duration::from_secs(10));
    }

    /// Expire learned MAC subnets. Lazy-armed by `learn_mac`.
    /// 10s = sweep frequency; macexpire (600s) = lease duration.
    pub(super) fn on_age_subnets(&mut self) {
        let now = self.timers.now();
        let (expired, any_left) = self.mac_leases.age(now);

        let myname = self.name.clone();
        for mac in &expired {
            // weight=10 matches learn_mac. del compares full Subnet
            // incl weight.
            let subnet = Subnet::Mac {
                addr: *mac,
                weight: 10,
            };
            log::info!(target: "tincd::net", "Subnet {subnet} expired");

            let targets = self.broadcast_targets(None);
            for cid in targets {
                let _ = self.send_subnet(cid, Request::DelSubnet, &myname, &subnet);
            }

            // Originator's expiry doesn't run subnet-down (only
            // receiver's del_subnet_h does).
            self.subnets.del(&subnet, &myname);
            self.mac_table.remove(mac);
        }
        // One refresh after the loop. MAC subnets are Switch-mode
        // only; `slowpath_all` is true for Switch (the `!= Router`
        // gate) so tx_probe never reads this snapshot. Gated on
        // `!expired.is_empty()` because the timer fires every 10s
        // but lease duration is 600s — most ticks delete nothing.
        if !expired.is_empty() {
            self.tx_snap_refresh_subnets();
        }

        // Re-arm only if leases remain. Else clear slot; next
        // learn_mac re-creates (learn() returns true on empty).
        if any_left {
            if let Some(tid) = self.age_subnets_timer {
                self.timers.set(tid, Duration::from_secs(10));
            }
        } else if let Some(tid) = self.age_subnets_timer.take() {
            self.timers.del(tid);
        }
    }

    // ─── signal handlers

    /// SIGTERM/SIGHUP/SIGALRM handlers.
    pub(super) fn on_signal(&mut self, s: SignalWhat) {
        match s {
            SignalWhat::Exit(sig) => {
                let name = nix::sys::signal::Signal::try_from(sig)
                    .map_or("signal", nix::sys::signal::Signal::as_str);
                log::info!(target: "tincd", "Got {name}, exiting");
                self.running = false;
            }
            SignalWhat::Reload => {
                // env_logger's file target is set-once; --logfile
                // is NOT reopened here. logrotate must use
                // `copytruncate` (see docs/OPERATING.md).
                log::info!(target: "tincd", "Got SIGHUP, reloading");
                if !self.reload_configuration() {
                    log::error!(target: "tincd",
                                "Unable to reload configuration");
                }
            }
            SignalWhat::Retry => {
                log::info!(target: "tincd", "Got SIGALRM, retrying outgoing connections");
                self.on_retry();
            }
        }
    }

    /// The "network came back, reconnect NOW" button: zeroes outgoing
    /// backoff, fires retry timers immediately, and kicks the ping
    /// sweep so in-progress connects (stuck on a stale fd before
    /// suspend) get reaped this turn instead of after `pingtimeout`
    /// more seconds.
    ///
    /// Triggered by SIGALRM and `tinc retry`. Without this, a laptop
    /// suspended past `MaxTimeout` waits up to 15 min for the next
    /// reconnect attempt.
    pub(super) fn on_retry(&mut self) {
        // Per outgoing, zero backoff + arm timer for now. Every
        // `outgoings` slot has a paired timer (`Daemon::setup` adds
        // it unconditionally at insert).
        for (oid, outgoing) in &mut self.outgoings {
            outgoing.timeout = 0;
            if let Some(&tid) = self.outgoing_timers.get(oid) {
                self.timers.set(tid, Duration::ZERO);
            }
        }

        // In-progress outgoing conns (pre-ACK ≡ `!conn.active`).
        // `Instant` has no zero, so subtract pingtimeout+1 from now.
        // Next ping sweep sees stale > pingtimeout and hits the
        // pre-ACK-timeout branch → terminate → `do_outgoing_
        // connection` retries from a fresh socket.
        let now = self.timers.now();
        let pingtimeout = Duration::from_secs(u64::from(self.settings.pingtimeout));
        if let Some(stale) = now.checked_sub(pingtimeout + Duration::from_secs(1)) {
            for conn in self.conns.values_mut() {
                if conn.outgoing.is_some() && !conn.active {
                    conn.last_ping_time = stale;
                }
            }
        }

        // Kick the ping sweep. The retry timers above fire BEFORE
        // this in the next `expired()` walk (BTreeMap order is
        // (when, seq); same `when`, lower seq wins) so by the time
        // the sweep runs, any new in-progress conns from the retry
        // already have a fresh `last_ping_time` and survive.
        self.timers.set(self.pingtimer, Duration::ZERO);
    }

    /// False if config re-read failed; daemon continues either way.
    ///
    /// NOT reloadable: Port, `AddressFamily`, `DeviceType` (need re-bind/
    /// re-open). Not-yet: Compression, Forwarding.
    pub(super) fn reload_configuration(&mut self) -> bool {
        let config = match tinc_conf::read_server_config(&self.confbase) {
            Ok(c) => c,
            Err(e) => {
                log::error!(target: "tincd",
                            "Unable to reread configuration file: {e}");
                return false;
            }
        };
        let mut config = config;
        let host_file = self.confbase.join("hosts").join(&self.name);
        if let Ok(entries) = tinc_conf::parse_file(&host_file) {
            config.merge(entries);
        }

        // Warn about edits to keys that need a full restart, so an
        // operator who changed Port= and ran `tinc reload` is told
        // why nothing happened instead of silently keeping the old
        // bind. Compared as raw strings (first value) against what
        // we are actually running with; only the keys that map to
        // listener/device/key state are checked.
        {
            let lookup = |k: &str| config.lookup(k).next().map(|e| e.get_str().to_owned());
            let warn = |k: &str| {
                log::warn!(target: "tincd",
                    "{k} changed in configuration but requires a restart to take effect");
            };
            if let Some(p) = lookup("Port")
                && p.parse::<u16>().ok() != Some(self.settings.port)
            {
                warn("Port");
            }
            if let Some(af) = lookup("AddressFamily")
                && crate::listen::AddrFamily::from_config(&af) != Some(self.settings.addressfamily)
            {
                warn("AddressFamily");
            }
            // Keys with no live value to compare against — just
            // detect that they were touched since the last check by
            // diffing against what setup() stashed. We don't stash
            // those, so use the simpler heuristic: warn if the key
            // is present and differs from the device/iface we have.
            if let Some(iface) = lookup("Interface")
                && iface != self.iface
            {
                warn("Interface");
            }
            // BindToAddress / ListenAddress / Device / DeviceType /
            // Mode / key paths are also restart-only but have no
            // single live value to diff against here; covered in
            // docs/OPERATING.md instead of a noisy per-reload note.
        }

        apply_reloadable_settings(&config, &mut self.settings);

        // Operator may have run `tinc invite` since boot.
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

        // ─── subnet diff
        let current_subnets: HashSet<Subnet> =
            self.subnets.owned_by(&self.name).into_iter().collect();
        let new_subnets = parse_subnets_from_config(&config, &self.name);
        let diff = reload::diff_subnets(&current_subnets, &new_subnets);

        // removed → send DEL, subnet-down, del
        let myname = self.name.clone();
        for s in diff.removed {
            let line = SubnetMsg {
                owner: myname.clone(),
                subnet: s,
            }
            .format(Request::DelSubnet, Self::nonce());
            // nw covered by `maybe_set_write_any` at fn end.
            let _nw = self.broadcast_line(&line);
            self.run_subnet_script(false, &myname, &s);
            self.subnets.del(&s, &myname);
            // mac_table sync (rare in practice)
            if let Subnet::Mac { addr, .. } = s {
                self.mac_table.remove(&addr);
            }
        }
        // added → add, send ADD, subnet-up
        for s in diff.added {
            self.subnets.add(s, myname.clone());
            let line = SubnetMsg {
                owner: myname.clone(),
                subnet: s,
            }
            .format(Request::AddSubnet, Self::nonce());
            // nw covered by `maybe_set_write_any` at fn end.
            let _nw = self.broadcast_line(&line);
            self.run_subnet_script(true, &myname, &s);
            if let Subnet::Mac { addr, .. } = s {
                self.mac_table.insert(addr, myname.clone());
            }
        }
        // SIGHUP-reload is rare; unconditional refresh is fine.
        self.tx_snap_refresh_subnets();

        // ─── ConnectTo diff
        let current_ct: BTreeSet<String> = self
            .outgoings
            .iter()
            .map(|(_, o)| o.node_name.clone())
            .collect();
        let new_ct: BTreeSet<String> = parse_connect_to_from_config(&config, &myname)
            .into_iter()
            .collect();
        let (to_add, to_remove) = reload::diff_connect_to(&current_ct, &new_ct);

        // Remove: terminate conn, drop slot+timer.
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

        // ─── host file mtime check
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

        // ConnectTo diff above doesn't read has_address, so order ok.
        self.load_all_nodes();

        self.last_config_check = SystemTime::now();

        self.maybe_set_write_any();

        true
    }

    /// Periodic SPTPS rekey: walk every reachable+validkey tunnel,
    /// call `sptps_force_kex`.
    ///
    /// We arm this timer even though it's traditionally a legacy-
    /// crypto concern: `outseqno` is the ChaCha20-Poly1305 nonce and
    /// wraps at `u32::MAX` with no check. Rekeying every `keylifetime`
    /// seconds keeps it well clear.
    pub(super) fn on_keyexpire(&mut self) {
        log::info!(target: "tincd", "Expiring symmetric keys");

        // Borrow dance: collect (nid, name, outs) first; dispatch_
        // tunnel_outputs needs `&mut self`.
        let mut pending: Vec<(NodeId, String, Vec<tinc_sptps::Output>)> = Vec::new();
        for (&nid, tunnel) in &mut self.dp.tunnels {
            if !tunnel.status.validkey {
                continue;
            }
            // `validkey` is cleared on BecameUnreachable, so
            // validkey ⇒ reachable here.
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
                    // InvalidState: rekey already in flight.
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

        self.timers.set(
            self.keyexpire_timer,
            Duration::from_secs(u64::from(self.settings.keylifetime)),
        );
    }

    // ─── io handlers
}
