use super::{ConnId, Daemon, IoWhat, NodeState};

use std::net::SocketAddr;
use std::os::fd::{AsFd, OwnedFd};
use std::time::Duration;

use crate::conn::Connection;
use crate::listen::fmt_addr;
use crate::outgoing::{
    ConnectAttempt, OutgoingId, ProxyConfig, probe_connecting, try_connect, try_connect_via_proxy,
};
use crate::pmtu::PmtuState;
use crate::proto::parse_ack;
use crate::tunnel::MTU;
use crate::{local_addr, socks};

use nix::fcntl::{FcntlArg, OFlag, fcntl};
use tinc_event::Io;
use tinc_proto::msg::DelEdge;
use tinc_proto::{AddrStr, Request};

use crate::proto::ConnOptions;

impl Daemon {
    /// ACK handler, mutation half. Parse done by `proto::parse_ack`;
    /// this does the world-model edits.
    pub(super) fn on_ack(
        &mut self,
        id: ConnId,
        body: &[u8],
    ) -> Result<bool, crate::proto::DispatchError> {
        let parsed = parse_ack(body)?;
        let conn = self.conn_mut(id);

        // `ack_h:237`: replayed ACK after `allow_request=None` would
        // re-run add_edge + send_everything.
        if conn.active {
            return Err(crate::proto::DispatchError::Unauthorized);
        }

        // PMTU only sticks if BOTH sides set it.
        let mut his = parsed.his_options;
        if !(conn.options & his).contains(ConnOptions::PMTU_DISCOVERY) {
            conn.options.remove(ConnOptions::PMTU_DISCOVERY);
            his.remove(ConnOptions::PMTU_DISCOVERY);
        }
        conn.options |= his;

        // Per-host ClampMSS force-set/force-clear AFTER merging
        // peer's options. Peer asked for ClampMSS but our hosts/NAME
        // says no → we win (local config trumps wire).
        if let Some(clamp) = conn.host_clamp_mss {
            if clamp {
                conn.options.insert(ConnOptions::CLAMP_MSS);
            } else {
                conn.options.remove(ConnOptions::CLAMP_MSS);
            }
        }

        // Per-host AND global PMTU clamp. We init `pmtu` lazily
        // (try_tx); seed it now with the clamp so the first probe
        // cycle starts from a sane ceiling instead of wasting probes
        // above the user's known path MTU. The min(host, global) is
        // computed in proto.rs::handle_id.
        let pmtu_cap = conn.pmtu_cap;

        conn.allow_request = None;

        log::info!(target: "tincd::conn",
                   "Connection with {} ({}) activated",
                   conn.name, conn.hostname);

        // Dup-conn: already have a live conn to this node → new
        // wins, terminate old.
        let name = conn.name.clone();
        let conn_outgoing = conn.outgoing.map(OutgoingId::from);
        let conn_addr = conn.address;
        let edge_addr = conn.address.map(|mut a| {
            // Peer's TCP-source addr, port rewritten to their UDP
            // port ("how do I reach you for data").
            a.set_port(parsed.his_udp_port);
            a
        });
        // midpoint: both weights non-negative so rounding mode is
        // moot. midpoint doesn't overflow.
        let edge_weight = i32::midpoint(parsed.his_weight, conn.estimated_weight);
        let edge_options = conn.options;

        // Reset backoff + add_recent_address. The conn got all the
        // way to ACK — the address WORKED. Idempotent; pinned by
        // tests/addrcache.rs.
        if let Some(oid) = conn_outgoing
            && let Some(o) = self.outgoings.get_mut(oid)
        {
            o.timeout = 0;
            if let Some(a) = conn_addr {
                o.addr_cache.add_recent(a);
            }
            o.addr_cache.reset();
        }

        // Idempotent (peer may already be in graph from transitive
        // ADD_EDGE).
        let peer_id = self.lookup_or_add_node(&name);

        // Seed pmtu (or clamp existing) so try_mtu's `maxmtu` and the
        // eventual fixed `mtu` don't exceed the user-declared ceiling.
        // We also clamp `maxmtu` — the search converges faster and
        // never probes above the cap.
        if let Some(cap) = pmtu_cap {
            let now = self.timers.now();
            let tunnel = self.dp.tunnels.entry(peer_id).or_default();
            let p = tunnel
                .pmtu
                .get_or_insert_with(|| PmtuState::new(now, cap.min(MTU)));
            if p.mtu == 0 || cap < p.mtu {
                p.mtu = cap;
            }
            p.maxmtu = p.maxmtu.min(cap);
        }

        if let Some(old) = self.nodes.get(&peer_id)
            && let Some(old_conn) = old.conn
            && old_conn != id
        {
            log::debug!(target: "tincd::conn",
                                "Established a second connection with {name}, \
                                 closing old connection");
            // `protocol_auth.c::ack_h`: move the dropped conn's
            // `outgoing` onto the survivor before terminating, so
            // `terminate()`'s tail `do_outgoing_connection` doesn't
            // redial. C always keeps the new conn; under mutual
            // `ConnectTo` with symmetric latency that makes each
            // end keep the stream the other end just dropped, so we
            // additionally pick by name: the side with the smaller
            // name keeps its OUTGOING conn. Both ends evaluate this
            // with swapped operands and agree on one TCP stream.
            // Without it every dedup round del-edges →
            // `BecameUnreachable` → `reset_unreachable()` and the
            // tunnel never settles (`tests/reqkey_simultaneous.rs`).
            let new_is_outgoing = conn_outgoing.is_some();
            let old_is_outgoing = self
                .conns
                .get(old_conn)
                .is_some_and(|oc| oc.outgoing.is_some());
            let keep_old = old_is_outgoing != new_is_outgoing
                && old_is_outgoing == (self.name.as_str() < name.as_str());
            let (keep, drop_id) = if keep_old {
                (old_conn, id)
            } else {
                (id, old_conn)
            };
            if let Some(dropped_oid) = self
                .conns
                .get_mut(drop_id)
                .and_then(|dc| dc.outgoing.take())
            {
                match self.conns.get_mut(keep) {
                    Some(kc) if kc.outgoing.is_none() => kc.outgoing = Some(dropped_oid),
                    _ => {
                        // Both conns own an Outgoing (cold-start
                        // duplicate `ConnectTo`). The slot was
                        // already `.take()`n off `drop_id` so
                        // `terminate()` won't see it; reap it here
                        // or it leaks for the daemon lifetime.
                        log::warn!(target: "tincd::conn",
                            "Two outgoing connections to the same node {name}!");
                        let dropped_oid = OutgoingId::from(dropped_oid);
                        if let Some(tid) = self.outgoing_timers.remove(dropped_oid) {
                            self.timers.del(tid);
                        }
                        self.outgoings.remove(dropped_oid);
                    }
                }
            }
            self.terminate(drop_id);
            if keep_old {
                // Old conn's edge/NodeState already in place from
                // its own on_ack; don't fall through and clobber
                // with the now-dead `id`.
                self.run_graph_and_log();
                return Ok(false);
            }
            // graph() covered by unconditional call below.
        }

        // Add ONLY the forward edge. The reverse comes from the
        // PEER's `send_add_edge(everyone)` gossip. SSSP skips edges
        // without a reverse, so our edge is dead until peer's gossip
        // arrives — which it does in the same burst. Do NOT
        // synthesize the reverse: at 3+ nodes the relay's
        // `lookup_edge` would find it, idempotent-return, never
        // forward, and transitive nodes never learn the reverse.
        let fwd_eid = self
            .graph
            .add_edge(self.myself, peer_id, edge_weight, edge_options.bits());

        // getsockname → local_address, port rewritten to myport.udp.
        // SockRef is the non-owning wrapper.
        let local_addr = self.conns.get(id).and_then(|c| {
            let sockref = socket2::SockRef::from(c.owned_fd());
            sockref.local_addr().ok().and_then(|sa| sa.as_socket())
        });
        if let Some(ea) = edge_addr {
            // Ipv6Addr::Display doesn't bracket (matches NI_NUMERICHOST).
            let addr = AddrStr::new(ea.ip().to_string()).expect("numeric IP is whitespace-free");
            let port = AddrStr::new(ea.port().to_string()).expect("numeric");
            // Rewrite local port to OUR udp port (peer sends UDP
            // there, not the ephemeral TCP port).
            let (la, lp) = if let Some(mut local) = local_addr {
                local.set_port(self.my_udp_port);
                (
                    AddrStr::new(local.ip().to_string()).expect("numeric"),
                    AddrStr::new(local.port().to_string()).expect("numeric"),
                )
            } else {
                let unspec = AddrStr::unspec();
                (unspec.clone(), unspec)
            };
            self.edge_addrs.insert(fwd_eid, (addr, port, la, lp));
        }
        self.nodes.insert(
            peer_id,
            NodeState {
                edge: Some(fwd_eid),
                conn: Some(id),
                edge_addr,
                edge_weight,
                edge_options,
            },
        );

        // `active` is the `broadcast_targets` "past ACK" filter. Set
        // BEFORE broadcast so the new conn DOES get its own edge back;
        // receiver's `seen.check` dups it.
        if let Some(conn) = self.conns.get_mut(id) {
            conn.active = true;
            conn.activated_at = Some(self.timers.now());
        }

        // We added the new edge before this call, so we double-send
        // it; peer's `seen.check` dups it. Harmless; not worth
        // skipping fwd_eid.
        let mut nw = self.send_everything(id);

        // tunnelserver: send only to the new peer (hub mode — spokes
        // never learn about each other). Format ONCE then broadcast
        // (one nonce for all targets).
        if let Some(line) = self.fmt_add_edge(fwd_eid, Self::nonce()) {
            if self.settings.tunnelserver {
                if let Some(c) = self.conns.get_mut(id) {
                    nw |= c.send(format_args!("{line}"));
                }
            } else {
                nw |= self.broadcast_line(&line);
            }
        }

        // First time peer becomes reachable.
        self.run_graph_and_log();

        Ok(nw)
    }

    /// Meta-conn WRITE handler.
    pub(super) fn on_conn_writable(&mut self, id: ConnId) {
        let conn = self.conn_mut(id);
        match conn.flush() {
            Ok(true) => {
                // outbuf empty → drop WRITE interest.
                if let Some(&io_id) = self.conn_io.get(id)
                    && let Err(e) = self.ev.set(io_id, Io::Read)
                {
                    log::error!(target: "tincd::conn",
                                    "io_set failed for {id:?}: {e}");
                    self.terminate(id);
                }
            }
            Ok(false) => {} // more to send; stay WRITE
            Err(e) => {
                log::info!(target: "tincd::conn",
                           "Connection write failed: {e}");
                self.terminate(id);
            }
        }
    }

    /// Connection teardown. `conn.active` gates `DEL_EDGE` broadcast
    /// (only past-ACK conns have an edge to delete).
    pub(super) fn terminate(&mut self, id: ConnId) {
        // Deregister from epoll BEFORE closing any fd. epoll keys on
        // the open-file-description; closing the dup'd Connection.fd
        // first makes epoll_ctl(DEL) EBADF (silently swallowed), and
        // if connecting_socks still holds the original socket the
        // description — and thus the epoll interest — survives →
        // level-triggered busy-loop on ERR|HUP into a freed slot.
        if let Some(io_id) = self.conn_io.remove(id) {
            self.ev.del(io_id);
        }

        let Some(conn) = self.conns.remove(id) else {
            // Slotmap is generational; stale ConnId → None. Idempotent.
            return;
        };
        if conn.control {
            log::debug!(target: "tincd::conn",
                        "Closing connection with {}", conn.name);
        } else {
            log::info!(target: "tincd::conn",
                       "Closing connection with {}", conn.name);
        }
        let was_active = conn.active;
        let was_log = conn.log_level.is_some();
        let restore_debug = conn.prev_debug_level;
        let conn_name = conn.name.clone();
        let conn_outgoing = conn.outgoing.map(OutgoingId::from);
        // Pre-ACK conns have no node_ids entry (only on_ack inserts).
        let conn_nid = self.node_ids.get(&conn_name).copied();
        // Drop now: OwnedFd closes; broadcast_line below skips this id.
        drop(conn);

        // If this was a log conn, re-check whether any remain and
        // close the gate if not. Doing this in `terminate` (not just
        // on EOF) covers all teardown paths (REQ_DISCONNECT, ping
        // timeout, error).
        if was_log && !self.conns.values().any(|c| c.log_level.is_some()) {
            crate::log_tap::set_active(false);
        }
        if let Some(prev) = restore_debug {
            crate::log_tap::set_debug_level(prev);
        }

        // Clear the back-ref (node outlives conn).
        let our_edge = conn_nid
            .and_then(|nid| self.nodes.get_mut(&nid))
            .and_then(|ns| {
                if ns.conn == Some(id) {
                    ns.conn = None;
                    ns.edge.take()
                } else {
                    None
                }
            });

        // Edge cleanup. Only fires post-ACK.
        if let Some(eid) = our_edge {
            if was_active && !self.settings.tunnelserver {
                let to_name = conn_name.clone();
                let my_name = self.name.clone();
                let line = DelEdge {
                    from: my_name,
                    to: to_name,
                }
                .format(Self::nonce());
                // nw covered by `maybe_set_write_any` below.
                let _nw = self.broadcast_line(&line);
            }

            self.graph.del_edge(eid);
            self.edge_addrs.remove(&eid);

            self.run_graph_and_log();

            // Reverse-edge cleanup if peer now unreachable.
            let peer_unreachable = conn_nid
                .and_then(|nid| self.graph.node(nid))
                .is_some_and(|n| !n.reachable);
            if was_active
                && peer_unreachable
                && let Some(peer_nid) = conn_nid
                && let Some(rev) = self.graph.lookup_edge(peer_nid, self.myself)
            {
                if !self.settings.tunnelserver {
                    let line = DelEdge {
                        from: conn_name.clone(),
                        to: self.name.clone(),
                    }
                    .format(Self::nonce());
                    // nw covered by `maybe_set_write_any` below
                    // (this is the `97ef5af0` callsite that exposed
                    // the bug class; `#[must_use]` now guards it).
                    let _nw = self.broadcast_line(&line);
                }
                self.graph.del_edge(rev);
                self.edge_addrs.remove(&rev);
            }

            // `broadcast_line` queues to outbuf but doesn't arm WRITE
            // (it returns `nw` for the caller to do that). With
            // pinginterval=60, the next natural write arm is up to a
            // minute away — the DEL_EDGE sits in outbuf and the mesh
            // never learns this peer died. We're edge-triggered
            // epoll. Exposed by the purge integration test (mid
            // never gossips bob's death to alice).
            self.maybe_set_write_any();
        }

        // Outgoing retry. C tinc retries UNCONDITIONALLY on `c->
        // outgoing` (net.c:160). The previous `was_active` gate here
        // wedged a pre-ACK timeout from the ping sweep forever:
        // `on_ping_tick` calls `terminate()` directly (not via
        // `on_connecting`), so nothing else re-drives the outgoing.
        // Exposed by `stress_link_flap`: lo-down during connect →
        // "Timeout while connecting" → conn dropped, no retry ever
        // scheduled → reconnect never happens after lo-up.
        if let Some(oid) = conn_outgoing.filter(|oid| self.outgoings.contains_key(*oid)) {
            // Reset backoff only if the conn got to ACK (proven-good
            // addr). Pre-ACK → keep the bumped backoff.
            if was_active && let Some(o) = self.outgoings.get_mut(oid) {
                o.timeout = 0;
            }
            self.do_outgoing_connection(oid);
        }
    }

    // ─── outgoing connections

    /// Non-blocking drain of the off-thread resolver into
    /// `dns_hints` / `proxy_addrs`, plus an `extend_resolved` push
    /// into any live `AddressCache` for the same node so a result
    /// that lands mid-round is usable without waiting for the next
    /// `reset`. Called from `on_periodic_tick` and at the top of
    /// `setup_outgoing_connection` (timer ordering between
    /// `RetryOutgoing` and `Periodic` isn't guaranteed).
    pub(super) fn drain_dns_worker(&mut self) {
        use crate::bgresolve::{DnsRes, DnsTag};
        for DnsRes { tag, addrs } in self.dns_worker.drain() {
            match tag {
                DnsTag::Outgoing(node) if !addrs.is_empty() => {
                    for o in self.outgoings.values_mut().filter(|o| o.node_name == node) {
                        o.addr_cache.extend_resolved(addrs.iter().copied());
                    }
                    self.dns_hints.insert(node, addrs);
                }
                DnsTag::Outgoing(_) => {}
                DnsTag::Proxy => self.proxy_addrs = addrs,
            }
        }
    }

    /// Kick off (or short-circuit) the SOCKS/HTTP proxy host resolve.
    /// Literal IPs fill `proxy_addrs` synchronously so the common
    /// `Proxy = socks5 127.0.0.1 9050` works on the first dial;
    /// hostnames are queued on the worker (dedup'd there). No-op when
    /// no proxy is configured or the cache is already populated.
    pub(super) fn request_proxy_resolve(&mut self) {
        if !self.proxy_addrs.is_empty() {
            return;
        }
        let Some((host, port)) = self
            .settings
            .proxy
            .as_ref()
            .and_then(ProxyConfig::proxy_addr)
        else {
            return;
        };
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            self.proxy_addrs = vec![SocketAddr::new(ip, port)];
        } else {
            self.dns_worker.request(
                crate::bgresolve::DnsTag::Proxy,
                vec![(host.to_owned(), port)],
            );
        }
    }

    pub(super) fn setup_outgoing_connection(&mut self, oid: OutgoingId) {
        // No timer del: the timer can't fire mid-connect (we don't
        // return to run() until exit); next `retry_outgoing` `set`
        // overwrites anyway.

        // Drain DNS results first: this fn is reached from the
        // `RetryOutgoing` timer at the same +5s cadence as
        // `Periodic`, and timer ordering isn't guaranteed. A drain
        // here makes worker results visible to *this* retry instead
        // of the next one. Non-blocking; near-free when empty.
        self.drain_dns_worker();

        let Some(outgoing) = self.outgoings.get(oid) else {
            return; // gone (chunk 8's mark-sweep)
        };
        let name = outgoing.node_name.clone();

        // No node_ids entry = never ACK'd.
        let nid = self.node_ids.get(&name).copied();
        if nid
            .and_then(|nid| self.nodes.get(&nid))
            .and_then(|ns| ns.conn)
            .is_some()
        {
            log::info!(target: "tincd::conn",
                       "Already connected to {name}");
            return;
        }

        // Edge-walk for known addresses. Walk eagerly here (still
        // per-retry: `RetryOutgoing` timer → this fn → fresh graph
        // snapshot). Walk bob's OUTgoing edges and read the reverse's
        // address: the reverse of bob→alice is alice→bob, whose
        // address field is what alice's `ADD_EDGE` reported for bob
        // ("I see bob at 10.0.0.5:655"). Skip reverseless edges
        // (gossip half-arrived). If bob was never gossiped (no
        // `node_ids` entry), `nid` is `None` and tier 2 stays empty.
        let known: Vec<SocketAddr> = nid
            .into_iter()
            .flat_map(|n| self.graph.node_edges(n).iter().copied())
            .filter_map(|eid| self.graph.edge(eid)?.reverse)
            .filter_map(|rev| {
                let (addr, port, _, _) = self.edge_addrs.get(&rev)?;
                local_addr::parse_addr_port(addr.as_str(), port.as_str())
            })
            // DHT hints chained AFTER edge-walk: edge addrs are
            // observed-live, DHT addrs are self-report (≤5min stale).
            // Empty unless `retry_outgoing` fired → degrades to C
            // edge-walk. `add_known_addresses` dedups.
            .chain(self.dht_hints.get(&name).into_iter().flatten().copied())
            // Same gate as `discovery::parse_record`: ADD_EDGE addrs
            // are peer-authored gossip, dht_hints are peer self-
            // report. Neither may steer us at loopback/link-local.
            .filter(|sa| !crate::addr::is_unwanted_dial_addr(sa))
            // Off-thread getaddrinfo results for `Address=` hostnames
            // are operator-authored config, NOT peer input — chain
            // them *after* the unwanted-addr gate so e.g.
            // `Address = localhost 655` keeps working.
            .chain(self.dns_hints.get(&name).into_iter().flatten().copied())
            .collect();
        // get_mut after the read-only walk (split borrow).
        if let Some(o) = self.outgoings.get_mut(oid) {
            o.addr_cache.add_known_addresses(known);
            // Pre-resolve hostname `Address=` lines for *this* round.
            // No-op for the common all-literal-IP config (NixOS test
            // fixtures). Fired here (not at `open()`) because
            // `add_known_addresses` resets the cursor anyway, and
            // every retry re-enters via this fn.
            let hosts = o.addr_cache.unresolved_hosts();
            if !hosts.is_empty() {
                self.dns_worker
                    .request(crate::bgresolve::DnsTag::Outgoing(name), hosts);
            }
        }

        self.do_outgoing_connection(oid);
    }

    /// Walk addr cache, register first non-sync-fail.
    /// `PROXY_EXEC`: socketpair+fork, skip async probe. `PROXY_SOCKS`/
    /// HTTP: connect to PROXY addr; peer addr still walked (it's the
    /// CONNECT target).
    pub(super) fn do_outgoing_connection(&mut self, oid: OutgoingId) {
        loop {
            let Some(outgoing) = self.outgoings.get_mut(oid) else {
                return;
            };
            let name = outgoing.node_name.clone();

            // ─── PROXY_EXEC
            // Walk addr cache for env vars; fd is socketpair half
            // (no probe).
            if let Some(ProxyConfig::Exec { cmd }) = self.settings.proxy.clone() {
                let Some(addr) = outgoing.addr_cache.next_addr() else {
                    log::error!(target: "tincd::conn",
                                "Could not set up a meta connection to {name}");
                    self.retry_outgoing(oid);
                    return;
                };
                log::info!(target: "tincd::conn",
                            "Trying to connect to {name} ({addr}) via proxy exec");
                let fd = match crate::outgoing::do_outgoing_pipe(&cmd, addr, &name, &self.name) {
                    Ok(fd) => fd,
                    Err(e) => {
                        log::error!(target: "tincd::conn",
                                    "Proxy exec failed for {name}: {e}");
                        continue; // try next addr
                    }
                };
                let flags = OFlag::from_bits_truncate(fcntl(&fd, FcntlArg::F_GETFL).unwrap_or(0));
                let _ = fcntl(&fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK));
                // No async connect; ready NOW.
                let now = self.timers.now();
                let mut conn = Connection::new_outgoing(
                    fd,
                    name.clone(),
                    fmt_addr(&addr),
                    addr,
                    slotmap::Key::data(&oid),
                    now,
                );
                conn.connecting = false;
                let id = self.conns.insert(conn);
                match self
                    .ev
                    .add(self.conns[id].as_fd(), Io::Read, IoWhat::Conn(id))
                {
                    Ok(io_id) => {
                        self.conn_io.insert(id, io_id);
                    }
                    Err(e) => {
                        log::error!(target: "tincd::conn",
                                    "io_add failed: {e}");
                        self.conns.remove(id);
                        continue;
                    }
                }
                // Proxy is transport; peer expects ID.
                if let Some(conn) = self.conns.get_mut(id) {
                    log::info!(target: "tincd::conn",
                                "Connected to {} ({}) via proxy exec",
                                conn.name, conn.hostname);
                    let needs_write = conn.send(format_args!(
                        "{} {} {}.{}",
                        Request::Id,
                        self.name,
                        tinc_proto::request::PROT_MAJOR,
                        tinc_proto::request::PROT_MINOR
                    ));
                    if needs_write
                        && let Some(&io_id) = self.conn_io.get(id)
                        && let Err(e) = self.ev.set(io_id, Io::ReadWrite)
                    {
                        log::error!(target: "tincd::conn",
                                            "io_set failed: {e}");
                        self.terminate(id);
                    }
                }
                return;
            }

            // ─── SOCKS/HTTP: connect to PROXY addr.
            // Addr cache still walks PEER addrs (CONNECT target
            // varies).
            let proxy_hp = self
                .settings
                .proxy
                .as_ref()
                .and_then(ProxyConfig::proxy_addr);
            let attempt = if proxy_hp.is_some() {
                let Some(peer_addr) = outgoing.addr_cache.next_addr() else {
                    log::error!(target: "tincd::conn",
                                "Could not set up a meta connection to {name}");
                    self.retry_outgoing(oid);
                    return;
                };
                // Pre-resolved off-thread (setup) and refreshed in
                // `retry_outgoing`. Empty ⇒ worker hasn't answered
                // yet, or NXDOMAIN — either way back off; the retry
                // timer re-drives once the worker fills it.
                let Some(&proxy_addr) = self.proxy_addrs.first() else {
                    log::error!(target: "tincd::conn",
                                "Proxy address not resolved (yet) for {name}");
                    self.retry_outgoing(oid);
                    return;
                };
                try_connect_via_proxy(proxy_addr, peer_addr, &name, &self.settings.sockopts)
            } else {
                try_connect(
                    &mut outgoing.addr_cache,
                    &name,
                    self.settings.bind_to_address,
                    &self.settings.sockopts,
                )
            };

            match attempt {
                ConnectAttempt::Started { sock, addr } => {
                    // WRITE registration triggers `on_connecting`
                    // when kernel finishes async connect.
                    let now = self.timers.now();
                    // ONE fd, ONE owner. probe_connecting() takes a
                    // BorrowedFd from Connection.fd; no dup, no
                    // second map. (An earlier shape dup'd into a
                    // separate `connecting_socks` map — two fds on
                    // one open-file-description → epoll-interest
                    // leak → 100% CPU busy-loop on the pre-ACK
                    // timeout path. See netns/busyloop.rs.)
                    let fd = OwnedFd::from(sock);
                    let conn = Connection::new_outgoing(
                        fd,
                        name,
                        fmt_addr(&addr),
                        addr,
                        slotmap::Key::data(&oid),
                        now,
                    );
                    let id = self.conns.insert(conn);
                    // IO_READ|IO_WRITE. EPOLLOUT fires on connect
                    // complete OR fail. READ too (loopback connect+
                    // immediate-data is possible).
                    match self
                        .ev
                        .add(self.conns[id].as_fd(), Io::ReadWrite, IoWhat::Conn(id))
                    {
                        Ok(io_id) => {
                            self.conn_io.insert(id, io_id);
                        }
                        Err(e) => {
                            log::error!(target: "tincd::conn",
                                        "io_add failed: {e}");
                            self.conns.remove(id);
                            continue;
                        }
                    }
                    return;
                }
                ConnectAttempt::Retry => {}
                ConnectAttempt::Exhausted => {
                    self.retry_outgoing(oid);
                    return;
                }
            }
        }
    }

    /// Exponential backoff for outgoing retry. No jitter: loop tick
    /// rate already desyncs identical-config daemons.
    pub(super) fn retry_outgoing(&mut self, oid: OutgoingId) {
        let Some(outgoing) = self.outgoings.get_mut(oid) else {
            return;
        };
        let timeout = outgoing.bump_timeout(self.settings.maxtimeout);
        // Reset HERE so next retry walks from top.
        outgoing.addr_cache.reset();
        let name = outgoing.node_name.clone();
        log::info!(target: "tincd::conn",
                   "Trying to re-establish outgoing connection in {timeout} seconds");
        if let Some(&tid) = self.outgoing_timers.get(oid) {
            self.timers
                .set(tid, Duration::from_secs(u64::from(timeout)));
        }

        // Clear the DNS hint map so the next `setup_outgoing_
        // connection` chains *fresh* DNS, not the addrs that just
        // failed. The re-queue itself happens there too (single call
        // site, dedup'd in the worker).
        self.dns_hints.remove(&name);
        // Proxy host re-resolve: only fires while the cache is empty
        // (NXDOMAIN or worker hasn't answered). A working proxy addr
        // is stable for the daemon lifetime.
        self.request_proxy_resolve();

        // Addr cache exhausted (every `retry_outgoing` call site is
        // reached via `next_addr()==None`). Fire-and-forget resolve;
        // result lands in `dht_hints` via `on_periodic_tick`, next
        // retry reads it. Clear stale hints (a previous resolve gave
        // addrs, connect still failed ⇒ record outdated). Dedup is
        // inside `request_resolve` — can't storm.
        if let Some(d) = self.discovery.as_mut() {
            self.dht_hints.remove(&name);
            // Same pubkey-read as `gossip.rs::on_req_key`. No key →
            // no resolve (couldn't verify SPTPS anyway).
            let host_file = self.confbase.join("hosts").join(&name);
            if let Ok(entries) = tinc_conf::parse_file(&host_file) {
                let mut cfg = tinc_conf::Config::default();
                cfg.merge(entries);
                if let Some(key) = crate::keys::read_ecdsa_public_key(&cfg, &self.confbase, &name) {
                    d.request_resolve(&name, key);
                }
            }
        }
    }

    /// Async connect completion check. Returns `true` to fall through
    /// to write/read. Fall-through saves a loop iteration: the socket
    /// is writable now and the ID line is queued. (LT would re-fire
    /// next turn anyway; this just avoids the round-trip.)
    pub(super) fn on_connecting(&mut self, id: ConnId) -> bool {
        let Some(conn) = self.conns.get(id) else {
            log::warn!(target: "tincd::conn",
                       "on_connecting: no conn for {id:?}");
            self.terminate(id);
            return false;
        };
        match probe_connecting(conn.owned_fd().as_fd()) {
            Ok(true) => {
                self.finish_connecting(id);
                true
            }
            Ok(false) => false, // spurious
            Err(e) => {
                // was_active=false (no edge yet) → terminate won't
                // gossip DEL_EDGE.
                let (name, hostname) = self
                    .conns
                    .get(id)
                    .map(|c| (c.name.clone(), c.hostname.clone()))
                    .unwrap_or_default();
                log::debug!(target: "tincd::conn",
                            "Error while connecting to {name} ({hostname}): {e}");
                // terminate() now re-drives do_outgoing_connection
                // for any conn that maps to an Outgoing (C parity);
                // no need to drive it again here.
                self.terminate(id);
                false
            }
        }
    }

    /// `add_recent_address` is deferred to `on_ack` (the right port
    /// alone doesn't mean tinc).
    pub(super) fn finish_connecting(&mut self, id: ConnId) {
        let Some(conn) = self.conns.get_mut(id) else {
            return;
        };
        log::info!(target: "tincd::conn",
                   "Connected to {} ({})", conn.name, conn.hostname);
        conn.last_ping_time = self.timers.now();
        conn.connecting = false;

        // send_proxyrequest BEFORE send_id. Both queue into outbuf,
        // flush in one send(). Pipelining is intentional: proxy
        // buffers the ID line while processing greeting.
        let mut needs_write = false;
        if let (true, Some(proxy)) = (conn.outgoing.is_some(), &self.settings.proxy) {
            match proxy {
                ProxyConfig::Exec { .. } => {
                    // Unreachable (Exec skips finish_connecting);
                    // arm makes match exhaustive.
                }
                ProxyConfig::Http { .. } => {
                    // send() appends `\n` → wire is `CONNECT h:p
                    // HTTP/1.1\r\n\r\n`. No Host: header (RFC 7230
                    // §5.4 violation; proxies accept it). conn.
                    // address is the PEER addr (proxy is transport).
                    let Some(target) = conn.address else {
                        log::error!(target: "tincd::conn",
                            "HTTP proxy: no peer address on {}", conn.name);
                        self.terminate(id);
                        return;
                    };
                    // Bracket IPv6 (RFC 7230 §2.7.1). `CONNECT
                    // ::1:655` would be ambiguous. SocketAddr::
                    // Display brackets v6.
                    let line = format!("CONNECT {target} HTTP/1.1\r\n\r\n");
                    needs_write |= conn.send_raw(line.as_bytes());
                    log::debug!(target: "tincd::conn",
                        "Queued HTTP CONNECT for {} → {target}", conn.name);
                    // No tcplen — response is line-based.
                }
                ProxyConfig::Socks4 { .. } | ProxyConfig::Socks5 { .. } => {
                    // Target = PEER addr.
                    let Some(target) = conn.address else {
                        log::error!(target: "tincd::conn",
                            "SOCKS proxy: no peer address on {}", conn.name);
                        self.terminate(id);
                        return;
                    };
                    let socks_type = proxy.socks_type().expect("Socks4/5 arm");
                    let creds = proxy.socks_creds();
                    match socks::build_request(socks_type, target, creds.as_ref()) {
                        Ok((bytes, resp_len)) => {
                            needs_write |= conn.send_raw(&bytes);
                            // SOCKS reply ≤ 26 bytes (SOCKS5 max), fits u16
                            #[allow(clippy::cast_possible_truncation)]
                            {
                                conn.tcplen = resp_len as u16;
                            }
                            log::debug!(target: "tincd::conn",
                                "Queued {} SOCKS bytes for {}, expecting {} reply bytes",
                                bytes.len(), conn.name, resp_len);
                        }
                        Err(e) => {
                            // SOCKS4+IPv6, or 256-byte cred.
                            log::error!(target: "tincd::conn",
                                "SOCKS request build failed for {}: {e:?}",
                                conn.name);
                            self.terminate(id);
                            return;
                        }
                    }
                }
            }
        }

        // send_id. WE go first (initiator); peer replies.
        // Split borrow: helper would lock all of `self`.
        let conn = self.conns.get_mut(id).expect("ConnId not live");
        needs_write |= conn.send(format_args!(
            "{} {} {}.{}",
            Request::Id,
            self.name,
            tinc_proto::request::PROT_MAJOR,
            tinc_proto::request::PROT_MINOR
        ));

        // Re-register: was ReadWrite (probe); now READ (or RW if
        // queued).
        if let Some(&io_id) = self.conn_io.get(id) {
            let interest = if needs_write { Io::ReadWrite } else { Io::Read };
            if let Err(e) = self.ev.set(io_id, interest) {
                log::error!(target: "tincd::conn",
                            "io_set failed for {id:?}: {e}");
                self.terminate(id);
            }
        }
    }
}
