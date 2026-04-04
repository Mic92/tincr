#[allow(clippy::wildcard_imports)]
use super::*;

use nix::fcntl::{FcntlArg, OFlag, fcntl};

use crate::proto::ConnOptions;

impl Daemon {
    /// `ack_h` mutation half (`protocol_auth.c:965-1064`). Parse done
    /// by `proto::parse_ack`; this does the world-model edits.
    #[allow(clippy::too_many_lines)] // C `ack_h` is 116 lines; close port
    pub(super) fn on_ack(
        &mut self,
        id: ConnId,
        body: &[u8],
    ) -> Result<bool, crate::proto::DispatchError> {
        let parsed = parse_ack(body)?;
        let conn = self.conns.get_mut(id).expect("caller checked");

        // C `:948-950` upgrade_h: unreachable (id_h rejected minor < 2).

        // C `:996-999`: PMTU only sticks if BOTH sides set it.
        let mut his = parsed.his_options;
        if !(conn.options & his).contains(ConnOptions::PMTU_DISCOVERY) {
            conn.options.remove(ConnOptions::PMTU_DISCOVERY);
            his.remove(ConnOptions::PMTU_DISCOVERY);
        }
        conn.options |= his;

        // C `:1011-1017`: per-host ClampMSS force-set/force-clear AFTER
        // merging peer's options. Peer asked for ClampMSS but our
        // hosts/NAME says no → we win (local config trumps wire).
        if let Some(clamp) = conn.host_clamp_mss {
            if clamp {
                conn.options.insert(ConnOptions::CLAMP_MSS);
            } else {
                conn.options.remove(ConnOptions::CLAMP_MSS);
            }
        }

        // C `:1003-1009`: per-host PMTU clamp on `n->mtu`. C `node.c:84`
        // inits `n->mtu = MTU` so the `< n->mtu` check passes for any
        // sane config. We init `pmtu` lazily (try_tx); seed it now
        // with the clamp so the first probe cycle starts from a sane
        // ceiling instead of wasting probes above the user's known
        // path MTU. Global `PMTU` (`:1007`) deferred (separate gap).
        let host_pmtu = conn.host_pmtu;

        conn.allow_request = None; // C `:1023`

        log::info!(target: "tincd::conn",
                   "Connection with {} ({}) activated",
                   conn.name, conn.hostname);

        // C `:965-994`: lookup_node / node_add. Dup-conn (`:975-990`):
        // already have a live conn to this node → new wins, terminate old.
        let name = conn.name.clone();
        let conn_outgoing = conn.outgoing.map(OutgoingId::from);
        let conn_addr = conn.address;
        let edge_addr = conn.address.map(|mut a| {
            // C `:1024-1025`: peer's TCP-source addr, port rewritten
            // to their UDP port ("how do I reach you for data").
            a.set_port(parsed.his_udp_port);
            a
        });
        // C `:1048`: `(weight + estimated) / 2`. midpoint rounds toward
        // neg-inf vs C's truncate-to-zero, but both weights non-negative
        // so identical. midpoint doesn't overflow (C is UB at 24-day RTT).
        let edge_weight = i32::midpoint(parsed.his_weight, conn.estimated_weight);
        let edge_options = conn.options;

        // C `protocol_misc.c:69-73` + `graph.c:238`: reset backoff +
        // add_recent_address. We do it ungated here, slightly earlier
        // than C (idempotent; pinned by tests/addrcache.rs). The conn
        // got all the way to ACK — the address WORKED.
        if let Some(oid) = conn_outgoing
            && let Some(o) = self.outgoings.get_mut(oid)
        {
            o.timeout = 0;
            if let Some(a) = conn_addr {
                o.addr_cache.add_recent(a);
            }
            o.addr_cache.reset(); // C `address_cache.c:251`
        }

        // C `:965-991`: lookup_node BEFORE dup-conn check. Idempotent
        // (peer may already be in graph from transitive ADD_EDGE).
        let peer_id = self.lookup_or_add_node(&name);

        // C `:1003-1005` `n->mtu = mtu`. Runs after node_add, before
        // edge_add. Seed pmtu (or clamp existing) so try_mtu's `maxmtu`
        // and the eventual fixed `mtu` don't exceed the user-declared
        // ceiling. C only writes `n->mtu` (probes still binary-search
        // 0..MTU); we also clamp `maxmtu` — strictly better, the
        // search converges faster and never probes above the cap.
        if let Some(cap) = host_pmtu {
            let now = self.timers.now();
            let tunnel = self.tunnels.entry(peer_id).or_default();
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
            // C `:976-978`
            log::debug!(target: "tincd::conn",
                                "Established a second connection with {name}, \
                                 closing old connection");
            self.terminate(old_conn);
            // C `:989` graph() covered by unconditional call below.
        }

        // C `:1032-1051`: `c->edge = new_edge(); edge_add()`. We add
        // ONLY the forward edge (`:1051`). The reverse comes from the
        // PEER's `send_add_edge(everyone)` gossip (their `:1058`). SSSP
        // skips edges without a reverse (`graph.c:159`), so our edge is
        // dead until peer's gossip arrives — which it does in the same
        // burst. Do NOT synthesize the reverse: at 3+ nodes the relay's
        // `lookup_edge` would find it, idempotent-return, never forward,
        // and transitive nodes never learn the reverse.
        let fwd_eid = self
            .graph
            .add_edge(self.myself, peer_id, edge_weight, edge_options.bits());

        // C `:1040-1045`: getsockname → local_address, port rewritten
        // to myport.udp. SockRef is the non-owning wrapper.
        let local_addr = self.conns.get(id).and_then(|c| {
            let sockref = socket2::SockRef::from(c.owned_fd());
            sockref.local_addr().ok().and_then(|sa| sa.as_socket())
        });
        if let Some(ea) = edge_addr {
            // Ipv6Addr::Display doesn't bracket (matches NI_NUMERICHOST).
            let addr = AddrStr::new(ea.ip().to_string()).expect("numeric IP is whitespace-free");
            let port = AddrStr::new(ea.port().to_string()).expect("numeric");
            // C `:1042-1045`: rewrite local port to OUR udp port (peer
            // sends UDP there, not the ephemeral TCP port).
            let (la, lp) = if let Some(mut local) = local_addr {
                local.set_port(self.my_udp_port);
                (
                    AddrStr::new(local.ip().to_string()).expect("numeric"),
                    AddrStr::new(local.port().to_string()).expect("numeric"),
                )
            } else {
                let unspec = AddrStr::new(AddrStr::UNSPEC).expect("literal");
                (unspec.clone(), unspec)
            };
            self.edge_addrs.insert(fwd_eid, (addr, port, la, lp));
        }
        // C `:993-994` + `:1051`: `n->connection = c; c->edge = e`.
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

        // C `:1051`: `c->edge = e` is the `broadcast_meta` (`meta.c:115`)
        // "past ACK" filter. C ordering: `:1051` is AFTER `:1028`
        // (send_everything) but BEFORE `:1058` (broadcast) — so the new
        // conn DOES get its own edge back; receiver's `seen.check` dups it.
        // Match: set active BEFORE broadcast.
        if let Some(conn) = self.conns.get_mut(id) {
            conn.active = true;
        }

        // C `:1028`: `send_everything(c)`. C runs this BEFORE `:1051`
        // edge_add, so C doesn't include the new edge. We added it
        // earlier (line ordering for NodeState.edge), so we double-send;
        // peer's `seen.check` dups it. Harmless; not worth skipping fwd_eid.
        let mut nw = self.send_everything(id);

        // C `:1055-1059`: `send_add_edge(everyone, c->edge)`.
        // tunnelserver: send only to the new peer (hub mode — spokes
        // never learn about each other). Format ONCE then broadcast
        // (one nonce for all targets, per `send_request:122`).
        if let Some(line) = self.fmt_add_edge(fwd_eid, Self::nonce()) {
            if self.settings.tunnelserver {
                if let Some(c) = self.conns.get_mut(id) {
                    nw |= c.send(format_args!("{line}"));
                }
            } else {
                nw |= self.broadcast_line(&line);
            }
        }

        // C `:1065`: `graph()`. First time peer becomes reachable.
        self.run_graph_and_log();

        Ok(nw)
    }

    /// `handle_meta_io` WRITE path → `handle_meta_write`
    /// (`net_socket.c:486-511`).
    pub(super) fn on_conn_writable(&mut self, id: ConnId) {
        let conn = self.conns.get_mut(id).expect("checked contains_key");
        match conn.flush() {
            Ok(true) => {
                // C `:509-511`: outbuf empty → io_set IO_READ.
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
                // C `:502-504`
                log::info!(target: "tincd::conn",
                           "Connection write failed: {e}");
                self.terminate(id);
            }
        }
    }

    /// `terminate_connection` (`net.c:118-170`). C's `report` flag
    /// (`:128`) gates DEL_EDGE broadcast; we test `conn.active`
    /// (same condition: `report = c->edge != NULL` at call sites).
    pub(super) fn terminate(&mut self, id: ConnId) {
        let Some(conn) = self.conns.remove(id) else {
            // Slotmap is generational; stale ConnId → None. Idempotent.
            if let Some(io_id) = self.conn_io.remove(id) {
                self.ev.del(io_id);
            }
            return;
        };
        log::info!(target: "tincd::conn",
                   "Closing connection with {}", conn.name);
        let was_active = conn.active;
        let conn_name = conn.name.clone();
        // Pre-ACK conns have no node_ids entry (only on_ack inserts).
        let conn_nid = self.node_ids.get(&conn_name).copied();
        // Drop now: OwnedFd closes; broadcast_line below skips this id.
        drop(conn);

        if let Some(io_id) = self.conn_io.remove(id) {
            self.ev.del(io_id);
        }

        // C `:121-123`: clear the back-ref (node outlives conn).
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

        // C `:126-152`: edge cleanup. Only fires post-ACK (`:1051` set c->edge).
        if let Some(eid) = our_edge {
            // C `:127-129`: `if(report && !tunnelserver) send_del_edge(everyone)`.
            if was_active && !self.settings.tunnelserver {
                let to_name = conn_name.clone();
                let my_name = self.name.clone();
                let line = DelEdge {
                    from: my_name,
                    to: to_name,
                }
                .format(Self::nonce());
                self.broadcast_line(&line);
            }

            // C `:131-132`
            self.graph.del_edge(eid);
            self.edge_addrs.remove(&eid);

            // C `:136`
            self.run_graph_and_log();

            // C `:140-152`: reverse-edge cleanup if peer now unreachable.
            let peer_unreachable = conn_nid
                .and_then(|nid| self.graph.node(nid))
                .is_some_and(|n| !n.reachable);
            if was_active
                && peer_unreachable
                && let Some(peer_nid) = conn_nid
                && let Some(rev) = self.graph.lookup_edge(peer_nid, self.myself)
            {
                // C `:144-146`
                if !self.settings.tunnelserver {
                    let line = DelEdge {
                        from: conn_name.clone(),
                        to: self.name.clone(),
                    }
                    .format(Self::nonce());
                    self.broadcast_line(&line);
                }
                self.graph.del_edge(rev); // C `:149`
                self.edge_addrs.remove(&rev);
            }

            // `broadcast_line` queues to outbuf but doesn't arm WRITE
            // (it returns `nw` for the caller to do that). With
            // pinginterval=60, the next natural write arm is up to a
            // minute away — the DEL_EDGE sits in outbuf and the mesh
            // never learns this peer died. C is push-based (`send_
            // request` writes synchronously, `meta.c:98`); we're
            // edge-triggered epoll. Exposed by the purge integration
            // test (mid never gossips bob's death to alice).
            self.maybe_set_write_any();
        }

        // C `net.c:155-161`: outgoing retry. C runs `:161` unconditionally;
        // we gate on was_active because a probe-fail is already handled
        // by `on_connecting`→`do_outgoing_connection` directly (no double-retry).
        if was_active
            && conn_nid.is_some_and(|nid| self.nodes.contains_key(&nid))
            // Can't read `conn.outgoing` (conn already dropped).
            // Look it up by name in `outgoings`.
            && let Some(oid) = self
                .outgoings
                .iter()
                .find(|(_, o)| o.node_name == conn_name)
                .map(|(id, _)| id)
        {
            // Reset backoff: a conn that got to ACK had a working addr.
            if let Some(o) = self.outgoings.get_mut(oid) {
                o.timeout = 0;
            }
            self.do_outgoing_connection(oid);
        }
    }

    // ─── outgoing connections (`net_socket.c:405-681`)

    /// `setup_outgoing_connection` (`net_socket.c:664-681`).
    pub(super) fn setup_outgoing_connection(&mut self, oid: OutgoingId) {
        // C `:666` timeout_del: not ported. tinc-event's `del` frees
        // the slot but we want to keep it. Safe to skip: the timer
        // can't fire mid-connect (we don't return to run() until exit);
        // next `retry_outgoing` `set` overwrites anyway.

        let Some(outgoing) = self.outgoings.get(oid) else {
            return; // gone (chunk 8's mark-sweep)
        };
        let name = outgoing.node_name.clone();

        // C `:674-676`: `if(n->connection)`. No node_ids entry = never ACK'd.
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

        // `get_known_addresses` (`address_cache.c:31-65`) edge-walk.
        // C does this lazily inside `get_recent_address:128-129` after
        // tier 1 is exhausted; we walk eagerly here (still per-retry:
        // `RetryOutgoing` timer → this fn → fresh graph snapshot). C
        // `reset_address_cache:261-263` frees `cache->ai` so each
        // retry re-walks too — same churn-tolerance, different timing.
        //
        // C walks `n->edge_tree` (bob's OUTgoing edges) and reads
        // `e->reverse->address`. The reverse of bob→alice is alice→
        // bob, whose address field is what alice's `ADD_EDGE` reported
        // for bob ("I see bob at 10.0.0.5:655"). C `:36-37` skips
        // reverseless edges (gossip half-arrived).
        //
        // We don't have an `n->edge_tree` for unknown nodes — if bob
        // was never gossiped (no `node_ids` entry), `nid` is `None`
        // and tier 2 stays empty. Same as C: no node, no edges.
        let known: Vec<SocketAddr> = nid
            .into_iter()
            .flat_map(|n| self.graph.node_edges(n).iter().copied())
            .filter_map(|eid| self.graph.edge(eid)?.reverse)
            .filter_map(|rev| {
                let (addr, port, _, _) = self.edge_addrs.get(&rev)?;
                local_addr::parse_addr_port(addr.as_str(), port.as_str())
            })
            .collect();
        // get_mut after the read-only walk (split borrow).
        if let Some(o) = self.outgoings.get_mut(oid) {
            o.addr_cache.add_known_addresses(known);
        }

        self.do_outgoing_connection(oid); // C `:678`
    }

    /// `do_outgoing_connection` (`net_socket.c:564-662`). The `goto
    /// begin` loop: walk addr cache, register first non-sync-fail.
    /// PROXY_EXEC (`:588,:631`): socketpair+fork, skip async probe.
    /// PROXY_SOCKS/HTTP (`:590-601,:637`): connect to PROXY addr;
    /// peer addr still walked (it's the CONNECT target).
    #[allow(clippy::too_many_lines)] // PROXY_EXEC is a parallel path; C is 98 lines, we're ~119
    pub(super) fn do_outgoing_connection(&mut self, oid: OutgoingId) {
        loop {
            let Some(outgoing) = self.outgoings.get_mut(oid) else {
                return;
            };
            let name = outgoing.node_name.clone();

            // ─── PROXY_EXEC (C `:588-590`, `:631`)
            // Walk addr cache for env vars; fd is socketpair half (no probe).
            if let Some(ProxyConfig::Exec { cmd }) = self.settings.proxy.clone() {
                let Some(addr) = outgoing.addr_cache.next_addr() else {
                    // C `:572-575`
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
                        continue; // C `:605-608` goto begin
                    }
                };
                let flags = OFlag::from_bits_truncate(
                    fcntl(fd.as_raw_fd(), FcntlArg::F_GETFL).unwrap_or(0),
                );
                let _ = fcntl(fd.as_raw_fd(), FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK));
                // C `:631`: `result = 0`. No async connect; ready NOW.
                let now = self.timers.now();
                let raw_fd = fd.as_raw_fd();
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
                match self.ev.add(raw_fd, Io::Read, IoWhat::Conn(id)) {
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
                // C `:425`: send_id. Proxy is transport; peer expects ID.
                if let Some(conn) = self.conns.get_mut(id) {
                    log::info!(target: "tincd::conn",
                                "Connected to {} ({}) via proxy exec",
                                conn.name, conn.hostname);
                    let needs_write = conn.send(format_args!(
                        "{} {} {}.{}",
                        Request::Id as u8,
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

            // ─── SOCKS/HTTP: connect to PROXY addr (C `:590-601`).
            // Addr cache still walks PEER addrs (CONNECT target varies).
            let proxy_hp = self
                .settings
                .proxy
                .as_ref()
                .and_then(ProxyConfig::proxy_addr);
            let attempt = if let Some((phost, pport)) = proxy_hp {
                let Some(peer_addr) = outgoing.addr_cache.next_addr() else {
                    log::error!(target: "tincd::conn",
                                "Could not set up a meta connection to {name}");
                    self.retry_outgoing(oid);
                    return;
                };
                try_connect_via_proxy(phost, pport, peer_addr, &name)
            } else {
                try_connect(
                    &mut outgoing.addr_cache,
                    &name,
                    self.settings.bind_to_address,
                )
            };

            match attempt {
                ConnectAttempt::Started { sock, addr } => {
                    // C `:649-658`. WRITE registration triggers
                    // `on_connecting` when kernel finishes async connect.
                    let now = self.timers.now();
                    // Probe needs `&Socket` (take_error); Connection.fd is
                    // OwnedFd. dup: the dup goes on Connection (long-lived,
                    // epoll-registered); original drops at finish_connecting.
                    // Register the DUP, not the original (original closes
                    // when connecting_socks removes it — stale epoll slot).
                    let dup = match sock.try_clone() {
                        Ok(d) => OwnedFd::from(d),
                        Err(e) => {
                            log::error!(target: "tincd::conn",
                                        "dup failed for {addr}: {e}");
                            continue;
                        }
                    };
                    let fd = dup.as_raw_fd();
                    let conn = Connection::new_outgoing(
                        dup,
                        name,
                        fmt_addr(&addr),
                        addr,
                        slotmap::Key::data(&oid),
                        now,
                    );
                    let id = self.conns.insert(conn);
                    self.connecting_socks.insert(id, sock);
                    // C `:658`: IO_READ|IO_WRITE. EPOLLOUT fires on
                    // connect complete OR fail. READ too (loopback
                    // connect+immediate-data is possible).
                    match self.ev.add(fd, Io::ReadWrite, IoWhat::Conn(id)) {
                        Ok(io_id) => {
                            self.conn_io.insert(id, io_id);
                        }
                        Err(e) => {
                            log::error!(target: "tincd::conn",
                                        "io_add failed: {e}");
                            self.conns.remove(id);
                            self.connecting_socks.remove(id);
                            continue;
                        }
                    }
                    return; // C `:660`
                }
                ConnectAttempt::Retry => {} // C `goto begin`
                ConnectAttempt::Exhausted => {
                    // C `:572-575`
                    self.retry_outgoing(oid);
                    return;
                }
            }
        }
    }

    /// `retry_outgoing` (`net_socket.c:405-417`). C `:414` jitter not
    /// ported (loop tick rate already desyncs identical-config daemons).
    pub(super) fn retry_outgoing(&mut self, oid: OutgoingId) {
        let Some(outgoing) = self.outgoings.get_mut(oid) else {
            return;
        };
        let timeout = outgoing.bump_timeout(self.settings.maxtimeout);
        // C resets in `setup_outgoing_connection:670`, not here. We
        // didn't port that line; reset HERE so next retry walks from top.
        outgoing.addr_cache.reset();
        log::info!(target: "tincd::conn",
                   "Trying to re-establish outgoing connection in {timeout} seconds");
        if let Some(&tid) = self.outgoing_timers.get(oid) {
            self.timers
                .set(tid, Duration::from_secs(u64::from(timeout)));
        }
    }

    /// `handle_meta_io` connecting branch (`net_socket.c:517-555`).
    /// Returns `true` to fall through to write/read (C `:553`). The
    /// fall-through matters: mio is edge-triggered; the WRITE edge
    /// that woke us is the same one that flushes the ID line.
    pub(super) fn on_connecting(&mut self, id: ConnId) -> bool {
        let Some(sock) = self.connecting_socks.get(id) else {
            log::warn!(target: "tincd::conn",
                       "on_connecting: no socket for {id:?}");
            self.terminate(id);
            return false;
        };
        match probe_connecting(sock) {
            Ok(true) => {
                self.finish_connecting(id); // C `:553-554`
                true
            }
            Ok(false) => false, // spurious; C `:534`
            Err(e) => {
                // C `:546-547`. C's `terminate_connection(c, false)`:
                // report=false ↔ our was_active=false (no edge yet).
                let (name, hostname) = self
                    .conns
                    .get(id)
                    .map(|c| (c.name.clone(), c.hostname.clone()))
                    .unwrap_or_default();
                log::debug!(target: "tincd::conn",
                            "Error while connecting to {name} ({hostname}): {e}");
                // Probe-fail doesn't trigger terminate's retry (not
                // was_active); drive do_outgoing_connection directly.
                let oid = self
                    .conns
                    .get(id)
                    .and_then(|c| c.outgoing)
                    .map(OutgoingId::from);
                self.connecting_socks.remove(id);
                self.terminate(id);
                if let Some(oid) = oid {
                    self.do_outgoing_connection(oid);
                }
                false
            }
        }
    }

    /// `finish_connecting` (`net_socket.c:419-426`). add_recent_address
    /// is deferred to `on_ack` (C does it there too at `:939-943`;
    /// the right port alone doesn't mean tinc).
    pub(super) fn finish_connecting(&mut self, id: ConnId) {
        // Drop probe socket; dup'd OwnedFd on Connection is live now.
        self.connecting_socks.remove(id);

        let Some(conn) = self.conns.get_mut(id) else {
            return;
        };
        log::info!(target: "tincd::conn",
                   "Connected to {} ({})", conn.name, conn.hostname);
        conn.last_ping_time = self.timers.now(); // C `:423`
        conn.connecting = false; // C `:424`

        // C `protocol_auth.c:111-114`: send_proxyrequest BEFORE send_id.
        // Both queue into outbuf, flush in one send(). Pipelining is
        // intentional: proxy buffers the ID line while processing greeting.
        let mut needs_write = false;
        if let (true, Some(proxy)) = (conn.outgoing.is_some(), &self.settings.proxy) {
            match proxy {
                ProxyConfig::Exec { .. } => {
                    // C `protocol_auth.c:84`. Unreachable (Exec skips
                    // finish_connecting); arm makes match exhaustive.
                }
                ProxyConfig::Http { .. } => {
                    // C `protocol_auth.c:60-68`. send_request appends `\n`
                    // → wire is `CONNECT h:p HTTP/1.1\r\n\r\n`. No Host:
                    // header (RFC 7230 §5.4 violation; proxies accept it).
                    // c->address is the PEER addr (proxy is transport).
                    let Some(target) = conn.address else {
                        log::error!(target: "tincd::conn",
                            "HTTP proxy: no peer address on {}", conn.name);
                        self.terminate(id);
                        return;
                    };
                    // STRICTER-than-C: bracket IPv6 (RFC 7230 §2.7.1).
                    // C's sockaddr2str doesn't bracket → `CONNECT ::1:655`
                    // is ambiguous. SocketAddr::Display brackets v6.
                    let line = format!("CONNECT {target} HTTP/1.1\r\n\r\n");
                    needs_write |= conn.send_raw(line.as_bytes());
                    log::debug!(target: "tincd::conn",
                        "Queued HTTP CONNECT for {} → {target}", conn.name);
                    // No tcplen — response is line-based (`protocol.c:148-161`).
                }
                ProxyConfig::Socks4 { .. } | ProxyConfig::Socks5 { .. } => {
                    // C `protocol_auth.c:71-77`. Target = PEER addr.
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
                            // C `:75-76`
                            needs_write |= conn.send_raw(&bytes);
                            // resp_len fits u16: SOCKS5 max 26, SOCKS4 8.
                            #[allow(clippy::cast_possible_truncation)]
                            {
                                conn.tcplen = resp_len as u16;
                            }
                            log::debug!(target: "tincd::conn",
                                "Queued {} SOCKS bytes for {}, expecting {} reply bytes",
                                bytes.len(), conn.name, resp_len);
                        }
                        Err(e) => {
                            // SOCKS4+IPv6, or 256-byte cred (C-is-WRONG #9).
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

        // C `:425`: send_id. WE go first (initiator); peer's `id_h:451` replies.
        let conn = self.conns.get_mut(id).expect("not terminated");
        needs_write |= conn.send(format_args!(
            "{} {} {}.{}",
            Request::Id as u8,
            self.name,
            tinc_proto::request::PROT_MAJOR,
            tinc_proto::request::PROT_MINOR
        ));

        // Re-register: was ReadWrite (probe); now READ (or RW if queued).
        // C `:658` registers RW always; `:509` drops WRITE when empty.
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
