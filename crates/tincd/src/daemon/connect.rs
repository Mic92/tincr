#[allow(clippy::wildcard_imports)]
use super::*;

impl Daemon {
    /// `ack_h` mutation half (`protocol_auth.c:965-1064`). Parse
    /// done by `proto::parse_ack`; this does the world-model edits
    /// (which need `&mut self`).
    ///
    /// C path traced:
    /// - `:965-991` lookup_node / new_node / dup-conn handling
    /// - `:993-994` `n->connection = c; c->node = n`
    /// - `:996-999` PMTU intersection (BOTH sides must want it)
    /// - `:1001` `c->options |= options`
    /// - `:1003-1019` PMTU/ClampMSS per-host re-read — STUBBED
    /// - `:1023` `c->allow_request = ALL`
    /// - `:1028` `send_everything(c)` — walks empty trees, sends 0
    /// - `:1032-1051` edge_add: address+port, getsockname, weight avg
    /// - `:1055-1059` `send_add_edge` broadcast — STUBBED (no peers)
    /// - `:1063` `graph()` — ✅ `run_graph_and_log()`
    ///
    /// Returns the io_set signal. (Always `false` in chunk 4b:
    /// `send_everything` iterates empty trees, `send_add_edge` is
    /// stubbed. Kept for chunk 5 when both fire.)
    pub(super) fn on_ack(
        &mut self,
        id: ConnId,
        body: &[u8],
    ) -> Result<bool, crate::proto::DispatchError> {
        let parsed = parse_ack(body)?;
        let conn = self.conns.get_mut(id).expect("caller checked");

        // C `:948-950`: `if(minor == 1) return upgrade_h(c, req)`.
        // We rejected minor < 2 in id_h. Unreachable.

        // ─── PMTU intersection (`:996-999`)
        // C: `if(!(c->options & options & PMTU)) { c->options &=
        // ~PMTU; options &= ~PMTU; }`. PMTU only sticks if BOTH
        // sides want it (the AND). If either's bit is clear, clear
        // both. Then OR in the rest.
        let mut his = parsed.his_options;
        if conn.options & his & crate::proto::OPTION_PMTU_DISCOVERY == 0 {
            conn.options &= !crate::proto::OPTION_PMTU_DISCOVERY;
            his &= !crate::proto::OPTION_PMTU_DISCOVERY;
        }
        conn.options |= his;

        // C `:1003-1019`: per-host PMTU/ClampMSS re-read. STUBBED
        // (config_tree not retained, see id_h doc).

        // C `:1023`: `c->allow_request = ALL`. Our `None`.
        conn.allow_request = None;

        log::info!(target: "tincd::conn",
                   "Connection with {} ({}) activated",
                   conn.name, conn.hostname);

        // ─── lookup_node / node_add (`:965-994`)
        // C: `n = lookup_node(c->name); if(!n) { n = new_node();
        // node_add(n); } else if(n->connection) { ... close old }`.
        //
        // The dup-conn case (`:975-990`): we already have a live
        // connection to this node, the new one wins, terminate the
        // old. The C reasons about `outgoing` ownership (which side
        // initiated which). Chunk 4b is responder-only — the dup
        // case is two simultaneous INBOUND conns from the same peer.
        // Possible (peer reboots, reconnects before we've timed out
        // the old). Handle it: terminate old, accept new.
        let name = conn.name.clone();
        let conn_outgoing = conn.outgoing.map(OutgoingId::from);
        let conn_addr = conn.address;
        let edge_addr = conn.address.map(|mut a| {
            // C `:1024-1025`: `sockaddrcpy(&edge->address, &c->
            // address); sockaddr_setport(&edge->address, hisport)`.
            // The peer's TCP-connect-from addr, but with the port
            // REWRITTEN to their UDP port. This is the "how do I
            // reach you for data packets" addr.
            a.set_port(parsed.his_udp_port);
            a
        });
        // C `:1048`: `c->edge->weight = (weight + c->estimated_
        // weight) / 2`. The arithmetic average. C `int /` truncates
        // toward zero; `i32::midpoint` rounds toward neg-inf. With
        // both weights non-negative (RTT in ms) they're identical,
        // but the OVERFLOW behavior differs: `(i32::MAX + i32::MAX)
        // /2` is UB in C, panics in debug Rust, wraps in release.
        // `i32::midpoint` doesn't overflow. The C is buggy at 24-
        // day RTT; we're not. The semantic divergence (rounding) is
        // unreachable. Take the no-overflow version.
        let edge_weight = i32::midpoint(parsed.his_weight, conn.estimated_weight);
        let edge_options = conn.options;

        // C `protocol_misc.c:69-73` (`pong_h`, gated on retry) and
        // `graph.c:238` (BecameReachable): `if(c->outgoing) { c->
        // outgoing->timeout = 0; add_recent_address(...) }`. We do
        // it here in `on_ack`, ungated — slightly earlier than C,
        // harmless (idempotent dedup), pinned by tests/addrcache.rs.
        // The
        // connection got all the way to ACK — the address WORKED.
        // Reset the backoff for next time; move the addr to front
        // of the cache.
        if let Some(oid) = conn_outgoing {
            if let Some(o) = self.outgoings.get_mut(oid) {
                o.timeout = 0;
                if let Some(a) = conn_addr {
                    o.addr_cache.add_recent(a);
                }
                // C `address_cache.c:251`: `reset_address_cache`.
                // Next retry walks from the top (which is now the
                // working addr).
                o.addr_cache.reset();
            }
        }

        // (drop conn borrow before touching self.nodes / terminate)
        if let Some(old) = self.nodes.get(&name) {
            if let Some(old_conn) = old.conn {
                if old_conn != id {
                    // C `:976-978`: "Established a second connection
                    // with X, closing old connection".
                    log::debug!(target: "tincd::conn",
                                "Established a second connection with {name}, \
                                 closing old connection");
                    self.terminate(old_conn);
                    // C `:989`: `graph()` after terminate. The
                    // unconditional `run_graph_and_log()` below
                    // covers it (extra graph() is idempotent).
                }
            }
        }

        // C `:993-994` + `:1032-1051`: NodeState records the edge
        // metadata (the address, which tinc-graph::Edge doesn't
        // carry — it's runtime annotation). The graph gets weight
        // + options below.
        // (NodeState insert deferred until we have `fwd_eid` below.)

        // C `:1032-1051`: `c->edge = new_edge(); ...; edge_add()`.
        // The bridge to the graph. `lookup_or_add_node` for the
        // peer (might already be in the graph if a transitive
        // ADD_EDGE arrived first — unlikely with chunk-5's single-
        // peer scope but the C handles it). Then `add_edge(myself
        // → peer)`.
        //
        // C builds a BIDIRECTIONAL pair via `e->reverse` linking
        // (`edge.c:59-73`). `Graph::add_edge` auto-links if the
        // twin exists. With ONE direction, sssp's `e->reverse`
        // check (`graph.c:159`) skips it — so the peer won't
        // become reachable until either (a) we add the reverse
        // here, or (b) the peer's ADD_EDGE for `peer→myself`
        // arrives. The C does (a) implicitly: `ack_h` runs on
        // BOTH sides, both add their `c->edge`, the first arrives
        // via the protocol and links. With chunk-5's stub forward
        // and no peer-initiated ADD_EDGE in tests, we add both
        // directions here. The C's `c->edge` is one direction;
        // the peer's `c->edge` (sent via ADD_EDGE) is the other.
        // We synthesize the reverse for the test to prove the
        // diff fires.
        let peer_id = self.lookup_or_add_node(&name);
        let fwd_eid = self
            .graph
            .add_edge(self.myself, peer_id, edge_weight, edge_options);
        // The reverse: C `ack_h` adds ONLY the forward edge
        // (`c->edge`, `:1051 edge_add(c->edge)`). The reverse
        // (`peer→myself`) comes from the PEER's `send_add_edge(
        // everyone, c->edge)` (their `:1058`) over gossip. SSSP
        // skips edges without a reverse (`graph.c:159 if(!e->
        // reverse) continue`); this means our edge is dead until
        // the peer's gossip arrives — which it does in the same
        // burst (their on_ack runs symmetrically).
        //
        // Chunk-5 originally synthesized the reverse here. WRONG
        // for 3+ nodes: when the peer's gossip arrives at the
        // RELAY, `lookup_edge` finds our synthesized reverse →
        // idempotent early-return → no forward → transitive nodes
        // never learn the reverse → their SSSP can't reach us. The
        // C avoids this by NOT synthesizing: the relay's `lookup_
        // edge` finds nothing, `edge_add` runs, `forward_request`
        // runs.

        // C `:1024-1025`: `c->edge->address = c->address` with port
        // rewritten to `hisport`. C `:1040-1045`: `c->edge->local_
        // address = getsockname()` with port rewritten to `myport.
        // udp`. We have the FORWARD edge's addr in `edge_addr`
        // (already port-rewritten above). Stash as wire-format
        // `AddrStr` tokens (numeric IP + numeric port — `getnameinfo
        // NI_NUMERICHOST` shape, what `sockaddr2str` would emit).
        //
        // The reverse edge is the one the PEER would `edge_add`
        // from THEIR `ack_h`. Its `address` would be OUR address
        // as seen from their side (which we don't know without
        // STUN-style probing). The C learns it from the peer's
        // `send_add_edge` broadcast. Chunk-5 synthesizes: leave the
        // reverse without an `edge_addrs` entry; `dump_edges`
        // formats missing entries as `"unknown port unknown"`
        // (the C default for `n->hostname == NULL`, `node.c:211`).
        // C `ack_h:1040-1045`: `getsockname` → `local_address`
        // with port rewritten to `myport.udp`. The `Connection.fd`
        // is an `OwnedFd`; `socket2::SockRef::from(&OwnedFd)` is
        // the non-owning wrapper for the `local_addr()` call.
        let local_addr = self.conns.get(id).and_then(|c| {
            let sockref = socket2::SockRef::from(c.owned_fd());
            sockref.local_addr().ok().and_then(|sa| sa.as_socket())
        });
        if let Some(ea) = edge_addr {
            // `Ipv6Addr::Display` doesn't bracket (matches
            // `getnameinfo NI_NUMERICHOST`); same as `fmt_addr`.
            let addr = AddrStr::new(ea.ip().to_string()).expect("numeric IP is whitespace-free");
            let port = AddrStr::new(ea.port().to_string()).expect("numeric");
            // C `:1042-1045`: `sockaddr_setport(&local, myport.udp)`.
            // The local addr is the OS-assigned source-addr of the
            // TCP socket; rewrite the port to OUR udp port (the peer
            // sends UDP back to that port, not the ephemeral TCP one).
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
        // Now that we have `fwd_eid`, populate `NodeState.edge`.
        // `terminate_connection` (`net.c:126-132`) reads it.
        self.nodes.insert(
            name.clone(),
            NodeState {
                edge: Some(fwd_eid),
                conn: Some(id),
                edge_addr,
                edge_weight,
                edge_options,
            },
        );

        // C `:1051`: `c->edge = e`. The `c->edge != NULL` check in
        // `broadcast_meta` (`meta.c:115`) is the "past ACK" filter.
        // We use a bool. NOT set earlier: `send_everything` calls
        // `conn.send()` which is fine (the conn isn't a broadcast
        // TARGET yet, but it can receive); the broadcast below
        // (`send_add_edge(everyone, ...)`) MUST exclude this conn
        // (it's not active yet — the C ordering is the same:
        // `:1051` `c->edge = e` is AFTER `:1028 send_everything`
        // but BEFORE `:1058 send_add_edge(everyone)`. Wait, no:
        // C `:1051` is after `:1028` but before `:1058`. So the
        // `c->edge` test PASSES at `:1058`. The `c == everyone`
        // path in `send_request` (`protocol.c:122`) calls
        // `broadcast_meta(NULL, ...)` — `from = NULL` means no
        // skip. The new conn DOES get its own edge back. The
        // `seen.check` on the receiver side dups it.
        //
        // Match: set `active` BEFORE the broadcast so the new conn
        // is included. The `seen.check` dedup makes this harmless;
        // matching the C wire output is what counts.
        if let Some(conn) = self.conns.get_mut(id) {
            conn.active = true;
        }

        // C `:1028`: `send_everything(c)`. Walks `node_tree`, for
        // each node walks `subnet_tree` and `edge_tree`, sends
        // ADD_SUBNET/ADD_EDGE for everything we know. NOTE: this
        // sends the edge we JUST added (the one fwd_eid we have
        // an addr for). The C does the same: `edge_add` at `:1051`
        // is BEFORE `:1028 send_everything` — wait, no, `:1028`
        // is the call site, `:1051` is `edge_add(c->edge)`. Read
        // again: `:1028 send_everything(c)` then `:1032-1051` build
        // and add the edge. So C `send_everything` does NOT include
        // the new edge. We added it earlier (line ordering moved
        // for `NodeState.edge`). Adjust: send_everything BEFORE
        // edge_addrs.insert. Actually it doesn't matter — the new
        // edge gets sent via the `send_add_edge(everyone)` below
        // anyway, and the peer's `seen.check` dups any double-
        // send. Match the C's wire-output by skipping `fwd_eid`
        // would be needless complexity. Leave as-is.
        let mut nw = self.send_everything(id);

        // C `:1055-1059`: `send_add_edge(everyone, c->edge)`. Tell
        // every OTHER active conn about the new edge. The C
        // `everyone` sentinel routes through `broadcast_meta(NULL,
        // ...)` (`protocol.c:122-125`). With one peer and that
        // peer being `id` (just-set active), the broadcast targets
        // include `id`; the peer's `seen.check` will dup it (since
        // `send_everything` already sent the same edge with a
        // DIFFERENT nonce — wait, that's NOT a dup then. The seen
        // cache keys on the full line including nonce. So the peer
        // gets two ADD_EDGEs for the same edge with different
        // nonces. Both pass `seen.check`. The SECOND one hits the
        // `lookup_edge` exists branch with same weight+options →
        // idempotent return. OK. The C has the same shape).
        //
        // C `:1055-1059`: tunnelserver gate. Hub mode: send the
        // edge ONLY to the new peer (`send_add_edge(c, c->edge)`),
        // not broadcast. The other spokes never learn about each
        // other.
        //
        // Format ONCE then broadcast (`send_request:122` formats
        // before `broadcast_meta`; one nonce for all targets).
        if let Some(line) = self.fmt_add_edge(fwd_eid, Self::nonce()) {
            if self.settings.tunnelserver {
                if let Some(c) = self.conns.get_mut(id) {
                    nw |= c.send(format_args!("{line}"));
                }
            } else {
                nw |= self.broadcast_line(&line);
            }
        }

        // C `:1065`: `graph()`. THE FIRST TIME this does anything:
        // peer was added with reachable=false (lookup_or_add_node);
        // the bidi edge means sssp visits it; diff emits
        // BecameReachable.
        self.run_graph_and_log();

        Ok(nw)
    }

    /// `handle_meta_io` WRITE path → `handle_meta_write`
    /// (`net_socket.c:486-511`).
    pub(super) fn on_conn_writable(&mut self, id: ConnId) {
        let conn = self.conns.get_mut(id).expect("checked contains_key");
        match conn.flush() {
            Ok(true) => {
                // outbuf empty. C `:509-511`: `io_set(&c->io, IO_READ)`.
                if let Some(&io_id) = self.conn_io.get(id) {
                    if let Err(e) = self.ev.set(io_id, Io::Read) {
                        log::error!(target: "tincd::conn",
                                    "io_set failed for {id:?}: {e}");
                        self.terminate(id);
                    }
                }
            }
            Ok(false) => {
                // More to send. Stay registered for WRITE.
            }
            Err(e) => {
                // C `:502-504`: log + terminate.
                log::info!(target: "tincd::conn",
                           "Connection write failed: {e}");
                self.terminate(id);
            }
        }
    }

    /// `terminate_connection` (`net.c:118-170`). Removes the conn,
    /// deletes its edge, broadcasts `DEL_EDGE`, runs `graph()`.
    /// Chunk 6: the `c->edge` cleanup path (`:126-152`) is REAL.
    ///
    /// The C's `report` flag (`:128`: `if(report && !tunnelserver)`)
    /// gates the DEL_EDGE broadcast. `report = c->edge != NULL` at
    /// most call sites (`net.c:225,243,253,310`). We test
    /// `conn.active` (same condition).
    ///
    /// `c->outgoing` retry (`:155-161`) is chunk 6 commit 2.
    pub(super) fn terminate(&mut self, id: ConnId) {
        let Some(conn) = self.conns.remove(id) else {
            // Already gone. The slotmap is generational; a stale
            // ConnId returns None. Idempotent.
            if let Some(io_id) = self.conn_io.remove(id) {
                self.ev.del(io_id);
            }
            return;
        };
        log::info!(target: "tincd::conn",
                   "Closing connection with {}", conn.name);
        let was_active = conn.active;
        let conn_name = conn.name.clone();
        // Drop conn now — OwnedFd closes the socket. Further
        // `broadcast_line` calls below will skip this id (it's
        // gone from `conns`).
        drop(conn);

        if let Some(io_id) = self.conn_io.remove(id) {
            self.ev.del(io_id);
        }

        // C `:121-123`: `if(c->node && c->node->connection == c)
        // c->node->connection = NULL`. The node OUTLIVES the conn;
        // clear the back-ref so a stale ConnId isn't read. Also
        // grab the edge while we're here.
        let our_edge = self.nodes.get_mut(&conn_name).and_then(|ns| {
            if ns.conn == Some(id) {
                ns.conn = None;
                ns.edge.take()
            } else {
                None
            }
        });

        // C `:126-152`: `if(c->edge)`. The edge cleanup. Only fires
        // for connections that got past ACK (`ack_h:1051` set
        // `c->edge`). Control conns and pre-ACK peers skip.
        if let Some(eid) = our_edge {
            // C `:127-129`: `if(report && !tunnelserver) send_del_
            // edge(everyone, c->edge)`. The `c == everyone` path
            // formats once + `broadcast_meta(NULL, ...)`. The conn
            // is already gone from `conns` so it's not a target.
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

            // C `:131-132`: `edge_del(c->edge); c->edge = NULL`.
            self.graph.del_edge(eid);
            self.edge_addrs.remove(&eid);

            // C `:136`: `graph()`. The peer might become
            // unreachable; the diff fires `BecameUnreachable`.
            self.run_graph_and_log();

            // C `:140-152`: reverse-edge cleanup. If the peer is
            // now unreachable AND has an edge back to us (the
            // synthesized reverse from `on_ack`), delete + broadcast
            // that too. The C `lookup_edge(c->node, myself)`.
            let peer_unreachable = self
                .node_ids
                .get(&conn_name)
                .and_then(|&nid| self.graph.node(nid))
                .is_some_and(|n| !n.reachable);
            if was_active && peer_unreachable {
                if let Some(&peer_nid) = self.node_ids.get(&conn_name) {
                    if let Some(rev) = self.graph.lookup_edge(peer_nid, self.myself) {
                        // C `:144-146`: `if(!tunnelserver)
                        // send_del_edge(everyone, e)`.
                        if !self.settings.tunnelserver {
                            let line = DelEdge {
                                from: conn_name.clone(),
                                to: self.name.clone(),
                            }
                            .format(Self::nonce());
                            self.broadcast_line(&line);
                        }
                        // C `:149`: `edge_del(e)`.
                        self.graph.del_edge(rev);
                        self.edge_addrs.remove(&rev);
                    }
                }
            }
        }

        // C `net.c:155-161`: `c->outgoing` retry. When an outgoing
        // connection drops, immediately try again. C `:161`:
        // `do_outgoing_connection(outgoing)`. The conn was already
        // removed; the addr cache cursor moves to the next addr.
        // If THAT also fails, `retry_outgoing` arms the backoff.
        //
        // The `was_active` gate is intentional: `:161` runs
        // unconditionally in C, but for us a NON-active outgoing
        // (probe failed) is already handled by `on_connecting`→
        // `do_outgoing_connection` directly. Don't double-retry.
        if was_active {
            if let Some(oid) = self.nodes.get(&conn_name).and_then(|_| {
                // Can't read `conn.outgoing` (conn already
                // dropped). Look it up by name in `outgoings`.
                self.outgoings
                    .iter()
                    .find(|(_, o)| o.node_name == conn_name)
                    .map(|(id, _)| id)
            }) {
                // C `ack_h:942`: `c->outgoing->timeout = 0` was
                // already done in `on_ack` — wait, no, we never
                // ported that. Do it here: a connection that GOT
                // to ACK had a working address; reset the backoff.
                if let Some(o) = self.outgoings.get_mut(oid) {
                    o.timeout = 0;
                }
                self.do_outgoing_connection(oid);
            }
        }
    }

    // ─── outgoing connections (`net_socket.c:405-681`)

    /// `setup_outgoing_connection` (`net_socket.c:664-681`). Disarm
    /// the retry timer, check if we're already connected, else dial.
    ///
    /// C `:666`: `timeout_del(&outgoing->ev)` — cancel any pending
    /// retry. We're about to TRY, so the backoff timer is moot.
    /// C `:674`: `if(n->connection) { log "Already connected";
    /// return }`. Don't dial out if we already have a conn (either
    /// they connected to US, or a previous outgoing succeeded).
    pub(super) fn setup_outgoing_connection(&mut self, oid: OutgoingId) {
        // C `:666`: `timeout_del(&outgoing->ev)`. Our `set` would
        // re-arm anyway, but explicitly disarming matches the C
        // and prevents the timer from firing while a connect is
        // in flight (which would start a SECOND connect).
        // tinc-event's `del` frees the slot; we want to KEEP the
        // slot, just disarm. There's no `unset`. Workaround: don't
        // del; the next `retry_outgoing` `set` overwrites. The
        // timer can't fire mid-connect because we won't return to
        // `run()` until this function exits.

        let Some(outgoing) = self.outgoings.get(oid) else {
            return; // gone (chunk 8's mark-sweep)
        };
        let name = outgoing.node_name.clone();

        // C `:674-676`: `if(n->connection)`. Our `NodeState.conn`.
        if self.nodes.get(&name).and_then(|ns| ns.conn).is_some() {
            log::info!(target: "tincd::conn",
                       "Already connected to {name}");
            return;
        }

        // C `:678`: `do_outgoing_connection(outgoing)`.
        self.do_outgoing_connection(oid);
    }

    /// `do_outgoing_connection` (`net_socket.c:564-662`). The `goto
    /// begin` loop: walk the addr cache, try each addr, register
    /// the first one that doesn't fail synchronously. Exhausted →
    /// arm the retry-backoff timer.
    ///
    /// `PROXY_EXEC` (`:588`, `:631`): instead of socket+connect,
    /// `do_outgoing_pipe` does socketpair+fork. The fd is already
    /// "connected" — skip the async-connect probe, send_id directly.
    ///
    /// `PROXY_SOCKS4`/`SOCKS5`/`HTTP` (`:590-601`, `:637`): connect
    /// to the PROXY's address (`try_connect_via_proxy`). The peer
    /// addr is still walked from the addr cache (it's the SOCKS
    /// CONNECT target). The async-connect probe runs same as direct;
    /// `finish_connecting` queues the SOCKS handshake bytes BEFORE
    /// the ID line and sets `conn.tcplen` for the response read.
    #[allow(clippy::too_many_lines)] // PROXY_EXEC adds a parallel
    // code path (socketpair vs socket+connect). Factoring would
    // thread oid/name/now/self through a helper for both arms.
    // C `do_outgoing_connection` is 98 lines; we're 119 with the
    // proxy branch. Same shape, two sockets-paths.
    pub(super) fn do_outgoing_connection(&mut self, oid: OutgoingId) {
        loop {
            let Some(outgoing) = self.outgoings.get_mut(oid) else {
                return;
            };
            let name = outgoing.node_name.clone();

            // ─── PROXY_EXEC (C `:588-590`, `:631`)
            // Walk the addr cache for the env vars (the proxy
            // script reads REMOTEADDRESS/REMOTEPORT). The fd is a
            // socketpair half — already "connected", no probe.
            if let Some(ProxyConfig::Exec { cmd }) = self.settings.proxy.clone() {
                let Some(addr) = outgoing.addr_cache.next_addr() else {
                    // C `:572-575`: addr cache exhausted. Same as
                    // the non-proxy path.
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
                        // C `:605-608`: "Creating socket failed"
                        // → goto begin. Try next addr.
                        continue;
                    }
                };
                // Set non-blocking on the parent fd. The child end
                // is already gone (closed in parent post-fork).
                // SAFETY: fd is valid (just from socketpair).
                #[allow(unsafe_code)]
                unsafe {
                    let flags = libc::fcntl(fd.as_raw_fd(), libc::F_GETFL);
                    libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
                }
                // C `:631`: `result = 0` for PROXY_EXEC. No async
                // connect; the conn is ready NOW. Build it with
                // connecting=false (new_outgoing sets it true; we
                // clear it after).
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
                // Register Read only — no probe. Same as a finished
                // async connect.
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
                // C `:425`: `send_id(c)`. The proxy is the
                // transport; the peer on the other side of the
                // proxy expects our ID line.
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
                    if needs_write {
                        if let Some(&io_id) = self.conn_io.get(id) {
                            if let Err(e) = self.ev.set(io_id, Io::ReadWrite) {
                                log::error!(target: "tincd::conn",
                                            "io_set failed: {e}");
                                self.terminate(id);
                            }
                        }
                    }
                }
                return;
            }

            // ─── SOCKS/HTTP proxy: connect to PROXY addr (`:590-601`)
            // The addr cache still walks PEER addrs (the SOCKS
            // target varies per attempt). C `:580`: `c->address`
            // is the peer addr regardless of proxy.
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
                    // C `:649-658`: `c->status.connecting = true;
                    // c->name = name; connection_add(c); io_add(
                    // ..., IO_READ | IO_WRITE)`. The WRITE
                    // registration is what triggers `on_connecting`
                    // when the kernel finishes (or fails) the
                    // async connect.
                    let now = self.timers.now();
                    // The probe needs `&Socket` (for `take_error`);
                    // `Connection.fd` is `OwnedFd`. Same fd, two
                    // owners would double-close. dup the fd: the
                    // dup goes on `Connection` (the LONG-lived
                    // handle, the one we register with epoll); the
                    // original sock drops after `finish_connecting`.
                    // One extra fd for ~1 RTT. The C doesn't have
                    // this split (its `getsockopt` takes raw `int`);
                    // it's the cost of type-safe ownership.
                    //
                    // Register the DUP's fd, NOT the original. The
                    // dup outlives the probe; the original closes
                    // when `connecting_socks` removes it. Registering
                    // the original would leave the event-loop slot
                    // stale post-probe (epoll on a closed fd).
                    let dup = match sock.try_clone() {
                        Ok(d) => OwnedFd::from(d),
                        Err(e) => {
                            log::error!(target: "tincd::conn",
                                        "dup failed for {addr}: {e}");
                            // sock drops; retry next addr.
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
                    // C `:658`: `io_add(..., IO_READ | IO_WRITE)`.
                    // ReadWrite: the WRITE wake is the probe trigger
                    // (epoll EPOLLOUT fires when connect completes
                    // OR fails). READ is registered too (the C does
                    // it; loopback connect+immediate-data is possible).
                    match self.ev.add(fd, Io::ReadWrite, IoWhat::Conn(id)) {
                        Ok(io_id) => {
                            self.conn_io.insert(id, io_id);
                        }
                        Err(e) => {
                            log::error!(target: "tincd::conn",
                                        "io_add failed: {e}");
                            self.conns.remove(id);
                            self.connecting_socks.remove(id);
                            continue; // try next addr
                        }
                    }
                    return; // C `:660`: `return true`.
                }
                ConnectAttempt::Retry => {
                    // C `goto begin`. Next iteration tries the next
                    // addr from the cache.
                }
                ConnectAttempt::Exhausted => {
                    // C `:572-575`: `retry_outgoing(outgoing);
                    // return false`.
                    self.retry_outgoing(oid);
                    return;
                }
            }
        }
    }

    /// `retry_outgoing` (`net_socket.c:405-417`). Bump the backoff
    /// (`timeout += 5`, cap at maxtimeout), arm the timer. The
    /// `RetryOutgoing(oid)` dispatch arm calls `setup_outgoing_
    /// connection` when it fires.
    ///
    /// C `:414` jitter: `+ jitter()` (≤ 1s random ms). Not ported
    /// (see lib.rs jitter doc — the loop's tick rate already
    /// desyncs identical-config daemons).
    pub(super) fn retry_outgoing(&mut self, oid: OutgoingId) {
        let Some(outgoing) = self.outgoings.get_mut(oid) else {
            return;
        };
        let timeout = outgoing.bump_timeout(self.settings.maxtimeout);
        // C `:413`: also resets the addr cache cursor for next time.
        // Wait — it doesn't. The C `reset_address_cache` is called
        // from `setup_outgoing_connection` (`:670`), not here. We
        // didn't port that line either. Reset HERE so the next
        // retry walks from the top.
        outgoing.addr_cache.reset();
        log::info!(target: "tincd::conn",
                   "Trying to re-establish outgoing connection in {timeout} seconds");
        if let Some(&tid) = self.outgoing_timers.get(oid) {
            self.timers
                .set(tid, Duration::from_secs(u64::from(timeout)));
        }
    }

    /// `handle_meta_io` connecting branch (`net_socket.c:517-555`).
    /// Probe the async connect. Success → `finish_connecting`. Fail
    /// → terminate (which retries the outgoing).
    ///
    /// Returns `true` if the caller should fall through to the
    /// write/read dispatch (probe succeeded; C `:553` falls through).
    /// `false` for spurious wake or failure (C `:534`/`:550` `return`).
    /// The fall-through matters: mio is edge-triggered; the WRITE
    /// edge that woke us is the same one that would let us flush the
    /// ID line. Consuming it for the probe and not flushing means
    /// the next WRITE wake never comes.
    pub(super) fn on_connecting(&mut self, id: ConnId) -> bool {
        let Some(sock) = self.connecting_socks.get(id) else {
            // Shouldn't happen (we always insert when conn.
            // connecting=true). Defensive.
            log::warn!(target: "tincd::conn",
                       "on_connecting: no socket for {id:?}");
            self.terminate(id);
            return false;
        };
        match probe_connecting(sock) {
            Ok(true) => {
                // C `:553-554`: `c->status.connecting = false;
                // finish_connecting(c)`. Fall through after.
                self.finish_connecting(id);
                true
            }
            Ok(false) => {
                // Spurious wakeup. Stay registered for WRITE.
                // C `:534`: `return`.
                false
            }
            Err(e) => {
                // C `:546-547`: log DEBUG "Error while connecting
                // to %s (%s): %s"; terminate. The C uses
                // `terminate_connection(c, false)` — the `false`
                // is `report = false` (don't broadcast DEL_EDGE,
                // there IS no edge yet). Our `terminate` keys on
                // `was_active` which is also false here.
                let (name, hostname) = self
                    .conns
                    .get(id)
                    .map(|c| (c.name.clone(), c.hostname.clone()))
                    .unwrap_or_default();
                log::debug!(target: "tincd::conn",
                            "Error while connecting to {name} ({hostname}): {e}");
                // Stash the OutgoingId BEFORE terminate (which
                // drops the conn). The probe-fail path (NOT
                // `was_active`) doesn't trigger terminate's retry,
                // so we drive `do_outgoing_connection` directly
                // — try the NEXT addr from the cache.
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

    /// `finish_connecting` (`net_socket.c:419-426`). The async
    /// connect succeeded. Clear the connecting flag, switch
    /// interest to READ-only, send our ID line. The peer's `id_h`
    /// then fires; OUR `id_h` fires on their reply.
    ///
    /// `addrcache.add_recent`: the address WORKED; move it to
    /// front. C does this in `ack_h` (`protocol_auth.c:939-943`
    /// `add_recent_address(c->outgoing->node->address_cache, ...)`)
    /// not here — the C waits until ACK to be sure. We do too:
    /// move the `add_recent` to `on_ack`. Connecting through ACK
    /// is the full proof; the right port alone doesn't mean tinc.
    pub(super) fn finish_connecting(&mut self, id: ConnId) {
        // Drop the probe socket. The dup'd `OwnedFd` on the
        // Connection is the live handle from here on.
        self.connecting_socks.remove(id);

        let Some(conn) = self.conns.get_mut(id) else {
            return;
        };
        // C `:421`: `"Connected to %s (%s)"`.
        log::info!(target: "tincd::conn",
                   "Connected to {} ({})", conn.name, conn.hostname);
        // C `:423`: `c->last_ping_time = now.tv_sec`. The pingtimer
        // sweep (chunk 8) keys on this.
        conn.last_ping_time = self.timers.now();
        // C `:424`: `c->status.connecting = false`.
        conn.connecting = false;

        // ─── send_proxyrequest (C `protocol_auth.c:111-114`) ────────
        // `if(proxytype && c->outgoing) send_proxyrequest(c)` BEFORE
        // `send_request(ID)`. Both queue into outbuf; both flush in
        // one `send()`. The proxy server reads the SOCKS bytes,
        // replies (we read that as `tcplen`-exact in `on_conn_
        // readable`), then forwards the ID line transparently to
        // the peer. The pipelining is intentional: TCP is a stream;
        // the proxy buffers the ID line while it processes our
        // greeting.
        //
        // `conn.outgoing.is_some()` is always true here (this IS
        // `finish_connecting`, only called for outgoing conns), but
        // check anyway to match the C's gate shape.
        let mut needs_write = false;
        if let (true, Some(proxy)) = (conn.outgoing.is_some(), &self.settings.proxy) {
            match proxy {
                ProxyConfig::Exec { .. } => {
                    // C `protocol_auth.c:84`: `case PROXY_EXEC:
                    // return true`. The pipe IS the connection;
                    // nothing to queue. We never reach here anyway
                    // (Exec skips finish_connecting in do_outgoing_
                    // connection), but the arm makes the match
                    // exhaustive.
                }
                ProxyConfig::Http { .. } => {
                    // C `protocol_auth.c:60-68`: `sockaddr2str(&c->
                    // address, &host, &port); send_request(c,
                    // "CONNECT %s:%s HTTP/1.1\r\n\r", host, port)`.
                    // `send_request` appends `\n` → wire is
                    // `CONNECT h:p HTTP/1.1\r\n\r\n` (the blank
                    // line terminates the HTTP request — no Host:
                    // header, technically RFC 7230 §5.4 violation
                    // but proxies accept it).
                    //
                    // `c->address` is the PEER addr (proxy is just
                    // transport; we connect to the proxy IP:port at
                    // the socket layer, then tell the proxy where
                    // to connect onward via CONNECT).
                    let Some(target) = conn.address else {
                        log::error!(target: "tincd::conn",
                            "HTTP proxy: no peer address on {}", conn.name);
                        self.terminate(id);
                        return;
                    };
                    // STRICTER-than-C: bracket IPv6 in the authority
                    // (RFC 7230 §2.7.1). The C `sockaddr2str` is
                    // `getnameinfo(NUMERIC)` which does NOT bracket,
                    // so `CONNECT ::1:655 HTTP/1.1` — ambiguous
                    // (which `:` is the port separator?). The C is
                    // probably never tested with IPv6 proxy targets.
                    // We use `SocketAddr::Display` (brackets v6).
                    let line = format!("CONNECT {target} HTTP/1.1\r\n\r\n");
                    needs_write |= conn.send_raw(line.as_bytes());
                    log::debug!(target: "tincd::conn",
                        "Queued HTTP CONNECT for {} → {target}", conn.name);
                    // No tcplen — response is line-based, handled
                    // by the intercept in metaconn.rs BEFORE
                    // check_gate (`protocol.c:148-161`).
                }
                ProxyConfig::Socks4 { .. } | ProxyConfig::Socks5 { .. } => {
                    // C `protocol_auth.c:71-77`: `c->tcplen =
                    // create_socks_req(...); send_meta(c, req,
                    // reqlen)`. Target is `c->address` — the PEER
                    // addr (the proxy is just transport). `send_
                    // meta` is raw bytes, no `\n`.
                    let Some(target) = conn.address else {
                        // Shouldn't happen: new_outgoing always sets
                        // address. Defensive.
                        log::error!(target: "tincd::conn",
                            "SOCKS proxy: no peer address on {}", conn.name);
                        self.terminate(id);
                        return;
                    };
                    let socks_type = proxy.socks_type().expect("Socks4/5 arm");
                    let creds = proxy.socks_creds();
                    match socks::build_request(socks_type, target, creds.as_ref()) {
                        Ok((bytes, resp_len)) => {
                            // C `:75`: `c->tcplen = create_socks_
                            // req(...)`. The return value is the
                            // expected response length. `:76`:
                            // `send_meta(c, req, reqlen)` — raw,
                            // no `\n`. Our `send_raw` matches.
                            needs_write |= conn.send_raw(&bytes);
                            // resp_len fits u16: SOCKS5 max is
                            // 2+2+4+18 = 26 bytes. SOCKS4 is 8.
                            #[allow(clippy::cast_possible_truncation)]
                            {
                                conn.tcplen = resp_len as u16;
                            }
                            log::debug!(target: "tincd::conn",
                                "Queued {} SOCKS bytes for {}, expecting {} reply bytes",
                                bytes.len(), conn.name, resp_len);
                        }
                        Err(e) => {
                            // SOCKS4 + IPv6, or 256-byte cred
                            // (C-is-WRONG #9). Config-level error
                            // really, but we only know `target` at
                            // connect time.
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

        // C `:425`: `send_id(c)`. WE go first (initiator). The
        // peer's `id_h:451` `if(!c->outgoing) send_id(c)` replies.
        // Same line as our responder-side `handle_id` sends.
        // Re-get conn: terminate above may have removed it. Actually
        // — we returned in those branches. Still valid.
        let conn = self.conns.get_mut(id).expect("not terminated");
        needs_write |= conn.send(format_args!(
            "{} {} {}.{}",
            Request::Id as u8,
            self.name,
            tinc_proto::request::PROT_MAJOR,
            tinc_proto::request::PROT_MINOR
        ));

        // Re-register: we were ReadWrite (for the WRITE-probe wake);
        // now we want READ (for the peer's ID reply). If we just
        // queued data, ReadWrite (let it flush). C `:658` registers
        // READ|WRITE always; `handle_meta_write` (`:509`) drops
        // WRITE when outbuf empties. Same.
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
