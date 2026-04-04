#![forbid(unsafe_code)]

#[allow(clippy::wildcard_imports)]
use super::*;

/// `Again`: caller should loop (kernel may have more). `Done`: stop.
enum FeedDrain {
    Again,
    Done,
}

impl Daemon {
    /// `handle_new_unix_connection` (`net_socket.c:781-812`).
    pub(super) fn on_unix_accept(&mut self) {
        let stream = match self.control.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
            Err(e) => {
                // C `:792`
                log::error!(target: "tincd::conn",
                            "Accepting a new connection failed: {e}");
                return;
            }
        };

        // C `:798-811`: new_connection + io_add + connection_add.
        let fd: OwnedFd = stream.into();
        let conn = Connection::new_control(fd, self.timers.now());
        let conn_fd = conn.fd();

        let id = self.conns.insert(conn);
        // C `:807`: io_add IO_READ only; `send` adds WRITE later.
        match self.ev.add(conn_fd, Io::Read, IoWhat::Conn(id)) {
            Ok(io_id) => {
                self.conn_io.insert(id, io_id);
                log::info!(target: "tincd::conn",
                           "Connection from {} (control)",
                           self.conns[id].hostname);
            }
            Err(e) => {
                self.conns.remove(id);
                log::error!(target: "tincd::conn",
                            "Failed to register connection: {e}");
            }
        }
    }

    /// `handle_meta_io` READ path (`net_socket.c:559-561` → `receive_meta`).
    ///
    /// Edge-triggered drain wrapper. C `receive_meta` does ONE `recv()`
    /// per callback (`meta.c:185`) because C's event loop is level-
    /// triggered. mio is edge-triggered: returning before `EAGAIN`
    /// loses the wake forever (found by `throughput.rs` deadlock when
    /// TCP-tunnelled SPTPS_PACKETs filled the kernel buffer). Bounded
    /// at 64 iters (≈136KB/turn) so UDP/TUN/timers get a turn; rearm()
    /// forces the next epoll_wait to fire if still readable.
    pub(super) fn on_conn_readable(&mut self, id: ConnId) {
        const META_DRAIN_CAP: u32 = 64;
        for _ in 0..META_DRAIN_CAP {
            // Prior iteration may have terminated this conn.
            if !self.conns.contains_key(id) {
                return;
            }
            match self.on_conn_readable_once(id) {
                FeedDrain::Again => {}
                FeedDrain::Done => return,
            }
        }
        // Hit the cap; rearm so next turn() fires immediately.
        if let Some(&io_id) = self.conn_io.get(id)
            && let Err(e) = self.ev.rearm(io_id)
        {
            log::error!(target: "tincd::conn",
                            "conn fd rearm failed for {id:?}: {e}");
            self.terminate(id);
        }
    }

    /// One `recv()` + dispatch. C `receive_meta` + `receive_request`
    /// (`meta.c:164-320`). Splitting would thread id/conn/self borrows.
    #[allow(clippy::too_many_lines)]
    fn on_conn_readable_once(&mut self, id: ConnId) -> FeedDrain {
        // C `meta.c:185`: one recv.
        let conn = self.conns.get_mut(id).expect("checked contains_key");
        match conn.feed(&mut OsRng) {
            FeedResult::WouldBlock => return FeedDrain::Done,
            FeedResult::Dead => {
                self.terminate(id);
                return FeedDrain::Done;
            }
            FeedResult::Data => {
                // ─── pre-SPTPS tcplen consume (SOCKS proxy reply)
                // C `meta.c:275-298`. Same `c->tcplen` field as the
                // SPTPS PACKET-blob path but consumed HERE (raw
                // read_n, before SPTPS-start). Mutually exclusive
                // with the Sptps arm. C gate: `:282-283`.
                let conn = self.conns.get_mut(id).expect("just fed");
                if conn.tcplen != 0
                    && conn.outgoing.is_some()
                    && conn.allow_request == Some(Request::Id)
                {
                    let n = usize::from(conn.tcplen);
                    let Some(range) = conn.inbuf.read_n(n) else {
                        // C `:278-280`: partial. Do NOT fall through to
                        // read_line (SOCKS bytes would parse as garbage).
                        return FeedDrain::Done;
                    };
                    let buf: Vec<u8> = conn.inbuf.bytes_raw()[range].to_vec();
                    conn.tcplen = 0;

                    // Only SOCKS sets tcplen in finish_connecting.
                    let Some(proxy) = &self.settings.proxy else {
                        // C `:288` abort case.
                        log::error!(target: "tincd::conn",
                            "tcplen set but no proxy configured for {}",
                            conn.name);
                        self.terminate(id);
                        return FeedDrain::Done;
                    };
                    let Some(socks_type) = proxy.socks_type() else {
                        log::error!(target: "tincd::conn",
                            "tcplen set but proxy is not SOCKS for {}",
                            conn.name);
                        self.terminate(id);
                        return FeedDrain::Done;
                    };
                    let creds = proxy.socks_creds();
                    match socks::check_response(socks_type, creds.as_ref(), &buf) {
                        socks::SocksResponse::Granted => {
                            // C `proxy.c:56`. Fall through: peer's ID
                            // may already be in inbuf (same segment).
                            log::debug!(target: "tincd::conn",
                                "Proxy request granted for {} ({n} reply bytes)",
                                conn.name);
                        }
                        socks::SocksResponse::Rejected => {
                            log::error!(target: "tincd::conn",
                                "Proxy request rejected for {}", conn.name);
                            self.terminate(id);
                            return FeedDrain::Done;
                        }
                        socks::SocksResponse::Malformed(why) => {
                            log::error!(target: "tincd::conn",
                                "Malformed proxy response for {}: {why}",
                                conn.name);
                            self.terminate(id);
                            return FeedDrain::Done;
                        }
                    }
                }
            }
            FeedResult::Sptps(events) => {
                // Order matters: an ADD_EDGE record before a blob can
                // change reachability that the blob's route reads.
                let mut needs_write = false;
                for ev in events {
                    match ev {
                        SptpsEvent::Record(o) => {
                            needs_write |= self.dispatch_sptps_outputs(id, vec![o]);
                        }
                        SptpsEvent::Blob(blob) => {
                            needs_write |= self.on_sptps_blob(id, &blob);
                        }
                    }
                    if !self.conns.contains_key(id) {
                        return FeedDrain::Done;
                    }
                }
                // Dispatch may have queued to ANY conn (broadcast,
                // forward, relay); sweep all.
                if needs_write {
                    self.maybe_set_write_any();
                }
                // SPTPS mode doesn't touch inbuf. Loop back to feed()
                // (edge-triggered; must drain to EAGAIN).
                return FeedDrain::Again;
            }
        }

        // ─── drain inbuf (C `meta.c:303-315`)
        loop {
            let conn = self.conns.get_mut(id).expect("not terminated mid-loop");
            let Some(range) = conn.inbuf.read_line() else {
                break;
            };
            // Copy: can't borrow bytes_raw() across &mut self calls.
            // Cheap (control lines <100 bytes).
            let line: Vec<u8> = conn.inbuf.bytes_raw()[range].to_vec();

            // ─── HTTP proxy response intercept (`protocol.c:148-161`)
            // `read_line` excludes `\n`, includes `\r`.
            //
            // C-is-WRONG #10 (dormant): the fall-through means header
            // lines (Via:, Content-Type:) go to atoi → 0 → terminate.
            // RFC 7231 §4.3.6 permits headers in 2xx CONNECT. proxy.py
            // sends none so C never triggers; real proxies (Squid) do.
            // We mirror C exactly.
            // TODO(http-proxy-lenient): skip lines until blank.
            if conn.outgoing.is_some()
                && conn.allow_request == Some(Request::Id)
                && matches!(self.settings.proxy, Some(ProxyConfig::Http { .. }))
            {
                if line.is_empty() || line[0] == b'\r' {
                    continue; // C `:149`: blank line
                }
                // C `:153`: strncasecmp (RFC 7230 case-insensitive).
                if line.len() >= 12 && line[..9].eq_ignore_ascii_case(b"HTTP/1.1 ") {
                    if &line[9..12] == b"200" {
                        log::debug!(target: "tincd::conn",
                            "HTTP proxy request granted for {}", conn.name);
                        continue;
                    }
                    let status = String::from_utf8_lossy(&line[9..]);
                    log::error!(target: "tincd::conn",
                        "HTTP proxy request rejected for {}: {}",
                        conn.name, status.trim_end_matches('\r'));
                    self.terminate(id);
                    return FeedDrain::Done;
                }
                // Fall through — the C bug (header → check_gate → terminate).
            }

            // ─── check_gate (protocol.c:164-178)
            let req = match check_gate(conn, &line) {
                Ok(r) => r,
                Err(e) => {
                    log::error!(target: "tincd::proto",
                                "Bad request from {}: {e:?}", conn.name);
                    self.terminate(id);
                    return FeedDrain::Done;
                }
            };

            // ─── handler dispatch (protocol.c:180 request_entries[] table)
            let (result, needs_write) = match req {
                Request::Id => {
                    // `id_h`. The clones aren't strictly needed (disjoint
                    // fields vs &mut self.conns) but cheap; keep for now.
                    let cookie = self.cookie.clone();
                    let my_name = self.name.clone();
                    let confbase = self.confbase.clone();
                    let ctx = IdCtx {
                        cookie: &cookie,
                        my_name: &my_name,
                        mykey: &self.mykey,
                        confbase: &confbase,
                        invitation_key: self.invitation_key.as_ref(),
                        global_pmtu: self.settings.global_pmtu,
                    };
                    let now = self.timers.now();
                    match handle_id(conn, &line, &ctx, now, &mut OsRng) {
                        Ok(IdOk::Control { needs_write }) => (DispatchResult::Ok, needs_write),
                        Ok(IdOk::Peer { needs_write, init }) => {
                            // SPTPS-start: queue init Wire (KEX),
                            // take_rest from inbuf, re-feed (the
                            // id-line piggyback), dispatch.
                            let mut nw = needs_write;
                            for o in init {
                                if let tinc_sptps::Output::Wire { bytes, .. } = o {
                                    nw |= conn.send_raw(&bytes);
                                }
                                // sptps_start only emits Wire.
                            }

                            // feed_sptps is an associated fn taking
                            // &mut Sptps directly (borrow split).
                            let leftover = conn.inbuf.take_rest();
                            let outs = if leftover.is_empty() {
                                Vec::new()
                            } else {
                                let sptps = conn
                                    .sptps
                                    .as_deref_mut()
                                    .expect("handle_id_peer just installed it");
                                match Connection::feed_sptps(
                                    sptps, &leftover, &conn.name, &mut OsRng,
                                ) {
                                    FeedResult::Sptps(evs) => evs
                                        .into_iter()
                                        .map(|ev| match ev {
                                            SptpsEvent::Record(o) => o,
                                            SptpsEvent::Blob(_) => {
                                                unreachable!("feed_sptps emits Record only")
                                            }
                                        })
                                        .collect(),
                                    FeedResult::Dead => {
                                        log::error!(
                                            target: "tincd::proto",
                                            "SPTPS error in piggyback from {}",
                                            conn.name
                                        );
                                        self.terminate(id);
                                        return FeedDrain::Done;
                                    }
                                    _ => unreachable!(),
                                }
                            };

                            if self.dispatch_sptps_outputs(id, outs) {
                                nw = true;
                            }
                            if !self.conns.contains_key(id) {
                                return FeedDrain::Done;
                            }

                            (DispatchResult::Ok, nw)
                        }
                        Ok(IdOk::Invitation { needs_write, init }) => {
                            // C `protocol_auth.c:340-373`. Same shape as
                            // Peer; the difference is `conn.invite` so
                            // dispatch_sptps_outputs early-branches.
                            // C `:353`: `c->status.invitation = true`.
                            conn.invite = Some(InvitePhase::WaitingCookie);

                            let mut nw = needs_write;
                            for o in init {
                                if let tinc_sptps::Output::Wire { bytes, .. } = o {
                                    nw |= conn.send_raw(&bytes);
                                }
                            }

                            let leftover = conn.inbuf.take_rest();
                            let outs = if leftover.is_empty() {
                                Vec::new()
                            } else {
                                let sptps = conn
                                    .sptps
                                    .as_deref_mut()
                                    .expect("handle_id Invitation just installed it");
                                match Connection::feed_sptps(
                                    sptps, &leftover, &conn.name, &mut OsRng,
                                ) {
                                    FeedResult::Sptps(evs) => evs
                                        .into_iter()
                                        .map(|ev| match ev {
                                            SptpsEvent::Record(o) => o,
                                            SptpsEvent::Blob(_) => {
                                                unreachable!("feed_sptps emits Record only")
                                            }
                                        })
                                        .collect(),
                                    FeedResult::Dead => {
                                        log::error!(
                                            target: "tincd::proto",
                                            "SPTPS error in invitation piggyback from {}",
                                            conn.hostname
                                        );
                                        self.terminate(id);
                                        return FeedDrain::Done;
                                    }
                                    _ => unreachable!(),
                                }
                            };

                            if self.dispatch_sptps_outputs(id, outs) {
                                nw = true;
                            }
                            if !self.conns.contains_key(id) {
                                return FeedDrain::Done;
                            }

                            (DispatchResult::Ok, nw)
                        }
                        Err(e) => {
                            log::error!(target: "tincd::proto",
                                        "ID rejected from {}: {e:?}", conn.name);
                            (DispatchResult::Drop, false)
                        }
                    }
                }
                Request::Control => {
                    let (r, nw) = handle_control(conn, &line);
                    // Dump arms: build rows with `&self` borrowed, drop
                    // it, re-fetch `&mut conn`, then `send_dump` writes
                    // rows + the bare-header terminator (C `:406/:221/
                    // :135/:173`). Same shape ×4; the terminator format
                    // is identical across all four C dump functions.
                    if matches!(r, DispatchResult::DumpSubnets) {
                        // `dump_subnets` (`subnet.c:395-410`).
                        let rows: Vec<String> = self
                            .subnets
                            .iter()
                            .map(|(subnet, owner)| {
                                format!(
                                    "{} {} {} {}",
                                    Request::Control as u8,
                                    crate::proto::REQ_DUMP_SUBNETS,
                                    subnet,
                                    owner
                                )
                            })
                            .collect();
                        let conn = self.conns.get_mut(id).expect("not terminated");
                        let nw2 = conn.send_dump(rows, crate::proto::REQ_DUMP_SUBNETS);
                        (DispatchResult::Ok, nw2)
                    } else if matches!(r, DispatchResult::DumpNodes) {
                        // `dump_nodes` (`node.c:201-223`).
                        let rows = self.dump_nodes_rows();
                        let conn = self.conns.get_mut(id).expect("not terminated");
                        let nw2 = conn.send_dump(rows, crate::proto::REQ_DUMP_NODES);
                        (DispatchResult::Ok, nw2)
                    } else if matches!(r, DispatchResult::DumpEdges) {
                        // `dump_edges` (`edge.c:123-137`).
                        let rows = self.dump_edges_rows();
                        let conn = self.conns.get_mut(id).expect("not terminated");
                        let nw2 = conn.send_dump(rows, crate::proto::REQ_DUMP_EDGES);
                        (DispatchResult::Ok, nw2)
                    } else if matches!(r, DispatchResult::DumpConnections) {
                        // `dump_connections` (`connection.c:166-175`).
                        let rows: Vec<String> = self
                            .conns
                            .values()
                            .map(|c| {
                                // `connection.c:168`: `"%d %d %s %s %x %d %x"`.
                                // hostname is the fused "host port port" string.
                                format!(
                                    "{} {} {} {} {:x} {} {:x}",
                                    Request::Control as u8,
                                    crate::proto::REQ_DUMP_CONNECTIONS,
                                    c.name,
                                    c.hostname,
                                    c.options.bits(),
                                    c.fd(),
                                    c.status_value()
                                )
                            })
                            .collect();
                        let conn = self.conns.get_mut(id).expect("not terminated");
                        let nw2 = conn.send_dump(rows, crate::proto::REQ_DUMP_CONNECTIONS);
                        (DispatchResult::Ok, nw2)
                    } else if matches!(r, DispatchResult::Reload) {
                        // C `control.c:56-57`. CLI only checks zero/nonzero.
                        let result = i32::from(!self.reload_configuration());
                        let conn = self.conns.get_mut(id).expect("not terminated");
                        let nw2 = conn.send(format_args!(
                            "{} {} {result}",
                            Request::Control as u8,
                            crate::proto::REQ_RELOAD
                        ));
                        (DispatchResult::Ok, nw2)
                    } else if matches!(r, DispatchResult::Retry) {
                        // C `control.c:95-96`: `retry(); control_ok(c, REQ_RETRY)`.
                        self.on_retry();
                        let conn = self.conns.get_mut(id).expect("not terminated");
                        let nw2 = conn.send(format_args!(
                            "{} {} 0",
                            Request::Control as u8,
                            crate::proto::REQ_RETRY
                        ));
                        (DispatchResult::Ok, nw2)
                    } else if matches!(r, DispatchResult::Purge) {
                        // C `control.c:75-77`: `purge(); control_ok(c, REQ_PURGE)`.
                        let nw_purge = self.purge();
                        let conn = self.conns.get_mut(id).expect("not terminated");
                        let nw2 = conn.send(format_args!(
                            "{} {} 0",
                            Request::Control as u8,
                            crate::proto::REQ_PURGE
                        ));
                        (DispatchResult::Ok, nw_purge | nw2)
                    } else if let DispatchResult::SetDebug(level) = r {
                        // C `control.c:79-93`. Reply with PREVIOUS
                        // level (`:86` send_request happens BEFORE
                        // the assignment at `:89`). `level >= 0` →
                        // update; `< 0` → query-only. None → C `:83`
                        // `return false` (terminate ctl conn — the
                        // ONLY ctl arm in C that does this; the rest
                        // reply REQ_INVALID and stay up).
                        let Some(level) = level else {
                            self.terminate(id);
                            return FeedDrain::Done;
                        };
                        let prev = crate::log_tap::set_debug_level(level);
                        let conn = self.conns.get_mut(id).expect("not terminated");
                        let nw2 = conn.send(format_args!(
                            "{} {} {prev}",
                            Request::Control as u8,
                            crate::proto::REQ_SET_DEBUG
                        ));
                        (DispatchResult::Ok, nw2)
                    } else if let DispatchResult::Disconnect(name) = r {
                        // C `control.c:102-122`. Walk conns, terminate
                        // by name. C `:116`: `terminate_connection(o,
                        // o->edge)` — our `terminate()` keys DEL_EDGE
                        // on `conn.active` already (same semantics).
                        // Control conns are skipped: their name is
                        // `<control>` (proto.rs:254), so a valid node
                        // name never matches; also covers self-disconnect.
                        let result = match name {
                            None => -1, // C `:108`: sscanf failed
                            Some(name) => {
                                let to_term: Vec<ConnId> = self
                                    .conns
                                    .iter()
                                    .filter(|(_, c)| !c.control && c.name == name)
                                    .map(|(cid, _)| cid)
                                    .collect();
                                let found = !to_term.is_empty();
                                for cid in to_term {
                                    self.terminate(cid);
                                }
                                if found { 0 } else { -2 }
                            }
                        };
                        // `terminate()` only touches the matched conn;
                        // the ctl conn `id` is still here.
                        let conn = self.conns.get_mut(id).expect("not terminated");
                        let nw2 = conn.send(format_args!(
                            "{} {} {result}",
                            Request::Control as u8,
                            crate::proto::REQ_DISCONNECT
                        ));
                        (DispatchResult::Ok, nw2)
                    } else if matches!(r, DispatchResult::DumpTraffic) {
                        // `dump_traffic` (`node.c:226-231`).
                        let rows = self.dump_traffic_rows();
                        let conn = self.conns.get_mut(id).expect("not terminated");
                        let nw2 = conn.send_dump(rows, crate::proto::REQ_DUMP_TRAFFIC);
                        (DispatchResult::Ok, nw2)
                    } else if let DispatchResult::Log(level) = r {
                        // C `control.c:133-140`: `c->status.log = true`,
                        // `c->log_level = CLAMP(level, ...)`, `logcontrol
                        // = true`. No reply (C `:140`: `return true`
                        // without `control_ok`). The conn now passively
                        // receives log records via `flush_log_tap`.
                        //
                        // C-level → `log::Level`. C debug levels
                        // (`logger.h:26-38`): -1=UNSET, 0=ALWAYS,
                        // 1=CONNECTIONS, ..., 5=TRAFFIC, ..., 10=SCARY.
                        // Map roughly: 0→Info, 1-2→Debug, 3+→Trace.
                        // Same shape as `main.rs::debug_level_to_filter`.
                        // -1 (UNSET) = "use daemon's level"; we use
                        // Trace (everything the tap captures — the
                        // daemon's stderr filter already applied).
                        let conn = self.conns.get_mut(id).expect("not terminated");
                        conn.log_level = Some(match level {
                            i32::MIN..=-1 => log::Level::Trace,
                            0 => log::Level::Info,
                            1 | 2 => log::Level::Debug,
                            _ => log::Level::Trace,
                        });
                        // C `:139`: `logcontrol = true`. Our gate.
                        crate::log_tap::set_active(true);
                        (DispatchResult::Ok, false)
                    } else if let DispatchResult::Pcap(snaplen) = r {
                        // C `control.c:127-131`. NO `control_ok` reply
                        // (`:131` is plain `return true`): the CLI
                        // (`tincctl.c:618`) writes the global pcap
                        // header then immediately starts reading
                        // `"18 14 LEN"` lines — a `"18 14 0"` ack would
                        // be misparsed as a 0-byte capture.
                        let conn = self.conns.get_mut(id).expect("not terminated");
                        conn.pcap = true;
                        conn.pcap_snaplen = snaplen;
                        // C `:130`: `pcap = true` (the route.c gate).
                        self.any_pcap = true;
                        (DispatchResult::Ok, false)
                    } else {
                        (r, nw)
                    }
                }
                _ => {
                    // allow_request gates to ID/CONTROL; shouldn't fire.
                    log::error!(target: "tincd::proto",
                                "Request {req:?} not implemented");
                    (DispatchResult::Drop, false)
                }
            };

            // C `meta.c:95`: io_set. Handler may have queued to OTHER
            // conns; sweep all (cheap, ~5 conns).
            if needs_write {
                self.maybe_set_write_any();
            }

            match result {
                // Dump variants rewritten inline above; explicit so a
                // new variant fails to compile.
                DispatchResult::DumpConnections
                | DispatchResult::DumpSubnets
                | DispatchResult::DumpNodes
                | DispatchResult::DumpEdges
                | DispatchResult::Reload
                | DispatchResult::Retry
                | DispatchResult::Purge
                | DispatchResult::Disconnect(_)
                | DispatchResult::DumpTraffic
                | DispatchResult::Log(_)
                | DispatchResult::Pcap(_)
                | DispatchResult::SetDebug(_) => {
                    unreachable!("Dump/Reload variants rewritten inline above")
                }
                DispatchResult::Ok => {}
                DispatchResult::Stop => {
                    // `event_exit()`. Don't return: finish this turn so
                    // the queued reply's WRITE event fires.
                    self.running = false;
                }
                DispatchResult::Drop => {
                    self.terminate(id);
                    return FeedDrain::Done;
                }
            }
        }
        // inbuf drained; more may be in the kernel — loop back.
        FeedDrain::Again
    }

    /// `receive_meta_sptps` (`meta.c:120-162`). Returns io_set signal.
    /// May `terminate(id)` — caller checks `conns.contains_key(id)`.
    /// Arms: Wire→`:50`, HandshakeDone→`:129-135`, Record→`:153-161`.
    #[allow(clippy::too_many_lines)] // C `receive_meta_sptps` is one function; the request-dispatch table is half of it
    pub(super) fn dispatch_sptps_outputs(
        &mut self,
        id: ConnId,
        outs: Vec<tinc_sptps::Output>,
    ) -> bool {
        use tinc_sptps::Output;

        // C `protocol_auth.c:372` sets a different callback for invites.
        // Our Sptps is callback-free, so branch here on `conn.invite`.
        if self.conns.get(id).is_some_and(|c| c.invite.is_some()) {
            return self.dispatch_invitation_outputs(id, outs);
        }

        let mut needs_write = false;
        for o in outs {
            let Some(conn) = self.conns.get_mut(id) else {
                return needs_write;
            };
            match o {
                Output::Wire { bytes, .. } => {
                    needs_write |= conn.send_raw(&bytes); // C `meta.c:50`
                }
                Output::HandshakeDone => {
                    // C `meta.c:129-135`: `if(allow_request==ACK)
                    // send_ack(c) else return true`. The else is for
                    // the SECOND HandshakeDone during rekey.
                    log::info!(target: "tincd::auth",
                               "SPTPS handshake completed with {} ({})",
                               conn.name, conn.hostname);
                    if conn.allow_request == Some(Request::Ack) {
                        let now = self.timers.now();
                        needs_write |= send_ack(
                            conn,
                            self.my_udp_port,
                            self.myself_options,
                            self.settings.global_weight,
                            now,
                        );
                    }
                }
                Output::Record { mut bytes, .. } => {
                    // ─── `c->tcplen` short-circuit (C `meta.c:143-151`)
                    // PACKET 17 sets tcplen; the NEXT record is a raw
                    // VPN blob (single-encrypted, meta-SPTPS only —
                    // direct neighbors only per `net_packet.c:725`).
                    // WIRE BUG found by crossimpl.rs: before this branch
                    // we'd terminate on every probe.
                    if conn.tcplen != 0 {
                        // C `:144`: SPTPS records are exact; mismatch
                        // is a framing bug, not a partial read.
                        if bytes.len() != usize::from(conn.tcplen) {
                            log::error!(target: "tincd::proto",
                                "TCP packet length mismatch from {}: \
                                 record {} != tcplen {}",
                                conn.name, bytes.len(), conn.tcplen);
                            self.terminate(id);
                            return needs_write;
                        }
                        // C `:148-150` + `receive_tcppacket` (`net_packet.c:595-614`) inlined.
                        conn.tcplen = 0;
                        // C `:599-601`: oversize → drop packet, KEEP conn.
                        if bytes.len() > usize::from(crate::tunnel::MTU) {
                            log::warn!(target: "tincd::proto",
                                "Oversized PACKET 17 from {} ({} > MTU {})",
                                conn.name, bytes.len(), crate::tunnel::MTU);
                            continue;
                        }
                        let conn_name = conn.name.clone();
                        // C `:613`. `c->node` set at ack_h; PACKET 17 before ACK is a peer bug.
                        let Some(from_nid) = self.node_ids.get(&conn_name).copied() else {
                            log::warn!(target: "tincd::proto",
                                "PACKET 17 from {conn_name} before ACK — dropping");
                            continue;
                        };
                        // C `receive_packet:397-405`: counters + route.
                        let len = bytes.len() as u64;
                        let tunnel = self.tunnels.entry(from_nid).or_default();
                        tunnel.in_packets += 1;
                        tunnel.in_bytes += len;
                        needs_write |= self.route_packet(&mut bytes, Some(from_nid));
                        continue;
                    }

                    // C `meta.c:155-161`: strip `\n`, dispatch.
                    let body = record_body(&bytes);

                    let req = match check_gate(conn, body) {
                        Ok(r) => r,
                        Err(e) => {
                            log::error!(target: "tincd::proto",
                                        "Bad SPTPS request from {}: {e:?}", conn.name);
                            self.terminate(id);
                            return needs_write;
                        }
                    };

                    // C `request_entries[]` (`protocol.c:58-86`).
                    let result = match req {
                        Request::Ack => self.on_ack(id, body),
                        Request::AddSubnet => self.on_add_subnet(id, body),
                        Request::DelSubnet => self.on_del_subnet(id, body),
                        Request::AddEdge => self.on_add_edge(id, body),
                        Request::DelEdge => self.on_del_edge(id, body),
                        Request::ReqKey => self.on_req_key(id, body),
                        Request::AnsKey => self.on_ans_key(id, body),
                        Request::UdpInfo => self.on_udp_info(id, body),
                        Request::MtuInfo => self.on_mtu_info(id, body),
                        Request::Ping => {
                            // `ping_h` (`protocol_misc.c:54-57`): send_pong.
                            let conn = self.conns.get_mut(id).expect("gate passed");
                            Ok(conn.send(format_args!("{}", Request::Pong as u8)))
                        }
                        Request::Pong => {
                            // `pong_h` (`protocol_misc.c:63-76`).
                            let conn = self.conns.get_mut(id).expect("gate passed");
                            conn.pinged = false; // C `:65`
                            // C `:69`: gate on non-zero timeout (healthy
                            // conn pongs every pinginterval; don't churn).
                            let oid = conn.outgoing.map(OutgoingId::from);
                            let addr = conn.address;
                            if let Some(oid) = oid
                                && let Some(out) = self.outgoings.get_mut(oid)
                                && out.timeout != 0
                            {
                                out.timeout = 0; // C `:70`
                                out.addr_cache.reset(); // C `:71-72`
                                if let Some(a) = addr {
                                    out.addr_cache.add_recent(a);
                                }
                            }
                            Ok(false)
                        }
                        Request::Packet => {
                            // `tcppacket_h` (`protocol_misc.c:105-119`):
                            // set tcplen; NEXT record is the blob.
                            let conn = self.conns.get_mut(id).expect("gate passed");
                            std::str::from_utf8(body)
                                .ok()
                                .and_then(|s| tinc_proto::msg::TcpPacket::parse(s).ok())
                                .map_or_else(
                                    || Err(DispatchError::BadKey("PACKET parse".into())),
                                    |pkt| {
                                        conn.tcplen = pkt.len;
                                        Ok(false)
                                    },
                                )
                        }
                        Request::KeyChanged => {
                            // `key_changed_h` (`protocol_key.c:63-
                            // 96`). C: parse name (`:67`), `seen_
                            // request` (`:73`), lookup_node, `if(!
                            // sptps) invalidate keys` (`:85` — DEAD
                            // for us, all peers are sptps), forward
                            // (`:92`), `return true` (`:95`). C
                            // peers built WITHOUT `-Dcrypto=nolegacy`
                            // (i.e. all distro builds) broadcast
                            // this every `KeyExpire` seconds (default
                            // 3600). Before this fix, we'd terminate
                            // every C connection at the one-hour
                            // mark. Bug audit `deef1268`.
                            //
                            // We don't `lookup_node` — the `:85`
                            // body is dead for SPTPS-only and `:80`
                            // is just a log line. The forward is the
                            // only thing that matters.
                            //
                            // TODO: cross-impl regression — build
                            // a `tincd-c-legacy` flake output WITHOUT
                            // `-Dcrypto=nolegacy` and assert the conn
                            // survives a KEY_CHANGED. crossimpl runs
                            // for ~10s; default KeyExpire is 3600s,
                            // so set `KeyExpire = 5` in the C peer's
                            // tinc.conf for that test.
                            if self.seen_request(body) {
                                Ok(false)
                            } else if self.settings.tunnelserver {
                                // C `:92` `if(!tunnelserver)`.
                                Ok(false)
                            } else {
                                Ok(self.forward_request(id, body))
                            }
                        }
                        Request::Status => {
                            // `status_h` (`protocol_misc.c:32-47`): log,
                            // noop. Bug audit `deef1268`: was terminating.
                            log::info!(target: "tincd::proto",
                                       "Status from peer: {:?}",
                                       std::str::from_utf8(body).unwrap_or("<non-utf8>"));
                            Ok(false)
                        }
                        Request::Error | Request::Termreq => {
                            // `error_h`/`termreq_h` (`protocol_misc.c:49-71`):
                            // C `return false` = terminate. Explicit so
                            // catch-all below is ONLY truly-unhandled.
                            log::warn!(target: "tincd::proto",
                                       "{req:?} from peer: {:?}",
                                       std::str::from_utf8(body).unwrap_or("<non-utf8>"));
                            self.terminate(id);
                            return needs_write;
                        }
                        _ => {
                            // SPTPS_PACKET (21) is consumed inside feed().
                            // Reaching here = a Request variant with no
                            // handler — a port gap.
                            log::warn!(target: "tincd::proto",
                                       "SPTPS request {req:?} not implemented");
                            self.terminate(id);
                            return needs_write;
                        }
                    };
                    match result {
                        Ok(nw) => needs_write |= nw,
                        Err(e) => {
                            log::error!(target: "tincd::proto",
                                        "{req:?} from {id:?}: {e:?}");
                            self.terminate(id);
                            return needs_write;
                        }
                    }
                }
            }
        }
        needs_write
    }

    /// `receive_tcppacket_sptps` (`net_packet.c:616-680`). Blob is an
    /// already-encrypted SPTPS UDP wireframe (`dst[6]‖src[6]‖ct`).
    /// Inlined ladder (vs `tcp_tunnel::route()`): we already have
    /// NodeIds from id6_table; avoids name→NodeId reverse lookup.
    pub(super) fn on_sptps_blob(&mut self, id: ConnId, blob: &[u8]) -> bool {
        // C `:617`: len < 12 → hard error.
        let Some((dst_id, src_id, ct)) = crate::tcp_tunnel::parse_frame(blob) else {
            log::error!(target: "tincd::net",
                        "Got too short SPTPS_PACKET ({} bytes)", blob.len());
            self.terminate(id);
            return false;
        };

        // C `:622-628`: lookup dst. `:627 return true` = keep conn, drop packet.
        let Some(to_nid) = self.id6_table.lookup(dst_id) else {
            log::warn!(target: "tincd::net",
                       "Got SPTPS_PACKET for unknown dest {dst_id}");
            return false;
        };

        // C `:631-637`
        let Some(from_nid) = self.id6_table.lookup(src_id) else {
            log::warn!(target: "tincd::net",
                       "Got SPTPS_PACKET for {dst_id} from unknown src {src_id}");
            return false;
        };
        let from_name = self.node_log_name(from_nid).to_owned();

        // C `:640-644`: reachable check (race vs DEL_EDGE).
        if !self.graph.node(to_nid).is_some_and(|n| n.reachable) {
            let to_name = self.node_log_name(to_nid);
            log::warn!(target: "tincd::net",
                       "Got SPTPS_PACKET from {from_name} for {to_name} \
                        which is unreachable");
            return false;
        }

        // C `:649-651`: send_udp_info, gated on `to->via == myself`
        // (static-relay check; for to==myself it's the sssp seed invariant).
        let to_via = self
            .last_routes
            .get(to_nid.0 as usize)
            .and_then(Option::as_ref)
            .map(|r| r.via);
        let mut nw = false;
        if to_via == Some(self.myself) {
            nw |= self.send_udp_info(from_nid, &from_name, true);
        }

        // C `:654-659`: relay. validkey gate skips unkeyed tunnels
        // (would buffer and stall). `:659`: try_tx always.
        if to_nid != self.myself {
            let validkey = self.tunnels.get(&to_nid).is_some_and(|t| t.status.validkey);
            if validkey {
                log::debug!(target: "tincd::net",
                            "Relaying SPTPS_PACKET {from_name} → {} \
                             ({} bytes)",
                            self.node_log_name(to_nid), ct.len());
                nw |= self.send_sptps_data_relay(to_nid, from_nid, 0, Some(ct));
            }
            nw |= self.try_tx(to_nid, true);
            return nw;
        }

        // C `:664-680`: deliver local. udppacket bit stays false (came via TCP).
        let Some(sptps) = self
            .tunnels
            .get_mut(&from_nid)
            .and_then(|t| t.sptps.as_deref_mut())
        else {
            // C `:664-667`: `if(!from->status.validkey)`; sptps presence is our proxy.
            log::debug!(target: "tincd::net",
                        "Got SPTPS_PACKET from {from_name} but no \
                         tunnel SPTPS state");
            nw |= self.send_req_key(from_nid);
            return nw;
        };
        let result = sptps.receive(ct, &mut OsRng);
        let outs = match result {
            Ok((_consumed, outs)) => outs,
            Err(e) => {
                // C `:674-679`: tunnel-stuck restart, gated on last_req_key+10s.
                log::debug!(target: "tincd::net",
                            "Failed to decode SPTPS_PACKET from \
                             {from_name}: {e:?}");
                let now = self.timers.now();
                let gate_ok = self.tunnels.get(&from_nid).is_none_or(|t| {
                    t.last_req_key
                        .is_none_or(|last| now.duration_since(last).as_secs() >= 10)
                });
                if gate_ok {
                    nw |= self.send_req_key(from_nid);
                }
                return nw;
            }
        };
        nw |= self.dispatch_tunnel_outputs(from_nid, &from_name, outs);
        // C `:680`: tell upstream relays our MTU floor.
        nw |= self.send_mtu_info(from_nid, &from_name, i32::from(MTU), true);
        nw
    }

    /// `receive_invitation_sptps` (`protocol_auth.c:185-310`).
    /// Records dispatch by `(type, InvitePhase)`, NOT `check_gate` —
    /// the bytes are file chunks and b64 pubkeys, not request lines.
    /// State machine = C's `c->status.invitation_used`.
    #[allow(clippy::too_many_lines)] // C is 125 lines; cookie→file→chunk→send shares too much state to split
    pub(super) fn dispatch_invitation_outputs(
        &mut self,
        id: ConnId,
        outs: Vec<tinc_sptps::Output>,
    ) -> bool {
        use tinc_sptps::Output;
        let mut needs_write = false;

        for o in outs {
            let Some(conn) = self.conns.get_mut(id) else {
                return needs_write;
            };
            match o {
                Output::Wire { bytes, .. } => {
                    needs_write |= conn.send_raw(&bytes);
                }
                Output::HandshakeDone => {
                    // C `:188`: swallow. Invitations don't ACK.
                    log::debug!(target: "tincd::auth",
                                "Invitation SPTPS handshake done with {}",
                                conn.hostname);
                }
                Output::Record { record_type, bytes } => {
                    let phase = conn.invite.take();
                    let hostname = conn.hostname.clone();
                    let conn_addr = conn.address;

                    match (record_type, phase) {
                        // C `:196`: `if(type != 0 || len != 18 || invitation_used) return false`.
                        (0, Some(InvitePhase::WaitingCookie))
                            if bytes.len() == invitation_serve::COOKIE_LEN =>
                        {
                            let mut cookie = [0u8; invitation_serve::COOKIE_LEN];
                            cookie.copy_from_slice(&bytes);

                            // C `:341` already checked at id_h.
                            let Some(inv_key) = self.invitation_key.as_ref() else {
                                log::error!(target: "tincd::auth",
                                            "invitation key vanished mid-handshake");
                                self.terminate(id);
                                return needs_write;
                            };

                            // C `:201-277`
                            let result = invitation_serve::serve_cookie(
                                &self.confbase,
                                inv_key,
                                &cookie,
                                &self.name,
                                self.settings.invitation_lifetime,
                                SystemTime::now(),
                            );
                            let (contents, invited_name, used_path) = match result {
                                Ok(t) => t,
                                Err(e) => {
                                    log::error!(target: "tincd::auth",
                                                "Invitation from {hostname}: {e}");
                                    self.terminate(id);
                                    return needs_write;
                                }
                            };

                            // C `:285`: `c->name = xstrdup(name)`.
                            let Some(conn) = self.conns.get_mut(id) else {
                                return needs_write;
                            };
                            conn.name.clone_from(&invited_name);

                            // C `:294-303`: chunk file (1024 = C's `char buf[1024]`).
                            for chunk in invitation_serve::chunk_file(
                                &contents,
                                invitation_serve::CHUNK_SIZE,
                            ) {
                                needs_write |= conn.send_sptps_record(0, chunk);
                            }
                            needs_write |= conn.send_sptps_record(1, &[]); // C `:303`

                            // C `:305`: unlink BEFORE type-1 reply arrives;
                            // the rename already enforced single-use.
                            if let Err(e) = std::fs::remove_file(&used_path) {
                                log::warn!(target: "tincd::auth",
                                            "Failed to unlink {}: {e}",
                                            used_path.display());
                            }

                            // C `:307`
                            conn.invite = Some(InvitePhase::WaitingPubkey {
                                name: invited_name.clone(),
                                used_path,
                            });

                            log::info!(target: "tincd::auth",
                                        "Invitation successfully sent to {invited_name} ({hostname})");
                        }

                        // C `:192-193`: `if(type==1 && invitation_used) return finalize_invitation(...)`.
                        (1, Some(InvitePhase::WaitingPubkey { name, .. })) => {
                            // C `:122` newline check happens inside finalize().
                            let Ok(pubkey_b64) = std::str::from_utf8(&bytes) else {
                                log::error!(target: "tincd::auth",
                                            "Invalid pubkey from {name} ({hostname}): non-UTF-8");
                                self.terminate(id);
                                return needs_write;
                            };

                            // C `:128-144`
                            match invitation_serve::finalize(&self.confbase, &name, pubkey_b64) {
                                Ok(host_path) => {
                                    log::info!(target: "tincd::auth",
                                                "Key successfully received from {name} ({hostname}), \
                                                 wrote {}",
                                                host_path.display());
                                }
                                Err(e) => {
                                    log::error!(target: "tincd::auth",
                                                "Finalize invitation for {name} ({hostname}): {e}");
                                    self.terminate(id);
                                    return needs_write;
                                }
                            }

                            // C `:148-161`: write addr cache. Our cache
                            // is per-Outgoing not per-Node, but the C
                            // writes the file anyway so a future
                            // ConnectTo finds it. We do the same.
                            if let Some(addr) = conn_addr {
                                let mut cache = crate::addrcache::AddressCache::open(
                                    &self.confbase,
                                    &name,
                                    Vec::new(),
                                );
                                cache.add_recent(addr);
                                if let Err(e) = cache.save() {
                                    log::warn!(target: "tincd::auth",
                                                "Failed to save address cache for {name}: {e}");
                                }
                            }

                            // C `:164-179`
                            self.run_invitation_accepted_script(&name, conn_addr);

                            // C `:181`: empty type-2 = ACK; joiner closes after reading it.
                            let Some(conn) = self.conns.get_mut(id) else {
                                return needs_write;
                            };
                            needs_write |= conn.send_sptps_record(2, &[]);

                            // C `:182`: stay open (joiner closes; we EOF
                            // normally). Don't terminate — type-2 still
                            // in outbuf. Set invite back to a rejecting
                            // phase so stray records die cleanly.
                            conn.invite = Some(InvitePhase::WaitingCookie);
                        }

                        // C `:196`: `return false`.
                        (rt, ph) => {
                            log::error!(target: "tincd::auth",
                                        "Unexpected invitation record type={rt} \
                                         len={} phase={ph:?} from {hostname}",
                                        bytes.len());
                            self.terminate(id);
                            return needs_write;
                        }
                    }
                }
            }
        }
        needs_write
    }

    /// `protocol_auth.c:164-179`: invitation-accepted script.
    pub(super) fn run_invitation_accepted_script(&self, node: &str, addr: Option<SocketAddr>) {
        let mut env = ScriptEnv::base(None, &self.name, None, Some(&self.iface), None);
        env.add("NODE", node.to_owned()); // C `:170`
        if let Some(a) = addr {
            // C `:171-173`
            env.add("REMOTEADDRESS", a.ip().to_string());
            env.add("REMOTEPORT", a.port().to_string());
        }
        Self::log_script(
            "invitation-accepted",
            script::execute(&self.confbase, "invitation-accepted", &env, None),
        );
    }
}
