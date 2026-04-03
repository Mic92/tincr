#![forbid(unsafe_code)]

#[allow(clippy::wildcard_imports)]
use super::*;

/// `on_conn_readable_once` outcome. `Again`: `feed()` produced data
/// (kernel may have more queued; caller loops). `Done`: `WouldBlock`
/// or terminal (`Dead`, `terminate()` called).
enum FeedDrain {
    Again,
    Done,
}

impl Daemon {
    /// `handle_new_unix_connection` (`net_socket.c:781-812`).
    /// accept, allocate Connection, register with event loop.
    pub(super) fn on_unix_accept(&mut self) {
        // C `:789`: `fd = accept(io->fd, &sa.sa, &len)`.
        let stream = match self.control.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                // Spurious wakeup. Level-triggered: re-fires next
                // turn if still readable.
                return;
            }
            Err(e) => {
                // C `:792`: log ERR, return. Connection wasn't
                // accepted; nothing to clean up.
                log::error!(target: "tincd::conn",
                            "Accepting a new connection failed: {e}");
                return;
            }
        };

        // ─── allocate connection
        // C `:798-811`: `c = new_connection(); c->name = "<control>";
        // ...; io_add(); connection_add(c); c->allow_request = ID`.
        // Our `Connection::new_control` sets the same defaults.
        //
        // OwnedFd from UnixStream: `into()` works (UnixStream:
        // Into<OwnedFd> via std).
        let fd: OwnedFd = stream.into();
        let conn = Connection::new_control(fd, self.timers.now());
        let conn_fd = conn.fd();

        let id = self.conns.insert(conn);
        // C `:807`: `io_add(&c->io, handle_meta_io, c, c->socket,
        // IO_READ)`. Read-only initially; `send` adds WRITE.
        match self.ev.add(conn_fd, Io::Read, IoWhat::Conn(id)) {
            Ok(io_id) => {
                self.conn_io.insert(id, io_id);
                // C `:808`: `"Connection from %s", c->hostname`.
                // hostname is the literal `"localhost port unix"`.
                log::info!(target: "tincd::conn",
                           "Connection from {} (control)",
                           self.conns[id].hostname);
            }
            Err(e) => {
                // ev.add failed (out of fds?). Roll back.
                self.conns.remove(id);
                log::error!(target: "tincd::conn",
                            "Failed to register connection: {e}");
            }
        }
    }

    /// `handle_meta_io` READ path (`net_socket.c:559-561` →
    /// `handle_meta_connection_data` → `receive_meta`).
    ///
    /// Edge-triggered drain wrapper. The C `receive_meta` does ONE
    /// `recv()` per callback (`meta.c:185`) because the C event loop
    /// is level-triggered (`select()`/`epoll` without `EPOLLET`): if
    /// data remains, the next poll fires immediately. mio is
    /// edge-triggered: returning before `EAGAIN` loses the wake
    /// forever. Found by `throughput.rs::rust_vs_c_throughput`
    /// (Rust↔Rust 0.0 Mbps): when PMTU was still converging and big
    /// packets fell back to TCP-tunnelled SPTPS_PACKET (~2KB each
    /// after b64), one `recv()` of `MAXBUFSIZE`=2176 read about one
    /// message; the rest stayed in the kernel's TCP receive buffer;
    /// the edge had already fired; the receiver never read again;
    /// the sender's TCP send buffer filled; the tunnel deadlocked.
    ///
    /// The drain is bounded: under sustained meta-conn flooding,
    /// returning lets the rest of the event loop (UDP, TUN, timers)
    /// run. At the cap, `rearm()` forces an `EPOLL_CTL_MOD` so the
    /// next `epoll_wait` fires if still readable. `feed()` reads
    /// `MAXBUFSIZE`=2176 per call; 64 iterations ≈ 136KB/turn.
    pub(super) fn on_conn_readable(&mut self, id: ConnId) {
        const META_DRAIN_CAP: u32 = 64;
        for _ in 0..META_DRAIN_CAP {
            // The conn may have been terminated by the previous
            // iteration's dispatch (e.g. bad-request → terminate).
            // The slotmap generation check catches stale `id`s.
            if !self.conns.contains_key(id) {
                return;
            }
            match self.on_conn_readable_once(id) {
                FeedDrain::Again => {}
                FeedDrain::Done => return,
            }
        }
        // Hit the cap with the socket still readable. Rearm so the
        // next turn() fires immediately.
        if let Some(&io_id) = self.conn_io.get(id) {
            if let Err(e) = self.ev.rearm(io_id) {
                log::error!(target: "tincd::conn",
                            "conn fd rearm failed for {id:?}: {e}");
                self.terminate(id);
            }
        }
    }

    /// One `recv()` + dispatch. feed → loop read_line → check_gate
    /// → handler. Returns `Again` if `feed()` produced data (might
    /// be more queued; caller should loop), `Done` for `WouldBlock`
    /// or terminal states (`Dead`, fall-through after inbuf drain).
    ///
    /// `too_many_lines`: the C `receive_meta` + `receive_request`
    /// dispatch inlined (`meta.c:164-320` is 156 lines). Splitting
    /// would thread `id`/`conn`/`self` borrows through helpers.
    /// chunk-4b's send_ack didn't shrink this — it GREW it (the
    /// SPTPS-mode dispatch + ACK handling moved IN, not out). The
    /// allow stays; the borrow-threading cost is real.
    #[allow(clippy::too_many_lines)]
    fn on_conn_readable_once(&mut self, id: ConnId) -> FeedDrain {
        // ─── feed (one recv)
        // C `meta.c:185`: `inlen = recv(...)`.
        // `OsRng`: feed() needs an rng for the SPTPS-mode receive
        // path. Only touched on rekey (HANDSHAKE record post-
        // initial-handshake). `OsRng` is zero-sized; passing `&mut`
        // is free.
        let conn = self.conns.get_mut(id).expect("checked contains_key");
        match conn.feed(&mut OsRng) {
            FeedResult::WouldBlock => return FeedDrain::Done,
            FeedResult::Dead => {
                self.terminate(id);
                return FeedDrain::Done;
            }
            FeedResult::Data => {
                // ─── pre-SPTPS tcplen consume (SOCKS proxy reply) ────────
                // C `meta.c:275-298`: same `c->tcplen` field as the
                // SPTPS PACKET-blob path (consumed inside `Output::
                // Record` at the dispatch_sptps_outputs site), but
                // consumed HERE (raw `read_n`, not SPTPS record). The
                // two consume sites are MUTUALLY EXCLUSIVE: this arm
                // is `FeedResult::Data` (no `conn.sptps`); the other
                // is `FeedResult::Sptps`. A SOCKS proxy reply arrives
                // BEFORE id_h, so before SPTPS-start.
                //
                // C dispatch key: `!c->node` (`:282`). Ours: `tcplen
                // != 0` AND we're in the Data arm AND outgoing AND
                // allow_request==Id (the C's `c->outgoing && c->allow_
                // request == ID` at `:283`). The C abort()s on
                // tcplen-set-but-not-proxy-state (`:288`); we just
                // wouldn't enter the if (no SOCKS proxy configured →
                // tcplen never set in finish_connecting).
                let conn = self.conns.get_mut(id).expect("just fed");
                if conn.tcplen != 0
                    && conn.outgoing.is_some()
                    && conn.allow_request == Some(Request::Id)
                {
                    let n = usize::from(conn.tcplen);
                    let Some(range) = conn.inbuf.read_n(n) else {
                        // C `:278-280`: `if(!tcpbuffer) break`.
                        // Partial — the proxy's reply spans more
                        // than one TCP segment. Wait for next wake.
                        // CRITICAL: do NOT enter the read_line loop;
                        // it would parse SOCKS bytes as a request
                        // line (garbage — SOCKS5 starts with 0x05,
                        // which atoi parses as 5 = METAKEY, fails
                        // gate, terminates).
                        return FeedDrain::Done;
                    };
                    let buf: Vec<u8> = conn.inbuf.bytes_raw()[range].to_vec();
                    conn.tcplen = 0;

                    // The proxy type/creds come from settings (proxy
                    // is a single global config, not per-conn). We
                    // know it's SOCKS (only SOCKS sets tcplen in
                    // finish_connecting); unwrap is safe.
                    let Some(proxy) = &self.settings.proxy else {
                        // tcplen set but no proxy — the C's abort
                        // case. Shouldn't happen (only finish_
                        // connecting's SOCKS arm sets tcplen pre-
                        // SPTPS). Log + drop.
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
                            // C `proxy.c:56`: `log_proxy_grant(
                            // true)`. Tunnel established. Fall
                            // through to read_line — the peer's ID
                            // reply may already be in inbuf (the
                            // proxy forwarded it right after its
                            // own reply; same TCP segment is
                            // possible).
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
                // SPTPS-mode connection. Dispatch ordered events.
                // `Record` → dispatch_sptps_outputs (one at a time;
                // it loops internally but vec![o] is fine — this is
                // the meta-conn, not hot). `Blob` → on_sptps_blob.
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
                        // dispatch terminated.
                        return FeedDrain::Done;
                    }
                }
                // `dispatch_sptps_outputs` may have queued to ANY
                // active conn (`broadcast_line`, `forward_request`,
                // `conn_for_nexthop` relay). The `needs_write`
                // signal only tells us SOMETHING was queued; it
                // doesn't say WHERE. Sweep all conns. (The fast-
                // path `id`-only set below is now dead but kept
                // for the "only this conn was touched" common case
                // — maybe_set_write_any is a no-op for already-set
                // conns.)
                if needs_write {
                    self.maybe_set_write_any();
                }
                // Don't fall through to the line-drain loop —
                // SPTPS mode doesn't touch inbuf. DO loop back to
                // `feed()`: the kernel may have more bytes queued
                // (edge-triggered, must drain to EAGAIN).
                return FeedDrain::Again;
            }
        }

        // ─── drain inbuf (loop readline + dispatch)
        // C `meta.c:303-315`: `while(c->inbuf.len) { ... }`.
        // We loop until `read_line` returns None (incomplete).
        loop {
            let conn = self.conns.get_mut(id).expect("not terminated mid-loop");
            let Some(range) = conn.inbuf.read_line() else {
                break;
            };
            // The line bytes. `bytes_raw()` returns the full backing
            // slice; `range` indexes into it. We can't borrow
            // `bytes_raw()` and call `&mut self` methods, so: copy.
            //
            // The copy is cheap (control lines are <100 bytes). The
            // ALTERNATIVE is `read_line` returning a `Vec<u8>` —
            // same copy, hidden inside. Making it explicit means
            // chunk 4 can later avoid the copy for the SPTPS path
            // (which has 1500-byte frames and IS hot).
            let line: Vec<u8> = conn.inbuf.bytes_raw()[range].to_vec();

            // ─── HTTP proxy response intercept (`protocol.c:148-161`)
            // Gate: outgoing && proxy==HTTP && allow_request==Id.
            // The gate closes naturally when id_h changes
            // allow_request — no proxy_passed state needed (the C
            // doesn't have one either).
            //
            // `read_line` excludes `\n`, includes `\r`. So:
            //   "HTTP/1.1 200 OK\r\n" → b"HTTP/1.1 200 OK\r"
            //   "\r\n" (blank line)   → b"\r"
            //
            // Three cases:
            //   - blank/empty → skip (continue loop)
            //   - "HTTP/1.1 200" prefix → granted, skip
            //   - "HTTP/1.1 " non-200 → rejected, terminate
            //   - anything else → FALL THROUGH to check_gate
            //
            // C-is-WRONG #10 (dormant): the fall-through means
            // header lines (Via:, Content-Type:) go to atoi → 0 →
            // "Bogus data" → terminate. RFC 7231 §4.3.6 permits
            // headers in 2xx CONNECT. proxy.py:155 sends none, so
            // the C never triggers. Real proxies (Squid, nginx) DO
            // send them. We mirror the C exactly.
            // TODO(chunk-12-http-proxy-lenient): skip ANY line
            // until blank — would handle header-sending proxies.
            if conn.outgoing.is_some()
                && conn.allow_request == Some(Request::Id)
                && matches!(self.settings.proxy, Some(ProxyConfig::Http { .. }))
            {
                if line.is_empty() || line[0] == b'\r' {
                    // C `:149`: `if(!request[0] || request[0] ==
                    // '\r') return true`. Blank line.
                    continue;
                }
                // C `:153`: `strncasecmp(request, "HTTP/1.1 ", 9)`.
                // Case-insensitive (RFC 7230). `len >= 12` guards
                // the `[9..12]` slice against short status lines.
                if line.len() >= 12 && line[..9].eq_ignore_ascii_case(b"HTTP/1.1 ") {
                    // C `:154`: `strncmp(request + 9, "200", 3)`.
                    // Case-sensitive (status codes are numeric).
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
                // Fall through — the C bug. Header line goes to
                // check_gate → BadRequest → terminate. We mirror.
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

            // ─── handler dispatch (protocol.c:180)
            // C: `entry->handler(c, request)`. We match. The match
            // arms are the request_entries[] table.
            let (result, needs_write) = match req {
                Request::Id => {
                    // `id_h`. The ctx fields come from `&self` — we
                    // can't borrow `&self.cookie` while holding `&mut
                    // conn` (both borrow `self`). The cookie+name are
                    // small — clone. mykey is borrowed (the BLOB-clone
                    // for sptps_start happens INSIDE handle_id, only
                    // on the peer branch). confbase: borrow into a
                    // PathBuf clone (same shape as the others).
                    //
                    // Hold on — `&self.mykey` while `&mut conn` is
                    // borrowed from `&mut self.conns`? Disjoint
                    // fields. The borrow checker allows
                    // `&self.mykey` and `&mut self.conns[id]`
                    // simultaneously. The `.get_mut(id)` borrow IS
                    // through `&mut self.conns` not `&mut self`.
                    //
                    // Except: `conn` was bound at the top of the
                    // loop body via `self.conns.get_mut`. That's
                    // `&mut self.conns`. `&self.mykey` is fine
                    // (different field). `&self.cookie` is fine.
                    // The clones aren't NEEDED for borrow reasons —
                    // they were a habit from earlier chunks. KEEP
                    // them for now (clones are cheap, refactor later
                    // if profiling says so).
                    let cookie = self.cookie.clone();
                    let my_name = self.name.clone();
                    let confbase = self.confbase.clone();
                    let ctx = IdCtx {
                        cookie: &cookie,
                        my_name: &my_name,
                        mykey: &self.mykey,
                        confbase: &confbase,
                        invitation_key: self.invitation_key.as_ref(),
                    };
                    let now = self.timers.now();
                    match handle_id(conn, &line, &ctx, now, &mut OsRng) {
                        Ok(IdOk::Control { needs_write }) => (DispatchResult::Ok, needs_write),
                        Ok(IdOk::Peer { needs_write, init }) => {
                            // ─── SPTPS-start dispatch
                            // 1. Queue init Wire bytes (responder's KEX).
                            //    C `send_meta_sptps`: buffer_add to
                            //    outbuf. Our `send_raw`.
                            // 2. take_rest from inbuf, re-feed via
                            //    feed_sptps. The id-line piggyback.
                            // 3. Dispatch THOSE outputs too.
                            //
                            // For chunk 4a, step 3 (and the regular
                            // FeedResult::Sptps arm above) terminate
                            // on HandshakeDone — we don't have
                            // send_ack yet. The integration test
                            // proves the handshake completes; chunk
                            // 4b adds the ack.
                            let mut nw = needs_write;
                            for o in init {
                                if let tinc_sptps::Output::Wire { bytes, .. } = o {
                                    nw |= conn.send_raw(&bytes);
                                }
                                // Output::Record / HandshakeDone:
                                // unreachable from sptps_start (it
                                // only emits Wire). The match isn't
                                // exhaustive; we let other variants
                                // fall through silently. They're
                                // unreachable, and panicking would
                                // be noise.
                            }

                            // take_rest + re-feed. Factor as a
                            // method so the regular Sptps arm can
                            // call the same dispatch.
                            let leftover = conn.inbuf.take_rest();
                            // Self::feed_sptps borrows ONLY sptps,
                            // not conn. We can borrow sptps then
                            // dispatch the outputs (which need
                            // &mut conn.outbuf). Disjoint fields
                            // inside Connection — except: feed_sptps
                            // takes &mut Sptps via conn.sptps.
                            // as_deref_mut(), and send_raw is
                            // &mut self (Connection). Conflict.
                            //
                            // Same borrow problem as feed(). Same
                            // fix: feed_sptps is an associated fn
                            // taking &mut Sptps directly. We pull
                            // the deref out here.
                            let outs = if leftover.is_empty() {
                                // Fast path: no piggyback. Common.
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
                                            // feed_sptps doesn't peek
                                            // for "21 "; it can only
                                            // emit Record. The
                                            // piggyback is right
                                            // after id_h — sptpslen
                                            // can't be set anyway.
                                            SptpsEvent::Blob(_) => {
                                                unreachable!("feed_sptps emits Record only")
                                            }
                                        })
                                        .collect(),
                                    FeedResult::Dead => {
                                        // Piggybacked bytes were
                                        // garbage. Unusual (a real
                                        // peer's KEX is well-formed)
                                        // but possible (fuzzer).
                                        log::error!(
                                            target: "tincd::proto",
                                            "SPTPS error in piggyback from {}",
                                            conn.name
                                        );
                                        self.terminate(id);
                                        return FeedDrain::Done;
                                    }
                                    // feed_sptps only returns
                                    // Sptps or Dead.
                                    _ => unreachable!(),
                                }
                            };

                            // Dispatch piggyback outputs. Same
                            // shape as the regular Sptps arm. For
                            // chunk 4a: terminate on HandshakeDone.
                            // (Reaching HandshakeDone in the
                            // PIGGYBACK is unlikely — needs the
                            // initiator's KEX AND SIG in the same
                            // segment as the ID line. Three writes
                            // coalesced. Possible on a slow link.)
                            if self.dispatch_sptps_outputs(id, outs) {
                                nw = true;
                            }
                            // dispatch_sptps_outputs may have
                            // terminated (HandshakeDone in 4a).
                            // Check.
                            if !self.conns.contains_key(id) {
                                return FeedDrain::Done;
                            }

                            (DispatchResult::Ok, nw)
                        }
                        Ok(IdOk::Invitation { needs_write, init }) => {
                            // C `protocol_auth.c:340-373`. Two
                            // plaintext lines (id reply + ACK with
                            // inv pubkey) already in outbuf. SPTPS
                            // installed. Same dispatch shape as
                            // Peer: queue init Wire, take_rest
                            // re-feed. The KEY difference: set
                            // `conn.invite` so dispatch_sptps_outputs
                            // early-branches to invitation handling.
                            //
                            // C `:353`: `c->status.invitation = true`.
                            conn.invite = Some(InvitePhase::WaitingCookie);

                            let mut nw = needs_write;
                            for o in init {
                                if let tinc_sptps::Output::Wire { bytes, .. } = o {
                                    nw |= conn.send_raw(&bytes);
                                }
                            }

                            // take_rest + re-feed. Same as Peer.
                            // The joiner's KEX might piggyback the
                            // greeting line.
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
                    if r == DispatchResult::DumpSubnets {
                        // `dump_subnets` (`subnet.c:395-410`). Same
                        // borrow dance as DumpConnections: drop
                        // `conn`, walk the tree into a Vec, re-fetch.
                        // C: `"%d %d %s %s"` per row, terminator
                        // `"%d %d"`. `netstr` is `net2str` output
                        // (= `Subnet::Display`). Owner is the name
                        // or `"(broadcast)"` for ownerless (`subnet.
                        // c:406`: `subnet->owner ? ->name : "(
                        // broadcast)"` — we don't have ownerless
                        // subnets yet; chunk 8's broadcast subnets).
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
                        let mut nw2 = false;
                        for row in rows {
                            nw2 |= conn.send(format_args!("{row}"));
                        }
                        // Terminator.
                        nw2 |= conn.send(format_args!(
                            "{} {}",
                            Request::Control as u8,
                            crate::proto::REQ_DUMP_SUBNETS
                        ));
                        (DispatchResult::Ok, nw2)
                    } else if r == DispatchResult::DumpNodes {
                        // `dump_nodes` (`node.c:201-223`). The 23-
                        // field beast. CLI parser: `tinc-tools::cmd::
                        // dump::NodeRow::parse` (22 sscanf fields —
                        // hostname is ONE %s = three tokens).
                        let rows = self.dump_nodes_rows();
                        let conn = self.conns.get_mut(id).expect("not terminated");
                        let mut nw2 = false;
                        for row in rows {
                            nw2 |= conn.send(format_args!("{row}"));
                        }
                        // Terminator (`node.c:223`).
                        nw2 |= conn.send(format_args!(
                            "{} {}",
                            Request::Control as u8,
                            crate::proto::REQ_DUMP_NODES
                        ));
                        (DispatchResult::Ok, nw2)
                    } else if r == DispatchResult::DumpEdges {
                        // `dump_edges` (`edge.c:123-137`). Nested
                        // walk: nodes × per-node edges. CLI parser:
                        // `tinc-tools::cmd::dump::EdgeRow::parse`
                        // (8 fields, 2 `" port "` literals).
                        let rows = self.dump_edges_rows();
                        let conn = self.conns.get_mut(id).expect("not terminated");
                        let mut nw2 = false;
                        for row in rows {
                            nw2 |= conn.send(format_args!("{row}"));
                        }
                        // Terminator (`edge.c:137`).
                        nw2 |= conn.send(format_args!(
                            "{} {}",
                            Request::Control as u8,
                            crate::proto::REQ_DUMP_EDGES
                        ));
                        (DispatchResult::Ok, nw2)
                    } else if r == DispatchResult::DumpConnections {
                        // `dump_connections` (`connection.c:166-175`).
                        // Walk ALL conns (including the one asking).
                        // C: `for list_each(connection_t, c, &list)
                        // send_request(cdump, "%d %d %s %s %x %d %x")`
                        // then a terminator `"%d %d"`.
                        //
                        // Borrow dance: `conn` borrows `self.conns`
                        // mutably. The walk needs `&self.conns`. Drop
                        // `conn`, walk into a Vec<String>, re-fetch
                        // `conn`, send. The Vec is one alloc per
                        // dump (not hot — control RPC).
                        let rows: Vec<String> = self
                            .conns
                            .values()
                            .map(|c| {
                                // `connection.c:168`: `"%d %d %s %s
                                // %x %d %x"`. `hostname` is the
                                // FUSED `"host port port"` string
                                // (one %s); the CLI splits it (`" port "`
                                // literal, `dump.rs::ConnRow::parse`).
                                format!(
                                    "{} {} {} {} {:x} {} {:x}",
                                    Request::Control as u8,
                                    crate::proto::REQ_DUMP_CONNECTIONS,
                                    c.name,
                                    c.hostname,
                                    c.options,
                                    c.fd(),
                                    c.status_value()
                                )
                            })
                            .collect();
                        let conn = self.conns.get_mut(id).expect("not terminated");
                        let mut nw2 = false;
                        for row in rows {
                            nw2 |= conn.send(format_args!("{row}"));
                        }
                        // Terminator: `"%d %d"` (`:173`). The CLI
                        // detects end-of-dump by a line with no
                        // body after the subtype int.
                        nw2 |= conn.send(format_args!(
                            "{} {}",
                            Request::Control as u8,
                            crate::proto::REQ_DUMP_CONNECTIONS
                        ));
                        (DispatchResult::Ok, nw2)
                    } else if r == DispatchResult::Reload {
                        // C `control.c:56-57`: `int result = reload_
                        // configuration(); return control_return(c,
                        // type, result)`. Result: 0 success, nonzero
                        // failure (C uses EINVAL, we use 1).
                        // C `control_return`: 0 = success, nonzero =
                        // failure (C uses EINVAL=22; we use 1 — the
                        // CLI only checks zero vs nonzero).
                        let result = i32::from(!self.reload_configuration());
                        let conn = self.conns.get_mut(id).expect("not terminated");
                        let nw2 = conn.send(format_args!(
                            "{} {} {result}",
                            Request::Control as u8,
                            crate::proto::REQ_RELOAD
                        ));
                        (DispatchResult::Ok, nw2)
                    } else {
                        (r, nw)
                    }
                }
                _ => {
                    // Any other request: skeleton doesn't handle.
                    // C would dispatch via the table; we Drop.
                    // (This shouldn't fire — `allow_request` gates
                    // to ID then CONTROL. But if a future chunk
                    // sets `allow_request = None` for some path
                    // and forgets to add the match arm, this is
                    // the catch.)
                    log::error!(target: "tincd::proto",
                                "Request {req:?} not implemented");
                    (DispatchResult::Drop, false)
                }
            };

            // ─── io_set (meta.c:95)
            // The handler may have queued to OTHER conns (the
            // pre-SPTPS phase doesn't broadcast, but the responder-
            // side `send_id` lands here). Same sweep as the SPTPS
            // branch above for safety; `maybe_set_write_any` is
            // cheap (one slotmap pass, ~5 conns).
            if needs_write {
                self.maybe_set_write_any();
            }

            match result {
                // Dump variants were already mapped to Ok above
                // (the Control arm rewrote them inline). Unreachable
                // here. Explicit-unreachable rather than `_` so a
                // new DispatchResult variant fails to compile.
                DispatchResult::DumpConnections
                | DispatchResult::DumpSubnets
                | DispatchResult::DumpNodes
                | DispatchResult::DumpEdges
                | DispatchResult::Reload => {
                    unreachable!("Dump/Reload variants rewritten inline above")
                }
                DispatchResult::Ok => {}
                DispatchResult::Stop => {
                    // `event_exit()`. The reply is queued; we set
                    // running=false; the loop finishes THIS turn
                    // (so the WRITE event for the reply fires) then
                    // exits. Don't `return` — let the read_line loop
                    // exhaust inbuf (CLI might have sent more after
                    // STOP; unlikely but harmless).
                    self.running = false;
                }
                DispatchResult::Drop => {
                    self.terminate(id);
                    return FeedDrain::Done;
                }
            }
        }
        // inbuf drained (read_line returned None). The plaintext
        // path's `feed()` already buffered all bytes from this
        // `recv()`; the line-drain loop above consumed them. More
        // bytes might be waiting in the kernel — loop back.
        FeedDrain::Again
    }

    /// `receive_meta_sptps` (`meta.c:120-162`). Dispatch SPTPS
    /// outputs. Called from BOTH the regular `FeedResult::Sptps`
    /// arm AND the `IdOk::Peer` piggyback re-feed.
    ///
    /// Returns `true` if any output queued bytes to outbuf (io_set
    /// signal). May `terminate(id)` — caller must check `conns.
    /// contains_key(id)` after.
    ///
    /// Match arms map 1:1 to the C callback's branches:
    /// - `Wire` → `send_meta_sptps` (`meta.c:50`): outbuf raw.
    /// - `HandshakeDone` → `meta.c:129-135`: `if(allow == ACK)
    ///   send_ack(c) else return true`.
    /// - `Record` → `meta.c:153-161`: strip `\n`, `receive_
    ///   request(c, data)`. Same `check_gate` + handler match as
    ///   the cleartext line path; only the FRAMING differs (SPTPS
    ///   record vs `\n`-terminated line).
    #[allow(clippy::too_many_lines)] // C `receive_meta_sptps` is one function; the request-dispatch table is half of it
    pub(super) fn dispatch_sptps_outputs(
        &mut self,
        id: ConnId,
        outs: Vec<tinc_sptps::Output>,
    ) -> bool {
        use tinc_sptps::Output;

        // ─── invitation early-branch
        // C: the SPTPS receive callback is `receive_invitation_sptps`
        // (NOT `receive_meta_sptps`) for invitation conns — set at
        // `protocol_auth.c:372`. Our `Sptps` is callback-free (returns
        // `Vec<Output>`), so we branch HERE on `conn.invite`.
        // Records dispatch via `InvitePhase`, not `check_gate`.
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
                    // C `send_meta_sptps` (`meta.c:50`).
                    needs_write |= conn.send_raw(&bytes);
                }
                Output::HandshakeDone => {
                    // C `meta.c:129-135`: `if(type == SPTPS_
                    // HANDSHAKE) { if(c->allow_request == ACK)
                    // return send_ack(c); else return true; }`.
                    //
                    // `else return true`: outgoing conns send their
                    // ACK from `id_h` (`:453` `if(!c->outgoing) ...
                    // else send_ack(c)` — wait no, that's not
                    // right either. The C `:451-453` is `if(!c->
                    // outgoing) send_id(c)`. The outgoing-side
                    // send_ack is from the SAME `meta.c:131` arm.
                    // The `else` is for the initiator's SECOND
                    // HandshakeDone callback during rekey. Chunk
                    // 4b is responder-only, no rekey: always ACK.
                    log::info!(target: "tincd::auth",
                               "SPTPS handshake completed with {} ({})",
                               conn.name, conn.hostname);
                    if conn.allow_request == Some(Request::Ack) {
                        let now = self.timers.now();
                        needs_write |= send_ack(conn, self.my_udp_port, self.myself_options, now);
                    }
                    // No terminate. No sync-flush. The chunk-4a
                    // shortcut is gone; the connection STAYS UP.
                    // The ACK is queued in outbuf (encrypted via
                    // sptps_send_record inside conn.send); the
                    // regular WRITE event flushes it.
                }
                Output::Record { bytes, .. } => {
                    // ─── `c->tcplen` short-circuit ───────────────────────────
                    // C `meta.c:143-151`: a `PACKET 17 <len>` line
                    // sets `c->tcplen`; the NEXT record is a raw VPN
                    // packet blob, not a request line. C calls
                    // `receive_tcppacket` to route it through the
                    // normal VPN-packet path.
                    //
                    // We DROP it. The blobs we see in practice are
                    // MTU probes (`send_udp_probe_packet` falls
                    // through to TCP-PACKET while `udp_confirmed` is
                    // false). We don't run TCP probes ourselves; once
                    // UDP confirms (it does, on loopback) the C stops
                    // sending these. Routing them (`STUB(chunk-12-tcp
                    // -fallback)`) is needed for `TCPOnly` mode and
                    // for MTU-probe replies; neither matters for the
                    // cross-impl ping. WIRE BUG found by crossimpl.rs:
                    // before this branch the request landed in the
                    // `_ => terminate` arm and we dropped the
                    // connection on every probe.
                    if conn.tcplen != 0 {
                        // C `:144`: `if(length != c->tcplen) return
                        // false`. SPTPS records are exact; mismatch
                        // is a framing bug, not a partial read.
                        if bytes.len() != usize::from(conn.tcplen) {
                            log::error!(target: "tincd::proto",
                                "TCP packet length mismatch from {}: \
                                 record {} != tcplen {}",
                                conn.name, bytes.len(), conn.tcplen);
                            self.terminate(id);
                            return needs_write;
                        }
                        // C `:148-150`: `receive_tcppacket(...);
                        // c->tcplen = 0; return true`.
                        log::debug!(target: "tincd::proto",
                            "Dropping TCP-tunnelled packet ({} bytes) \
                             from {} — STUB(chunk-12-tcp-fallback)",
                            conn.tcplen, conn.name);
                        conn.tcplen = 0;
                        continue;
                    }

                    // C `meta.c:155-161`. Strip `\n`, dispatch.
                    // `record_type` is always 0 here (app data;
                    // SPTPS_HANDSHAKE became `HandshakeDone`).
                    // The C ignores `type` (`meta.c:153`: only
                    // checked against SPTPS_HANDSHAKE earlier).
                    let body = record_body(&bytes);

                    // ─── receive_request: same as cleartext
                    let req = match check_gate(conn, body) {
                        Ok(r) => r,
                        Err(e) => {
                            log::error!(target: "tincd::proto",
                                        "Bad SPTPS request from {}: {e:?}", conn.name);
                            self.terminate(id);
                            return needs_write;
                        }
                    };

                    // Handler match. C `request_entries[]` table
                    // (`protocol.c:58-86`). The body is owned (a
                    // Vec inside `Output::Record`); the handlers
                    // need `&mut self` so we can't borrow `conn`
                    // across the call — already dropped above.
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
                            // `ping_h` (`protocol_misc.c:54-57`):
                            // `return send_pong(c)`. That's it.
                            // `send_pong` (`:59-61`): `"%d", PONG`.
                            let conn = self.conns.get_mut(id).expect("gate passed");
                            Ok(conn.send(format_args!("{}", Request::Pong as u8)))
                        }
                        Request::Pong => {
                            // `pong_h` (`protocol_misc.c:63-76`):
                            // clear pinged bit. If outgoing AND its
                            // backoff is non-zero, reset it + the
                            // addr cache cursor + add the working
                            // address as recent. The connection IS
                            // healthy — next reconnect tries this
                            // address first.
                            let conn = self.conns.get_mut(id).expect("gate passed");
                            // C `:65`: `c->status.pinged = false`.
                            conn.pinged = false;
                            // C `:69`: `if(c->outgoing && c->
                            // outgoing->timeout)`. Gate on non-zero
                            // timeout: a healthy conn pongs every
                            // pinginterval; don't churn the cache
                            // each time.
                            let oid = conn.outgoing.map(OutgoingId::from);
                            let addr = conn.address;
                            if let Some(oid) = oid {
                                if let Some(out) = self.outgoings.get_mut(oid) {
                                    if out.timeout != 0 {
                                        // C `:70`: `timeout = 0`.
                                        out.timeout = 0;
                                        // C `:71-72`: reset cursor +
                                        // prepend the address.
                                        out.addr_cache.reset();
                                        if let Some(a) = addr {
                                            out.addr_cache.add_recent(a);
                                        }
                                    }
                                }
                            }
                            Ok(false)
                        }
                        Request::Packet => {
                            // `tcppacket_h` (`protocol_misc.c:105-
                            // 119`): parse `len`, set `c->tcplen`,
                            // return true. The NEXT record is the
                            // blob — see `Output::Record` arm above.
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
                        _ => {
                            // KEY_CHANGED, Status, Error, Termreq.
                            // SPTPS_PACKET (21) is consumed inside
                            // feed() (the "21 " peek) and never
                            // reaches here. UDP_INFO/MTU_INFO have
                            // arms above. The gate passed (allow_
                            // request = None post-ACK).
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

    /// `receive_tcppacket_sptps` (`net_packet.c:616-680`). The blob is
    /// an already-encrypted SPTPS UDP wireframe (`dst[6]‖src[6]‖ct`).
    /// Route it.
    ///
    /// `tcp_tunnel::route()` is the spec (line-by-line C diff). We
    /// inline the ladder here instead of calling it: `route()` deals in
    /// `&str` names (for testability) but the daemon already has
    /// `NodeId`s from `id6_table.lookup()` and using NodeIds directly
    /// avoids the name→NodeId reverse lookup. Same shape as
    /// `handle_incoming_vpn_packet` (`net.rs`); the C `:616-680` and
    /// `:1736-1840` are nearly identical too (TCP vs UDP arrival).
    ///
    /// `id` only used for `terminate` on `TooShort` (the C `:617
    /// return false` — hard error).
    pub(super) fn on_sptps_blob(&mut self, id: ConnId, blob: &[u8]) -> bool {
        // ─── :617: parse_frame, len < 12 → hard error ────────────
        let Some((dst_id, src_id, ct)) = crate::tcp_tunnel::parse_frame(blob) else {
            log::error!(target: "tincd::net",
                        "Got too short SPTPS_PACKET ({} bytes)", blob.len());
            self.terminate(id);
            return false;
        };

        // ─── :622-628: to = lookup_node_id(dst) ─────────────────
        // C `:627 return true` — keep conn, log, drop packet.
        let Some(to_nid) = self.id6_table.lookup(dst_id) else {
            log::warn!(target: "tincd::net",
                       "Got SPTPS_PACKET for unknown dest {dst_id}");
            return false;
        };

        // ─── :631-637: from = lookup_node_id(src) ────────────────
        let Some(from_nid) = self.id6_table.lookup(src_id) else {
            log::warn!(target: "tincd::net",
                       "Got SPTPS_PACKET for {dst_id} from unknown src {src_id}");
            return false;
        };
        let from_name = self
            .graph
            .node(from_nid)
            .map_or("<gone>", |n| n.name.as_str())
            .to_owned();

        // ─── :640-644: reachable check ───────────────────────────
        // Race vs DEL_EDGE. C `:644 return true`.
        if !self.graph.node(to_nid).is_some_and(|n| n.reachable) {
            let to_name = self
                .graph
                .node(to_nid)
                .map_or("<gone>", |n| n.name.as_str());
            log::warn!(target: "tincd::net",
                       "Got SPTPS_PACKET from {from_name} for {to_name} \
                        which is unreachable");
            return false;
        }

        // ─── :649-651: send_udp_info(myself, from) ────────────────
        // Gate: `to->via == myself`. The static-relay check. When `to
        // == myself`, `to->via == myself` is the sssp seed invariant.
        let to_via = self
            .last_routes
            .get(to_nid.0 as usize)
            .and_then(Option::as_ref)
            .map(|r| r.via);
        let mut nw = false;
        if to_via == Some(self.myself) {
            nw |= self.send_udp_info(from_nid, &from_name, true);
        }

        // ─── :654-659: relay if to != myself ──────────────────────
        // C `:656`: `if(to->status.validkey) send_sptps_data(to,
        // from, 0, data, len)`. The validkey gate skips sending
        // through a tunnel that hasn't keyed yet (would just buffer
        // and stall). C `:659`: `try_tx(to, true)` always.
        if to_nid != self.myself {
            let to_name = self
                .graph
                .node(to_nid)
                .map_or("<gone>", |n| n.name.as_str())
                .to_owned();
            let validkey = self.tunnels.get(&to_nid).is_some_and(|t| t.status.validkey);
            if validkey {
                log::debug!(target: "tincd::net",
                            "Relaying SPTPS_PACKET {from_name} → {to_name} \
                             ({} bytes)", ct.len());
                nw |= self.send_sptps_data_relay(to_nid, &to_name, from_nid, 0, ct);
            }
            nw |= self.try_tx(to_nid, true);
            return nw;
        }

        // ─── :664-680: deliver local ─────────────────────────────
        // `to == myself`. Feed `ct` to `from`'s tunnel SPTPS. Same
        // shape as `handle_incoming_vpn_packet`'s direct-receive arm
        // and `gossip.rs`'s b64 SPTPS_PACKET arm. The udppacket bit
        // stays false (came via TCP).
        let Some(sptps) = self
            .tunnels
            .get_mut(&from_nid)
            .and_then(|t| t.sptps.as_deref_mut())
        else {
            // C `:664-667`: `if(!from->status.validkey)`. We use the
            // sptps presence (it's installed at the same time validkey
            // would be flipped). The C kicks send_req_key here.
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
                // C `:674-679`: tunnel-stuck restart. Gate on
                // `last_req_key + 10 < now`.
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
        // C `:680`: `send_mtu_info(myself, from, MTU)`. Tell upstream
        // relays our MTU floor so they can switch to UDP.
        nw |= self.send_mtu_info(from_nid, &from_name, i32::from(MTU), true);
        nw
    }

    /// `receive_invitation_sptps` (`protocol_auth.c:185-310`).
    /// SPTPS record dispatch for invitation conns. Called from
    /// `dispatch_sptps_outputs` early-branch when `conn.invite.
    /// is_some()`. Records dispatch by `(type, InvitePhase)`, NOT
    /// `check_gate` — the bytes are file chunks and b64 pubkey
    /// strings, not newline-terminated request lines.
    ///
    /// State machine (`c->status.invitation_used` in C):
    /// - `Wire` → outbuf raw (same as Peer).
    /// - `HandshakeDone` (type 128 in C) → swallow (`:188`). Don't
    ///   send_ack — invitations don't ACK.
    /// - `Record { 0, len=18 }` + `WaitingCookie` → serve_cookie,
    ///   chunk file, send type-0 chunks + empty type-1, transition
    ///   to WaitingPubkey. C `:196-310`.
    /// - `Record { 1, _ }` + `WaitingPubkey` → finalize, run
    ///   invitation-accepted script, send empty type-2, unlink
    ///   .used, terminate. C `:119-183`.
    /// - Anything else → terminate (`:196`).
    ///
    /// Returns the io_set signal. May terminate.
    #[allow(clippy::too_many_lines)] // C receive_invitation_sptps
    // is 125 lines; the cookie→file→chunk→send sequence shares
    // too much state to split cleanly.
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
                    // Same as Peer: framed SPTPS bytes → outbuf.
                    needs_write |= conn.send_raw(&bytes);
                }
                Output::HandshakeDone => {
                    // C `:188`: `if(type == 128) return true`.
                    // Swallow. The handshake completing is the
                    // signal that the joiner can now send the
                    // cookie (type-0 record); we just wait.
                    log::debug!(target: "tincd::auth",
                                "Invitation SPTPS handshake done with {}",
                                conn.hostname);
                }
                Output::Record { record_type, bytes } => {
                    // Read what we need from conn, drop borrow, then
                    // re-fetch for sends. Same two-phase as everywhere.
                    let phase = conn.invite.take();
                    let hostname = conn.hostname.clone();
                    let conn_addr = conn.address;

                    match (record_type, phase) {
                        // ─── type-0, len-18, WaitingCookie ───
                        // C `:196`: `if(type != 0 || len != 18 ||
                        // c->status.invitation_used) return false`.
                        (0, Some(InvitePhase::WaitingCookie))
                            if bytes.len() == invitation_serve::COOKIE_LEN =>
                        {
                            let mut cookie = [0u8; invitation_serve::COOKIE_LEN];
                            cookie.copy_from_slice(&bytes);

                            // C `:341`: `if(!invitation_key)` was
                            // already checked at id_h. The key is
                            // Some here (id_h would have rejected).
                            let Some(inv_key) = self.invitation_key.as_ref() else {
                                log::error!(target: "tincd::auth",
                                            "invitation key vanished mid-handshake");
                                self.terminate(id);
                                return needs_write;
                            };

                            // C `:201-277`: serve_cookie does the
                            // rename + stat + read + name-parse.
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
                            // Re-fetch conn (we dropped the borrow
                            // for the serve_cookie call which only
                            // needed &self fields, but the inv_key
                            // borrow above also conflicts).
                            let Some(conn) = self.conns.get_mut(id) else {
                                return needs_write;
                            };
                            conn.name.clone_from(&invited_name);

                            // C `:294-303`: chunk file, send each
                            // chunk as type-0, then empty type-1.
                            // `chunk_file` returns slices into
                            // `contents`; we copy each via
                            // send_sptps_record. The CHUNK_SIZE
                            // (1024) matches the C's `char buf[1024]`.
                            for chunk in invitation_serve::chunk_file(
                                &contents,
                                invitation_serve::CHUNK_SIZE,
                            ) {
                                needs_write |= conn.send_sptps_record(0, chunk);
                            }
                            // C `:303`: `sptps_send_record(&c->sptps, 1, buf, 0)`.
                            needs_write |= conn.send_sptps_record(1, &[]);

                            // C `:305`: `unlink(usedname)`. The C
                            // does this BEFORE the type-1 reply
                            // arrives (right after sending the
                            // file). The .used file's purpose
                            // (single-use enforcement via rename)
                            // is already served.
                            if let Err(e) = std::fs::remove_file(&used_path) {
                                log::warn!(target: "tincd::auth",
                                            "Failed to unlink {}: {e}",
                                            used_path.display());
                            }

                            // C `:307`: `c->status.invitation_used = true`.
                            conn.invite = Some(InvitePhase::WaitingPubkey {
                                name: invited_name.clone(),
                                used_path,
                            });

                            log::info!(target: "tincd::auth",
                                        "Invitation successfully sent to {invited_name} ({hostname})");
                        }

                        // ─── type-1, WaitingPubkey ───
                        // C `:192-193`: `if(type == 1 && c->status.
                        // invitation_used) return finalize_
                        // invitation(c, data, len)`.
                        (1, Some(InvitePhase::WaitingPubkey { name, .. })) => {
                            // bytes is the joiner's pubkey, b64,
                            // no newline. C `:122`: `if(strchr(data,
                            // '\n'))` — finalize() checks this.
                            let Ok(pubkey_b64) = std::str::from_utf8(&bytes) else {
                                log::error!(target: "tincd::auth",
                                            "Invalid pubkey from {name} ({hostname}): non-UTF-8");
                                self.terminate(id);
                                return needs_write;
                            };

                            // C `:128-144`: write hosts/{name}.
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

                            // C `:148-161`: lookup_or_add_node +
                            // open_address_cache + add_recent_
                            // address. The invited node is now a
                            // real peer; future outgoing connects
                            // can find them at this address.
                            //
                            // Our addrcache is per-Outgoing (not
                            // per-Node), so there's no slot to
                            // write to (the invited node isn't a
                            // ConnectTo target — THEY connect to
                            // US). The C writes anyway (the cache
                            // file lives in confbase/cache/); a
                            // future ConnectTo for this node would
                            // open_address_cache and find it.
                            // We do the same: write the cache file
                            // directly.
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

                            // C `:164-179`: invitation-accepted script.
                            // Env: NODE, REMOTEADDRESS, REMOTEPORT, NAME.
                            self.run_invitation_accepted_script(&name, conn_addr);

                            // C `:181`: `sptps_send_record(&c->sptps, 2, data, 0)`.
                            // The empty type-2 is the ACK; joiner
                            // closes after reading it. Re-fetch conn.
                            let Some(conn) = self.conns.get_mut(id) else {
                                return needs_write;
                            };
                            needs_write |= conn.send_sptps_record(2, &[]);

                            // C `:182`: `return true`. The conn
                            // stays open; the joiner closes from
                            // their end after reading type-2. We
                            // get EOF and terminate normally.
                            // Don't terminate here — the type-2
                            // bytes are still in outbuf, need to
                            // flush first.
                            //
                            // BUT: don't restore `invite` either.
                            // Any further records are an error;
                            // leave invite as None so a stray
                            // record falls through to the meta
                            // dispatch and dies on check_gate.
                            // Actually that's wrong — the conn
                            // would then be in the meta dispatch
                            // with no allow_request and gibberish
                            // SPTPS state. Set a phase that
                            // terminates on any further record.
                            // Simpler: set invite back to a phase
                            // that rejects everything.
                            conn.invite = Some(InvitePhase::WaitingCookie);
                            // (WaitingCookie rejects type-1 and
                            // wrong-len type-0; no further records
                            // should arrive anyway since the joiner
                            // closes after type-2.)
                        }

                        // ─── anything else ───
                        // C `:196`: `return false`. Bad type, bad
                        // length, or wrong phase.
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

    /// `protocol_auth.c:164-179`: the invitation-accepted script.
    /// Env: `NODE` (invited node's name), `REMOTEADDRESS`/
    /// `REMOTEPORT` (the conn's TCP address), plus the base env.
    pub(super) fn run_invitation_accepted_script(&self, node: &str, addr: Option<SocketAddr>) {
        let mut env = ScriptEnv::base(None, &self.name, None, Some(&self.iface), None);
        // C `:170`: `"NODE=%s", c->name`.
        env.add("NODE", node.to_owned());
        // C `:171-173`: `sockaddr2str(&c->address, &address, &port)`.
        if let Some(a) = addr {
            env.add("REMOTEADDRESS", a.ip().to_string());
            env.add("REMOTEPORT", a.port().to_string());
        }
        Self::log_script(
            "invitation-accepted",
            script::execute(&self.confbase, "invitation-accepted", &env, None),
        );
    }
}
