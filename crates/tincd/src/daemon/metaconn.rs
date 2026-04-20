#![forbid(unsafe_code)]

use super::{ConnId, Daemon, IoWhat};

use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsFd, OwnedFd};
use std::time::SystemTime;

use crate::conn::{Connection, FeedResult, SptpsEvent};
use crate::invitation_serve::InvitePhase;
use crate::outgoing::{OutgoingId, ProxyConfig};
use crate::proto::{
    CtlReq, DispatchError, DispatchResult, IdCtx, IdOk, check_gate, handle_control, handle_id,
    record_body, send_ack,
};
use crate::script::ScriptEnv;
use crate::tunnel::MTU;
use crate::{invitation_serve, script, socks};

use rand_core::OsRng;
use tinc_event::Io;
use tinc_proto::Request;

/// `Again`: caller should loop (kernel may have more). `Done`: stop.
enum FeedDrain {
    Again,
    Done,
}

const MAX_CONTROL_CONNS: usize = 64;

impl Daemon {
    pub(super) fn on_unix_accept(&mut self) {
        let stream = match self.control.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
            Err(e) => {
                log::error!(target: "tincd::conn",
                            "Accepting a new connection failed: {e}");
                return;
            }
        };

        if self.conns.values().filter(|c| c.is_unix_ctl).count() >= MAX_CONTROL_CONNS {
            log::warn!(target: "tincd::conn",
                       "Too many control connections; rejecting");
            return;
        }

        let fd: OwnedFd = stream.into();
        let conn = Connection::new_control(fd, self.timers.now());

        let id = self.conns.insert(conn);
        // io_add IO_READ only; `send` adds WRITE later.
        match self
            .ev
            .add(self.conns[id].as_fd(), Io::Read, IoWhat::Conn(id))
        {
            Ok(io_id) => {
                self.conn_io.insert(id, io_id);
                log::debug!(target: "tincd::conn",
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

    /// Fairness cap, not ET requirement. LT epoll re-fires next
    /// `turn()` if the fd is still readable. C does one `recv()` per
    /// wake (`meta.c:185`); we do up to 64 (≈136KB/turn) — cheap
    /// insurance against a peer flooding the line and starving the
    /// device fd.
    pub(super) fn on_conn_readable(&mut self, id: ConnId) {
        const META_DRAIN_CAP: u32 = 64;
        for _ in 0..META_DRAIN_CAP {
            // Prior iteration may have terminated this conn.
            if !self.conns.contains_key(id) {
                return;
            }
            match self.on_conn_readable_once(id) {
                FeedDrain::Again => {}
                FeedDrain::Done => break,
            }
        }
        // Cap hit (or Done). LT re-fires next turn — no rearm needed.
        // Belt-and-braces over the per-batch flush in `on_feed_sptps`.
        self.flush_graph_dirty();
    }

    /// One `recv()` + dispatch. Splitting would thread id/conn/self
    /// borrows.
    fn on_conn_readable_once(&mut self, id: ConnId) -> FeedDrain {
        let conn = self.conn_mut(id);
        match conn.feed(&mut OsRng) {
            FeedResult::WouldBlock => return FeedDrain::Done,
            FeedResult::Dead => {
                self.terminate(id);
                return FeedDrain::Done;
            }
            FeedResult::Data => {
                if let Some(r) = self.on_feed_data(id) {
                    return r;
                }
                // fall through to line drain
            }
            FeedResult::Sptps(events) => return self.on_feed_sptps(id, events),
        }

        // ─── drain inbuf
        loop {
            // Split borrow: helper would lock all of `self`.
            let conn = self.conns.get_mut(id).expect("ConnId not live");
            let Some(range) = conn.inbuf.read_line() else {
                break;
            };
            // Copy: can't borrow bytes_raw() across &mut self calls.
            // Cheap (control lines <100 bytes).
            let line: Vec<u8> = conn.inbuf.bytes_raw()[range].to_vec();

            // ─── HTTP proxy response intercept
            // `read_line` excludes `\n`, includes `\r`.
            //
            // Real HTTP proxies (Squid) send headers in 2xx CONNECT
            // (RFC 7231 §4.3.6). Don't let them fall through to
            // check_gate — they'd parse as garbage protocol commands.
            // TODO(http-proxy-lenient): skip lines until blank.
            if conn.outgoing.is_some()
                && conn.allow_request == Some(Request::Id)
                && matches!(self.settings.proxy, Some(ProxyConfig::Http { .. }))
            {
                if line.is_empty() || line[0] == b'\r' {
                    continue; // blank line
                }
                // RFC 7230 case-insensitive.
                if line.len() >= 12 && line[..9].eq_ignore_ascii_case(b"HTTP/1.1 ") {
                    if &line[9..12] == b"200" {
                        log::debug!(target: "tincd::conn",
                            "HTTP proxy request granted for {}", conn.name);
                        continue;
                    }
                    let status = String::from_utf8_lossy(&line[9..]);
                    log::error!(target: "tincd::conn",
                        "HTTP proxy request rejected for {}: {:?}",
                        conn.name, status.trim_end_matches('\r'));
                    self.terminate(id);
                    return FeedDrain::Done;
                }
                // Fall through — header → check_gate → terminate.
            }

            // ─── check_gate
            let req = match check_gate(conn, &line) {
                Ok(r) => r,
                Err(e) => {
                    log::error!(target: "tincd::proto",
                                "Bad request from {}: {e:?}", conn.name);
                    self.terminate(id);
                    return FeedDrain::Done;
                }
            };

            // ─── handler dispatch
            let (result, needs_write) = match req {
                Request::Id => match self.dispatch_request_id(id, &line) {
                    Some(r) => r,
                    None => return FeedDrain::Done, // terminated mid-handshake
                },
                Request::Control => self.dispatch_control(id, &line),
                _ => {
                    // allow_request gates to ID/CONTROL; shouldn't fire.
                    log::error!(target: "tincd::proto",
                                "Request {req:?} not implemented");
                    (DispatchResult::Drop, false)
                }
            };

            // Handler may have queued to OTHER conns; sweep all
            // (cheap, ~5 conns).
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
                    // Don't return: finish this turn so the queued
                    // reply's WRITE event fires.
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

    /// `Request::Id` arm: build `IdCtx`, call `handle_id`, then drain
    /// the SPTPS-init piggyback.
    ///
    /// `handle_id` itself is pure (in `proto.rs`); the piggyback is
    /// the messy part. SPTPS-start emits the first KEX as `Output::Wire`.
    /// We queue that, then `take_rest` from inbuf — the peer often
    /// sends ID + KEX in one TCP segment, and the bytes after the
    /// ID-line newline are now SPTPS framing, not protocol lines.
    /// Re-feed those through `feed_sptps` immediately.
    ///
    /// `Peer` and `Invitation` cases are the same shape; the only
    /// per-case bits are `conn.invite = Some(...)` for invitations
    /// and which name field goes in the error log.
    ///
    /// Returns `None` if the conn was terminated (SPTPS error in
    /// piggyback, or `dispatch_sptps_outputs` killed it). Caller
    /// must `return FeedDrain::Done`.
    fn dispatch_request_id(&mut self, id: ConnId, line: &[u8]) -> Option<(DispatchResult, bool)> {
        // Split borrow: helper would lock all of `self`.
        let conn = self.conns.get_mut(id).expect("ConnId not live");
        let ctx = IdCtx {
            cookie: &self.cookie,
            my_name: &self.name,
            mykey: &self.mykey,
            confbase: &self.confbase,
            invitation_key: self.invitation_key.as_ref(),
            global_pmtu: self.settings.global_pmtu,
        };
        let now = self.timers.now();
        let id_result = handle_id(conn, line, &ctx, now, &mut OsRng);

        let (needs_write, init, is_invite) = match id_result {
            Ok(IdOk::Control { needs_write }) => return Some((DispatchResult::Ok, needs_write)),
            Ok(IdOk::Peer { needs_write, init }) => (needs_write, init, false),
            Ok(IdOk::Invitation { needs_write, init }) => {
                conn.invite = Some(InvitePhase::WaitingCookie);
                (needs_write, init, true)
            }
            Err(e) => {
                log::error!(target: "tincd::proto",
                            "ID rejected from {}: {e:?}", conn.name);
                return Some((DispatchResult::Drop, false));
            }
        };

        // ─── SPTPS-init piggyback (Peer + Invitation common path)
        // Queue the init Wire frames (sptps_start emits KEX-only).
        let mut nw = needs_write;
        for o in init {
            if let tinc_sptps::Output::Wire { bytes, .. } = o {
                nw |= conn.send_raw(&bytes);
            }
        }

        // take_rest: bytes after the ID-line newline are SPTPS now,
        // not protocol lines. feed_sptps is an associated fn taking
        // &mut Sptps directly (borrow split: &mut conn.sptps + &conn.name).
        let leftover = conn.inbuf.take_rest();
        let outs = if leftover.is_empty() {
            Vec::new()
        } else {
            let log_name = if is_invite {
                &conn.hostname
            } else {
                &conn.name
            };
            let sptps = conn
                .sptps
                .as_deref_mut()
                .expect("handle_id just installed it");
            match Connection::feed_sptps(sptps, &leftover, &conn.name, &mut OsRng) {
                FeedResult::Sptps(evs) => evs
                    .into_iter()
                    .map(|ev| match ev {
                        SptpsEvent::Record(o) => o,
                        SptpsEvent::Blob(_) => unreachable!("feed_sptps emits Record only"),
                    })
                    .collect(),
                FeedResult::Dead => {
                    log::error!(
                        target: "tincd::proto",
                        "SPTPS error in {}piggyback from {}",
                        if is_invite { "invitation " } else { "" },
                        log_name
                    );
                    self.terminate(id);
                    return None;
                }
                _ => unreachable!(),
            }
        };

        if self.dispatch_sptps_outputs(id, outs) {
            nw = true;
        }
        self.flush_graph_dirty();
        if !self.conns.contains_key(id) {
            return None;
        }

        Some((DispatchResult::Ok, nw))
    }

    /// Dump-arm tail: re-fetch `&mut conn`, `send_dump` rows +
    /// bare-header terminator.
    fn ctl_send_dump(
        &mut self,
        id: ConnId,
        rows: Vec<String>,
        req: CtlReq,
    ) -> (DispatchResult, bool) {
        let conn = self.conn_mut(id);
        let nw = conn.send_dump(rows, req);
        (DispatchResult::Ok, nw)
    }

    /// Simple-ack tail: `"{Control} {req} {result}"`.
    fn ctl_ack(&mut self, id: ConnId, req: CtlReq, result: i32) -> (DispatchResult, bool) {
        let conn = self.conn_mut(id);
        let nw = conn.send(format_args!("{} {} {}", Request::Control, req, result));
        (DispatchResult::Ok, nw)
    }

    /// CONTROL request dispatch. Dump arms: build rows with `&self`
    /// borrowed, drop it, then `ctl_send_dump`. Ack arms: do the
    /// side-effect, then `ctl_ack`.
    fn dispatch_control(&mut self, id: ConnId, line: &[u8]) -> (DispatchResult, bool) {
        let now = self.timers.now();
        let conn = self.conn_mut(id);
        // Refresh idle-reap window on any client activity.
        conn.last_ping_time = now + std::time::Duration::from_secs(3600);
        let (r, nw) = handle_control(conn, line);
        match r {
            DispatchResult::DumpSubnets => {
                let rows: Vec<String> = self
                    .subnets
                    .iter()
                    .map(|(subnet, owner)| {
                        format!(
                            "{} {} {} {}",
                            Request::Control,
                            crate::proto::REQ_DUMP_SUBNETS,
                            subnet,
                            owner
                        )
                    })
                    .collect();
                self.ctl_send_dump(id, rows, crate::proto::REQ_DUMP_SUBNETS)
            }
            DispatchResult::DumpNodes => {
                let rows = self.dump_nodes_rows();
                self.ctl_send_dump(id, rows, crate::proto::REQ_DUMP_NODES)
            }
            DispatchResult::DumpEdges => {
                let rows = self.dump_edges_rows();
                self.ctl_send_dump(id, rows, crate::proto::REQ_DUMP_EDGES)
            }
            DispatchResult::DumpConnections => {
                let rows: Vec<String> = self
                    .conns
                    .values()
                    .map(|c| {
                        // hostname is the fused "host port port" string.
                        format!(
                            "{} {} {} {} {:x} {} {:x}",
                            Request::Control,
                            crate::proto::REQ_DUMP_CONNECTIONS,
                            c.name,
                            c.hostname,
                            c.options.bits(),
                            std::os::fd::AsRawFd::as_raw_fd(&c.as_fd()),
                            c.status_value()
                        )
                    })
                    .collect();
                self.ctl_send_dump(id, rows, crate::proto::REQ_DUMP_CONNECTIONS)
            }
            DispatchResult::Reload => {
                // CLI only checks zero/nonzero.
                let result = i32::from(!self.reload_configuration());
                self.ctl_ack(id, crate::proto::REQ_RELOAD, result)
            }
            DispatchResult::Retry => {
                self.on_retry();
                self.ctl_ack(id, crate::proto::REQ_RETRY, 0)
            }
            DispatchResult::Purge => {
                let nw_purge = self.purge();
                let (r, nw2) = self.ctl_ack(id, crate::proto::REQ_PURGE, 0);
                (r, nw_purge | nw2)
            }
            DispatchResult::SetDebug(level) => {
                // Reply with PREVIOUS level. `level >= 0` → update;
                // `< 0` → query-only. None → terminate ctl conn (the
                // ONLY ctl arm that does this; the rest reply
                // REQ_INVALID and stay up).
                let Some(level) = level else {
                    return (DispatchResult::Drop, false);
                };
                let prev = crate::log_tap::set_debug_level(level);
                if level >= 0 {
                    // Remember the FIRST prev so close restores the original.
                    self.conn_mut(id).prev_debug_level.get_or_insert(prev);
                }
                self.ctl_ack(id, crate::proto::REQ_SET_DEBUG, prev)
            }
            DispatchResult::Disconnect(name) => {
                // Walk conns, terminate by name. `terminate()` keys
                // DEL_EDGE on `conn.active` already. Control conns are
                // skipped: their name is `<control>`, so a valid node
                // name never matches; also covers self-disconnect.
                let result = match name {
                    None => -1, // parse failed
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
                self.ctl_ack(id, crate::proto::REQ_DISCONNECT, result)
            }
            DispatchResult::DumpTraffic => {
                let rows = self.dump_traffic_rows();
                self.ctl_send_dump(id, rows, crate::proto::REQ_DUMP_TRAFFIC)
            }
            DispatchResult::Log(level) => {
                // No reply. The conn now passively receives log records
                // via `flush_log_tap`.
                //
                // Debug levels: -1=UNSET, 0=ALWAYS, 1=CONNECTIONS, ...,
                // 5=TRAFFIC, ..., 10=SCARY. Map roughly: 0→Info,
                // 1-2→Debug, 3+→Trace. Same shape as `main.rs::
                // debug_level_to_filter`. -1 (UNSET) = "use daemon's
                // level"; we use Trace (everything the tap captures —
                // the daemon's stderr filter already applied).
                let conn = self.conn_mut(id);
                conn.log_level = Some(match level {
                    i32::MIN..=-1 => log::Level::Trace,
                    0 => log::Level::Info,
                    1 | 2 => log::Level::Debug,
                    _ => log::Level::Trace,
                });
                crate::log_tap::set_active(true);
                (DispatchResult::Ok, false)
            }
            DispatchResult::Pcap(snaplen) => {
                // NO ack reply: the CLI writes the global pcap header
                // then immediately starts reading `"18 14 LEN"` lines —
                // a `"18 14 0"` ack would be misparsed as a 0-byte
                // capture.
                let conn = self.conn_mut(id);
                conn.pcap = true;
                conn.pcap_snaplen = snaplen;
                self.any_pcap = true;
                (DispatchResult::Ok, false)
            }
            r => (r, nw),
        }
    }

    /// Returns `io_set` signal. May `terminate(id)` — caller checks
    /// `conns.contains_key(id)`.
    /// `FeedResult::Data` body: pre-SPTPS tcplen consume (SOCKS proxy
    /// reply). Returns `Some(FeedDrain)` if the conn is mid-SOCKS
    /// (caller should return that), `None` if SOCKS either didn't
    /// apply or completed cleanly and the caller should fall through
    /// to the line-based dispatch loop.
    fn on_feed_data(&mut self, id: ConnId) -> Option<FeedDrain> {
        // ─── pre-SPTPS tcplen consume (SOCKS proxy reply)
        // Mutually exclusive with the Sptps arm: SOCKS sets
        // tcplen before SPTPS starts.
        // Split borrow: helper would lock all of `self`.
        let conn = self.conns.get_mut(id).expect("ConnId not live");
        if conn.tcplen != 0 && conn.outgoing.is_some() && conn.allow_request == Some(Request::Id) {
            let n = usize::from(conn.tcplen);
            let Some(range) = conn.inbuf.read_n(n) else {
                // Partial. Do NOT fall through to read_line
                // (SOCKS bytes would parse as garbage).
                return Some(FeedDrain::Done);
            };
            let buf: Vec<u8> = conn.inbuf.bytes_raw()[range].to_vec();
            conn.tcplen = 0;

            // Only SOCKS sets tcplen in finish_connecting.
            let Some(proxy) = &self.settings.proxy else {
                log::error!(target: "tincd::conn",
                    "tcplen set but no proxy configured for {}",
                    conn.name);
                self.terminate(id);
                return Some(FeedDrain::Done);
            };
            let Some(socks_type) = proxy.socks_type() else {
                log::error!(target: "tincd::conn",
                    "tcplen set but proxy is not SOCKS for {}",
                    conn.name);
                self.terminate(id);
                return Some(FeedDrain::Done);
            };
            let creds = proxy.socks_creds();
            match socks::check_response(socks_type, creds.as_ref(), &buf) {
                socks::SocksResponse::Granted => {
                    // Fall through: peer's ID may already be
                    // in inbuf (same segment).
                    log::debug!(target: "tincd::conn",
                        "Proxy request granted for {} ({n} reply bytes)",
                        conn.name);
                }
                socks::SocksResponse::Rejected => {
                    log::error!(target: "tincd::conn",
                        "Proxy request rejected for {}", conn.name);
                    self.terminate(id);
                    return Some(FeedDrain::Done);
                }
                socks::SocksResponse::Malformed(why) => {
                    log::error!(target: "tincd::conn",
                        "Malformed proxy response for {}: {why}",
                        conn.name);
                    self.terminate(id);
                    return Some(FeedDrain::Done);
                }
            }
        }
        None
    }

    /// `FeedResult::Sptps` body: drain SPTPS events in order.
    fn on_feed_sptps(&mut self, id: ConnId, events: Vec<SptpsEvent>) -> FeedDrain {
        // Order matters: an ADD_EDGE record before a blob can
        // change reachability that the blob's route reads — so
        // flush the deferred BFS before each blob. The bulk
        // send_everything batch (pure ADD_EDGE/ADD_SUBNET, no
        // blobs) still coalesces to one BFS at the tail.
        let mut needs_write = false;
        for ev in events {
            match ev {
                SptpsEvent::Record(o) => {
                    needs_write |= self.dispatch_sptps_outputs(id, vec![o]);
                }
                SptpsEvent::Blob(blob) => {
                    self.flush_graph_dirty();
                    needs_write |= self.on_sptps_blob(id, &blob);
                }
            }
            if !self.conns.contains_key(id) {
                // `terminate` ran `run_graph_and_log` itself.
                return FeedDrain::Done;
            }
        }
        // One BFS for all ADD_EDGEs in this batch (`graph_dirty`).
        self.flush_graph_dirty();
        // Dispatch may have queued to ANY conn (broadcast,
        // forward, relay); sweep all.
        if needs_write {
            self.maybe_set_write_any();
        }
        // SPTPS mode doesn't touch inbuf. Loop back to feed()
        // (edge-triggered; must drain to EAGAIN).
        FeedDrain::Again
    }

    pub(super) fn dispatch_sptps_outputs(
        &mut self,
        id: ConnId,
        outs: Vec<tinc_sptps::Output>,
    ) -> bool {
        use tinc_sptps::Output;

        // Our Sptps is callback-free, so branch here on `conn.invite`
        // for the invite-serve path.
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
                    needs_write |= conn.send_raw(&bytes);
                }
                Output::HandshakeDone => {
                    // The else is for the SECOND HandshakeDone during
                    // rekey.
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
                    // ─── tcplen short-circuit
                    // PACKET 17 sets tcplen; the NEXT record is a raw
                    // VPN blob (single-encrypted, meta-SPTPS only —
                    // direct neighbors only). crossimpl.rs pins this:
                    // terminating here drops every C-peer MTU probe.
                    if conn.tcplen != 0 {
                        // SPTPS records are exact; mismatch is a
                        // framing bug, not a partial read.
                        if bytes.len() != usize::from(conn.tcplen) {
                            log::error!(target: "tincd::proto",
                                "TCP packet length mismatch from {}: \
                                 record {} != tcplen {}",
                                conn.name, bytes.len(), conn.tcplen);
                            self.terminate(id);
                            return needs_write;
                        }
                        conn.tcplen = 0;
                        // oversize → drop packet, KEEP conn.
                        if bytes.len() > usize::from(crate::tunnel::MTU) {
                            log::warn!(target: "tincd::proto",
                                "Oversized PACKET 17 from {} ({} > MTU {})",
                                conn.name, bytes.len(), crate::tunnel::MTU);
                            continue;
                        }
                        let conn_name = conn.name.clone();
                        // PACKET 17 before ACK is a peer bug.
                        let Some(from_nid) = self.node_ids.get(&conn_name).copied() else {
                            log::warn!(target: "tincd::proto",
                                "PACKET 17 from {conn_name} before ACK — dropping");
                            continue;
                        };
                        let len = bytes.len() as u64;
                        let tunnel = self.dp.tunnels.entry(from_nid).or_default();
                        tunnel.stats.add_in(1, len);
                        needs_write |= self.route_packet(&mut bytes, Some(from_nid));
                        continue;
                    }

                    // strip `\n`, dispatch.
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
                            let conn = self.conn_mut(id);
                            Ok(conn.send(format_args!("{}", Request::Pong)))
                        }
                        Request::Pong => {
                            // Real clock, not `self.timers.now()`: that
                            // is cached at `tick()` BEFORE `epoll_wait`
                            // blocked, so it can be stale by up to one
                            // wakeup interval and under-reads RTT by
                            // exactly the latency of whichever OTHER
                            // conn's PONG woke epoll first.
                            let now = std::time::Instant::now();
                            let conn = self.conn_mut(id);
                            conn.pinged = false;
                            if let Some(sent) = conn.last_ping_sent.take() {
                                let rtt = now.saturating_duration_since(sent).as_millis();
                                conn.ping_rtt_ms = u32::try_from(rtt).unwrap_or(u32::MAX);
                            }
                            // Gate on non-zero timeout (healthy conn
                            // pongs every pinginterval; don't churn).
                            let oid = conn.outgoing.map(OutgoingId::from);
                            let addr = conn.address;
                            if let Some(oid) = oid
                                && let Some(out) = self.outgoings.get_mut(oid)
                                && out.timeout != 0
                            {
                                out.timeout = 0;
                                out.addr_cache.reset();
                                if let Some(a) = addr {
                                    out.addr_cache.add_recent(a);
                                }
                            }
                            Ok(self.on_pong_rtt(id, now))
                        }
                        Request::Packet => {
                            // set tcplen; NEXT record is the blob.
                            let conn = self.conn_mut(id);
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
                            // Legacy-crypto distro builds broadcast
                            // this every `KeyExpire` seconds (default
                            // 3600). Before this fix, we'd terminate
                            // every such connection at the one-hour
                            // mark. Bug audit `deef1268`.
                            //
                            // The forward is the only thing that
                            // matters for an SPTPS-only build.
                            //
                            // TODO: cross-impl regression — build a
                            // `tincd-c-legacy` flake output WITHOUT
                            // `-Dcrypto=nolegacy` and assert the conn
                            // survives a KEY_CHANGED. crossimpl runs
                            // for ~10s; default KeyExpire is 3600s,
                            // so set `KeyExpire = 5` in the C peer's
                            // tinc.conf for that test.
                            self.on_key_changed(id, body)
                        }
                        Request::Status => {
                            // log, noop. Bug audit `deef1268`: was
                            // terminating.
                            log::info!(target: "tincd::proto",
                                       "Status from peer: {:?}",
                                       std::str::from_utf8(body).unwrap_or("<non-utf8>"));
                            Ok(false)
                        }
                        Request::Error | Request::Termreq => {
                            // Terminate. Explicit so catch-all below
                            // is ONLY truly-unhandled.
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

    /// Blob is an already-encrypted SPTPS UDP wireframe (`dst[6]‖
    /// src[6]‖ct`). Inlined ladder (vs `tcp_tunnel::route()`): we
    /// already have `NodeIds` from `id6_table`; avoids name→NodeId
    /// reverse lookup.
    pub(super) fn on_sptps_blob(&mut self, id: ConnId, blob: &[u8]) -> bool {
        // len < 12 → hard error.
        let Some((dst_id, src_id, ct)) = crate::tcp_tunnel::parse_frame(blob) else {
            log::error!(target: "tincd::net",
                        "Got too short SPTPS_PACKET ({} bytes)", blob.len());
            self.terminate(id);
            return false;
        };

        // lookup dst. Unknown → keep conn, drop packet.
        let Some(to_nid) = self.id6_table.lookup(dst_id) else {
            log::warn!(target: "tincd::net",
                       "Got SPTPS_PACKET for unknown dest {dst_id}");
            return false;
        };

        let Some(from_nid) = self.id6_table.lookup(src_id) else {
            log::warn!(target: "tincd::net",
                       "Got SPTPS_PACKET for {dst_id} from unknown src {src_id}");
            return false;
        };
        let from_name = self.node_log_name(from_nid).to_owned();

        // Reachable check (race vs DEL_EDGE).
        if !self.graph.node(to_nid).is_some_and(|n| n.reachable) {
            let to_name = self.node_log_name(to_nid);
            log::warn!(target: "tincd::net",
                       "Got SPTPS_PACKET from {from_name} for {to_name} \
                        which is unreachable");
            return false;
        }

        // send_udp_info, gated on `to.via == myself` (static-relay
        // check; for to==myself it's the sssp seed invariant).
        let to_via = self.route_of(to_nid).map(|r| r.via);
        let mut nw = false;
        if to_via == Some(self.myself) {
            nw |= self.send_udp_info(from_nid, &from_name, true);
        }

        // Relay. validkey gate skips unkeyed tunnels (would buffer
        // and stall). try_tx always.
        if to_nid != self.myself {
            let validkey = self
                .dp
                .tunnels
                .get(&to_nid)
                .is_some_and(|t| t.status.validkey);
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

        // Deliver local. udppacket bit stays false (came via TCP).
        let Some(sptps) = self
            .dp
            .tunnels
            .get_mut(&from_nid)
            .and_then(|t| t.sptps.as_deref_mut())
        else {
            // sptps presence is our validkey proxy.
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
                // Only restart if `!validkey`; see
                // `maybe_restart_stuck_tunnel` doc.
                log::debug!(target: "tincd::net",
                            "Failed to decode SPTPS_PACKET from \
                             {from_name}: {e:?}");
                nw |= self.maybe_restart_stuck_tunnel(from_nid);
                return nw;
            }
        };
        nw |= self.dispatch_tunnel_outputs(from_nid, &from_name, outs);
        // Tell upstream relays our MTU floor.
        nw |= self.send_mtu_info(from_nid, &from_name, i32::from(MTU), true);
        nw
    }

    /// Records dispatch by `(type, InvitePhase)`, NOT `check_gate` —
    /// the bytes are file chunks and b64 pubkeys, not request lines.
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
                    // Swallow. Invitations don't ACK.
                    log::debug!(target: "tincd::auth",
                                "Invitation SPTPS handshake done with {}",
                                conn.hostname);
                }
                Output::Record { record_type, bytes } => {
                    let phase = conn.invite.take();
                    let hostname = conn.hostname.clone();
                    let conn_addr = conn.address;

                    match (record_type, phase) {
                        (0, Some(InvitePhase::WaitingCookie))
                            if bytes.len() == invitation_serve::COOKIE_LEN =>
                        {
                            let mut cookie = [0u8; invitation_serve::COOKIE_LEN];
                            cookie.copy_from_slice(&bytes);

                            // Already checked at id_h.
                            let Some(inv_key) = self.invitation_key.as_ref() else {
                                log::error!(target: "tincd::auth",
                                            "invitation key vanished mid-handshake");
                                self.terminate(id);
                                return needs_write;
                            };

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

                            let Some(conn) = self.conns.get_mut(id) else {
                                return needs_write;
                            };
                            conn.name.clone_from(&invited_name);

                            for chunk in invitation_serve::chunk_file(
                                &contents,
                                invitation_serve::CHUNK_SIZE,
                            ) {
                                needs_write |= conn.send_sptps_record(0, chunk);
                            }
                            needs_write |= conn.send_sptps_record(1, &[]);

                            // Unlink BEFORE type-1 reply arrives; the
                            // rename already enforced single-use.
                            if let Err(e) = std::fs::remove_file(&used_path) {
                                log::warn!(target: "tincd::auth",
                                            "Failed to unlink {}: {e}",
                                            used_path.display());
                            }

                            conn.invite = Some(InvitePhase::WaitingPubkey {
                                name: invited_name.clone(),
                                used_path,
                            });

                            log::info!(target: "tincd::auth",
                                        "Invitation successfully sent to {invited_name} ({hostname})");
                        }

                        (1, Some(InvitePhase::WaitingPubkey { name, .. })) => {
                            // newline check happens inside finalize().
                            let Ok(pubkey_b64) = std::str::from_utf8(&bytes) else {
                                log::error!(target: "tincd::auth",
                                            "Invalid pubkey from {name} ({hostname}): non-UTF-8");
                                self.terminate(id);
                                return needs_write;
                            };

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

                            // Write addr cache. Our cache is per-
                            // Outgoing not per-Node, but write the
                            // file anyway so a future ConnectTo finds
                            // it.
                            if let Some(addr) = conn_addr {
                                let mut cache = crate::addrcache::AddressCache::open(
                                    &self.confbase,
                                    &name,
                                    Vec::new(),
                                );
                                cache.add_recent(addr);
                                if let Some((path, bytes)) = cache.serialize() {
                                    self.script_worker.submit(
                                        crate::scriptworker::Job::WriteFile { path, bytes },
                                    );
                                }
                                cache.disarm();
                            }

                            self.run_invitation_accepted_script(&name, conn_addr);

                            // empty type-2 = ACK; joiner closes after
                            // reading it.
                            let Some(conn) = self.conns.get_mut(id) else {
                                return needs_write;
                            };
                            needs_write |= conn.send_sptps_record(2, &[]);

                            // Stay open (joiner closes; we EOF
                            // normally). Don't terminate — type-2
                            // still in outbuf. Terminal phase: any
                            // further record hits the catch-all arm.
                            conn.invite = Some(InvitePhase::Done);
                        }

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

    pub(super) fn run_invitation_accepted_script(&self, node: &str, addr: Option<SocketAddr>) {
        let mut env = ScriptEnv::base(None, &self.name, None, Some(&self.iface), None);
        env.add("NODE", node.to_owned());
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
