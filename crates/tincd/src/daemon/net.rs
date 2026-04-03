#[allow(clippy::wildcard_imports)]
use super::*;

impl Daemon {
    /// `handle_new_meta_connection` (`net_socket.c:734-779`).
    /// accept on TCP listener `i`, tarpit-check, configure, allocate
    /// Connection, register with event loop.
    ///
    /// Same shape as `on_unix_accept` plus: `sockaddrunmap` (v4-mapped
    /// v6 → plain v4), `is_local`+tarpit (rate-limit non-loopback),
    /// `configure_tcp` (NONBLOCK + NODELAY).
    pub(super) fn on_tcp_accept(&mut self, i: u8) {
        let listener = &self.listeners[usize::from(i)];

        // C `:745`: `fd = accept(l->tcp.fd, &sa.sa, &len)`.
        // socket2 uses accept4(SOCK_CLOEXEC) on Linux/BSD — the C
        // doesn't set CLOEXEC on accepted fds (small leak into
        // script.c children, fixed for free).
        let (sock, peer_sockaddr) = match listener.tcp.accept() {
            Ok(pair) => pair,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                // The listener fd is NOT non-blocking but accept can
                // still spuriously return EAGAIN if a peer connect+
                // RST'd between epoll wake and our accept (TOCTOU).
                return;
            }
            Err(e) => {
                // C `:748`: `logger(ERR); return`. Nothing to clean.
                log::error!(target: "tincd::conn",
                            "Accepting a new connection failed: {e}");
                return;
            }
        };

        // ─── sockaddrunmap (`:751`)
        // V6ONLY is set so we shouldn't see mapped addrs in practice.
        // Canonicalize anyway: `fmt_addr` and the tarpit's prev-addr
        // compare want plain v4.
        //
        // `as_socket()` returns None for AF_UNIX (impossible here —
        // TCP accept returns AF_INET/AF_INET6). The `else` branch is
        // a kernel-bug-guard: log + dummy. `expect()` would crash
        // the whole daemon for one bizarre accept; not proportionate.
        // The dummy 0.0.0.0:0 won't match prev_addr (no false
        // tarpit), won't be is_local (no false exemption either).
        let peer = if let Some(sa) = peer_sockaddr.as_socket() {
            unmap(sa)
        } else {
            log::error!(target: "tincd::conn",
                        "accept returned non-IP family {:?}",
                        peer_sockaddr.family());
            (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
        };

        // ─── tarpit check (`:753`)
        // C: `if(!is_local_connection(&sa) && check_tarpit(&sa, fd))
        //   return`. The `&&` short-circuits: local conns never tick
        // the buckets. The pidfile address is loopback; `tinc start`
        // followed by 100 `tinc info` queries doesn't get tarpitted.
        if !is_local(&peer) {
            let now = self.timers.now();
            if self.tarpit.check(peer, now) {
                // C: `tarpit(fd); return true` from check → caller
                // returns. We do the pit() here; the C splits
                // check/pit because `check_tarpit` is `static bool`
                // and `tarpit` is `void`. Our struct fuses both.
                //
                // `sock.into()`: Socket → OwnedFd. The fd is NOT
                // configured (no NONBLOCK, no NODELAY) — we never
                // touch it again. The peer's reads block forever.
                self.tarpit.pit(sock.into());
                log::info!(target: "tincd::conn",
                           "Tarpitting connection from {peer}");
                return;
            }
        }

        // ─── configure_tcp (`:773`)
        // C ordering: new_connection (`:758`) BEFORE configure_tcp
        // (`:773`). We flip: configure first, THEN allocate. If
        // configure fails (set_nonblocking error), we don't have a
        // half-registered Connection to clean up. The C ordering
        // works because C errors don't unwind — `:73-75` just logs
        // and continues with a blocking fd. We're stricter.
        let fd = match configure_tcp(sock) {
            Ok(fd) => fd,
            Err(e) => {
                log::error!(target: "tincd::conn",
                            "configure_tcp failed for {peer}: {e}");
                return; // sock dropped (fd closed)
            }
        };

        // ─── allocate connection (`:758-776`)
        // C `:762`: `c->hostname = sockaddr2hostname(&sa)`. The
        // "10.0.0.5 port 50123" string. Never changes after this.
        // C `:749`: `memcpy(&c->address, &sa, salen)`. We pass the
        // `SocketAddr` (already unmapped) for `ack_h`'s edge build.
        let hostname = fmt_addr(&peer);
        let conn = Connection::new_meta(fd, hostname, peer, self.timers.now());
        let conn_fd = conn.fd();

        let id = self.conns.insert(conn);
        // C `:771`: `io_add(&c->io, handle_meta_io, c, c->socket,
        // IO_READ)`. Read-only initially. Same registration as unix.
        match self.ev.add(conn_fd, Io::Read, IoWhat::Conn(id)) {
            Ok(io_id) => {
                self.conn_io.insert(id, io_id);
                // C `:767`: `"Connection from %s", c->hostname`.
                log::info!(target: "tincd::conn",
                           "Connection from {peer}");
            }
            Err(e) => {
                // ev.add failed (out of fds?). Roll back.
                self.conns.remove(id);
                log::error!(target: "tincd::conn",
                            "Failed to register connection: {e}");
            }
        }
    }

    /// `handle_incoming_vpn_data` (`net_packet.c:1845-1913`) +
    /// `handle_incoming_vpn_packet` (`:1718-1842`) +
    /// `receive_udppacket` SPTPS branch (`:424-455`).
    ///
    /// Wire layout for a 1.1-SPTPS direct packet (`net.h:92-93`):
    /// `[dst_id:6][src_id:6][seqno:4][type:1][body][tag:16]`. The
    /// 12-byte ID prefix is OUTSIDE the SPTPS framing (C `DEFAULT_
    /// PACKET_OFFSET = 12`); the receiver strips it then feeds the
    /// rest to `sptps_receive_data`.
    ///
    /// `dst == nullid` means "direct to you" (`net_packet.c:1013`
    /// on the send side, `:1741` on the receive side). Relay path
    /// (`dst != nullid && to != myself`) is wired (chunk-9b).
    ///
    /// **The drain loop is bounded.** Same shape as `on_device_read`
    /// (bug audit `deef1268`, sibling of EPOLLET #3): under sustained
    /// UDP ingress (we are the iperf3 receiver), the kernel UDP
    /// socket buffer refills as fast as we drain. The TUN write-back
    /// inside `route_packet` runs inline so traffic flows; but
    /// meta-conn flush, REQ_KEY restarts, and timers starve. At the
    /// cap, `rearm()` forces an `EPOLL_CTL_MOD` so the next turn()
    /// fires immediately — after the rest of the event loop has had
    /// a turn. C `recvmmsg(..., MAX_MSG=64, ...)` is one batch per
    /// callback (level-triggered); we match that batch size.
    /// STUB(chunk-11-perf): `recvmmsg` batching.
    pub(super) fn on_udp_recv(&mut self, i: u8) {
        /// C `net_packet.c:1845` `MAX_MSG`. Packets per turn before
        /// rearming. Tune via the throughput gate.
        const UDP_DRAIN_CAP: u32 = 64;

        // C `MAXSIZE` is `MTU + 4 + cipher overhead`. We use a
        // generous fixed buf; oversize packets truncate (MSG_TRUNC)
        // and we'd reject them anyway (the SPTPS decrypt fails).
        let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); 2048];
        let mut drained = 0u32;
        loop {
            if drained >= UDP_DRAIN_CAP {
                // Hit the cap with the fd still readable. Rearm so
                // the next turn() fires immediately — after outbuf
                // flush and timers have had their turn.
                if let Some(&io_id) = self.listener_udp_io.get(usize::from(i)) {
                    if let Err(e) = self.ev.rearm(io_id) {
                        log::error!(target: "tincd::net",
                                    "UDP fd rearm failed: {e}");
                    }
                }
                break;
            }
            drained += 1;
            // socket2 `recv_from` into `[MaybeUninit<u8>]`. Returns
            // `(n, SockAddr)`. `as_socket()` for the SocketAddr.
            let (n, sockaddr) = match self.listeners[usize::from(i)].udp.recv_from(&mut buf) {
                Ok(pair) => pair,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    // C `:1878`: `"Receiving packet failed: %s"`.
                    log::error!(target: "tincd::net",
                                "Receiving packet failed: {e}");
                    break;
                }
            };
            // SAFETY: `recv_from` returned `n` bytes written. The
            // first `n` slots are initialized. Transmute the
            // `MaybeUninit<u8>` slice to `u8` for those bytes.
            // (`MaybeUninit::slice_assume_init_ref` is unstable;
            // the manual cast is the stable equivalent.)
            #[allow(unsafe_code)]
            let pkt: &[u8] = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), n) };
            // C `:1724`: `sockaddrunmap(addr)`. v4-mapped → v4.
            let peer = sockaddr.as_socket().map(unmap);

            self.handle_incoming_vpn_packet(pkt, peer);
        }
    }

    /// `handle_incoming_vpn_packet` (`net_packet.c:1718-1842`).
    /// One UDP datagram → ID-prefix lookup → SPTPS receive → route.
    ///
    /// SPTPS-only: skips `lookup_node_udp` (`:1728`) and `try_harder`
    /// (`:1754`). Goes straight to the source-ID lookup at `:1736`.
    /// The C does udp-addr-first because legacy-crypto packets have
    /// no ID prefix; we don't have legacy.
    #[allow(clippy::too_many_lines)] // C `:1718-1842` is 124 LOC.
    // The relay/receive branches share the prefix-parse + lookup
    // prelude; splitting would duplicate or thread 5 locals through.
    pub(super) fn handle_incoming_vpn_packet(&mut self, pkt: &[u8], peer: Option<SocketAddr>) {
        // C `:1736`: `pkt->offset = 2 * sizeof(node_id_t)`. The
        // 12-byte [dst][src] prefix. Too-short packet: drop.
        if pkt.len() < 12 {
            log::debug!(target: "tincd::net",
                        "Dropping {}-byte UDP packet (too short for ID prefix)",
                        pkt.len());
            return;
        }
        // `net.h:92-93`: `DSTID(x) = data + offset - 12` (i.e. byte
        // 0 with offset=12), `SRCID(x) = data + offset - 6` (byte 6).
        let dst_id = NodeId6::from_bytes(pkt[0..6].try_into().unwrap());
        let src_id = NodeId6::from_bytes(pkt[6..12].try_into().unwrap());
        let ct = &pkt[12..];

        // C `:1739`: `from = lookup_node_id(SRCID(pkt))`. The fast
        // path. STUB(chunk-never): `try_harder` fallback (decrypt-
        // by-trial when the lookup misses — happens for ID
        // collisions or pre-1.1 packets, neither of which we
        // support; only fires on protocol downgrade or misconfig).
        let Some(from_nid) = self.id6_table.lookup(src_id) else {
            log::debug!(target: "tincd::net",
                        "Received UDP packet from unknown source ID {src_id} ({peer:?})");
            return;
        };
        let from_name = self
            .graph
            .node(from_nid)
            .map_or("<gone>", |n| n.name.as_str())
            .to_owned();

        // C `:1786-1821`: `if(!memcmp(dst, nullid)) { direct=true;
        // from=n; to=myself } else { from=lookup(src); to=lookup(
        // dst) }`. With `dst==null`, the packet is direct-to-us.
        // With `dst!=null`: either it's STILL for us (`dst ==
        // myself` — the sender just didn't set nullid; happens
        // when they didn't know we're a direct neighbor) OR it's
        // a relay packet we forward.
        if !dst_id.is_null() {
            let Some(to_nid) = self.id6_table.lookup(dst_id) else {
                log::debug!(target: "tincd::net",
                            "Received UDP relay packet from {from_name} \
                             with unknown dst ID {dst_id}");
                return;
            };
            // C `:1800-1803`: `if(!to->status.reachable) return`.
            // Race: the dst just became unreachable. Drop.
            if !self.graph.node(to_nid).is_some_and(|n| n.reachable) {
                log::debug!(target: "tincd::net",
                            "Cannot relay UDP packet from {from_name}: \
                             dst {dst_id} is unreachable");
                return;
            }
            // C `:1817-1821`: `if(to != myself) { send_sptps_data(
            // to, from, 0, DATA, len); try_tx(to, true); return }`.
            // The HOT relay path. We pass `from_nid` so the relay
            // wire prefix carries the ORIGINAL source ID.
            if to_nid != self.myself {
                let to_name = self
                    .graph
                    .node(to_nid)
                    .map_or("<gone>", |n| n.name.as_str())
                    .to_owned();
                log::debug!(target: "tincd::net",
                            "Relaying UDP packet from {from_name} to {to_name} \
                             ({} bytes)", ct.len());
                let mut nw = self.send_sptps_data_relay(to_nid, &to_name, from_nid, 0, Some(ct));
                nw |= self.try_tx(to_nid, true);
                if nw {
                    self.maybe_set_write_any();
                }
                return;
            }
            // dst == myself but not nullid: fall through to the
            // direct-receive path. Same as `dst.is_null()`.
            // C `:1810-1815`: `if(n != from->via && to->via ==
            // myself) send_udp_info(myself, from)`. The packet
            // arrived via a dynamic relay (`n` is the immediate UDP
            // sender; `from->via` is the static relay). If WE'RE
            // the static relay (`to->via == myself`), tell `from`
            // where they're reachable so the next packet can skip
            // the dynamic relay. Gated to static-relay-only to
            // avoid every hop in a chain emitting its own hint.
            let from_via = self
                .last_routes
                .get(from_nid.0 as usize)
                .and_then(Option::as_ref)
                .map(|r| r.via);
            // `n` (the immediate sender) is whoever owns `recv_
            // from` — we don't track that NodeId here, but the C
            // condition `n != from->via` is equivalent to "the
            // packet was relayed at all" when the dst_id6 prefix
            // is non-null (which is THIS branch). The non-null
            // prefix means SOMEONE relayed; if that someone is
            // `from` itself, the prefix would be null. So `n !=
            // from->via` is implicitly satisfied here. Just check
            // the second half.
            if from_via == Some(self.myself) && self.send_udp_info(from_nid, &from_name, true) {
                self.maybe_set_write_any();
            }
        }

        // C `:1825`: `receive_udppacket(from, pkt)`. SPTPS branch
        // (`net_packet.c:424-455`).
        let tunnel = self.tunnels.entry(from_nid).or_default();
        let Some(sptps) = tunnel.sptps.as_deref_mut() else {
            // C `:426-433`: `if(!n->sptps.state)`. We got a UDP
            // packet before the per-tunnel handshake started. The C
            // kicks `send_req_key` here; we do too (it's harmless
            // — if a handshake is already in flight, the responder
            // side restarts it).
            if tunnel.status.waitingforkey {
                log::debug!(target: "tincd::net",
                            "Got packet from {from_name} but they haven't \
                             got our key yet");
            } else {
                log::debug!(target: "tincd::net",
                            "Got packet from {from_name} but we haven't \
                             exchanged keys yet");
                let _ = self.send_req_key(from_nid);
            }
            return;
        };

        // C `:437`: `n->status.udppacket = true`. Tells `receive_
        // sptps_record` (the callback) that THIS record came via UDP
        // (vs TCP-tunneled). The C resets it to false at `:439`
        // after `sptps_receive_data` returns; we do the same
        // (the bit is ephemeral, `route.c` reads it for "reply
        // same way" logic in chunk 9).
        tunnel.status.udppacket = true;

        // C `:438`: `sptps_receive_data(&n->sptps, DATA, len)`.
        // Datagram framing: one whole record per call. `OsRng` for
        // the rekey-response edge (rare; it's a peer-initiated
        // KEX during established session).
        let result = sptps.receive(ct, &mut OsRng);
        // C `:439`: `n->status.udppacket = false`. The C SPTPS
        // callback fires RE-ENTRANTLY inside `sptps_receive_data`,
        // so the bit is set during dispatch then cleared here. Our
        // SPTPS returns Vec<Output>; dispatch happens AFTER. Defer
        // the clear until after dispatch (below).
        let outs = match result {
            Ok((_consumed, outs)) => outs,
            Err(e) => {
                // C `:441-450`: "tunnel stuck" restart logic. Gate
                // on `last_req_key + 10 < now` to prevent storms.
                log::debug!(target: "tincd::net",
                            "Failed to decode UDP packet from {from_name}: {e:?}");
                let now = self.timers.now();
                let gate_ok = self.tunnels.get(&from_nid).is_none_or(|t| {
                    t.last_req_key
                        .is_none_or(|last| now.duration_since(last).as_secs() >= 10)
                });
                if gate_ok {
                    let _ = self.send_req_key(from_nid);
                }
                return;
            }
        };

        // C `:1833-1835`: `if(direct && sockaddrcmp(addr,
        // &n->address)) update_node_udp(n, addr)`. The FIRST valid
        // UDP packet from this peer confirms the address. We don't
        // have full `update_node_udp` (which also re-indexes
        // `node_udp_tree`); just stash + set the bit.
        if let Some(peer_addr) = peer {
            // Resolve the listener index ONCE here, on the first
            // confirmed packet, instead of per-send. `adapt_socket`
            // scans listeners for a family match; the answer doesn't
            // change while `udp_addr` doesn't change. ≤8 listeners
            // (`net.h` MAXSOCKETS) so the borrow-clone is tiny.
            let listener_addrs: Vec<SocketAddr> = self.listeners.iter().map(|l| l.local).collect();
            let sock = local_addr::adapt_socket(&peer_addr, 0, &listener_addrs);
            let tunnel = self.tunnels.entry(from_nid).or_default();
            if !tunnel.status.udp_confirmed {
                log::debug!(target: "tincd::net",
                            "UDP address of {from_name} confirmed: {peer_addr}");
                tunnel.status.udp_confirmed = true;
            }
            tunnel.udp_addr = Some(peer_addr);
            // Pre-convert to sockaddr_storage so sendto doesn't
            // re-pack v4/v6 every packet (was 0.37% self-time).
            tunnel.udp_addr_cached = Some((socket2::SockAddr::from(peer_addr), sock));
        }

        // Dispatch SPTPS outputs (`receive_sptps_record`, `net_
        // packet.c:1056-1152`). May produce `HandshakeDone`
        // (handshake completed mid-stream after a rekey) and/or
        // `Record{type=0, data}` (one IP packet) and/or `Wire`
        // (rekey response, `send_sptps_data` it).
        let nw = self.dispatch_tunnel_outputs(from_nid, &from_name, outs);
        // C `:439`: now clear udppacket (see comment above).
        if let Some(t) = self.tunnels.get_mut(&from_nid) {
            t.status.udppacket = false;
        }
        if nw {
            self.maybe_set_write_any();
        }
    }

    /// `handle_device_data` (`net_packet.c:1916-1938`).
    ///
    /// TUN read → `route()` → `send_packet`. The C reads ONE packet
    /// per io callback (level-triggered `select()`/`epoll`); we drain
    /// in a loop because mio is edge-triggered (`EPOLLET`): returning
    /// before `EAGAIN` would miss the rest of the queue forever.
    /// C `DEFAULT_PACKET_OFFSET = 12` reserves room for the
    /// `[dst][src]` prefix; we don't need that pre-padding (our
    /// `send_sptps_data` builds the prefix into a fresh Vec).
    ///
    /// **The drain loop is bounded.** Under sustained line-rate
    /// ingress (iperf3 saturating the TUN), the kernel queue may
    /// refill faster than we drain it: an unbounded loop would never
    /// return to the event loop, starving meta-conn flush, UDP recv,
    /// PMTU probes, and timers. At the cap, `rearm()` forces an
    /// `EPOLL_CTL_MOD` which re-evaluates readiness and fires on the
    /// next turn. Idle links hit `EAGAIN` after a few packets and
    /// skip the rearm — the syscall cost only applies under load.
    pub(super) fn on_device_read(&mut self) {
        /// Packets per `on_device_read` call. The C reads one
        /// (level-triggered); we batch to amortize the `epoll_wait`
        /// return. 64 is heuristic: enough to amortize, small enough
        /// that one batch's UDP sendto burst doesn't overflow the
        /// peer's receive buffer before they get a turn to drain.
        /// Tune via the throughput gate.
        const DEVICE_DRAIN_CAP: u32 = 64;

        // `MTU = 1518`. The device's `read()` writes up to that.
        // FdTun reads at `+14` and synthesizes the ethernet header
        // into `[0..14]`; the buffer must be ≥ MTU.
        let mut buf = vec![0u8; crate::tunnel::MTU as usize];
        let mut nw = false;
        let mut drained = 0u32;
        loop {
            if drained >= DEVICE_DRAIN_CAP {
                // Hit the cap with the fd still readable. Rearm so
                // the next turn() fires immediately — after outbuf
                // flush, UDP recv, and timers have had their turn.
                if let Some(io_id) = self.device_io {
                    if let Err(e) = self.ev.rearm(io_id) {
                        // Shouldn't happen (the fd is open, we just
                        // read from it). Worst case: one stalled
                        // turn until the kernel queues more (which
                        // generates a fresh edge).
                        log::error!(target: "tincd::net",
                                    "device fd rearm failed: {e}");
                    }
                }
                break;
            }
            drained += 1;
            let n = match self.device.read(&mut buf) {
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    // C `:1933-1936`: `errors++; if > 10 event_
                    // exit()`. The C also `sleep_millis(errors*50)`
                    // (rate-limit a tight error loop on a flapping
                    // TUN). We're simpler: log + break. The fd stays
                    // registered; if it's truly dead (EBADFD), every
                    // turn fires this arm.
                    log::error!(target: "tincd::net",
                                "Error reading from device: {e}");
                    // C `:1933-1936`: at 10 consecutive failures,
                    // `event_exit()`. The kernel device is gone;
                    // tight-looping helps nobody. The C also does
                    // `sleep_millis(errors * 50)` to rate-limit a
                    // flapping TUN; we don't (the bound is 10 — the
                    // sleep would total 2.75s, then exit anyway).
                    self.device_errors += 1;
                    if self.device_errors > 10 {
                        log::error!(target: "tincd",
                                    "Too many errors from device, exiting!");
                        self.running = false;
                    }
                    break;
                }
            };
            // C `:1931`: `errors = 0`. Reset on success.
            self.device_errors = 0;
            // C `:1928-1929`: `myself->in_packets++; in_bytes +=`.
            let myself_tunnel = self.tunnels.entry(self.myself).or_default();
            myself_tunnel.in_packets += 1;
            myself_tunnel.in_bytes += n as u64;

            // C `:1930`: `route(myself, &packet)`. `from = None`
            // means source is myself (device read).
            nw |= self.route_packet(&mut buf[..n], None);
        }
        if nw {
            self.maybe_set_write_any();
        }
    }

    /// `route()` (`route.c:1130`) → `send_packet` (`net_packet.c:
    /// 1553-1617`). The forwarding decision plus the dispatch.
    ///
    /// `data` is the full ethernet frame (14-byte header + payload).
    /// `&mut` because `device.write()` mutates (the TUN write-path
    /// zeroes `tun_pi.flags`; FdTun doesn't, but the trait is `&mut`).
    ///
    /// `from`: `None` = device read (source = myself). `Some(nid)` =
    /// from a peer (`receive_sptps_record`). The C `route()` takes
    /// `node_t *source` for the same distinction.
    ///
    /// Returns the io_set signal (true if a meta-conn outbuf went
    /// nonempty — `send_req_key` or the TCP-tunneled handshake).
    pub(super) fn route_packet(&mut self, data: &mut [u8], from: Option<NodeId>) -> bool {
        // C `route.c:1135-1138`: `if(forwarding_mode == FMODE_KERNEL
        // && source != myself) { send_packet(myself, ...); return; }`.
        // Kernel mode shortcut: anything from a peer goes straight
        // to the TUN; let the OS forwarding table decide. Packets
        // from OUR device still go through routing (we're the
        // originator). BEFORE the length check — matches C order;
        // device.write rejects undersized anyway.
        if self.settings.forwarding_mode == ForwardingMode::Kernel && from.is_some() {
            let len = data.len() as u64;
            let myself_tunnel = self.tunnels.entry(self.myself).or_default();
            myself_tunnel.out_packets += 1;
            myself_tunnel.out_bytes += len;
            if let Err(e) = self.device.write(data) {
                log::debug!(target: "tincd::net", "Error writing to device: {e}");
            }
            return false;
        }

        // C `route.c:1146`: `switch(routing_mode)`. The dispatch.
        match self.settings.routing_mode {
            RoutingMode::Switch => {
                // `route.c:1159`: `route_mac(source, packet)`.
                return self.route_packet_mac(data, from);
            }
            RoutingMode::Hub => {
                // `route.c:1163`: `route_broadcast(source, packet)`.
                // Hub mode = always broadcast. No learning, no
                // lookup. The decrement_ttl gate is inside
                // `dispatch_route_result`'s Broadcast arm.
                return self.dispatch_route_result(&RouteResult::Broadcast, data, from);
            }
            RoutingMode::Router => {
                // Fall through to the IP-layer dispatch below.
            }
        }

        // ─── ARP intercept (`route.c:1149` `case ETH_P_ARP`).
        // ROUTER-ONLY. Switch mode treats ARP as opaque eth and
        // already returned above. The C dispatch puts ARP in the
        // same ethertype switch as IPv4/IPv6, but `route_arp` does
        // its OWN subnet lookup (`route.c:988`) so we handle it
        // here before `route()` (which just returns
        // `Unsupported{"arp"}`).
        if data.len() >= 14 && u16::from_be_bytes([data[12], data[13]]) == crate::packet::ETH_P_ARP
        {
            return self.handle_arp(data);
        }

        // The reachability oracle for `route()`. C `route.c:655`
        // reads `subnet->owner->status.reachable` directly (it's
        // all one big graph of pointers). We close over `node_ids`
        // + `graph` and look it up.
        //
        // Materialize the result with `'static`/local lifetime: the
        // `RouteResult<'a>` lifetime ties back to `self.subnets`,
        // and `dispatch_route_result` is `&mut self` (conflict).
        // The Forward arm clones `to` anyway; we just hoist that.
        // Exhaustively rebuild every arm so the output's `'a` is
        // tied to a local, not `self`.
        let owned_to;
        let result: RouteResult<'_> = {
            let node_ids = &self.node_ids;
            let graph = &self.graph;
            let r = route(data, &self.subnets, &self.name, |name| {
                node_ids
                    .get(name)
                    .and_then(|&nid| graph.node(nid))
                    .is_some_and(|n| n.reachable)
            });
            owned_to = if let RouteResult::Forward { to } = r {
                Some(to.to_owned())
            } else {
                None
            };
            detach_route_result(&r, owned_to.as_deref())
        };

        self.dispatch_route_result(&result, data, from)
    }

    /// `route_mac` wrapper. The Switch-mode dispatch arm. Calls the
    /// pure `route_mac::route_mac`, then acts on the
    /// `(RouteResult, LearnAction)` two-channel return.
    ///
    /// `route_mac.rs` takes a `&HashMap<Mac, String>` snapshot. We
    /// pass `self.mac_table` directly. The borrow is `&` only (the
    /// function is pure); no conflict with the `&mut self` calls
    /// below.
    fn route_packet_mac(&mut self, data: &mut [u8], from: Option<NodeId>) -> bool {
        let from_myself = from.is_none();
        // C `route.c:1031`: `if(source == myself)`. The source name
        // for the loop check (`:1047 owner == source`).
        let source_name = match from {
            None => self.name.clone(),
            Some(nid) => self
                .graph
                .node(nid)
                .map_or_else(|| "<unknown>".to_owned(), |n| n.name.clone()),
        };

        // Materialize the result with local lifetime (see
        // `route_packet` for the same hoist — `RouteResult<'a>`
        // borrows `self.mac_table` here).
        let owned_to;
        let (result, learn) = {
            let (r, l) =
                route_mac::route_mac(data, from_myself, &source_name, &self.name, &self.mac_table);
            owned_to = if let RouteResult::Forward { to } = r {
                Some(to.to_owned())
            } else {
                None
            };
            (detach_route_result(&r, owned_to.as_deref()), l)
        };

        // ─── LearnAction first (C `route.c:1031-1035` is BEFORE the
        // routing decision in source order, but they're independent).
        let mut nw = false;
        match learn {
            route_mac::LearnAction::NotOurs => {}
            route_mac::LearnAction::New(mac) => {
                // C `route.c:528-551` `learn_mac`: `subnet_add` +
                // broadcast ADD_SUBNET + timer arm.
                nw |= self.learn_mac(mac);
            }
            route_mac::LearnAction::Refresh(mac) => {
                // C `route.c:551-555 else`: `subnet->expires = now +
                // macexpire`. BUT: route_mac's snapshot doesn't scope
                // to myself (see `LearnAction::Refresh` doc). The C
                // `lookup_subnet_mac(myself, &src)` at `:525` is
                // myself-scoped. Check ownership:
                if self.mac_table.get(&mac).map(String::as_str) == Some(self.name.as_str()) {
                    let now = self.timers.now();
                    self.mac_leases.refresh(mac, now, self.settings.macexpire);
                } else {
                    // Remotely owned. The C myself-scoped lookup
                    // would fail → branch to New. VM migrated to us.
                    nw |= self.learn_mac(mac);
                }
            }
        }

        // ─── RouteResult dispatch. Reuse the same arms as Router.
        nw |= self.dispatch_route_result(&result, data, from);
        nw
    }

    /// `learn_mac` (`route.c:524-556`). We saw a new source MAC on
    /// our TAP. Record it as a transient `Subnet::Mac`, broadcast
    /// ADD_SUBNET so peers route replies back to us, arm the
    /// `age_subnets` timer.
    ///
    /// Returns the io_set signal (the broadcast ADD_SUBNET sends
    /// queue to meta-conn outbufs).
    fn learn_mac(&mut self, mac: route_mac::Mac) -> bool {
        log::info!(target: "tincd::net",
                   "Learned new MAC address \
                    {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

        // C `:534-541`: `new_subnet; type=MAC; expires=now+macexpire;
        // weight=10; subnet_add(myself, ..); subnet_update(..)`.
        let subnet = Subnet::Mac {
            addr: mac,
            weight: 10,
        };
        let myname = self.name.clone();
        self.subnets.add(subnet, myname.clone());
        self.mac_table.insert(mac, myname.clone());
        // C `:540` `subnet_update(myself, subnet, true)` →
        // subnet-up script. Our subnets are always reachable (we
        // ARE myself).
        self.run_subnet_script(true, &myname, &subnet);

        // C `:536`: `subnet->expires = now + macexpire`. mac_lease
        // tracks this. `learn()` returns true if the table was
        // empty (= first lease, arm the timer).
        let now = self.timers.now();
        let arm_timer = self.mac_leases.learn(mac, now, self.settings.macexpire);

        // C `:544-548`: broadcast ADD_SUBNET. `for(c) if(c->edge)
        // send_add_subnet(c, subnet)`. Our `broadcast_targets(None)`
        // gives active conns (C's `c->edge` = our `c.active`).
        let mut nw = false;
        let targets = self.broadcast_targets(None);
        for cid in targets {
            nw |= self.send_subnet(cid, Request::AddSubnet, &myname, &subnet);
        }

        // C `:549-551`: `timeout_add(&age_subnets_timeout, ...,
        // {10, jitter()})`. C `timeout_add` is idempotent (only
        // adds if not already in heap). We arm only when `learn()`
        // says "table was empty" AND we don't already have a slot
        // (defensive — `arm_timer` should imply `is_none()`, but
        // see the `on_age_subnets` clear below).
        if arm_timer && self.age_subnets_timer.is_none() {
            let tid = self.timers.add(TimerWhat::AgeSubnets);
            self.timers.set(tid, Duration::from_secs(10));
            self.age_subnets_timer = Some(tid);
        }

        nw
    }

    /// `broadcast_packet` (`net_packet.c:1612-1660`). Send a frame
    /// to "everyone" per `broadcast_mode`.
    ///
    /// `from`: `None` = we originated (device read). `Some(nid)` =
    /// from a peer (we're forwarding their broadcast).
    ///
    /// Returns the io_set signal.
    fn broadcast_packet(&mut self, data: &mut [u8], from: Option<NodeId>) -> bool {
        // C `:1616-1618`: `if(from != myself) send_packet(myself,
        // packet)`. Echo to local kernel — a broadcast we're
        // FORWARDING is also for US.
        if from.is_some() {
            let len = data.len() as u64;
            let myself_tunnel = self.tunnels.entry(self.myself).or_default();
            myself_tunnel.out_packets += 1;
            myself_tunnel.out_bytes += len;
            if let Err(e) = self.device.write(data) {
                log::debug!(target: "tincd::net",
                            "Error writing to device: {e}");
            }
        }

        // C `:1624-1626`: `if(tunnelserver || BMODE_NONE) return`.
        // Tunnelserver: MST might be invalid (filtered ADD_EDGE) →
        // loops. BMODE_NONE: operator opted out.
        if self.settings.tunnelserver
            || self.settings.broadcast_mode == broadcast::BroadcastMode::None
        {
            return false;
        }

        let from_is_self = from.is_none();
        log::debug!(target: "tincd::net",
                    "Broadcasting packet of {} bytes from {}",
                    data.len(),
                    if from_is_self { "MYSELF" } else { "peer" });

        // ─── Compute targets per broadcast_mode ──────────────────
        // C `:1633-1652`. Our `broadcast.rs` leaf does the
        // filtering; we provide the iterators.
        let target_nids: Vec<NodeId> = match self.settings.broadcast_mode {
            broadcast::BroadcastMode::None => unreachable!("checked above"),
            broadcast::BroadcastMode::Mst => {
                // C `:1635`: `c->edge && c->status.mst && c !=
                // from->nexthop->connection`.
                //
                // `from_conn`: which conn did the broadcast arrive
                // on? C uses `from->nexthop->connection`. If `from`
                // is set, find `last_routes[from].nexthop`, then
                // `nodes[nexthop_name].conn`.
                let from_conn: Option<ConnId> = from.and_then(|nid| {
                    let route = self.last_routes.get(nid.0 as usize)?.as_ref()?;
                    let nexthop_name = self.graph.node(route.nexthop)?.name.clone();
                    self.nodes.get(&nexthop_name)?.conn
                });

                // Active conns → (ConnId, EdgeId) via NodeState.edge.
                let active: Vec<(ConnId, EdgeId)> = self
                    .conns
                    .iter()
                    .filter(|&(_, c)| c.active)
                    .filter_map(|(cid, c)| {
                        let eid = self.nodes.get(&c.name)?.edge?;
                        Some((cid, eid))
                    })
                    .collect();

                let target_conns =
                    broadcast::mst_targets(active.into_iter(), &self.last_mst, from_conn);

                // Conns → NodeIds via `node_ids[c.name]`.
                target_conns
                    .into_iter()
                    .filter_map(|cid| {
                        let cname = &self.conns.get(cid)?.name;
                        self.node_ids.get(cname).copied()
                    })
                    .collect()
            }
            broadcast::BroadcastMode::Direct => {
                // C `:1648-1652`: walk reachable nodes, filter to
                // one-hop. `direct_targets` wants `(NodeId,
                // Option<via>, Option<nexthop>)`. Feed all
                // `node_ids`; `last_routes[nid]` is `None` for
                // unreachable, which we skip.
                let nodes_iter = self.node_ids.values().filter_map(|&nid| {
                    let r = self.last_routes.get(nid.0 as usize)?.as_ref()?;
                    Some((nid, Some(r.via), Some(r.nexthop)))
                });
                broadcast::direct_targets(nodes_iter, self.myself, from_is_self)
            }
        };

        // ─── Send to each target ──────────────────────────────────
        // C `:1636,1651`: `send_packet(target, packet)`. Same body
        // as `send_packet`: counters + send_sptps_packet + try_tx.
        // No clamp_mss/directonly/decrement_ttl — those are
        // route()-level concerns; broadcast bypasses route().
        //
        // `send_sptps_packet` takes `data: &[u8]` (immutable slice;
        // it copies into a fresh SPTPS record), so iterating sends
        // of the SAME buffer is zero-copy-safe.
        let mut nw = false;
        for nid in target_nids {
            let Some(name) = self.graph.node(nid).map(|n| n.name.clone()) else {
                continue;
            };
            let len = data.len();
            let tunnel = self.tunnels.entry(nid).or_default();
            tunnel.out_packets += 1;
            tunnel.out_bytes += len as u64;
            // C `:1586-1590`: `send_sptps_packet; try_tx(n, true)`.
            nw |= self.send_sptps_packet(nid, &name, data);
            nw |= self.try_tx(nid, true);
        }
        nw
    }

    /// The `match RouteResult { ... }` dispatch. Factored out so
    /// BOTH the Router-mode path (`route()` result) and the
    /// Switch-mode path (`route_mac()` result) call the same arms.
    ///
    /// C: `route_ipv4`/`route_ipv6`/`route_mac` all call
    /// `send_packet`/`route_broadcast`/etc directly. We funnel
    /// through `RouteResult` then dispatch here.
    #[allow(clippy::too_many_lines)] // C `route()` + `send_packet`
    // are ~200 LOC together. The match arms are the dispatch table;
    // splitting them scatters the C line refs.
    fn dispatch_route_result(
        &mut self,
        result: &RouteResult<'_>,
        data: &mut [u8],
        from: Option<NodeId>,
    ) -> bool {
        match *result {
            RouteResult::Forward { to } if to == self.name => {
                // C `send_packet:1556-1568`: `if(n == myself) {
                // devops.write(packet); return; }`. The packet is
                // for US (it came in over the wire and `route()`
                // matched one of our subnets). Write it to the TUN.
                // NOT-PORTING(overwrite-mac): `overwrite_mac`
                // (`:1557-1562`) for `Mode=router DeviceType=tap`.
                // We don't parse `OverwriteMAC`; if set, it's
                // silently ignored. The fix is 6 LOC (memcpy mymac
                // into `data[0..6]`, XOR `data[11]`) if anyone
                // needs it.
                let len = data.len() as u64;
                let myself_tunnel = self.tunnels.entry(self.myself).or_default();
                myself_tunnel.out_packets += 1;
                myself_tunnel.out_bytes += len;
                if let Err(e) = self.device.write(data) {
                    log::debug!(target: "tincd::net",
                                "Error writing to device: {e}");
                }
                false
            }
            RouteResult::Forward { to } => {
                // C `send_packet:1571-1590`. To a remote node.
                let to = to.to_owned();
                let Some(&to_nid) = self.node_ids.get(&to) else {
                    // (see below for the comment block)
                    log::warn!(target: "tincd::net",
                               "route() chose unknown node {to}");
                    return false;
                };

                // C `route.c:649,745`: `if(subnet->owner == source)
                // { logger(WARNING, "Packet looping back to %s!");
                // return; }`. The packet's destination subnet is
                // OWNED by who sent it — they sent us a packet for
                // themselves. Overlapping subnets, misconfiguration.
                // C `:649` is right after `lookup_subnet`, before
                // the reachable check; we slot it right after
                // node-id resolve (same effect — both are early-out
                // before any routing-state reads).
                if Some(to_nid) == from {
                    log::warn!(target: "tincd::net",
                               "Packet looping back to {to}");
                    return false;
                }

                // C `route.c:698`: `clamp_mss(source, via, packet)`.
                // BEFORE `send_packet`, AFTER the routing decision.
                // C `:390`: `if(!(via->options & OPTION_CLAMP_MSS))
                // return`. C `:394-398`: `mtu = source->mtu; if(via
                // != myself && via->mtu < mtu) mtu = via->mtu`.
                //
                // For TUN-origin packets, source is `myself` (whose
                // `mtu` is `MTU`=1518, never probed). The
                // OPTION_CLAMP_MSS check: `via->options` comes from
                // the SSSP result (`graph.c:192`: `e->to->options =
                // e->options`). `last_routes[to_nid].options`
                // carries it. Default-on (bit 3 in `myself_options_
                // default()`).
                //
                // C `route.c:672`: `via = (owner->via == myself) ?
                // owner->nexthop : owner->via`. Read once, copy out
                // (NodeId is Copy), drop the borrow before calling
                // `&mut self` methods below. Invariant: `last_
                // routes` is current for any `Forward` target
                // (`route()` only returns Forward for reachable
                // owners; sssp populates `last_routes` for those).
                let route = self
                    .last_routes
                    .get(to_nid.0 as usize)
                    .and_then(Option::as_ref);
                let via_options = route.map_or(0, |r| r.options);
                let via_nid = route.map_or(to_nid, |r| {
                    if r.via == self.myself {
                        r.nexthop
                    } else {
                        r.via
                    }
                });

                // C `route.c:675,770`: `if(via == source) { logger(
                // ERR, "Routing loop for packet from %s!"); return;
                // }`. The next hop IS who sent it to us — bounce
                // loop. Can fire when graph routing data is stale
                // (DEL_EDGE arrived but `run_graph` hasn't yet
                // recomputed `via`). C `:677 return` is silent drop.
                if Some(via_nid) == from {
                    let from_name = from
                        .and_then(|nid| self.graph.node(nid))
                        .map_or("?", |n| n.name.as_str());
                    log::error!(target: "tincd::net",
                                "Routing loop for packet from {from_name}");
                    return false;
                }

                // C `route.c:685`: `via->mtu`. Read once, used by
                // both the FRAG_NEEDED gate (unconditional) and the
                // CLAMP_MSS block (option-gated). Hoisted out of the
                // CLAMP_MSS scope — the C reads it at `:685`
                // regardless. `MTU` if no tunnel yet (matches C's
                // xzalloc → 0 → the C `< mtu` check fails →
                // uses source->mtu — wait, C's `n->mtu` starts 0,
                // but `route.c:396` is `via->mtu < mtu` so a 0 mtu
                // would WIN. Our `TunnelState::default()` inits to
                // `MTU` instead — see tunnel.rs:128. Either way:
                // until PMTU runs, this is the 1518 ceiling).
                let via_mtu = self.tunnels.get(&via_nid).map_or(MTU, TunnelState::mtu);

                // C `route.c:679-682`: `if(directonly && owner !=
                // via) route_ipv4_unreachable(..., NET_ANO);
                // return`. The relay path EXISTS (chunk-9b proves
                // it); this knob lets the operator opt out. v6:
                // ICMP6_DST_UNREACH_ADMIN (`route.c:774`).
                if self.settings.directonly && to_nid != via_nid {
                    let ethertype = u16::from_be_bytes([data[12], data[13]]);
                    let (t, c) = if ethertype == crate::packet::ETH_P_IP {
                        (route::ICMP_DEST_UNREACH, route::ICMP_NET_ANO)
                    } else {
                        (route::ICMP6_DST_UNREACH, route::ICMP6_DST_UNREACH_ADMIN)
                    };
                    self.write_icmp_to_device(data, t, c);
                    return false;
                }
                // C `route.c:685-696,779-784`. Packet too big for
                // next hop's discovered PMTU. `via_nid != myself`:
                // only when relaying — we don't FRAG_NEEDED for our
                // OWN endpoint (`clamp_mss` and the kernel's PMTU
                // handle our outbound). Floors: 590 = 576 (RFC 791
                // IPv4 minimum) + 14 eth; 1294 = 1280 (RFC 8200
                // IPv6 minimum) + 14. The `MAX(via->mtu, FLOOR)`
                // means: even if PMTU discovery hasn't run
                // (via->mtu small/0), don't send a FRAG_NEEDED
                // claiming MTU < 576 — that'd be RFC-violating
                // nonsense. The C `:690 packet->len = MAX(...)`
                // truncation is for the ICMP quote; our
                // `build_v4_unreachable` already caps internally
                // (`icmp.rs::V4_QUOTE_CAP`), so we skip it.
                if via_nid != self.myself {
                    let ethertype = u16::from_be_bytes([data[12], data[13]]);
                    let floor: u16 = if ethertype == crate::packet::ETH_P_IP {
                        590
                    } else {
                        1294
                    };
                    let limit = via_mtu.max(floor);
                    if data.len() > usize::from(limit) {
                        if ethertype == crate::packet::ETH_P_IP {
                            // C `:688`: DF flag at IP-hdr byte 6 =
                            // frame byte 20. `data.len() > 590`
                            // guarantees `[20]` is in bounds.
                            let df_set = data[20] & 0x40 != 0;
                            if df_set {
                                // `limit - 14`: IP-layer MTU (no
                                // eth). C `:690` truncates `packet
                                // ->len` then `:174 icmp.icmp_
                                // nextmtu = htons(packet->len -
                                // ether_size)`. We thread it
                                // directly. `limit >= 590` so the
                                // sub never wraps.
                                self.write_icmp_frag_needed(data, limit - 14);
                            }
                            // else: C calls `fragment_ipv4_packet`
                            // (`:614-681`).
                            // NOT-PORTING(ipv4-fragment): in-transit
                            // IPv4 frag. The C does it (~70 LOC of
                            // pointer arithmetic for RFC 791 header
                            // copy + offset/MF flag manipulation).
                            // Modern OS sets DF on TCP (PMTUD); UDP
                            // without DF through a narrow-MTU relay
                            // drops here. Niche. See
                            // RUST_REWRITE_PLAN.md `route.c` row.
                        } else {
                            // v6: always ICMP6_PACKET_TOO_BIG (no
                            // in-transit frag, RFC 8200 §5).
                            self.write_icmp_pkt_too_big(data, u32::from(limit - 14));
                        }
                        return false;
                    }
                }

                if via_options & crate::proto::OPTION_CLAMP_MSS != 0 {
                    let mtu = via_mtu.min(MTU);
                    // `mss::clamp` mutates in place. `data` is `&mut
                    // [u8]` (the TUN read buffer is OURS). Return
                    // value (was-clamped?) ignored — C `:698`
                    // doesn't check it either.
                    let _ = mss::clamp(data, mtu);
                }

                // C `route.c:664,759`: `if(decrement_ttl &&
                // source != myself && !do_decrement_ttl(source,
                // packet)) return`. AFTER the route decision,
                // BEFORE clamp_mss/send. The `source != myself`
                // gate: don't decrement on TUN-origin packets (we
                // ARE the first hop; the kernel already set TTL).
                // `from.is_some()` is exactly the C `source !=
                // myself` predicate.
                if self.settings.decrement_ttl && from.is_some() {
                    match route::decrement_ttl(data) {
                        TtlResult::Decremented => {}
                        TtlResult::TooShort | TtlResult::DropSilent => {
                            return false;
                        }
                        TtlResult::SendIcmp {
                            icmp_type,
                            icmp_code,
                        } => {
                            // Same shape as the Unreachable arm
                            // below: synthesize ICMP TIME_EXCEEDED,
                            // write back to the TUN. v4/v6 picked
                            // by the type (11 vs 3).
                            self.write_icmp_to_device(data, icmp_type, icmp_code);
                            return false;
                        }
                    }
                }

                let len = data.len();
                log::debug!(target: "tincd::net",
                            "Sending packet of {len} bytes to {to}");
                // C `:1582-1583`: traffic counters BEFORE the send
                // (the C counts attempts, not deliveries).
                let tunnel = self.tunnels.entry(to_nid).or_default();
                tunnel.out_packets += 1;
                tunnel.out_bytes += len as u64;

                // C `:1586-1590`: `if(n->status.sptps) { send_sptps
                // _packet(n, packet); try_tx(n); return; }`. Always
                // SPTPS for us (no legacy fork). `try_tx(n, true)`:
                // the `true` is `mtu` — every forwarded packet drives
                // the PMTU discovery one step.
                let mut nw = self.send_sptps_packet(to_nid, &to, data);
                nw |= self.try_tx(to_nid, true);
                nw
            }
            RouteResult::Unreachable {
                icmp_type,
                icmp_code,
            } => {
                // C `route_ipv4_unreachable` (`route.c:121-215`).
                // Synthesize an ICMP error and write it BACK to the
                // source (the TUN — the packet came FROM us).
                //
                // C `:130-132`: `if(ratelimit(3)) return`. Max 3/sec.
                // The limiter keys on `now.tv_sec` (wall clock) but
                // only compares for same-second; daemon-uptime works.
                let now_sec = self.timers.now().duration_since(self.started_at).as_secs();
                if self.icmp_ratelimit.should_drop(now_sec, 3) {
                    log::debug!(target: "tincd::net",
                                "route: unreachable (type={icmp_type} \
                                 code={icmp_code}), rate-limited");
                    return false;
                }
                // `data` is the full eth frame from the TUN.
                // `route()` only returns NET_UNKNOWN/NET_UNREACH
                // here; FRAG_NEEDED is in the Forward arm (`:685`)
                // where `via_mtu` is in scope. `frag_mtu = None`.
                //
                // C `route.c:734` `route_ipv6` no-subnet exit calls
                // `route_ipv6_unreachable`; `:608` v4 exit calls
                // `route_ipv4_unreachable`. We collapsed both into
                // one `Unreachable` variant; the v4/v6 distinction
                // lives in NEITHER the pure half NOR (until now) the
                // dispatch — bug audit `deef1268`. `data.len() >= 14`
                // is guaranteed: route() returns `TooShort` for
                // shorter; Unreachable means it parsed a full IP hdr.
                let ethertype = u16::from_be_bytes([data[12], data[13]]);
                let reply = if ethertype == 0x86DD {
                    // ETH_P_IPV6
                    icmp::build_v6_unreachable(data, icmp_type, icmp_code, None)
                } else {
                    icmp::build_v4_unreachable(data, icmp_type, icmp_code, None)
                };
                let Some(reply) = reply else {
                    // Too short to parse eth+IP. `route()` already
                    // returned `TooShort` for that case; reaching
                    // here means a route variant we don't expect.
                    log::debug!(target: "tincd::net",
                                "route: unreachable, ICMP synth failed (short input)");
                    return false;
                };
                log::debug!(target: "tincd::net",
                            "route: unreachable, sending ICMP type={icmp_type} \
                             code={icmp_code} ({} bytes)", reply.len());
                self.write_icmp_reply(reply);
                false
            }
            RouteResult::NeighborSolicit => {
                // C `route.c:710-713` → `route_neighborsol`
                // (`:793-954`). Synthesise an NDP advert reply.
                self.handle_ndp(data);
                false
            }
            RouteResult::Unsupported { reason } => {
                log::debug!(target: "tincd::net",
                            "route: dropping packet ({reason})");
                false
            }
            RouteResult::Broadcast => {
                // C `route.c:1042-1045` → `route_broadcast` →
                // `broadcast_packet`. Reachable from `route_mac`
                // (RMODE_SWITCH unknown-dst) and Hub mode.
                //
                // C `route_broadcast:559-563`: `if(decrement_ttl &&
                // source != myself) if(!do_decrement_ttl(..))
                // return`. The C `do_decrement_ttl` is eth-aware
                // (`:327` returns true for non-IP frames like ARP
                // — too short to have an IP TTL). Match: gate, but
                // `decrement_ttl()` will pass on ARP via TooShort.
                if self.settings.decrement_ttl && from.is_some() {
                    match route::decrement_ttl(data) {
                        TtlResult::Decremented | TtlResult::TooShort => {}
                        TtlResult::DropSilent | TtlResult::SendIcmp { .. } => {
                            // C `route_broadcast` doesn't synth
                            // ICMP on TTL expiry — `:563` just
                            // `return`s. Match.
                            return false;
                        }
                    }
                }
                self.broadcast_packet(data, from)
            }
            RouteResult::TooShort { need, have } => {
                // C `route.c:103-108`: `"Got too short packet from
                // %s"` at DEBUG_TRAFFIC.
                log::debug!(target: "tincd::net",
                            "route: too short (need {need}, have {have})");
                false
            }
        }
    }

    /// `send_sptps_packet` (`net_packet.c:683-730`). Wrap an IP
    /// packet in an SPTPS record and ship it.
    ///
    /// C `:684-686`: `if(!validkey && !n->connection) return`. The
    /// gate. If we don't have a session key AND no direct meta-conn
    /// to fall back to (the `send_tcppacket` path at `:725`), drop.
    /// We don't have `send_tcppacket` (chunk-9, the PACKET request
    /// type); the gate is just `!validkey`.
    ///
    /// C `:696-698`: `if(RMODE_ROUTER) offset = 14`. Strips the
    /// ethernet header before encrypting — the receiver re-
    /// synthesizes it from the IP version nibble (`receive_sptps_
    /// record:1128-1144`). Saves 14 bytes/packet.
    pub(super) fn send_sptps_packet(&mut self, to_nid: NodeId, to_name: &str, data: &[u8]) -> bool {
        // C `:696-700`: `if(routing_mode == RMODE_ROUTER) { offset =
        // 14; } else { type = PKT_MAC; }`. Router strips the 14-byte
        // eth header (receiver re-synths from IP version nibble).
        // Switch/Hub: full eth frame on the wire, mark `PKT_MAC`.
        let (offset, base_type) = match self.settings.routing_mode {
            RoutingMode::Router => (14, PKT_NORMAL),
            RoutingMode::Switch | RoutingMode::Hub => (0, PKT_MAC),
        };
        let tunnel = self.tunnels.entry(to_nid).or_default();

        // ─── PACKET 17 short-circuit (`net_packet.c:725`) ────────────
        // C: `if(n->connection && origpkt->len > n->minmtu) send_
        // tcppacket(n->connection, origpkt)`. Direct meta-conn AND
        // packet doesn't fit discovered MTU → single-encrypt via
        // meta-SPTPS, skip per-tunnel SPTPS entirely.
        //
        // Gated BEFORE the validkey check: C `:684 if(!validkey &&
        // !n->connection) return` — with a direct conn, validkey
        // doesn't matter (PACKET 17 doesn't touch per-tunnel SPTPS).
        // With `TCPOnly = yes`, `try_tx_sptps:1477` returns early so
        // SPTPS never starts → validkey stays false forever; this
        // gate is the ONLY way to send.
        //
        // C-IS-WRONG #11: the C `:725` gates AFTER compression at
        // `:708-718`. When compression HELPS, `:716 origpkt = &outpkt`
        // reassigns to a stack `vpn_packet_t` whose `data[0..offset]`
        // is uninitialized (`:710` writes only at `+offset`). `:726`
        // then sends 14 garbage bytes + compressed body. The receiver
        // (`route.c:1144`) reads `data[12..14]` for ethertype →
        // garbage → "unknown type" → drop. PACKET 17 carries no
        // PKT_COMPRESSED bit (raw frame, not SPTPS record); receiver
        // can't know to decompress. Triple-gate dormancy: TCPOnly +
        // direct neighbor + Compression > 0 + the packet actually
        // shrank. Nobody runs that. STRICTER-than-C: gate BEFORE
        // compression, send the original frame, also save the wasted
        // compression work the C does anyway.
        let direct_conn = self.nodes.get(to_name).and_then(|ns| ns.conn);
        if let Some(conn_id) = direct_conn {
            if data.len() > usize::from(tunnel.minmtu()) {
                let Some(conn) = self.conns.get_mut(conn_id) else {
                    // NodeState.conn stale (race with terminate).
                    // Fall through to SPTPS.
                    return false;
                };
                // C `protocol_misc.c:90-103 send_tcppacket`.
                // RED first (`:94`). `maxoutbufsize` (`net_setup.c
                // :1255-1257`, default 10*MTU = 15180). RED kicks
                // in when the meta-conn outbuf exceeds threshold —
                // under load this prevents unbounded growth.
                if crate::tcp_tunnel::random_early_drop(
                    conn.outbuf.live_len(),
                    self.settings.maxoutbufsize,
                    &mut OsRng,
                ) {
                    return true; // C `:95 return true` — fake success
                }
                // C `:98 send_request("%d %d", PACKET, len)`. Goes
                // via `send_meta` → `sptps_send_record(type=0)`.
                // `len` fits u16: MTU is 1518 < i16::MAX.
                #[allow(clippy::cast_possible_truncation)]
                let req = tinc_proto::msg::TcpPacket {
                    len: data.len() as u16,
                };
                let mut nw = conn.send(format_args!("{}", req.format()));
                // C `:102 send_meta(DATA(packet), len)` →
                // `meta.c:65 sptps_send_record(type=0, blob)`. The
                // FULL eth frame, NOT stripped, NOT compressed (see
                // C-IS-WRONG #11 above). Receiver routes it as-is.
                nw |= conn.send_sptps_record(0, data);
                return nw;
            }
        }

        if !tunnel.status.validkey {
            // C `try_sptps` (`net_packet.c:1157-1180`): `"No valid
            // key known yet for %s"` then `if(!waitingforkey) send_
            // req_key(n)`. The packet is dropped; the next one (a
            // few hundred ms later) finds the handshake done.
            log::debug!(target: "tincd::net",
                        "No valid key known yet for {to_name}");
            if !tunnel.status.waitingforkey {
                return self.send_req_key(to_nid);
            }
            // C `:1167-1173`: the 10-second debounce. If we sent a
            // REQ_KEY recently and got no answer, the peer might
            // have dropped it (TCP queue full during a flood). Re-
            // send. Not on the first-packet hot path; `try_tx`
            // handles the 10-second restart.
            return false;
        }

        // C `:691-694`: `if(ethertype == 0 && outstate) PKT_PROBE`.
        // The MTU-probe path (zero-ethertype is the probe marker).
        // (PMTU probes go via `try_tx`/`send_udp_probe`, not here.)

        // C `:702`: `if(origpkt->len < offset) return`. Only matters
        // for Router (Switch offset=0 always passes).
        if data.len() < offset {
            return false;
        }

        // C `:708-718`: `if(n->outcompression != COMPRESS_NONE) {
        // len = compress_packet(...); if(len && len < origlen) {
        // origpkt = &outpkt; type |= PKT_COMPRESSED; } }`. Only set
        // the bit if compression actually HELPED. The peer asked for
        // this level in their ANS_KEY (`tunnel.outcompression`).
        //
        // PERF(chunk-10): one alloc per forwarded packet when the
        // peer asked for compression. The C uses a stack `vpn_
        // packet_t outpkt`. Measure with iperf3 before optimizing.
        let payload = &data[offset..];
        let level = compress::Level::from_wire(tunnel.outcompression);
        let mut record_type = base_type;
        let compressed;
        let body: &[u8] = if level == compress::Level::None {
            payload
        } else if let Some(c) = self.compressor.compress(payload, level) {
            if c.len() < payload.len() {
                record_type |= PKT_COMPRESSED;
                compressed = c;
                &compressed
            } else {
                // C `:714`: `else if(len < origlen) ... else: fall
                // back to raw`. Compression didn't help. The C
                // doesn't log; we don't either.
                payload
            }
        } else {
            // C `:712-713`: `if(!len) logger(..."Error while
            // compressing"...)`. LZO stub or backend error.
            log::debug!(target: "tincd::net",
                        "Error while compressing packet to {to_name}");
            payload
        };

        // C `:725` PACKET 17 gate already handled above (BEFORE
        // validkey + compression — STRICTER-than-C, see C-IS-WRONG
        // #11). Fall-through here is the SPTPS-UDP path.

        // C `:728`: `sptps_send_record(&n->sptps, type, DATA +
        // offset, len - offset)`.
        let Some(sptps) = tunnel.sptps.as_deref_mut() else {
            // `validkey` is true but `sptps` is `None`? Shouldn't
            // happen (the bit is set BY `HandshakeDone` which only
            // fires after `Sptps::start`). Defensive: log + drop.
            log::warn!(target: "tincd::net",
                       "validkey set but no SPTPS for {to_name}?");
            return false;
        };

        // ALWAYS encrypt into the daemon scratch with 12 bytes of
        // headroom. The 12 bytes are the C `DEFAULT_PACKET_OFFSET`
        // for `[dst_id6‖src_id6]`; what happens to the result depends
        // on `send_sptps_data_relay`'s go-TCP/go-UDP decision below.
        // Either way: zero per-packet allocs in SPTPS, zero in this
        // function. Previous shape: `send_record` alloc'd `Vec<
        // Output>` + the wire `Vec`, then `dispatch_tunnel_outputs`
        // matched on the variant, then `send_sptps_data_relay`
        // alloc'd ANOTHER Vec to prepend the 12-byte header. Three
        // allocs + one body memmove; see `seal_data_into` doc.
        if let Err(e) = sptps.seal_data_into(record_type, body, &mut self.tx_scratch, 12) {
            // `InvalidState` if `outcipher` is None. Shouldn't
            // happen: `validkey` was checked above. Also fires if
            // SPTPS isn't datagram-framed — per-tunnel SPTPS always
            // is (`Sptps::start` with `Framing::Datagram` in
            // `protocol_key.rs`).
            log::warn!(target: "tincd::net",
                       "seal_data_into for {to_name}: {e:?}");
            return false;
        }
        self.send_sptps_data_relay(to_nid, to_name, self.myself, record_type, None)
    }

    /// `receive_sptps_record` (`net_packet.c:1056-1152`) +
    /// `send_sptps_data` (`:965-1054`) callback bridge.
    ///
    /// The C registers TWO callbacks with `sptps_start`: `receive_
    /// sptps_record` (for `Output::Record`/`HandshakeDone`) and
    /// `send_sptps_data` (for `Output::Wire`). Our SPTPS returns a
    /// `Vec<Output>`; this function IS both callbacks.
    ///
    /// Returns the io_set signal (TCP-tunneled handshake records
    /// queue to a meta-conn outbuf).
    pub(super) fn dispatch_tunnel_outputs(
        &mut self,
        peer: NodeId,
        peer_name: &str,
        outs: Vec<tinc_sptps::Output>,
    ) -> bool {
        use tinc_sptps::Output;
        let mut nw = false;
        for o in outs {
            match o {
                Output::Wire { record_type, bytes } => {
                    // `send_sptps_data` (`net_packet.c:965-1054`).
                    // `record_type == REC_HANDSHAKE` (128) goes via
                    // the meta connection (ANS_KEY); everything
                    // else goes UDP.
                    nw |= self.send_sptps_data(peer, peer_name, record_type, &bytes);
                }
                Output::HandshakeDone => {
                    // C `receive_sptps_record:1059-1065`: `if(type
                    // == SPTPS_HANDSHAKE) { validkey = true; waiting
                    // forkey = false; "SPTPS key exchange with %s
                    // successful" }`. The per-tunnel handshake just
                    // completed.
                    let tunnel = self.tunnels.entry(peer).or_default();
                    if !tunnel.status.validkey {
                        tunnel.status.validkey = true;
                        tunnel.status.waitingforkey = false;
                        log::info!(target: "tincd::net",
                                   "SPTPS key exchange with {peer_name} successful");
                    }
                }
                Output::Record { record_type, bytes } => {
                    // `receive_sptps_record` data branch
                    // (`:1071-1152`). One decrypted packet.
                    nw |= self.receive_sptps_record(peer, peer_name, record_type, &bytes);
                }
            }
        }
        nw
    }

    /// `receive_sptps_record` data branch (`net_packet.c:1071-1152`).
    /// One decrypted IP packet from a peer — re-synthesize the
    /// ethernet header and route it.
    pub(super) fn receive_sptps_record(
        &mut self,
        peer: NodeId,
        peer_name: &str,
        record_type: u8,
        body: &[u8],
    ) -> bool {
        // C `:1068-1070`: `if(len > MTU) return false`. Oversize.
        if body.len() > usize::from(crate::tunnel::MTU) {
            log::error!(target: "tincd::net",
                        "Packet from {peer_name} larger than MTU ({} > {})",
                        body.len(), crate::tunnel::MTU);
            return false;
        }

        // C `:1078-1092`: `if(type == PKT_PROBE)`. PMTU probe.
        // The probe body is `[type_byte][len_be:2?][padding]`.
        // type=0: request → echo back. type=1/2: reply → feed
        // `pmtu.on_probe_reply`. The `udppacket` gate (`:1079-
        // 1082`): probes only make sense over UDP (they ARE the
        // PMTU discovery mechanism); a TCP-tunneled probe is a
        // peer bug.
        if record_type == PKT_PROBE {
            let udppacket = self.tunnels.get(&peer).is_some_and(|t| t.status.udppacket);
            if !udppacket {
                log::error!(target: "tincd::net",
                            "Got SPTPS PROBE from {peer_name} via TCP");
                return false;
            }
            // C `:1088-1090`: `if(inpkt.len > maxrecentlen)
            // maxrecentlen = inpkt.len`. The gratuitous-reply
            // keepalive (`try_udp:1211-1222`) uses this length.
            // The PROBE body length IS the wire-level probe size
            // (the SPTPS overhead was already stripped).
            #[allow(clippy::cast_possible_truncation)] // body ≤ MTU
            let body_len = body.len() as u16;
            if let Some(p) = self.tunnels.get_mut(&peer).and_then(|t| t.pmtu.as_mut()) {
                if body_len > p.maxrecentlen {
                    p.maxrecentlen = body_len;
                }
            }
            // C `:1091`: `udp_probe_h(from, &inpkt, len)`.
            return self.udp_probe_h(peer, peer_name, body);
        }
        // C `:1094-1097`: `if(type & ~(PKT_COMPRESSED | PKT_MAC))`.
        // Unknown type bits.
        if record_type & !(PKT_COMPRESSED | PKT_MAC) != 0 {
            log::error!(target: "tincd::net",
                        "Unexpected SPTPS record type {record_type} from {peer_name}");
            return false;
        }
        // C `:1101-1105`: cross-mode warnings.
        //   `routing_mode != RMODE_ROUTER && !(type & PKT_MAC)` →
        //     ERROR (we're switch, peer is router; peer stripped
        //     the eth header, we can't route_mac without it).
        //   `routing_mode == RMODE_ROUTER && (type & PKT_MAC)` →
        //     WARN (peer is switch, we're router; we'll re-synth
        //     the eth header anyway. Lenient — matches C.)
        let has_mac = record_type & PKT_MAC != 0;
        match (self.settings.routing_mode, has_mac) {
            (RoutingMode::Switch | RoutingMode::Hub, false) => {
                log::error!(target: "tincd::net",
                    "Received packet from {peer_name} without MAC header \
                     (maybe Mode is not set correctly)");
                return false;
            }
            (RoutingMode::Router, true) => {
                log::warn!(target: "tincd::net",
                    "Received packet from {peer_name} with MAC header \
                     (maybe Mode is not set correctly)");
                // Continue — lenient. Discard their eth header,
                // re-synth from IP version nibble.
            }
            _ => {}
        }

        // C `:1108`: `int offset = (type & PKT_MAC) ? 0 : 14`.
        // TYPE-driven, not mode-driven: a switch-mode node receiving
        // from a misconfigured router-mode peer (warning case above)
        // still parses correctly using offset=14.
        let offset: usize = if has_mac { 0 } else { 14 };
        // C `:1109-1121`: `if(type & PKT_COMPRESSED) { ulen =
        // uncompress_packet(..., from->incompression); if(!ulen)
        // return false; }`. Decompress at the level WE asked for
        // (`tunnel.incompression` was copied from `settings.
        // compression` when we sent ANS_KEY).
        let decompressed;
        let body: &[u8] = if record_type & PKT_COMPRESSED != 0 {
            let incomp = self.tunnels.get(&peer).map_or(0, |t| t.incompression);
            let level = compress::Level::from_wire(incomp);
            if let Some(d) = self.compressor.decompress(body, level, MTU as usize) {
                decompressed = d;
                &decompressed
            } else {
                // C `:1113-1115`: `if(!ulen) return false`.
                // Corrupt stream OR LZO stub.
                log::warn!(target: "tincd::net",
                           "Error while decompressing packet from {peer_name}");
                return false;
            }
        } else {
            body
        };

        // C `:1123`: `memcpy(DATA + offset, data, len)`. C `:1128-
        // 1144`: synthesize the ethertype from the IP version nibble
        // — ROUTER ONLY (Switch: body IS the full eth frame).
        let mut frame: Vec<u8>;
        if offset == 0 {
            // Switch: body is already a full eth frame. Just clone
            // (we need ownership for `route_packet(&mut frame)`).
            frame = body.to_vec();
        } else {
            // Router: re-prepend the eth header. Zero MACs (C
            // `:1128` doesn't touch them — they're already zero
            // from `vpn_packet_t` zero-init).
            if body.is_empty() {
                return false; // need byte 0 for the version nibble
            }
            let ethertype: u16 = match body[0] >> 4 {
                4 => crate::packet::ETH_P_IP,
                6 => 0x86DD, // ETH_P_IPV6
                v => {
                    // C `:1141-1144`: `"Unknown IP version %d"`.
                    log::debug!(target: "tincd::net",
                                "Unknown IP version {v} in packet from {peer_name}");
                    return false;
                }
            };
            frame = vec![0u8; offset + body.len()];
            frame[12..14].copy_from_slice(&ethertype.to_be_bytes());
            frame[offset..].copy_from_slice(body);
        }

        // C `:1148-1150`: `if(udppacket && len > from->maxrecentlen)
        // from->maxrecentlen = len`. The largest data record we've
        // received via UDP recently. `try_udp:1213-1221` uses this
        // for the gratuitous probe-reply size.
        #[allow(clippy::cast_possible_truncation)] // frame.len() ≤ MTU
        let frame_len = frame.len() as u16;
        if let Some(t) = self.tunnels.get_mut(&peer) {
            if t.status.udppacket {
                if let Some(p) = t.pmtu.as_mut() {
                    if frame_len > p.maxrecentlen {
                        p.maxrecentlen = frame_len;
                    }
                }
            }
        }

        // C `:1152`: `receive_packet(from, &inpkt)` → (`:397-405`)
        // `n->in_packets++; n->in_bytes += len; route(n, packet)`.
        let len = frame.len() as u64;
        let tunnel = self.tunnels.entry(peer).or_default();
        tunnel.in_packets += 1;
        tunnel.in_bytes += len;

        // route() → `Forward{to: myself}` (we're the endpoint) →
        // device.write. If route() says forward-to-someone-else,
        // we're a relay — `route_packet`'s Forward arm recurses
        // into `send_sptps_packet` for THEM (chunk-9b). The
        // `route.c:649` source-loop check (`if(subnet->owner ==
        // source) drop`) is in the Forward arm.
        self.route_packet(&mut frame, Some(peer))
    }

    /// `send_sptps_data` (`net_packet.c:965-1054`). The per-tunnel
    /// SPTPS "send_data" callback. Thin wrapper for the common case
    /// (`from = myself`); see [`send_sptps_data_relay`] for the full
    /// relay decision.
    pub(super) fn send_sptps_data(
        &mut self,
        to_nid: NodeId,
        to_name: &str,
        record_type: u8,
        ct: &[u8],
    ) -> bool {
        // C `send_sptps_data_myself` (`net_packet.c:99-101`):
        // `send_sptps_data(to, myself, type, data, len)`.
        self.send_sptps_data_relay(to_nid, to_name, self.myself, record_type, Some(ct))
    }

    /// `send_sptps_data` (`net_packet.c:965-1054`). The relay
    /// decision: pick TCP vs UDP, pick `via` vs `nexthop`, build
    /// the `[dst_id6][src_id6]` prefix.
    ///
    /// ## The `:967-974` decision tree (read this 3 times)
    ///
    /// **`via` vs `nexthop`** (the relay choice, `:967`):
    /// - `via` is the "static relay" — the last DIRECT node on the
    ///   SSSP path. Set by `IndirectData = yes` edges. If `via !=
    ///   myself`, the destination is behind an indirect edge; UDP
    ///   to it directly won't work.
    /// - `nexthop` is the FIRST hop — the immediate neighbor whose
    ///   meta-connection routes toward `to`. Always reachable via
    ///   TCP (it's a direct neighbor).
    /// - We PREFER `via` (skip the in-between hops, go straight to
    ///   the last direct node) BUT only if the packet FITS through
    ///   `via`'s discovered MTU. Otherwise fall back to `nexthop`
    ///   (hop-by-hop, each hop's MTU is probably fine).
    /// - PROBE packets ALWAYS prefer `via`: they're tiny, and the
    ///   whole point is to discover `via`'s MTU.
    ///
    /// **TCP if any of** (`:974`):
    /// - `type == SPTPS_HANDSHAKE`: use ANS_KEY (`:992-994` —
    ///   relays shouldn't switch to UDP for these; also lets us
    ///   learn reflexive UDP addr).
    /// - `tcponly`: config knob.
    /// - `!direct && !relay_supported`: relay node is too old
    ///   (proto minor < 4, doesn't understand the 12-byte prefix).
    /// - `origlen > relay->minmtu` (and not a PROBE): packet won't
    ///   fit through the relay's UDP path. TCP fragments fine.
    ///
    /// `from_nid`: the ORIGINAL source. Usually `self.myself` (we
    /// generated this packet). For relay forwarding (`on_udp_recv`
    /// when `dst != myself`), it's the original sender's NodeId —
    /// the wire prefix carries THEIR src_id6, not ours.
    #[allow(clippy::too_many_lines)] // The :967-974 decision tree
    // is one cohesive block. Splitting it makes the conditions hard
    // to cross-reference against the C.
    pub(super) fn send_sptps_data_relay(
        &mut self,
        to_nid: NodeId,
        to_name: &str,
        from_nid: NodeId,
        record_type: u8,
        ct: Option<&[u8]>,
    ) -> bool {
        // `ct` is `None` on the hot path: the SPTPS frame is at
        // `self.tx_scratch[12..]`, written there by `seal_data_into`
        // with 12 bytes of headroom for us to fill below. `Some(ct)`
        // is the relay/handshake/probe path: we got bytes from
        // somewhere else (UDP recv for relay forwarding, or the
        // alloc-y `Vec<Output>` path for handshake records).
        //
        // C `:966`: `origlen = len - SPTPS_DATAGRAM_OVERHEAD`.
        // The PLAINTEXT body length (the relay's MTU is measured
        // at that layer; the SPTPS overhead is constant).
        let ct_len = ct.map_or_else(|| self.tx_scratch.len() - 12, <[u8]>::len);
        let origlen = ct_len.saturating_sub(tinc_sptps::DATAGRAM_OVERHEAD);

        // ─── :967: relay = via or nexthop ────────────────────────
        // Read `last_routes[to]`. If `to` is unreachable (no
        // route), the C would deref NULL; we drop.
        let Some(route) = self
            .last_routes
            .get(to_nid.0 as usize)
            .and_then(Option::as_ref)
        else {
            log::debug!(target: "tincd::net",
                        "No route to {to_name}; dropping");
            return false;
        };
        let via_nid = route.via;
        let nexthop_nid = route.nexthop;

        // `to->via != myself`: the destination is behind an
        // indirect edge. AND: PROBE always prefers via (probes
        // are tiny + measure via's MTU); data prefers via only if
        // it FITS. `via->minmtu` reads the relay's discovered MTU
        // (0 until discovery runs — so until then, all data goes
        // hop-by-hop via nexthop, which is correct: we don't know
        // via's MTU yet).
        let via_minmtu = self.tunnels.get(&via_nid).map_or(0, TunnelState::minmtu);
        let relay_nid = if via_nid != self.myself
            && (record_type == PKT_PROBE || origlen <= usize::from(via_minmtu))
        {
            via_nid
        } else {
            nexthop_nid
        };

        // ─── :968: direct = from == myself && to == relay ───────
        // "Direct": we're the origin AND the chosen relay IS the
        // destination (no intermediate). The wire prefix uses
        // nullid for dst in this case (`:1013-1015`): the recipient
        // knows it's not a relay.
        let from_is_myself = from_nid == self.myself;
        let direct = from_is_myself && to_nid == relay_nid;

        // ─── :969: relay_supported = (relay->options >> 24) >= 4 ─
        // Proto minor 4+ understands the 12-byte ID prefix.
        let relay_options = self
            .last_routes
            .get(relay_nid.0 as usize)
            .and_then(Option::as_ref)
            .map_or(0, |r| r.options);
        let relay_supported = (relay_options >> 24) >= 4;

        // ─── :970: tcponly ──────────────────────────────────────
        // `(myself->options | relay->options) & OPTION_TCPONLY`.
        // EITHER side requesting tcponly forces TCP.
        let tcponly = (self.myself_options | relay_options) & crate::proto::OPTION_TCPONLY != 0;

        // ─── :974: the go-TCP decision ──────────────────────────
        let relay_minmtu = self.tunnels.get(&relay_nid).map_or(0, TunnelState::minmtu);
        // The `too_big` gate only meaningful once discovery has
        // run: `minmtu == 0` means "unknown", not "zero". The C
        // handles this differently — `send_sptps_packet:724-726`
        // short-circuits to `send_tcppacket` (PACKET type 17, raw
        // VPN bytes over the meta-conn) for direct neighbors with
        // `len > minmtu` BEFORE reaching `send_sptps_data`. We
        // don't have `send_tcppacket` (chunk-9c); go UDP
        // optimistically until discovery raises `minmtu`. EMSGSIZE
        // on the first big packet bootstraps discovery.
        let too_big =
            record_type != PKT_PROBE && relay_minmtu > 0 && origlen > usize::from(relay_minmtu);
        let go_tcp = record_type == tinc_sptps::REC_HANDSHAKE
            || tcponly
            || (!direct && !relay_supported)
            || too_big;

        if go_tcp {
            // ─── :975-996: TCP encapsulation ────────────────────
            // Two sub-paths: SPTPS_PACKET (raw bytes via the
            // length-prefixed binary mechanism, `:975-986`) for
            // proto minor ≥7 nexthops; ANS_KEY/REQ_KEY (b64'd via
            // the text protocol) otherwise.

            // TCP fallback: cold path. Materialize `ct` once from
            // either the caller's slice or `tx_scratch[12..]`. The
            // `match` (not `unwrap_or`) because `unwrap_or` is
            // eager: `&self.tx_scratch[12..]` would slice-panic on
            // an empty scratch even when `ct` is `Some`.
            let ct = match ct {
                Some(s) => s,
                None => &self.tx_scratch[12..],
            };

            let Some(conn_id) = self.conn_for_nexthop(to_nid) else {
                log::warn!(target: "tincd::net",
                           "No meta connection toward {to_name}");
                return false;
            };
            let Some(conn) = self.conns.get_mut(conn_id) else {
                return false;
            };

            // ─── :975-986: SPTPS_PACKET (binary path) ───────────
            // `type != SPTPS_HANDSHAKE && (to->nexthop->connection
            // ->options >> 24) >= 7`. The handshake check: ANS_KEY
            // also propagates the reflexive UDP address (`:993`
            // doc); binary doesn't. Handshakes stay on b64. The
            // minor check: SPTPS_PACKET introduced in proto minor 7
            // (commit 9e3ca7d, 2013). Older nexthops don't parse
            // `21 LEN`; b64 is the universal fallback.
            //
            // `conn.options` is `c->options` post-`ack_h`; ORs the
            // peer's `PROT_MINOR << 24` from the wire ACK
            // (`protocol_auth.c:1001`). C uses `to->nexthop->
            // connection->options` — our `conn` IS that (we looked
            // it up via `conn_for_nexthop`).
            //
            // The OLD STUB COMMENT WAS WRONG ("the binary blob
            // would need to go through sptps_send_record"). C
            // `send_meta_raw` (`meta.c:99-112`) is `buffer_add(
            // &c->outbuf, ...)` directly — NO SPTPS framing. The
            // blob is ALREADY per-tunnel-SPTPS-encrypted; double-
            // encrypting would be wasteful. Our `conn.send_raw()`
            // is exactly that.
            if record_type != tinc_sptps::REC_HANDSHAKE && (conn.options >> 24) >= 7 {
                // C `protocol_misc.c:125-135`. Random Early Drop
                // FIRST. `maxoutbufsize` (`net_setup.c:1255-1257`,
                // default `10 * MTU`).
                if crate::tcp_tunnel::random_early_drop(
                    conn.outbuf.live_len(),
                    self.settings.maxoutbufsize,
                    &mut OsRng,
                ) {
                    // C `:126 return true` — silently drop, fake
                    // success.
                    return true;
                }
                // Same id6 lookups as the UDP path below. C `:976-
                // 984`: `memcpy(packet, &to->id, 6); memcpy(packet+
                // 6, &from->id, 6); memcpy(packet+12, data, len)`.
                // The `direct ⇒ nullid` for dst is UDP-only (`:1013
                // -1015`); the binary TCP path always uses the real
                // dst id (the C `:976` is unconditional).
                let src_id = self.id6_table.id_of(from_nid).unwrap_or(NodeId6::NULL);
                let dst_id = self.id6_table.id_of(to_nid).unwrap_or(NodeId6::NULL);
                let frame = crate::tcp_tunnel::build_frame(dst_id, src_id, ct);
                // `:129`: `send_request("%d %lu", SPTPS_PACKET,
                // len)`. `send` goes via SPTPS (encrypted record).
                let mut nw = conn.send(format_args!(
                    "{} {}",
                    Request::SptpsPacket as u8,
                    frame.len()
                ));
                // `:133`: `send_meta_raw(packet, len)`. RAW to
                // outbuf, no SPTPS.
                nw |= conn.send_raw(&frame);
                return nw;
            }

            let b64 = tinc_crypto::b64::encode(ct);
            let from_name = if from_is_myself {
                self.name.clone()
            } else {
                self.graph
                    .node(from_nid)
                    .map_or_else(|| "<gone>".to_owned(), |n| n.name.clone())
            };

            if record_type == tinc_sptps::REC_HANDSHAKE {
                // C `:995-996`: ANS_KEY. `to->incompression =
                // myself->incompression` only when from==myself
                // (relayed handshakes don't touch our state).
                let my_compression = self.settings.compression;
                if from_is_myself {
                    self.tunnels.entry(to_nid).or_default().incompression = my_compression;
                }
                // C `net_packet.c:996`: `"%d %s %s %s -1 -1 -1 %d"`.
                // The `-1 -1 -1` are LITERAL string, not `%d` args —
                // cipher/digest/maclen placeholders for SPTPS mode
                // (never read by `ans_key_h` when SPTPS is on). We
                // emit byte-identical wire so Phase-6 pcap-compare
                // doesn't flag a spurious diff. The `Tok::lu` parser
                // was loosened to accept `-1` (glibc strtoul "negate
                // as unsigned" → `u64::MAX`); see `tok.rs::lu`.
                return conn.send(format_args!(
                    "{} {} {} {} -1 -1 -1 {}",
                    Request::AnsKey,
                    from_name,
                    to_name,
                    b64,
                    my_compression,
                ));
            }
            // C `:998`: `"%d %s %s %d %s"` REQ_KEY with reqno=
            // SPTPS_PACKET. The b64'd ciphertext is the payload.
            // The receiver's `req_key_ext_h` case SPTPS_PACKET
            // (`protocol_key.c:149-188`) decodes and feeds it to
            // `from->sptps` (or relays).
            return conn.send(format_args!(
                "{} {} {} {} {}",
                Request::ReqKey,
                from_name,
                to_name,
                Request::SptpsPacket as u8,
                b64,
            ));
        }

        // ─── :1001-1054: UDP transport ───────────────────────────
        // C `:1003-1006`: overhead = relay_supported ? 12 : 0.
        // We always prefix (our peers are ≥1.1). C `:1012-1020`:
        // direct ⇒ dst=nullid; else dst=to->id.
        let src_id = self.id6_table.id_of(from_nid).unwrap_or(NodeId6::NULL);
        let dst_id = if direct {
            NodeId6::NULL
        } else {
            self.id6_table.id_of(to_nid).unwrap_or(NodeId6::NULL)
        };
        // Hot path: SPTPS bytes are at `tx_scratch[12..]` and we
        // overwrite the 12-byte headroom in-place. Zero allocs,
        // zero body copies. The C author's `net_packet.c:1027`
        // pre-padding TODO; they `alloca + memcpy` instead.
        //
        // Relay/handshake path (`Some(ct)`): build into the same
        // scratch. One body memmove (the `extend_from_slice`); the
        // alloc is amortized to zero (scratch capacity persists).
        // The relay path is colder (≤1 hop in a flat mesh) and the
        // handshake path is once-per-tunnel.
        if let Some(ct) = ct {
            self.tx_scratch.clear();
            self.tx_scratch.extend_from_slice(dst_id.as_bytes());
            self.tx_scratch.extend_from_slice(src_id.as_bytes());
            self.tx_scratch.extend_from_slice(ct);
        } else {
            self.tx_scratch[0..6].copy_from_slice(dst_id.as_bytes());
            self.tx_scratch[6..12].copy_from_slice(src_id.as_bytes());
        }

        // C `:1031-1040`: `choose_udp_address(relay, ...)`. NOT
        // `to`: we send to the RELAY, who forwards to `to`. The
        // `send_locally` override (`:1034-1036`) and the 1-in-3
        // cycle (`:758-762`) are folded into `choose_udp_address`.
        //
        // Fast path: `udp_addr_cached` set when `udp_confirmed`
        // flips (UDP recv path). Once confirmed, the answer is
        // deterministic: `(tunnel.udp_addr, adapt_socket(...))`.
        // The full `choose_udp_address` allocs a `Vec<SocketAddr>`
        // of listener addrs and scans it — every packet. That was
        // visible in the profile: `send_sptps_data_relay` 2.18%
        // self-time, mostly in here.
        let cached = self
            .tunnels
            .get(&relay_nid)
            .and_then(|t| t.udp_addr_cached.clone());
        // Cold-path storage when no cache hit. Declared here to
        // outlive the `&SockAddr` borrow.
        let cold_sockaddr;
        let (sockaddr, sock) = if let Some((sa, sock)) = &cached {
            (sa, *sock)
        } else {
            // Cold path: pre-confirmation discovery, send_locally
            // override, edge exploration. `relay_name` is only
            // needed by `choose_udp_address`'s `nodes.get(name)`
            // edge-addr lookup and the debug log; alloc it lazily
            // here, NOT per-packet. Previous code did `to_owned()`
            // unconditionally — a String alloc per packet, never
            // read once `udp_confirmed`.
            let relay_name = self
                .graph
                .node(relay_nid)
                .map_or("<gone>", |n| n.name.as_str())
                .to_owned();
            let Some((addr, sock)) = self.choose_udp_address(relay_nid, &relay_name) else {
                log::debug!(target: "tincd::net",
                            "No UDP address known for relay {relay_name}; dropping");
                return false;
            };
            cold_sockaddr = socket2::SockAddr::from(addr);
            (&cold_sockaddr, sock)
        };

        // C `:1044`: `sendto(listen_socket[sock].udp.fd, ...)`.
        // `adapt_socket` (done inside `choose_udp_address`) picked
        // the listener whose addr family matches `addr`.
        if let Some(l) = self.listeners.get(usize::from(sock)) {
            if let Err(e) = l.udp.send_to(&self.tx_scratch, sockaddr) {
                if e.kind() == io::ErrorKind::WouldBlock {
                    // Drop. UDP is unreliable anyway.
                } else if e.raw_os_error() == Some(libc::EMSGSIZE) {
                    // C `:1046-1048`: `if(sockmsgsize(errno))
                    // reduce_mtu(relay, origlen - 1)`. EMSGSIZE
                    // means the LOCAL kernel rejected the datagram
                    // (interface MTU). Shrink `relay`'s maxmtu.
                    // Don't log: this IS the discovery mechanism.
                    #[allow(clippy::cast_possible_truncation)]
                    // origlen ≤ MTU
                    let at_len = origlen as u16;
                    if let Some(p) = self
                        .tunnels
                        .get_mut(&relay_nid)
                        .and_then(|t| t.pmtu.as_mut())
                    {
                        // `relay_name` only on the EMSGSIZE path
                        // (rare — PMTU discovery edge). Format
                        // lazily; the hot path never reaches here.
                        let relay_name = self
                            .graph
                            .node(relay_nid)
                            .map_or("<gone>", |n| n.name.as_str());
                        for a in p.on_emsgsize(at_len) {
                            Self::log_pmtu_action(relay_name, &a);
                        }
                    }
                } else {
                    let relay_name = self
                        .graph
                        .node(relay_nid)
                        .map_or("<gone>", |n| n.name.as_str());
                    log::warn!(target: "tincd::net",
                               "Error sending UDP SPTPS packet to \
                                {relay_name}: {e}");
                }
            }
        }
        false // UDP send doesn't touch any meta-conn outbuf
    }

    // ───────────────────────────────────────────────────────────────
    // ARP / NDP neighbor reply synthesis (route.c:793-1035)

    /// `route_arp` (`route.c:956-1023`). Called for `ETH_P_ARP`
    /// frames from the TUN. Parse, lookup, synthesise reply, write
    /// back. The kernel caches the fake MAC, traffic flows.
    pub(super) fn handle_arp(&mut self, data: &[u8]) -> bool {
        // `route.c:960,977-984`: parse + validate.
        let Some(target) = neighbor::parse_arp_req(data) else {
            // Not a valid Ethernet/IP ARP who-has. C `:984`: `else
            // { logger(DEBUG_TRAFFIC, ...); return; }`.
            log::debug!(target: "tincd::net",
                        "route: dropping ARP packet (not a valid request)");
            return false;
        };
        // `route.c:988-996`: `subnet = lookup_subnet_ipv4(dest);
        // if(!subnet) return`. Do WE route to this IP? The C uses
        // `lookup_subnet_ipv4` directly (no reachability check —
        // ARP just answers "does someone own this", not "are they
        // up"). We pass `|_| true`.
        let Some((_, owner)) = self.subnets.lookup_ipv4(&target, |_| true) else {
            log::debug!(target: "tincd::net",
                        "route: ARP for unknown {target}");
            return false;
        };
        // `route.c:999`: `if(subnet->owner == myself) return`.
        // "Silently ignore ARPs for our own subnets" — the kernel
        // already knows its own address; an ARP for it means
        // someone misconfigured. Don't reply (a reply would create
        // an arp-cache entry pointing at the TUN, which is wrong).
        if owner == self.name {
            return false;
        }
        // `route.c:1011-1022`: build + send.
        let mut reply = neighbor::build_arp_reply(data);
        log::debug!(target: "tincd::net",
                    "route: ARP reply for {target} (owner {owner})");
        if let Err(e) = self.device.write(&mut reply) {
            log::debug!(target: "tincd::net",
                        "Error writing ARP reply to device: {e}");
        }
        false
    }

    /// `route_neighborsol` (`route.c:793-954`). Same shape as ARP
    /// for v6. `route()` already returned `NeighborSolicit` so the
    /// ICMPv6-type check has passed; the parser re-validates +
    /// verifies the checksum.
    pub(super) fn handle_ndp(&mut self, data: &[u8]) {
        let Some(target) = neighbor::parse_ndp_solicit(data) else {
            log::debug!(target: "tincd::net",
                        "route: dropping NDP solicit (parse/checksum failed)");
            return;
        };
        // `route.c:865-879`: subnet lookup. Same `|_| true` as ARP.
        let Some((_, owner)) = self.subnets.lookup_ipv6(&target, |_| true) else {
            log::debug!(target: "tincd::net",
                        "route: NDP solicit for unknown {target}");
            return;
        };
        // `route.c:883`: `if(subnet->owner == myself) return`.
        if owner == self.name {
            return;
        }
        // `route.c:890-948`: build + send.
        let Some(mut reply) = neighbor::build_ndp_advert(data) else {
            return;
        };
        log::debug!(target: "tincd::net",
                    "route: NDP advert for {target} (owner {owner})");
        if let Err(e) = self.device.write(&mut reply) {
            log::debug!(target: "tincd::net",
                        "Error writing NDP advert to device: {e}");
        }
    }

    /// Shared tail for the `Unreachable` arm and the `decrement_ttl`
    /// `SendIcmp` outcome. v4/v6 dispatch on **ethertype**, not
    /// `icmp_type`: `ICMP_DEST_UNREACH=3` collides with
    /// `ICMP6_TIME_EXCEEDED=3` (bug audit `deef1268`). The previous
    /// type-based dispatch was structurally unsound — currently
    /// dark (no v4 type-3 caller via this path) but the next caller
    /// to pass `(ICMP_DEST_UNREACH, code)` for a v4 frame would have
    /// gotten ICMPv6. `data.len() >= 14` holds: every caller is
    /// post-route() (which gates on `TooShort`) or post-decrement_ttl
    /// (which gates on `len < ETHER_SIZE+IP_SIZE`).
    pub(super) fn write_icmp_to_device(&mut self, data: &[u8], icmp_type: u8, icmp_code: u8) {
        let now_sec = self.timers.now().duration_since(self.started_at).as_secs();
        if self.icmp_ratelimit.should_drop(now_sec, 3) {
            return;
        }
        let ethertype = u16::from_be_bytes([data[12], data[13]]);
        let reply = if ethertype == 0x86DD {
            // ETH_P_IPV6
            icmp::build_v6_unreachable(data, icmp_type, icmp_code, None)
        } else {
            icmp::build_v4_unreachable(data, icmp_type, icmp_code, None)
        };
        if let Some(reply) = reply {
            log::debug!(target: "tincd::net",
                        "route: TTL exceeded, sending ICMP type={icmp_type} \
                         code={icmp_code} ({} bytes)", reply.len());
            self.write_icmp_reply(reply);
        }
    }

    /// `route.c:690` v4 FRAG_NEEDED specialization. Passes `frag_mtu`
    /// through to `build_v4_unreachable` so `icmp.icmp_nextmtu` gets
    /// the right value (`:174 icmp.icmp_nextmtu = htons(packet->len -
    /// ether_size)`). Separate helper because [`write_icmp_to_device`]
    /// dispatches v4/v6 by type and always passes `None`.
    pub(super) fn write_icmp_frag_needed(&mut self, data: &[u8], frag_mtu: u16) {
        let now_sec = self.timers.now().duration_since(self.started_at).as_secs();
        if self.icmp_ratelimit.should_drop(now_sec, 3) {
            return;
        }
        if let Some(reply) = icmp::build_v4_unreachable(
            data,
            route::ICMP_DEST_UNREACH,
            route::ICMP_FRAG_NEEDED,
            Some(frag_mtu),
        ) {
            log::debug!(target: "tincd::net",
                        "route: FRAG_NEEDED, mtu={frag_mtu} ({} bytes)",
                        reply.len());
            self.write_icmp_reply(reply);
        }
    }

    /// `route.c:781` v6 PACKET_TOO_BIG specialization. Passes
    /// `pkt_too_big_mtu` through to `build_v6_unreachable` so
    /// `icmp6.icmp6_mtu` gets filled (`:278-280`).
    pub(super) fn write_icmp_pkt_too_big(&mut self, data: &[u8], mtu: u32) {
        let now_sec = self.timers.now().duration_since(self.started_at).as_secs();
        if self.icmp_ratelimit.should_drop(now_sec, 3) {
            return;
        }
        if let Some(reply) =
            icmp::build_v6_unreachable(data, route::ICMP6_PACKET_TOO_BIG, 0, Some(mtu))
        {
            log::debug!(target: "tincd::net",
                        "route: PACKET_TOO_BIG, mtu={mtu} ({} bytes)",
                        reply.len());
            self.write_icmp_reply(reply);
        }
    }

    /// `send_packet(source=myself, ...)` short-circuit (`net_
    /// packet.c:1556-1568`): write back to the TUN.
    pub(super) fn write_icmp_reply(&mut self, mut reply: Vec<u8>) {
        if let Err(e) = self.device.write(&mut reply) {
            log::debug!(target: "tincd::net",
                        "Error writing ICMP to device: {e}");
        }
    }

    // ───────────────────────────────────────────────────────────────
    // PMTU probe handling + try_tx chain
}

/// Rebind a `RouteResult<'a>` to a local lifetime. The `Forward`
/// arm's `&str` borrows the `SubnetTree`/`mac_table`; we need to
/// drop that borrow before calling `&mut self` methods. The caller
/// pre-clones the owner string into `owned_to`; this function picks
/// the right variant. Exhaustive match: any new `RouteResult`
/// variant trips a compile error here.
///
/// Why not make `RouteResult` own a `String`? Because `route()` /
/// `route_mac()` are pure functions called per-packet; the no-route
/// (`TooShort`/`Unreachable`/`Broadcast`) cases would alloc-then-
/// drop. The alloc is cheap but the API contract ("this fn is
/// pure") is cleaner with a borrow.
fn detach_route_result<'b>(r: &RouteResult<'_>, owned_to: Option<&'b str>) -> RouteResult<'b> {
    match *r {
        RouteResult::Forward { .. } => RouteResult::Forward {
            // owned_to.is_some() iff r was Forward; caller invariant.
            to: owned_to.expect("Forward without owned_to"),
        },
        RouteResult::Unreachable {
            icmp_type,
            icmp_code,
        } => RouteResult::Unreachable {
            icmp_type,
            icmp_code,
        },
        RouteResult::Unsupported { reason } => RouteResult::Unsupported { reason },
        RouteResult::NeighborSolicit => RouteResult::NeighborSolicit,
        RouteResult::Broadcast => RouteResult::Broadcast,
        RouteResult::TooShort { need, have } => RouteResult::TooShort { need, have },
    }
}
