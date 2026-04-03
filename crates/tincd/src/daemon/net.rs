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
    /// Loop drains ALL pending datagrams (edge-triggered epoll).
    /// STUB(chunk-11-perf): `recvmmsg` batching.
    pub(super) fn on_udp_recv(&mut self, i: u8) {
        // C `MAXSIZE` is `MTU + 4 + cipher overhead`. We use a
        // generous fixed buf; oversize packets truncate (MSG_TRUNC)
        // and we'd reject them anyway (the SPTPS decrypt fails).
        let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); 2048];
        loop {
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
                let mut nw = self.send_sptps_data_relay(to_nid, &to_name, from_nid, 0, ct);
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
            let tunnel = self.tunnels.entry(from_nid).or_default();
            if !tunnel.status.udp_confirmed {
                log::debug!(target: "tincd::net",
                            "UDP address of {from_name} confirmed: {peer_addr}");
                tunnel.status.udp_confirmed = true;
            }
            tunnel.udp_addr = Some(peer_addr);
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

            // C `:1930`: `route(myself, &packet)`.
            nw |= self.route_packet(&mut buf[..n]);
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
    /// Returns the io_set signal (true if a meta-conn outbuf went
    /// nonempty — `send_req_key` or the TCP-tunneled handshake).
    #[allow(clippy::too_many_lines)] // C `route()` + `send_packet`
    // are ~200 LOC together. The match arms are the dispatch table;
    // splitting them scatters the C line refs.
    pub(super) fn route_packet(&mut self, data: &mut [u8]) -> bool {
        // ─── ARP intercept (`route.c:1163`: `case ETH_P_ARP:
        // route_arp(source, packet)`). ARP isn't IP routing; handle
        // BEFORE `route()`. The C dispatch puts it in the same
        // ethertype switch but `route_arp` doesn't touch the subnet
        // tree the way `route_ipv4` does — it does its OWN lookup
        // (`route.c:988`). We do it here because `route()` only
        // returns `Unsupported{"arp"}` for ETH_P_ARP.
        if data.len() >= 14 && u16::from_be_bytes([data[12], data[13]]) == crate::packet::ETH_P_ARP
        {
            return self.handle_arp(data);
        }

        // The reachability oracle for `route()`. C `route.c:655`
        // reads `subnet->owner->status.reachable` directly (it's
        // all one big graph of pointers). We close over `node_ids`
        // + `graph` and look it up.
        let result = {
            let node_ids = &self.node_ids;
            let graph = &self.graph;
            route(data, &self.subnets, &self.name, |name| {
                node_ids
                    .get(name)
                    .and_then(|&nid| graph.node(nid))
                    .is_some_and(|n| n.reachable)
            })
        };

        match result {
            RouteResult::Forward { to } if to == self.name => {
                // C `send_packet:1556-1568`: `if(n == myself) {
                // devops.write(packet); return; }`. The packet is
                // for US (it came in over the wire and `route()`
                // matched one of our subnets). Write it to the TUN.
                // STUB(chunk-12-switch): `overwrite_mac` (`:1557-
                // 1562`) — TAP-mode source-MAC rewriting. RMODE_
                // ROUTER doesn't need it.
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
                if via_options & crate::proto::OPTION_CLAMP_MSS != 0 {
                    // `via->mtu`: read from `tunnels[to_nid]` (direct
                    // case). `MTU` if no tunnel yet (matches C's
                    // xzalloc → 0 → the C `< mtu` check fails →
                    // uses source->mtu — wait, C's `n->mtu` starts
                    // 0, but `route.c:396` is `via->mtu < mtu` so a
                    // 0 mtu would WIN. Our `TunnelState::default()`
                    // inits to `MTU` instead — see tunnel.rs:128.
                    // Either way: until PMTU runs, MSS clamps to the
                    // 1518 ceiling, which is a no-op for normal
                    // ethernet payloads).
                    let via_mtu = self.tunnels.get(&via_nid).map_or(MTU, TunnelState::mtu);
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
                // For chunk-9b: `route_packet` is called from BOTH
                // `on_device_read` (source=myself) AND `receive_
                // sptps_record` (source=peer). We don't carry the
                // source through; STUB the gate as always-on. The
                // config default is OFF so this is dark anyway.
                // Chunk-9c threads `source` through.
                if self.settings.decrement_ttl {
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
                // STUB(chunk-9b): `frag_mtu` for FRAG_NEEDED — needs
                // the relay path's `via->mtu`. `route()` only
                // returns NET_UNKNOWN/NET_UNREACH today; FRAG_NEEDED
                // is the `:685-696` block which needs `via`.
                let Some(reply) = icmp::build_v4_unreachable(data, icmp_type, icmp_code, None)
                else {
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
                // STUB(chunk-12-switch): `route.c:1042-1045` →
                // `route_broadcast` → `broadcast_packet`. Only
                // reachable from `route_mac` (RMODE_SWITCH); the
                // IP-layer dispatch above never produces this.
                log::debug!(target: "tincd::net",
                            "route: broadcast (RMODE_SWITCH stub, dropping)");
                false
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
        // C `:696-698`: RMODE_ROUTER strips the 14-byte ether hdr.
        // STUB(chunk-12-switch): RMODE_SWITCH (`type = PKT_MAC`,
        // no strip).
        const OFFSET: usize = 14;
        let tunnel = self.tunnels.entry(to_nid).or_default();

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

        if data.len() < OFFSET {
            return false; // C `:702`: `if(origpkt->len < offset) return`.
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
        let payload = &data[OFFSET..];
        let level = compress::Level::from_wire(tunnel.outcompression);
        let mut record_type = PKT_NORMAL;
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

        // STUB(chunk-11-perf): `if(n->connection && origpkt->len >
        // n->minmtu) send_tcppacket()` (`:724-726`). The TCP
        // fallback when the packet is too big for the discovered
        // MTU. We always go via SPTPS-UDP for now (`send_sptps_
        // data`'s `too_big` gate falls through to the b64-REQ_KEY
        // path which works; this is the OPTIMIZED binary encap).

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
        let outs = match sptps.send_record(record_type, body) {
            Ok(outs) => outs,
            Err(e) => {
                // `InvalidState` if `outcipher` is None. Shouldn't
                // happen: `validkey` was checked above.
                log::warn!(target: "tincd::net",
                           "sptps_send_record for {to_name}: {e:?}");
                return false;
            }
        };
        // The output is exactly one `Wire`. Dispatch via the same
        // bridge as the handshake outputs (it'll go UDP this time:
        // record_type=0 < REC_HANDSHAKE).
        self.dispatch_tunnel_outputs(to_nid, to_name, outs)
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
        // C `:1108`: `int offset = (type & PKT_MAC) ? 0 : 14`.
        // RMODE_ROUTER: peer stripped the ether header; we re-prepend.
        const OFFSET: usize = 14;
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
        // C `:1100-1105`: RMODE check vs PKT_MAC. We're RMODE_
        // ROUTER; PKT_MAC means the peer is in switch mode and
        // sent a full ethernet frame (no offset). We don't handle
        // that. STUB(chunk-12-switch): switch mode.
        if record_type & PKT_MAC != 0 {
            log::warn!(target: "tincd::net",
                       "Received packet from {peer_name} with MAC header \
                        (peer in switch mode?)");
            return false;
        }
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
        // 1144`: synthesize the ethertype from the IP version nibble.
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
        let mut frame = vec![0u8; OFFSET + body.len()];
        // MACs stay zero (`set_etherheader` in `tinc-device` does
        // the same; C `:1128` doesn't touch them — they're already
        // zero from the `vpn_packet_t` zero-init).
        frame[12..14].copy_from_slice(&ethertype.to_be_bytes());
        frame[OFFSET..].copy_from_slice(body);

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
        // into `send_sptps_packet` for THEM (chunk-9b).
        // DEFERRED(chunk-7-daemon): `route.c:648` source-loop check
        // (`if(subnet->owner == source) drop`). With 2 nodes and
        // /32 subnets, the destination subnet is never owned by
        // the sender. The check matters for overlapping subnets.
        self.route_packet(&mut frame)
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
        self.send_sptps_data_relay(to_nid, to_name, self.myself, record_type, ct)
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
        ct: &[u8],
    ) -> bool {
        // C `:966`: `origlen = len - SPTPS_DATAGRAM_OVERHEAD`.
        // The PLAINTEXT body length (the relay's MTU is measured
        // at that layer; the SPTPS overhead is constant).
        let origlen = ct.len().saturating_sub(tinc_sptps::DATAGRAM_OVERHEAD);

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
                // FIRST. STUB(chunk-12): the `maxoutbufsize` config
                // knob (C `net_setup.c:437`, default `10 * MTU`).
                // Pass usize::MAX for now — RED degenerates to
                // never-drop, which is the safe default until the
                // knob is wired.
                if crate::tcp_tunnel::random_early_drop(
                    conn.outbuf.live_len(),
                    usize::MAX,
                    &mut OsRng,
                ) {
                    // C `:126 return true` — silently drop, fake
                    // success. Unreachable with usize::MAX.
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
        let mut wire = Vec::with_capacity(12 + ct.len());
        wire.extend_from_slice(dst_id.as_bytes());
        wire.extend_from_slice(src_id.as_bytes());
        wire.extend_from_slice(ct);

        // C `:1031-1040`: `choose_udp_address(relay, ...)`. NOT
        // `to`: we send to the RELAY, who forwards to `to`. The
        // `send_locally` override (`:1034-1036`) and the 1-in-3
        // cycle (`:758-762`) are folded into `choose_udp_address`.
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

        // C `:1044`: `sendto(listen_socket[sock].udp.fd, ...)`.
        // `adapt_socket` (done inside `choose_udp_address`) picked
        // the listener whose addr family matches `addr`.
        log::debug!(target: "tincd::net",
                    "Sending {}-byte UDP packet to {to_name} via {relay_name} ({addr})",
                    wire.len());
        let sockaddr = socket2::SockAddr::from(addr);
        if let Some(l) = self.listeners.get(usize::from(sock)) {
            if let Err(e) = l.udp.send_to(&wire, &sockaddr) {
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
                        for a in p.on_emsgsize(at_len) {
                            Self::log_pmtu_action(&relay_name, &a);
                        }
                    }
                } else {
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
    /// `SendIcmp` outcome. v4/v6 dispatch on `icmp_type` (11=v4
    /// TIME_EXCEEDED, 3=v6 TIME_EXCEEDED — mutually exclusive).
    pub(super) fn write_icmp_to_device(&mut self, data: &[u8], icmp_type: u8, icmp_code: u8) {
        let now_sec = self.timers.now().duration_since(self.started_at).as_secs();
        if self.icmp_ratelimit.should_drop(now_sec, 3) {
            return;
        }
        // v4 TIME_EXCEEDED is type 11; v6 is type 3. The Unreachable
        // arm only emits v4 (type 3 = DEST_UNREACH); decrement_ttl
        // emits 11 or 3. Dispatch on the v6 marker.
        let reply =
            if icmp_type == route::ICMP6_TIME_EXCEEDED || icmp_type == route::ICMP6_DST_UNREACH {
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
