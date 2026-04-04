#[allow(clippy::wildcard_imports)]
use super::*;

use std::io::IoSliceMut;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use nix::errno::Errno;
use nix::sys::socket::{
    AddressFamily, MsgFlags, MultiHeaders, SockFlag, SockType, SockaddrStorage, connect,
    getsockname, recvmmsg, socket,
};

/// C `net_packet.c:1845`: `#define MAX_MSG 64`.
const UDP_RX_BATCH: usize = 64;
/// C `vpn_packet_t` is ~1700; we use 2KB (oversize truncates and
/// the SPTPS decrypt fails — same outcome as the old stack buf).
const UDP_RX_BUFSZ: usize = 2048;

/// Persistent recvmmsg state. C `net_packet.c:1853-1857` uses
/// `static` arrays (`pkt[64]`, `addr[64]`, `msg[64]`, `iov[64]`).
/// Heap-once, reuse-forever.
pub(crate) struct UdpRxBatch {
    /// 64 × 2KB packet buffers (`static vpn_packet_t pkt[MAX_MSG]`).
    /// Boxed so `Option<UdpRxBatch>` is `mem::take`-cheap (one ptr,
    /// not 128KB).
    bufs: Box<[[u8; UDP_RX_BUFSZ]; UDP_RX_BATCH]>,
    /// nix's `mmsghdr` + `sockaddr_storage` arrays (`static struct
    /// mmsghdr msg[64]` + `static sockaddr_t addr[64]`).
    headers: MultiHeaders<SockaddrStorage>,
}

impl UdpRxBatch {
    pub(crate) fn new() -> Self {
        // `Box::new([[0u8; 2048]; 64])` would build 128KB on the
        // stack first then move — overflow risk. vec→boxed→array
        // goes straight to the heap.
        let bufs: Box<[[u8; UDP_RX_BUFSZ]]> =
            vec![[0u8; UDP_RX_BUFSZ]; UDP_RX_BATCH].into_boxed_slice();
        let bufs: Box<[[u8; UDP_RX_BUFSZ]; UDP_RX_BATCH]> = bufs
            .try_into()
            .expect("vec![_; 64].into_boxed_slice() has length 64");
        Self {
            bufs,
            headers: MultiHeaders::preallocate(UDP_RX_BATCH, None),
        }
    }
}

/// nix `SockaddrStorage` → std `SocketAddr`. nix has `From` impls
/// for the v4/v6 views but not the union; do it by hand.
fn ss_to_std(ss: &SockaddrStorage) -> Option<SocketAddr> {
    if let Some(v4) = ss.as_sockaddr_in() {
        Some(SocketAddr::V4(SocketAddrV4::from(*v4)))
    } else {
        ss.as_sockaddr_in6()
            .map(|v6| SocketAddr::V6(SocketAddrV6::from(*v6)))
    }
}

impl Daemon {
    /// `handle_new_meta_connection` (`net_socket.c:734-779`).
    /// accept → tarpit-check → configure_tcp → allocate → register.
    pub(super) fn on_tcp_accept(&mut self, i: u8) {
        let listener = &self.listeners[usize::from(i)].listener;

        // C `:745`. socket2 accept4(SOCK_CLOEXEC) fixes the C's
        // small CLOEXEC leak into script.c children for free.
        let (sock, peer_sockaddr) = match listener.tcp.accept() {
            Ok(pair) => pair,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                // Spurious EAGAIN: peer connect+RST'd between epoll
                // wake and accept (TOCTOU).
                return;
            }
            Err(e) => {
                // C `:748`
                log::error!(target: "tincd::conn",
                            "Accepting a new connection failed: {e}");
                return;
            }
        };

        // C `:751` sockaddrunmap. V6ONLY is set so mapped addrs
        // shouldn't appear; canonicalize anyway for fmt_addr/tarpit.
        // `as_socket()` None is a kernel-bug-guard: log + dummy 0:0
        // (won't false-tarpit or false-exempt; expect() would crash
        // the daemon for one bizarre accept).
        let peer = if let Some(sa) = peer_sockaddr.as_socket() {
            unmap(sa)
        } else {
            log::error!(target: "tincd::conn",
                        "accept returned non-IP family {:?}",
                        peer_sockaddr.family());
            (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
        };

        // C `:753`: `&&` short-circuits so local conns never tick
        // the buckets (`tinc info` queries don't get tarpitted).
        if !is_local(&peer) {
            let now = self.timers.now();
            if self.tarpit.check(peer, now) {
                // fd NOT configured — peer's reads block forever.
                self.tarpit.pit(sock.into());
                log::info!(target: "tincd::conn",
                           "Tarpitting connection from {peer}");
                return;
            }
        }

        // C `:773`. C ordering is new_connection (`:758`) BEFORE
        // configure_tcp; we flip so a configure failure doesn't
        // leave a half-registered Connection (C errors don't unwind
        // so the C order is fine — it just continues with a blocking
        // fd at `:73-75`).
        let fd = match configure_tcp(sock) {
            Ok(fd) => fd,
            Err(e) => {
                log::error!(target: "tincd::conn",
                            "configure_tcp failed for {peer}: {e}");
                return; // sock dropped (fd closed)
            }
        };

        // C `:758-776`. `:762` hostname; `:749` address (already
        // unmapped) for `ack_h`'s edge build.
        let hostname = fmt_addr(&peer);
        let conn = Connection::new_meta(fd, hostname, peer, self.timers.now());
        let conn_fd = conn.fd();

        let id = self.conns.insert(conn);
        // C `:771`: io_add IO_READ only.
        match self.ev.add(conn_fd, Io::Read, IoWhat::Conn(id)) {
            Ok(io_id) => {
                self.conn_io.insert(id, io_id);
                log::info!(target: "tincd::conn",
                           "Connection from {peer}");
            }
            Err(e) => {
                self.conns.remove(id);
                log::error!(target: "tincd::conn",
                            "Failed to register connection: {e}");
            }
        }
    }

    /// `handle_incoming_vpn_data` (`net_packet.c:1845-1913`).
    ///
    /// Wire layout (`net.h:92-93`): `[dst_id:6][src_id:6][sptps...]`.
    /// The 12-byte ID prefix is OUTSIDE SPTPS framing; `dst == nullid`
    /// means "direct to you" (`:1013` send / `:1741` recv).
    ///
    /// C `recvmmsg(MAX_MSG=64)` is one batch per callback (level-
    /// triggered: kernel re-fires if more queued). We're EPOLLET, so
    /// a full batch (64 returned) means "maybe more" → rearm so the
    /// next turn() picks them up after the rest of the event loop
    /// runs. Same drain semantics as the old `recv_from` loop's
    /// `UDP_DRAIN_CAP=64` (bug audit `deef1268`): 64 packets per
    /// turn, then yield to TUN-read/meta-conn/timers. iperf3 is
    /// TCP-over-tunnel — alice MUST get back to TUN reads or the
    /// send window fills and the whole thing stalls.
    pub(super) fn on_udp_recv(&mut self, i: u8) {
        // Take the batch out so we can borrow bufs immutably while
        // calling `&mut self.handle_incoming_vpn_packet`. Same
        // pattern as `rx_scratch` (`e49b5af6`). `expect` is fine —
        // this is the only `take` site, no re-entrancy (epoll is
        // single-threaded), and we always put it back below.
        let mut batch = self
            .udp_rx_batch
            .take()
            .expect("udp_rx_batch is Some between on_udp_recv calls");

        let count = self.recvmmsg_batch(i, &mut batch);

        self.udp_rx_batch = Some(batch);

        // EPOLLET: kernel had ≥64 queued → there may be more.
        // Rearm; next turn() drains the rest after meta-conn/timers
        // get a slice. C is level-triggered so it just returns and
        // gets called again — same effect, no rearm syscall.
        if count == UDP_RX_BATCH
            && let Some(slot) = self.listeners.get(usize::from(i))
            && let Err(e) = self.ev.rearm(slot.udp_io)
        {
            log::error!(target: "tincd::net", "UDP fd rearm failed: {e}");
        }
    }

    /// One `recvmmsg(64)` + dispatch. Returns the number of
    /// messages the kernel gave us (0..=64). Separate fn so the
    /// `batch` borrow doesn't overlap `&mut self` at the call site.
    fn recvmmsg_batch(&mut self, i: u8, batch: &mut UdpRxBatch) -> usize {
        let fd = self.listeners[usize::from(i)].listener.udp.as_raw_fd();

        // ─── Phase 1: syscall + extract (len, peer) per message.
        //
        // C `:1858-1872` re-wires the iov array every call too.
        // The IoSliceMut borrows `batch.bufs` for `'a`; nix's
        // `recvmmsg` ties `MultiResults<'a>` to that same lifetime
        // (it borrows `MultiHeaders`). We can't hold MultiResults
        // alive across `&mut self` calls anyway (it borrows
        // `batch.headers`), so collect what we need into a stack
        // array first, drop the iterator, then dispatch from `bufs`.
        //
        // The inner block scopes the iov borrows so phase 2 can
        // re-read `batch.bufs`.
        let mut meta: [(u16, Option<SocketAddr>); UDP_RX_BATCH] = [(0u16, None); UDP_RX_BATCH];
        let count = {
            // 64 × 1-element [IoSliceMut]. Array of arrays (not
            // array of IoSliceMut) because nix wants `I: AsMut<
            // [IoSliceMut]>` — each msg gets a SLICE of iovs.
            let mut iovs: [[IoSliceMut<'_>; 1]; UDP_RX_BATCH] =
                batch.bufs.each_mut().map(|b| [IoSliceMut::new(&mut b[..])]);

            match recvmmsg(
                fd,
                &mut batch.headers,
                iovs.iter_mut(),
                MsgFlags::MSG_DONTWAIT,
                None,
            ) {
                Ok(msgs) => {
                    let mut k = 0usize;
                    for (idx, msg) in msgs.enumerate() {
                        k = idx + 1;
                        // C `:1884`: `pkt[i].len = msg[i].msg_len`.
                        // u16 cast: UDP_RX_BUFSZ=2048 fits.
                        #[allow(clippy::cast_possible_truncation)]
                        let n = msg.bytes.min(UDP_RX_BUFSZ) as u16;
                        // C `:1724` sockaddrunmap.
                        let peer = msg.address.as_ref().and_then(ss_to_std).map(unmap);
                        meta[idx] = (n, peer);
                    }
                    k
                }
                // EAGAIN ≡ EWOULDBLOCK on Linux (alias in nix).
                // C `:1878`: `if(!sockwouldblock) logger(...)`.
                Err(Errno::EAGAIN) => 0,
                Err(e) => {
                    log::error!(target: "tincd::net",
                                "Receiving packet failed: {e}");
                    0
                }
            }
        };

        // ─── Phase 2: dispatch. iov borrows are dead; `batch.bufs`
        // is now free to read while we hold `&mut self`.
        for (idx, &(n, peer)) in meta.iter().enumerate().take(count) {
            let n = usize::from(n);
            // C `:1887`: `if(len <= 0 || len > MAXSIZE) continue`.
            if n == 0 {
                continue;
            }
            let pkt = &batch.bufs[idx][..n];
            self.handle_incoming_vpn_packet(pkt, peer);
        }

        count
    }

    /// `handle_incoming_vpn_packet` (`net_packet.c:1718-1842`).
    ///
    /// Authenticates the immediate UDP sender (`n` in C, `:1728-
    /// 1758`) before the relay branch at `:1817`. SRCID-fallback
    /// (`:1741`) only fires when `dst==nullid` — a relay packet
    /// cannot bootstrap auth via SRCID. For direct receive, SRCID
    /// alone is fine (AEAD tag validates end-to-end); for relay we
    /// never decrypt, so this gate is the only thing stopping a 1:1
    /// UDP reflector attack (security audit `2f72c2ba`).
    #[allow(clippy::too_many_lines)] // C `:1718-1842` is 124 LOC
    pub(super) fn handle_incoming_vpn_packet(&mut self, pkt: &[u8], peer: Option<SocketAddr>) {
        // C `:1736`: 12-byte [dst][src] prefix.
        if pkt.len() < 12 {
            log::debug!(target: "tincd::net",
                        "Dropping {}-byte UDP packet (too short for ID prefix)",
                        pkt.len());
            return;
        }
        // `net.h:92-93`: DSTID at byte 0, SRCID at byte 6.
        let dst_id = NodeId6::from_bytes(pkt[0..6].try_into().unwrap());
        let src_id = NodeId6::from_bytes(pkt[6..12].try_into().unwrap());
        let ct = &pkt[12..];

        // C `:1728-1745`. No `node_udp_tree`; O(nodes) scan is fine
        // (relay is the rare branch). `n.is_some()` ≡ "this UDP src
        // addr belongs to a node that has confirmed UDP with us".
        let n: Option<NodeId> = peer.and_then(|peer_addr| {
            self.tunnels.iter().find_map(|(&nid, t)| {
                (t.status.udp_confirmed && t.udp_addr == Some(peer_addr)).then_some(nid)
            })
        });

        // C `:1739` `try_harder`: decrypt-by-trial for tinc 1.0
        // packets (no NodeId6 prefix) and the ~never NodeId6
        // collision case (sha512(name)[:6], birthday on 48 bits).
        // SPTPS-only build — log + drop.
        let Some(from_nid) = self.id6_table.lookup(src_id) else {
            log::debug!(target: "tincd::net",
                        "Received UDP packet from unknown source ID {src_id} ({peer:?})");
            return;
        };
        let from_name = self.node_log_name(from_nid).to_owned();

        // C `:1786-1821`. `dst==null` → direct-to-us. `dst!=null`:
        // either still for us (sender didn't know we're a direct
        // neighbor) or a relay packet we forward.
        if !dst_id.is_null() {
            let Some(to_nid) = self.id6_table.lookup(dst_id) else {
                log::debug!(target: "tincd::net",
                            "Received UDP relay packet from {from_name} \
                             with unknown dst ID {dst_id}");
                return;
            };
            // C `:1800-1803`: dst just became unreachable (race).
            if !self.graph.node(to_nid).is_some_and(|n| n.reachable) {
                log::debug!(target: "tincd::net",
                            "Cannot relay UDP packet from {from_name}: \
                             dst {dst_id} is unreachable");
                return;
            }
            // C `:1817-1821`: hot relay path. `from_nid` so the
            // wire prefix carries the ORIGINAL source ID.
            if to_nid != self.myself {
                // C `:1758`: unauthenticated sender cannot relay.
                // Without this gate anyone who knows two node names
                // can use us as a 1:1 UDP reflector (security audit
                // `2f72c2ba`).
                if n.is_none() {
                    log::debug!(target: "tincd::net",
                                "Dropping relay request from unauthenticated UDP \
                                 sender ({peer:?}): dst={dst_id} src={src_id}");
                    return;
                }
                log::debug!(target: "tincd::net",
                            "Relaying UDP packet from {from_name} to {} \
                             ({} bytes)",
                            self.node_log_name(to_nid), ct.len());
                let mut nw = self.send_sptps_data_relay(to_nid, from_nid, 0, Some(ct));
                nw |= self.try_tx(to_nid, true);
                if nw {
                    self.maybe_set_write_any();
                }
                return;
            }
            // dst == myself but not nullid: fall through to direct
            // receive. C `:1810-1815`: packet arrived via a dynamic
            // relay; if WE're the static relay (`to->via == myself`)
            // tell `from` where they're reachable so next packet
            // skips the dynamic relay. Gated to static-relay-only
            // so every hop in a chain doesn't emit its own hint.
            let from_via = self
                .last_routes
                .get(from_nid.0 as usize)
                .and_then(Option::as_ref)
                .map(|r| r.via);
            // C `n != from->via` is implicitly satisfied: non-null
            // dst_id6 means SOMEONE relayed (if `from` itself, the
            // prefix would be null). Check only the second half.
            if from_via == Some(self.myself) && self.send_udp_info(from_nid, &from_name, true) {
                self.maybe_set_write_any();
            }
        }

        // C `:1825` → `receive_udppacket` SPTPS branch (`:424-455`).
        let tunnel = self.tunnels.entry(from_nid).or_default();
        let Some(sptps) = tunnel.sptps.as_deref_mut() else {
            // C `:426-433`: UDP packet before handshake started;
            // kick send_req_key (harmless if one's already in flight).
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

        // C `:437-439`. The bit tells `receive_sptps_record` this
        // came via UDP (vs TCP-tunneled). The C clears it at `:439`
        // after the re-entrant callback returns; ours returns
        // Vec<Output> so dispatch is AFTER — defer the clear below.
        tunnel.status.udppacket = true;

        // Fast path: decrypt directly into rx_scratch with 14 bytes
        // headroom (ETH_HLEN, for the synthetic header). Mirror of
        // seal_data_into→tx_scratch. Falls through to the slow
        // Vec<Output> path on:
        //   - InvalidState: no incipher yet (pre-handshake UDP)
        //   - BadRecord: REC_HANDSHAKE/KEX-renegotiate (rare; replay
        //     window NOT advanced, receive() sees the seqno fresh)
        match sptps.open_data_into(ct, &mut self.rx_scratch, 14) {
            Ok(record_type) => {
                // C `:1833-1835`: only direct (dst == nullid) confirms
                // udp_addr; relayed-to-us would cache the relay's addr.
                // Once confirmed at the same address this is a no-op:
                // skip the listener Vec alloc + adapt_socket scan.
                let direct = dst_id.is_null();
                if let Some(peer_addr) = peer.filter(|_| direct)
                    && tunnel.udp_addr != Some(peer_addr)
                {
                    let listener_addrs: Vec<SocketAddr> =
                        self.listeners.iter().map(|s| s.listener.local).collect();
                    let sock = local_addr::adapt_socket(&peer_addr, 0, &listener_addrs);
                    if !tunnel.status.udp_confirmed {
                        log::debug!(target: "tincd::net",
                                    "UDP address of {from_name} confirmed: {peer_addr}");
                        tunnel.status.udp_confirmed = true;
                    }
                    tunnel.udp_addr = Some(peer_addr);
                    tunnel.udp_addr_cached = Some((socket2::SockAddr::from(peer_addr), sock));
                }
                // C `:439`: clear udppacket. Do it here so the borrow
                // of `tunnel` ends before receive_sptps_record_fast
                // takes &mut self.
                tunnel.status.udppacket = false;

                // C `:1840`: send_mtu_info if relayed-to-us.
                let mut nw = false;
                if !direct {
                    nw |= self.send_mtu_info(from_nid, &from_name, i32::from(MTU), true);
                }
                nw |= self.receive_sptps_record_fast(from_nid, &from_name, record_type);
                if nw {
                    self.maybe_set_write_any();
                }
                return;
            }
            Err(tinc_sptps::SptpsError::InvalidState | tinc_sptps::SptpsError::BadRecord) => {
                // Fall through to slow path below.
            }
            Err(e) => {
                // DecryptFailed / BadSeqno: real error. Same handling
                // as the existing receive() Err arm (10s req_key gate).
                tunnel.status.udppacket = false;
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
        }

        // Slow path stays exactly as-is.
        let Some(sptps) = self
            .tunnels
            .get_mut(&from_nid)
            .and_then(|t| t.sptps.as_deref_mut())
        else {
            return;
        };
        let result = sptps.receive(ct, &mut OsRng);
        let outs = match result {
            Ok((_consumed, outs)) => outs,
            Err(e) => {
                // C `:441-450`: tunnel-stuck restart, gated 10s.
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

        // C `:1833-1835`. `direct` set true ONLY when dst_id ==
        // nullid (`:1786`). When `dst != null && to == myself`
        // (relayed-to-us), `peer_addr` is the RELAY's address;
        // caching it would route the next direct send to the relay
        // forever (bug audit `deef1268`).
        let direct = dst_id.is_null();
        if let Some(peer_addr) = peer.filter(|_| direct) {
            // Resolve listener index once instead of per-send;
            // answer doesn't change while udp_addr doesn't.
            let listener_addrs: Vec<SocketAddr> =
                self.listeners.iter().map(|s| s.listener.local).collect();
            let sock = local_addr::adapt_socket(&peer_addr, 0, &listener_addrs);
            let tunnel = self.tunnels.entry(from_nid).or_default();
            if !tunnel.status.udp_confirmed {
                log::debug!(target: "tincd::net",
                            "UDP address of {from_name} confirmed: {peer_addr}");
                tunnel.status.udp_confirmed = true;
            }
            tunnel.udp_addr = Some(peer_addr);
            // Pre-converted SockAddr: was 0.37% self-time per-packet.
            tunnel.udp_addr_cached = Some((socket2::SockAddr::from(peer_addr), sock));
        }
        // C `:1840`: tell `from` our MTU floor so they can switch to
        // direct UDP. Bug audit `deef1268`: was missing entirely.
        if !direct {
            let nw = self.send_mtu_info(from_nid, &from_name, i32::from(MTU), true);
            if nw {
                self.maybe_set_write_any();
            }
        }

        let nw = self.dispatch_tunnel_outputs(from_nid, &from_name, outs);
        // C `:439`: clear udppacket (deferred, see above).
        if let Some(t) = self.tunnels.get_mut(&from_nid) {
            t.status.udppacket = false;
        }
        if nw {
            self.maybe_set_write_any();
        }
    }

    /// `handle_device_data` (`net_packet.c:1916-1938`).
    ///
    /// C reads ONE packet per callback (level-triggered); we drain
    /// because mio is edge-triggered — returning before EAGAIN loses
    /// the wake forever. Bounded so iperf3 saturating the TUN doesn't
    /// starve meta-conn flush/UDP recv/timers.
    pub(super) fn on_device_read(&mut self) {
        const DEVICE_DRAIN_CAP: u32 = 64;

        // Stack buf (was `vec![0u8; MTU]` — one alloc per epoll wake
        // for no reason; recvmmsg work flushed it out).
        let mut buf = [0u8; crate::tunnel::MTU as usize];
        let mut nw = false;
        let mut drained = 0u32;
        loop {
            if drained >= DEVICE_DRAIN_CAP {
                if let Some(io_id) = self.device_io
                    && let Err(e) = self.ev.rearm(io_id)
                {
                    log::error!(target: "tincd::net",
                                    "device fd rearm failed: {e}");
                }
                break;
            }
            drained += 1;
            let n = match self.device.read(&mut buf) {
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    // C `:1933-1936`: 10 consecutive failures →
                    // event_exit(). C also sleep_millis(errors*50)
                    // for a flapping TUN; we don't (bound is 10,
                    // sleep would total 2.75s then exit anyway).
                    log::error!(target: "tincd::net",
                                "Error reading from device: {e}");
                    self.device_errors += 1;
                    if self.device_errors > 10 {
                        log::error!(target: "tincd",
                                    "Too many errors from device, exiting!");
                        self.running = false;
                    }
                    break;
                }
            };
            self.device_errors = 0; // C `:1931`
            // C `:1928-1929`
            let myself_tunnel = self.tunnels.entry(self.myself).or_default();
            myself_tunnel.in_packets += 1;
            myself_tunnel.in_bytes += n as u64;

            nw |= self.route_packet(&mut buf[..n], None); // C `:1930`
        }
        if nw {
            self.maybe_set_write_any();
        }
    }

    /// `route()` (`route.c:1130`) → `send_packet` (`net_packet.c:
    /// 1553-1617`). `from`: `None` = device read; `Some` = peer.
    /// Returns the io_set signal.
    pub(super) fn route_packet(&mut self, data: &mut [u8], from: Option<NodeId>) -> bool {
        // C `route.c:1131`: `if(pcap) send_pcap(packet)`. FIRST thing
        // in route() — a tap, sees everything (incl. kernel-mode
        // forward, runt frames, ARP). The cheap-gate is the field
        // load; `send_pcap` walks conns only when armed (debugging).
        let mut nw = false;
        if self.any_pcap {
            nw |= self.send_pcap(data);
        }

        // C `route.c:1135-1138`: kernel-mode shortcut — peer traffic
        // straight to TUN, OS forwarding table decides. Packets from
        // our device still route (we're the originator). BEFORE the
        // length check (matches C order; device.write rejects short).
        if self.settings.forwarding_mode == ForwardingMode::Kernel && from.is_some() {
            // C `:1137`: `send_packet(myself, packet)`.
            self.send_packet_myself(data);
            return nw;
        }

        // C `route.c:1146`
        match self.settings.routing_mode {
            RoutingMode::Switch => {
                return nw | self.route_packet_mac(data, from); // `route.c:1159`
            }
            RoutingMode::Hub => {
                // `route.c:1163`: always broadcast, no learning.
                return nw | self.dispatch_route_result(RouteResult::Broadcast, data, from);
            }
            RoutingMode::Router => {}
        }

        // C `route.c:1149` ARP intercept. ROUTER-ONLY (Switch treats
        // ARP as opaque eth, returned above). `route_arp` does its
        // own subnet lookup (`route.c:988`) so we handle it before
        // `route()` (which would return `Unsupported{"arp"}`).
        if data.len() >= 14 && u16::from_be_bytes([data[12], data[13]]) == crate::packet::ETH_P_ARP
        {
            return nw | self.handle_arp(data, from);
        }

        // C `route.c:655` reads `subnet->owner->status.reachable`
        // via pointer chain; we close over node_ids+graph and gate
        // on reachability. `myself` is always reachable, so the C
        // `:655` "only check reachable for REMOTE owners" falls out
        // without an explicit string compare.
        let node_ids = &self.node_ids;
        let graph = &self.graph;
        let result = route(data, &self.subnets, |name| {
            let nid = *node_ids.get(name)?;
            graph.node(nid).filter(|n| n.reachable).map(|_| nid)
        });

        nw | self.dispatch_route_result(result, data, from)
    }

    /// `send_pcap` (`route.c:1109-1128`). Walk pcap subscribers,
    /// emit `"18 14 LEN\n"` + raw packet body to each. The body is
    /// the FULL eth frame (whatever `route()` sees — same `vpn_
    /// packet_t` `DATA(packet)` the C dumps at `:1125`).
    ///
    /// Recomputes `any_pcap` as it walks (`:1110-1117`): the C sets
    /// `pcap = false` at the top, then `pcap = true` for each live
    /// subscriber. If a subscriber dropped, the NEXT packet's walk
    /// finds zero and clears the gate — `terminate()` stays ignorant.
    /// One wasted walk per disconnect; cheap (conns is ~5).
    ///
    /// Wire shape (control conns are plaintext, no SPTPS):
    ///   `send_request`: `"18 14 LEN\n"` (`send` appends `\n`)
    ///   `send_meta`:    raw `data[..LEN]` bytes, no terminator
    /// The CLI's `recv_line()` reads to `\n`, then `recv_data(LEN)`
    /// reads exactly LEN bytes (`stream.rs:556-571`). The packet body
    /// MAY contain `\n`; the length-prefixed framing makes that safe.
    ///
    /// Hot path WHEN armed (which is rare — debugging only). The
    /// `any_pcap` gate keeps the unarmed cost at one branch.
    fn send_pcap(&mut self, data: &[u8]) -> bool {
        let mut nw = false;
        let mut still_armed = false; // C `:1110`: `pcap = false`
        for (_, conn) in &mut self.conns {
            if !conn.pcap {
                continue; // C `:1113-1115`
            }
            still_armed = true; // C `:1117`

            // C `:1118-1122`: `int len = packet->len; if(c->
            // outmaclength && c->outmaclength < len) len =
            // c->outmaclength`. snaplen=0 → no clip (the `&&`).
            let snap = usize::from(conn.pcap_snaplen);
            let len = if snap != 0 && snap < data.len() {
                snap
            } else {
                data.len()
            };

            // C `:1124`: `send_request(c, "%d %d %d", CONTROL,
            // REQ_PCAP, len)`. Control conns are plaintext (`conn.
            // sptps` is None), so `send` formats straight to outbuf.
            nw |= conn.send(format_args!(
                "{} {} {len}",
                tinc_proto::Request::Control as u8,
                crate::proto::REQ_PCAP
            ));
            // C `:1125`: `send_meta(c, DATA(packet), len)`. Raw body,
            // no `\n`. C gates this on send_request's bool return
            // (`if(...)`); our `send` is infallible (queues to
            // outbuf, write errors surface at `flush()`).
            nw |= conn.send_raw(&data[..len]);
        }
        self.any_pcap = still_armed;
        nw
    }

    /// `route_mac` wrapper (`route.c:1031`). Switch-mode dispatch.
    fn route_packet_mac(&mut self, data: &mut [u8], from: Option<NodeId>) -> bool {
        let from_myself = from.is_none();
        // C `route.c:1031`: source name for loop check (`:1047`).
        let source_name = match from {
            None => self.name.clone(),
            Some(nid) => self
                .graph
                .node(nid)
                .map_or_else(|| "<unknown>".to_owned(), |n| n.name.clone()),
        };

        let node_ids = &self.node_ids;
        let (result, learn) = route_mac::route_mac(
            data,
            from_myself,
            &source_name,
            &self.name,
            &self.mac_table,
            |name| node_ids.get(name).copied(),
        );

        // C `route.c:1031-1035`: LearnAction is BEFORE routing in
        // source order but they're independent.
        let mut nw = false;
        match learn {
            route_mac::LearnAction::NotOurs => {}
            route_mac::LearnAction::New(mac) => {
                nw |= self.learn_mac(mac); // C `route.c:528-551`
            }
            route_mac::LearnAction::Refresh(mac) => {
                // C `route.c:551-555` else. C `:525` lookup is
                // myself-scoped; route_mac's snapshot isn't — check.
                if self.mac_table.get(&mac).map(String::as_str) == Some(self.name.as_str()) {
                    let now = self.timers.now();
                    self.mac_leases.refresh(mac, now, self.settings.macexpire);
                } else {
                    // Remotely owned: C's myself-scoped lookup would
                    // fail → branch to New. VM migrated to us.
                    nw |= self.learn_mac(mac);
                }
            }
        }

        nw |= self.dispatch_route_result(result, data, from);
        nw
    }

    /// `learn_mac` (`route.c:524-556`). New source MAC on TAP →
    /// Subnet::Mac + broadcast ADD_SUBNET + arm age_subnets timer.
    fn learn_mac(&mut self, mac: route_mac::Mac) -> bool {
        log::info!(target: "tincd::net",
                   "Learned new MAC address \
                    {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

        // C `:534-541`
        let subnet = Subnet::Mac {
            addr: mac,
            weight: 10,
        };
        let myname = self.name.clone();
        self.subnets.add(subnet, myname.clone());
        self.mac_table.insert(mac, myname.clone());
        // C `:540` subnet_update → subnet-up script.
        self.run_subnet_script(true, &myname, &subnet);

        // C `:536`. learn() returns true if table was empty.
        let now = self.timers.now();
        let arm_timer = self.mac_leases.learn(mac, now, self.settings.macexpire);

        // C `:544-548`: broadcast ADD_SUBNET (c->edge = c.active).
        let mut nw = false;
        let targets = self.broadcast_targets(None);
        for cid in targets {
            nw |= self.send_subnet(cid, Request::AddSubnet, &myname, &subnet);
        }

        // C `:549-551`: timeout_add is idempotent. Arm only when
        // learn() says table was empty AND no slot (defensive).
        if arm_timer && self.age_subnets_timer.is_none() {
            let tid = self.timers.add(TimerWhat::AgeSubnets);
            self.timers.set(tid, Duration::from_secs(10));
            self.age_subnets_timer = Some(tid);
        }

        nw
    }

    /// `send_packet(myself, packet)` (`net_packet.c:1556-1568`).
    /// The local-delivery half: write to the device, with the
    /// `overwrite_mac` stamp (`:1557-1562`) gated on Mode=router +
    /// TAP-ish device. Factored out so the kernel-mode shortcut
    /// (`route.c:1137`), broadcast echo (`net_packet.c:1617`), and
    /// `Forward{to:myself}` arms all hit the same stamp.
    fn send_packet_myself(&mut self, data: &mut [u8]) {
        // C `:1557-1562`. Dest MAC ← the kernel's own (snatched from
        // ARP/NDP); source MAC ← dest XOR 0xFF on the last byte
        // ("arbitrary fake source" — just-different so the kernel
        // doesn't see its own MAC as src). data.len()≥12 holds at
        // every callsite (post-route or post-checklength).
        if self.overwrite_mac && data.len() >= 12 {
            data[0..6].copy_from_slice(&self.mymac);
            data[6..12].copy_from_slice(&self.mymac);
            data[11] ^= 0xFF;
        }
        // C `:1565-1567`
        let len = data.len() as u64;
        let myself_tunnel = self.tunnels.entry(self.myself).or_default();
        myself_tunnel.out_packets += 1;
        myself_tunnel.out_bytes += len;
        if let Err(e) = self.device.write(data) {
            log::debug!(target: "tincd::net", "Error writing to device: {e}");
        }
    }

    /// `broadcast_packet` (`net_packet.c:1612-1660`).
    fn broadcast_packet(&mut self, data: &mut [u8], from: Option<NodeId>) -> bool {
        // C `:1616-1618`: echo a forwarded broadcast to local kernel.
        // C `:1617`: `send_packet(myself, packet)`.
        if from.is_some() {
            self.send_packet_myself(data);
        }

        // C `:1624-1626`. Tunnelserver: MST might be invalid
        // (filtered ADD_EDGE → loops). BMODE_NONE: opted out.
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

        // C `:1633-1652`
        let target_nids: Vec<NodeId> = match self.settings.broadcast_mode {
            broadcast::BroadcastMode::None => unreachable!("checked above"),
            broadcast::BroadcastMode::Mst => {
                // C `:1635`. from_conn: C uses from->nexthop->
                // connection → last_routes[from].nexthop → .conn.
                let from_conn: Option<ConnId> = from.and_then(|nid| {
                    let route = self.last_routes.get(nid.0 as usize)?.as_ref()?;
                    self.nodes.get(&route.nexthop)?.conn
                });

                let active: Vec<(ConnId, EdgeId)> = self
                    .conns
                    .iter()
                    .filter(|&(_, c)| c.active)
                    .filter_map(|(cid, c)| {
                        let nid = self.node_ids.get(&c.name)?;
                        let eid = self.nodes.get(nid)?.edge?;
                        Some((cid, eid))
                    })
                    .collect();

                let target_conns =
                    broadcast::mst_targets(active.into_iter(), &self.last_mst, from_conn);

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
                // one-hop. last_routes[nid] None for unreachable.
                let nodes_iter = self.node_ids.values().filter_map(|&nid| {
                    let r = self.last_routes.get(nid.0 as usize)?.as_ref()?;
                    Some((nid, Some(r.via), Some(r.nexthop)))
                });
                broadcast::direct_targets(nodes_iter, self.myself, from_is_self)
            }
        };

        // C `:1636,1651`. No clamp_mss/directonly/decrement_ttl —
        // route()-level concerns; broadcast bypasses route().
        let mut nw = false;
        for nid in target_nids {
            let len = data.len();
            let tunnel = self.tunnels.entry(nid).or_default();
            tunnel.out_packets += 1;
            tunnel.out_bytes += len as u64;
            nw |= self.send_sptps_packet(nid, data); // C `:1586-1590`
            nw |= self.try_tx(nid, true);
        }
        nw
    }

    /// `RouteResult` dispatch. Shared by Router and Switch paths;
    /// C `route_ipv4`/`route_ipv6`/`route_mac` call `send_packet`
    /// directly, we funnel here.
    #[allow(clippy::too_many_lines)] // C route()+send_packet ≈200 LOC
    #[allow(clippy::needless_pass_by_value)] // RouteResult<NodeId>: Copy
    fn dispatch_route_result(
        &mut self,
        result: RouteResult<NodeId>,
        data: &mut [u8],
        from: Option<NodeId>,
    ) -> bool {
        match result {
            RouteResult::Forward { to } if to == self.myself => {
                // C `send_packet:1556-1568`: packet is for US.
                self.send_packet_myself(data);
                false
            }
            RouteResult::Forward { to: to_nid } => {
                // C `send_packet:1571-1590`
                let to = self
                    .graph
                    .node(to_nid)
                    .map_or_else(|| "<gone>".to_owned(), |n| n.name.clone());

                // C `route.c:649,745`: dest subnet OWNED by sender —
                // overlapping subnets, misconfig.
                if Some(to_nid) == from {
                    log::warn!(target: "tincd::net",
                               "Packet looping back to {to}");
                    return false;
                }

                // C `route.c:659-662,753-756,1052-1054`: FMODE_OFF —
                // operator says "I am an endpoint, not a relay". Gate
                // is `source != myself && owner != myself`: `from.
                // is_some()` is the first; this match arm (NOT the
                // `to == self.myself` arm above) is the second. v4
                // → NET_ANO (`:660`), v6 → ADMIN (`:754`); MAC
                // (Switch) → silent drop (`:1053`). Gap audit
                // `bcc5c3e3`: parsed since `daemon.rs:1244`, never
                // read — the security knob silently no-op'd.
                if self.settings.forwarding_mode == ForwardingMode::Off && from.is_some() {
                    log::debug!(target: "tincd::net",
                                "Forwarding=off: dropping transit packet \
                                 to {to} (we are not a relay)");
                    if self.settings.routing_mode == RoutingMode::Router {
                        let ethertype = u16::from_be_bytes([data[12], data[13]]);
                        let (t, c) = if ethertype == crate::packet::ETH_P_IP {
                            (route::ICMP_DEST_UNREACH, route::ICMP_NET_ANO)
                        } else {
                            (route::ICMP6_DST_UNREACH, route::ICMP6_DST_UNREACH_ADMIN)
                        };
                        self.write_icmp_to_device(data, t, c);
                    }
                    return false;
                }

                // C `route.c:698` clamp_mss BEFORE send_packet, AFTER
                // routing. C `:390-398` gate on OPTION_CLAMP_MSS;
                // `via->options` from SSSP (`graph.c:192`).
                // C `route.c:672`: via = (owner->via == myself) ?
                // owner->nexthop : owner->via. last_routes is current
                // for any Forward target (route() only returns Forward
                // for reachable owners).
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

                // C `route.c:675,770`: next hop IS the sender —
                // bounce loop (stale graph data, DEL_EDGE arrived but
                // run_graph hasn't recomputed via).
                if Some(via_nid) == from {
                    let from_name = from
                        .and_then(|nid| self.graph.node(nid))
                        .map_or("?", |n| n.name.as_str());
                    log::error!(target: "tincd::net",
                                "Routing loop for packet from {from_name}");
                    return false;
                }

                // C `route.c:685`. C's n->mtu starts 0 (xzalloc) so
                // `route.c:396` `via->mtu < mtu` would let 0 WIN.
                // Our TunnelState::default() inits to MTU instead
                // (tunnel.rs). Until PMTU runs: 1518 ceiling.
                let via_mtu = self.tunnels.get(&via_nid).map_or(MTU, TunnelState::mtu);

                // C `route.c:679-682`: directonly — operator opts out
                // of relay. v6: ICMP6_DST_UNREACH_ADMIN (`:774`).
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
                // next hop's PMTU. Only when relaying (clamp_mss +
                // kernel PMTU handle our own outbound). Floors:
                // 590=576+14 (RFC 791), 1294=1280+14 (RFC 8200) —
                // don't claim MTU < 576 even if discovery hasn't run.
                // C `:690` truncation is for the ICMP quote; our
                // build_v4_unreachable caps internally.
                //
                // `via_mtu != 0`: don't claim a path MTU before
                // discovery has measured one. `try_fix_mtu`
                // (`pmtu.rs:251`) only sets `mtu` once `minmtu >=
                // maxmtu`; until then it's 0, `MAX(0,590)` claims
                // 576, and the kernel caches that per-dst for 10
                // minutes — any TCP flow in that window is stuck at
                // MSS 536 forever. 3× packets/crypto/syscalls for
                // the same bytes.
                //
                // C `:685` has the same `via->mtu==0` window but
                // `choose_initial_maxmtu` (`:1249`, getsockopt
                // IP_MTU → probe at exact value) makes it ~1 RTT.
                // We walk the ~10-probe ladder (333ms each, ~3.3s).
                // C with `#undef IP_MTU` would have the same bug.
                if via_nid != self.myself && via_mtu != 0 {
                    let ethertype = u16::from_be_bytes([data[12], data[13]]);
                    let floor: u16 = if ethertype == crate::packet::ETH_P_IP {
                        590
                    } else {
                        1294
                    };
                    let limit = via_mtu.max(floor);
                    if data.len() > usize::from(limit) {
                        if ethertype == crate::packet::ETH_P_IP {
                            // C `:688`: DF flag (data.len()>590 ⇒ [20] in bounds).
                            let df_set = data[20] & 0x40 != 0;
                            if df_set {
                                // C `:690,:174`: limit-14 = IP-layer
                                // MTU. limit≥590 so sub never wraps.
                                self.write_icmp_frag_needed(data, limit - 14);
                            } else {
                                // C `route.c:692`: fragment_ipv4_packet.
                                // RFC 791 §2.3: routers MUST fragment.
                                // Rare path (modern OS sets DF on TCP)
                                // but UDP without DF through narrow-
                                // MTU relay needs this.
                                let Some(frags) = crate::fragment::fragment_v4(data, limit) else {
                                    log::debug!(target: "tincd::net",
                                        "fragment_v4: malformed input, dropping");
                                    return false;
                                };
                                // C `:611`: send_packet(dest, &fragment)
                                // per loop iter. Mirror the normal
                                // send path below: send_sptps_packet
                                // + try_tx for PMTU drive.
                                let n = frags.len();
                                log::debug!(target: "tincd::net",
                                    "Fragmenting packet of {} bytes into \
                                     {n} pieces for {to}", data.len());
                                {
                                    let tunnel = self.tunnels.entry(to_nid).or_default();
                                    for frag in &frags {
                                        tunnel.out_packets += 1;
                                        tunnel.out_bytes += frag.len() as u64;
                                    }
                                }
                                let mut nw = false;
                                for frag in &frags {
                                    nw |= self.send_sptps_packet(to_nid, frag);
                                }
                                nw |= self.try_tx(to_nid, true);
                                return nw;
                            }
                        } else {
                            // v6: no in-transit frag (RFC 8200 §5).
                            self.write_icmp_pkt_too_big(data, u32::from(limit - 14));
                        }
                        return false;
                    }
                }

                if via_options & crate::proto::OPTION_CLAMP_MSS != 0 {
                    let mtu = via_mtu.min(MTU);
                    let _ = mss::clamp(data, mtu); // C `:698`
                }

                // C `route.c:664,759`. `source != myself` gate: don't
                // decrement on TUN-origin (we ARE the first hop).
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
                            self.write_icmp_to_device(data, icmp_type, icmp_code);
                            return false;
                        }
                    }
                }

                // C `route.c:669,765,1063`: read inner TOS for the
                // outer UDP socket. C threads via vpn_packet_t.priority
                // (`net.h:84`); we via Daemon.tx_priority. Reset to 0
                // each packet (C `:1921,1076,1190`: `packet.priority=0`
                // — priority only ever flows from data through to UDP
                // send). Done here, not at route_packet entry, to stay
                // clear of the dump-traffic agent's route boundary.
                self.tx_priority = if self.settings.priorityinheritance {
                    route::extract_tos(data).unwrap_or(0)
                } else {
                    0
                };

                let len = data.len();
                log::debug!(target: "tincd::net",
                            "Sending packet of {len} bytes to {to}");
                // C `:1582-1583`: counts attempts, not deliveries.
                let tunnel = self.tunnels.entry(to_nid).or_default();
                tunnel.out_packets += 1;
                tunnel.out_bytes += len as u64;

                // C `:1586-1590`. try_tx(n, true): every forwarded
                // packet drives PMTU discovery one step.
                let mut nw = self.send_sptps_packet(to_nid, data);
                nw |= self.try_tx(to_nid, true);
                nw
            }
            RouteResult::Unreachable {
                icmp_type,
                icmp_code,
            } => {
                // C `route_ipv4_unreachable` (`route.c:121-215`).
                // C `:130-132`: ratelimit(3), keyed on same-second.
                let now_sec = self.timers.now().duration_since(self.started_at).as_secs();
                if self.icmp_ratelimit.should_drop(now_sec, 3) {
                    log::debug!(target: "tincd::net",
                                "route: unreachable (type={icmp_type} \
                                 code={icmp_code}), rate-limited");
                    return false;
                }
                // C `route.c:734` v6 / `:608` v4 collapsed into one
                // variant; v4/v6 dispatch on ethertype here (bug
                // audit `deef1268`). data.len() ≥ 14 guaranteed:
                // route() returns TooShort for shorter.
                let ethertype = u16::from_be_bytes([data[12], data[13]]);
                let reply = if ethertype == 0x86DD {
                    // ETH_P_IPV6
                    icmp::build_v6_unreachable(data, icmp_type, icmp_code, None, None)
                } else {
                    icmp::build_v4_unreachable(data, icmp_type, icmp_code, None, None)
                };
                let Some(reply) = reply else {
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
                self.handle_ndp(data, from);
                false
            }
            RouteResult::Unsupported { reason } => {
                log::debug!(target: "tincd::net",
                            "route: dropping packet ({reason})");
                false
            }
            RouteResult::Broadcast => {
                // C `route.c:1042-1045` → `route_broadcast`.
                // C `route_broadcast:559-563`: do_decrement_ttl is
                // eth-aware (`:327` returns true for non-IP like ARP);
                // our decrement_ttl() passes ARP via TooShort.
                if self.settings.decrement_ttl && from.is_some() {
                    match route::decrement_ttl(data) {
                        TtlResult::Decremented | TtlResult::TooShort => {}
                        TtlResult::DropSilent | TtlResult::SendIcmp { .. } => {
                            // C `:563` just returns (no ICMP synth).
                            return false;
                        }
                    }
                }
                self.broadcast_packet(data, from)
            }
            RouteResult::TooShort { need, have } => {
                // C `route.c:103-108`
                log::debug!(target: "tincd::net",
                            "route: too short (need {need}, have {have})");
                false
            }
        }
    }

    /// `send_sptps_packet` (`net_packet.c:683-730`).
    /// C `:696-698`: Router strips the eth header (receiver re-
    /// synthesizes from IP version nibble, `:1128-1144`).
    pub(super) fn send_sptps_packet(&mut self, to_nid: NodeId, data: &[u8]) -> bool {
        // Direct graph access (disjoint from tunnels/compressor).
        let to_name = self
            .graph
            .node(to_nid)
            .map_or("<gone>", |n| n.name.as_str());
        // C `:696-700`
        let (offset, base_type) = match self.settings.routing_mode {
            RoutingMode::Router => (14, PKT_NORMAL),
            RoutingMode::Switch | RoutingMode::Hub => (0, PKT_MAC),
        };
        let tunnel = self.tunnels.entry(to_nid).or_default();

        // PACKET 17 short-circuit (C `net_packet.c:725`): direct
        // meta-conn + doesn't fit MTU → single-encrypt via meta-
        // SPTPS. Gated BEFORE validkey (C `:684`): with a direct
        // conn, validkey doesn't matter; with TCPOnly, validkey stays
        // false forever and this is the ONLY way to send.
        //
        // C-IS-WRONG #11: C `:725` gates AFTER compression (`:708-
        // 718`); when compression helps, `:716 origpkt = &outpkt`
        // points at a stack vpn_packet_t with `data[0..offset]`
        // uninitialized → 14 garbage bytes on the wire → receiver
        // drops. Triple-gate dormancy (TCPOnly + Compression>0 +
        // packet shrank). STRICTER-than-C: gate BEFORE compression.
        let direct_conn = self.nodes.get(&to_nid).and_then(|ns| ns.conn);
        if let Some(conn_id) = direct_conn
            && data.len() > usize::from(tunnel.minmtu())
        {
            let Some(conn) = self.conns.get_mut(conn_id) else {
                return false; // NodeState.conn stale (race)
            };
            // C `protocol_misc.c:90-103`. RED first (`:94`);
            // maxoutbufsize default 10*MTU (`net_setup.c:1255`).
            if crate::tcp_tunnel::random_early_drop(
                conn.outbuf.live_len(),
                self.settings.maxoutbufsize,
                &mut OsRng,
            ) {
                return true; // C `:95` fake success
            }
            // C `:98`. len fits u16: MTU=1518.
            #[allow(clippy::cast_possible_truncation)]
            let req = tinc_proto::msg::TcpPacket {
                len: data.len() as u16,
            };
            let mut nw = conn.send(format_args!("{}", req.format()));
            // C `:102`. FULL eth frame, NOT stripped/compressed
            // (see C-IS-WRONG #11).
            nw |= conn.send_sptps_record(0, data);
            return nw;
        }

        if !tunnel.status.validkey {
            // C `try_sptps` (`net_packet.c:1157-1180`).
            log::debug!(target: "tincd::net",
                        "No valid key known yet for {to_name}");
            if !tunnel.status.waitingforkey {
                return self.send_req_key(to_nid);
            }
            // C `:1167-1173`: 10-second debounce; try_tx handles
            // the restart.
            return false;
        }

        // C `:691-694`: PKT_PROBE path goes via try_tx, not here.
        // C `:702`: only matters for Router (Switch offset=0).
        if data.len() < offset {
            return false;
        }

        // C `:708-718`: only set PKT_COMPRESSED if compression
        // actually helped. Peer asked for this level in ANS_KEY.
        // PERF(chunk-10): one alloc per packet when peer asked for
        // compression (C uses a stack vpn_packet_t).
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
                payload // C `:714`: didn't help, fall back to raw
            }
        } else {
            // C `:712-713`: LZO stub or backend error.
            log::debug!(target: "tincd::net",
                        "Error while compressing packet to {to_name}");
            payload
        };

        // C `:728`. PACKET 17 gate already handled above (STRICTER-
        // than-C, see C-IS-WRONG #11).
        let Some(sptps) = tunnel.sptps.as_deref_mut() else {
            // validkey true but no sptps shouldn't happen (set by
            // HandshakeDone after Sptps::start). Defensive.
            log::warn!(target: "tincd::net",
                       "validkey set but no SPTPS for {to_name}?");
            return false;
        };

        // Encrypt into scratch with 12 bytes headroom (C `DEFAULT_
        // PACKET_OFFSET` for [dst_id6‖src_id6]). Zero per-packet
        // allocs; see `seal_data_into` doc for the previous 3-alloc
        // shape.
        if let Err(e) = sptps.seal_data_into(record_type, body, &mut self.tx_scratch, 12) {
            // Shouldn't happen: validkey checked, per-tunnel SPTPS
            // is always datagram-framed.
            log::warn!(target: "tincd::net",
                       "seal_data_into for {to_name}: {e:?}");
            return false;
        }
        self.send_sptps_data_relay(to_nid, self.myself, record_type, None)
    }

    /// `receive_sptps_record` (`net_packet.c:1056-1152`) +
    /// `send_sptps_data` (`:965-1054`) callback bridge. The C
    /// registers two callbacks; our SPTPS returns Vec<Output> so
    /// this IS both.
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
                    // `send_sptps_data` (`net_packet.c:965-1054`)
                    nw |= self.send_sptps_data(peer, record_type, &bytes);
                }
                Output::HandshakeDone => {
                    // C `receive_sptps_record:1059-1065`
                    let tunnel = self.tunnels.entry(peer).or_default();
                    if !tunnel.status.validkey {
                        tunnel.status.validkey = true;
                        tunnel.status.waitingforkey = false;
                        log::info!(target: "tincd::net",
                                   "SPTPS key exchange with {peer_name} successful");
                    }
                }
                Output::Record { record_type, bytes } => {
                    // `:1071-1152`
                    nw |= self.receive_sptps_record(peer, peer_name, record_type, &bytes);
                }
            }
        }
        nw
    }

    /// `receive_sptps_record` data branch (`net_packet.c:1071-1152`).
    pub(super) fn receive_sptps_record(
        &mut self,
        peer: NodeId,
        peer_name: &str,
        record_type: u8,
        body: &[u8],
    ) -> bool {
        // C `:1068-1070`
        if body.len() > usize::from(crate::tunnel::MTU) {
            log::error!(target: "tincd::net",
                        "Packet from {peer_name} larger than MTU ({} > {})",
                        body.len(), crate::tunnel::MTU);
            return false;
        }

        // C `:1078-1092`: PMTU probe. The udppacket gate (`:1079-
        // 1082`): probes only make sense over UDP (they ARE the
        // PMTU discovery mechanism); TCP-tunneled probe = peer bug.
        if record_type == PKT_PROBE {
            let udppacket = self.tunnels.get(&peer).is_some_and(|t| t.status.udppacket);
            if !udppacket {
                log::error!(target: "tincd::net",
                            "Got SPTPS PROBE from {peer_name} via TCP");
                return false;
            }
            // C `:1088-1090`: maxrecentlen for try_udp's gratuitous
            // reply (`:1211-1222`).
            #[allow(clippy::cast_possible_truncation)] // body ≤ MTU
            let body_len = body.len() as u16;
            if let Some(p) = self.tunnels.get_mut(&peer).and_then(|t| t.pmtu.as_mut())
                && body_len > p.maxrecentlen
            {
                p.maxrecentlen = body_len;
            }
            return self.udp_probe_h(peer, peer_name, body); // C `:1091`
        }
        // C `:1094-1097`: unknown type bits.
        if record_type & !(PKT_COMPRESSED | PKT_MAC) != 0 {
            log::error!(target: "tincd::net",
                        "Unexpected SPTPS record type {record_type} from {peer_name}");
            return false;
        }
        // C `:1101-1105`: cross-mode warnings. Switch needs the eth
        // header (ERROR if peer stripped it); Router re-synths
        // anyway (WARN, lenient).
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
            }
            _ => {}
        }

        // C `:1108`: TYPE-driven, not mode-driven — a switch node
        // receiving from a misconfigured router peer still parses
        // correctly using offset=14.
        let offset: usize = if has_mac { 0 } else { 14 };
        // C `:1109-1121`: decompress at the level WE asked for.
        let decompressed;
        let body: &[u8] = if record_type & PKT_COMPRESSED != 0 {
            let incomp = self.tunnels.get(&peer).map_or(0, |t| t.incompression);
            let level = compress::Level::from_wire(incomp);
            if let Some(d) = self.compressor.decompress(body, level, MTU as usize) {
                decompressed = d;
                &decompressed
            } else {
                // C `:1113-1115`: corrupt stream or LZO stub.
                log::warn!(target: "tincd::net",
                           "Error while decompressing packet from {peer_name}");
                return false;
            }
        } else {
            body
        };

        // C `:1123,:1128-1144`: synthesize ethertype from IP version
        // nibble (Router only; Switch body IS the full eth frame).
        let mut frame: Vec<u8>;
        if offset == 0 {
            frame = body.to_vec();
        } else {
            // Zero MACs (C `:1128` leaves them zero from xzalloc).
            if body.is_empty() {
                return false; // need byte 0 for the version nibble
            }
            let ethertype: u16 = match body[0] >> 4 {
                4 => crate::packet::ETH_P_IP,
                6 => 0x86DD, // ETH_P_IPV6
                v => {
                    // C `:1141-1144`
                    log::debug!(target: "tincd::net",
                                "Unknown IP version {v} in packet from {peer_name}");
                    return false;
                }
            };
            frame = vec![0u8; offset + body.len()];
            frame[12..14].copy_from_slice(&ethertype.to_be_bytes());
            frame[offset..].copy_from_slice(body);
        }

        // C `:1148-1150`: maxrecentlen for try_udp's gratuitous
        // probe-reply size (`:1213-1221`).
        #[allow(clippy::cast_possible_truncation)] // frame.len() ≤ MTU
        let frame_len = frame.len() as u16;
        if let Some(t) = self.tunnels.get_mut(&peer)
            && t.status.udppacket
            && let Some(p) = t.pmtu.as_mut()
            && frame_len > p.maxrecentlen
        {
            p.maxrecentlen = frame_len;
        }

        // C `:1152` → `receive_packet` (`:397-405`).
        let len = frame.len() as u64;
        let tunnel = self.tunnels.entry(peer).or_default();
        tunnel.in_packets += 1;
        tunnel.in_bytes += len;

        self.route_packet(&mut frame, Some(peer))
    }

    /// Fast-path version of [`receive_sptps_record`]. Reads the body
    /// from `self.rx_scratch[14..]` instead of a borrowed slice. Avoids
    /// the `frame: Vec<u8>` allocation by building the ethernet frame
    /// in-place in `rx_scratch` (the headroom was pre-reserved by
    /// `open_data_into`).
    ///
    /// LOGIC IS IDENTICAL to `receive_sptps_record`; only the byte
    /// storage changed. The slow-path version is still called from
    /// `dispatch_tunnel_outputs` (handshake fallback) and the
    /// TCP-tunneled path in `gossip.rs`.
    #[allow(clippy::too_many_lines)] // mirrors receive_sptps_record (C `:1071-1152`)
    fn receive_sptps_record_fast(
        &mut self,
        peer: NodeId,
        peer_name: &str,
        record_type: u8,
    ) -> bool {
        let body_len = self.rx_scratch.len() - 14;

        // C `:1068-1070`
        if body_len > usize::from(crate::tunnel::MTU) {
            log::error!(target: "tincd::net",
                        "Packet from {peer_name} larger than MTU ({} > {})",
                        body_len, crate::tunnel::MTU);
            return false;
        }

        // C `:1078-1092`: PMTU probe. Probes are tiny and rare; just
        // hand the slice to the existing handler. udppacket gate: this
        // path is only reached from handle_incoming_vpn_packet (UDP),
        // but the bit was already cleared above. Probes via UDP are
        // valid by construction here — skip the gate.
        if record_type == PKT_PROBE {
            #[allow(clippy::cast_possible_truncation)] // body ≤ MTU
            let body_len_u16 = body_len as u16;
            if let Some(p) = self.tunnels.get_mut(&peer).and_then(|t| t.pmtu.as_mut())
                && body_len_u16 > p.maxrecentlen
            {
                p.maxrecentlen = body_len_u16;
            }
            // udp_probe_h takes &[u8] and does its own copy for the
            // reply; safe to slice rx_scratch here (it borrows self
            // but udp_probe_h is &mut self... mem::take dance).
            let scratch = std::mem::take(&mut self.rx_scratch);
            let nw = self.udp_probe_h(peer, peer_name, &scratch[14..]);
            self.rx_scratch = scratch;
            return nw;
        }
        // C `:1094-1097`
        if record_type & !(PKT_COMPRESSED | PKT_MAC) != 0 {
            log::error!(target: "tincd::net",
                        "Unexpected SPTPS record type {record_type} from {peer_name}");
            return false;
        }
        // C `:1101-1105`
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
            }
            _ => {}
        }

        // C `:1108`
        let offset: usize = if has_mac { 0 } else { 14 };

        // C `:1109-1121`: decompression. Compressed packets are RARE
        // (compression=0 is default); fall back to a local Vec for
        // the decompressed output. The compressor already returns
        // Vec; don't fight it.
        let decompressed: Option<Vec<u8>>;
        if record_type & PKT_COMPRESSED != 0 {
            let incomp = self.tunnels.get(&peer).map_or(0, |t| t.incompression);
            let level = compress::Level::from_wire(incomp);
            // mem::take so we can borrow rx_scratch immutably while
            // calling &mut self.compressor.
            let scratch = std::mem::take(&mut self.rx_scratch);
            let d = self
                .compressor
                .decompress(&scratch[14..], level, MTU as usize);
            self.rx_scratch = scratch;
            if let Some(d) = d {
                decompressed = Some(d);
            } else {
                log::warn!(target: "tincd::net",
                           "Error while decompressing packet from {peer_name}");
                return false;
            }
        } else {
            decompressed = None;
        }

        // Build the frame. Three cases:
        //  1. compressed: body lives in `decompressed`, build a fresh
        //     frame Vec (one alloc, but rare).
        //  2. has_mac (Switch): body IS the eth frame, lives at
        //     rx_scratch[14..]. Route that slice directly. Zero alloc.
        //  3. !has_mac (Router, the iperf hot path): body is at
        //     rx_scratch[14..], headroom [0..14] is zeros. Write the
        //     ethertype at [12..14], route rx_scratch in full. Zero alloc.
        //
        // route_packet takes &mut self + &mut [u8], so we mem::take
        // rx_scratch out of self for the call and put it back after.
        // The take leaves an empty Vec (no alloc); the restore brings
        // back the capacity-carrying one.
        let mut frame_vec: Vec<u8>;
        let mut scratch = std::mem::take(&mut self.rx_scratch);
        let frame: &mut [u8] = if let Some(body) = &decompressed {
            // Compressed: synth a frame Vec the slow way.
            if offset == 0 {
                frame_vec = body.clone();
            } else {
                if body.is_empty() {
                    self.rx_scratch = scratch;
                    return false;
                }
                let ethertype: u16 = match body[0] >> 4 {
                    4 => crate::packet::ETH_P_IP,
                    6 => 0x86DD,
                    v => {
                        log::debug!(target: "tincd::net",
                                    "Unknown IP version {v} in packet from {peer_name}");
                        self.rx_scratch = scratch;
                        return false;
                    }
                };
                frame_vec = vec![0u8; offset + body.len()];
                frame_vec[12..14].copy_from_slice(&ethertype.to_be_bytes());
                frame_vec[offset..].copy_from_slice(body);
            }
            &mut frame_vec
        } else if offset == 0 {
            // Switch mode: body at scratch[14..] IS the frame.
            &mut scratch[14..]
        } else {
            // Router mode (THE HOT PATH). C `:1128-1144`.
            if body_len == 0 {
                self.rx_scratch = scratch;
                return false;
            }
            let ethertype: u16 = match scratch[14] >> 4 {
                4 => crate::packet::ETH_P_IP,
                6 => 0x86DD,
                v => {
                    log::debug!(target: "tincd::net",
                                "Unknown IP version {v} in packet from {peer_name}");
                    self.rx_scratch = scratch;
                    return false;
                }
            };
            // Headroom [0..14] is already zero (open_data_into wrote
            // it). Just stamp the ethertype.
            scratch[12..14].copy_from_slice(&ethertype.to_be_bytes());
            &mut scratch
        };

        // C `:1148-1150`: maxrecentlen. udppacket was already cleared
        // by the caller, but this path is by-construction UDP-only,
        // so update unconditionally (matches what the C effectively
        // does: the bit is set during the entire receive callback).
        #[allow(clippy::cast_possible_truncation)] // frame.len() ≤ 14+MTU
        let frame_len = frame.len() as u16;
        if let Some(p) = self.tunnels.get_mut(&peer).and_then(|t| t.pmtu.as_mut())
            && frame_len > p.maxrecentlen
        {
            p.maxrecentlen = frame_len;
        }

        // C `:1152` → `receive_packet` (`:397-405`).
        let len = frame.len() as u64;
        let tunnel = self.tunnels.entry(peer).or_default();
        tunnel.in_packets += 1;
        tunnel.in_bytes += len;

        let nw = self.route_packet(frame, Some(peer));
        self.rx_scratch = scratch;
        nw
    }

    /// `send_sptps_data_myself` (`net_packet.c:99-101`).
    pub(super) fn send_sptps_data(&mut self, to_nid: NodeId, record_type: u8, ct: &[u8]) -> bool {
        self.send_sptps_data_relay(to_nid, self.myself, record_type, Some(ct))
    }

    /// `send_sptps_data` (`net_packet.c:965-1054`). The `:967-974`
    /// relay decision: TCP vs UDP, `via` vs `nexthop`.
    ///
    /// `via` (`:967`): the static relay — last DIRECT node on the
    /// SSSP path. Prefer it (skip in-between hops) BUT only if the
    /// packet FITS through its MTU; otherwise fall back to `nexthop`
    /// (immediate neighbor, always TCP-reachable). PROBEs always
    /// prefer `via` (tiny, and the point is to discover via's MTU).
    ///
    /// TCP if (`:974`): SPTPS_HANDSHAKE (ANS_KEY also propagates
    /// reflexive UDP addr); tcponly; relay too old (proto minor<4);
    /// or `origlen > relay->minmtu` (TCP fragments fine).
    ///
    /// `from_nid`: ORIGINAL source. For relay forwarding it's the
    /// original sender's NodeId — wire prefix carries THEIR src_id6.
    #[allow(clippy::too_many_lines)] // :967-974 decision tree
    pub(super) fn send_sptps_data_relay(
        &mut self,
        to_nid: NodeId,
        from_nid: NodeId,
        record_type: u8,
        ct: Option<&[u8]>,
    ) -> bool {
        // `ct` is None on the hot path: SPTPS frame at
        // tx_scratch[12..] from seal_data_into. Some(ct): relay/
        // handshake/probe path. C `:966`: origlen is plaintext body
        // length (relay's MTU measured at that layer).
        let ct_len = ct.map_or_else(|| self.tx_scratch.len() - 12, <[u8]>::len);
        let origlen = ct_len.saturating_sub(tinc_sptps::DATAGRAM_OVERHEAD);

        // C `:967`. Unreachable `to` would deref NULL in C; we drop.
        let Some(route) = self
            .last_routes
            .get(to_nid.0 as usize)
            .and_then(Option::as_ref)
        else {
            log::debug!(target: "tincd::net",
                        "No route to {}; dropping",
                        self.node_log_name(to_nid));
            return false;
        };
        let via_nid = route.via;
        let nexthop_nid = route.nexthop;

        // PROBE always prefers via (tiny + measures via's MTU); data
        // prefers via only if it FITS. minmtu=0 until discovery →
        // data goes hop-by-hop via nexthop until then (correct).
        let via_minmtu = self.tunnels.get(&via_nid).map_or(0, TunnelState::minmtu);
        let relay_nid = if via_nid != self.myself
            && (record_type == PKT_PROBE || origlen <= usize::from(via_minmtu))
        {
            via_nid
        } else {
            nexthop_nid
        };

        // C `:968`. Direct → wire prefix uses nullid for dst
        // (`:1013-1015`); recipient knows it's not a relay.
        let from_is_myself = from_nid == self.myself;
        let direct = from_is_myself && to_nid == relay_nid;

        // C `:969`: proto minor 4+ understands the 12-byte ID prefix.
        let relay_options = self
            .last_routes
            .get(relay_nid.0 as usize)
            .and_then(Option::as_ref)
            .map_or(0, |r| r.options);
        let relay_supported = (relay_options >> 24) >= 4;

        // C `:970`: EITHER side requesting tcponly forces TCP.
        // TODO(bitflags-opts): relay_options is u32 from tinc-graph Route;
        // .bits() shim until tinc-graph migrates / udp-info-carry lands.
        let tcponly =
            (self.myself_options.bits() | relay_options) & crate::proto::OPTION_TCPONLY != 0;

        // C `:974`. minmtu==0 means "unknown" not "zero"; C's
        // `origlen > relay->minmtu` with minmtu=0 → always TCP. We
        // go UDP optimistically until PMTU runs. Stricter-than-C:
        // C's TCP-first means first packet over a fresh relay drops
        // at mid's on_sptps_blob validkey gate; our UDP-first drops
        // at n.is_none() in handle_incoming_vpn_packet. Either way
        // first packet needs the dance to settle.
        let relay_minmtu = self.tunnels.get(&relay_nid).map_or(0, TunnelState::minmtu);
        let too_big =
            record_type != PKT_PROBE && relay_minmtu > 0 && origlen > usize::from(relay_minmtu);
        let go_tcp = record_type == tinc_sptps::REC_HANDSHAKE
            || tcponly
            || (!direct && !relay_supported)
            || too_big;

        if go_tcp {
            // C `:975-996`. Two sub-paths: SPTPS_PACKET (binary,
            // `:975-986`) for proto minor≥7; ANS_KEY/REQ_KEY (b64)
            // otherwise. `match` not `unwrap_or`: latter is eager,
            // would slice-panic on empty scratch even when ct=Some.
            let ct = match ct {
                Some(s) => s,
                None => &self.tx_scratch[12..],
            };

            let Some(conn_id) = self.conn_for_nexthop(to_nid) else {
                log::warn!(target: "tincd::net",
                           "No meta connection toward {}",
                           self.node_log_name(to_nid));
                return false;
            };
            let to_name = self
                .graph
                .node(to_nid)
                .map_or("<gone>", |n| n.name.as_str());
            let Some(conn) = self.conns.get_mut(conn_id) else {
                return false;
            };

            // C `:975-986` SPTPS_PACKET (binary). Handshakes stay on
            // b64 (ANS_KEY also propagates reflexive UDP addr; binary
            // doesn't). SPTPS_PACKET introduced in proto minor 7;
            // b64 is the universal fallback. C `send_meta_raw`
            // (`meta.c:99-112`) is buffer_add directly — NO SPTPS
            // framing (blob is already per-tunnel-encrypted).
            if record_type != tinc_sptps::REC_HANDSHAKE && conn.options.prot_minor() >= 7 {
                // C `protocol_misc.c:125-135`. RED first.
                if crate::tcp_tunnel::random_early_drop(
                    conn.outbuf.live_len(),
                    self.settings.maxoutbufsize,
                    &mut OsRng,
                ) {
                    return true; // C `:126` fake success
                }
                // C `:976-984`. The `direct⇒nullid` for dst is UDP-
                // only (`:1013-1015`); binary TCP path always uses
                // the real dst id (C `:976` is unconditional).
                let src_id = self.id6_table.id_of(from_nid).unwrap_or(NodeId6::NULL);
                let dst_id = self.id6_table.id_of(to_nid).unwrap_or(NodeId6::NULL);
                let frame = crate::tcp_tunnel::build_frame(dst_id, src_id, ct);
                // C `:129`
                let mut nw = conn.send(format_args!(
                    "{} {}",
                    Request::SptpsPacket as u8,
                    frame.len()
                ));
                nw |= conn.send_raw(&frame); // C `:133` RAW, no SPTPS
                return nw;
            }

            let b64 = tinc_crypto::b64::encode(ct);
            let from_name = if from_is_myself {
                self.name.clone()
            } else {
                self.graph
                    .node(from_nid)
                    .map_or("<gone>", |n| n.name.as_str())
                    .to_owned()
            };

            if record_type == tinc_sptps::REC_HANDSHAKE {
                // C `:995-996`: ANS_KEY. Only set incompression when
                // from==myself (relayed handshakes don't touch state).
                let my_compression = self.settings.compression;
                if from_is_myself {
                    self.tunnels.entry(to_nid).or_default().incompression = my_compression;
                }
                // C `net_packet.c:996`: `-1 -1 -1` are LITERAL string
                // (cipher/digest/maclen placeholders for SPTPS mode,
                // never read by ans_key_h). Byte-identical wire for
                // pcap-compare. tok.rs::lu accepts `-1` (glibc strtoul
                // "negate as unsigned" → u64::MAX).
                return conn.send(format_args!(
                    "{} {} {} {} -1 -1 -1 {}",
                    Request::AnsKey,
                    from_name,
                    to_name,
                    b64,
                    my_compression,
                ));
            }
            // C `:998`: REQ_KEY with reqno=SPTPS_PACKET. Receiver's
            // `req_key_ext_h` (`protocol_key.c:149-188`) decodes.
            return conn.send(format_args!(
                "{} {} {} {} {}",
                Request::ReqKey,
                from_name,
                to_name,
                Request::SptpsPacket as u8,
                b64,
            ));
        }

        // C `:1001-1054`. We always prefix (peers are ≥1.1).
        // C `:1012-1020`: direct ⇒ dst=nullid.
        let src_id = self.id6_table.id_of(from_nid).unwrap_or(NodeId6::NULL);
        let dst_id = if direct {
            NodeId6::NULL
        } else {
            self.id6_table.id_of(to_nid).unwrap_or(NodeId6::NULL)
        };
        // Hot path: overwrite 12-byte headroom in-place — zero
        // allocs/copies (C `net_packet.c:1027` pre-padding TODO;
        // they alloca+memcpy). Some(ct): relay/handshake — one body
        // memmove, alloc amortized to zero (scratch persists).
        if let Some(ct) = ct {
            self.tx_scratch.clear();
            self.tx_scratch.extend_from_slice(dst_id.as_bytes());
            self.tx_scratch.extend_from_slice(src_id.as_bytes());
            self.tx_scratch.extend_from_slice(ct);
        } else {
            self.tx_scratch[0..6].copy_from_slice(dst_id.as_bytes());
            self.tx_scratch[6..12].copy_from_slice(src_id.as_bytes());
        }

        // C `:1031-1040`: send to RELAY, not `to`. Fast path:
        // udp_addr_cached set when udp_confirmed flips; once
        // confirmed the answer is deterministic. Full choose_udp_
        // address was 2.18% self-time (Vec alloc + scan per packet).
        let cached = self
            .tunnels
            .get(&relay_nid)
            .and_then(|t| t.udp_addr_cached.clone());
        let cold_sockaddr;
        let (sockaddr, sock) = if let Some((sa, sock)) = &cached {
            (sa, *sock)
        } else {
            // Cold path: pre-confirmation discovery, send_locally
            // override, edge exploration.
            let Some((addr, sock)) = self.choose_udp_address(relay_nid) else {
                log::debug!(target: "tincd::net",
                            "No UDP address known for relay {}; dropping",
                            self.node_log_name(relay_nid));
                return false;
            };
            cold_sockaddr = socket2::SockAddr::from(addr);
            (&cold_sockaddr, sock)
        };

        // C `net_packet.c:920-946`: copy inner TOS to outer socket.
        // C does this in `send_udppacket` (legacy path); SPTPS path
        // never had it. We're SPTPS-only — different-from-C, but the
        // *feature* is what matters: without it, all encrypted traffic
        // gets default DSCP regardless of inner QoS marking.
        if self.settings.priorityinheritance {
            let prio = self.tx_priority;
            let sock_idx = usize::from(sock);
            if let Some(slot) = self.listeners.get_mut(sock_idx)
                && slot.last_tos != prio
            {
                slot.last_tos = prio;
                set_udp_tos(&slot.listener, sockaddr.is_ipv6(), prio);
            }
        }

        // C `:1044`
        if let Some(slot) = self.listeners.get(usize::from(sock))
            && let Err(e) = slot.listener.udp.send_to(&self.tx_scratch, sockaddr)
        {
            if e.kind() == io::ErrorKind::WouldBlock {
                // Drop; UDP is unreliable.
            } else if e.raw_os_error() == Some(libc::EMSGSIZE) {
                // C `:1046-1048`: EMSGSIZE = LOCAL kernel rejected
                // (interface MTU). Shrink relay's maxmtu. Don't log:
                // this IS the discovery mechanism.
                #[allow(clippy::cast_possible_truncation)] // origlen ≤ MTU
                let at_len = origlen as u16;
                if let Some(p) = self
                    .tunnels
                    .get_mut(&relay_nid)
                    .and_then(|t| t.pmtu.as_mut())
                {
                    let relay_name = self
                        .graph
                        .node(relay_nid)
                        .map_or("<gone>", |n| n.name.as_str());
                    for a in p.on_emsgsize(at_len) {
                        Self::log_pmtu_action(relay_name, &a);
                    }
                }
            } else {
                let relay_name = self.node_log_name(relay_nid);
                log::warn!(target: "tincd::net",
                               "Error sending UDP SPTPS packet to \
                                {relay_name}: {e}");
            }
        }
        false // UDP send doesn't touch any meta-conn outbuf
    }

    /// `route_arp` (`route.c:956-1023`).
    pub(super) fn handle_arp(&mut self, data: &[u8], from: Option<NodeId>) -> bool {
        // C `:964-967`: ARP from a peer in router mode is a misconfig
        // (their kernel shouldn't be ARPing across an L3 tunnel).
        if let Some(from_nid) = from {
            log::warn!(target: "tincd::net",
                       "Got ARP request from {} while in router mode!",
                       self.node_log_name(from_nid));
            return false;
        }
        // C `:960,977-984`
        let Some(target) = neighbor::parse_arp_req(data) else {
            // C `:984`
            log::debug!(target: "tincd::net",
                        "route: dropping ARP packet (not a valid request)");
            return false;
        };
        // C `:970-973`: snatch the kernel's MAC. parse_arp_req gated
        // data.len()≥42 so [6..12] is safe. C snatches BEFORE the
        // subnet lookup (and before the decrement_ttl gate at `:1004`
        // — which is dead for ARP anyway: do_decrement_ttl returns
        // true on non-IP ethertype).
        if self.overwrite_mac {
            self.mymac.copy_from_slice(&data[6..12]);
        }
        // C `:988-996`: no reachability check — ARP just answers
        // "does someone own this", not "are they up".
        let Some((_, owner)) = self.subnets.lookup_ipv4(&target, |_| true) else {
            log::debug!(target: "tincd::net",
                        "route: ARP for unknown {target}");
            return false;
        };
        // C `:999`: silently ignore ARPs for our own subnets — the
        // kernel already knows; replying would create a wrong
        // arp-cache entry pointing at the TUN.
        if owner == Some(&self.name) {
            return false;
        }
        // C `:1011-1022`
        let mut reply = neighbor::build_arp_reply(data);
        log::debug!(target: "tincd::net",
                    "route: ARP reply for {target} (owner {})",
                    owner.unwrap_or("(broadcast)"));
        if let Err(e) = self.device.write(&mut reply) {
            log::debug!(target: "tincd::net",
                        "Error writing ARP reply to device: {e}");
        }
        false
    }

    /// `route_neighborsol` (`route.c:793-954`).
    pub(super) fn handle_ndp(&mut self, data: &mut [u8], from: Option<NodeId>) {
        // C `:814-817`: NDP solicit from a peer in router mode —
        // misconfig (router-mode is L3; kernel shouldn't be doing
        // neighbor discovery across the tunnel).
        if let Some(from_nid) = from {
            log::warn!(target: "tincd::net",
                       "Got neighbor solicitation request from {} \
                        while in router mode!",
                       self.node_log_name(from_nid));
            return;
        }
        let Some(target) = neighbor::parse_ndp_solicit(data) else {
            log::debug!(target: "tincd::net",
                        "route: dropping NDP solicit (parse/checksum failed)");
            return;
        };
        // C `:830-832`: snatch the kernel's MAC. parse_ndp_solicit
        // gated data.len()≥78. C snatches BEFORE the subnet lookup;
        // the snatch is the only useful side effect even if no subnet
        // owns the target (we still learned the kernel's MAC).
        if self.overwrite_mac {
            self.mymac.copy_from_slice(&data[6..12]);
        }
        // C `:865-879`
        let Some((_, owner)) = self.subnets.lookup_ipv6(&target, |_| true) else {
            log::debug!(target: "tincd::net",
                        "route: NDP solicit for unknown {target}");
            return;
        };
        // C `:883`
        if owner == Some(&self.name) {
            return;
        }
        // C `:893-896`: decrement_ttl on the SOLICIT before building
        // the advert. Triple-gate: DecrementTTL=yes (rare) + NDP
        // (rarer) + the from-peer arm is unreachable here (gated
        // above). decrement_ttl(v6, hlim=255) → 254 in the original;
        // build_ndp_advert copies that hlim into the reply.
        if self.settings.decrement_ttl {
            match route::decrement_ttl(data) {
                TtlResult::Decremented | TtlResult::TooShort => {}
                TtlResult::DropSilent | TtlResult::SendIcmp { .. } => {
                    // C `:895`: `if(!do_decrement_ttl) return`. No
                    // ICMP synth (matches C — it just returns).
                    return;
                }
            }
        }
        // C `:890-948`
        let Some(mut reply) = neighbor::build_ndp_advert(data) else {
            return;
        };
        log::debug!(target: "tincd::net",
                    "route: NDP advert for {target} (owner {})",
                    owner.unwrap_or("(broadcast)"));
        if let Err(e) = self.device.write(&mut reply) {
            log::debug!(target: "tincd::net",
                        "Error writing NDP advert to device: {e}");
        }
    }

    /// v4/v6 dispatch on ethertype, not icmp_type: ICMP_DEST_UNREACH
    /// =3 collides with ICMP6_TIME_EXCEEDED=3 (bug audit `deef1268`).
    /// data.len()≥14 holds: every caller is post-route() (TooShort
    /// gate) or post-decrement_ttl.
    pub(super) fn write_icmp_to_device(&mut self, data: &[u8], icmp_type: u8, icmp_code: u8) {
        let now_sec = self.timers.now().duration_since(self.started_at).as_secs();
        if self.icmp_ratelimit.should_drop(now_sec, 3) {
            return;
        }
        // C `route.c:148-169`/`:254-275`: only TIME_EXCEEDED gets the
        // source-override dance — so traceroute shows OUR hop. This
        // helper's only caller is the TtlResult::SendIcmp arm, which
        // is always TIME_EXCEEDED, so do it unconditionally here.
        // orig src lives at fixed offsets: eth(14)+ip_src(12)=[26..30]
        // for v4, eth(14)+ip6_src(8)=[22..38] for v6. None on any
        // failure (slice short, kernel says no) → falls back to the
        // orig-dst-as-src behavior the C also falls back to.
        let ethertype = u16::from_be_bytes([data[12], data[13]]);
        let reply = if ethertype == 0x86DD {
            // ETH_P_IPV6
            let src = data
                .get(22..38)
                .and_then(|s| <[u8; 16]>::try_from(s).ok())
                .map(Ipv6Addr::from)
                .and_then(|a| match local_ip_facing(IpAddr::V6(a))? {
                    IpAddr::V6(v6) => Some(v6.octets()),
                    IpAddr::V4(_) => None,
                });
            icmp::build_v6_unreachable(data, icmp_type, icmp_code, None, src)
        } else {
            let src = data
                .get(26..30)
                .and_then(|s| <[u8; 4]>::try_from(s).ok())
                .map(Ipv4Addr::from)
                .and_then(|a| match local_ip_facing(IpAddr::V4(a))? {
                    IpAddr::V4(v4) => Some(v4.octets()),
                    IpAddr::V6(_) => None,
                });
            icmp::build_v4_unreachable(data, icmp_type, icmp_code, None, src)
        };
        if let Some(reply) = reply {
            log::debug!(target: "tincd::net",
                        "route: TTL exceeded, sending ICMP type={icmp_type} \
                         code={icmp_code} ({} bytes)", reply.len());
            self.write_icmp_reply(reply);
        }
    }

    /// `route.c:690` v4 FRAG_NEEDED. Separate helper: passes
    /// frag_mtu through (`:174 icmp_nextmtu`).
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
            None,
        ) {
            log::debug!(target: "tincd::net",
                        "route: FRAG_NEEDED, mtu={frag_mtu} ({} bytes)",
                        reply.len());
            self.write_icmp_reply(reply);
        }
    }

    /// `route.c:781` v6 PACKET_TOO_BIG (`:278-280` icmp6_mtu).
    pub(super) fn write_icmp_pkt_too_big(&mut self, data: &[u8], mtu: u32) {
        let now_sec = self.timers.now().duration_since(self.started_at).as_secs();
        if self.icmp_ratelimit.should_drop(now_sec, 3) {
            return;
        }
        if let Some(reply) =
            icmp::build_v6_unreachable(data, route::ICMP6_PACKET_TOO_BIG, 0, Some(mtu), None)
        {
            log::debug!(target: "tincd::net",
                        "route: PACKET_TOO_BIG, mtu={mtu} ({} bytes)",
                        reply.len());
            self.write_icmp_reply(reply);
        }
    }

    /// `send_packet(source=myself, ...)` (`net_packet.c:1556-1568`).
    pub(super) fn write_icmp_reply(&mut self, mut reply: Vec<u8>) {
        if let Err(e) = self.device.write(&mut reply) {
            log::debug!(target: "tincd::net",
                        "Error writing ICMP to device: {e}");
        }
    }
}

/// `route.c:148-169` (v4) / `:254-275` (v6). For ICMP TIME_EXCEEDED:
/// find our local IP facing the original sender so traceroute shows
/// us correctly. UDP `connect()` + `getsockname()` — no packets sent
/// (UDP connect is a route lookup + dst association). Same trick
/// `choose_initial_maxmtu` uses (`9e2540ab`).
///
/// Port is irrelevant (route lookup); use 1 (some kernels reject 0
/// for connect). The C ignores all errors and falls through to the
/// default; we do the same with `?` → `None`.
fn local_ip_facing(orig_src: IpAddr) -> Option<IpAddr> {
    let af = match orig_src {
        IpAddr::V4(_) => AddressFamily::Inet,
        IpAddr::V6(_) => AddressFamily::Inet6,
    };
    let sock = socket(af, SockType::Datagram, SockFlag::SOCK_CLOEXEC, None).ok()?;
    let ss = SockaddrStorage::from(SocketAddr::new(orig_src, 1));
    connect(sock.as_raw_fd(), &ss).ok()?;
    let local: SockaddrStorage = getsockname(sock.as_raw_fd()).ok()?;
    match orig_src {
        IpAddr::V4(_) => Some(IpAddr::V4(local.as_sockaddr_in()?.ip())),
        IpAddr::V6(_) => Some(IpAddr::V6(local.as_sockaddr_in6()?.ip())),
    }
}

/// `net_packet.c:920-946`: setsockopt `IP_TOS`/`IPV6_TCLASS`. Sets
/// the DSCP for OUTGOING UDP datagrams. `is_ipv6`: family of the
/// dest sockaddr (C `:922` switches on `sa->sa.sa_family`).
///
/// Log-on-error, never fail. C `:930,941` log at LOG_ERR; we log
/// at debug — a busy system flipping TOS per-packet would spam if
/// the kernel ever started rejecting these.
fn set_udp_tos(l: &Listener, is_ipv6: bool, prio: u8) {
    let optval: libc::c_int = libc::c_int::from(prio);
    let (level, optname, label) = if is_ipv6 {
        (libc::IPPROTO_IPV6, libc::IPV6_TCLASS, "IPV6_TCLASS")
    } else {
        (libc::IPPROTO_IP, libc::IP_TOS, "IP_TOS")
    };
    log::debug!(target: "tincd::net",
                "Setting outgoing packet priority to {prio} ({label})");
    // SAFETY: fd is live (Socket owns it); optval is a stack c_int
    // whose address+len we pass for the duration of the call.
    // truncation: size_of::<c_int>() == 4, fits socklen_t.
    #[allow(unsafe_code, clippy::cast_possible_truncation)]
    let rc = unsafe {
        libc::setsockopt(
            l.udp.as_raw_fd(),
            level,
            optname,
            (&raw const optval).cast::<libc::c_void>(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        log::debug!(target: "tincd::net",
                    "setsockopt {label} failed: {}",
                    io::Error::last_os_error());
    }
}

#[cfg(test)]
mod tos_tests {
    /// Cache-dedup logic: only setsockopt when changed. Tested as
    /// pure logic (the syscall itself is trusted; readback would
    /// need a real socket pair). C `net_packet.c:920`: `if(prio !=
    /// listen_socket[sock].priority)` then `:921` cache it.
    #[test]
    fn tos_cache_dedup() {
        let mut cache = [0u8; 2];
        let mut sets = 0;

        // Same packet TOS twice on sock 0 → one set.
        for prio in [0xb8, 0xb8] {
            if cache[0] != prio {
                cache[0] = prio;
                sets += 1;
            }
        }
        assert_eq!(sets, 1);

        // Flip-flop on sock 0 → two more sets.
        for prio in [0x00, 0xb8] {
            if cache[0] != prio {
                cache[0] = prio;
                sets += 1;
            }
        }
        assert_eq!(sets, 3);

        // sock 1 still untouched at 0.
        assert_eq!(cache[1], 0);
    }
}
