#[allow(clippy::wildcard_imports)]
use super::*;

use std::io::IoSliceMut;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use nix::errno::Errno;
use nix::sys::socket::{
    AddressFamily, MsgFlags, MultiHeaders, SockFlag, SockType, SockaddrStorage, connect,
    getsockname, recvmmsg, socket,
};

const UDP_RX_BATCH: usize = 64;

/// Device drain cap. `pub(super)` so `daemon::setup` can size the
/// arena. The 64-per-turn-then-yield is load-bearing (`0f120b11`:
/// over-draining starves the TUN reader of TX time — iperf3
/// saturating the device must not block UDP recv/meta-conn flush).
pub(super) const DEVICE_DRAIN_CAP: usize = 64;
/// Wire packets cap ~1700; 2KB oversize truncates and the SPTPS
/// decrypt fails (same outcome as the old stack buf).
const UDP_RX_BUFSZ: usize = 2048;

/// Persistent recvmmsg state. Heap-once, reuse-forever.
pub(crate) struct UdpRxBatch {
    /// 64 × 2KB packet buffers. Boxed so `Option<UdpRxBatch>` is
    /// `mem::take`-cheap (one ptr, not 128KB).
    bufs: Box<[[u8; UDP_RX_BUFSZ]; UDP_RX_BATCH]>,
    /// nix's `mmsghdr` + `sockaddr_storage` arrays.
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
    /// accept → tarpit-check → configure_tcp → allocate → register.
    pub(super) fn on_tcp_accept(&mut self, i: u8) {
        let listener = &self.listeners[usize::from(i)].listener;

        // socket2 accept4(SOCK_CLOEXEC) avoids fd leaks into script
        // children for free.
        let (sock, peer_sockaddr) = match listener.tcp.accept() {
            Ok(pair) => pair,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                // Spurious EAGAIN: peer connect+RST'd between epoll
                // wake and accept (TOCTOU).
                return;
            }
            Err(e) => {
                log::error!(target: "tincd::conn",
                            "Accepting a new connection failed: {e}");
                return;
            }
        };

        // V6ONLY is set so mapped addrs shouldn't appear;
        // canonicalize anyway for fmt_addr/tarpit. `as_socket()`
        // None is a kernel-bug-guard: log + dummy 0:0 (won't
        // false-tarpit or false-exempt; expect() would crash the
        // daemon for one bizarre accept).
        let peer = if let Some(sa) = peer_sockaddr.as_socket() {
            unmap(sa)
        } else {
            log::error!(target: "tincd::conn",
                        "accept returned non-IP family {:?}",
                        peer_sockaddr.family());
            (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
        };

        // Local conns never tick the buckets (`tinc info` queries
        // don't get tarpitted).
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

        // Configure BEFORE allocating the Connection so a configure
        // failure doesn't leave a half-registered slot.
        let fd = match configure_tcp(sock) {
            Ok(fd) => fd,
            Err(e) => {
                log::error!(target: "tincd::conn",
                            "configure_tcp failed for {peer}: {e}");
                return; // sock dropped (fd closed)
            }
        };

        let hostname = fmt_addr(&peer);
        let conn = Connection::new_meta(fd, hostname, peer, self.timers.now());
        let conn_fd = conn.fd();

        let id = self.conns.insert(conn);
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

    /// Wire layout: `[dst_id:6][src_id:6][sptps...]`. The 12-byte
    /// ID prefix is OUTSIDE SPTPS framing; `dst == nullid` means
    /// "direct to you".
    ///
    /// We're EPOLLET, so a full batch (64 returned) means "maybe
    /// more" → rearm so the next turn() picks them up after the rest
    /// of the event loop runs. Same drain semantics as the old
    /// `recv_from` loop's `UDP_DRAIN_CAP=64` (bug audit `deef1268`):
    /// 64 packets per turn, then yield to TUN-read/meta-conn/timers.
    /// iperf3 is TCP-over-tunnel — alice MUST get back to TUN reads
    /// or the send window fills and the whole thing stalls.
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
        // get a slice.
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
                        // u16 cast: UDP_RX_BUFSZ=2048 fits.
                        #[allow(clippy::cast_possible_truncation)]
                        let n = msg.bytes.min(UDP_RX_BUFSZ) as u16;
                        let peer = msg.address.as_ref().and_then(ss_to_std).map(unmap);
                        meta[idx] = (n, peer);
                    }
                    k
                }
                // EAGAIN ≡ EWOULDBLOCK on Linux (alias in nix).
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
        //
        // Phase 2b GRO TUN write: arm the coalescer for the duration
        // of this dispatch loop. `send_packet_myself` (the local-
        // delivery sink, hit via `route_packet` when the inner dst
        // is in our subnet) sees `gro_bucket.is_some()` and offers
        // the IP packet to it instead of writing immediately. Batch
        // boundary = coalesce window: flush after the loop, never
        // hold across recvmmsg calls (latency cap; the kernel's own
        // GRO has a similar napi-poll-quantum boundary).
        //
        // Only meaningful when count > 1 (single packet → nothing
        // to coalesce with; the bucket would round-trip it through a
        // memcpy for no win). And only when the device can take a
        // vnet_hdr super — see the `gro_enabled` gate at setup.
        let mut gro = if self.gro_enabled && count > 1 {
            self.gro_bucket_spare.take()
        } else {
            None
        };
        for (idx, &(n, peer)) in meta.iter().enumerate().take(count) {
            let n = usize::from(n);
            if n == 0 {
                continue;
            }
            let pkt = &batch.bufs[idx][..n];
            // Park the bucket in self for the duration of this one
            // packet's journey through handle_incoming_vpn_packet →
            // route_packet → send_packet_myself. Same out-and-back
            // as `rx_scratch`. Taken back below before the next
            // iteration so the local `gro` owns it across the loop.
            self.gro_bucket = gro.take();
            self.handle_incoming_vpn_packet(pkt, peer);
            gro = self.gro_bucket.take();
        }
        if let Some(mut bucket) = gro {
            self.gro_flush(&mut bucket);
            // 64KB stays warm for the next batch.
            self.gro_bucket_spare = Some(bucket);
        }

        count
    }

    /// Authenticates the immediate UDP sender before the relay
    /// branch. SRCID-fallback only fires when `dst==nullid` — a
    /// relay packet cannot bootstrap auth via SRCID. For direct
    /// receive, SRCID alone is fine (AEAD tag validates end-to-end);
    /// for relay we never decrypt, so this gate is the only thing
    /// stopping a 1:1 UDP reflector attack (security audit `2f72c2ba`).
    #[allow(clippy::too_many_lines)] // fast-path open_data_into + slow-path Vec<Output> fallback share the dst_id/src_id parse and the udp_addr-confirm logic
    pub(super) fn handle_incoming_vpn_packet(&mut self, pkt: &[u8], peer: Option<SocketAddr>) {
        // ─── DHT port-probe demux (Rust extension). Gate is source
        // addr, NOT `pkt[0]==b'd'`: SPTPS's first byte is dst_id6[0] =
        // sha512(name)[:6][0], uniformly random; ~1/256 of legitimate
        // traffic starts with 'd'. Spoofing a known target's source addr
        // is the same threat model as ADD_EDGE's unauthenticated addr.
        if let Some(peer) = peer
            && self.dht_probe_sent.contains(&peer)
            && let Some(reflexive) = crate::discovery::parse_port_probe_reply(pkt)
            && let Some(d) = self.discovery.as_mut()
        {
            if d.set_reflexive_v4(reflexive) {
                log::info!(target: "tincd::discovery",
                           "port probe: tincd reflexive v4 = {reflexive}");
            }
            return;
        }

        if pkt.len() < 12 {
            log::debug!(target: "tincd::net",
                        "Dropping {}-byte UDP packet (too short for ID prefix)",
                        pkt.len());
            return;
        }
        let dst_id = NodeId6::from_bytes(pkt[0..6].try_into().unwrap());
        let src_id = NodeId6::from_bytes(pkt[6..12].try_into().unwrap());
        let ct = &pkt[12..];

        // O(nodes) scan is fine (relay is the rare branch).
        // `n.is_some()` ≡ "this UDP src addr belongs to a node that
        // has confirmed UDP with us".
        let n: Option<NodeId> = peer.and_then(|peer_addr| {
            self.tunnels.iter().find_map(|(&nid, t)| {
                (t.status.udp_confirmed && t.udp_addr == Some(peer_addr)).then_some(nid)
            })
        });

        // No decrypt-by-trial for legacy packets (no NodeId6 prefix)
        // or the ~never NodeId6 collision case (sha512(name)[:6],
        // birthday on 48 bits). SPTPS-only build — log + drop.
        let Some(from_nid) = self.id6_table.lookup(src_id) else {
            log::debug!(target: "tincd::net",
                        "Received UDP packet from unknown source ID {src_id} ({peer:?})");
            return;
        };
        let from_name = self.node_log_name(from_nid).to_owned();

        // `dst==null` → direct-to-us. `dst!=null`: either still for
        // us (sender didn't know we're a direct neighbor) or a relay
        // packet we forward.
        if !dst_id.is_null() {
            let Some(to_nid) = self.id6_table.lookup(dst_id) else {
                log::debug!(target: "tincd::net",
                            "Received UDP relay packet from {from_name} \
                             with unknown dst ID {dst_id}");
                return;
            };
            // dst just became unreachable (race).
            if !self.graph.node(to_nid).is_some_and(|n| n.reachable) {
                log::debug!(target: "tincd::net",
                            "Cannot relay UDP packet from {from_name}: \
                             dst {dst_id} is unreachable");
                return;
            }
            // Hot relay path. `from_nid` so the wire prefix carries
            // the ORIGINAL source ID.
            if to_nid != self.myself {
                // Unauthenticated sender cannot relay. Without this
                // gate anyone who knows two node names can use us as
                // a 1:1 UDP reflector (security audit `2f72c2ba`).
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
            // receive. Packet arrived via a dynamic relay; if WE're
            // the static relay tell `from` where they're reachable
            // so next packet skips the dynamic relay. Gated to
            // static-relay-only so every hop in a chain doesn't emit
            // its own hint.
            let from_via = self
                .last_routes
                .get(from_nid.0 as usize)
                .and_then(Option::as_ref)
                .map(|r| r.via);
            // Non-null dst_id6 means SOMEONE relayed (if `from`
            // itself, the prefix would be null).
            if from_via == Some(self.myself) && self.send_udp_info(from_nid, &from_name, true) {
                self.maybe_set_write_any();
            }
        }

        let tunnel = self.tunnels.entry(from_nid).or_default();
        let Some(sptps) = tunnel.sptps.as_deref_mut() else {
            // UDP packet before handshake started; kick send_req_key
            // (harmless if one's already in flight).
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

        // The bit tells `receive_sptps_record` this came via UDP (vs
        // TCP-tunneled). Dispatch is AFTER (Vec<Output> return), so
        // defer the clear below.
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
                // Only direct (dst == nullid) confirms udp_addr;
                // relayed-to-us would cache the relay's addr. Once
                // confirmed at the same address this is a no-op:
                // skip the listener Vec alloc + adapt_socket scan.
                //
                // Gate on `cached.is_none() OR addr changed`, NOT just
                // addr changed. `gossip.rs:803` (BecameReachable) and
                // `txpath.rs:1027` (UDP_INFO) seed `udp_addr` from
                // edge_addr while clearing `udp_addr_cached`. If the
                // peer then sends from that same addr (common: edge
                // addr IS the source addr in a direct setup), the old
                // `udp_addr != Some(peer_addr)` gate was false and the
                // cache stayed None forever — every send fell through
                // to `choose_udp_address` (the "2.18% self-time" cold
                // path this cache was built to avoid).
                let direct = dst_id.is_null();
                if let Some(peer_addr) = peer.filter(|_| direct)
                    && (tunnel.udp_addr_cached.is_none() || tunnel.udp_addr != Some(peer_addr))
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
                // Clear udppacket here so the borrow of `tunnel` ends
                // before receive_sptps_record_fast takes &mut self.
                tunnel.status.udppacket = false;

                // send_mtu_info if relayed-to-us.
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
                // Tunnel-stuck restart, gated 10s.
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

        // `direct` set true ONLY when dst_id == nullid. When
        // `dst != null && to == myself` (relayed-to-us), `peer_addr`
        // is the RELAY's address; caching it would route the next
        // direct send to the relay forever (bug audit `deef1268`).
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
        // Tell `from` our MTU floor so they can switch to direct
        // UDP. Bug audit `deef1268`: was missing entirely.
        if !direct {
            let nw = self.send_mtu_info(from_nid, &from_name, i32::from(MTU), true);
            if nw {
                self.maybe_set_write_any();
            }
        }

        let nw = self.dispatch_tunnel_outputs(from_nid, &from_name, outs);
        // Clear udppacket (deferred, see above).
        if let Some(t) = self.tunnels.get_mut(&from_nid) {
            t.status.udppacket = false;
        }
        if nw {
            self.maybe_set_write_any();
        }
    }

    /// We drain because mio is edge-triggered — returning before
    /// EAGAIN loses the wake forever. Bounded so iperf3 saturating
    /// the TUN doesn't starve meta-conn flush/UDP recv/timers.
    ///
    /// Phase 0 (`RUST_REWRITE_10G.md`): same loop body, but the
    /// per-read `device.read(&mut stack_buf)` becomes one
    /// `device.drain(&mut arena, cap)` returning N frames in arena
    /// slots. The default `drain()` IS `read()`-in-a-loop — byte-for-
    /// byte the same syscall sequence on bsd/linux/fd backends. The
    /// seam is in place for Phase 2 (vnet_hdr device returns `Super`).
    #[allow(clippy::too_many_lines)] // three drain-result arms; the
    // `Super` arm is the Phase-2a TSO-split path. Factoring it out
    // would mean threading `arena`/`nw`/`tx_batch` through a helper;
    // the control flow reads cleaner inline.
    pub(super) fn on_device_read(&mut self) {
        let mut nw = false;
        // EPOLLET drain loop. The default `Device::drain` loops
        // INTERNALLY until EAGAIN or cap; one call suffices. The
        // vnet_hdr drain reads ONE skb (`Super` or `Frames{1}`)
        // per call — looping HERE keeps the EPOLLET contract
        // (return to epoll only after EAGAIN). Bounded so a
        // saturating sender doesn't starve UDP/timers (`0f120b11`).
        //
        // The `Frames` arm with the default drain hits this loop
        // once: it returns count<cap (drained to EAGAIN, the second
        // iteration sees `Empty`) or count==cap (we break out of
        // the loop and rearm below). Either way, no behavior change
        // for the non-vnet path.
        let mut iters = 0usize;
        let mut hit_cap = false;
        // tx_batch armed ACROSS outer-loop iterations. The Phase-1
        // batch-then-ship logic was designed for one drain returning
        // N frames; the vnet path returns 1 frame per drain but
        // multiple drains per epoll wake. The burst is in `iters`,
        // not `count`. Arm here, ship after the loop.
        //
        // The non-vnet path is unchanged: it hits the loop once with
        // count>1, the Frames arm flushes inline (so the sendmsg
        // happens before this fn returns either way), and the
        // post-loop flush is a no-op on an already-empty batch.
        let mut batch_armed = false;
        while iters < DEVICE_DRAIN_CAP {
            iters += 1;
            // mem::take: `route_packet` borrows `&mut self`; the
            // arena slot borrow conflicts. Same dance as
            // `udp_rx_batch`. The arena is `Some` between calls
            // (set in `setup`, never taken elsewhere).
            let mut arena = self
                .device_arena
                .take()
                .expect("device_arena is Some between on_device_read calls");

            let result = match self.device.drain(&mut arena, DEVICE_DRAIN_CAP) {
                Ok(r) => r,
                Err(e) => {
                    // 10 consecutive failures → exit. No sleep-on-
                    // error backoff (bound is 10, sleep would total
                    // 2.75s then exit anyway).
                    log::error!(target: "tincd::net",
                                "Error reading from device: {e}");
                    self.device_errors += 1;
                    if self.device_errors > 10 {
                        log::error!(target: "tincd",
                                    "Too many errors from device, exiting!");
                        self.running = false;
                    }
                    self.device_arena = Some(arena);
                    if nw {
                        self.maybe_set_write_any();
                    }
                    return;
                }
            };

            match result {
                tinc_device::DrainResult::Empty => {
                    // EAGAIN. Queue drained; we hold the EPOLLET
                    // contract. Put arena back, exit the loop.
                    self.device_arena = Some(arena);
                    break;
                }
                tinc_device::DrainResult::Frames { count } => {
                    self.device_errors = 0;
                    // Phase 1 (`RUST_REWRITE_10G.md`): same per-frame
                    // route+encrypt loop, but the SEND is deferred.
                    // `tx_batch` being `Some` signals the send site
                    // (`send_sptps_data_relay` UDP path) to stage
                    // instead of `sendto`. After the loop, ship the
                    // accumulated run in one `EgressBatch` (one
                    // `sendmsg` with `UDP_SEGMENT` cmsg on Linux).
                    //
                    // The encrypt still goes into `tx_scratch` per-
                    // frame (Phase 0 unchanged); the batch COPIES from
                    // there. One extra ~1.5KB memcpy per frame vs
                    // 43× fewer syscalls. Phase 3 (par-encrypt) will
                    // encrypt directly into batch slots; for now the
                    // memcpy is the price of not restructuring
                    // `seal_data_into`'s Vec-based API.
                    //
                    // Lazy init: the ~100KB buffer only allocates the
                    // first time a device read fires. A tunnelserver
                    // (no local TUN) never gets here.
                    //
                    // Arm tx_batch when there's a burst to coalesce.
                    // "Burst" = either count>1 (default drain batched
                    // multiple frames) OR iters>1 (vnet drain returned
                    // Frames{1} multiple times this epoll wake — bob's
                    // ACK-burst case). An idle ping fires epoll per-
                    // frame, hits count==1 && iters==1, falls through
                    // to Phase-0 immediate send (no memcpy tax).
                    //
                    // Once armed, stays armed across outer iterations:
                    // the vnet's Frames{1}-then-Frames{1}-then-Super
                    // sequence accumulates into one sendmsg.
                    if !batch_armed && (count > 1 || iters > 1) {
                        if self.tx_batch.is_none() {
                            self.tx_batch = Some(crate::egress::TxBatch::new(
                                DEVICE_DRAIN_CAP
                                    * (12 + usize::from(MTU) + tinc_sptps::DATAGRAM_OVERHEAD),
                            ));
                        }
                        batch_armed = true;
                    }
                    for i in 0..count {
                        let n = arena.lens()[i];
                        let myself_tunnel = self.tunnels.entry(self.myself).or_default();
                        myself_tunnel.in_packets += 1;
                        myself_tunnel.in_bytes += n as u64;

                        // `slot_mut` because route_packet mutates
                        // (overwrite_mac, fragment in-place). The send
                        // site sees `tx_batch.is_some()` and stages;
                        // or flushes-then-stages on dst/size mismatch;
                        // or falls through to immediate send for the
                        // cold path (no `udp_addr_cached`).
                        nw |= self.route_packet(&mut arena.slot_mut(i)[..n], None);
                    }
                    // count>1: default drain already drained to
                    // EAGAIN (or hit cap). Ship now. The vnet
                    // count==1 case ships AFTER the outer loop
                    // (accumulating across iterations).
                    if count > 1 {
                        self.flush_tx_batch();
                    }
                    self.device_arena = Some(arena);
                    if count == DEVICE_DRAIN_CAP {
                        hit_cap = true;
                        break;
                    }
                    // count < cap: the default drain looped to EAGAIN
                    // internally. We're done (the next outer iteration
                    // would just see Empty). Exit the loop. The vnet
                    // drain returns Frames{1} for GSO_NONE — we DO
                    // need to loop for those (the next read might be
                    // another GSO_NONE or a Super).
                    if count > 1 {
                        // count>1 only happens with the default drain
                        // (it batched). It already drained to EAGAIN.
                        break;
                    }
                    // count==1: vnet GSO_NONE. Loop again.
                }
                tinc_device::DrainResult::Super {
                    len,
                    gso_size,
                    gso_type,
                    csum_start,
                    csum_offset,
                } => {
                    // Phase 2a (`RUST_REWRITE_10G.md`): the vnet_hdr
                    // device put a ≤64KB TCP super-segment in `arena`.
                    // `tso_split` re-segments it into MTU-sized frames
                    // with re-synthesized TCP/IP headers. `route_packet`
                    // runs ONCE (chunk[0]; same dst for all chunks — TSO
                    // is single-flow) then the rest skip the trie lookup.
                    self.device_errors = 0;

                    // Lazy alloc the scratch (first Super only).
                    let scratch = self.tso_scratch.get_or_insert_with(|| {
                        vec![0u8; DEVICE_DRAIN_CAP * tinc_device::DeviceArena::STRIDE]
                            .into_boxed_slice()
                    });
                    // Same `mem::take` dance as `device_arena`:
                    // `route_packet` borrows `&mut self`, the slice
                    // borrow conflicts.
                    let mut scratch = std::mem::take(scratch);
                    let mut tso_lens = std::mem::take(&mut self.tso_lens);

                    let hdr = tinc_device::VirtioNetHdr {
                        flags: 0,    // unused by tso_split (it always csums)
                        gso_type: 0, // ditto; gso_type passed separately
                        hdr_len: 0,  // recomputed from csum_start + tcp doff
                        gso_size,
                        csum_start,
                        csum_offset,
                    };
                    let split = tinc_device::tso_split(
                        &arena.as_contiguous()[..len],
                        &hdr,
                        gso_type,
                        &mut scratch,
                        tinc_device::DeviceArena::STRIDE,
                        &mut tso_lens,
                    );
                    match split {
                        Ok(count) => {
                            // Same TX-batch staging as `Frames`. Gate on
                            // count>1 (one segment = no batch advantage).
                            if count > 1 && self.tx_batch.is_none() {
                                self.tx_batch = Some(crate::egress::TxBatch::new(
                                    DEVICE_DRAIN_CAP
                                        * (12 + usize::from(MTU) + tinc_sptps::DATAGRAM_OVERHEAD),
                                ));
                            }
                            // Stats: count the super-packet as one ingest
                            // (the "read() drops 30×" gate metric counts
                            // syscalls, not stat increments). Bytes = the
                            // raw IP payload we got from the kernel.
                            let myself_tunnel = self.tunnels.entry(self.myself).or_default();
                            myself_tunnel.in_packets += 1;
                            myself_tunnel.in_bytes += len as u64;

                            // The win: `route_packet` runs once per super.
                            // The first call does the trie lookup; the
                            // rest reuse the same dst (TSO is single-flow,
                            // mixed-dst super-packets don't exist — the
                            // kernel TCP stack segments per-socket).
                            //
                            // BUT: route_packet has side effects per-packet
                            // (TX stats, PMTU drive via try_tx, the dense
                            // batch staging). Calling it once and looping
                            // would mean rewriting the send path. For now:
                            // call it `count` times. The 0.94µs→0.56µs
                            // "other" projection assumed the trie lookup
                            // amortizes; it does (same `last_routes[]`
                            // index), and that's the expensive half.
                            //
                            // Re-profile after this lands: if `route_packet`
                            // overhead is still visible, factor a
                            // `route_first_then_send_rest` that hoists the
                            // dst out. ~+40 LOC; not yet.
                            for i in 0..count {
                                let n = tso_lens[i];
                                let off = i * tinc_device::DeviceArena::STRIDE;
                                nw |= self.route_packet(&mut scratch[off..off + n], None);
                            }
                            // Ship the super's segments. The post-loop
                            // flush below is a no-op on empty.
                            self.flush_tx_batch();
                        }
                        Err(e) => {
                            // Kernel-contract violation (vnet_hdr describes
                            // a packet shape that doesn't match the bytes)
                            // or undersized scratch (gso_size tiny). Log +
                            // drop. Inner-TCP retransmits.
                            log::warn!(target: "tincd::net",
                                   "tso_split: {e:?} (len={len} \
                                    gso_size={gso_size}); dropping");
                        }
                    }

                    self.tso_scratch = Some(scratch);
                    self.tso_lens = tso_lens;
                    self.device_arena = Some(arena);

                    // One Super = ~30-43 frames worth. Count it against
                    // the iteration budget as if it were a Frames{cap}
                    // — we don't want 64× super-packets per epoll wake
                    // (that's 64×43 = 2752 frames; encrypt/send would
                    // run for milliseconds, starving recv). One Super
                    // per wake is the design; loop only to drain the
                    // tail (the GSO_NONE ACKs that pile up behind).
                    hit_cap = true;
                    break;
                }
            } // match result
        } // while iters

        // Ship anything accumulated across vnet Frames{1} iterations.
        // No-op for the non-vnet path (count>1 arm flushed already)
        // and for the iters==1 idle-ping case (batch never armed).
        // Disarm so UDP-recv→forward / meta-conn→relay / probes go
        // back to Phase-0 immediate-send outside this fn.
        if batch_armed {
            self.flush_tx_batch();
            self.tx_batch = None;
        }
        // Hit cap (or Super): there MAY be more queued. Rearm so
        // the next epoll cycle checks. With EPOLLET, the rearm
        // (epoll_ctl MOD) doesn't generate a synthetic wake, but
        // mio's underlying registration uses EPOLLONESHOT-style
        // semantics where the MOD does trigger a fresh check on
        // the next epoll_wait. (If this is wrong and we still
        // stall: the daemon's 1s ping tick will eventually call
        // here and unwedge. Degraded but not deadlocked.)
        if hit_cap
            && let Some(io_id) = self.device_io
            && let Err(e) = self.ev.rearm(io_id)
        {
            log::error!(target: "tincd::net",
                        "device fd rearm failed: {e}");
        }
        if nw {
            self.maybe_set_write_any();
        }
    }

    /// Ship the staged TX batch (Phase 1). Called at the end of
    /// `on_device_read`'s drain loop and on dst/size mismatch
    /// mid-loop. No-op on empty.
    fn flush_tx_batch(&mut self) {
        if let Some(mut b) = self.tx_batch.take() {
            Self::ship_tx_batch(&mut b, &mut self.listeners, &mut self.tunnels, &self.graph);
            self.tx_batch = Some(b);
        }
    }

    /// Ship one batch run. Static + explicit field borrows so the
    /// mid-loop flush (in `send_sptps_data_relay`, while
    /// `tx_scratch` is also borrowed) doesn't fight `&mut self`.
    /// Same `EMSGSIZE`/`WouldBlock` dispatch as the immediate-send
    /// path; the wire result is identical to `count` immediate
    /// sends, so the error handling is too.
    fn ship_tx_batch(
        batch: &mut crate::egress::TxBatch,
        listeners: &mut [super::ListenerSlot],
        tunnels: &mut crate::inthash::IntHashMap<NodeId, TunnelState>,
        graph: &tinc_graph::Graph,
    ) {
        let Some((b, sock, relay_nid, origlen)) = batch.take() else {
            return;
        };
        // Ship, then let `b` (which borrows `batch.buf`/`batch.dst`)
        // fall out of scope before `reset` mutates `batch`.
        let result = {
            let r = listeners
                .get_mut(usize::from(sock))
                .map(|slot| slot.egress.send_batch(&b));
            let _ = b;
            r
        };
        batch.reset();

        let Some(result) = result else {
            // Listener gone (reload mid-batch). Same as the
            // immediate path's `listeners.get_mut` returning None:
            // silently drop. UDP is unreliable.
            return;
        };
        if let Err(e) = result {
            if e.kind() == io::ErrorKind::WouldBlock {
                // sndbuf full. Drop the whole run — same outcome
                // as the per-frame path dropping each one. The
                // kernel's UDP sndbuf doesn't partial-accept a
                // GSO send (`udp_send_skb` is all-or-nothing).
            } else if e.raw_os_error() == Some(libc::EMSGSIZE) {
                // PMTU shrank under us. Shrink the relay's maxmtu
                // so the NEXT batch's stride is smaller. The frames
                // in THIS batch are lost (the kernel rejected the
                // whole sendmsg) — same as the per-frame path losing
                // one frame, just `count×` at once. Inner-TCP
                // retransmits.
                if let Some(p) = tunnels.get_mut(&relay_nid).and_then(|t| t.pmtu.as_mut()) {
                    let relay_name = graph.node(relay_nid).map_or("<gone>", |n| n.name.as_str());
                    for a in p.on_emsgsize(origlen) {
                        Self::log_pmtu_action(relay_name, &a);
                    }
                }
            } else {
                let relay_name = graph.node(relay_nid).map_or("<gone>", |n| n.name.as_str());
                log::warn!(target: "tincd::net",
                           "Error sending UDP SPTPS batch to \
                            {relay_name}: {e}");
            }
        }
    }

    /// `from`: `None` = device read; `Some` = peer. Returns the
    /// io_set signal.
    pub(super) fn route_packet(&mut self, data: &mut [u8], from: Option<NodeId>) -> bool {
        // pcap is FIRST — a tap, sees everything (incl. kernel-mode
        // forward, runt frames, ARP). The cheap-gate is the field
        // load; `send_pcap` walks conns only when armed (debugging).
        let mut nw = false;
        if self.any_pcap {
            nw |= self.send_pcap(data);
        }

        // Kernel-mode shortcut — peer traffic straight to TUN, OS
        // forwarding table decides. Packets from our device still
        // route (we're the originator). BEFORE the length check
        // (device.write rejects short).
        if self.settings.forwarding_mode == ForwardingMode::Kernel && from.is_some() {
            self.send_packet_myself(data);
            return nw;
        }

        match self.settings.routing_mode {
            RoutingMode::Switch => {
                return nw | self.route_packet_mac(data, from);
            }
            RoutingMode::Hub => {
                // Always broadcast, no learning.
                return nw | self.dispatch_route_result(RouteResult::Broadcast, data, from);
            }
            RoutingMode::Router => {}
        }

        // ARP intercept. ROUTER-ONLY (Switch treats ARP as opaque
        // eth, returned above). `handle_arp` does its own subnet
        // lookup so handle it before `route()` (which would return
        // `Unsupported{"arp"}`).
        if data.len() >= 14 && u16::from_be_bytes([data[12], data[13]]) == crate::packet::ETH_P_ARP
        {
            return nw | self.handle_arp(data, from);
        }

        // DNS stub intercept (Rust-only). Tailscale's trick: no
        // socket bind, just match `dst==magic && dport==53` on TUN
        // ingress (`wgengine/netstack/netstack.go:847-858`). ROUTER-
        // mode + device-read only — `from.is_some()` means a peer
        // sent us a DNS query, which is either misconfig (their
        // resolved is pointed at OUR magic IP) or weird; let it hit
        // route() and Forward/Unreachable normally. The `is_some()`
        // gate is the cheap path: feature off = one branch.
        if from.is_none() && self.dns.is_some() && self.try_dns_intercept(data) {
            return nw;
        }

        // Close over node_ids+graph and gate on reachability.
        // `myself` is always reachable, so the "only check reachable
        // for REMOTE owners" falls out without an explicit string
        // compare.
        let node_ids = &self.node_ids;
        let graph = &self.graph;
        let result = route(data, &self.subnets, |name| {
            let nid = *node_ids.get(name)?;
            graph.node(nid).filter(|n| n.reachable).map(|_| nid)
        });

        nw | self.dispatch_route_result(result, data, from)
    }

    /// Walk pcap subscribers, emit `"18 14 LEN\n"` + raw packet
    /// body to each. The body is the FULL eth frame.
    ///
    /// Recomputes `any_pcap` as it walks: clears the flag at the
    /// top, then sets it for each live subscriber. If a subscriber
    /// dropped, the NEXT packet's walk finds zero and clears the
    /// gate — `terminate()` stays ignorant. One wasted walk per
    /// disconnect; cheap (conns is ~5).
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
        let mut still_armed = false;
        for (_, conn) in &mut self.conns {
            if !conn.pcap {
                continue;
            }
            still_armed = true;

            // snaplen=0 → no clip.
            let snap = usize::from(conn.pcap_snaplen);
            let len = if snap != 0 && snap < data.len() {
                snap
            } else {
                data.len()
            };

            // Control conns are plaintext (`conn.sptps` is None), so
            // `send` formats straight to outbuf.
            nw |= conn.send(format_args!(
                "{} {} {len}",
                tinc_proto::Request::Control as u8,
                crate::proto::REQ_PCAP
            ));
            // Raw body, no `\n`. `send` is infallible (queues to
            // outbuf, write errors surface at `flush()`).
            nw |= conn.send_raw(&data[..len]);
        }
        self.any_pcap = still_armed;
        nw
    }

    /// Switch-mode dispatch.
    fn route_packet_mac(&mut self, data: &mut [u8], from: Option<NodeId>) -> bool {
        let from_myself = from.is_none();
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

        // LearnAction and routing are independent.
        let mut nw = false;
        match learn {
            route_mac::LearnAction::NotOurs => {}
            route_mac::LearnAction::New(mac) => {
                nw |= self.learn_mac(mac);
            }
            route_mac::LearnAction::Refresh(mac) => {
                // route_mac's snapshot isn't myself-scoped — check.
                if self.mac_table.get(&mac).map(String::as_str) == Some(self.name.as_str()) {
                    let now = self.timers.now();
                    self.mac_leases.refresh(mac, now, self.settings.macexpire);
                } else {
                    // Remotely owned → VM migrated to us.
                    nw |= self.learn_mac(mac);
                }
            }
        }

        nw |= self.dispatch_route_result(result, data, from);
        nw
    }

    /// New source MAC on TAP → Subnet::Mac + broadcast ADD_SUBNET +
    /// arm age_subnets timer.
    fn learn_mac(&mut self, mac: route_mac::Mac) -> bool {
        log::info!(target: "tincd::net",
                   "Learned new MAC address \
                    {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

        let subnet = Subnet::Mac {
            addr: mac,
            weight: 10,
        };
        let myname = self.name.clone();
        self.subnets.add(subnet, myname.clone());
        self.mac_table.insert(mac, myname.clone());
        self.run_subnet_script(true, &myname, &subnet);

        // learn() returns true if table was empty.
        let now = self.timers.now();
        let arm_timer = self.mac_leases.learn(mac, now, self.settings.macexpire);

        let mut nw = false;
        let targets = self.broadcast_targets(None);
        for cid in targets {
            nw |= self.send_subnet(cid, Request::AddSubnet, &myname, &subnet);
        }

        // Arm only when learn() says table was empty AND no slot
        // (defensive).
        if arm_timer && self.age_subnets_timer.is_none() {
            let tid = self.timers.add(TimerWhat::AgeSubnets);
            self.timers.set(tid, Duration::from_secs(10));
            self.age_subnets_timer = Some(tid);
        }

        nw
    }

    /// The local-delivery half: write to the device, with the
    /// `overwrite_mac` stamp gated on Mode=router + TAP-ish device.
    /// Factored out so the kernel-mode shortcut, broadcast echo, and
    /// `Forward{to:myself}` arms all hit the same stamp.
    fn send_packet_myself(&mut self, data: &mut [u8]) {
        // Dest MAC ← the kernel's own (snatched from ARP/NDP);
        // source MAC ← dest XOR 0xFF on the last byte ("arbitrary
        // fake source" — just-different so the kernel doesn't see
        // its own MAC as src). data.len()≥12 holds at every callsite
        // (post-route or post-checklength).
        if self.overwrite_mac && data.len() >= 12 {
            data[0..6].copy_from_slice(&self.mymac);
            data[6..12].copy_from_slice(&self.mymac);
            data[11] ^= 0xFF;
        }
        let len = data.len() as u64;
        let myself_tunnel = self.tunnels.entry(self.myself).or_default();
        myself_tunnel.out_packets += 1;
        myself_tunnel.out_bytes += len;

        // ─── Phase 2b GRO write ────────────────────────────────────
        // Armed only inside `recvmmsg_batch`'s dispatch loop. The
        // other call sites (broadcast echo, kernel-mode forward,
        // ICMP unreachable) reach here with `gro_bucket = None` and
        // fall through to the immediate write.
        //
        // `data` is `[synth eth(14)][IP]` — the offer wants raw IP.
        // The eth header is throwaway in TUN mode anyway (the
        // existing `device.write` stomps it for the vnet_hdr stomp).
        if let Some(mut bucket) = self.gro_bucket.take() {
            use tinc_device::GroVerdict;
            const ETH_HLEN: usize = 14;
            if data.len() > ETH_HLEN {
                match bucket.offer(&data[ETH_HLEN..]) {
                    GroVerdict::Coalesced => {
                        self.gro_bucket = Some(bucket);
                        return; // absorbed; written on flush
                    }
                    GroVerdict::FlushFirst => {
                        // Ship the run, then re-offer. The packet
                        // is a valid candidate (passed all the
                        // shape checks), it just doesn't fit —
                        // different ack, seq gap, post-PSH. Seeding
                        // it now starts the NEXT run.
                        self.gro_flush(&mut bucket);
                        let v = bucket.offer(&data[ETH_HLEN..]);
                        // Either it seeds the empty bucket
                        // (Coalesced) or some race made it stop
                        // qualifying (NotCandidate, can't happen
                        // with an immutable slice but we don't
                        // build correctness on that). Never
                        // FlushFirst on an empty bucket.
                        debug_assert_ne!(v, GroVerdict::FlushFirst);
                        self.gro_bucket = Some(bucket);
                        if v == GroVerdict::Coalesced {
                            return;
                        }
                        // NotCandidate: fall through to write.
                    }
                    GroVerdict::NotCandidate => {
                        // Non-TCP, FIN/SYN/RST, pure-ACK, fragment,
                        // IP options. Ordering: anything already in
                        // the bucket goes out FIRST. Same-flow stuff
                        // can't be in the bucket (would've been a
                        // key mismatch → FlushFirst), but a non-
                        // candidate from the SAME flow (e.g. a FIN)
                        // mustn't reorder past data with lower seq.
                        self.gro_flush(&mut bucket);
                        self.gro_bucket = Some(bucket);
                    }
                }
            } else {
                self.gro_bucket = Some(bucket);
            }
        }

        if let Err(e) = self.device.write(data) {
            log::debug!(target: "tincd::net", "Error writing to device: {e}");
        }
    }

    /// Ship the GRO bucket. `bucket.flush()` finalizes vnet_hdr +
    /// IP totlen/csum; `device.write_super` is a raw fd write.
    /// `Unsupported` here means `gro_enabled` was wrong at setup
    /// (the gate is supposed to make this unreachable). Log at
    /// `warn` not `debug`: it's a daemon bug, not a transient.
    fn gro_flush(&mut self, bucket: &mut tinc_device::GroBucket) {
        if let Some(buf) = bucket.flush()
            && let Err(e) = self.device.write_super(buf)
        {
            log::warn!(target: "tincd::net",
                       "GRO super write failed: {e} — \
                        gro_enabled gate let a non-vnet device through?");
        }
    }

    fn broadcast_packet(&mut self, data: &mut [u8], from: Option<NodeId>) -> bool {
        // Echo a forwarded broadcast to local kernel.
        if from.is_some() {
            self.send_packet_myself(data);
        }

        // Tunnelserver: MST might be invalid (filtered ADD_EDGE →
        // loops). BMODE_NONE: opted out.
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

        let target_nids: Vec<NodeId> = match self.settings.broadcast_mode {
            broadcast::BroadcastMode::None => unreachable!("checked above"),
            broadcast::BroadcastMode::Mst => {
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
                // Walk reachable nodes, filter to one-hop.
                // last_routes[nid] None for unreachable.
                let nodes_iter = self.node_ids.values().filter_map(|&nid| {
                    let r = self.last_routes.get(nid.0 as usize)?.as_ref()?;
                    Some((nid, Some(r.via), Some(r.nexthop)))
                });
                broadcast::direct_targets(nodes_iter, self.myself, from_is_self)
            }
        };

        // No clamp_mss/directonly/decrement_ttl — route()-level
        // concerns; broadcast bypasses route().
        let mut nw = false;
        for nid in target_nids {
            let len = data.len();
            let tunnel = self.tunnels.entry(nid).or_default();
            tunnel.out_packets += 1;
            tunnel.out_bytes += len as u64;
            nw |= self.send_sptps_packet(nid, data);
            nw |= self.try_tx(nid, true);
        }
        nw
    }

    /// `RouteResult` dispatch. Shared by Router and Switch paths.
    #[allow(clippy::too_many_lines)]
    // Forward arm alone is ~100 LOC: directonly/forwarding-off/PMTU-frag/clamp_mss/decrement_ttl all gate on via_nid/via_mtu computed at the top
    #[allow(clippy::needless_pass_by_value)] // RouteResult<NodeId>: Copy
    fn dispatch_route_result(
        &mut self,
        result: RouteResult<NodeId>,
        data: &mut [u8],
        from: Option<NodeId>,
    ) -> bool {
        match result {
            RouteResult::Forward { to } if to == self.myself => {
                self.send_packet_myself(data);
                false
            }
            RouteResult::Forward { to: to_nid } => {
                let to = self
                    .graph
                    .node(to_nid)
                    .map_or_else(|| "<gone>".to_owned(), |n| n.name.clone());

                // Dest subnet OWNED by sender — overlapping subnets,
                // misconfig.
                if Some(to_nid) == from {
                    log::warn!(target: "tincd::net",
                               "Packet looping back to {to}");
                    return false;
                }

                // FMODE_OFF — operator says "I am an endpoint, not a
                // relay". Gate is `source != myself && owner !=
                // myself`: `from.is_some()` is the first; this match
                // arm (NOT the `to == self.myself` arm above) is the
                // second. v4 → NET_ANO, v6 → ADMIN; MAC (Switch) →
                // silent drop. Gap audit `bcc5c3e3`: parsed in
                // `parse_settings`, never read — the security knob
                // silently no-op'd.
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

                // clamp_mss BEFORE send, AFTER routing. last_routes
                // is current for any Forward target (route() only
                // returns Forward for reachable owners).
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

                // Next hop IS the sender — bounce loop (stale graph
                // data, DEL_EDGE arrived but run_graph hasn't
                // recomputed via).
                if Some(via_nid) == from {
                    let from_name = from
                        .and_then(|nid| self.graph.node(nid))
                        .map_or("?", |n| n.name.as_str());
                    log::error!(target: "tincd::net",
                                "Routing loop for packet from {from_name}");
                    return false;
                }

                // TunnelState::default() inits to MTU (not 0); until
                // PMTU runs: 1518 ceiling.
                let via_mtu = self.tunnels.get(&via_nid).map_or(MTU, TunnelState::mtu);

                // directonly — operator opts out of relay.
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
                // Packet too big for next hop's PMTU. Only when
                // relaying (clamp_mss + kernel PMTU handle our own
                // outbound). Floors: 590=576+14 (RFC 791),
                // 1294=1280+14 (RFC 8200) — don't claim MTU < 576
                // even if discovery hasn't run.
                //
                // `via_mtu != 0`: don't claim a path MTU before
                // discovery has measured one. `try_fix_mtu` only
                // sets `mtu` once `minmtu >= maxmtu`; until then
                // it's 0, `MAX(0,590)` claims 576, and the kernel
                // caches that per-dst for 10 minutes — any TCP flow
                // in that window is stuck at MSS 536 forever. 3×
                // packets/crypto/syscalls for the same bytes.
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
                            // DF flag (data.len()>590 ⇒ [20] in bounds).
                            let df_set = data[20] & 0x40 != 0;
                            if df_set {
                                // limit-14 = IP-layer MTU. limit≥590
                                // so sub never wraps.
                                self.write_icmp_frag_needed(data, limit - 14);
                            } else {
                                // RFC 791 §2.3: routers MUST fragment.
                                // Rare path (modern OS sets DF on TCP)
                                // but UDP without DF through narrow-
                                // MTU relay needs this.
                                let Some(frags) = crate::fragment::fragment_v4(data, limit) else {
                                    log::debug!(target: "tincd::net",
                                        "fragment_v4: malformed input, dropping");
                                    return false;
                                };
                                // Mirror the normal send path below:
                                // send_sptps_packet + try_tx for PMTU
                                // drive.
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
                    let _ = mss::clamp(data, mtu);
                }

                // `source != myself` gate: don't decrement on
                // TUN-origin (we ARE the first hop).
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

                // Read inner TOS for the outer UDP socket. Threaded
                // via Daemon.tx_priority. Reset to 0 each packet —
                // priority only ever flows from data through to UDP
                // send. Done here, not at route_packet entry, to stay
                // clear of the dump-traffic agent's route boundary.
                self.tx_priority = if self.settings.priorityinheritance {
                    route::extract_tos(data).unwrap_or(0)
                } else {
                    0
                };

                let len = data.len();
                log::debug!(target: "tincd::net",
                            "Sending packet of {len} bytes to {to}");
                // Counts attempts, not deliveries.
                let tunnel = self.tunnels.entry(to_nid).or_default();
                tunnel.out_packets += 1;
                tunnel.out_bytes += len as u64;

                // try_tx: every forwarded packet drives PMTU
                // discovery one step.
                let mut nw = self.send_sptps_packet(to_nid, data);
                nw |= self.try_tx(to_nid, true);
                nw
            }
            RouteResult::Unreachable {
                icmp_type,
                icmp_code,
            } => {
                // ratelimit(3), keyed on same-second.
                let now_sec = self.timers.now().duration_since(self.started_at).as_secs();
                if self.icmp_ratelimit.should_drop(now_sec, 3) {
                    log::debug!(target: "tincd::net",
                                "route: unreachable (type={icmp_type} \
                                 code={icmp_code}), rate-limited");
                    return false;
                }
                // v4/v6 dispatch on ethertype here (bug audit
                // `deef1268`). data.len() ≥ 14 guaranteed: route()
                // returns TooShort for shorter.
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
                self.handle_ndp(data, from);
                false
            }
            RouteResult::Unsupported { reason } => {
                log::debug!(target: "tincd::net",
                            "route: dropping packet ({reason})");
                false
            }
            RouteResult::Broadcast => {
                // decrement_ttl() passes ARP via TooShort.
                if self.settings.decrement_ttl && from.is_some() {
                    match route::decrement_ttl(data) {
                        TtlResult::Decremented | TtlResult::TooShort => {}
                        TtlResult::DropSilent | TtlResult::SendIcmp { .. } => {
                            // No ICMP synth.
                            return false;
                        }
                    }
                }
                self.broadcast_packet(data, from)
            }
            RouteResult::TooShort { need, have } => {
                log::debug!(target: "tincd::net",
                            "route: too short (need {need}, have {have})");
                false
            }
        }
    }

    /// Router strips the eth header (receiver re-synthesizes from
    /// IP version nibble).
    pub(super) fn send_sptps_packet(&mut self, to_nid: NodeId, data: &[u8]) -> bool {
        // Direct graph access (disjoint from tunnels/compressor).
        let to_name = self
            .graph
            .node(to_nid)
            .map_or("<gone>", |n| n.name.as_str());
        let (offset, base_type) = match self.settings.routing_mode {
            RoutingMode::Router => (14, PKT_NORMAL),
            RoutingMode::Switch | RoutingMode::Hub => (0, PKT_MAC),
        };
        let tunnel = self.tunnels.entry(to_nid).or_default();

        // PACKET 17 short-circuit: direct meta-conn + doesn't fit
        // MTU → single-encrypt via meta-SPTPS. Gated BEFORE
        // validkey: with a direct conn, validkey doesn't matter;
        // with TCPOnly, validkey stays false forever and this is
        // the ONLY way to send.
        //
        // Gate BEFORE compression: gating after means if compression
        // helped, the eth-header bytes (offset 0..14) are
        // uninitialized → garbage on the wire → receiver drops.
        let direct_conn = self.nodes.get(&to_nid).and_then(|ns| ns.conn);
        if let Some(conn_id) = direct_conn
            && data.len() > usize::from(tunnel.minmtu())
        {
            let Some(conn) = self.conns.get_mut(conn_id) else {
                return false; // NodeState.conn stale (race)
            };
            // RED first; maxoutbufsize default 10*MTU.
            if crate::tcp_tunnel::random_early_drop(
                conn.outbuf.live_len(),
                self.settings.maxoutbufsize,
                &mut OsRng,
            ) {
                return true; // fake success
            }
            // len fits u16: MTU=1518.
            #[allow(clippy::cast_possible_truncation)]
            let req = tinc_proto::msg::TcpPacket {
                len: data.len() as u16,
            };
            let mut nw = conn.send(format_args!("{}", req.format()));
            // FULL eth frame, NOT stripped/compressed (see above).
            nw |= conn.send_sptps_record(0, data);
            return nw;
        }

        if !tunnel.status.validkey {
            log::debug!(target: "tincd::net",
                        "No valid key known yet for {to_name}");
            if !tunnel.status.waitingforkey {
                return self.send_req_key(to_nid);
            }
            // 10-second debounce; try_tx handles the restart.
            return false;
        }

        // PKT_PROBE goes via try_tx, not here. The offset check only
        // matters for Router (Switch offset=0).
        if data.len() < offset {
            return false;
        }

        // Only set PKT_COMPRESSED if compression actually helped.
        // Peer asked for this level in ANS_KEY. PERF(chunk-10): one
        // alloc per packet when peer asked for compression.
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
                payload // didn't help, fall back to raw
            }
        } else {
            // LZO stub or backend error.
            log::debug!(target: "tincd::net",
                        "Error while compressing packet to {to_name}");
            payload
        };

        // PACKET 17 gate already handled above.
        let Some(sptps) = tunnel.sptps.as_deref_mut() else {
            // validkey true but no sptps shouldn't happen (set by
            // HandshakeDone after Sptps::start). Defensive.
            log::warn!(target: "tincd::net",
                       "validkey set but no SPTPS for {to_name}?");
            return false;
        };

        // Encrypt into scratch with 12 bytes headroom for
        // [dst_id6‖src_id6]. Zero per-packet allocs; see
        // `seal_data_into` doc for the previous 3-alloc shape.
        if let Err(e) = sptps.seal_data_into(record_type, body, &mut self.tx_scratch, 12) {
            // Shouldn't happen: validkey checked, per-tunnel SPTPS
            // is always datagram-framed.
            log::warn!(target: "tincd::net",
                       "seal_data_into for {to_name}: {e:?}");
            return false;
        }
        self.send_sptps_data_relay(to_nid, self.myself, record_type, None)
    }

    /// SPTPS callback bridge. SPTPS returns Vec<Output> so this is
    /// both the receive_sptps_record and send_sptps_data sides.
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
                    nw |= self.send_sptps_data(peer, record_type, &bytes);
                }
                Output::HandshakeDone => {
                    let tunnel = self.tunnels.entry(peer).or_default();
                    if !tunnel.status.validkey {
                        tunnel.status.validkey = true;
                        tunnel.status.waitingforkey = false;
                        log::info!(target: "tincd::net",
                                   "SPTPS key exchange with {peer_name} successful");
                    }
                }
                Output::Record { record_type, bytes } => {
                    nw |= self.receive_sptps_record(peer, peer_name, record_type, &bytes);
                }
            }
        }
        nw
    }

    pub(super) fn receive_sptps_record(
        &mut self,
        peer: NodeId,
        peer_name: &str,
        record_type: u8,
        body: &[u8],
    ) -> bool {
        if body.len() > usize::from(crate::tunnel::MTU) {
            log::error!(target: "tincd::net",
                        "Packet from {peer_name} larger than MTU ({} > {})",
                        body.len(), crate::tunnel::MTU);
            return false;
        }

        // PMTU probe. The udppacket gate: probes only make sense
        // over UDP (they ARE the PMTU discovery mechanism);
        // TCP-tunneled probe = peer bug.
        if record_type == PKT_PROBE {
            let udppacket = self.tunnels.get(&peer).is_some_and(|t| t.status.udppacket);
            if !udppacket {
                log::error!(target: "tincd::net",
                            "Got SPTPS PROBE from {peer_name} via TCP");
                return false;
            }
            // maxrecentlen for try_udp's gratuitous reply.
            #[allow(clippy::cast_possible_truncation)] // body ≤ MTU
            let body_len = body.len() as u16;
            if let Some(p) = self.tunnels.get_mut(&peer).and_then(|t| t.pmtu.as_mut())
                && body_len > p.maxrecentlen
            {
                p.maxrecentlen = body_len;
            }
            return self.udp_probe_h(peer, peer_name, body);
        }
        if record_type & !(PKT_COMPRESSED | PKT_MAC) != 0 {
            log::error!(target: "tincd::net",
                        "Unexpected SPTPS record type {record_type} from {peer_name}");
            return false;
        }
        // Cross-mode warnings. Switch needs the eth header (ERROR if
        // peer stripped it); Router re-synths anyway (WARN, lenient).
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

        // TYPE-driven, not mode-driven — a switch node receiving
        // from a misconfigured router peer still parses correctly
        // using offset=14.
        let offset: usize = if has_mac { 0 } else { 14 };
        // Decompress at the level WE asked for.
        let decompressed;
        let body: &[u8] = if record_type & PKT_COMPRESSED != 0 {
            let incomp = self.tunnels.get(&peer).map_or(0, |t| t.incompression);
            let level = compress::Level::from_wire(incomp);
            if let Some(d) = self.compressor.decompress(body, level, MTU as usize) {
                decompressed = d;
                &decompressed
            } else {
                // Corrupt stream or LZO stub.
                log::warn!(target: "tincd::net",
                           "Error while decompressing packet from {peer_name}");
                return false;
            }
        } else {
            body
        };

        // Synthesize ethertype from IP version nibble (Router only;
        // Switch body IS the full eth frame).
        let mut frame: Vec<u8>;
        if offset == 0 {
            frame = body.to_vec();
        } else {
            // Zero MACs.
            if body.is_empty() {
                return false; // need byte 0 for the version nibble
            }
            let ethertype: u16 = match body[0] >> 4 {
                4 => crate::packet::ETH_P_IP,
                6 => 0x86DD, // ETH_P_IPV6
                v => {
                    log::debug!(target: "tincd::net",
                                "Unknown IP version {v} in packet from {peer_name}");
                    return false;
                }
            };
            frame = vec![0u8; offset + body.len()];
            frame[12..14].copy_from_slice(&ethertype.to_be_bytes());
            frame[offset..].copy_from_slice(body);
        }

        // maxrecentlen for try_udp's gratuitous probe-reply size.
        #[allow(clippy::cast_possible_truncation)] // frame.len() ≤ MTU
        let frame_len = frame.len() as u16;
        if let Some(t) = self.tunnels.get_mut(&peer)
            && t.status.udppacket
            && let Some(p) = t.pmtu.as_mut()
            && frame_len > p.maxrecentlen
        {
            p.maxrecentlen = frame_len;
        }

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
    #[allow(clippy::too_many_lines)] // mirrors receive_sptps_record; the rx_scratch mem::take dance for &mut self conflicts is unavoidable per-branch
    fn receive_sptps_record_fast(
        &mut self,
        peer: NodeId,
        peer_name: &str,
        record_type: u8,
    ) -> bool {
        let body_len = self.rx_scratch.len() - 14;

        if body_len > usize::from(crate::tunnel::MTU) {
            log::error!(target: "tincd::net",
                        "Packet from {peer_name} larger than MTU ({} > {})",
                        body_len, crate::tunnel::MTU);
            return false;
        }

        // PMTU probe. Probes are tiny and rare; just hand the slice
        // to the existing handler. udppacket gate: this path is only
        // reached from handle_incoming_vpn_packet (UDP), but the bit
        // was already cleared above. Probes via UDP are valid by
        // construction here — skip the gate.
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
        if record_type & !(PKT_COMPRESSED | PKT_MAC) != 0 {
            log::error!(target: "tincd::net",
                        "Unexpected SPTPS record type {record_type} from {peer_name}");
            return false;
        }
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

        let offset: usize = if has_mac { 0 } else { 14 };

        // Compressed packets are RARE (compression=0 is default);
        // fall back to a local Vec for the decompressed output. The
        // compressor already returns Vec; don't fight it.
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
            // Router mode (THE HOT PATH).
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

        // maxrecentlen. udppacket was already cleared by the caller,
        // but this path is by-construction UDP-only, so update
        // unconditionally.
        #[allow(clippy::cast_possible_truncation)] // frame.len() ≤ 14+MTU
        let frame_len = frame.len() as u16;
        if let Some(p) = self.tunnels.get_mut(&peer).and_then(|t| t.pmtu.as_mut())
            && frame_len > p.maxrecentlen
        {
            p.maxrecentlen = frame_len;
        }

        let len = frame.len() as u64;
        let tunnel = self.tunnels.entry(peer).or_default();
        tunnel.in_packets += 1;
        tunnel.in_bytes += len;

        let nw = self.route_packet(frame, Some(peer));
        self.rx_scratch = scratch;
        nw
    }

    pub(super) fn send_sptps_data(&mut self, to_nid: NodeId, record_type: u8, ct: &[u8]) -> bool {
        self.send_sptps_data_relay(to_nid, self.myself, record_type, Some(ct))
    }

    /// Relay decision: TCP vs UDP, `via` vs `nexthop`.
    ///
    /// `via`: the static relay — last DIRECT node on the SSSP path.
    /// Prefer it (skip in-between hops) BUT only if the packet FITS
    /// through its MTU; otherwise fall back to `nexthop` (immediate
    /// neighbor, always TCP-reachable). PROBEs always prefer `via`
    /// (tiny, and the point is to discover via's MTU).
    ///
    /// TCP if: SPTPS_HANDSHAKE (ANS_KEY also propagates reflexive
    /// UDP addr); tcponly; relay too old (proto minor<4); or
    /// `origlen > relay->minmtu` (TCP fragments fine).
    ///
    /// `from_nid`: ORIGINAL source. For relay forwarding it's the
    /// original sender's NodeId — wire prefix carries THEIR src_id6.
    #[allow(clippy::too_many_lines)] // TCP-b64/TCP-binary/UDP-batch/UDP-immediate arms all need relay_nid/direct/from_is_myself computed by the decision tree at the top
    pub(super) fn send_sptps_data_relay(
        &mut self,
        to_nid: NodeId,
        from_nid: NodeId,
        record_type: u8,
        ct: Option<&[u8]>,
    ) -> bool {
        // `ct` is None on the hot path: SPTPS frame at
        // tx_scratch[12..] from seal_data_into. Some(ct): relay/
        // handshake/probe path. origlen is plaintext body length
        // (relay's MTU measured at that layer).
        let ct_len = ct.map_or_else(|| self.tx_scratch.len() - 12, <[u8]>::len);
        let origlen = ct_len.saturating_sub(tinc_sptps::DATAGRAM_OVERHEAD);

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

        // Direct → wire prefix uses nullid for dst; recipient knows
        // it's not a relay.
        let from_is_myself = from_nid == self.myself;
        let direct = from_is_myself && to_nid == relay_nid;

        // proto minor 4+ understands the 12-byte ID prefix.
        let relay_options = self
            .last_routes
            .get(relay_nid.0 as usize)
            .and_then(Option::as_ref)
            .map_or(0, |r| r.options);
        let relay_supported = (relay_options >> 24) >= 4;

        // EITHER side requesting tcponly forces TCP.
        // TODO(bitflags-opts): relay_options is u32 from tinc-graph Route;
        // .bits() shim until tinc-graph migrates / udp-info-carry lands.
        let tcponly =
            (self.myself_options.bits() | relay_options) & crate::proto::OPTION_TCPONLY != 0;

        // minmtu==0 means "unknown" not "zero"; we go UDP
        // optimistically until PMTU runs. First packet over a fresh
        // relay needs the dance to settle either way.
        let relay_minmtu = self.tunnels.get(&relay_nid).map_or(0, TunnelState::minmtu);
        let too_big =
            record_type != PKT_PROBE && relay_minmtu > 0 && origlen > usize::from(relay_minmtu);
        let go_tcp = record_type == tinc_sptps::REC_HANDSHAKE
            || tcponly
            || (!direct && !relay_supported)
            || too_big;

        if go_tcp {
            // Two sub-paths: SPTPS_PACKET (binary) for proto
            // minor≥7; ANS_KEY/REQ_KEY (b64) otherwise. `match` not
            // `unwrap_or`: latter is eager, would slice-panic on
            // empty scratch even when ct=Some.
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

            // SPTPS_PACKET (binary). Handshakes stay on b64
            // (ANS_KEY also propagates reflexive UDP addr; binary
            // doesn't). SPTPS_PACKET introduced in proto minor 7;
            // b64 is the universal fallback. send_raw bypasses SPTPS
            // framing (blob is already per-tunnel-encrypted).
            if record_type != tinc_sptps::REC_HANDSHAKE && conn.options.prot_minor() >= 7 {
                if crate::tcp_tunnel::random_early_drop(
                    conn.outbuf.live_len(),
                    self.settings.maxoutbufsize,
                    &mut OsRng,
                ) {
                    return true; // fake success
                }
                // The `direct⇒nullid` for dst is UDP-only; binary
                // TCP path always uses the real dst id.
                let src_id = self.id6_table.id_of(from_nid).unwrap_or(NodeId6::NULL);
                let dst_id = self.id6_table.id_of(to_nid).unwrap_or(NodeId6::NULL);
                let frame = crate::tcp_tunnel::build_frame(dst_id, src_id, ct);
                let mut nw = conn.send(format_args!(
                    "{} {}",
                    Request::SptpsPacket as u8,
                    frame.len()
                ));
                nw |= conn.send_raw(&frame);
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
                // ANS_KEY. Only set incompression when from==myself
                // (relayed handshakes don't touch state).
                let my_compression = self.settings.compression;
                if from_is_myself {
                    self.tunnels.entry(to_nid).or_default().incompression = my_compression;
                }
                // `-1 -1 -1` are LITERAL string (cipher/digest/maclen
                // placeholders for SPTPS mode, never read by
                // ans_key_h). Byte-identical wire for pcap-compare.
                // tok.rs::lu accepts `-1` (glibc strtoul "negate as
                // unsigned" → u64::MAX).
                return conn.send(format_args!(
                    "{} {} {} {} -1 -1 -1 {}",
                    Request::AnsKey,
                    from_name,
                    to_name,
                    b64,
                    my_compression,
                ));
            }
            // REQ_KEY with reqno=SPTPS_PACKET.
            return conn.send(format_args!(
                "{} {} {} {} {}",
                Request::ReqKey,
                from_name,
                to_name,
                Request::SptpsPacket as u8,
                b64,
            ));
        }

        // We always prefix (peers are ≥1.1). direct ⇒ dst=nullid.
        let src_id = self.id6_table.id_of(from_nid).unwrap_or(NodeId6::NULL);
        let dst_id = if direct {
            NodeId6::NULL
        } else {
            self.id6_table.id_of(to_nid).unwrap_or(NodeId6::NULL)
        };
        // Hot path: overwrite 12-byte headroom in-place — zero
        // allocs/copies. Some(ct): relay/handshake — one body
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

        // Send to RELAY, not `to`. Fast path: udp_addr_cached set
        // when udp_confirmed flips; once confirmed the answer is
        // deterministic. Full choose_udp_address was 2.18% self-time
        // (Vec alloc + scan per packet).
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

        // Copy inner TOS to outer socket. Without it, all encrypted
        // traffic gets default DSCP regardless of inner QoS marking.
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

        // Phase 1 (`RUST_REWRITE_10G.md`): if we're inside
        // `on_device_read`'s drain loop AND on the cached-
        // addr fast path, STAGE into `tx_batch` instead of sending.
        // The drain loop ships the whole run in one `sendmsg` with
        // `UDP_SEGMENT` cmsg after walking all slots.
        //
        // Gates for staging:
        //   - `tx_batch.is_some()`: only set during the drain loop.
        //     UDP-recv→forward, meta-conn→relay, probes hit `None`
        //     and fall through to immediate send (Phase 0 path).
        //   - `cached.is_some()`: the cold path's `cold_sockaddr`
        //     is a stack local that dies at function return; can't
        //     stash a reference to it. Cold path is pre-PMTU-
        //     discovery anyway (rare, ~1 per peer per session).
        //   - `ct.is_none()`: hot path (encrypt-into-tx_scratch).
        //     `Some(ct)` is relay/handshake — they ALSO hit the
        //     cached path but the relay case rebuilds tx_scratch;
        //     staging that is correct but rare enough to not bother.
        //     Keep the fast path simple.
        //
        // On dst/size mismatch (`!can_coalesce`): flush the
        // current run, start a new one. Never worse than per-frame.
        if ct.is_none()
            && cached.is_some()
            && let Some(batch) = self.tx_batch.as_mut()
        {
            // origlen for EMSGSIZE → pmtu.on_emsgsize. Same value
            // the immediate-send path uses below.
            #[allow(clippy::cast_possible_truncation)] // ≤ MTU
            let at_len = origlen as u16;
            if !batch.can_coalesce(sockaddr, sock, self.tx_scratch.len()) {
                // Take the batch out, flush, put back. Can't call
                // `flush_tx_batch` (borrows &mut self while batch
                // is borrowed). Same `mem::take` dance as the
                // arena.
                let mut b = self.tx_batch.take().expect("checked Some above");
                Self::ship_tx_batch(&mut b, &mut self.listeners, &mut self.tunnels, &self.graph);
                self.tx_batch = Some(b);
            }
            // Reborrow after the possible take/restore.
            let batch = self.tx_batch.as_mut().expect("restored above");
            batch.stage(sockaddr, sock, relay_nid, at_len, &self.tx_scratch);
            return false; // staged; UDP send doesn't touch outbuf
        }

        // Immediate-send path (Phase 0). Hit when: outside the
        // drain loop, OR cold path (no cached addr), OR relay/
        // handshake (`ct.is_some()`). `count=1` means `stride ==
        // last_len`; both `Portable` and `linux::Fast` skip GSO.
        #[allow(clippy::cast_possible_truncation)] // tx_scratch ≤ MTU+33+12 < u16::MAX
        let len = self.tx_scratch.len() as u16;
        if let Some(slot) = self.listeners.get_mut(usize::from(sock))
            && let Err(e) = slot.egress.send_batch(&crate::egress::EgressBatch {
                dst: sockaddr,
                frames: &self.tx_scratch,
                stride: len,
                count: 1,
                last_len: len,
            })
        {
            if e.kind() == io::ErrorKind::WouldBlock {
                // Drop; UDP is unreliable.
            } else if e.raw_os_error() == Some(libc::EMSGSIZE) {
                // EMSGSIZE = LOCAL kernel rejected (interface MTU).
                // Shrink relay's maxmtu. Don't log: this IS the
                // discovery mechanism.
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

    /// DNS stub TUN intercept (Rust-only). Returns `true` if `data`
    /// was a DNS query for the magic IP and we wrote a reply; the
    /// caller skips `route()` entirely. `false` for non-match (wrong
    /// dst, wrong port, not UDP, ihl!=5) — packet falls through to
    /// normal routing. Ownership stays with the borrow; we read
    /// `data` and write a fresh reply frame.
    ///
    /// Hot-path cost: when the feature is on but the packet isn't
    /// for us, this is ~5 byte compares (`match_v4` early-outs on
    /// the first non-matching field). When off (`self.dns == None`),
    /// the caller's `is_some()` gate skips this call entirely.
    ///
    /// Caller pre-checks `self.dns.is_some()`; the `take()` here
    /// always succeeds. The take/put-back dance avoids the borrow
    /// conflict between `&self.dns` and `device.write(&mut self)`
    /// — same pattern as `device_arena` in `on_device_read`.
    /// `DnsConfig` is two `Option<IpAddr>` + a `String`; the move
    /// is cheap (no realloc, the String's heap buffer stays put).
    fn try_dns_intercept(&mut self, data: &[u8]) -> bool {
        let cfg = self.dns.take().expect("caller gated on is_some()");
        // v4 path. `match_v4` does the full eth+IP+UDP+port check;
        // None means "not for us" — fall through to v6 then route().
        let hit = if let Some(dns_ip) = cfg.dns_addr4
            && let Some((src, sport, dns)) = crate::dns::match_v4(data, &dns_ip)
        {
            let Some(reply) = crate::dns::answer(dns, &cfg, &self.subnets, &self.name) else {
                // Malformed past header recovery (truncated ID, or
                // QR bit set = reflection attempt). Drop silently.
                // NOT route() — it'd Forward{to:myself} (the magic IP
                // is on the TUN), and the kernel would ICMP port-
                // unreachable, leaking that something's there.
                self.dns = Some(cfg);
                return true;
            };
            let mut frame = crate::dns::wrap_v4(data, &reply, &dns_ip, &src, sport);
            log::debug!(target: "tincd::dns",
                        "reply {} bytes to {src}:{sport}", reply.len());
            if let Err(e) = self.device.write(&mut frame) {
                log::debug!(target: "tincd::dns",
                            "device write failed: {e}");
            }
            true
        }
        // v6 path. Same shape; UDP checksum is mandatory here
        // (RFC 8200 §8.1) — wrap_v6 always computes it.
        else if let Some(dns_ip) = cfg.dns_addr6
            && let Some((src, sport, dns)) = crate::dns::match_v6(data, &dns_ip)
        {
            let Some(reply) = crate::dns::answer(dns, &cfg, &self.subnets, &self.name) else {
                self.dns = Some(cfg);
                return true;
            };
            let mut frame = crate::dns::wrap_v6(data, &reply, &dns_ip, &src, sport);
            log::debug!(target: "tincd::dns",
                        "reply {} bytes to [{src}]:{sport}", reply.len());
            if let Err(e) = self.device.write(&mut frame) {
                log::debug!(target: "tincd::dns",
                            "device write failed: {e}");
            }
            true
        } else {
            false
        };
        self.dns = Some(cfg);
        hit
    }

    pub(super) fn handle_arp(&mut self, data: &[u8], from: Option<NodeId>) -> bool {
        // ARP from a peer in router mode is a misconfig (their
        // kernel shouldn't be ARPing across an L3 tunnel).
        if let Some(from_nid) = from {
            log::warn!(target: "tincd::net",
                       "Got ARP request from {} while in router mode!",
                       self.node_log_name(from_nid));
            return false;
        }
        let Some(target) = neighbor::parse_arp_req(data) else {
            log::debug!(target: "tincd::net",
                        "route: dropping ARP packet (not a valid request)");
            return false;
        };
        // Snatch the kernel's MAC. parse_arp_req gated data.len()≥42
        // so [6..12] is safe. Snatch BEFORE the subnet lookup; the
        // snatch is the only useful side effect even if no subnet
        // owns the target.
        if self.overwrite_mac {
            self.mymac.copy_from_slice(&data[6..12]);
        }
        // No reachability check — ARP just answers "does someone own
        // this", not "are they up".
        let Some((_, owner)) = self.subnets.lookup_ipv4(&target, |_| true) else {
            log::debug!(target: "tincd::net",
                        "route: ARP for unknown {target}");
            return false;
        };
        // Silently ignore ARPs for our own subnets — the kernel
        // already knows; replying would create a wrong arp-cache
        // entry pointing at the TUN.
        if owner == Some(&self.name) {
            return false;
        }
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

    pub(super) fn handle_ndp(&mut self, data: &mut [u8], from: Option<NodeId>) {
        // NDP solicit from a peer in router mode — misconfig
        // (router-mode is L3; kernel shouldn't be doing neighbor
        // discovery across the tunnel).
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
        // Snatch the kernel's MAC. parse_ndp_solicit gated
        // data.len()≥78. Snatch BEFORE the subnet lookup; the snatch
        // is the only useful side effect even if no subnet owns the
        // target (we still learned the kernel's MAC).
        if self.overwrite_mac {
            self.mymac.copy_from_slice(&data[6..12]);
        }
        let Some((_, owner)) = self.subnets.lookup_ipv6(&target, |_| true) else {
            log::debug!(target: "tincd::net",
                        "route: NDP solicit for unknown {target}");
            return;
        };
        if owner == Some(&self.name) {
            return;
        }
        // decrement_ttl on the SOLICIT before building the advert.
        // Triple-gate: DecrementTTL=yes (rare) + NDP (rarer) + the
        // from-peer arm is unreachable here (gated above).
        // decrement_ttl(v6, hlim=255) → 254 in the original;
        // build_ndp_advert copies that hlim into the reply.
        if self.settings.decrement_ttl {
            match route::decrement_ttl(data) {
                TtlResult::Decremented | TtlResult::TooShort => {}
                TtlResult::DropSilent | TtlResult::SendIcmp { .. } => {
                    // No ICMP synth.
                    return;
                }
            }
        }
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
        // Only TIME_EXCEEDED gets the source-override dance — so
        // traceroute shows OUR hop. This helper's only caller is the
        // TtlResult::SendIcmp arm, which is always TIME_EXCEEDED, so
        // do it unconditionally here. orig src lives at fixed
        // offsets: eth(14)+ip_src(12)=[26..30] for v4,
        // eth(14)+ip6_src(8)=[22..38] for v6. None on any failure
        // (slice short, kernel says no) → falls back to the
        // orig-dst-as-src behavior.
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

    /// v4 FRAG_NEEDED. Separate helper: passes frag_mtu through.
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

    /// v6 PACKET_TOO_BIG.
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

    pub(super) fn write_icmp_reply(&mut self, mut reply: Vec<u8>) {
        if let Err(e) = self.device.write(&mut reply) {
            log::debug!(target: "tincd::net",
                        "Error writing ICMP to device: {e}");
        }
    }
}

/// For ICMP TIME_EXCEEDED: find our local IP facing the original
/// sender so traceroute shows us correctly. UDP `connect()` then
/// `getsockname()` — no packets sent (UDP connect is a route lookup
/// plus dst association). Same trick `choose_initial_maxmtu` uses
/// (`9e2540ab`).
///
/// Port is irrelevant (route lookup); use 1 (some kernels reject 0
/// for connect). All errors fall through to the default via `?` →
/// `None`.
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

/// setsockopt `IP_TOS`/`IPV6_TCLASS`. Sets the DSCP for OUTGOING
/// UDP datagrams. `is_ipv6`: family of the dest sockaddr.
///
/// Log-on-error at debug, never fail — a busy system flipping TOS
/// per-packet would spam if the kernel ever started rejecting these.
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
