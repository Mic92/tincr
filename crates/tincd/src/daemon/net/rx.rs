use super::super::{Daemon, IoWhat};
use super::{UDP_RX_BATCH, UDP_RX_BUFSZ, UdpRxBatch, ss_to_std};

use std::io;
#[cfg(target_os = "linux")]
use std::io::IoSliceMut;
use std::net::SocketAddr;
use std::os::fd::{AsFd, AsRawFd};

use crate::conn::Connection;
use crate::listen::{configure_tcp, fmt_addr, is_local, unmap};
use crate::local_addr;
use crate::node_id::NodeId6;
use crate::tunnel::MTU;

use rand_core::OsRng;
use tinc_device::{Device, GroBucket, GroVerdict};
use tinc_event::Io;
use tinc_graph::NodeId;

use nix::errno::Errno;
#[cfg(target_os = "linux")]
use nix::sys::socket::{MsgFlags, recvmmsg};

impl Daemon {
    /// accept → tarpit-check → `configure_tcp` → allocate → register.
    pub(in crate::daemon) fn on_tcp_accept(&mut self, i: u8) {
        let listener = &self.listeners[usize::from(i)].listener;

        // socket2 accept4(SOCK_CLOEXEC) avoids fd leaks into script
        // children for free.
        let (sock, peer_sockaddr) = match listener.tcp.accept() {
            Ok(pair) => {
                crate::set_nosigpipe(&pair.0);
                pair
            }
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

        let id = self.conns.insert(conn);
        match self
            .ev
            .add(self.conns[id].as_fd(), Io::Read, IoWhat::Conn(id))
        {
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

    /// RX fast-path TUN sink. Mirror of `send_packet_myself`'s GRO
    /// arm (device.rs:429-474), but as an associated fn so the
    /// dispatch loop can call it while `tx_snap` is borrowed out of
    /// `self`. `&mut self.device` + `&mut gro` (the dispatch loop's
    /// local `Option<GroBucket>`) is the disjoint-borrow shape.
    ///
    /// `data` is `[synth_eth:14][IP]` (`rx_open`'s output). The
    /// offer wants raw IP; the eth header is throwaway in TUN mode
    /// (the device write stomps it for the vnet header anyway).
    ///
    /// `gro = None` (`gro_enabled` false, or count == 1): immediate
    /// device write, no coalesce attempt. Same fall-through as
    /// `send_packet_myself`.
    ///
    /// FlushFirst/NotCandidate flush inline (no `gro_flush` — that's
    /// `&mut self`). The `flush()` + `write_super` body is two lines;
    /// inlined. The error log matches `gro_flush`'s wording so grep
    /// finds both.
    fn rx_fast_sink(device: &mut Box<dyn Device>, gro: &mut Option<GroBucket>, data: &mut [u8]) {
        const ETH_HLEN: usize = 14;
        // Inline gro_flush body: `&mut self` not available here.
        // The `gro_enabled` setup gate makes the Unsupported error
        // unreachable in practice (same wording as device.rs:491).
        let flush = |device: &mut Box<dyn Device>, b: &mut GroBucket| {
            if let Some(buf) = b.flush()
                && let Err(e) = device.write_super(buf)
            {
                log::warn!(target: "tincd::net",
                           "GRO super write failed: {e} — \
                            gro_enabled gate let a non-vnet device through?");
            }
        };
        if let Some(bucket) = gro.as_mut()
            && data.len() > ETH_HLEN
        {
            match bucket.offer(&data[ETH_HLEN..]) {
                GroVerdict::Coalesced => return, // absorbed; written on batch flush
                GroVerdict::FlushFirst => {
                    // Ship the run, re-offer to seed the next run.
                    // Same dance as send_packet_myself (device.rs:444).
                    flush(device, bucket);
                    let v = bucket.offer(&data[ETH_HLEN..]);
                    debug_assert_ne!(v, GroVerdict::FlushFirst);
                    if v == GroVerdict::Coalesced {
                        return;
                    }
                    // NotCandidate: fall through to write.
                }
                GroVerdict::NotCandidate => {
                    // Ordering: anything in the bucket goes out
                    // first. A non-candidate from the same flow
                    // (FIN) mustn't reorder past lower-seq data.
                    flush(device, bucket);
                }
            }
        }
        if let Err(e) = device.write(data) {
            log::debug!(target: "tincd::net", "Error writing to device: {e}");
        }
    }

    /// Wire layout: `[dst_id:6][src_id:6][sptps...]`. The 12-byte
    /// ID prefix is OUTSIDE SPTPS framing; `dst == nullid` means
    /// "direct to you".
    ///
    /// One `recvmmsg(64)` per wake. LT epoll: if the kernel had ≥64
    /// queued, the next `turn()` re-fires after TUN-read/meta-conn/
    /// timers get a slice. Same fairness as the old `recv_from` loop's
    /// `UDP_DRAIN_CAP=64` (bug audit `deef1268`).
    /// iperf3 is TCP-over-tunnel — alice MUST get back to TUN reads
    /// or the send window fills and the whole thing stalls.
    pub(in crate::daemon) fn on_udp_recv(&mut self, i: u8) {
        // Take the batch out so we can borrow bufs immutably while
        // calling `&mut self.handle_incoming_vpn_packet`. Same
        // pattern as `rx_scratch` (`e49b5af6`). `expect` is fine —
        // this is the only `take` site, no re-entrancy (epoll is
        // single-threaded), and we always put it back below.
        let mut batch = self
            .dp
            .udp_rx_batch
            .take()
            .expect("udp_rx_batch is Some between on_udp_recv calls");

        self.recvmmsg_batch(i, &mut batch);

        self.dp.udp_rx_batch = Some(batch);
    }

    /// One `recvmmsg(64)` + dispatch. Returns the number of
    /// messages the kernel gave us (0..=64). Separate fn so the
    /// `batch` borrow doesn't overlap `&mut self` at the call site.
    /// Phase 1 of UDP receive: syscall + extract (len, peer) per message.
    /// Linux: one recvmmsg(64). macOS: recvfrom loop.
    #[cfg(target_os = "linux")]
    fn udp_recv_phase1(
        fd: std::os::fd::RawFd,
        batch: &mut UdpRxBatch,
        meta: &mut [(u16, Option<SocketAddr>); UDP_RX_BATCH],
    ) -> usize {
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
                    #[allow(clippy::cast_possible_truncation)]
                    let n = msg.bytes.min(UDP_RX_BUFSZ) as u16;
                    let peer = msg.address.as_ref().and_then(ss_to_std).map(unmap);
                    meta[idx] = (n, peer);
                }
                k
            }
            Err(Errno::EAGAIN) => 0,
            Err(e) => {
                log::error!(target: "tincd::net", "Receiving packet failed: {e}");
                0
            }
        }
    }

    /// Phase 1 on macOS: recvfrom loop (no recvmmsg).
    #[cfg(not(target_os = "linux"))]
    fn udp_recv_phase1(
        fd: std::os::fd::RawFd,
        batch: &mut UdpRxBatch,
        meta: &mut [(u16, Option<SocketAddr>); UDP_RX_BATCH],
    ) -> usize {
        use nix::sys::socket::{SockaddrStorage as NixSS, recvfrom};
        let mut count = 0;
        while count < UDP_RX_BATCH {
            match recvfrom::<NixSS>(fd, &mut batch.bufs[count]) {
                Ok((n, addr)) => {
                    #[allow(clippy::cast_possible_truncation)]
                    let n = n.min(UDP_RX_BUFSZ) as u16;
                    let peer = addr.as_ref().and_then(ss_to_std).map(unmap);
                    meta[count] = (n, peer);
                    count += 1;
                }
                Err(Errno::EAGAIN) => break,
                Err(e) => {
                    log::error!(target: "tincd::net", "Receiving packet failed: {e}");
                    break;
                }
            }
        }
        count
    }

    fn recvmmsg_batch(&mut self, i: u8, batch: &mut UdpRxBatch) -> usize {
        let fd = self.listeners[usize::from(i)].listener.udp.as_raw_fd();

        // ─── Phase 1: syscall + extract (len, peer) per message.
        let mut meta: [(u16, Option<SocketAddr>); UDP_RX_BATCH] = [(0u16, None); UDP_RX_BATCH];
        let count = Self::udp_recv_phase1(fd, batch, &mut meta);

        // ─── Phase 2: dispatch. iov borrows are dead; `batch.bufs`
        // is now free to read while we hold `&mut self`.
        //
        // GRO TUN write: arm the coalescer for the duration
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
        let mut gro = if self.dp.gro_enabled && count > 1 {
            self.dp.gro_bucket_spare.take()
        } else {
            None
        };
        // RX fast-path: take the snapshot out for the loop body.
        // rx_probe is &TxSnapshot but rx_open's GRO offer +
        // device.write needs &mut self.device alongside. Same dance
        // as the TX Super arm (device.rs:256). The any_pcap gate is
        // checked once here, not per-packet — it flips at gossip-
        // rate via `tinc pcap`, not packet-rate; a packet that
        // sneaks past during the flip just doesn't get captured.
        // Same one-packet window as TX.
        //
        // rx_fast_scratch: dp.rx_fast_scratch, NOT dp.rx_scratch.
        // The slow path mem::takes dp.rx_scratch internally (sptps.
        // rs:354,389,428); a separate Vec lets fast/slow interleave
        // in one batch without scratch contention. Taken out here
        // (not Vec::new) so capacity persists across wakes — ~50k
        // recvmmsg calls per bench run, one alloc-per-wake would be
        // measurable.
        let snap = if self.any_pcap {
            None
        } else {
            self.tx_snap.take()
        };
        let mut rx_fast_scratch = std::mem::take(&mut self.dp.rx_fast_scratch);
        let mut dst_memo = crate::shard::RxDstMemo::default();
        for (idx, &(n, peer)) in meta.iter().enumerate().take(count) {
            let n = usize::from(n);
            if n == 0 {
                continue;
            }
            let pkt = &batch.bufs[idx][..n];

            // ─── RX fast-path attempt. rx_probe walks the gate
            // chain (slowpath_all/dst_null/src_known/tunnel/udp_addr);
            // rx_open decrypts + post-gates + replay-commits. On Ok
            // we have `[eth:14][IP]` in rx_fast_scratch ready for
            // GRO/TUN. On any miss we fall through to the slow path
            // with the replay window UNTOUCHED (rx.rs hard rule).
            //
            // Ordering invariant: the GRO bucket is a SINGLE bucket
            // shared by fast and slow paths. Packet 4 (fast) coalesces
            // into `gro`; packet 5 (slow, e.g. PKT_PROBE) parks the
            // SAME bucket into dp.gro_bucket via the take/restore
            // below; send_packet_myself sees packet 4's data in there
            // and either coalesces into it or flushes-first. Same
            // bucket, same handoff, no reordering.
            if let Some(snap) = snap.as_ref()
                && let Some(target) = crate::shard::rx_probe(snap, pkt)
                && let Ok(len) =
                    crate::shard::rx_open(&target, snap, &mut rx_fast_scratch, &mut dst_memo)
            {
                // Consumed. Replay window IS advanced — the slow
                // path won't see this packet. GRO offer/TUN write
                // inline (no &mut self via send_packet_myself; we
                // own the bucket and the device borrow directly).
                Self::rx_fast_sink(&mut self.device, &mut gro, &mut rx_fast_scratch[..len]);
                continue;
            }

            // ─── Slow path. Park the bucket in self for the
            // duration of this one packet's journey through
            // handle_incoming_vpn_packet → route_packet →
            // send_packet_myself. Same out-and-back as `rx_scratch`.
            // Taken back below before the next iteration so the
            // local `gro` owns it across the loop.
            self.dp.gro_bucket = gro.take();
            self.handle_incoming_vpn_packet(pkt, peer);
            gro = self.dp.gro_bucket.take();
        }
        // Restore before gro_flush takes &mut self. The is_some()
        // gate keeps tx_snap untouched on the any_pcap branch (it
        // was never taken).
        if snap.is_some() {
            self.tx_snap = snap;
        }
        self.dp.rx_fast_scratch = rx_fast_scratch;
        if let Some(mut bucket) = gro {
            self.gro_flush(&mut bucket);
            // 64KB stays warm for the next batch.
            self.dp.gro_bucket_spare = Some(bucket);
        }

        count
    }

    /// Authenticates the immediate UDP sender before the relay
    /// branch. SRCID-fallback only fires when `dst==nullid` — a
    /// relay packet cannot bootstrap auth via SRCID. For direct
    /// receive, SRCID alone is fine (AEAD tag validates end-to-end);
    /// for relay we never decrypt, so this gate is the only thing
    /// stopping a 1:1 UDP reflector attack (security audit `2f72c2ba`).
    fn handle_incoming_vpn_packet(&mut self, pkt: &[u8], peer: Option<SocketAddr>) {
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
        if !dst_id.is_null()
            && self.handle_relay_receive(ct, peer, dst_id, src_id, from_nid, &from_name)
        {
            return;
        }

        let tunnel = self.dp.tunnels.entry(from_nid).or_default();
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
                if self.send_req_key(from_nid) {
                    // The decode-error arms below thread through
                    // `maybe_restart_stuck_tunnel`; this cold-start
                    // arm is the only one that fires `send_req_key`
                    // unconditionally. Either way the REQ_KEY is
                    // sitting in a meta-conn outbuf and nothing on
                    // the UDP-receive path arms EPOLLOUT for it —
                    // without this flush the new handshake stalls
                    // until the next ping tick.
                    self.maybe_set_write_any();
                }
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
        //
        // Across a REQ_KEY restart, `tunnel.sptps` is the *new*
        // mid-handshake session but the peer's in-flight datagrams
        // (and anything they keep sealing until our REQ_KEY/ANS_KEY
        // reaches them) are still under the *old* key. The salvaged
        // `prev_sptps` covers that gap: try it on `InvalidState` (new
        // session has no incipher yet) and on `DecryptFailed` (new
        // session HAS its incipher but old-key stragglers are still
        // arriving — ordering between `HandshakeDone` and the last
        // old-key datagram is RTT-dependent). `BadRecord`/`BadSeqno`
        // do NOT retry: those mean the new session DID authenticate
        // the packet, so it can't also be an old-key straggler.
        let mut open_result = sptps.open_data_into(ct, &mut self.dp.rx_scratch, 14);
        if matches!(
            open_result,
            Err(tinc_sptps::SptpsError::InvalidState | tinc_sptps::SptpsError::DecryptFailed)
        ) && let Some(prev) = tunnel.prev_sptps.as_deref_mut()
        {
            open_result = prev.open_data_into(ct, &mut self.dp.rx_scratch, 14);
        }
        match open_result {
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
                    let cached = (socket2::SockAddr::from(peer_addr), sock);
                    tunnel.udp_addr_cached = Some(cached.clone());
                    // Mirror into the fast-path handles. tx_probe
                    // gates on `udp_addr.is_some()`; HandshakeDone
                    // typically fans None (UDP not yet confirmed).
                    // Uncontended lock single-threaded.
                    if let Some(h) = self.tunnel_handles.get(&from_nid) {
                        *h.udp_addr.lock().unwrap() = Some(cached);
                    }
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
                // Fall through to slow path below. After the
                // `prev_sptps` retry above, `InvalidState` here means
                // neither session has an incipher (initial cold
                // start) and `BadRecord` means it's a handshake
                // record for one of them — `receive()` sorts both.
            }
            Err(e) => {
                // DecryptFailed / BadSeqno on a single datagram. Log
                // and drop; only restart SPTPS if the session was
                // already not delivering (`!validkey`). See
                // `maybe_restart_stuck_tunnel` doc for why a healthy
                // session must not be torn down here.
                tunnel.status.udppacket = false;
                log::debug!(target: "tincd::net",
                            "Failed to decode UDP packet from {from_name}: {e:?}");
                if self.maybe_restart_stuck_tunnel(from_nid) {
                    self.maybe_set_write_any();
                }
                return;
            }
        }

        // Slow path stays exactly as-is.
        let Some(sptps) = self
            .dp
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
                // Same gate as the open_data_into arm above.
                log::debug!(target: "tincd::net",
                            "Failed to decode UDP packet from {from_name}: {e:?}");
                if self.maybe_restart_stuck_tunnel(from_nid) {
                    self.maybe_set_write_any();
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
            let tunnel = self.dp.tunnels.entry(from_nid).or_default();
            if !tunnel.status.udp_confirmed {
                log::debug!(target: "tincd::net",
                            "UDP address of {from_name} confirmed: {peer_addr}");
                tunnel.status.udp_confirmed = true;
            }
            tunnel.udp_addr = Some(peer_addr);
            // Pre-converted SockAddr: was 0.37% self-time per-packet.
            let cached = (socket2::SockAddr::from(peer_addr), sock);
            tunnel.udp_addr_cached = Some(cached.clone());
            if let Some(h) = self.tunnel_handles.get(&from_nid) {
                *h.udp_addr.lock().unwrap() = Some(cached);
            }
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
        if let Some(t) = self.dp.tunnels.get_mut(&from_nid) {
            t.status.udppacket = false;
        }
        if nw {
            self.maybe_set_write_any();
        }
    }

    /// Relay-receive path. `dst_id != null` → packet is addressed to
    /// someone, possibly us-via-relay. Returns `true` when the packet
    /// was consumed (forwarded or dropped); `false` when `dst ==
    /// myself` and the caller should fall through to local decrypt.
    ///
    /// Validates the immediate UDP sender against the addr-confirm
    /// gate before forwarding — we never decrypt on the relay path,
    /// so without this check anyone who knows two node names could
    /// use us as a 1:1 UDP reflector (security audit `2f72c2ba`).
    fn handle_relay_receive(
        &mut self,
        ct: &[u8],
        peer: Option<SocketAddr>,
        dst_id: NodeId6,
        src_id: NodeId6,
        from_nid: NodeId,
        from_name: &str,
    ) -> bool {
        let Some(to_nid) = self.id6_table.lookup(dst_id) else {
            log::debug!(target: "tincd::net",
                        "Received UDP relay packet from {from_name} \
                         with unknown dst ID {dst_id}");
            return true;
        };
        // dst just became unreachable (race).
        if !self.graph.node(to_nid).is_some_and(|n| n.reachable) {
            log::debug!(target: "tincd::net",
                        "Cannot relay UDP packet from {from_name}: \
                         dst {dst_id} is unreachable");
            return true;
        }
        // Hot relay path. `from_nid` so the wire prefix carries
        // the ORIGINAL source ID.
        if to_nid != self.myself {
            // Unauthenticated sender cannot relay. Without this
            // gate anyone who knows two node names can use us as
            // a 1:1 UDP reflector (security audit `2f72c2ba`).
            // O(nodes) scan is fine (relay is the rare branch):
            // "does this UDP src addr belong to a node that has
            // confirmed UDP with us?"
            let n_confirmed = peer.is_some_and(|peer_addr| {
                self.dp
                    .tunnels
                    .values()
                    .any(|t| t.status.udp_confirmed && t.udp_addr == Some(peer_addr))
            });
            if !n_confirmed {
                log::debug!(target: "tincd::net",
                            "Dropping relay request from unauthenticated UDP \
                             sender ({peer:?}): dst={dst_id} src={src_id}");
                return true;
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
            return true;
        }
        // dst == myself but not nullid: fall through to direct
        // receive. Packet arrived via a dynamic relay; if WE're
        // the static relay tell `from` where they're reachable
        // so next packet skips the dynamic relay. Gated to
        // static-relay-only so every hop in a chain doesn't emit
        // its own hint.
        let from_via = self.route_of(from_nid).map(|r| r.via);
        // Non-null dst_id6 means SOMEONE relayed (if `from`
        // itself, the prefix would be null).
        if from_via == Some(self.myself) && self.send_udp_info(from_nid, from_name, true) {
            self.maybe_set_write_any();
        }
        false
    }
}
