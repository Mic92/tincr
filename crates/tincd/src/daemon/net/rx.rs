use super::super::Daemon;
use super::{UDP_RX_BATCH, UDP_RX_BUFSZ, UdpRxBatch, ss_to_std};
#[cfg(not(any(target_os = "linux", target_os = "android")))]
use nix::sys::socket::{SockaddrStorage as NixSS, recvfrom};
use std::io;
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::io::IoSliceMut;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::time::Duration;

use crate::conn::Connection;
use crate::listen::{configure_tcp, fmt_addr, is_local, unmap};
use crate::node_id::NodeId6;
use crate::tunnel::MTU;

use crate::event::Io;
use crate::graph::NodeId;
use tinc_crypto::os_rng;
use tinc_device::{Device, GroBucket};

use super::helpers;
#[cfg(target_os = "macos")]
use super::macos_rx;
use crate::set_nosigpipe;
use crate::shard;
use crate::shard::RxDstMemo;
use nix::errno::Errno;
#[cfg(any(target_os = "linux", target_os = "android"))]
use nix::sys::socket::{MsgFlags, recvmmsg};
use std::mem;
use std::net::Ipv4Addr;
use std::os::fd::RawFd;

/// Cap on inbound pre-auth meta conns. `Tarpit` is per-IP; a
/// many-source slowloris walks past it. 64 ≫ any legit cold-start
/// burst, ≪ `RLIMIT_NOFILE`.
pub const MAX_PENDING_META: usize = 64;

impl Daemon {
    /// accept → tarpit-check → `configure_tcp` → allocate → register.
    pub(in crate::daemon) fn on_tcp_accept(&mut self, i: u8) {
        let listener = &self.listeners[usize::from(i)].listener;

        // socket2 accept4(SOCK_CLOEXEC) avoids fd leaks into script
        // children for free.
        let (sock, peer_sockaddr) = match listener.tcp.accept() {
            Ok(pair) => {
                set_nosigpipe(&pair.0);
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
            (Ipv4Addr::UNSPECIFIED, 0).into()
        };

        // Checked after accept: refusing to accept would busy-loop
        // LT epoll. accept+close is cheap; the SPTPS state isn't.
        if self.pending_meta >= MAX_PENDING_META {
            let now = self.timers.now();
            if self
                .pending_meta_warned_at
                .is_none_or(|t| now.duration_since(t) >= Duration::from_mins(1))
            {
                log::warn!(target: "tincd::conn",
                           "Too many unauthenticated connections ({}), \
                            rejecting {peer}",
                           self.pending_meta);
                self.pending_meta_warned_at = Some(now);
            }
            return; // `sock` drops → close
        }

        // Local conns never tick the buckets (`tinc info` queries
        // don't get tarpitted).
        if !is_local(&peer) {
            let now = self.timers.now();
            if self.tarpit.check(peer, now) {
                // fd not configured — peer's reads block forever.
                self.tarpit.pit(sock.into());
                log::info!(target: "tincd::conn",
                           "Tarpitting connection from {peer}");
                return;
            }
        }

        // Configure before allocating the Connection so a configure
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

        if let Some(id) = self.register_conn(conn, Io::Read) {
            self.conns[id].counted_pending = true;
            self.pending_meta += 1;
            log::info!(target: "tincd::conn", "Connection from {peer}");
        }
    }

    /// RX fast-path TUN sink, the GRO arm of `send_packet_myself` as an associated
    /// fn so the dispatch loop can call it with `tx_snap` borrowed out of `self`
    /// (`&mut device` + `&mut gro` are disjoint). `data` is `[synth_eth:14][IP]`;
    /// the offer wants raw IP. `gro = None` writes immediately.
    fn rx_fast_sink(device: &mut Box<dyn Device>, gro: &mut Option<GroBucket>, data: &mut [u8]) {
        helpers::gro_offer_or_write(device.as_mut(), gro, data);
    }

    /// Wire layout `[dst_id:6][src_id:6][sptps...]`; the 12-byte prefix is outside
    /// SPTPS framing and `dst == nullid` means direct. One `recvmmsg(64)` per wake;
    /// under LT epoll a fuller queue re-fires after TUN reads, meta conns and
    /// timers had their slice (`deef1268`), which TCP-over-tunnel needs to keep its
    /// send window moving.
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
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn udp_recv_phase1(
        fd: RawFd,
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
                    #[expect(clippy::cast_possible_truncation)]
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

    /// Phase 1, non-Linux: `recvmsg_x` on macOS (one syscall for up
    /// to `UDP_RX_BATCH` datagrams), `recvfrom` loop everywhere else
    /// and as the macOS `ENOSYS` fallback.
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn udp_recv_phase1(
        fd: RawFd,
        batch: &mut UdpRxBatch,
        meta: &mut [(u16, Option<SocketAddr>); UDP_RX_BATCH],
    ) -> usize {
        #[cfg(target_os = "macos")]
        if let Some(n) = macos_rx::phase1(fd, batch, meta) {
            return n;
        }
        let mut count = 0;
        while count < UDP_RX_BATCH {
            match recvfrom::<NixSS>(fd, &mut batch.bufs[count]) {
                Ok((n, addr)) => {
                    #[expect(clippy::cast_possible_truncation)]
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

        // Phase 1: syscall + extract (len, peer) per message.
        let mut meta: [(u16, Option<SocketAddr>); UDP_RX_BATCH] = [(0u16, None); UDP_RX_BATCH];
        let count = Self::udp_recv_phase1(fd, batch, &mut meta);

        // Phase 2: dispatch; iov borrows are dead so `batch.bufs` is readable under
        // `&mut self`. Arm the GRO coalescer for this loop: `send_packet_myself`
        // offers local-delivery packets to it and we flush after the loop, never
        // across recvmmsg calls (latency cap, like the kernel's napi quantum). Only
        // when count > 1 and the device takes vnet_hdr supers (`gro_enabled`).
        let mut gro = if self.dp.gro_enabled && count > 1 {
            self.dp.gro_bucket_spare.take()
        } else {
            None
        };
        // RX fast path: take the snapshot out for the loop body (`rx_probe` borrows it
        // while `rx_open` needs `&mut self.device`). `any_pcap` is checked once per
        // batch; it flips at human rate. `rx_fast_scratch` is separate from
        // `rx_scratch`, which the slow path `mem::take`s internally, so both paths can
        // interleave in one batch; taken rather than fresh so capacity persists across
        // wakes.
        let snap = if self.any_pcap {
            None
        } else {
            self.tx_snap.take()
        };
        let mut rx_fast_scratch = mem::take(&mut self.dp.rx_fast_scratch);
        let mut dst_memo = RxDstMemo::default();
        for (idx, &(n, peer)) in meta.iter().enumerate().take(count) {
            let n = usize::from(n);
            if n == 0 {
                continue;
            }
            let pkt = &batch.bufs[idx][..n];

            // RX fast-path attempt: `rx_probe` walks the gate chain, `rx_open` decrypts,
            // post-gates and commits replay, leaving `[eth:14][IP]` in `rx_fast_scratch`.
            // Any miss falls to the slow path with the replay window untouched. Fast and
            // slow share one GRO bucket (handed over via the take/restore below), so mixed
            // batches keep packet order.
            if let Some(snap) = snap.as_ref()
                && let Some(target) = shard::rx_probe(snap, pkt)
                && let Ok(len) = shard::rx_open(&target, snap, &mut rx_fast_scratch, &mut dst_memo)
            {
                target.handles.stats.add_in(1, len as u64);
                // Consumed; the replay window advanced so the slow path won't see it. GRO
                // offer or TUN write inline. Without GRO (Darwin utun) use `write_stage` so
                // the batch ships in one `sendmsg_x`; elsewhere that is plain `write`.
                if gro.is_some() {
                    Self::rx_fast_sink(&mut self.device, &mut gro, &mut rx_fast_scratch[..len]);
                } else if let Err(e) = self.device.write_stage(&mut rx_fast_scratch[..len]) {
                    log::debug!(target: "tincd::net", "Error writing to device: {e}");
                }
                continue;
            }

            // Slow path. Flush staged TUN writes first so a.
            // slow-path `device.write` doesn't reorder past staged
            // fast-path frames from the same flow.
            if let Err(e) = self.device.write_flush() {
                log::debug!(target: "tincd::net", "device write_flush: {e}");
            }
            // Park the bucket in self for the
            // duration of this one packet's journey through
            // handle_incoming_vpn_packet → forward_packet →
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
        if let Err(e) = self.device.write_flush() {
            log::debug!(target: "tincd::net", "device write_flush: {e}");
        }
        if let Some(mut bucket) = gro {
            self.gro_flush(&mut bucket);
            // 64KB stays warm for the next batch.
            self.dp.gro_bucket_spare = Some(bucket);
        }

        count
    }

    /// Drain worker `k`'s punt queue: clear the eventfd, then run each packet
    /// through the normal slow path.
    pub(in crate::daemon) fn on_shard_punt(&mut self, k: u8) {
        let Some((punt, efd)) = self.shards.punt_handle(usize::from(k)) else {
            return;
        };
        let mut buf = [0u8; 8];
        let _ = nix::unistd::read(&*efd, &mut buf);
        let mut nw = false;
        while let Some(mut p) = punt.pop() {
            let len = usize::from(p.len);
            match p.src {
                Some(src) => self.handle_incoming_vpn_packet(&p.buf[..len], Some(src)),
                None => nw |= self.forward_packet(&mut p.buf[..len], None),
            }
            punt.recycle(p.buf);
        }
        if nw {
            self.maybe_set_write_any();
        }
    }

    fn handle_incoming_vpn_packet(&mut self, pkt: &[u8], peer: Option<SocketAddr>) {
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
                    // This cold-start arm fires `send_req_key` unconditionally (the decode-error
                    // arms go through `maybe_restart_stuck_tunnel`). The REQ_KEY now sits in a
                    // meta-conn outbuf and nothing on the UDP path arms EPOLLOUT, so flush here or
                    // the handshake waits for the next ping tick.
                    self.maybe_set_write_any();
                }
            }
            return;
        };

        // The bit tells `receive_sptps_record` this came via UDP (vs
        // TCP-tunneled). Dispatch is after (Vec<Output> return), so
        // defer the clear below.
        tunnel.status.udppacket = true;

        // Fast path: decrypt into `rx_scratch` with 14 bytes headroom for the
        // synthetic header; `InvalidState` (no incipher) and `BadRecord` (handshake
        // record, replay untouched) fall to the `Vec<Output>` path. Across a REQ_KEY
        // restart in-flight datagrams are still under the old key, so `prev_sptps` is
        // retried on `InvalidState` and `DecryptFailed`; `BadRecord`/`BadSeqno` mean
        // the new session authenticated the packet, so no retry.
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
                // relayed-to-us would cache the relay's addr.
                let direct = dst_id.is_null();
                if let Some(peer_addr) = peer.filter(|_| direct) {
                    helpers::confirm_udp_addr(
                        &mut self.dp.tunnels,
                        &self.listeners,
                        &self.tunnel_handles,
                        from_nid,
                        &from_name,
                        peer_addr,
                    );
                }
                let mut nw = false;
                if !direct {
                    // Relayed-to-us: tell sender our MTU floor.
                    nw |= self.send_mtu_info(from_nid, &from_name, i32::from(MTU), true);
                }
                nw |= self.receive_sptps_record(from_nid, &from_name, record_type);
                // Clear udppacket after the call: the PROBE gate and
                // maxrecentlen update inside need to see the true value.
                if let Some(t) = self.dp.tunnels.get_mut(&from_nid) {
                    t.status.udppacket = false;
                }
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
        let result = sptps.receive(ct, &mut os_rng());
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

        // `direct` only when dst_id == nullid. On relayed-to-us
        // (`dst != null && to == myself`), `peer_addr` is the
        // RELAY's address; caching would pin direct sends to the
        // relay forever (bug audit `deef1268`).
        let direct = dst_id.is_null();
        if let Some(peer_addr) = peer.filter(|_| direct) {
            helpers::confirm_udp_addr(
                &mut self.dp.tunnels,
                &self.listeners,
                &self.tunnel_handles,
                from_nid,
                &from_name,
                peer_addr,
            );
        }
        // Tell `from` our MTU floor so they can switch to direct
        // UDP. Bug audit `deef1268`: was missing entirely.
        if !direct {
            let nw = self.send_mtu_info(from_nid, &from_name, i32::from(MTU), true);
            if nw {
                self.maybe_set_write_any();
            }
        }

        let nw = self
            .dispatch_tunnel_outputs(from_nid, &from_name, outs)
            .needs_write;
        // Clear udppacket (deferred, see above).
        if let Some(t) = self.dp.tunnels.get_mut(&from_nid) {
            t.status.udppacket = false;
        }
        if nw {
            self.maybe_set_write_any();
        }
    }

    /// Relay-receive path (`dst_id != null`): `true` when forwarded or dropped,
    /// `false` when `dst == myself` and the caller should decrypt locally. The
    /// immediate UDP sender is validated against the addr-confirm gate first; we
    /// never decrypt on this path, so otherwise two node names would make us a 1:1
    /// UDP reflector (`2f72c2ba`).
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
            let mut nw = self
                .send_sptps_data_relay(to_nid, from_nid, 0, Some(ct))
                .needs_write;
            nw |= self.try_tx(to_nid, true);
            if nw {
                self.maybe_set_write_any();
            }
            return true;
        }
        // dst == myself but not nullid: fall through to direct
        // receive. Packet arrived via a dynamic relay; if we're
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
