use super::super::{Daemon, PKT_COMPRESSED, PKT_MAC, PKT_NORMAL, PKT_PROBE, RoutingMode};

use std::io;
use std::os::fd::AsFd;

use crate::compress;
use crate::listen::Listener;
use crate::node_id::NodeId6;
use crate::tunnel::{MTU, TunnelState};

use rand_core::OsRng;
use crate::graph::NodeId;
use tinc_proto::Request;

impl Daemon {
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
        let tunnel = self.dp.tunnels.entry(to_nid).or_default();

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
            #[allow(clippy::cast_possible_truncation)] // data.len() ≤ MTU (1518)
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
        } else if let Some(c) = self.dp.compressor.compress(payload, level) {
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
        if let Err(e) = sptps.seal_data_into(record_type, body, &mut self.dp.tx_scratch, 12) {
            // Shouldn't happen: validkey checked, per-tunnel SPTPS
            // is always datagram-framed.
            log::warn!(target: "tincd::net",
                       "seal_data_into for {to_name}: {e:?}");
            return false;
        }
        self.send_sptps_data_relay(to_nid, self.myself, record_type, None)
    }

    /// SPTPS callback bridge. SPTPS returns Vec<Output> so this is
    /// both the `receive_sptps_record` and `send_sptps_data` sides.
    pub(in crate::daemon) fn dispatch_tunnel_outputs(
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
                    let tunnel = self.dp.tunnels.entry(peer).or_default();
                    // `prev_sptps` is intentionally NOT cleared here:
                    // our `HandshakeDone` does not imply the peer has
                    // switched their `outcipher` yet (initiator vs
                    // responder finish at different times, plus
                    // jitter). Old-key stragglers can still arrive
                    // for ~RTT after this point; the slow-path retry
                    // in `rx.rs` keeps catching them. RX-only — we
                    // never seal with it — so no nonce-reuse risk,
                    // and AEAD-tag-then-replay-window means an
                    // attacker can't inject under the old key.
                    // Reclaimed by `on_ping_tick` once `validkey &&
                    // last_req_key + 2×PingInterval` (forward-
                    // secrecy bound), the next salvage, or
                    // `reset_unreachable`.
                    if !tunnel.status.validkey {
                        tunnel.status.validkey = true;
                        tunnel.status.waitingforkey = false;
                        log::info!(target: "tincd::net",
                                   "SPTPS key exchange with {peer_name} successful");
                    }
                    // Build the fast-path handles. The Sptps just
                    // emitted HandshakeDone so both ciphers are
                    // populated; the expects on outcipher_key/
                    // incipher_key are post-handshake invariants.
                    // outseqno_handle/replay_handle clone the existing
                    // Arcs inside the Sptps — the fast path's
                    // fetch_add/lock hits the SAME counter the
                    // control-side seal_data_into would. Rekey: this
                    // arm fires again, fresh Arc replaces; old drops.
                    if let Some(sptps) = tunnel.sptps.as_deref() {
                        let handles = std::sync::Arc::new(crate::shard::TunnelHandles {
                            outseqno: sptps.outseqno_handle(),
                            replay: sptps.replay_handle(),
                            outkey: *sptps.outcipher_key().expect("post-HandshakeDone"),
                            inkey: *sptps.incipher_key().expect("post-HandshakeDone"),
                            udp_addr: std::sync::Mutex::new(tunnel.udp_addr_cached.clone()),
                            validkey: std::sync::atomic::AtomicBool::new(true),
                            minmtu: std::sync::atomic::AtomicU16::new(tunnel.minmtu()),
                            outcompression: tunnel.outcompression,
                            stats: std::sync::Arc::clone(&tunnel.stats),
                        });
                        // Mirror first so on_probe_reply's minmtu
                        // store finds it.
                        self.tunnel_handles
                            .insert(peer, std::sync::Arc::clone(&handles));
                        if let Some(s) = self.tx_snap.as_mut() {
                            s.tunnels.insert(peer, handles);
                        }
                    }
                }
                Output::Record { record_type, bytes } => {
                    // Cold path (handshake-interleaved records, TCP
                    // fallback). Stage body into rx_scratch's headroom
                    // layout so the unified receiver can run.
                    self.dp.rx_scratch.clear();
                    self.dp.rx_scratch.resize(14, 0);
                    self.dp.rx_scratch.extend_from_slice(&bytes);
                    nw |= self.receive_sptps_record(peer, peer_name, record_type);
                }
            }
        }
        nw
    }

    /// Decode, decompress (if needed) and route one SPTPS record.
    ///
    /// Reads the body from `self.dp.rx_scratch[14..]`. Builds the
    /// ethernet frame in-place in `rx_scratch` (the 14-byte headroom
    /// was pre-reserved by `open_data_into` on the fast path, or by
    /// `dispatch_tunnel_outputs` on the rare handshake-interleaved
    /// path). Zero allocs in the common uncompressed case.
    pub(super) fn receive_sptps_record(
        &mut self,
        peer: NodeId,
        peer_name: &str,
        record_type: u8,
    ) -> bool {
        let body_len = self.dp.rx_scratch.len() - 14;

        if body_len > usize::from(crate::tunnel::MTU) {
            log::error!(target: "tincd::net",
                        "Packet from {peer_name} larger than MTU ({} > {})",
                        body_len, crate::tunnel::MTU);
            return false;
        }

        // PMTU probe. Probes only make sense over UDP (they ARE the
        // PMTU discovery mechanism); TCP-tunneled probe = peer bug.
        if record_type == PKT_PROBE {
            let udppacket = self
                .dp
                .tunnels
                .get(&peer)
                .is_some_and(|t| t.status.udppacket);
            if !udppacket {
                log::error!(target: "tincd::net",
                            "Got SPTPS PROBE from {peer_name} via TCP");
                return false;
            }
            #[allow(clippy::cast_possible_truncation)] // body ≤ MTU
            let body_len_u16 = body_len as u16;
            if let Some(p) = self.dp.tunnels.get_mut(&peer).and_then(|t| t.pmtu.as_mut())
                && body_len_u16 > p.maxrecentlen
            {
                p.maxrecentlen = body_len_u16;
            }
            // mem::take dance: udp_probe_h is &mut self.
            let scratch = std::mem::take(&mut self.dp.rx_scratch);
            let nw = self.udp_probe_h(peer, peer_name, &scratch[14..]);
            self.dp.rx_scratch = scratch;
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

        // Compressed packets are rare (compression=0 is default);
        // fall back to a local Vec. Compressor returns Vec anyway.
        let decompressed: Option<Vec<u8>>;
        if record_type & PKT_COMPRESSED != 0 {
            let incomp = self.dp.tunnels.get(&peer).map_or(0, |t| t.incompression);
            let level = compress::Level::from_wire(incomp);
            let scratch = std::mem::take(&mut self.dp.rx_scratch);
            let d = self
                .dp
                .compressor
                .decompress(&scratch[14..], level, MTU as usize);
            self.dp.rx_scratch = scratch;
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
        //  1. compressed: body in `decompressed`, build a fresh Vec.
        //  2. has_mac (Switch): body at rx_scratch[14..] IS the eth
        //     frame. Route that slice directly.
        //  3. !has_mac (Router, hot path): body at rx_scratch[14..],
        //     headroom [0..14] is zeros. Stamp ethertype at [12..14],
        //     route rx_scratch in full.
        // mem::take swaps out rx_scratch for the &mut borrow during
        // route_packet; restored after.
        let mut frame_vec: Vec<u8>;
        let mut scratch = std::mem::take(&mut self.dp.rx_scratch);
        let frame: &mut [u8] = if let Some(body) = &decompressed {
            if offset == 0 {
                frame_vec = body.clone();
            } else {
                if body.is_empty() {
                    self.dp.rx_scratch = scratch;
                    return false;
                }
                let ethertype: u16 = match body[0] >> 4 {
                    4 => crate::packet::ETH_P_IP,
                    6 => 0x86DD,
                    v => {
                        log::debug!(target: "tincd::net",
                                    "Unknown IP version {v} in packet from {peer_name}");
                        self.dp.rx_scratch = scratch;
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
                self.dp.rx_scratch = scratch;
                return false;
            }
            let ethertype: u16 = match scratch[14] >> 4 {
                4 => crate::packet::ETH_P_IP,
                6 => 0x86DD,
                v => {
                    log::debug!(target: "tincd::net",
                                "Unknown IP version {v} in packet from {peer_name}");
                    self.dp.rx_scratch = scratch;
                    return false;
                }
            };
            // Headroom [0..14] is already zero; stamp ethertype.
            scratch[12..14].copy_from_slice(&ethertype.to_be_bytes());
            &mut scratch
        };

        // maxrecentlen for try_udp's gratuitous probe-reply size.
        // Gated on udppacket: TCP-tunneled frames don't inform PMTU.
        #[allow(clippy::cast_possible_truncation)] // frame.len() ≤ 14+MTU
        let frame_len = frame.len() as u16;
        if let Some(t) = self.dp.tunnels.get_mut(&peer)
            && t.status.udppacket
            && let Some(p) = t.pmtu.as_mut()
            && frame_len > p.maxrecentlen
        {
            p.maxrecentlen = frame_len;
        }

        let len = frame.len() as u64;
        self.dp
            .tunnels
            .entry(peer)
            .or_default()
            .stats
            .add_in(1, len);

        let nw = self.route_packet(frame, Some(peer));
        self.dp.rx_scratch = scratch;
        nw
    }

    pub(in crate::daemon) fn send_sptps_data(
        &mut self,
        to_nid: NodeId,
        record_type: u8,
        ct: &[u8],
    ) -> bool {
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
    /// TCP if: `SPTPS_HANDSHAKE` (`ANS_KEY` also propagates reflexive
    /// UDP addr); tcponly; relay too old (proto minor<4); or
    /// TCP-transport slow path for [`Self::send_sptps_data_relay`].
    /// Two sub-paths: `SPTPS_PACKET` (binary) for proto minor≥7;
    /// `ANS_KEY`/`REQ_KEY` (b64) otherwise. Queues to the relay's
    /// metaconn.
    fn send_sptps_tcp(
        &mut self,
        to_nid: NodeId,
        from_nid: NodeId,
        record_type: u8,
        ct: Option<&[u8]>,
        from_is_myself: bool,
    ) -> bool {
        // `match` not `unwrap_or`: latter is eager, would
        // slice-panic on empty scratch even when ct=Some.
        let ct = match ct {
            Some(s) => s,
            None => &self.dp.tx_scratch[12..],
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

        // RED gate on the data-plane → metaconn enqueue, both the
        // binary and b64 SPTPS_PACKET paths. Handshake records are
        // exempt: O(100B), state-machine-paced, and ANS_KEY drops
        // would wedge the tunnel.
        if record_type != tinc_sptps::REC_HANDSHAKE
            && crate::tcp_tunnel::random_early_drop(
                conn.outbuf.live_len(),
                self.settings.maxoutbufsize,
                &mut OsRng,
            )
        {
            return true; // fake success
        }

        // SPTPS_PACKET (binary). Handshakes stay on b64
        // (ANS_KEY also propagates reflexive UDP addr; binary
        // doesn't). SPTPS_PACKET introduced in proto minor 7;
        // b64 is the universal fallback. send_raw bypasses SPTPS
        // framing (blob is already per-tunnel-encrypted).
        if record_type != tinc_sptps::REC_HANDSHAKE && conn.options.prot_minor() >= 7 {
            // The `direct⇒nullid` for dst is UDP-only; binary
            // TCP path always uses the real dst id.
            let src_id = self.id6_table.id_of(from_nid).unwrap_or(NodeId6::NULL);
            let dst_id = self.id6_table.id_of(to_nid).unwrap_or(NodeId6::NULL);
            let frame = crate::tcp_tunnel::build_frame(dst_id, src_id, ct);
            let mut nw = conn.send(format_args!("{} {}", Request::SptpsPacket, frame.len()));
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
                self.dp.tunnels.entry(to_nid).or_default().incompression = my_compression;
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
        conn.send(format_args!(
            "{} {} {} {} {}",
            Request::ReqKey,
            from_name,
            to_name,
            Request::SptpsPacket,
            b64,
        ))
    }

    /// `origlen > relay->minmtu` (TCP fragments fine).
    ///
    /// `from_nid`: ORIGINAL source. For relay forwarding it's the
    /// original sender's `NodeId` — wire prefix carries THEIR `src_id6`.
    pub(in crate::daemon) fn send_sptps_data_relay(
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
        let ct_len = ct.map_or_else(|| self.dp.tx_scratch.len() - 12, <[u8]>::len);
        let origlen = ct_len.saturating_sub(tinc_sptps::DATAGRAM_OVERHEAD);

        let Some(route) = self.route_of(to_nid) else {
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
        let via_minmtu = self.dp.tunnels.get(&via_nid).map_or(0, TunnelState::minmtu);
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
        let relay_options = self.route_of(relay_nid).map_or(0, |r| r.options);
        let relay_supported = (relay_options >> 24) >= 4;

        // EITHER side requesting tcponly forces TCP.
        // TODO(bitflags-opts): relay_options is u32 from tinc-graph Route;
        // .bits() shim until tinc-graph migrates / udp-info-carry lands.
        let tcponly =
            (self.myself_options.bits() | relay_options) & crate::proto::OPTION_TCPONLY != 0;

        // C parity (`net_packet.c:974`): data stays on TCP until a
        // probe reply lifts `minmtu` above 0. Probes are exempt so
        // discovery still runs; behind a UDP-blackholing firewall
        // minmtu stays 0 and data correctly never goes UDP.
        let relay_minmtu = self
            .dp
            .tunnels
            .get(&relay_nid)
            .map_or(0, TunnelState::minmtu);
        let too_big = record_type != PKT_PROBE && origlen > usize::from(relay_minmtu);
        let go_tcp = record_type == tinc_sptps::REC_HANDSHAKE
            || tcponly
            || (!direct && !relay_supported)
            || too_big;

        // ── relay_tx_bytes ─────────────────────────────────────────
        // Autoconnect-shortcut signal: bytes WE originated for `to`
        // that left via a relay (not direct). `!direct` already
        // encodes "from==myself && relay!=to"; the only exclusions
        // are probes (drive PMTU, not demand) and handshakes (rare,
        // always-TCP). 1 add + 1 store, no clock, no EWMA — the
        // cold-path `decide_autoconnect` does the rate derivation.
        if !direct
            && from_is_myself
            && record_type != PKT_PROBE
            && record_type != tinc_sptps::REC_HANDSHAKE
        {
            self.dp.tunnels.entry(to_nid).or_default().relay_tx_bytes += origlen as u64;
        }

        if go_tcp {
            return self.send_sptps_tcp(to_nid, from_nid, record_type, ct, from_is_myself);
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
            self.dp.tx_scratch.clear();
            self.dp.tx_scratch.extend_from_slice(dst_id.as_bytes());
            self.dp.tx_scratch.extend_from_slice(src_id.as_bytes());
            self.dp.tx_scratch.extend_from_slice(ct);
        } else {
            self.dp.tx_scratch[0..6].copy_from_slice(dst_id.as_bytes());
            self.dp.tx_scratch[6..12].copy_from_slice(src_id.as_bytes());
        }

        // Send to RELAY, not `to`. Fast path: udp_addr_cached set
        // when udp_confirmed flips; once confirmed the answer is
        // deterministic. Full choose_udp_address was 2.18% self-time
        // (Vec alloc + scan per packet).
        let cached = self
            .dp
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

        if self.settings.priorityinheritance {
            inherit_tos(&mut self.listeners, sock, sockaddr, self.dp.tx_priority);
        }

        // TX batching: stage into `tx_batch` instead of sending when
        // all gates pass; the drain loop ships the run in one sendmsg.
        //   - tx_batch_live: only inside on_device_read's drain loop
        //   - cached.is_some(): cold-path sockaddr is stack-local
        //   - ct.is_none(): hot path only (relay/handshake are rare)
        // dst/size mismatch → flush + restart. Never worse than per-frame.
        if self.dp.tx_batch_live && ct.is_none() && cached.is_some() {
            let dp = &mut self.dp;
            // origlen for EMSGSIZE → pmtu.on_emsgsize. Same value
            // the immediate-send path uses below.
            #[allow(clippy::cast_possible_truncation)] // ≤ MTU
            let at_len = origlen as u16;
            if !dp
                .tx_batch
                .can_coalesce(sockaddr, sock, dp.tx_scratch.len())
            {
                // Disjoint dp fields; ship directly (flush_tx_batch
                // would reborrow &mut self).
                Self::ship_tx_batch(
                    &mut dp.tx_batch,
                    &mut self.listeners,
                    &mut dp.tunnels,
                    &self.graph,
                );
            }
            dp.tx_batch
                .stage(sockaddr, sock, relay_nid, at_len, &dp.tx_scratch);
            return false; // staged; UDP send doesn't touch outbuf
        }

        // Immediate-send path. Hit when: outside the drain loop,
        // OR cold path (no cached addr), OR relay/
        // handshake (`ct.is_some()`).
        self.send_sptps_udp_immediate(sockaddr, sock, relay_nid, origlen);
        false // UDP send doesn't touch any meta-conn outbuf
    }

    /// Single-frame UDP send for [`Self::send_sptps_data_relay`].
    /// `count=1` means `stride == last_len`; both `Portable` and
    /// `linux::Fast` skip GSO. Handles `EMSGSIZE` → PMTU shrink.
    fn send_sptps_udp_immediate(
        &mut self,
        sockaddr: &socket2::SockAddr,
        sock: u8,
        relay_nid: NodeId,
        origlen: usize,
    ) {
        #[allow(clippy::cast_possible_truncation)] // tx_scratch ≤ MTU+33+12 < u16::MAX
        let len = self.dp.tx_scratch.len() as u16;
        let Some(slot) = self.listeners.get_mut(usize::from(sock)) else {
            return;
        };
        let Err(e) = slot.egress.send_batch(&crate::egress::EgressBatch {
            dst: sockaddr,
            frames: &self.dp.tx_scratch,
            stride: len,
            count: 1,
            last_len: len,
        }) else {
            return;
        };
        if e.kind() == io::ErrorKind::WouldBlock {
            // Drop; UDP is unreliable.
        } else if e.raw_os_error() == Some(nix::Error::EMSGSIZE as i32) {
            #[allow(clippy::cast_possible_truncation)] // origlen ≤ MTU
            let at_len = origlen as u16;
            super::helpers::handle_udp_emsgsize(
                &mut self.dp.tunnels,
                &self.graph,
                relay_nid,
                at_len,
            );
        } else {
            let relay_name = self.node_log_name(relay_nid);
            log::warn!(target: "tincd::net",
                       "Error sending UDP SPTPS packet to {relay_name}: {e}");
        }
    }
}

/// Copy inner TOS to outer socket. Without it, all encrypted
/// traffic gets default DSCP regardless of inner QoS marking.
fn inherit_tos(
    listeners: &mut [crate::daemon::ListenerSlot],
    sock: u8,
    sockaddr: &socket2::SockAddr,
    prio: u8,
) {
    if let Some(slot) = listeners.get_mut(usize::from(sock))
        && slot.last_tos != prio
    {
        slot.last_tos = prio;
        set_udp_tos(&slot.listener, sockaddr.is_ipv6(), prio);
    }
}

/// setsockopt `IP_TOS`/`IPV6_TCLASS` on the listener's UDP socket.
/// Thin shim over [`crate::set_udp_tos`] that picks the right fd.
fn set_udp_tos(l: &Listener, is_ipv6: bool, prio: u8) {
    crate::set_udp_tos(l.udp.as_fd(), is_ipv6, prio);
}
