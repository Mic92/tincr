//! `REQ_KEY` / `ANS_KEY` / `KEY_CHANGED` — routed per-tunnel SPTPS
//! handshake messages.

use crate::daemon::{ConnId, Daemon, ForwardingMode};

use crate::dispatch::DispatchError;
use crate::local_addr;
use crate::tunnel::{MTU, make_udp_label};

use crate::graph::NodeId;
use rand_core::OsRng;
use tinc_crypto::sign::SigningKey;
use tinc_proto::Request;
use tinc_proto::msg::{AnsKey, KeyChanged, ReqKey};
use tinc_sptps::{Framing, Role, Sptps};

impl Daemon {
    /// Start per-tunnel SPTPS as initiator; send KEX via `REQ_KEY`.
    ///
    /// `Sptps::start` returns `Vec<Output>`. First Wire goes via
    /// `REQ_KEY`; subsequent (none from `start()`) would go via `ANS_KEY`.
    ///
    /// `REQ_PUBKEY`: hard-errored. Operator provisions `hosts/{to}`.
    pub(in crate::daemon) fn send_req_key(&mut self, to_nid: NodeId) -> bool {
        let Some(to_name) = self.graph.node(to_nid).map(|n| n.name.clone()) else {
            return false;
        };

        // Re-reads every call (10s debounce gates it).
        let Some((hiskey, aead)) = self.load_peer_tunnel_cfg(&to_name) else {
            // Hard-error: surface in logs, not as silent drops.
            // Operator provisions by hand.
            log::warn!(target: "tincd::net",
                       "No Ed25519 key known for {to_name}; cannot start tunnel");
            return false;
        };

        // Initiator name first in label.
        let label = make_udp_label(&self.name, &to_name);

        let mykey = SigningKey::from_blob(&self.mykey.to_blob());
        let (sptps, outs) = Sptps::start_with(
            Role::Initiator,
            Framing::Datagram,
            self.peer_sptps_kex(&to_name),
            mykey,
            hiskey,
            tinc_sptps::SptpsLabel::with_aead(label, aead),
            self.settings.replaywin,
            &mut OsRng,
        );
        let now = self.timers.now();
        let tunnel = self.dp.tunnels.entry(to_nid).or_default();
        // Salvage the outgoing session for RX until the new one's
        // `HandshakeDone`: peer's in-flight datagrams (and any they
        // seal before our REQ_KEY reaches them) are still under the
        // old key. Only keep it if it actually had an `incipher` -
        // a half-handshaken session can't decrypt anything and would
        // just waste a `Box`. See `TunnelState::prev_sptps`.
        if let Some(old) = tunnel.sptps.take()
            && old.incipher_key().is_some()
        {
            tunnel.prev_sptps = Some(old);
            tunnel.prev_sptps_installed_at = Some(now);
        }
        tunnel.sptps = Some(Box::new(sptps));
        tunnel.status.validkey = false;
        tunnel.status.waitingforkey = true;
        tunnel.status.sptps = true;
        tunnel.last_req_key = Some(now);

        // First Wire is KEX, goes via REQ_KEY. The doubled REQ_KEY
        // (outer=request type, inner=reqno ext) tells the receiver
        // it's SPTPS-init. start() only emits one Wire, so the else
        // branch is defensive.
        let mut nw = false;
        let mut first = true;
        for o in outs {
            if let tinc_sptps::Output::Wire { bytes, .. } = o {
                if first {
                    first = false;
                    let b64 = tinc_crypto::b64::encode(&bytes);
                    let Some(conn_id) = self.conn_for_nexthop(to_nid) else {
                        log::warn!(target: "tincd::net",
                                   "No meta connection toward {to_name} for REQ_KEY");
                        return false;
                    };
                    let Some(conn) = self.conns.get_mut(conn_id) else {
                        return false;
                    };
                    nw |= conn.send(format_args!(
                        "{} {} {} {} {}",
                        Request::ReqKey,
                        self.name,
                        to_name,
                        Request::ReqKey,
                        b64,
                    ));
                } else {
                    // start() emits one Wire; defensive.
                    nw |= self.send_sptps_data(to_nid, tinc_sptps::REC_HANDSHAKE, &bytes);
                }
            }
        }
        nw
    }

    /// `send_req_key`, but only if the session is plausibly stuck.
    ///
    /// Called from per-packet decode-error paths (`rx.rs` UDP,
    /// `metaconn.rs` binary `SPTPS_PACKET`, `gossip.rs` b64
    /// `SPTPS_PACKET`). C tinc fires `send_req_key` on every
    /// `sptps_receive_data` failure once `last_req_key+10` has passed
    /// (`net_packet.c:444`). We additionally gate on `!validkey`: a
    /// session that is currently delivering data must not be torn
    /// down by a single bad datagram. UDP is unauthenticated up to
    /// the AEAD tag check, so anyone who can spoof the peer's source
    /// address (or any on-path corruption) would otherwise reset a
    /// healthy tunnel and blackhole RTT×2 worth of traffic - the
    /// production `seqno != 0` bursts.
    ///
    /// If the session really is broken (peer rebooted, key mismatch),
    /// recovery still happens via the meta-conn: the peer's own
    /// `try_tx`/`send_req_key` reaches our `on_req_key` and we
    /// restart as responder. The UDP decode-error path was never the
    /// load-bearing recovery mechanism.
    pub(in crate::daemon) fn maybe_restart_stuck_tunnel(&mut self, from_nid: NodeId) -> bool {
        let now = self.timers.now();
        let restart = self.dp.tunnels.get(&from_nid).is_none_or(|t| {
            !t.status.validkey
                && t.last_req_key
                    .is_none_or(|last| now.duration_since(last).as_secs() >= 10)
        });
        if restart {
            self.send_req_key(from_nid)
        } else {
            false
        }
    }

    /// Relay leg of `on_req_key`: `to_nid != self.myself`. Returns
    /// `None` if the message is for us (caller handles locally),
    /// `Some(nw)` once forwarded or dropped.
    ///
    /// Two relay shapes: `SPTPS_PACKET` goes via `send_sptps_data_relay`
    /// (may shortcut to UDP); everything else forwards verbatim over
    /// the meta nexthop, optionally appending `from`'s reflexive UDP
    /// addr for the punch hint (see body comment).
    fn relay_req_key(
        &mut self,
        to_nid: NodeId,
        from_nid: NodeId,
        msg: &ReqKey,
        body_str: &str,
        conn_name: &str,
    ) -> Option<bool> {
        if to_nid == self.myself {
            return None;
        }
        // Hub doesn't relay key requests for indirect peers.
        if self.settings.tunnelserver {
            return Some(false);
        }
        if !self.graph.node(to_nid).is_some_and(|n| n.reachable) {
            log::warn!(target: "tincd::proto",
                       "Got REQ_KEY from {conn_name} destination {} \
                        which is not reachable", msg.to);
            return Some(false);
        }
        // SPTPS_PACKET relay: decode + send_sptps_data (may go
        // UDP). Only when FMODE_INTERNAL; else falls through to
        // verbatim-forward.
        if let Some(ext) = &msg.ext
            && ext.reqno == Request::SptpsPacket as i32
            && self.settings.forwarding_mode == ForwardingMode::Internal
        {
            let Some(payload) = ext.payload.as_deref() else {
                return Some(false);
            };
            let Some(data) = tinc_crypto::b64::decode(payload) else {
                log::error!(target: "tincd::proto",
                                "Got bad SPTPS_PACKET relay from {}",
                                msg.from);
                return Some(false);
            };
            log::debug!(target: "tincd::proto",
                            "Relaying SPTPS_PACKET {} → {} ({} bytes)",
                            msg.from, msg.to, data.len());
            let mut nw = self.send_sptps_data_relay(to_nid, from_nid, 0, Some(&data));
            nw |= self.try_tx(to_nid, true);
            return Some(nw);
        }
        // Forward verbatim.
        //
        // Tier-0 punch coordination: append `from`'s observed UDP
        // addr, mirroring the ANS_KEY append below. The ANS_KEY
        // append teaches the *initiator* where to punch the
        // *responder*; this teaches the responder where to punch
        // the initiator. Both legs of one handshake → both sides
        // punch within ~1 RTT → simultaneous open.
        //
        // Gates (same shape as ANS_KEY's):
        // - `msg.udp_addr.is_none()`: first relay only (no double-append
        //   over multi-hop - each hop sees a different src addr; only
        //   the first one is what `from` actually mapped through)
        // - `ext.reqno == REQ_KEY`: SPTPS-init only (the message that
        //   has a payload to anchor against; SPTPS_PACKET goes via
        //   send_sptps_data above and doesn't reach here)
        // - `from`'s tunnel has a `udp_addr`: we've actually seen UDP
        //   from them (set by recvfrom in net.rs or by ADD_EDGE/UDP_INFO)
        //
        // Dropped from the ANS_KEY recipe: `to->minmtu > 0` ("is `to`
        // already using UDP"). For REQ_KEY the responder hasn't started
        // yet - minmtu is always 0 here. The append is *speculative*:
        // worst case the responder probes a closed port. Same risk as
        // ADD_EDGE's port guess.
        //
        // Wire compat: legacy peers parse the payload with `%s`,
        // which stops at whitespace; trailing tokens are silently
        // dropped. Relays forward verbatim including the append.
        // So a Rust→C→Rust path works; a C endpoint just doesn't
        // see the hint.
        let appended = if msg.udp_addr.is_none()
            && msg
                .ext
                .as_ref()
                .is_some_and(|e| e.reqno == Request::ReqKey as i32)
        {
            self.dp
                .tunnels
                .get(&from_nid)
                .and_then(|t| t.udp_addr)
                .map(|from_addr| {
                    log::debug!(target: "tincd::proto",
                                "Appending reflexive UDP address to \
                                 REQ_KEY from {} to {}",
                                msg.from, msg.to);
                    let (a, p) = local_addr::format_addr_port(&from_addr);
                    format!("{body_str} {a} {p}")
                })
        } else {
            None
        };
        let Some(conn_id) = self.conn_for_nexthop(to_nid) else {
            log::warn!(target: "tincd::proto",
                       "No nexthop connection toward {} for REQ_KEY relay",
                       msg.to);
            return Some(false);
        };
        let Some(conn) = self.conns.get_mut(conn_id) else {
            return Some(false);
        };
        log::debug!(target: "tincd::proto",
                    "Relaying REQ_KEY {} → {}", msg.from, msg.to);
        Some(match appended {
            Some(a) => conn.send(format_args!("{a}")),
            None => conn.send(format_args!("{body_str}")),
        })
    }

    /// Per-tunnel SPTPS responder side. `REQ_KEY` is heavily
    /// overloaded; `to == myself` + `ext.reqno == REQ_KEY` ⇒ peer
    /// initiating SPTPS ⇒ start as responder, feed their KEX.
    /// `REQ_PUBKEY/ANS_PUBKEY`: hard-error.
    pub(in crate::daemon) fn on_req_key(
        &mut self,
        from_conn: ConnId,
        body: &[u8],
    ) -> Result<bool, DispatchError> {
        let (body_str, msg) = crate::dispatch::parse_key_msg(body, "REQ_KEY", ReqKey::parse)?;

        // lookup, NOT lookup_or_add.
        let Some((conn_name, from_nid, to_nid)) =
            self.routed_prologue(from_conn, "REQ_KEY", &msg.from, &msg.to)
        else {
            return Ok(false);
        };

        if let Some(nw) = self.relay_req_key(to_nid, from_nid, &msg, body_str, &conn_name) {
            return Ok(nw);
        }

        if !self.graph.node(from_nid).is_some_and(|n| n.reachable) {
            log::error!(target: "tincd::proto",
                        "Got REQ_KEY from {conn_name} origin {} which is unreachable",
                        msg.from);
            return Ok(false);
        }

        let Some(ext) = &msg.ext else {
            // Legacy 3-token form (cleartext-hex session key
            // exchange). SPTPS-only build - log + reject.
            log::error!(target: "tincd::proto",
                        "Got legacy REQ_KEY from {} (no SPTPS extension)",
                        msg.from);
            return Ok(false);
        };

        // reqno: REQ_KEY=15 SPTPS-init, REQ_PUBKEY=19,
        // ANS_PUBKEY=20, SPTPS_PACKET=21.
        if ext.reqno == Request::SptpsPacket as i32 {
            // ─── case SPTPS_PACKET ───────────────────────────────
            let Some(payload) = ext.payload.as_deref() else {
                log::error!(target: "tincd::proto",
                            "Got bad SPTPS_PACKET from {}: no payload",
                            msg.from);
                return Ok(false);
            };
            let Some(data) = tinc_crypto::b64::decode(payload) else {
                log::error!(target: "tincd::proto",
                            "Got bad SPTPS_PACKET from {}: invalid SPTPS data",
                            msg.from);
                return Ok(false);
            };
            let Some(sptps) = self
                .dp
                .tunnels
                .get_mut(&from_nid)
                .and_then(|t| t.sptps.as_deref_mut())
            else {
                // Tunnel-stuck restart.
                log::warn!(target: "tincd::proto",
                           "Got SPTPS_PACKET from {} but no SPTPS state",
                           msg.from);
                return Ok(self.send_req_key(from_nid));
            };
            let result = sptps.receive(&data, &mut OsRng);
            let outs = match result {
                Ok((_consumed, outs)) => outs,
                Err(e) => {
                    log::warn!(target: "tincd::proto",
                               "Failed to decode SPTPS_PACKET from {}: {e:?}",
                               msg.from);
                    return Ok(self.maybe_restart_stuck_tunnel(from_nid));
                }
            };
            // `to.via == myself` trivially holds for `to == myself`.
            let mut nw = self.dispatch_tunnel_outputs(from_nid, &msg.from, outs);
            nw |= self.send_mtu_info(from_nid, &msg.from, i32::from(MTU), true);
            nw |= self.send_udp_info(from_nid, &msg.from, true);
            return Ok(nw);
        }
        if ext.reqno != Request::ReqKey as i32 {
            // REQ_PUBKEY/ANS_PUBKEY: hard-error - operator provisions
            // by hand.
            log::error!(target: "tincd::proto",
                       "Got REQ_KEY ext reqno={} from {}: REQ_PUBKEY/\
                        ANS_PUBKEY unsupported - provision hosts/{} with \
                        Ed25519PublicKey",
                       ext.reqno, msg.from, msg.from);
            return Ok(false);
        }

        // ─── case REQ_KEY: SPTPS responder start.
        let Some((hiskey, aead)) = self.load_peer_tunnel_cfg(&msg.from) else {
            // Hard-error.
            log::error!(target: "tincd::proto",
                       "No Ed25519 key known for {}; cannot start tunnel \
                        - provision hosts/{} with Ed25519PublicKey",
                       msg.from, msg.from);
            return Ok(false);
        };

        // Crossed-REQ_KEY tie-break. If both sides initiated
        // simultaneously, an unconditional reset (as C tinc does)
        // leaves both as Responder → stall → both retry as
        // Initiator → livelock (no jitter on our `last_req_key`).
        // Greater name keeps Initiator and drops the REQ_KEY; lesser
        // resets to Responder below. Only when handshake is still in
        // flight (`!validkey` + Initiator) — otherwise peer is
        // legitimately re-initiating. See
        // `tests/two_daemons/reqkey_race.rs`.
        if let Some(t) = self.dp.tunnels.get(&from_nid)
            && let Some(sptps) = t.sptps.as_deref()
        {
            if !t.status.validkey
                && sptps.role() == Role::Initiator
                && self.name.as_str() > msg.from.as_str()
            {
                log::debug!(target: "tincd::proto",
                            "Got REQ_KEY from {} while already Initiator; \
                             keeping role (name tie-break)",
                            msg.from);
                return Ok(false);
            }
            log::debug!(target: "tincd::proto",
                        "Got REQ_KEY from {} while SPTPS already started; restarting",
                        msg.from);
        }

        let Some(payload) = ext.payload.as_deref() else {
            log::error!(target: "tincd::proto",
                        "Got bad REQ_SPTPS_START from {}: no payload", msg.from);
            return Ok(false);
        };
        let Some(kex_bytes) = tinc_crypto::b64::decode(payload) else {
            log::error!(target: "tincd::proto",
                        "Got bad REQ_SPTPS_START from {}: invalid SPTPS data",
                        msg.from);
            return Ok(false);
        };

        // Label has initiator's name first (same both sides).
        let label = make_udp_label(&msg.from, &self.name);
        let mykey = SigningKey::from_blob(&self.mykey.to_blob());
        let (mut sptps, init_outs) = Sptps::start_with(
            Role::Responder,
            Framing::Datagram,
            self.peer_sptps_kex(&msg.from),
            mykey,
            hiskey,
            tinc_sptps::SptpsLabel::with_aead(label, aead),
            self.settings.replaywin,
            &mut OsRng,
        );

        // Feed their KEX.
        let recv_result = sptps.receive(&kex_bytes, &mut OsRng);

        // Stash SPTPS before dispatching outputs.
        let now = self.timers.now();
        let tunnel = self.dp.tunnels.entry(from_nid).or_default();
        // Same salvage as `send_req_key`: peer is re-initiating but
        // their UDP datagrams already on the wire (and anything the
        // RX fast path is still mirroring through stale
        // `tunnel_handles.inkey`) are sealed under the OLD session.
        if let Some(old) = tunnel.sptps.take()
            && old.incipher_key().is_some()
        {
            tunnel.prev_sptps = Some(old);
            tunnel.prev_sptps_installed_at = Some(now);
        }
        tunnel.sptps = Some(Box::new(sptps));
        tunnel.status.validkey = false;
        tunnel.status.waitingforkey = true;
        tunnel.status.sptps = true;
        tunnel.last_req_key = Some(now);

        let mut hint_nw = self.send_mtu_info(from_nid, &msg.from, i32::from(MTU), true);
        hint_nw |= self.send_udp_info(from_nid, &msg.from, true);

        // Tier-0 punch coordination, responder side: a relay between us and
        // `from` may have appended `from`'s NAT-reflexive UDP address. Stash
        // it now (REQ_KEY arrives *before* validkey - unlike ANS_KEY's
        // gate). The threat: a relay could lie. But the relay is already
        // in the meta path (it's relaying our SPTPS handshake) so it can
        // already drop packets to deny the punch. Worst case we send one
        // probe to a relay-chosen address; the SPTPS data plane never goes
        // there (`udp_confirmed` is set only by an *authenticated* probe
        // reply, see `udp_probe_h`). Same risk envelope as ADD_EDGE's
        // unauthenticated `addr` field, which we already trust for the same
        // purpose.
        if let Some((addr_s, port_s)) = &msg.udp_addr
            && let Some(addr) = local_addr::parse_addr_port(addr_s.as_str(), port_s.as_str())
        {
            log::debug!(target: "tincd::proto",
                        "Relay-observed UDP address for {} (REQ_KEY): {addr}",
                        msg.from);
            let t = self.dp.tunnels.entry(from_nid).or_default();
            t.udp_addr = Some(addr);
            t.udp_addr_cached = None;
        }

        // Responder start() always emits KEX (→ ANS_KEY via
        // send_sptps_data, no init special-case). receive(init's
        // KEX) just stashes - recv_outs is empty here.
        let mut nw = hint_nw;
        nw |= self.dispatch_tunnel_outputs(from_nid, &msg.from, init_outs);
        match recv_result {
            Ok((_consumed, recv_outs)) => {
                nw |= self.dispatch_tunnel_outputs(from_nid, &msg.from, recv_outs);
            }
            Err(e) => {
                log::error!(target: "tincd::proto",
                            "Failed to decode REQ_KEY SPTPS data from {}: {e:?}",
                            msg.from);
                // Don't drop conn.
            }
        }

        // Tier-0: if the relay gave us `from`'s address (stashed above),
        // probe immediately. validkey may already be set (responder's
        // HandshakeDone fires inside the dispatch above when the SIG
        // round-trip completes via init_outs/recv_outs); if it isn't yet,
        // try_udp fires the probe but send_probe_record gates on validkey
        // and returns false - no harm. The next periodic tick (≤1s) catches
        // the case where the SIG/ACK is still in flight over the meta link.
        if msg.udp_addr.is_some() {
            let now = self.timers.now();
            nw |= self.try_udp(from_nid, &msg.from, now);
        }
        Ok(nw)
    }

    /// SPTPS branch only. b64-decode key field, feed to
    /// `tunnels[from].sptps`. Legacy branch not present.
    pub(in crate::daemon) fn on_ans_key(
        &mut self,
        from_conn: ConnId,
        body: &[u8],
    ) -> Result<bool, DispatchError> {
        let (body_str, msg) = crate::dispatch::parse_key_msg(body, "ANS_KEY", AnsKey::parse)?;

        let Some((conn_name, from_nid, to_nid)) =
            self.routed_prologue(from_conn, "ANS_KEY", &msg.from, &msg.to)
        else {
            return Ok(false);
        };

        // Relay.
        if to_nid != self.myself {
            if self.settings.tunnelserver {
                return Ok(false);
            }
            if !self.graph.node(to_nid).is_some_and(|n| n.reachable) {
                log::warn!(target: "tincd::proto",
                           "Got ANS_KEY from {conn_name} destination {} \
                            which is not reachable", msg.to);
                return Ok(false);
            }
            // Three gates - first relay only (no double-append), we
            // have a UDP addr for from, `to.minmtu>0` (to is actively
            // using UDP so reflexive addr is useful).
            let appended = if msg.udp_addr.is_none() {
                let from_udp = self.dp.tunnels.get(&from_nid).and_then(|t| t.udp_addr);
                let to_minmtu = self
                    .dp
                    .tunnels
                    .get(&to_nid)
                    .map_or(0, crate::tunnel::TunnelState::minmtu);
                match from_udp {
                    Some(from_addr) if to_minmtu > 0 => {
                        log::debug!(target: "tincd::proto",
                                    "Appending reflexive UDP address to \
                                     ANS_KEY from {} to {}", msg.from, msg.to);
                        let (a, p) = local_addr::format_addr_port(&from_addr);
                        Some(format!("{body_str} {a} {p}"))
                    }
                    _ => None,
                }
            } else {
                None
            };
            let Some(conn_id) = self.conn_for_nexthop(to_nid) else {
                log::warn!(target: "tincd::proto",
                           "No nexthop connection toward {} for ANS_KEY relay",
                           msg.to);
                return Ok(false);
            };
            let Some(conn) = self.conns.get_mut(conn_id) else {
                return Ok(false);
            };
            log::debug!(target: "tincd::proto",
                        "Relaying ANS_KEY {} → {}", msg.from, msg.to);
            // Forward verbatim (or with append).
            return Ok(match appended {
                Some(a) => conn.send(format_args!("{a}")),
                None => conn.send(format_args!("{body_str}")),
            });
        }

        // Reject LzoHi (11): minilzo lacks `lzo1x_999_compress`, so
        // surface it here instead of silent packet loss on their side.
        let their_compression = u8::try_from(msg.compression).unwrap_or(0);
        if matches!(
            crate::compress::Level::from_wire(their_compression),
            crate::compress::Level::LzoHi
        ) {
            log::error!(target: "tincd::proto",
                        "Node {} uses bogus compression level {}: \
                         LZO level 11 (lzo1x_999) is unavailable on this node",
                        msg.from, their_compression);
            return Ok(false); // don't terminate meta conn
        }
        self.dp.tunnels.entry(from_nid).or_default().outcompression = their_compression;

        let Some(hs_bytes) = tinc_crypto::b64::decode(&msg.key) else {
            log::error!(target: "tincd::proto",
                        "Got bad ANS_KEY from {}: invalid SPTPS data", msg.from);
            return Ok(false);
        };

        // SPTPS must already exist (send_req_key set it).
        let Some(sptps) = self
            .dp
            .tunnels
            .get_mut(&from_nid)
            .and_then(|t| t.sptps.as_deref_mut())
        else {
            log::warn!(target: "tincd::proto",
                       "Got ANS_KEY from {} but no SPTPS state; restarting",
                       msg.from);
            return Ok(self.send_req_key(from_nid));
        };

        let result = sptps.receive(&hs_bytes, &mut OsRng);
        let outs = match result {
            Ok((_consumed, outs)) => outs,
            Err(e) => {
                // Same gate as the UDP/SPTPS_PACKET decode-error
                // sites: only escalate if `!validkey`. A stale or
                // duplicated ANS_KEY (relay re-forward, peer retried
                // before our REQ_KEY arrived) landing AFTER
                // HandshakeDone would otherwise nuke a healthy
                // session here - the production log line that
                // motivated this fix was exactly this site.
                log::debug!(target: "tincd::proto",
                            "Failed to decode ANS_KEY SPTPS data from {}: {e:?}",
                            msg.from);
                return Ok(self.maybe_restart_stuck_tunnel(from_nid));
            }
        };

        let mut nw = self.dispatch_tunnel_outputs(from_nid, &msg.from, outs);

        // Two gates - validkey (set above on HandshakeDone; without
        // it the addr could be a replay) + relay appended one.
        if let Some((addr_s, port_s)) = &msg.udp_addr {
            let validkey = self
                .dp
                .tunnels
                .get(&from_nid)
                .is_some_and(|t| t.status.validkey);
            if validkey
                && let Some(addr) = local_addr::parse_addr_port(addr_s.as_str(), port_s.as_str())
            {
                log::debug!(target: "tincd::proto",
                                "Using reflexive UDP address from {}: {addr}",
                                msg.from);
                let t = self.dp.tunnels.entry(from_nid).or_default();
                t.udp_addr = Some(addr);
                t.udp_addr_cached = None; // stale: reflexive addr supersedes

                // Tier-0 punch coordination, initiator side: validkey just
                // went true (HandshakeDone in dispatch_tunnel_outputs above)
                // and we have a fresh relay-observed address. Probe NOW -
                // don't wait for the next periodic try_tx tick (up to 1s
                // away). The responder fired their probe ~1⁄2 RTT ago when
                // *their* HandshakeDone landed (REQ_KEY's append + the
                // try_tx call after dispatch). Both probes in flight
                // simultaneously is the difference between "NAT sees
                // reply-to-my-outbound" and "NAT sees unsolicited inbound".
                let now = self.timers.now();
                nw |= self.try_udp(from_nid, &msg.from, now);
            }
        }

        nw |= self.send_mtu_info(from_nid, &msg.from, i32::from(MTU), true);
        Ok(nw)
    }

    /// `key_changed_h`. SPTPS-only build doesn't act on it; just
    /// dedup + forward. Re-formatted rather than forwarded raw so
    /// trailing padding (sscanf-compat parsers ignore extra tokens)
    /// isn't stored in `seen` or re-broadcast.
    pub(in crate::daemon) fn on_key_changed(
        &mut self,
        from_conn: ConnId,
        body: &[u8],
    ) -> Result<bool, DispatchError> {
        let (s, kc) = crate::dispatch::parse_key_msg(body, "KEY_CHANGED", KeyChanged::parse)?;
        if !tinc_proto::check_id(&kc.node) {
            return Err(DispatchError::BadKey("KEY_CHANGED: bad node name".into()));
        }

        // Canonical form: wire nonce kept for the forwarded line (C
        // peers key on it); `seen.check` strips it for dedup. Padding
        // dropped. `Tok` capped each token at 2048B.
        let mut t = s.split_ascii_whitespace();
        let req = t.next().unwrap_or("14");
        let nonce = t.next().unwrap_or("0");
        let canonical = format!("{req} {nonce} {}", kc.node);

        if self.seen.check(&canonical, self.timers.now()) || self.settings.tunnelserver {
            return Ok(false);
        }
        Ok(self.forward_request(from_conn, canonical.as_bytes()))
    }
}
