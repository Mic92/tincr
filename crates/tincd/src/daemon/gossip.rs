#![forbid(unsafe_code)]

use super::{ConnId, Daemon, ForwardingMode};

use crate::graph_glue::{Transition, run_graph};
use crate::listen::fmt_addr;
use crate::node_id::NodeId6;
use crate::proto::{
    DispatchError, parse_add_edge, parse_add_subnet, parse_del_edge, parse_del_subnet,
};
use crate::tunnel::{MTU, TunnelState, make_udp_label};
use crate::{compress, local_addr};

use rand_core::{OsRng, RngCore};
use tinc_crypto::sign::SigningKey;
use tinc_graph::{EdgeId, NodeId};
use tinc_proto::msg::{AddEdge, AnsKey, DelEdge, ReqKey, SubnetMsg};
use tinc_proto::{AddrStr, Request, Subnet};
use tinc_sptps::{Framing, Role, Sptps};

impl Daemon {
    /// Lookup-or-add fused. Does NOT add a `NodeState` — transitives
    /// are in the graph only.
    pub(super) fn lookup_or_add_node(&mut self, name: &str) -> NodeId {
        if let Some(&id) = self.node_ids.get(name) {
            return id;
        }
        let id = self.graph.add_node(name);
        // Graph crate defaults reachable=true; zero it so run_graph
        // emits BecameReachable.
        self.graph.set_reachable(id, false);
        self.node_ids.insert(name.to_owned(), id);
        self.id6_table.add(name, id);
        id
    }

    /// Start per-tunnel SPTPS as initiator; send KEX via `REQ_KEY`.
    ///
    /// `Sptps::start` returns `Vec<Output>`. First Wire goes via
    /// `REQ_KEY`; subsequent (none from `start()`) would go via `ANS_KEY`.
    ///
    /// `REQ_PUBKEY`: hard-errored. Operator provisions `hosts/{to}`.
    pub(super) fn send_req_key(&mut self, to_nid: NodeId) -> bool {
        let Some(to_name) = self.graph.node(to_nid).map(|n| n.name.clone()) else {
            return false;
        };

        // Re-reads every call (10s debounce gates it).
        let host_config = {
            let host_file = self.confbase.join("hosts").join(&to_name);
            let mut cfg = tinc_conf::Config::default();
            if let Ok(entries) = tinc_conf::parse_file(&host_file) {
                cfg.merge(entries);
            }
            cfg
        };
        let Some(hiskey) =
            crate::keys::read_ecdsa_public_key(&host_config, &self.confbase, &to_name)
        else {
            // Hard-error: surface in logs, not as silent drops.
            // Operator provisions by hand.
            log::warn!(target: "tincd::net",
                       "No Ed25519 key known for {to_name}; cannot start tunnel");
            return false;
        };

        // Initiator name first in label.
        let label = make_udp_label(&self.name, &to_name);

        let mykey = SigningKey::from_blob(&self.mykey.to_blob());
        let (sptps, outs) = Sptps::start(
            Role::Initiator,
            Framing::Datagram,
            mykey,
            hiskey,
            label,
            self.settings.replaywin,
            &mut OsRng,
        );
        let now = self.timers.now();
        let tunnel = self.tunnels.entry(to_nid).or_default();
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
                        Request::ReqKey as u8,
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

    /// Per-tunnel SPTPS responder side. `REQ_KEY` is heavily
    /// overloaded; `to == myself` + `ext.reqno == REQ_KEY` ⇒ peer
    /// initiating SPTPS ⇒ start as responder, feed their KEX.
    /// `REQ_PUBKEY/ANS_PUBKEY`: hard-error.
    #[allow(clippy::too_many_lines)] // relay path, SPTPS_PACKET deliver, SPTPS-init responder — three disjoint protocols multiplexed on one request type
    pub(super) fn on_req_key(
        &mut self,
        from_conn: ConnId,
        body: &[u8],
    ) -> Result<bool, DispatchError> {
        let body_str = std::str::from_utf8(body)
            .map_err(|_| DispatchError::BadKey("non-UTF-8 REQ_KEY".into()))?;
        let msg = ReqKey::parse(body_str)
            .map_err(|_| DispatchError::BadKey("REQ_KEY parse failed".into()))?;

        let conn_name = self
            .conns
            .get(from_conn)
            .expect("dispatched from live conn")
            .name
            .clone();

        // lookup, NOT lookup_or_add.
        let Some(&from_nid) = self.node_ids.get(&msg.from) else {
            log::error!(target: "tincd::proto",
                        "Got REQ_KEY from {conn_name} origin {} which is unknown",
                        msg.from);
            return Ok(false);
        };
        let Some(&to_nid) = self.node_ids.get(&msg.to) else {
            log::error!(target: "tincd::proto",
                        "Got REQ_KEY from {conn_name} destination {} which is unknown",
                        msg.to);
            return Ok(false);
        };

        if to_nid != self.myself {
            // Hub doesn't relay key requests for indirect peers.
            if self.settings.tunnelserver {
                return Ok(false);
            }
            if !self.graph.node(to_nid).is_some_and(|n| n.reachable) {
                log::warn!(target: "tincd::proto",
                           "Got REQ_KEY from {conn_name} destination {} \
                            which is not reachable", msg.to);
                return Ok(false);
            }
            // SPTPS_PACKET relay: decode + send_sptps_data (may go
            // UDP). Only when FMODE_INTERNAL; else falls through to
            // verbatim-forward.
            if let Some(ext) = &msg.ext
                && ext.reqno == Request::SptpsPacket as i32
                && self.settings.forwarding_mode == ForwardingMode::Internal
            {
                let Some(payload) = ext.payload.as_deref() else {
                    return Ok(false);
                };
                let Some(data) = tinc_crypto::b64::decode(payload) else {
                    log::error!(target: "tincd::proto",
                                    "Got bad SPTPS_PACKET relay from {}",
                                    msg.from);
                    return Ok(false);
                };
                log::debug!(target: "tincd::proto",
                                "Relaying SPTPS_PACKET {} → {} ({} bytes)",
                                msg.from, msg.to, data.len());
                let mut nw = self.send_sptps_data_relay(to_nid, from_nid, 0, Some(&data));
                nw |= self.try_tx(to_nid, true);
                return Ok(nw);
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
            //   over multi-hop — each hop sees a different src addr; only
            //   the first one is what `from` actually mapped through)
            // - `ext.reqno == REQ_KEY`: SPTPS-init only (the message that
            //   has a payload to anchor against; SPTPS_PACKET goes via
            //   send_sptps_data above and doesn't reach here)
            // - `from`'s tunnel has a `udp_addr`: we've actually seen UDP
            //   from them (set by recvfrom in net.rs or by ADD_EDGE/UDP_INFO)
            //
            // Dropped from the ANS_KEY recipe: `to->minmtu > 0` ("is `to`
            // already using UDP"). For REQ_KEY the responder hasn't started
            // yet — minmtu is always 0 here. The append is *speculative*:
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
                self.tunnels
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
                return Ok(false);
            };
            let Some(conn) = self.conns.get_mut(conn_id) else {
                return Ok(false);
            };
            log::debug!(target: "tincd::proto",
                        "Relaying REQ_KEY {} → {}", msg.from, msg.to);
            return Ok(match appended {
                Some(a) => conn.send(format_args!("{a}")),
                None => conn.send(format_args!("{body_str}")),
            });
        }

        if !self.graph.node(from_nid).is_some_and(|n| n.reachable) {
            log::error!(target: "tincd::proto",
                        "Got REQ_KEY from {conn_name} origin {} which is unreachable",
                        msg.from);
            return Ok(false);
        }

        let Some(ext) = &msg.ext else {
            // Legacy 3-token form (cleartext-hex session key
            // exchange). SPTPS-only build — log + reject.
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
                    let now = self.timers.now();
                    let gate_ok = self.tunnels.get(&from_nid).is_none_or(|t| {
                        t.last_req_key
                            .is_none_or(|last| now.duration_since(last).as_secs() >= 10)
                    });
                    if gate_ok {
                        return Ok(self.send_req_key(from_nid));
                    }
                    return Ok(false);
                }
            };
            // `to.via == myself` trivially holds for `to == myself`.
            let mut nw = self.dispatch_tunnel_outputs(from_nid, &msg.from, outs);
            nw |= self.send_mtu_info(from_nid, &msg.from, i32::from(MTU), true);
            nw |= self.send_udp_info(from_nid, &msg.from, true);
            return Ok(nw);
        }
        if ext.reqno != Request::ReqKey as i32 {
            // REQ_PUBKEY/ANS_PUBKEY: hard-error — operator provisions
            // by hand.
            log::error!(target: "tincd::proto",
                       "Got REQ_KEY ext reqno={} from {}: REQ_PUBKEY/\
                        ANS_PUBKEY unsupported — provision hosts/{} with \
                        Ed25519PublicKey",
                       ext.reqno, msg.from, msg.from);
            return Ok(false);
        }

        // ─── case REQ_KEY: SPTPS responder start.
        // Same loader as send_req_key.
        let host_config = {
            let host_file = self.confbase.join("hosts").join(&msg.from);
            let mut cfg = tinc_conf::Config::default();
            if let Ok(entries) = tinc_conf::parse_file(&host_file) {
                cfg.merge(entries);
            }
            cfg
        };
        let Some(hiskey) =
            crate::keys::read_ecdsa_public_key(&host_config, &self.confbase, &msg.from)
        else {
            // Hard-error.
            log::error!(target: "tincd::proto",
                       "No Ed25519 key known for {}; cannot start tunnel \
                        — provision hosts/{} with Ed25519PublicKey",
                       msg.from, msg.from);
            return Ok(false);
        };

        // Peer re-initiating; the assignment below resets state.
        if self
            .tunnels
            .get(&from_nid)
            .is_some_and(|t| t.sptps.is_some())
        {
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
        let (mut sptps, init_outs) = Sptps::start(
            Role::Responder,
            Framing::Datagram,
            mykey,
            hiskey,
            label,
            self.settings.replaywin,
            &mut OsRng,
        );

        // Feed their KEX.
        let recv_result = sptps.receive(&kex_bytes, &mut OsRng);

        // Stash SPTPS before dispatching outputs.
        let now = self.timers.now();
        let tunnel = self.tunnels.entry(from_nid).or_default();
        tunnel.sptps = Some(Box::new(sptps));
        tunnel.status.validkey = false;
        tunnel.status.waitingforkey = true;
        tunnel.status.sptps = true;
        tunnel.last_req_key = Some(now);

        let mut hint_nw = self.send_mtu_info(from_nid, &msg.from, i32::from(MTU), true);
        hint_nw |= self.send_udp_info(from_nid, &msg.from, true);

        // Tier-0 punch coordination, responder side: a relay between us and
        // `from` may have appended `from`'s NAT-reflexive UDP address. Stash
        // it now (REQ_KEY arrives *before* validkey — unlike ANS_KEY's
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
            let t = self.tunnels.entry(from_nid).or_default();
            t.udp_addr = Some(addr);
            t.udp_addr_cached = None;
        }

        // Responder start() always emits KEX (→ ANS_KEY via
        // send_sptps_data, no init special-case). receive(init's
        // KEX) just stashes — recv_outs is empty here.
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
        // and returns false — no harm. The next periodic tick (≤1s) catches
        // the case where the SIG/ACK is still in flight over the meta link.
        if msg.udp_addr.is_some() {
            let now = self.timers.now();
            nw |= self.try_udp(from_nid, &msg.from, now);
        }
        Ok(nw)
    }

    /// SPTPS branch only. b64-decode key field, feed to
    /// `tunnels[from].sptps`. Legacy branch not present.
    #[allow(clippy::too_many_lines)] // relay-with-append, compression check, sptps feed, reflexive-addr punch — sequential phases sharing from_nid/msg
    pub(super) fn on_ans_key(
        &mut self,
        from_conn: ConnId,
        body: &[u8],
    ) -> Result<bool, DispatchError> {
        let body_str = std::str::from_utf8(body)
            .map_err(|_| DispatchError::BadKey("non-UTF-8 ANS_KEY".into()))?;
        let msg = AnsKey::parse(body_str)
            .map_err(|_| DispatchError::BadKey("ANS_KEY parse failed".into()))?;

        let conn_name = self
            .conns
            .get(from_conn)
            .expect("dispatched from live conn")
            .name
            .clone();

        let Some(&from_nid) = self.node_ids.get(&msg.from) else {
            log::error!(target: "tincd::proto",
                        "Got ANS_KEY from {conn_name} origin {} which is unknown",
                        msg.from);
            return Ok(false);
        };
        let Some(&to_nid) = self.node_ids.get(&msg.to) else {
            log::error!(target: "tincd::proto",
                        "Got ANS_KEY from {conn_name} destination {} which is unknown",
                        msg.to);
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
            // Three gates — first relay only (no double-append), we
            // have a UDP addr for from, `to.minmtu>0` (to is actively
            // using UDP so reflexive addr is useful).
            let appended = if msg.udp_addr.is_none() {
                let from_udp = self.tunnels.get(&from_nid).and_then(|t| t.udp_addr);
                let to_minmtu = self.tunnels.get(&to_nid).map_or(0, TunnelState::minmtu);
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

        // Compression capability check. LZO 10/11 stubbed: compress()
        // returns None, peer's decompress fails. Reject explicitly so
        // misconfig surfaces in OUR logs, not as silent packet loss
        // on THEIR side.
        let their_compression = u8::try_from(msg.compression).unwrap_or(0);
        match compress::Level::from_wire(their_compression) {
            compress::Level::LzoLo | compress::Level::LzoHi => {
                log::error!(target: "tincd::proto",
                            "Node {} uses bogus compression level {}: \
                             LZO compression is unavailable on this node",
                            msg.from, their_compression);
                return Ok(false); // don't terminate meta conn
            }
            _ => {}
        }
        self.tunnels.entry(from_nid).or_default().outcompression = their_compression;

        let Some(hs_bytes) = tinc_crypto::b64::decode(&msg.key) else {
            log::error!(target: "tincd::proto",
                        "Got bad ANS_KEY from {}: invalid SPTPS data", msg.from);
            return Ok(false);
        };

        // SPTPS must already exist (send_req_key set it).
        let Some(sptps) = self
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
                // Tunnel-stuck restart, gated on last_req_key+10.
                log::warn!(target: "tincd::proto",
                           "Failed to decode ANS_KEY SPTPS data from {}: {e:?}; restarting",
                           msg.from);
                let now = self.timers.now();
                let gate_ok = self.tunnels.get(&from_nid).is_none_or(|t| {
                    t.last_req_key
                        .is_none_or(|last| now.duration_since(last).as_secs() >= 10)
                });
                if gate_ok {
                    return Ok(self.send_req_key(from_nid));
                }
                return Ok(false);
            }
        };

        let mut nw = self.dispatch_tunnel_outputs(from_nid, &msg.from, outs);

        // Two gates — validkey (set above on HandshakeDone; without
        // it the addr could be a replay) + relay appended one.
        if let Some((addr_s, port_s)) = &msg.udp_addr {
            let validkey = self
                .tunnels
                .get(&from_nid)
                .is_some_and(|t| t.status.validkey);
            if validkey
                && let Some(addr) = local_addr::parse_addr_port(addr_s.as_str(), port_s.as_str())
            {
                log::debug!(target: "tincd::proto",
                                "Using reflexive UDP address from {}: {addr}",
                                msg.from);
                let t = self.tunnels.entry(from_nid).or_default();
                t.udp_addr = Some(addr);
                t.udp_addr_cached = None; // stale: reflexive addr supersedes

                // Tier-0 punch coordination, initiator side: validkey just
                // went true (HandshakeDone in dispatch_tunnel_outputs above)
                // and we have a fresh relay-observed address. Probe NOW —
                // don't wait for the next periodic try_tx tick (up to 1s
                // away). The responder fired their probe ~½ RTT ago when
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

    /// Dedup gate; `true` = already seen, caller drops silently. Key
    /// is the whole line; the nonce token makes distinct origins
    /// distinct.
    pub(super) fn seen_request(&mut self, body: &[u8]) -> bool {
        // Parsers validated UTF-8; failure → not-seen (handler rejects).
        let Ok(s) = std::str::from_utf8(body) else {
            return false;
        };
        self.seen.check(s, self.timers.now())
    }

    /// Dedup nonce. `OsRng` (overkill, but linked + not hot).
    pub(super) fn nonce() -> u32 {
        OsRng.next_u32()
    }

    /// Vec not iterator: callers `get_mut` while sending; slotmap
    /// borrow would conflict.
    pub(super) fn broadcast_targets(&self, from: Option<ConnId>) -> Vec<ConnId> {
        self.conns
            .iter()
            .filter(|&(id, c)| Some(id) != from && c.active)
            .map(|(id, _)| id)
            .collect()
    }

    /// Re-send to every active conn except `from`. Receivers'
    /// `seen.check` + the `from` skip = loop break.
    pub(super) fn forward_request(&mut self, from: ConnId, body: &[u8]) -> bool {
        // Post-parse; from_utf8 already succeeded.
        let Ok(s) = std::str::from_utf8(body) else {
            log::warn!(target: "tincd::proto",
                       "forward_request: non-UTF-8 body, dropping");
            return false;
        };
        let targets = self.broadcast_targets(Some(from));
        if targets.is_empty() {
            return false;
        }
        log::debug!(target: "tincd::proto",
                    "Forwarding to {} peer(s): {s}", targets.len());
        let mut nw = false;
        for id in targets {
            if let Some(c) = self.conns.get_mut(id) {
                nw |= c.send(format_args!("{s}"));
            }
        }
        nw
    }

    /// `from=None` skips nothing; new/dying conn isn't `active` so
    /// filtered anyway. Format once outside loop → one nonce.
    ///
    /// `#[must_use]`: dropping the return is the `97ef5af0` bug class
    /// — line sits in outbuf until the next natural WRITE arm (up to
    /// pinginterval=60s away). Either OR into the caller's `nw`, or
    /// `let _nw =` with a comment pointing at the `maybe_set_write_any`
    /// that covers it.
    #[must_use]
    pub(super) fn broadcast_line(&mut self, line: &str) -> bool {
        let targets = self.broadcast_targets(None);
        let mut nw = false;
        for id in targets {
            if let Some(c) = self.conns.get_mut(id) {
                nw |= c.send(format_args!("{line}"));
            }
        }
        nw
    }

    /// Returns `None` if edge or addr entry missing — the
    /// synthesized reverse from `on_ack` has no addr; skip rather
    /// than emit `"unknown port unknown"` (peers would parse to
    /// `AF_UNKNOWN`, never connect).
    pub(super) fn fmt_add_edge(&self, eid: EdgeId, nonce: u32) -> Option<String> {
        let e = self.graph.edge(eid)?;
        let (addr, port, la, lp) = self.edge_addrs.get(&eid)?;
        let from = self.graph.node(e.from)?.name.clone();
        let to = self.graph.node(e.to)?.name.clone();
        // Our sentinel is "unspec" string.
        let local = if la.as_str() == AddrStr::UNSPEC {
            None
        } else {
            Some((la.clone(), lp.clone()))
        };
        let msg = AddEdge {
            from,
            to,
            addr: addr.clone(),
            port: port.clone(),
            options: e.options,
            weight: e.weight,
            local,
        };
        Some(msg.format(nonce))
    }

    /// Correction path: send back what WE know about an edge.
    pub(super) fn send_add_edge(&mut self, to: ConnId, eid: EdgeId) -> bool {
        let Some(line) = self.fmt_add_edge(eid, Self::nonce()) else {
            log::warn!(target: "tincd::proto",
                       "send_add_edge: edge {eid:?} has no addr entry, skipping");
            return false;
        };
        self.conns
            .get_mut(to)
            .is_some_and(|c| c.send(format_args!("{line}")))
    }

    /// Contradiction reply: take names directly.
    pub(super) fn send_del_edge(&mut self, to: ConnId, from_name: &str, to_name: &str) -> bool {
        let msg = DelEdge {
            from: from_name.to_owned(),
            to: to_name.to_owned(),
        };
        let line = msg.format(Self::nonce());
        self.conns
            .get_mut(to)
            .is_some_and(|c| c.send(format_args!("{line}")))
    }

    pub(super) fn send_subnet(
        &mut self,
        to: ConnId,
        which: Request,
        owner: &str,
        subnet: &Subnet,
    ) -> bool {
        let msg = SubnetMsg {
            owner: owner.to_owned(),
            subnet: *subnet,
        };
        let line = msg.format(which, Self::nonce());
        self.conns
            .get_mut(to)
            .is_some_and(|c| c.send(format_args!("{line}")))
    }

    /// Called from `on_ack`. Flatten over global trees — same wire
    /// output, order irrelevant.
    pub(super) fn send_everything(&mut self, to: ConnId) -> bool {
        if self.settings.tunnelserver {
            // ONLY myself's subnets, NO edges. Peer's edge to us
            // comes from on_ack's send_add_edge.
            let mut lines: Vec<String> = Vec::new();
            for (subnet, owner) in self.subnets.iter() {
                if owner == self.name.as_str() {
                    let msg = SubnetMsg {
                        owner: owner.to_owned(),
                        subnet: *subnet,
                    };
                    lines.push(msg.format(Request::AddSubnet, Self::nonce()));
                }
            }
            let Some(conn) = self.conns.get_mut(to) else {
                return false;
            };
            let mut nw = false;
            for line in lines {
                nw |= conn.send(format_args!("{line}"));
            }
            log::debug!(target: "tincd::proto",
                        "send_everything (tunnelserver) to {}: own subnets only",
                        conn.name);
            return nw;
        }
        // Pre-format: subnets.iter() borrows &self; conn.send() needs &mut.
        let mut lines: Vec<String> = Vec::new();

        for (subnet, owner) in self.subnets.iter() {
            let msg = SubnetMsg {
                owner: owner.to_owned(),
                subnet: *subnet,
            };
            lines.push(msg.format(Request::AddSubnet, Self::nonce()));
        }

        // Addr-less edges (synthesized reverse) skipped by
        // fmt_add_edge; peer learns them from the other endpoint.
        let eids: Vec<EdgeId> = self.graph.edge_iter().map(|(id, _)| id).collect();
        for eid in eids {
            if let Some(line) = self.fmt_add_edge(eid, Self::nonce()) {
                lines.push(line);
            }
        }

        let Some(conn) = self.conns.get_mut(to) else {
            return false;
        };
        let mut nw = false;
        for line in lines {
            nw |= conn.send(format_args!("{line}"));
        }
        log::debug!(target: "tincd::proto",
                    "send_everything to {}: {} subnets, {} edges sent",
                    conn.name, self.subnets.len(),
                    self.edge_addrs.len());
        nw
    }

    /// sssp + diff + mst.
    pub(super) fn run_graph_and_log(&mut self) {
        let (transitions, mst, routes) = run_graph(&mut self.graph, self.myself);
        // Side-table for dump_nodes.
        self.last_routes = routes;
        // Keep edge IDs and map at broadcast time.
        self.last_mst = mst;
        for t in transitions {
            match t {
                Transition::BecameReachable { node, via: via_nid } => {
                    // `device_enable` is idempotent so we just call
                    // on every BecameReachable; the flag inside
                    // dedups. Gated on standby: when !standby,
                    // setup() already fired tinc-up.
                    if self.settings.device_standby {
                        self.device_enable();
                    }
                    let name = self
                        .graph
                        .node(node)
                        .map_or("<unknown>", |n| n.name.as_str());
                    let via_name = self
                        .graph
                        .node(via_nid)
                        .map_or("<unknown>", |n| n.name.as_str());
                    log::info!(target: "tincd::graph",
                               "Node {name} became reachable (via {via_name})");

                    // Use edge addr from on_ack (direct neighbors).
                    // We key incoming UDP on [dst_id6][src_id6]
                    // prefix — no tree to re-index.
                    let name_owned = name.to_owned();
                    let addr = self.nodes.get(&node).and_then(|ns| ns.edge_addr);
                    if let Some(addr) = addr {
                        let tunnel = self.tunnels.entry(node).or_default();
                        tunnel.udp_addr = Some(addr);
                        tunnel.udp_addr_cached = None;
                    }

                    // host-up AFTER addr known.
                    self.run_host_script(true, &name_owned, addr);

                    // subnet-up for every owned subnet.
                    for s in &self.subnets.owned_by(&name_owned) {
                        self.run_subnet_script(true, &name_owned, s);
                    }
                    // Always true (no legacy); set for dump.
                    self.tunnels.entry(node).or_default().status.sptps = true;
                }
                Transition::BecameUnreachable { node } => {
                    let name = self
                        .graph
                        .node(node)
                        .map_or("<unknown>", |n| n.name.as_str());
                    log::info!(target: "tincd::graph",
                               "Node {name} became unreachable");

                    let name_owned = name.to_owned();
                    // Read addr BEFORE reset clears it.
                    let addr = self
                        .tunnels
                        .get(&node)
                        .and_then(|t| t.udp_addr)
                        .or_else(|| self.nodes.get(&node).and_then(|ns| ns.edge_addr));

                    self.run_host_script(false, &name_owned, addr);

                    // subnet-down for every owned subnet.
                    for s in &self.subnets.owned_by(&name_owned) {
                        self.run_subnet_script(false, &name_owned, s);
                    }

                    // reset_unreachable: sptps_stop + mtu reset +
                    // clear UDP addr.
                    if let Some(tunnel) = self.tunnels.get_mut(&node) {
                        tunnel.reset_unreachable();
                    }
                }
            }
        }
        // device_disable: check post-loop reachable count.
        if self.settings.device_standby && self.device_enabled {
            let any_reachable = self
                .graph
                .node_ids()
                .filter(|&n| n != self.myself)
                .any(|n| self.graph.node(n).is_some_and(|n| n.reachable));
            if !any_reachable {
                self.device_disable();
            }
        }
    }

    /// 21 fields per row; CLI parses 22 (`" port "` re-split).
    /// Placeholders: cipher/digest/maclength=0 (legacy-only);
    /// `last_state_change=0` (deferred). status bitfield: bit 4
    /// reachable feeds CLI's filter.
    pub(super) fn dump_nodes_rows(&self) -> Vec<String> {
        let mut rows = Vec::new();
        for nid in self.graph.node_ids() {
            let Some(node) = self.graph.node(nid) else {
                continue; // freed slot (concurrent del; defensive)
            };
            let name = node.name.as_str();

            // myself = "MYSELF port <tcp>". Direct peers: address
            // rewritten to UDP in on_ack. Transitives: literal.
            let hostname = if nid == self.myself {
                format!("MYSELF port {}", self.my_udp_port)
            } else if let Some(ea) = self.nodes.get(&nid).and_then(|ns| ns.edge_addr.as_ref()) {
                fmt_addr(ea) // "%s port %s", no v6 brackets
            } else {
                "unknown port unknown".to_string()
            };

            // options: written by sssp from incoming edge. myself: 0.
            // Unreachable: 0.
            let route = self
                .last_routes
                .get(nid.0 as usize)
                .and_then(Option::as_ref);
            let options = route.map_or(0, |r| r.options);

            // status. myself: just reachable.
            let tunnel = self.tunnels.get(&nid);
            let status = tunnel.map_or_else(
                || {
                    if node.reachable { 1 << 4 } else { 0 }
                },
                |t| t.status.as_u32(node.reachable),
            );

            // Unreachable → "-".
            let (nexthop, via, distance) = match route {
                Some(r) => {
                    let nh = self.graph.node(r.nexthop).map_or("-", |n| n.name.as_str());
                    let via = self.graph.node(r.via).map_or("-", |n| n.name.as_str());
                    (nh, via, r.distance)
                }
                None => ("-", "-", 0),
            };

            // udp_ping_rtt=-1 is the unmeasured sentinel.
            rows.push(format!(
                "{} {} {} {} {} {} {} {} {} {:x} {:x} {} {} {} {} {} {} {} {} {} {} {} {}",
                Request::Control as u8,       // %d CONTROL
                crate::proto::REQ_DUMP_NODES, // %d
                name,                         // %s
                self.id6_table.id_of(nid).unwrap_or(NodeId6::NULL), // %s id
                hostname,                     // %s ("HOST port PORT")
                0,                            // %d cipher (DISABLE_LEGACY)
                0,                            // %d digest
                0,                            // %lu maclength
                tunnel.map_or(0, |t| t.outcompression), // %d compression
                options,                      // %x
                status,                       // %x
                nexthop,                      // %s
                via,                          // %s
                distance,                     // %d
                tunnel.and_then(|t| t.pmtu.as_ref()).map_or(0, |p| p.mtu), // %d mtu
                tunnel.and_then(|t| t.pmtu.as_ref()).map_or(0, |p| p.minmtu), // %d minmtu
                tunnel.and_then(|t| t.pmtu.as_ref()).map_or(0, |p| p.maxmtu), // %d maxmtu
                0,                            // %ld last_state_change
                tunnel
                    .and_then(|t| t.pmtu.as_ref())
                    .and_then(|p| p.udp_ping_rtt)
                    .map_or(-1_i32, u32::cast_signed), // %d
                tunnel.map_or(0, |t| t.in_packets), // %PRIu64
                tunnel.map_or(0, |t| t.in_bytes),
                tunnel.map_or(0, |t| t.out_packets),
                tunnel.map_or(0, |t| t.out_bytes),
            ));
        }
        rows
    }

    /// 6 body fields; CLI parses 8 (two `" port "` re-splits).
    /// `edge_addrs` stores raw `AddrStr` tokens; format as `"%s port %s"`.
    pub(super) fn dump_edges_rows(&self) -> Vec<String> {
        let mut rows = Vec::new();
        // Order differs from a tree walk; tincctl sorts client-side
        // anyway.
        for (eid, e) in self.graph.edge_iter() {
            let from = self.node_log_name(e.from);
            let to = self.node_log_name(e.to);

            let (addr, local) = match self.edge_addrs.get(&eid) {
                Some((a, p, la, lp)) => (format!("{a} port {p}"), format!("{la} port {lp}")),
                // Synthesized reverse (see on_ack).
                None => (
                    "unknown port unknown".to_string(),
                    "unknown port unknown".to_string(),
                ),
            };

            rows.push(format!(
                "{} {} {} {} {} {} {:x} {}",
                Request::Control as u8,
                crate::proto::REQ_DUMP_EDGES,
                from,
                to,
                addr,
                local,
                e.options,
                e.weight,
            ));
        }
        rows
    }

    /// Walk all known nodes (not just tunnels): includes myself +
    /// unreachables. Nodes without a `TunnelState` emit zeros.
    pub(super) fn dump_traffic_rows(&self) -> Vec<String> {
        let mut rows = Vec::new();
        for nid in self.graph.node_ids() {
            let Some(node) = self.graph.node(nid) else {
                continue;
            };
            let t = self.tunnels.get(&nid);
            rows.push(format!(
                "{} {} {} {} {} {} {}",
                Request::Control as u8,
                crate::proto::REQ_DUMP_TRAFFIC,
                node.name.as_str(),
                t.map_or(0, |t| t.in_packets),
                t.map_or(0, |t| t.in_bytes),
                t.map_or(0, |t| t.out_packets),
                t.map_or(0, |t| t.out_bytes),
            ));
        }
        rows
    }

    /// Subnets don't change topology — NO `graph()` call.
    pub(super) fn on_add_subnet(
        &mut self,
        from_conn: ConnId,
        body: &[u8],
    ) -> Result<bool, DispatchError> {
        let (owner_name, subnet) = parse_add_subnet(body)?;

        if self.seen_request(body) {
            return Ok(false);
        }

        // tunnelserver indirect filter. Check BEFORE
        // lookup_or_add_node — don't pollute graph with indirect
        // names. ORDER: seen_request first — mark seen even on drop.
        if self.settings.tunnelserver {
            let conn_name = self
                .conns
                .get(from_conn)
                .expect("dispatched from live conn")
                .name
                .as_str();
            if owner_name != self.name && owner_name != conn_name {
                log::warn!(target: "tincd::proto",
                           "Ignoring indirect ADD_SUBNET from {conn_name} \
                            for {owner_name} ({subnet})");
                return Ok(false);
            }
        }

        // Lookup-first idempotency. With strictsubnets this lets
        // AUTHORIZED subnets through silently (load_all_nodes
        // preloaded; gossip finds it, return). UNAUTHORIZED falls
        // through. Without strictsubnets: belt-and-braces over
        // seen_request (saves lookup_or_add + script run).
        if self.subnets.contains(&subnet, &owner_name) {
            return Ok(false);
        }

        let owner = self.lookup_or_add_node(&owner_name);

        // Peer wrong about us — retaliate DEL_SUBNET.
        if owner == self.myself {
            let conn_name = self
                .conns
                .get(from_conn)
                .expect("dispatched from live conn")
                .name
                .clone();
            log::warn!(target: "tincd::proto",
                       "Got ADD_SUBNET from {conn_name} for ourself ({subnet})");
            // Dark in single-peer tests; reachable via stale gossip
            // in multi-peer mesh.
            let nw = self.send_subnet(from_conn, Request::DelSubnet, &self.name.clone(), &subnet);
            return Ok(nw);
        }

        // tunnelserver second gate. Reached when owner IS the direct
        // peer but subnet wasn't preloaded from hosts/ ("unauthorized"
        // — tunnelserver implies strictsubnets; load_all_nodes
        // preloaded those; reaching here means NOT on disk). NO
        // forward. (50800c0d fixed a spurious forward here that made
        // three_daemon_tunnelserver intermittent.)
        if self.settings.tunnelserver {
            log::warn!(target: "tincd::proto",
                       "Ignoring unauthorized ADD_SUBNET for {owner_name} \
                        ({subnet}) (tunnelserver)");
            return Ok(false);
        }

        // strictsubnets — hosts/ file is authority. Forward (others
        // may not be strict) but don't add locally.
        if self.settings.strictsubnets {
            log::warn!(target: "tincd::proto",
                       "Ignoring unauthorized ADD_SUBNET for {owner_name} \
                        ({subnet}) (strictsubnets)");
            let nw = self.forward_request(from_conn, body);
            return Ok(nw);
        }

        self.subnets.add(subnet, owner_name.clone());

        // mac_table sync for route_mac.rs.
        if let Subnet::Mac { addr, .. } = subnet {
            self.mac_table.insert(addr, owner_name.clone());

            // Fast handoff. Peer learned a MAC we also leased (VM
            // migrated). Our mac_leases only holds myself's leases,
            // so refresh()==true IS the "do we own this" check.
            // refresh(addr,now,0) → expires next age() tick.
            if owner != self.myself {
                let now = self.timers.now();
                if self.mac_leases.refresh(addr, now, 0) {
                    log::debug!(target: "tincd::proto",
                        "Fast handoff: peer {owner_name} learned our \
                         leased MAC {addr:02x?}; expiring ours");
                }
            }
        }

        // subnet-up only if reachable (else BecameReachable fires it
        // later).
        let reachable = self.graph.node(owner).is_some_and(|n| n.reachable);
        if reachable {
            self.run_subnet_script(true, &owner_name, &subnet);
        }

        // seen.check above prevents the loop.
        let nw = if self.settings.tunnelserver {
            false
        } else {
            self.forward_request(from_conn, body)
        };

        Ok(nw)
    }

    /// DEL for unknown owner/subnet is warn-and-drop (NOT
    /// `lookup_or_add`).
    pub(super) fn on_del_subnet(
        &mut self,
        from_conn: ConnId,
        body: &[u8],
    ) -> Result<bool, DispatchError> {
        let (owner_name, subnet) = parse_del_subnet(body)?;

        if self.seen_request(body) {
            return Ok(false);
        }

        let conn_name = self
            .conns
            .get(from_conn)
            .expect("dispatched from live conn")
            .name
            .clone();

        // tunnelserver indirect filter. ORDER: seen first.
        if self.settings.tunnelserver && owner_name != self.name && owner_name != conn_name {
            log::warn!(target: "tincd::proto",
                       "Ignoring indirect DEL_SUBNET from {conn_name} \
                        for {owner_name} ({subnet})");
            return Ok(false);
        }

        // NOT lookup_or_add. Warn, return.
        let Some(&owner) = self.node_ids.get(&owner_name) else {
            log::warn!(target: "tincd::proto",
                       "Got DEL_SUBNET from {conn_name} for {owner_name} \
                        which is not in our node tree");
            return Ok(false);
        };

        // Peer says we don't own a subnet we DO own. ORDERING: lookup
        // FIRST, bail if not found. Security audit `2f72c2ba`: without
        // that gate, a malicious peer sends DEL_SUBNET for a subnet
        // we never claimed; we retaliate ADD; victim adds bogus route
        // pointing at us.
        if owner == self.myself {
            // Don't lie about subnets we never owned.
            if !self.subnets.contains(&subnet, &self.name) {
                log::warn!(target: "tincd::proto",
                           "Got DEL_SUBNET from {conn_name} for ourself ({subnet}) \
                            which does not appear in our subnet tree");
                return Ok(false);
            }
            log::warn!(target: "tincd::proto",
                       "Got DEL_SUBNET from {conn_name} for ourself ({subnet})");
            let nw = self.send_subnet(from_conn, Request::AddSubnet, &self.name.clone(), &subnet);
            return Ok(nw);
        }

        // AFTER retaliate, BEFORE forward+del.
        if self.settings.tunnelserver {
            return Ok(false);
        }

        let nw = self.forward_request(from_conn, body);

        // AFTER forward, BEFORE del. (not-found-strictsubnets case
        // folds into del()==false below: same observable behavior —
        // forward, no del.)
        if self.settings.strictsubnets {
            return Ok(nw);
        }

        // ORDERING: lookup gates script + del. Security audit
        // `2f72c2ba`: subnet-down for a subnet we never up'd is a
        // peer-triggers-fork-exec DoS (flood DEL with fresh nonces).
        // Do del() FIRST. We invert script-before-del (del() returns
        // bool) — script env doesn't read the table; same behavior.
        if !self.subnets.del(&subnet, &owner_name) {
            // Warn, no script.
            log::warn!(target: "tincd::proto",
                       "Got DEL_SUBNET from {conn_name} for {owner_name} \
                        which does not appear in his subnet tree");
            return Ok(nw);
        }

        let reachable = self.graph.node(owner).is_some_and(|n| n.reachable);
        if reachable {
            self.run_subnet_script(false, &owner_name, &subnet);
        }

        // mac_table sync; only remove if owner matches (defensive).
        if let Subnet::Mac { addr, .. } = subnet
            && self.mac_table.get(&addr).map(String::as_str) == Some(owner_name.as_str())
        {
            self.mac_table.remove(&addr);
        }

        Ok(nw)
    }

    /// Edge exists with different params ⇒ update in place (`Graph::`
    /// `update_edge` keeps `EdgeId` slot stable; `edge_addrs` is keyed on
    /// it).
    pub(super) fn on_add_edge(
        &mut self,
        from_conn: ConnId,
        body: &[u8],
    ) -> Result<bool, DispatchError> {
        let edge = parse_add_edge(body)?;

        if self.seen_request(body) {
            return Ok(false);
        }

        let conn_name = self
            .conns
            .get(from_conn)
            .expect("dispatched from live conn")
            .name
            .clone();

        // Drop if NEITHER endpoint is us-or-direct-peer. Before
        // lookup_or_add. ORDER: seen first.
        if self.settings.tunnelserver
            && edge.from != self.name
            && edge.from != conn_name
            && edge.to != self.name
            && edge.to != conn_name
        {
            log::warn!(target: "tincd::proto",
                       "Ignoring indirect ADD_EDGE from {conn_name} \
                        ({} → {})", edge.from, edge.to);
            return Ok(false);
        }

        let from_id = self.lookup_or_add_node(&edge.from);
        let to_id = self.lookup_or_add_node(&edge.to);

        if let Some(existing) = self.graph.lookup_edge(from_id, to_id) {
            // Idempotent only if weight+options+ADDRESS all match.
            // The address compare matters: synthesized reverse from
            // on_ack has no edge_addrs entry; when peer's real
            // ADD_EDGE arrives (same weight/options, real addr), it
            // must fall through to update+forward. Weight-only check
            // early-returned and broke hub-spoke (three_daemon_relay
            // regression). Check edge_addrs too.
            let e = self.graph.edge(existing).expect("just looked up");
            let same_addr = self.edge_addrs.get(&existing).is_some_and(|(a, p, _, _)| {
                // Compare addr+port only. Stricter than necessary —
                // harmless (extra forward, seen dedups).
                a == &edge.addr && p == &edge.port
            });
            if e.weight == edge.weight && e.options == edge.options && same_addr {
                return Ok(false); // no forward, no graph()
            }

            // Peer's view of OUR edge is wrong.
            if from_id == self.myself {
                log::warn!(target: "tincd::proto",
                           "Got ADD_EDGE from {conn_name} for ourself \
                            which does not match existing entry");
                // Send back what WE know (existing, not wire body).
                let nw = self.send_add_edge(from_conn, existing);
                return Ok(nw);
            }

            // In-place update. NOT del+add: edge_addrs is keyed on
            // EdgeId; del+add recycles same slot only by
            // LIFO-freelist accident. update_edge makes it explicit.
            log::warn!(target: "tincd::proto",
                       "Got ADD_EDGE from {conn_name} which does not \
                        match existing entry");
            self.graph
                .update_edge(existing, edge.weight, edge.options)
                .expect("lookup_edge just returned this EdgeId; no await, no free");
            let unspec = AddrStr::unspec;
            let (la, lp) = edge.local.clone().unwrap_or_else(|| (unspec(), unspec()));
            self.edge_addrs
                .insert(existing, (edge.addr.clone(), edge.port.clone(), la, lp));
        } else if from_id == self.myself {
            // Contradiction — peer says we have an edge we don't.
            // Counter read by on_periodic_tick.
            log::warn!(target: "tincd::proto",
                       "Got ADD_EDGE from {conn_name} for ourself \
                        which does not exist");
            self.contradicting_add_edge += 1;
            // Send DEL with the wire body's names.
            let nw = self.send_del_edge(from_conn, &edge.from, &edge.to);
            return Ok(nw);
        } else {
            let eid = self
                .graph
                .add_edge(from_id, to_id, edge.weight, edge.options);
            // local optional (pre-1.0.24); default to "unspec".
            let unspec = AddrStr::unspec;
            let (la, lp) = edge.local.clone().unwrap_or_else(|| (unspec(), unspec()));
            self.edge_addrs
                .insert(eid, (edge.addr.clone(), edge.port.clone(), la, lp));
        }

        let nw = if self.settings.tunnelserver {
            false
        } else {
            self.forward_request(from_conn, body)
        };

        self.run_graph_and_log();

        Ok(nw)
    }

    /// Missing node/edge is warn-and-drop (NOT `lookup_or_add`).
    pub(super) fn on_del_edge(
        &mut self,
        from_conn: ConnId,
        body: &[u8],
    ) -> Result<bool, DispatchError> {
        let edge = parse_del_edge(body)?;

        if self.seen_request(body) {
            return Ok(false);
        }

        let conn_name = self
            .conns
            .get(from_conn)
            .expect("dispatched from live conn")
            .name
            .clone();

        // ORDER: seen first.
        if self.settings.tunnelserver
            && edge.from != self.name
            && edge.from != conn_name
            && edge.to != self.name
            && edge.to != conn_name
        {
            log::warn!(target: "tincd::proto",
                       "Ignoring indirect DEL_EDGE from {conn_name} \
                        ({} → {})", edge.from, edge.to);
            return Ok(false);
        }

        // missing → warn-and-drop (view already consistent).
        let Some(&from_id) = self.node_ids.get(&edge.from) else {
            log::warn!(target: "tincd::proto",
                       "Got DEL_EDGE from {conn_name} which does not \
                        appear in the edge tree (unknown from: {})", edge.from);
            return Ok(false);
        };
        let Some(&to_id) = self.node_ids.get(&edge.to) else {
            log::warn!(target: "tincd::proto",
                       "Got DEL_EDGE from {conn_name} which does not \
                        appear in the edge tree (unknown to: {})", edge.to);
            return Ok(false);
        };

        let Some(eid) = self.graph.lookup_edge(from_id, to_id) else {
            log::warn!(target: "tincd::proto",
                       "Got DEL_EDGE from {conn_name} which does not \
                        appear in the edge tree");
            return Ok(false);
        };

        // Peer says we DON'T have an edge we DO have.
        if from_id == self.myself {
            log::warn!(target: "tincd::proto",
                       "Got DEL_EDGE from {conn_name} for ourself");
            self.contradicting_del_edge += 1;
            // Edge exists (just looked up); send what we know.
            let nw = self.send_add_edge(from_conn, eid);
            return Ok(nw);
        }

        let mut nw = if self.settings.tunnelserver {
            false
        } else {
            self.forward_request(from_conn, body)
        };

        self.graph.del_edge(eid);
        self.edge_addrs.remove(&eid);

        self.run_graph_and_log();

        // If `to` became unreachable AND has edge back to us (the
        // synthesized reverse from on_ack), delete + broadcast.
        if !self.graph.node(to_id).is_some_and(|n| n.reachable)
            && let Some(rev) = self.graph.lookup_edge(to_id, self.myself)
        {
            if !self.settings.tunnelserver {
                let to_name = edge.to.clone();
                let my_name = self.name.clone();
                let line = DelEdge {
                    from: to_name,
                    to: my_name,
                }
                .format(Self::nonce());
                // `97ef5af0` bug class: this DEL_EDGE was queued but
                // never armed WRITE. `purge()` below CAN cover it (same
                // conns, broadcast = all active) — but only if purge has
                // anything to broadcast. After `del_edge(rev)` below,
                // `to` has zero outgoing edges; if it also owns no
                // subnets, purge pass-1 emits nothing, `nw_purge=false`,
                // and this line sits for up to pinginterval. OR it in.
                nw |= self.broadcast_line(&line);
            }
            self.graph.del_edge(rev);
            self.edge_addrs.remove(&rev);
        }

        // If the deleted edge disconnected `to` from the mesh, GC it
        // now. Without this, a node that disconnects and has its
        // edges gossiped away stays in `graph` forever — the only
        // other purge triggers are REQ_PURGE (operator-manual) and
        // the contradiction storm (rare). Our slotmap walks are
        // O(slots) for `dump_nodes`/`send_everything`. The check is
        // cheap (one `reachable` read); the actual purge runs only on
        // the unreachability transition.
        if !self.graph.node(to_id).is_some_and(|n| n.reachable) {
            let nw_purge = self.purge();
            return Ok(nw | nw_purge);
        }

        Ok(nw)
    }
}
