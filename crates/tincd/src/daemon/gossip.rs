#![forbid(unsafe_code)]

#[allow(clippy::wildcard_imports)]
use super::*;

impl Daemon {
    /// `lookup_node`+`new_node`+`node_add` fused (`node.c:74,96`). The
    /// C `if(!n) { n = new_node(); node_add(n); }` pattern. Does NOT
    /// add a `NodeState` — transitives are in the graph only.
    pub(super) fn lookup_or_add_node(&mut self, name: &str) -> NodeId {
        if let Some(&id) = self.node_ids.get(name) {
            return id;
        }
        let id = self.graph.add_node(name);
        // C `node.c:75`: xzalloc → reachable=false. Graph crate
        // defaults true; zero it so run_graph emits BecameReachable.
        self.graph.set_reachable(id, false);
        self.node_ids.insert(name.to_owned(), id);
        self.id6_table.add(name, id); // C node.c:126-131
        id
    }

    /// `send_req_key` (`protocol_key.c:114-135`) + `send_initial_sptps_data`
    /// (`:103-112`). Start per-tunnel SPTPS as initiator; send KEX via REQ_KEY.
    ///
    /// C splits into two functions for the re-entrant callback dance;
    /// our `Sptps::start` returns `Vec<Output>` instead. First Wire goes
    /// via REQ_KEY; subsequent (none from start()) would go via ANS_KEY.
    ///
    /// C `:116-120` REQ_PUBKEY: hard-errored. Operator provisions `hosts/{to}`.
    pub(super) fn send_req_key(&mut self, to_nid: NodeId) -> bool {
        let Some(to_name) = self.graph.node(to_nid).map(|n| n.name.clone()) else {
            return false;
        };

        // C `:116-120`: `node_read_ecdsa_public_key(to)`. Re-reads
        // every call (C caches lazily; we don't — 10s debounce gates it).
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
            // C `:117-119` sends REQ_PUBKEY. We hard-error: surface
            // in logs, not as silent drops. Operator provisions by hand.
            log::warn!(target: "tincd::net",
                       "No Ed25519 key known for {to_name}; cannot start tunnel");
            return false;
        };

        // C `:122-124`: initiator name first in label.
        let label = make_udp_label(&self.name, &to_name);

        // C `:126-131`: sptps_stop; validkey=false; waitingforkey=true;
        // sptps_start(..., true, true, ...) — initiator, datagram.
        let mykey = SigningKey::from_blob(&self.mykey.to_blob());
        let (sptps, outs) = Sptps::start(
            Role::Initiator,
            Framing::Datagram,
            mykey,
            hiskey,
            label,
            16, // C `sptps_replaywin` default
            &mut OsRng,
        );
        let now = self.timers.now();
        let tunnel = self.tunnels.entry(to_nid).or_default();
        tunnel.sptps = Some(Box::new(sptps));
        tunnel.status.validkey = false;
        tunnel.status.waitingforkey = true;
        tunnel.status.sptps = true;
        tunnel.last_req_key = Some(now);

        // C `send_initial_sptps_data` (`:103-112`): first Wire is KEX,
        // goes via REQ_KEY. The doubled REQ_KEY (`:111`: outer=request
        // type, inner=reqno ext) tells `req_key_ext_h` it's SPTPS-init.
        // After first send C swaps callback (`:106`); start() only emits
        // one Wire, so the else branch is defensive.
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
                    // C `:111`: `"%d %s %s %d %s"`.
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

    /// `req_key_h` (`protocol_key.c:276-345`) + `req_key_ext_h` case
    /// REQ_KEY (`:234-269`). Per-tunnel SPTPS responder side. REQ_KEY
    /// is heavily overloaded; `to == myself` + `ext.reqno == REQ_KEY`
    /// ⇒ peer initiating SPTPS ⇒ start as responder, feed their KEX.
    /// REQ_PUBKEY/ANS_PUBKEY (`:196-231`): hard-error.
    #[allow(clippy::too_many_lines)] // C is 207 LOC; splitting scatters refs
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

        // C `:293-299`: lookup, NOT lookup_or_add.
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

        // C `:310-345`: `if(to == myself)` vs relay.
        if to_nid != self.myself {
            // C `:326`: hub doesn't relay key requests for indirect peers.
            if self.settings.tunnelserver {
                return Ok(false);
            }
            if !self.graph.node(to_nid).is_some_and(|n| n.reachable) {
                log::warn!(target: "tincd::proto",
                           "Got REQ_KEY from {conn_name} destination {} \
                            which is not reachable", msg.to);
                return Ok(false);
            }
            // C `:165-170` SPTPS_PACKET relay: decode + send_sptps_data
            // (may go UDP). `:167` only when FMODE_INTERNAL; else
            // falls through to verbatim-forward (`:192`).
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
            // C `:192-194`, `:341`: forward verbatim.
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
            return Ok(conn.send(format_args!("{body_str}")));
        }

        // C `:312-315`
        if !self.graph.node(from_nid).is_some_and(|n| n.reachable) {
            log::error!(target: "tincd::proto",
                        "Got REQ_KEY from {conn_name} origin {} which is unreachable",
                        msg.from);
            return Ok(false);
        }

        // C `:318-320`: `if(experimental && reqno)`. Always-experimental.
        let Some(ext) = &msg.ext else {
            // C `:323`: legacy 3-token form (cleartext-hex session
            // key exchange). SPTPS-only build — log + reject.
            log::error!(target: "tincd::proto",
                        "Got legacy REQ_KEY from {} (no SPTPS extension)",
                        msg.from);
            return Ok(false);
        };

        // C `req_key_ext_h:139` switch(reqno). REQ_KEY=15 SPTPS-init,
        // REQ_PUBKEY=19, ANS_PUBKEY=20, SPTPS_PACKET=21.
        if ext.reqno == Request::SptpsPacket as i32 {
            // ─── case SPTPS_PACKET (`protocol_key.c:171-188`) ───
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
            // C `:173`
            let Some(sptps) = self
                .tunnels
                .get_mut(&from_nid)
                .and_then(|t| t.sptps.as_deref_mut())
            else {
                // C `:177-183`: tunnel-stuck restart logic.
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
            // C `:184`: send_mtu_info. C `:146`: send_udp_info
            // (`to->via == myself` trivially holds for `to == myself`).
            let mut nw = self.dispatch_tunnel_outputs(from_nid, &msg.from, outs);
            nw |= self.send_mtu_info(from_nid, &msg.from, i32::from(MTU), true);
            nw |= self.send_udp_info(from_nid, &msg.from, true);
            return Ok(nw);
        }
        if ext.reqno != Request::ReqKey as i32 {
            // REQ_PUBKEY/ANS_PUBKEY (`:196-231`): hard-error — operator
            // provisions by hand. C `:270` default: log + return true.
            log::error!(target: "tincd::proto",
                       "Got REQ_KEY ext reqno={} from {}: REQ_PUBKEY/\
                        ANS_PUBKEY unsupported — provision hosts/{} with \
                        Ed25519PublicKey",
                       ext.reqno, msg.from, msg.from);
            return Ok(false);
        }

        // ─── case REQ_KEY (`:234-269`): SPTPS responder start.
        // C `:235-239`: same loader as send_req_key.
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
            // C `:236-238` sends REQ_PUBKEY. Hard-error.
            log::error!(target: "tincd::proto",
                       "No Ed25519 key known for {}; cannot start tunnel \
                        — provision hosts/{} with Ed25519PublicKey",
                       msg.from, msg.from);
            return Ok(false);
        };

        // C `:241-243`: peer re-initiating; C logs + continues (sptps_stop
        // at :261 resets).
        if self
            .tunnels
            .get(&from_nid)
            .is_some_and(|t| t.sptps.is_some())
        {
            log::debug!(target: "tincd::proto",
                        "Got REQ_KEY from {} while SPTPS already started; restarting",
                        msg.from);
        }

        // C `:245-254`
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

        // C `:256-263`: label has initiator's name first (same both
        // sides). sptps_start(..., false, true, ...) = responder, datagram.
        let label = make_udp_label(&msg.from, &self.name);
        let mykey = SigningKey::from_blob(&self.mykey.to_blob());
        let (mut sptps, init_outs) = Sptps::start(
            Role::Responder,
            Framing::Datagram,
            mykey,
            hiskey,
            label,
            16,
            &mut OsRng,
        );

        // C `:264`: feed their KEX.
        let recv_result = sptps.receive(&kex_bytes, &mut OsRng);

        // Stash SPTPS before dispatching outputs.
        let now = self.timers.now();
        let tunnel = self.tunnels.entry(from_nid).or_default();
        tunnel.sptps = Some(Box::new(sptps));
        tunnel.status.validkey = false;
        tunnel.status.waitingforkey = true;
        tunnel.status.sptps = true;
        tunnel.last_req_key = Some(now);

        // C `:266` send_mtu_info; `:146` send_udp_info.
        let mut hint_nw = self.send_mtu_info(from_nid, &msg.from, i32::from(MTU), true);
        hint_nw |= self.send_udp_info(from_nid, &msg.from, true);

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
                // C `:249`: returns true (don't drop conn).
            }
        }
        Ok(nw)
    }

    /// `ans_key_h` (`protocol_key.c:420-648`), SPTPS branch only
    /// (`:549-581`). b64-decode key field, feed to `tunnels[from].sptps`.
    /// Legacy branch (`:585-648`) not present: SPTPS-only build.
    #[allow(clippy::too_many_lines)] // direct port of `ans_key_h`
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

        // C `:444-460`
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

        // C `:462-484`: relay.
        if to_nid != self.myself {
            if self.settings.tunnelserver {
                // C `:463-465`
                return Ok(false);
            }
            if !self.graph.node(to_nid).is_some_and(|n| n.reachable) {
                log::warn!(target: "tincd::proto",
                           "Got ANS_KEY from {conn_name} destination {} \
                            which is not reachable", msg.to);
                return Ok(false);
            }
            // C `:473-482`: three gates — `!*address` (first relay only,
            // no double-append), `from->address != AF_UNSPEC` (we have a
            // UDP addr for from), `to->minmtu` (to is actively using UDP
            // so reflexive addr is useful). Match ⇒ raw-concat addr/port.
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
            // C `:484`: forward verbatim (or with append).
            return Ok(match appended {
                Some(a) => conn.send(format_args!("{a}")),
                None => conn.send(format_args!("{body_str}")),
            });
        }

        // C `:499-545`: compression capability check + `:545` store.
        // LZO 10/11 stubbed: compress() returns None, peer's decompress
        // fails. Reject explicitly so misconfig surfaces in OUR logs,
        // not as silent packet loss on THEIR side.
        let their_compression = u8::try_from(msg.compression).unwrap_or(0);
        match compress::Level::from_wire(their_compression) {
            compress::Level::LzoLo | compress::Level::LzoHi => {
                log::error!(target: "tincd::proto",
                            "Node {} uses bogus compression level {}: \
                             LZO compression is unavailable on this node",
                            msg.from, their_compression);
                return Ok(false); // C `:517`: don't terminate meta conn
            }
            _ => {}
        }
        self.tunnels.entry(from_nid).or_default().outcompression = their_compression;

        // C `:549`: `if(from->status.sptps)`. Always true (no legacy).
        let Some(hs_bytes) = tinc_crypto::b64::decode(&msg.key) else {
            log::error!(target: "tincd::proto",
                        "Got bad ANS_KEY from {}: invalid SPTPS data", msg.from);
            return Ok(false);
        };

        // C `:553`: SPTPS must already exist (send_req_key set it).
        let Some(sptps) = self
            .tunnels
            .get_mut(&from_nid)
            .and_then(|t| t.sptps.as_deref_mut())
        else {
            // C derefs a zeroed struct → false → restart at `:556-563`.
            log::warn!(target: "tincd::proto",
                       "Got ANS_KEY from {} but no SPTPS state; restarting",
                       msg.from);
            return Ok(self.send_req_key(from_nid));
        };

        let result = sptps.receive(&hs_bytes, &mut OsRng);
        let outs = match result {
            Ok((_consumed, outs)) => outs,
            Err(e) => {
                // C `:555-563`: tunnel-stuck restart, gated on last_req_key+10.
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

        // C `:568-576`: two gates — validkey (set above on HandshakeDone;
        // without it the addr could be a replay) + relay appended one.
        // update_node_udp = set tunnel.udp_addr (no node_udp_tree).
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
            }
        }

        // C `:576`: after dispatch, regardless of handshake completion.
        nw |= self.send_mtu_info(from_nid, &msg.from, i32::from(MTU), true);
        Ok(nw)
    }

    /// `seen_request` (`protocol.c:234-249`). Dedup gate; `true` =
    /// already seen, caller drops silently. C keys on strcmp of the
    /// whole line; the `%x` nonce token makes distinct origins distinct.
    pub(super) fn seen_request(&mut self, body: &[u8]) -> bool {
        // Parsers validated UTF-8; failure → not-seen (handler rejects).
        let Ok(s) = std::str::from_utf8(body) else {
            return false;
        };
        self.seen.check(s, self.timers.now())
    }

    /// `prng(UINT32_MAX)` (`utils.c`). Dedup nonce. C uses xoshiro;
    /// we use OsRng (overkill, but linked + not hot).
    pub(super) fn nonce() -> u32 {
        OsRng.next_u32()
    }

    /// C `meta.c:115`: `if(c != from && c->edge)`. Vec not iterator:
    /// callers `get_mut` while sending; slotmap borrow would conflict.
    pub(super) fn broadcast_targets(&self, from: Option<ConnId>) -> Vec<ConnId> {
        self.conns
            .iter()
            .filter(|&(id, c)| Some(id) != from && c.active)
            .map(|(id, _)| id)
            .collect()
    }

    /// `forward_request` (`protocol.c:135-146`) → `broadcast_meta`
    /// (`meta.c:113-117`). Re-send to every active conn except `from`.
    /// Receivers' `seen.check` + the `from` skip = loop break.
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

    /// `send_request(everyone, ...)` (`protocol.c:122-125`). `from=None`
    /// skips nothing; new/dying conn isn't `active` so filtered anyway.
    /// C formats once then re-sends same bytes → one nonce, format outside loop.
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

    /// `send_add_edge` (`protocol_edge.c:37-62`). Returns `None` if
    /// edge or addr entry missing — the synthesized reverse from
    /// `on_ack` has no addr; skip rather than emit `"unknown port
    /// unknown"` (peers would str2sockaddr to AF_UNKNOWN, never connect).
    pub(super) fn fmt_add_edge(&self, eid: EdgeId, nonce: u32) -> Option<String> {
        let e = self.graph.edge(eid)?;
        let (addr, port, la, lp) = self.edge_addrs.get(&eid)?;
        let from = self.graph.node(e.from)?.name.clone();
        let to = self.graph.node(e.to)?.name.clone();
        // C `:44`: AF_UNSPEC test; our sentinel is "unspec" string.
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

    /// `send_add_edge(c, e)` correction path (`protocol_edge.c:153,289`).
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

    /// `send_del_edge(c, e)` (`protocol_edge.c:219-222`). C builds a
    /// transient `edge_t` for `:190` contradiction; we take names directly.
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

    /// `send_add_subnet`/`send_del_subnet` (`protocol_subnet.c:33-44,153-161`).
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

    /// `send_everything` (`protocol_auth.c:870-900`). Called from
    /// `on_ack` (`ack_h:1028`). C nests `splay_each(node){subnet;edge}`;
    /// we flatten over global trees — same wire output, order irrelevant.
    /// `disablebuggypeers` (`:873-881`) skipped (ancient niche).
    pub(super) fn send_everything(&mut self, to: ConnId) -> bool {
        if self.settings.tunnelserver {
            // C `:884-889`: ONLY myself's subnets, NO edges. Peer's
            // edge to us comes from on_ack's send_add_edge(c, c->edge).
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

        // C `:893` flattened.
        for (subnet, owner) in self.subnets.iter() {
            let msg = SubnetMsg {
                owner: owner.to_owned(),
                subnet: *subnet,
            };
            lines.push(msg.format(Request::AddSubnet, Self::nonce()));
        }

        // C `:897`. Addr-less edges (synthesized reverse) skipped by
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

    /// `graph()` (`graph.c:322-327`): sssp + diff + mst.
    pub(super) fn run_graph_and_log(&mut self) {
        let (transitions, mst, routes) = run_graph(&mut self.graph, self.myself);
        // C `graph.c:188-196` writes nexthop/via/distance into node_t;
        // we side-table for dump_nodes (`node.c:218`).
        self.last_routes = routes;
        // C `graph.c:103,107` sets per-conn status.mst; we keep edge
        // IDs and map at broadcast time.
        self.last_mst = mst;
        // C `graph.c:323` subnet_cache_flush_tables: we have no cache.
        for t in transitions {
            match t {
                Transition::BecameReachable { node, via: via_nid } => {
                    // C `graph.c:261-262`
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

                    // C `graph.c:201`: update_node_udp(n, &e->reverse
                    // ->address). Use edge addr from on_ack (direct
                    // neighbors). C also re-indexes node_udp_tree
                    // (`net_packet.c:1708-1745`) for legacy receive;
                    // we key incoming UDP on [dst_id6][src_id6] prefix
                    // (SPTPS-only `:1779-1825`), no tree to re-index.
                    let name_owned = name.to_owned();
                    let addr = self.nodes.get(&node).and_then(|ns| ns.edge_addr);
                    if let Some(addr) = addr {
                        let tunnel = self.tunnels.entry(node).or_default();
                        tunnel.udp_addr = Some(addr);
                        tunnel.udp_addr_cached = None;
                    }

                    // C `graph.c:273-289`: host-up AFTER addr known.
                    self.run_host_script(true, &name_owned, addr);

                    // C `graph.c:294` subnet_update(n, NULL, true):
                    // subnet-up for every owned subnet (`subnet.c:352-372`).
                    for s in &self.subnets.owned_by(&name_owned) {
                        self.run_subnet_script(true, &name_owned, s);
                    }
                    // C `protocol_edge.c:163-165` sets status.sptps from
                    // options>>24>=2. Always true (no legacy); set for dump.
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
                    // Read addr BEFORE reset clears it (C order: `:284`
                    // script before `:296` update_node_udp(n, NULL)).
                    let addr = self
                        .tunnels
                        .get(&node)
                        .and_then(|t| t.udp_addr)
                        .or_else(|| self.nodes.get(&node).and_then(|ns| ns.edge_addr));

                    // C `graph.c:273-289`
                    self.run_host_script(false, &name_owned, addr);

                    // C `graph.c:294`: subnet-down for every owned subnet.
                    for s in &self.subnets.owned_by(&name_owned) {
                        self.run_subnet_script(false, &name_owned, s);
                    }

                    // C `graph.c:256-297`: sptps_stop + mtu reset + clear
                    // UDP addr = reset_unreachable. C `:270` timeout_del:
                    // UdpPing never armed (pmtu.tick() inline), nothing to del.
                    if let Some(tunnel) = self.tunnels.get_mut(&node) {
                        tunnel.reset_unreachable();
                    }
                }
            }
        }
    }

    /// `dump_nodes` row builder (`node.c:201-223`). C format `:210`:
    /// 21 printf conversions; CLI sscanf has 22 (`" port "` re-split).
    /// Placeholders: cipher/digest/maclength=0 (DISABLE_LEGACY `:213`);
    /// last_state_change=0 (deferred). status bitfield (`node.h:32-48`,
    /// GCC LSB-first): bit 4 reachable feeds CLI's filter (`tincctl.c:1306`).
    pub(super) fn dump_nodes_rows(&self) -> Vec<String> {
        let mut rows = Vec::new();
        for nid in self.graph.node_ids() {
            let Some(node) = self.graph.node(nid) else {
                continue; // freed slot (concurrent del; defensive)
            };
            let name = node.name.as_str();

            // C `:211`. C `net_setup.c:1199`: myself = "MYSELF port <tcp>".
            // Direct peers: c->address rewritten to UDP (`ack_h:1024-1025`).
            // Transitives: literal (C learns via update_node_udp).
            let hostname = if nid == self.myself {
                format!("MYSELF port {}", self.my_udp_port)
            } else if let Some(ea) = self.nodes.get(&nid).and_then(|ns| ns.edge_addr.as_ref()) {
                fmt_addr(ea) // "%s port %s", no v6 brackets
            } else {
                "unknown port unknown".to_string()
            };

            // C `:217` n->options: C `graph.c:192` writes incoming-edge
            // options during sssp. myself: 0. Unreachable: C reads stale, we 0.
            let route = self
                .last_routes
                .get(nid.0 as usize)
                .and_then(Option::as_ref);
            let options = route.map_or(0, |r| r.options);

            // C `:217` n->status.value. myself: just reachable
            // (C `setup_myself:1050` sets only that).
            let tunnel = self.tunnels.get(&nid);
            let status = tunnel.map_or_else(
                || {
                    if node.reachable { 1 << 4 } else { 0 }
                },
                |t| t.status.as_u32(node.reachable),
            );

            // C `:218`: nexthop ? name : "-". Unreachable → "-".
            let (nexthop, via, distance) = match route {
                Some(r) => {
                    let nh = self.graph.node(r.nexthop).map_or("-", |n| n.name.as_str());
                    let via = self.graph.node(r.via).map_or("-", |n| n.name.as_str());
                    (nh, via, r.distance)
                }
                // C keeps stale distance; we emit 0.
                None => ("-", "-", 0),
            };

            // C `:210`. udp_ping_rtt=-1 is C `node.c:58` init.
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
                    .map_or(-1, |p| p.udp_ping_rtt), // %d
                tunnel.map_or(0, |t| t.in_packets), // %PRIu64
                tunnel.map_or(0, |t| t.in_bytes),
                tunnel.map_or(0, |t| t.out_packets),
                tunnel.map_or(0, |t| t.out_bytes),
            ));
        }
        rows
    }

    /// `dump_edges` row builder (`edge.c:123-137`). C format `:128`:
    /// 6 body conversions; CLI sscanf has 8 (two `" port "` re-splits).
    /// `edge_addrs` stores raw AddrStr tokens; format as `"%s port %s"`
    /// (sockaddr2hostname AF_UNKNOWN branch, `netutl.c:163`).
    pub(super) fn dump_edges_rows(&self) -> Vec<String> {
        let mut rows = Vec::new();
        // C `:124-125` nested splay; we slab-walk. Order differs:
        // tincctl sorts client-side anyway.
        for (eid, e) in self.graph.edge_iter() {
            let from = self.node_log_name(e.from);
            let to = self.node_log_name(e.to);

            // C `:126-127`
            let (addr, local) = match self.edge_addrs.get(&eid) {
                Some((a, p, la, lp)) => (format!("{a} port {p}"), format!("{la} port {lp}")),
                // Synthesized reverse (see on_ack); C never addr-less.
                None => (
                    "unknown port unknown".to_string(),
                    "unknown port unknown".to_string(),
                ),
            };

            // C `:128`
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

    /// `add_subnet_h` (`protocol_subnet.c:43-140`). Subnets don't
    /// change topology — NO graph() call (C calls subnet_update only).
    pub(super) fn on_add_subnet(
        &mut self,
        from_conn: ConnId,
        body: &[u8],
    ) -> Result<bool, DispatchError> {
        let (owner_name, subnet) = parse_add_subnet(body)?;

        // C `:71`
        if self.seen_request(body) {
            return Ok(false);
        }

        // C `:79-84`: tunnelserver indirect filter. Check BEFORE
        // lookup_or_add_node — don't pollute graph with indirect names.
        // (C checks after lookup but before new_node; ours is fused.)
        // ORDER: seen_request (`:71`) first — mark seen even on drop.
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

        // C `:93`: lookup-first idempotency. With strictsubnets this
        // lets AUTHORIZED subnets through silently (load_all_nodes
        // preloaded; gossip finds it, return). UNAUTHORIZED falls
        // through to `:116`. Without strictsubnets: belt-and-braces
        // over seen_request (saves lookup_or_add + script run).
        if self.subnets.contains(&subnet, &owner_name) {
            return Ok(false);
        }

        // C `:77,86-89`
        let owner = self.lookup_or_add_node(&owner_name);

        // C `:98-104`: peer wrong about us — retaliate DEL_SUBNET.
        if owner == self.myself {
            let conn_name = self
                .conns
                .get(from_conn)
                .expect("dispatched from live conn")
                .name
                .clone();
            log::warn!(target: "tincd::proto",
                       "Got ADD_SUBNET from {conn_name} for ourself ({subnet})");
            // C `:103`. Dark in single-peer tests; reachable via stale
            // gossip in multi-peer mesh.
            let nw = self.send_subnet(from_conn, Request::DelSubnet, &self.name.clone(), &subnet);
            return Ok(nw);
        }

        // C `:109-113`: tunnelserver second gate. Reached when owner
        // IS the direct peer but subnet wasn't preloaded from hosts/
        // ("unauthorized" — `:880 strictsubnets|=tunnelserver` means
        // load_all_nodes preloaded; `:93` noops on those; reaching here
        // means NOT on disk). NO forward: C `:113` is just `return true`.
        // Only `:116` strictsubnets forwards. (50800c0d fixed a spurious
        // forward here that made three_daemon_tunnelserver intermittent.)
        if self.settings.tunnelserver {
            log::warn!(target: "tincd::proto",
                       "Ignoring unauthorized ADD_SUBNET for {owner_name} \
                        ({subnet}) (tunnelserver)");
            return Ok(false);
        }

        // C `:116-122`: strictsubnets — hosts/ file is authority. Forward
        // (others may not be strict) but don't add locally.
        if self.settings.strictsubnets {
            log::warn!(target: "tincd::proto",
                       "Ignoring unauthorized ADD_SUBNET for {owner_name} \
                        ({subnet}) (strictsubnets)");
            let nw = self.forward_request(from_conn, body);
            return Ok(nw);
        }

        // C `:126`
        self.subnets.add(subnet, owner_name.clone());

        // mac_table sync for route_mac.rs.
        if let Subnet::Mac { addr, .. } = subnet {
            self.mac_table.insert(addr, owner_name.clone());

            // C `protocol_subnet.c:142-148`: fast handoff. Peer learned
            // a MAC we also leased (VM migrated). C does `lookup_subnet
            // (myself,&s)` + `old->expires=1`; our mac_leases only holds
            // myself's leases, so refresh()==true IS that check.
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

        // C `:130-132`: subnet-up only if reachable (else BecameReachable
        // fires it later).
        let reachable = self.graph.node(owner).is_some_and(|n| n.reachable);
        if reachable {
            self.run_subnet_script(true, &owner_name, &subnet);
        }

        // C `:136-138`. seen.check above prevents the loop.
        let nw = if self.settings.tunnelserver {
            false
        } else {
            self.forward_request(from_conn, body)
        };

        Ok(nw)
    }

    /// `del_subnet_h` (`protocol_subnet.c:163-261`). DEL for unknown
    /// owner/subnet is warn-and-drop (NOT lookup_or_add).
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

        // C `:199-204`: tunnelserver indirect filter. ORDER: seen (`:191`) first.
        if self.settings.tunnelserver && owner_name != self.name && owner_name != conn_name {
            log::warn!(target: "tincd::proto",
                       "Ignoring indirect DEL_SUBNET from {conn_name} \
                        for {owner_name} ({subnet})");
            return Ok(false);
        }

        // C `:197,206-210`: NOT lookup_or_add. Warn, return true.
        let Some(&owner) = self.node_ids.get(&owner_name) else {
            log::warn!(target: "tincd::proto",
                       "Got DEL_SUBNET from {conn_name} for {owner_name} \
                        which is not in our node tree");
            return Ok(false);
        };

        // C `:231-236`: peer says we don't own a subnet we DO own.
        // C ORDERING: `:216` lookup_subnet FIRST, `:218` bail if not
        // found. Security audit `2f72c2ba`: without that gate, a
        // malicious peer sends DEL_SUBNET for a subnet we never claimed;
        // we retaliate ADD; victim adds bogus route pointing at us.
        if owner == self.myself {
            // C `:216-225`: don't lie about subnets we never owned.
            if !self.subnets.contains(&subnet, &self.name) {
                log::warn!(target: "tincd::proto",
                           "Got DEL_SUBNET from {conn_name} for ourself ({subnet}) \
                            which does not appear in our subnet tree");
                return Ok(false);
            }
            log::warn!(target: "tincd::proto",
                       "Got DEL_SUBNET from {conn_name} for ourself ({subnet})");
            // C `:234`
            let nw = self.send_subnet(from_conn, Request::AddSubnet, &self.name.clone(), &subnet);
            return Ok(nw);
        }

        // C `:238-240`: AFTER retaliate, BEFORE forward+del.
        if self.settings.tunnelserver {
            return Ok(false);
        }

        // C `:244`
        let nw = self.forward_request(from_conn, body);

        // C `:247-249`: AFTER forward, BEFORE del. (C `:220-225`
        // not-found-strictsubnets case folds into del()==false below:
        // same observable behavior — forward, no del.)
        if self.settings.strictsubnets {
            return Ok(nw);
        }

        // C ORDERING: `:216` lookup gates `:254` script + `:258` del.
        // Security audit `2f72c2ba`: subnet-down for a subnet we never
        // up'd is a peer-triggers-fork-exec DoS (flood DEL with fresh
        // nonces). C `:218` short-circuits before fork. Do del() FIRST.
        // C `:254-256` orders script BEFORE del; we invert (del() returns
        // bool) — script env doesn't read the table; same behavior.
        if !self.subnets.del(&subnet, &owner_name) {
            // C `:218-225`: warn, no script.
            log::warn!(target: "tincd::proto",
                       "Got DEL_SUBNET from {conn_name} for {owner_name} \
                        which does not appear in his subnet tree");
            return Ok(nw);
        }

        // C `:254-256`
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

    /// `add_edge_h` (`protocol_edge.c:63-217`). Edge exists with
    /// different params ⇒ update in place (Graph::update_edge keeps
    /// EdgeId slot stable; edge_addrs is keyed on it).
    #[allow(clippy::too_many_lines)] // C add_edge_h is 154 LOC; same
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

        // C `protocol_edge.c:103-111`: drop if NEITHER endpoint is
        // us-or-direct-peer. Before lookup_or_add. ORDER: seen (`:94`) first.
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

        // C `:134`
        if let Some(existing) = self.graph.lookup_edge(from_id, to_id) {
            // C `:144`: idempotent only if weight+options+ADDRESS all
            // match. The address compare matters: synthesized reverse
            // from on_ack has no edge_addrs entry; when peer's real
            // ADD_EDGE arrives (same weight/options, real addr), C's
            // sockaddrcmp is nonzero, falls through to update+forward.
            // Weight-only check early-returned and broke hub-spoke
            // (three_daemon_relay regression). Check edge_addrs too.
            let e = self.graph.edge(existing).expect("just looked up");
            let same_addr = self.edge_addrs.get(&existing).is_some_and(|(a, p, _, _)| {
                // Compare addr+port only. C's sockaddrcmp ignores local
                // unless sa_family set (`:141-143`); we're stricter —
                // harmless (extra forward, seen dedups).
                a == &edge.addr && p == &edge.port
            });
            if e.weight == edge.weight && e.options == edge.options && same_addr {
                return Ok(false); // C `:145-148`: no forward, no graph()
            }

            // C `:150-157`: peer's view of OUR edge is wrong.
            if from_id == self.myself {
                log::warn!(target: "tincd::proto",
                           "Got ADD_EDGE from {conn_name} for ourself \
                            which does not match existing entry");
                // C `:153`: send back what WE know (existing, not wire body).
                let nw = self.send_add_edge(from_conn, existing);
                return Ok(nw);
            }

            // C `:159-183`: in-place update. NOT del+add: edge_addrs
            // is keyed on EdgeId; del+add recycles same slot only by
            // LIFO-freelist accident. update_edge makes it explicit.
            log::warn!(target: "tincd::proto",
                       "Got ADD_EDGE from {conn_name} which does not \
                        match existing entry");
            self.graph
                .update_edge(existing, edge.weight, edge.options)
                .expect("lookup_edge just returned this EdgeId; no await, no free");
            // C `:173`
            let unspec = || AddrStr::new(AddrStr::UNSPEC).expect("literal");
            let (la, lp) = edge.local.clone().unwrap_or_else(|| (unspec(), unspec()));
            self.edge_addrs
                .insert(existing, (edge.addr.clone(), edge.port.clone(), la, lp));
        } else if from_id == self.myself {
            // C `:184-196`: contradiction — peer says we have an edge
            // we don't. Counter read by periodic_handler (`net.c:268`).
            log::warn!(target: "tincd::proto",
                       "Got ADD_EDGE from {conn_name} for ourself \
                        which does not exist");
            self.contradicting_add_edge += 1; // C `:186`
            // C `:187-192`: send DEL with the wire body's names.
            let nw = self.send_del_edge(from_conn, &edge.from, &edge.to);
            return Ok(nw);
        } else {
            // C `:197-205`
            let eid = self
                .graph
                .add_edge(from_id, to_id, edge.weight, edge.options);
            // C `:199-204`. local optional (pre-1.0.24); C leaves zeroed
            // (AF_UNSPEC → "unspec port unspec", `netutl.c:159-160`).
            let unspec = || AddrStr::new(AddrStr::UNSPEC).expect("literal");
            let (la, lp) = edge.local.clone().unwrap_or_else(|| (unspec(), unspec()));
            self.edge_addrs
                .insert(eid, (edge.addr.clone(), edge.port.clone(), la, lp));
        }

        // C `:209-211`
        let nw = if self.settings.tunnelserver {
            false
        } else {
            self.forward_request(from_conn, body)
        };

        self.run_graph_and_log(); // C `:215`

        Ok(nw)
    }

    /// `del_edge_h` (`protocol_edge.c:225-322`). Missing node/edge
    /// is warn-and-drop (NOT lookup_or_add).
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

        // C `protocol_edge.c:253-261`. ORDER: seen (`:244`) first.
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

        // C `:250-273`: missing → warn-and-drop (view already consistent).
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

        // C `:277-283`
        let Some(eid) = self.graph.lookup_edge(from_id, to_id) else {
            log::warn!(target: "tincd::proto",
                       "Got DEL_EDGE from {conn_name} which does not \
                        appear in the edge tree");
            return Ok(false);
        };

        // C `:285-291`: peer says we DON'T have an edge we DO have.
        if from_id == self.myself {
            log::warn!(target: "tincd::proto",
                       "Got DEL_EDGE from {conn_name} for ourself");
            self.contradicting_del_edge += 1; // C `:288`
            // C `:289`: edge exists (just looked up); send what we know.
            let nw = self.send_add_edge(from_conn, eid);
            return Ok(nw);
        }

        // C `:295-297`
        let nw = if self.settings.tunnelserver {
            false
        } else {
            self.forward_request(from_conn, body)
        };

        // C `:301`
        self.graph.del_edge(eid);
        self.edge_addrs.remove(&eid);

        self.run_graph_and_log(); // C `:305`

        // C `:309-320`: if `to` became unreachable AND has edge back
        // to us (the synthesized reverse from ack_h), delete + broadcast.
        if !self.graph.node(to_id).is_some_and(|n| n.reachable)
            && let Some(rev) = self.graph.lookup_edge(to_id, self.myself)
        {
            // C `:313-315`
            if !self.settings.tunnelserver {
                let to_name = edge.to.clone();
                let my_name = self.name.clone();
                let line = DelEdge {
                    from: to_name,
                    to: my_name,
                }
                .format(Self::nonce());
                self.broadcast_line(&line);
            }
            // C `:318`
            self.graph.del_edge(rev);
            self.edge_addrs.remove(&rev);
        }

        Ok(nw)
    }
}
