#![forbid(unsafe_code)]

#[allow(clippy::wildcard_imports)]
use super::*;

impl Daemon {
    /// `lookup_node` + `new_node`/`node_add` fused (`node.c:74,96`).
    /// The C pattern from `add_edge_h:112-120` and `add_subnet_h:
    /// 86-89`: `n = lookup_node(name); if(!n) { n = new_node();
    /// node_add(n); }`.
    ///
    /// Adds to `graph` AND `node_ids` (the name→id map). Does NOT
    /// add a `NodeState` — only directly-connected peers get one
    /// (via `on_ack`). A node learned from a forwarded ADD_EDGE is
    /// transitive: in the graph, but no live connection.
    ///
    /// C `xzalloc` zeroes `reachable`; `Graph::add_node` defaults
    /// it `true`. We zero it back: a freshly-learned node IS
    /// unreachable until `run_graph` proves otherwise. The diff
    /// then emits `BecameReachable` and we get the host-up log.
    pub(super) fn lookup_or_add_node(&mut self, name: &str) -> NodeId {
        if let Some(&id) = self.node_ids.get(name) {
            return id;
        }
        let id = self.graph.add_node(name);
        // C `node.c:75`: `xzalloc` → `reachable = false`. The
        // graph crate's `true` default is for the steady-state
        // "all nodes already known" tests; the daemon's reality
        // is "just learned this name, haven't run sssp yet".
        self.graph.set_reachable(id, false);
        self.node_ids.insert(name.to_owned(), id);
        // C `node.c:126-131`: `node_add` computes the SHA-512
        // prefix and indexes `node_id_tree`. UDP fast-path lookup.
        self.id6_table.add(name, id);
        id
    }

    /// `send_req_key` (`protocol_key.c:114-135`) + `send_initial_
    /// sptps_data` (`:103-112`). Start the per-tunnel SPTPS as
    /// initiator and send the first handshake record (the KEX) via
    /// REQ_KEY on the meta connection.
    ///
    /// The C splits this into two functions because of the callback
    /// dance: `sptps_start` takes `send_initial_sptps_data` as the
    /// callback, which gets fired re-entrantly with the KEX bytes.
    /// Our `Sptps::start` returns `Vec<Output>` instead; we dispatch
    /// the FIRST `Wire` here (it's the KEX, goes via REQ_KEY) and
    /// any subsequent ones via `send_sptps_data` (they'd go via
    /// ANS_KEY — but `start()` only emits one Wire so this is moot).
    ///
    /// C `:116-120`: `if(!node_read_ecdsa_public_key(to)) send REQ_
    /// PUBKEY`. We REQUIRE the key in `hosts/{to}` (no on-the-fly
    /// fetch). REQ_PUBKEY is hard-errored (operator must provision
    /// `hosts/{to}` with `Ed25519PublicKey`; better than silently
    /// never sending data).
    ///
    /// Returns the io_set signal (the REQ_KEY queued on a meta-conn).
    pub(super) fn send_req_key(&mut self, to_nid: NodeId) -> bool {
        let Some(to_name) = self.graph.node(to_nid).map(|n| n.name.clone()) else {
            return false;
        };

        // C `:116-120`: `node_read_ecdsa_public_key(to)`. Load from
        // `hosts/{to_name}`. Same loader as `id_h` (`proto.rs:572`).
        // Re-reads on every `send_req_key` (C does too; `node_t.
        // ecdsa` is set lazily by `node_read_ecdsa_public_key` and
        // `:116` checks it first — we don't cache, so we read every
        // time. The 10-second debounce gates it; not hot).
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
            // C `:117-119`: `"No Ed25519 key known for %s"` then
            // `send REQ_PUBKEY`. We don't do on-the-fly key fetch
            // (REQ_PUBKEY/ANS_PUBKEY, `protocol_key.c:196-231`).
            // The C feature exists for auto-provisioning trusted-
            // mesh setups; the operator can do it by hand. Hard-
            // error so it surfaces in logs, not as silent drops.
            log::warn!(target: "tincd::net",
                       "No Ed25519 key known for {to_name}; cannot start tunnel");
            return false;
        };

        // C `:122-124`: `snprintf(label, ..., "tinc UDP key
        // expansion %s %s", myself->name, to->name)`. Initiator
        // name first.
        let label = make_udp_label(&self.name, &to_name);

        // C `:126-131`: `sptps_stop; validkey=false; waitingforkey=
        // true; last_req_key=now; sptps_start(..., true, true, ...)`.
        // The two `true`s are `initiator` and `datagram`.
        // `mykey` clone: `Sptps::start` consumes `SigningKey`; same
        // blob-roundtrip as `handle_id_peer` (`proto.rs:663`).
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

        // C `send_initial_sptps_data` (`:103-112`): the FIRST Wire
        // from `start()` is the KEX. Goes via REQ_KEY (NOT ANS_KEY —
        // C `:111`: `send_request(..., "%d %s %s %d %s", REQ_KEY,
        // myself->name, to->name, REQ_KEY, buf)`). The DOUBLE
        // `REQ_KEY` is intentional: outer is the request type,
        // inner (the `reqno` extension) tells `req_key_ext_h` this
        // is an SPTPS-init payload.
        //
        // After the first send, the C swaps the callback to `send_
        // sptps_data_myself` (`:106`: `to->sptps.send_data = ...`)
        // so subsequent Wires go via `send_sptps_data` (ANS_KEY for
        // handshake, UDP for data). `start()` only emits ONE Wire
        // (the initiator KEX), so for chunk 7 the loop has one
        // iteration. The general dispatch handles subsequent
        // outputs from `receive()`.
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
                    // C `:111`: `"%d %s %s %d %s"`. ReqKeyExt::reqno
                    // = REQ_KEY (15). The doubled-request-type is
                    // `req_key_ext_h`'s SPTPS-init dispatch key.
                    nw |= conn.send(format_args!(
                        "{} {} {} {} {}",
                        Request::ReqKey,
                        self.name,
                        to_name,
                        Request::ReqKey as u8,
                        b64,
                    ));
                } else {
                    // Shouldn't fire from `start()` (one Wire only).
                    // But if SPTPS internals change: route via the
                    // general dispatch (ANS_KEY for handshake).
                    nw |= self.send_sptps_data(to_nid, &to_name, tinc_sptps::REC_HANDSHAKE, &bytes);
                }
            }
            // HandshakeDone/Record from start(): unreachable.
        }
        nw
    }

    /// `req_key_h` (`protocol_key.c:276-345`) + `req_key_ext_h`
    /// `case REQ_KEY` (`:234-269`). The per-tunnel SPTPS responder
    /// side.
    ///
    /// REQ_KEY is heavily overloaded (see `tinc-proto::msg::key`
    /// doc). The chunk-7 path: `to == myself` AND `ext.reqno ==
    /// REQ_KEY` ⇒ peer is initiating per-tunnel SPTPS. We start
    /// ours as RESPONDER, feed their KEX into it, send our KEX +
    /// SIG back via `send_sptps_data` (→ ANS_KEY).
    ///
    /// REQ_PUBKEY/ANS_PUBKEY (`:196-231`): hard-error (operator
    /// provisions keys by hand). `send_udp_info`/`send_mtu_info`
    /// (`:146`/`:184`/`:266`): wired.
    #[allow(clippy::too_many_lines)] // C `req_key_h`+`req_key_ext_h`
    // are 207 LOC together; the SPTPS-init branch alone is 36 LOC of
    // dense state-machine. Splitting would scatter the C line refs.
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
            .map_or("<gone>", |c| c.name.as_str())
            .to_owned();

        // C `:293-299`: `from = lookup_node(from_name)`. NOT
        // lookup_or_add: a REQ_KEY from an unknown node is an error
        // (the meta-conn should have ADD_EDGE'd them first).
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
            // C `:326-344`: relay. `if(tunnelserver) return true`
            // (`:326`); `if(!to->status.reachable)` (`:330-334`);
            // SPTPS_PACKET takes a special path (`:149-188` decode
            // + `send_sptps_data` re-encode — "we want to use UDP
            // if available"). Everything else: `send_request(to->
            // nexthop->connection, "%s", request)` — forward
            // verbatim (`:192-194`, `:341`).
            // C `:326`: `if(tunnelserver) return true`. The hub
            // doesn't relay key requests for indirect peers (it
            // never told them about each other in the first place).
            if self.settings.tunnelserver {
                return Ok(false);
            }
            if !self.graph.node(to_nid).is_some_and(|n| n.reachable) {
                log::warn!(target: "tincd::proto",
                           "Got REQ_KEY from {conn_name} destination {} \
                            which is not reachable", msg.to);
                return Ok(false);
            }
            // SPTPS_PACKET relay (`protocol_key.c:165-170`): decode,
            // re-send via `send_sptps_data` (which may go UDP).
            // `:167`: `if(forwarding_mode == FMODE_INTERNAL)`. The
            // C only takes the OPTIMIZED `send_sptps_data` path
            // when INTERNAL; otherwise it falls through to the
            // verbatim-forward (`:192`). Match: gate the optimized
            // path on `== Internal`.
            if let Some(ext) = &msg.ext {
                if ext.reqno == Request::SptpsPacket as i32
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
                    let mut nw = self.send_sptps_data_relay(to_nid, &msg.to, from_nid, 0, &data);
                    nw |= self.try_tx(to_nid, true);
                    return Ok(nw);
                }
            }
            // Everything else (REQ_KEY init, REQ_PUBKEY, ANS_
            // PUBKEY): forward verbatim (`:192-194`, `:341`).
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
            // Forward verbatim. body_str is the full line (already
            // \n-stripped); `conn.send` re-appends.
            return Ok(conn.send(format_args!("{body_str}")));
        }

        // C `:312-315`: `if(!from->status.reachable) return true`.
        if !self.graph.node(from_nid).is_some_and(|n| n.reachable) {
            log::error!(target: "tincd::proto",
                        "Got REQ_KEY from {conn_name} origin {} which is unreachable",
                        msg.from);
            return Ok(false);
        }

        // C `:318-320`: `if(experimental && reqno) req_key_ext_h()`.
        // We're always-experimental (SPTPS-only). `ext` is the
        // parsed `reqno [payload]` tail.
        let Some(ext) = &msg.ext else {
            // C `:323`: `send_ans_key(from)`. The legacy 3-token
            // `"%d %s %s"` form (no extension). The legacy peer
            // wants our session key in plaintext-hex. We don't do
            // legacy. STUB(chunk-never).
            log::error!(target: "tincd::proto",
                        "Got legacy REQ_KEY from {} (no SPTPS extension)",
                        msg.from);
            return Ok(false);
        };

        // C `req_key_ext_h:139` `switch(reqno)`.
        // `reqno` re-uses `request_t` enum values: REQ_KEY=15 is
        // SPTPS-init, REQ_PUBKEY=19, ANS_PUBKEY=20, SPTPS_PACKET=21.
        if ext.reqno == Request::SptpsPacket as i32 {
            // ─── case SPTPS_PACKET (`protocol_key.c:171-188`) ───
            // TCP-tunneled data record. The `to == myself` was
            // already checked above. Decode, feed to `from->sptps`.
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
            // C `:173`: `sptps_receive_data(&from->sptps, buf, len)`.
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
            // udppacket = false (came via TCP). Already false
            // unless something set it; clear defensively.
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
            // C `:184`: `send_mtu_info(myself, from, MTU)`. We just
            // received an SPTPS_PACKET (TCP-tunneled data) from
            // `from`; tell upstream relays our MTU floor so they
            // can switch to UDP if it fits.
            let mut nw = self.dispatch_tunnel_outputs(from_nid, &msg.from, outs);
            nw |= self.send_mtu_info(from_nid, &msg.from, i32::from(MTU), true);
            // C `:146`: `if((reqno == REQ_KEY || reqno == SPTPS_
            // PACKET) && to->via == myself) send_udp_info(myself,
            // from)`. Same gate as the UDP receive path: only the
            // static relay (or destination, since `to == myself`
            // here) emits the breadcrumb. `to->via == myself` is
            // trivially true when `to == myself` (sssp seeds
            // `myself.via = myself`).
            nw |= self.send_udp_info(from_nid, &msg.from, true);
            return Ok(nw);
        }
        if ext.reqno != Request::ReqKey as i32 {
            // REQ_PUBKEY/ANS_PUBKEY (`:196-231`): hard-error. The
            // C feature exists for auto-provisioning trusted-mesh
            // setups; the operator can do it by hand. Better than
            // silently never sending data. C `:270`: `default:
            // "Unknown extended REQ_KEY" return true`.
            log::error!(target: "tincd::proto",
                       "Got REQ_KEY ext reqno={} from {}: REQ_PUBKEY/\
                        ANS_PUBKEY unsupported — provision hosts/{} with \
                        Ed25519PublicKey",
                       ext.reqno, msg.from, msg.from);
            return Ok(false);
        }

        // ─── case REQ_KEY (`:234-269`): SPTPS responder start.
        // C `:235-239`: `if(!node_read_ecdsa_public_key(from))
        // send REQ_PUBKEY`. Same loader as send_req_key.
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
            // C `:236-238`: `send REQ_PUBKEY`. Hard-error (see
            // `send_req_key` for rationale).
            log::error!(target: "tincd::proto",
                       "No Ed25519 key known for {}; cannot start tunnel \
                        — provision hosts/{} with Ed25519PublicKey",
                       msg.from, msg.from);
            return Ok(false);
        };

        // C `:241-243`: `if(from->sptps.label) "Got REQ_KEY while
        // we already started a SPTPS session!"`. The peer is re-
        // initiating (their previous attempt timed out, or they
        // restarted). C just logs and continues (`sptps_stop` at
        // `:261` resets); we match.
        if self
            .tunnels
            .get(&from_nid)
            .is_some_and(|t| t.sptps.is_some())
        {
            log::debug!(target: "tincd::proto",
                        "Got REQ_KEY from {} while SPTPS already started; restarting",
                        msg.from);
        }

        // C `:245-254`: b64decode the payload.
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

        // C `:256-263`: `snprintf(label, ..., from->name, myself->
        // name)` then `sptps_stop; validkey=false; waitingforkey=
        // true; sptps_start(..., false, true, ...)`. Note arg order:
        // INITIATOR's name first — same label both sides. `false,
        // true` = responder, datagram.
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

        // C `:264`: `sptps_receive_data(&from->sptps, buf, len)`.
        // Feed their KEX. This produces our KEX + SIG (responder
        // sends both after receiving initiator's KEX) — those go
        // via `send_sptps_data` → ANS_KEY.
        let recv_result = sptps.receive(&kex_bytes, &mut OsRng);

        // Stash the SPTPS BEFORE dispatching the outputs (the
        // dispatch may call `send_sptps_data` which doesn't read
        // it, but be safe).
        let now = self.timers.now();
        let tunnel = self.tunnels.entry(from_nid).or_default();
        tunnel.sptps = Some(Box::new(sptps));
        tunnel.status.validkey = false;
        tunnel.status.waitingforkey = true;
        tunnel.status.sptps = true;
        tunnel.last_req_key = Some(now);

        // C `:266`: `send_mtu_info(myself, from, MTU)`.
        // C `:146`: `send_udp_info(myself, from)` (the `reqno ==
        // REQ_KEY` branch of the same gate). We're the destination
        // (`to == myself`), so `to->via == myself` holds.
        let mut hint_nw = self.send_mtu_info(from_nid, &msg.from, i32::from(MTU), true);
        hint_nw |= self.send_udp_info(from_nid, &msg.from, true);

        // Dispatch: init_outs (responder's `start()` KEX, but
        // datagram-mode responder ALSO emits a KEX from `start()`
        // — wait, no: re-read state.rs. `start()` always sends KEX
        // (`send_kex` at `:378`). For datagram-responder that goes
        // via `send_sptps_data` (ANS_KEY). C does this too: `sptps_
        // start(..., send_sptps_data_myself, ...)` at `:263` means
        // the responder's KEX immediately fires the callback.
        // BUT C also has the initiator's `send_initial_sptps_data`
        // special-case for the FIRST Wire — the responder doesn't
        // (`:263` uses `send_sptps_data_myself` not the init one).
        // So responder KEX goes via ANS_KEY straight away.)
        //
        // recv_outs has the responder's SIG (from `receive_kex` →
        // `send_sig`, but only initiator-side... no, re-read:
        // `receive_kex` only sends SIG `if(is_initiator)`. So
        // responder's SIG comes later, from `receive_sig`. The
        // recv here is the initiator's KEX; responder stashes it
        // and that's all. recv_outs is empty.)
        //
        // ACTUAL flow:
        //   responder start() → KEX → ANS_KEY (init_outs)
        //   responder receive(init's KEX) → stash, no output
        //   [initiator gets responder's KEX via ans_key_h]
        //   [initiator receive() → sends SIG via ANS_KEY]
        //   responder receive(init's SIG) → send own SIG +
        //     HandshakeDone (`receive_sig:684-695` responder branch)
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
                // C `:249`: returns true (don't drop conn). We match.
            }
        }
        Ok(nw)
    }

    /// `ans_key_h` (`protocol_key.c:420-648`), SPTPS branch only
    /// (`:549-581`). The other end of the per-tunnel handshake:
    /// b64-decode the key field, feed it to `tunnels[from].sptps`.
    ///
    /// The legacy branch (`!from->status.sptps`, `:585-648`) is
    /// the OpenSSL cipher/digest negotiation. STUB(chunk-never):
    /// we're SPTPS-only.
    ///
    /// `:462` relay wired (chunk-9b). `:473-482` reflexive-addr
    /// append (`:473-482`): three-gate, then `"%s %s %s"`. The
    /// LAN-direct workstream. `:578` `send_mtu_info`: wired.
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
            .map_or("<gone>", |c| c.name.as_str())
            .to_owned();

        // C `:444-460`: `from = lookup_node`; `to = lookup_node`.
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

        // C `:462-484`: `if(to != myself)` relay.
        if to_nid != self.myself {
            // C `:463-465`: `if(tunnelserver) return true`.
            if self.settings.tunnelserver {
                return Ok(false);
            }
            if !self.graph.node(to_nid).is_some_and(|n| n.reachable) {
                log::warn!(target: "tincd::proto",
                           "Got ANS_KEY from {conn_name} destination {} \
                            which is not reachable", msg.to);
                return Ok(false);
            }
            // C `:473-482`: `if(!*address && from->address.sa.
            // sa_family != AF_UNSPEC && to->minmtu)`. Three gates:
            //   - `!*address`: wire didn't already have addr/port
            //     (we're the FIRST relay; subsequent relays don't
            //     double-append). Maps: `msg.udp_addr.is_none()`.
            //   - `from->address ... != AF_UNSPEC`: we have a UDP
            //     addr for `from` (their probes reached us OR
            //     they're a direct peer). Maps: `tunnels[from].
            //     udp_addr.is_some()`.
            //   - `to->minmtu`: PMTU has converged for `to`. The C
            //     comment is silent on why; rationale: "to is
            //     actively using UDP, so the reflexive addr is
            //     useful to them". TCP-only nodes wouldn't use it.
            //
            // On match: `send_request("%s %s %s", request, addr,
            // port)` — the ORIGINAL request line plus appended
            // addr/port. We do the C-literal raw concat (cheaper
            // than rebuilding `AnsKey`; identical wire shape per
            // `key.rs:273` comment).
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
            // C `:484`: `send_request(to->nexthop->connection,
            // "%s", request)`. Forward verbatim (or with append).
            return Ok(match appended {
                Some(a) => conn.send(format_args!("{a}")),
                None => conn.send(format_args!("{body_str}")),
            });
        }

        // C `:499-545`: compression-level capability check, then
        // `:545`: `from->outcompression = compression`. We compress
        // TOWARDS them at the level they asked for. The C `switch`
        // rejects levels we don't support (LZO without HAVE_LZO);
        // `Level::from_wire` maps unknown→None which compresses to
        // a no-op — same outcome (we send raw, they decompress raw
        // at level None which is memcpy). LZO 10/11 are stubbed:
        // `compress()` returns None, fallback to raw, peer's
        // decompress at LZO level fails. Reject explicitly here so
        // the peer's misconfig surfaces in OUR logs, not as silent
        // packet loss on THEIR side.
        // C uses signed `%d`; clamp negative→0 (± cast safety).
        let their_compression = u8::try_from(msg.compression).unwrap_or(0);
        match compress::Level::from_wire(their_compression) {
            compress::Level::LzoLo | compress::Level::LzoHi => {
                log::error!(target: "tincd::proto",
                            "Node {} uses bogus compression level {}: \
                             LZO compression is unavailable on this node",
                            msg.from, their_compression);
                // C `:517`: `return true` (don't terminate the META
                // conn). Just ignore this ANS_KEY.
                return Ok(false);
            }
            _ => {}
        }
        self.tunnels.entry(from_nid).or_default().outcompression = their_compression;

        // C `:549`: `if(from->status.sptps)`. Always true for us
        // (no legacy). The `key` field is the b64'd SPTPS
        // handshake record.
        let Some(hs_bytes) = tinc_crypto::b64::decode(&msg.key) else {
            log::error!(target: "tincd::proto",
                        "Got bad ANS_KEY from {}: invalid SPTPS data", msg.from);
            return Ok(false);
        };

        // C `:553`: `sptps_receive_data(&from->sptps, buf, len)`.
        // The SPTPS state machine MUST already exist (we sent
        // REQ_KEY first; `send_req_key` set `tunnel.sptps`).
        let Some(sptps) = self
            .tunnels
            .get_mut(&from_nid)
            .and_then(|t| t.sptps.as_deref_mut())
        else {
            // C `:553` would deref a NULL `from->sptps.state`.
            // The C reaches `sptps_receive_data` with a zeroed
            // struct → returns false → hits the restart logic
            // at `:556-563`. We're safer: log + restart.
            log::warn!(target: "tincd::proto",
                       "Got ANS_KEY from {} but no SPTPS state; restarting",
                       msg.from);
            return Ok(self.send_req_key(from_nid));
        };

        let result = sptps.receive(&hs_bytes, &mut OsRng);
        let outs = match result {
            Ok((_consumed, outs)) => outs,
            Err(e) => {
                // C `:555-563`: "tunnel stuck" restart logic. Gate
                // on `last_req_key + 10 < now`.
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

        // Dispatch. May contain `HandshakeDone` (→ set validkey,
        // log "successful") and/or `Wire` (next handshake step,
        // → ANS_KEY back).
        let mut nw = self.dispatch_tunnel_outputs(from_nid, &msg.from, outs);

        // C `:568-576`: `if(from->status.validkey) { if(*address
        // && *port) { ... update_node_udp(from, &sa); } }`.
        // Two gates:
        //   - `validkey`: handshake just completed (set INSIDE
        //     `dispatch_tunnel_outputs` above on `HandshakeDone`).
        //     Without it the addr is stale/untrusted (could be a
        //     replay).
        //   - `*address && *port`: relay actually appended one.
        //
        // `update_node_udp` for us is `tunnel.udp_addr = Some(addr)`
        // (the `node_udp_tree` re-index is for legacy receive; we
        // don't have that — see `:1035-1043` comment below).
        if let Some((addr_s, port_s)) = &msg.udp_addr {
            let validkey = self
                .tunnels
                .get(&from_nid)
                .is_some_and(|t| t.status.validkey);
            if validkey {
                if let Some(addr) = local_addr::parse_addr_port(addr_s.as_str(), port_s.as_str()) {
                    log::debug!(target: "tincd::proto",
                                "Using reflexive UDP address from {}: {addr}",
                                msg.from);
                    self.tunnels.entry(from_nid).or_default().udp_addr = Some(addr);
                }
            }
        }

        // C `:576`: `send_mtu_info(myself, from, MTU)`. After
        // dispatch — the C order is `sptps_receive_data` then
        // `send_mtu_info`. The hint goes regardless of whether
        // the handshake completed.
        nw |= self.send_mtu_info(from_nid, &msg.from, i32::from(MTU), true);
        Ok(nw)
    }

    /// Dedup gate for flooded messages. `seen_request` (`protocol.
    /// c:234-249`). Returns `true` if `body` was already seen —
    /// caller drops silently (return `Ok(false)`, don't process,
    /// don't forward).
    ///
    /// `body` is the FULL line (`\n` already stripped). C keys on
    /// `strcmp` of the whole `request` string; the dedup nonce
    /// (second `%x` token) makes identical-payload-different-origin
    /// messages distinct. We pass `body` as-is. The &[u8]→&str
    /// conversion: C `strcmp` is byte-compare; `seen.check` keys on
    /// `&str` (HashMap via `Borrow<str>`). Node names are `check_id`-
    /// gated to ASCII so the body IS valid UTF-8; `from_utf8` here
    /// is just a type cast.
    pub(super) fn seen_request(&mut self, body: &[u8]) -> bool {
        // `from_utf8` failure: body has high bytes. Shouldn't
        // happen (the parsers already validated). Treat as not-
        // seen (don't dup-drop garbage — let the handler reject).
        let Ok(s) = std::str::from_utf8(body) else {
            return false;
        };
        self.seen.check(s, self.timers.now())
    }

    /// `prng(UINT32_MAX)` (`utils.c`). Nonce for the dedup field
    /// in flooded ADD/DEL messages. The C uses a fast non-crypto
    /// PRNG (xoshiro256**); we use `OsRng` — overkill but already
    /// linked, no extra dep, and these messages are not hot (one
    /// per topology change). The nonce only needs to be unique-ish
    /// across the mesh's TTL window; cryptographic strength is
    /// gratuitous, not wrong.
    pub(super) fn nonce() -> u32 {
        OsRng.next_u32()
    }

    /// Connections eligible for broadcast: every conn that's past
    /// ACK and isn't `from`. C `meta.c:115`: `if(c != from && c->
    /// edge)`. We test `conn.active` (set in `on_ack`).
    ///
    /// Returns `Vec<ConnId>` (not an iterator) so callers can
    /// `get_mut` while sending — the slotmap iterator borrow would
    /// conflict. Same two-phase collect-then-send shape as
    /// `dispatch_sptps_outputs`. Broadcast is per-topology-change,
    /// not per-packet; the alloc is fine.
    pub(super) fn broadcast_targets(&self, from: Option<ConnId>) -> Vec<ConnId> {
        self.conns
            .iter()
            .filter(|&(id, c)| Some(id) != from && c.active)
            .map(|(id, _)| id)
            .collect()
    }

    /// `forward_request` (`protocol.c:135-146`) → `broadcast_meta`
    /// (`meta.c:113-117`). Re-send `body` (a decrypted SPTPS record
    /// payload, `\n` already stripped by `record_body`) to every
    /// active connection except `from`. The receivers' `seen.check`
    /// drops it if they already have it — that plus the `from` skip
    /// is the loop break.
    ///
    /// C `protocol.c:144` re-appends `\n` then calls `broadcast_
    /// meta` which calls `send_meta` (NOT `send_meta_raw`) — i.e.
    /// the SPTPS-encrypted path. `conn.send()` does both: appends
    /// `\n`, routes through `sptps_send_record`. The body is UTF-8
    /// (parsers already validated; tinc protocol is text); the
    /// `from_utf8` here is the `&[u8]` → `Display` impedance match.
    ///
    /// Returns `true` if any target's outbuf went empty→nonempty.
    pub(super) fn forward_request(&mut self, from: ConnId, body: &[u8]) -> bool {
        // Body is post-parse: `parse_add_subnet` etc already
        // succeeded, which means `from_utf8` did. Shouldn't fire.
        let Ok(s) = std::str::from_utf8(body) else {
            log::warn!(target: "tincd::proto",
                       "forward_request: non-UTF-8 body, dropping");
            return false;
        };
        let targets = self.broadcast_targets(Some(from));
        if targets.is_empty() {
            // One peer: `from` was the only active conn. The skip
            // makes this a no-op. Chunk-5 tests live here.
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

    /// `send_request(everyone, ...)` (`protocol.c:122-125`). The
    /// `c == everyone` branch: format with a fresh nonce then
    /// `broadcast_meta(NULL, ...)`. The `from = None` means NO conn
    /// is skipped — used by `on_ack`'s `send_add_edge(everyone, e)`
    /// (`ack_h:1058`) and `terminate`'s `send_del_edge(everyone, e)`
    /// (`net.c:128`). The new conn / dying conn isn't `active` yet
    /// (or anymore), so it's filtered by `broadcast_targets` anyway.
    ///
    /// Each target gets its OWN nonce — the C `prng(UINT32_MAX)`
    /// is INSIDE `send_request`, which `broadcast_meta` calls
    /// once. Wait, no: `broadcast_meta` calls `send_meta` per
    /// target, but `send_request(everyone, ...)` formats ONCE then
    /// `broadcast_meta` re-sends the SAME bytes. So: one nonce.
    /// Same here: format outside the loop.
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

    /// `send_add_edge` (`protocol_edge.c:37-62`). Format the edge
    /// from `graph` + `edge_addrs` and queue to ONE conn.
    ///
    /// C `:42`: `sockaddr2str(&e->address, &address, &port)`. Our
    /// `edge_addrs` stores the `AddrStr` tokens verbatim. The
    /// `e->local_address.sa.sa_family` check (`:44`) is the
    /// `AF_UNSPEC` test — our `local_addr == "unspec"` is the
    /// equivalent (we stored the literal in `on_ack`/`on_add_edge`).
    ///
    /// Returns `None` if either the edge or its addr entry is gone
    /// (caller skips with a warn). The C never has the missing-addr
    /// case (`e->address` is always set); chunk-5's synthesized
    /// reverse from `on_ack` does. The proper fix is `on_ack`
    /// populating both halves, but until then we skip rather than
    /// emit `"unknown port unknown"` on the wire (peers would
    /// `str2sockaddr` it to `AF_UNKNOWN` and never connect).
    pub(super) fn fmt_add_edge(&self, eid: EdgeId, nonce: u32) -> Option<String> {
        let e = self.graph.edge(eid)?;
        let (addr, port, la, lp) = self.edge_addrs.get(&eid)?;
        let from = self.graph.node(e.from)?.name.clone();
        let to = self.graph.node(e.to)?.name.clone();
        // C `:44`: `if(e->local_address.sa.sa_family)`. AF_UNSPEC
        // is 0; our sentinel is the `"unspec"` string token.
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

    /// `send_add_edge(c, e)` to ONE target. Correction path
    /// (`protocol_edge.c:153,289`).
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

    /// `send_del_edge(c, e)` (`protocol_edge.c:219-222`). Just
    /// `"%d %x %s %s"`. The C builds a transient `edge_t` for the
    /// `:190` contradiction case (no real edge to format from); we
    /// take names directly.
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

    /// `send_add_subnet`/`send_del_subnet` (`protocol_subnet.c:
    /// 33-44,153-161`). Same wire shape; `which` picks the reqno.
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

    /// `send_everything` (`protocol_auth.c:870-900`). Walk the
    /// world model, send ADD_SUBNET + ADD_EDGE for everything we
    /// know. Called from `on_ack` (`ack_h:1028`) — bring the new
    /// peer up to speed.
    ///
    /// C: nested `splay_each(node) { splay_each(subnet); splay_
    /// each(edge) }`. We flatten: `SubnetTree::iter()` walks ALL
    /// subnets in one pass (no per-node grouping needed — the wire
    /// format carries `(owner, subnet)`, the order doesn't matter);
    /// `Graph::edge_iter()` walks ALL edges. The C's per-node
    /// nesting is an artifact of `n->subnet_tree`/`n->edge_tree`
    /// hanging off each `node_t`; we have global trees. Same wire
    /// output, less indirection.
    ///
    /// `disablebuggypeers` (`:873-881`): the zeropkt workaround
    /// for an ancient bug. Niche knob; skipped. `tunnelserver`
    /// (`:884-889`): myself-only mode — the hub doesn't gossip the
    /// whole graph; it sends only ITS OWN subnets. NO edges.
    pub(super) fn send_everything(&mut self, to: ConnId) -> bool {
        if self.settings.tunnelserver {
            // C `protocol_auth.c:884-889`: tunnelserver mode sends
            // ONLY `myself`'s subnets, NO edges. The peer doesn't
            // get to learn the rest of the graph from us. The
            // peer's edge to us comes from `on_ack`'s `send_add_
            // edge(c, c->edge)` (NOT `everyone` — see `on_ack`).
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
        // Collect into a `Vec<String>` first: `subnets.iter()`
        // borrows `&self`, `conn.send()` needs `&mut self.conns`.
        // Disjoint fields, but `self.nonce()` (associated fn,
        // doesn't borrow) and `format` are pure — easiest to
        // pre-format.
        let mut lines: Vec<String> = Vec::new();

        // C `:893`: `for splay_each(subnet_t, s, &n->subnet_tree)`.
        // Flattened: one walk over the global tree.
        for (subnet, owner) in self.subnets.iter() {
            let msg = SubnetMsg {
                owner: owner.to_owned(),
                subnet: *subnet,
            };
            lines.push(msg.format(Request::AddSubnet, Self::nonce()));
        }

        // C `:897`: `for splay_each(edge_t, e, &n->edge_tree)`.
        // `edge_iter()` is one slab pass. Edges with no `edge_
        // addrs` entry (chunk-5's synthesized reverse) are skipped
        // — see `fmt_add_edge` doc. The peer will learn that edge
        // from the OTHER endpoint's `send_add_edge(everyone, ...)`
        // when THEY connect.
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

    /// `graph()` (`graph.c:322-327`): sssp + diff + mst. Logs each
    /// transition. The script-spawn / sptps_stop / mtu-reset are
    /// chunk-7/8 deferrals; the LOG proves the diff fired.
    ///
    /// C `graph.c:227`: `"Node %s (%s) became reachable"` at
    /// `DEBUG_TRAFFIC`. We don't have the hostname (no `NodeState`
    /// for transitive nodes); log the name from the graph.
    pub(super) fn run_graph_and_log(&mut self) {
        let (transitions, mst, routes) = run_graph(&mut self.graph, self.myself);
        // Stash for `dump_nodes` (`node.c:218`: nexthop/via/distance
        // are read straight off `node_t`, which the C `graph.c:188-
        // 196` writes into). We keep the side table.
        self.last_routes = routes;
        // C `graph.c:103,107` sets each MST-edge's connection's
        // `status.mst` bit; we keep the edge IDs and map at
        // broadcast time (`broadcast_packet` in `net.rs`).
        self.last_mst = mst;
        //
        // C `graph.c:323` calls `subnet_cache_flush_tables`. We
        // don't HAVE a cache (`subnet_tree.rs:31` says so). The C
        // cache is a hot-path memo over the trie walk; ours walks
        // every time. If profiling shows the trie is hot, add a
        // cache; THEN add a flush. No stub for a flush of a cache
        // that doesn't exist.
        for t in transitions {
            match t {
                Transition::BecameReachable { node, via: via_nid } => {
                    // `graph.c:261-262`: INFO. Look up the name —
                    // graph.node() is `Some` (just came from
                    // node_ids() inside diff_reachability).
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

                    // C `graph.c:201`: `update_node_udp(n,
                    // &e->reverse->address)`. The SSSP `prevedge`'s
                    // reverse address is the "how to reach this
                    // node via UDP" guess. For chunk 7: use the
                    // edge addr from `on_ack` (`NodeState.edge_addr`,
                    // already port-rewritten to UDP). With direct
                    // neighbors, that's the right answer; transitives
                    // would need the prevedge-walk (chunk 9).
                    //
                    // The C `update_node_udp` (`net_packet.c:
                    // 1708-1745`) ALSO re-indexes `node_udp_tree`
                    // (addr → node lookup for the legacy receive
                    // path at `:1728`). We don't have that tree:
                    // incoming UDP keys on the `[dst_id6][src_id6]`
                    // prefix (the SPTPS-only path, `:1779-1825`),
                    // never `node_udp_tree`. So `update_node_udp`
                    // for us is just "set `tunnel.udp_addr`".
                    let name_owned = name.to_owned();
                    let addr = self.nodes.get(&name_owned).and_then(|ns| ns.edge_addr);
                    if let Some(addr) = addr {
                        let tunnel = self.tunnels.entry(node).or_default();
                        tunnel.udp_addr = Some(addr);
                    }

                    // C `graph.c:273-289`: `execute_script("host-
                    // up")` + `"hosts/NAME-up"`. AFTER the address
                    // is known (the script may want it).
                    self.run_host_script(true, &name_owned, addr);

                    // C `graph.c:294`: `subnet_update(n, NULL,
                    // reachable)`. The `subnet=NULL` branch
                    // (`subnet.c:352-372`): fire subnet-up for
                    // EVERY subnet this node owns. The node was
                    // unreachable; its subnets weren't routable;
                    // now they are.
                    let owned: Vec<Subnet> = self
                        .subnets
                        .iter()
                        .filter(|(_, o)| *o == name_owned)
                        .map(|(s, _)| *s)
                        .collect();
                    for s in &owned {
                        self.run_subnet_script(true, &name_owned, s);
                    }
                    // C `node.c:58-59` (`new_node`): `n->status.
                    // sptps` is set by `add_edge_h` (`protocol_edge.
                    // c:163-165`: `if(edge->options >> 24 >= 2)
                    // status.sptps = true`). For chunk 7: always
                    // true (no legacy peers). Set it here so `dump
                    // nodes` shows bit 6.
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
                    // The address: read BEFORE `reset_unreachable`
                    // clears `udp_addr`. C `n->address` is also
                    // cleared by `update_node_udp(n, NULL)` at
                    // `:296`, but the script call at `:284` happens
                    // first. Match.
                    let addr = self
                        .tunnels
                        .get(&node)
                        .and_then(|t| t.udp_addr)
                        .or_else(|| self.nodes.get(&name_owned).and_then(|ns| ns.edge_addr));

                    // C `graph.c:273-289`: host-down + hosts/NAME-down.
                    self.run_host_script(false, &name_owned, addr);

                    // C `graph.c:294`: subnet-down for every owned
                    // subnet. Mirror of the BecameReachable case.
                    let owned: Vec<Subnet> = self
                        .subnets
                        .iter()
                        .filter(|(_, o)| *o == name_owned)
                        .map(|(s, _)| *s)
                        .collect();
                    for s in &owned {
                        self.run_subnet_script(false, &name_owned, s);
                    }

                    // C `graph.c:256-297`: sptps_stop, reset mtu
                    // probe state, clear status bits, clear UDP
                    // addr. `TunnelState::reset_unreachable` IS
                    // that whole block.
                    //
                    // C `:270`: `timeout_del(&n->udp_ping_timeout)`.
                    // The `TimerWhat::UdpPing` variant exists but
                    // is never armed (PMTU is driven by `try_tx`
                    // calling `pmtu.tick()` inline, not a separate
                    // timer). Nothing to del. If a per-node UDP
                    // timer ever lands, it gets killed here.
                    if let Some(tunnel) = self.tunnels.get_mut(&node) {
                        tunnel.reset_unreachable();
                    }
                }
            }
        }
    }

    /// `dump_nodes` row builder (`node.c:201-223`). Walks the graph
    /// (every known node, not just `nodes` — transitives included).
    ///
    /// C format string (`:210`): `"%d %d %s %s %s %d %d %lu %d %x
    /// %x %s %s %d %d %d %d %ld %d %"PRIu64×4`. Twenty-one printf
    /// conversions; the CLI's sscanf has 22 (`" port "` re-splits
    /// the fused hostname — see `tinc-tools::cmd::dump` doc).
    ///
    /// Chunk-5 placeholders for daemon state we don't track yet:
    /// - `id` (`node_id_t` 6-byte hash, `node.c:204-208`): chunk 7
    ///   (UDP) computes it. Zero-hex.
    /// - `cipher/digest/maclength`: `0 0 0` (DISABLE_LEGACY path,
    ///   `node.c:213`).
    /// - `compression`: `0` (`n->outcompression` defaults zero).
    /// - `mtu/minmtu/maxmtu`: `0 0 0` (chunk 9, PMTU discovery).
    /// - `last_state_change`: `0` (would need an `Instant` stash
    ///   per-node at transition time; deferred).
    /// - `udp_ping_rtt`: `-1` (the C init value, `node.c:58`).
    /// - traffic counters: `0` (chunk 7, per-tunnel stats).
    ///
    /// `status` bitfield (`node.h:32-48`, GCC LSB-first packing):
    /// only bit 4 (`reachable`) is real — read from `graph.node().
    /// reachable` (written by `run_graph_and_log`'s diff). The CLI's
    /// `dump reachable nodes` filter (`tincctl.c:1306`) keys on it.
    pub(super) fn dump_nodes_rows(&self) -> Vec<String> {
        let mut rows = Vec::new();
        for nid in self.graph.node_ids() {
            let Some(node) = self.graph.node(nid) else {
                continue; // freed slot (concurrent del; defensive)
            };
            let name = node.name.as_str();

            // C `:211`: `n->hostname ? n->hostname : "unknown port
            // unknown"`. C `net_setup.c:1199`: `myself->hostname =
            // "MYSELF port <tcp>"`. Directly-connected peers get a
            // hostname from `c->address` rewritten to UDP port
            // (`ack_h:1024-1025`, our `NodeState.edge_addr`).
            // Transitives have no hostname (the C learns it from
            // `update_node_udp`, chunk-7 UDP territory) → the
            // literal.
            let hostname = if nid == self.myself {
                format!("MYSELF port {}", self.my_udp_port)
            } else if let Some(ea) = self.nodes.get(name).and_then(|ns| ns.edge_addr.as_ref()) {
                // `fmt_addr` shape: `"%s port %s"`, no v6 brackets
                // (matches `getnameinfo NI_NUMERICHOST`).
                fmt_addr(ea)
            } else {
                "unknown port unknown".to_string()
            };

            // C `:217`: `n->options`. The C `graph.c:192` writes
            // `e->to->options = e->options` during sssp — i.e. the
            // INCOMING edge's options. `last_routes` carries that.
            // For `myself`, sssp seeds `options=0` (`graph.c:144`
            // never writes it; `sssp` here mirrors that). For
            // unreachable nodes (no route), C reads stale; we read
            // 0.
            let route = self
                .last_routes
                .get(nid.0 as usize)
                .and_then(Option::as_ref);
            let options = route.map_or(0, |r| r.options);

            // C `:217`: `n->status.value`. `TunnelStatus::as_u32`
            // packs the bits we track (validkey, waitingforkey,
            // sptps, udp_confirmed, udppacket); `reachable` is the
            // param. `myself`'s status: just `reachable` (we don't
            // tunnel to ourselves). C `:217` reads `n->status.value`
            // which for `myself` is whatever `xzalloc` left; the C
            // `setup_myself:1050` sets `reachable=true` and that's
            // it.
            let tunnel = self.tunnels.get(&nid);
            let status = tunnel.map_or_else(
                || {
                    if node.reachable { 1 << 4 } else { 0 }
                },
                |t| t.status.as_u32(node.reachable),
            );

            // C `:218`: `n->nexthop ? n->nexthop->name : "-"`. Read
            // from `last_routes`. Unreachable → `"-"` (C: `nexthop`
            // is whatever stale pointer `xzalloc` left, but the C
            // `node.c:218` does NULL-check; freshly-created nodes
            // have NULL nexthop).
            let (nexthop, via, distance) = match route {
                Some(r) => {
                    let nh = self.graph.node(r.nexthop).map_or("-", |n| n.name.as_str());
                    let via = self.graph.node(r.via).map_or("-", |n| n.name.as_str());
                    (nh, via, r.distance)
                }
                // C: unreachable nodes keep stale `distance` (last
                // sssp that DID reach them). `xzalloc` fresh nodes
                // have `distance=0`. We don't track stale; emit 0.
                None => ("-", "-", 0),
            };

            // C `:210` format. The %lu (maclength) and %ld (last_
            // state_change) are `0` literals; %"PRIu64" ×4 are `0`.
            // udp_ping_rtt is `-1` (C `node.c:58`: `n->udp_ping_rtt
            // = -1`).
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

    /// `dump_edges` row builder (`edge.c:123-137`). Nested walk:
    /// per node, per outgoing edge — the C `splay_each(node) splay_
    /// each(edge)` shape. Edges are directional; both halves of a
    /// bidi pair appear as separate rows.
    ///
    /// C format (`:128`): `"%d %d %s %s %s %s %x %d"`. Six body
    /// conversions; CLI sscanf has 8 (TWO `" port "` re-splits —
    /// addr AND local_addr are `sockaddr2hostname` output).
    ///
    /// `e->address` formatting: C `sockaddr2hostname` (`netutl.c:
    /// 153-175`). For `AF_UNKNOWN` addrs (the unparsed-string case,
    /// what `str2sockaddr` builds when the addr token isn't a
    /// numeric IP), it's `"%s port %s"` of the stored strings
    /// (`netutl.c:163`). That's what we stored in `edge_addrs` —
    /// raw `AddrStr` tokens, round-tripped verbatim.
    ///
    /// Edges with no `edge_addrs` entry (the synthesized reverse
    /// from `on_ack`, see the STUB note there): `"unknown port
    /// unknown"`. The C wouldn't have such edges (the peer's
    /// `send_add_edge` would've populated them); chunk-5 specific.
    pub(super) fn dump_edges_rows(&self) -> Vec<String> {
        let mut rows = Vec::new();
        // C `:124-125`: `for splay_each(node) for splay_each(edge,
        // &n->edge_tree)`. `edge_iter()` is one slab pass, no per-
        // node hops. Order diverges from C (slab vs nested-splay);
        // intentional — `tincctl.c` reads dump rows into an
        // unordered set and sorts client-side. See `edge_iter()`
        // doc comment.
        for (eid, e) in self.graph.edge_iter() {
            let from = self
                .graph
                .node(e.from)
                .map_or("<gone>", |n| n.name.as_str());
            let to = self.graph.node(e.to).map_or("<gone>", |n| n.name.as_str());

            // C `:126-127`: `sockaddr2hostname(&e->address)` /
            // `sockaddr2hostname(&e->local_address)`. Our
            // `edge_addrs` stores the wire `AddrStr` pairs
            // verbatim; format as `"%s port %s"` (the
            // `AF_UNKNOWN` branch, `netutl.c:163`).
            let (addr, local) = match self.edge_addrs.get(&eid) {
                Some((a, p, la, lp)) => (format!("{a} port {p}"), format!("{la} port {lp}")),
                // Synthesized-reverse case (chunk-5 STUB; see
                // `on_ack`). The C never has addr-less edges.
                None => (
                    "unknown port unknown".to_string(),
                    "unknown port unknown".to_string(),
                ),
            };

            // C `:128`: `"%d %d %s %s %s %s %x %d"`.
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

    /// `add_subnet_h` mutation half (`protocol_subnet.c:43-140`).
    ///
    /// C path traced:
    /// - `:49-68` parse + check_id + str2net — `parse_add_subnet`
    /// - `:71` `seen_request(request)` — dup-drop
    /// - `:77` `lookup_node(name)` — `lookup_or_add_node`
    /// - `:79-84` `tunnelserver` filter — STUBBED (deferred niche)
    /// - `:86-89` `if(!owner) new_node` — fused into lookup
    /// - `:93` `lookup_subnet(owner, &s)` — SubnetTree::add is
    ///   idempotent, but the C returns early WITHOUT forward. We
    ///   match: `seen` already dedups the flood; `add` idempotent.
    /// - `:98-104` `if(owner == myself)` — retaliate — STUBBED
    /// - `:116-122` `strictsubnets` — STUBBED (deferred)
    /// - `:126-128` `subnet_add(owner, new)` — SubnetTree::add
    /// - `:130-132` `subnet_update` script — STUBBED (chunk 8)
    /// - `:136-138` `forward_request` — STUBBED
    /// - `:142-148` MAC fast-handoff — STUBBED (no MAC subnets yet)
    ///
    /// NO `graph()` — subnets don't change topology. The C calls
    /// `subnet_update` (`subnet.c:327-393`, script firing) not
    /// `graph()`.
    ///
    /// Returns the io_set signal. Always `false` in chunk 5
    /// (forward stubbed, retaliate stubbed). Kept for chunk 5b.
    pub(super) fn on_add_subnet(
        &mut self,
        from_conn: ConnId,
        body: &[u8],
    ) -> Result<bool, DispatchError> {
        let (owner_name, subnet) = parse_add_subnet(body)?;

        // C `:71`: `if(seen_request(request)) return true`.
        if self.seen_request(body) {
            return Ok(false);
        }

        // C `:79-84`: tunnelserver indirect filter. Drop if owner
        // is neither us nor the directly-connected peer who sent
        // this. The check goes BEFORE `lookup_or_add_node` — the
        // whole point is to NOT learn indirect names. C does it
        // after lookup but before `new_node` (because their lookup
        // is just lookup; ours is lookup-or-add). String-compare
        // before to avoid polluting the graph.
        //
        // ORDER: `seen_request` FIRST (`:71`), THEN tunnelserver
        // filter (`:79`). Even if we're going to drop, mark it seen
        // so a dup from another conn doesn't get re-processed.
        if self.settings.tunnelserver {
            let conn_name = self
                .conns
                .get(from_conn)
                .map_or("<gone>", |c| c.name.as_str());
            if owner_name != self.name && owner_name != conn_name {
                log::warn!(target: "tincd::proto",
                           "Ignoring indirect ADD_SUBNET from {conn_name} \
                            for {owner_name} ({subnet})");
                return Ok(false);
            }
        }

        // C `:93`: `if(lookup_subnet(owner, &s)) return true`.
        // Lookup-first idempotency. With `strictsubnets`, this is
        // what lets AUTHORIZED subnets through silently:
        // `load_all_nodes` preloaded them; gossip arrives, lookup
        // finds it, return. UNAUTHORIZED subnets fall through to
        // the `:116` gate below. Without strictsubnets this is
        // belt-and-braces over `seen_request` (our `subnets.add`
        // is BTreeSet-idempotent, but checking here saves the
        // `lookup_or_add_node` call AND the script run — the C's
        // intent at `:93`).
        if self.subnets.contains(&subnet, &owner_name) {
            return Ok(false);
        }

        // C `:77,86-89`: lookup_node + conditional new_node.
        let owner = self.lookup_or_add_node(&owner_name);

        // C `:98-104`: `if(owner == myself)`. Peer is wrong about
        // us — they think we own a subnet we don't. C sends
        // DEL_SUBNET correction back.
        if owner == self.myself {
            let conn_name = self
                .conns
                .get(from_conn)
                .map_or("<gone>", |c| c.name.as_str())
                .to_owned();
            log::warn!(target: "tincd::proto",
                       "Got ADD_SUBNET from {conn_name} for ourself ({subnet})");
            // C `:103`: `send_del_subnet(c, &s)`. Retaliate: tell
            // the peer to delete it. Our name as owner; the subnet
            // they just sent. Dark in single-peer tests (peer never
            // gossips our own subnets back at us); reachable via
            // stale gossip in a multi-peer mesh.
            let nw = self.send_subnet(from_conn, Request::DelSubnet, &self.name.clone(), &subnet);
            return Ok(nw);
        }

        // C `:109-112`: `if(tunnelserver)` second gate. Reached
        // when owner IS the direct peer but the subnet wasn't in
        // our hosts/ file ("unauthorized"). The C `:880`
        // `strictsubnets |= tunnelserver` makes the `:116` check
        // below fire on the SAME predicate, so this gate is DEAD
        // CODE in practice. The C keeps both for clarity (they
        // ARE conceptually distinct: `:109` is "hub doesn't trust
        // direct peers' arbitrary claims", `:116` is "operator's
        // hosts/ is authority"). Match the C: keep both, in C order.
        if self.settings.tunnelserver {
            // Same gate body as `:116` below; the C's `:109` does
            // `forward_request(c)` then `return true`. The implication
            // makes this unreachable, but keep it for C-parity.
            log::warn!(target: "tincd::proto",
                       "Ignoring unauthorized ADD_SUBNET for {owner_name} \
                        ({subnet}) (tunnelserver)");
            let nw = self.forward_request(from_conn, body);
            return Ok(nw);
        }

        // C `:116-122`: `if(strictsubnets) { forward_request;
        // return true }`. The on-disk hosts/ file is authority;
        // gossip can't add what's not there. Forward (the peer's
        // worldview is wrong but propagate the gossip to others
        // who may not be strict) but don't `subnet_add` locally.
        if self.settings.strictsubnets {
            log::warn!(target: "tincd::proto",
                       "Ignoring unauthorized ADD_SUBNET for {owner_name} \
                        ({subnet}) (strictsubnets)");
            let nw = self.forward_request(from_conn, body);
            return Ok(nw);
        }

        // C `:126`: `subnet_add(owner, new)`. Idempotent on dup
        // (the C `:93` `if(lookup_subnet) return true` is
        // belt-and-braces over `seen_request`; our `add` is a
        // BTreeSet insert which is also idempotent). Clone the
        // owner: `subnet_update` below needs it. `Subnet` is `Copy`.
        self.subnets.add(subnet, owner_name.clone());

        // mac_table sync: every Subnet::Mac add/del also updates the
        // flat lookup table that `route_mac.rs` reads.
        if let Subnet::Mac { addr, .. } = subnet {
            self.mac_table.insert(addr, owner_name.clone());

            // C `protocol_subnet.c:142-148`: fast handoff. A peer
            // learned a MAC that WE also have leased (a VM migrated
            // to behind them). Set our lease's expiry to now so the
            // next age_subnets pass DELs it (and they win).
            //
            // C: `lookup_subnet(myself, &s)` + `if(old && old->
            // expires) old->expires = 1`. Our `mac_leases` ONLY
            // holds myself's leases, so `refresh()` returning
            // `true` IS the `lookup_subnet(myself,..)` check.
            // `refresh(addr, now, 0)` sets `expires = now`; with
            // `age()`'s strict-less compare it expires next tick.
            // Same net effect as the C's `expires = 1`.
            if owner != self.myself {
                let now = self.timers.now();
                if self.mac_leases.refresh(addr, now, 0) {
                    log::debug!(target: "tincd::proto",
                        "Fast handoff: peer {owner_name} learned our \
                         leased MAC {addr:02x?}; expiring ours");
                }
            }
        }

        // C `:130-132`: `if(owner->status.reachable) subnet_update(
        // owner, new, true)`. Only fire subnet-up if the owner is
        // reachable: a subnet learned via gossip for a node we can't
        // reach isn't actually routable yet (the host-up handler
        // fires it later, in the BecameReachable arm).
        let reachable = self.graph.node(owner).is_some_and(|n| n.reachable);
        if reachable {
            self.run_subnet_script(true, &owner_name, &subnet);
        }

        // C `:136-138`: `if(!tunnelserver) forward_request(c, req)`.
        // The `seen.check` ABOVE prevents the loop (`seen_request`
        // is FIRST in C too, `:71`).
        let nw = if self.settings.tunnelserver {
            false
        } else {
            self.forward_request(from_conn, body)
        };

        Ok(nw)
    }

    /// `del_subnet_h` mutation half (`protocol_subnet.c:163-261`).
    ///
    /// C path traced:
    /// - `:163-188` parse — `parse_del_subnet`
    /// - `:191` `seen_request`
    /// - `:197` `lookup_node` — NOT lookup_or_add: DEL for an
    ///   unknown owner is a warn-and-drop (`:206-210`)
    /// - `:216` `lookup_subnet` — same: DEL for unknown subnet is
    ///   warn-and-drop (`:218-225`). Our `del()` returns `bool`.
    /// - `:199-204` `tunnelserver` filter — STUBBED (deferred niche)
    /// - `:231-236` `if(owner == myself)` retaliate ADD — STUBBED
    /// - `:244` `forward_request` — STUBBED
    /// - `:254-256` `subnet_update(..., false)` — STUBBED (chunk 8)
    /// - `:258` `subnet_del`
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
            .map_or("<gone>", |c| c.name.as_str())
            .to_owned();

        // C `:199-204`: tunnelserver indirect filter. Drop if owner
        // is neither us nor the direct peer. ORDER: seen_request
        // (`:191`) first, THEN this. `conn_name` already computed.
        if self.settings.tunnelserver && owner_name != self.name && owner_name != conn_name {
            log::warn!(target: "tincd::proto",
                       "Ignoring indirect DEL_SUBNET from {conn_name} \
                        for {owner_name} ({subnet})");
            return Ok(false);
        }

        // C `:197,206-210`: `lookup_node`. NOT lookup_or_add — a
        // DEL for a node we've never heard of is wrong. Warn,
        // return true (don't drop conn).
        let Some(&owner) = self.node_ids.get(&owner_name) else {
            log::warn!(target: "tincd::proto",
                       "Got DEL_SUBNET from {conn_name} for {owner_name} \
                        which is not in our node tree");
            return Ok(false);
        };

        // C `:231-236`: `if(owner == myself)`. Peer says we don't
        // own a subnet we DO own. C sends ADD_SUBNET correction.
        if owner == self.myself {
            log::warn!(target: "tincd::proto",
                       "Got DEL_SUBNET from {conn_name} for ourself ({subnet})");
            // C `:234`: `send_add_subnet(c, find)`. The C looks up
            // the subnet WE actually own (`find = lookup_subnet(
            // myself, &s)` at `:227`); if we don't own it either,
            // `:228-230` returns true (no correction — peer is
            // right, we DON'T own it). We don't track per-node
            // ownership of subnets here (`SubnetTree` is global +
            // owner-string); send back what they sent. Dark in
            // single-peer tests.
            let nw = self.send_subnet(from_conn, Request::AddSubnet, &self.name.clone(), &subnet);
            return Ok(nw);
        }

        // C `:238-240`: `if(tunnelserver) return true`. AFTER the
        // owner==myself retaliate, BEFORE forward+del. The hub
        // never propagates DEL for direct-peer subnets (no one
        // else knows about them anyway).
        if self.settings.tunnelserver {
            return Ok(false);
        }

        // C `:244`: `if(!tunnelserver) forward_request(c, req)`.
        let nw = self.forward_request(from_conn, body);

        // C `:247-249`: `if(strictsubnets) return true`. AFTER
        // forward, BEFORE the actual del. The hosts/ file is
        // authoritative; gossip can't delete authorized subnets.
        // (The C's `:220-225` `if(!find && strictsubnets) {
        // forward; return }` not-found case is folded into the
        // `del()`-returns-false branch below — with strictsubnets,
        // del-of-preloaded → found → we hit THIS gate first; del-
        // of-unauthorized → not found → we forwarded above + warn
        // below. Same observable behavior as C: forward, no del.)
        if self.settings.strictsubnets {
            return Ok(nw);
        }

        // C `:254-256`: `if(owner->status.reachable) subnet_update(
        // owner, find, false)`. BEFORE the del (the script may want
        // to see the route one last time — the C orders it this
        // way). Reachable check: same gate as add.
        let reachable = self.graph.node(owner).is_some_and(|n| n.reachable);
        if reachable {
            self.run_subnet_script(false, &owner_name, &subnet);
        }

        // C `:258`: `subnet_del`. The C does `lookup_subnet` at
        // `:216` first and warns at `:218` if not found. Our
        // `del()` returns the bool; same outcome, one fewer walk.
        if !self.subnets.del(&subnet, &owner_name) {
            // C `:218-225`: warn, return true.
            log::warn!(target: "tincd::proto",
                       "Got DEL_SUBNET from {conn_name} for {owner_name} \
                        which does not appear in his subnet tree");
        }

        // mac_table sync. Only remove if the entry's owner matches
        // (don't wipe a different owner's entry on a stale DEL —
        // shouldn't happen since MAC is exact-match, but defensively).
        if let Subnet::Mac { addr, .. } = subnet {
            if self.mac_table.get(&addr).map(String::as_str) == Some(owner_name.as_str()) {
                self.mac_table.remove(&addr);
            }
        }

        Ok(nw)
    }

    /// `add_edge_h` mutation half (`protocol_edge.c:63-217`).
    ///
    /// C path traced:
    /// - `:77-92` parse — `parse_add_edge` (incl check_id, from≠to)
    /// - `:94` `seen_request`
    /// - `:99-100` `lookup_node(from/to)`
    /// - `:102-111` `tunnelserver` filter — STUBBED
    /// - `:112-120` `if(!from/to) new_node` — lookup_or_add
    /// - `:126-130` `str2sockaddr` — SKIPPED (graph doesn't store
    ///   addrs; AddrStr is opaque per Phase-1 finding)
    /// - `:134-183` `lookup_edge` exists branch:
    ///   - same weight+options → idempotent drop (`:145-148`)
    ///   - `from == myself` + different → send correction (`:150-
    ///     157`) — STUBBED
    ///   - different → update in place. `Graph::update_edge`
    ///     keeps the `EdgeId` slot stable (`edge_addrs` is keyed
    ///     on it; del+add only worked because the slab freelist is
    ///     LIFO — same slot back, by accident not contract).
    /// - `:184-196` `from == myself` + doesn't exist → contradiction.
    ///   C bumps `contradicting_add_edge`, sends DEL correction.
    ///   STUBBED.
    /// - `:197-205` `edge_add` — graph.add_edge
    /// - `:209-211` `forward_request` — STUBBED
    /// - `:215` `graph()` — run_graph_and_log
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
            .map_or("<gone>", |c| c.name.as_str())
            .to_owned();

        // C `protocol_edge.c:103-111`: tunnelserver indirect filter.
        // Drop only if NEITHER endpoint is us-or-direct-peer. If
        // `alice→mid` and we're mid, `from == c->node`; keep it.
        // BEFORE `lookup_or_add_node` — don't pollute the graph
        // with indirect names. ORDER: seen_request (`:94`) first.
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

        // C `:134`: `e = lookup_edge(from, to)`.
        if let Some(existing) = self.graph.lookup_edge(from_id, to_id) {
            // C `:144`: idempotent only if weight + options + address
            // + local_address ALL match. The address compare matters
            // for two cases the chunk-5 "weight+options is enough"
            // comment missed:
            //   - C `update_node_udp` cache invalidation (`net_packet.
            //     c:639-648`): UDP target changes if address changes.
            //   - The synthesized reverse edge from `on_ack:5912` has
            //     NO `edge_addrs` entry. When the peer's real ADD_
            //     EDGE arrives (same weight/options but with an addr),
            //     the C `sockaddrcmp(&e->address, &address)` is non-
            //     zero (zeroed sockaddr vs real); it falls through to
            //     the update + forward. Our weight-only check early-
            //     returned, never populated `edge_addrs`, never
            //     forwarded. Hub-spoke breaks: alice never learns
            //     bob→mid (`three_daemon_relay` regression).
            // Fix: also check whether `edge_addrs.get(existing)` is
            // None (synthesized reverse — always falls through) or
            // differs from the wire body.
            let e = self.graph.edge(existing).expect("just looked up");
            let same_addr = self.edge_addrs.get(&existing).is_some_and(|(a, p, _, _)| {
                // Compare only addr+port. C's `sockaddrcmp` ignores
                // local_address unless `sa_family` is set AND not
                // AF_UNKNOWN (`:141-143`); we sidestep by treating
                // any local-addr change as non-idempotent (stricter
                // than C, harmless: extra forward, `seen` dedups).
                a == &edge.addr && p == &edge.port
            });
            if e.weight == edge.weight && e.options == edge.options && same_addr {
                // C `:145-148`: `return true`. No forward, no graph().
                return Ok(false);
            }

            // C `:150-157`: `from == myself` + edge exists with
            // different params. Peer's view of OUR edge is wrong.
            if from_id == self.myself {
                log::warn!(target: "tincd::proto",
                           "Got ADD_EDGE from {conn_name} for ourself \
                            which does not match existing entry");
                // C `:153`: `send_add_edge(c, e)`. Send back what
                // WE think the edge is (the existing one, NOT the
                // wire body). Dark in single-peer tests.
                let nw = self.send_add_edge(from_conn, existing);
                return Ok(nw);
            }

            // C `:159-183`: in-place update. C `splay_unlink`/
            // `splay_insert_node` (`:179-182`) re-keys edge_weight_
            // tree; `update_edge` does the same for `weight_order`.
            //
            // Why not del+add: `edge_addrs` is keyed on `EdgeId`.
            // del+add happens to recycle the same slot (LIFO
            // freelist), so `eid == existing` and the re-insert
            // keys to the same slot — correct by accident, not by
            // contract. One unrelated alloc between del and add and
            // the keys are stale. `update_edge` makes the slot
            // stability explicit; `edge_addrs.insert(existing, ...)`
            // is a plain overwrite of the same key.
            log::warn!(target: "tincd::proto",
                       "Got ADD_EDGE from {conn_name} which does not \
                        match existing entry");
            self.graph
                .update_edge(existing, edge.weight, edge.options)
                .expect("lookup_edge just returned this EdgeId; no await, no free");
            // C `:173`: `e->address = address`. Same key, overwrite.
            let unspec = || AddrStr::new(AddrStr::UNSPEC).expect("literal");
            let (la, lp) = edge.local.clone().unwrap_or_else(|| (unspec(), unspec()));
            self.edge_addrs
                .insert(existing, (edge.addr.clone(), edge.port.clone(), la, lp));
        } else if from_id == self.myself {
            // C `:184-196`: peer says WE have an edge we don't.
            // Contradiction. C bumps `contradicting_add_edge`
            // counter (read by periodic_handler `net.c:268`),
            // sends DEL_EDGE correction.
            log::warn!(target: "tincd::proto",
                       "Got ADD_EDGE from {conn_name} for ourself \
                        which does not exist");
            // C `:186`: `contradicting_add_edge++`. Reader is
            // chunk 8's periodic_handler.
            self.contradicting_add_edge += 1;
            // C `:187-192`: build a transient `edge_t` (just
            // from/to names; no addr) for `send_del_edge`. We
            // pass names directly. The wire body's from/to are
            // what we deny.
            let nw = self.send_del_edge(from_conn, &edge.from, &edge.to);
            return Ok(nw);
        } else {
            // C `:197-205`: `edge_add`. The fresh-edge case.
            let eid = self
                .graph
                .add_edge(from_id, to_id, edge.weight, edge.options);
            // C `:199-204`: `e->address = address; e->local_address
            // = local_address`. The wire tokens, verbatim. `local`
            // is optional (pre-1.0.24 6-token form) — C leaves
            // `local_address` zeroed (`AF_UNSPEC`) which `sockaddr2
            // hostname` formats as `"unspec port unspec"` (`netutl.
            // c:159-160`).
            let unspec = || AddrStr::new(AddrStr::UNSPEC).expect("literal");
            let (la, lp) = edge.local.clone().unwrap_or_else(|| (unspec(), unspec()));
            self.edge_addrs
                .insert(eid, (edge.addr.clone(), edge.port.clone(), la, lp));
        }

        // C `:209-211`: `if(!tunnelserver) forward_request(c, req)`.
        let nw = if self.settings.tunnelserver {
            false
        } else {
            self.forward_request(from_conn, body)
        };

        // C `:215`: `graph()`.
        self.run_graph_and_log();

        Ok(nw)
    }

    /// `del_edge_h` mutation half (`protocol_edge.c:225-322`).
    ///
    /// C path traced:
    /// - `:230-241` parse — `parse_del_edge`
    /// - `:244` `seen_request`
    /// - `:250-251` `lookup_node` (NOT lookup_or_add)
    /// - `:263-273` `from`/`to` not found → warn + return true
    /// - `:277-283` `lookup_edge` not found → warn + return true
    /// - `:253-261` `tunnelserver` filter — STUBBED (deferred niche)
    /// - `:285-291` `from == myself` → retaliate ADD — STUBBED
    /// - `:295-297` `forward_request` — STUBBED
    /// - `:301` `edge_del`
    /// - `:305` `graph()`
    /// - `:309-320` cleanup unreachable's reverse edge — STUBBED
    ///   (the daemon doesn't add reverse edges from on_ack yet;
    ///   the C's `lookup_edge(to, myself)` would find nothing)
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
            .map_or("<gone>", |c| c.name.as_str())
            .to_owned();

        // C `protocol_edge.c:253-261`: tunnelserver indirect filter.
        // Same dual-endpoint shape as ADD_EDGE. BEFORE lookup (which
        // is just lookup here, not lookup_or_add — but consistency).
        // ORDER: seen_request (`:244`) first.
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

        // C `:250-273`: `lookup_node`. Missing is warn-and-drop
        // (return true), NOT a new_node. A DEL for a node we've
        // never heard of means our view is already consistent.
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

        // C `:277-283`: `lookup_edge`. Missing is warn-and-drop.
        let Some(eid) = self.graph.lookup_edge(from_id, to_id) else {
            log::warn!(target: "tincd::proto",
                       "Got DEL_EDGE from {conn_name} which does not \
                        appear in the edge tree");
            return Ok(false);
        };

        // C `:285-291`: `from == myself`. Peer says we DON'T have
        // an edge we DO have. C sends ADD_EDGE correction.
        if from_id == self.myself {
            log::warn!(target: "tincd::proto",
                       "Got DEL_EDGE from {conn_name} for ourself");
            // C `:288`: `contradicting_del_edge++`.
            self.contradicting_del_edge += 1;
            // C `:289`: `send_add_edge(c, e)`. The edge DOES exist
            // (we just looked it up); send what we know.
            let nw = self.send_add_edge(from_conn, eid);
            return Ok(nw);
        }

        // C `:295-297`: `if(!tunnelserver) forward_request(c, req)`.
        let nw = if self.settings.tunnelserver {
            false
        } else {
            self.forward_request(from_conn, body)
        };

        // C `:301`: `edge_del`.
        self.graph.del_edge(eid);
        self.edge_addrs.remove(&eid);

        // C `:305`: `graph()`.
        self.run_graph_and_log();

        // C `:309-320`: reverse-edge cleanup. If `to` became
        // unreachable AND has an edge back to us, delete +
        // broadcast that too. The C `lookup_edge(to, myself)` is
        // the synthesized reverse from `ack_h`. We DO add both
        // halves in `on_ack`; check.
        if !self.graph.node(to_id).is_some_and(|n| n.reachable) {
            if let Some(rev) = self.graph.lookup_edge(to_id, self.myself) {
                // C `:313-315`: `if(!tunnelserver) send_del_edge(
                // everyone, e)`. The hub never broadcasts.
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
                // C `:318`: `edge_del(e)`.
                self.graph.del_edge(rev);
                self.edge_addrs.remove(&rev);
            }
        }

        Ok(nw)
    }
}
