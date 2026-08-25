//! `UDP_INFO`/`MTU_INFO` send and receive. Gate logic is pure and lives
//! in `crate::udp_info`; this gathers daemon state for it and queues
//! the wire messages on the nexthop meta connection.

#![forbid(unsafe_code)]

use super::{ConnId, Daemon};

use std::time::Duration;

use crate::dispatch;
use crate::dispatch::{ConnOptions, DispatchError};
use crate::graph::NodeId;
use crate::tunnel::{MTU, TunnelState};
use crate::udp_info::{self, FromMtuState, FromState, MtuInfoAction, PmtuSnapshot, UdpInfoAction};
use std::fmt;
use std::mem;
use std::sync::atomic;
use tinc_proto::AddrStr;
use tinc_proto::msg::{MtuInfo, UdpInfo};

impl Daemon {
    /// The double indirection (route of `nid`
    /// → route of its nexthop → options) appears at every
    /// `UDP_INFO`/`MTU_INFO` gate; centralised so the empty-on-miss
    /// fallback stays consistent.
    fn nexthop_options(&self, nid: NodeId) -> ConnOptions {
        self.route_of(nid)
            .and_then(|r| self.route_of(r.nexthop))
            .map_or(ConnOptions::empty(), |nr| {
                ConnOptions::from_bits_retain(nr.options)
            })
    }

    /// Resolve `nid`'s nexthop conn and queue `msg` on it. Shared
    /// tail of the `UDP_INFO`/`MTU_INFO` senders; returns the
    /// `conn.send` needs-write flag, or `false` when no conn.
    fn send_via_nexthop(&mut self, nid: NodeId, msg: impl fmt::Display) -> bool {
        let Some(conn_id) = self.conn_for_nexthop(nid) else {
            return false;
        };
        let Some(conn) = self.conns.get_mut(conn_id) else {
            return false;
        };
        conn.send(format_args!("{msg}"))
    }

    /// For `adjust_mtu_for_send`.
    pub(super) fn pmtu_snapshot(&self, nid: NodeId) -> Option<PmtuSnapshot> {
        self.dp
            .tunnels
            .get(&nid)?
            .pmtu
            .as_ref()
            .map(|p| PmtuSnapshot {
                minmtu: p.minmtu,
                maxmtu: p.maxmtu,
            })
    }

    /// Gates in `udp_info::should_send_udp_info`; this gathers state,
    /// builds wire, queues on nexthop conn. `from_is_myself` is true
    /// at all daemon call sites; forwarding goes via
    /// `send_udp_info_forward`.
    pub(super) fn send_udp_info(
        &mut self,
        to_nid: NodeId,
        to_name: &str,
        from_is_myself: bool,
    ) -> bool {
        // Static-relay deref. UDP_INFO terminates at the relay (last
        // node seeing from's UDP directly). Original to's options
        // feed to_options; dereffed to's route feeds the rest.
        let Some(orig_route) = self.route_of(to_nid) else {
            // Our callers are opportunistic hints, just skip.
            return false;
        };
        let to_options_orig = ConnOptions::from_bits_retain(orig_route.options);
        let dereffed = if orig_route.via == self.myself {
            orig_route.nexthop
        } else {
            orig_route.via
        };

        // Gates apply to the dereffed `to`.
        let to_is_myself = dereffed == self.myself;
        let to_reachable = self.graph.node(dereffed).is_some_and(|n| n.reachable);
        let to_directly_connected = self.nodes.get(&dereffed).and_then(|ns| ns.conn).is_some();
        let nexthop_options = self.nexthop_options(dereffed);

        let from_options = if from_is_myself {
            self.myself_options
        } else {
            self.route_of(to_nid).map_or(ConnOptions::empty(), |r| {
                ConnOptions::from_bits_retain(r.options)
            })
        };

        let now = self.timers.now();
        let last_sent = self.dp.tunnels.get(&dereffed).and_then(|t| t.udp_info_sent);
        let interval = Duration::from_secs(u64::from(self.settings.udp_info_interval));

        if !udp_info::should_send_udp_info(
            to_is_myself,
            to_reachable,
            to_directly_connected,
            from_is_myself,
            from_options,
            to_options_orig,
            self.myself_options,
            nexthop_options,
            last_sent,
            now,
            interval,
        ) {
            return false;
        }

        // When from==myself, the first hop ignores whatever address
        // we send (replaces with what they observe). Send unspec.
        // The from!=myself case goes via send_udp_info_forward.
        let (addr, port) = (AddrStr::unspec(), AddrStr::unspec());

        let from_name: &str = if from_is_myself { &self.name } else { to_name };
        let msg = UdpInfo {
            from: from_name.to_owned(),
            to: self
                .graph
                .node(dereffed)
                .map_or_else(|| to_name.to_owned(), |n| n.name.clone()),
            addr,
            port,
        };
        // Not `send_via_nexthop`: the debounce stamp below must not
        // fire when no conn exists, so we need the explicit
        // early-returns here.
        let Some(conn_id) = self.conn_for_nexthop(dereffed) else {
            return false;
        };
        let Some(conn) = self.conns.get_mut(conn_id) else {
            return false;
        };
        let nw = conn.send(format_args!("{}", msg.format()));

        if from_is_myself {
            self.dp.tunnels.entry(dereffed).or_default().udp_info_sent = Some(now);
        }
        nw
    }

    /// `send_udp_info(from, to)` forward path. Called from
    /// `on_udp_info` after the action decision. Unlike the originate
    /// path, this carries `from`'s observed address (which may have
    /// just been updated by `UpdateAndForward`).
    pub(super) fn send_udp_info_forward(&mut self, from_nid: NodeId, to_nid: NodeId) -> bool {
        let Some(from_name) = self.graph.node(from_nid).map(|n| n.name.clone()) else {
            return false;
        };
        let Some(to_name) = self.graph.node(to_nid).map(|n| n.name.clone()) else {
            return false;
        };

        // Same static-relay deref as the originate path.
        let Some(orig_route) = self.route_of(to_nid) else {
            return false;
        };
        let to_options_orig = ConnOptions::from_bits_retain(orig_route.options);
        let dereffed = if orig_route.via == self.myself {
            orig_route.nexthop
        } else {
            orig_route.via
        };

        let to_is_myself = dereffed == self.myself;
        let to_reachable = self.graph.node(dereffed).is_some_and(|n| n.reachable);
        // to->connection check only fires when from==myself.
        let from_options = self.route_of(from_nid).map_or(ConnOptions::empty(), |r| {
            ConnOptions::from_bits_retain(r.options)
        });
        let nexthop_options = self.nexthop_options(dereffed);

        if !udp_info::should_send_udp_info(
            to_is_myself,
            to_reachable,
            false, // to_directly_connected — only checked when from==myself
            false, // from_is_myself
            from_options,
            to_options_orig,
            self.myself_options,
            nexthop_options,
            None, // last_sent — only checked when from==myself
            self.timers.now(),
            Duration::ZERO,
        ) {
            return false;
        }

        // Our observation of from's UDP address (or unspec).
        let (addr, port) = self
            .dp
            .tunnels
            .get(&from_nid)
            .and_then(|t| t.udp_addr)
            .map_or_else(
                || (AddrStr::unspec(), AddrStr::unspec()),
                |a| {
                    (
                        AddrStr::new(a.ip().to_string()).expect("ip is valid token"),
                        AddrStr::new(a.port().to_string()).expect("port is valid token"),
                    )
                },
            );

        let msg = UdpInfo {
            from: from_name,
            to: to_name,
            addr,
            port,
        };
        self.send_via_nexthop(dereffed, msg.format())
    }

    /// No static-relay deref unlike `UDP_INFO`.
    pub(super) fn send_mtu_info(
        &mut self,
        to_nid: NodeId,
        to_name: &str,
        mtu: i32,
        from_is_myself: bool,
    ) -> bool {
        self.send_mtu_info_from(self.myself, to_nid, to_name, mtu, from_is_myself)
    }

    /// `send_mtu_info` with explicit `from`. `from_is_myself` separate
    /// from `from_nid`: gate logic keys on it independently (debounce).
    pub(super) fn send_mtu_info_from(
        &mut self,
        from_nid: NodeId,
        to_nid: NodeId,
        to_name: &str,
        mtu: i32,
        from_is_myself: bool,
    ) -> bool {
        let to_is_myself = to_nid == self.myself;
        let to_reachable = self.graph.node(to_nid).is_some_and(|n| n.reachable);
        let to_directly_connected = self.nodes.get(&to_nid).and_then(|ns| ns.conn).is_some();
        let nexthop_options = self.nexthop_options(to_nid);

        let now = self.timers.now();
        let last_sent = self.dp.tunnels.get(&to_nid).and_then(|t| t.mtu_info_sent);
        let interval = Duration::from_secs(u64::from(self.settings.mtu_info_interval));

        if !udp_info::should_send_mtu_info(
            to_is_myself,
            to_reachable,
            to_directly_connected,
            from_is_myself,
            last_sent,
            now,
            interval,
            nexthop_options,
        ) {
            return false;
        }

        // Adjust MTU based on our knowledge of the path to `from`.
        let from_route = self.route_of(from_nid);
        let from_via_is_myself = from_route.is_some_and(|r| r.via == self.myself);
        let via_nid = from_route.map(|r| {
            if r.via == self.myself {
                r.nexthop
            } else {
                r.via
            }
        });
        let via_nexthop_nid = via_nid.and_then(|v| self.route_of(v).map(|r| r.nexthop));

        let mtu = udp_info::adjust_mtu_for_send(
            mtu,
            from_via_is_myself,
            self.pmtu_snapshot(from_nid),
            via_nid.and_then(|v| self.pmtu_snapshot(v)),
            via_nexthop_nid.and_then(|v| self.pmtu_snapshot(v)),
        );

        if from_is_myself {
            self.dp.tunnels.entry(to_nid).or_default().mtu_info_sent = Some(now);
        }

        // Not `send_via_nexthop`: the `mem::take(udp_rx_maxlen)`
        // below must not fire when no conn exists (the high-water
        // mark would be lost without ever being sent), so we need
        // the explicit early-returns first.
        let Some(conn_id) = self.conn_for_nexthop(to_nid) else {
            return false;
        };
        let Some(conn) = self.conns.get_mut(conn_id) else {
            return false;
        };
        let from_name = self
            .graph
            .node(from_nid)
            .map_or_else(|| self.name.clone(), |n| n.name.clone());
        // Piggy-back the udp-rx ack on outgoing MTU_INFOs we
        // originate (forwarded ones carry the originator's view, not
        // ours). The dedicated `send_udp_rx_ack` covers the direct-
        // peer case this gate excludes; this catches the relayed-
        // peer case for free.
        let udp_rx_len = if from_is_myself {
            self.dp
                .tunnels
                .get_mut(&to_nid)
                .map_or(0, |t| mem::take(&mut t.udp_rx_maxlen))
        } else {
            0
        };
        let msg = MtuInfo {
            from: from_name,
            to: to_name.to_owned(),
            mtu,
            udp_rx_len,
        };
        conn.send(format_args!("{}", msg.format()))
    }

    /// Err only on parse failure (→ teardown); semantic drops are
    /// Ok(false).
    pub(super) fn on_udp_info(
        &mut self,
        from_conn: ConnId,
        body: &[u8],
    ) -> Result<bool, DispatchError> {
        let (_, parsed) = dispatch::parse_key_msg(body, "UDP_INFO", UdpInfo::parse)?;

        let conn_name = self.conn(from_conn).name.clone();

        let from = self.node_ids.get(&parsed.from).copied().map(|nid| {
            let directly_connected = self.nodes.get(&nid).and_then(|ns| ns.conn).is_some();
            let udp_confirmed = self
                .dp
                .tunnels
                .get(&nid)
                .is_some_and(|t| t.status.udp_confirmed);
            // `from->via == from`: false means "wandered past static relay".
            let via_is_self = self.route_of(nid).is_some_and(|r| r.via == nid);
            (
                nid,
                FromState {
                    directly_connected,
                    udp_confirmed,
                    via_is_self,
                },
            )
        });
        let to = self.node_ids.get(&parsed.to).copied();
        let current_from_addr =
            from.and_then(|(nid, _)| self.dp.tunnels.get(&nid).and_then(|t| t.udp_addr));

        match udp_info::on_receive_udp_info(&parsed, from, to, current_from_addr) {
            UdpInfoAction::UnknownNode => {
                log::error!(target: "tincd::proto",
                            "Got UDP_INFO from {conn_name} for unknown node \
                             {} → {}", parsed.from, parsed.to);
                Ok(false)
            }
            UdpInfoAction::DroppedPastRelay => {
                log::warn!(target: "tincd::proto",
                           "Got UDP_INFO from {conn_name} for {} which we \
                            can't reach directly", parsed.from);
                Ok(false)
            }
            UdpInfoAction::UpdateAndForward { from, to, new_addr } => {
                log::debug!(target: "tincd::proto",
                            "UDP_INFO from {conn_name}: learned {} at {new_addr}",
                            parsed.from);
                let t = self.dp.tunnels.entry(from).or_default();
                t.udp_addr = Some(new_addr);
                t.udp_addr_cached = None; // stale
                Ok(self.send_udp_info_forward(from, to))
            }
            UdpInfoAction::Forward { from, to } => Ok(self.send_udp_info_forward(from, to)),
        }
    }

    /// Malformed (mtu<512) is Err → teardown; everything else Ok.
    pub(super) fn on_mtu_info(
        &mut self,
        from_conn: ConnId,
        body: &[u8],
    ) -> Result<bool, DispatchError> {
        let (_, parsed) = dispatch::parse_key_msg(body, "MTU_INFO", MtuInfo::parse)?;

        let conn_name = self.conn(from_conn).name.clone();

        // udp_rx_len meta-ack (tincr extension): `from` says "I received your UDP probe of length N". If
        // we're `to` and our UDP-reply path to `from` is dead
        // (inbound filter on our side), this is the only way we
        // learn our outbound UDP works. Treat it like a probe reply
        // for the TX-direction: confirm + raise minmtu. Leave
        // `udp_addr` alone — we have no working RX addr; `choose_udp_
        // address` already prefers the edge-seeded one for sends.
        if parsed.udp_rx_len > 0
            && self.node_ids.get(&parsed.to).copied() == Some(self.myself)
            && let Some(&from_nid) = self.node_ids.get(&parsed.from)
        {
            // Same on-path guard as the clamp below: only the
            // conn that actually routes toward `from` may confirm.
            let on_path =
                parsed.from == conn_name || self.conn_for_nexthop(from_nid) == Some(from_conn);
            if on_path {
                self.apply_meta_udp_confirm(from_nid, &parsed.from, parsed.udp_rx_len);
            }
        }

        // Only honour the clamp if the reporting conn is on-path to `from`.
        let on_path = parsed.from == conn_name
            || self
                .node_ids
                .get(&parsed.from)
                .and_then(|&nid| self.conn_for_nexthop(nid))
                == Some(from_conn);

        let from = self.node_ids.get(&parsed.from).copied().map(|nid| {
            // Supply zero defaults for missing tunnel state.
            let t = self.dp.tunnels.get(&nid);
            (
                nid,
                FromMtuState {
                    mtu: t.map_or(0, TunnelState::mtu),
                    minmtu: t.map_or(0, TunnelState::minmtu),
                    maxmtu: t.map_or(MTU, TunnelState::maxmtu),
                },
            )
        });
        let to = self.node_ids.get(&parsed.to).copied();

        match udp_info::on_receive_mtu_info(&parsed, from, to) {
            MtuInfoAction::Malformed => {
                // Not conn-fatal (C tinc tears down): older tincr
                // peers still emit 0/18, and teardown turned one bad
                // hop into a mesh-wide outage (#21).
                log::warn!(target: "tincd::proto",
                           "Ignoring MTU_INFO from {conn_name} with invalid MTU {}",
                           parsed.mtu);
                Ok(false)
            }
            MtuInfoAction::UnknownNode => {
                log::error!(target: "tincd::proto",
                            "Got MTU_INFO from {conn_name} for unknown node \
                             {} → {}", parsed.from, parsed.to);
                Ok(false)
            }
            MtuInfoAction::ClampAndForward { from, to, new_mtu } => {
                // Direct peers only send MTU_INFO to us via
                // `send_udp_rx_ack` (the 4th-field ack); the `mtu`
                // field there is the sender's compile-time MTU — not
                // a relay measurement of our→from path — so don't
                // adopt it as a provisional.
                let from_direct = self.nodes.get(&from).and_then(|ns| ns.conn).is_some();
                if on_path && !from_direct {
                    // Provisional mtu (probing will overwrite). Only
                    // matters if pmtu seeded; unseeded reads MTU anyway.
                    log::debug!(target: "tincd::proto",
                                "Using provisional MTU {new_mtu} for {}", parsed.from);
                    if let Some(p) = self.dp.tunnels.get_mut(&from).and_then(|t| t.pmtu.as_mut()) {
                        p.mtu = new_mtu;
                    }
                } else {
                    log::debug!(target: "tincd::proto",
                                "Ignoring off-path MTU_INFO for {} via {conn_name}",
                                parsed.from);
                }
                Ok(self.send_mtu_info_from(from, to, &parsed.to, i32::from(new_mtu), false))
            }
            MtuInfoAction::Forward { from, to } => {
                // adjust_mtu_for_send may tighten further with our knowledge.
                let mtu = parsed.mtu.min(udp_info::MTU_MAX);
                Ok(self.send_mtu_info_from(from, to, &parsed.to, mtu, false))
            }
        }
    }

    /// Asymmetric TX-only UDP confirmation. `len` is what `peer`
    /// reported receiving from us over UDP; treat it as a probe-
    /// reply for the send direction only. State-machine bits
    /// (clamp, solicit-gate, confirm, minmtu raise) live in
    /// [`PmtuState::on_meta_ack`] so they're unit-testable without a
    /// full `Daemon`. Leaves `udp_addr` alone — we never saw a
    /// packet come back.
    fn apply_meta_udp_confirm(&mut self, peer: NodeId, peer_name: &str, len: u16) {
        let now = self.timers.now();
        let tunnel = self.dp.tunnels.entry(peer).or_default();
        // No `get_or_insert`: if we've never seeded PMTU we've never
        // sent a probe, so any ack is by definition unsolicited.
        let Some(p) = tunnel.pmtu.as_mut() else {
            log::debug!(target: "tincd::net",
                        "ignoring unsolicited udp_rx_len from {peer_name}");
            return;
        };
        let was_confirmed = p.udp_confirmed;
        if !p.on_meta_ack(len, now) {
            log::debug!(target: "tincd::net",
                        "ignoring unsolicited udp_rx_len from {peer_name}");
            return;
        }
        tunnel.status.udp_confirmed = true;
        if !was_confirmed {
            log::info!(target: "tincd::net",
                       "UDP send to {peer_name} confirmed via meta \
                        (rx-filtered, asymmetric mode)");
        }
        // Publish minmtu to the fast path (same as the real probe-
        // reply arm; seconds-apart, not hot).
        if let Some(h) = self.tunnel_handles.get(&peer) {
            let m = self.dp.tunnels.get(&peer).map_or(0, TunnelState::minmtu);
            h.minmtu.store(m, atomic::Ordering::Relaxed);
        }
    }
}
