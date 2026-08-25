//! Daemon glue for the sim-open punch (`REQ_KEY` lines, timers,
//! dials, RST recovery). Pure logic in `crate::punch`. See
//! `docs/PUNCH.md`.

use std::net::{IpAddr, SocketAddr};
use std::os::fd::OwnedFd;
use std::time::Duration;

use crate::conn::Connection;
use crate::daemon::{ConnId, Daemon, TimerWhat};
use crate::event::Io;
use crate::graph::NodeId;
use crate::listen::fmt_addr;
use crate::outgoing::{self, PunchSock};
use crate::punch::{self, PunchAction, PunchState};
use rand_core::Rng;
use socket2::Domain;
use std::time::Instant;
use tinc_crypto::os_rng;
use tinc_proto::Request;
use tinc_proto::msg::ReqKeyExt;
use tinc_proto::request::{REQ_KEY_PUNCH, REQ_KEY_PUNCH_SYNC};

/// Re-dial backoff after an inbound RST killed a punch dial.
const REDIAL_BACKOFF: Duration = Duration::from_millis(50);
const MAX_REDIALS: u8 = 3;

/// One inflight punch round.
#[derive(Debug)]
pub(crate) struct PunchEntry {
    /// Round id; echoed by the peer in reply and SYNC.
    pub(crate) nonce: u64,
    pub(crate) state: PunchState,
}

/// A punch dial we may have to replay after an RST.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PunchDial {
    pub(crate) nid: NodeId,
    pub(crate) local: SocketAddr,
    pub(crate) target: SocketAddr,
    pub(crate) tries: u8,
}

impl Daemon {
    /// B entry point. Called from `retry_outgoing` on `AutoShortcut`
    /// addr-cache exhaustion. One attempt per backoff cycle.
    pub(super) fn maybe_start_punch(&mut self, name: &str) -> bool {
        if self.settings.proxy.is_some() {
            return false; // proxy owns the socket; we can't bind/connect raw.
        }
        let Some(&nid) = self.node_ids.get(name) else {
            return false;
        };
        if self.punches.contains_key(&nid)
            || !self.graph.node(nid).is_some_and(|n| n.reachable)
            || self.nodes.get(&nid).and_then(|ns| ns.conn).is_some()
        {
            return false;
        }
        let Some((my_addrs, socks)) = self.punch_prepare() else {
            return false;
        };
        self.punch_socks.insert(nid, socks);
        let now = self.timers.now();
        let nonce = os_rng().next_u64();
        let (state, actions) = punch::start(now, my_addrs);
        log::info!(target: "tincd::punch", "Starting sim-open punch toward {name}");
        self.punches.insert(nid, PunchEntry { nonce, state });
        self.run_punch_actions(nid, name, nonce, actions);
        true
    }

    /// Dispatch `REQ_KEY ... 64/65` (already routed to us). Returns
    /// the write-wake flag (same contract as other gossip handlers).
    pub(in crate::daemon) fn on_punch_msg(
        &mut self,
        from_nid: NodeId,
        from_name: &str,
        ext: &ReqKeyExt,
    ) -> bool {
        if self.nodes.get(&from_nid).and_then(|ns| ns.conn).is_some() {
            self.clear_punch(from_nid);
            return false; // already directly connected
        }
        let now = self.timers.now();
        let (nonce, transition) = match ext.reqno {
            REQ_KEY_PUNCH => {
                let Some((nonce, peer_addrs)) =
                    ext.payload.as_deref().and_then(punch::parse_punch_payload)
                else {
                    return false; // unknown version / malformed
                };
                if peer_addrs.is_empty() {
                    return false;
                }
                match self.punches.get(&from_nid) {
                    Some(e) if e.nonce == nonce => {
                        (nonce, punch::on_punch_reply(&e.state, now, peer_addrs))
                    }
                    Some(e) if matches!(e.state, PunchState::AwaitConnect { .. }) => {
                        // Simultaneous start: both sides sent PUNCH.
                        // Lower name keeps the B role; the higher one
                        // folds and answers as A.
                        if self.name.as_str() < from_name {
                            return false;
                        }
                        self.clear_punch(from_nid);
                        (
                            nonce,
                            self.punch_as_responder(from_nid, from_name, now, peer_addrs),
                        )
                    }
                    Some(_) => return false, // stale round
                    None => (
                        nonce,
                        self.punch_as_responder(from_nid, from_name, now, peer_addrs),
                    ),
                }
            }
            REQ_KEY_PUNCH_SYNC => {
                let Some(nonce) = ext.payload.as_deref().and_then(punch::parse_sync_payload) else {
                    return false;
                };
                match self.punches.get(&from_nid) {
                    Some(e) if e.nonce == nonce => (nonce, punch::on_sync(&e.state, now)),
                    _ => return false, // lost state or stale round
                }
            }
            _ => unreachable!("caller dispatches only on 64/65"),
        };
        let Some((state, actions)) = transition else {
            return false; // replay/race
        };
        self.punches.insert(from_nid, PunchEntry { nonce, state });
        self.run_punch_actions(from_nid, from_name, nonce, actions)
    }

    /// A side of a fresh round: bind sockets, reply with our addrs.
    fn punch_as_responder(
        &mut self,
        from_nid: NodeId,
        from_name: &str,
        now: Instant,
        peer_addrs: Vec<SocketAddr>,
    ) -> Option<(PunchState, Vec<PunchAction>)> {
        let (my_addrs, socks) = self.punch_prepare()?;
        self.punch_socks.insert(from_nid, socks);
        log::info!(target: "tincd::punch",
                   "PUNCH from {from_name}, replying with {} addrs",
                   my_addrs.len());
        Some(punch::on_punch_fresh(now, peer_addrs, my_addrs))
    }

    /// `TimerWhat::Punch(nid)` fired: pop state, dial.
    pub(super) fn on_punch_timer(&mut self, nid: NodeId) {
        self.punch_timers.remove(&nid);
        let Some(PunchEntry {
            state: PunchState::Delaying { addrs, .. },
            ..
        }) = self.punches.remove(&nid)
        else {
            return; // cleared elsewhere
        };
        if self.nodes.get(&nid).and_then(|ns| ns.conn).is_some() {
            return; // a normal connect landed during the delay
        }
        let name = self
            .graph
            .node(nid)
            .map(|n| n.name.clone())
            .unwrap_or_default();
        self.dial_punch(nid, &name, &addrs);
    }

    /// Periodic sweep: drop expired states.
    pub(super) fn sweep_punches(&mut self) {
        let now = self.timers.now();
        let expired: Vec<NodeId> = self
            .punches
            .extract_if(|_, e| punch::is_expired(&e.state, now))
            .map(|(nid, _)| nid)
            .collect();
        for nid in expired {
            self.clear_punch(nid);
        }
    }

    /// Cancel a punch. Drops unconsumed sockets and pending redials.
    pub(super) fn clear_punch(&mut self, nid: NodeId) {
        self.punches.remove(&nid);
        self.punch_socks.remove(&nid);
        self.punch_redials.remove(&nid);
        if let Some(tid) = self.punch_timers.remove(&nid) {
            self.timers.del(tid);
        }
        self.punch_dials.retain(|_, d| d.nid != nid);
    }

    fn run_punch_actions(
        &mut self,
        nid: NodeId,
        name: &str,
        nonce: u64,
        actions: Vec<PunchAction>,
    ) -> bool {
        let mut nw = false;
        for act in actions {
            match act {
                PunchAction::SendPunch { addrs } => {
                    let payload = punch::format_punch_payload(nonce, &addrs);
                    nw |= self.send_punch_line(nid, name, REQ_KEY_PUNCH, &payload);
                }
                PunchAction::SendSync => {
                    let payload = punch::format_sync_payload(nonce);
                    nw |= self.send_punch_line(nid, name, REQ_KEY_PUNCH_SYNC, &payload);
                }
                PunchAction::DialAt { at, addrs } => {
                    let now = self.timers.now();
                    let delay = at.saturating_duration_since(now);
                    if delay.is_zero() {
                        self.punches.remove(&nid);
                        self.dial_punch(nid, name, &addrs);
                    } else {
                        let tid = self.timers.add(TimerWhat::Punch(nid));
                        self.timers.set(tid, delay);
                        self.punch_timers.insert(nid, tid);
                    }
                }
            }
        }
        nw
    }

    fn send_punch_line(
        &mut self,
        to_nid: NodeId,
        to_name: &str,
        reqno: i32,
        payload: &str,
    ) -> bool {
        let Some(conn) = self
            .conn_for_nexthop(to_nid)
            .and_then(|cid| self.conns.get_mut(cid))
        else {
            return false;
        };
        conn.send(format_args!(
            "{} {} {to_name} {reqno} {payload}",
            Request::ReqKey,
            self.name,
        ))
    }

    /// Bind one ephemeral punch socket per address family with a
    /// usable interface address. Behind NAT the advertised local
    /// port won't match the external one — known v1 limitation.
    fn punch_prepare(&self) -> Option<(Vec<SocketAddr>, Vec<PunchSock>)> {
        let mut v4_ips: Vec<IpAddr> = Vec::new();
        let mut v6_ips: Vec<IpAddr> = Vec::new();
        for iface in nix::ifaddrs::getifaddrs().ok()? {
            let Some(sa) = iface.address else { continue };
            if let Some(v4) = sa.as_sockaddr_in() {
                let ip = v4.ip();
                if !ip.is_loopback() && !ip.is_link_local() && !ip.is_unspecified() {
                    v4_ips.push(IpAddr::V4(ip));
                }
            } else if let Some(v6) = sa.as_sockaddr_in6() {
                let ip = v6.ip();
                if (ip.segments()[0] & 0xe000) == 0x2000 {
                    v6_ips.push(IpAddr::V6(ip));
                }
            }
        }
        let mut addrs = Vec::new();
        let mut socks = Vec::new();
        for (ips, dom) in [(v4_ips, Domain::IPV4), (v6_ips, Domain::IPV6)] {
            if ips.is_empty() {
                continue;
            }
            let Some(ps) = outgoing::punch_bind(dom, &self.settings.sockopts) else {
                continue;
            };
            let port = ps.local.port();
            addrs.extend(ips.into_iter().map(|ip| SocketAddr::new(ip, port)));
            socks.push(ps);
        }
        (!addrs.is_empty()).then_some((addrs, socks))
    }

    /// Connect each pre-bound socket to the first matching-family
    /// peer addr. One connect per socket. Failures silent.
    fn dial_punch(&mut self, nid: NodeId, name: &str, peer_addrs: &[SocketAddr]) {
        for ps in self.punch_socks.remove(&nid).unwrap_or_default() {
            let want_v4 = matches!(ps.local, SocketAddr::V4(_));
            let Some(&target) = peer_addrs
                .iter()
                .find(|a| matches!(a, SocketAddr::V4(_)) == want_v4)
            else {
                continue;
            };
            self.dial_punch_sock(nid, name, ps, target, 0);
        }
    }

    fn dial_punch_sock(
        &mut self,
        nid: NodeId,
        name: &str,
        ps: PunchSock,
        target: SocketAddr,
        tries: u8,
    ) {
        let local = ps.local;
        let Some(sock) = outgoing::punch_connect(ps, target) else {
            return;
        };
        // Same path as a normal outgoing dial. Pre-set name so
        // id_h's mismatch check fires.
        let fd = OwnedFd::from(sock);
        let mut conn = Connection::new_meta(fd, fmt_addr(&target), target, self.timers.now());
        conn.connecting = true;
        name.clone_into(&mut conn.name);
        log::info!(target: "tincd::punch",
                   "Sim-open dialing {name}: {local} → {target}");
        if let Some(id) = self.register_conn(conn, Io::ReadWrite) {
            self.punch_dials.insert(
                id,
                PunchDial {
                    nid,
                    local,
                    target,
                    tries,
                },
            );
        }
    }

    /// Connect failed. The pinhole from our first SYN survives the
    /// RST, so re-dial from the same port after a short backoff.
    pub(super) fn on_punch_dial_failed(&mut self, id: ConnId) {
        let Some(dial) = self.punch_dials.remove(&id) else {
            return;
        };
        if dial.tries >= MAX_REDIALS {
            return;
        }
        let pending = self.punch_redials.entry(dial.nid).or_default();
        pending.push(dial);
        if pending.len() == 1 {
            let tid = self.timers.add(TimerWhat::PunchRedial(dial.nid));
            self.timers.set(tid, REDIAL_BACKOFF);
        }
    }

    /// `TimerWhat::PunchRedial(nid)` fired: rebind and reconnect.
    pub(super) fn on_punch_redial_timer(&mut self, nid: NodeId) {
        let Some(dials) = self.punch_redials.remove(&nid) else {
            return;
        };
        if self.nodes.get(&nid).and_then(|ns| ns.conn).is_some() {
            return; // another lane made it
        }
        let name = self
            .graph
            .node(nid)
            .map(|n| n.name.clone())
            .unwrap_or_default();
        for d in dials {
            let Some(ps) = outgoing::punch_rebind(d.local, &self.settings.sockopts) else {
                continue;
            };
            self.dial_punch_sock(nid, &name, ps, d.target, d.tries + 1);
        }
    }

    /// Conn is gone for any reason: drop its redial bookkeeping.
    pub(super) fn forget_punch_dial(&mut self, id: ConnId) {
        self.punch_dials.remove(&id);
    }
}
