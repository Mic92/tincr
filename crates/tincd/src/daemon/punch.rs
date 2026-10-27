//! Daemon glue for the sim-open punch (`REQ_KEY` lines, timers,
//! dials, RST recovery). Pure logic in `crate::punch`. See
//! `docs/PUNCH.md`.

use std::net::{IpAddr, SocketAddr};
use std::os::fd::OwnedFd;
use std::time::Duration;

use crate::addr;
use crate::conn::Connection;
use crate::daemon::{ConnId, Daemon, TimerWhat};
use crate::event::Io;
use crate::event::TimerHandle;
use crate::graph::NodeId;
use crate::listen::fmt_addr;
use crate::outgoing::{self, PunchSock};
use crate::punch::{self, AWAIT_CONNECT_TIMEOUT, AWAIT_SYNC_TIMEOUT, PunchAction, PunchState};
use rand_core::Rng;
use socket2::Domain;
use tinc_crypto::os_rng;
use tinc_proto::Request;
use tinc_proto::msg::ReqKeyExt;
use tinc_proto::request::{REQ_KEY_PUNCH, REQ_KEY_PUNCH_SYNC};
use tinc_sptps::Role;

/// Re-dial backoff after an inbound RST killed a punch dial.
const REDIAL_BACKOFF: Duration = Duration::from_millis(50);
const MAX_REDIALS: u8 = 3;

/// Cap on concurrent punch rounds. Each holds up to two bound sockets,
/// and the `from` of a relayed PUNCH is not authenticated.
const MAX_PUNCHES: usize = 8;

/// One inflight punch round.
pub(crate) struct PunchEntry {
    /// Round id; echoed by the peer in reply and SYNC.
    nonce: u64,
    state: PunchState,
    /// Bound before `PUNCH` so the port is known, consumed at dial.
    socks: Vec<PunchSock>,
    /// Expiry while waiting for the peer, the dial while `Delaying`.
    timer: TimerHandle,
}

/// A punch dial we may have to replay after an RST.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PunchDial {
    pub(crate) nid: NodeId,
    pub(crate) local: SocketAddr,
    pub(crate) target: SocketAddr,
    pub(crate) role: Role,
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
        let nonce = os_rng().next_u64();
        let (state, actions) = punch::start(self.timers.now(), my_addrs);
        log::info!(target: "tincd::punch", "Starting sim-open punch toward {name}");
        self.insert_punch(nid, nonce, state, socks);
        self.run_punch_actions(nid, name, nonce, actions)
    }

    /// Dispatch `REQ_KEY ... 64/65` (already routed to us). Returns
    /// the write-wake flag (same contract as other gossip handlers).
    pub(in crate::daemon) fn on_punch_msg(
        &mut self,
        from_nid: NodeId,
        from_name: &str,
        ext: &ReqKeyExt,
    ) -> bool {
        if !self.settings.autoconnect {
            return false;
        }
        if self.nodes.get(&from_nid).and_then(|ns| ns.conn).is_some() {
            self.clear_punch(from_nid);
            return false; // already directly connected
        }
        let now = self.timers.now();
        let (nonce, state, actions) = match ext.reqno {
            REQ_KEY_PUNCH => {
                let Some((nonce, peer_addrs)) =
                    ext.payload.as_deref().and_then(punch::parse_punch_payload)
                else {
                    return false; // unknown version / malformed
                };
                if peer_addrs.is_empty() {
                    return false;
                }
                let next = match self.punches.get(&from_nid) {
                    Some(e) if e.nonce == nonce => punch::on_punch_reply(&e.state, now, peer_addrs),
                    Some(e) if matches!(e.state, PunchState::AwaitConnect { .. }) => {
                        // Simultaneous start: both sides sent PUNCH.
                        // Lower name keeps the B role; the higher one
                        // folds and answers as A.
                        if self.name.as_str() < from_name {
                            return false;
                        }
                        self.clear_punch(from_nid);
                        return self.punch_as_responder(from_nid, from_name, nonce, peer_addrs);
                    }
                    Some(_) => return false, // stale round
                    None => {
                        return self.punch_as_responder(from_nid, from_name, nonce, peer_addrs);
                    }
                };
                let Some((state, actions)) = next else {
                    return false; // replay/race
                };
                (nonce, state, actions)
            }
            REQ_KEY_PUNCH_SYNC => {
                let Some(nonce) = ext.payload.as_deref().and_then(punch::parse_sync_payload) else {
                    return false;
                };
                let next = match self.punches.get(&from_nid) {
                    Some(e) if e.nonce == nonce => punch::on_sync(&e.state, now),
                    _ => return false, // lost state or stale round
                };
                let Some((state, actions)) = next else {
                    return false;
                };
                (nonce, state, actions)
            }
            _ => unreachable!("caller dispatches only on 64/65"),
        };
        if let Some(e) = self.punches.get_mut(&from_nid) {
            e.state = state;
        }
        self.run_punch_actions(from_nid, from_name, nonce, actions)
    }

    /// A side of a fresh round: bind sockets, reply with our addrs.
    fn punch_as_responder(
        &mut self,
        from_nid: NodeId,
        from_name: &str,
        nonce: u64,
        peer_addrs: Vec<SocketAddr>,
    ) -> bool {
        if self.punches.len() >= MAX_PUNCHES {
            log::debug!(target: "tincd::punch", "Too many punches, ignoring {from_name}");
            return false;
        }
        let Some((my_addrs, socks)) = self.punch_prepare() else {
            return false;
        };
        log::info!(target: "tincd::punch",
                   "PUNCH from {from_name}, replying with {} addrs",
                   my_addrs.len());
        let (state, actions) = punch::on_punch_fresh(self.timers.now(), peer_addrs, my_addrs);
        self.insert_punch(from_nid, nonce, state, socks);
        self.run_punch_actions(from_nid, from_name, nonce, actions)
    }

    fn insert_punch(&mut self, nid: NodeId, nonce: u64, state: PunchState, socks: Vec<PunchSock>) {
        let timer = self.timers.add(TimerWhat::Punch(nid));
        let entry = PunchEntry {
            nonce,
            state,
            socks,
            timer,
        };
        self.punches.insert(nid, entry);
    }

    /// `TimerWhat::Punch(nid)` fired: dial a `Delaying` round, expire
    /// any other.
    pub(super) fn on_punch_timer(&mut self, nid: NodeId) {
        let Some(e) = self.punches.remove(&nid) else {
            return;
        };
        let PunchState::Delaying { addrs, role, .. } = e.state else {
            log::debug!(target: "tincd::punch", "Punch round expired");
            self.clear_punch(nid);
            return;
        };
        if self.nodes.get(&nid).and_then(|ns| ns.conn).is_some() {
            return; // a normal connect landed during the delay
        }
        let name = self
            .graph
            .node(nid)
            .map(|n| n.name.clone())
            .unwrap_or_default();
        self.dial_punch(nid, &name, e.socks, &addrs, role);
    }

    /// Cancel a punch. Drops unconsumed sockets and pending redials.
    pub(super) fn clear_punch(&mut self, nid: NodeId) {
        self.punches.remove(&nid);
        self.punch_redials.remove(&nid);
        self.punch_dials.retain(|_, d| d.nid != nid);
    }

    /// Send what the state machine asked for, then arm the round's
    /// timer for its new state.
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
                PunchAction::DialAt { .. } => {}
            }
        }
        let now = self.timers.now();
        if let Some(e) = self.punches.get(&nid) {
            let after = match &e.state {
                PunchState::AwaitConnect { .. } => AWAIT_CONNECT_TIMEOUT,
                PunchState::AwaitSync { .. } => AWAIT_SYNC_TIMEOUT,
                PunchState::Delaying { fire_at, .. } => fire_at.saturating_duration_since(now),
            };
            if after.is_zero() {
                self.on_punch_timer(nid);
            } else {
                self.timers.set(&e.timer, after);
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

    /// Connect each pre-bound socket to a peer addr. Failures silent.
    fn dial_punch(
        &mut self,
        nid: NodeId,
        name: &str,
        socks: Vec<PunchSock>,
        peer_addrs: &[SocketAddr],
        role: Role,
    ) {
        for ps in socks {
            let Some(target) = punch_target(ps.local, peer_addrs) else {
                continue;
            };
            let dial = PunchDial {
                nid,
                local: ps.local,
                target,
                role,
                tries: 0,
            };
            self.dial_punch_sock(name, ps, dial);
        }
    }

    fn dial_punch_sock(&mut self, name: &str, ps: PunchSock, dial: PunchDial) {
        let Some(sock) = outgoing::punch_connect(ps, dial.target) else {
            return;
        };
        // Pre-set name so id_h's mismatch check fires.
        let fd = OwnedFd::from(sock);
        let addr = dial.target;
        let mut conn = Connection::new_meta(fd, fmt_addr(&addr), addr, self.timers.now());
        conn.connecting = true;
        conn.role = dial.role;
        name.clone_into(&mut conn.name);
        log::info!(target: "tincd::punch",
                   "Sim-open dialing {name}: {} → {addr}", dial.local);
        if let Some(id) = self.register_conn(conn, Io::ReadWrite) {
            self.punch_dials.insert(id, dial);
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
        let timers = &mut self.timers;
        let (_, pending) = self.punch_redials.entry(dial.nid).or_insert_with(|| {
            let tid = timers.add_after(TimerWhat::PunchRedial(dial.nid), REDIAL_BACKOFF);
            (tid, Vec::new())
        });
        pending.push(dial);
    }

    /// `TimerWhat::PunchRedial(nid)` fired: rebind and reconnect.
    pub(super) fn on_punch_redial_timer(&mut self, nid: NodeId) {
        let Some((_, dials)) = self.punch_redials.remove(&nid) else {
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
            self.dial_punch_sock(
                &name,
                ps,
                PunchDial {
                    tries: d.tries + 1,
                    ..d
                },
            );
        }
    }

    /// Conn is gone for any reason: drop its redial bookkeeping.
    pub(super) fn forget_punch_dial(&mut self, id: ConnId) {
        self.punch_dials.remove(&id);
    }
}

/// The first peer-supplied address of the socket's family that is fit to
/// dial. The list comes from the peer, so loopback and the like are out.
fn punch_target(local: SocketAddr, peer_addrs: &[SocketAddr]) -> Option<SocketAddr> {
    peer_addrs
        .iter()
        .copied()
        .find(|a| a.is_ipv4() == local.is_ipv4() && !addr::is_unwanted_dial_addr(a))
}

#[cfg(test)]
mod tests {
    use super::punch_target;
    use std::net::SocketAddr;

    #[test]
    fn punch_target_filters() {
        let sa = |s: &str| s.parse::<SocketAddr>().unwrap();
        let v4 = sa("0.0.0.0:1");
        let v6 = sa("[::]:1");
        let peer = [
            sa("127.0.0.1:655"),
            sa("[2001:db8::1]:655"),
            sa("192.0.2.1:655"),
        ];
        assert_eq!(punch_target(v4, &peer), Some(sa("192.0.2.1:655")));
        assert_eq!(punch_target(v6, &peer), Some(sa("[2001:db8::1]:655")));
        assert_eq!(punch_target(v4, &peer[..2]), None);
    }
}
