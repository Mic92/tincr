//! Daemon glue for the sim-open punch. Pure logic lives in
//! `crate::punch`. This module owns I/O: the `REQ_KEY` lines, timer
//! wiring, parallel dials, conn registration. See `docs/PUNCH.md`.

use std::net::{IpAddr, SocketAddr};
use std::os::fd::OwnedFd;
use std::time::Duration;

use crate::conn::Connection;
use crate::daemon::{Daemon, TimerWhat};
use crate::event::Io;
use crate::graph::NodeId;
use crate::listen::fmt_addr;
use crate::outgoing::{self, PunchSock};
use crate::punch::{self, PunchAction, PunchState};
use socket2::Domain;
use tinc_proto::Request;
use tinc_proto::msg::ReqKeyExt;
use tinc_proto::request::{REQ_KEY_PUNCH, REQ_KEY_PUNCH_SYNC};

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
        let (state, actions) = punch::start(now, my_addrs);
        log::info!(target: "tincd::punch", "Starting sim-open punch toward {name}");
        self.punches.insert(nid, state);
        self.run_punch_actions(nid, name, actions);
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
        let actions: Vec<PunchAction> = match ext.reqno {
            REQ_KEY_PUNCH => {
                let peer_addrs = ext
                    .payload
                    .as_deref()
                    .map(punch::parse_addrlist)
                    .unwrap_or_default();
                if peer_addrs.is_empty() {
                    return false;
                }
                let (next, acts) = match self.punches.get(&from_nid) {
                    None => {
                        // We're A. Bind sockets, advertise ports, await SYNC.
                        let Some((my_addrs, socks)) = self.punch_prepare() else {
                            return false;
                        };
                        self.punch_socks.insert(from_nid, socks);
                        log::info!(target: "tincd::punch",
                                   "PUNCH from {from_name}, replying with {} addrs",
                                   my_addrs.len());
                        let (st, acts) = punch::on_punch_fresh(now, peer_addrs, my_addrs);
                        (Some(st), acts)
                    }
                    Some(st) => punch::on_punch_reply(st, now, peer_addrs),
                };
                if let Some(s) = next {
                    self.punches.insert(from_nid, s);
                }
                acts
            }
            REQ_KEY_PUNCH_SYNC => {
                let Some(st) = self.punches.get(&from_nid) else {
                    return false; // lost state (timeout/restart)
                };
                let srtt = self.punch_srtt_to(from_nid);
                let (next, acts) = punch::on_sync(st, now, srtt);
                if let Some(s) = next {
                    self.punches.insert(from_nid, s);
                }
                acts
            }
            _ => unreachable!("caller dispatches only on 64/65"),
        };
        self.run_punch_actions(from_nid, from_name, actions)
    }

    /// `TimerWhat::Punch(nid)` fired: pop state, dial.
    pub(super) fn on_punch_timer(&mut self, nid: NodeId) {
        self.punch_timers.remove(&nid);
        let Some(PunchState::Delaying { addrs, .. }) = self.punches.remove(&nid) else {
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
            .iter()
            .filter(|(_, st)| punch::is_expired(st, now))
            .map(|(&nid, _)| nid)
            .collect();
        for nid in expired {
            self.clear_punch(nid);
        }
    }

    /// Cancel a punch. Drops unconsumed sockets.
    pub(super) fn clear_punch(&mut self, nid: NodeId) {
        self.punches.remove(&nid);
        self.punch_socks.remove(&nid);
        if let Some(tid) = self.punch_timers.remove(&nid) {
            self.timers.del(tid);
        }
    }

    fn run_punch_actions(&mut self, nid: NodeId, name: &str, actions: Vec<PunchAction>) -> bool {
        let mut nw = false;
        for act in actions {
            match act {
                PunchAction::SendPunch { addrs } => {
                    let list = punch::format_addrlist(&addrs);
                    nw |= self.send_punch_line(nid, name, REQ_KEY_PUNCH, Some(&list));
                }
                PunchAction::SendSync => {
                    nw |= self.send_punch_line(nid, name, REQ_KEY_PUNCH_SYNC, None);
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
                PunchAction::Drop => {}
            }
        }
        nw
    }

    fn send_punch_line(
        &mut self,
        to_nid: NodeId,
        to_name: &str,
        reqno: i32,
        payload: Option<&str>,
    ) -> bool {
        let Some(conn) = self
            .conn_for_nexthop(to_nid)
            .and_then(|cid| self.conns.get_mut(cid))
        else {
            return false;
        };
        match payload {
            Some(p) => conn.send(format_args!(
                "{} {} {to_name} {reqno} {p}",
                Request::ReqKey,
                self.name,
            )),
            None => conn.send(format_args!(
                "{} {} {to_name} {reqno}",
                Request::ReqKey,
                self.name,
            )),
        }
    }

    /// Bind one ephemeral punch socket per address family with a
    /// usable interface address; pair each address with its socket's
    /// bound port. NAT'd peers' advertised local port won't match
    /// the external one — known v1 limitation, fine for the
    /// stateful-firewall-no-NAT case.
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

    /// A's RTT estimate: meta-conn SRTT toward `nid`'s nexthop.
    fn punch_srtt_to(&self, nid: NodeId) -> Duration {
        self.conn_for_nexthop(nid)
            .and_then(|cid| self.conns.get(cid))
            .map(|c| c.srtt_ms)
            .filter(|&ms| ms > 0)
            .map_or(Duration::from_millis(200), |ms| {
                Duration::from_millis(u64::from(ms))
            })
    }

    /// Connect each pre-bound socket to the first matching-family
    /// peer addr. One connect per socket. Failures silent.
    fn dial_punch(&mut self, nid: NodeId, name: &str, peer_addrs: &[SocketAddr]) {
        let now = self.timers.now();
        for ps in self.punch_socks.remove(&nid).unwrap_or_default() {
            let local = ps.local;
            let want_v4 = matches!(local, SocketAddr::V4(_));
            let Some(&target) = peer_addrs
                .iter()
                .find(|a| matches!(a, SocketAddr::V4(_)) == want_v4)
            else {
                continue;
            };
            let Some(sock) = outgoing::punch_connect(ps, target) else {
                continue;
            };
            // Same path as a normal outgoing dial: connecting=true
            // routes EPOLLOUT → on_connecting → finish_connecting →
            // ID exchange. Pre-set name so id_h's mismatch check fires.
            let fd = OwnedFd::from(sock);
            let mut conn = Connection::new_meta(fd, fmt_addr(&target), target, now);
            conn.connecting = true;
            name.clone_into(&mut conn.name);
            log::info!(target: "tincd::punch",
                       "Sim-open dialing {name}: {local} → {target}");
            self.register_conn(conn, Io::ReadWrite);
        }
    }
}
