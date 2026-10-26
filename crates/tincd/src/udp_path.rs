//! The UDP path to one peer. One owner, so the address, the
//! confirmation and the PMTU bounds always change together.

use std::mem;
use std::net::SocketAddr;
use std::time::Instant;

use socket2::SockAddr;

use crate::pmtu::{MTU, PmtuAction, PmtuState};

#[derive(Default)]
pub(crate) struct UdpPath {
    addr: Option<SocketAddr>,
    /// `addr` is where an authenticated datagram came from, not a hint.
    addr_seen: bool,
    pmtu: Option<PmtuState>,
    send_failed_at: Option<Instant>,
    /// Derived by [`Self::refresh_target`], cached for the hot path.
    target: Option<(SockAddr, u8)>,
}

impl UdpPath {
    #[must_use]
    pub(crate) const fn addr(&self) -> Option<SocketAddr> {
        self.addr
    }

    #[must_use]
    pub(crate) fn confirmed(&self) -> bool {
        self.pmtu.as_ref().is_some_and(|p| p.udp_confirmed)
    }

    #[must_use]
    pub(crate) const fn pmtu(&self) -> Option<&PmtuState> {
        self.pmtu.as_ref()
    }

    pub(crate) fn pmtu_mut(&mut self, now: Instant) -> &mut PmtuState {
        self.pmtu.get_or_insert_with(|| PmtuState::new(now, MTU))
    }

    /// `MTU` if unseeded.
    #[must_use]
    pub(crate) fn mtu(&self) -> u16 {
        self.pmtu.as_ref().map_or(MTU, |p| p.mtu)
    }

    #[must_use]
    pub(crate) fn minmtu(&self) -> u16 {
        self.pmtu.as_ref().map_or(0, |p| p.minmtu)
    }

    #[must_use]
    pub(crate) fn maxmtu(&self) -> u16 {
        self.pmtu.as_ref().map_or(MTU, |p| p.maxmtu)
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn send_failed_at(&self) -> Option<Instant> {
        self.send_failed_at
    }

    #[must_use]
    pub(crate) const fn target(&self) -> Option<&(SockAddr, u8)> {
        self.target.as_ref()
    }

    #[must_use]
    pub(crate) fn derive_target(&self, sock: impl Fn(&SocketAddr) -> u8) -> Option<(SockAddr, u8)> {
        let addr = self.addr.filter(|_| self.confirmed())?;
        Some((SockAddr::from(addr), sock(&addr)))
    }

    pub(crate) fn refresh_target(&mut self, sock: impl Fn(&SocketAddr) -> u8) -> bool {
        let t = self.derive_target(sock);
        if t == self.target {
            return false;
        }
        self.target = t;
        true
    }

    #[must_use]
    pub(crate) const fn addr_seen(&self) -> bool {
        self.addr_seen
    }

    /// Proves only the peer→us leg, so it moves the address without
    /// confirming the path.
    pub(crate) fn on_authenticated_rx(&mut self, src: SocketAddr) -> bool {
        self.addr_seen = true;
        self.addr.replace(src) != Some(src)
    }

    pub(crate) fn on_probe_reply(&mut self, len: u16, now: Instant) -> Vec<PmtuAction> {
        self.pmtu_mut(now).on_probe_reply(len, now)
    }

    /// `None` if we never probed, else whether it was already confirmed.
    pub(crate) fn on_meta_ack(&mut self, len: u16, now: Instant) -> Option<bool> {
        let p = self.pmtu.as_mut()?;
        let was = p.udp_confirmed;
        p.on_meta_ack(len, now).then_some(was)
    }

    pub(crate) fn on_emsgsize(&mut self, len: u16) -> Vec<PmtuAction> {
        self.pmtu
            .as_mut()
            .map_or_else(Vec::new, |p| p.on_emsgsize(len))
    }

    /// Returns the previous failure time.
    pub(crate) fn on_unreachable(&mut self, now: Instant) -> Option<Instant> {
        self.addr = None;
        self.target = None;
        self.addr_seen = false;
        if let Some(p) = self.pmtu.as_mut() {
            p.reset_path();
        }
        self.send_failed_at.replace(now)
    }

    pub(crate) fn on_timeout(&mut self) {
        if let Some(p) = self.pmtu.as_mut() {
            p.on_udp_timeout();
        }
        self.target = None;
    }

    /// Gossip or relay hints can't displace a confirmed or seen address,
    /// which stops forged `REQ_KEY`s redirecting traffic.
    pub(crate) fn on_addr_hint(&mut self, addr: SocketAddr) -> bool {
        if self.confirmed() || self.addr_seen || self.addr == Some(addr) {
            return false;
        }
        self.addr = Some(addr);
        if let Some(p) = self.pmtu.as_mut() {
            p.reset_path();
        }
        true
    }

    pub(crate) fn reset(&mut self) {
        self.addr = None;
        self.target = None;
        self.addr_seen = false;
        self.send_failed_at = None;
        if let Some(p) = self.pmtu.as_mut() {
            p.reset_path();
        }
    }

    pub(crate) fn set_policy(&mut self, cap: u16, discovery: bool, now: Instant) {
        self.pmtu_mut(now).set_policy(cap, discovery);
    }

    pub(crate) fn set_provisional_mtu(&mut self, mtu: u16) {
        if let Some(p) = self.pmtu.as_mut() {
            p.mtu = mtu;
        }
    }

    pub(crate) fn note_recent_len(&mut self, len: u16) {
        if let Some(p) = self.pmtu.as_mut() {
            p.maxrecentlen = p.maxrecentlen.max(len);
        }
    }

    pub(crate) fn take_recent_len(&mut self) -> u16 {
        self.pmtu
            .as_mut()
            .map_or(0, |p| mem::take(&mut p.maxrecentlen))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn invalidation_is_atomic() {
        type Kill = fn(&mut UdpPath, Instant);
        let now = Instant::now();
        let listeners = |_: &SocketAddr| 0;
        let confirmed = || {
            let mut p = UdpPath::default();
            p.on_authenticated_rx(addr("192.0.2.1:655"));
            let pm = p.pmtu_mut(now);
            pm.ping_sent = true;
            let _ = pm.on_probe_reply(1400, now);
            pm.minmtu = 1400;
            pm.maxmtu = 1400;
            assert!(p.refresh_target(listeners));
            p
        };
        let cases: [(&str, Kill); 3] = [
            ("unreachable", |p, now| {
                p.on_unreachable(now);
            }),
            ("timeout", |p, _| p.on_timeout()),
            ("reset", |p, _| p.reset()),
        ];
        for (name, kill) in cases {
            let mut p = confirmed();
            kill(&mut p, now);
            assert!(!p.confirmed(), "{name}");
            assert_eq!(p.minmtu(), 0, "{name}");
            assert_eq!(p.maxmtu(), MTU, "{name}");
            assert!(p.target().is_none(), "{name}");
            assert!(!p.refresh_target(listeners), "{name}");
        }
    }

    #[test]
    fn hint_does_not_displace_confirmed_addr() {
        let now = Instant::now();
        let mut p = UdpPath::default();
        assert!(p.on_addr_hint(addr("192.0.2.1:655")));
        assert!(p.on_addr_hint(addr("192.0.2.2:655")));
        p.on_authenticated_rx(addr("192.0.2.1:655"));
        assert!(!p.on_addr_hint(addr("198.51.100.7:655")));
        assert_eq!(p.addr(), Some(addr("192.0.2.1:655")));

        p.on_unreachable(now);
        assert!(p.on_addr_hint(addr("198.51.100.7:655")));
        assert_eq!(p.minmtu(), 0);
    }

    #[test]
    fn rebinding_moves_the_target() {
        let now = Instant::now();
        let listeners = |_: &SocketAddr| 0;
        let mut p = UdpPath::default();
        assert!(p.on_authenticated_rx(addr("192.0.2.1:655")));
        assert!(!p.on_authenticated_rx(addr("192.0.2.1:655")));
        let pm = p.pmtu_mut(now);
        pm.ping_sent = true;
        let _ = pm.on_probe_reply(18, now);
        assert!(p.refresh_target(listeners));
        assert!(p.on_authenticated_rx(addr("192.0.2.1:40000")));
        assert!(p.refresh_target(listeners));
        assert_eq!(
            p.target().and_then(|(sa, _)| sa.as_socket()),
            Some(addr("192.0.2.1:40000"))
        );
    }

    #[test]
    fn policy_caps_every_reset() {
        let now = Instant::now();
        let mut p = UdpPath::default();
        p.set_policy(1400, true, now);
        assert_eq!(p.maxmtu(), 1400);
        let _ = p.on_probe_reply(18, now);
        p.on_timeout();
        assert_eq!(p.maxmtu(), 1400);
        let _ = p.on_probe_reply(1500, now);
        assert!(p.maxmtu() <= 1400);
        p.reset();
        assert_eq!(p.maxmtu(), 1400);
    }

    #[test]
    fn no_discovery_pins_at_cap() {
        let now = Instant::now();
        let mut p = UdpPath::default();
        p.set_policy(1400, false, now);
        assert_eq!(p.minmtu(), 0);
        p.pmtu_mut(now).ping_sent = true;
        let _ = p.on_probe_reply(18, now);
        assert_eq!((p.minmtu(), p.maxmtu(), p.mtu()), (1400, 1400, 1400));
        assert!(p.pmtu_mut(now).tick(now, Duration::ZERO).is_empty());
    }
}
