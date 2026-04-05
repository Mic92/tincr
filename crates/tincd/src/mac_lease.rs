//! Learned-MAC lease table.
//!
//! `route_mac.rs` decides PER-PACKET whether the source MAC is
//! `New`/`Refresh`/`NotOurs`. This module holds the expiry CLOCK for
//! those decisions: `New` inserts a lease, `Refresh` bumps it, the
//! daemon's `age_subnets` timer (fires every 10s) calls
//! [`MacLeases::age`] to find expired entries.
//!
//! C smushes `expires` into `subnet_t` (`subnet.h:53`). We don't —
//! `tinc_proto::Subnet` is wire-format, and configured subnets vs
//! learned MACs have different lifecycles. Side table; daemon mirrors
//! learn/age into `SubnetTree::add/del`.
//!
//! ## What's NOT here
//!
//! - The actual `Subnet::Mac` add/del + `ADD/DEL_SUBNET` gossip — daemon,
//!   on `learn`/`age` return.
//! - The `route_mac::LearnAction → mac_lease` plumbing — daemon's
//!   `route_packet_mac` (`daemon/net.rs`).
//! - The skip-configured-subnets guard: we ONLY hold learned MACs.
//!   The daemon's `SubnetTree` holds both; only learned ones are
//!   mirrored here. The guard is implicit.
//! - The 10s timer arming — daemon's `TimerWhat`.
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::route_mac::Mac;

/// Default `macexpire`. 10 minutes.
pub const DEFAULT_EXPIRE_SECS: u64 = 600;

/// Learned-MAC expiry table.
#[derive(Debug, Default)]
pub struct MacLeases {
    /// MAC → expires-at. C: `subnet_t.expires` for `myself`-owned MAC
    /// subnets with nonzero expires.
    leases: HashMap<Mac, Instant>,
}

impl MacLeases {
    /// New MAC. Returns `true` if this was the FIRST lease (table
    /// was empty). Daemon arms the age timer on first add (on
    /// `true`).
    /// return.
    ///
    /// Idempotent: `learn` of an already-leased MAC just refreshes
    /// (`route_mac` returns `Refresh`, not `New` → daemon calls
    /// `refresh`, not `learn`). But guard against caller mistakes:
    /// if the MAC is
    /// already in the table, log debug + treat as refresh.
    pub fn learn(&mut self, mac: Mac, now: Instant, expire_secs: u64) -> bool {
        let expires = now + Duration::from_secs(expire_secs);
        if let Some(slot) = self.leases.get_mut(&mac) {
            // Already known — caller should have called refresh().
            // Stale routing snapshot, or race vs age(). Treat as
            // refresh; don't claim "first lease".
            log::debug!("mac_lease: learn() of already-leased MAC {mac:02x?}; treating as refresh");
            *slot = expires;
            return false;
        }
        let was_empty = self.leases.is_empty();
        self.leases.insert(mac, expires);
        was_empty
    }

    /// Known MAC; bump lease.
    ///
    /// `false` if the MAC wasn't in the table (`route_mac` thought it was
    /// known — stale routing snapshot? race vs `age()`?). Daemon: log
    /// warn, treat as no-op (the next `New` re-adds).
    pub fn refresh(&mut self, mac: Mac, now: Instant, expire_secs: u64) -> bool {
        match self.leases.get_mut(&mac) {
            Some(slot) => {
                *slot = now + Duration::from_secs(expire_secs);
                true
            }
            None => false,
        }
    }

    /// Prune expired. Returns `(expired_macs, any_left)`.
    ///
    /// `any_left` = at least one unexpired lease remains (`:512-514`).
    /// Daemon re-arms the 10s timer iff `any_left`; otherwise lets it
    /// lapse (`:518-521`).
    ///
    /// `expired` are removed from `self`. Daemon for each:
    /// `subnets.del(Subnet::Mac{addr,..})` + broadcast DEL.
    ///
    /// Expiry boundary: STRICT less. A lease expiring exactly at
    /// `now` is still alive for one more tick.
    pub fn age(&mut self, now: Instant) -> (Vec<Mac>, bool) {
        let mut expired = Vec::new();
        // Strict less. `expires == now` → NOT expired yet.
        self.leases.retain(|mac, &mut expires| {
            if expires < now {
                expired.push(*mac);
                false
            } else {
                true
            }
        });
        let any_left = !self.leases.is_empty();
        (expired, any_left)
    }

    /// `dump_subnets` debugging. C doesn't have a separate dump for
    /// learned-vs-configured; we might. Doc-only for now; just expose
    /// the map.
    pub fn iter(&self) -> impl Iterator<Item = (&Mac, &Instant)> {
        self.leases.iter()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.leases.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.leases.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: Mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0xaa];
    const B: Mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0xbb];

    fn t0() -> Instant {
        Instant::now()
    }

    fn secs(s: u64) -> Duration {
        Duration::from_secs(s)
    }

    #[test]
    fn learn_first_returns_true() {
        let mut m = MacLeases::default();
        assert!(m.learn(A, t0(), 600));
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn learn_second_returns_false() {
        let mut m = MacLeases::default();
        let now = t0();
        assert!(m.learn(A, now, 600));
        assert!(!m.learn(B, now, 600));
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn learn_existing_is_refresh() {
        let mut m = MacLeases::default();
        let t = t0();
        assert!(m.learn(A, t, 600));
        // learn again at t+100 — should NOT claim first, len unchanged,
        // expiry bumped
        assert!(!m.learn(A, t + secs(100), 600));
        assert_eq!(m.len(), 1);
        let exp = *m.iter().next().unwrap().1;
        assert_eq!(exp, t + secs(100) + secs(600));
    }

    #[test]
    fn refresh_known_bumps() {
        let mut m = MacLeases::default();
        let t = t0();
        m.learn(A, t, 600);
        assert!(m.refresh(A, t + secs(50), 600));
        let exp = *m.iter().next().unwrap().1;
        // expiry is t+50+600, NOT t+600
        assert_eq!(exp, t + secs(650));
    }

    #[test]
    fn refresh_unknown_returns_false() {
        let mut m = MacLeases::default();
        assert!(!m.refresh(B, t0(), 600));
        assert_eq!(m.len(), 0);
    }

    #[test]
    fn age_nothing_expired() {
        let mut m = MacLeases::default();
        let t = t0();
        m.learn(A, t, 600);
        let (exp, left) = m.age(t + secs(100));
        assert!(exp.is_empty());
        assert!(left);
    }

    #[test]
    fn age_some_expired() {
        let mut m = MacLeases::default();
        let t = t0();
        m.learn(A, t, 600); // expires at t+600
        m.learn(B, t + secs(500), 600); // expires at t+1100
        let (mut exp, left) = m.age(t + secs(601));
        exp.sort_unstable();
        assert_eq!(exp, vec![A]);
        assert!(left);
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn age_all_expired() {
        let mut m = MacLeases::default();
        let t = t0();
        m.learn(A, t, 600);
        let (exp, left) = m.age(t + secs(601));
        assert_eq!(exp, vec![A]);
        assert!(!left); // timer should NOT re-arm
        assert!(m.is_empty());
    }

    #[test]
    fn age_exactly_at_expiry() {
        // STRICT less: lease expiring exactly at `now` survives.
        let mut m = MacLeases::default();
        let t = t0();
        m.learn(A, t, 600); // expires at exactly t+600
        let (exp, left) = m.age(t + secs(600));
        assert!(exp.is_empty(), "expires == now → NOT expired (strict <)");
        assert!(left);
        // one more second and it goes
        let (exp, left) = m.age(t + secs(601));
        assert_eq!(exp, vec![A]);
        assert!(!left);
    }

    #[test]
    fn age_idempotent() {
        let mut m = MacLeases::default();
        let t = t0();
        m.learn(A, t, 600);
        m.learn(B, t, 600);
        let now = t + secs(601);
        let (exp1, _) = m.age(now);
        assert_eq!(exp1.len(), 2);
        let (exp2, left) = m.age(now);
        assert!(exp2.is_empty());
        assert!(!left);
    }
}
