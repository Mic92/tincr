//! `seen_request` anti-loop cache + per-conn flood limiter.
//!
//! `ADD_EDGE`/`ADD_SUBNET` flood the mesh: a node receiving one
//! re-broadcasts to all OTHER connections. Without dedup, any cycle
//! in the connection graph bounces the same message forever.
//!
//! C keys a splay tree on `strcmp` of the **full message line**
//! (`"12 a3f alice bob 10.0.0.1 655 ..."`). Handlers call
//! `seen_request(request)` before processing; `true` → dup, drop.
//! Entries TTL out after `pinginterval` seconds; the age timer
//! re-arms every 10s, so real lifetime is `pinginterval`..`+10s`.
//!
//! At the cap the oldest entry is evicted, so an unseen line is always
//! applied. A rotated nonce is a new line, as in C: handlers forward only
//! state-changing lines and `FloodLimiter` bounds distinct-content floods.

#![forbid(unsafe_code)]

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Hard cap on cache entries. 4096 × ~2KB ≈ 8MB.
pub(crate) const SEEN_CAP: usize = 4096;

/// [`FloodLimiter`] refill: forwarded gossip msgs/s per connection.
pub(crate) const FLOOD_RATE_PER_SEC: u32 = 200;
/// [`FloodLimiter`] burst cap.
pub(crate) const FLOOD_BURST: u32 = 1000;

/// Dedup cache keyed on the full wire line.
pub(crate) struct SeenRequests {
    cache: HashMap<String, Instant>,
    /// Insertion order. Entries share one TTL, so this is also age order.
    order: VecDeque<(Instant, String)>,
}

impl SeenRequests {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            cache: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    /// `true` = already seen (drop).
    pub(crate) fn check(&mut self, line: &str, now: Instant) -> bool {
        if self.cache.contains_key(line) {
            return true;
        }
        while self.cache.len() >= SEEN_CAP {
            self.pop_oldest();
        }
        self.cache.insert(line.to_owned(), now);
        self.order.push_back((now, line.to_owned()));
        false
    }

    fn pop_oldest(&mut self) -> Option<Instant> {
        let (at, key) = self.order.pop_front()?;
        // Skip stale order entries left by `purge_mentions`.
        if self.cache.get(&key) == Some(&at) {
            self.cache.remove(&key);
        }
        Some(at)
    }

    /// Evict entries at least `max_age` old (C's `<=` boundary) and return
    /// `(deleted, left)` for the debug log.
    pub(crate) fn age(&mut self, now: Instant, max_age: Duration) -> (usize, usize) {
        let before = self.cache.len();
        while self
            .order
            .front()
            .is_some_and(|(at, _)| now.saturating_duration_since(*at) >= max_age)
        {
            self.pop_oldest();
        }
        let left = self.cache.len();
        (before - left, left)
    }

    /// Drop entries mentioning `name` as a token. Called when a meta
    /// connection with that node activates: a reconnected peer
    /// re-gossips byte-identical lines, which must not dedup against
    /// its previous incarnation.
    pub(crate) fn purge_mentions(&mut self, name: &str) {
        self.cache
            .retain(|k, _| !k.split(' ').any(|tok| tok == name));
    }
}

/// Per-connection token bucket on *re-forwarded* gossip. Dedup can't
/// bound distinct-content floods (minted node names); cap blast
/// radius at `FLOOD_RATE_PER_SEC` × fan-out. Over-budget = drop, not
/// disconnect — C peers legitimately burst at `send_everything`.
pub(crate) struct FloodLimiter {
    tokens: u32,
    last_refill: Option<Instant>,
    /// Latches the once-per-refill warning.
    warned: bool,
}

impl FloodLimiter {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            tokens: FLOOD_BURST,
            last_refill: None,
            warned: false,
        }
    }

    /// Take one token; `true` = forward, `false` = over budget.
    pub(crate) fn allow(&mut self, now: Instant) -> bool {
        self.refill(now);
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }

    /// `true` once per refill interval (rate-limited log).
    pub(crate) fn should_warn(&mut self) -> bool {
        if self.warned {
            false
        } else {
            self.warned = true;
            true
        }
    }

    fn refill(&mut self, now: Instant) {
        let Some(last) = self.last_refill else {
            self.last_refill = Some(now);
            return;
        };
        let elapsed = now.saturating_duration_since(last);
        // ms granularity; clamp before u32 cast so long idle can't wrap.
        let add = (u128::from(FLOOD_RATE_PER_SEC) * elapsed.as_millis() / 1000)
            .min(u128::from(FLOOD_BURST));
        let add = u32::try_from(add).unwrap_or(FLOOD_BURST);
        if add > 0 {
            self.tokens = self.tokens.saturating_add(add).min(FLOOD_BURST);
            self.last_refill = Some(now);
            self.warned = false;
        }
    }
}

impl Default for FloodLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for SeenRequests {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real ADD_EDGE / ADD_SUBNET wire bodies. See
    // `crates/tinc-proto/src/msg/`.
    const ADD_EDGE: &str = "12 a3f alice bob 10.0.0.1 655 0 50 192.168.1.1 655";
    const ADD_SUBNET: &str = "10 b4e alice 10.0.0.0/24#10";

    #[test]
    fn purge_mentions_frees_node_lines() {
        let mut s = SeenRequests::new();
        let now = Instant::now();
        assert!(!s.check(ADD_EDGE, now));
        assert!(!s.check(ADD_SUBNET, now));
        s.purge_mentions("bob");
        assert!(!s.check(ADD_EDGE, now), "bob line purged");
        assert!(s.check(ADD_SUBNET, now), "alice-only line kept");
        s.purge_mentions("ali");
        assert!(s.check(ADD_SUBNET, now), "token match, not substring");
    }

    #[test]
    fn check_second_is_true() {
        let mut s = SeenRequests::new();
        let now = Instant::now();
        assert!(!s.check(ADD_EDGE, now));
        assert!(s.check(ADD_EDGE, now));
    }

    #[test]
    fn check_different_false() {
        let mut s = SeenRequests::new();
        let now = Instant::now();
        assert!(!s.check(ADD_EDGE, now));
        assert!(!s.check(ADD_SUBNET, now));
    }

    #[test]
    fn age_evicts_old() {
        let mut s = SeenRequests::new();
        let t0 = Instant::now();
        s.check(ADD_EDGE, t0);
        let t1 = t0 + Duration::from_secs(61);
        s.age(t1, Duration::from_mins(1));
        // Gone: re-seeing it is a miss again.
        assert!(!s.check(ADD_EDGE, t1));
    }

    #[test]
    fn age_keeps_young() {
        let mut s = SeenRequests::new();
        let t0 = Instant::now();
        s.check(ADD_EDGE, t0);
        let t1 = t0 + Duration::from_secs(30);
        s.age(t1, Duration::from_mins(1));
        // Still there: still a dup.
        assert!(s.check(ADD_EDGE, t1));
    }

    #[test]
    fn age_counts() {
        let mut s = SeenRequests::new();
        let t0 = Instant::now();
        s.check(ADD_EDGE, t0); // old
        let t1 = t0 + Duration::from_secs(61);
        s.check(ADD_SUBNET, t1); // young
        let (deleted, left) = s.age(t1, Duration::from_mins(1));
        assert_eq!((deleted, left), (1, 1));
    }

    #[test]
    fn check_after_age_is_false() {
        let mut s = SeenRequests::new();
        let t0 = Instant::now();
        assert!(!s.check(ADD_EDGE, t0));
        assert!(s.check(ADD_EDGE, t0));
        let t1 = t0 + Duration::from_secs(61);
        s.age(t1, Duration::from_mins(1));
        assert!(!s.check(ADD_EDGE, t1));
    }

    /// A repeated `DEL_EDGE` within the TTL carries a fresh nonce and must apply.
    #[test]
    fn check_keys_full_line() {
        let mut s = SeenRequests::new();
        let now = Instant::now();
        assert!(!s.check("13 a3f alice bob", now));
        assert!(!s.check("13 ffffffff alice bob", now));
        assert!(s.check("13 ffffffff alice bob", now));
    }

    #[test]
    fn check_evicts_oldest_at_cap() {
        let mut s = SeenRequests::new();
        let t0 = Instant::now();
        for i in 0..SEEN_CAP {
            assert!(!s.check(&format!("12 0 n{i} b"), t0));
        }
        let t1 = t0 + Duration::from_secs(1);
        assert!(!s.check("12 0 brand new", t1));
        assert!(!s.check("12 0 n0 b", t1), "oldest evicted");
        assert!(s.check(&format!("12 0 n{} b", SEEN_CAP - 1), t1));
        let (_, left) = s.age(t1, Duration::from_hours(1));
        assert_eq!(left, SEEN_CAP);
    }

    #[test]
    fn flood_limiter_allows_then_drops_then_refills() {
        let mut f = FloodLimiter::new();
        let t0 = Instant::now();
        for _ in 0..FLOOD_BURST {
            assert!(f.allow(t0));
        }
        assert!(!f.allow(t0));
        assert!(f.should_warn());
        assert!(!f.should_warn(), "warn fires once per interval");
        let t1 = t0 + Duration::from_secs(1);
        for _ in 0..FLOOD_RATE_PER_SEC {
            assert!(f.allow(t1));
        }
        assert!(!f.allow(t1));
        assert!(f.should_warn(), "warn latch resets on refill");
    }

    #[test]
    fn flood_limiter_caps_at_burst() {
        let mut f = FloodLimiter::new();
        let t0 = Instant::now();
        assert!(f.allow(t0)); // anchor last_refill
        let t1 = t0 + Duration::from_hours(168);
        for _ in 0..FLOOD_BURST {
            assert!(f.allow(t1));
        }
        assert!(!f.allow(t1));
    }

    #[test]
    fn age_boundary_evicts() {
        // `firstseen + pinginterval <= now` — `<=`, so
        // exactly-max_age-old is evicted.
        let mut s = SeenRequests::new();
        let t0 = Instant::now();
        s.check(ADD_EDGE, t0);
        let t1 = t0 + Duration::from_mins(1);
        let (deleted, left) = s.age(t1, Duration::from_mins(1));
        assert_eq!((deleted, left), (1, 0));
    }
}
