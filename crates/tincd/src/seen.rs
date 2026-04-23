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
//! Diverges from C: the nonce token is stripped before hashing. C's
//! full-line key lets a peer rotate the nonce to bypass dedup and
//! drive an O(n²) re-flood. Stricter-than-C is intentional; first-
//! sight acceptance is unchanged.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Hard cap on cache entries. At the cap, [`SeenRequests::check`]
/// reports unseen lines as duplicates: drop, don't forward — refuse
/// to amplify the flood that filled the cache. 4096 × ~2KB ≈ 8MB.
pub(crate) const SEEN_CAP: usize = 4096;

/// [`FloodLimiter`] refill: forwarded gossip msgs/s per connection.
/// 1k-node initial sync ≈ 3k msgs → ~15s, well under `pinginterval`.
pub(crate) const FLOOD_RATE_PER_SEC: u32 = 200;
/// [`FloodLimiter`] burst cap. Sized for `send_everything` in one read.
pub(crate) const FLOOD_BURST: u32 = 1000;

/// Dedup cache. Key = wire line with the nonce token (field 2)
/// stripped — see [`normalize_key`].
pub(crate) struct SeenRequests {
    cache: HashMap<String, Instant>,
}

impl SeenRequests {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }

    /// `true` = already seen (drop). Nonce token stripped before
    /// lookup so nonce-only variations dedup; one alloc per call.
    pub(crate) fn check(&mut self, line: &str, now: Instant) -> bool {
        let key = normalize_key(line);
        if self.cache.contains_key(key.as_str()) {
            return true;
        }
        if self.cache.len() >= SEEN_CAP {
            // Refuse insert, report as seen. Next `age()` frees room.
            return true;
        }
        self.cache.insert(key, now);
        false
    }

    /// Evict entries older than `max_age`. Returns `(deleted, left)`
    /// for the debug log: `"Aging past requests: deleted %d, left
    /// %d"`.
    ///
    /// C condition is `p->firstseen + pinginterval <= now.tv_sec`
    /// (`:219`); we keep the `<=` boundary: an entry exactly
    /// `max_age` old is evicted.
    ///
    /// `saturating_duration_since` not `duration_since`: an entry
    /// inserted at `t1` with `age()` later called with `t0 < t1`
    /// would panic. The daemon won't do this (both `now`s come from
    /// `timers.now()`, monotonic) but future timestamps shouldn't
    /// crash either — they just don't expire.
    pub(crate) fn age(&mut self, now: Instant, max_age: Duration) -> (usize, usize) {
        let before = self.cache.len();
        self.cache.retain(|_, firstseen| {
            // Keep if NOT expired. C: `firstseen + pinginterval <=
            // now` deletes; so keep when `now - firstseen < max_age`.
            now.saturating_duration_since(*firstseen) < max_age
        });
        let left = self.cache.len();
        (before - left, left)
    }
}

/// Drop token 2 (nonce) from `"<REQ> <nonce> <rest...>"`. The nonce
/// has no semantic weight; <2 tokens is degenerate → pass through.
fn normalize_key(line: &str) -> String {
    let mut it = line.split_ascii_whitespace();
    let Some(req) = it.next() else {
        return String::new();
    };
    if it.next().is_none() {
        return req.to_owned();
    }
    let mut key = String::with_capacity(line.len());
    key.push_str(req);
    for tok in it {
        key.push(' ');
        key.push_str(tok);
    }
    key
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
        #[allow(clippy::cast_possible_truncation)] // ≤ FLOOD_BURST: u32
        let add = add as u32;
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
        s.age(t1, Duration::from_secs(60));
        // Gone: re-seeing it is a miss again.
        assert!(!s.check(ADD_EDGE, t1));
    }

    #[test]
    fn age_keeps_young() {
        let mut s = SeenRequests::new();
        let t0 = Instant::now();
        s.check(ADD_EDGE, t0);
        let t1 = t0 + Duration::from_secs(30);
        s.age(t1, Duration::from_secs(60));
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
        let (deleted, left) = s.age(t1, Duration::from_secs(60));
        assert_eq!((deleted, left), (1, 1));
    }

    #[test]
    fn check_after_age_is_false() {
        let mut s = SeenRequests::new();
        let t0 = Instant::now();
        assert!(!s.check(ADD_EDGE, t0));
        assert!(s.check(ADD_EDGE, t0));
        let t1 = t0 + Duration::from_secs(61);
        s.age(t1, Duration::from_secs(60));
        assert!(!s.check(ADD_EDGE, t1));
    }

    #[test]
    fn check_dedups_across_nonce() {
        let mut s = SeenRequests::new();
        let now = Instant::now();
        let a = "12 a3f alice bob 10.0.0.1 655 0 50 192.168.1.1 655";
        let b = "12 ffffffff alice bob 10.0.0.1 655 0 50 192.168.1.1 655";
        assert!(!s.check(a, now));
        assert!(s.check(b, now), "nonce-only difference must dedup");
        // Real content change still distinct.
        let c = "12 a3f alice bob 10.0.0.1 655 0 51 192.168.1.1 655";
        assert!(!s.check(c, now));
    }

    #[test]
    fn check_refuses_past_cap() {
        let mut s = SeenRequests::new();
        let now = Instant::now();
        for i in 0..SEEN_CAP {
            assert!(!s.check(&format!("12 0 n{i} b"), now));
        }
        assert!(s.check("12 0 brand new", now));
        assert!(s.check("12 0 n0 b", now));
        let (_, left) = s.age(now, Duration::from_secs(3600));
        assert_eq!(left, SEEN_CAP);
        s.age(now + Duration::from_secs(3601), Duration::from_secs(60));
        assert!(!s.check("12 0 brand new", now));
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
        let t1 = t0 + Duration::from_secs(7 * 24 * 3600);
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
        let t1 = t0 + Duration::from_secs(60);
        let (deleted, left) = s.age(t1, Duration::from_secs(60));
        assert_eq!((deleted, left), (1, 0));
    }
}
