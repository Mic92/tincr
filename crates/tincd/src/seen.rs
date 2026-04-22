//! `seen_request` anti-loop cache.
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
//! We swap the splay tree for `HashMap<String, Instant>`. Lookup
//! goes through `Borrow<str>` so a cache hit allocates nothing; only
//! a miss pays for `to_owned()`. The C is the same: `splay_search`
//! borrows the caller's `const char*` on the stack, `xstrdup` only
//! on insert.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Hard cap on cache entries. At the cap, [`SeenRequests::check`]
/// reports unseen lines as duplicates: drop, don't forward — refuse
/// to amplify the flood that filled the cache. 4096 × ~2KB ≈ 8MB.
pub(crate) const SEEN_CAP: usize = 4096;

/// Dedup cache. Key = full wire line.
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

    /// Returns `true` if `line` was already seen (dup — drop it).
    /// Inserts `(line, now)` and returns `false` if not.
    ///
    /// No alloc on hit: `HashMap<String, _>::contains_key(&str)`
    /// works via `String: Borrow<str>`. Mirrors C's stack-borrowed
    /// `past_request_t p` for the lookup, `xstrdup` on miss only.
    pub(crate) fn check(&mut self, line: &str, now: Instant) -> bool {
        if self.cache.contains_key(line) {
            return true;
        }
        if self.cache.len() >= SEEN_CAP {
            // Refuse insert, report as seen. Next `age()` frees room.
            return true;
        }
        self.cache.insert(line.to_owned(), now);
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
    fn check_refuses_past_cap() {
        let mut s = SeenRequests::new();
        let now = Instant::now();
        for i in 0..SEEN_CAP {
            assert!(!s.check(&format!("12 {i:x} a b"), now));
        }
        assert!(s.check("12 ffffffff brand new", now));
        assert!(s.check("12 0 a b", now));
        let (_, left) = s.age(now, Duration::from_secs(3600));
        assert_eq!(left, SEEN_CAP);
        s.age(now + Duration::from_secs(3601), Duration::from_secs(60));
        assert!(!s.check("12 ffffffff brand new", now));
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
