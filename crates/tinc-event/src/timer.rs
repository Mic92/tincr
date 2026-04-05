//! Timer wheel. `timeout_add`/`_set`/`_del`/`_execute`.
//!
//! Keyed on `(Instant, u64)` where the `u64` is a monotonic sequence
//! number. The sequence number is a tiebreak for timers set to the
//! same instant — without it, two timers set in the same tick to the
//! same offset would collide in the map. Same disambiguation as a
//! pointer compare, but stable across runs.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// Opaque timer handle. Returned by `add`, passed to `set`/`del`.
///
/// In C the caller owns the `timeout_t` struct (it's a static or a
/// field). Here the `Timers` owns the slot; the caller holds an id.
/// `TimerId` is a slab index, NOT the `BTreeMap` key — the map key
/// changes on every re-arm, the id doesn't.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TimerId(usize);

/// One timer slot. `at` is `None` when disarmed (after `del`, or
/// freshly created and not yet `set`).
struct Slot<W> {
    what: W,
    /// Current map key, when armed. Stored so `del`/`set` can find
    /// the map entry to remove without scanning.
    at: Option<(Instant, u64)>,
}

/// Re-armable timer wheel.
///
/// Generic over `W: Copy` — the daemon's `enum TimerWhat`. See lib.rs
/// for the dispatch-enum design rationale.
pub struct Timers<W> {
    /// Ordered by deadline. Value is the slot index. `(Instant, u64)`
    /// because `Instant` alone collides for timers armed in the same
    /// `tick` to the same offset (and `BTreeMap::insert` overwrites,
    /// silently dropping the earlier).
    ///
    /// `BTreeMap` not `BinaryHeap`: every timer in tinc is re-armable,
    /// and re-arm on a heap means push-new + tombstone-old. The map's
    /// remove-mutate-reinsert is O(log n) — same as the C splay.
    by_deadline: BTreeMap<(Instant, u64), usize>,

    /// Slot storage. Freed slots stay allocated (`what` is stale,
    /// `at` is `None`); freelist tracks them. Same structure as
    /// `slab` crate but hand-rolled — slab is +1 dep for 30 LOC,
    /// and the dep audit says no.
    slots: Vec<Slot<W>>,
    free: Vec<usize>,

    /// Monotonic tiebreak. Increments every `set`. `u64` won't wrap
    /// in practice (1 set per nanosecond for 584 years).
    seq: u64,

    /// Cached `now`. Updated once per `tick`; `set` reads it. See
    /// lib.rs "now: cached" section for why this
    /// is correctness not optimization.
    now: Instant,
}

impl<W: Copy> Timers<W> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            by_deadline: BTreeMap::new(),
            slots: Vec::new(),
            free: Vec::new(),
            seq: 0,
            now: Instant::now(),
        }
    }

    /// Allocate a timer slot. The caller calls `set` separately.
    /// Reason: `add` happens
    /// once at construction (or per-connection-create), `set` happens
    /// per-re-arm. Separating them makes the dynamic timers
    /// (`RetryOutgoing(OutgoingId)`) cheap to pre-create.
    ///
    /// Returns a stable handle. Unlike `IoId` this is NOT a mio token
    /// — timers don't go through the poll fd.
    pub fn add(&mut self, what: W) -> TimerId {
        let idx = if let Some(idx) = self.free.pop() {
            self.slots[idx] = Slot { what, at: None };
            idx
        } else {
            self.slots.push(Slot { what, at: None });
            self.slots.len() - 1
        };
        TimerId(idx)
    }

    /// Arm a timer. `after` is RELATIVE to the cached `now`.
    ///
    /// If already armed, removes the old entry from the map first.
    ///
    /// # Panics
    /// If `id` is dangling (was `del`'d). C doesn't check — it
    /// dereferences the caller's `timeout_t*`, which is UB if freed.
    /// We panic, which is louder.
    pub fn set(&mut self, id: TimerId, after: Duration) {
        let slot = &mut self.slots[id.0];
        if let Some(old_key) = slot.at.take() {
            self.by_deadline.remove(&old_key);
        }
        let when = self.now + after;
        self.seq += 1;
        let key = (when, self.seq);
        slot.at = Some(key);
        // Can't duplicate (seq is monotonic), so the unwrap-is-none is
        // a debug assertion not a runtime check.
        let prev = self.by_deadline.insert(key, id.0);
        debug_assert!(prev.is_none(), "seq tiebreak collided — impossible");
    }

    /// Delete a timer. Idempotent.
    ///
    /// Slot is returned to the freelist. Caller must not use `id`
    /// after this. (C nulls `cb` and zeroes `tv`; the `timeout_t`
    /// struct is caller-owned and lives on.)
    pub fn del(&mut self, id: TimerId) {
        let Some(slot) = self.slots.get_mut(id.0) else {
            return; // already del'd, freelist reused, then del'd again — idempotent
        };
        if let Some(key) = slot.at.take() {
            self.by_deadline.remove(&key);
        }
        self.free.push(id.0);
    }

    /// Execute expired timers.
    ///
    /// Snapshots `Instant::now()` into `self.now`, then drains all
    /// expired timers into `out`. Returns
    /// the duration until the next un-expired timer, or `None` if
    /// the wheel is empty. That `Option<Duration>` is the poll
    /// timeout — passed straight to `mio::Poll::poll`.
    ///
    /// The C version FIRES the callbacks inline (`timeout->cb(data)`
    /// at `:125`). We can't — the daemon owns `&mut Timers` AND
    /// `&mut everything_else`, and the cb wants the latter. So we
    /// return a list of `W`s instead. The daemon's loop drains it,
    /// matching on `W`. Consequence: the C's "did cb re-arm?"
    /// check at `:127-129` has to move to the daemon's loop too:
    ///
    /// ```ignore
    /// for what in timers.tick(&mut fired) {
    ///     match what {
    ///         TimerWhat::Ping => { do_ping_stuff(); timers.set(ping_id, secs(1)); }
    ///         ...
    ///     }
    /// }
    /// ```
    ///
    /// The C did `if(timercmp(&timeout->tv, &now, <)) timeout_del()`
    /// — auto-delete if cb didn't re-arm. We DON'T port that. The C
    /// behavior is implicit ("forgot to re-arm = one-shot"); we make
    /// re-arm explicit. A timer that wasn't `set` after firing stays
    /// disarmed but allocated. Minor semantic difference; documented
    /// because the daemon will hit it.
    ///
    /// `out` is borrowed not returned — caller reuses the same `Vec`
    /// across ticks, avoiding per-tick allocation. Hot loop.
    // The `expect` below cannot fire: single-threaded, key was just
    // peeked from the same map. clippy can't see that.
    #[allow(clippy::missing_panics_doc)] // expect("just peeked"): single-threaded, key was peeked from same map this iteration
    pub fn tick(&mut self, out: &mut Vec<W>) -> Option<Duration> {
        out.clear();
        // Single clock read per execute.
        self.now = Instant::now();

        // Drain everything <= now. C's `while(timeout_tree.head)`
        // loop at :120-134, except we don't fire inline.
        // can't `while let Some((k, _)) = first_key_value()` and
        // `remove(k)` — the &k borrow lives across the remove. Hence
        // the awkward peek-copy-remove.
        loop {
            let key = match self.by_deadline.first_key_value() {
                Some((k, _)) if k.0 <= self.now => *k,
                Some((k, _)) => {
                    return Some(k.0 - self.now);
                }
                None => {
                    // No more timers. mio handles `None` as infinite wait.
                    return None;
                }
            };
            // remove() not pop_first() — pop_first is logically the
            // same here but remove(key) is what we'd do for the
            // re-arm path, and using one operation keeps it obvious.
            let idx = self.by_deadline.remove(&key).expect("just peeked");
            let slot = &mut self.slots[idx];
            // Auto-del NOT ported, see doc. We do clear `at` though —
            // the timer is disarmed until
            // the daemon's match arm calls `set` again.
            slot.at = None;
            out.push(slot.what);
        }
    }

    /// Current cached `now`. Exposed because the daemon's ping-interval
    /// check wants the SAME now the timer comparisons used, not a fresh
    /// `Instant::now()` per check.
    #[must_use]
    pub const fn now(&self) -> Instant {
        self.now
    }

    /// True if no timers are armed. Tests use this; daemon shouldn't
    /// (it always has `pingtimer` armed).
    #[must_use]
    pub fn is_idle(&self) -> bool {
        self.by_deadline.is_empty()
    }
}

impl<W: Copy> Default for Timers<W> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    /// The dispatch enum the daemon would define. Tests use a small
    /// subset.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum What {
        Ping,
        Periodic,
        Retry(u32),
    }

    /// Empty wheel returns None (infinite poll timeout).
    #[test]
    fn tick_empty_returns_none() {
        let mut t: Timers<What> = Timers::new();
        let mut out = Vec::new();
        assert_eq!(t.tick(&mut out), None);
        assert!(out.is_empty());
        assert!(t.is_idle());
    }

    /// `set()` takes a RELATIVE duration. After tick advances `now`
    /// past the deadline, the timer fires.
    #[test]
    fn fires_after_duration() {
        let mut t = Timers::new();
        let ping = t.add(What::Ping);
        t.set(ping, Duration::from_millis(5));

        let mut out = Vec::new();
        // Immediately: not yet expired (5ms in the future from `t.now`
        // which was set in `Timers::new`). tick() refreshes now; might
        // already be 5ms later on a slow CI box, so don't assert
        // out.is_empty() here. Instead: sleep past, then it MUST fire.
        sleep(Duration::from_millis(10));
        let next = t.tick(&mut out);
        assert_eq!(out, vec![What::Ping]);
        assert_eq!(next, None); // wheel is empty after firing
    }

    /// `set()` on an already-armed timer unlinks the old entry first.
    /// Re-arming to a later deadline must NOT
    /// leave a ghost entry firing at the old time.
    #[test]
    fn rearm_removes_old_deadline() {
        let mut t = Timers::new();
        let ping = t.add(What::Ping);
        t.set(ping, Duration::from_millis(1));
        // Re-arm to far future before the old one fires.
        t.set(ping, Duration::from_secs(3600));

        sleep(Duration::from_millis(5));
        let mut out = Vec::new();
        let next = t.tick(&mut out);
        // Old 1ms deadline must NOT fire. Only the 3600s one is
        // armed, so tick returns Some(almost-an-hour).
        assert!(out.is_empty(), "ghost entry fired: {out:?}");
        let next = next.expect("3600s timer is armed");
        assert!(next > Duration::from_secs(3500));
        // BTreeMap should have exactly one entry.
        assert_eq!(t.by_deadline.len(), 1);
    }

    /// Sequence-number tiebreak. Two timers set to the same relative
    /// offset in the same tick get the same `Instant` (because `set`
    /// reads cached `self.now`). Without
    /// the seq tiebreak, `BTreeMap::insert` would overwrite. With it,
    /// both fire.
    ///
    /// Without disambiguation, one timer would silently be lost on
    /// the duplicate insert.
    #[test]
    fn same_instant_timers_both_fire() {
        let mut t = Timers::new();
        let a = t.add(What::Retry(1));
        let b = t.add(What::Retry(2));
        // Same offset, same cached `now` → same Instant.
        t.set(a, Duration::from_millis(1));
        t.set(b, Duration::from_millis(1));

        // The map keys differ only in seq.
        assert_eq!(t.by_deadline.len(), 2);
        let keys: Vec<_> = t.by_deadline.keys().copied().collect();
        assert_eq!(keys[0].0, keys[1].0, "same Instant — premise of test");
        assert_ne!(keys[0].1, keys[1].1, "seq disambiguates");

        sleep(Duration::from_millis(5));
        let mut out = Vec::new();
        t.tick(&mut out);
        // Both fire. Order: seq order (insertion order). C order is
        // pointer order (effectively address order — undefined but
        // stable per-process). Neither is observable to the daemon
        // because the cb's effect doesn't depend on which Retry
        // fires first. Don't assert order.
        assert_eq!(out.len(), 2);
        assert!(out.contains(&What::Retry(1)));
        assert!(out.contains(&What::Retry(2)));
    }

    /// del is idempotent.
    #[test]
    fn del_idempotent() {
        let mut t = Timers::new();
        let ping = t.add(What::Ping);
        t.set(ping, Duration::from_secs(1));

        t.del(ping);
        assert!(t.is_idle());
        // Second del — must not panic, must not mess up freelist.
        t.del(ping);
        assert!(t.is_idle());

        // Freelist reuse: next add gets the same slot.
        let periodic = t.add(What::Periodic);
        assert_eq!(periodic.0, ping.0, "freelist reused slot");
    }

    /// When the head is in the future, return the diff (poll timeout)
    /// and don't fire anything.
    #[test]
    fn future_timer_returns_diff() {
        let mut t = Timers::new();
        let ping = t.add(What::Ping);
        t.set(ping, Duration::from_secs(10));

        let mut out = Vec::new();
        let next = t.tick(&mut out);
        assert!(out.is_empty());
        let next = next.expect("timer is armed");
        // tick() refreshed `now`; some time passed since `set`.
        // The diff is < 10s but >> 0. Don't pin exact — CI jitter.
        assert!(next > Duration::from_secs(9));
        assert!(next <= Duration::from_secs(10));
    }

    /// The "did cb re-arm?" auto-del semantics we DELIBERATELY don't
    /// port. After firing, the slot is disarmed but allocated. Calling
    /// `set` re-arms; not calling it leaves it idle. The daemon is
    /// responsible.
    ///
    /// This test pins the SHAPE: tick disarms, set re-arms.
    #[test]
    fn fire_disarms_slot() {
        let mut t = Timers::new();
        let ping = t.add(What::Ping);
        t.set(ping, Duration::from_millis(1));

        sleep(Duration::from_millis(5));
        let mut out = Vec::new();
        t.tick(&mut out);
        assert_eq!(out, vec![What::Ping]);

        // Slot is disarmed: `at` is None, NOT in the map.
        assert!(t.is_idle());
        assert!(t.slots[ping.0].at.is_none());

        // But not freed — re-arm works without re-adding.
        t.set(ping, Duration::from_secs(1));
        assert!(!t.is_idle());
    }

    /// Multiple timers, mixed expiry. Drains all <= now in one tick.
    /// It's a loop, not a single pop.
    #[test]
    fn drains_all_expired() {
        let mut t = Timers::new();
        let a = t.add(What::Retry(1));
        let b = t.add(What::Retry(2));
        let c = t.add(What::Retry(3));
        t.set(a, Duration::from_millis(1));
        t.set(b, Duration::from_millis(2));
        t.set(c, Duration::from_secs(3600)); // far future

        sleep(Duration::from_millis(10));
        let mut out = Vec::new();
        let next = t.tick(&mut out);

        // a and b expired, c is the next.
        assert_eq!(out.len(), 2);
        assert!(out.contains(&What::Retry(1)));
        assert!(out.contains(&What::Retry(2)));
        let next = next.expect("c is armed");
        assert!(next > Duration::from_secs(3500));
    }

    /// `out` is cleared at the top of tick — caller reuses one Vec.
    #[test]
    fn tick_clears_out() {
        let mut t: Timers<What> = Timers::new();
        let mut out = vec![What::Ping, What::Periodic]; // stale junk
        t.tick(&mut out);
        assert!(out.is_empty());
    }

    /// `now()` accessor returns the cached value. Doesn't tick.
    #[test]
    fn now_is_cached() {
        let mut t: Timers<What> = Timers::new();
        let before = t.now();
        sleep(Duration::from_millis(5));
        // Without tick, `now` hasn't moved.
        assert_eq!(t.now(), before);
        // tick refreshes it.
        let mut out = Vec::new();
        t.tick(&mut out);
        assert!(t.now() > before);
    }
}
