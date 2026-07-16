//! Connection-rate-limit tarpit.
//!
//! Two leaky buckets (same-host, all-host) plus a fixed-size ring of
//! accepted-but-ignored fds. Peers in the pit see a connected socket
//! that never reads — slows scanners without spending state on them.

use std::net::SocketAddr;
use std::os::fd::OwnedFd;
use std::time::Instant;

/// Default leaky-bucket capacity; the runtime value comes from
/// `MaxConnectionBurst` config via `Tarpit::new`. Tests use this to
/// seed the default behaviour.
#[cfg(test)]
const MAX_BURST: u32 = 10;

/// Ring-buffer length for tarpitted fds.
const PIT_SIZE: usize = 10;

/// Connection-burst rate limiter.
///
/// Two leaky buckets:
/// - same-host: if this peer matches the previous one, drain+refill
///   the same-host bucket. `> max_burst` → pit.
/// - all-host: drain+refill regardless of peer. `>= max_burst` → pit.
///
/// The off-by-one between `>` and `>=` matches C tinc for identical
/// behavior: same-host triggers at 11, all-host at 10.
///
/// `pits[]`: ring buffer of fds we accepted but won't serve. They
/// stay open, doing nothing, until evicted by a newer pit (10 slots).
/// The peer's `connect()` succeeds (TCP handshake completes — kernel
/// did that before we called `accept`), but reads block forever.
/// Slows down scanners.
///
/// `now` is `tinc-event::Timers::now()` — the cached per-tick Instant.
/// Comparisons are at second granularity (`.as_secs()`) to match
/// C tinc's `time_t` arithmetic.
pub(crate) struct Tarpit {
    /// The last peer's address, port-stripped. `None` is the initial
    /// state — first peer never matches.
    prev_addr: Option<SocketAddr>,

    /// Current same-host bucket fill.
    samehost_burst: u32,
    /// Last same-host refill time.
    samehost_time: Instant,

    /// All-host bucket fill.
    allhost_burst: u32,
    /// Last all-host refill time.
    allhost_time: Instant,

    /// From `MaxConnectionBurst` config. The `>` vs `>=` off-by-one
    /// (see struct doc) is preserved.
    max_burst: u32,

    /// Tarpitted fds. Option because a slot is empty until first
    /// eviction. `OwnedFd` because Drop closes; eviction happens by
    /// replacing (and dropping) the old value.
    pits: [Option<OwnedFd>; PIT_SIZE],
    /// Ring cursor.
    next_pit: usize,
}

impl Tarpit {
    /// Construct empty. `now` seeds the refill times so the first leak
    /// doesn't drain an arbitrarily long window.
    #[must_use]
    pub(crate) fn new(now: Instant, max_burst: u32) -> Self {
        Self {
            prev_addr: None,
            samehost_burst: 0,
            samehost_time: now,
            allhost_burst: 0,
            allhost_time: now,
            max_burst,
            pits: Default::default(),
            next_pit: 0,
        }
    }

    /// Returns `true` if this connection should be pitted; the caller
    /// hands the fd to `pit()` and does NOT register the connection.
    ///
    /// Mutates self even on `false` — the buckets always update.
    ///
    /// `addr` should be `unmap()`ed. Comparison is on `.ip()`, so the
    /// port doesn't matter.
    ///
    /// `now` from `Timers::now()`. The drain is second-granularity.
    pub(crate) fn check(&mut self, addr: SocketAddr, now: Instant) -> bool {
        // Same-host bucket.
        let same_host = self.prev_addr.is_some_and(|p| p.ip() == addr.ip());

        if same_host {
            // Leak: subtract elapsed seconds, floor at zero. A clock
            // going backwards is clamped to zero elapsed (never
            // increases the bucket).
            let elapsed = now.saturating_duration_since(self.samehost_time).as_secs();
            // elapsed: u32 overflows after 136yr uptime; would only under-drain anyway
            #[expect(clippy::cast_possible_truncation)]
            {
                self.samehost_burst = self.samehost_burst.saturating_sub(elapsed as u32);
            }
            self.samehost_time = now;
            self.samehost_burst += 1;

            // Strictly greater: triggers at 11.
            if self.samehost_burst > self.max_burst {
                return true;
            }
        }

        // Update prev AFTER the same-host check. First connection from
        // a new host doesn't tick the same-host bucket (it's
        // "different from prev"); the SECOND connection does.
        self.prev_addr = Some(addr);

        // All-host bucket: same arithmetic.
        let elapsed = now.saturating_duration_since(self.allhost_time).as_secs();
        #[expect(clippy::cast_possible_truncation)] // see same-host bucket above
        {
            self.allhost_burst = self.allhost_burst.saturating_sub(elapsed as u32);
        }
        self.allhost_time = now;
        self.allhost_burst += 1;

        // Greater-or-equal: triggers at 10, then clamps, so the
        // all-host bucket never exceeds max_burst and one second of
        // leak lets the next conn in. Same-host has no clamp (and `>`
        // not `>=`), so it can go to 11 and needs two seconds of leak.
        // The asymmetry looks accidental in C tinc but is kept for
        // identical behavior.
        if self.allhost_burst >= self.max_burst {
            self.allhost_burst = self.max_burst;
            return true;
        }

        false
    }

    /// Shove the fd into the pit ring. Evict-on-insert: if the slot is
    /// occupied, drop the old fd (closes it).
    ///
    /// The fd MUST NOT be registered with the event loop. We're
    /// silent-treatment-ing the peer: their `connect` succeeded (the
    /// kernel did the 3-way handshake before `accept` returned),
    /// reads block, writes succeed until the kernel buffer fills.
    /// They look connected but nothing happens.
    ///
    /// 10 slots = 10 simultaneous tarpitted peers. The 11th evicts
    /// the 1st (its `OwnedFd` drops, peer sees RST). Fixed memory.
    pub(crate) fn pit(&mut self, fd: OwnedFd) {
        // Option::replace drops the old OwnedFd; Drop closes. `let _ =`
        // so clippy knows the discard is intentional.
        let _ = self.pits[self.next_pit].replace(fd);
        self.next_pit = (self.next_pit + 1) % PIT_SIZE;
    }

    /// Test seam: how full are the buckets? Useful for asserting "9
    /// connections is fine, 10th gets pitted" without spawning real
    /// sockets.
    #[cfg(test)]
    pub(crate) const fn buckets(&self) -> (u32, u32) {
        (self.samehost_burst, self.allhost_burst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv6Addr, SocketAddrV4, SocketAddrV6};
    use std::time::Duration;

    /// Reduce stutter. `addr("10.0.0.5", 0)` for v4, `addr("::1", 0)` for v6.
    fn addr(s: &str, port: u16) -> SocketAddr {
        SocketAddr::new(s.parse().unwrap(), port)
    }

    // Seeded `now` lets us control time. The pit-ring is tested
    // separately with real fds (devnull); the bucket math is pure.

    /// Advance time by N seconds. Kept tiny so test bodies read.
    fn after(base: Instant, secs: u64) -> Instant {
        base + Duration::from_secs(secs)
    }

    /// 9 connections from DIFFERENT hosts in 0 seconds: all OK.
    /// 10th: pitted. The all-host bucket triggers at `>= 10`.
    #[test]
    fn tarpit_allhost_triggers_at_ten() {
        let t0 = Instant::now();
        let mut tp = Tarpit::new(t0, MAX_BURST);

        // 9 different /24 hosts, no time elapsed.
        for i in 1..=9u8 {
            let a = SocketAddr::V4(SocketAddrV4::new([10, 0, 0, i].into(), 0));
            assert!(!tp.check(a, t0), "conn {i} should pass");
        }
        let (_, allhost) = tp.buckets();
        assert_eq!(allhost, 9);

        // 10th: triggers.
        let a10 = addr("10.0.0.100", 0);
        assert!(tp.check(a10, t0), "10th should be pitted");
        // Bucket clamped at 10.
        let (_, allhost) = tp.buckets();
        assert_eq!(allhost, 10);
    }

    /// The same-host early-return. When same-host triggers, `check`
    /// returns BEFORE updating `prev_addr` or the all-host bucket.
    ///
    /// Observable effect: once same-host triggers, the attacker's burst
    /// stops ticking all-host. The all-host bucket can leak. A legit
    /// different host arriving 1+ sec later might get through.
    ///
    /// Trace (all conns at t=0 unless noted):
    /// - conn 1 (A): prev=None, no match. sh=0. ah=1.
    /// - conn 2..9 (A): prev=A, match. sh ticks: 1,2,...,8. ah: 2..9.
    /// - conn 10 (A): sh=9. ah=10, >=10, PITTED by all-host. ah clamped
    ///   at 10. `prev_addr` was updated (`prev_sa` update is BEFORE the
    ///   all-host check, AFTER the same-host check).
    /// - conn 11 (A): sh=10. >10? no. ah: 10-0+1=11, >=10, PITTED by
    ///   all-host. Clamped at 10 again.
    /// - conn 12 (A): sh=11. >10? YES. PITTED BY SAME-HOST. Early
    ///   return: ah stays at 10, `prev_addr` stays A.
    /// - conn 13 (A): sh=12. Same-host pit again. ah STILL 10.
    /// - conn 14 (B) at t=2: prev=A, no match. sh stays 12. ah: 10-2=8,
    ///   refill to 9. PASSES.
    ///
    /// Observable difference vs no-early-return: `prev_addr` and
    /// `allhost_time` freeze. A subsequent DIFFERENT host's leak
    /// measures from the last pre-pit allhost timestamp, giving it
    /// MORE leak. This test pins the early-return-skips-allhost shape.
    #[test]
    fn tarpit_samehost_early_return() {
        let t0 = Instant::now();
        let mut tp = Tarpit::new(t0, MAX_BURST);
        let attacker = addr("10.0.0.5", 0);

        // conn 1: prev=None, sh stays 0, ah=1.
        assert!(!tp.check(attacker, t0));
        assert_eq!(tp.buckets(), (0, 1));

        // conns 2..=9: sh and ah both tick. sh: 1..8, ah: 2..9.
        for i in 2..=9 {
            assert!(!tp.check(attacker, t0), "conn {i} passes");
        }
        assert_eq!(tp.buckets(), (8, 9));

        // conn 10: sh=9 (>10? no). ah hits 10, >=10, PIT. Clamp to 10.
        assert!(tp.check(attacker, t0), "conn 10: all-host pit");
        assert_eq!(tp.buckets(), (9, 10));

        // conn 11: sh=10 (>10? no, still pass to ah). ah=10→11→clamp.
        assert!(tp.check(attacker, t0), "conn 11: all-host pit again");
        assert_eq!(tp.buckets(), (10, 10));

        // conn 12: sh=11. >10? YES. SAME-HOST pit. Early return:
        // ah NOT touched.
        assert!(tp.check(attacker, t0), "conn 12: SAME-HOST pit");
        assert_eq!(tp.buckets(), (11, 10), "ah frozen — early return");

        // conn 13..15: same-host keeps firing. ah still frozen.
        for _ in 13..=15 {
            assert!(tp.check(attacker, t0));
        }
        let (sh, ah) = tp.buckets();
        assert_eq!(sh, 14, "sh keeps ticking");
        assert_eq!(ah, 10, "ah STILL frozen — the early-return proof");

        // The observable part: prev_addr is still `attacker` (last update was conn 11,
        // before same-host took over). A different host at t=2:
        // doesn't match prev (good), ah leaks from t=0 (allhost_time
        // also frozen at conn 11's timestamp).
        assert_eq!(tp.prev_addr, Some(attacker), "prev frozen too");
        // allhost_time was last updated at conn 11 (t=0). At t=2,
        // elapsed = 2, ah: 10-2=8, +1 = 9. Passes.
        let legit = addr("10.0.0.200", 0);
        assert!(!tp.check(legit, after(t0, 2)), "legit host passes");
        assert_eq!(tp.buckets().1, 9);
    }

    /// One more bucket-independence proof: alternating hosts. A→B→A→B
    /// never ticks the same-host bucket (each conn's prev is the OTHER
    /// host). Only all-host accumulates.
    ///
    /// This is realistic: a port scanner that walks IPs is caught via
    /// all-host, not same-host.
    #[test]
    fn tarpit_alternating_hosts_only_allhost() {
        let t0 = Instant::now();
        let mut tp = Tarpit::new(t0, MAX_BURST);
        let host_a = addr("10.0.0.1", 0);
        let host_b = addr("10.0.0.2", 0);

        // 9 alternating conns: A,B,A,B,A,B,A,B,A. sh stays 0
        // throughout (prev never matches the CURRENT conn:
        // A→prev=None→no, B→prev=A→no, A→prev=B→no, ...).
        // After conn 9 (A), prev = A.
        for i in 0..9 {
            let h = if i % 2 == 0 { host_a } else { host_b };
            assert!(!tp.check(h, t0));
            assert_eq!(tp.buckets().0, 0, "conn {}: sh stays 0", i + 1);
        }
        assert_eq!(tp.buckets().1, 9);

        // 10th: B (continuing the alternation; i=9 would be odd → B).
        // prev=A≠B, sh stays 0. ah hits 10, pitted by all-host.
        assert!(tp.check(host_b, t0));
        assert_eq!(tp.buckets(), (0, 10), "sh STILL 0; ah triggered");
    }

    /// Drain: wait long enough, bucket empties.
    #[test]
    fn tarpit_drain() {
        let t0 = Instant::now();
        let mut tp = Tarpit::new(t0, MAX_BURST);
        let host_a = addr("10.0.0.1", 0);

        // Fill to 5 (different hosts to avoid samehost interaction).
        for i in 1..=5u8 {
            let a = SocketAddr::V4(SocketAddrV4::new([10, 0, 0, i].into(), 0));
            assert!(!tp.check(a, t0));
        }
        assert_eq!(tp.buckets().1, 5);

        // Wait 5 seconds. Next conn drains 5 (bucket → 0), refills 1.
        assert!(!tp.check(host_a, after(t0, 5)));
        assert_eq!(tp.buckets().1, 1);

        // Wait MORE than the bucket holds. saturating_sub clamps to 0.
        assert!(!tp.check(host_a, after(t0, 100)));
        assert_eq!(tp.buckets().1, 1, "drained to 0, refilled to 1");
    }

    /// `prev_addr` updates regardless of whether check returned true
    /// (the update is before the all-host check). So: a pitted conn
    /// becomes the new prev. Next conn from a DIFFERENT host doesn't
    /// tick samehost.
    #[test]
    fn tarpit_prev_updates_on_pit() {
        let t0 = Instant::now();
        let mut tp = Tarpit::new(t0, MAX_BURST);

        // Fill all-host to threshold.
        for i in 1..=9u8 {
            let a = SocketAddr::V4(SocketAddrV4::new([10, 0, 0, i].into(), 0));
            assert!(!tp.check(a, t0));
        }
        // 10th: pitted. prev becomes 10.0.0.100.
        assert!(tp.check(addr("10.0.0.100", 0), t0));
        assert_eq!(tp.prev_addr, Some(addr("10.0.0.100", 0)));

        // Different host. After 10 sec, all-host drained.
        // Samehost bucket stays at 0 (10.0.0.200 != prev=10.0.0.100).
        let later = after(t0, 10);
        assert!(!tp.check(addr("10.0.0.200", 0), later));
        let (sh, _) = tp.buckets();
        assert_eq!(sh, 0, "different host, samehost untouched");
    }

    /// Same-host check is on `.ip()`, port-agnostic. Different ports
    /// from same IP = same host.
    #[test]
    fn tarpit_ignores_port() {
        let t0 = Instant::now();
        let mut tp = Tarpit::new(t0, MAX_BURST);

        // Seed prev.
        assert!(!tp.check(addr("10.0.0.5", 1000), t0));
        // Same IP, different port. Ticks samehost.
        assert!(!tp.check(addr("10.0.0.5", 2000), after(t0, 1)));
        assert_eq!(tp.buckets().0, 1, "same IP = same host");
    }

    /// v6 addresses too.
    #[test]
    fn tarpit_v6() {
        let t0 = Instant::now();
        let mut tp = Tarpit::new(t0, MAX_BURST);

        // 10 different v6 hosts.
        for i in 1..=9u16 {
            let a = SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, i),
                0,
                0,
                0,
            ));
            assert!(!tp.check(a, t0));
        }
        assert!(tp.check(addr("2001:db8::ffff", 0), t0));
    }

    /// /dev/null fd. Dup'd because we want distinct `OwnedFd`'s that
    /// each genuinely close on drop. `OwnedFd::try_clone` returns a
    /// fresh fd (dup).
    fn nullfd() -> OwnedFd {
        std::fs::File::open("/dev/null").unwrap().into()
    }

    /// The ring wraps at 10. 11th eviction closes the 1st.
    /// We can't observe "fd closed" directly without leaking
    /// implementation details, but we CAN verify the cursor wraps
    /// and no panic occurs.
    #[test]
    fn pit_ring_wrap() {
        let t0 = Instant::now();
        let mut tp = Tarpit::new(t0, MAX_BURST);

        // Fill all 10 slots.
        for _ in 0..PIT_SIZE {
            tp.pit(nullfd());
        }
        assert_eq!(tp.next_pit, 0, "wrapped");
        // All slots Some.
        assert!(tp.pits.iter().all(Option::is_some));

        // 11th evicts slot 0 (the OLD fd drops here).
        tp.pit(nullfd());
        assert_eq!(tp.next_pit, 1);
    }

    /// Drop closes everything. We can verify the drop actually runs
    /// by counting open fds before/after, but that's brittle (other
    /// tests in the same process open fds). Instead: verify the
    /// destructure doesn't panic. The actual close is `OwnedFd`'s
    /// contract (which std tests).
    #[test]
    fn pit_drop_is_clean() {
        let t0 = Instant::now();
        let mut tp = Tarpit::new(t0, MAX_BURST);
        for _ in 0..5 {
            tp.pit(nullfd());
        }
        drop(tp);
        // No panic. OwnedFd dropped 5 fds.
    }
}
