//! PMTU discovery (`net_packet.c:90-240, 1170-1460`).
//!
//! Per-node binary search for the largest UDP datagram that fits
//! without fragmentation. The `mtuprobes` integer encodes a
//! 5-phase state machine; the probe sizes follow an exponential
//! that front-loads near-typical-MTU sizes (1329, then 1407 —
//! `net_packet.c:1417-1424` "math simulations").
//!
//! ## State machine
//!
//! | `mtuprobes` | Phase | Tick action |
//! |---|---|---|
//! | `0..19` | Discovery | 8-probe burst, exponential offsets |
//! | `20` | Fix | `mtu := minmtu`, → `-1` |
//! | `-1` | Steady | Probe `maxmtu` and `maxmtu+1` every `pinginterval` |
//! | `-2..=-3` | Re-validate | One `maxmtu` probe/sec |
//! | `-4` | Lost | Reset → `0` |
//!
//! Events: `Tick` (driven by `try_tx`, ~1/sec), `ProbeReply{len}`,
//! `Emsgsize{at_len}`. Actions: `SendProbe{len}`,
//! `LogFixed{mtu, after_probes}`, `LogReset`.
//!
//! ## Divergence from C
//!
//! C `try_mtu`'s `for(;;)` loop (`:1412-1450`) sends a probe and
//! synchronously observes EMSGSIZE shrinking `maxmtu` mid-call,
//! then recomputes and retries in the same tick. We don't have
//! that synchronous feedback (the daemon sends later); instead
//! `tick()` returns ONE probe, `on_emsgsize()` recomputes bounds,
//! and the *next* `tick()` uses the new bounds. Slightly slower
//! convergence on the first cycle, identical outcome.

#![forbid(unsafe_code)]

use std::time::{Duration, Instant};

/// `net.h:36` — 1500 bytes payload + 14 ethernet + 4 VLAN.
pub const MTU: u16 = 1518;
/// `net.h:39` — below this we don't consider UDP to be working.
pub const MINMTU: u16 = 512;
/// `net_packet.c:62` — eth header (14) + 4 random bytes.
pub const MIN_PROBE_SIZE: u16 = 18;

/// `net_packet.c:1415`.
const PROBES_PER_CYCLE: u32 = 8;

/// Per-node PMTU discovery state. Embedded in `TunnelState` by
/// the daemon. Fields mirror
/// `node_t.{mtu,minmtu,maxmtu,mtuprobes,udp_ping_sent,...}`.
#[derive(Debug)]
pub struct PmtuState {
    pub mtu: u16,
    pub minmtu: u16,
    pub maxmtu: u16,
    pub mtuprobes: i32,
    pub udp_confirmed: bool,
    /// `node_status_t::ping_sent` — a UDP-discovery probe is in
    /// flight; the next reply is the one we time RTT against.
    pub ping_sent: bool,
    pub udp_ping_sent: Instant,
    pub mtu_ping_sent: Instant,
    pub maxrecentlen: u16,
    /// RTT in microseconds; -1 = unknown (`node.c` init).
    pub udp_ping_rtt: i32,
}

/// Action emitted by the state machine for the daemon to dispatch.
#[derive(Debug, PartialEq, Eq)]
pub enum PmtuAction {
    /// `send_udp_probe_packet(n, len)` (`net_packet.c:1175-1195`).
    /// Daemon builds a `len`-byte SPTPS record with byte[0]=0
    /// (request marker), bytes[1..14]=0, bytes[14..len]=random,
    /// and sends via the tunnel's SPTPS. `len` is already clamped
    /// to `>= MIN_PROBE_SIZE`.
    SendProbe { len: u16 },

    /// `:103-104` log: "Fixing MTU of %s to %d after %d probes".
    LogFixed { mtu: u16, probes: i32 },

    /// `:1390` log: "Decrease in PMTU detected, restarting".
    LogReset,

    /// `:220` log: "Increase in PMTU detected, restarting".
    LogIncrease,
}

impl PmtuState {
    /// Init state. C `node.c` zeros the struct then sets
    /// `n->maxmtu = MTU`, `n->udp_ping_rtt = -1`.
    ///
    /// `initial_maxmtu` — the daemon may pre-seed this with the
    /// kernel's PMTU cache (`choose_initial_maxmtu`,
    /// `net_packet.c:1249-1340` — `getsockopt(IP_MTU)` minus
    /// IP/UDP/SPTPS overhead). `STUB(chunk-9b)` for the syscall;
    /// for now pass `MTU`, the C fallback. Discovery still
    /// converges, just from scratch.
    #[must_use]
    pub fn new(now: Instant, initial_maxmtu: u16) -> Self {
        Self {
            mtu: 0,
            minmtu: 0,
            maxmtu: initial_maxmtu,
            mtuprobes: 0,
            udp_confirmed: false,
            ping_sent: false,
            udp_ping_sent: now,
            mtu_ping_sent: now,
            maxrecentlen: 0,
            udp_ping_rtt: -1,
        }
    }

    /// `try_mtu` (`net_packet.c:1346-1458`) + `try_fix_mtu`
    /// (`:90-107`). Advance the state machine by one tick. `now`
    /// gates the cadence (333ms during discovery, `pinginterval`
    /// during steady-state, 1s during re-validate). Returns probes
    /// to send.
    ///
    /// Preconditions handled by the caller (the daemon's
    /// `try_mtu` wrapper): `OPTION_PMTU_DISCOVERY` is set, and if
    /// `udp_discovery` is on then `udp_confirmed` is true. The
    /// `:1358-1364` reset for the not-confirmed case is the
    /// caller's responsibility (it's identical to
    /// `on_udp_timeout`).
    pub fn tick(&mut self, now: Instant, pinginterval: Duration) -> Vec<PmtuAction> {
        // ── Cadence gate ───── net_packet.c:1372-1386 ──────────
        let elapsed = now.duration_since(self.mtu_ping_sent);
        if self.mtuprobes >= 0 {
            // Discovery: 333ms between probes (after the first).
            // C: `elapsed.tv_sec == 0 && tv_usec < 333333`. The
            // tv_sec==0 check means anything ≥1s passes; we
            // approximate with 333ms straight.
            if self.mtuprobes != 0 && elapsed < Duration::from_micros(333_333) {
                return vec![];
            }
        } else if self.mtuprobes < -1 {
            // Re-validate: 1 probe/sec.
            if elapsed < Duration::from_secs(1) {
                return vec![];
            }
        } else {
            // Steady (-1): 1 probe pair/pinginterval.
            if elapsed < pinginterval {
                return vec![];
            }
        }

        self.mtu_ping_sent = now;

        let mut out = Vec::new();

        // ── try_fix_mtu ──── net_packet.c:1389 → :90-107 ───────
        self.try_fix_mtu(&mut out);

        // ── Lost-reprobes reset ──── :1391-1396 ────────────────
        if self.mtuprobes < -3 {
            out.push(PmtuAction::LogReset);
            self.mtuprobes = 0;
            self.minmtu = 0;
        }

        // ── Steady / re-validate branch ──── :1398-1406 ────────
        if self.mtuprobes < 0 {
            // Send maxmtu, and at -1 also maxmtu+1 (PMTU-increase
            // detector). Then decrement: -1→-2, -2→-3, -3→-4.
            // A maxmtu-sized reply rewinds to -1 (on_probe_reply).
            out.push(PmtuAction::SendProbe {
                len: self.maxmtu.max(MIN_PROBE_SIZE),
            });
            if self.mtuprobes == -1 && self.maxmtu + 1 < MTU {
                out.push(PmtuAction::SendProbe {
                    len: self.maxmtu + 1,
                });
            }
            self.mtuprobes -= 1;
            return out;
        }

        // ── Discovery branch ──── :1407-1455 ───────────────────
        // C re-seeds maxmtu at probe 0 via choose_initial_maxmtu.
        // We took the seed in `new()`; nothing to do here.
        //
        // C's for(;;) sends, observes synchronous EMSGSIZE
        // shrinking maxmtu, recomputes, retries. We send ONE.
        let len = probe_size(self.minmtu, self.maxmtu, self.mtuprobes);
        out.push(PmtuAction::SendProbe {
            len: len.max(MIN_PROBE_SIZE),
        });
        self.mtuprobes += 1;
        out
    }

    /// `udp_probe_h` reply branch (`net_packet.c:196-238`). Called
    /// when a type-1 or type-2 PROBE reply arrives (the daemon
    /// has already extracted the type-2 length-in-packet at
    /// `:177-182`). Updates `minmtu`, confirms UDP, records RTT.
    ///
    /// Side effects the daemon does itself: address-cache update
    /// (`:203-209`), UDP-timeout-timer reset (`:213-217`).
    pub fn on_probe_reply(&mut self, len: u16, now: Instant) -> Vec<PmtuAction> {
        let mut out = Vec::new();

        // ── RTT measurement ──── :184-194 ──────────────────────
        if self.ping_sent {
            let rtt = now.duration_since(self.udp_ping_sent);
            // C: tv_sec * 1_000_000 + tv_usec, into a signed int.
            // Saturate at i32::MAX (~35 min — never happens).
            self.udp_ping_rtt = i32::try_from(rtt.as_micros()).unwrap_or(i32::MAX);
            self.ping_sent = false;
        }

        // ── UDP confirmed ──── :199-210 ────────────────────────
        // (address-cache work is the daemon's job)
        self.udp_confirmed = true;

        // ── PMTU-increase detector ──── :219-225 ───────────────
        // A reply *larger* than maxmtu means the path opened up:
        // restart discovery from this new floor. mtuprobes := 1
        // (not 0) so the C-side maxmtu re-seed doesn't undo this.
        if len > self.maxmtu {
            out.push(PmtuAction::LogIncrease);
            self.minmtu = len;
            self.maxmtu = MTU;
            self.mtuprobes = 1;
            return out;
        }

        // ── Steady-state confirmation ──── :226-230 ────────────
        // A maxmtu-sized reply during steady/re-validate confirms
        // PMTU is still good; rewind the lost-probe counter.
        if self.mtuprobes < 0 && len == self.maxmtu {
            self.mtuprobes = -1;
            self.mtu_ping_sent = now;
        }

        // ── Raise minmtu ──── :234-237 ─────────────────────────
        if self.minmtu < len {
            self.minmtu = len;
            self.try_fix_mtu(&mut out);
        }

        out
    }

    /// `reduce_mtu` (`net_packet.c:109-122`). EMSGSIZE on UDP
    /// send: cap `maxmtu` and `mtu` to one less than the failed
    /// size. May converge if minmtu meets the new ceiling.
    pub fn on_emsgsize(&mut self, at_len: u16) -> Vec<PmtuAction> {
        // C callers pass `len - 1` already; we take the failed
        // size and subtract here for a cleaner API. Floor at
        // MINMTU (`:110-112`).
        let mtu = at_len.saturating_sub(1).max(MINMTU);
        if self.maxmtu > mtu {
            self.maxmtu = mtu;
        }
        if self.mtu > mtu {
            self.mtu = mtu;
        }
        let mut out = Vec::new();
        self.try_fix_mtu(&mut out);
        out
    }

    /// `udp_probe_timeout_handler` (`net_packet.c:124-137`).
    /// UDP-silence timeout: clear `udp_confirmed`, reset bounds.
    /// Idempotent on already-unconfirmed (`:127-129`).
    pub fn on_udp_timeout(&mut self) {
        if !self.udp_confirmed {
            return;
        }
        self.udp_confirmed = false;
        self.udp_ping_rtt = -1;
        self.maxrecentlen = 0;
        self.mtuprobes = 0;
        self.minmtu = 0;
        self.maxmtu = MTU;
    }

    /// `try_fix_mtu` (`net_packet.c:90-107`). The "lock in"
    /// decision. Either we've sent 20 probes (timeout — settle for
    /// what we've got) or `minmtu` reached `maxmtu` (converged).
    fn try_fix_mtu(&mut self, out: &mut Vec<PmtuAction>) {
        if self.mtuprobes < 0 {
            return;
        }
        if self.mtuprobes == 20 || self.minmtu >= self.maxmtu {
            // Snap the bounds together (whichever way is needed).
            if self.minmtu > self.maxmtu {
                self.minmtu = self.maxmtu;
            } else {
                self.maxmtu = self.minmtu;
            }
            self.mtu = self.minmtu;
            out.push(PmtuAction::LogFixed {
                mtu: self.mtu,
                probes: self.mtuprobes,
            });
            self.mtuprobes = -1;
        }
    }
}

/// `net_packet.c:1424-1440`: the exponential probe-size formula.
/// Separate fn for testability.
///
/// Why exponential, not linear: most probes that are too large
/// vanish silently (no ICMP, no nothing). So we *concentrate*
/// probes near `minmtu` — small offsets where replies actually
/// happen — and spend few probes on the long tail near `maxmtu`.
/// As `minmtu` rises with each reply, the search window shrinks
/// and the next exponential lands tighter. The last probe of each
/// 8-cycle is always `minmtu+1`: a guaranteed reply, guaranteed
/// progress (`:1438-1439`).
///
/// The 0.97 multiplier (only when `maxmtu == MTU`) is hand-tuned
/// (`:1417-1424` "math simulations"): probe #0 lands at 1329,
/// and *if that gets a reply*, probe #1 (with the raised minmtu)
/// lands at 1407 — "just below the range of tinc MTUs over typical
/// networks". Two probes, done.
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
fn probe_size(minmtu: u16, maxmtu: u16, mtuprobes: i32) -> u16 {
    let multiplier: f32 = if maxmtu == MTU { 0.97 } else { 1.0 };

    // C: `probes_per_cycle - (mtuprobes % probes_per_cycle) - 1`.
    // Counts DOWN from 7 to 0 within each 8-probe cycle.
    // mtuprobes is non-negative here (discovery branch only).
    #[allow(clippy::cast_sign_loss)]
    let cycle_position =
        PROBES_PER_CYCLE as f32 - (mtuprobes as u32 % PROBES_PER_CYCLE) as f32 - 1.0;

    let minmtu_eff = minmtu.max(MINMTU);
    let interval = f32::from(maxmtu.saturating_sub(minmtu_eff));

    // C `:1432`: guard against powf underflow when maxmtu < MINMTU.
    let offset: u16 = if interval > 0.0 {
        let exp = multiplier * cycle_position / (PROBES_PER_CYCLE - 1) as f32;
        // lrintf — round-to-nearest-int. f32::round matches.
        interval.powf(exp).round() as u16
    } else {
        0
    };

    minmtu_eff + offset
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t0() -> Instant {
        Instant::now()
    }

    // ─── probe_size formula ────────────────────────────────────

    #[test]
    fn probe_size_first_is_1329() {
        // mtuprobes=0 → cycle_position=7. minmtu=0 → eff=512.
        // interval=1006, offset=round(1006^0.97)≈817. 512+817≈1329.
        // C's comment says 1329; f32 lrintf rounding may yield ±1.
        let p = probe_size(0, MTU, 0);
        assert!((1329..=1330).contains(&p), "got {p}");
    }

    #[test]
    fn probe_size_second_is_1407() {
        // After a reply at 1329, minmtu=1329. mtuprobes=1 →
        // cycle_position=6. interval=189,
        // offset=round(189^(0.97·6/7))≈78. 1329+78=1407.
        assert_eq!(probe_size(1329, MTU, 1), 1407);
    }

    #[test]
    fn probe_size_last_is_min_plus_1() {
        // mtuprobes=7 → cycle_position=0 → interval^0=1.
        // The "guaranteed reply" smallest probe of the cycle.
        assert_eq!(probe_size(0, MTU, 7), MINMTU + 1);
        assert_eq!(probe_size(1000, MTU, 7), 1001);
    }

    #[test]
    fn probe_size_maxmtu_not_1518_multiplier_1() {
        // maxmtu != MTU → multiplier=1.0 → first probe is exactly
        // maxmtu (interval^1). This is the fast path: if
        // choose_initial_maxmtu got it right, one probe confirms.
        // minmtu=0→eff=512, interval=888, offset=888, →1400.
        assert_eq!(probe_size(0, 1400, 0), 1400);
    }

    #[test]
    fn probe_size_interval_zero() {
        // maxmtu <= minmtu_eff: offset=0. (try_fix_mtu would have
        // already converged, but the formula must not blow up.)
        assert_eq!(probe_size(0, 400, 0), MINMTU);
    }

    // ─── tick: discovery ───────────────────────────────────────

    #[test]
    fn tick_discovery_advances_mtuprobes() {
        let now = t0();
        let mut s = PmtuState::new(now, MTU);
        let out = s.tick(now, Duration::from_secs(60));
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0], PmtuAction::SendProbe { len } if (1329..=1330).contains(&len)));
        assert_eq!(s.mtuprobes, 1);
    }

    #[test]
    fn tick_gated_by_333ms() {
        let now = t0();
        let mut s = PmtuState::new(now, MTU);
        s.tick(now, Duration::from_secs(60));
        // 100ms later: gated.
        let out = s.tick(now + Duration::from_millis(100), Duration::from_secs(60));
        assert!(out.is_empty());
        assert_eq!(s.mtuprobes, 1);
        // 400ms later: fires.
        let out = s.tick(now + Duration::from_millis(400), Duration::from_secs(60));
        assert_eq!(out.len(), 1);
        assert_eq!(s.mtuprobes, 2);
    }

    #[test]
    fn tick_at_20_fixes() {
        let now = t0();
        let mut s = PmtuState::new(now, MTU);
        s.mtuprobes = 19;
        s.minmtu = 1400;
        // First tick: probe #19, mtuprobes → 20. (Advance past the
        // 333ms gate since mtuprobes != 0.)
        let out = s.tick(now + Duration::from_secs(1), Duration::from_secs(60));
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0], PmtuAction::SendProbe { .. }));
        assert_eq!(s.mtuprobes, 20);
        // Second tick: try_fix_mtu fires (mtuprobes==20).
        let out = s.tick(now + Duration::from_secs(2), Duration::from_secs(60));
        assert_eq!(s.mtu, 1400);
        assert_eq!(s.maxmtu, 1400);
        assert_eq!(s.mtuprobes, -2); // -1 from fix, then -- from steady branch
        // LogFixed first, then a steady-state SendProbe (maxmtu).
        assert!(out.contains(&PmtuAction::LogFixed {
            mtu: 1400,
            probes: 20
        }));
    }

    // ─── on_probe_reply ────────────────────────────────────────

    #[test]
    fn on_probe_reply_raises_minmtu() {
        let now = t0();
        let mut s = PmtuState::new(now, MTU);
        s.minmtu = 1000;
        let out = s.on_probe_reply(1200, now);
        assert!(out.is_empty());
        assert_eq!(s.minmtu, 1200);
        assert!(s.udp_confirmed);
    }

    #[test]
    fn on_probe_reply_early_converge() {
        let now = t0();
        let mut s = PmtuState::new(now, 1400);
        s.minmtu = 1000;
        // Reply at maxmtu: minmtu rises to meet it → fix.
        let out = s.on_probe_reply(1400, now);
        assert_eq!(
            out,
            vec![PmtuAction::LogFixed {
                mtu: 1400,
                probes: 0
            }]
        );
        assert_eq!(s.mtu, 1400);
        assert_eq!(s.mtuprobes, -1);
    }

    #[test]
    fn on_probe_reply_increase_detected() {
        let now = t0();
        let mut s = PmtuState::new(now, MTU);
        s.maxmtu = 1400;
        s.minmtu = 1400;
        s.mtu = 1400;
        s.mtuprobes = -1;
        // The maxmtu+1 probe got through!
        let out = s.on_probe_reply(1401, now);
        assert_eq!(out, vec![PmtuAction::LogIncrease]);
        assert_eq!(s.minmtu, 1401);
        assert_eq!(s.maxmtu, MTU);
        assert_eq!(s.mtuprobes, 1);
    }

    #[test]
    fn on_probe_reply_steady_confirm_rewinds() {
        let now = t0();
        let mut s = PmtuState::new(now, MTU);
        s.maxmtu = 1400;
        s.minmtu = 1400;
        s.mtuprobes = -3; // two re-probes lost
        let out = s.on_probe_reply(1400, now + Duration::from_secs(5));
        assert!(out.is_empty());
        assert_eq!(s.mtuprobes, -1);
        assert_eq!(s.mtu_ping_sent, now + Duration::from_secs(5));
    }

    #[test]
    fn on_probe_reply_records_rtt() {
        let now = t0();
        let mut s = PmtuState::new(now, MTU);
        s.ping_sent = true;
        s.udp_ping_sent = now;
        s.on_probe_reply(800, now + Duration::from_millis(42));
        assert_eq!(s.udp_ping_rtt, 42_000);
        assert!(!s.ping_sent);
    }

    // ─── on_emsgsize ───────────────────────────────────────────

    #[test]
    fn on_emsgsize_caps_maxmtu() {
        let now = t0();
        let mut s = PmtuState::new(now, MTU);
        s.mtu = 1500;
        let out = s.on_emsgsize(1450);
        assert!(out.is_empty());
        assert_eq!(s.maxmtu, 1449);
        assert_eq!(s.mtu, 1449);
    }

    #[test]
    fn on_emsgsize_floors_at_minmtu() {
        let now = t0();
        let mut s = PmtuState::new(now, MTU);
        let _ = s.on_emsgsize(100);
        assert_eq!(s.maxmtu, MINMTU);
    }

    #[test]
    fn on_emsgsize_can_converge() {
        let now = t0();
        let mut s = PmtuState::new(now, MTU);
        s.minmtu = 1400;
        // EMSGSIZE at 1401 → maxmtu=1400 → minmtu==maxmtu → fix.
        let out = s.on_emsgsize(1401);
        assert_eq!(
            out,
            vec![PmtuAction::LogFixed {
                mtu: 1400,
                probes: 0
            }]
        );
        assert_eq!(s.mtu, 1400);
    }

    // ─── steady state & reset ──────────────────────────────────

    #[test]
    fn steady_state_probes_maxmtu_plus_one() {
        let now = t0();
        let mut s = PmtuState::new(now, MTU);
        s.mtu = 1400;
        s.minmtu = 1400;
        s.maxmtu = 1400;
        s.mtuprobes = -1;
        s.mtu_ping_sent = now;
        // Gated by pinginterval.
        let out = s.tick(now + Duration::from_secs(30), Duration::from_secs(60));
        assert!(out.is_empty());
        // After pinginterval: maxmtu + maxmtu+1.
        let out = s.tick(now + Duration::from_secs(61), Duration::from_secs(60));
        assert_eq!(
            out,
            vec![
                PmtuAction::SendProbe { len: 1400 },
                PmtuAction::SendProbe { len: 1401 },
            ]
        );
        assert_eq!(s.mtuprobes, -2);
    }

    #[test]
    fn steady_state_at_mtu_no_plus_one() {
        // maxmtu+1 >= MTU: skip the +1 probe (no point probing
        // beyond the protocol ceiling). C `:1402`.
        let now = t0();
        let mut s = PmtuState::new(now, MTU);
        s.maxmtu = MTU - 1;
        s.minmtu = MTU - 1;
        s.mtuprobes = -1;
        let out = s.tick(now + Duration::from_secs(61), Duration::from_secs(60));
        assert_eq!(out, vec![PmtuAction::SendProbe { len: MTU - 1 }]);
    }

    #[test]
    fn four_lost_reprobes_reset() {
        let now = t0();
        let mut s = PmtuState::new(now, MTU);
        s.mtu = 1400;
        s.minmtu = 1400;
        s.maxmtu = 1400;
        s.mtuprobes = -1;
        s.udp_confirmed = true;
        let pi = Duration::from_secs(60);
        // Tick 1 (after pinginterval): -1 → -2.
        s.tick(now + Duration::from_secs(61), pi);
        assert_eq!(s.mtuprobes, -2);
        // Tick 2 (1s later): -2 → -3.
        s.tick(now + Duration::from_secs(62), pi);
        assert_eq!(s.mtuprobes, -3);
        // Tick 3: -3 → -4.
        s.tick(now + Duration::from_secs(63), pi);
        assert_eq!(s.mtuprobes, -4);
        // Tick 4: mtuprobes < -3 → reset.
        let out = s.tick(now + Duration::from_secs(64), pi);
        assert!(out.contains(&PmtuAction::LogReset));
        // After reset: mtuprobes was set to 0, minmtu=0, then the
        // discovery branch ran one probe → mtuprobes=1.
        assert_eq!(s.mtuprobes, 1);
        assert_eq!(s.minmtu, 0);
        // maxmtu is NOT reset by C's :1391-1396 — only minmtu.
        // (It's reset by on_udp_timeout, the harsher event.)
        assert_eq!(s.maxmtu, 1400);
    }

    // ─── on_udp_timeout ────────────────────────────────────────

    #[test]
    fn on_udp_timeout_resets() {
        let now = t0();
        let mut s = PmtuState::new(now, MTU);
        s.udp_confirmed = true;
        s.mtu = 1400;
        s.minmtu = 1400;
        s.maxmtu = 1400;
        s.mtuprobes = -1;
        s.maxrecentlen = 1200;
        s.udp_ping_rtt = 42_000;
        s.on_udp_timeout();
        assert!(!s.udp_confirmed);
        assert_eq!(s.udp_ping_rtt, -1);
        assert_eq!(s.maxrecentlen, 0);
        assert_eq!(s.mtuprobes, 0);
        assert_eq!(s.minmtu, 0);
        assert_eq!(s.maxmtu, MTU);
        // mtu itself is NOT reset (C `:124-137` doesn't touch it).
        assert_eq!(s.mtu, 1400);
    }

    #[test]
    fn on_udp_timeout_idempotent_when_unconfirmed() {
        let now = t0();
        let mut s = PmtuState::new(now, MTU);
        s.maxmtu = 1400; // distinct value to detect mutation
        s.on_udp_timeout();
        assert_eq!(s.maxmtu, 1400); // untouched
    }
}
