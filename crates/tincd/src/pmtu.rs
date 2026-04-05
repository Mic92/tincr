//! PMTU discovery.
//!
//! Per-node binary search for the largest UDP datagram that fits
//! without fragmentation. The `mtuprobes` integer encodes a 5-phase
//! state machine via sign+magnitude; here that's [`PmtuPhase`]. The
//! probe sizes follow an exponential that front-loads
//! near-typical-MTU sizes (1329, then 1407 — "math simulations").
//!
//! ## State machine
//!
//! | `mtuprobes` | [`PmtuPhase`] | Tick action |
//! |---|---|---|
//! | `0..19` | `Discovery{sent}` | 8-probe burst, exponential offsets |
//! | `20` | `Fix` | `mtu := minmtu`, → `Steady` |
//! | `-1` | `Steady` | Probe `maxmtu` and `maxmtu+1` every `pinginterval` |
//! | `-2..=-3` | `Revalidate{misses}` | One `maxmtu` probe/sec |
//! | `-4` | `Lost` | Reset → `Discovery{0}` |
//!
//! Events: `Tick` (driven by `try_tx`, ~1/sec), `ProbeReply{len}`,
//! `Emsgsize{at_len}`. Actions: `SendProbe{len}`,
//! `LogFixed{mtu, after_probes}`, `LogReset`.
//!
//! ## Divergence from C
//!
//! `try_mtu`'s `for(;;)` loop sends a probe and synchronously
//! observes EMSGSIZE shrinking `maxmtu` mid-call, then recomputes
//! and retries in the same tick. We don't have
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
/// eth header (14) + 4 random bytes.
pub const MIN_PROBE_SIZE: u16 = 18;

const PROBES_PER_CYCLE: u32 = 8;

/// PMTU discovery phase. Replaces `node_t.mtuprobes` (i32) where
/// sign+magnitude select the phase.
///
/// `mtu`/`minmtu`/`maxmtu` stay flat on [`PmtuState`] (orthogonal
/// to phase — the same `minmtu` raise can happen in Discovery or
/// Revalidate).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PmtuPhase {
    /// `mtuprobes ∈ 0..19`. `sent` = probes sent so far; also
    /// the input to the exponential probe-size formula (cycle
    /// position = `sent % 8`).
    Discovery { sent: u8 },
    /// `mtuprobes == 20`. Next `tick()` locks `mtu := minmtu`
    /// and goes to `Steady`. Distinct from `Discovery{20}` because
    /// `try_fix_mtu` runs at the *top* of the tick, before the
    /// discovery branch would send probe #20.
    Fix,
    /// `mtuprobes == -1`. Probe `maxmtu` (+ `maxmtu+1` increase
    /// detector) every `pinginterval`.
    Steady,
    /// `mtuprobes ∈ -2..=-3`. `misses` = unanswered steady-state
    /// probes (1 or 2). One `maxmtu` probe/sec.
    Revalidate { misses: u8 },
    /// `mtuprobes == -4`. Next `tick()` resets to `Discovery{0}`.
    Lost,
}

impl PmtuPhase {
    /// `mtuprobes == 0`: discovery hasn't sent its first probe.
    /// `txpath.rs` uses this to gate the maxmtu re-seed
    /// (`choose_initial_maxmtu`).
    #[must_use]
    pub const fn is_discovery_start(&self) -> bool {
        matches!(self, Self::Discovery { sent: 0 })
    }

    /// `mtuprobes < 0`: MTU already fixed (steady/revalidate/lost).
    #[must_use]
    pub const fn is_fixed(&self) -> bool {
        matches!(self, Self::Steady | Self::Revalidate { .. } | Self::Lost)
    }
}

/// Per-node PMTU state. Mirrors `node_t.{mtu,minmtu,maxmtu,mtuprobes,...}`.
#[derive(Debug)]
pub struct PmtuState {
    pub mtu: u16,
    pub minmtu: u16,
    pub maxmtu: u16,
    pub phase: PmtuPhase,
    pub udp_confirmed: bool,
    /// `node_status_t::ping_sent` — next reply is the RTT measurement.
    pub ping_sent: bool,
    pub udp_ping_sent: Instant,
    pub mtu_ping_sent: Instant,
    pub maxrecentlen: u16,
    /// RTT µs; `None` = unknown (`node.c` init: `-1`).
    pub udp_ping_rtt: Option<u32>,
}

/// Action emitted by the state machine for the daemon to dispatch.
#[derive(Debug, PartialEq, Eq)]
pub enum PmtuAction {
    /// `send_udp_probe_packet`. `len` already clamped to
    /// `>= MIN_PROBE_SIZE`.
    SendProbe { len: u16 },

    /// `:103-104` log: "Fixing MTU of %s to %d after %d probes".
    /// `probes` = how many discovery probes were sent before
    /// converging (0..=20; 20 = timeout).
    LogFixed { mtu: u16, probes: u8 },

    /// `:1390` log: "Decrease in PMTU detected, restarting".
    LogReset,

    /// `:220` log: "Increase in PMTU detected, restarting".
    LogIncrease,
}

impl PmtuState {
    /// Zeroed struct, `maxmtu = MTU`, `udp_ping_rtt = -1`.
    ///
    /// `initial_maxmtu`: from `choose_initial_maxmtu`
    /// (`getsockopt(IP_MTU)`). With it, PMTU converges in ~1 RTT.
    /// Without it (kernel lacks `IP_MTU`, or `socket()/connect()`
    /// fails), pass `MTU` and convergence takes ~10 probes (~3.3s at
    /// 333ms cadence) — `dispatch_route_result` gates the frag-needed
    /// check on `via_mtu != 0` during that window so we don't send
    /// bogus ICMP claiming MTU 576.
    /// (That ICMP poisoned the kernel's per-dst PMTU cache for 10
    /// minutes)
    #[must_use]
    pub const fn new(now: Instant, initial_maxmtu: u16) -> Self {
        Self {
            mtu: 0,
            minmtu: 0,
            maxmtu: initial_maxmtu,
            phase: PmtuPhase::Discovery { sent: 0 },
            udp_confirmed: false,
            ping_sent: false,
            udp_ping_sent: now,
            mtu_ping_sent: now,
            maxrecentlen: 0,
            udp_ping_rtt: None,
        }
    }

    /// `mtuprobes := 0` — restart discovery from scratch. Used by
    /// `tunnel.rs::reset_unreachable` and `on_udp_timeout`.
    pub const fn start_discovery(&mut self) {
        self.phase = PmtuPhase::Discovery { sent: 0 };
    }

    /// `try_mtu` + `try_fix_mtu`. Cadence: 333ms discovery, `pinginterval` steady, 1s re-validate.
    ///
    /// Caller handles preconditions: `OPTION_PMTU_DISCOVERY` set,
    /// `udp_confirmed` if `udp_discovery` on. The `:1358-1364` reset
    /// for not-confirmed is `on_udp_timeout`.
    pub fn tick(&mut self, now: Instant, pinginterval: Duration) -> Vec<PmtuAction> {
        // ── Cadence gate ──────────────────────────────────────
        let elapsed = now.duration_since(self.mtu_ping_sent);
        match self.phase {
            PmtuPhase::Discovery { sent } => {
                // 333ms (C: tv_sec==0 && tv_usec<333333). First probe
                // (sent==0) is ungated.
                if sent != 0 && elapsed < Duration::from_micros(333_333) {
                    return vec![];
                }
            }
            // Fix gates as Discovery (mtuprobes >= 0); sent != 0 here.
            PmtuPhase::Fix => {
                if elapsed < Duration::from_micros(333_333) {
                    return vec![];
                }
            }
            PmtuPhase::Steady => {
                // 1/pinginterval.
                if elapsed < pinginterval {
                    return vec![];
                }
            }
            PmtuPhase::Revalidate { .. } | PmtuPhase::Lost => {
                // 1/sec.
                if elapsed < Duration::from_secs(1) {
                    return vec![];
                }
            }
        }

        self.mtu_ping_sent = now;

        let mut out = Vec::new();

        // ── try_fix_mtu ───────────────────────────────────────
        self.try_fix_mtu(&mut out);

        // ── Lost-reprobes reset ───────────────────────────────
        // `if (mtuprobes < -3)`. After try_fix_mtu we might have
        // just transitioned Fix→Steady; check phase fresh.
        if self.phase == PmtuPhase::Lost {
            out.push(PmtuAction::LogReset);
            self.phase = PmtuPhase::Discovery { sent: 0 };
            self.minmtu = 0;
        }

        // ── Steady / re-validate branch ───────────────────────
        // `if (mtuprobes < 0)`. Probe maxmtu, in Steady also
        // maxmtu+1 (increase detector). Then "decrement"; a maxmtu
        // reply rewinds to Steady (on_probe_reply).
        match self.phase {
            PmtuPhase::Steady => {
                out.push(PmtuAction::SendProbe {
                    len: self.maxmtu.max(MIN_PROBE_SIZE),
                });
                if self.maxmtu + 1 < MTU {
                    out.push(PmtuAction::SendProbe {
                        len: self.maxmtu + 1,
                    });
                }
                // `mtuprobes--`: -1 → -2.
                self.phase = PmtuPhase::Revalidate { misses: 1 };
            }
            PmtuPhase::Revalidate { misses } => {
                out.push(PmtuAction::SendProbe {
                    len: self.maxmtu.max(MIN_PROBE_SIZE),
                });
                // `mtuprobes--`: -2→-3, -3→-4.
                self.phase = if misses >= 2 {
                    PmtuPhase::Lost
                } else {
                    PmtuPhase::Revalidate { misses: misses + 1 }
                };
            }
            // Lost was reset above; Fix was consumed by try_fix_mtu.
            PmtuPhase::Lost | PmtuPhase::Fix => unreachable!(),
            PmtuPhase::Discovery { sent } => {
                // ── Discovery branch ──── :1407-1455 ───────────────
                // C re-seeds maxmtu via choose_initial_maxmtu; we did in new().
                // C's for(;;) observes synchronous EMSGSIZE; we send ONE.
                let len = probe_size(self.minmtu, self.maxmtu, sent);
                out.push(PmtuAction::SendProbe {
                    len: len.max(MIN_PROBE_SIZE),
                });
                // `mtuprobes++`: 19→20 = Fix.
                self.phase = if sent + 1 >= 20 {
                    PmtuPhase::Fix
                } else {
                    PmtuPhase::Discovery { sent: sent + 1 }
                };
            }
        }
        out
    }

    /// `udp_probe_h` reply branch. Daemon already extracted type-2
    /// length. Daemon-side: address-cache, UDP-timeout reset.
    pub fn on_probe_reply(&mut self, len: u16, now: Instant) -> Vec<PmtuAction> {
        let mut out = Vec::new();

        // ── RTT measurement ──── :184-194 ──────────────────────
        if self.ping_sent {
            let rtt = now.duration_since(self.udp_ping_sent);
            // Saturate at u32::MAX (~71 min — never happens).
            self.udp_ping_rtt = Some(u32::try_from(rtt.as_micros()).unwrap_or(u32::MAX));
            self.ping_sent = false;
        }

        // ── UDP confirmed ──── :199-210 ────────────────────────
        self.udp_confirmed = true;

        // ── PMTU-increase detector. `mtuprobes := 1` (not 0) so
        // the maxmtu re-seed doesn't undo this.
        if len > self.maxmtu {
            out.push(PmtuAction::LogIncrease);
            self.minmtu = len;
            self.maxmtu = MTU;
            self.phase = PmtuPhase::Discovery { sent: 1 };
            return out;
        }

        // ── Steady-state confirmation ────────────────────────
        // `if (mtuprobes < 0 && len == maxmtu) mtuprobes = -1`.
        if self.phase.is_fixed() && len == self.maxmtu {
            self.phase = PmtuPhase::Steady;
            self.mtu_ping_sent = now;
        }

        // ── Raise minmtu ──── :234-237 ─────────────────────────
        if self.minmtu < len {
            self.minmtu = len;
            self.try_fix_mtu(&mut out);
        }

        out
    }

    /// `reduce_mtu`. EMSGSIZE: cap maxmtu/mtu.
    pub fn on_emsgsize(&mut self, at_len: u16) -> Vec<PmtuAction> {
        // Upstream callers pass len-1; we take failed size. Floor at MINMTU.
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

    /// `udp_probe_timeout_handler`. Idempotent on already-unconfirmed.
    pub const fn on_udp_timeout(&mut self) {
        if !self.udp_confirmed {
            return;
        }
        self.udp_confirmed = false;
        self.udp_ping_rtt = None;
        self.maxrecentlen = 0;
        self.start_discovery();
        self.minmtu = 0;
        self.maxmtu = MTU;
    }

    /// `try_fix_mtu`. Lock in: 20 probes (timeout) or
    /// `minmtu >= maxmtu` (converged).
    ///
    /// `if (mtuprobes < 0) return` → only acts in Discovery/Fix.
    fn try_fix_mtu(&mut self, out: &mut Vec<PmtuAction>) {
        // Only fires when mtuprobes >= 0.
        let probes = match self.phase {
            PmtuPhase::Discovery { sent } => sent,
            PmtuPhase::Fix => 20,
            PmtuPhase::Steady | PmtuPhase::Revalidate { .. } | PmtuPhase::Lost => return,
        };
        // mtuprobes == 20 || minmtu >= maxmtu.
        if matches!(self.phase, PmtuPhase::Fix) || self.minmtu >= self.maxmtu {
            if self.minmtu > self.maxmtu {
                self.minmtu = self.maxmtu;
            } else {
                self.maxmtu = self.minmtu;
            }
            self.mtu = self.minmtu;
            out.push(PmtuAction::LogFixed {
                mtu: self.mtu,
                probes,
            });
            self.phase = PmtuPhase::Steady;
        }
    }
}

/// Exponential probe-size formula.
///
/// Exponential (not linear) because too-large probes vanish silently;
/// concentrate near `minmtu` where replies happen. Last probe per
/// 8-cycle is `minmtu+1` (guaranteed progress, `:1438-1439`).
///
/// 0.97 multiplier (when `maxmtu == MTU`) is hand-tuned (`:1417-1424`
/// "math simulations"): probe #0 → 1329, then probe #1 → 1407 —
/// "just below typical tinc MTUs". Two probes, done.
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
fn probe_size(minmtu: u16, maxmtu: u16, sent: u8) -> u16 {
    let multiplier: f32 = if maxmtu == MTU { 0.97 } else { 1.0 };

    // Counts down 7→0 per 8-cycle.
    let cycle_position =
        PROBES_PER_CYCLE as f32 - (u32::from(sent) % PROBES_PER_CYCLE) as f32 - 1.0;

    let minmtu_eff = minmtu.max(MINMTU);
    let interval = f32::from(maxmtu.saturating_sub(minmtu_eff));

    // :1432 powf underflow guard
    let offset: u16 = if interval > 0.0 {
        let exp = multiplier * cycle_position / (PROBES_PER_CYCLE - 1) as f32;
        interval.powf(exp).round() as u16 // lrintf
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
        // cyc=7, eff=512, interval=1006, offset≈817. C says 1329; ±1 from f32.
        let p = probe_size(0, MTU, 0);
        assert!((1329..=1330).contains(&p), "got {p}");
    }

    #[test]
    fn probe_size_second_is_1407() {
        // minmtu=1329, cyc=6, interval=189, offset≈78.
        assert_eq!(probe_size(1329, MTU, 1), 1407);
    }

    #[test]
    fn probe_size_last_is_min_plus_1() {
        // cyc=0 → interval^0=1. The guaranteed-reply probe.
        assert_eq!(probe_size(0, MTU, 7), MINMTU + 1);
        assert_eq!(probe_size(1000, MTU, 7), 1001);
    }

    #[test]
    fn probe_size_maxmtu_not_1518_multiplier_1() {
        // maxmtu != MTU → mult=1.0 → first probe IS maxmtu. Fast path
        // when choose_initial_maxmtu got it right.
        assert_eq!(probe_size(0, 1400, 0), 1400);
    }

    #[test]
    fn probe_size_interval_zero() {
        // try_fix_mtu would've converged, but formula must not blow up.
        assert_eq!(probe_size(0, 400, 0), MINMTU);
    }

    // ─── tick: discovery ───────────────────────────────────────

    #[test]
    fn tick_discovery_advances_phase() {
        let now = t0();
        let mut s = PmtuState::new(now, MTU);
        let out = s.tick(now, Duration::from_secs(60));
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0], PmtuAction::SendProbe { len } if (1329..=1330).contains(&len)));
        assert_eq!(s.phase, PmtuPhase::Discovery { sent: 1 });
    }

    #[test]
    fn tick_gated_by_333ms() {
        let now = t0();
        let mut s = PmtuState::new(now, MTU);
        s.tick(now, Duration::from_secs(60));
        let out = s.tick(now + Duration::from_millis(100), Duration::from_secs(60));
        assert!(out.is_empty());
        assert_eq!(s.phase, PmtuPhase::Discovery { sent: 1 });
        let out = s.tick(now + Duration::from_millis(400), Duration::from_secs(60));
        assert_eq!(out.len(), 1);
        assert_eq!(s.phase, PmtuPhase::Discovery { sent: 2 });
    }

    #[test]
    fn tick_at_20_fixes() {
        let now = t0();
        let mut s = PmtuState::new(now, MTU);
        s.phase = PmtuPhase::Discovery { sent: 19 };
        s.minmtu = 1400;
        // Probe #19 → Fix.
        let out = s.tick(now + Duration::from_secs(1), Duration::from_secs(60));
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0], PmtuAction::SendProbe { .. }));
        assert_eq!(s.phase, PmtuPhase::Fix);
        // try_fix_mtu fires.
        let out = s.tick(now + Duration::from_secs(2), Duration::from_secs(60));
        assert_eq!(s.mtu, 1400);
        assert_eq!(s.maxmtu, 1400);
        // Fix → Steady (try_fix_mtu), then steady probe → Revalidate{1}.
        assert_eq!(s.phase, PmtuPhase::Revalidate { misses: 1 });
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
        let out = s.on_probe_reply(1400, now);
        assert_eq!(
            out,
            vec![PmtuAction::LogFixed {
                mtu: 1400,
                probes: 0
            }]
        );
        assert_eq!(s.mtu, 1400);
        assert_eq!(s.phase, PmtuPhase::Steady);
    }

    #[test]
    fn on_probe_reply_increase_detected() {
        let now = t0();
        let mut s = PmtuState::new(now, MTU);
        s.maxmtu = 1400;
        s.minmtu = 1400;
        s.mtu = 1400;
        s.phase = PmtuPhase::Steady;
        let out = s.on_probe_reply(1401, now);
        assert_eq!(out, vec![PmtuAction::LogIncrease]);
        assert_eq!(s.minmtu, 1401);
        assert_eq!(s.maxmtu, MTU);
        // `mtuprobes := 1` — skip the maxmtu re-seed.
        assert_eq!(s.phase, PmtuPhase::Discovery { sent: 1 });
    }

    #[test]
    fn on_probe_reply_steady_confirm_rewinds() {
        let now = t0();
        let mut s = PmtuState::new(now, MTU);
        s.maxmtu = 1400;
        s.minmtu = 1400;
        s.phase = PmtuPhase::Revalidate { misses: 2 };
        let out = s.on_probe_reply(1400, now + Duration::from_secs(5));
        assert!(out.is_empty());
        assert_eq!(s.phase, PmtuPhase::Steady);
        assert_eq!(s.mtu_ping_sent, now + Duration::from_secs(5));
    }

    #[test]
    fn on_probe_reply_records_rtt() {
        let now = t0();
        let mut s = PmtuState::new(now, MTU);
        s.ping_sent = true;
        s.udp_ping_sent = now;
        s.on_probe_reply(800, now + Duration::from_millis(42));
        assert_eq!(s.udp_ping_rtt, Some(42_000));
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
        s.phase = PmtuPhase::Steady;
        s.mtu_ping_sent = now;
        let out = s.tick(now + Duration::from_secs(30), Duration::from_secs(60));
        assert!(out.is_empty());
        let out = s.tick(now + Duration::from_secs(61), Duration::from_secs(60));
        assert_eq!(
            out,
            vec![
                PmtuAction::SendProbe { len: 1400 },
                PmtuAction::SendProbe { len: 1401 },
            ]
        );
        assert_eq!(s.phase, PmtuPhase::Revalidate { misses: 1 });
    }

    #[test]
    fn steady_state_at_mtu_no_plus_one() {
        // C :1402: maxmtu+1 >= MTU → skip the +1 probe.
        let now = t0();
        let mut s = PmtuState::new(now, MTU);
        s.maxmtu = MTU - 1;
        s.minmtu = MTU - 1;
        s.phase = PmtuPhase::Steady;
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
        s.phase = PmtuPhase::Steady;
        s.udp_confirmed = true;
        let pi = Duration::from_secs(60);
        s.tick(now + Duration::from_secs(61), pi);
        assert_eq!(s.phase, PmtuPhase::Revalidate { misses: 1 });
        s.tick(now + Duration::from_secs(62), pi);
        assert_eq!(s.phase, PmtuPhase::Revalidate { misses: 2 });
        s.tick(now + Duration::from_secs(63), pi);
        assert_eq!(s.phase, PmtuPhase::Lost);
        // Lost → reset
        let out = s.tick(now + Duration::from_secs(64), pi);
        assert!(out.contains(&PmtuAction::LogReset));
        // Reset to Discovery{0}, then discovery ran one probe → {1}.
        assert_eq!(s.phase, PmtuPhase::Discovery { sent: 1 });
        assert_eq!(s.minmtu, 0);
        // C :1391-1396 does NOT reset maxmtu (on_udp_timeout does).
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
        s.phase = PmtuPhase::Steady;
        s.maxrecentlen = 1200;
        s.udp_ping_rtt = Some(42_000);
        s.on_udp_timeout();
        assert!(!s.udp_confirmed);
        assert_eq!(s.udp_ping_rtt, None);
        assert_eq!(s.maxrecentlen, 0);
        assert_eq!(s.phase, PmtuPhase::Discovery { sent: 0 });
        assert_eq!(s.minmtu, 0);
        assert_eq!(s.maxmtu, MTU);
        assert_eq!(s.mtu, 1400); // C :124-137 doesn't touch mtu
    }

    #[test]
    fn on_udp_timeout_idempotent_when_unconfirmed() {
        let now = t0();
        let mut s = PmtuState::new(now, MTU);
        s.maxmtu = 1400;
        s.on_udp_timeout();
        assert_eq!(s.maxmtu, 1400); // untouched
    }

    // ─── phase helpers ─────────────────────────────────────────

    #[test]
    fn is_discovery_start_only_at_zero() {
        assert!(PmtuPhase::Discovery { sent: 0 }.is_discovery_start());
        assert!(!PmtuPhase::Discovery { sent: 1 }.is_discovery_start());
        assert!(!PmtuPhase::Steady.is_discovery_start());
    }
}
