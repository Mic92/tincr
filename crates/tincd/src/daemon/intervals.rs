//! Periodic / retry interval constants.
//!
//! Single place to read the daemon's timing picture. Only re-arm
//! cadences and retry backoffs — user-configurable protocol timeouts
//! (`PingTimeout`, `MACExpire`, …) stay in [`super::settings`].

#![forbid(unsafe_code)]

use std::time::Duration;

// ── main loop timers ────────────────────────────────────────────────

/// `on_ping_tick`: dead-conn sweep + keepalive PING. 1 Hz so a dead
/// peer is noticed within `PingTimeout + 1 s`.
pub(crate) const PING_SWEEP: Duration = Duration::from_secs(1);

/// `on_periodic_tick`: autoconnect / portmap / discovery plumbing.
/// 5 s is the floor; edge-storm backoff (`sleeptime`) raises it.
pub(crate) const PERIODIC_TICK: Duration = Duration::from_secs(5);

/// `on_age_past_requests` / `on_age_subnets` / MAC-lease re-arm.
/// Three independent caches; all cheap O(n) walks.
pub(crate) const HOUSEKEEP_SWEEP: Duration = Duration::from_secs(10);

// ── edge-storm backoff (`sleeptime`) ────────────────────────────────

/// 100+ contradicting `ADD_EDGE` *and* 100+ `DEL_EDGE` in one periodic
/// tick ⇒ two daemons fighting over the same edge. Throttle.
pub(crate) const EDGE_STORM_THRESHOLD: u32 = 100;
/// `sleeptime` doubles on each storm tick, capped here (1 h).
pub(crate) const SLEEPTIME_MAX: u32 = 3600;
/// `sleeptime` halves on each calm tick, floored here.
pub(crate) const SLEEPTIME_MIN: u32 = 10;

// ── SPTPS key request ───────────────────────────────────────────────

/// `try_tx`: `REQ_KEY` sent, no `ANS_KEY` after this long → tear down
/// half-open SPTPS and resend. Checked on next outbound packet, not
/// timer-driven.
pub(crate) const REQ_KEY_RETRY: Duration = Duration::from_secs(10);

// ── PMTU probe burst ────────────────────────────────────────────────

/// `PmtuState::tick` discovery phase: 3 probes/sec (1 s / 3).
pub(crate) const PMTU_PROBE_TICK: Duration = Duration::from_micros(333_333);
/// Revalidate/Lost phases: one probe per second.
pub(crate) const PMTU_REVALIDATE_TICK: Duration = Duration::from_secs(1);

// ── DHT discovery ───────────────────────────────────────────────────

/// `Discovery` publish backoff seed; doubles on failure. Equals
/// [`PERIODIC_TICK`] because that's the poll cadence — anything
/// smaller is unobservable.
pub(crate) const DISCOVERY_BACKOFF_SEED: Duration = PERIODIC_TICK;
