//! A clock that keeps running across suspend. `Instant` stops on Linux
//! (`CLOCK_MONOTONIC`) and macOS (`CLOCK_UPTIME_RAW`), so it can't see
//! how long the host slept.

use std::time::Duration;

use nix::time::{ClockId, clock_gettime};

#[cfg(any(target_os = "linux", target_os = "android"))]
const CLOCK: ClockId = ClockId::CLOCK_BOOTTIME;
// Darwin's CLOCK_MONOTONIC counts sleep. Elsewhere, wall time as C tinc.
#[cfg(target_vendor = "apple")]
const CLOCK: ClockId = ClockId::CLOCK_MONOTONIC;
#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
const CLOCK: ClockId = ClockId::CLOCK_REALTIME;

/// Time since an arbitrary epoch, suspend included. Only differences
/// are meaningful.
pub(crate) fn boottime() -> Duration {
    clock_gettime(CLOCK).map_or(Duration::ZERO, Duration::from)
}
