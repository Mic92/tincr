//! `REQ_LOG` log tap and the runtime debug level.
//!
//! The `log::Log` impl runs on whatever thread logs (event loop, shard
//! workers, script/DNS/portmap threads), so tapped records go into one
//! global bounded queue the event loop drains each turn. Overflow drops
//! records and reports how many were lost.
//!
//! `tinc debug N` must take effect at runtime, so unless `RUST_LOG` names
//! its own filter the inner `env_logger` is built at Trace and [`SINK`]
//! gates what reaches stderr or the logfile.

#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::mem;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, AtomicUsize, Ordering};

/// Gate. `enabled()` checks this before formatting.
static LOG_TAP_ACTIVE: AtomicBool = AtomicBool::new(false);

/// The tinc-style debug level (0..=5+). Separate from the filter because
/// the mapping is lossy (1 and 2 both → Debug). `REQ_SET_DEBUG` replies
/// with the exact previous value.
static DEBUG_LEVEL: AtomicI32 = AtomicI32::new(0);

/// `LevelFilter as usize` for the stderr/logfile sink.
static SINK: AtomicUsize = AtomicUsize::new(log::LevelFilter::Trace as usize);

/// Records waiting for the event loop, and how many overflowed.
static TAP: Mutex<VecDeque<(log::Level, String)>> = Mutex::new(VecDeque::new());
static DROPPED: AtomicU64 = AtomicU64::new(0);
const TAP_CAP: usize = 4096;

/// The CLI (Rust and C) ends the session on a record over this.
pub const MAX_RECORD: usize = 1024;

const FILTERS: [log::LevelFilter; 6] = [
    log::LevelFilter::Off,
    log::LevelFilter::Error,
    log::LevelFilter::Warn,
    log::LevelFilter::Info,
    log::LevelFilter::Debug,
    log::LevelFilter::Trace,
];

fn sink() -> log::LevelFilter {
    FILTERS
        .get(SINK.load(Ordering::Relaxed))
        .copied()
        .unwrap_or(log::LevelFilter::Trace)
}

/// tinc `debug_level` → `log::LevelFilter`. Same mapping as
/// `main.rs::debug_level_to_filter`.
const fn level_to_filter(d: i32) -> log::LevelFilter {
    match d {
        ..=0 => log::LevelFilter::Info,
        1 | 2 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    }
}

fn refresh_max_level() {
    let tap = if LOG_TAP_ACTIVE.load(Ordering::Relaxed) {
        log::LevelFilter::Trace
    } else {
        log::LevelFilter::Off
    };
    log::set_max_level(sink().max(tap));
}

/// Seed the C-style debug level for `REQ_SET_DEBUG` readback.
pub fn init_debug_level(level: i32) {
    DEBUG_LEVEL.store(level, Ordering::Relaxed);
}

#[must_use]
pub fn debug_level() -> i32 {
    DEBUG_LEVEL.load(Ordering::Relaxed)
}

/// Set the debug level and sink filter, return the previous level.
/// Negative only queries.
pub fn set_debug_level(new_level: i32) -> i32 {
    let prev = DEBUG_LEVEL.load(Ordering::Relaxed);
    if new_level >= 0 {
        DEBUG_LEVEL.store(new_level, Ordering::Relaxed);
        SINK.store(level_to_filter(new_level) as usize, Ordering::Relaxed);
        refresh_max_level();
    }
    prev
}

/// Wraps `env_logger::Logger`, gated by [`SINK`], and tees to the tap.
struct TapLogger {
    inner: env_logger::Logger,
}

impl log::Log for TapLogger {
    fn enabled(&self, m: &log::Metadata<'_>) -> bool {
        (m.level() <= sink() && self.inner.enabled(m)) || LOG_TAP_ACTIVE.load(Ordering::Relaxed)
    }

    fn log(&self, r: &log::Record<'_>) {
        if r.level() <= sink() {
            self.inner.log(r);
        }
        if LOG_TAP_ACTIVE.load(Ordering::Relaxed) {
            push(
                r.level(),
                format!("{:5} {}: {}", r.level(), r.target(), r.args()),
            );
        }
    }

    fn flush(&self) {
        self.inner.flush();
    }
}

fn push(level: log::Level, mut msg: String) {
    if msg.len() > MAX_RECORD {
        let mut cut = MAX_RECORD;
        while !msg.is_char_boundary(cut) {
            cut -= 1;
        }
        msg.truncate(cut);
    }
    let Ok(mut q) = TAP.lock() else { return };
    if q.len() >= TAP_CAP {
        DROPPED.fetch_add(1, Ordering::Relaxed);
        return;
    }
    q.push_back((level, msg));
}

/// Install the tap logger. `sink` is the initial stderr/logfile level.
///
/// # Panics
/// As `env_logger::Builder::init`: called twice or another logger installed.
#[expect(clippy::expect_used, reason = "documented panic, same as env_logger")]
pub fn init(inner: env_logger::Logger, sink: log::LevelFilter) {
    SINK.store(sink as usize, Ordering::Relaxed);
    log::set_boxed_logger(Box::new(TapLogger { inner }))
        .expect("log_tap::init called after logger already set");
    refresh_max_level();
}

/// Take the queued records, plus a note if any were dropped.
#[must_use]
pub fn drain() -> Vec<(log::Level, String)> {
    let mut out: Vec<_> = TAP
        .lock()
        .map(|mut q| mem::take(&mut *q).into())
        .unwrap_or_default();
    let dropped = DROPPED.swap(0, Ordering::Relaxed);
    if dropped > 0 {
        out.push((
            log::Level::Warn,
            format!("WARN  tincd: log tap dropped {dropped} records"),
        ));
    }
    out
}

/// Open the gate on the first `REQ_LOG`, close it with the last.
pub fn set_active(on: bool) {
    LOG_TAP_ACTIVE.store(on, Ordering::Relaxed);
    if !on && let Ok(mut q) = TAP.lock() {
        q.clear();
    }
    refresh_max_level();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    /// One test owns the global queue: order, truncation, overflow and
    /// records from another thread.
    #[test]
    fn push_and_drain() {
        push(log::Level::Info, "hello".into());
        thread::spawn(|| push(log::Level::Debug, "world".into()))
            .join()
            .unwrap();
        push(log::Level::Info, "é".repeat(MAX_RECORD));
        let d = drain();
        assert_eq!(d.len(), 3);
        assert_eq!(d[0], (log::Level::Info, "hello".to_string()));
        assert_eq!(d[1], (log::Level::Debug, "world".to_string()));
        assert_eq!(d[2].1.len(), MAX_RECORD);
        assert!(drain().is_empty());

        for _ in 0..TAP_CAP + 3 {
            push(log::Level::Info, String::new());
        }
        let d = drain();
        assert_eq!(d.len(), TAP_CAP + 1);
        assert!(
            d[TAP_CAP].1.contains("dropped 3 records"),
            "{:?}",
            d[TAP_CAP]
        );
    }

    /// `set_active` flips the atomic. The integration test (stop.rs)
    /// proves the full path through the global logger.
    #[test]
    fn gate_toggles() {
        // Don't actually call set_active(true) here: it bumps the
        // GLOBAL max_level which other tests might observe. Just
        // check the atomic directly.
        assert!(!LOG_TAP_ACTIVE.load(Ordering::Relaxed));
        LOG_TAP_ACTIVE.store(true, Ordering::Relaxed);
        assert!(LOG_TAP_ACTIVE.load(Ordering::Relaxed));
        LOG_TAP_ACTIVE.store(false, Ordering::Relaxed);
    }

    /// `set_debug_level`: stores the i32, returns previous, respects
    /// `LOG_TAP_ACTIVE`. We DON'T assert on `log::max_level()` here:
    /// it's process-global and tests race (same problem as
    /// `gate_toggles` above). The atomic + return value are local.
    #[test]
    fn debug_level_roundtrip() {
        // Snapshot+restore: DEBUG_LEVEL is a process global; other
        // tests don't touch it but be defensive.
        let saved = DEBUG_LEVEL.load(Ordering::Relaxed);

        DEBUG_LEVEL.store(0, Ordering::Relaxed);
        // Set 5 → returns previous (0).
        assert_eq!(set_debug_level(5), 0);
        assert_eq!(debug_level(), 5);
        // Negative → query-only; returns 5, doesn't change.
        assert_eq!(set_debug_level(-1), 5);
        assert_eq!(debug_level(), 5);
        // Set 2 → returns 5.
        assert_eq!(set_debug_level(2), 5);
        assert_eq!(debug_level(), 2);

        DEBUG_LEVEL.store(saved, Ordering::Relaxed);
    }

    #[test]
    fn level_to_filter_mapping() {
        // Same shape as main.rs::debug_level_to_filter.
        assert_eq!(level_to_filter(-1), log::LevelFilter::Info);
        assert_eq!(level_to_filter(0), log::LevelFilter::Info);
        assert_eq!(level_to_filter(1), log::LevelFilter::Debug);
        assert_eq!(level_to_filter(2), log::LevelFilter::Debug);
        assert_eq!(level_to_filter(3), log::LevelFilter::Trace);
        assert_eq!(level_to_filter(5), log::LevelFilter::Trace);
    }
}
