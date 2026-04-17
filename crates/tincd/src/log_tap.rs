//! `REQ_LOG` log tap. In the log write hook, walk conns with
//! `status.log`, send each log line over the ctl socket.
//!
//! ## The interception problem
//!
//! C hooks into its own `logger()` macro. We use `log::info!` etc.
//! The `log::Log` impl runs at the call site (any module's `info!`);
//! the conns are in `Daemon`'s `&mut self`. The `'static` logger
//! can't reach in directly.
//!
//! What makes this cheap: **the daemon is single-threaded**. Every `log::info!` happens INSIDE `daemon.run()`'s
//! event loop, on the same thread, in the middle of some handler.
//!
//! So the tap doesn't need synchronization. The `log::Log` impl
//! pushes to a thread-local buffer; the daemon drains it once per
//! event-loop turn. The buffer is shared-static but never contended.
//!
//! ## Perf
//!
//! - **No log conns** (steady state): one Relaxed atomic load per
//!   `log::*!` call, BEFORE format. The `log::log!` macro calls
//!   `enabled()` first and only evaluates `format_args!` if that
//!   returns true — the format is the expensive part.
//! - **Log conn exists**: per log line, one `to_string()` format
//!   (unavoidable — C does `vsnprintf` into a buffer too) + Vec
//!   push. Drained once per event-loop turn. `mem::take` leaves
//!   capacity.
//! - **No mutex**: `thread_local!` + `RefCell`. Never contended
//!   because single-threaded.
//!
//! ## Re-entrancy
//!
//! An `info!` whose args trigger another `info!` would double-borrow
//! the `RefCell` and panic. Doesn't happen — our log formatting is
//! plain values, no method calls that log. If it ever does, the
//! panic is loud and points here.

#![forbid(unsafe_code)]

use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

/// Gate. `enabled()` checks this BEFORE formatting.
static LOG_TAP_ACTIVE: AtomicBool = AtomicBool::new(false);

/// The tinc-style debug level (0..=5+). Separate from
/// `log::max_level()` because the tinc↔Rust mapping is
/// lossy (1 and 2 both → Debug). Stored so `REQ_SET_DEBUG` can
/// reply with the exact previous value.
static DEBUG_LEVEL: AtomicI32 = AtomicI32::new(0);

/// tinc `debug_level` → `log::LevelFilter`. Same mapping as
/// `main.rs::debug_level_to_filter` (5-line dup — the binary
/// doesn't dep on this module's internals).
const fn level_to_filter(d: i32) -> log::LevelFilter {
    match d {
        ..=0 => log::LevelFilter::Info,
        1 | 2 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    }
}

/// Seed the C-style debug level. main.rs calls this once after
/// `init()`. Does NOT touch `log::max_level()`: `init()` already
/// set it from `inner.filter()`, which reflects `RUST_LOG`. Calling
/// `set_debug_level` here would clobber that (`RUST_LOG=debug` + no
/// `-d` flag → we'd reset `max_level` back to Info).
pub fn init_debug_level(level: i32) {
    DEBUG_LEVEL.store(level, Ordering::Relaxed);
}

/// Read the current tinc-style debug level. For `REQ_SET_DEBUG`'s
/// "reply with previous level".
#[must_use]
pub fn debug_level() -> i32 {
    DEBUG_LEVEL.load(Ordering::Relaxed)
}

/// Set the debug level. Updates both the stored i32 (for readback)
/// and `log::max_level()` (the actual gate). Negative = no-op
/// (query-only). Returns the PREVIOUS level.
///
/// Interaction with `set_active`: `REQ_LOG` already bumps
/// `max_level` to Trace. If a log conn is active and someone does
/// `tinc debug 0`, we'd lower `max_level` back to Info, breaking
/// the log tap. Check `LOG_TAP_ACTIVE` and don't lower below Trace
/// if it's set.
pub fn set_debug_level(new_level: i32) -> i32 {
    let prev = DEBUG_LEVEL.load(Ordering::Relaxed);
    if new_level >= 0 {
        DEBUG_LEVEL.store(new_level, Ordering::Relaxed);
        let filter = level_to_filter(new_level);
        // Don't drop below Trace if a REQ_LOG conn is tapping.
        // log_tap::set_active(true) sets Trace and expects it to
        // stay. REQ_SET_DEBUG to a lower level would otherwise
        // silence the tap mid-stream.
        if !LOG_TAP_ACTIVE.load(Ordering::Relaxed) || filter >= log::LevelFilter::Trace {
            log::set_max_level(filter);
        }
    }
    prev
}

thread_local! {
    /// Tap buffer. `RefCell` because single-threaded; the `log::Log`
    /// impl is `Sync` per the trait bound, but we only ever call it
    /// from the daemon thread. `thread_local!` makes the type system
    /// see this without a mutex.
    static TAP: RefCell<Vec<(log::Level, String)>> = const { RefCell::new(Vec::new()) };
}

/// Wraps `env_logger::Logger`. Forwards everything to the inner
/// logger; ADDITIONALLY pushes to `TAP` when the gate is open.
struct TapLogger {
    inner: env_logger::Logger,
}

impl log::Log for TapLogger {
    fn enabled(&self, m: &log::Metadata<'_>) -> bool {
        // Short-circuit: if neither stderr nor the tap wants it,
        // skip the format entirely. The format is the expensive part.
        // The `log::log!` macro calls this BEFORE evaluating
        // `format_args!`; returning `false` here means the args
        // (which may include `Display` impls) never execute.
        self.inner.enabled(m) || LOG_TAP_ACTIVE.load(Ordering::Relaxed)
    }

    fn log(&self, r: &log::Record<'_>) {
        // env_logger does its own `matches()` check inside (filter
        // by target etc), so unconditional forward is correct.
        self.inner.log(r);

        if LOG_TAP_ACTIVE.load(Ordering::Relaxed) {
            // Format ONCE, push. Daemon drains per-turn. Prefix
            // with level + target so `tinc log 5` on a busy mesh
            // is grep-able rather than an undifferentiated wall;
            // the CLI side prints the body verbatim. No timestamp:
            // the tap drains once per event-loop turn so a
            // wall-clock stamp here would be misleadingly precise,
            // and the operator's terminal/journal already stamps
            // arrival.
            TAP.with_borrow_mut(|v| {
                v.push((
                    r.level(),
                    format!("{:5} {}: {}", r.level(), r.target(), r.args()),
                ));
            });
        }
    }

    fn flush(&self) {
        self.inner.flush();
    }
}

/// Install the tap logger as the global logger. Replaces the usual
/// `builder.init()`. Called once from `main.rs::init_logging`.
///
/// `max_level` is computed from the inner logger's filter. With no
/// log conns, that's the floor: `log::log!` checks `max_level()`
/// FIRST (before `enabled()`), so a `trace!` with stderr at `Info`
/// is zero-cost — the macro doesn't even reach our `enabled()`.
///
/// When a log conn arrives, `set_active(true)` ALSO bumps
/// `max_level` to `Trace` so `enabled()` gets called for everything.
/// Dropped back when the last log conn leaves.
///
/// # Panics
/// Same as `env_logger::Builder::init`: called twice, or another
/// logger already installed.
pub fn init(inner: env_logger::Logger) {
    let max_level = inner.filter();
    log::set_boxed_logger(Box::new(TapLogger { inner }))
        .expect("log_tap::init called after logger already set");
    log::set_max_level(max_level);
}

/// Drain the tap buffer. Called once per event-loop turn from
/// `daemon.rs::run`. `mem::take` leaves the Vec's capacity so the
/// next turn doesn't re-allocate.
#[must_use]
pub fn drain() -> Vec<(log::Level, String)> {
    TAP.with_borrow_mut(std::mem::take)
}

/// Gate control. Daemon calls `set_active(true)` when the first
/// `REQ_LOG` arrives, `set_active(false)` when the last log conn
/// disconnects.
///
/// `on=true` also raises `max_level` to `Trace` so the `log!` macro
/// reaches our `enabled()`. `on=false` does NOT lower it back: we
/// don't know what the inner filter wanted, and the cost is one
/// `enabled()` call per log macro (which short-circuits on the
/// atomic). The next `set_active(true)/false` cycle costs nothing
/// extra. Simpler than caching the inner level.
pub fn set_active(on: bool) {
    LOG_TAP_ACTIVE.store(on, Ordering::Relaxed);
    if on {
        log::set_max_level(log::LevelFilter::Trace);
    }
}

/// Test-only: push a record directly to `TAP` without going through
/// the global logger (which is a process singleton; tests would
/// stomp each other). Same code path as `TapLogger::log`'s push.
#[cfg(test)]
fn push_for_test(level: log::Level, msg: &str) {
    TAP.with_borrow_mut(|v| v.push((level, msg.to_string())));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Push then drain. Order preserved (Vec). `mem::take` clears.
    #[test]
    fn push_and_drain() {
        push_for_test(log::Level::Info, "hello");
        push_for_test(log::Level::Debug, "world");

        let d = drain();
        assert_eq!(d.len(), 2);
        assert_eq!(d[0], (log::Level::Info, "hello".to_string()));
        assert_eq!(d[1], (log::Level::Debug, "world".to_string()));

        // Drained: next drain is empty.
        assert!(drain().is_empty());
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
