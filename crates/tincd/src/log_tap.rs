//! `REQ_LOG` log tap. C `logger.c:192-218`: in the log write hook,
//! walk conns with `status.log`, send each log line over the ctl
//! socket.
//!
//! ## The interception problem
//!
//! C hooks into its own `logger()` macro. We use `log::info!` etc.
//! The `log::Log` impl runs at the call site (any module's `info!`);
//! the conns are in `Daemon`'s `&mut self`. The `'static` logger
//! can't reach in directly.
//!
//! What makes this cheap: **the daemon is single-threaded**. The
//! only other thread is the sd_notify watchdog (`8967cb7f`), which
//! doesn't log. Every `log::info!` happens INSIDE `daemon.run()`'s
//! event loop, on the same thread, in the middle of some handler.
//!
//! So the tap doesn't need synchronization. The `log::Log` impl
//! pushes to a thread-local buffer; the daemon drains it once per
//! event-loop turn. The buffer is shared-static but never contended.
//!
//! ## Perf
//!
//! - **No log conns** (steady state): one Relaxed atomic load per
//!   `log::*!` call, BEFORE format. Same overhead as the C global
//!   `if(!logcontrol)` (`logger.c:192`). The `log::log!` macro calls
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
use std::sync::atomic::{AtomicBool, Ordering};

/// Gate. `enabled()` checks this BEFORE formatting. C's
/// `if(!logcontrol)` is the same gate (`logger.c:192`).
static LOG_TAP_ACTIVE: AtomicBool = AtomicBool::new(false);

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
            // Format ONCE, push. Daemon drains per-turn.
            //
            // C `logger.c:197`: `vsnprintf(message, sizeof message,
            // format, ap)` then `:213` send. We don't have access to
            // the env_logger-formatted output (timestamps, level
            // tag); the CLI side (`tincctl.c:658`) just reads raw
            // bytes anyway. The `args()` is the bare message — same
            // as C's `message` buffer pre-`format_pretty`.
            TAP.with_borrow_mut(|v| v.push((r.level(), r.args().to_string())));
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
/// disconnects. Mirrors C's `logcontrol = true/false` recompute-
/// during-walk (`logger.c:195,203`).
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

    /// Gate is off → drain is empty even if something pushed (which
    /// it can't through the real logger, but the daemon might call
    /// drain() before any REQ_LOG arrives).
    #[test]
    fn drain_starts_empty() {
        // thread_local: each test thread gets a fresh TAP.
        let d = drain();
        assert!(d.is_empty());
    }

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
}
