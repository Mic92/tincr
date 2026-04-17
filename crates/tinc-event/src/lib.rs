//! Daemon-agnostic event-loop scaffolding: an [`EventLoop`] for I/O
//! readiness, a [`Timers`] wheel for deadlines, and a [`SelfPipe`] for
//! waking the loop from signal handlers.
//!
//! Both [`EventLoop`] and [`Timers`] are generic over a `W: Copy`
//! dispatch tag chosen by the caller — typically a small enum like
//! `IoWhat` / `TimerWhat` — so the crate never reaches into daemon
//! state. [`EventLoop::turn`] runs a single poll iteration, draining
//! ready events into a `Vec<W>` for the caller to match on, and
//! quietly returns empty on `EINTR` so the outer `while running` loop
//! can re-check its flag after a signal.
//!
//! [`Timers`] caches `Instant::now()` once per [`tick`](Timers::tick)
//! and computes new deadlines against that cached instant rather than
//! against a fresh clock read, so a timer that fires at `T` and
//! re-arms with `+1s` always lands at `T + 1s` instead of drifting by
//! the callback's runtime — rate-based timers rely on this.

#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

mod io;
mod timer;

#[cfg(unix)]
mod sig;

pub use io::{EventLoop, Io, IoId, Ready};
pub use timer::{TimerId, Timers};

#[cfg(unix)]
pub use sig::SelfPipe;

/// Maximum events processed per `turn()`. Ports `MAX_EVENTS_PER_LOOP`
/// from `net.h:31`. The C comment doesn't explain it; it's just the
/// `epoll_wait` `maxevents` cap. `Vec::with_capacity` in
/// `EventLoop::new` sets the same knob.
pub const MAX_EVENTS_PER_TURN: usize = 32;
