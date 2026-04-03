//! Event loop scaffolding — ports `event.c` + `linux/event.c` + `signal.c`.
//!
//! The C API is fn-pointer + `void*` callbacks that reach daemon state
//! via globals. That doesn't translate (storing `fn(&mut Daemon)` inside
//! `Daemon` is a self-borrow), so [`EventLoop`] / [`Timers`] are generic
//! over a `W: Copy` dispatch tag instead. The daemon defines
//! `enum IoWhat` / `enum TimerWhat`; [`EventLoop::turn`] and
//! [`Timers::tick`] drain ready events into a `Vec<W>`; the daemon
//! `match`es. This crate stays daemon-agnostic.
//!
//! [`EventLoop::turn`] is **one** poll iteration. The `while running`
//! loop is the caller's. `EINTR` returns `Ok(())` with an empty out
//! buffer so that loop re-checks its flag (the [`SelfPipe`] handler
//! wrote a byte; it's readable next turn).
//!
//! [`Timers`] caches `Instant::now()` once per [`tick`](Timers::tick),
//! and [`set`](Timers::set) computes deadlines against that cache, not
//! a fresh clock read. This is correctness, not optimisation: a timer
//! that fires at `T` and re-arms with `+1s` gets deadline `T + 1s`,
//! not `(T + cb_runtime) + 1s`. Rate-based timers depend on it.
//!
//! See [`EventLoop::turn`] for the generation-guard substitute and the
//! [`Timers`] field docs for why `BTreeMap` over `BinaryHeap`.

#![deny(unsafe_code)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown)]

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
/// `epoll_wait` `maxevents` cap. mio's `Events::with_capacity` is the
/// same knob.
pub const MAX_EVENTS_PER_TURN: usize = 32;
