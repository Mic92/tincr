//! Event loop scaffolding — ports `event.c` + `linux/event.c` + `signal.c`.
//!
//! # Design: dispatch enum, not callbacks
//!
//! The C API is `io_add(&io, cb, data, fd, flags)` where `cb` is a fn
//! pointer and `data` is `void*`. The callbacks reach `node_tree`,
//! `connection_list`, etc. via globals.
//!
//! Rust can't store `fn(&mut Daemon)` in a struct that lives inside
//! `Daemon` — that's a self-borrow. Options were:
//!
//! 1. **Dispatch enum.** The cb set is closed (6 io callbacks, 7 timer
//!    callbacks across all of `src/`). Encode them as an enum; the loop
//!    body is a `match`. No fn pointers, no boxing.
//! 2. `Box<dyn FnMut(&mut Daemon)>` per slot — doesn't work, the
//!    closure captures nothing useful (can't borrow `Daemon`).
//! 3. Loop produces `Vec<Ready>`, drains after — what (1) becomes
//!    when you notice the cb set is closed.
//!
//! We do (1). [`EventLoop`] is generic over `W: Copy` (the "what"
//! payload). The daemon defines `enum IoWhat`/`enum TimerWhat` and
//! does the match. This crate stays daemon-agnostic.
//!
//! # The generation guard (`linux/event.c:141-149`)
//!
//! C bumps `io_tree.generation` on every `io_del`/`io_set(0)` and
//! bails the dispatch loop if it changed mid-batch. The bug-class:
//! `cb()` calls `io_del()` on a *different* fd that's already in this
//! batch's `events[]` — next iteration reads freed memory.
//!
//! With `Slab<IoSlot<W>>` + `Token = slab key`, the failure mode is
//! token reuse not UAF, but the bug is the same. We don't port the
//! generation counter. Instead each event is checked at dispatch:
//! `slab.get(token)` returns `None` if the slot was removed; if the
//! slot exists but its interest no longer includes the readiness we
//! got, the event is stale and skipped. mio is level-triggered — a
//! stale READ for a slot just reregistered to WRITE-only is harmless
//! to drop; epoll will re-report it next round if still readable.
//!
//! That's WEAKER than C's bail-the-batch but CORRECT. C bails because
//! it can't distinguish "this slot was removed" from "any slot was
//! removed" (no per-slot check, just a global generation). We can
//! distinguish, so we keep going. More events processed per wake.
//!
//! # C-is-WRONG #5: `linux/event.c:121` NULL deref
//!
//! `timeout_execute` returns `NULL` when `timeout_tree` is empty.
//! `event_select.c:98` passes it straight to `select(..., NULL)`
//! (block forever — correct). `linux/event.c:121` does
//! `tv->tv_sec * 1000` — segfault. Masked by `net.c:489-492` arming
//! `pingtimer` + `periodictimer` before `event_loop()` runs. Same
//! bug-class as `fd_device.c:73`: works because the caller is nice.
//!
//! [`EventLoop::turn`] takes `Option<Duration>` and passes it through
//! to `mio::Poll::poll`. `None` = block forever. No deref.
//!
//! # Timer wheel: `BTreeMap`, not `BinaryHeap`
//!
//! The 7 timer callbacks across `src/` are all *re-armable*. The C
//! protocol (`event.c:127-129`): cb runs, may call `timeout_set` to
//! re-arm to a future time, then `timeout_execute` checks
//! `timercmp(&timeout->tv, &now, <)` — if cb re-armed, comparison
//! fails, timer stays in the tree. If cb didn't re-arm, comparison
//! passes, `timeout_del`.
//!
//! `BinaryHeap<(Instant, TimerId)>` makes re-arm awkward: heap entries
//! are immutable, so re-arm = push-new + tombstone-old. `BTreeMap`
//! supports remove-mutate-reinsert in O(log n) — same as the C splay.
//! Key is `(Instant, u64)` where `u64` is a monotonic tiebreak (does
//! what `event.c:62-72`'s pointer-compare does, but stably).
//!
//! # `now`: cached, not `Instant::now()` per call
//!
//! C `event.c:24` `struct timeval now` is updated once per
//! `timeout_execute` (`gettimeofday` at `:117`). All timer comparisons
//! within one loop iteration use the same `now`. We do the same:
//! [`EventLoop::tick`] caches `Instant::now()` once and reuses it.
//! This isn't an optimization; it's correctness. `timeout_set(tv)`
//! computes `tv + now` (`event.c:97`) — if a cb that fires at T
//! re-arms with `+1s`, the new deadline is `T + 1s`, not
//! `(T + cb_runtime) + 1s`. Rate-based timers depend on this.

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
