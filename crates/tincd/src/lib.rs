//! tincd library crate. The binary `main.rs` is a thin entry point;
//! all the daemon logic lives here so integration tests can construct
//! a `Daemon` directly.
//!
//! ## Event dispatch
//!
//! `tinc-event` is generic over `W: Copy`. The daemon's `IoWhat` has
//! six variants for six C callbacks. `ConnId` is a generational
//! `slotmap::DefaultKey`; `conns.get(id)` returning `None` for a
//! reused slot replaces C's `linux/event.c:141` generation guard.
//!
//! ## Logger mapping
//!
//! C `logger(DEBUG_TOPIC, LOG_PRIORITY, ...)` has two axes; the `log`
//! crate has `target=` and `Level`. `LOG_NOTICE` collapses into
//! `Info`. `RUST_LOG=tincd::meta=debug` ≈ `tincd -d4`.
//!
//! | C topic | `log` target | C priority | `log::Level` |
//! |---|---|---|---|
//! | `DEBUG_ALWAYS` | `"tincd"` | `LOG_ERR` | `Error` |
//! | `DEBUG_CONNECTIONS` | `"tincd::conn"` | `LOG_WARNING` | `Warn` |
//! | `DEBUG_PROTOCOL` | `"tincd::proto"` | `LOG_NOTICE` | `Info` |
//! | `DEBUG_META` | `"tincd::meta"` | `LOG_INFO` | `Info` |
//! | `DEBUG_TRAFFIC` | `"tincd::route"` | `LOG_DEBUG` | `Debug` |

#![deny(unsafe_code)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown)]

pub mod addrcache;
pub mod conn;
pub mod control;
pub mod daemon;
pub mod graph_glue;
pub mod keys;
pub mod listen;
pub mod packet;
pub mod proto;
pub mod seen;
pub mod subnet_tree;

pub use daemon::{Daemon, DaemonSettings, RunOutcome};
