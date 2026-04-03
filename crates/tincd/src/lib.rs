//! tincd library crate. The binary `main.rs` is a thin entry point;
//! all the daemon logic lives here so integration tests can construct
//! a `Daemon` directly.
//!
//! ## Walking-skeleton scope
//!
//! Ports the **control-only** path through:
//!
//! | C | Rust | LOC consumed |
//! |---|---|---|
//! | `pidfile.c::write_pidfile` | `control.rs::write_pidfile` | 13 |
//! | `control.c::init_control` (unix socket bits) | `control.rs::ControlSocket::bind` | 42 |
//! | `control.c::control_h` `REQ_STOP` only | `proto.rs::handle_control` | ~20 |
//! | `protocol_auth.c::id_h` `^` branch only | `proto.rs::handle_id` | 14 |
//! | `protocol.c::receive_request` (no proxy) | `proto.rs::dispatch` | 49 |
//! | `protocol.c::send_request` | `conn.rs::Connection::send` | ~30 |
//! | `meta.c::receive_meta` plaintext path | `conn.rs::Connection::feed` | ~40 of 158 |
//! | `meta.c::send_meta` plaintext path | `conn.rs::Connection::queue` | ~10 of 60 |
//! | `net_socket.c::handle_meta_write` | `conn.rs::Connection::flush` | 26 |
//! | `net_socket.c::handle_new_unix_connection` | `daemon.rs::accept_control` | 31 |
//! | `buffer.c` | `conn.rs::LineBuf` | 110 |
//! | `net.c::main_loop` | `daemon.rs::Daemon::run` | 41 |
//! | `net.c::timeout_handler` (no peers → noop) | `daemon.rs::on_ping_tick` | ~5 stub |
//! | `net.c::sigterm_handler` etc | `daemon.rs::on_signal` | ~10 |
//!
//! Total C LOC traced through: ~440. Rust: see `wc -l` after.
//!
//! ## What's NOT here (deliberate scope cuts)
//!
//! These return when the next chunks land. Tracking them so we don't
//! forget what was excised:
//!
//! - **`listen_sockets`** (`net_setup.c:1180` `if(!listen_sockets) return false`):
//!   skipped entirely. C demands ≥1 TCP+UDP listener; we open zero.
//!   Chunk 3 ports `add_listen_address` + `setup_vpn_in_socket`.
//! - **`setup_myself_reloadable`** (`net_setup.c:252-575`): the 40-knob
//!   settings substruct stays defaulted. `pinginterval=60`,
//!   `pingtimeout=5` are the only two we read.
//! - **`graph()` on `terminate_connection`** (`net.c:135`): no peers,
//!   no edges, so `terminate` is just `conns.remove + io_del`.
//! - **`id_h` peer/invitation branches** (`protocol_auth.c:340-470`):
//!   reject everything that isn't `^<cookie>`.
//! - **`control_h` cases other than `REQ_STOP`**: respond `REQ_INVALID`.
//! - **`device_standby` / `device_enable`**: dummy device has `fd() →
//!   None` so it's never registered with the event loop. The C
//!   `if(device_fd >= 0) io_add(...)` (`net_setup.c:1100`) becomes
//!   `if let Some(fd) = device.fd()`.
//! - **`jitter()`**: timers re-arm with zero jitter. The C `prng(131072)`
//!   adds 0..131ms; without it, all timers in a fleet fire on the same
//!   wall-clock second after a `kill -HUP` to all daemons. Doesn't
//!   matter for one daemon.
//!
//! ## The dispatch enum
//!
//! `tinc-event` is generic over `W: Copy`. The daemon's `IoWhat`:
//!
//! ```ignore
//! enum IoWhat { Signal, UnixListener, Conn(ConnId), Device, Tcp(u8), Udp(u8) }
//! ```
//!
//! Six variants for six C callbacks. `Tcp`/`Udp` are stubs in this
//! chunk (no listeners). `ConnId` is `slotmap::DefaultKey` —
//! generational, can't dangle. The C `linux/event.c:141` generation
//! guard is replaced by `conns.get(id)` returning `None` for a key
//! whose slot was reused.
//!
//! ## Logger mapping
//!
//! C `logger(DEBUG_TOPIC, LOG_PRIORITY, ...)` has TWO axes: topic
//! (filtered by `debug_level` int) and priority (sent to syslog). The
//! `log` crate has `target=` (topic) and `Level` (priority). Mapping:
//!
//! | C topic | `log` target | C priority | `log::Level` |
//! |---|---|---|---|
//! | `DEBUG_ALWAYS` | `"tincd"` | `LOG_ERR` | `Error` |
//! | `DEBUG_CONNECTIONS` | `"tincd::conn"` | `LOG_WARNING` | `Warn` |
//! | `DEBUG_PROTOCOL` | `"tincd::proto"` | `LOG_NOTICE` | `Info` |
//! | `DEBUG_META` | `"tincd::meta"` | `LOG_INFO` | `Info` |
//! | `DEBUG_TRAFFIC` | `"tincd::route"` | `LOG_DEBUG` | `Debug` |
//!
//! `LOG_NOTICE` collapses into `Info` (log crate has no Notice level).
//! `RUST_LOG=tincd::meta=debug` is the equivalent of `tincd -d4`.
//! Better than C: the integer level conflates verbosity with topic;
//! `target=` filtering is per-subsystem.

#![deny(unsafe_code)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown)]
// 14 bools in DaemonSettings is the C globals census, not a smell.
// Same for the daemon struct itself.
#![allow(clippy::struct_excessive_bools)]
// std::env::set_var is safe in edition 2021. Integration test sets
// RUST_LOG; nothing else here uses set_var, but the standing rule
// applies workspace-wide.

pub mod conn;
pub mod control;
pub mod daemon;
pub mod keys;
pub mod listen;
pub mod proto;

pub use daemon::{Daemon, DaemonSettings, RunOutcome};
