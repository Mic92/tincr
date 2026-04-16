//! tincd as a library: the `main.rs` binary is a thin entry point and
//! all daemon state lives here so integration tests can construct a
//! [`Daemon`] directly.
//!
//! I/O readiness goes through `tinc-event` with an `IoWhat` dispatch
//! tag per kind of socket the daemon owns; connections are addressed
//! by a generational `ConnId`, so a slot reused after a peer drops
//! safely returns `None` instead of misrouting an event. Logging is
//! routed through the `log` crate using per-subsystem targets like
//! `tincd::conn`, `tincd::proto`, `tincd::meta` and `tincd::route`,
//! which `RUST_LOG` can filter at the usual `log::Level` granularity.

#![deny(unsafe_code)]

pub mod addrcache;
pub mod autoconnect;
pub mod broadcast;
pub mod compress;
pub mod conn;
pub mod control;
pub mod daemon;
pub mod discovery;
pub mod dns;
pub mod egress;
pub mod fragment;
pub mod graph_glue;
pub mod icmp;
pub mod inthash;
pub mod invitation_serve;
pub mod keys;
pub mod listen;
pub mod local_addr;
pub mod log_tap;
pub mod mac_lease;
pub mod mss;
pub mod neighbor;
pub mod node_id;
pub mod outgoing;
pub mod packet;
pub mod pmtu;
pub mod proto;
pub mod reload;
pub mod route;
pub mod route_mac;
pub mod sandbox;
pub mod script;
pub mod sd_notify;
pub mod seen;
pub mod shard;
pub mod socks;
pub mod subnet_tree;
pub mod tcp_tunnel;
pub mod tunnel;
pub mod udp_info;
mod platform;
pub use platform::{msg_nosignal, set_cloexec, set_nosigpipe, sock_cloexec_flag};

pub use daemon::{Daemon, DaemonSettings, RunOutcome};
