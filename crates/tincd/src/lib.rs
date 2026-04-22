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
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(unreachable_pub)]

mod addr;
mod addrcache;
mod autoconnect;
mod bgresolve;
mod broadcast;
mod compress;
mod conn;
mod control;
pub mod daemon;
pub mod discovery;
mod dns;
mod egress;
mod fragment;
mod graph_glue;
mod icmp;
mod ids;
mod inthash;
mod invitation_serve;
mod keys;
mod listen;
mod local_addr;
pub mod log_tap;
mod mac_lease;
mod mss;
mod neighbor;
pub mod node_id;
mod outgoing;
mod packet;
mod platform;
mod pmtu;
#[cfg(feature = "upnp")]
mod portmap;
mod proto;
mod reload;
mod route;
mod route_mac;
pub mod sandbox;
mod script;
mod scriptworker;
pub mod sd_notify;
mod seen;
pub mod shard;
mod socks;
mod subnet_tree;
mod tcp_tunnel;
mod tunnel;
mod udp_info;
#[cfg(target_os = "linux")]
pub use platform::set_int_sockopt;
pub(crate) use platform::{
    bind_to_interface, msg_nosignal, set_cloexec, set_nosigpipe, set_udp_tos, sock_cloexec_flag,
};
pub use platform::{daemonize, initgroups};

pub use daemon::{Daemon, DaemonSettings, RunOutcome};

/// Per-test tempdir. PID+TID in the name keeps nextest-parallel runs
/// disjoint without pulling in the `tempfile` crate.
#[cfg(test)]
pub(crate) mod testutil {
    use std::path::{Path, PathBuf};

    pub(crate) struct TmpDir(pub(crate) PathBuf);
    impl TmpDir {
        pub(crate) fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!(
                "tincd-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
        pub(crate) fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}
