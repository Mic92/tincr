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

pub mod addr;
pub mod addrcache;
pub mod autoconnect;
pub mod bgresolve;
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
mod platform;
pub mod pmtu;
#[cfg(feature = "upnp")]
pub mod portmap;
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
#[cfg(target_os = "linux")]
pub use platform::set_int_sockopt;
pub use platform::{
    bind_to_interface, daemonize, initgroups, msg_nosignal, set_cloexec, set_nosigpipe,
    set_udp_tos, sock_cloexec_flag,
};

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
