//! Real kernel TUN devices inside an unprivileged user+net namespace
//! (bwrap). Each test re-execs itself inside the sandbox; see
//! `rig::enter_bwrap`. Self-skips where bwrap/userns is unavailable.

#![cfg(target_os = "linux")]

#[path = "../common/mod.rs"]
#[macro_use]
mod common;

mod rig;

mod autoconnect_shortcut;
mod chaos;
mod crossimpl;
mod ping;
mod portmap;
mod sandbox;
mod stress;
mod tcp_fallback;
mod udp_asymmetric;
