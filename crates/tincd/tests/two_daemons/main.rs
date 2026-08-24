//! Two or three real `tincd` processes on loopback, driven over their
//! control sockets and, where a data path is needed, `DeviceType = fd`
//! socketpairs (see `fd_tunnel`).

#[path = "../common/mod.rs"]
#[macro_use]
mod common;

mod fd_tunnel;

mod basic;
mod data_path;
mod dns;
mod proxy;
mod purge;
mod reload;
mod reqkey_race;
mod script_latency;
mod three_node;
