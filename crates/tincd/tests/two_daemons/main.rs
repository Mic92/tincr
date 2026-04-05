//! Two real `tincd` processes. Alice has `ConnectTo = bob`; bob's
//! port is pre-allocated. Proves the full chain: `do_outgoing_
//! connection` → async-connect probe → `finish_connecting` → ID
//! exchange (initiator side) → SPTPS handshake → ACK exchange →
//! `send_everything` → graph(). Then stop alice, prove bob's
//! `terminate` → DEL_EDGE → graph() → unreachable.
//!
//! ## The chicken-and-egg
//!
//! Bob binds port 0 (kernel picks). Alice's `hosts/bob` needs that
//! port. Option (b) from the task brief: pre-allocate a port in the
//! TEST (bind port 0, read it back, close), write it into bob's
//! `hosts/bob` `Port = N`, and into alice's `hosts/bob` `Address =
//! 127.0.0.1 N`. Racy in theory (something else could grab the port
//! between close and bob's bind); works in practice (loopback,
//! high-range port, sub-millisecond gap).
//!
//! ## Timing
//!
//! These tests spinloop with timeouts. The connect+handshake takes
//! <100ms on loopback. Timeouts are 10s for slack on a loaded CI box;
//! the tests typically complete in <1s.

// Integration tests are end-to-end scenarios; their length reflects
// the steps (spawn N daemons → wait for mesh → inject → assert →
// teardown). The `Node` helper below already absorbs the per-daemon
// boilerplate; the test BODIES diverge on the load-bearing config
// differences (TunnelServer/StrictSubnets/Forwarding/AutoConnect).
#![allow(clippy::too_many_lines)]

#[path = "../common/mod.rs"]
mod common;

mod fd_tunnel;
mod node;

mod basic;
mod data_path;
mod proxy;
mod purge;
mod reload;
mod three_node;
