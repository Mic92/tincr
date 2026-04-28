//! Integration test: spawn real `tincd`, control it via the socket
//! protocol, daemon exits 0.
//!
//! ## Why this test exists
//!
//! `tinc-tools/tests/tinc_cli.rs::fake_daemon_setup` is the INVERSE:
//! it stands up a fake daemon and lets the real `tinc` CLI connect.
//! THIS test stands up a real daemon and connects to it directly.
//!
//! Together they prove the protocol from both sides. The full proof
//! (real `tinc` CLI → real `tincd`) is the next step but needs
//! `CARGO_BIN_EXE_tinc` from another crate's binary, which is
//! awkward (cargo only sets `CARGO_BIN_EXE_*` for the crate-under-
//! test's own binaries). For now: speak the protocol by hand.
//!
//! ## What's proven
//!
//! - `Daemon::setup`: tinc.conf read, dummy device opened, control
//!   socket bound, pidfile written
//! - `Daemon::run`: the dispatch enum compiles inside a real loop,
//!   `tick → turn → match` works
//! - `tinc-event`: a real epoll wakes on a real unix socket; timers
//!   tick (Ping fires and re-arms)
//! - `dispatch.rs`: the greeting exchange + `REQ_STOP` path
//! - `conn.rs`: feed/send/flush over a real fd
//! - `control.rs`: pidfile format readable by the same parser
//!   `tinc-tools::Pidfile::read` uses
//!
//! ## `SelfPipe` singleton
//!
//! `Daemon::setup` calls `SelfPipe::new()` which is a process
//! singleton (panics if called twice). Tests can't construct a
//! `Daemon` in-process. Hence: subprocess. The subprocess is its
//! own process; `SelfPipe` is fresh.

#[path = "../common/mod.rs"]
#[macro_use]
pub mod common;

mod cli_flags;
mod control;
mod lifecycle;
mod peer;

use common::write_ed25519_privkey;

/// Write a minimal config: `tinc.conf`, `hosts/testnode`, AND
/// `ed25519_key.priv`.
///
/// `Port = 0` is critical: the daemon binds TCP+UDP listeners now.
/// Port 655 would clash between parallel test threads. Port 0 =
/// kernel picks. Each test gets its own port.
///
/// `AddressFamily = ipv4` reduces to one listener. v6 might be
/// disabled in the build sandbox.
///
/// `Port` is HOST-tagged. Goes in `hosts/testnode`. The daemon's `read_host_config` merges it.
///
/// `ed25519_key.priv` is required since chunk 4a (`net_setup.c`:803
/// loads it; we forbid the legacy fallback). The key is deterministic
/// (seeded from a constant) so tests are reproducible. Mode 0600 to
/// avoid the perm warning. The daemon never USES this key in tests
/// that don't peer-connect, but `setup()` loads it unconditionally
/// (the C does too — you can't run tincd without a key).
///
/// Returns the daemon's PUBLIC key. Tests that don't peer-connect
/// ignore it; `peer_handshake_reaches_done` needs it for the SPTPS
/// initiator side.
pub(crate) fn write_config(confbase: &std::path::Path) -> [u8; 32] {
    std::fs::create_dir_all(confbase.join("hosts")).unwrap();
    std::fs::write(
        confbase.join("tinc.conf"),
        "Name = testnode\nDeviceType = dummy\nAddressFamily = ipv4\n",
    )
    .unwrap();
    std::fs::write(confbase.join("hosts").join("testnode"), "Port = 0\n").unwrap();

    // Daemon's private key. Seed `[0x42; 32]` — distinct from any
    // test-helper seeds (keys.rs uses 1..11, conn.rs uses 1/2/10/20).
    let seed = [0x42; 32];
    write_ed25519_privkey(confbase, &seed);
    common::pubkey_from_seed(&seed)
}
