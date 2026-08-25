//! The daemon dials from the on-disk address cache when `hosts/PEER`
//! has no `Address =`. Unit tests cover the file format; this covers
//! that a real handshake populates it and a real restart uses it.

use std::fs;
use std::time::Duration;

#[macro_use]
mod common;
use common::node::Node;

/// SIGTERM, not SIGKILL: the cache is saved on graceful shutdown.
fn terminate(node: &mut Node) {
    node.signal(nix::sys::signal::Signal::SIGTERM);
    assert!(node.wait_exit().success());
}

#[test]
fn restart_dials_from_cache() {
    let tmp = tmp!("restart_dials_from_cache");
    let mut alice = Node::new(tmp.path(), "alice", 0xA1);
    let mut bob = Node::new(tmp.path(), "bob", 0xB0);
    let cache_file = alice.confbase.join("addrcache").join("bob");

    bob.write_config(&alice, false);
    alice.start_dialing(&mut bob);
    terminate(&mut alice);
    assert_eq!(
        std::fs::read_to_string(&cache_file).unwrap(),
        format!("tinc-addrcache 1\n127.0.0.1:{}\n", bob.port)
    );

    // The listener must not cache the dialer's ephemeral source port.
    terminate(&mut bob);
    if let Ok(bob_cache) = fs::read_to_string(bob.confbase.join("addrcache").join("alice")) {
        assert!(
            bob_cache.lines().skip(1).all(str::is_empty),
            "{bob_cache:?}"
        );
    }

    // No Address line anymore: only the cache knows where bob is.
    alice.write_host_file(&bob, false);
    bob.start();
    alice.start();
    bob.wait_for_peer("alice", true, Duration::from_secs(10));
}
