//! Regression for the crossed-`REQ_KEY` livelock, reproduced portably
//! with `DeviceType = fd` socketpairs: after the meta handshake, write
//! a packet into both device fds before either daemon polls so both
//! send `REQ_KEY` at once. Fixed by the name-order tie-break in
//! `on_req_key`.

use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

use super::common::node::*;
use super::common::*;
use super::fd_tunnel::*;

const VALIDKEY: u32 = 0x02;

#[test]
fn simultaneous_req_key_settles() {
    let tmp = tmp!("fd-race");
    let (alice_dev, alice_daemon_end) = sockpair_datagram();
    let (bob_dev, bob_daemon_end) = sockpair_datagram();
    let mut alice = Node::new(tmp.path(), "alice", 0xA1)
        .with_conf("PingInterval = 2\n")
        .fd(alice_daemon_end.as_raw_fd())
        .subnet("10.44.0.1/32");
    let mut bob = Node::new(tmp.path(), "bob", 0xB1)
        .with_conf("PingInterval = 2\n")
        .fd(bob_daemon_end.as_raw_fd())
        .subnet("10.44.0.2/32");

    // Mutual ConnectTo also exercises the duplicate-connection path.
    alice.reserve_port();
    bob.write_config_multi(&[&alice], &[&alice]);
    bob.start_with_fd(&bob_daemon_end);
    drop(bob_daemon_end);
    alice.write_config_multi(&[&bob], &[&bob]);
    alice.start_with_fd(&alice_daemon_end);
    drop(alice_daemon_end);

    let mut alice_ctl = alice.ctl();
    let mut bob_ctl = bob.ctl();
    poll_until(Duration::from_secs(10), || {
        (node_reachable(&alice_ctl.dump(3), "bob") && node_reachable(&bob_ctl.dump(3), "alice"))
            .then_some(())
    });

    let alice_to_bob = mk_ipv4_pkt([10, 44, 0, 1], [10, 44, 0, 2], b"race-a");
    let bob_to_alice = mk_ipv4_pkt([10, 44, 0, 2], [10, 44, 0, 1], b"race-b");
    for _ in 0..5 {
        write_fd(&alice_dev, &alice_to_bob);
        write_fd(&bob_dev, &bob_to_alice);
        std::thread::sleep(Duration::from_millis(50));
    }

    // Sample validkey until it has held on both sides for 10s.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut steady_since = None;
    let mut flaps = 0;
    let mut was_valid = false;
    while Instant::now() < deadline {
        let both_valid = node_status(&alice_ctl.dump(3), "bob").is_some_and(|s| s & VALIDKEY != 0)
            && node_status(&bob_ctl.dump(3), "alice").is_some_and(|s| s & VALIDKEY != 0);
        if both_valid && steady_since.is_none() {
            steady_since = Some(Instant::now());
        }
        if was_valid && !both_valid {
            flaps += 1;
        }
        was_valid = both_valid;
        if steady_since.is_some_and(|since: Instant| since.elapsed() >= Duration::from_secs(10)) {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    let alice_log = alice.stop();
    let bob_log = bob.stop();
    let logs = format!("=== alice ===\n{alice_log}\n=== bob ===\n{bob_log}");
    for log in [&alice_log, &bob_log] {
        assert!(
            log.matches("became unreachable").count() <= 1,
            "dedup redials;\n{logs}"
        );
        // One crossing is inherent to the protocol; the bug was unbounded.
        assert!(
            log.matches("SPTPS already started").count() <= 3,
            "livelock;\n{logs}"
        );
    }
    assert!(steady_since.is_some(), "validkey never settled;\n{logs}");
    assert_eq!(flaps, 0, "validkey flapped;\n{logs}");
}
