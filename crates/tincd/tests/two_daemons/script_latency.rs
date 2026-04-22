//! Regression: a slow `host-up` (waitpid on the event loop) must not
//! stall tun/UDP forwarding on reachability flips.

use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

use super::common::*;
use super::fd_tunnel::*;
use super::node::*;

fn which_sleep() -> String {
    for p in std::env::var("PATH").unwrap_or_default().split(':') {
        let cand = std::path::Path::new(p).join("sleep");
        if cand.is_file() {
            return cand.display().to_string();
        }
    }
    "/bin/sleep".into()
}

#[test]
fn slow_host_up_does_not_stall_forwarding() {
    let tmp = tmp!("script-latency");
    // Longer PingTimeout: with the OLD code alice's loop is dead for
    // 2 s, which would otherwise trip bob's 1 s auth-timeout sweep
    // and tear the conn down — masking the latency we want to see.
    let alice = Node::new(tmp.path(), "alice", 0xA9).with_conf("PingTimeout = 10\n");
    let bob = Node::new(tmp.path(), "bob", 0xB9).with_conf("PingTimeout = 10\n");

    let (alice_tun, alice_far) = sockpair_datagram();
    let (bob_tun, bob_far) = sockpair_datagram();

    bob.write_config_with(
        &alice,
        false,
        Some(bob_far.as_raw_fd()),
        Some("10.0.0.2/32"),
    );
    alice.write_config_with(&bob, true, Some(alice_far.as_raw_fd()), Some("10.0.0.1/32"));

    // Slow host-up on ALICE, fired at the post-ACK graph run.
    // Absolute `sleep`: scripts get a fixed PATH sans coreutils on NixOS.
    let sleep = which_sleep();
    let hu = alice.confbase.join("host-up");
    std::fs::write(&hu, format!("#!/bin/sh\nexec {sleep} 2\n")).unwrap();
    std::fs::set_permissions(&hu, std::fs::Permissions::from_mode(0o755)).unwrap();

    let mut bob_child = bob.spawn_with_fd(&bob_far);
    assert!(
        wait_for_file(&bob.socket),
        "bob setup failed:\n{}",
        drain_stderr(bob_child)
    );
    drop(bob_far);

    let alice_child = alice.spawn_with_fd(&alice_far);
    if !wait_for_file(&alice.socket) {
        let _ = bob_child.kill();
        panic!("alice setup failed:\n{}", drain_stderr(alice_child));
    }
    drop(alice_far);

    // Wait for the meta-conn handshake from BOB's side. Bob has no
    // scripts, so his ctl answers immediately. Alice's side fires
    // host-up at ~the same instant and (old code) goes deaf for 2 s.
    let mut bob_ctl = bob.ctl();
    poll_until(Duration::from_secs(10), || {
        node_status(&bob_ctl.dump(3), "alice")
            .filter(|s| s & 0x10 != 0)
            .map(|_| ())
    });

    // 10 probes at 50 ms. Direct meta-conn → PACKET 17 short-circuit
    // delivers via TCP even before validkey, so no UDP-handshake wait
    // needed. We only need alice's loop to be alive.
    let mut max_rtt = Duration::ZERO;
    for i in 0..10u8 {
        let pkt = mk_ipv4_pkt([10, 0, 0, 1], [10, 0, 0, 2], &[i; 8]);
        let sent = Instant::now();
        write_fd(&alice_tun, &pkt);
        let got = poll_until(Duration::from_secs(5), || read_fd_nb(&bob_tun));
        let rtt = sent.elapsed();
        assert_eq!(&got[got.len() - 8..], &[i; 8], "payload echo");
        max_rtt = max_rtt.max(rtt);
        std::thread::sleep(Duration::from_millis(50));
    }

    let _ = drain_stderr(alice_child);
    let _ = drain_stderr(bob_child);

    // Old code: first probe waits out the full 2 s `host-up`. New
    // code: scripts run on a worker thread; loop stays hot.
    assert!(
        max_rtt < Duration::from_millis(500),
        "data-plane stalled by host-up: max RTT {max_rtt:?}"
    );
}
