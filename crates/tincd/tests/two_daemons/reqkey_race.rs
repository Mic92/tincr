//! Portable reproducer for the simultaneous `REQ_KEY` livelock.
//!
//! Uses `DeviceType=fd` socketpairs instead of bwrap/netns + real
//! TUN + `ping` + tc netem, so it runs on Linux AND macOS.
//!
//! Trick: after meta handshake completes, write an IP packet into
//! BOTH test-end fds before either daemon polls. Both daemons hit
//! `try_tx` → `send_req_key` simultaneously → the race triggers.
//!
//! Regression test for the crossed-`REQ_KEY` livelock. The race
//! triggers reliably even without tc netem delay — loopback fd
//! writes land before either daemon polls. Fixed by the name-order
//! tie-break in `on_req_key` (greater name stays Initiator).

use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

use super::common::*;
use super::fd_tunnel::*;
use super::node::*;

fn tmp(tag: &str) -> TmpGuard {
    TmpGuard::new("rqk", tag)
}

const VALIDKEY: u32 = 0x02;
const REACHABLE: u32 = 0x10;

const RESTART_MARKER: &str = "SPTPS already started";

fn count_restarts(log: &str) -> usize {
    log.matches(RESTART_MARKER).count()
}

/// Portable simultaneous `REQ_KEY` race test. No netns needed.
#[test]
fn reqkey_race_fd() {
    let tmp = tmp("fd-race");
    let alice = Node::new(tmp.path(), "alice", 0xA1).with_conf("PingInterval = 2\n");
    let bob = Node::new(tmp.path(), "bob", 0xB1).with_conf("PingInterval = 2\n");

    let (alice_tun, alice_far) = sockpair_datagram();
    let (bob_tun, bob_far) = sockpair_datagram();

    // Symmetric: both ConnectTo each other (triggers dedup path).
    alice.write_config_multi(
        &[&bob],
        &["bob"],
        Some(alice_far.as_raw_fd()),
        Some("10.44.0.1/32"),
    );
    bob.write_config_multi(
        &[&alice],
        &["alice"],
        Some(bob_far.as_raw_fd()),
        Some("10.44.0.2/32"),
    );

    let mut bob_child = bob.spawn_with_fd(&bob_far);
    assert!(
        wait_for_file(&bob.socket),
        "bob setup failed; stderr:\n{}",
        drain_stderr(bob_child)
    );
    drop(bob_far);

    let alice_child = alice.spawn_with_fd(&alice_far);
    if !wait_for_file(&alice.socket) {
        let _ = bob_child.kill();
        panic!("alice setup failed; stderr:\n{}", drain_stderr(alice_child));
    }
    drop(alice_far);

    let mut alice_ctl = alice.ctl();
    let mut bob_ctl = bob.ctl();

    // ─── wait for meta handshake (both reachable) ───────────────
    let meta = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        poll_until(Duration::from_secs(10), || {
            let a = alice_ctl.dump(3);
            let b = bob_ctl.dump(3);
            let a_ok = node_status(&a, "bob").is_some_and(|s| s & REACHABLE != 0);
            let b_ok = node_status(&b, "alice").is_some_and(|s| s & REACHABLE != 0);
            if a_ok && b_ok { Some(()) } else { None }
        });
    }));
    if meta.is_err() {
        let _ = bob_child.kill();
        let bl = drain_stderr(bob_child);
        let al = drain_stderr(alice_child);
        panic!("meta handshake timed out;\n=== alice ===\n{al}\n=== bob ===\n{bl}");
    }

    // ─── THE SIMULTANEOUS KICK ──────────────────────────────────
    // Write an IP packet to BOTH test-end fds before either daemon
    // polls. Both daemons' event loops will see device-readable on
    // the next epoll and hit try_tx → send_req_key simultaneously.
    // Retry a few times: on fast loopback the window is tight.
    let pkt_a2b = mk_ipv4_pkt([10, 44, 0, 1], [10, 44, 0, 2], b"race-a");
    let pkt_b2a = mk_ipv4_pkt([10, 44, 0, 2], [10, 44, 0, 1], b"race-b");

    for _ in 0..5 {
        write_fd(&alice_tun, &pkt_a2b);
        write_fd(&bob_tun, &pkt_b2a);
        std::thread::sleep(Duration::from_millis(50));
    }

    // ─── observation window ─────────────────────────────────────
    // Sample validkey every 200 ms. Track when both sides first
    // have validkey (steady state), then watch for flaps.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut steady_since: Option<Instant> = None;
    let mut validkey_flaps = 0u32;
    let mut last_both_valid = false;

    while Instant::now() < deadline {
        let a = alice_ctl.dump(3);
        let b = bob_ctl.dump(3);
        let a_valid = node_status(&a, "bob").is_some_and(|s| s & VALIDKEY != 0);
        let b_valid = node_status(&b, "alice").is_some_and(|s| s & VALIDKEY != 0);
        let both = a_valid && b_valid;
        if both && steady_since.is_none() {
            steady_since = Some(Instant::now());
        }
        if last_both_valid && !both {
            validkey_flaps += 1;
        }
        last_both_valid = both;
        // Once steady for 10 s, stop early.
        if steady_since.is_some_and(|t| t.elapsed() >= Duration::from_secs(10)) {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    // ─── collect logs and assert ────────────────────────────────
    drop(alice_ctl);
    drop(bob_ctl);
    drop(alice_tun);
    drop(bob_tun);
    let _ = bob_child.kill();
    let alice_full = drain_stderr(alice_child);
    let bob_full = drain_stderr(bob_child);

    let a_restarts = count_restarts(&alice_full);
    let b_restarts = count_restarts(&bob_full);

    eprintln!(
        "── reqkey_race_fd summary ──\n\
         alice restarts: {a_restarts}, bob restarts: {b_restarts}\n\
         validkey flaps: {validkey_flaps}, steady_since: {steady_since:?}"
    );

    // 1. Peer never becomes unreachable after initial convergence.
    let a_unreach = alice_full.matches("became unreachable").count();
    let b_unreach = bob_full.matches("became unreachable").count();
    assert!(
        a_unreach <= 1 && b_unreach <= 1,
        "meta-conn dedup is redialling (alice {a_unreach}, bob {b_unreach} unreachable);\n\
         === alice ===\n{alice_full}\n=== bob ===\n{bob_full}"
    );

    // 2. validkey reaches steady state.
    assert!(
        steady_since.is_some(),
        "validkey never set on both sides within 30 s;\n\
         === alice ===\n{alice_full}\n=== bob ===\n{bob_full}"
    );

    // 3. validkey never flaps after settling.
    assert_eq!(
        validkey_flaps, 0,
        "validkey flapped {validkey_flaps}\u{d7} during steady state;\n\
         === alice ===\n{alice_full}\n=== bob ===\n{bob_full}"
    );

    // 4. "SPTPS already started" should be bounded (≤2 per side:
    //    one initial crossing is protocol-inherent). The bug is
    //    unbounded recurrence. Allow up to 3 per side for margin.
    assert!(
        a_restarts <= 3 && b_restarts <= 3,
        "excessive SPTPS restarts (alice {a_restarts}, bob {b_restarts}) - \
         livelock not resolved;\n\
         === alice ===\n{alice_full}\n=== bob ===\n{bob_full}"
    );
}
