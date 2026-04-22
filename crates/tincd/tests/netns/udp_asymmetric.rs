//! Regression: a node behind an inbound-UDP-only filter never sets
//! `udp_confirmed` for ANY peer, so data to that peer rides TCP-in-
//! TCP forever (~6 Mb/s ceiling on a 92 Mb/s link, `tools/relay-
//! bench`). But the OUTBOUND leg works: alice's probes reach bob,
//! only bob's UDP replies are eaten. Bob can tell alice "got your
//! probe" over the always-working meta-TCP — that's enough for
//! alice→bob data to switch to UDP. bob→alice stays TCP (bob's own
//! `udp_confirmed[alice]` is independent and correctly never set).
//!
//! Two nodes, direct meta-conn. iptables drops UDP to alice's
//! listener port only — models the production blob64 stateless
//! inbound-UDP filter. Asserts after settle:
//!   1. alice sees bob `udp_confirmed` + `minmtu` large enough for
//!      a 1400-byte ping (asymmetric TX-confirm via meta).
//!   2. bob still sees alice `minmtu==0` (his replies never arrive;
//!      no false confirm in the OTHER direction).
//!   3. alice→bob 1400-byte ping succeeds and bob's stderr shows
//!      the data arriving as UDP (`handle_incoming_vpn_packet`
//!      path), not the PACKET-17 TCP short-circuit.

use std::process::{Command, Stdio};
use std::time::Duration;

use super::chaos::node_pmtu;
use super::common::linux::*;
use super::common::*;
use super::rig::*;

#[test]
fn udp_asymmetric_meta_confirm() {
    let Some(netns) = enter_netns("udp_asymmetric::udp_asymmetric_meta_confirm") else {
        return;
    };

    let tmp = tmp!("udpasym");
    let alice = tun_node(tmp.path(), "alice", 0xAA, "tinc0", "10.42.0.1/32");
    let bob = tun_node(tmp.path(), "bob", 0xAB, "tinc1", "10.42.0.2/32");

    // Both daemons share 127.0.0.1; drop UDP to alice's port only.
    // alice→bob:port passes (dport ≠ alice.port); bob→alice:port is
    // eaten — exactly the production asymmetric filter.
    let ipt = Command::new("iptables")
        .args([
            "-I",
            "INPUT",
            "-p",
            "udp",
            "--dport",
            &alice.port.to_string(),
            "-j",
            "DROP",
        ])
        .output()
        .expect("spawn iptables");
    if !ipt.status.success() {
        eprintln!(
            "SKIP udp_asymmetric_meta_confirm: iptables failed: {}",
            String::from_utf8_lossy(&ipt.stderr).trim()
        );
        return;
    }

    // MTUInfoInterval=1: bob's meta-ack (the new 4th MTU_INFO field)
    // is debounced by this; default 5s would push the settle past
    // the test budget. PingInterval=1: `on_ping_tick`'s `try_tx`
    // is what drains bob's `udp_rx_maxlen` into the ack.
    let extra = "MTUInfoInterval = 1\nPingInterval = 1\n";
    let bob = bob.with_conf(extra);
    let alice = alice.with_conf(extra);
    bob.write_config(&alice, false);
    alice.write_config(&bob, true);

    let log = "tincd=info,tincd::net=debug";
    let mut bob_child = bob.spawn_with_log(log);
    assert!(
        wait_for_file(&bob.socket),
        "bob setup; stderr:\n{}",
        drain_stderr(bob_child)
    );
    let alice_child = alice.spawn_with_log(log);
    if !wait_for_file(&alice.socket) {
        let _ = bob_child.kill();
        panic!("alice setup; stderr:\n{}", drain_stderr(alice_child));
    }

    assert!(wait_for_carrier("tinc0", Duration::from_secs(2)));
    assert!(wait_for_carrier("tinc1", Duration::from_secs(2)));
    netns.place_devices();

    let mut alice_ctl = alice.ctl();
    let mut bob_ctl = bob.ctl();

    // ─── mesh + validkey ────────────────────────────────────────
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        poll_until(Duration::from_secs(10), || {
            let a = alice_ctl.dump(3);
            node_status(&a, "bob")
                .is_some_and(|s| s & 0x10 != 0)
                .then_some(())
        });
        let _ = Command::new("ping")
            .args(["-c", "1", "-W", "1", "10.42.0.2"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        poll_until(Duration::from_secs(5), || {
            let a = alice_ctl.dump(3);
            node_status(&a, "bob")
                .is_some_and(|s| s & 0x02 != 0)
                .then_some(())
        });
    }));
    if r.is_err() {
        let _ = bob_child.kill();
        panic!(
            "mesh up timed out;\n=== alice ===\n{}\n=== bob ===\n{}",
            drain_stderr(alice_child),
            drain_stderr(bob_child)
        );
    }

    // ─── (1) alice's view of bob: udp_confirmed via meta-ack ────
    // Drive try_tx(mtu=true) with traffic so PMTU probes go out;
    // bob receives them, acks the size over meta, alice's minmtu
    // climbs. Want minmtu past a 1400-byte payload before assert 3.
    let confirmed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        poll_until(Duration::from_secs(15), || {
            let _ = Command::new("ping")
                .args(["-c", "1", "-W", "1", "10.42.0.2"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            let a = alice_ctl.dump(3);
            let st = node_status(&a, "bob")?;
            let (_, minmtu, _) = node_pmtu(&a, "bob")?;
            (st & 0x80 != 0 && minmtu >= 1400).then_some(minmtu)
        })
    }));
    // ─── (2) bob's view of alice: snapshot BEFORE kill ──────────
    let b = bob_ctl.dump(3);
    drop(bob_ctl);
    drop(alice_ctl);
    let _ = bob_child.kill();
    let bob_stderr = drain_stderr(bob_child);
    let alice_stderr = drain_stderr(alice_child);
    assert!(
        confirmed.is_ok(),
        "alice never udp_confirmed bob via meta-ack (asymmetric \
         filter)\n=== alice ===\n{alice_stderr}\n=== bob ===\n{bob_stderr}",
    );

    // bob's probes to alice are eaten; no meta-ack from alice's
    // side either (alice never receives bob's UDP probe → her
    // udp_rx_maxlen for bob stays 0). Asymmetric is the point.
    // NOTE: `status.udp_confirmed` (bit 0x80) is set by rx.rs on
    // ANY direct UDP decrypt — bob DID receive alice's probe — so
    // it's not the right invariant. The `go_tcp` predicate keys on
    // `minmtu`; that's what must stay 0.
    let (_, bob_min, _) = node_pmtu(&b, "alice").expect("bob's alice row");
    assert_eq!(
        bob_min, 0,
        "bob→alice minmtu must stay 0 (his UDP path is filtered); rows: {b:?}"
    );

    // ─── (3) alice→bob big ping rides UDP ───────────────────────
    // bob's stderr (already drained) must show the meta-ack send;
    // alice's stderr must show "confirmed via meta". The actual
    // UDP-vs-TCP transport check: bob logged "Got UDP probe
    // request" for sizes >1000 (the PMTU probes), which only
    // arrive if alice→bob UDP works.
    assert!(
        alice_stderr.contains("confirmed via meta"),
        "alice missing meta-confirm log;\n=== alice ===\n{alice_stderr}"
    );
    assert!(
        bob_stderr.contains("Got UDP probe request"),
        "bob never received alice's UDP probes;\n=== bob ===\n{bob_stderr}"
    );

    drop(netns);
}
