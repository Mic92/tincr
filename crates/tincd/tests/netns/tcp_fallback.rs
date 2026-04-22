//! Regression: data must ride TCP while `relay.minmtu == 0`.
//!
//! Models a node behind a UDP-blackholing firewall (retiolum blob64
//! on TUM net): no inbound UDP, no hole-punch. C tinc keeps non-
//! probe data on TCP until a probe reply lifts `minmtu` above 0
//! (`net_packet.c:974`). The Rust port had a `relay_minmtu > 0 &&`
//! guard that inverted this — data went UDP into the blackhole.
//!
//! Three nodes because two with a direct meta-conn never reach
//! `send_sptps_data_relay`: `send_sptps_packet`'s PACKET 17 short-
//! circuit fires first. The bug only bites indirect destinations
//! (the production `turingmachine ↔ eva ↔ blob64` shape).

use std::process::{Command, Stdio};
use std::time::Duration;

use super::chaos::node_pmtu;
use super::common::linux::*;
use super::common::*;
use super::rig::*;

#[test]
fn tcp_fallback_udp_blackhole() {
    let Some(netns) = enter_netns("tcp_fallback::tcp_fallback_udp_blackhole") else {
        return;
    };

    // All three daemons share 127.0.0.1; one INPUT rule blackholes
    // every inter-daemon UDP. CAP_NET_ADMIN inside the userns is
    // enough for the nf_tables backend.
    let ipt = Command::new("iptables")
        .args(["-I", "INPUT", "-p", "udp", "-j", "DROP"])
        .output()
        .expect("spawn iptables");
    if !ipt.status.success() {
        eprintln!(
            "SKIP tcp_fallback_udp_blackhole: iptables failed: {}",
            String::from_utf8_lossy(&ipt.stderr).trim()
        );
        return;
    }

    let tmp = tmp!("tcpfb");
    let alice = Node::new(tmp.path(), "alice", 0xFA, "tinc0", "10.42.0.1/32");
    let bob = Node::new(tmp.path(), "bob", 0xFB, "tinc1", "10.42.0.2/32");
    let mid = Node::new(tmp.path(), "mid", 0xFC, "tinc0", "10.42.0.0/32");

    // AutoConnect=no: otherwise bob learns alice's address via
    // ADD_EDGE and dials direct → PACKET 17 short-circuit, predicate
    // never reached.
    let extra = "AutoConnect = no\n";
    mid.write_config_hub(&[&alice, &bob], extra);
    alice.write_config_multi(&[&mid, &bob], &["mid"], extra);
    bob.write_config_multi(&[&mid, &alice], &["mid"], extra);

    let log = "tincd=info,tincd::net=debug";
    let mut mid_child = mid.spawn_with_log(log);
    assert!(
        wait_for_file(&mid.socket),
        "mid setup; stderr:\n{}",
        drain_stderr(mid_child)
    );
    let mut bob_child = bob.spawn_with_log(log);
    if !wait_for_file(&bob.socket) {
        let _ = mid_child.kill();
        panic!("bob setup; stderr:\n{}", drain_stderr(bob_child));
    }
    let alice_child = alice.spawn_with_log(log);
    if !wait_for_file(&alice.socket) {
        let _ = mid_child.kill();
        let _ = bob_child.kill();
        panic!("alice setup; stderr:\n{}", drain_stderr(alice_child));
    }

    assert!(wait_for_carrier("tinc0", Duration::from_secs(2)));
    assert!(wait_for_carrier("tinc1", Duration::from_secs(2)));
    netns.place_devices();

    let mut alice_ctl = alice.ctl();

    // ─── mesh up (meta TCP only) ────────────────────────────────
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        poll_until(Duration::from_secs(10), || {
            let a = alice_ctl.dump(3);
            node_status(&a, "bob")
                .is_some_and(|s| s & 0x10 != 0)
                .then_some(())
        });
    }));
    if r.is_err() {
        let _ = mid_child.kill();
        let _ = bob_child.kill();
        panic!(
            "mesh up timed out;\n=== alice ===\n{}\n=== mid ===\n{}\n=== bob ===\n{}",
            drain_stderr(alice_child),
            drain_stderr(mid_child),
            drain_stderr(bob_child)
        );
    }

    // Kick alice↔bob per-tunnel SPTPS (REC_HANDSHAKE always rides
    // TCP, so this completes regardless of the bug).
    let _ = Command::new("ping")
        .args(["-c", "1", "-W", "1", "10.42.0.2"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let validkey = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        poll_until(Duration::from_secs(5), || {
            let a = alice_ctl.dump(3);
            node_status(&a, "bob")
                .is_some_and(|s| s & 0x02 != 0)
                .then_some(())
        });
    }));
    if validkey.is_err() {
        let _ = mid_child.kill();
        let _ = bob_child.kill();
        panic!(
            "validkey timed out;\n=== alice ===\n{}\n=== mid ===\n{}\n=== bob ===\n{}",
            drain_stderr(alice_child),
            drain_stderr(mid_child),
            drain_stderr(bob_child)
        );
    }

    // Sanity: the predicate's input. relay=mid must have minmtu==0
    // and udp_confirmed clear, else the test isn't testing anything.
    let a = alice_ctl.dump(3);
    let (_, mid_min, _) = node_pmtu(&a, "mid").expect("alice's mid row");
    assert_eq!(mid_min, 0, "alice should see minmtu=0 for mid; rows: {a:?}");
    assert!(
        node_status(&a, "mid").is_some_and(|s| s & 0x80 == 0),
        "alice udp_confirmed for mid should be clear; rows: {a:?}"
    );

    // No direct alice↔bob meta-conn → `send_sptps_data_relay` with
    // relay=mid, minmtu=0. C-parity predicate sends via TCP; the old
    // `relay_minmtu > 0 &&` guard sent via UDP → 100% loss here.
    let ping = Command::new("ping")
        .args(["-c", "3", "-W", "2", "10.42.0.2"])
        .output()
        .expect("spawn ping");

    drop(alice_ctl);
    let _ = mid_child.kill();
    let _ = bob_child.kill();
    let mid_stderr = drain_stderr(mid_child);
    let bob_stderr = drain_stderr(bob_child);
    let alice_stderr = drain_stderr(alice_child);

    assert!(
        ping.status.success(),
        "ping must succeed via TCP fallback while relay minmtu==0.\n\
         stdout: {}\nstderr: {}\n\
         === alice ===\n{alice_stderr}\n\
         === mid ===\n{mid_stderr}\n\
         === bob ===\n{bob_stderr}",
        String::from_utf8_lossy(&ping.stdout),
        String::from_utf8_lossy(&ping.stderr),
    );
    eprintln!("{}", String::from_utf8_lossy(&ping.stdout));

    drop(netns);
}
