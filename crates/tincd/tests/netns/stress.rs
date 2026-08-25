//! Perturbing the meta path: link flap, MTU clamp, handshake under
//! loss, peer/relay restarts, idle PMTU.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::common::linux::run_ip;
use super::common::{KillOnDrop, node_status, try_poll};
use super::rig::{Netem, Node, TunPair, enter_netns, node_pmtu, ping, ping_received};

fn count_fds(pid: nix::unistd::Pid) -> usize {
    std::fs::read_dir(format!("/proc/{pid}/fd")).map_or(0, Iterator::count)
}

fn flood_ping() -> KillOnDrop {
    KillOnDrop(
        Command::new("ping")
            .args(["-i", "0.1", "-W", "1", "10.42.0.2"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn flood ping"),
    )
}

fn alice_sees_bob(pair: &TunPair, reachable: bool, timeout: Duration) -> bool {
    try_poll(timeout, || {
        let nodes = pair.alice.ctl().dump(3);
        (node_status(&nodes, "bob").is_some_and(|s| s & 0x10 != 0) == reachable).then_some(())
    })
    .is_some()
}

fn assert_no_panic(alice_log: &str, bob_log: &str) {
    assert!(
        !alice_log.contains("panicked at") && !bob_log.contains("panicked at"),
        "=== alice ===\n{alice_log}\n=== bob ===\n{bob_log}"
    );
}

/// `lo` (the daemon↔daemon transport; control sockets are `AF_UNIX` and
/// unaffected) down for 3s. The ping sweep must notice, the outgoing
/// must retry (`MaxTimeout` caps backoff), traffic must resume.
#[test]
fn stress_link_flap() {
    let Some(netns) = enter_netns("stress::stress_link_flap") else {
        return;
    };
    let tmp = tmp!("flap");
    let pair = TunPair::start(netns, &tmp, "PingInterval = 1\nMaxTimeout = 2");
    pair.wait_validkey();
    assert!(ping(&["-c", "2", "-W", "1"], "10.42.0.2").status.success());

    run_ip(&["link", "set", "lo", "down"]);
    let dropped = alice_sees_bob(&pair, false, Duration::from_secs(8));
    std::thread::sleep(Duration::from_secs(3));
    run_ip(&["link", "set", "lo", "up"]);
    if !dropped {
        let (alice_log, bob_log) = pair.finish();
        panic!("alice never dropped bob\n=== alice ===\n{alice_log}\n=== bob ===\n{bob_log}");
    }

    if !alice_sees_bob(&pair, true, Duration::from_secs(15)) {
        let (alice_log, bob_log) = pair.finish();
        panic!("no reconnect\n=== alice ===\n{alice_log}\n=== bob ===\n{bob_log}");
    }
    pair.wait_validkey();
    let output = ping(&["-c", "3", "-W", "2"], "10.42.0.2");
    let (alice_log, bob_log) = pair.finish();
    assert!(
        output.status.success(),
        "=== alice ===\n{alice_log}\n=== bob ===\n{bob_log}"
    );
    assert!(
        alice_log.contains("didn't respond to PING") || alice_log.contains("Closing connection"),
        "{alice_log}"
    );
    assert!(
        alice_log.contains("Trying to re-establish") || alice_log.contains("Trying to connect"),
        "{alice_log}"
    );
    assert_no_panic(&alice_log, &bob_log);
}

/// `lo` MTU 1400: PMTU must converge to ≤ 1400 − 20 − 8 − 12 − 21 =
/// 1339, and a DF ping that no longer fits must get `FRAG_NEEDED` back
/// rather than vanish.
#[test]
fn stress_asymmetric_mtu() {
    let Some(netns) = enter_netns("stress::stress_asymmetric_mtu") else {
        return;
    };
    let tmp = tmp!("amtu");
    // Before the daemons start so the initial maxmtu guess sees it.
    run_ip(&["link", "set", "lo", "mtu", "1400"]);
    let pair = TunPair::start(netns, &tmp, "PingInterval = 1");
    pair.wait_validkey();
    pair.wait_udp_confirmed();

    // PMTU discovery is driven by data traffic only.
    let flood = flood_ping();
    let pmtu = try_poll(Duration::from_secs(20), || {
        let alice = node_pmtu(&pair.alice.ctl().dump(3), "bob")?;
        let bob = node_pmtu(&pair.bob.ctl().dump(3), "alice")?;
        (alice.0 != 0 && bob.0 != 0).then_some([alice.0, bob.0])
    });
    drop(flood);
    let Some(mtus) = pmtu else {
        let (alice_log, bob_log) = pair.finish();
        panic!("PMTU never fixed\n=== alice ===\n{alice_log}\n=== bob ===\n{bob_log}");
    };
    for mtu in mtus {
        assert!((1200..=1339).contains(&mtu), "mtu {mtu}");
    }

    let output = ping(
        &["-c", "2", "-W", "2", "-M", "do", "-s", "1300"],
        "10.42.0.2",
    );
    let text = String::from_utf8_lossy(&output.stdout) + String::from_utf8_lossy(&output.stderr);
    let (alice_log, bob_log) = pair.finish();
    assert!(
        ["Frag needed", "frag needed", "Message too long"]
            .iter()
            .any(|needle| text.contains(needle)),
        "{text}\n=== alice ===\n{alice_log}\n=== bob ===\n{bob_log}"
    );
    assert!(alice_log.contains("Fixing MTU of bob"), "{alice_log}");
    assert!(alice_log.contains("FRAG_NEEDED"), "{alice_log}");
}

/// 20% loss on `lo` from the start: the TCP meta handshake, the
/// per-tunnel key exchange and UDP PMTU discovery must all still
/// converge.
#[test]
fn stress_handshake_under_loss() {
    let Some(netns) = enter_netns("stress::stress_handshake_under_loss") else {
        return;
    };
    let tmp = tmp!("hsloss");
    let _netem = Netem::apply("lo", "loss 20%");
    // PingTimeout 1 would race the kernel's 1s SYN retransmit.
    let mut pair = TunPair::new(netns, &tmp, "PingTimeout = 5\nPingInterval = 5");
    pair.bob.write_config(&pair.alice, false);
    pair.bob.start();
    pair.alice.write_config(&pair.bob, true);
    pair.alice.start();
    pair.netns.place_devices();
    if !alice_sees_bob(&pair, true, Duration::from_secs(20)) {
        let (alice_log, bob_log) = pair.finish();
        panic!("meta handshake\n=== alice ===\n{alice_log}\n=== bob ===\n{bob_log}");
    }

    let flood = flood_ping();
    let converged = try_poll(Duration::from_secs(30), || {
        let alice = pair.alice.ctl().dump(3);
        let bob = pair.bob.ctl().dump(3);
        (node_status(&alice, "bob")? & 0x82 == 0x82
            && node_status(&bob, "alice")? & 0x82 == 0x82
            && node_pmtu(&alice, "bob")?.0 != 0)
            .then_some(())
    });
    drop(flood);
    if converged.is_none() {
        let (alice_log, bob_log) = pair.finish();
        panic!("validkey/PMTU under loss\n=== alice ===\n{alice_log}\n=== bob ===\n{bob_log}");
    }

    // Expect ~0.64 × 30; TCP bulk under this loss is too slow to test.
    let received = ping_received(&ping(&["-c", "30", "-i", "0.05", "-W", "1"], "10.42.0.2"));
    let (alice_log, bob_log) = pair.finish();
    assert!(
        received >= 5,
        "{received}/30\n=== alice ===\n{alice_log}\n=== bob ===\n{bob_log}"
    );
}

/// Kill and restart bob ten times; alice must end with the same edge
/// count and (±2) fd count she started with.
#[test]
fn stress_rapid_reconnect_storm() {
    let Some(netns) = enter_netns("stress::stress_rapid_reconnect_storm") else {
        return;
    };
    let tmp = tmp!("storm");
    let mut pair = TunPair::start(netns, &tmp, "PingInterval = 1\nMaxTimeout = 2");
    pair.wait_validkey();
    let fd_baseline = count_fds(pair.alice.pid());
    assert_eq!(pair.alice.ctl().dump(4).len(), 2);

    for churn in 0..10 {
        pair.bob.stop();
        // SIGKILL → RST → alice terminates the connection at once.
        std::thread::sleep(Duration::from_millis(200));
        pair.bob.start();
        if !alice_sees_bob(&pair, true, Duration::from_secs(10)) {
            let (alice_log, bob_log) = pair.finish();
            panic!("churn {churn}\n=== alice ===\n{alice_log}\n=== bob ===\n{bob_log}");
        }
    }
    std::thread::sleep(Duration::from_millis(500));
    let edges = pair.alice.ctl().dump(4).len();
    let fds = count_fds(pair.alice.pid());
    let (alice_log, bob_log) = pair.finish();
    assert_eq!(edges, 2, "edge leak\n{alice_log}");
    assert!(
        fds <= fd_baseline + 2,
        "fd leak: {fd_baseline} → {fds}\n{alice_log}"
    );
    assert_no_panic(&alice_log, &bob_log);
}

/// alice ↔ mid ↔ bob, mid has no TUN. Killing mid makes bob
/// unreachable; restarting it brings traffic back. The first packets
/// after (re)forming are expected to be lost to `REQ_KEY` and to mid's
/// relay gate needing a probe round-trip first.
#[test]
fn stress_relay_mid_restart() {
    let Some(netns) = enter_netns("stress::stress_relay_mid_restart") else {
        return;
    };
    let tmp = tmp!("midrestart");
    let extra = "PingInterval = 1\nMaxTimeout = 2\nUDPDiscoveryInterval = 1";
    let TunPair {
        netns,
        mut alice,
        mut bob,
    } = TunPair::new(netns, &tmp, extra);
    let mut mid = Node::new(tmp.path(), "mid", 0xC6)
        .with_conf(extra)
        .log_level("tincd=info,tincd::net=debug");
    mid.write_config_multi(&[&alice, &bob], &[]);
    mid.start();
    alice.write_config_multi(&[&mid, &bob], &[&mid]);
    bob.write_config_multi(&[&mid, &alice], &[&mid]);
    bob.start();
    alice.start();
    netns.place_devices();
    let pair = TunPair { netns, alice, bob };
    let logs = |pair: TunPair, mid: &mut Node| {
        let mid_log = mid.stop();
        let (alice_log, bob_log) = pair.finish();
        format!("=== alice ===\n{alice_log}\n=== mid ===\n{mid_log}\n=== bob ===\n{bob_log}")
    };
    assert!(
        alice_sees_bob(&pair, true, Duration::from_secs(10)),
        "mesh up\n{}",
        logs(pair, &mut mid)
    );
    let relay_ping = || ping_received(&ping(&["-c", "8", "-i", "0.5", "-W", "2"], "10.42.0.2"));
    assert!(
        relay_ping() >= 2,
        "initial relay ping\n{}",
        logs(pair, &mut mid)
    );

    mid.stop();
    assert!(
        alice_sees_bob(&pair, false, Duration::from_secs(10)),
        "bob still reachable without mid\n{}",
        logs(pair, &mut mid)
    );
    mid.start();
    assert!(
        alice_sees_bob(&pair, true, Duration::from_secs(15)),
        "mesh did not re-form\n{}",
        logs(pair, &mut mid)
    );
    let received = relay_ping();
    let alice_log = pair.alice.log();
    let all_logs = logs(pair, &mut mid);
    assert!(received >= 2, "{received}/8 after restart\n{all_logs}");
    assert!(alice_log.contains("became unreachable"), "{alice_log}");
    assert!(!all_logs.contains("panicked at"), "{all_logs}");
}

/// C parity: with keepalives only (one ping to get validkey, then
/// idle), `udp_confirmed` flips but `mtu` is never fixed because the
/// ping tick calls `try_tx(.., mtu=false)`. If idle PMTU ever
/// converges, this documents the behaviour change.
#[test]
fn stress_idle_pmtu_convergence() {
    let Some(netns) = enter_netns("stress::stress_idle_pmtu_convergence") else {
        return;
    };
    let tmp = tmp!("idlepmtu");
    let mut pair = TunPair::new(netns, &tmp, "PingInterval = 1");
    pair.alice = pair.alice.log_level("tincd=info");
    pair.bob = pair.bob.log_level("tincd=info");
    pair.start_direct();
    pair.wait_validkey();

    // > 10s so at least one keepalive-interval cycle happens.
    let deadline = Instant::now() + Duration::from_secs(12);
    let mut udp_confirmed = false;
    while Instant::now() < deadline {
        udp_confirmed |=
            node_status(&pair.alice.ctl().dump(3), "bob").is_some_and(|s| s & 0x80 != 0);
        std::thread::sleep(Duration::from_secs(1));
    }
    let (mtu, _, _) = node_pmtu(&pair.alice.ctl().dump(3), "bob").unwrap();
    let (alice_log, bob_log) = pair.finish();
    assert!(
        udp_confirmed,
        "=== alice ===\n{alice_log}\n=== bob ===\n{bob_log}"
    );
    assert_eq!(
        mtu, 0,
        "idle PMTU converged; update BUGS-NETNS.md §6\n{alice_log}"
    );
}
