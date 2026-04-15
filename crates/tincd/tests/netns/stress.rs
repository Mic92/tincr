//! Stress / chaos scenarios beyond `chaos.rs`'s steady-state netem.
//!
//! `chaos.rs` perturbs the UDP path WHILE the meta-conn stays up.
//! These tests perturb the META path too: link flap, daemon
//! restarts, asymmetric MTU, handshake-under-loss. They reproduce
//! the failure modes a live mesh hits that the unit tests can't
//! reach (the live test that found 5 bugs is the model — see the
//! commit that introduced this file).
//!
//! Same bwrap re-exec gate as everything else under `netns/`. Each
//! scenario is its own `#[test]` so failures are isolated and
//! nextest can shard/timeout them independently.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::chaos::{ChaosRig, Netem, node_pmtu};
use super::common::linux::*;
use super::common::*;
use super::rig::*;

fn tmp(tag: &str) -> TmpGuard {
    TmpGuard::new("netns", tag)
}

fn count_fds(pid: u32) -> usize {
    std::fs::read_dir(format!("/proc/{pid}/fd"))
        .map(|d| d.count())
        .unwrap_or(0)
}

// ═══════════════════════════════ 1. link flap ═════════════════════════════

/// Bring `lo` (the daemon↔daemon transport) down for 3s, back up.
///
/// **What's tested**: the periodic ping sweep notices the dead conn
/// (`"didn't respond to PING"`), `terminate()` fires, `retry_
/// outgoing` schedules a reconnect, the reconnect succeeds, and
/// data traffic resumes. No daemon crash, no fd leak.
///
/// `PingInterval = 1` + `PingTimeout = 1`: with the default 60s
/// pinginterval the sweep wouldn't even SEND a ping during the 3s
/// flap. `MaxTimeout = 2`: caps the retry backoff at 2s so the
/// reconnect happens inside the test budget (default cap is 900s).
///
/// `lo` not a veth: the existing harness puts both daemons'
/// 127.0.0.1 listeners in the OUTER netns (only the TUNs are
/// split). Downing `lo` blackholes alice↔bob TCP+UDP but leaves
/// the test's AF_UNIX `Ctl` sockets alone (they don't traverse a
/// netdev). Same observation `chaos.rs` made for netem.
#[test]
fn stress_link_flap() {
    let Some(netns) = enter_netns("stress::stress_link_flap") else {
        return;
    };
    let tmp = tmp("flap");
    let mut rig = ChaosRig::setup_with(netns, &tmp, "PingInterval = 1\nMaxTimeout = 2\n");

    // Baseline ping to prove the rig is up (ChaosRig already waited
    // for udp_confirmed).
    let p = Command::new("ping")
        .args(["-c", "2", "-W", "1", "10.42.0.2"])
        .output()
        .expect("spawn ping");
    assert!(p.status.success(), "pre-flap ping failed");

    // ─── flap ────────────────────────────────────────────────────
    // `lo down` blackholes 127.0.0.1. The kernel doesn't RST
    // existing TCP sessions on link-down; it just stops delivering.
    // The daemons must detect this themselves (PING timeout).
    run_ip(&["link", "set", "lo", "down"]);
    eprintln!("lo DOWN");

    // Wait for alice to drop bob. PingInterval=1 + PingTimeout=1
    // (clamped to ≤pinginterval) → sweep sends PING at t≈1s, no
    // PONG by t≈2s, terminate. Poll `dump nodes`: bob's reachable
    // bit clears once the edge is removed and graph() reruns.
    let dropped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        poll_until(Duration::from_secs(8), || {
            let a = rig.alice_ctl.dump(3);
            let unreachable = node_status(&a, "bob").is_none_or(|s| s & 0x10 == 0);
            unreachable.then_some(())
        });
    }));
    if dropped.is_err() {
        run_ip(&["link", "set", "lo", "up"]);
        let (a, b) = rig.finish();
        panic!(
            "alice never dropped bob during 3s lo-down. PING sweep \
             broken? (PingInterval=1, PingTimeout=1)\n\
             === alice ===\n{a}\n=== bob ===\n{b}"
        );
    }
    // Hold down for the full 3s so retry_outgoing's first attempt
    // (t+5s? no — bump_timeout starts at 0+5=5, MaxTimeout=2 caps
    // it at 2) definitely fails once before lo comes back.
    std::thread::sleep(Duration::from_secs(3));

    run_ip(&["link", "set", "lo", "up"]);
    eprintln!("lo UP");

    // ─── recover ─────────────────────────────────────────────────
    // alice's ConnectTo=bob outgoing re-fires (MaxTimeout=2 → next
    // attempt within 2s of the failed one). Then full handshake
    // again. Budget: 15s (2s backoff + handshake + udp_confirmed
    // ping kick, plus CI slack).
    let recover = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        poll_until(Duration::from_secs(15), || {
            let a = rig.alice_ctl.dump(3);
            node_status(&a, "bob")
                .is_some_and(|s| s & 0x10 != 0)
                .then_some(())
        });
        // Kick + wait validkey again (terminate() reset the tunnel).
        let _ = Command::new("ping")
            .args(["-c", "1", "-W", "1", "10.42.0.2"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        poll_until(Duration::from_secs(10), || {
            let a = rig.alice_ctl.dump(3);
            node_status(&a, "bob")
                .is_some_and(|s| s & 0x02 != 0)
                .then_some(())
        });
    }));
    if recover.is_err() {
        let (a, b) = rig.finish();
        panic!("post-flap reconnect timed out;\n=== alice ===\n{a}\n=== bob ===\n{b}");
    }

    // Traffic resumes.
    let p = Command::new("ping")
        .args(["-c", "3", "-W", "2", "10.42.0.2"])
        .output()
        .expect("spawn ping");
    let stdout = String::from_utf8_lossy(&p.stdout);
    eprintln!("{stdout}");

    let (alice_stderr, bob_stderr) = rig.finish();
    assert!(
        p.status.success(),
        "post-flap ping failed;\n=== alice ===\n{alice_stderr}\n=== bob ===\n{bob_stderr}"
    );

    // ─── log sequence ────────────────────────────────────────────
    // The expected trail. Substrings, not order: stderr is two
    // daemons interleaved by the kernel pipe scheduler.
    assert!(
        alice_stderr.contains("didn't respond to PING")
            || alice_stderr.contains("Closing connection"),
        "alice should log the dead-conn detection;\n{alice_stderr}"
    );
    assert!(
        alice_stderr.contains("Trying to re-establish")
            || alice_stderr.contains("Trying to connect"),
        "alice should log the retry;\n{alice_stderr}"
    );
    // No panic backtrace in either daemon.
    assert!(
        !alice_stderr.contains("panicked at") && !bob_stderr.contains("panicked at"),
        "daemon panicked during flap;\n=== alice ===\n{alice_stderr}\n=== bob ===\n{bob_stderr}"
    );
}

// ════════════════════════════ 2. asymmetric MTU ═══════════════════════════

/// `lo` MTU clamped to 1400. The daemons' UDP traverses lo, so
/// their PMTU discovery should converge to ≤ 1400 - 20 - 8 - 12 -
/// 21 = **1339** (the SPTPS encapsulation overhead — see
/// `choose_initial_maxmtu`). Then a 1300-byte ICMP echo with DF
/// set fits; a 1400-byte one would get FRAG_NEEDED — but THAT
/// path is `via_nid != myself` only (relay), so for direct
/// neighbors the kernel's own PMTU on tinc0 governs. We assert
/// the daemon-side PMTU value via `dump nodes` and that the
/// 1300-byte ping with DF succeeds end-to-end.
///
/// "Asymmetric" in the brief meant veth ends with different MTUs;
/// the existing harness uses `lo`, which has one MTU. We clamp it
/// to the smaller value (1400) — semantically equivalent for what
/// PMTU discovery observes (the bottleneck). True asymmetry would
/// need the veth-based rig from `BUGS-NETNS.md` TODO.
///
/// PMTU discovery is data-driven (`try_tx(.., mtu=true)` only on
/// the route_packet path). We feed it with a low-rate flood ping
/// while polling `dump nodes` for `mtu != 0`. 333ms cadence × 20
/// probes = ~7s worst case; budget 15s.
#[test]
fn stress_asymmetric_mtu() {
    let Some(netns) = enter_netns("stress::stress_asymmetric_mtu") else {
        return;
    };
    let tmp = tmp("amtu");

    // Clamp lo BEFORE spawning daemons so `choose_initial_maxmtu`
    // (which reads IP_MTU on a connected DGRAM socket to 127.0.0.1)
    // sees 1400 from the start. Otherwise the first probe goes out
    // at MTU=1518 and we depend on the EMSGSIZE shrink path —
    // which is ALSO worth testing, but separately.
    run_ip(&["link", "set", "lo", "mtu", "1400"]);

    let mut rig = ChaosRig::setup_with(netns, &tmp, "PingInterval = 1\n");

    // Drive PMTU. Background flood ping at 100ms; poll for mtu
    // fixed (mtu != 0) on BOTH sides.
    let mut flood = Command::new("ping")
        .args(["-i", "0.1", "-W", "1", "10.42.0.2"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn flood ping");

    let pmtu_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        poll_until(Duration::from_secs(20), || {
            let a = rig.alice_ctl.dump(3);
            let b = rig.bob_ctl.dump(3);
            let am = node_pmtu(&a, "bob")?;
            let bm = node_pmtu(&b, "alice")?;
            if am.0 != 0 && bm.0 != 0 {
                Some((am, bm))
            } else {
                None
            }
        })
    }));
    let _ = flood.kill();
    let _ = flood.wait();

    let (a_pmtu, b_pmtu) = match pmtu_result {
        Ok(v) => v,
        Err(_) => {
            let (a, b) = rig.finish();
            panic!(
                "PMTU never fixed under traffic (lo mtu=1400). \
                 try_tx(.., mtu=true) not driving discovery?\n\
                 === alice ===\n{a}\n=== bob ===\n{b}"
            );
        }
    };
    eprintln!("alice→bob pmtu: {a_pmtu:?}, bob→alice pmtu: {b_pmtu:?}");

    // 1400 - 20(ip) - 8(udp) - 12(id6) - 21(sptps) = 1339. Allow
    // a small slack: choose_initial_maxmtu computes exactly this,
    // but EMSGSIZE-driven shrink lands at probe_len-1 which can be
    // a few bytes lower. Assert ≤1339 (didn't blow past the
    // bottleneck) and ≥1200 (didn't collapse to the floor).
    for (who, (mtu, _, _)) in [("alice→bob", a_pmtu), ("bob→alice", b_pmtu)] {
        assert!(
            (1200..=1339).contains(&mtu),
            "{who} fixed mtu={mtu}, expected ≤1339 (lo mtu 1400 minus \
             encap overhead) and ≥1200 (sane floor). PMTU discovery \
             converged to the wrong value."
        );
    }

    // 1300-byte payload with DF set must succeed. 1300+8(icmp)+
    // 20(ip) = 1328 < 1339 inner MTU — fits. `-M do` sets DF.
    let p = Command::new("ping")
        .args(["-c", "2", "-W", "2", "-M", "do", "-s", "1300", "10.42.0.2"])
        .output()
        .expect("spawn ping");
    let out = String::from_utf8_lossy(&p.stdout);
    eprintln!("{out}");

    let (alice_stderr, bob_stderr) = rig.finish();
    assert!(
        p.status.success(),
        "1300-byte DF ping should fit inside discovered PMTU 1339; \
         got: {out}\n=== alice ===\n{alice_stderr}\n=== bob ===\n{bob_stderr}"
    );
    assert!(
        alice_stderr.contains("Fixing MTU of bob"),
        "alice should log LogFixed;\n{alice_stderr}"
    );
}

// ═══════════════════════ 3. handshake under loss ══════════════════════════

/// 20% loss on `lo` BEFORE the daemons are up. `chaos.rs` applies
/// netem AFTER validkey; this test does the opposite: prove the
/// SPTPS meta handshake (TCP) and the per-tunnel handshake
/// (REQ_KEY/ANS_KEY over TCP) still complete under loss, that
/// PMTU discovery still converges (probes are UDP, so 20% of them
/// drop — the 20-probe budget should absorb that), and that a
/// bulk transfer completes (slower).
///
/// Can't reuse `ChaosRig::setup` (it asserts validkey BEFORE we'd
/// apply chaos). Inline the setup with netem applied first.
#[test]
fn stress_handshake_under_loss() {
    let Some(netns) = enter_netns("stress::stress_handshake_under_loss") else {
        return;
    };
    let tmp = tmp("hsloss");

    // Apply netem to lo BEFORE spawning. 20% per direction.
    let _chaos = Netem::apply("lo", "loss 20%");

    let alice = Node::new(tmp.path(), "alice", 0xCA, "tinc0", "10.42.0.1/32");
    let bob = Node::new(tmp.path(), "bob", 0xCB, "tinc1", "10.42.0.2/32");
    bob.write_config_with(&alice, false, "PingInterval = 1\n");
    alice.write_config_with(&bob, true, "PingInterval = 1\n");

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

    // Meta handshake. TCP retransmits cover the 20% loss; budget
    // 20s (default RTO is 200ms on lo, ~5 retransmits worst case).
    let hs = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        poll_until(Duration::from_secs(20), || {
            let a = alice_ctl.dump(3);
            node_status(&a, "bob")
                .is_some_and(|s| s & 0x10 != 0)
                .then_some(())
        });
    }));
    if hs.is_err() {
        let _ = bob_child.kill();
        panic!(
            "meta handshake under 20% loss timed out;\n=== alice ===\n{}\n=== bob ===\n{}",
            drain_stderr(alice_child),
            drain_stderr(bob_child)
        );
    }

    // Drive PMTU + validkey with a flood ping. 20% loss on UDP
    // probes → some bisection steps lose; the 20-probe cap still
    // converges (each step is independent; expected ~16 land).
    let mut flood = Command::new("ping")
        .args(["-i", "0.1", "-W", "1", "10.42.0.2"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn flood ping");

    let conv = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        poll_until(Duration::from_secs(30), || {
            let a = alice_ctl.dump(3);
            let b = bob_ctl.dump(3);
            let a_ok = node_status(&a, "bob").is_some_and(|s| s & 0x82 == 0x82);
            let b_ok = node_status(&b, "alice").is_some_and(|s| s & 0x82 == 0x82);
            let am = node_pmtu(&a, "bob").map(|p| p.0).unwrap_or(0);
            (a_ok && b_ok && am != 0).then_some(am)
        })
    }));
    let _ = flood.kill();
    let _ = flood.wait();
    let am = match conv {
        Ok(m) => m,
        Err(_) => {
            let _ = bob_child.kill();
            panic!(
                "validkey/PMTU under 20% loss timed out;\n=== alice ===\n{}\n=== bob ===\n{}",
                drain_stderr(alice_child),
                drain_stderr(bob_child)
            );
        }
    };
    eprintln!("PMTU under 20% loss converged to {am}");

    // Bulk transfer: 1 MiB via socat. Slower (TCP congestion
    // control under 20% loss is brutal) but must complete. 8 MiB
    // would take ~minutes at 20% loss; 1 MiB is enough to prove
    // tso_split + the data path don't break under loss.
    if Command::new("socat").arg("-V").output().is_ok() {
        let data_path = tmp.path().join("stream.bin");
        let dd = Command::new("dd")
            .args(["if=/dev/urandom", "bs=1M", "count=1"])
            .arg(format!("of={}", data_path.display()))
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(dd.success());
        let ref_hash = Command::new("sha256sum").arg(&data_path).output().unwrap();
        let ref_hash = String::from_utf8_lossy(&ref_hash.stdout)
            .split_whitespace()
            .next()
            .unwrap()
            .to_owned();

        let rx_hash_path = tmp.path().join("rx.sha256");
        let rx = Command::new("ip")
            .args(["netns", "exec", "bobside", "sh", "-c"])
            .arg(format!(
                "socat -u TCP-LISTEN:18098,reuseaddr - | sha256sum > '{}'",
                rx_hash_path.display()
            ))
            .spawn()
            .unwrap();
        std::thread::sleep(Duration::from_millis(300));

        let tx = Command::new("socat")
            .arg("-u")
            .arg(format!("FILE:{}", data_path.display()))
            .arg("TCP:10.42.0.2:18098,connect-timeout=10")
            .output()
            .unwrap();
        let rx_status = rx.wait_with_output().unwrap().status;

        drop(alice_ctl);
        drop(bob_ctl);
        let _ = bob_child.kill();
        let bob_stderr = drain_stderr(bob_child);
        let alice_stderr = drain_stderr(alice_child);

        assert!(
            tx.status.success() && rx_status.success(),
            "bulk transfer under 20% loss failed; tx={:?} rx={rx_status:?}\n\
             === alice ===\n{alice_stderr}\n=== bob ===\n{bob_stderr}",
            tx.status
        );
        let rx_hash = std::fs::read_to_string(&rx_hash_path)
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .to_owned();
        assert_eq!(
            ref_hash, rx_hash,
            "sha256 mismatch under loss — data path corrupted the stream"
        );
    } else {
        eprintln!("SKIP bulk-transfer leg: socat not found");
        drop(alice_ctl);
        drop(bob_ctl);
        let _ = bob_child.kill();
        let _ = drain_stderr(bob_child);
        let _ = drain_stderr(alice_child);
    }
    drop(netns);
}

// ════════════════════════ 4. rapid reconnect storm ════════════════════════

/// Kill+restart bob 10× in quick succession. alice is the observer.
///
/// **What's tested**:
/// - alice's edge tree returns to baseline after each churn (no
///   leaked edges from a half-torn-down conn). `dump edges` count
///   should be exactly 2 (alice→bob + bob→alice) when settled.
/// - alice's fd count returns to baseline (no leaked TCP/epoll
///   fds from terminate()). `/proc/<pid>/fd` before vs after.
/// - alice never panics.
///
/// `MaxTimeout = 2` so alice's outgoing retry doesn't back off
/// past the test budget. `PingInterval = 1` so dead-bob is
/// detected fast even when SIGKILL leaves the TCP socket in a
/// state where the kernel doesn't immediately RST (it usually
/// does, but FIN-WAIT races happen).
#[test]
fn stress_rapid_reconnect_storm() {
    let Some(netns) = enter_netns("stress::stress_rapid_reconnect_storm") else {
        return;
    };
    let tmp = tmp("storm");
    let mut rig = ChaosRig::setup_with(netns, &tmp, "PingInterval = 1\nMaxTimeout = 2\n");

    // ─── baselines ──────────────────────────────────────────────
    let alice_pid = rig.alice_pid();
    let fd_baseline = count_fds(alice_pid);
    eprintln!("alice fd baseline: {fd_baseline}");
    let edge_baseline = rig.alice_ctl.dump(4).len();
    assert_eq!(
        edge_baseline, 2,
        "expected 2 edges at baseline (alice↔bob); got {edge_baseline}"
    );

    // ─── the storm ──────────────────────────────────────────────
    for i in 0..10 {
        eprintln!("── churn {i} ──");
        let _ = rig.kill_bob();

        // Wait for alice to notice. SIGKILL → kernel sends RST on
        // bob's sockets → alice's read() returns ECONNRESET →
        // terminate() immediate. Don't wait for unreachable bit
        // (graph rerun is async); just give it a turn.
        std::thread::sleep(Duration::from_millis(200));

        rig.respawn_bob();

        // Wait for alice to re-establish. alice has ConnectTo=bob;
        // her retry_outgoing fires within MaxTimeout=2. Budget 10s
        // per cycle.
        let ok = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            poll_until(Duration::from_secs(10), || {
                let a = rig.alice_ctl.dump(3);
                node_status(&a, "bob")
                    .is_some_and(|s| s & 0x10 != 0)
                    .then_some(())
            });
        }));
        if ok.is_err() {
            let (a, b) = rig.finish();
            panic!("churn {i}: alice never re-saw bob;\n=== alice ===\n{a}\n=== bob ===\n{b}");
        }
    }

    // ─── settle + check ─────────────────────────────────────────
    // Let any in-flight terminate()/DEL_EDGE drain.
    std::thread::sleep(Duration::from_millis(500));

    let edge_final = rig.alice_ctl.dump(4).len();
    let fd_final = count_fds(alice_pid);
    eprintln!("alice fd final: {fd_final}, edges: {edge_final}");

    let (alice_stderr, bob_stderr) = rig.finish();

    assert_eq!(
        edge_final, edge_baseline,
        "edge count drifted after 10× reconnect ({edge_baseline}→{edge_final}). \
         terminate() leaked an edge or on_ack double-inserted.\n\
         === alice ===\n{alice_stderr}"
    );
    // fd count: allow ±2 slack (the ctl reconnects in respawn_bob
    // bump it transiently; addrcache writes may hold a tmpfile).
    // A real leak is +10 or more (one per churn).
    assert!(
        fd_final <= fd_baseline + 2,
        "fd leak: baseline {fd_baseline} → final {fd_final} after 10× churn. \
         terminate() / connect_result not closing something.\n\
         === alice ===\n{alice_stderr}"
    );
    assert!(
        !alice_stderr.contains("panicked at") && !bob_stderr.contains("panicked at"),
        "daemon panicked during reconnect storm"
    );
}

// ═════════════════════ 5. three-node relay, mid restart ═══════════════════

/// alice ↔ mid ↔ bob (no direct alice↔bob). Real TUN on alice and
/// bob (so we can ping); mid is `DeviceType = dummy`. Kill mid →
/// alice sees bob become unreachable. Restart mid → alice→bob
/// traffic resumes.
///
/// Reuses the `NetNs` two-TUN rig (tinc0=alice, tinc1=bob). Mid
/// has no TUN. All three listen on 127.0.0.1 in the OUTER netns,
/// so mid relays both meta (REQ_KEY/ANS_KEY) and UDP data.
///
/// `MaxTimeout = 2` on alice/bob so their ConnectTo=mid retries
/// fast after mid restarts.
#[test]
fn stress_relay_mid_restart() {
    let Some(netns) = enter_netns("stress::stress_relay_mid_restart") else {
        return;
    };
    let tmp = tmp("midrestart");

    let alice = Node::new(tmp.path(), "alice", 0xA6, "tinc0", "10.42.0.1/32");
    let bob = Node::new(tmp.path(), "bob", 0xB6, "tinc1", "10.42.0.2/32");
    // mid: dummy device, no subnet. iface/subnet fields unused by
    // write_config_hub but Node::new wants them.
    let mid = Node::new(tmp.path(), "mid", 0xC6, "tinc0", "10.42.0.0/32");

    let extra = "PingInterval = 1\nMaxTimeout = 2\n";
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

    // ─── mesh up ────────────────────────────────────────────────
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

    // The brief's observation: first packet to a new indirect node
    // is always lost (REQ_KEY round-trip drops the trigger). Prove
    // the SECOND packet (and after) gets through. `ping -c 3`: at
    // least 2/3 must reply.
    let p = Command::new("ping")
        .args(["-c", "3", "-W", "2", "10.42.0.2"])
        .output()
        .expect("spawn ping");
    let stdout = String::from_utf8_lossy(&p.stdout);
    eprintln!("initial relay ping:\n{stdout}");
    let received: u32 = stdout
        .lines()
        .find(|l| l.contains("received"))
        .and_then(|l| {
            l.split(',')
                .find(|f| f.contains("received"))?
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        })
        .expect("ping summary");
    assert!(
        received >= 2,
        "first-packet-lost is expected, but 2nd/3rd should land; got {received}/3.\n{stdout}"
    );

    // ─── kill mid ───────────────────────────────────────────────
    let _ = mid_child.kill();
    let mid_stderr1 = drain_stderr(mid_child);
    eprintln!("mid killed");

    // alice should see bob become unreachable. PingInterval=1 →
    // alice's mid-conn dies (RST) → DEL_EDGE → graph() → bob
    // unreachable.
    let unr = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        poll_until(Duration::from_secs(10), || {
            let a = alice_ctl.dump(3);
            let bob_unreachable = node_status(&a, "bob").is_none_or(|s| s & 0x10 == 0);
            bob_unreachable.then_some(())
        });
    }));
    if unr.is_err() {
        let _ = bob_child.kill();
        panic!(
            "alice never saw bob become unreachable after mid died;\n\
             === alice ===\n{}\n=== mid ===\n{mid_stderr1}\n=== bob ===\n{}",
            drain_stderr(alice_child),
            drain_stderr(bob_child)
        );
    }

    // ─── restart mid ────────────────────────────────────────────
    std::fs::remove_file(&mid.socket).ok();
    let mut mid_child = mid.spawn_with_log(log);
    assert!(
        wait_for_file(&mid.socket),
        "mid respawn; stderr:\n{}",
        drain_stderr(mid_child)
    );

    // alice/bob retry ConnectTo=mid within MaxTimeout=2. Mesh
    // re-forms; alice→bob traffic resumes.
    let resume = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        poll_until(Duration::from_secs(15), || {
            let a = alice_ctl.dump(3);
            node_status(&a, "bob")
                .is_some_and(|s| s & 0x10 != 0)
                .then_some(())
        });
    }));
    if resume.is_err() {
        let _ = mid_child.kill();
        let _ = bob_child.kill();
        panic!(
            "mesh didn't re-form after mid restart;\n\
             === alice ===\n{}\n=== mid ===\n{}\n=== bob ===\n{}",
            drain_stderr(alice_child),
            drain_stderr(mid_child),
            drain_stderr(bob_child)
        );
    }

    // Traffic resumes. Same first-packet-lost caveat (REQ_KEY for
    // bob has to redo — terminate() on mid's conn reset alice's
    // bob-tunnel via `Node became unreachable`).
    let p = Command::new("ping")
        .args(["-c", "5", "-W", "2", "10.42.0.2"])
        .output()
        .expect("spawn ping");
    let stdout = String::from_utf8_lossy(&p.stdout);
    eprintln!("post-restart relay ping:\n{stdout}");
    let received: u32 = stdout
        .lines()
        .find(|l| l.contains("received"))
        .and_then(|l| {
            l.split(',')
                .find(|f| f.contains("received"))?
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        })
        .expect("ping summary");

    drop(alice_ctl);
    let _ = mid_child.kill();
    let _ = bob_child.kill();
    let alice_stderr = drain_stderr(alice_child);
    let mid_stderr2 = drain_stderr(mid_child);
    let bob_stderr = drain_stderr(bob_child);

    assert!(
        received >= 3,
        "post-mid-restart relay: only {received}/5 pings landed.\n\
         === alice ===\n{alice_stderr}\n=== mid ===\n{mid_stderr2}\n=== bob ===\n{bob_stderr}"
    );
    assert!(
        alice_stderr.contains("became unreachable"),
        "alice should log bob unreachable;\n{alice_stderr}"
    );
    assert!(
        !alice_stderr.contains("panicked at") && !bob_stderr.contains("panicked at"),
        "daemon panicked"
    );

    drop(netns);
}

// ═════════════════════════ 6. idle PMTU convergence ═══════════════════════

/// Two directly-connected nodes, NO data traffic, only the
/// keepalive `try_tx(.., mtu=false)` from `on_ping_tick`. After
/// 30s, does `dump nodes` show a fixed `mtu` or still `0`?
///
/// The brief observed: PMTU for an idle direct neighbor never
/// converges. `try_tx` with `mtu=true` only fires from
/// `route_packet` (data path); the periodic ping tick passes
/// `mtu=false` (`periodic.rs:108`). C tinc does the same
/// (`net.c:248: try_tx(c->node, false)`). So **`mtu == 0` after
/// idle is C-PARITY behavior**, not a Rust bug.
///
/// We assert that:
/// 1. `udp_confirmed` (bit 7) DOES flip on idle — `try_udp` sends
///    MIN_PROBE_SIZE keepalives every `udp_discovery_interval`
///    (2s), and the reply sets it. So UDP works; just not sized.
/// 2. `mtu` stays 0 (parity). If a future change makes idle PMTU
///    converge, this assert documents the behavior change.
///
/// `PingInterval = 1` so `on_ping_tick`'s `try_tx` runs. Can't
/// reuse `ChaosRig::setup` — it sends pings to drive validkey/
/// udp_confirmed, which IS data traffic. Inline setup that ONLY
/// waits for the meta handshake (reachable bit), then idles.
///
/// `#[ignore]` if comparing against C is desired: the harness
/// here runs Rust only. The C-parity claim is verified by source
/// inspection (`~/git/tinc/src/net.c:248`). See `BUGS-NETNS.md`.
#[test]
fn stress_idle_pmtu_convergence() {
    let Some(netns) = enter_netns("stress::stress_idle_pmtu_convergence") else {
        return;
    };
    let tmp = tmp("idlepmtu");

    let alice = Node::new(tmp.path(), "alice", 0xCA, "tinc0", "10.42.0.1/32");
    let bob = Node::new(tmp.path(), "bob", 0xCB, "tinc1", "10.42.0.2/32");
    // PingInterval=1 → on_ping_tick fires try_tx(.., false) every
    // second once validkey is set. But validkey requires REQ_KEY,
    // which requires a data packet to kick it… UNLESS the daemon
    // proactively REQ_KEYs. It doesn't (try_tx in on_ping_tick is
    // gated on validkey already set — `periodic.rs:100-104`).
    //
    // So a TRULY idle pair never even gets validkey. That's also
    // C parity. We send ONE ping to kick REQ_KEY (the brief's "no
    // data traffic, only keepalives" is post-handshake). Then
    // idle.
    bob.write_config_with(&alice, false, "PingInterval = 1\n");
    alice.write_config_with(&bob, true, "PingInterval = 1\n");

    let log = "tincd=info";
    let mut bob_child = bob.spawn_with_log(log);
    assert!(wait_for_file(&bob.socket), "{}", drain_stderr(bob_child));
    let alice_child = alice.spawn_with_log(log);
    if !wait_for_file(&alice.socket) {
        let _ = bob_child.kill();
        panic!("{}", drain_stderr(alice_child));
    }
    assert!(wait_for_carrier("tinc0", Duration::from_secs(2)));
    assert!(wait_for_carrier("tinc1", Duration::from_secs(2)));
    netns.place_devices();

    let mut alice_ctl = alice.ctl();
    poll_until(Duration::from_secs(10), || {
        let a = alice_ctl.dump(3);
        node_status(&a, "bob")
            .is_some_and(|s| s & 0x10 != 0)
            .then_some(())
    });

    // ONE ping to kick REQ_KEY. Then nothing for 30s.
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

    // ─── idle ───────────────────────────────────────────────────
    // 30s. on_ping_tick runs try_tx(bob, false) each second
    // (validkey gate now passes). try_udp sends MIN_PROBE_SIZE
    // keepalives. mtu=false → p.tick() never runs → mtu stays 0.
    eprintln!("idling 30s (keepalives only)...");
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut udp_confirmed_seen = false;
    while Instant::now() < deadline {
        let a = alice_ctl.dump(3);
        if node_status(&a, "bob").is_some_and(|s| s & 0x80 != 0) {
            udp_confirmed_seen = true;
        }
        std::thread::sleep(Duration::from_secs(1));
    }

    let a = alice_ctl.dump(3);
    let (mtu, minmtu, maxmtu) = node_pmtu(&a, "bob").expect("bob row");
    eprintln!("after 30s idle: mtu={mtu} minmtu={minmtu} maxmtu={maxmtu}");

    drop(alice_ctl);
    let _ = bob_child.kill();
    let bob_stderr = drain_stderr(bob_child);
    let alice_stderr = drain_stderr(alice_child);

    // udp_confirmed should flip (try_udp keepalives work).
    assert!(
        udp_confirmed_seen,
        "udp_confirmed never flipped on idle. try_udp keepalive broken?\n\
         === alice ===\n{alice_stderr}\n=== bob ===\n{bob_stderr}"
    );

    // C-PARITY: mtu stays 0. If this fires, behavior changed —
    // either a bug (idle data leaking onto the tunnel) or an
    // intentional improvement (idle PMTU). See BUGS-NETNS.md §6.
    assert_eq!(
        mtu, 0,
        "idle PMTU converged to {mtu} — diverges from C tinc \
         (net.c:248 try_tx(c->node, false)). If intentional, \
         update BUGS-NETNS.md §6 and this assert.\n\
         === alice ===\n{alice_stderr}"
    );
    // minmtu may be 18 (the MIN_PROBE_SIZE keepalive reply raises
    // it). That's fine — it's not a "fixed" mtu.
    assert!(
        minmtu <= 64,
        "idle minmtu={minmtu} — something larger than the keepalive \
         probe got through. Data leak?"
    );

    drop(netns);
}
