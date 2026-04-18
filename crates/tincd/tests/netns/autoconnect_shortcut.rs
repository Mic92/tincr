//! Regression: autoconnect never promotes a hot relay path to a
//! direct meta-connection.
//!
//! `alice — {mid,mid2,mid3} — bob` with bob's UDP blackholed: alice's
//! data to bob rides `SPTPS_PACKET` over TCP through mid at 2× RTT,
//! forever, because upstream `do_autoconnect` is satisfied at
//! degree ≥3 and never looks at the data plane.
//!
//! Three hubs (not one) so alice reaches `nc=3` and the shortcut arm
//! actually fires — at `nc<3` the random-backbone arm early-returns.
//! All knobs are hardcoded (`autoconnect.rs::ShortcutKnobs`); the
//! only config here is `AutoConnect = yes` on alice and `= no`
//! everywhere else so the hubs/bob don't dial around the test.
//!
//! Asserts: a flood at >`RELAY_HI` (32 KiB/s) makes alice open a
//! direct meta connection to bob within ~6 ticks; once the flood
//! stops, the shortcut is dropped within EWMA-decay (~9 ticks).

use std::process::{Command, Stdio};
use std::time::Duration;

use super::common::linux::*;
use super::common::*;
use super::rig::*;

/// alice has a direct meta-conn to `name`?
fn has_direct_conn(ctl: &mut Ctl, name: &str) -> bool {
    ctl.dump(6).iter().any(|r| {
        r.strip_prefix("18 6 ")
            .and_then(|b| b.split_whitespace().next())
            == Some(name)
    })
}

#[test]
fn autoconnect_shortcut_promotes_hot_relay() {
    let Some(netns) = enter_netns("autoconnect_shortcut::autoconnect_shortcut_promotes_hot_relay")
    else {
        return;
    };

    let tmp = TmpGuard::new("netns", "ac-shortcut");
    let alice = Node::new(tmp.path(), "alice", 0xFA, "tinc0", "10.42.0.1/32");
    let bob = Node::new(tmp.path(), "bob", 0xFB, "tinc1", "10.42.0.2/32");
    let mid = Node::new(tmp.path(), "mid", 0xFC, "tinc0", "10.42.0.0/32");
    let mid2 = Node::new(tmp.path(), "mid2", 0xFD, "tinc0", "10.42.0.0/32");
    let mid3 = Node::new(tmp.path(), "mid3", 0xFE, "tinc0", "10.42.0.0/32");

    // Hubs: dummy device, AutoConnect=no. Only mid is on the data
    // path to bob; mid2/mid3 exist purely to fill alice's degree-3
    // backbone so the shortcut arm is reachable.
    let off = "AutoConnect = no\n";
    mid.write_config_hub(&[&alice, &bob, &mid2, &mid3], off);
    mid2.write_config_hub(&[&alice, &mid, &mid3], off);
    mid3.write_config_hub(&[&alice, &mid, &mid2], off);
    bob.write_config_multi(&[&mid, &alice], &["mid"], off);
    // alice: AutoConnect=yes (default), ConnectTo all three hubs.
    // bob's hosts/ file MUST carry `Address` so `has_address` is set
    // — write_config_multi only writes Address for ConnectTo targets,
    // so patch it in afterwards.
    alice.write_config_multi(&[&mid, &mid2, &mid3, &bob], &["mid", "mid2", "mid3"], "");
    std::fs::write(
        alice.confbase.join("hosts").join("bob"),
        format!(
            "Ed25519PublicKey = {}\nAddress = 127.0.0.1 {}\n",
            tinc_crypto::b64::encode(&bob.pubkey()),
            bob.port,
        ),
    )
    .unwrap();

    let log = "tincd=info";
    let mut hubs: Vec<_> = [&mid, &mid2, &mid3]
        .iter()
        .map(|n| {
            let c = n.spawn_with_log(log);
            assert!(wait_for_file(&n.socket), "{} setup", n.confbase.display());
            c
        })
        .collect();
    let mut bob_child = bob.spawn_with_log(log);
    if !wait_for_file(&bob.socket) {
        for h in &mut hubs {
            let _ = h.kill();
            let _ = h.wait();
        }
        panic!("bob setup; stderr:\n{}", drain_stderr(bob_child));
    }

    // Blackhole bob's UDP listener: alice↔mid* UDP works (so the
    // PACKET 17 short-circuit fires for the hubs and relay_rate=0
    // there), but alice→bob UDP never confirms — data goes via mid
    // over TCP and bumps relay_tx_bytes[bob].
    let ipt = Command::new("iptables")
        .args([
            "-I",
            "INPUT",
            "-p",
            "udp",
            "--dport",
            &bob.port.to_string(),
            "-j",
            "DROP",
        ])
        .output()
        .expect("spawn iptables");
    if !ipt.status.success() {
        for h in &mut hubs {
            let _ = h.kill();
            let _ = h.wait();
        }
        let _ = bob_child.kill();
        let _ = bob_child.wait();
        eprintln!(
            "SKIP autoconnect_shortcut: iptables failed: {}",
            String::from_utf8_lossy(&ipt.stderr).trim()
        );
        return;
    }

    let alice_child = alice.spawn_with_log(log);
    if !wait_for_file(&alice.socket) {
        for h in &mut hubs {
            let _ = h.kill();
            let _ = h.wait();
        }
        let _ = bob_child.kill();
        let _ = bob_child.wait();
        panic!("alice setup; stderr:\n{}", drain_stderr(alice_child));
    }

    assert!(wait_for_carrier("tinc0", Duration::from_secs(2)));
    assert!(wait_for_carrier("tinc1", Duration::from_secs(2)));
    netns.place_devices();

    let mut alice_ctl = alice.ctl();

    // ─── mesh up: bob reachable (via mid), alice at nc≥3 ────────
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        poll_until(Duration::from_secs(10), || {
            let a = alice_ctl.dump(3);
            let bob_reach = node_status(&a, "bob").is_some_and(|s| s & 0x10 != 0);
            let nc = alice_ctl
                .dump(6)
                .iter()
                .filter(|r| r.starts_with("18 6 ") && !r.contains("<control>"))
                .count();
            (bob_reach && nc >= 3).then_some(())
        });
    }));
    if r.is_err() {
        for h in &mut hubs {
            let _ = h.kill();
            let _ = h.wait();
        }
        let _ = bob_child.kill();
        let _ = bob_child.wait();
        panic!(
            "mesh up timed out;\n=== alice ===\n{}",
            drain_stderr(alice_child)
        );
    }
    // Precondition: NO direct conn to bob yet.
    assert!(
        !has_direct_conn(&mut alice_ctl, "bob"),
        "precondition: alice must not be directly connected to bob yet"
    );

    // ─── flood alice→bob above RELAY_HI (32 KiB/s) ──────────────
    // 0.01s × 1000B payload ≈ 100 KiB/s. Runs in background.
    let mut flood = Command::new("ping")
        .args(["-i", "0.01", "-s", "1000", "-q", "10.42.0.2"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ping flood");

    // ≤6 ticks × 5s = 30s.
    let promoted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        poll_until(Duration::from_secs(30), || {
            has_direct_conn(&mut alice_ctl, "bob").then_some(())
        });
    }));
    let _ = flood.kill();
    let _ = flood.wait();

    if promoted.is_err() {
        for h in &mut hubs {
            let _ = h.kill();
            let _ = h.wait();
        }
        let _ = bob_child.kill();
        let _ = bob_child.wait();
        panic!(
            "shortcut not added within 30s;\n=== alice ===\n{}",
            drain_stderr(alice_child)
        );
    }

    // ─── flood stopped → shortcut dropped ───────────────────────
    // min_hold (60s post-activation) must elapse first, then
    // tx_rate decays ×0.7/tick; from ~100 KiB/s to <4 KiB/s ≈ 9
    // ticks ≈ 45s. nc=4>D_LO so the idle-reap arm fires.
    let dropped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        poll_until(Duration::from_secs(90), || {
            (!has_direct_conn(&mut alice_ctl, "bob")).then_some(())
        });
    }));

    drop(alice_ctl);
    for h in &mut hubs {
        let _ = h.kill();
    }
    let _ = bob_child.kill();
    let alice_stderr = drain_stderr(alice_child);
    let bob_stderr = drain_stderr(bob_child);
    for h in hubs {
        let _ = drain_stderr(h);
    }

    assert!(
        dropped.is_ok(),
        "shortcut not dropped after idle;\n=== alice ===\n{alice_stderr}\n\
         === bob ===\n{bob_stderr}",
    );

    drop(netns);
}

/// Regression: shortcut conn must not flap when the load that
/// triggered it pauses briefly. Same alice-hub-bob shape, but after
/// the direct conn activates, STOP the flood for 30s, then resume.
/// Without `min_hold` the idle-reap drops the seconds-old conn during
/// the gap and the resumed flood re-adds it → ≥2 activations.
#[test]
fn shortcut_survives_traffic_gap() {
    let Some(netns) = enter_netns("autoconnect_shortcut::shortcut_survives_traffic_gap") else {
        return;
    };

    let tmp = TmpGuard::new("netns", "ac-shortcut-gap");
    let alice = Node::new(tmp.path(), "alice", 0xEA, "tinc0", "10.42.0.1/32");
    let bob = Node::new(tmp.path(), "bob", 0xEB, "tinc1", "10.42.0.2/32");
    let mid = Node::new(tmp.path(), "mid", 0xEC, "tinc0", "10.42.0.0/32");
    let mid2 = Node::new(tmp.path(), "mid2", 0xED, "tinc0", "10.42.0.0/32");
    let mid3 = Node::new(tmp.path(), "mid3", 0xEE, "tinc0", "10.42.0.0/32");

    let off = "AutoConnect = no\n";
    mid.write_config_hub(&[&alice, &bob, &mid2, &mid3], off);
    mid2.write_config_hub(&[&alice, &mid, &mid3], off);
    mid3.write_config_hub(&[&alice, &mid, &mid2], off);
    bob.write_config_multi(&[&mid, &alice], &["mid"], off);
    alice.write_config_multi(&[&mid, &mid2, &mid3, &bob], &["mid", "mid2", "mid3"], "");
    std::fs::write(
        alice.confbase.join("hosts").join("bob"),
        format!(
            "Ed25519PublicKey = {}\nAddress = 127.0.0.1 {}\n",
            tinc_crypto::b64::encode(&bob.pubkey()),
            bob.port,
        ),
    )
    .unwrap();

    let log = "tincd=info";
    let mut hubs: Vec<_> = [&mid, &mid2, &mid3]
        .iter()
        .map(|n| {
            let c = n.spawn_with_log(log);
            assert!(wait_for_file(&n.socket), "{} setup", n.confbase.display());
            c
        })
        .collect();
    let mut bob_child = bob.spawn_with_log(log);
    if !wait_for_file(&bob.socket) {
        for h in &mut hubs {
            let _ = h.kill();
            let _ = h.wait();
        }
        panic!("bob setup; stderr:\n{}", drain_stderr(bob_child));
    }

    let ipt = Command::new("iptables")
        .args([
            "-I",
            "INPUT",
            "-p",
            "udp",
            "--dport",
            &bob.port.to_string(),
            "-j",
            "DROP",
        ])
        .output()
        .expect("spawn iptables");
    if !ipt.status.success() {
        for h in &mut hubs {
            let _ = h.kill();
            let _ = h.wait();
        }
        let _ = bob_child.kill();
        let _ = bob_child.wait();
        eprintln!(
            "SKIP shortcut_survives_traffic_gap: iptables failed: {}",
            String::from_utf8_lossy(&ipt.stderr).trim()
        );
        return;
    }

    let alice_child = alice.spawn_with_log(log);
    if !wait_for_file(&alice.socket) {
        for h in &mut hubs {
            let _ = h.kill();
            let _ = h.wait();
        }
        let _ = bob_child.kill();
        let _ = bob_child.wait();
        panic!("alice setup; stderr:\n{}", drain_stderr(alice_child));
    }

    assert!(wait_for_carrier("tinc0", Duration::from_secs(2)));
    assert!(wait_for_carrier("tinc1", Duration::from_secs(2)));
    netns.place_devices();

    let mut alice_ctl = alice.ctl();

    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        poll_until(Duration::from_secs(10), || {
            let a = alice_ctl.dump(3);
            let bob_reach = node_status(&a, "bob").is_some_and(|s| s & 0x10 != 0);
            let nc = alice_ctl
                .dump(6)
                .iter()
                .filter(|r| r.starts_with("18 6 ") && !r.contains("<control>"))
                .count();
            (bob_reach && nc >= 3).then_some(())
        });
    }));
    if r.is_err() {
        for h in &mut hubs {
            let _ = h.kill();
            let _ = h.wait();
        }
        let _ = bob_child.kill();
        let _ = bob_child.wait();
        panic!(
            "mesh up timed out;\n=== alice ===\n{}",
            drain_stderr(alice_child)
        );
    }
    assert!(!has_direct_conn(&mut alice_ctl, "bob"));

    // ─── flood → shortcut activates ──────────────────────────────
    let mut flood = Command::new("ping")
        .args(["-i", "0.01", "-s", "1000", "-q", "10.42.0.2"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ping flood");
    let promoted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        poll_until(Duration::from_secs(30), || {
            has_direct_conn(&mut alice_ctl, "bob").then_some(())
        });
    }));
    let _ = flood.kill();
    let _ = flood.wait();
    if promoted.is_err() {
        for h in &mut hubs {
            let _ = h.kill();
            let _ = h.wait();
        }
        let _ = bob_child.kill();
        let _ = bob_child.wait();
        panic!(
            "shortcut not added within 30s;\n=== alice ===\n{}",
            drain_stderr(alice_child)
        );
    }

    // ─── 30s gap (no traffic) ───────────────────────────────────
    // Shorter than min_hold (60s) — the conn must stay up the whole
    // time. Poll the conn list so a flap is caught immediately, not
    // just inferred from the activation count at the end.
    let gap_start = std::time::Instant::now();
    let mut flapped = false;
    while gap_start.elapsed() < Duration::from_secs(30) {
        if !has_direct_conn(&mut alice_ctl, "bob") {
            flapped = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }

    // ─── resume flood briefly ────────────────────────────────────
    let mut flood2 = Command::new("ping")
        .args(["-i", "0.01", "-s", "1000", "-q", "-w", "10", "10.42.0.2"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ping flood");
    let _ = flood2.wait();

    drop(alice_ctl);
    for h in &mut hubs {
        let _ = h.kill();
    }
    let _ = bob_child.kill();
    let alice_stderr = drain_stderr(alice_child);
    let _ = drain_stderr(bob_child);
    for h in hubs {
        let _ = drain_stderr(h);
    }

    // Exactly one "Connection with bob ... activated" over the whole
    // run. Pre-fix: ≥2 (gap drops, resume re-adds).
    let activations = alice_stderr
        .lines()
        .filter(|l| l.contains("Connection with bob") && l.contains("activated"))
        .count();
    assert!(
        !flapped,
        "shortcut dropped during 30s traffic gap;\n=== alice ===\n{alice_stderr}"
    );
    assert_eq!(
        activations, 1,
        "expected exactly 1 bob activation, got {activations};\n\
         === alice ===\n{alice_stderr}"
    );

    drop(netns);
}
