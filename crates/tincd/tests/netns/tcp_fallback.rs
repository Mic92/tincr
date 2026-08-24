//! Regression: with all UDP blackholed, data to an *indirect* node
//! must stay on TCP while the relay's `minmtu` is 0. Needs three
//! nodes since direct peers short-circuit before the relay decision.

use std::process::Command;

use super::common::*;
use super::rig::*;

pub(crate) fn iptables(args: &[&str]) -> bool {
    let out = Command::new("iptables")
        .args(args)
        .output()
        .expect("spawn iptables");
    if !out.status.success() {
        eprintln!(
            "SKIP: iptables {args:?}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    out.status.success()
}

#[test]
fn tcp_fallback_udp_blackhole() {
    let Some(netns) = enter_netns("tcp_fallback::tcp_fallback_udp_blackhole") else {
        return;
    };
    if !iptables(&["-I", "INPUT", "-p", "udp", "-j", "DROP"]) {
        return;
    }
    let tmp = tmp!("tcpfb");
    // AutoConnect would let bob dial alice directly.
    let TunPair {
        netns,
        mut alice,
        mut bob,
    } = TunPair::new(netns, &tmp, "AutoConnect = no");
    let mut mid = Node::new(tmp.path(), "mid", 0xFC).with_conf("AutoConnect = no");
    mid.write_config_multi(&[&alice, &bob], &[]);
    mid.start();
    alice.write_config_multi(&[&mid, &bob], &[&mid]);
    bob.write_config_multi(&[&mid, &alice], &[&mid]);
    bob.start();
    alice.start();
    netns.place_devices();
    let pair = TunPair { netns, alice, bob };
    pair.wait_reachable();
    // The handshake itself always rides TCP.
    pair.wait_validkey();

    let alice_nodes = pair.alice.ctl().dump(3);
    assert_eq!(node_pmtu(&alice_nodes, "mid").map(|pmtu| pmtu.1), Some(0));
    assert!(node_status(&alice_nodes, "mid").is_some_and(|s| s & 0x80 == 0));

    let output = ping(&["-c", "3", "-W", "2"], "10.42.0.2");
    let mid_log = mid.stop();
    let (alice_log, bob_log) = pair.finish();
    assert!(
        output.status.success(),
        "{}\n=== alice ===\n{alice_log}\n=== mid ===\n{mid_log}\n=== bob ===\n{bob_log}",
        String::from_utf8_lossy(&output.stdout)
    );
}
