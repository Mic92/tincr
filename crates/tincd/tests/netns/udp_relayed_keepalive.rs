//! Regression: frames relayed to us over UDP must not feed the
//! gratuitous keepalive reply, or the peer takes their size as a
//! direct-path PMTU.
//!
//! alice and bob each dial only relay. The direct alice↔bob UDP path
//! drops everything but tiny datagrams, so UDP confirms while PMTU
//! discovery finds nothing and data rides the relay.

use std::process::Command;
use std::time::Duration;

use super::common::{node_status, try_poll};
use super::rig::{Node, TunPair, enter_netns, node_pmtu, ping};

/// Drop UDP from `sport` to `dport` at 300 bytes and up.
fn drop_big_udp(sport: u16, dport: u16) -> bool {
    let (sport, dport) = (sport.to_string(), dport.to_string());
    let args = [
        "-I",
        "INPUT",
        "-p",
        "udp",
        "--sport",
        &sport,
        "--dport",
        &dport,
        "-m",
        "length",
        "--length",
        "300:65535",
        "-j",
        "DROP",
    ];
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
fn relayed_frames_do_not_confirm_direct_pmtu() {
    let Some(netns) =
        enter_netns("udp_relayed_keepalive::relayed_frames_do_not_confirm_direct_pmtu")
    else {
        return;
    };
    let tmp = tmp!("udprelayka");
    let conf = "AutoConnect = no\nUDPDiscoveryKeepaliveInterval = 1\n";
    let TunPair {
        netns,
        mut alice,
        mut bob,
    } = TunPair::new(netns, &tmp, conf);
    let alice_port = alice.reserve_port();
    let mut relay = Node::new(tmp.path(), "relay", 0xCC).with_conf(conf);
    relay.write_config_multi(&[&alice, &bob], &[]);
    relay.start();
    alice.write_config_multi(&[&relay, &bob], &[&relay]);
    bob.write_config_multi(&[&relay, &alice], &[&relay]);
    bob.start();
    if !drop_big_udp(bob.port, alice_port) || !drop_big_udp(alice_port, bob.port) {
        relay.stop();
        bob.stop();
        return;
    }
    alice.start();
    netns.place_devices();
    let pair = TunPair { netns, alice, bob };
    pair.wait_reachable();
    pair.wait_udp_confirmed();

    // bob's 1000-byte echo replies reach alice only via relay. Pinging
    // across several keepalive intervals gives alice the chance to echo
    // their size back to bob.
    let bogus = try_poll(Duration::from_secs(6), || {
        ping(&["-c", "1", "-W", "1", "-s", "1000"], "10.42.0.2");
        node_pmtu(&pair.bob.ctl().dump(3), "alice").filter(|pmtu| pmtu.1 != 0)
    });
    let confirmed = node_status(&pair.bob.ctl().dump(3), "alice").is_some_and(|s| s & 0x80 != 0);
    let relay_log = relay.stop();
    let (alice_log, bob_log) = pair.finish();
    let logs =
        format!("=== alice ===\n{alice_log}\n=== relay ===\n{relay_log}\n=== bob ===\n{bob_log}");
    assert_eq!(bogus, None, "bob learned a minmtu to alice\n{logs}");
    assert!(confirmed, "bob lost the small-packet UDP path\n{logs}");
}
