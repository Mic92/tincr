//! Regression: a rekey must not move a confirmed direct UDP path to
//! the address a relay appends to `REQ_KEY`.
//!
//! alice and bob each dial only relay, so their key exchange is
//! relayed. alice dials relay over `::1`, bob over `127.0.0.1`, and
//! relay's port drops IPv4 UDP, so relay observes alice at `[::1]`.
//! bob's port drops IPv6 UDP until alice and bob confirm each other
//! over IPv4; alice's `KeyExpire` rekey then carries relay's `[::1]`
//! hint to bob.

use std::fs;
use std::process::Command;
use std::time::Duration;

use super::common::{node_status, try_poll};
use super::rig::{Node, TunPair, enter_netns, ping_once};

/// Insert (`-I`) or delete (`-D`) rules dropping UDP to and from
/// `port`; `xtables` is `iptables` or `ip6tables`.
fn drop_udp(xtables: &str, op: &str, port: u16) -> bool {
    let port = port.to_string();
    ["--dport", "--sport"].iter().all(|dir| {
        let args = [op, "INPUT", "-p", "udp", dir, &port, "-j", "DROP"];
        let out = Command::new(xtables)
            .args(args)
            .output()
            .expect("spawn xtables");
        if !out.status.success() {
            eprintln!(
                "SKIP: {xtables} {args:?}: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        out.status.success()
    })
}

/// `write_config_multi` pins IPv4; listen on both families.
fn dual_stack(node: &Node) {
    let path = node.confbase.join("tinc.conf");
    let conf = fs::read_to_string(&path).unwrap();
    fs::write(
        path,
        conf.replace("AddressFamily = ipv4", "AddressFamily = any"),
    )
    .unwrap();
}

/// UDP address `node` has for `peer` (`dump nodes` host field).
fn udp_host(node: &Node, peer: &str) -> Option<String> {
    node.ctl().dump(3).iter().find_map(|row| {
        let mut fields = row.strip_prefix("18 3 ")?.split_whitespace();
        (fields.next()? == peer).then_some(())?;
        fields.nth(1).map(str::to_owned)
    })
}

#[test]
fn rekey_keeps_confirmed_udp_path() {
    let Some(netns) = enter_netns("rekey_udp_path::rekey_keeps_confirmed_udp_path") else {
        return;
    };
    let tmp = tmp!("rekeyudp");
    let TunPair {
        netns,
        mut alice,
        mut bob,
    } = TunPair::new(netns, &tmp, "AutoConnect = no\n");
    alice.extra_conf.push_str("KeyExpire = 60\n");
    let mut relay = Node::new(tmp.path(), "relay", 0xCC).with_conf("AutoConnect = no\n");
    relay.write_config_multi(&[&alice, &bob], &[]);
    dual_stack(&relay);
    relay.start();
    alice.write_config_multi(&[&relay, &bob], &[&relay]);
    bob.write_config_multi(&[&relay, &alice], &[&relay]);
    let relay_host = alice.confbase.join("hosts/relay");
    let host = fs::read_to_string(&relay_host).unwrap();
    fs::write(&relay_host, host.replace("127.0.0.1", "::1")).unwrap();
    dual_stack(&alice);
    dual_stack(&bob);
    bob.start();
    if !drop_udp("iptables", "-I", relay.port) || !drop_udp("ip6tables", "-I", bob.port) {
        relay.stop();
        bob.stop();
        return;
    }
    alice.start();
    netns.place_devices();
    let pair = TunPair { netns, alice, bob };
    pair.wait_reachable();
    pair.wait_udp_confirmed();

    let v4 = Some("127.0.0.1".to_owned());
    assert_eq!(udp_host(&pair.bob, "alice"), v4);
    assert_eq!(udp_host(&pair.alice, "bob"), v4);
    assert!(drop_udp("ip6tables", "-D", pair.bob.port));

    // bob, the responder, logs a second success once alice's rekey
    // is done. Pings keep the UDP path from going idle meanwhile.
    let success = "SPTPS key exchange with alice successful";
    let rekeyed = try_poll(Duration::from_secs(90), || {
        ping_once("10.42.0.2");
        (pair.bob.log().matches(success).count() >= 2).then_some(())
    });
    for _ in 0..3 {
        ping_once("10.42.0.2");
    }
    let bob_sees = udp_host(&pair.bob, "alice");
    let alice_sees = udp_host(&pair.alice, "bob");
    let confirmed = node_status(&pair.bob.ctl().dump(3), "alice").is_some_and(|s| s & 0x80 != 0);
    let relay_log = relay.stop();
    let (alice_log, bob_log) = pair.finish();
    let logs =
        format!("=== alice ===\n{alice_log}\n=== relay ===\n{relay_log}\n=== bob ===\n{bob_log}");
    assert!(rekeyed.is_some(), "alice never rekeyed\n{logs}");
    assert!(confirmed, "bob lost the UDP path to alice\n{logs}");
    assert_eq!(bob_sees, v4, "bob moved alice's UDP address\n{logs}");
    assert_eq!(alice_sees, v4, "alice moved bob's UDP address\n{logs}");
}
