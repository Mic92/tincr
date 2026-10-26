//! UDP path selection: which path (direct UDP, relayed UDP, TCP) data
//! takes, and what each node believes about the direct path, under
//! firewall rules that break it in different ways.
//!
//! Every scenario is one `Scenario::start` call on the same rig: alice
//! (tinc0, 10.42.0.1) and bob (tinc1 in `bobside`, 10.42.0.2), either
//! dialling each other or both dialling only `relay`. New UDP-path
//! regressions should be a new scenario here, not a new file.

use std::fmt;
use std::time::Duration;

use super::common::{TmpGuard, node_status, try_poll};
use super::rig::{Node, TunPair, enter_netns, iptables, node_pmtu, ping, ping_once};

/// `node_status` bit: UDP to this node is confirmed.
const UDP_CONFIRMED: u32 = 0x80;

#[derive(Clone, Copy)]
enum Topology {
    /// alice dials bob.
    Direct,
    /// alice and bob each dial only `relay`, with `AutoConnect = no`
    /// so neither dials the other.
    ViaRelay,
}

/// An iptables `INPUT … -j DROP` rule. Ports are resolved once the rig knows
/// them.
#[derive(Clone, Copy)]
enum Drop {
    /// Every UDP datagram.
    AllUdp,
    /// UDP addressed to alice's port: her probes go out, replies die.
    UdpToAlice,
    /// alice↔bob UDP of at least this many bytes, both directions.
    BigUdpBetweenPeers(u16),
}

struct Scenario {
    pair: TunPair,
    relay: Option<Node>,
    _tmp: TmpGuard,
}

impl Scenario {
    /// Configure, firewall, start, and wait until both see each other.
    /// `None` means the test should skip (no netns or no iptables).
    fn start(test: &str, topology: Topology, conf: &str, rules: &[Drop]) -> Option<Self> {
        let netns = enter_netns(&format!("udp_path::{test}"))?;
        // Short tag: control sockets live under it, and sun_path is
        // ~100 bytes.
        let tmp = tmp!(&test[..test.len().min(10)]);
        let mut conf = conf.to_owned();
        if matches!(topology, Topology::ViaRelay) {
            conf.push_str("\nAutoConnect = no");
        }
        let TunPair {
            netns,
            mut alice,
            mut bob,
        } = TunPair::new(netns, &tmp, &conf);
        let alice_port = alice.reserve_port();

        let mut relay = match topology {
            Topology::Direct => {
                bob.write_config(&alice, false);
                None
            }
            Topology::ViaRelay => {
                let mut relay = Node::new(tmp.path(), "relay", 0xCC).with_conf(&conf);
                relay.write_config_multi(&[&alice, &bob], &[]);
                relay.start();
                alice.write_config_multi(&[&relay, &bob], &[&relay]);
                bob.write_config_multi(&[&relay, &alice], &[&relay]);
                Some(relay)
            }
        };
        bob.start();
        if matches!(topology, Topology::Direct) {
            // Needs bob's port, known only once he runs.
            alice.write_config(&bob, true);
        }

        if !rules.iter().all(|&rule| apply(rule, alice_port, bob.port)) {
            bob.stop();
            if let Some(relay) = relay.as_mut() {
                relay.stop();
            }
            return None;
        }

        alice.start();
        netns.place_devices();
        let pair = TunPair { netns, alice, bob };
        pair.wait_reachable();
        Some(Self {
            pair,
            relay,
            _tmp: tmp,
        })
    }

    fn alice_view(&self) -> Vec<String> {
        self.pair.alice.ctl().dump(3)
    }

    fn bob_view(&self) -> Vec<String> {
        self.pair.bob.ctl().dump(3)
    }

    /// Stop every node and return all logs, labelled, for assertion messages.
    fn finish(mut self) -> Logs {
        let relay = self.relay.as_mut().map(Node::stop).unwrap_or_default();
        let (alice, bob) = self.pair.finish();
        Logs { alice, bob, relay }
    }
}

struct Logs {
    alice: String,
    bob: String,
    relay: String,
}

impl fmt::Display for Logs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "=== alice ===\n{}\n", self.alice)?;
        if !self.relay.is_empty() {
            write!(f, "=== relay ===\n{}\n", self.relay)?;
        }
        write!(f, "=== bob ===\n{}", self.bob)
    }
}

fn apply(rule: Drop, alice: u16, bob: u16) -> bool {
    let (alice, bob) = (alice.to_string(), bob.to_string());
    match rule {
        Drop::AllUdp => drop_input(&["-p", "udp"]),
        Drop::UdpToAlice => drop_input(&["-p", "udp", "--dport", &alice]),
        Drop::BigUdpBetweenPeers(min) => {
            let len = format!("{min}:65535");
            [(&bob, &alice), (&alice, &bob)]
                .iter()
                .all(|(sport, dport)| {
                    drop_input(&[
                        "-p", "udp", "--sport", sport, "--dport", dport, "-m", "length",
                        "--length", &len,
                    ])
                })
        }
    }
}

/// `iptables -I INPUT <matches> -j DROP`.
fn drop_input(matches: &[&str]) -> bool {
    iptables(&[&["-I", "INPUT"], matches, &["-j", "DROP"]].concat())
}

/// alice's probes reach bob, bob's replies are dropped. bob acks probe
/// sizes over the meta connection, so alice→bob may still use UDP,
/// while bob→alice must stay on TCP (`minmtu == 0`).
#[test]
fn asymmetric_confirm_via_meta() {
    asymmetric_confirm("asymmetric_confirm_via_meta", Topology::Direct, 1400);
}

/// Acks are debounced per hop, so only confirmation is checked.
#[test]
fn asymmetric_confirm_via_relayed_meta() {
    asymmetric_confirm("asymmetric_confirm_via_relayed_meta", Topology::ViaRelay, 0);
}

fn asymmetric_confirm(test: &str, topology: Topology, want_minmtu: u16) {
    // The meta ack is debounced by MTUInfoInterval and driven by the
    // ping tick. Defaults would exceed the test budget.
    let Some(s) = Scenario::start(
        test,
        topology,
        "MTUInfoInterval = 1\nPingInterval = 1",
        &[Drop::UdpToAlice],
    ) else {
        return;
    };
    s.pair.wait_validkey();

    let confirmed = try_poll(Duration::from_secs(15), || {
        ping_once("10.42.0.2");
        let nodes = s.alice_view();
        let udp_confirmed = node_status(&nodes, "bob")? & UDP_CONFIRMED != 0;
        let (_, minmtu, _) = node_pmtu(&nodes, "bob")?;
        (udp_confirmed && minmtu >= want_minmtu).then_some(())
    });
    let bob_nodes = s.bob_view();
    let logs = s.finish();
    assert!(
        confirmed.is_some(),
        "alice never confirmed bob via meta\n{logs}"
    );
    // bob only receives alice's UDP, which proves nothing about his
    // direction: minmtu keeps bob→alice on TCP.
    assert_eq!(
        node_pmtu(&bob_nodes, "alice").map(|pmtu| pmtu.1),
        Some(0),
        "{bob_nodes:?}"
    );
    assert!(logs.alice.contains("confirmed via meta"), "{logs}");
    assert!(logs.bob.contains("Got UDP probe request"), "{logs}");
}

/// All UDP blackholed: data to an *indirect* node must stay on TCP
/// while the relay's `minmtu` is 0. Direct peers short-circuit before
/// the relay decision, hence the relay topology.
#[test]
fn blackhole_stays_on_tcp() {
    let Some(s) = Scenario::start(
        "blackhole_stays_on_tcp",
        Topology::ViaRelay,
        "",
        &[Drop::AllUdp],
    ) else {
        return;
    };
    // The handshake itself always rides TCP.
    s.pair.wait_validkey();

    let alice_nodes = s.alice_view();
    assert_eq!(node_pmtu(&alice_nodes, "relay").map(|pmtu| pmtu.1), Some(0));
    assert!(node_status(&alice_nodes, "relay").is_some_and(|s| s & UDP_CONFIRMED == 0));

    let output = ping(&["-c", "3", "-W", "2"], "10.42.0.2");
    let logs = s.finish();
    assert!(
        output.status.success(),
        "{}\n{logs}",
        String::from_utf8_lossy(&output.stdout)
    );
}

/// The direct alice↔bob path passes only small datagrams, so UDP
/// confirms while PMTU discovery finds nothing and data rides the
/// relay. Frames relayed to alice over UDP must not count as direct
/// receptions, or her keepalive reply teaches bob a bogus minmtu.
#[test]
fn relayed_frames_do_not_confirm_direct_pmtu() {
    let Some(s) = Scenario::start(
        "relayed_frames_do_not_confirm_direct_pmtu",
        Topology::ViaRelay,
        "UDPDiscoveryKeepaliveInterval = 1",
        &[Drop::BigUdpBetweenPeers(300)],
    ) else {
        return;
    };
    s.pair.wait_udp_confirmed();

    // bob's 1000-byte echo replies reach alice only via relay. Pinging
    // across several keepalive intervals gives alice the chance to echo
    // their size back to bob.
    let bogus = try_poll(Duration::from_secs(6), || {
        ping(&["-c", "1", "-W", "1", "-s", "1000"], "10.42.0.2");
        node_pmtu(&s.bob_view(), "alice").filter(|pmtu| pmtu.1 != 0)
    });
    let confirmed = node_status(&s.bob_view(), "alice").is_some_and(|st| st & UDP_CONFIRMED != 0);
    let logs = s.finish();
    assert_eq!(bogus, None, "bob learned a minmtu to alice\n{logs}");
    assert!(confirmed, "bob lost the small-packet UDP path\n{logs}");
}

#[test]
fn pmtu_config_pins_mtu() {
    let Some(s) = Scenario::start(
        "pmtu_config_pins_mtu",
        Topology::Direct,
        "PMTU = 1300\nPMTUDiscovery = no",
        &[],
    ) else {
        return;
    };
    s.pair.wait_validkey();

    let pinned = try_poll(Duration::from_secs(10), || {
        ping_once("10.42.0.2");
        node_pmtu(&s.alice_view(), "bob").filter(|&pmtu| pmtu == (1300, 1300, 1300))
    });
    let output = ping(&["-c", "1", "-W", "2", "-s", "1200"], "10.42.0.2");
    let logs = s.finish();
    assert!(pinned.is_some(), "{logs}");
    assert!(output.status.success(), "{logs}");
    assert!(!logs.alice.contains("Fixing MTU"), "{logs}");
}
