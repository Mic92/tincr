//! UDP path selection: which path (direct UDP, relayed UDP, TCP) data
//! takes, and what each node believes about the direct path, under
//! firewall rules that break it in different ways.
//!
//! Every scenario is one `Scenario::start` call on the same rig: alice
//! (tinc0, 10.42.0.1) and bob (tinc1 in `bobside`, 10.42.0.2), either
//! dialling each other or both dialling only `relay`. New UDP-path
//! regressions should be a new scenario here, not a new file.

use std::fmt;
use std::fs;
use std::process::Command;
use std::time::Duration;

use super::common::linux::run_ip;
use super::common::{TmpGuard, node_status, try_poll};
use super::rig::{Node, TunPair, enter_netns, iptables, node_pmtu, ping, ping_once, ping_received};

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
    /// All alice↔bob UDP, both directions.
    UdpBetweenPeers,
    /// UDP from relay to alice.
    UdpRelayToAlice,
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
                let mut relay = Node::new(tmp.path(), "relay", 0xCC)
                    .with_conf(&conf)
                    .log_level("tincd=info,tincd::net=debug");
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

        let relay_port = relay.as_ref().map_or(0, |r| r.port);
        if !rules
            .iter()
            .all(|&rule| apply(rule, alice_port, bob.port, relay_port))
        {
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

fn apply(rule: Drop, alice: u16, bob: u16, relay: u16) -> bool {
    let (alice, bob, relay) = (alice.to_string(), bob.to_string(), relay.to_string());
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
        Drop::UdpBetweenPeers => [(&bob, &alice), (&alice, &bob)]
            .iter()
            .all(|(sport, dport)| drop_input(&["-p", "udp", "--sport", sport, "--dport", dport])),
        Drop::UdpRelayToAlice => drop_input(&["-p", "udp", "--sport", &relay, "--dport", &alice]),
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

/// relay's UDP to alice is dropped: alice confirms relay through meta
/// acks, relay never confirms alice, yet must relay her UDP to bob.
#[test]
fn relay_forwards_for_one_way_sender() {
    let Some(s) = Scenario::start(
        "relay_forwards_for_one_way_sender",
        Topology::ViaRelay,
        "MTUInfoInterval = 1\nPingInterval = 1",
        &[Drop::UdpBetweenPeers, Drop::UdpRelayToAlice],
    ) else {
        return;
    };
    s.pair.wait_validkey();
    // Data only takes UDP to relay once a meta ack raised minmtu.
    let relay_confirmed = try_poll(Duration::from_secs(20), || {
        ping_once("10.42.0.2");
        let nodes = s.alice_view();
        let (_, minmtu, _) = node_pmtu(&nodes, "relay")?;
        (node_status(&nodes, "relay")? & UDP_CONFIRMED != 0 && minmtu > 0).then_some(())
    });

    let output = ping(&["-c", "5", "-i", "0.2", "-W", "2"], "10.42.0.2");
    let logs = s.finish();
    assert!(
        relay_confirmed.is_some(),
        "alice never confirmed relay\n{logs}"
    );
    assert_eq!(ping_received(&output), 5, "{logs}");
}

/// UDP turns `ENETUNREACH` under a converged tunnel. Unconfirmed UDP
/// must mean `minmtu` 0, so data falls back to TCP at once instead of
/// failing locally, and UDP re-confirms once the address works again.
#[test]
fn unreachable_falls_back_to_tcp() {
    // `Shards = 1`: the unreachable errno is handled on the control path.
    let Some(s) = Scenario::start(
        "unreachable_falls_back_to_tcp",
        Topology::Direct,
        "PingInterval = 1\nShards = 1",
        &[],
    ) else {
        return;
    };
    s.pair.wait_udp_confirmed();

    let fixed = try_poll(Duration::from_secs(20), || {
        ping_once("10.42.0.2");
        let alice = node_pmtu(&s.alice_view(), "bob")?;
        let bob = node_pmtu(&s.bob_view(), "alice")?;
        (alice.0 != 0 && bob.0 != 0).then_some(())
    });

    // Daemon UDP now fails with ENETUNREACH; TCP is untouched. The
    // local rule moves behind ours so loopback is affected too, and
    // 10.42/16 stays routable (ping `connect()`s a UDP socket).
    run_ip(&["rule", "add", "pref", "100", "lookup", "local"]);
    run_ip(&["rule", "del", "pref", "0", "lookup", "local"]);
    run_ip(&[
        "rule",
        "add",
        "pref",
        "10",
        "to",
        "127.0.0.0/8",
        "ipproto",
        "udp",
        "unreachable",
    ]);
    let output = ping(&["-c", "5", "-i", "0.5", "-W", "2"], "10.42.0.2");
    let received = ping_received(&output);
    let alice_nodes = s.alice_view();
    run_ip(&["rule", "del", "pref", "10"]);

    let recovered = try_poll(Duration::from_secs(20), || {
        ping_once("10.42.0.2");
        let nodes = s.alice_view();
        (node_status(&nodes, "bob")? & UDP_CONFIRMED != 0 && node_pmtu(&nodes, "bob")?.1 != 0)
            .then_some(())
    });
    let logs = s.finish();
    assert!(fixed.is_some(), "PMTU never fixed\n{logs}");
    assert!(logs.alice.contains("Network is unreachable"), "{logs}");
    let status = node_status(&alice_nodes, "bob").unwrap_or(0);
    let pmtu = node_pmtu(&alice_nodes, "bob");
    assert!(
        received >= 3,
        "{received}/5 over TCP fallback; status {status:#x} pmtu {pmtu:?}\n{logs}"
    );
    assert!(
        status & UDP_CONFIRMED == 0 && pmtu.is_some_and(|p| p.1 == 0),
        "unconfirmed UDP must imply minmtu 0: status {status:#x} pmtu {pmtu:?}"
    );
    assert!(recovered.is_some(), "UDP never re-confirmed\n{logs}");
}

/// `iptables`/`ip6tables` `op` (`-I`/`-D`) of rules dropping UDP between
/// ports `a` and `b`, both directions.
fn drop_udp_between(xtables: &str, op: &str, a: u16, b: u16) -> bool {
    let (a, b) = (a.to_string(), b.to_string());
    [(&a, &b), (&b, &a)].iter().all(|(sport, dport)| {
        let args = [
            op, "INPUT", "-p", "udp", "--sport", sport, "--dport", dport, "-j", "DROP",
        ];
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

/// A confirmed UDP path whose address dies silently (a NAT mapping
/// flushed, a source the peer can no longer be reached at) must not pin
/// both ends to it forever while another address works.
///
/// alice and bob each dial only relay: alice over IPv4, bob over IPv6,
/// so the edges advertise alice at `127.0.0.1` and bob at `::1`. IPv4
/// UDP between them is dropped first, so they confirm each other over
/// IPv6 and each learns the other's `::1` source. Then IPv6 UDP between
/// them dies and IPv4 opens: bob must find alice's IPv4 edge address
/// again instead of probing only the dead `::1` one.
#[test]
fn dead_seen_address_is_released() {
    let Some(netns) = enter_netns("udp_path::dead_seen_address_is_released") else {
        return;
    };
    let tmp = tmp!("deadseen");
    let conf = "AutoConnect = no\nLocalDiscovery = no\nPingInterval = 1\n\
                UDPDiscoveryTimeout = 3\nUDPDiscoveryKeepaliveInterval = 1\n\
                UDPDiscoveryInterval = 1\n";
    let TunPair {
        netns,
        mut alice,
        mut bob,
    } = TunPair::new(netns, &tmp, conf);
    let (a, b) = (alice.reserve_port(), bob.reserve_port());
    let mut relay = Node::new(tmp.path(), "relay", 0xCC).with_conf(conf);
    relay.write_config_multi(&[&alice, &bob], &[]);
    dual_stack(&relay);
    relay.start();
    alice.write_config_multi(&[&relay, &bob], &[&relay]);
    bob.write_config_multi(&[&relay, &alice], &[&relay]);
    let relay_host = bob.confbase.join("hosts/relay");
    let host = fs::read_to_string(&relay_host).unwrap();
    fs::write(&relay_host, host.replace("127.0.0.1", "::1")).unwrap();
    dual_stack(&alice);
    dual_stack(&bob);
    if !drop_udp_between("iptables", "-I", a, b) {
        relay.stop();
        return;
    }
    bob.start();
    alice.start();
    netns.place_devices();
    let pair = TunPair { netns, alice, bob };
    pair.wait_reachable();
    let confirmed = |node: &Node, peer| {
        node_status(&node.ctl().dump(3), peer).is_some_and(|s| s & UDP_CONFIRMED != 0)
    };
    let over_v6 = try_poll(Duration::from_secs(15), || {
        ping_once("10.42.0.2");
        (confirmed(&pair.alice, "bob") && confirmed(&pair.bob, "alice")).then_some(())
    });
    let v6 = Some("::1".to_owned());
    if over_v6.is_none() || udp_host(&pair.alice, "bob") != v6 || udp_host(&pair.bob, "alice") != v6
    {
        relay.stop();
        let (alice_log, bob_log) = pair.finish();
        panic!(
            "no IPv6 UDP path to start from\n=== alice ===\n{alice_log}\n=== bob ===\n{bob_log}"
        );
    }

    assert!(drop_udp_between("iptables", "-D", a, b));
    assert!(drop_udp_between("ip6tables", "-I", a, b));

    // Data keeps flowing over relay meanwhile; it is what drives probing
    // towards a peer without a meta connection.
    let recovered = try_poll(Duration::from_secs(30), || {
        ping_once("10.42.0.2");
        (confirmed(&pair.alice, "bob")
            && confirmed(&pair.bob, "alice")
            && udp_host(&pair.bob, "alice").as_deref() == Some("127.0.0.1"))
        .then_some(())
    });
    let alice_sees = udp_host(&pair.alice, "bob");
    let bob_sees = udp_host(&pair.bob, "alice");
    let relay_log = relay.stop();
    let (alice_log, bob_log) = pair.finish();
    let logs =
        format!("=== alice ===\n{alice_log}\n=== relay ===\n{relay_log}\n=== bob ===\n{bob_log}");
    assert!(
        recovered.is_some(),
        "UDP never re-confirmed over IPv4 (alice has bob at {alice_sees:?}, \
         bob has alice at {bob_sees:?})\n{logs}"
    );
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
