//! alice → mid ← bob: mid is the only path between alice and bob.

use std::os::fd::{AsRawFd, OwnedFd};
use std::time::{Duration, Instant};

use super::common::node::has_subnet;
use super::common::{Node, node_reachable, node_status, node_traffic, poll_until};
use super::fd_tunnel::{mk_ipv4_pkt, read_fd_nb, sockpair_datagram, write_fd};
use std::fs::OpenOptions;
use std::io::Write;
use std::iter;
use std::net::UdpSocket;
use std::thread;

/// Write all three configs and start mid, bob, alice in that order.
/// hosts/ tweaks must happen via `edit_hosts` because configs are
/// written here (mid's port is only known after it starts).
fn start_hub(
    mid: &mut Node,
    alice: &mut Node,
    bob: &mut Node,
    alice_fd: Option<OwnedFd>,
    bob_fd: Option<OwnedFd>,
    edit_hosts: impl FnOnce(&Node, &Node, &Node),
) {
    mid.write_config_multi(&[alice, bob], &[]);
    mid.start();
    alice.write_config_multi(&[mid, bob], &[mid]);
    bob.write_config_multi(&[mid, alice], &[mid]);
    edit_hosts(mid, alice, bob);
    match bob_fd {
        Some(fd) => bob.start_with_fd(&fd),
        None => bob.start(),
    };
    match alice_fd {
        Some(fd) => alice.start_with_fd(&fd),
        None => alice.start(),
    };
    mid.wait_for_peer("alice", true, Duration::from_secs(10));
    mid.wait_for_peer("bob", true, Duration::from_secs(10));
}

fn append_host_line(node: &Node, host: &str, line: &str) {
    let mut file = OpenOptions::new()
        .append(true)
        .open(node.confbase.join("hosts").join(host))
        .unwrap();
    writeln!(file, "{line}").unwrap();
}

fn reachable_count(rows: &[String]) -> usize {
    rows.iter()
        .filter_map(|row| node_status(rows, row.split_whitespace().nth(2)?))
        .filter(|status| status & 0x10 != 0)
        .count()
}

fn assert_icmp_net_unknown(device: &OwnedFd, probe: &[u8]) {
    write_fd(device, probe);
    let icmp = poll_until(Duration::from_secs(5), || read_fd_nb(device));
    assert!(icmp.len() >= 22, "{icmp:02x?}");
    assert_eq!(
        (icmp[9], icmp[20], icmp[21]),
        (1, 3, 6),
        "not ICMP unreach/net-unknown: {icmp:02x?}"
    );
}

fn probe() -> Vec<u8> {
    mk_ipv4_pkt([10, 0, 0, 1], [10, 0, 0, 2], b"probe")
}

/// alice and bob never connect directly; mid relays both the key
/// exchange and the data, and alice learns bob's UDP address anyway.
#[test]
fn relays_via_mid() {
    let tmp = tmp!("relay3");
    let (alice_dev, alice_daemon_end) = sockpair_datagram();
    let (bob_dev, bob_daemon_end) = sockpair_datagram();
    let mut alice = Node::new(tmp.path(), "alice", 0xA3)
        .fd(alice_daemon_end.as_raw_fd())
        .subnet("10.0.0.1/32");
    let mut mid = Node::new(tmp.path(), "mid", 0xC3).log_level("tincd=debug");
    let mut bob = Node::new(tmp.path(), "bob", 0xB3)
        .fd(bob_daemon_end.as_raw_fd())
        .subnet("10.0.0.2/32");
    start_hub(
        &mut mid,
        &mut alice,
        &mut bob,
        Some(alice_daemon_end),
        Some(bob_daemon_end),
        |_, _, _| {},
    );

    let mut alice_ctl = alice.ctl();
    let mut bob_ctl = bob.ctl();
    poll_until(Duration::from_secs(10), || {
        (node_reachable(&alice_ctl.dump(3), "bob") && node_reachable(&bob_ctl.dump(3), "alice"))
            .then_some(())
    });
    let nodes = alice_ctl.dump(3);
    let bob_row = nodes.iter().find(|r| r.starts_with("18 3 bob ")).unwrap();
    assert_eq!(
        bob_row.split_whitespace().nth(13),
        Some("mid"),
        "nexthop: {bob_row}"
    );

    write_fd(&alice_dev, &probe());
    poll_until(Duration::from_secs(10), || {
        (node_status(&alice_ctl.dump(3), "bob").is_some_and(|s| s & 0x02 != 0)
            && node_status(&bob_ctl.dump(3), "alice").is_some_and(|s| s & 0x02 != 0))
        .then_some(())
    });
    let packet = mk_ipv4_pkt([10, 0, 0, 1], [10, 0, 0, 2], b"relayed via mid");
    poll_until(Duration::from_secs(5), || {
        write_fd(&alice_dev, &packet);
        iter::from_fn(|| read_fd_nb(&bob_dev)).find(|received| *received == packet)
    });

    let nodes = alice_ctl.dump(3);
    let bob_row = nodes.iter().find(|r| r.starts_with("18 3 bob ")).unwrap();
    assert!(
        bob_row.contains(" 127.0.0.1 port "),
        "udp addr not learned: {bob_row}"
    );
    assert!(mid.stop().contains("Relaying"));
}

/// `TunnelServer` on mid: it forwards neither edges nor subnets, so
/// alice and bob each see only themselves and mid.
#[test]
fn tunnelserver_isolates_spokes() {
    let tmp = tmp!("tunnelserver3");
    let (alice_dev, alice_daemon_end) = sockpair_datagram();
    let mut alice = Node::new(tmp.path(), "alice", 0xA4)
        .fd(alice_daemon_end.as_raw_fd())
        .subnet("10.0.0.1/32");
    let mut mid = Node::new(tmp.path(), "mid", 0xC4)
        .with_conf("TunnelServer = yes\n")
        .log_level("tincd=debug");
    let mut bob = Node::new(tmp.path(), "bob", 0xB4).subnet("10.0.0.2/32");
    // TunnelServer implies StrictSubnets: mid only accepts subnets
    // that are in its hosts/ files.
    start_hub(
        &mut mid,
        &mut alice,
        &mut bob,
        Some(alice_daemon_end),
        None,
        |mid, _, _| {
            append_host_line(mid, "alice", "Subnet = 10.0.0.1/32");
            append_host_line(mid, "bob", "Subnet = 10.0.0.2/32");
        },
    );

    let mut alice_ctl = alice.ctl();
    // Let gossip settle: two identical dumps 50ms apart.
    let alice_nodes = poll_until(Duration::from_secs(5), || {
        let first = alice_ctl.dump(3);
        thread::sleep(Duration::from_millis(50));
        (first == alice_ctl.dump(3) && first.len() >= 2).then_some(first)
    });
    assert_eq!(reachable_count(&alice_nodes), 2, "{alice_nodes:?}");
    assert!(!node_reachable(&alice_nodes, "bob"));
    assert!(!node_reachable(&bob.ctl().dump(3), "alice"));
    assert_eq!(reachable_count(&mid.ctl().dump(3)), 3);
    assert_eq!(alice_ctl.dump(5).len(), 1, "only own subnet");

    assert_icmp_net_unknown(&alice_dev, &probe());
    assert!(mid.stop().contains("tunnelserver"));
}

/// `StrictSubnets` on alice: bob's gossiped subnet is ignored until it
/// also appears in alice's hosts/bob (after a restart).
#[test]
fn strictsubnets_ignores_gossip_until_hosts_file_agrees() {
    let tmp = tmp!("strictsubnets3");
    let (alice_dev, alice_daemon_end) = sockpair_datagram();
    let mut alice = Node::new(tmp.path(), "alice", 0xA5)
        .with_conf("StrictSubnets = yes\n")
        .fd(alice_daemon_end.as_raw_fd())
        .subnet("10.0.0.1/32");
    let mut mid = Node::new(tmp.path(), "mid", 0xC5);
    let mut bob = Node::new(tmp.path(), "bob", 0xB5).subnet("10.0.0.2/32");
    start_hub(
        &mut mid,
        &mut alice,
        &mut bob,
        Some(alice_daemon_end),
        None,
        |_, _, _| {},
    );

    let mut alice_ctl = alice.ctl();
    let mut mid_ctl = mid.ctl();
    poll_until(Duration::from_secs(10), || {
        (reachable_count(&alice_ctl.dump(3)) == 3).then_some(())
    });
    poll_until(Duration::from_secs(5), || {
        has_subnet(&mid_ctl.dump(5), "10.0.0.2", "bob").then_some(())
    });
    let alice_subnets = poll_until(Duration::from_secs(5), || {
        let first = alice_ctl.dump(5);
        thread::sleep(Duration::from_millis(50));
        (first == alice_ctl.dump(5)).then_some(first)
    });
    assert!(
        !has_subnet(&alice_subnets, "10.0.0.2", "bob"),
        "{alice_subnets:?}"
    );
    assert!(has_subnet(&alice_subnets, "10.0.0.1", "alice"));
    assert_icmp_net_unknown(&alice_dev, &probe());
    drop(alice_ctl);
    assert!(alice.stop().contains("Ignoring unauthorized"));
    drop(alice_dev);

    let (_alice_dev, alice_daemon_end) = sockpair_datagram();
    let mut alice = alice.fd(alice_daemon_end.as_raw_fd());
    alice.write_config_multi(&[&mid, &bob], &[&mid]);
    append_host_line(&alice, "bob", "Subnet = 10.0.0.2/32");
    alice.start_with_fd(&alice_daemon_end);
    drop(alice_daemon_end);
    let mut alice_ctl = alice.ctl();
    poll_until(Duration::from_secs(10), || {
        has_subnet(&alice_ctl.dump(5), "10.0.0.2", "bob").then_some(())
    });
}

/// Security regression: mid must not relay a UDP packet whose source
/// id claims to be alice but comes from an address alice never used.
#[test]
fn mid_does_not_relay_for_spoofed_udp_sender() {
    let tmp = tmp!("relay-gate");
    let mut alice = Node::new(tmp.path(), "alice", 0xA4).subnet("10.0.0.1/32");
    let mut mid = Node::new(tmp.path(), "mid", 0xC4).log_level("tincd=debug");
    let mut bob = Node::new(tmp.path(), "bob", 0xB4).subnet("10.0.0.2/32");
    start_hub(&mut mid, &mut alice, &mut bob, None, None, |_, _, _| {});
    let mut mid_ctl = mid.ctl();
    poll_until(Duration::from_secs(10), || {
        let nodes = mid_ctl.dump(3);
        (node_reachable(&nodes, "alice") && node_reachable(&nodes, "bob")).then_some(())
    });

    let bob_in_packets = || {
        node_traffic(&bob.ctl().dump(13), "alice")
            .expect("alice row")
            .0
    };
    let before = bob_in_packets();
    let mut spoof = Vec::new();
    spoof.extend_from_slice(tincd::node_id::NodeId6::from_name("bob").as_bytes());
    spoof.extend_from_slice(tincd::node_id::NodeId6::from_name("alice").as_bytes());
    spoof.extend_from_slice(&[0xAA; 100]);
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .send_to(&spoof, mid.tcp_addr())
        .unwrap();
    thread::sleep(Duration::from_millis(200));
    assert_eq!(bob_in_packets(), before, "spoofed packet reached bob");

    let mid_log = mid.stop();
    assert!(mid_log.contains("unauthenticated UDP sender"), "{mid_log}");
    assert!(
        !mid_log.contains("Relaying UDP packet from alice to bob"),
        "{mid_log}"
    );
}

/// `Forwarding = off` on mid: alice routes 10.0.0.2 to mid via mid's
/// /24 (her `StrictSubnets` hides bob's /32), mid refuses to pass it on
/// to bob and answers ICMP unreachable instead.
#[test]
fn forwarding_off_drops_transit() {
    let tmp = tmp!("fmode-off");
    let (alice_dev, alice_daemon_end) = sockpair_datagram();
    let (bob_dev, bob_daemon_end) = sockpair_datagram();
    let mut alice = Node::new(tmp.path(), "alice", 0xAF)
        .with_conf("StrictSubnets = yes\n")
        .fd(alice_daemon_end.as_raw_fd())
        .subnet("10.0.0.1/32");
    let mut mid = Node::new(tmp.path(), "mid", 0xCF)
        .with_conf("Forwarding = off\n")
        .log_level("tincd=debug");
    let mut bob = Node::new(tmp.path(), "bob", 0xBF)
        .fd(bob_daemon_end.as_raw_fd())
        .subnet("10.0.0.2/32");
    start_hub(
        &mut mid,
        &mut alice,
        &mut bob,
        Some(alice_daemon_end),
        Some(bob_daemon_end),
        |_, alice, _| {
            append_host_line(alice, "mid", "Subnet = 10.0.0.0/24");
        },
    );

    let mut alice_ctl = alice.ctl();
    let mut mid_ctl = mid.ctl();
    poll_until(Duration::from_secs(5), || {
        has_subnet(&mid_ctl.dump(5), "10.0.0.2", "bob").then_some(())
    });
    poll_until(Duration::from_secs(5), || {
        has_subnet(&alice_ctl.dump(5), "10.0.0.0/24", "mid").then_some(())
    });
    assert!(!has_subnet(&alice_ctl.dump(5), "10.0.0.2", "bob"));

    write_fd(&alice_dev, &probe());
    poll_until(Duration::from_secs(10), || {
        node_status(&alice_ctl.dump(3), "mid")
            .is_some_and(|s| s & 0x02 != 0)
            .then_some(())
    });

    let payload = b"transit-forbidden";
    let transit = mk_ipv4_pkt([10, 0, 0, 1], [10, 0, 0, 2], payload);
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut bob_got_transit = false;
    let mut alice_got_unreachable = false;
    while Instant::now() < deadline {
        write_fd(&alice_dev, &transit);
        bob_got_transit |= iter::from_fn(|| read_fd_nb(&bob_dev)).any(|r| r.ends_with(payload));
        alice_got_unreachable |= iter::from_fn(|| read_fd_nb(&alice_dev))
            .any(|r| r[0] == 0x45 && r.get(9) == Some(&1) && r.get(20) == Some(&3));
        thread::sleep(Duration::from_millis(50));
    }
    let mid_log = mid.stop();
    assert!(!bob_got_transit, "mid forwarded transit:\n{mid_log}");
    assert!(mid_log.contains("Forwarding=off"), "{mid_log}");
    assert!(alice_got_unreachable, "no ICMP from mid:\n{mid_log}");
}
