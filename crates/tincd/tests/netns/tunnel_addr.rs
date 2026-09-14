//! Endpoints inside the mesh's own Subnets are never dialled, never
//! accepted, never published. Two LAN nodes with `LocalDiscovery`;
//! their Subnet addresses (10.42.0.1 / 10.42.0.2) are put on `lo` so
//! a connection to them succeeds at the socket level — which is
//! exactly how a tunnel address behaves while the VPN is up, and why
//! it self-perpetuates without a gate (dialled OK → persisted as
//! "recent" → republished as edge address and `local_address`).
//!
//! The seed here is an `Address =` line; in the field it was a
//! gossiped edge (retiolum, 2026-09-14: `massulus` dialling
//! `ignavia` at `42:0:ce16::16a2`, then auth timing out inside the
//! tunnel every few minutes).

use std::io::Read;
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::time::Duration;

use super::common::linux::run_ip;
use super::common::{TmpGuard, try_poll};
use super::rig::{Node, enter_bwrap};
use socket2::{Domain, Socket, Type};
use std::fs;

const ALICE_TUN: &str = "10.42.0.1";
const BOB_TUN: &str = "10.42.0.2";

/// Both nodes up and alice dialling bob; alice's `hosts/bob` lists
/// bob's tunnel address before the loopback one.
fn start_pair(tmp: &TmpGuard) -> (Node, Node) {
    for tun in [ALICE_TUN, BOB_TUN] {
        run_ip(&["addr", "add", &format!("{tun}/32"), "dev", "lo"]);
    }
    let conf = "AutoConnect = no\nLocalDiscovery = yes\n";
    let mut alice = Node::new(tmp.path(), "alice", 0xA1)
        .subnet(&format!("{ALICE_TUN}/32"))
        .with_conf(conf);
    let mut bob = Node::new(tmp.path(), "bob", 0xB0)
        .subnet(&format!("{BOB_TUN}/32"))
        .with_conf(conf);

    bob.write_config(&alice, false);
    bob.start();

    alice.write_config(&bob, true);
    // Poison: bob's tunnel address first, the real one second.
    let host = alice.confbase.join("hosts").join("bob");
    let mut text = fs::read_to_string(&host).unwrap();
    text = text.replace(
        &format!("Address = 127.0.0.1 {}\n", bob.port),
        &format!(
            "Address = {BOB_TUN} {p}\nAddress = 127.0.0.1 {p}\n",
            p = bob.port
        ),
    );
    fs::write(host, text).unwrap();
    alice.start();
    (alice, bob)
}

/// `dump connections` row for `peer`, if any: `18 6 NAME HOST port P …`.
fn conn_host(node: &Node, peer: &str) -> Option<String> {
    node.ctl().dump(6).into_iter().find_map(|row| {
        let mut f = row.strip_prefix("18 6 ")?.split_whitespace();
        (f.next()? == peer).then(|| f.next().unwrap_or("").to_owned())
    })
}

/// First contact: alice does not yet know bob's Subnet (nothing in
/// her `hosts/bob` says so) and dials the tunnel address; bob closes
/// it before `ID` and alice falls through to loopback. Reconnect: bob's
/// gossip has told alice the Subnet, so she skips the address herself.
/// Throughout, nobody's edges name a tunnel address.
#[test]
fn tunnel_address_never_dialled_or_published() {
    let test_name = "tunnel_addr::tunnel_address_never_dialled_or_published";
    if !enter_bwrap(test_name) {
        return;
    }
    let tmp = TmpGuard::new("tunaddr", "dial");
    let (mut alice, mut bob) = start_pair(&tmp);

    alice.wait_for_peer("bob", true, Duration::from_secs(10));
    bob.wait_for_peer("alice", true, Duration::from_secs(10));

    let tried_tun = format!("Trying to connect to bob ({BOB_TUN}:{})", bob.port);
    let skipped = format!(
        "Not connecting to bob at {BOB_TUN}:{}: address is inside the VPN",
        bob.port
    );
    let alice_log = alice.log();
    assert!(alice_log.contains(&tried_tun), "test premise:\n{alice_log}");
    assert!(
        alice_log.contains("Connection closed by bob"),
        "bob did not refuse the tunnel-address dial:\n{alice_log}"
    );
    assert_eq!(conn_host(&bob, "alice").as_deref(), Some("127.0.0.1"));

    // Edges are gossiped both ways; the row carries the wire and
    // local addresses.
    let edges = try_poll(Duration::from_secs(5), || {
        let rows = alice.ctl().dump(4);
        (rows.len() >= 2).then_some(rows)
    })
    .expect("both edges");
    for row in &edges {
        assert!(
            !row.contains("10.42.0."),
            "edge names a tunnel address: {row}\nall: {edges:#?}"
        );
    }

    // Reconnect with the Subnet known.
    bob.stop();
    bob.start();
    assert!(
        try_poll(Duration::from_secs(15), || alice
            .has_active_peer("bob")
            .then_some(()))
        .is_some(),
        "reconnect failed\n=== alice ===\n{}\n=== bob ===\n{}",
        alice.log(),
        bob.log()
    );
    let alice_log = alice.log();
    assert!(
        alice_log.contains(&skipped),
        "alice did not skip the tunnel address on reconnect:\n{alice_log}"
    );
    assert_eq!(
        alice_log.matches(&tried_tun).count(),
        1,
        "tunnel address dialled again after the Subnet was known:\n{alice_log}"
    );
    assert_eq!(conn_host(&bob, "alice").as_deref(), Some("127.0.0.1"));

    bob.stop();
    alice.stop();
}

/// A TCP connection arriving *from* a tunnel address (what a peer
/// that did dial through the VPN looks like) is closed before `ID`.
#[test]
fn inbound_from_tunnel_address_refused() {
    let test_name = "tunnel_addr::inbound_from_tunnel_address_refused";
    if !enter_bwrap(test_name) {
        return;
    }
    let tmp = TmpGuard::new("tunaddr", "accept");
    let (mut alice, mut bob) = start_pair(&tmp);
    bob.wait_for_peer("alice", true, Duration::from_secs(10));

    // Source-bound to alice's Subnet address, like a dial that went
    // out of the tun device.
    let sock = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
    let src: SocketAddr = format!("{ALICE_TUN}:0").parse().unwrap();
    sock.bind(&src.into()).unwrap();
    sock.connect(&bob.tcp_addr().into()).unwrap();
    let mut stream: TcpStream = sock.into();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf).expect("read");
    assert_eq!(n, 0, "bob greeted a tunnel-address peer: {:?}", &buf[..n]);
    let _ = stream.shutdown(Shutdown::Both);

    let refused = format!("Refusing connection from {ALICE_TUN}:");
    let log = try_poll(Duration::from_secs(5), || {
        let log = bob.log();
        log.contains(&refused).then_some(log)
    })
    .expect("bob logged the refusal");
    // The legitimate loopback connection is untouched.
    assert!(
        bob.has_active_peer("alice"),
        "loopback conn dropped:\n{log}"
    );

    bob.stop();
    alice.stop();
}
