use std::os::fd::AsRawFd;
use std::time::Duration;

use super::common::{Node, poll_until};
use super::fd_tunnel::{FdPair, mk_ipv4_pkt, read_fd_nb, sockpair_datagram, write_fd};
use std::array;
use std::thread;

/// Last four columns of a `dump nodes` (3) or `dump traffic` (13) row:
/// `in_packets in_bytes out_packets out_bytes`.
fn counters(rows: &[String], subtype: u8, name: &str) -> [u64; 4] {
    let prefix = format!("18 {subtype} {name} ");
    let row = rows
        .iter()
        .find(|row| row.starts_with(&prefix))
        .unwrap_or_else(|| panic!("no {name} row in {rows:?}"));
    let fields: Vec<&str> = row.split_whitespace().collect();
    array::from_fn(|i| fields[fields.len() - 4 + i].parse().unwrap())
}

/// alice's device → route → per-node SPTPS over UDP → bob's device,
/// byte for byte, with traffic counters on both ends agreeing.
#[test]
fn packet_crosses_tunnel_and_is_counted() {
    let tmp = tmp!("first-pkt");
    let pair = FdPair::new(tmp.path(), "", "").start();
    pair.establish_udp_key();
    let packet = pair.alice_to_bob(b"hello from alice");

    let alice_nodes = counters(&pair.alice.ctl().dump(3), 3, "bob");
    let bob_nodes = counters(&pair.bob.ctl().dump(3), 3, "alice");
    assert!(
        alice_nodes[2] >= 1 && alice_nodes[3] >= packet.len() as u64,
        "{alice_nodes:?}"
    );
    assert!(
        bob_nodes[0] >= 1 && bob_nodes[1] >= packet.len() as u64,
        "{bob_nodes:?}"
    );

    let alice_traffic = pair.alice.ctl().dump(13);
    assert_eq!(alice_traffic.len(), 2);
    assert_eq!(counters(&alice_traffic, 13, "bob")[2..], alice_nodes[2..]);
    assert!(
        counters(&alice_traffic, 13, "alice")[0] >= 2,
        "own row counts device reads"
    );
    let bob_traffic = pair.bob.ctl().dump(13);
    assert_eq!(counters(&bob_traffic, 13, "alice")[..2], bob_nodes[..2]);
    assert!(
        counters(&bob_traffic, 13, "bob")[2] >= 1,
        "own row counts device writes"
    );

    let logs = pair.logs();
    assert!(
        logs.contains("SPTPS key exchange with bob successful"),
        "{logs}"
    );
    assert!(
        logs.contains("SPTPS key exchange with alice successful"),
        "{logs}"
    );
}

/// Each side compresses at the level the *receiver* asked for: alice
/// asks zlib-6, bob asks LZ4 (12). Zeros make both codecs kick in.
#[test]
fn compression_levels_are_negotiated_per_direction() {
    let tmp = tmp!("compress");
    let pair = FdPair::new(tmp.path(), "Compression = 6\n", "Compression = 12\n").start();
    pair.establish_udp_key();

    let compression_towards = |node: &Node, peer: &str| -> u8 {
        let rows = node.ctl().dump(3);
        let row = rows
            .iter()
            .find(|r| r.starts_with(&format!("18 3 {peer} ")))
            .unwrap();
        row.split_whitespace().nth(10).unwrap().parse().unwrap()
    };
    assert_eq!(compression_towards(&pair.alice, "bob"), 12);
    assert_eq!(compression_towards(&pair.bob, "alice"), 6);

    pair.alice_to_bob(&[0u8; 200]);
    pair.bob_to_alice(&[0u8; 200]);
}

/// Regression: an unroutable IPv6 destination got an ICMPv4-shaped
/// reply. Expect `ICMPv6` dst-unreach/addr back to the sender.
#[test]
fn unroutable_ipv6_gets_icmpv6_unreachable() {
    let tmp = tmp!("v6-unreach");
    let (alice_dev, daemon_end) = sockpair_datagram();
    let mut alice = Node::new(tmp.path(), "alice", 0xA5)
        .fd(daemon_end.as_raw_fd())
        .subnet("10.0.0.1/32");
    alice.write_config_multi(&[], &[]);
    alice.start_with_fd(&daemon_end);
    drop(daemon_end);

    let src = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let mut ipv6 = vec![0x60, 0, 0, 0];
    ipv6.extend_from_slice(&8u16.to_be_bytes());
    ipv6.extend_from_slice(&[17, 64]);
    ipv6.extend_from_slice(&src);
    ipv6.extend_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99]);
    ipv6.extend_from_slice(&[0; 8]);
    write_fd(&alice_dev, &ipv6);

    let reply = poll_until(Duration::from_secs(5), || read_fd_nb(&alice_dev));
    assert!(reply.len() >= 48, "{reply:02x?}");
    assert_eq!(reply[0] >> 4, 6, "not IPv6: {reply:02x?}");
    assert_eq!(reply[6], 58, "next header not ICMPv6");
    assert_eq!(reply[40..42], [1, 3], "type/code not unreach/addr");
    assert_eq!(reply[24..40], src);
}

/// `KeyExpire = 1` forces a rekey within the test; traffic must keep
/// flowing across it.
#[test]
fn traffic_survives_key_expiry() {
    let tmp = tmp!("keyexpire");
    let pair = FdPair::new(tmp.path(), "KeyExpire = 1\n", "KeyExpire = 1\n").start();
    pair.establish_udp_key();
    thread::sleep(Duration::from_secs(2));
    // A packet may land mid-rekey and be dropped; retry.
    let packet = mk_ipv4_pkt([10, 0, 0, 1], [10, 0, 0, 2], b"post-rekey");
    let received = poll_until(Duration::from_secs(5), || {
        write_fd(&pair.alice_dev, &packet);
        read_fd_nb(&pair.bob_dev)
    });
    assert_eq!(received, packet);

    let alice_log = pair.alice.log();
    assert!(alice_log.contains("Expiring symmetric keys"), "{alice_log}");
    assert!(pair.bob.log().contains("Expiring symmetric keys"));
    assert!(
        alice_log
            .matches("SPTPS key exchange with bob successful")
            .count()
            >= 2,
        "{alice_log}"
    );
}
