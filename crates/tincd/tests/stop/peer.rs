//! Meta-protocol behaviour after a successful SPTPS handshake, with
//! this process as the peer (`PeerFixture`): ACK exchange, gossip
//! handling, graph transitions, and the pcap tap. Plus one negative
//! handshake test.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use super::common::{
    Node, PeerFixture, is_timeout, node_reachable, node_status, read_cookie, read_line_unbuffered,
};
use std::str;
use tinc_crypto::sign::SigningKey;
use tinc_sptps::{Framing, Output, Role, Sptps};

/// Our ACK (`4 udp-port weight options`) followed by the edge a real
/// peer would announce for its side of the connection. Without that
/// reverse edge the daemon's `testnode→testpeer` edge is one-way and
/// SSSP never marks us reachable.
fn activate(peer: &mut PeerFixture) {
    peer.send_record(b"4 0 1 700000c\n");
    peer.send_record(b"12 deadbeef testpeer testnode 127.0.0.1 655 700000c 1\n");
}

fn find_row<'a>(rows: &'a [String], prefix: &str) -> &'a str {
    rows.iter()
        .find(|row| row.starts_with(prefix))
        .unwrap_or_else(|| panic!("no row starting with {prefix:?} in {rows:#?}"))
}

fn assert_no_reply(peer: &mut PeerFixture, what: &str) {
    let records = peer.drain_records(100);
    assert!(
        records.is_empty(),
        "daemon answered {what} (should only forward, and we are the only peer): {records:?}"
    );
}

/// Handshake → ACK exchange → connection active; then `ADD_SUBNET` /
/// duplicate / `DEL_SUBNET` are applied and visible in `dump subnets`.
#[test]
fn ack_activates_connection_and_subnet_gossip_applies() {
    let mut peer = PeerFixture::spawn("ack-subnets");

    let ack = str::from_utf8(&peer.daemon_ack)
        .expect("ACK is ASCII")
        .trim_end();
    let fields: Vec<&str> = ack.split_whitespace().collect();
    assert_eq!(fields.len(), 4, "ACK: {ack:?}");
    assert_eq!(fields[0], "4");
    let udp_port: u16 = fields[1].parse().expect("udp port");
    assert_ne!(udp_port, 0);
    let weight_ms: i32 = fields[2].parse().expect("weight");
    assert!((0..5000).contains(&weight_ms), "weight: {weight_ms}");
    // PMTU | CLAMP with protocol minor 7 in the top byte.
    assert_eq!(u32::from_str_radix(fields[3], 16).unwrap(), 0x0700_000c);

    activate(&mut peer);

    // On activation the daemon sends everything it knows plus a
    // broadcast of the new edge: one or two ADD_EDGE for
    // testnode→testpeer, port 0 because our ACK said so.
    let announced = peer.drain_records(500);
    assert!(!announced.is_empty(), "no ADD_EDGE after activation");
    for record in &announced {
        let line = str::from_utf8(record).unwrap();
        assert!(
            line.starts_with("12 ") && line.contains(" testnode testpeer 127.0.0.1 0 "),
            "unexpected post-ACK record: {line:?}"
        );
    }

    let mut ctl = peer.node.ctl();
    let connections = ctl.dump(6);
    assert_eq!(connections.len(), 2, "peer + control: {connections:?}");
    let peer_row = find_row(&connections, "18 6 testpeer ");
    assert!(
        peer_row.starts_with("18 6 testpeer 127.0.0.1 port ") && peer_row.contains(" 700000c "),
        "{peer_row}"
    );

    // Default weight 10 is omitted in the dump.
    let add_subnet = b"10 deadbeef testpeer 192.168.99.0/24#10\n";
    peer.send_record(add_subnet);
    assert_no_reply(&mut peer, "ADD_SUBNET");
    assert_eq!(ctl.dump(5), ["18 5 192.168.99.0/24 testpeer"]);

    // Same line incl. nonce → dropped by the seen-request cache.
    peer.send_record(add_subnet);
    assert_no_reply(&mut peer, "duplicate ADD_SUBNET");
    assert_eq!(ctl.dump(5).len(), 1);

    peer.send_record(b"11 cafef00d testpeer 192.168.99.0/24#10\n");
    assert_no_reply(&mut peer, "DEL_SUBNET");
    assert!(ctl.dump(5).is_empty());

    let log = peer.kill_and_stderr();
    for expected in [
        "SPTPS handshake completed with testpeer",
        "activated",
        "Node testpeer became reachable",
    ] {
        assert!(log.contains(expected), "missing {expected:?}:\n{log}");
    }
}

/// `ADD_EDGE` for a node we have no connection to makes it reachable
/// through the graph alone; weight and local-address updates to an
/// existing edge are applied in place.
#[test]
fn transitive_edge_makes_node_reachable() {
    let mut peer = PeerFixture::spawn("transitive-edge");
    activate(&mut peer);
    let _ = peer.drain_records(500);

    // SSSP only follows edges whose reverse exists, so announce both
    // directions like the two real nodes would.
    peer.send_record(b"12 11111111 testpeer faraway 10.99.0.2 655 0 50\n");
    peer.send_record(b"12 22222222 faraway testpeer 10.99.0.1 655 0 50\n");
    assert_no_reply(&mut peer, "ADD_EDGE");

    let mut ctl = peer.node.ctl();

    let connections = ctl.dump(6);
    assert_eq!(connections.len(), 2, "{connections:?}");
    assert!(
        !connections.iter().any(|row| row.contains("faraway")),
        "faraway is graph-only: {connections:?}"
    );

    let nodes = ctl.dump(3);
    assert_eq!(nodes.len(), 3, "{nodes:?}");
    for name in ["testnode", "testpeer", "faraway"] {
        assert!(
            node_reachable(&nodes, name),
            "{name} unreachable: {nodes:#?}"
        );
    }
    // 0x40 = reached via SPTPS; set on BecameReachable, so not on self.
    for name in ["testpeer", "faraway"] {
        assert!(
            node_status(&nodes, name).unwrap() & 0x40 != 0,
            "{name} sptps bit: {nodes:#?}"
        );
    }
    // Row tail after status: nexthop via distance …
    let myself = find_row(&nodes, "18 3 testnode ");
    assert!(
        myself.contains(" MYSELF port ") && myself.contains(" testnode testnode 0 "),
        "{myself}"
    );
    let direct = find_row(&nodes, "18 3 testpeer ");
    assert!(
        direct.contains(" 127.0.0.1 port 0 ") && direct.contains(" testpeer testpeer 1 "),
        "{direct}"
    );
    // A transitive node's UDP address is seeded from the edge that
    // made it reachable (used to be "unknown port unknown", which
    // silently disabled direct UDP probes). rtt -1, counters 0.
    let transitive = find_row(&nodes, "18 3 faraway ");
    assert!(
        transitive.contains(" 10.99.0.2 port 655 ")
            && transitive.contains(" testpeer faraway 2 ")
            && transitive.ends_with(" -1 0 0 0 0"),
        "{transitive}"
    );

    let edges = ctl.dump(4);
    assert_eq!(edges.len(), 4, "{edges:#?}");
    // remote = connection address + UDP port from our ACK (0);
    // local = getsockname with the daemon's own UDP port.
    assert!(
        find_row(&edges, "18 4 testnode testpeer ").contains(" 127.0.0.1 port 0 127.0.0.1 port "),
        "{edges:#?}"
    );
    // The reverse edge starts without an address; our ADD_EDGE in
    // `activate` must have filled it in rather than being treated as
    // a no-op (hub-and-spoke relaying depends on that).
    assert!(
        find_row(&edges, "18 4 testpeer testnode ").contains(" 127.0.0.1 port 655 "),
        "{edges:#?}"
    );
    assert_eq!(
        find_row(&edges, "18 4 testpeer faraway "),
        "18 4 testpeer faraway 10.99.0.2 port 655 unspec port unspec 0 50"
    );
    assert_eq!(
        find_row(&edges, "18 4 faraway testpeer "),
        "18 4 faraway testpeer 10.99.0.1 port 655 unspec port unspec 0 50"
    );

    // Weight change only: updated in place, address kept.
    peer.send_record(b"12 33333333 testpeer faraway 10.99.0.2 655 0 99\n");
    assert_no_reply(&mut peer, "ADD_EDGE weight update");
    assert_eq!(
        find_row(&ctl.dump(4), "18 4 testpeer faraway "),
        "18 4 testpeer faraway 10.99.0.2 port 655 unspec port unspec 0 99"
    );

    // Local-address change only: must not be ignored as idempotent,
    // or LocalDiscovery keeps probing a stale LAN address after a
    // peer roams.
    peer.send_record(b"12 44444444 testpeer faraway 10.99.0.2 655 0 99 192.168.1.9 655\n");
    assert_no_reply(&mut peer, "ADD_EDGE local address update");
    assert_eq!(
        find_row(&ctl.dump(4), "18 4 testpeer faraway "),
        "18 4 testpeer faraway 10.99.0.2 port 655 192.168.1.9 port 655 0 99"
    );

    let log = peer.kill_and_stderr();
    assert!(log.contains("Node testpeer became reachable"), "{log}");
    assert!(log.contains("Node faraway became reachable"), "{log}");
}

/// The daemon has a different public key on file for `testpeer` than
/// the one we sign with: SIG verification must fail and the
/// connection must be dropped.
#[test]
fn handshake_with_wrong_key_is_rejected() {
    let tmp = tmp!("wrong-key");
    let registered_peer = Node::new(tmp.path(), "testpeer", 0x88);
    let mut node = Node::new(tmp.path(), "testnode", 0x42);
    node.write_config(&registered_peer, false);
    node.start();

    let stream = TcpStream::connect(node.tcp_addr()).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    writeln!(&stream, "0 testpeer 17.7").unwrap();
    assert_eq!(read_line_unbuffered(&stream), b"0 testnode 17.7\n");

    let signing_key = SigningKey::from_seed(&[0x77; 32]);
    let (mut sptps, init_output) = Sptps::start(
        Role::Initiator,
        Framing::Stream,
        signing_key,
        node.pubkey(),
        b"tinc TCP key expansion testpeer testnode\0".to_vec(),
        0,
        &mut tinc_crypto::os_rng(),
    );
    let send = |outputs: Vec<Output>| {
        for output in outputs {
            if let Output::Wire { bytes, .. } = output {
                // The daemon may already have reset the connection.
                let _ = (&stream).write_all(&bytes);
            }
        }
    };
    send(init_output);

    // Feed the daemon's KEX (and SIG, which verifies fine on our side)
    // so that our SIG goes out; then expect the daemon to hang up.
    let mut buf = [0u8; 4096];
    let closed = loop {
        match (&stream).read(&mut buf) {
            Ok(0) => break true,
            Ok(n) => {
                let mut consumed = 0;
                while consumed < n {
                    match sptps.receive(&buf[consumed..n], &mut tinc_crypto::os_rng()) {
                        Ok((0, _)) | Err(_) => break,
                        Ok((used, outputs)) => {
                            consumed += used;
                            send(outputs);
                        }
                    }
                }
            }
            Err(e) if is_timeout(&e) => break false,
            Err(_) => break true,
        }
    };

    let log = node.stop();
    assert!(
        closed,
        "daemon kept a connection with a bad SIG open:\n{log}"
    );
    assert!(log.contains("BadSig"), "{log}");
    assert!(!log.contains("SPTPS handshake completed"), "{log}");
}

/// Control connection subscribed to the packet tap with `18 14 SNAPLEN`.
struct PcapTap<'a> {
    reader: BufReader<&'a UnixStream>,
}

impl<'a> PcapTap<'a> {
    fn subscribe(socket: &'a UnixStream, cookie: &str, snaplen: usize) -> Self {
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut reader = BufReader::new(socket);
        writeln!(&mut &*socket, "0 ^{cookie} 0").unwrap();
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        reader.read_line(&mut line).unwrap();
        // No ack for REQ_PCAP; captured packets just start arriving.
        writeln!(&mut &*socket, "18 14 {snaplen}").unwrap();
        Self { reader }
    }

    /// One `18 14 LEN\n` header followed by LEN raw bytes.
    fn next_packet(&mut self) -> Vec<u8> {
        let mut header = String::new();
        self.reader.read_line(&mut header).expect("pcap header");
        let len: usize = header
            .strip_prefix("18 14 ")
            .and_then(|rest| rest.trim_end().parse().ok())
            .unwrap_or_else(|| panic!("pcap header: {header:?}"));
        let mut body = vec![0u8; len];
        self.reader.read_exact(&mut body).expect("pcap body");
        body
    }
}

/// `REQ_PCAP`: a packet routed by the daemon is copied to subscribed
/// control connections as `18 14 LEN\n` + LEN raw bytes, clipped to
/// the subscriber's snaplen. The frame deliberately contains `\n` to
/// show the body is length-delimited, not line-delimited.
#[test]
fn pcap_tap_delivers_routed_frames() {
    // Switch mode floods frames for unknown MACs, so a lone PACKET
    // reaches the router without any subnets configured.
    let mut peer = PeerFixture::spawn_with_conf("pcap", "Mode = switch");
    activate(&mut peer);
    let _ = peer.drain_records(300);

    let mut frame = Vec::with_capacity(60);
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, b'\n']); // dst MAC
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x02]); // src MAC
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    frame.resize(60, 0xee);
    // `17 LEN` announces that the next record is a raw frame.
    let packet_header = format!("17 {}\n", frame.len());

    let cookie = read_cookie(&peer.node.pidfile);
    let full_socket = UnixStream::connect(&peer.node.socket).unwrap();
    let mut full_tap = PcapTap::subscribe(&full_socket, &cookie, 0);
    peer.send_record(packet_header.as_bytes());
    peer.send_record(&frame);
    assert_eq!(full_tap.next_packet(), frame);
    drop(full_tap);
    drop(full_socket);

    let clipped_socket = UnixStream::connect(&peer.node.socket).unwrap();
    let mut clipped_tap = PcapTap::subscribe(&clipped_socket, &cookie, 20);
    peer.send_record(packet_header.as_bytes());
    peer.send_record(&frame);
    assert_eq!(clipped_tap.next_packet(), &frame[..20]);
}
