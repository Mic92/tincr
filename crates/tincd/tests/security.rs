//! Security boundary of the meta protocol, tested with this process
//! acting as the (hostile) peer. Ports C tinc's `security.py` and
//! `splice.py`, plus a few tincr-specific cases.
//!
//! Not covered here: the per-IP tarpit is loopback-exempt, so it is
//! unit-tested in `listen.rs` instead.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::thread;
use std::time::{Duration, Instant};
use tincd::daemon::MAX_PENDING_META;

#[macro_use]
mod common;
use common::{
    Node, PeerFixture, TmpGuard, is_timeout, node_reachable, read_cookie, read_line_unbuffered,
    read_to_eof,
};

const ID_REPLY: &[u8] = b"0 testnode 17.7\n";

fn connect(node: &Node, read_timeout: Duration) -> TcpStream {
    let stream = TcpStream::connect(node.tcp_addr()).expect("TCP connect");
    stream.set_read_timeout(Some(read_timeout)).unwrap();
    stream
}

/// Single daemon `testnode` that knows a peer `bar`.
fn start_testnode(tag: &str, extra_conf: &str) -> (TmpGuard, Node) {
    let tmp = tmp!(tag);
    let bar = Node::new(tmp.path(), "bar", 0x99);
    let mut testnode = Node::new(tmp.path(), "testnode", 0x42)
        .with_conf(extra_conf)
        .log_level("tincd=debug");
    testnode.write_config(&bar, false);
    testnode.start();
    (tmp, testnode)
}

/// Send one `ID` line and expect the daemon to hang up without a
/// word. Returns the daemon log.
fn expect_id_dropped(tag: &str, id_line: &str) -> String {
    let (_tmp, mut testnode) = start_testnode(tag, "");
    let stream = connect(&testnode, Duration::from_secs(5));
    writeln!(&stream, "{id_line}").unwrap();
    match read_to_eof(&stream) {
        Ok(got) if got.is_empty() => {}
        Ok(got) => panic!(
            "{id_line:?}: expected silent drop, got {:?}",
            String::from_utf8_lossy(&got)
        ),
        Err(got) => panic!(
            "{id_line:?}: daemon kept the connection open (sent {:?})",
            String::from_utf8_lossy(&got)
        ),
    }
    let log = testnode.stop();
    assert!(log.contains("ID rejected"), "{id_line:?}: log:\n{log}");
    log
}

/// A peer claiming our own name would create a self-loop in the graph.
#[test]
fn id_with_own_name_is_dropped() {
    let log = expect_id_dropped("own-id", "0 testnode 17.7");
    assert!(log.contains("claims to be us"), "log:\n{log}");
}

/// No `hosts/NAME` (or one without a key) means we cannot authenticate
/// the peer, so don't even answer.
#[test]
fn id_from_unknown_peer_is_dropped() {
    let log = expect_id_dropped("unknown-id", "0 nonexistent 17.7");
    assert!(log.contains("unknown identity"), "log:\n{log}");
}

/// Minor version < 2 asks for the legacy RSA metaprotocol, which tincr
/// does not implement. A known peer name isolates the version gate
/// from the unknown-identity one.
#[test]
fn id_requesting_legacy_protocol_is_dropped() {
    let log = expect_id_dropped("legacy-minor", "0 bar 17.0");
    assert!(log.contains("roll back protocol version"), "log:\n{log}");
}

/// A peer that passes `ID` but never starts the SPTPS handshake is
/// reaped after `PingTimeout`, and the daemon keeps serving.
#[test]
fn stalled_handshake_is_reaped_after_ping_timeout() {
    let (_tmp, mut testnode) = start_testnode("stalled-handshake", "PingTimeout = 1");

    let stream = connect(&testnode, Duration::from_secs(5));
    writeln!(&stream, "0 bar 17.7").unwrap();
    // ID reply (followed by the daemon's KEX, which we ignore).
    assert_eq!(read_line_unbuffered(&stream), ID_REPLY);

    // Sweep runs once a second; allow generous slack.
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    assert!(
        read_to_eof(&stream).is_ok(),
        "half-open connection was not reaped; log:\n{}",
        testnode.log()
    );

    testnode.assert_alive();
    let cookie = read_cookie(&testnode.pidfile);
    let ctl = UnixStream::connect(&testnode.socket).expect("control socket");
    writeln!(&ctl, "0 ^{cookie} 0").unwrap();
    let mut line = String::new();
    BufReader::new(&ctl).read_line(&mut line).unwrap();
    assert_eq!(line.as_bytes(), ID_REPLY);

    let log = testnode.stop();
    assert!(log.contains("Timeout"), "log:\n{log}");
}

/// `splice.py`: a relay connects to alice as bob and to bob as alice and pipes
/// bytes between them. Both hold valid keys, so this would authenticate if
/// SPTPS didn't bind sessions to roles and names. It must not: both daemons are
/// responders waiting for an initiator SIG, and the key-derivation labels name
/// the parties in opposite order. Neither may see a reachable peer.
#[test]
fn spliced_responders_never_authenticate() {
    let tmp = tmp!("splice");
    let mut alice = Node::new(tmp.path(), "alice", 0xAA).log_level("tincd=debug");
    let mut bob = Node::new(tmp.path(), "bob", 0xBB).log_level("tincd=debug");
    alice.write_config(&bob, false);
    bob.write_config(&alice, false);
    alice.start();
    bob.start();

    let to_alice = connect(&alice, Duration::from_secs(5));
    let to_bob = connect(&bob, Duration::from_secs(5));
    writeln!(&to_alice, "0 bob 17.7").unwrap();
    writeln!(&to_bob, "0 alice 17.7").unwrap();

    // Consume exactly the ID line; everything after it is SPTPS and
    // must be relayed verbatim.
    assert_eq!(read_line_unbuffered(&to_alice), b"0 alice 17.7\n");
    assert_eq!(read_line_unbuffered(&to_bob), b"0 bob 17.7\n");

    // Pipe both directions until a side closes or the deadline
    // passes. A loopback handshake takes milliseconds; two seconds is
    // ample for anything that was going to happen.
    let deadline = Instant::now() + Duration::from_secs(2);
    let pipe = |source: TcpStream, mut sink: TcpStream| {
        source
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while Instant::now() < deadline {
                match (&source).read(&mut buf) {
                    Ok(0) => return,
                    Ok(n) => {
                        if sink.write_all(&buf[..n]).is_err() {
                            return;
                        }
                    }
                    Err(e) if is_timeout(&e) => {}
                    Err(_) => return,
                }
            }
        })
    };
    let alice_to_bob = pipe(to_alice.try_clone().unwrap(), to_bob.try_clone().unwrap());
    let bob_to_alice = pipe(to_bob, to_alice);
    alice_to_bob.join().unwrap();
    bob_to_alice.join().unwrap();

    let alice_sees_bob = node_reachable(&alice.ctl().dump(3), "bob");
    let bob_sees_alice = node_reachable(&bob.ctl().dump(3), "alice");
    let alice_log = alice.stop();
    let bob_log = bob.stop();
    assert!(
        !alice_sees_bob && !bob_sees_alice,
        "spliced peers became reachable (alice→bob {alice_sees_bob}, bob→alice {bob_sees_alice})\n\
         alice:\n{alice_log}\nbob:\n{bob_log}"
    );
    for log in [&alice_log, &bob_log] {
        assert!(
            !log.contains("SPTPS handshake completed"),
            "handshake completed through splice:\n{log}"
        );
    }
}

/// An authenticated peer sends one malformed request. The daemon must
/// drop that connection, stay up, and keep answering the control
/// socket. One daemon per case because the first bad line ends the
/// connection.
fn expect_bad_request_drops_peer(tag: &str, body: &[u8]) {
    let mut peer = PeerFixture::spawn(tag);
    // Finish activation (our ACK + the reverse edge) so the request
    // reaches its handler instead of bouncing off the pre-ACK gate.
    peer.send_record(b"4 0 1 700000c\n");
    peer.send_record(b"12 deadbeef testpeer testnode 127.0.0.1 655 700000c 1\n");
    let _ = peer.drain_records(300);

    peer.send_record(body);

    peer.stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    assert!(
        read_to_eof(&peer.stream).is_ok(),
        "{tag}: connection survived malformed record {body:?}"
    );
    peer.node.assert_alive();
    let nodes = peer.node.ctl().dump(3);
    assert!(
        nodes.iter().any(|row| row.contains("testnode")),
        "{tag}: control dump after drop: {nodes:?}"
    );
}

#[test]
fn bad_request_drops_peer_not_daemon() {
    #[rustfmt::skip]
    let cases: &[(&str, &[u8])] = &[
        ("edge-weight-ovf", b"12 0 a b 1.2.3.4 655 0 99999999999999999999\n"), // weight > i32
        ("edge-too-short",  b"12 0 a b\n"),
        ("subnet-prefix",   b"10 0 alice ::/200\n"),                           // prefix > 128
        ("anskey-short",    b"16 a b k 0 0 0\n"),                              // 7 fields required
        ("keychg-bad-name", b"14 0 bad-name\n"),                               // fails check_id
        ("mtuinfo-nan",     b"23 a b notanint\n"),
        ("packet-no-len",   b"17\n"),
        ("unknown-request", b"99 whatever\n"),
        ("edge-non-utf8",   b"12 0 a b \xff\xfe 655 0 1\n"),
    ];
    for &(tag, body) in cases {
        expect_bad_request_drops_peer(tag, body);
    }
}

/// The per-IP tarpit does not stop a slowloris from many sources, so
/// there is also a global cap on unauthenticated connections. Loopback
/// is tarpit-exempt, which lets one process fill it.
#[test]
fn unauthenticated_conn_cap_rejects_then_frees() {
    // Long PingTimeout so the sweep doesn't free slots mid-test.
    let (_tmp, mut testnode) =
        start_testnode("pending-cap", "PingInterval = 120\nPingTimeout = 120");

    // An admitted idle connection just sits there (read times out);
    // a rejected one is closed immediately.
    let is_admitted = |stream: &TcpStream| match read_to_eof(stream) {
        Err(got) if got.is_empty() => true,
        Ok(got) if got.is_empty() => false,
        other => panic!("unexpected data on idle pre-auth conn: {other:?}"),
    };

    // One at a time: kqueue is edge-triggered and the daemon accepts
    // once per wake, so give each SYN its own edge.
    let mut held = Vec::with_capacity(MAX_PENDING_META);
    loop {
        let stream = connect(&testnode, Duration::from_millis(300));
        thread::sleep(Duration::from_millis(30));
        if !is_admitted(&stream) {
            break;
        }
        held.push(stream);
        assert!(
            held.len() <= MAX_PENDING_META,
            "cap never tripped after {} conns",
            held.len()
        );
    }
    assert_eq!(held.len(), MAX_PENDING_META, "cap tripped at wrong count");
    assert!(is_admitted(&held[0]), "first slot dropped");
    assert!(is_admitted(held.last().unwrap()), "last slot dropped");

    drop(held.pop());
    thread::sleep(Duration::from_millis(300));
    let again = connect(&testnode, Duration::from_millis(500));
    assert!(is_admitted(&again), "not admitted after freeing a slot");

    drop(held);
    drop(again);
    let log = testnode.stop();
    assert!(
        log.contains("Too many unauthenticated connections"),
        "log:\n{log}"
    );
}
