//! Security boundary of the meta protocol, tested with this process
//! acting as the (hostile) peer. Ports C tinc's `security.py` and
//! `splice.py`, plus a few tincr-specific cases.
//!
//! Not covered here: the per-IP tarpit is loopback-exempt, so it is
//! unit-tested in `listen.rs` instead.

use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

#[macro_use]
mod common;
use common::{
    ChildWithLog, Ctl, PeerFixture, TmpGuard, node_status, pubkey_from_seed, read_cookie,
    read_tcp_addr, tincd_at, wait_for_file, write_ed25519_privkey,
};

const ID_REPLY: &[u8] = b"0 testnode 17.7\n";

/// A running `tincd` with a dummy device, listening on an ephemeral
/// port. Killed on drop; stderr is drained in the background so a
/// chatty daemon can never block on a full pipe.
struct Daemon {
    child: ChildWithLog,
    tcp_addr: SocketAddr,
    pidfile: PathBuf,
    socket: PathBuf,
}

impl Daemon {
    /// `peers` are `(name, seed)` pairs written to `hosts/` so the
    /// daemon recognises them in `ID`.
    fn start(dir: &Path, name: &str, seed: u8, extra_conf: &str, peers: &[(&str, u8)]) -> Self {
        let confbase = dir.join(name);
        let pidfile = dir.join(format!("{name}.pid"));
        let socket = dir.join(format!("{name}.socket"));

        std::fs::create_dir_all(confbase.join("hosts")).unwrap();
        std::fs::write(
            confbase.join("tinc.conf"),
            format!("Name = {name}\nDeviceType = dummy\nAddressFamily = ipv4\n{extra_conf}"),
        )
        .unwrap();
        std::fs::write(confbase.join("hosts").join(name), "Port = 0\n").unwrap();
        write_ed25519_privkey(&confbase, &[seed; 32]);
        for &(peer, peer_seed) in peers {
            let b64 = tinc_crypto::b64::encode(&pubkey_from_seed(&[peer_seed; 32]));
            std::fs::write(
                confbase.join("hosts").join(peer),
                format!("Ed25519PublicKey = {b64}\n"),
            )
            .unwrap();
        }

        let child = tincd_at(&confbase, &pidfile, &socket)
            .env("RUST_LOG", "tincd=debug")
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn tincd");
        let child = ChildWithLog::spawn(child);
        assert!(
            wait_for_file(&socket),
            "{name}: setup failed; stderr:\n{}",
            child.kill_and_log()
        );
        Self {
            tcp_addr: read_tcp_addr(&pidfile),
            child,
            pidfile,
            socket,
        }
    }

    fn connect(&self, read_timeout: Duration) -> TcpStream {
        let s = TcpStream::connect(self.tcp_addr).expect("TCP connect");
        s.set_read_timeout(Some(read_timeout)).unwrap();
        s
    }

    fn ctl(&self) -> Ctl {
        Ctl::connect(&self.socket, &self.pidfile)
    }

    fn assert_alive(&mut self) {
        if let Some(status) = self.child.child.try_wait().unwrap() {
            panic!(
                "daemon exited ({status}); stderr:\n{}",
                self.child.log_snapshot()
            );
        }
    }

    fn into_log(self) -> String {
        self.child.kill_and_log()
    }
}

/// Single daemon named `testnode` that knows a peer `bar`.
fn start_testnode(tag: &str, extra_conf: &str) -> (TmpGuard, Daemon) {
    let tmp = tmp!(tag);
    let d = Daemon::start(tmp.path(), "testnode", 0x42, extra_conf, &[("bar", 0x99)]);
    (tmp, d)
}

fn is_timeout(e: &std::io::Error) -> bool {
    matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
}

/// Read until the peer closes. `Ok(bytes)` on EOF/RST, `Err(bytes)`
/// if the socket's read timeout fired first.
fn read_to_eof(mut s: &TcpStream) -> Result<Vec<u8>, Vec<u8>> {
    let mut got = Vec::new();
    let mut buf = [0u8; 512];
    loop {
        match s.read(&mut buf) {
            Ok(0) => return Ok(got),
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(e) if is_timeout(&e) => return Err(got),
            Err(_) => return Ok(got),
        }
    }
}

/// Send one `ID` line and expect the daemon to hang up without a
/// word. Returns the daemon log.
fn expect_id_dropped(tag: &str, id_line: &str) -> String {
    let (_tmp, d) = start_testnode(tag, "");
    let s = d.connect(Duration::from_secs(5));
    writeln!(&s, "{id_line}").unwrap();
    match read_to_eof(&s) {
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
    let log = d.into_log();
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
    let (_tmp, mut d) = start_testnode("stalled-handshake", "PingTimeout = 1\n");

    let s = d.connect(Duration::from_secs(5));
    writeln!(&s, "0 bar 17.7").unwrap();

    // ID reply plus the daemon's KEX record, then silence from us.
    let mut reply = vec![0u8; ID_REPLY.len()];
    (&s).read_exact(&mut reply).expect("ID reply");
    assert_eq!(reply, ID_REPLY);

    // Sweep runs once a second; allow generous slack.
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    assert!(
        read_to_eof(&s).is_ok(),
        "half-open connection was not reaped; log:\n{}",
        d.child.log_snapshot()
    );

    d.assert_alive();
    let cookie = read_cookie(&d.pidfile);
    let ctl = UnixStream::connect(&d.socket).expect("control socket");
    writeln!(&ctl, "0 ^{cookie} 0").unwrap();
    let mut line = String::new();
    BufReader::new(&ctl).read_line(&mut line).unwrap();
    assert_eq!(line.as_bytes(), ID_REPLY);

    let log = d.into_log();
    assert!(log.contains("Timeout"), "log:\n{log}");
}

/// `splice.py`: a relay connects to alice claiming to be bob and to
/// bob claiming to be alice, then pipes bytes between them. Both ends
/// hold the right keys, so if SPTPS did not bind the session to
/// (initiator, responder) roles and names this would authenticate.
///
/// It must not: both daemons are responders and wait for an initiator
/// SIG that never comes, and even if one did, the key-derivation
/// labels name the parties in opposite order. Neither side may end up
/// with a reachable peer.
#[test]
fn spliced_responders_never_authenticate() {
    let tmp = tmp!("splice");
    let alice = Daemon::start(tmp.path(), "alice", 0xAA, "", &[("bob", 0xBB)]);
    let bob = Daemon::start(tmp.path(), "bob", 0xBB, "", &[("alice", 0xAA)]);

    let to_alice = alice.connect(Duration::from_secs(5));
    let to_bob = bob.connect(Duration::from_secs(5));
    writeln!(&to_alice, "0 bob 17.7").unwrap();
    writeln!(&to_bob, "0 alice 17.7").unwrap();

    // Consume exactly the ID line; everything after it is SPTPS and
    // must be relayed verbatim.
    let read_line = |mut s: &TcpStream| {
        let mut out = Vec::new();
        let mut b = [0u8; 1];
        while b[0] != b'\n' {
            s.read_exact(&mut b).expect("ID reply");
            out.push(b[0]);
        }
        out
    };
    assert_eq!(read_line(&to_alice), b"0 alice 17.7\n");
    assert_eq!(read_line(&to_bob), b"0 bob 17.7\n");

    // Pipe both directions until a side closes or the deadline
    // passes. A loopback handshake takes milliseconds; two seconds is
    // ample for anything that was going to happen.
    let deadline = Instant::now() + Duration::from_secs(2);
    let pipe = |from: TcpStream, mut to: TcpStream| {
        from.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while Instant::now() < deadline {
                match (&from).read(&mut buf) {
                    Ok(0) => return,
                    Ok(n) => {
                        if to.write_all(&buf[..n]).is_err() {
                            return;
                        }
                    }
                    Err(e) if is_timeout(&e) => {}
                    Err(_) => return,
                }
            }
        })
    };
    let a2b = pipe(to_alice.try_clone().unwrap(), to_bob.try_clone().unwrap());
    let b2a = pipe(to_bob, to_alice);
    a2b.join().unwrap();
    b2a.join().unwrap();

    let reachable =
        |d: &Daemon, peer: &str| node_status(&d.ctl().dump(3), peer).is_some_and(|s| s & 0x10 != 0);
    let alice_sees_bob = reachable(&alice, "bob");
    let bob_sees_alice = reachable(&bob, "alice");
    let alice_log = alice.into_log();
    let bob_log = bob.into_log();
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
    let mut fx = PeerFixture::spawn(tag);
    // Finish activation (our ACK + the reverse edge) so the request
    // reaches its handler instead of bouncing off the pre-ACK gate.
    fx.send_record(b"4 0 1 700000c\n");
    fx.send_record(b"12 deadbeef testpeer testnode 127.0.0.1 655 700000c 1\n");
    let _ = fx.drain_records(300);

    fx.send_record(body);

    fx.stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    assert!(
        read_to_eof(&fx.stream).is_ok(),
        "{tag}: connection survived malformed record {body:?}"
    );
    assert!(
        fx.child.try_wait().unwrap().is_none(),
        "{tag}: daemon died on {body:?}; stderr:\n{}",
        fx.kill_and_stderr()
    );
    let nodes = Ctl::connect(&fx.socket, &fx.pidfile).dump(3);
    assert!(
        nodes.iter().any(|r| r.contains("testnode")),
        "{tag}: control dump after drop: {nodes:?}"
    );
    let _ = fx.kill_and_stderr();
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
    use tincd::daemon::MAX_PENDING_META;

    // Long PingTimeout so the sweep doesn't free slots mid-test.
    let (_tmp, d) = start_testnode("pending-cap", "PingInterval = 120\nPingTimeout = 120\n");

    // An admitted idle connection just sits there (read times out);
    // a rejected one is closed immediately.
    let is_admitted = |s: &TcpStream| match read_to_eof(s) {
        Err(got) if got.is_empty() => true,
        Ok(got) if got.is_empty() => false,
        r => panic!("unexpected data on idle pre-auth conn: {r:?}"),
    };

    // One at a time: kqueue is edge-triggered and the daemon accepts
    // once per wake, so give each SYN its own edge.
    let mut held = Vec::with_capacity(MAX_PENDING_META);
    loop {
        let s = d.connect(Duration::from_millis(300));
        std::thread::sleep(Duration::from_millis(30));
        if !is_admitted(&s) {
            break;
        }
        held.push(s);
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
    std::thread::sleep(Duration::from_millis(300));
    let again = d.connect(Duration::from_millis(500));
    assert!(is_admitted(&again), "not admitted after freeing a slot");

    drop(held);
    drop(again);
    let log = d.into_log();
    assert!(
        log.contains("Too many unauthenticated connections"),
        "log:\n{log}"
    );
}
