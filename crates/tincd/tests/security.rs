//! S1 (test-process-as-peer) port of `test/integration/security.py`
//! and `test/integration/splice.{c,py}`.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

#[macro_use]
mod common;
use common::{
    Ctl, PeerFixture, TmpGuard, drain_stderr, pubkey_from_seed, read_cookie, read_tcp_addr,
    tincd_at, wait_for_file, write_ed25519_privkey,
};

fn write_config(confbase: &std::path::Path, name: &str, seed: u8, extra_conf: &str) -> [u8; 32] {
    std::fs::create_dir_all(confbase.join("hosts")).unwrap();
    std::fs::write(
        confbase.join("tinc.conf"),
        format!("Name = {name}\nDeviceType = dummy\nAddressFamily = ipv4\n{extra_conf}"),
    )
    .unwrap();
    std::fs::write(confbase.join("hosts").join(name), "Port = 0\n").unwrap();

    let seed = [seed; 32];
    write_ed25519_privkey(confbase, &seed);
    pubkey_from_seed(&seed)
}

fn spawn_daemon(
    confbase: &std::path::Path,
    pidfile: &std::path::Path,
    socket: &std::path::Path,
) -> Child {
    tincd_at(confbase, pidfile, socket)
        .env("RUST_LOG", "tincd=debug")
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tincd")
}

/// One daemon spawned + ready check
struct OneDaemon {
    _tmp: TmpGuard,
    child: Child,
    tcp_addr: std::net::SocketAddr,
}

impl OneDaemon {
    fn spawn(tag: &str, extra_conf: &str) -> Self {
        let tmp = tmp!(tag);
        let (confbase, pidfile, socket) = tmp.std_paths();

        write_config(&confbase, "testnode", 0x42, extra_conf);

        let mut child = spawn_daemon(&confbase, &pidfile, &socket);
        assert!(wait_for_file(&socket), "tincd setup failed; stderr: {}", {
            drain_stderr(std::mem::replace(
                &mut child,
                // dummy; we panic before using it
                Command::new("true").spawn().unwrap(),
            ))
        });

        let tcp_addr = read_tcp_addr(&pidfile);
        // socket/pidfile go out of scope here; the negative tests
        // only need the TCP addr. (Tmp dir keeps the files alive.)
        let _ = socket;
        Self {
            _tmp: tmp,
            child,
            tcp_addr,
        }
    }
}

/// Send `id_line` and assert the daemon drops the connection
/// `expect_reply` → we expect `"0 testnode 17.7\n"` then EOF
fn assert_dropped(daemon: OneDaemon, id_line: &str, expect_reply: bool) -> String {
    let stream = TcpStream::connect(daemon.tcp_addr).expect("TCP connect");
    // Short timeout because `terminate` is synchronous
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    writeln!(&stream, "{id_line}").unwrap();

    // Read everything until EOF
    let mut got = Vec::new();
    let mut buf = [0u8; 256];
    loop {
        match (&stream).read(&mut buf) {
            Ok(0) => break, // EOF — daemon dropped us. EXPECTED.
            Ok(n) => got.extend_from_slice(&buf[..n]),
            // WouldBlock after the read timeout: daemon DIDN'T close.
            Err(e) => panic!(
                "read from daemon errored ({e}); got so far: {:?}",
                String::from_utf8_lossy(&got)
            ),
        }
    }

    if expect_reply {
        assert_eq!(
            got,
            b"0 testnode 17.7\n",
            "expected ID reply then EOF; got {:?}",
            String::from_utf8_lossy(&got)
        );
    } else {
        assert!(
            got.is_empty(),
            "expected daemon to drop with no reply; got {:?}",
            String::from_utf8_lossy(&got)
        );
    }

    drain_stderr(daemon.child)
}

/// Reject ID claiming our own name (`dispatch.rs::handle_id`)
/// to avoid that a self-loop in the meta-graph
///
/// The daemon sees `"0 testnode 17.7\n"` — its OWN name. The
/// peer-is-us check fires before `send_id`, so we get nothing back.
///
/// Why this gate exists: .
#[test]
fn own_id_rejected() {
    let d = OneDaemon::spawn("own-id", "");
    let stderr = assert_dropped(d, "0 testnode 17.7", false);
    // The exact `Debug` format from `metaconn.rs`:
    // `"ID rejected from {}: {e:?}"`. The conn name at this point
    // is still `<unknown>` (the peer-branch's `conn.name = name`
    // line is AFTER the own-name check).
    assert!(
        stderr.contains("ID rejected"),
        "expected ID-rejected log; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("claims to be us"),
        "expected own-name BadId; stderr:\n{stderr}"
    );
}

/// Reject ID for unknown peer (no `hosts/baz`). (`dispatch.rs::handle_id`)
///
/// "File missing" and "file has no key" collapse into one error and we get no reply
#[test]
fn unknown_id_rejected() {
    let d = OneDaemon::spawn("unknown-id", "");
    // `nonexistent` — no `hosts/nonexistent` was written.
    let stderr = assert_dropped(d, "0 nonexistent 17.7", false);
    assert!(
        stderr.contains("ID rejected"),
        "expected ID-rejected log; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("unknown identity") || stderr.contains("no Ed25519 public key"),
        "expected unknown-identity BadId; stderr:\n{stderr}"
    );
}

/// Rejeet the old meta legacy protocol that we never implemented in tincr
#[test]
fn legacy_minor_rejected() {
    let tmp = tmp!("legacy-minor");
    let (confbase, pidfile, socket) = tmp.std_paths();

    write_config(&confbase, "testnode", 0x42, "");
    let bar_pub = *tinc_crypto::sign::SigningKey::from_seed(&[0x99; 32]).public_key();
    std::fs::write(
        confbase.join("hosts").join("bar"),
        format!(
            "Ed25519PublicKey = {}\n",
            tinc_crypto::b64::encode(&bar_pub)
        ),
    )
    .unwrap();

    let mut child = spawn_daemon(&confbase, &pidfile, &socket);
    assert!(wait_for_file(&socket), "setup; stderr: {}", {
        drain_stderr(std::mem::replace(
            &mut child,
            Command::new("true").spawn().unwrap(),
        ))
    });
    let tcp_addr = read_tcp_addr(&pidfile);

    let stream = TcpStream::connect(tcp_addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    // `17.0`: legacy. `handle_id` → BadId.
    writeln!(&stream, "0 bar 17.0").unwrap();

    let mut got = Vec::new();
    let mut buf = [0u8; 256];
    loop {
        match (&stream).read(&mut buf) {
            Ok(0) => break,
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(e) => panic!("read errored ({e}); got: {got:?}"),
        }
    }
    assert!(
        got.is_empty(),
        "expected drop on minor=0; got {:?}",
        String::from_utf8_lossy(&got)
    );

    let stderr = drain_stderr(child);
    assert!(
        stderr.contains("roll back protocol version"),
        "expected rollback BadId; stderr:\n{stderr}"
    );
}

/// `security.py::test_id_timeout`. Python: send `"0 bar 17.7"` then
/// SLEEP 3s (1.5× `PingTimeout=2`). Daemon drops us via the
/// pre-edge timeout sweep.
///
/// We send a name that PASSES `id_h` (so the daemon enters the
/// post-ID-waiting-for-KEX state — the realistic half-open). For
/// that we need `hosts/bar` with a pubkey. With `17.7` and a known
/// pubkey, `handle_id` succeeds, daemon sends its ID reply + KEX,
/// then waits forever for OUR KEX. THIS is the conn the sweep
/// reaps: `!conn.active` (no ACK yet) AND `last_ping_time +
/// pingtimeout` elapsed → "Timeout during authentication".
#[test]
fn id_timeout_half_open_survives() {
    let tmp = tmp!("id-timeout");
    let (confbase, pidfile, socket) = tmp.std_paths();

    // PingTimeout=1 keeps the test fast.
    write_config(&confbase, "testnode", 0x42, "PingTimeout = 1\n");
    let bar_pub = *tinc_crypto::sign::SigningKey::from_seed(&[0x99; 32]).public_key();
    std::fs::write(
        confbase.join("hosts").join("bar"),
        format!(
            "Ed25519PublicKey = {}\n",
            tinc_crypto::b64::encode(&bar_pub)
        ),
    )
    .unwrap();

    let mut child = spawn_daemon(&confbase, &pidfile, &socket);
    assert!(wait_for_file(&socket), "setup; stderr: {}", {
        drain_stderr(std::mem::replace(
            &mut child,
            Command::new("true").spawn().unwrap(),
        ))
    });
    let tcp_addr = read_tcp_addr(&pidfile);

    // connect, send ID, drain the reply, then DO NOTHING
    let stream = TcpStream::connect(tcp_addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    writeln!(&stream, "0 bar 17.7").unwrap();

    // Daemon's `id_h` peer-branch succeeds: queues ID reply +
    // responder KEX. We read both (they arrive in one segment
    // typically; loop until WouldBlock).
    let mut got = Vec::new();
    let mut buf = [0u8; 256];
    loop {
        match (&stream).read(&mut buf) {
            Ok(0) => {
                // EOF before we even got the ID reply — the sweep
                // shouldn't be THIS fast (PingTimeout=1, sweep ticks
                // at +1s). The 500ms read timeout above bounds the
                // first-batch latency. If this fires, the daemon
                // dropped us at id_h instead (config bug).
                panic!("daemon closed before ID reply; got {} bytes", got.len());
            }
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => panic!("read errored: {e}"),
        }
    }
    // Got the ID reply + KEX. The daemon now waits for OUR KEX.
    // We hold the conn open and do nothing.
    assert!(
        got.starts_with(b"0 testnode 17.7\n"),
        "expected ID reply; got {:?}",
        String::from_utf8_lossy(&got[..got.len().min(40)])
    );

    // wait for the sweep to reap us
    // PingTimeout=1; the sweep ticks every 1s. The pre-edge
    // timeout fires when `now - last_ping_time > pingtimeout`.
    // `last_ping_time` was set at accept time. After ~1s the conn
    // becomes stale; the next 1s tick reaps it. Generous timeout
    // for CI: 5s.
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let eof = match (&stream).read(&mut buf) {
        Ok(0) => true,
        Ok(n) => panic!("expected EOF, got {n} bytes"),
        Err(e) => panic!("expected EOF, got error: {e}"),
    };
    assert!(eof, "sweep should have reaped the half-open conn");

    // daemon still alive + responsive after the reap
    // The terminate path itself mustn't wedge the loop.
    assert!(
        child.try_wait().unwrap().is_none(),
        "daemon died after reaping conn; stderr: {}",
        drain_stderr(child)
    );
    let cookie = read_cookie(&pidfile);
    let ctl = UnixStream::connect(&socket).expect("daemon still responsive");
    let mut r = BufReader::new(&ctl);
    writeln!(&ctl, "0 ^{cookie} 0").unwrap();
    let mut line = String::new();
    r.read_line(&mut line).unwrap();
    assert_eq!(line, "0 testnode 17.7\n", "daemon responsive after reap");

    let _ = child.kill();
    let _ = child.wait();
}

// Adversarial-input regression: malformed protocol lines after ACK.
//
// `security.py` and the tests above probe the *pre-auth* gates
// (`id_h`). This test probes *post-auth*: an authenticated peer that
// sends garbage gossip. Threat model: a node in the mesh whose key
// was compromised, or a buggy alternate implementation. The daemon
// MUST drop the connection cleanly and stay up; it must not panic
// inside a parser.
//
// One garbage line per spawn: `dispatch_sptps_outputs` terminates
// on the first parse error, so a single test sending N bad lines
// only exercises the first. Spawning a fresh daemon per case is the
// honest way to prove each handler's reject path independently.

/// Send `body` over an activated SPTPS meta connection, then assert:
/// (a) the daemon closed *that* connection (read → EOF), (b) the
/// daemon process is still alive, (c) a fresh control-socket dump
/// works (event loop didn't wedge).
///
/// Separate fn so the per-case daemon spawn boilerplate doesn't
/// drown the table of inputs.
fn assert_malformed_record_drops_conn(tag: &str, body: &[u8]) {
    use std::io::Read;

    let mut fx = PeerFixture::spawn(tag);
    // Complete the activation: send our ACK so `allow_request`
    // goes to `None` (ALL) and the gossip handlers are reachable.
    // Without this, the garbage line would be rejected by
    // `check_gate` (`allow_request == Some(Ack)`), which proves the
    // gate but not the per-handler parsers.
    fx.send_record(b"4 0 1 700000c\n");
    // The reverse ADD_EDGE a real peer would send. Makes
    // `BecameReachable` fire so the daemon is in steady state.
    fx.send_record(b"12 deadbeef testpeer testnode 127.0.0.1 655 700000c 1\n");
    // Drain the daemon's `send_everything` burst so the read below
    // sees only the close.
    let _ = fx.drain_records(300);

    // the malformed line
    fx.send_record(body);

    // (a) connection dropped: EOF on the TCP stream
    // The daemon may flush a few queued bytes before close (e.g.
    // a pending Wire frame); read until EOF or timeout.
    fx.stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut buf = [0u8; 256];
    let mut closed = false;
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        match (&fx.stream).read(&mut buf) {
            Ok(0) => {
                closed = true;
                break;
            }
            Ok(_) => {} // drain
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => {
                // RST counts as closed for our purposes.
                closed = true;
                break;
            }
        }
    }
    assert!(
        closed,
        "{tag}: daemon did not drop conn after malformed record {body:?}"
    );

    // (b) process still alive
    // Panic in a handler → process abort → try_wait returns Some.
    assert!(
        fx.child.try_wait().unwrap().is_none(),
        "{tag}: daemon DIED on malformed record {body:?}; stderr:\n{}",
        fx.kill_and_stderr()
    );

    // (c) event loop still serving: fresh control dump works
    let nodes = Ctl::connect(&fx.socket, &fx.pidfile).dump(3);
    assert!(
        nodes.iter().any(|r| r.contains("testnode")),
        "{tag}: control dump after drop didn't list self: {nodes:?}"
    );

    let _ = fx.child.kill();
    let _ = fx.child.wait();
}

/// Malformed gossip lines, one per handler. Each is chosen to fail
/// inside the per-type `parse()` (not at `check_gate`), so we're
/// exercising `on_add_edge` / `on_add_subnet` / etc. directly.
#[test]
fn malformed_gossip_drops_conn_daemon_survives() {
    #[rustfmt::skip]
    let cases: &[(&str, &[u8])] = &[
        // ADD_EDGE: weight overflows i32. `Tok::d` → ParseError.
        ("adv-edge-ovf",   b"12 0 a b 1.2.3.4 655 0 99999999999999999999\n"),
        // ADD_EDGE: too few fields.
        ("adv-edge-short", b"12 0 a b\n"),
        // ADD_SUBNET: prefix > 128.
        ("adv-sub-pfx",    b"10 0 alice ::/200\n"),
        // ANS_KEY: only 6 fields (7 mandatory).
        ("adv-ans-short",  b"16 a b k 0 0 0\n"),
        // KEY_CHANGED: name fails check_id.
        ("adv-kc-badname", b"14 0 bad-name\n"),
        // MTU_INFO: non-integer mtu.
        ("adv-mtu-bad",    b"23 a b notanint\n"),
        // PACKET: length token missing entirely.
        ("adv-pkt-short",  b"17\n"),
        // Unknown request number: check_gate → UnknownRequest.
        ("adv-req-unk",    b"99 whatever\n"),
        // Non-UTF-8 body: `parse_add_edge`'s from_utf8 gate.
        ("adv-nonutf8",    b"12 0 a b \xff\xfe 655 0 1\n"),
    ];
    for &(tag, body) in cases {
        assert_malformed_record_drops_conn(tag, body);
    }
}

/// Aggregate pre-auth connection cap. `Tarpit` is per-IP; a
/// many-source slowloris walks past it. Loopback is tarpit-exempt so
/// one test process can fill the cap.
#[test]
fn pending_meta_cap_rejects_then_recovers() {
    use tincd::daemon::MAX_PENDING_META;

    // Long PingTimeout: the sweep must not reap idle pre-auth conns
    // and free slots behind our back.
    let d = OneDaemon::spawn("pending-cap", "PingInterval = 120\nPingTimeout = 120\n");

    // Admitted = read times out; rejected = EOF.
    let assert_admitted = |s: &TcpStream, tag: &str| {
        let mut b = [0u8; 1];
        match (&*s).read(&mut b) {
            Ok(0) => panic!("{tag}: daemon closed an admitted pre-auth conn"),
            Ok(n) => panic!("{tag}: unexpected {n} bytes from idle pre-auth conn"),
            Err(e) => assert!(
                matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ),
                "{tag}: unexpected read error {e}"
            ),
        }
    };

    // Fill one-by-one. macOS kqueue is edge-triggered and
    // `on_tcp_accept` does one accept per wake; spacing lets the
    // backlog drain so each SYN is a fresh edge.
    let mut held: Vec<TcpStream> = Vec::with_capacity(MAX_PENDING_META);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let s = TcpStream::connect(d.tcp_addr).expect("connect");
        s.set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        std::thread::sleep(Duration::from_millis(30));
        let mut b = [0u8; 1];
        match (&s).read(&mut b) {
            Ok(0) => break, // rejected: cap reached
            Ok(n) => panic!("unexpected {n} bytes from idle pre-auth conn"),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                held.push(s);
            }
            Err(e) => panic!("pre-auth read error: {e}"),
        }
        assert!(
            Instant::now() < deadline,
            "cap never tripped after {} conns",
            held.len()
        );
    }
    assert_eq!(held.len(), MAX_PENDING_META, "cap tripped at wrong count");

    assert_admitted(&held[0], "first slot");
    assert_admitted(held.last().unwrap(), "last slot");

    // Free one slot → next connect admitted again.
    drop(held.pop());
    std::thread::sleep(Duration::from_millis(300));

    let again = TcpStream::connect(d.tcp_addr).expect("connect after free");
    again
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    assert_admitted(&again, "after freeing one slot");

    drop(held);
    drop(again);
    let stderr = drain_stderr(d.child);
    assert!(
        stderr.contains("Too many unauthenticated connections"),
        "expected cap warning in stderr:\n{stderr}"
    );
}
