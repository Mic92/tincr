//! S1 (test-process-as-peer) port of `test/integration/security.py`
//! and `test/integration/splice.{c,py}`.
//!
//! ## Why
//!
//! These tests pin the protocol's **security boundary** — the cases
//! where `id_h` MUST drop the connection rather than trust adversarial
//! input. Chunk 4a landed all the gates (`proto.rs::handle_id`):
//! own-ID rejection (`:495`), unknown-identity (`:587`), version
//! rollback (`:606`). `stop.rs::peer_wrong_key_fails_sig` is the
//! one existing S1 negative case (SIG verify); these add the
//! pre-SPTPS gates.
//!
//! `splice_mitm` is the BIG one: it proves that `tcp_label`'s
//! argument ordering (initiator, responder) is the MITM defense.
//! A relay that lies about identity to BOTH daemons makes their
//! labels diverge → transcripts diverge → SIG verify fails. This
//! is the ONLY thing standing between "key exchange" and "key
//! exchange that authenticates". Without it, a passive relay gets
//! key compromise.
//!
//! ## What ISN'T here
//!
//! `security.py::test_tarpitted` — the tarpit is loopback-exempt
//! (`daemon.rs:1288` `if !is_local(&peer)`). Integration test
//! from `127.0.0.1` would never trigger it. The bucket arithmetic
//! is pinned by `listen.rs::tarpit_*` unit tests; that's enough.
//!
//! ## Harness sharing
//!
//! Same helpers as `stop.rs` and `two_daemons.rs`, copied. Option-1
//! from the task brief: test files are independent compilation units;
//! the duplication is small and a `tests/common/mod.rs` is a 3-way
//! merge hazard while other agents touch the existing files.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

mod common;
use common::{
    Ctl, PeerFixture, TmpGuard, drain_stderr, pubkey_from_seed, read_cookie, read_tcp_addr,
    tincd_cmd, wait_for_file, write_ed25519_privkey,
};

fn tmp(tag: &str) -> TmpGuard {
    TmpGuard::new("sec", tag)
}

/// Minimal config for one daemon. Returns the daemon's pubkey
/// (unused by the negative tests; the splice test reads it).
/// `extra_conf` is appended to `tinc.conf` (for `PingTimeout`).
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

/// Spawn a daemon. Same flags everywhere.
fn spawn_daemon(
    confbase: &std::path::Path,
    pidfile: &std::path::Path,
    socket: &std::path::Path,
) -> Child {
    tincd_cmd()
        .arg("-c")
        .arg(confbase)
        .arg("--pidfile")
        .arg(pidfile)
        .arg("--socket")
        .arg(socket)
        .env("RUST_LOG", "tincd=debug")
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tincd")
}

/// One daemon spawned + ready. The fixture for the single-daemon
/// negative tests.
struct OneDaemon {
    _tmp: TmpGuard,
    child: Child,
    tcp_addr: std::net::SocketAddr,
}

impl OneDaemon {
    fn spawn(tag: &str, extra_conf: &str) -> Self {
        let tmp = tmp(tag);
        let confbase = tmp.path().join("vpn");
        let pidfile = tmp.path().join("tinc.pid");
        let socket = tmp.path().join("tinc.socket");

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
/// (immediate EOF — `handle_id` returns `BadId`, `DispatchResult::
/// Drop` → `terminate(id)`). Returns the daemon's stderr after
/// kill (for log-message assertions).
///
/// `expect_reply` → we expect `"0 testnode 17.7\n"` THEN EOF (the
/// daemon got far enough to queue its `send_id` reply before the
/// later gate fired). Currently no test uses it, but the python
/// `test_tarpitted` did — kept for symmetry.
fn assert_dropped(daemon: OneDaemon, id_line: &str, expect_reply: bool) -> String {
    let stream = TcpStream::connect(daemon.tcp_addr).expect("TCP connect");
    // Short timeout: `terminate` is synchronous in the dispatch
    // path; the close happens before `handle_id`'s caller returns.
    // 2s is generous.
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    writeln!(&stream, "{id_line}").unwrap();

    // Read everything until EOF. `BadId` → `Drop` → `terminate`
    // closes the fd. We see EOF (read returns 0). If the daemon
    // somehow proceeded (sent its ID reply + KEX bytes), we'd
    // read non-empty and fail below.
    let mut got = Vec::new();
    let mut buf = [0u8; 256];
    loop {
        match (&stream).read(&mut buf) {
            Ok(0) => break, // EOF — daemon dropped us. EXPECTED.
            Ok(n) => got.extend_from_slice(&buf[..n]),
            // WouldBlock after the read timeout: daemon DIDN'T close.
            // Treat as failure (the test expected a drop).
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
        // `security.py` `check.false(data)`: no reply at all.
        assert!(
            got.is_empty(),
            "expected daemon to drop with no reply; got {:?}",
            String::from_utf8_lossy(&got)
        );
    }

    drain_stderr(daemon.child)
}

// ═══════════════════════════════════════════════════════════════════
// security.py ports

/// Reject ID claiming our own name. Gate: `proto.rs::handle_id`
/// `if name == ctx.my_name`.
///
/// The daemon sees `"0 testnode 17.7\n"` — its OWN name. The
/// peer-is-us check fires before `send_id` (the C orders the check
/// at `:376`, BEFORE the version check at `:398` and `send_id` at
/// `:451`). We get nothing back.
///
/// Why this gate exists: a self-loop in the meta-graph would make
/// every `ADD_EDGE` we broadcast come back via this peer, get
/// re-broadcast, infinite. C rejects early.
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

/// Reject ID for unknown peer (no `hosts/baz`). Gate:
/// `proto.rs::handle_id` pubkey-load fails (the
/// `let Some(ecdsa) = ecdsa else` arm).
///
/// The C distinguishes "file missing" (`:428`) vs "file has no key"
/// (the `read_ecdsa_public_key` fail). We collapse both into one
/// error — see the comment at the `host_config` parse in `handle_id`.
/// Either way: drop.
///
/// **Timing nuance**: the C's `:428` check is BEFORE the version
/// check; our pubkey-load is AFTER the version check and AFTER
/// `conn.name = name`. But still BEFORE the `send_id` reply. So:
/// same observable behavior — no reply.
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

/// `security.py::test_null_metakey`. The python test sends a legacy
/// `17.0` ID followed by a `METAKEY` with empty hex. We forbid
/// legacy entirely (`DISABLE_LEGACY` equivalent). The relevant
/// gate is the version-minor check.
///
/// We're stricter than upstream: `minor < 2` is reject (we don't
/// speak legacy at any minor). The daemon never
/// gets to the METAKEY line.
///
/// **The catch**: the python sends to `foo` (the daemon's own name)
/// AND `17.0`. Two gates fire; the C's `check_id` is first. We send a
/// KNOWN peer name with `17.0` to isolate the version gate.
#[test]
fn legacy_minor_rejected() {
    let tmp = tmp("legacy-minor");
    let confbase = tmp.path().join("vpn");
    let pidfile = tmp.path().join("tinc.pid");
    let socket = tmp.path().join("tinc.socket");

    write_config(&confbase, "testnode", 0x42, "");
    // We DO need a hosts/bar with a pubkey: the version check at
    // The `minor < 2` check is AFTER the pubkey load. Without
    // a pubkey, the unknown-identity gate fires first.
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
    // `17.0`: legacy. `handle_id` `if minor < 2` → BadId.
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
    let tmp = tmp("id-timeout");
    let confbase = tmp.path().join("vpn");
    let pidfile = tmp.path().join("tinc.pid");
    let socket = tmp.path().join("tinc.socket");

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

    // ─── connect, send ID, drain the reply, then DO NOTHING ───
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

    // ─── wait for the sweep to reap us ─────────────────────────
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

    // ─── daemon still alive + responsive after the reap ────────
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

// ═══════════════════════════════════════════════════════════════════
// splice.py / splice.c port

/// `splice.py` / `splice.c` — the MITM relay. Two daemons (alice,
/// bob), both passive (NO `ConnectTo`). Test process opens two
/// `TcpStream`s. To alice we send `"0 bob 17.7\n"`; to bob we send
/// `"0 alice 17.7\n"`. Each daemon's `id_h` succeeds (both have
/// each other's pubkey). Each sends its ID reply + responder KEX.
/// We consume the ID-reply lines, then proxy raw bytes between them.
///
/// **Why this fails to authenticate** — TWO defense layers:
///
/// 1. **Role asymmetry** (`tinc-sptps::receive_kex:553`): only
///    initiators send SIG on receiving the peer's KEX. Responders
///    wait for the initiator's SIG before sending theirs
///    (`receive_sig` step 3). Both daemons here are RESPONDERS
///    (inbound conns, `outgoing.is_none()`). Both send KEX (in
///    `sptps_start`), both receive the other's KEX via the relay,
///    NEITHER sends SIG. Deadlock. The C splice has the same
///    behavior — `splice.py` only asserts node count, not `BadSig`.
///
/// 2. **Label asymmetry** (`proto.rs::tcp_label`): IF a SIG ever
///    arrived (e.g. the relay also injected a fake one, or one
///    daemon was an initiator via `ConnectTo`), the labels would
///    diverge — alice computes `tcp_label("bob", "alice")`, bob
///    computes `tcp_label("alice", "bob")`. Different transcripts
///    → `BadSig`. This layer is WHY the relay can't just inject SIGs
///    or forward an initiator's bytes: even with real keys on both
///    ends, the labels disagree. THIS test exercises layer 1;
///    `stop.rs::peer_wrong_key_fails_sig` exercises the SIG verify
///    machinery; the label-ordering itself is pinned by
///    `proto::tests::tcp_label_has_trailing_nul`.
///
/// **Assertion**: `dump nodes` on each daemon shows exactly 1
/// REACHABLE node (itself). Neither gained a peer.
///
/// (`load_all_nodes` adds the OTHER name to the graph at setup
/// — each daemon has a hosts/ file for the other for the pubkey.
/// The MITM-defense invariant is reachability: no edge →
/// unreachable.)
#[test]
#[allow(clippy::too_many_lines, clippy::items_after_statements)] // e2e MITM scenario: splitting fragments narrative; helpers scoped here
fn splice_mitm_rejected() {
    use std::net::TcpListener;

    let tmp = tmp("splice");

    // ─── two-daemon setup (no ConnectTo on either side) ────────
    // Same shape as `two_daemons.rs::Node` but inlined: we need
    // BOTH daemons to be PASSIVE (the relay is the initiator).
    // Pre-allocate ports so each daemon can bind a known port,
    // and so the test can connect to it.
    let alloc_port = || {
        TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    };
    struct N {
        confbase: PathBuf,
        pidfile: PathBuf,
        socket: PathBuf,
        port: u16,
        pubkey: [u8; 32],
    }
    let mk = |name: &str, seed: u8| -> N {
        let confbase = tmp.path().join(name);
        N {
            pidfile: tmp.path().join(format!("{name}.pid")),
            socket: tmp.path().join(format!("{name}.socket")),
            port: alloc_port(),
            pubkey: write_config(&confbase, name, seed, ""),
            confbase,
        }
    };
    let alice = mk("alice", 0xAA);
    let bob = mk("bob", 0xBB);

    // Override hosts/SELF with the pre-allocated port (write_config
    // wrote `Port = 0`; we need the port known to the test).
    std::fs::write(
        alice.confbase.join("hosts").join("alice"),
        format!("Port = {}\n", alice.port),
    )
    .unwrap();
    std::fs::write(
        bob.confbase.join("hosts").join("bob"),
        format!("Port = {}\n", bob.port),
    )
    .unwrap();

    // Cross-register pubkeys. Each daemon's `id_h` reads the
    // OTHER's pubkey from `hosts/OTHER`. NO `Address` line —
    // neither daemon initiates. The relay does.
    std::fs::write(
        alice.confbase.join("hosts").join("bob"),
        format!(
            "Ed25519PublicKey = {}\n",
            tinc_crypto::b64::encode(&bob.pubkey)
        ),
    )
    .unwrap();
    std::fs::write(
        bob.confbase.join("hosts").join("alice"),
        format!(
            "Ed25519PublicKey = {}\n",
            tinc_crypto::b64::encode(&alice.pubkey)
        ),
    )
    .unwrap();

    // ─── spawn both ────────────────────────────────────────────
    let mut alice_child = spawn_daemon(&alice.confbase, &alice.pidfile, &alice.socket);
    let mut bob_child = spawn_daemon(&bob.confbase, &bob.pidfile, &bob.socket);

    assert!(wait_for_file(&alice.socket), "alice setup; stderr: {}", {
        let _ = bob_child.kill();
        let _ = bob_child.wait();
        drain_stderr(std::mem::replace(
            &mut alice_child,
            Command::new("true").spawn().unwrap(),
        ))
    });
    assert!(wait_for_file(&bob.socket), "bob setup; stderr: {}", {
        let _ = alice_child.kill();
        let _ = alice_child.wait();
        drain_stderr(std::mem::replace(
            &mut bob_child,
            Command::new("true").spawn().unwrap(),
        ))
    });

    // ─── the splice: connect to both, lie about identity ───────
    // To alice: pretend to be bob. To bob: pretend to be alice.
    // The cross-over.
    let to_alice = TcpStream::connect(("127.0.0.1", alice.port)).expect("connect alice");
    let to_bob = TcpStream::connect(("127.0.0.1", bob.port)).expect("connect bob");
    to_alice
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    to_bob
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();

    writeln!(&to_alice, "0 bob 17.7").unwrap();
    writeln!(&to_bob, "0 alice 17.7").unwrap();

    // ─── consume ID replies (read until '\n') ───────────────────
    // Read byte-by-byte until `\n` — can't use BufReader (it
    // buffers past the `\n` into KEX bytes which
    // we then can't proxy). Same gotcha as `stop.rs:1028`.
    fn read_until_nl(mut s: &TcpStream) -> Vec<u8> {
        let mut out = Vec::new();
        let mut b = [0u8; 1];
        loop {
            // EXACT match for splice.c `:116`: `recv(sock[i], buf, 1, 0)`.
            match s.read(&mut b) {
                Ok(0) => panic!("daemon closed before ID reply; got: {out:?}"),
                Ok(_) => {
                    if b[0] == b'\n' {
                        return out;
                    }
                    out.push(b[0]);
                }
                Err(e) => panic!("read ID reply: {e}"),
            }
        }
    }
    let alice_id = read_until_nl(&to_alice);
    let bob_id = read_until_nl(&to_bob);
    assert_eq!(alice_id, b"0 alice 17.7", "alice ID reply");
    assert_eq!(bob_id, b"0 bob 17.7", "bob ID reply");

    // ─── proxy: spawn two threads, copy bytes each direction ────
    // splice.c `:125-157` is a select() loop. Rust: two threads.
    // `TcpStream` impls Read/Write for `&TcpStream`; clone the
    // streams for the duplex split.
    //
    // The proxy runs until ONE side closes (BadSig → terminate →
    // EOF). `io::copy` returns when the read side hits EOF. The
    // write side then errors (broken pipe) — ignored.
    // splice.c uses select() (level-triggered, no timeout). Our
    // streams have read timeouts; `io::copy` would bail on the
    // first WouldBlock. Hand-roll the loop: keep relaying until
    // BOTH sides EOF or the deadline hits. The handshake is two
    // round trips (KEX then SIG); the threads need to survive the
    // gap between them.
    fn relay(mut from: &TcpStream, mut to: &TcpStream, deadline: Instant) {
        let mut buf = [0u8; 1024];
        while Instant::now() < deadline {
            match from.read(&mut buf) {
                Ok(0) => return, // EOF — daemon closed (BadSig fired)
                Ok(n) => {
                    // Broken pipe (other side already closed) → done.
                    if to.write_all(&buf[..n]).is_err() {
                        return;
                    }
                }
                // WouldBlock = read timeout fired, no data yet.
                // Keep going — the SIG might arrive next.
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => return,
            }
        }
    }

    // Short read timeout so the relay loop checks `deadline`
    // frequently. The 2s timeout above was for the ID-reply read;
    // tighten now.
    to_alice
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    to_bob
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();

    let to_alice_r = to_alice.try_clone().unwrap();
    let to_alice_w = to_alice.try_clone().unwrap();
    let to_bob_r = to_bob.try_clone().unwrap();
    let to_bob_w = to_bob.try_clone().unwrap();

    // 3s deadline: handshake is <100ms on loopback; CI slop.
    let deadline = Instant::now() + Duration::from_secs(3);
    let t_ab = std::thread::spawn(move || relay(&to_alice_r, &to_bob_w, deadline));
    let t_ba = std::thread::spawn(move || relay(&to_bob_r, &to_alice_w, deadline));
    let _ = t_ab.join();
    let _ = t_ba.join();

    // ─── ASSERT: dump nodes on each shows 1 row (self only) ────
    // `splice.py:85-86`. `REQ_DUMP_NODES = 3`. Row format
    // (`gossip.rs::dump_nodes`): `"18 3 NAME ID HOST port PORT ..."`.
    // Terminator: bare `"18 3"`.
    let alice_nodes = Ctl::connect(&alice.socket, &alice.pidfile).dump(3);
    let bob_nodes = Ctl::connect(&bob.socket, &bob.pidfile).dump(3);

    let alice_stderr = drain_stderr(alice_child);
    let bob_stderr = drain_stderr(bob_child);

    // Exactly 1 REACHABLE node each: itself. The splice did NOT
    // add a peer edge. `load_all_nodes` puts the other name in
    // the graph (each has a hosts/ file for the other's pubkey),
    // but unreachable. Status bit 4 (`0x10`) = reachable.
    let reachable = |rows: &[String]| -> Vec<String> {
        rows.iter()
            .filter_map(|r| {
                let body = r.strip_prefix("18 3 ")?;
                let mut t = body.split_whitespace();
                let name = t.next()?;
                // Body tokens: name id host "port" port cipher
                // digest maclen compression options STATUS …
                // Status is token 10; after `next()` consumed
                // name, that's nth(9).
                let status = u32::from_str_radix(t.nth(9)?, 16).ok()?;
                (status & 0x10 != 0).then(|| name.to_owned())
            })
            .collect()
    };
    let alice_reach = reachable(&alice_nodes);
    let bob_reach = reachable(&bob_nodes);
    assert_eq!(
        alice_reach,
        vec!["alice".to_owned()],
        "alice should see only herself reachable; all rows: {alice_nodes:?}\n\
         alice stderr:\n{alice_stderr}\nbob stderr:\n{bob_stderr}"
    );
    assert_eq!(
        bob_reach,
        vec!["bob".to_owned()],
        "bob should see only himself reachable; all rows: {bob_nodes:?}\n\
         alice stderr:\n{alice_stderr}\nbob stderr:\n{bob_stderr}"
    );

    // NEITHER completed. The role-asymmetry deadlock means no SIG
    // ever flowed; both daemons are stuck in `State::Sig` waiting.
    // (See doc comment: this is defense layer 1.)
    assert!(
        !alice_stderr.contains("SPTPS handshake completed"),
        "alice should NOT complete; stderr:\n{alice_stderr}"
    );
    assert!(
        !bob_stderr.contains("SPTPS handshake completed"),
        "bob should NOT complete; stderr:\n{bob_stderr}"
    );
}

// ═══════════════════════════════════════════════════════════════════
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

    // ─── the malformed line ───
    fx.send_record(body);

    // ─── (a) connection dropped: EOF on the TCP stream ───
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

    // ─── (b) process still alive ───
    // Panic in a handler → process abort → try_wait returns Some.
    assert!(
        fx.child.try_wait().unwrap().is_none(),
        "{tag}: daemon DIED on malformed record {body:?}; stderr:\n{}",
        fx.kill_and_stderr()
    );

    // ─── (c) event loop still serving: fresh control dump works ───
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
