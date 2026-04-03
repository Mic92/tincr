//! Two real `tincd` processes. Alice has `ConnectTo = bob`; bob's
//! port is pre-allocated. Proves the full chain: `do_outgoing_
//! connection` → async-connect probe → `finish_connecting` → ID
//! exchange (initiator side) → SPTPS handshake → ACK exchange →
//! `send_everything` → graph(). Then stop alice, prove bob's
//! `terminate` → DEL_EDGE → graph() → unreachable.
//!
//! ## The chicken-and-egg
//!
//! Bob binds port 0 (kernel picks). Alice's `hosts/bob` needs that
//! port. Option (b) from the task brief: pre-allocate a port in the
//! TEST (bind port 0, read it back, close), write it into bob's
//! `hosts/bob` `Port = N`, and into alice's `hosts/bob` `Address =
//! 127.0.0.1 N`. Racy in theory (something else could grab the port
//! between close and bob's bind); works in practice (loopback,
//! high-range port, sub-millisecond gap).
//!
//! ## Timing
//!
//! These tests spinloop with timeouts. The connect+handshake takes
//! <100ms on loopback. Timeouts are 10s for slack on a loaded CI box;
//! the tests typically complete in <1s.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

// Shared with stop.rs but tests can't share helpers across files
// without a `tests/common/mod.rs`. Inline the small bits.

struct TmpGuard(PathBuf);

impl TmpGuard {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "tincd-2d-{}-{:?}",
            tag,
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TmpGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tincd_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tincd"))
}

fn wait_for_file(path: &std::path::Path) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}

fn read_cookie(pidfile: &std::path::Path) -> String {
    let content = std::fs::read_to_string(pidfile).unwrap();
    content
        .split_whitespace()
        .nth(1)
        .expect("pidfile has cookie")
        .to_owned()
}

/// Pre-allocate a port: bind to 0, read it back, drop. The race
/// window is sub-millisecond on loopback.
fn alloc_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind 0");
    l.local_addr().unwrap().port()
}

/// One daemon's config bundle. Seeds are distinct per node so the
/// keys differ.
struct Node {
    name: &'static str,
    seed: [u8; 32],
    confbase: PathBuf,
    pidfile: PathBuf,
    socket: PathBuf,
    /// Pre-allocated TCP port. Written into THIS node's `hosts/NAME`
    /// `Port = N` AND the OTHER node's `hosts/NAME` `Address = 127.0.0.1 N`.
    port: u16,
}

impl Node {
    fn new(tmp: &std::path::Path, name: &'static str, seed_byte: u8) -> Self {
        Self {
            name,
            seed: [seed_byte; 32],
            confbase: tmp.join(name),
            pidfile: tmp.join(format!("{name}.pid")),
            socket: tmp.join(format!("{name}.socket")),
            port: alloc_port(),
        }
    }

    /// Ed25519 pubkey for cross-registration.
    fn pubkey(&self) -> [u8; 32] {
        use tinc_crypto::sign::SigningKey;
        *SigningKey::from_seed(&self.seed).public_key()
    }

    /// Write `tinc.conf` + `hosts/NAME` + `ed25519_key.priv` +
    /// `hosts/OTHER`. `connect_to` adds `ConnectTo = other` to
    /// tinc.conf and `Address = 127.0.0.1 OTHER_PORT` to hosts/OTHER.
    fn write_config(&self, other: &Node, connect_to: bool) {
        use std::os::unix::fs::OpenOptionsExt;
        use tinc_crypto::sign::SigningKey;

        std::fs::create_dir_all(self.confbase.join("hosts")).unwrap();

        // tinc.conf
        let mut tinc_conf = format!(
            "Name = {}\nDeviceType = dummy\nAddressFamily = ipv4\n",
            self.name
        );
        if connect_to {
            tinc_conf.push_str(&format!("ConnectTo = {}\n", other.name));
        }
        // PingTimeout = 1 keeps the test fast (terminate-on-EOF is
        // immediate but the ping sweep also runs).
        tinc_conf.push_str("PingTimeout = 1\n");
        std::fs::write(self.confbase.join("tinc.conf"), tinc_conf).unwrap();

        // hosts/SELF — Port. The pre-allocated port. The daemon
        // re-binds it; the race is benign (high-range, just-freed).
        std::fs::write(
            self.confbase.join("hosts").join(self.name),
            format!("Port = {}\n", self.port),
        )
        .unwrap();

        // hosts/OTHER — pubkey + maybe Address. Both sides need the
        // other's pubkey (id_h reads it). Only the initiator needs
        // Address.
        let other_pub = tinc_crypto::b64::encode(&other.pubkey());
        let mut other_cfg = format!("Ed25519PublicKey = {other_pub}\n");
        if connect_to {
            other_cfg.push_str(&format!("Address = 127.0.0.1 {}\n", other.port));
        }
        std::fs::write(self.confbase.join("hosts").join(other.name), other_cfg).unwrap();

        // Private key.
        let sk = SigningKey::from_seed(&self.seed);
        let f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(self.confbase.join("ed25519_key.priv"))
            .unwrap();
        let mut w = std::io::BufWriter::new(f);
        tinc_conf::write_pem(&mut w, "ED25519 PRIVATE KEY", &sk.to_blob()).unwrap();
    }

    fn spawn(&self) -> Child {
        Command::new(tincd_bin())
            .arg("-c")
            .arg(&self.confbase)
            .arg("--pidfile")
            .arg(&self.pidfile)
            .arg("--socket")
            .arg(&self.socket)
            .env("RUST_LOG", "tincd=info")
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn tincd")
    }
}

/// Control-socket client. Connects, does the greeting, ready for
/// dump RPCs.
struct Ctl {
    r: BufReader<UnixStream>,
    w: UnixStream,
}

impl Ctl {
    fn connect(node: &Node) -> Self {
        let cookie = read_cookie(&node.pidfile);
        let stream = UnixStream::connect(&node.socket).expect("ctl connect");
        let r = BufReader::new(stream.try_clone().unwrap());
        let mut ctl = Self { r, w: stream };
        // Greeting dance.
        writeln!(ctl.w, "0 ^{cookie} 0").unwrap();
        let mut line = String::new();
        ctl.r.read_line(&mut line).unwrap(); // "0 NAME 17.7"
        line.clear();
        ctl.r.read_line(&mut line).unwrap(); // "4 0 PID"
        ctl
    }

    /// Send a dump request, collect rows until terminator.
    fn dump(&mut self, subtype: u8) -> Vec<String> {
        writeln!(self.w, "18 {subtype}").unwrap();
        let term = format!("18 {subtype}");
        let mut rows = Vec::new();
        loop {
            let mut line = String::new();
            self.r.read_line(&mut line).expect("dump row");
            let line = line.trim_end().to_owned();
            if line == term {
                break;
            }
            rows.push(line);
        }
        rows
    }
}

/// Spinloop helper: poll `f` until it returns `Some` or timeout.
fn poll_until<T>(timeout: Duration, mut f: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(v) = f() {
            return v;
        }
        assert!(
            Instant::now() < deadline,
            "poll timed out after {timeout:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Read a child's stderr (after kill+wait).
fn drain_stderr(mut child: Child) -> String {
    let _ = child.kill();
    let out = child.wait_with_output().unwrap();
    String::from_utf8_lossy(&out.stderr).into_owned()
}

// ═══════════════════════════════════════════════════════════════════

/// Two real daemons. Alice has `ConnectTo = bob`. Full handshake →
/// ACK → both reachable. Then stop alice; bob sees the disconnect,
/// edge gone, alice unreachable.
///
/// ## What's proven (per step)
///
/// 1. **`do_outgoing_connection` + async-connect probe**: alice
///    connects to bob's port. The probe succeeds (loopback).
/// 2. **Initiator-side `id_h`**: alice's `finish_connecting` sends
///    ID first; bob's `id_h` fires (responder); bob's ID reply fires
///    alice's `id_h` (with `outgoing.is_some()` → name check + Role::
///    Initiator). Label arg order is swapped; both sides agree.
/// 3. **SPTPS handshake**: both reach HandshakeDone. The trailing-NUL
///    label is the same construction on both sides (still can't catch
///    "both wrong"; the `tcp_label_has_trailing_nul` unit test pins
///    gcc bytes).
/// 4. **ACK exchange + `on_ack`**: both add `myself→peer` edges +
///    synthesized reverses. `conn.active = true`. `dump connections`
///    shows status bit 1 set (`0x2`).
/// 5. **`send_everything` + `send_add_edge(everyone)`**: each sends
///    its forward edge. The `seen.check` dedup makes the double-send
///    (one from `send_everything`, one from broadcast) harmless.
/// 6. **`dump nodes` 2 rows, both reachable**: `run_graph_and_log`
///    fired on both sides. Status bit 4 (reachable) = `0x10`.
/// 7. **Stop alice → bob's `terminate`**: bob's `dump connections`
///    drops to 1 (control only). `dump nodes` shows alice with
///    status `0x0` (unreachable). Proves `terminate` → `del_edge`
///    → `graph()` → `BecameUnreachable`.
#[test]
fn two_daemons_connect_and_reach() {
    let tmp = TmpGuard::new("connect");
    let alice = Node::new(tmp.path(), "alice", 0xAA);
    let bob = Node::new(tmp.path(), "bob", 0xBB);

    // ─── configs: alice initiates, bob accepts ──────────────────
    bob.write_config(&alice, false);
    alice.write_config(&bob, true);

    // ─── spawn bob first ────────────────────────────────────────
    // Bob has no ConnectTo; he just listens. Spawn order matters:
    // if alice starts first, her `do_outgoing_connection` tries to
    // connect before bob is bound → ECONNREFUSED → `retry_outgoing`
    // arms a 5s backoff. Would still work, but slow.
    let mut bob_child = bob.spawn();
    if !wait_for_file(&bob.socket) {
        panic!("bob setup failed; stderr:\n{}", drain_stderr(bob_child));
    }

    let mut alice_child = alice.spawn();
    if !wait_for_file(&alice.socket) {
        let _ = bob_child.kill();
        panic!("alice setup failed; stderr:\n{}", drain_stderr(alice_child));
    }

    // ─── poll: both have an active peer connection ──────────────
    // `dump connections` (subtype 6). Alice should have ONE peer
    // row (bob) with status bit 1 set (`active`, our `c->edge` proxy
    // — `0x2`). Same for bob. The control conn is also a row; it
    // has status `0x200` (bit 9). Filter on bit 1.
    //
    // Row format (`connection.c:168`): `"18 6 NAME HOST port P
    // OPTS_HEX FD STATUS_HEX"`. STATUS_HEX is the LAST field.
    let has_active_peer = |rows: &[String], peer_name: &str| -> bool {
        rows.iter().any(|r| {
            // Body after "18 6 ".
            let Some(body) = r.strip_prefix("18 6 ") else {
                return false;
            };
            // Name is first body token.
            let mut t = body.split_whitespace();
            if t.next() != Some(peer_name) {
                return false;
            }
            // Status is the LAST hex field.
            let status = t.last().and_then(|s| u32::from_str_radix(s, 16).ok());
            status.is_some_and(|s| s & 0x2 != 0)
        })
    };

    let mut alice_ctl = Ctl::connect(&alice);
    let mut bob_ctl = Ctl::connect(&bob);

    poll_until(Duration::from_secs(10), || {
        let a_conns = alice_ctl.dump(6);
        let b_conns = bob_ctl.dump(6);
        if has_active_peer(&a_conns, "bob") && has_active_peer(&b_conns, "alice") {
            Some(())
        } else {
            None
        }
    });

    // ─── dump nodes: 2 rows, both reachable ─────────────────────
    // Row format (`node.c:210`): 23 fields. Status is field 11
    // (`%x`). Bit 4 = reachable = `0x10`.
    let node_reachable = |rows: &[String], name: &str| -> bool {
        rows.iter().any(|r| {
            let Some(body) = r.strip_prefix("18 3 ") else {
                return false;
            };
            let toks: Vec<&str> = body.split_whitespace().collect();
            // toks[0] = name, toks[10] = status hex (after: id,
            // host, "port", port, cipher, digest, maclen, comp,
            // opts, status). That's index 10 — wait, hostname is
            // FUSED ("HOST port PORT") = 3 tokens, so the count
            // shifts. Re-count: name(0), id(1), host(2), "port"(3),
            // port(4), cipher(5), digest(6), maclen(7), comp(8),
            // opts(9), status(10). Index 10.
            toks.first() == Some(&name)
                && toks
                    .get(10)
                    .and_then(|s| u32::from_str_radix(s, 16).ok())
                    .is_some_and(|s| s & 0x10 != 0)
        })
    };

    let a_nodes = alice_ctl.dump(3);
    let b_nodes = bob_ctl.dump(3);
    assert_eq!(a_nodes.len(), 2, "alice nodes: {a_nodes:?}");
    assert_eq!(b_nodes.len(), 2, "bob nodes: {b_nodes:?}");
    assert!(
        node_reachable(&a_nodes, "alice") && node_reachable(&a_nodes, "bob"),
        "alice's view: {a_nodes:?}"
    );
    assert!(
        node_reachable(&b_nodes, "alice") && node_reachable(&b_nodes, "bob"),
        "bob's view: {b_nodes:?}"
    );

    // ─── dump edges: both see myself→peer ───────────────────────
    // Each daemon's `on_ack` added `myself→peer` (with addr) +
    // synthesized reverse (no addr). Then `send_everything` sent
    // the forward edge to the peer. So each side has FOUR edges:
    // its own pair + the peer's forward (received via ADD_EDGE) +
    // ... wait. Let me trace.
    //
    // Alice's graph: alice→bob (on_ack fwd, has addr), bob→alice
    // (on_ack synthesized reverse, no addr). Then bob's send_
    // everything sends bob's `bob→alice` (which has bob's addr) —
    // arrives as ADD_EDGE on alice. Alice's `on_add_edge` does
    // `lookup_edge(bob, alice)` → finds the synthesized reverse →
    // weight/options compare (probably same) → idempotent return
    // (no addr update because the C `:136-148` returns early on
    // weight+options match without updating address).
    //
    // So alice's graph has 2 edges. Same for bob. Both see both
    // directions; the synthesized reverse has no `edge_addrs` entry
    // (chunk-5 STUB) so dumps as "unknown port unknown".
    //
    // Just count rows. The exact addr semantics are pinned by
    // `peer_edge_triggers_reachable` in stop.rs.
    let a_edges = alice_ctl.dump(4);
    let b_edges = bob_ctl.dump(4);
    assert_eq!(a_edges.len(), 2, "alice edges: {a_edges:?}");
    assert_eq!(b_edges.len(), 2, "bob edges: {b_edges:?}");
    // Alice has alice→bob with a real addr (127.0.0.1).
    assert!(
        a_edges
            .iter()
            .any(|r| r.starts_with("18 4 alice bob 127.0.0.1 port ")),
        "alice→bob fwd edge missing: {a_edges:?}"
    );

    // ─── stop alice → bob sees the disconnect ───────────────────
    // Alice exits. Bob's read on the meta connection gets EOF →
    // `FeedResult::Dead` → `terminate` → `del_edge` → `graph()`.
    // Bob's `dump connections` drops to 1 (control only); `dump
    // nodes` shows alice status `0x0` (unreachable).
    drop(alice_ctl); // close alice's ctl conn first
    let _ = alice_child.kill();
    let _ = alice_child.wait();

    poll_until(Duration::from_secs(10), || {
        let b_conns = bob_ctl.dump(6);
        // Only the ctl conn (us) left. No peer with name "alice".
        let has_alice = b_conns.iter().any(|r| {
            r.strip_prefix("18 6 ")
                .and_then(|b| b.split_whitespace().next())
                == Some("alice")
        });
        if !has_alice { Some(()) } else { None }
    });

    // dump nodes: alice still THERE (graph keeps the node), but
    // unreachable (status bit 4 clear).
    let b_nodes_after = bob_ctl.dump(3);
    assert_eq!(b_nodes_after.len(), 2, "bob nodes after: {b_nodes_after:?}");
    assert!(
        !node_reachable(&b_nodes_after, "alice"),
        "alice should be unreachable; bob's view: {b_nodes_after:?}"
    );
    assert!(
        node_reachable(&b_nodes_after, "bob"),
        "bob (myself) should stay reachable: {b_nodes_after:?}"
    );

    // dump edges: bob's terminate did `del_edge` for `bob→alice`
    // AND the synthesized reverse `alice→bob`. Zero edges left.
    let b_edges_after = bob_ctl.dump(4);
    assert_eq!(
        b_edges_after.len(),
        0,
        "edges should be gone; bob's view: {b_edges_after:?}"
    );

    // ─── stderr: bob's reachability transitions ─────────────────
    drop(bob_ctl);
    let bob_stderr = drain_stderr(bob_child);
    assert!(
        bob_stderr.contains("Node alice became reachable"),
        "bob's on_ack → graph() → BecameReachable; stderr:\n{bob_stderr}"
    );
    assert!(
        bob_stderr.contains("Node alice became unreachable"),
        "bob's terminate → del_edge → graph() → BecameUnreachable; stderr:\n{bob_stderr}"
    );
    assert!(
        bob_stderr.contains("Connection with alice") && bob_stderr.contains("activated"),
        "bob's on_ack activation log; stderr:\n{bob_stderr}"
    );
}

/// Retry-backoff: alice's `ConnectTo = bob` but bob ISN'T running.
/// Alice's `do_outgoing_connection` gets ECONNREFUSED → addr cache
/// exhausted (only one Address) → `retry_outgoing` arms the 5s
/// backoff. Then we start bob; alice's RetryOutgoing timer fires →
/// `setup_outgoing_connection` → connects.
///
/// The 5s wait makes this slower than the happy-path test. Tag
/// `#[ignore]` if CI is impatient; un-ignore once confident.
#[test]
fn outgoing_retry_after_refused() {
    let tmp = TmpGuard::new("retry");
    let alice = Node::new(tmp.path(), "alice", 0xA1);
    let bob = Node::new(tmp.path(), "bob", 0xB1);

    bob.write_config(&alice, false);
    alice.write_config(&bob, true);

    // ─── spawn alice FIRST. Bob isn't running. ─────────────────
    let mut alice_child = alice.spawn();
    if !wait_for_file(&alice.socket) {
        panic!("alice setup failed; stderr:\n{}", drain_stderr(alice_child));
    }

    // Alice tries to connect immediately in setup(). ECONNREFUSED
    // → retry_outgoing arms +5s. Prove no active conn yet.
    let mut alice_ctl = Ctl::connect(&alice);
    let conns = alice_ctl.dump(6);
    // Only the ctl conn. No "bob" row.
    assert!(
        !conns.iter().any(|r| r.contains(" bob ")),
        "alice connected before bob is up?? {conns:?}"
    );

    // ─── start bob ─────────────────────────────────────────────
    let mut bob_child = bob.spawn();
    if !wait_for_file(&bob.socket) {
        let _ = alice_child.kill();
        panic!("bob setup failed; stderr:\n{}", drain_stderr(bob_child));
    }

    // ─── wait for alice's retry timer to fire (~5s) ────────────
    // `retry_outgoing` set timeout=5; the next `setup_outgoing_
    // connection` runs in ~5s + tick slop. Poll with a generous
    // timeout (15s) for slow CI.
    let has_active_peer = |rows: &[String], peer_name: &str| -> bool {
        rows.iter().any(|r| {
            let Some(body) = r.strip_prefix("18 6 ") else {
                return false;
            };
            let mut t = body.split_whitespace();
            t.next() == Some(peer_name)
                && t.last()
                    .and_then(|s| u32::from_str_radix(s, 16).ok())
                    .is_some_and(|s| s & 0x2 != 0)
        })
    };

    poll_until(Duration::from_secs(15), || {
        let a_conns = alice_ctl.dump(6);
        if has_active_peer(&a_conns, "bob") {
            Some(())
        } else {
            None
        }
    });

    // ─── stderr: prove the retry path fired ─────────────────────
    drop(alice_ctl);
    let _ = bob_child.kill();
    let _ = bob_child.wait();
    let alice_stderr = drain_stderr(alice_child);
    // C `:416`: "Trying to re-establish outgoing connection in N seconds".
    assert!(
        alice_stderr.contains("Trying to re-establish outgoing connection in 5 seconds"),
        "retry_outgoing log missing; stderr:\n{alice_stderr}"
    );
    // The eventual success.
    assert!(
        alice_stderr.contains("Connected to bob"),
        "finish_connecting log; stderr:\n{alice_stderr}"
    );
    assert!(
        alice_stderr.contains("Connection with bob") && alice_stderr.contains("activated"),
        "alice's on_ack activation; stderr:\n{alice_stderr}"
    );
}
