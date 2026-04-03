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
/// Row format (`connection.c:168`): `"18 6 NAME HOST port P
/// OPTS_HEX FD STATUS_HEX"`. Status bit 1 (`0x2`) is `active`
/// (past ACK — `c->edge != NULL` in C). Control conn has bit 9
/// (`0x200`). Filter rows by name AND active bit.
fn has_active_peer(rows: &[String], peer_name: &str) -> bool {
    rows.iter().any(|r| {
        let Some(body) = r.strip_prefix("18 6 ") else {
            return false;
        };
        let mut t = body.split_whitespace();
        if t.next() != Some(peer_name) {
            return false;
        }
        let status = t.last().and_then(|s| u32::from_str_radix(s, 16).ok());
        status.is_some_and(|s| s & 0x2 != 0)
    })
}

struct Node {
    name: &'static str,
    seed: [u8; 32],
    confbase: PathBuf,
    pidfile: PathBuf,
    socket: PathBuf,
    /// Pre-allocated TCP port. Written into THIS node's `hosts/NAME`
    /// `Port = N` AND the OTHER node's `hosts/NAME` `Address = 127.0.0.1 N`.
    port: u16,
    /// Extra lines appended to `tinc.conf`. `with_conf()` populates.
    extra_conf: String,
}

impl Node {
    /// Extra lines appended to `tinc.conf`. Empty by default.
    /// `ping_pong_keepalive` sets `PingInterval = 1` here.
    fn with_conf(mut self, extra: &str) -> Self {
        self.extra_conf.push_str(extra);
        self
    }

    fn new(tmp: &std::path::Path, name: &'static str, seed_byte: u8) -> Self {
        Self {
            name,
            seed: [seed_byte; 32],
            confbase: tmp.join(name),
            pidfile: tmp.join(format!("{name}.pid")),
            socket: tmp.join(format!("{name}.socket")),
            port: alloc_port(),
            extra_conf: String::new(),
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
    /// `device_fd` adds `DeviceType = fd` and `Device = N` (the test
    /// process's socketpair end, inherited via `Command::pre_exec`-
    /// less fd inheritance — we just don't set CLOEXEC). `subnet`
    /// adds `Subnet = X` to hosts/SELF.
    fn write_config_with(
        &self,
        other: &Node,
        connect_to: bool,
        device_fd: Option<i32>,
        subnet: Option<&str>,
    ) {
        use std::os::unix::fs::OpenOptionsExt;
        use tinc_crypto::sign::SigningKey;

        std::fs::create_dir_all(self.confbase.join("hosts")).unwrap();

        // tinc.conf
        let mut tinc_conf = format!("Name = {}\nAddressFamily = ipv4\n", self.name);
        if let Some(fd) = device_fd {
            tinc_conf.push_str(&format!("DeviceType = fd\nDevice = {fd}\n"));
        } else {
            tinc_conf.push_str("DeviceType = dummy\n");
        }
        if connect_to {
            tinc_conf.push_str(&format!("ConnectTo = {}\n", other.name));
        }
        // `extra_conf` (e.g. `Compression = N`) before the default
        // PingTimeout: first-occurrence-wins in tinc-conf lookup.
        tinc_conf.push_str(&self.extra_conf);
        tinc_conf.push_str("PingTimeout = 1\n");
        std::fs::write(self.confbase.join("tinc.conf"), tinc_conf).unwrap();

        // hosts/SELF — Port + maybe Subnet.
        let mut self_cfg = format!("Port = {}\n", self.port);
        if let Some(s) = subnet {
            self_cfg.push_str(&format!("Subnet = {s}\n"));
        }
        std::fs::write(self.confbase.join("hosts").join(self.name), self_cfg).unwrap();

        // hosts/OTHER — pubkey + maybe Address.
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
        // `extra_conf` FIRST: tinc-conf's `lookup().next()` is
        // first-occurrence-wins; tests that set PingTimeout via
        // `with_conf()` need to shadow the default below.
        tinc_conf.push_str(&self.extra_conf);
        // PingTimeout = 1 keeps the test fast (terminate-on-EOF is
        // immediate but the ping sweep also runs). Shadowed by
        // `extra_conf` if present.
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

    /// Spawn with an inherited fd. Clears CLOEXEC on `fd` so the
    /// child sees it; the child's `FdTun::open(Inherited(fd))`
    /// wraps it. The TEST process keeps the other socketpair end.
    fn spawn_with_fd(&self, fd: i32) -> Child {
        // Clear CLOEXEC so the fd survives `exec()`. Rust's `Command::
        // spawn` doesn't close inherited fds (only stdin/out/err are
        // managed). C tincd's `Device = N` mode (`fd_device.c:163`)
        // assumes the parent did this.
        // SAFETY: `fcntl(F_SETFD, 0)` clears the CLOEXEC bit. The fd
        // is valid (just from socketpair).
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFD);
            assert!(flags >= 0, "fcntl GETFD");
            assert_eq!(libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC), 0);
        }
        Command::new(tincd_bin())
            .arg("-c")
            .arg(&self.confbase)
            .arg("--pidfile")
            .arg(&self.pidfile)
            .arg("--socket")
            .arg(&self.socket)
            .env("RUST_LOG", "tincd=debug")
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn tincd")
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
    // PingTimeout=3 (not the default `write_config` PingTimeout=1):
    // alice's connect arrives mid-`turn()` on bob's side, so bob's
    // `Connection::new_meta` stamps `last_ping_time` from the
    // CACHED `timers.now()` — up to ~1s stale (the sweep ticks at
    // 1s). With PingTimeout=1 the conn is born already-stale and
    // the next sweep reaps it before `id_h` even runs. The C has
    // the same race (`net_socket.c:764` uses the cached global
    // `now`); PingTimeout=1 is just an unrealistic config. 3s
    // gives the handshake room.
    let alice = Node::new(tmp.path(), "alice", 0xA1).with_conf("PingTimeout = 3\n");
    let bob = Node::new(tmp.path(), "bob", 0xB1).with_conf("PingTimeout = 3\n");

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

/// **THE FIRST PACKET.** End-to-end: alice's TUN → bob's TUN.
///
/// Full chain: `IoWhat::Device` → `route()` → `Forward{to: bob}`
/// → `send_sptps_packet` → (no validkey yet) `send_req_key` →
/// REQ_KEY over the meta-conn SPTPS → bob's `on_req_key` →
/// responder `Sptps::start` → ANS_KEY back → alice's `on_ans_key`
/// → `HandshakeDone` → validkey set. Then alice's NEXT TUN read →
/// `send_sptps_packet` → `sptps.send_record(0, ip_bytes)` →
/// `Output::Wire` → `send_sptps_data` UDP branch → `[nullid][src]
/// [ct]` → `sendto(bob_udp)`. Bob's `on_udp_recv` → strip prefix →
/// `lookup_node_id(src)` = alice → `sptps.receive(ct)` → `Output::
/// Record{type=0, ip_bytes}` → `receive_sptps_record` → re-prepend
/// ethertype → `route()` → `Forward{to: myself}` → `device.write`.
///
/// ## The device rig
///
/// `socketpair(AF_UNIX, SOCK_SEQPACKET)` for each daemon. SEQPACKET
/// gives datagram semantics (one `read()` = one packet, like a real
/// TUN fd) over a connection-oriented unix socket. The test holds
/// one end; the daemon's `FdTun` wraps the other. `FdTun::read()`
/// does the `+14` ethernet-header synthesis from the IP version
/// nibble, so we write RAW IP bytes and the daemon's `route()` sees
/// a proper ethernet frame.
///
/// `O_NONBLOCK` on the daemon's end: `FdTun` doesn't set it; the
/// daemon's `on_device_read` loops until `WouldBlock`, so blocking
/// fds would hang the loop. We set it in the test before passing the
/// fd in. (C tincd's `linux/device.c:63` does `O_NONBLOCK` via the
/// `ioctl` flow; `fd_device.c` doesn't — the Java parent is supposed
/// to. We're the Java parent.)
///
/// ## The first packet is dropped
///
/// `send_sptps_packet:684` (`if(!validkey) return`). The C buffers
/// nothing; the first packet kicks `send_req_key` and is dropped. We
/// wait for `validkey` (poll `dump nodes` for status bit 1), THEN
/// send the packet that actually crosses.
#[test]
fn first_packet_across_tunnel() {
    let tmp = TmpGuard::new("first-pkt");
    let alice = Node::new(tmp.path(), "alice", 0xA7);
    let bob = Node::new(tmp.path(), "bob", 0xB7);

    // ─── socketpairs: one per daemon ────────────────────────────
    // [0] = test end (we read/write IP packets), [1] = daemon end
    // (FdTun wraps it). SOCK_SEQPACKET for datagram boundaries.
    let alice_pair = sockpair_seqpacket();
    let bob_pair = sockpair_seqpacket();

    // Daemon ends need O_NONBLOCK (on_device_read loops to EAGAIN).
    // Test ends too (read_fd_nb polls).
    for &fd in &alice_pair {
        set_nonblocking(fd);
    }
    for &fd in &bob_pair {
        set_nonblocking(fd);
    }

    // ─── configs: subnets pin route() decisions ────────────────
    // alice owns 10.0.0.1/32; bob owns 10.0.0.2/32. A packet to
    // 10.0.0.2 routes Forward{to: bob} on alice's side, then
    // Forward{to: myself} on bob's side.
    bob.write_config_with(&alice, false, Some(bob_pair[1]), Some("10.0.0.2/32"));
    alice.write_config_with(&bob, true, Some(alice_pair[1]), Some("10.0.0.1/32"));

    // ─── spawn ──────────────────────────────────────────────────
    let mut bob_child = bob.spawn_with_fd(bob_pair[1]);
    if !wait_for_file(&bob.socket) {
        panic!("bob setup failed; stderr:\n{}", drain_stderr(bob_child));
    }
    // Close OUR copy of bob's daemon-end fd. The child has its own
    // (dup'd by fork). If we keep ours open, bob's read() never
    // sees EOF and the test process leaks an fd. Same for alice.
    unsafe { libc::close(bob_pair[1]) };

    let alice_child = alice.spawn_with_fd(alice_pair[1]);
    if !wait_for_file(&alice.socket) {
        let _ = bob_child.kill();
        panic!("alice setup failed; stderr:\n{}", drain_stderr(alice_child));
    }
    unsafe { libc::close(alice_pair[1]) };

    // ─── wait for meta-conn handshake (chunk-6 milestone) ────────
    let mut alice_ctl = Ctl::connect(&alice);
    let mut bob_ctl = Ctl::connect(&bob);

    // Status bit 4 (reachable) = both daemons completed ACK +
    // graph(). `dump nodes` row format: status is body token 10.
    let node_status = |rows: &[String], name: &str| -> Option<u32> {
        rows.iter().find_map(|r| {
            let body = r.strip_prefix("18 3 ")?;
            let toks: Vec<&str> = body.split_whitespace().collect();
            if toks.first() != Some(&name) {
                return None;
            }
            u32::from_str_radix(toks.get(10)?, 16).ok()
        })
    };

    poll_until(Duration::from_secs(10), || {
        let a = alice_ctl.dump(3);
        let b = bob_ctl.dump(3);
        let a_ok = node_status(&a, "bob").is_some_and(|s| s & 0x10 != 0);
        let b_ok = node_status(&b, "alice").is_some_and(|s| s & 0x10 != 0);
        if a_ok && b_ok { Some(()) } else { None }
    });

    // ─── kick the per-tunnel handshake ──────────────────────────
    // Send one packet to alice's TUN. `route()` says Forward{to:
    // bob}; `send_sptps_packet` sees `!validkey` and kicks
    // `send_req_key`. The packet is DROPPED (C `:686`).
    //
    // Packet shape for FdTun: RAW IPv4 bytes (no ether header,
    // no tun_pi). `FdTun::read` writes them at `+14` and sets
    // ethertype from byte-0 nibble. dst at IP header offset 16.
    let kick_pkt = mk_ipv4_pkt([10, 0, 0, 1], [10, 0, 0, 2], b"kick");
    write_fd(alice_pair[0], &kick_pkt);

    // ─── wait for validkey ──────────────────────────────────────
    // Status bit 1 (validkey) = per-tunnel SPTPS handshake done.
    // BOTH sides need it (bob is responder; his `HandshakeDone`
    // fires when he gets alice's SIG via ANS_KEY). The handshake
    // is 3 round-trips over the meta-conn SPTPS; loopback is
    // sub-millisecond per RTT.
    // catch_unwind: on timeout, dump BOTH daemons' stderr. Without
    // this, the test panics with "poll timed out" and the captured
    // stderr is lost (Child::stderr is piped, never read).
    let validkey_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        poll_until(Duration::from_secs(5), || {
            let a = alice_ctl.dump(3);
            let b = bob_ctl.dump(3);
            let a_ok = node_status(&a, "bob").is_some_and(|s| s & 0x02 != 0);
            let b_ok = node_status(&b, "alice").is_some_and(|s| s & 0x02 != 0);
            if a_ok && b_ok { Some(()) } else { None }
        });
    }));
    if validkey_result.is_err() {
        let _ = bob_child.kill();
        let bs = drain_stderr(bob_child);
        let asd = drain_stderr(alice_child);
        panic!("validkey timed out;\n=== alice ===\n{asd}\n=== bob ===\n{bs}");
    }

    // ─── THE PACKET ─────────────────────────────────────────────
    // Now validkey is set. Send a packet; it crosses.
    let payload = b"hello from alice";
    let ip_pkt = mk_ipv4_pkt([10, 0, 0, 1], [10, 0, 0, 2], payload);
    write_fd(alice_pair[0], &ip_pkt);

    // Read from bob's TUN. `FdTun::write` strips the 14-byte
    // ether header (writes `data[14..]`); we get RAW IP bytes.
    let recv = poll_until(Duration::from_secs(5), || read_fd_nb(bob_pair[0]));

    // The IP packet round-trips byte-exact (the 14-byte ether
    // header is added by alice's FdTun::read, stripped by
    // alice's `send_sptps_packet`, re-added by bob's `receive_
    // sptps_record`, stripped by bob's `FdTun::write`).
    assert_eq!(
        recv,
        ip_pkt,
        "packet body mismatch; sent {} bytes, got {} bytes",
        ip_pkt.len(),
        recv.len()
    );
    // The payload is at the IP-header offset (20 bytes).
    assert_eq!(&recv[20..], payload);

    // ─── traffic counters bumped ────────────────────────────────
    // alice: out_packets/out_bytes for bob ≥ 1. bob: in_packets/
    // in_bytes for alice ≥ 1. The kick packet also counts (it was
    // counted at `send_packet:1582` BEFORE the validkey gate at
    // `send_sptps_packet:684`). Row tail: `... in_p in_b out_p out_b`.
    let node_traffic = |rows: &[String], name: &str| -> Option<(u64, u64, u64, u64)> {
        rows.iter().find_map(|r| {
            let body = r.strip_prefix("18 3 ")?;
            let toks: Vec<&str> = body.split_whitespace().collect();
            if toks.first() != Some(&name) {
                return None;
            }
            let n = toks.len();
            Some((
                toks[n - 4].parse().ok()?,
                toks[n - 3].parse().ok()?,
                toks[n - 2].parse().ok()?,
                toks[n - 1].parse().ok()?,
            ))
        })
    };
    let a_nodes = alice_ctl.dump(3);
    let b_nodes = bob_ctl.dump(3);
    let (_, _, a_out_p, a_out_b) = node_traffic(&a_nodes, "bob").expect("alice's bob row");
    let (b_in_p, b_in_b, _, _) = node_traffic(&b_nodes, "alice").expect("bob's alice row");
    assert!(
        a_out_p >= 1 && a_out_b >= ip_pkt.len() as u64,
        "alice out counters: {a_out_p}/{a_out_b}; nodes: {a_nodes:?}"
    );
    assert!(
        b_in_p >= 1 && b_in_b >= ip_pkt.len() as u64,
        "bob in counters: {b_in_p}/{b_in_b}; nodes: {b_nodes:?}"
    );

    // ─── udp_confirmed: bob received a valid UDP packet from
    // alice; status bit 7 should be set. (Alice's bit might not
    // be: bob hasn't sent anything BACK over UDP yet.)
    let b_status = node_status(&b_nodes, "alice").unwrap();
    assert!(
        b_status & 0x80 != 0,
        "bob's udp_confirmed for alice; status={b_status:x}"
    );

    // ─── stderr: the SPTPS-key-exchange-successful log ──────────
    drop(alice_ctl);
    drop(bob_ctl);
    unsafe { libc::close(alice_pair[0]) };
    unsafe { libc::close(bob_pair[0]) };
    let _ = bob_child.kill();
    let bob_stderr = drain_stderr(bob_child);
    let alice_stderr = drain_stderr(alice_child);
    assert!(
        alice_stderr.contains("SPTPS key exchange with bob successful"),
        "alice's per-tunnel HandshakeDone; stderr:\n{alice_stderr}"
    );
    assert!(
        bob_stderr.contains("SPTPS key exchange with alice successful"),
        "bob's per-tunnel HandshakeDone; stderr:\n{bob_stderr}"
    );
}

// ─── first_packet test plumbing ────────────────────────────────────────────────────────────

/// `socketpair(AF_UNIX, SOCK_SEQPACKET)`. SEQPACKET = datagram
/// boundaries (one read = one packet) on a connection-oriented unix
/// socket. Exactly the semantics a real TUN fd has.
fn sockpair_seqpacket() -> [i32; 2] {
    let mut fds = [0i32; 2];
    // SAFETY: `socketpair` writes 2 ints. AF_UNIX/SOCK_SEQPACKET is
    // standard on Linux.
    let ret = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0, fds.as_mut_ptr()) };
    assert_eq!(ret, 0, "socketpair: {}", std::io::Error::last_os_error());
    fds
}

fn set_nonblocking(fd: i32) {
    // SAFETY: fcntl on a valid fd.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        assert!(flags >= 0);
        assert_eq!(libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK), 0);
    }
}

fn write_fd(fd: i32, buf: &[u8]) {
    // SAFETY: write(2) on a valid fd. SEQPACKET is one-shot (no
    // short writes for in-flight datagrams).
    let ret = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
    assert_eq!(
        ret as usize,
        buf.len(),
        "write fd={fd}: {}",
        std::io::Error::last_os_error()
    );
}

/// Non-blocking read; `None` on EAGAIN. The poll loop wraps this.
fn read_fd_nb(fd: i32) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 2048];
    // SAFETY: read(2) on a valid fd into our buffer.
    let ret = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if ret < 0 {
        let e = std::io::Error::last_os_error();
        if e.kind() == std::io::ErrorKind::WouldBlock {
            return None;
        }
        panic!("read fd={fd}: {e}");
    }
    if ret == 0 {
        panic!("read fd={fd}: EOF (peer closed)");
    }
    buf.truncate(ret as usize);
    Some(buf)
}

/// Minimal IPv4 packet: 20-byte header + payload. Only the fields
/// `route_ipv4` reads (version nibble for FdTun's ethertype synth,
/// dst addr for the subnet lookup). Checksum/len are filled but
/// nothing checks them (`route_ipv4` doesn't, and the packet never
/// hits a kernel IP stack).
fn mk_ipv4_pkt(src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let total_len = (20 + payload.len()) as u16;
    let mut p = Vec::with_capacity(20 + payload.len());
    p.push(0x45); // version=4, IHL=5
    p.push(0); // DSCP/ECN
    p.extend_from_slice(&total_len.to_be_bytes());
    p.extend_from_slice(&[0, 0]); // ident
    p.extend_from_slice(&[0, 0]); // flags+fragoff
    p.push(64); // TTL
    p.push(17); // proto (UDP, arbitrary)
    p.extend_from_slice(&[0, 0]); // checksum (don't care)
    p.extend_from_slice(&src);
    p.extend_from_slice(&dst);
    p.extend_from_slice(payload);
    p
}

// ═══════════════════════════════════════════════════════════════════

/// Per-tunnel compression negotiation. alice asks for zlib-6, bob
/// for LZ4. Each advertises its level in ANS_KEY (`net_packet.c:
/// 996`); the peer stores it as `outcompression` (`protocol_key.c:
/// 545`) and compresses TOWARDS them at that level. The compressed
/// SPTPS record carries `PKT_COMPRESSED`; receiver decompresses at
/// `incompression` (its OWN level, copied at handshake).
///
/// Asymmetry is the point: alice→bob traffic is LZ4-compressed (bob
/// asked for 12); bob→alice is zlib-6 (alice asked for 6). Proves
/// the per-tunnel level is read from the right field on each path.
///
/// Compressible payload: 200 bytes of zeros. Both zlib and LZ4
/// crush this; `compressed.len() < payload.len()` triggers and
/// `PKT_COMPRESSED` is set. With an incompressible payload (random
/// bytes), compression backs off to raw and the bit stays clear —
/// also valid, but doesn't exercise the decompress path. The KAT in
/// `compress.rs` proves codec correctness; THIS proves negotiation
/// + bit handling + per-tunnel level dispatch.
#[test]
fn compression_roundtrip() {
    let tmp = TmpGuard::new("compress");
    // Compression is HOST-tagged but our `setup` reads from the
    // merged config tree (host file is merged into tinc.conf at
    // setup). Put it in tinc.conf via `with_conf`.
    let alice = Node::new(tmp.path(), "alice", 0xAC).with_conf("Compression = 6\n");
    let bob = Node::new(tmp.path(), "bob", 0xBC).with_conf("Compression = 12\n");

    let alice_pair = sockpair_seqpacket();
    let bob_pair = sockpair_seqpacket();
    for &fd in &alice_pair {
        set_nonblocking(fd);
    }
    for &fd in &bob_pair {
        set_nonblocking(fd);
    }

    bob.write_config_with(&alice, false, Some(bob_pair[1]), Some("10.0.0.2/32"));
    alice.write_config_with(&bob, true, Some(alice_pair[1]), Some("10.0.0.1/32"));

    let mut bob_child = bob.spawn_with_fd(bob_pair[1]);
    if !wait_for_file(&bob.socket) {
        panic!("bob setup failed; stderr:\n{}", drain_stderr(bob_child));
    }
    unsafe { libc::close(bob_pair[1]) };

    let alice_child = alice.spawn_with_fd(alice_pair[1]);
    if !wait_for_file(&alice.socket) {
        let _ = bob_child.kill();
        panic!("alice setup failed; stderr:\n{}", drain_stderr(alice_child));
    }
    unsafe { libc::close(alice_pair[1]) };

    let mut alice_ctl = Ctl::connect(&alice);
    let mut bob_ctl = Ctl::connect(&bob);

    // ─── reachable + validkey, same dance as first_packet ────────
    let node_status = |rows: &[String], name: &str| -> Option<u32> {
        rows.iter().find_map(|r| {
            let body = r.strip_prefix("18 3 ")?;
            let toks: Vec<&str> = body.split_whitespace().collect();
            if toks.first() != Some(&name) {
                return None;
            }
            u32::from_str_radix(toks.get(10)?, 16).ok()
        })
    };
    poll_until(Duration::from_secs(10), || {
        let a = alice_ctl.dump(3);
        let b = bob_ctl.dump(3);
        let a_ok = node_status(&a, "bob").is_some_and(|s| s & 0x10 != 0);
        let b_ok = node_status(&b, "alice").is_some_and(|s| s & 0x10 != 0);
        if a_ok && b_ok { Some(()) } else { None }
    });

    let kick_pkt = mk_ipv4_pkt([10, 0, 0, 1], [10, 0, 0, 2], b"kick");
    write_fd(alice_pair[0], &kick_pkt);

    let validkey_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        poll_until(Duration::from_secs(5), || {
            let a = alice_ctl.dump(3);
            let b = bob_ctl.dump(3);
            let a_ok = node_status(&a, "bob").is_some_and(|s| s & 0x02 != 0);
            let b_ok = node_status(&b, "alice").is_some_and(|s| s & 0x02 != 0);
            if a_ok && b_ok { Some(()) } else { None }
        });
    }));
    if validkey_result.is_err() {
        let _ = bob_child.kill();
        let bs = drain_stderr(bob_child);
        let asd = drain_stderr(alice_child);
        panic!("validkey timed out;\n=== alice ===\n{asd}\n=== bob ===\n{bs}");
    }

    // ─── negotiated levels in dump_nodes ──────────────────────────
    // The `compression` column (body token 8) is `n->outcompression`
    // — the level the PEER asked for. alice's row for bob = 12 (LZ4,
    // bob's `Compression = 12`); bob's row for alice = 6 (zlib).
    let node_compression = |rows: &[String], name: &str| -> Option<u8> {
        rows.iter().find_map(|r| {
            let body = r.strip_prefix("18 3 ")?;
            let toks: Vec<&str> = body.split_whitespace().collect();
            if toks.first() != Some(&name) {
                return None;
            }
            // Body tokens: name id host "port" port cipher digest
            // maclen compression(idx 8) options status ...
            toks.get(8)?.parse().ok()
        })
    };
    let a_nodes = alice_ctl.dump(3);
    let b_nodes = bob_ctl.dump(3);
    assert_eq!(
        node_compression(&a_nodes, "bob"),
        Some(12),
        "alice should compress towards bob at LZ4 (bob's ask); rows:\n{a_nodes:#?}"
    );
    assert_eq!(
        node_compression(&b_nodes, "alice"),
        Some(6),
        "bob should compress towards alice at zlib-6; rows:\n{b_nodes:#?}"
    );

    // ─── alice → bob: LZ4-compressed on the wire ──────────────────
    // 200 zeros: LZ4 crushes to ~20 bytes. `compressed.len() <
    // origlen` triggers; PKT_COMPRESSED is set; bob decompresses
    // at incompression=12.
    let payload = vec![0u8; 200];
    let ip_pkt = mk_ipv4_pkt([10, 0, 0, 1], [10, 0, 0, 2], &payload);
    write_fd(alice_pair[0], &ip_pkt);

    let recv = poll_until(Duration::from_secs(5), || read_fd_nb(bob_pair[0]));
    assert_eq!(
        recv,
        ip_pkt,
        "LZ4 round-trip mismatch; sent {} bytes, got {} bytes",
        ip_pkt.len(),
        recv.len()
    );

    // ─── bob → alice: zlib-6 compressed on the wire ───────────────
    // The reverse direction. Bob compresses at 6 (alice's ask);
    // alice decompresses at incompression=6.
    let ip_pkt2 = mk_ipv4_pkt([10, 0, 0, 2], [10, 0, 0, 1], &payload);
    write_fd(bob_pair[0], &ip_pkt2);

    let recv2 = poll_until(Duration::from_secs(5), || read_fd_nb(alice_pair[0]));
    assert_eq!(
        recv2,
        ip_pkt2,
        "zlib round-trip mismatch; sent {} bytes, got {} bytes",
        ip_pkt2.len(),
        recv2.len()
    );

    drop(alice_ctl);
    drop(bob_ctl);
    unsafe { libc::close(alice_pair[0]) };
    unsafe { libc::close(bob_pair[0]) };
    let _ = bob_child.kill();
    let _ = drain_stderr(bob_child);
    let _ = drain_stderr(alice_child);
}

// ═══════════════════════════════════════════════════════════════════

/// PING/PONG keepalive. `PingInterval=1` so the sweep sends PING
/// every second; the peer's `ping_h` replies PONG; `pong_h` clears
/// the bit; the conn survives `PingTimeout`.
///
/// Then SIGSTOP one daemon. The other side's PING goes unanswered
/// (the stopped process doesn't `recv()`). After `PingTimeout`, the
/// `pinged` bit is still set → "didn't respond to PING" → terminate
/// (`net.c:253-257`). SIGCONT → the stopped daemon wakes, sees EOF
/// on its socket (the OTHER side closed it), terminates, and its
/// outgoing retry kicks in. `PingTimeout=3` gives the stopped
/// daemon room to NOT trigger its OWN sweep on wake (it was asleep
/// for ~5s but `last_periodic_run_time` updates on the first tick
/// post-wake — wait, no, the suspend detector triggers if the GAP
/// is >60s. SIGSTOP for 5s doesn't trigger it).
///
/// Exercises `protocol_misc.c:47-76` (PING/PONG) and the `:253-
/// 257` pinged-but-no-pong terminate path.
#[test]
fn ping_pong_keepalive() {
    let tmp = TmpGuard::new("pingpong");
    // PingInterval=1 makes PING observable in a 5s window.
    // PingTimeout=3 gives the SIGSTOP phase room: the stopped
    // daemon is paused for ~5s, the OTHER daemon's sweep needs
    // pingtimeout (3s) to elapse after the unanswered PING.
    let alice =
        Node::new(tmp.path(), "alice", 0xA8).with_conf("PingInterval = 1\nPingTimeout = 3\n");
    let bob = Node::new(tmp.path(), "bob", 0xB8).with_conf("PingInterval = 1\nPingTimeout = 3\n");

    bob.write_config(&alice, false);
    alice.write_config(&bob, true);

    let mut bob_child = bob.spawn();
    if !wait_for_file(&bob.socket) {
        panic!("bob setup failed; stderr:\n{}", drain_stderr(bob_child));
    }
    let mut alice_child = alice.spawn();
    if !wait_for_file(&alice.socket) {
        let _ = bob_child.kill();
        panic!("alice setup failed; stderr:\n{}", drain_stderr(alice_child));
    }

    let mut alice_ctl = Ctl::connect(&alice);
    let mut bob_ctl = Ctl::connect(&bob);

    // ─── wait for ACK on both sides ─────────────────────────────
    poll_until(Duration::from_secs(10), || {
        let a = alice_ctl.dump(6);
        let b = bob_ctl.dump(6);
        (has_active_peer(&a, "bob") && has_active_peer(&b, "alice")).then_some(())
    });

    // ─── keepalive phase: hold for 5s, conn must survive ──────
    // PingInterval=1, PingTimeout=3. Five 1s ticks. Each tick
    // sends PING; the PONG arrives <100ms later (loopback); the
    // bit clears before the next sweep checks it. If PONG handling
    // is broken, the conn dies at ~tick 3.
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(500));
        let b = bob_ctl.dump(6);
        assert!(
            has_active_peer(&b, "alice"),
            "conn died during keepalive; PONG not clearing pinged bit?"
        );
    }

    // ─── SIGSTOP alice; bob's PING goes unanswered ─────────────
    // Bob sends PING, alice doesn't `recv()`, `pingtimeout` (3s)
    // elapses with `pinged` still set → "didn't respond to PING"
    // → terminate. The TCP socket stays open (kernel buffers the
    // PING bytes until alice wakes); only the application-layer
    // timeout fires.
    // SAFETY: kill() with SIGSTOP on a valid pid. The child is
    // alive (we just polled it).
    let alice_pid = alice_child.id() as libc::pid_t;
    assert_eq!(unsafe { libc::kill(alice_pid, libc::SIGSTOP) }, 0);

    // PingTimeout=3 + 2s slop. Bob's sweep needs: one tick to
    // notice idle (>pinginterval since last_ping_time) and send
    // PING, then >pingtimeout for the stale check to fire.
    poll_until(Duration::from_secs(10), || {
        let b = bob_ctl.dump(6);
        (!has_active_peer(&b, "alice")).then_some(())
    });

    // ─── SIGCONT alice; she sees EOF, retries, reconnects ──────
    // Alice wakes. Bob already closed his side; alice's next read
    // sees EOF → terminate → outgoing retry (`net.c:155-161`).
    // The retry connects; the handshake runs; ACK; both active
    // again. The retry is immediate (`timeout = 0` after a conn
    // that reached ACK).
    assert_eq!(unsafe { libc::kill(alice_pid, libc::SIGCONT) }, 0);

    poll_until(Duration::from_secs(10), || {
        let b = bob_ctl.dump(6);
        has_active_peer(&b, "alice").then_some(())
    });

    let _ = alice_child.kill();
    let _ = alice_child.wait();
    let _ = bob_child.kill();
    let _ = bob_child.wait();
}

/// `tinc-up` runs at setup. Write a script that touches a marker;
/// spawn the daemon; assert the marker exists. Also covers the
/// `INTERFACE` env var (`script.c:125`): the script reads it and
/// echoes into the marker.
///
/// Shebang required: `Command::status` is direct `execve()`, not
/// `sh -c`. A shebang-less script fails `ENOEXEC`. Doc'd in
/// `script.rs` module comment.
#[test]
fn tinc_up_runs() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = TmpGuard::new("tincup");
    let alice = Node::new(tmp.path(), "alice", 0xA9);
    let bob = Node::new(tmp.path(), "bob", 0xB9);

    bob.write_config(&alice, false);
    alice.write_config(&bob, false);

    let marker = tmp.path().join("tinc-up-ran");
    // `#!/bin/sh` shebang. The C uses `system()` (= `sh -c`) which
    // would also work without; we don't (see script.rs doc).
    // `INTERFACE` for `DeviceType=dummy` is `"dummy"` (`tinc-
    // device::Dummy::iface`).
    let script = format!(
        "#!/bin/sh\necho \"iface=$INTERFACE name=$NAME\" > '{}'\n",
        marker.display()
    );
    let script_path = alice.confbase.join("tinc-up");
    std::fs::write(&script_path, script).unwrap();
    let mut perm = std::fs::metadata(&script_path).unwrap().permissions();
    perm.set_mode(0o755);
    std::fs::set_permissions(&script_path, perm).unwrap();

    let mut alice_child = alice.spawn();
    if !wait_for_file(&alice.socket) {
        panic!("alice setup failed; stderr:\n{}", drain_stderr(alice_child));
    }

    // tinc-up runs synchronously inside `setup()`, BEFORE the
    // socket is created. `wait_for_file` already proved setup
    // returned; the marker must exist by now.
    assert!(marker.exists(), "tinc-up didn't run");
    let got = std::fs::read_to_string(&marker).unwrap();
    assert_eq!(got.trim(), "iface=dummy name=alice");

    let _ = alice_child.kill();
    let _ = alice_child.wait();
}
