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

    /// Three-node config: write `tinc.conf` with `ConnectTo` for
    /// each name in `connect_to`, write `hosts/PEER` for each
    /// `peers` entry (pubkey + maybe Address), write `hosts/SELF`
    /// with Port + Subnet. `device_fd`: same as `write_config_with`.
    ///
    /// Why a separate fn instead of generalizing `write_config_with`:
    /// the two-node case is the dominant test shape (8 callers);
    /// keeping it simple preserves readability there.
    fn write_config_multi(
        &self,
        peers: &[&Node],
        connect_to: &[&str],
        device_fd: Option<i32>,
        subnet: Option<&str>,
    ) {
        use std::os::unix::fs::OpenOptionsExt;
        use tinc_crypto::sign::SigningKey;

        std::fs::create_dir_all(self.confbase.join("hosts")).unwrap();

        let mut tinc_conf = format!("Name = {}\nAddressFamily = ipv4\n", self.name);
        if let Some(fd) = device_fd {
            tinc_conf.push_str(&format!("DeviceType = fd\nDevice = {fd}\n"));
        } else {
            tinc_conf.push_str("DeviceType = dummy\n");
        }
        for ct in connect_to {
            tinc_conf.push_str(&format!("ConnectTo = {ct}\n"));
        }
        tinc_conf.push_str(&self.extra_conf);
        tinc_conf.push_str("PingTimeout = 1\n");
        std::fs::write(self.confbase.join("tinc.conf"), tinc_conf).unwrap();

        let mut self_cfg = format!("Port = {}\n", self.port);
        if let Some(s) = subnet {
            self_cfg.push_str(&format!("Subnet = {s}\n"));
        }
        std::fs::write(self.confbase.join("hosts").join(self.name), self_cfg).unwrap();

        for peer in peers {
            let pk = tinc_crypto::b64::encode(&peer.pubkey());
            let mut cfg = format!("Ed25519PublicKey = {pk}\n");
            // Address only for ConnectTo targets.
            if connect_to.contains(&peer.name) {
                cfg.push_str(&format!("Address = 127.0.0.1 {}\n", peer.port));
            }
            // The peer's Subnet must be in OUR copy of hosts/PEER
            // so `route()` knows to forward to them. The C reads
            // it from disk at ADD_SUBNET-gossip time? No — the C
            // gets it from the wire (ADD_SUBNET). We do too. So
            // no Subnet line needed here. (The pubkey is the only
            // host-file dependency for `read_ecdsa_public_key`.)
            std::fs::write(self.confbase.join("hosts").join(peer.name), cfg).unwrap();
        }

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
    // bob}; `send_sptps_packet`'s PACKET 17 short-circuit fires
    // (direct conn, minmtu=0) so the kick is DELIVERED, not dropped.
    // The C `:684` was `!validkey && !connection`; with a direct
    // conn validkey doesn't matter. The follow-up `try_tx` kicks
    // `send_req_key` for the UDP path.
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

    // Drain the kick: PACKET 17 delivered it (direct conn bypasses
    // validkey). Don't let it shadow THE PACKET assert below.
    let kicked = poll_until(Duration::from_secs(5), || read_fd_nb(bob_pair[0]));
    assert_eq!(kicked, kick_pkt, "kick packet went via PACKET 17");

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

    // udp_confirmed (bit 7) is NOT asserted: with the C `:725`
    // gate now wired, `data.len() > minmtu(=0)` → PACKET 17 over
    // the meta-conn, not UDP. minmtu only goes nonzero after PMTU
    // converges (separate from validkey). The C would do the same.
    // The previous assert relied on the PACKET 17 send path being
    // stubbed (every pre-PMTU packet went UDP-SPTPS instead).

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
    // The kick goes via PACKET 17 (direct conn, minmtu=0). Drain it
    // so it doesn't shadow the round-trip read below. Compression
    // doesn't apply on PACKET 17 (raw frame, no PKT_COMPRESSED bit).
    let _ = poll_until(Duration::from_secs(5), || read_fd_nb(bob_pair[0]));

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

// ═══════════════════════════════════════════════════════════════════

/// **THREE DAEMONS, RELAY PATH.** alice ← mid → bob, NO direct
/// alice↔bob ConnectTo. Alice's packet to bob's subnet routes
/// `Forward{to: bob}`; `send_sptps_data`'s relay decision sends
/// it via `mid` (the nexthop). Mid's `on_udp_recv` sees
/// `dst_id == bob`, calls `send_sptps_data_relay(to=bob, from=
/// alice)`. Bob receives, decrypts with the alice↔bob per-tunnel
/// SPTPS, writes to TUN.
///
/// Exercises the full chunk-9b chain:
/// - REQ_KEY/ANS_KEY relay (`on_req_key`/`on_ans_key` `to !=
///   myself`): alice's REQ_KEY for bob goes via mid's meta-conn.
/// - `send_sptps_data_relay` `:967` `relay = nexthop` (since
///   `via == myself` for alice — bob is reachable but indirect
///   only via the SSSP path through mid).
/// - UDP relay receive (`on_udp_recv` `dst != null && dst !=
///   myself`): mid forwards. The packet carries bob's `dst_id6`.
/// - The `[dst_id6][src_id6]` prefix on the wire (`direct=false`
///   ⇒ `dst = to->id`, not nullid).
///
/// What this DOESN'T test: `via != myself` (the static-relay
/// path, set by `IndirectData = yes`). With three nodes connected
/// linearly, SSSP gives `via=bob` for bob (`via` is the LAST
/// direct node — and bob IS the destination, reached via mid's
/// edge). So `via_nid == myself` is false... actually no, `via`
/// for a node is the last NON-indirect hop. With no `IndirectData`,
/// every edge is direct, so `via == nid` for every node. The relay
/// here happens because `nexthop != to` (mid is the first hop).
///
/// ## TCP-tunneled handshake, possibly TCP-tunneled data
///
/// alice↔bob have no direct TCP connection. Their per-tunnel SPTPS
/// handshake goes via REQ_KEY/ANS_KEY relayed by mid. That's the
/// `to != myself` arms in `on_req_key`/`on_ans_key`.
///
/// The DATA path: until `mid`'s `minmtu` is discovered (which
/// requires probes from alice→mid), the `too_big` gate would force
/// TCP. But chunk-9b's gate is `relay_minmtu > 0 && origlen >
/// minmtu` — `minmtu==0` ⇒ go UDP optimistically. So data goes
/// UDP. EMSGSIZE would correct if the loopback MTU is small, but
/// it's 65536 on Linux loopback so no problem.
#[test]
fn three_daemon_relay() {
    let tmp = TmpGuard::new("relay3");
    let alice = Node::new(tmp.path(), "alice", 0xA3);
    let mid = Node::new(tmp.path(), "mid", 0xC3);
    let bob = Node::new(tmp.path(), "bob", 0xB3);

    let alice_pair = sockpair_seqpacket();
    let bob_pair = sockpair_seqpacket();
    for &fd in &alice_pair {
        set_nonblocking(fd);
    }
    for &fd in &bob_pair {
        set_nonblocking(fd);
    }

    // mid is the hub: no device (dummy), no subnet, no ConnectTo.
    // Both alice and bob ConnectTo mid. mid knows everyone's pubkey.
    mid.write_config_multi(&[&alice, &bob], &[], None, None);
    // alice: ConnectTo=mid, owns 10.0.0.1/32. Knows bob's pubkey
    // (needed for the per-tunnel SPTPS handshake).
    alice.write_config_multi(
        &[&mid, &bob],
        &["mid"],
        Some(alice_pair[1]),
        Some("10.0.0.1/32"),
    );
    // bob: ConnectTo=mid, owns 10.0.0.2/32. Knows alice's pubkey.
    bob.write_config_multi(
        &[&mid, &alice],
        &["mid"],
        Some(bob_pair[1]),
        Some("10.0.0.2/32"),
    );

    // ─── spawn: mid first (the hub everyone connects to) ─────────
    // mid runs at debug-level so we can assert the relay log lines.
    let mut mid_child = Command::new(tincd_bin())
        .arg("-c")
        .arg(&mid.confbase)
        .arg("--pidfile")
        .arg(&mid.pidfile)
        .arg("--socket")
        .arg(&mid.socket)
        .env("RUST_LOG", "tincd=debug")
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mid");
    if !wait_for_file(&mid.socket) {
        panic!("mid setup failed; stderr:\n{}", drain_stderr(mid_child));
    }

    let mut bob_child = bob.spawn_with_fd(bob_pair[1]);
    if !wait_for_file(&bob.socket) {
        let _ = mid_child.kill();
        panic!("bob setup failed; stderr:\n{}", drain_stderr(bob_child));
    }
    unsafe { libc::close(bob_pair[1]) };

    let alice_child = alice.spawn_with_fd(alice_pair[1]);
    if !wait_for_file(&alice.socket) {
        let _ = mid_child.kill();
        let _ = bob_child.kill();
        panic!("alice setup failed; stderr:\n{}", drain_stderr(alice_child));
    }
    unsafe { libc::close(alice_pair[1]) };

    // ─── wait for full mesh reachability ────────────────────────
    let mut alice_ctl = Ctl::connect(&alice);
    let mut bob_ctl = Ctl::connect(&bob);
    let _mid_ctl = Ctl::connect(&mid);

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

    // alice must see bob as reachable (transitively, via mid).
    // SSSP: alice—mid edge from alice's ACK; mid—bob edge gossiped
    // via ADD_EDGE from mid. graph() runs, bob becomes reachable.
    let mesh_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        poll_until(Duration::from_secs(10), || {
            let a = alice_ctl.dump(3);
            let b = bob_ctl.dump(3);
            // bit 4 = reachable
            let a_sees_bob = node_status(&a, "bob").is_some_and(|s| s & 0x10 != 0);
            let b_sees_alice = node_status(&b, "alice").is_some_and(|s| s & 0x10 != 0);
            (a_sees_bob && b_sees_alice).then_some(())
        });
    }));
    if mesh_result.is_err() {
        let _ = mid_child.kill();
        let _ = bob_child.kill();
        let ms = drain_stderr(mid_child);
        let bs = drain_stderr(bob_child);
        let asd = drain_stderr(alice_child);
        panic!(
            "mesh reachability timed out;\n=== alice ===\n{asd}\n=== mid ===\n{ms}\n=== bob ===\n{bs}"
        );
    }

    // ─── nexthop check: alice's route to bob goes via mid ────────
    // dump_nodes body tokens 11/12 are nexthop/via. For alice's
    // bob row: nexthop should be "mid".
    let node_nexthop = |rows: &[String], name: &str| -> Option<String> {
        rows.iter().find_map(|r| {
            let body = r.strip_prefix("18 3 ")?;
            let toks: Vec<&str> = body.split_whitespace().collect();
            if toks.first() != Some(&name) {
                return None;
            }
            Some(toks.get(11)?.to_string())
        })
    };
    let a_nodes = alice_ctl.dump(3);
    let nh = node_nexthop(&a_nodes, "bob");
    assert_eq!(
        nh.as_deref(),
        Some("mid"),
        "alice's nexthop for bob should be mid; nodes:\n{a_nodes:#?}"
    );

    // ─── kick the per-tunnel handshake ──────────────────────────
    // alice's REQ_KEY for bob goes via `nexthop->connection` =
    // alice's mid-conn. mid's `on_req_key` sees `to != myself`,
    // forwards verbatim to bob via mid's bob-conn. Bob starts
    // responder SPTPS, ANS_KEY back via mid.
    let kick = mk_ipv4_pkt([10, 0, 0, 1], [10, 0, 0, 2], b"kick");
    write_fd(alice_pair[0], &kick);

    let validkey_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        poll_until(Duration::from_secs(10), || {
            let a = alice_ctl.dump(3);
            let b = bob_ctl.dump(3);
            // bit 1 = validkey
            let a_ok = node_status(&a, "bob").is_some_and(|s| s & 0x02 != 0);
            let b_ok = node_status(&b, "alice").is_some_and(|s| s & 0x02 != 0);
            (a_ok && b_ok).then_some(())
        });
    }));
    if validkey_result.is_err() {
        let _ = mid_child.kill();
        let _ = bob_child.kill();
        let ms = drain_stderr(mid_child);
        let bs = drain_stderr(bob_child);
        let asd = drain_stderr(alice_child);
        panic!("validkey timed out;\n=== alice ===\n{asd}\n=== mid ===\n{ms}\n=== bob ===\n{bs}");
    }

    // ─── THE PACKET ─────────────────────────────────────────────
    // alice → mid (UDP, dst_id6=bob) → bob. mid's `on_udp_recv`
    // sees dst != null && dst != myself, calls `send_sptps_data_
    // relay`. The ciphertext is the alice↔bob SPTPS record; mid
    // can't decrypt it (and doesn't try — just re-prefixes and
    // forwards). bob decrypts.
    let payload = b"relayed via mid";
    let ip_pkt = mk_ipv4_pkt([10, 0, 0, 1], [10, 0, 0, 2], payload);
    write_fd(alice_pair[0], &ip_pkt);

    let recv_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        poll_until(Duration::from_secs(5), || read_fd_nb(bob_pair[0]))
    }));
    let recv = match recv_result {
        Ok(r) => r,
        Err(_) => {
            let _ = mid_child.kill();
            let _ = bob_child.kill();
            let ms = drain_stderr(mid_child);
            let bs = drain_stderr(bob_child);
            let asd = drain_stderr(alice_child);
            panic!(
                "packet relay timed out;\n=== alice ===\n{asd}\n=== mid ===\n{ms}\n=== bob ===\n{bs}"
            );
        }
    };

    assert_eq!(
        recv,
        ip_pkt,
        "relay round-trip mismatch; sent {} got {}",
        ip_pkt.len(),
        recv.len()
    );
    assert_eq!(&recv[20..], payload);

    // ─── mid stderr: the relay log ──────────────────────────────
    drop(alice_ctl);
    drop(bob_ctl);
    unsafe { libc::close(alice_pair[0]) };
    unsafe { libc::close(bob_pair[0]) };
    let _ = mid_child.kill();
    let _ = bob_child.kill();
    let mid_stderr = drain_stderr(mid_child);
    let _bob_stderr = drain_stderr(bob_child);
    let _alice_stderr = drain_stderr(alice_child);
    // mid should have logged at least one relay forward. The "via"
    // log line is from `send_sptps_data_relay`; the "Relaying
    // REQ_KEY" / "Relaying ANS_KEY" lines are from the meta-relay.
    assert!(
        mid_stderr.contains("Relaying"),
        "mid should log relay activity; stderr:\n{mid_stderr}"
    );
}

/// Three daemons, hub-and-spoke, with `TunnelServer = yes` on the
/// hub. Same physical setup as `three_daemon_relay` (alice and bob
/// both `ConnectTo = mid`, no direct alice↔bob meta connection).
///
/// The DIFFERENCE: tunnelserver makes mid a router-only hub. mid's
/// `send_everything` sends only its OWN subnets (none here); mid's
/// `on_ack` sends the new edge to the new peer ONLY (`send_add_
/// edge(c, ...)` not `send_add_edge(everyone, ...)`); mid's
/// `on_add_subnet`/`on_add_edge` never `forward_request`. So:
///
/// - alice's `dump nodes` shows bob as **unreachable**. She
///   never received bob's ADD_EDGE because mid didn't forward it.
///   (bob IS in alice's graph: `load_all_nodes` walks hosts/ at
///   setup and adds every name — C `net_setup.c:186-189`. But
///   no edge reaches him.)
/// - bob: same. alice is unreachable from bob's view.
/// - mid: 3 nodes, all REACHABLE. Hub knows spokes; spokes don't
///   know each other's edges.
/// - A packet from alice to `10.0.0.2` (bob's subnet) → alice's
///   `route()` returns `Unreachable` (alice doesn't have bob's
///   subnet — mid didn't forward bob's ADD_SUBNET). alice writes
///   ICMP DEST_UNREACH back to her own TUN. **This is the
///   operator-visible behavior**: tunnelserver makes mid a router-
///   only hub; alice can't reach bob through it without explicit
///   config.
///
/// `net.py::test_tunnel_server` checks the dump only; asserting
/// the ICMP is BETTER (proves the data-plane consequence, not just
/// the control-plane state).
///
/// Timing: poll until alice sees 2 nodes STABILIZE (poll, sleep
/// 50ms, poll again, same answer) — otherwise we might catch the
/// moment before mid's edge arrives at alice and get a false pass
/// on "only 2 nodes".
#[test]
fn three_daemon_tunnelserver() {
    let tmp = TmpGuard::new("tunnelserver3");
    let alice = Node::new(tmp.path(), "alice", 0xA4);
    // mid: TunnelServer = yes. The whole point.
    let mid = Node::new(tmp.path(), "mid", 0xC4).with_conf("TunnelServer = yes\n");
    let bob = Node::new(tmp.path(), "bob", 0xB4);

    let alice_pair = sockpair_seqpacket();
    for &fd in &alice_pair {
        set_nonblocking(fd);
    }

    // mid: hub. dummy device, no subnet, no ConnectTo. Knows both
    // spokes' pubkeys (for the meta-SPTPS auth).
    mid.write_config_multi(&[&alice, &bob], &[], None, None);
    // mid: append `Subnet =` to hosts/{alice,bob}. With
    // `:880 strictsubnets|=tunnelserver`, mid's `load_all_nodes`
    // preloads these; bob's gossip'd ADD_SUBNET hits the `:93`
    // lookup-first noop. Without preload, mid hits `:109` ("we
    // should already know all allowed subnets") and DROPS bob's
    // subnet — mid can't route to bob. The C requires this preload
    // for tunnelserver hubs; our pre-strictsubnets code accepted
    // gossip without it (the `:109` gate didn't exist), so the
    // test predates the requirement. `write_config_multi` only
    // writes pubkey to hosts/PEER, so append.
    let mid_hosts = mid.confbase.join("hosts");
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(mid_hosts.join("alice"))
            .unwrap();
        writeln!(f, "Subnet = 10.0.0.1/32").unwrap();
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(mid_hosts.join("bob"))
            .unwrap();
        writeln!(f, "Subnet = 10.0.0.2/32").unwrap();
    }
    // alice: ConnectTo=mid, owns 10.0.0.1/32, fd device. Knows
    // bob's pubkey (irrelevant here — she'll never start a tunnel
    // to bob because she never learns he exists).
    alice.write_config_multi(
        &[&mid, &bob],
        &["mid"],
        Some(alice_pair[1]),
        Some("10.0.0.1/32"),
    );
    // bob: ConnectTo=mid, owns 10.0.0.2/32. dummy device (we only
    // assert from alice's side).
    bob.write_config_multi(&[&mid, &alice], &["mid"], None, Some("10.0.0.2/32"));

    // ─── spawn: mid first (the hub) ──────────────────────────────
    let mut mid_child = Command::new(tincd_bin())
        .arg("-c")
        .arg(&mid.confbase)
        .arg("--pidfile")
        .arg(&mid.pidfile)
        .arg("--socket")
        .arg(&mid.socket)
        .env("RUST_LOG", "tincd=debug")
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mid");
    if !wait_for_file(&mid.socket) {
        panic!("mid setup failed; stderr:\n{}", drain_stderr(mid_child));
    }

    let mut bob_child = bob.spawn();
    if !wait_for_file(&bob.socket) {
        let _ = mid_child.kill();
        panic!("bob setup failed; stderr:\n{}", drain_stderr(bob_child));
    }

    let alice_child = alice.spawn_with_fd(alice_pair[1]);
    if !wait_for_file(&alice.socket) {
        let _ = mid_child.kill();
        let _ = bob_child.kill();
        panic!("alice setup failed; stderr:\n{}", drain_stderr(alice_child));
    }
    unsafe { libc::close(alice_pair[1]) };

    let mut alice_ctl = Ctl::connect(&alice);
    let mut bob_ctl = Ctl::connect(&bob);
    let mut mid_ctl = Ctl::connect(&mid);

    // ─── wait for alice↔mid and bob↔mid to settle ────────────────
    // mid sees both spokes as active connections. Once that's
    // true, all the gossip that's going to happen HAS happened
    // (each ACK fires `send_everything` + `send_add_edge`; with
    // tunnelserver, mid's send_everything is empty and the
    // add_edge goes only to that peer).
    poll_until(Duration::from_secs(10), || {
        let m = mid_ctl.dump(6);
        let a_ok = has_active_peer(&m, "alice");
        let b_ok = has_active_peer(&m, "bob");
        (a_ok && b_ok).then_some(())
    });

    // ─── the count assertions, with stabilization ──────────────
    // alice should see EXACTLY 2 nodes. NOT 3. Poll until stable
    // (two consecutive reads agree) to rule out catching the
    // pre-mid-edge moment.
    let alice_stable = poll_until(Duration::from_secs(5), || {
        let a1 = alice_ctl.dump(3);
        std::thread::sleep(Duration::from_millis(50));
        let a2 = alice_ctl.dump(3);
        (a1.len() == a2.len() && a1.len() >= 2).then_some(a1)
    });

    let node_names = |rows: &[String]| -> Vec<String> {
        rows.iter()
            .filter_map(|r| {
                r.strip_prefix("18 3 ")?
                    .split_whitespace()
                    .next()
                    .map(String::from)
            })
            .collect()
    };

    // `load_all_nodes` (C `net_setup.c:186-189`) adds every
    // hosts/-file name to the graph at setup, so bob IS in
    // alice's `dump nodes` (alice has hosts/bob for the pubkey).
    // The tunnelserver assertion is REACHABILITY, not presence:
    // mid never forwarded bob's ADD_EDGE → no edge to bob →
    // bob unreachable. Status bit 4 (`0x10`) is `reachable`.
    let reachable_names = |rows: &[String]| -> Vec<String> {
        rows.iter()
            .filter_map(|r| {
                let body = r.strip_prefix("18 3 ")?;
                let mut t = body.split_whitespace();
                let name = t.next()?;
                // Body tokens: name id host "port" port cipher
                // digest maclen compression options STATUS …
                let status = u32::from_str_radix(t.nth(9)?, 16).ok()?;
                (status & 0x10 != 0).then(|| name.to_owned())
            })
            .collect()
    };

    let a_names = node_names(&alice_stable);
    let a_reachable = reachable_names(&alice_stable);
    assert_eq!(
        a_reachable.len(),
        2,
        "alice should see exactly 2 REACHABLE nodes (alice, mid) — \
         mid's tunnelserver mode never forwarded bob's ADD_EDGE; \
         all: {a_names:?}, reachable: {a_reachable:?}"
    );
    assert!(
        a_reachable.contains(&"alice".to_string()),
        "{a_reachable:?}"
    );
    assert!(a_reachable.contains(&"mid".to_string()), "{a_reachable:?}");
    assert!(
        !a_reachable.contains(&"bob".to_string()),
        "bob should be UNREACHABLE from alice (no edge gossiped); \
         got reachable: {a_reachable:?}"
    );

    // bob: same. 2 REACHABLE (bob, mid); alice is in graph but
    // unreachable.
    let b_nodes = bob_ctl.dump(3);
    let b_names = node_names(&b_nodes);
    let b_reachable = reachable_names(&b_nodes);
    assert_eq!(
        b_reachable.len(),
        2,
        "bob should see exactly 2 REACHABLE nodes (bob, mid); \
         all: {b_names:?}, reachable: {b_reachable:?}"
    );
    assert!(
        !b_reachable.contains(&"alice".to_string()),
        "alice should be UNREACHABLE from bob; got: {b_reachable:?}"
    );

    // mid: 3 REACHABLE. Hub knows both spokes via direct edges.
    let m_nodes = mid_ctl.dump(3);
    let m_names = node_names(&m_nodes);
    let m_reachable = reachable_names(&m_nodes);
    assert_eq!(
        m_reachable.len(),
        3,
        "mid (the hub) should see all 3 nodes REACHABLE; \
         all: {m_names:?}, reachable: {m_reachable:?}"
    );

    // alice's subnets: she knows her OWN (10.0.0.1/32) and mid's
    // (none). NOT bob's. So `dump subnets` (subtype 5) shows 1.
    let a_subnets = alice_ctl.dump(5);
    assert_eq!(
        a_subnets.len(),
        1,
        "alice should have exactly 1 subnet (her own); mid's \
         tunnelserver send_everything sends only OWN subnets (none) \
         and on_add_subnet doesn't forward bob's; got: {a_subnets:?}"
    );

    // ─── the data-plane consequence: ICMP unreachable ──────────
    // A packet from alice to 10.0.0.2 (bob's subnet) hits alice's
    // `route()` → NO subnet match (alice doesn't have bob's
    // subnet) → `Unreachable{ICMP_DEST_UNREACH, ICMP_NET_UNKNOWN}`
    // → ICMP synth → written BACK to alice's TUN. The TEST end of
    // the socketpair reads it.
    //
    // ICMP layout (FdTun strips/adds ether so we see raw IP):
    // bytes [0..20] = IPv4 header (proto=1 ICMP at byte 9),
    // byte [20] = ICMP type (3 = DEST_UNREACH),
    // byte [21] = ICMP code (6 = NET_UNKNOWN).
    let probe = mk_ipv4_pkt([10, 0, 0, 1], [10, 0, 0, 2], b"nowhere");
    write_fd(alice_pair[0], &probe);

    let icmp = poll_until(Duration::from_secs(5), || read_fd_nb(alice_pair[0]));
    assert!(
        icmp.len() >= 22,
        "expected ICMP reply, got {} bytes: {icmp:02x?}",
        icmp.len()
    );
    assert_eq!(icmp[9], 1, "IP proto should be ICMP; got: {icmp:02x?}");
    assert_eq!(
        icmp[20], 3,
        "ICMP type should be DEST_UNREACH (3); got: {icmp:02x?}"
    );
    assert_eq!(
        icmp[21], 6,
        "ICMP code should be NET_UNKNOWN (6); got: {icmp:02x?}"
    );

    // ─── mid stderr: tunnelserver send_everything log ──────────
    drop(alice_ctl);
    drop(bob_ctl);
    drop(mid_ctl);
    unsafe { libc::close(alice_pair[0]) };
    let _ = mid_child.kill();
    let _ = bob_child.kill();
    let mid_stderr = drain_stderr(mid_child);
    let _ = drain_stderr(bob_child);
    let _ = drain_stderr(alice_child);
    assert!(
        mid_stderr.contains("tunnelserver"),
        "mid should log tunnelserver-mode send_everything; stderr:\n{mid_stderr}"
    );
}

/// `StrictSubnets = yes`: alice's `hosts/bob` is the AUTHORITY for
/// which subnets bob may claim. bob owns `10.0.0.2/32` in his own
/// config; he gossips ADD_SUBNET for it via mid → alice. alice's
/// `hosts/bob` does NOT have `Subnet = 10.0.0.2/32`. The gate at
/// `protocol_subnet.c:116-122` fires: alice forwards the gossip
/// (to nobody, no other peers) but does NOT add it locally.
///
/// Unlike `tunnelserver`, `strictsubnets` does NOT filter topology:
/// alice still learns bob exists (mid forwards bob's ADD_EDGE). She
/// just won't route to subnets she didn't pre-authorize on disk.
///
/// ## Shape
///
/// - alice: `StrictSubnets = yes`, `ConnectTo = mid`, owns
///   `10.0.0.1/32`. Her `hosts/bob` has the pubkey ONLY — no
///   `Subnet` line.
/// - mid: dumb relay (NOT strictsubnets). `ConnectTo` neither.
///   Forwards gossip both ways.
/// - bob: `ConnectTo = mid`, owns `10.0.0.2/32`. His ADD_SUBNET
///   reaches alice via mid's `forward_request`.
///
/// ## Assertions
///
/// 1. alice `dump nodes` shows 3 reachable (topology unfiltered).
/// 2. alice `dump subnets` does NOT have `10.0.0.2` (the gate).
/// 3. mid `dump subnets` DOES have `10.0.0.2` (mid isn't strict).
/// 4. ping `10.0.0.2` from alice → ICMP NET_UNKNOWN (no route).
/// 5. Append `Subnet = 10.0.0.2/32` to alice's `hosts/bob`, restart
///    alice → `load_all_nodes` preloads it → ADD_SUBNET gossip
///    arrives, `subnets.contains` finds it (the `:93` lookup-first),
///    silent noop → `dump subnets` now shows it. (Restart not
///    SIGHUP; reload diff is `TODO(chunk-12-strictsubnets-reload)`.)
///
/// Regression-first: before the gate exists, step 2 fails (alice
/// wrongly accepts the gossip).
#[test]
fn three_daemon_strictsubnets() {
    let tmp = TmpGuard::new("strictsubnets3");
    // alice: StrictSubnets = yes. The RECEIVER of gossip.
    let alice = Node::new(tmp.path(), "alice", 0xA5).with_conf("StrictSubnets = yes\n");
    // mid: plain relay. NOT strict (so we can prove it accepts).
    let mid = Node::new(tmp.path(), "mid", 0xC5);
    let bob = Node::new(tmp.path(), "bob", 0xB5);

    let alice_pair = sockpair_seqpacket();
    for &fd in &alice_pair {
        set_nonblocking(fd);
    }

    // mid: hub. dummy device, no subnet, no ConnectTo. Knows both.
    mid.write_config_multi(&[&alice, &bob], &[], None, None);
    // alice: ConnectTo=mid, owns 10.0.0.1/32, fd device. Knows
    // bob's pubkey. CRITICALLY: alice's hosts/bob (written by
    // write_config_multi) has NO `Subnet =` line — see the
    // "no Subnet line needed here" comment in that fn. That's
    // exactly what we want: bob's subnet is unauthorized.
    alice.write_config_multi(
        &[&mid, &bob],
        &["mid"],
        Some(alice_pair[1]),
        Some("10.0.0.1/32"),
    );
    // bob: ConnectTo=mid, owns 10.0.0.2/32. dummy device.
    bob.write_config_multi(&[&mid, &alice], &["mid"], None, Some("10.0.0.2/32"));

    // ─── spawn: mid first ────────────────────────────────────────
    let mut mid_child = mid.spawn();
    if !wait_for_file(&mid.socket) {
        panic!("mid setup failed; stderr:\n{}", drain_stderr(mid_child));
    }
    let mut bob_child = bob.spawn();
    if !wait_for_file(&bob.socket) {
        let _ = mid_child.kill();
        panic!("bob setup failed; stderr:\n{}", drain_stderr(bob_child));
    }
    let alice_child = alice.spawn_with_fd(alice_pair[1]);
    if !wait_for_file(&alice.socket) {
        let _ = mid_child.kill();
        let _ = bob_child.kill();
        panic!("alice setup failed; stderr:\n{}", drain_stderr(alice_child));
    }
    unsafe { libc::close(alice_pair[1]) };

    let mut alice_ctl = Ctl::connect(&alice);
    let mut mid_ctl = Ctl::connect(&mid);

    // ─── wait: mid sees both spokes active ───────────────────────
    poll_until(Duration::from_secs(10), || {
        let m = mid_ctl.dump(6);
        (has_active_peer(&m, "alice") && has_active_peer(&m, "bob")).then_some(())
    });
    // mid forwards bob's ADD_EDGE to alice. Wait for alice to see
    // 3 reachable nodes (proves topology is NOT filtered by
    // strictsubnets — that's tunnelserver's job).
    let alice_nodes = poll_until(Duration::from_secs(10), || {
        let a = alice_ctl.dump(3);
        let reachable = a
            .iter()
            .filter(|r| {
                r.strip_prefix("18 3 ")
                    .and_then(|b| b.split_whitespace().nth(10))
                    .and_then(|s| u32::from_str_radix(s, 16).ok())
                    .is_some_and(|s| s & 0x10 != 0)
            })
            .count();
        (reachable == 3).then_some(a)
    });
    assert_eq!(
        alice_nodes.iter().filter(|r| r.contains(" bob ")).count(),
        1,
        "alice should see bob in node list (topology unfiltered): {alice_nodes:?}"
    );

    // ─── the gate: alice does NOT have bob's subnet ──────────────
    // mid DOES (proves the gossip propagated; alice's gate is
    // alice-local). Wait for mid to receive it first.
    poll_until(Duration::from_secs(5), || {
        let m = mid_ctl.dump(5);
        // `Subnet::Display` omits `/32` (max prefix). `net2str`.
        has_subnet(&m, "10.0.0.2", "bob").then_some(())
    });
    // Stabilize: alice has had time to receive the same gossip.
    // Two consecutive reads agree, neither has 10.0.0.2.
    let a_subnets = poll_until(Duration::from_secs(5), || {
        let a1 = alice_ctl.dump(5);
        std::thread::sleep(Duration::from_millis(50));
        let a2 = alice_ctl.dump(5);
        (a1 == a2).then_some(a1)
    });
    assert!(
        !has_subnet(&a_subnets, "10.0.0.2", "bob"),
        "alice's StrictSubnets gate should reject bob's gossiped \
         10.0.0.2/32 (not in her hosts/bob); got: {a_subnets:?}"
    );
    assert!(
        has_subnet(&a_subnets, "10.0.0.1", "alice"),
        "alice's own subnet should still be there: {a_subnets:?}"
    );

    // ─── data plane: ICMP NET_UNKNOWN ────────────────────────────
    // Same shape as tunnelserver: no route → synth ICMP unreachable.
    let probe = mk_ipv4_pkt([10, 0, 0, 1], [10, 0, 0, 2], b"nowhere");
    write_fd(alice_pair[0], &probe);
    let icmp = poll_until(Duration::from_secs(5), || read_fd_nb(alice_pair[0]));
    assert!(icmp.len() >= 22, "ICMP reply too short: {icmp:02x?}");
    assert_eq!(icmp[9], 1, "IP proto should be ICMP: {icmp:02x?}");
    assert_eq!(icmp[20], 3, "ICMP type DEST_UNREACH: {icmp:02x?}");
    assert_eq!(icmp[21], 6, "ICMP code NET_UNKNOWN: {icmp:02x?}");

    // ─── restart with authorized hosts/bob ────────────────────────
    // Append `Subnet = 10.0.0.2/32` to alice's hosts/bob. Restart
    // alice. `load_all_nodes` preloads it; the ADD_SUBNET gossip
    // hits the `:93` lookup-first → already-have-it → noop. The
    // subnet appears.
    drop(alice_ctl);
    let alice_stderr1 = drain_stderr(alice_child);
    assert!(
        alice_stderr1.contains("Ignoring unauthorized"),
        "alice should have logged the strictsubnets gate firing; stderr:\n{alice_stderr1}"
    );
    unsafe { libc::close(alice_pair[0]) };

    let bob_hosts = alice.confbase.join("hosts").join("bob");
    let mut bob_cfg = std::fs::read_to_string(&bob_hosts).unwrap();
    bob_cfg.push_str("Subnet = 10.0.0.2/32\n");
    std::fs::write(&bob_hosts, bob_cfg).unwrap();

    // Fresh socketpair for the new alice.
    let alice_pair2 = sockpair_seqpacket();
    for &fd in &alice_pair2 {
        set_nonblocking(fd);
    }
    // Re-write tinc.conf with the new fd (DeviceType=fd / Device=N).
    // hosts/ files persist (we just appended to hosts/bob above).
    alice.write_config_multi(
        &[&mid, &bob],
        &["mid"],
        Some(alice_pair2[1]),
        Some("10.0.0.1/32"),
    );
    // write_config_multi re-truncates hosts/bob. Re-append.
    let mut bob_cfg = std::fs::read_to_string(&bob_hosts).unwrap();
    bob_cfg.push_str("Subnet = 10.0.0.2/32\n");
    std::fs::write(&bob_hosts, bob_cfg).unwrap();

    std::fs::remove_file(&alice.socket).ok();
    let alice_child2 = alice.spawn_with_fd(alice_pair2[1]);
    if !wait_for_file(&alice.socket) {
        let _ = mid_child.kill();
        let _ = bob_child.kill();
        panic!(
            "alice respawn failed; stderr:\n{}",
            drain_stderr(alice_child2)
        );
    }
    unsafe { libc::close(alice_pair2[1]) };

    let mut alice_ctl2 = Ctl::connect(&alice);
    // Wait for alice↔mid handshake; bob's gossip via mid follows.
    // The preloaded subnet is there from cold-start regardless,
    // but wait for full mesh to prove the gossip path doesn't
    // accidentally DELETE it.
    poll_until(Duration::from_secs(10), || {
        let a = alice_ctl2.dump(5);
        has_subnet(&a, "10.0.0.2", "bob").then_some(())
    });

    // ─── cleanup ─────────────────────────────────────────────────
    drop(alice_ctl2);
    drop(mid_ctl);
    unsafe { libc::close(alice_pair2[0]) };
    let _ = mid_child.kill();
    let _ = bob_child.kill();
    let _ = drain_stderr(mid_child);
    let _ = drain_stderr(bob_child);
    let _ = drain_stderr(alice_child2);
}

// ═══ chunk-10: SIGHUP reload, invitation server ═════════════════════

/// Check if `dump subnets` rows contain a given subnet owned by a
/// given owner. Row format: `"18 5 SUBNET OWNER"`.
fn has_subnet(rows: &[String], subnet: &str, owner: &str) -> bool {
    rows.iter().any(|r| {
        let Some(body) = r.strip_prefix("18 5 ") else {
            return false;
        };
        let mut t = body.split_whitespace();
        t.next() == Some(subnet) && t.next() == Some(owner)
    })
}

/// SIGHUP reload: alice changes her own Subnets, sends SIGHUP, bob
/// sees the diff via ADD_SUBNET / DEL_SUBNET.
///
/// ## What's proven (per step)
///
/// 1. **Reload reads config**: alice's `read_server_config` re-runs
///    on SIGHUP. The diff sees `10.1.0.0/24` as new.
/// 2. **`diff_subnets` + broadcast**: alice's `reload_configuration`
///    sends `ADD_SUBNET` for the new subnet. Bob's `on_add_subnet`
///    fires; `dump subnets` shows it.
/// 3. **DEL half**: removing the subnet + SIGHUP → bob sees it gone.
///
/// This is the strongest reload test — it exercises the full chain:
/// signal → self-pipe wake → reload_configuration → diff → broadcast
/// → peer's on_add_subnet → SubnetTree.
#[test]
fn sighup_reload_subnets() {
    let tmp = TmpGuard::new("reload");
    let alice = Node::new(tmp.path(), "alice", 0xAA);
    let bob = Node::new(tmp.path(), "bob", 0xBB);

    // alice has ONE subnet initially.
    alice.write_config_with(&bob, false, None, Some("10.0.0.0/24"));
    bob.write_config_with(&alice, true, None, None);

    let mut alice_child = alice.spawn();
    if !wait_for_file(&alice.socket) {
        panic!("alice setup failed: {}", drain_stderr(alice_child));
    }
    let mut bob_child = bob.spawn();
    if !wait_for_file(&bob.socket) {
        let _ = alice_child.kill();
        panic!("bob setup failed: {}", drain_stderr(bob_child));
    }

    // Wait for the connection.
    let mut alice_ctl = Ctl::connect(&alice);
    let mut bob_ctl = Ctl::connect(&bob);
    poll_until(Duration::from_secs(10), || {
        if has_active_peer(&bob_ctl.dump(6), "alice") {
            Some(())
        } else {
            None
        }
    });

    // ─── baseline: bob sees alice's 10.0.0.0/24 ──────────────
    poll_until(Duration::from_secs(5), || {
        if has_subnet(&bob_ctl.dump(5), "10.0.0.0/24", "alice") {
            Some(())
        } else {
            None
        }
    });
    let baseline = bob_ctl.dump(5);
    assert!(
        !has_subnet(&baseline, "10.1.0.0/24", "alice"),
        "baseline should NOT have 10.1.0.0/24 yet: {baseline:?}"
    );

    // ─── step 1: ADD a subnet ───────────────────────────────
    // Rewrite alice's hosts/alice with BOTH subnets. Port stays.
    // Sleep 1.1s before write: `conns_to_terminate` uses
    // `mtime > last_config_check` (strict, second-granularity);
    // a write in the same wall-clock second as boot would have
    // `mtime == last_config_check` and not trigger. Our test
    // doesn't WANT it to trigger (we're rewriting alice's OWN
    // hosts file, not a peer's), but the safety margin avoids
    // flakiness if mtime semantics differ across filesystems.
    std::thread::sleep(Duration::from_millis(1100));
    std::fs::write(
        alice.confbase.join("hosts").join("alice"),
        format!(
            "Port = {}\nSubnet = 10.0.0.0/24\nSubnet = 10.1.0.0/24\n",
            alice.port
        ),
    )
    .unwrap();

    // SIGHUP alice. Read pid from pidfile (first token).
    let alice_pid: i32 = std::fs::read_to_string(&alice.pidfile)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(unsafe { libc::kill(alice_pid, libc::SIGHUP) }, 0);

    // Poll bob until 10.1.0.0/24 appears. This proves: alice
    // re-read config, diff_subnets found the new one, sent
    // ADD_SUBNET, bob received and added.
    poll_until(Duration::from_secs(10), || {
        let s = bob_ctl.dump(5);
        if has_subnet(&s, "10.1.0.0/24", "alice") && has_subnet(&s, "10.0.0.0/24", "alice") {
            Some(())
        } else {
            None
        }
    });

    // alice's own dump: also shows both (proves SubnetTree.add).
    let a_subnets = alice_ctl.dump(5);
    assert!(
        has_subnet(&a_subnets, "10.1.0.0/24", "alice"),
        "alice should have new subnet locally: {a_subnets:?}"
    );

    // ─── step 2: REMOVE a subnet ────────────────────────────
    std::thread::sleep(Duration::from_millis(1100));
    std::fs::write(
        alice.confbase.join("hosts").join("alice"),
        format!("Port = {}\nSubnet = 10.0.0.0/24\n", alice.port),
    )
    .unwrap();
    assert_eq!(unsafe { libc::kill(alice_pid, libc::SIGHUP) }, 0);

    // Poll until 10.1.0.0/24 is GONE. Proves DEL_SUBNET path.
    poll_until(Duration::from_secs(10), || {
        let s = bob_ctl.dump(5);
        if !has_subnet(&s, "10.1.0.0/24", "alice") && has_subnet(&s, "10.0.0.0/24", "alice") {
            Some(())
        } else {
            None
        }
    });

    // ─── cleanup ───────────────────────────────────────────────
    drop(alice_ctl);
    drop(bob_ctl);
    let _ = bob_child.kill();
    let alice_stderr = drain_stderr(alice_child);
    let _ = drain_stderr(bob_child);
    // alice should have logged the reload.
    assert!(
        alice_stderr.contains("SIGHUP") || alice_stderr.contains("reload"),
        "alice should log reload; stderr:\n{alice_stderr}"
    );
}

/// `tinc join` against a real daemon. The strongest invitation test:
/// real TCP, real epoll, real `tinc-tools::cmd::join::join()`.
///
/// ## Setup chain
///
/// 1. Alice's confbase: tinc.conf + hosts/alice + ed25519_key.priv
///    + invitations/ed25519_key.priv (the per-mesh invitation key).
/// 2. The invitation FILE: `invitations/<cookie_filename>` with
///    `Name = bob\n#-----#\n<alice's host file>\n`.
/// 3. The URL: `127.0.0.1:<alice-port>/<slug>` where slug =
///    `b64(key_hash(inv_pubkey)) || b64(cookie)`.
///
/// ## What's proven (full chain)
///
/// - daemon's id_h `?` branch: throwaway-key parse, invitation_key
///   present, plaintext greeting (line1+line2), SPTPS start with
///   the 15-byte no-NUL label.
/// - SPTPS handshake: joiner Initiator, daemon Responder. Label
///   match (both sides use 15 bytes).
/// - dispatch_invitation_outputs: cookie record → serve_cookie →
///   chunk_file → type-0 records + type-1 marker.
/// - join's finalize: receives file, writes bob's tinc.conf +
///   hosts/alice, generates bob's identity key, sends it as type-1.
/// - daemon's finalize: writes hosts/bob, sends type-2.
/// - Single-use: second join with same cookie fails (the rename to
///   .used + unlink left no file behind).
#[test]
fn tinc_join_against_real_daemon() {
    use tinc_crypto::invite::{build_slug, cookie_filename};
    use tinc_crypto::sign::SigningKey;

    let tmp = TmpGuard::new("join");
    let alice = Node::new(tmp.path(), "alice", 0xAA);

    // ─── alice's basic config (no peer; she just listens) ──────
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::create_dir_all(alice.confbase.join("hosts")).unwrap();
        std::fs::write(
            alice.confbase.join("tinc.conf"),
            format!(
                "Name = {}\nDeviceType = dummy\nAddressFamily = ipv4\nPingTimeout = 1\n",
                alice.name
            ),
        )
        .unwrap();
        // hosts/alice: Port + Address (the invitation file copies
        // this section so bob knows where to connect).
        std::fs::write(
            alice.confbase.join("hosts").join("alice"),
            format!(
                "Port = {}\nAddress = 127.0.0.1 {}\n",
                alice.port, alice.port
            ),
        )
        .unwrap();
        // alice's identity key.
        let sk = SigningKey::from_seed(&alice.seed);
        let f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(alice.confbase.join("ed25519_key.priv"))
            .unwrap();
        let mut w = std::io::BufWriter::new(f);
        tinc_conf::write_pem(&mut w, "ED25519 PRIVATE KEY", &sk.to_blob()).unwrap();
    }

    // ─── invitation key + invitation file ───────────────────────
    let inv_dir = alice.confbase.join("invitations");
    std::fs::create_dir_all(&inv_dir).unwrap();
    let inv_key = SigningKey::from_seed(&[0x11; 32]);
    {
        use std::os::unix::fs::OpenOptionsExt;
        let f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(inv_dir.join("ed25519_key.priv"))
            .unwrap();
        let mut w = std::io::BufWriter::new(f);
        tinc_conf::write_pem(&mut w, "ED25519 PRIVATE KEY", &inv_key.to_blob()).unwrap();
    }

    // Cookie: deterministic for the test.
    let cookie: [u8; 18] = *b"test-cookie-18bxxx";
    let inv_filename = cookie_filename(&cookie, inv_key.public_key());

    // Invitation file body. Format (`invitation.c:536-558`):
    //   Name = <invited>\n
    //   <some-config>\n
    //   #---#\n
    //   <copy of inviter's hosts/NAME>\n
    // The joiner's `finalize_join` parses this; the `#---#` line
    // separates joiner-config from inviter-host-file.
    let alice_pub_b64 = tinc_crypto::b64::encode(&alice.pubkey());
    let inv_body = format!(
        "Name = bob\n\
         ConnectTo = alice\n\
         #---------------------------------------------------------------#\n\
         Name = alice\n\
         Ed25519PublicKey = {alice_pub_b64}\n\
         Address = 127.0.0.1 {}\n",
        alice.port
    );
    std::fs::write(inv_dir.join(&inv_filename), &inv_body).unwrap();

    // ─── spawn alice ────────────────────────────────────────────
    let alice_child = alice.spawn();
    if !wait_for_file(&alice.socket) {
        panic!("alice setup failed: {}", drain_stderr(alice_child));
    }

    // ─── build URL + run join ──────────────────────────────────
    // URL = `host:port/slug`. slug = b64(key_hash) || b64(cookie).
    let slug = build_slug(inv_key.public_key(), &cookie);
    let url = format!("127.0.0.1:{}/{slug}", alice.port);

    // bob's confbase (where join() writes). `for_cli` with explicit
    // confbase: confdir stays None (we passed --config explicitly).
    let bob_confbase = tmp.path().join("bob");
    let bob_paths = tinc_tools::names::Paths::for_cli(&tinc_tools::names::PathsInput {
        confbase: Some(bob_confbase.clone()),
        ..Default::default()
    });

    // The actual join. In-process — the test IS the joiner client.
    let result = tinc_tools::cmd::join::join(&url, &bob_paths, false);
    if let Err(e) = &result {
        let stderr = drain_stderr(alice_child);
        panic!("join failed: {e:?}\nalice stderr:\n{stderr}");
    }

    // ─── verify join() wrote bob's config ──────────────────────
    let bob_tinc_conf = std::fs::read_to_string(bob_confbase.join("tinc.conf"))
        .expect("join should write bob/tinc.conf");
    assert!(
        bob_tinc_conf.contains("Name = bob"),
        "bob/tinc.conf should have Name = bob: {bob_tinc_conf}"
    );
    assert!(
        bob_tinc_conf.contains("ConnectTo = alice"),
        "bob/tinc.conf should have ConnectTo = alice: {bob_tinc_conf}"
    );

    // bob/hosts/alice from the invitation file's second section.
    let bob_hosts_alice = std::fs::read_to_string(bob_confbase.join("hosts").join("alice"))
        .expect("join should write bob/hosts/alice");
    assert!(
        bob_hosts_alice.contains("Ed25519PublicKey"),
        "bob/hosts/alice should have alice's pubkey: {bob_hosts_alice}"
    );

    // bob's own identity key was generated.
    assert!(
        bob_confbase.join("ed25519_key.priv").exists(),
        "join should generate bob's identity key"
    );

    // ─── verify daemon wrote alice/hosts/bob ───────────────────
    // The type-1 record carried bob's pubkey; finalize() wrote it.
    // Poll: the daemon's epoll loop processes records on the next
    // turn; might lag by a few ms after join() returns.
    let alice_hosts_bob = alice.confbase.join("hosts").join("bob");
    poll_until(Duration::from_secs(5), || {
        if alice_hosts_bob.exists() {
            Some(())
        } else {
            None
        }
    });
    let hosts_bob_content = std::fs::read_to_string(&alice_hosts_bob).unwrap();
    assert!(
        hosts_bob_content.starts_with("Ed25519PublicKey = "),
        "alice/hosts/bob: {hosts_bob_content}"
    );

    // ─── verify .used file was unlinked ────────────────────────
    // The original invitation file was renamed to .used by
    // serve_cookie, then unlinked by dispatch_invitation_outputs
    // after the file chunks were sent. Neither should exist.
    assert!(
        !inv_dir.join(&inv_filename).exists(),
        "original invitation file should be gone (renamed)"
    );
    assert!(
        !inv_dir.join(format!("{inv_filename}.used")).exists(),
        ".used file should be unlinked after serving"
    );

    // ─── single-use: second join fails ─────────────────────────
    // Same cookie, fresh confbase. serve_cookie's rename hits
    // ENOENT → NonExisting → daemon terminates the conn → join
    // gets EOF mid-handshake.
    let bob2_confbase = tmp.path().join("bob2");
    let bob2_paths = tinc_tools::names::Paths::for_cli(&tinc_tools::names::PathsInput {
        confbase: Some(bob2_confbase),
        ..Default::default()
    });
    let result2 = tinc_tools::cmd::join::join(&url, &bob2_paths, false);
    assert!(
        result2.is_err(),
        "second join with same cookie should fail (single-use); got: {result2:?}"
    );

    // ─── cleanup ───────────────────────────────────────────────
    let alice_stderr = drain_stderr(alice_child);
    assert!(
        alice_stderr.contains("Invitation") || alice_stderr.contains("invitation"),
        "alice should log invitation activity; stderr:\n{alice_stderr}"
    );
}

// ═══════════════════════════════════════════════════════════════════
// autoconnect (chunk-11)

/// `load_all_nodes` populates `has_address` AND adds hosts/-only
/// names to the graph (`net_setup.c:186-189`). Alice has a `hosts/
/// carol` file with `Address =` but NO `ConnectTo = carol` and
/// carol never runs. After spawn, `dump nodes` shows carol as a
/// row — proves `lookup_or_add_node` ran for hosts/-file-only
/// names. Carol stays unreachable (status bit 4 clear).
///
/// `AutoConnect = no`: don't let the periodic tick try to dial
/// carol (her port is bogus, the connect would just ECONNREFUSED
/// and clutter stderr).
#[test]
fn load_all_nodes_populates_graph() {
    let tmp = TmpGuard::new("loadall");
    let alice = Node::new(tmp.path(), "alice", 0xA9).with_conf("AutoConnect = no\n");
    let bob = Node::new(tmp.path(), "bob", 0xB9);

    bob.write_config(&alice, false);
    alice.write_config(&bob, false); // no ConnectTo

    // hosts/carol with Address — NO key, never spawned. Just a
    // file in alice's hosts/ dir. `load_all_nodes` should add
    // "carol" to the graph and `has_address`.
    std::fs::write(
        alice.confbase.join("hosts").join("carol"),
        "Address = 127.0.0.1 1\n",
    )
    .unwrap();

    // hosts/.swp — editor swap file, NOT a valid `check_id`.
    // `load_all_nodes` should skip it (no `.swp` row in dump).
    std::fs::write(alice.confbase.join("hosts").join(".swp"), "garbage\n").unwrap();

    let alice_child = alice.spawn();
    if !wait_for_file(&alice.socket) {
        panic!("alice setup failed: {}", drain_stderr(alice_child));
    }

    let mut ctl = Ctl::connect(&alice);
    let nodes = ctl.dump(3); // REQ_DUMP_NODES

    // Expect 3 rows: alice (myself), bob (hosts/ file), carol
    // (hosts/ file with Address). NOT 4 (.swp filtered).
    let names: Vec<&str> = nodes
        .iter()
        .filter_map(|r| r.strip_prefix("18 3 "))
        .filter_map(|b| b.split_whitespace().next())
        .collect();
    assert_eq!(names.len(), 3, "dump nodes: {nodes:?}");
    assert!(names.contains(&"alice"), "missing alice: {names:?}");
    assert!(names.contains(&"bob"), "missing bob: {names:?}");
    assert!(names.contains(&"carol"), "missing carol: {names:?}");

    // carol's status: bit 4 (reachable) CLEAR. She's in the graph
    // but no edge reaches her. Body token 10 (0-indexed) = status.
    let carol_row = nodes
        .iter()
        .find(|r| {
            r.strip_prefix("18 3 ")
                .is_some_and(|b| b.starts_with("carol "))
        })
        .expect("carol row");
    let status = carol_row
        .strip_prefix("18 3 ")
        .unwrap()
        .split_whitespace()
        .nth(10)
        .and_then(|s| u32::from_str_radix(s, 16).ok())
        .expect("status hex");
    assert_eq!(
        status & 0x10,
        0,
        "carol should be unreachable (no edges); status={status:x}"
    );

    drop(ctl);
    let stderr = drain_stderr(alice_child);
    // No "Autoconnecting" log: AutoConnect = no.
    assert!(
        !stderr.contains("Autoconnecting"),
        "AutoConnect = no should suppress autoconnect; stderr:\n{stderr}"
    );
}

/// `do_autoconnect` `<3 → make_new_connection` loop. Alice has
/// `AutoConnect = yes` (the default) and `hosts/{bob,carol,dave}`
/// all with `Address =`, but ZERO `ConnectTo =` lines. The periodic
/// tick (every 5s) runs `decide_autoconnect`; with `nc=0` it picks
/// one eligible node per tick → `Connect`. Three ticks later (~15s)
/// alice has 3 active connections.
///
/// **Why ~15s and not faster**: `make_new_connection` randomizes
/// over eligible nodes. With 3 eligibles, the first pick is 1/3
/// each. Once one connects, `nc=1`, next tick picks from 2. The
/// `pending_outgoings` check (`autoconnect.c:59-71`) means a
/// re-roll on the SAME node is `Noop` — doesn't burn a tick. With
/// the periodic timer at 5s, worst-case is 3 successful picks =
/// 15s. Add slop for the connect+handshake latency (loopback,
/// ~100ms each).
///
/// **Slow test**: ~15s. The 5s periodic is hardcoded (C `net.c:
/// 298`: `{ 5, jitter() }`). Nextest's default slow-timeout is
/// 30s; this fits. The CI profile has 60s.
#[test]
fn autoconnect_converges_to_three() {
    let tmp = TmpGuard::new("autoconnect");
    // PingTimeout=10 on the peers: an inbound conn arriving at
    // +15s gets stamped with the cached `timers.now()` from the
    // previous event-loop turn (up to 5s stale — the periodic
    // timer is the only thing waking an idle peer). With the
    // `write_config_multi` default PingTimeout=1, the conn is
    // born already-stale and reaped before id_h. Same root cause
    // as `outgoing_retry_after_refused`'s note; bigger window
    // here because the connect lands much later. PingTimeout=10
    // > 5s periodic + handshake. (PingTimeout is clamped to
    // `≤ PingInterval`; default PingInterval=60 leaves room.)
    let alice = Node::new(tmp.path(), "alice", 0xA0).with_conf("PingTimeout = 10\n");
    let peer_conf = "PingTimeout = 10\nAutoConnect = no\n";
    let bob = Node::new(tmp.path(), "bob", 0xB0).with_conf(peer_conf);
    let carol = Node::new(tmp.path(), "carol", 0xC0).with_conf(peer_conf);
    let dave = Node::new(tmp.path(), "dave", 0xD0).with_conf(peer_conf);

    // The peers: just listen, no ConnectTo. AutoConnect=no on
    // them so THEY don't start dialing each other (we only want
    // alice's autoconnect to fire; cross-dialing would muddy the
    // "exactly 3 conns from alice" assertion).
    bob.write_config_multi(&[&alice], &[], None, None);
    carol.write_config_multi(&[&alice], &[], None, None);
    dave.write_config_multi(&[&alice], &[], None, None);

    // alice: NO ConnectTo. Her hosts/ files for bob/carol/dave
    // all need `Address =` so `load_all_nodes` populates
    // `has_address`. `write_config_multi` only writes Address
    // for ConnectTo targets; we write hosts/ manually instead.
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::create_dir_all(alice.confbase.join("hosts")).unwrap();
        std::fs::write(
            alice.confbase.join("tinc.conf"),
            format!(
                "Name = alice\nDeviceType = dummy\nAddressFamily = ipv4\n{}PingTimeout = 1\n",
                alice.extra_conf
            ),
        )
        .unwrap();
        std::fs::write(
            alice.confbase.join("hosts").join("alice"),
            format!("Port = {}\n", alice.port),
        )
        .unwrap();
        for peer in [&bob, &carol, &dave] {
            let pk = tinc_crypto::b64::encode(&peer.pubkey());
            std::fs::write(
                alice.confbase.join("hosts").join(peer.name),
                format!(
                    "Ed25519PublicKey = {pk}\nAddress = 127.0.0.1 {}\n",
                    peer.port
                ),
            )
            .unwrap();
        }
        let sk = tinc_crypto::sign::SigningKey::from_seed(&alice.seed);
        let f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(alice.confbase.join("ed25519_key.priv"))
            .unwrap();
        let mut w = std::io::BufWriter::new(f);
        tinc_conf::write_pem(&mut w, "ED25519 PRIVATE KEY", &sk.to_blob()).unwrap();
    }

    // ─── spawn peers first (so alice's connects succeed) ─────────
    // Stderr → file: this test runs ~15s with 4 daemons cross-
    // gossiping. Piped stderr (~64K buffer) fills and blocks the
    // event loop on `write(2)`. /dev/null discards diagnostics; a
    // tmpfile captures them for the failure dump.
    let spawn_logged = |n: &Node| {
        let log = std::fs::File::create(tmp.path().join(format!("{}.stderr", n.name))).unwrap();
        Command::new(tincd_bin())
            .arg("-c")
            .arg(&n.confbase)
            .arg("--pidfile")
            .arg(&n.pidfile)
            .arg("--socket")
            .arg(&n.socket)
            .env("RUST_LOG", "tincd=info")
            .stderr(log)
            .spawn()
            .expect("spawn tincd")
    };
    let mut bob_child = spawn_logged(&bob);
    let mut carol_child = spawn_logged(&carol);
    let mut dave_child = spawn_logged(&dave);
    for (n, child) in [
        (&bob, &mut bob_child),
        (&carol, &mut carol_child),
        (&dave, &mut dave_child),
    ] {
        if !wait_for_file(&n.socket) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{} setup failed", n.name);
        }
    }

    let mut alice_child = alice.spawn();
    if !wait_for_file(&alice.socket) {
        let _ = bob_child.kill();
        let _ = carol_child.kill();
        let _ = dave_child.kill();
        panic!("alice setup failed: {}", drain_stderr(alice_child));
    }

    // ─── poll: alice converges to 3 active peer conns ────────────
    // First periodic tick at +5s; one Connect per tick. 3 ticks
    // ≈ 15s to fill all three slots. 25s timeout for CI slop.
    let mut alice_ctl = Ctl::connect(&alice);
    let deadline = Instant::now() + Duration::from_secs(25);
    let mut last_conns;
    let mut last_count;
    let converged = loop {
        let conns = alice_ctl.dump(6);
        let active_peers: usize = conns
            .iter()
            .filter(|r| {
                r.strip_prefix("18 6 ").is_some_and(|b| {
                    let mut t = b.split_whitespace();
                    let name = t.next();
                    let status = t.last().and_then(|s| u32::from_str_radix(s, 16).ok());
                    // Active (bit 1) AND not the control conn (bit 9).
                    matches!(name, Some("bob") | Some("carol") | Some("dave"))
                        && status.is_some_and(|s| s & 0x2 != 0)
                })
            })
            .count();
        last_count = active_peers;
        last_conns = conns;
        if active_peers == 3 {
            break true;
        }
        if Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(100));
    };

    // ─── collect stderr (also for failure diagnosis) ────────────
    drop(alice_ctl);
    let _ = alice_child.kill();
    let alice_out = alice_child.wait_with_output().unwrap();
    let alice_stderr = String::from_utf8_lossy(&alice_out.stderr);
    let _ = bob_child.kill();
    let _ = carol_child.kill();
    let _ = dave_child.kill();
    let _ = bob_child.wait();
    let _ = carol_child.wait();
    let _ = dave_child.wait();

    if !converged {
        // Dump all peer logs on failure.
        let mut peer_logs = String::new();
        for n in [&bob, &carol, &dave] {
            let path = tmp.path().join(format!("{}.stderr", n.name));
            let _ = std::fmt::Write::write_fmt(
                &mut peer_logs,
                format_args!(
                    "\n--- {} stderr ---\n{}",
                    n.name,
                    std::fs::read_to_string(&path).unwrap_or_default()
                ),
            );
        }
        panic!(
            "timed out waiting for 3 active peer conns; \
             last count={last_count}, last dump conns: {last_conns:?}\n\
             alice stderr:\n{alice_stderr}{peer_logs}"
        );
    }

    // Three Autoconnecting log lines (one per peer).
    let auto_count = alice_stderr.matches("Autoconnecting to ").count();
    assert_eq!(
        auto_count, 3,
        "expected 3 Autoconnecting logs (one per peer), got {auto_count}; \
         stderr:\n{alice_stderr}"
    );
}

// ═══════════════════════════════════════════════════════════════════
// SOCKS5 proxy roundtrip (chunk-11-proxy)
// ═══════════════════════════════════════════════════════════════════

/// In-process anonymous SOCKS5 server. Reads the RFC 1928 greeting +
/// CONNECT request, replies, then relays bytes bidirectionally to the
/// target. Same shape as `proxy_exec_roundtrip("cat")` but with the
/// real SOCKS5 byte handshake — proves `socks::build_request` produces
/// bytes a server reading the RFC accepts, and we accept ITS reply.
///
/// One-shot: handles ONE connection then exits. Enough for the test
/// (alice connects once).
fn fake_socks5_server() -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpStream};

    let listener = TcpListener::bind("127.0.0.1:0").expect("socks5 bind");
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut client, _) = listener.accept().expect("socks5 accept");

        // ─── Greeting (RFC 1928 §3) ────────────────────────────────
        // tinc sends [05][01][00] (1 method: anonymous). socks.rs:182.
        let mut greet = [0u8; 3];
        client.read_exact(&mut greet).expect("read greet");
        assert_eq!(greet[0], 5, "SOCKS version");
        assert_eq!(greet[1], 1, "nmethods");
        assert_eq!(greet[2], 0, "method = anonymous");
        // Reply: [05][00] (chose anonymous).
        client.write_all(&[5, 0]).expect("write choice");

        // ─── CONNECT (RFC 1928 §4) ─────────────────────────────────
        // [05][01][00][atyp][addr][port]. tinc sends atyp=01 (IPv4)
        // for our 127.0.0.1 target. socks.rs:213-216.
        let mut hdr = [0u8; 4];
        client.read_exact(&mut hdr).expect("read conn hdr");
        assert_eq!(hdr[0], 5, "version");
        assert_eq!(hdr[1], 1, "cmd = CONNECT");
        assert_eq!(hdr[3], 1, "atyp = IPv4");
        let mut ip = [0u8; 4];
        client.read_exact(&mut ip).expect("read ip");
        let mut port = [0u8; 2];
        client.read_exact(&mut port).expect("read port");
        let target = std::net::SocketAddr::from((ip, u16::from_be_bytes(port)));

        // Connect to the real target (bob).
        let upstream = TcpStream::connect(target).expect("upstream connect");

        // Reply: [05][00][00][01][0.0.0.0][0] (granted; bound addr
        // is "don't care" — tinc ignores it, socks.rs:267-271).
        client
            .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
            .expect("write conn reply");

        // ─── Bidirectional relay ───────────────────────────────────
        // Two threads, copy each direction. Shutdown the write half
        // when one side closes its read; the other thread's read
        // returns 0 and it exits too.
        let mut c_r = client.try_clone().unwrap();
        let mut u_w = upstream.try_clone().unwrap();
        let t1 = std::thread::spawn(move || {
            let _ = std::io::copy(&mut c_r, &mut u_w);
            let _ = u_w.shutdown(Shutdown::Write);
        });
        let mut u_r = upstream;
        let mut c_w = client;
        let _ = std::io::copy(&mut u_r, &mut c_w);
        let _ = c_w.shutdown(Shutdown::Write);
        let _ = t1.join();
    });
    (addr, handle)
}

/// Two daemons through a SOCKS5 proxy. Alice has `Proxy = socks5
/// 127.0.0.1 PORT` and `ConnectTo = bob`. The fake proxy validates
/// the RFC 1928 byte format on the wire (so we KNOW `build_request`
/// is right, not just that our build/check are inverses), relays to
/// bob, both reach ACK.
///
/// ## What's proven
///
/// 1. **`try_connect_via_proxy`**: alice's TCP connect goes to the
///    proxy addr, NOT bob's port. (If it went to bob directly the
///    test would still pass — but the proxy thread asserts on the
///    SOCKS bytes, so wrong-address would deadlock or assert-fail
///    the proxy.)
/// 2. **`finish_connecting` SOCKS arm**: SOCKS bytes queued BEFORE
///    the ID line. The proxy reads `[05][01][00]...`, asserts on
///    each byte. Proves `socks::build_request` produces RFC-valid
///    bytes.
/// 3. **`on_conn_readable` tcplen consume**: alice reads the proxy's
///    12-byte reply via `read_n` (NOT `read_line` — which would
///    misparse `[05][00]...` as "5" = METAKEY → gate fail). Proves
///    the pre-SPTPS `tcplen` branch fires before the line-drain loop.
/// 4. **`socks::check_response` Granted**: alice doesn't terminate
///    on the reply. The byte format we send and accept MATCHES.
/// 5. **Full handshake through the relay**: ID + SPTPS + ACK all
///    pass through the proxy's `io::copy` loops. Same end state as
///    `two_daemons_connect_and_reach`.
#[test]
fn socks5_proxy_roundtrip() {
    let tmp = TmpGuard::new("socks5");
    let alice = Node::new(tmp.path(), "alice", 0xA5);
    let bob = Node::new(tmp.path(), "bob", 0xB5);

    // Spawn the fake SOCKS5 server first.
    let (proxy_addr, proxy_handle) = fake_socks5_server();

    // Bob: plain config, no proxy.
    bob.write_config(&alice, false);
    // Alice: ConnectTo bob, Proxy = socks5 <fake>.
    let alice = alice.with_conf(&format!(
        "Proxy = socks5 {} {}\n",
        proxy_addr.ip(),
        proxy_addr.port()
    ));
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

    // Poll for active peer conns on both sides. Same check as
    // `two_daemons_connect_and_reach`.
    let mut alice_ctl = Ctl::connect(&alice);
    let mut bob_ctl = Ctl::connect(&bob);
    poll_until(Duration::from_secs(10), || {
        let a = alice_ctl.dump(6);
        let b = bob_ctl.dump(6);
        if has_active_peer(&a, "bob") && has_active_peer(&b, "alice") {
            Some(())
        } else {
            None
        }
    });

    // Clean up.
    drop(alice_ctl);
    drop(bob_ctl);
    let _ = alice_child.kill();
    let _ = alice_child.wait();
    let _ = bob_child.kill();
    let _ = bob_child.wait();
    // Proxy thread exits when alice's connection closes (io::copy
    // returns 0). Join with timeout via a poll-loop on is_finished.
    let deadline = Instant::now() + Duration::from_secs(5);
    while !proxy_handle.is_finished() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    // Don't assert is_finished — the proxy thread might still be in
    // io::copy if shutdown ordering raced. The test already proved
    // what it needs to (active conns through the proxy).
}

// ═══════════════════════════════════════════════════════════════════
// HTTP CONNECT proxy roundtrip (chunk-12-http-proxy)
// ═══════════════════════════════════════════════════════════════════

/// Minimal HTTP CONNECT proxy. Reads until `\r\n\r\n`, parses the
/// CONNECT line, dials upstream, sends 200, bidirectional relay.
///
/// Mirrors `test/integration/proxy.py:127-158`. Sends NO headers
/// (just status + blank line) — same as the python, which is what
/// the C `protocol.c:148-161` works with. A header-sending proxy
/// would terminate the C tinc connection (C-is-WRONG #10).
///
/// One-shot: handles ONE connection then exits.
fn fake_http_proxy() -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
    use std::io::{BufRead, BufReader, Write};
    use std::net::{Shutdown, TcpStream};

    let listener = TcpListener::bind("127.0.0.1:0").expect("http proxy bind");
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (client, _) = listener.accept().expect("http proxy accept");
        let mut reader = BufReader::new(client.try_clone().unwrap());

        // ─── Read CONNECT line ──────────────────────────────────────
        // `CONNECT 127.0.0.1:PORT HTTP/1.1\r\n`
        let mut connect_line = String::new();
        reader.read_line(&mut connect_line).expect("read CONNECT");
        let connect_line = connect_line.trim_end();
        assert!(
            connect_line.starts_with("CONNECT "),
            "expected CONNECT, got {connect_line:?}"
        );
        let target = connect_line
            .strip_prefix("CONNECT ")
            .and_then(|s| s.strip_suffix(" HTTP/1.1"))
            .expect("CONNECT format");
        let target: std::net::SocketAddr = target
            .parse()
            .unwrap_or_else(|e| panic!("parse {target:?}: {e}"));

        // ─── Read until blank line (just `\r\n`) ────────────────────
        // tinc sends `CONNECT ... HTTP/1.1\r\n\r\n` — one CONNECT
        // line + immediate blank. No intermediate headers.
        let mut line = String::new();
        reader.read_line(&mut line).expect("read blank");
        assert_eq!(line, "\r\n", "expected blank line, got {line:?}");

        // ─── Dial upstream ──────────────────────────────────────────
        let upstream = TcpStream::connect(target).expect("upstream connect");

        // ─── Reply: status + blank line, NO headers ─────────────────
        // Same as proxy.py:155. The C only works with this minimal
        // form (C-is-WRONG #10).
        //
        // tinc queues CONNECT + ID in the same flush (`connect.rs`:
        // `send_raw(CONNECT)` then `conn.send(Id)` before any read),
        // so `BufReader` may have buffered the ID line. Drain it
        // before `into_inner()` and forward upstream.
        let leftover = reader.buffer().to_vec();
        let mut client = reader.into_inner();
        client
            .write_all(b"HTTP/1.1 200 OK\r\n\r\n")
            .expect("write 200");
        if !leftover.is_empty() {
            (&upstream).write_all(&leftover).expect("forward leftover");
        }

        // ─── Bidirectional relay ────────────────────────────────────
        // Same as fake_socks5_server.
        let mut c_r = client.try_clone().unwrap();
        let mut u_w = upstream.try_clone().unwrap();
        let t1 = std::thread::spawn(move || {
            let _ = std::io::copy(&mut c_r, &mut u_w);
            let _ = u_w.shutdown(Shutdown::Write);
        });
        let mut u_r = upstream;
        let mut c_w = client;
        let _ = std::io::copy(&mut u_r, &mut c_w);
        let _ = c_w.shutdown(Shutdown::Write);
        let _ = t1.join();
    });
    (addr, handle)
}

/// Two daemons through an HTTP CONNECT proxy. Alice has `Proxy =
/// http 127.0.0.1 PORT` and `ConnectTo = bob`. The fake proxy
/// validates the CONNECT line on the wire, relays to bob, both
/// reach ACK.
///
/// ## What's proven
///
/// 1. **`finish_connecting` HTTP arm**: `CONNECT host:port
///    HTTP/1.1\r\n\r\n` queued via `send_raw`. The proxy asserts
///    on the exact line format.
/// 2. **`metaconn` HTTP intercept**: alice reads `HTTP/1.1 200
///    OK\r\n\r\n` BEFORE `check_gate`. Status line → skip; blank
///    line → skip. Then bob's ID line hits `check_gate` normally.
///    Without the intercept, `atoi("HTTP/1.1")=0` → BadRequest.
/// 3. **Gate closes naturally**: no `proxy_passed` flag. Once
///    `id_h` changes `allow_request`, the intercept condition
///    `allow_request==Id` is false — subsequent lines go straight
///    to `check_gate`.
/// 4. **Full handshake through the relay**: ID + SPTPS + ACK.
#[test]
fn http_proxy_roundtrip() {
    let tmp = TmpGuard::new("httpproxy");
    let alice = Node::new(tmp.path(), "alice", 0xA6);
    let bob = Node::new(tmp.path(), "bob", 0xB6);

    // Spawn the fake HTTP CONNECT proxy first.
    let (proxy_addr, proxy_handle) = fake_http_proxy();

    // Bob: plain config, no proxy.
    bob.write_config(&alice, false);
    // Alice: ConnectTo bob, Proxy = http <fake>.
    let alice = alice.with_conf(&format!(
        "Proxy = http {} {}\n",
        proxy_addr.ip(),
        proxy_addr.port()
    ));
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

    // Poll for active peer conns on both sides.
    let mut alice_ctl = Ctl::connect(&alice);
    let mut bob_ctl = Ctl::connect(&bob);
    poll_until(Duration::from_secs(10), || {
        let a = alice_ctl.dump(6);
        let b = bob_ctl.dump(6);
        if has_active_peer(&a, "bob") && has_active_peer(&b, "alice") {
            Some(())
        } else {
            None
        }
    });

    // Clean up.
    drop(alice_ctl);
    drop(bob_ctl);
    let _ = alice_child.kill();
    let _ = alice_child.wait();
    let _ = bob_child.kill();
    let _ = bob_child.wait();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !proxy_handle.is_finished() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
}
