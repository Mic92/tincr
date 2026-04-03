//! Port of `test/integration/address_cache.py`: prove the daemon
//! actually **dials from the on-disk address cache** after a restart
//! when `hosts/PEER` has no `Address =` line.
//!
//! ## What's already covered elsewhere
//!
//! `addrcache.rs` unit tests prove the file-format roundtrip
//! (`open` → `save` → `load`). They don't prove `daemon.rs:1389`
//! actually wires `AddressCache::open()` into the dial path, or
//! that `add_recent` actually fires from a real handshake. This is
//! the wire test: two real daemons, three restart rounds.
//!
//! ## A small intentional divergence from C
//!
//! C `protocol_misc.c:69-72` (`pong_h`) is gated on `c->outgoing
//! && c->outgoing->timeout` — i.e. it only caches after a RETRY
//! succeeded. On a clean first connect (timeout still 0), C's
//! `pong_h` doesn't cache. C *does* cache on first connect via
//! `graph.c:238` (BecameReachable arm), but only if
//! `n->connection && n->connection->outgoing`.
//!
//! We diverge: `daemon/connect.rs::on_ack` calls `add_recent`
//! UNGATED — every successful ACK caches the address. The comment
//! there cites `protocol_auth.c:939-945` but that's actually
//! `upgrade_h` (legacy upgrade path); the real C `ack_h` has no
//! `add_recent_address` call at all. Our `on_ack` add is a small
//! Rust addition: harmless (idempotent dedup), arguably better
//! (cache earlier, no failure cycle needed).
//!
//! Net effect: round 3 below passes without source changes. The
//! test pins this good behavior — if someone later "fixes" the
//! ungated `add_recent` to match C exactly, this catches it.
//!
//! ## Skipped vs the Python
//!
//! - `:53` invitee address cached after `INVITATION_ACCEPTED` —
//!   the invite path is covered by `tinc_join_against_real_daemon`
//!   and the cache-on-invite is a 1-line `add_recent` we have no
//!   clean hook to assert separately.

use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

// ═══════════════════════════════════════════════════════════════════
// Fixture (cribbed from scripts.rs — tests/ files are separate
// compile units, no shared `mod common`; we copy what we need).

struct TmpGuard(PathBuf);

impl TmpGuard {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "tincd-addrcache-{}-{:?}",
            tag,
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
    fn path(&self) -> &Path {
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

/// Pre-allocate a port: bind to 0, read it back, drop. Race window
/// is sub-ms on loopback. Port is allocated ONCE at `Node::new` and
/// reused across restarts — the cache file bakes in `127.0.0.1:PORT`.
fn alloc_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind 0");
    l.local_addr().unwrap().port()
}

fn drain_stderr(mut child: Child) -> String {
    let _ = child.kill();
    let out = child.wait_with_output().unwrap();
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn wait_for_file(path: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}

/// Poll for `path` existing AND non-empty. Simpler than scripts.rs's
/// full event parser — we just need a "connected" pulse.
fn wait_for_line(path: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.len() > 0 {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

/// SIGTERM + wait. NOT `child.kill()` (= SIGKILL → no Drop →
/// `addrcache::Drop::save()` never runs → cache file never written).
/// SIGTERM → `run()` returns → `Daemon::Drop` → `AddressCache::Drop`
/// → `save()` → disk write.
fn sigterm_and_wait(mut child: Child) {
    let pid = child.id() as libc::pid_t;
    // SAFETY: kill(2) on a known-live child PID.
    unsafe {
        assert_eq!(libc::kill(pid, libc::SIGTERM), 0, "SIGTERM failed");
    }
    let status = child.wait().expect("wait");
    assert!(status.success(), "tincd exited non-zero: {status:?}");
}

/// Minimal node fixture. Dummy device only.
struct Node {
    name: &'static str,
    seed: [u8; 32],
    confbase: PathBuf,
    pidfile: PathBuf,
    socket: PathBuf,
    /// Stable across restarts. Allocated once at `new()`.
    port: u16,
}

impl Node {
    fn new(tmp: &Path, name: &'static str, seed_byte: u8) -> Self {
        Self {
            name,
            seed: [seed_byte; 32],
            confbase: tmp.join(name),
            pidfile: tmp.join(format!("{name}.pid")),
            socket: tmp.join(format!("{name}.socket")),
            port: alloc_port(),
        }
    }

    fn pubkey(&self) -> [u8; 32] {
        use tinc_crypto::sign::SigningKey;
        *SigningKey::from_seed(&self.seed).public_key()
    }

    /// Write config. `peer` for cross-registration. `connect_to` adds
    /// `ConnectTo = peer`. `addr_in_hosts` toggles ONLY the
    /// `Address =` line in `hosts/PEER` — the pubkey is always
    /// written (peer stays trusted; just no dial target). Dummy
    /// device always.
    fn write_config(&self, peer: Option<&Node>, connect_to: bool, addr_in_hosts: bool) {
        use std::os::unix::fs::OpenOptionsExt;
        use tinc_crypto::sign::SigningKey;

        std::fs::create_dir_all(self.confbase.join("hosts")).unwrap();

        let mut tinc_conf = format!(
            "Name = {}\nDeviceType = dummy\nAddressFamily = ipv4\n",
            self.name
        );
        if connect_to {
            let p = peer.expect("connect_to requires peer");
            tinc_conf.push_str(&format!("ConnectTo = {}\n", p.name));
        }
        tinc_conf.push_str("PingTimeout = 1\n");
        std::fs::write(self.confbase.join("tinc.conf"), tinc_conf).unwrap();

        // hosts/SELF — Port only.
        let self_cfg = format!("Port = {}\n", self.port);
        std::fs::write(self.confbase.join("hosts").join(self.name), self_cfg).unwrap();

        // hosts/PEER — pubkey always; Address only if `addr_in_hosts`.
        if let Some(p) = peer {
            let pk = tinc_crypto::b64::encode(&p.pubkey());
            let mut cfg = format!("Ed25519PublicKey = {pk}\n");
            if addr_in_hosts {
                cfg.push_str(&format!("Address = 127.0.0.1 {}\n", p.port));
            }
            std::fs::write(self.confbase.join("hosts").join(p.name), cfg).unwrap();
        }

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

/// Write `CONFBASE/hosts/PEER-up` as a one-line shell appender.
/// Fires after meta handshake → ACK → graph runs → BecameReachable
/// (`gossip.rs:1051`). By then `add_recent` has already fired in
/// `on_ack` (`connect.rs`). Shebang required — direct `execve()`,
/// not `sh -c`; shebang-less script fails `ENOEXEC`.
fn write_host_up_script(confbase: &Path, peer: &str, log: &Path) {
    let path = confbase.join("hosts").join(format!("{peer}-up"));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let body = format!("#!/bin/sh\necho connected >> '{}'\n", log.display());
    std::fs::write(&path, body).unwrap();
    let mut perm = std::fs::metadata(&path).unwrap().permissions();
    perm.set_mode(0o755);
    std::fs::set_permissions(&path, perm).unwrap();
}

// ═══════════════════════════════════════════════════════════════════

/// `address_cache.py` port. Four assertions, two restarts.
///
/// The mechanism (`addrcache.rs`):
/// - `AddressCache::open()` reads `CONFBASE/cache/NODENAME` (one
///   `SocketAddr::Display` per line, `:112-130`). Cached addrs go
///   FIRST in the dial order (`:84-90`). Config `Address =` lines
///   go after.
/// - `on_ack` (`daemon/connect.rs`) calls `add_recent()` ungated
///   on every successful ACK. Dedups + prepends.
/// - `Drop` calls `save()` (`:203-207`). Writes the file. SIGKILL
///   skips Drop → file not written. SIGTERM → graceful → written.
///
/// Why this isn't already covered: the `addrcache.rs` unit tests
/// prove `open`/`save`/`load` roundtrip (file format). They don't
/// prove the daemon CALLS `open()` correctly (`daemon.rs:1389`) or
/// that `add_recent` actually fires from a real handshake. This is
/// the wire test.
#[test]
fn restart_dials_from_cache() {
    let tmp = TmpGuard::new("restart_dials_from_cache");
    let alice = Node::new(tmp.path(), "alice", 0xA1);
    let bob = Node::new(tmp.path(), "bob", 0xB0);

    let alice_log = tmp.path().join("alice.connected.log");
    let cache_file = alice.confbase.join("cache").join("bob");

    // ─── Round 1: connect with `Address =` in hosts/ ────────────────
    // Normal config. Alice dials bob. Bob listens.
    bob.write_config(Some(&alice), false, /*addr_in_hosts*/ true);
    alice.write_config(Some(&bob), true, /*addr_in_hosts*/ true);
    write_host_up_script(&alice.confbase, "bob", &alice_log);

    let bob_child = bob.spawn();
    if !wait_for_file(&bob.socket, Duration::from_secs(5)) {
        panic!("r1 bob setup failed:\n{}", drain_stderr(bob_child));
    }
    let alice_child = alice.spawn();
    if !wait_for_file(&alice.socket, Duration::from_secs(5)) {
        panic!("r1 alice setup failed:\n{}", drain_stderr(alice_child));
    }

    // Wait for host-up. PONG fires after meta handshake → ACK →
    // graph runs → reachable → host-up. By then `add_recent` has
    // fired (on_ack arm).
    if !wait_for_line(&alice_log, Duration::from_secs(10)) {
        let a = drain_stderr(alice_child);
        let b = drain_stderr(bob_child);
        panic!("round 1: alice never connected to bob\n--- alice ---\n{a}\n--- bob ---\n{b}");
    }

    // ─── Assert: alice cached bob's address ─────────────────────────
    // address_cache.py:67. The file exists. Contents: one line,
    // `127.0.0.1:BOBPORT` (SocketAddr::Display format).
    //
    // It's NOT written yet — `add_recent` is in-memory; `save()` is
    // on Drop. Kill alice gracefully first.
    sigterm_and_wait(alice_child);
    assert!(
        cache_file.exists(),
        "cache file should exist after SIGTERM; cache dir: {:?}",
        std::fs::read_dir(alice.confbase.join("cache"))
            .ok()
            .map(|d| d.flatten().map(|e| e.path()).collect::<Vec<_>>())
    );
    let contents = std::fs::read_to_string(&cache_file).unwrap();
    let expected = format!("127.0.0.1:{}\n", bob.port);
    assert_eq!(contents, expected, "cache file should have bob's address");

    // ─── Assert: bob did NOT cache alice's outgoing address ─────────
    // address_cache.py:70. Bob is listener; alice dialed FROM an
    // ephemeral port. `on_ack` (`connect.rs`) only caches when
    // `conn.outgoing` is `Some`. Bob has no Outgoing for alice. No
    // `add_recent` → no cache file (or empty file — `save()` may
    // still create the dir/file for other nodes' caches; check
    // contents not just existence).
    sigterm_and_wait(bob_child);
    let bob_cache = bob.confbase.join("cache").join("alice");
    if bob_cache.exists() {
        let bc = std::fs::read_to_string(&bob_cache).unwrap();
        assert!(
            bc.trim().is_empty(),
            "listener should NOT cache dialer's ephemeral port; found: {bc:?}"
        );
    }

    // ─── Round 2: delete cache dir, reconnect, dir recreated ────────
    // address_cache.py:80. Same config — `Address =` still present.
    // Just proves `save()` does `create_dir_all` (`addrcache.rs:188`).
    std::fs::remove_dir_all(alice.confbase.join("cache")).unwrap();
    std::fs::remove_file(&alice_log).ok();
    // Daemon::Drop unlinks pidfile/socket; should be clean. Belt-and-
    // suspenders in case a prior round crashed mid-teardown.
    std::fs::remove_file(&alice.pidfile).ok();
    std::fs::remove_file(&bob.pidfile).ok();

    let bob_child = bob.spawn();
    if !wait_for_file(&bob.socket, Duration::from_secs(5)) {
        panic!("r2 bob setup failed:\n{}", drain_stderr(bob_child));
    }
    let alice_child = alice.spawn();
    if !wait_for_file(&alice.socket, Duration::from_secs(5)) {
        panic!("r2 alice setup failed:\n{}", drain_stderr(alice_child));
    }
    if !wait_for_line(&alice_log, Duration::from_secs(10)) {
        let a = drain_stderr(alice_child);
        let b = drain_stderr(bob_child);
        panic!("round 2: alice never reconnected\n--- alice ---\n{a}\n--- bob ---\n{b}");
    }
    sigterm_and_wait(alice_child);
    sigterm_and_wait(bob_child);
    assert!(
        cache_file.exists(),
        "cache dir should be recreated by save() create_dir_all"
    );

    // ─── Round 3: NO `Address =` in hosts/. Dial from cache. ────────
    // address_cache.py:87-96. THE assertion. Rewrite alice's
    // `hosts/bob` without the `Address =` line. ConnectTo stays.
    // `resolve_config_addrs()` (`daemon.rs:1388`) returns empty.
    // `AddressCache::open()` loads cache file → addrs = [127.0.0.1:BOBPORT].
    // `try_connect` (`outgoing.rs`) → `next_addr()` → dials.
    alice.write_config(Some(&bob), true, /*addr_in_hosts*/ false); // ← FALSE
    // write_config rewrote hosts/; the bob-up script lives there.
    // Re-install it.
    write_host_up_script(&alice.confbase, "bob", &alice_log);
    std::fs::remove_file(&alice_log).ok();
    std::fs::remove_file(&alice.pidfile).ok();
    std::fs::remove_file(&bob.pidfile).ok();

    // Sanity: cache file survived the config rewrite (write_config
    // doesn't touch cache/).
    assert!(
        cache_file.exists(),
        "cache file must survive config rewrite for round 3 to mean anything"
    );
    // Sanity: hosts/bob really has no Address line now.
    let hosts_bob = std::fs::read_to_string(alice.confbase.join("hosts").join("bob")).unwrap();
    assert!(
        !hosts_bob.contains("Address"),
        "hosts/bob should have no Address= line in round 3; got:\n{hosts_bob}"
    );

    let bob_child = bob.spawn();
    if !wait_for_file(&bob.socket, Duration::from_secs(5)) {
        panic!("r3 bob setup failed:\n{}", drain_stderr(bob_child));
    }
    let alice_child = alice.spawn();
    if !wait_for_file(&alice.socket, Duration::from_secs(5)) {
        panic!("r3 alice setup failed:\n{}", drain_stderr(alice_child));
    }

    // The proof. With no `Address =` and an empty/missing cache,
    // alice would have nothing to dial. `next_addr()` returns None.
    // `try_connect` → `ConnectAttempt::Exhausted` → retry timer arms.
    // Never connects. host-up never fires. This wait would time out.
    if !wait_for_line(&alice_log, Duration::from_secs(10)) {
        let a = drain_stderr(alice_child);
        let b = drain_stderr(bob_child);
        panic!(
            "round 3: dial-from-cache FAILED. alice has no Address= and \
             must use cache file. Cache contents: {:?}\n\
             --- alice stderr ---\n{a}\n--- bob stderr ---\n{b}",
            std::fs::read_to_string(&cache_file).ok()
        );
    }

    sigterm_and_wait(alice_child);
    sigterm_and_wait(bob_child);
}
