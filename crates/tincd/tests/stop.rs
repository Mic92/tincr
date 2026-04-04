//! Integration test: spawn real `tincd`, control it via the socket
//! protocol, daemon exits 0.
//!
//! ## Why this test exists
//!
//! `tinc-tools/tests/tinc_cli.rs::fake_daemon_setup` is the INVERSE:
//! it stands up a fake daemon and lets the real `tinc` CLI connect.
//! THIS test stands up a real daemon and connects to it directly.
//!
//! Together they prove the protocol from both sides. The full proof
//! (real `tinc` CLI → real `tincd`) is the next step but needs
//! `CARGO_BIN_EXE_tinc` from another crate's binary, which is
//! awkward (cargo only sets `CARGO_BIN_EXE_*` for the crate-under-
//! test's own binaries). For now: speak the protocol by hand.
//!
//! ## What's proven
//!
//! - `Daemon::setup`: tinc.conf read, dummy device opened, control
//!   socket bound, pidfile written
//! - `Daemon::run`: the dispatch enum compiles inside a real loop,
//!   `tick → turn → match` works
//! - `tinc-event`: a real epoll wakes on a real unix socket; timers
//!   tick (Ping fires and re-arms)
//! - `proto.rs`: the greeting exchange + REQ_STOP path
//! - `conn.rs`: feed/send/flush over a real fd
//! - `control.rs`: pidfile format readable by the same parser
//!   `tinc-tools::Pidfile::read` uses
//!
//! ## SelfPipe singleton
//!
//! `Daemon::setup` calls `SelfPipe::new()` which is a process
//! singleton (panics if called twice). Tests can't construct a
//! `Daemon` in-process. Hence: subprocess. The subprocess is its
//! own process; SelfPipe is fresh.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

mod common;
use common::{
    TmpGuard, read_cookie, read_tcp_addr, tincd_bin, wait_for_file, write_ed25519_privkey,
};

fn tmp(tag: &str) -> TmpGuard {
    TmpGuard::new("stop", tag)
}

/// Write a minimal config: `tinc.conf`, `hosts/testnode`, AND
/// `ed25519_key.priv`.
///
/// `Port = 0` is critical: the daemon binds TCP+UDP listeners now.
/// Port 655 would clash between parallel test threads. Port 0 =
/// kernel picks. Each test gets its own port.
///
/// `AddressFamily = ipv4` reduces to one listener. v6 might be
/// disabled in the build sandbox.
///
/// `Port` is HOST-tagged (per `tincctl.c:1751`). Goes in `hosts/
/// testnode`. The daemon's `read_host_config` merges it.
///
/// `ed25519_key.priv` is required since chunk 4a (`net_setup.c:803`
/// loads it; we forbid the legacy fallback). The key is deterministic
/// (seeded from a constant) so tests are reproducible. Mode 0600 to
/// avoid the perm warning. The daemon never USES this key in tests
/// that don't peer-connect, but setup() loads it unconditionally
/// (the C does too — you can't run tincd without a key).
///
/// Returns the daemon's PUBLIC key. Tests that don't peer-connect
/// ignore it; `peer_handshake_reaches_done` needs it for the SPTPS
/// initiator side.
fn write_config(confbase: &std::path::Path) -> [u8; 32] {
    std::fs::create_dir_all(confbase.join("hosts")).unwrap();
    std::fs::write(
        confbase.join("tinc.conf"),
        "Name = testnode\nDeviceType = dummy\nAddressFamily = ipv4\n",
    )
    .unwrap();
    std::fs::write(confbase.join("hosts").join("testnode"), "Port = 0\n").unwrap();

    // Daemon's private key. Seed `[0x42; 32]` — distinct from any
    // test-helper seeds (keys.rs uses 1..11, conn.rs uses 1/2/10/20).
    let seed = [0x42; 32];
    write_ed25519_privkey(confbase, &seed);
    common::pubkey_from_seed(&seed)
}

// ═══════════════════════════════════════════════════════════════════

/// THE walking-skeleton proof. Spawn tincd, connect to its control
/// socket, do the greeting dance, send REQ_STOP, daemon exits 0.
///
/// Exact same protocol bytes as `tinc-tools/tests/tinc_cli.rs::
/// fake_daemon_setup` expects from a daemon. If THIS passes and
/// `fake_daemon_setup`'s tests pass, both sides agree on the wire.
#[test]
fn spawn_connect_stop() {
    let tmp = tmp("connect-stop");
    let confbase = tmp.path().join("vpn");
    let pidfile = tmp.path().join("tinc.pid");
    let socket = tmp.path().join("tinc.socket");

    write_config(&confbase);

    // ─── spawn ────────────────────────────────────────────────────
    // RUST_LOG=tincd=debug so failure stderr is informative.
    let mut child = Command::new(tincd_bin())
        .arg("-c")
        .arg(&confbase)
        .arg("--pidfile")
        .arg(&pidfile)
        .arg("--socket")
        .arg(&socket)
        .env("RUST_LOG", "tincd=debug")
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tincd");

    // ─── wait for ready ──────────────────────────────────────────
    // The daemon writes the pidfile in setup(), AFTER which it
    // binds the socket. Wait for the socket file.
    assert!(
        wait_for_file(&socket),
        "tincd didn't bind socket; stderr: {}",
        // Best-effort stderr drain. The child is still running
        // (or crashed); kill + wait + read.
        {
            let _ = child.kill();
            let out = child.wait_with_output().unwrap();
            String::from_utf8_lossy(&out.stderr).into_owned()
        }
    );

    // ─── connect + greeting ──────────────────────────────────────
    let cookie = read_cookie(&pidfile);
    assert_eq!(cookie.len(), 64, "cookie is 64 hex chars");

    let stream = UnixStream::connect(&socket).expect("connect to tincd");
    let mut reader = BufReader::new(&stream);
    let mut writer = &stream;

    // Send ID. `tinc-tools/ctl.rs:491`: `"0 ^<cookie> 0\n"`.
    writeln!(writer, "0 ^{cookie} 0").unwrap();

    // Recv line 1: daemon's send_id. `"0 testnode 17.7\n"`.
    let mut line1 = String::new();
    reader.read_line(&mut line1).unwrap();
    assert_eq!(line1, "0 testnode 17.7\n", "daemon greeting line 1");

    // Recv line 2: ACK. `"4 0 <pid>\n"`.
    let mut line2 = String::new();
    reader.read_line(&mut line2).unwrap();
    let mut t2 = line2.split_whitespace();
    assert_eq!(t2.next(), Some("4"), "ACK code");
    assert_eq!(t2.next(), Some("0"), "CTL_VERSION");
    // pid is some positive integer (the daemon's process id).
    let pid: u32 = t2.next().unwrap().parse().unwrap();
    assert!(pid > 0);

    // ─── send REQ_STOP ───────────────────────────────────────────
    // `"18 0\n"` — CONTROL=18, REQ_STOP=0.
    writeln!(writer, "18 0").unwrap();

    // C protocol: the ack `"18 0 0"` MAY OR MAY NOT arrive. C
    // `tincctl.c:679-681` does `while(recvline()) {}` — drain until
    // EOF, ignoring contents. The C daemon QUEUES the ack but
    // `event_loop()` exits before flushing (the WRITE event would
    // fire on the next turn, but `running=false` means there is no
    // next turn). The connection closes with the ack stuck in outbuf.
    //
    // Our daemon does the same. The CLI's `cmd_stop` (`tinc-tools/
    // src/cmd/ctl_simple.rs:186`) does `while let Ok(Some(_)) =
    // ctl.recv_line()` — same drain-to-EOF.
    //
    // EOF is the contract. It proves the daemon closed the connection
    // (during `Daemon::drop` when the slotmap drops).
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break, // EOF — daemon closed
            Ok(_) => {}     // ack or anything else; drain, don't check
            Err(e) => panic!("read error after STOP: {e}"),
        }
    }

    // ─── daemon exits ────────────────────────────────────────────
    // After REQ_STOP, `running = false`, the loop exits, daemon
    // returns 0. Wait with timeout.
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        assert!(
            Instant::now() < deadline,
            "tincd didn't exit after REQ_STOP"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(status.success(), "tincd exit status: {status:?}");

    // ─── cleanup verification ────────────────────────────────────
    // Daemon::drop unlinks pidfile; ControlSocket::drop unlinks
    // socket. Both should be gone.
    assert!(!pidfile.exists(), "pidfile should be unlinked on exit");
    assert!(!socket.exists(), "socket should be unlinked on exit");
}

/// SIGTERM also stops the daemon. Proves the SelfPipe + signal
/// handler path. Same setup; instead of sending REQ_STOP, send a
/// signal.
#[test]
fn sigterm_stops() {
    let tmp = tmp("sigterm");
    let confbase = tmp.path().join("vpn");
    let pidfile = tmp.path().join("tinc.pid");
    let socket = tmp.path().join("tinc.socket");

    write_config(&confbase);

    let mut child = Command::new(tincd_bin())
        .arg("-c")
        .arg(&confbase)
        .arg("--pidfile")
        .arg(&pidfile)
        .arg("--socket")
        .arg(&socket)
        .env("RUST_LOG", "tincd=info")
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tincd");

    assert!(wait_for_file(&socket), "tincd didn't bind socket");

    // ─── SIGTERM ──────────────────────────────────────────────────
    // The pidfile has the pid in it (same as `child.id()`, but
    // reading it from the pidfile proves the format).
    let content = std::fs::read_to_string(&pidfile).unwrap();
    let pid: u32 = content.split_whitespace().next().unwrap().parse().unwrap();
    assert_eq!(pid, child.id(), "pidfile has the right pid");

    // SAFETY: kill(2) on a valid pid. We just spawned this child;
    // it's alive (wait_for_file confirmed it bound the socket).
    // SIGTERM is the polite shutdown signal.
    #[allow(unsafe_code)]
    unsafe {
        let rc = libc::kill(pid as libc::pid_t, libc::SIGTERM);
        assert_eq!(rc, 0, "kill failed: {}", std::io::Error::last_os_error());
    }

    // ─── daemon exits ────────────────────────────────────────────
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        assert!(Instant::now() < deadline, "tincd didn't exit on SIGTERM");
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(status.success(), "tincd should exit cleanly on SIGTERM");
    assert!(!pidfile.exists());
}

/// Second tincd on the same socket refuses to start. The connect-
/// probe in `ControlSocket::bind` sees the first daemon listening.
#[test]
fn second_daemon_refused() {
    let tmp = tmp("second");
    let confbase = tmp.path().join("vpn");
    let pidfile = tmp.path().join("tinc.pid");
    let pidfile2 = tmp.path().join("tinc2.pid");
    let socket = tmp.path().join("tinc.socket");

    write_config(&confbase);

    let mut first = Command::new(tincd_bin())
        .arg("-c")
        .arg(&confbase)
        .arg("--pidfile")
        .arg(&pidfile)
        .arg("--socket")
        .arg(&socket)
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    assert!(wait_for_file(&socket));

    // Second daemon, same socket, different pidfile (so it doesn't
    // clobber the first's). Should fail in setup().
    let second = Command::new(tincd_bin())
        .arg("-c")
        .arg(&confbase)
        .arg("--pidfile")
        .arg(&pidfile2)
        .arg("--socket")
        .arg(&socket)
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    assert!(
        !second.status.success(),
        "second daemon should fail; stderr: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    let stderr = String::from_utf8_lossy(&second.stderr);
    assert!(
        stderr.contains("already in use"),
        "expected 'already in use' in stderr; got: {stderr}"
    );

    // Clean up first daemon.
    let _ = first.kill();
    let _ = first.wait();
}

/// Pingtimer fires and re-arms. We can't observe this directly
/// (it's internal), but: leave the daemon running for >2s (initial
/// pingtimeout=5s is too long; reduce via config? — no, the
/// skeleton doesn't read PingTimeout. Ugh.)
///
/// What we CAN test: the daemon stays alive for several seconds
/// without crashing. If `on_ping_tick` forgot to re-arm, `tick()`
/// returns `None` next time → `turn(None)` blocks forever → daemon
/// is unresponsive. Connect after 2s to prove it's still listening.
///
/// (Weaker than a direct timer-fired check but proves the loop
/// stays alive across multiple iterations. The `pingtimeout=5s`
/// means the timer fires once at most in this test. Chunk 3 reads
/// PingTimeout from config and we can set it to 1s.)
#[test]
fn stays_alive_across_iterations() {
    let tmp = tmp("alive");
    let confbase = tmp.path().join("vpn");
    let pidfile = tmp.path().join("tinc.pid");
    let socket = tmp.path().join("tinc.socket");

    // Override write_config's tinc.conf to add `PingTimeout = 1`.
    // The 6-second sleep was the bottleneck (`stop.rs::stays_alive`
    // dominated the suite at 6.01s). PingTimeout=1 means the timer
    // fires after 1 second; sleeping 2 seconds spans at least one
    // fire-and-re-arm. Suite drops from 6s to 2s.
    write_config(&confbase);
    std::fs::write(
        confbase.join("tinc.conf"),
        "Name = testnode\nDeviceType = dummy\nAddressFamily = ipv4\nPingTimeout = 1\n",
    )
    .unwrap();

    let mut child = Command::new(tincd_bin())
        .arg("-c")
        .arg(&confbase)
        .arg("--pidfile")
        .arg(&pidfile)
        .arg("--socket")
        .arg(&socket)
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    assert!(wait_for_file(&socket));

    // Sleep across at least one timer tick. PingTimeout=1 → first
    // tick at +1s, re-arm at +1s thereafter. 2s spans at least one.
    std::thread::sleep(Duration::from_secs(2));

    // Daemon should still be alive (no panic, no exit).
    assert!(
        child.try_wait().unwrap().is_none(),
        "tincd died during sleep"
    );

    // And still responsive: connect succeeds.
    let _stream = UnixStream::connect(&socket).expect("daemon still listening after 2s");

    // Clean up.
    let _ = child.kill();
    let _ = child.wait();
}

/// Missing tinc.conf → setup fails. The error message comes from
/// `tinc-conf::read_server_config`.
#[test]
fn missing_config_fails() {
    let tmp = tmp("noconfig");
    let confbase = tmp.path().join("vpn");
    let pidfile = tmp.path().join("tinc.pid");
    let socket = tmp.path().join("tinc.socket");

    // confbase exists but no tinc.conf inside.
    std::fs::create_dir_all(&confbase).unwrap();

    let out = Command::new(tincd_bin())
        .arg("-c")
        .arg(&confbase)
        .arg("--pidfile")
        .arg(&pidfile)
        .arg("--socket")
        .arg(&socket)
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    assert!(!out.status.success());
    // Don't pin the exact message (tinc-conf owns it). Just: it
    // mentions tinc.conf or config.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.to_lowercase().contains("tinc.conf") || stderr.to_lowercase().contains("config"),
        "expected config error in stderr; got: {stderr}"
    );

    // No pidfile/socket created on setup failure.
    assert!(!pidfile.exists());
    assert!(!socket.exists());
}

/// `Name` missing from config → `setup_myself` fails. C
/// `net_setup.c:778`: `logger(..., "Name for tinc daemon required!")`.
#[test]
fn missing_name_fails() {
    let tmp = tmp("noname");
    let confbase = tmp.path().join("vpn");
    let pidfile = tmp.path().join("tinc.pid");
    let socket = tmp.path().join("tinc.socket");

    std::fs::create_dir_all(&confbase).unwrap();
    // Config without Name.
    std::fs::write(confbase.join("tinc.conf"), "DeviceType = dummy\n").unwrap();

    let out = Command::new(tincd_bin())
        .arg("-c")
        .arg(&confbase)
        .arg("--pidfile")
        .arg(&pidfile)
        .arg("--socket")
        .arg(&socket)
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Name") && stderr.contains("required"),
        "expected 'Name required' error; got: {stderr}"
    );
}

/// Bad cookie in greeting → connection dropped. Proves the
/// `handle_id` cookie check + `terminate` path.
#[test]
fn bad_cookie_dropped() {
    let tmp = tmp("badcookie");
    let confbase = tmp.path().join("vpn");
    let pidfile = tmp.path().join("tinc.pid");
    let socket = tmp.path().join("tinc.socket");

    write_config(&confbase);

    let mut child = Command::new(tincd_bin())
        .arg("-c")
        .arg(&confbase)
        .arg("--pidfile")
        .arg(&pidfile)
        .arg("--socket")
        .arg(&socket)
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    assert!(wait_for_file(&socket));

    // Connect with WRONG cookie.
    let stream = UnixStream::connect(&socket).unwrap();
    let mut reader = BufReader::new(&stream);
    let mut writer = &stream;
    let bad_cookie = "f".repeat(64);
    writeln!(writer, "0 ^{bad_cookie} 0").unwrap();

    // Daemon drops the connection. read_line returns 0 (EOF).
    let mut line = String::new();
    let n = reader.read_line(&mut line).unwrap();
    assert_eq!(n, 0, "daemon should close connection on bad cookie");

    // Daemon is still alive and accepting NEW connections.
    drop(stream);
    let cookie = read_cookie(&pidfile);
    let stream2 = UnixStream::connect(&socket).unwrap();
    let mut reader2 = BufReader::new(&stream2);
    let mut writer2 = &stream2;
    writeln!(writer2, "0 ^{cookie} 0").unwrap();
    let mut line1 = String::new();
    reader2.read_line(&mut line1).unwrap();
    assert_eq!(line1, "0 testnode 17.7\n");

    // Clean up.
    let _ = child.kill();
    let _ = child.wait();
}

/// TCP control connection. Same protocol bytes as `spawn_connect_stop`
/// but over TCP instead of unix socket. Proves:
///
/// - `open_listeners` actually binds (port in pidfile is real)
/// - `IoWhat::Tcp(i)` arm dispatches to `on_tcp_accept`
/// - `on_tcp_accept` does `unmap` + `is_local` + `configure_tcp`
/// - `Connection::new_meta` sets the right initial state
/// - The greeting + STOP path is transport-agnostic (the dispatch
///   from `id_h`'s `^` branch onward doesn't care which `accept`
///   produced the fd)
/// - `pidfile_addr` writes a connectable addr (the unspec→loopback
///   mapping; THIS is the test for `init_control:164-173`)
/// - Tarpit doesn't fire (peer is `127.0.0.1`, `is_local` exempts)
///
/// Runs alongside `spawn_connect_stop`; each picks a different
/// kernel-assigned port (Port=0). The daemon also opens a unix
/// socket; we don't touch it here.
///
/// What this DOESN'T prove: tarpit firing (loopback is exempt). The
/// `listen.rs::tarpit_*` unit tests cover the bucket arithmetic.
#[test]
fn tcp_connect_stop() {
    use std::net::TcpStream;

    let tmp = tmp("tcp-stop");
    let confbase = tmp.path().join("vpn");
    let pidfile = tmp.path().join("tinc.pid");
    let socket = tmp.path().join("tinc.socket");

    write_config(&confbase);

    let mut child = Command::new(tincd_bin())
        .arg("-c")
        .arg(&confbase)
        .arg("--pidfile")
        .arg(&pidfile)
        .arg("--socket")
        .arg(&socket)
        .env("RUST_LOG", "tincd=debug")
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tincd");

    // Wait for the unix socket file (proxy for "setup done"). The
    // TCP listener is bound BEFORE the unix socket (setup order:
    // listeners → cookie → pidfile → unix socket); waiting on the
    // socket file means the TCP listener is also ready.
    assert!(wait_for_file(&socket), "tincd setup failed; stderr: {}", {
        let _ = child.kill();
        let out = child.wait_with_output().unwrap();
        String::from_utf8_lossy(&out.stderr).into_owned()
    });

    // ─── read TCP addr from pidfile ────────────────────────────
    // The unspec→loopback mapping (`init_control:164-173`) is
    // tested implicitly: if the addr were `0.0.0.0`, the connect
    // would fail (or connect to something unexpected).
    let cookie = read_cookie(&pidfile);
    let tcp_addr = read_tcp_addr(&pidfile);
    assert!(
        tcp_addr.ip().is_loopback(),
        "pidfile addr should be loopback (got {tcp_addr})"
    );
    assert_ne!(tcp_addr.port(), 0, "port should be kernel-assigned, not 0");

    // ─── connect over TCP ─────────────────────────────────────
    let stream = TcpStream::connect(tcp_addr).expect("TCP connect to tincd");
    let mut reader = BufReader::new(&stream);
    let mut writer = &stream;

    // ─── same greeting dance as unix ───────────────────────────
    // The protocol is transport-agnostic. `^cookie` over TCP gets
    // the same `id_h` `^` branch as over unix. The C does the same:
    // `handle_new_meta_connection` and `handle_new_unix_connection`
    // both register `handle_meta_io`, which calls the same
    // `receive_meta` → `receive_request` → `id_h`.
    writeln!(writer, "0 ^{cookie} 0").unwrap();

    let mut line1 = String::new();
    reader.read_line(&mut line1).unwrap();
    assert_eq!(line1, "0 testnode 17.7\n", "daemon greeting (TCP)");

    let mut line2 = String::new();
    reader.read_line(&mut line2).unwrap();
    assert!(line2.starts_with("4 0 "), "ACK line: {line2:?}");

    // ─── STOP + drain ─────────────────────────────────────────
    writeln!(writer, "18 0").unwrap();
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break, // EOF
            Ok(_) => {}
            Err(e) => panic!("read error after STOP: {e}"),
        }
    }

    // ─── daemon exits 0 ───────────────────────────────────────
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("tincd didn't exit after STOP (TCP)");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(status.success(), "tincd exit nonzero: {status:?}");
}

/// `hosts/NAME` missing → daemon starts anyway, port defaults to 655.
/// C `net_setup.c:786` calls `read_host_config` and DOESN'T check the
/// return value. We match: warn + continue.
///
/// We can't actually let it bind 655 (might clash with something on
/// the build host, or with another test). So: this test ONLY checks
/// the daemon doesn't crash on missing hosts/NAME by overriding Port
/// in tinc.conf instead. Wait — Port is HOST-tagged. Can it go in
/// tinc.conf?
///
/// Per the C: `lookup_config("Port")` searches the merged tree.
/// `read_server_config` merges tinc.conf; `read_host_config` merges
/// hosts/NAME. If hosts/NAME is missing, the tree only has tinc.conf
/// entries. So putting Port in tinc.conf works — the C `lookup`
/// doesn't care which file an entry came from. The `vars.rs` HOST
/// tag is for `cmd_config set` (which file to WRITE to), not lookup.
///
/// What this proves: `read_host_config` is genuinely optional. A
/// freshly `tinc init`-ed daemon (which has hosts/NAME) is fine; a
/// hand-crafted minimal config (tinc.conf only) is also fine.
#[test]
fn missing_hosts_file_ok() {
    let tmp = tmp("nohosts");
    let confbase = tmp.path().join("vpn");
    let pidfile = tmp.path().join("tinc.pid");
    let socket = tmp.path().join("tinc.socket");

    // tinc.conf + private key, but NO hosts/ dir. Port goes in
    // tinc.conf (HOST-tagged, but lookup doesn't care which file —
    // see doc). The key IS required (chunk 4a); hosts/ is the
    // optional one being tested.
    //
    // Can't use write_config() here — it creates hosts/.
    std::fs::create_dir_all(&confbase).unwrap();
    std::fs::write(
        confbase.join("tinc.conf"),
        "Name = testnode\nDeviceType = dummy\nAddressFamily = ipv4\nPort = 0\n",
    )
    .unwrap();
    write_ed25519_privkey(&confbase, &[0x42; 32]);
    // Precondition: hosts/ doesn't exist. THIS is what's tested.
    assert!(!confbase.join("hosts").exists());

    let mut child = Command::new(tincd_bin())
        .arg("-c")
        .arg(&confbase)
        .arg("--pidfile")
        .arg(&pidfile)
        .arg("--socket")
        .arg(&socket)
        .env("RUST_LOG", "tincd=warn")
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // Daemon starts (doesn't crash on missing hosts/testnode).
    assert!(
        wait_for_file(&socket),
        "daemon should start without hosts/; stderr: {}",
        {
            let _ = child.kill();
            let out = child.wait_with_output().unwrap();
            String::from_utf8_lossy(&out.stderr).into_owned()
        }
    );

    // The pidfile addr is real (port from tinc.conf was respected).
    let addr = read_tcp_addr(&pidfile);
    assert_ne!(addr.port(), 0);

    let _ = child.kill();
    // Stderr should mention the warning. Matching exact text is
    // brittle; matching the substring `hosts/testnode` is enough
    // to prove the warn-path executed (vs silently skipping).
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("hosts/testnode"),
        "expected hosts-missing warning; stderr: {stderr}"
    );
}

/// UDP packets sent to the daemon don't crash it and don't busy-spin.
/// `IoWhat::Udp(i)` is wired now (the listener IS bound). The arm
/// drains and discards. Proves: a stray UDP packet (from a peer that
/// thinks we're a node, or a network probe) doesn't burn CPU.
///
/// We send a packet, wait briefly, verify the daemon is still alive
/// AND still responsive over the unix socket. "Doesn't busy-spin"
/// is harder to prove directly without checking CPU usage; the
/// implicit proof is that the unix-socket greeting still works
/// promptly (a busy-spinning loop would delay it).
///
/// Reading the daemon's UDP port: the pidfile only has the TCP port,
/// and without `bind_reusing_port` (deferred), TCP and UDP get
/// DIFFERENT kernel-assigned ports. We read `/proc/PID/net/udp` —
/// Linux-only. On non-Linux this test still compiles but skips at
/// runtime via the `read_to_string` failure (the path doesn't exist;
/// we early-return). Correct: it's a defense-in-depth check, not
/// a wire-format proof.
#[test]
fn udp_stray_packet_drained() {
    use std::net::UdpSocket;

    let tmp = tmp("udp-stray");
    let confbase = tmp.path().join("vpn");
    let pidfile = tmp.path().join("tinc.pid");
    let socket = tmp.path().join("tinc.socket");

    write_config(&confbase);

    let mut child = Command::new(tincd_bin())
        .arg("-c")
        .arg(&confbase)
        .arg("--pidfile")
        .arg(&pidfile)
        .arg("--socket")
        .arg(&socket)
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    assert!(wait_for_file(&socket));

    // ─── find the daemon's UDP port via /proc ──────────────────
    let pid_str = std::fs::read_to_string(&pidfile).unwrap();
    let daemon_pid: u32 = pid_str.split_whitespace().next().unwrap().parse().unwrap();
    let Ok(udp_table) = std::fs::read_to_string(format!("/proc/{daemon_pid}/net/udp")) else {
        // Not Linux. Skip gracefully.
        eprintln!("/proc/PID/net/udp not available; skipping UDP probe");
        let _ = child.kill();
        let _ = child.wait();
        return;
    };

    // /proc/PID/net/udp shows ALL udp sockets visible to the
    // process's netns — not just the process's own. Filter by
    // matching against the inodes in /proc/PID/fd/* symlinks.
    // Hmm, that's a lot of plumbing.
    //
    // SIMPLER filter: our daemon is the only thing in this test
    // binding UDP on 0.0.0.0 with the inode-matching uid. Actually
    // no — other tests in the same process also spawn daemons.
    //
    // SIMPLEST: the local_address `00000000:PORT` where the inode
    // appears in /proc/PID/fd/. socket symlinks are "socket:[INODE]".
    let socket_inodes: std::collections::HashSet<String> =
        std::fs::read_dir(format!("/proc/{daemon_pid}/fd"))
            .unwrap()
            .filter_map(|e| e.ok())
            .filter_map(|e| std::fs::read_link(e.path()).ok())
            .filter_map(|target| {
                target
                    .to_str()?
                    .strip_prefix("socket:[")?
                    .strip_suffix("]")
                    .map(String::from)
            })
            .collect();

    // /proc/net/udp format: `sl  local_address rem_address  ... inode`
    // Column 1 (0-indexed) is local_address, column 9 is inode.
    let udp_port = udp_table
        .lines()
        .skip(1) // header
        .find_map(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            let local = cols.get(1)?;
            let inode = cols.get(9)?;
            if !socket_inodes.contains(*inode) {
                return None;
            }
            // local is "00000000:HEXPORT" for our 0.0.0.0 bind.
            local
                .strip_prefix("00000000:")
                .and_then(|hex_port| u16::from_str_radix(hex_port, 16).ok())
        });

    let Some(udp_port) = udp_port else {
        // Daemon has no UDP socket on 0.0.0.0 visible in /proc.
        // This would be a real failure (open_listeners didn't bind
        // UDP) but might also be a /proc parsing issue. Panic.
        let _ = child.kill();
        let out = child.wait_with_output().unwrap();
        panic!(
            "no UDP socket found in /proc/{daemon_pid}/net/udp; \
             stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };

    // ─── send garbage ─────────────────────────────────────────
    // 5 packets. The daemon's `on_udp_drain` reads and discards.
    // If it didn't drain (level-triggered, fd stays ready), the
    // loop would spin.
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    let target = format!("127.0.0.1:{udp_port}");
    for _ in 0..5 {
        let _ = sender.send_to(b"garbage that's not a valid packet", &target);
    }

    // Brief sleep: let the event loop process the UDP wake.
    std::thread::sleep(Duration::from_millis(100));

    // ─── daemon still alive AND responsive ───────────────────────
    assert!(
        child.try_wait().unwrap().is_none(),
        "daemon died after UDP packet"
    );

    let cookie = read_cookie(&pidfile);
    let stream = UnixStream::connect(&socket).expect("daemon still responsive");
    let mut reader = BufReader::new(&stream);
    let mut writer = &stream;
    writeln!(writer, "0 ^{cookie} 0").unwrap();
    let mut line1 = String::new();
    reader.read_line(&mut line1).unwrap();
    assert_eq!(line1, "0 testnode 17.7\n");

    let _ = child.kill();
    let _ = child.wait();
}

// ════════════════════════════════════════════════════════════════════
// SPTPS peer handshake → ACK exchange (chunk 4b)
//
// THE TEST IS THE INITIATOR. We don't have outgoing connections
// (`do_outgoing_connection` is chunk 6). So: we drive the initiator
// side from the test process using `tinc-sptps::Sptps` directly.
// Same shape as `tinc-tools/cmd/join.rs`'s pump loop.
//
// Chunk 4a stopped at HandshakeDone. Chunk 4b CONTINUES:
//   - daemon's HandshakeDone arm calls send_ack (NOT terminate)
//   - the ACK arrives as a SPTPS Record (encrypted)
//   - we send our ACK back (also encrypted)
//   - daemon's Record arm → check_gate → ack_h → "activated"
//   - connection STAYS UP (allow_request = ALL)
//   - `tinc dump connections` over control socket shows the row
//
// The label-NUL caveat from 4a still applies: this test uses the
// same construction on both sides; can't distinguish "both wrong".
// `proto::tests::tcp_label_has_trailing_nul` pins gcc bytes.

/// SPTPS handshake → ACK exchange → connection activated. The
/// daemon's HandshakeDone arm queues `send_ack`; we receive it as
/// an SPTPS `Record`, parse `"%d %s %d %x"`, send our ACK, daemon
/// activates. `tinc dump connections` then shows ONE peer row.
#[test]
fn peer_ack_exchange() {
    use rand_core::OsRng;
    use std::io::Read;
    use std::net::TcpStream;
    use tinc_crypto::sign::SigningKey;
    use tinc_sptps::{Framing, Output, Role, Sptps};

    let tmp = tmp("peer-handshake");
    let confbase = tmp.path().join("vpn");
    let pidfile = tmp.path().join("tinc.pid");
    let socket = tmp.path().join("tinc.socket");

    // ─── setup: daemon's config + OUR (testpeer) hosts entry ───
    // The daemon needs `hosts/testpeer` with our pubkey.
    let daemon_pub = write_config(&confbase);
    let our_key = SigningKey::from_seed(&[0x77; 32]);
    let our_pub = *our_key.public_key();
    let b64 = tinc_crypto::b64::encode(&our_pub);
    std::fs::write(
        confbase.join("hosts").join("testpeer"),
        format!("Ed25519PublicKey = {b64}\n"),
    )
    .unwrap();

    // ─── spawn daemon ────────────────────────────────────────────
    let mut child = Command::new(tincd_bin())
        .arg("-c")
        .arg(&confbase)
        .arg("--pidfile")
        .arg(&pidfile)
        .arg("--socket")
        .arg(&socket)
        // INFO captures the "SPTPS handshake completed" line.
        .env("RUST_LOG", "tincd=info")
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tincd");

    assert!(wait_for_file(&socket), "tincd setup failed; stderr: {}", {
        let _ = child.kill();
        let out = child.wait_with_output().unwrap();
        String::from_utf8_lossy(&out.stderr).into_owned()
    });

    let tcp_addr = read_tcp_addr(&pidfile);

    // ─── TCP connect + send ID line ────────────────────────────────
    // C `protocol_auth.c:116`: `"%d %s %d.%d"`. We are testpeer,
    // version 17.7. The daemon's id_h fires, peer branch.
    //
    // `TcpStream` impls Read AND Write for `&TcpStream` (the
    // shared-ref impl) — the kernel handles the duplex; Rust's
    // borrow checker just needs the type-level workaround. We
    // bind `let stream` (no `mut`) and use `(&stream).read()` /
    // `(&stream).write_all()`. Same trick as `tcp_connect_stop`
    // but here we INTERLEAVE reads and writes (the handshake
    // pump), so the trick is load-bearing.
    let stream = TcpStream::connect(tcp_addr).expect("TCP connect to tincd");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    writeln!(&stream, "0 testpeer 17.7").unwrap();

    // ─── recv daemon's ID line ────────────────────────────────────
    // The daemon's `send_id` reply: `"0 testnode 17.7\n"`. THEN
    // the responder's KEX bytes (binary, no newline). We CAN'T use
    // BufReader.read_line for the ID — it'll buffer MORE than the
    // line and we lose the KEX bytes into BufReader's internal
    // buffer. Read raw, find the `\n` ourselves.
    let mut buf = Vec::with_capacity(256);
    let mut tmp_buf = [0u8; 256];
    let id_end = loop {
        let n = (&stream).read(&mut tmp_buf).expect("recv from daemon");
        if n == 0 {
            panic!("daemon closed before sending ID line; buf so far: {buf:?}");
        }
        buf.extend_from_slice(&tmp_buf[..n]);
        if let Some(pos) = buf.iter().position(|&b| b == b'\n') {
            break pos;
        }
    };
    let id_line = std::str::from_utf8(&buf[..id_end]).expect("ID line ASCII");
    assert_eq!(id_line, "0 testnode 17.7", "daemon ID reply");

    // ─── SPTPS start: WE are the initiator ───────────────────────
    // C `id_h:460-462`: outgoing → `"tinc TCP key expansion %s %s",
    // myself, c->name`. We're outgoing (we connected). myself=
    // testpeer, c->name=testnode. Label: `(testpeer, testnode)`.
    //
    // SAME bytes as the daemon's `tcp_label("testpeer", "testnode")`.
    // Including the NUL. We construct via the same fn (proto::
    // tcp_label is pub(crate), not reachable from here — inline).
    let mut label = b"tinc TCP key expansion testpeer testnode".to_vec();
    label.push(0);
    // Sanity: matches the C `25 + strlen + strlen`.
    assert_eq!(label.len(), 25 + 8 + 8);

    let (mut sptps, init) = Sptps::start(
        Role::Initiator,
        Framing::Stream,
        our_key,
        daemon_pub,
        label,
        0,
        &mut OsRng,
    );

    // Send our KEX. `init` has one Wire (initiator's KEX from
    // sptps_start's send_kex).
    for o in init {
        if let Output::Wire { bytes, .. } = o {
            (&stream).write_all(&bytes).expect("send KEX");
        }
    }

    // ─── the pump: feed daemon's bytes to sptps until done ────────
    // The daemon sends: KEX (already in buf past id_end+1), then
    // (after we send our SIG) SIG. We feed everything we receive,
    // send everything sptps emits, stop on HandshakeDone.
    //
    // The pump is borrowed from `tinc-tools/cmd/join.rs:980` but
    // simpler — we only care about reaching HandshakeDone, not
    // post-handshake records. Same NoRng idiom (initiator's
    // receive() doesn't trigger send_kex during the initial
    // handshake).
    struct NoRng;
    impl rand_core::RngCore for NoRng {
        fn next_u32(&mut self) -> u32 {
            unreachable!("rng touched")
        }
        fn next_u64(&mut self) -> u64 {
            unreachable!("rng touched")
        }
        fn fill_bytes(&mut self, _: &mut [u8]) {
            unreachable!("rng touched")
        }
        fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), rand_core::Error> {
            unreachable!("rng touched")
        }
    }

    // Seed the pump with bytes already in `buf` past the ID line.
    let mut pending: Vec<u8> = buf[id_end + 1..].to_vec();
    let mut handshake_done = false;
    let mut daemon_ack: Option<Vec<u8>> = None;
    let pump_deadline = Instant::now() + Duration::from_secs(5);

    'pump: loop {
        if Instant::now() > pump_deadline {
            let _ = child.kill();
            let out = child.wait_with_output().unwrap();
            panic!(
                "handshake didn't complete in 5s; stderr:\n{}",
                String::from_utf8_lossy(&out.stderr)
            );
        }

        // Feed pending bytes to sptps. The do-while: receive()
        // processes one record at a time.
        //
        // (Match not unwrap_or_else: the closure would capture
        // `child` by move once, making it unusable for the later
        // panic-with-stderr arms. The borrow checker can't see
        // that the closure body diverges. Match is explicit.)
        let mut off = 0;
        while off < pending.len() {
            let (n, outs) = match sptps.receive(&pending[off..], &mut NoRng) {
                Ok(r) => r,
                Err(e) => {
                    let _ = child.kill();
                    let out = child.wait_with_output().unwrap();
                    panic!(
                        "SPTPS receive failed: {e:?}; stderr:\n{}",
                        String::from_utf8_lossy(&out.stderr)
                    );
                }
            };
            off += n;
            for o in outs {
                match o {
                    Output::Wire { bytes, .. } => {
                        // Our SIG (initiator sends SIG after
                        // receiving responder's KEX).
                        (&stream).write_all(&bytes).expect("send Wire");
                    }
                    Output::HandshakeDone => {
                        handshake_done = true;
                    }
                    Output::Record { bytes, .. } => {
                        // Chunk 4b: the daemon's ACK. First (and
                        // only, in 4b) post-handshake record.
                        // Stash for parsing after the pump.
                        daemon_ack = Some(bytes);
                    }
                }
            }
            // Stream-mode receive() can return 0 only on empty
            // input. We checked `off < pending.len()`. If it
            // returns 0 anyway, that's a tinc-sptps bug — break
            // to avoid spin.
            if n == 0 {
                break;
            }
        }
        pending.clear();

        // Chunk 4b: pump until we have BOTH HandshakeDone AND the
        // daemon's ACK record. They might arrive in the same
        // `pending` chunk (the daemon's SIG + send_ack are queued
        // in the same outbuf flush) or separate reads.
        if handshake_done && daemon_ack.is_some() {
            break 'pump;
        }

        // Read more from the daemon. read_timeout is set; this
        // returns WouldBlock after 5s if the daemon stalls.
        let n = match (&stream).read(&mut tmp_buf) {
            Ok(0) => {
                // EOF before HandshakeDone. The daemon dropped us.
                // Probably: id_h reject (bad name, version, no
                // pubkey). The stderr will say why.
                let _ = child.kill();
                let out = child.wait_with_output().unwrap();
                panic!(
                    "daemon EOF before HandshakeDone; stderr:\n{}",
                    String::from_utf8_lossy(&out.stderr)
                );
            }
            Ok(n) => n,
            Err(e) => {
                let _ = child.kill();
                let out = child.wait_with_output().unwrap();
                panic!(
                    "read error: {e}; stderr:\n{}",
                    String::from_utf8_lossy(&out.stderr)
                );
            }
        };
        pending.extend_from_slice(&tmp_buf[..n]);
    }

    // ─── parse the daemon's ACK ─────────────────────────────────
    // C `:867`: `"%d %s %d %x"` = `"4 <udp-port> <weight> <opts>"`.
    // Record body has trailing `\n` (`send_request:120` appends).
    let ack = daemon_ack.expect("pump exited with daemon_ack set");
    let body = ack.strip_suffix(b"\n").unwrap_or(&ack);
    let body = std::str::from_utf8(body).expect("ACK is ASCII");
    let mut t = body.split_whitespace();
    assert_eq!(t.next(), Some("4"), "ACK reqno: {body:?}");
    // UDP port: kernel-assigned (Port=0). Just: it's a valid u16,
    // and ≠ the TCP port (`bind_reusing_port` not yet — chunk 10).
    let daemon_udp_port: u16 = t.next().unwrap().parse().expect("udp port");
    assert_ne!(daemon_udp_port, 0);
    // Weight: RTT in ms. Localhost handshake is fast; >= 0, < some
    // sane bound. The C `:840` is `(now - c->start)` ms.
    let daemon_weight: i32 = t.next().unwrap().parse().expect("weight");
    assert!(
        (0..5000).contains(&daemon_weight),
        "weight: {daemon_weight}"
    );
    // Options hex: `myself_options_default()` = `0x0700000c` (PMTU
    // + CLAMP + PROT_MINOR=7 in top byte). The `& 0xffffff` mask
    // doesn't change it (low 24 bits already include PMTU+CLAMP);
    // the `| PROT_MINOR<<24` re-adds the top byte. Same value.
    let daemon_opts = u32::from_str_radix(t.next().unwrap(), 16).expect("opts hex");
    assert_eq!(daemon_opts, 0x0700_000c, "options: {body:?}");

    // ─── send OUR ACK ─────────────────────────────────────────────
    // C INITIATOR side: `meta.c:131` `if(allow == ACK) send_ack(c)`.
    // The initiator's HandshakeDone fires the SAME arm. We model
    // that here. Port 0 (we have no UDP listener); weight 1ms
    // (fake); same default options. The `\n` is required (`meta.c:
    // 156` strips it; daemon's `record_body`).
    let our_ack = b"4 0 1 700000c\n";
    let outs = sptps.send_record(0, our_ack).expect("post-handshake");
    for o in outs {
        if let Output::Wire { bytes, .. } = o {
            (&stream).write_all(&bytes).expect("send our ACK");
        }
    }
    // C `ack_h:1058 send_add_edge(everyone, c->edge)`: a real
    // peer's `on_ack` broadcasts ITS edge (testpeer→testnode).
    // The daemon's SSSP only follows edges with `e->reverse` set
    // (`graph.c:159`); without this gossip, the daemon's testnode→
    // testpeer edge has no twin and `BecameReachable` never fires.
    // (chunk-9b removed the synthesized reverse from `on_ack` —
    // it broke 3-node relay forwarding. Tests that drive the
    // daemon manually now must send what a real peer sends.)
    let our_edge = b"12 deadbeef testpeer testnode 127.0.0.1 655 700000c 1\n";
    let outs = sptps.send_record(0, our_edge).expect("our edge");
    for o in outs {
        if let Output::Wire { bytes, .. } = o {
            (&stream).write_all(&bytes).expect("send our ADD_EDGE");
        }
    }

    // ─── daemon activates: send_everything + send_add_edge ─────
    // C `:1025` log: "Connection with X (Y) activated". Then
    // `:1028 send_everything(c)` walks the world model. With zero
    // subnets and ONE edge (testnode→testpeer, just added with an
    // addr entry), we get 1 ADD_EDGE record. Then `:1058 send_add_
    // edge(everyone, c->edge)` broadcasts the same edge — we ARE
    // the only active conn, so we get a SECOND ADD_EDGE for the
    // same edge with a DIFFERENT nonce. Both pass `seen.check`;
    // the second hits `lookup_edge`-exists-same-weight → idempotent.
    //
    // The synthesized reverse (testpeer→testnode) has NO `edge_
    // addrs` entry (chunk-5 STUB), so `fmt_add_edge` skips it.
    //
    // Receive both records. Parse the first; assert it's `ADD_EDGE
    // testnode testpeer`. Then drain until WouldBlock — proves the
    // skip-from logic for `forward_request` (we ARE `from` for any
    // ADD_SUBNET we send below; broadcast skips us).
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let mut post_ack_records: Vec<Vec<u8>> = Vec::new();
    pending.clear();
    let drain_deadline = Instant::now() + Duration::from_secs(5);
    'drain: loop {
        if Instant::now() > drain_deadline {
            panic!("send_everything drain timeout");
        }
        let mut off = 0;
        while off < pending.len() {
            let (n, outs) = sptps.receive(&pending[off..], &mut NoRng).expect("sptps");
            if n == 0 {
                break;
            }
            off += n;
            for o in outs {
                if let Output::Record { bytes, .. } = o {
                    post_ack_records.push(bytes);
                }
            }
        }
        pending.drain(..off);
        match (&stream).read(&mut tmp_buf) {
            Ok(0) => {
                let _ = child.kill();
                let out = child.wait_with_output().unwrap();
                panic!(
                    "daemon closed post-ACK; stderr:\n{}",
                    String::from_utf8_lossy(&out.stderr)
                );
            }
            Ok(n) => pending.extend_from_slice(&tmp_buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Nothing more. If we got at least one record we're done.
                if !post_ack_records.is_empty() {
                    break 'drain;
                }
                // Else: keep waiting (daemon might not have flushed yet).
            }
            Err(e) => panic!("read error post-ACK: {e}"),
        }
    }
    // At least 1 ADD_EDGE (send_everything). Possibly 2 (the
    // `send_add_edge(everyone)` broadcast).
    assert!(
        !post_ack_records.is_empty(),
        "expected ADD_EDGE from send_everything"
    );
    // Parse first: `"12 <nonce> testnode testpeer 127.0.0.1 <port> <opts> <weight>"`.
    let first = std::str::from_utf8(&post_ack_records[0])
        .unwrap()
        .trim_end();
    let mut t = first.split_whitespace();
    assert_eq!(t.next(), Some("12"), "ADD_EDGE reqno: {first:?}");
    let _nonce = t.next().unwrap();
    assert_eq!(t.next(), Some("testnode"), "from: {first:?}");
    assert_eq!(t.next(), Some("testpeer"), "to: {first:?}");
    assert_eq!(t.next(), Some("127.0.0.1"), "addr: {first:?}");
    // port: his_udp_port from our ACK = 0. options + weight follow.
    assert_eq!(t.next(), Some("0"), "port (his_udp_port=0): {first:?}");
    // All records are ADD_EDGE for testnode→testpeer (the only
    // edge with an addr entry).
    for rec in &post_ack_records {
        let s = std::str::from_utf8(rec).unwrap();
        assert!(
            s.starts_with("12 ") && s.contains(" testnode testpeer "),
            "unexpected post-ACK record: {s:?}"
        );
    }
    // Short timeout for subsequent no-reply checks.
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();

    // ─── dump connections over control socket ────────────────────
    // `connection.c:166-175`: walk connection_list, format `"%d %d
    // %s %s %x %d %x"` per row, then terminator `"%d %d"`. With
    // ONE peer + ONE control conn (us), we get 2 rows.
    //
    // The peer row's name is `testpeer`, hostname is `127.0.0.1
    // port <some-port>` (the FUSED string — see dump.rs's `" port "`
    // literal note). options is the OR'd value (PMTU intersection
    // applied: both sides had it, so it sticks).
    let cookie = read_cookie(&pidfile);
    let ctl = UnixStream::connect(&socket).expect("control connect");
    let mut ctl_r = BufReader::new(&ctl);
    let mut ctl_w = &ctl;
    writeln!(ctl_w, "0 ^{cookie} 0").unwrap();
    let mut greet = String::new();
    ctl_r.read_line(&mut greet).unwrap();
    assert_eq!(greet, "0 testnode 17.7\n");
    let mut ack = String::new();
    ctl_r.read_line(&mut ack).unwrap(); // "4 0 <pid>"

    // REQ_DUMP_CONNECTIONS = 6.
    writeln!(ctl_w, "18 6").unwrap();
    let mut rows = Vec::new();
    loop {
        let mut line = String::new();
        ctl_r.read_line(&mut line).expect("dump row");
        let line = line.trim_end().to_owned();
        // Terminator: `"18 6"` (no body). Row: `"18 6 <body>"`.
        if line == "18 6" {
            break;
        }
        rows.push(line);
    }
    // 2 conns: testpeer (TCP) + <control> (this unix socket).
    // Order is slotmap-iteration (insertion order). Don't pin order;
    // find the testpeer row.
    assert_eq!(rows.len(), 2, "dump rows: {rows:?}");
    let peer_row = rows
        .iter()
        .find(|r| r.contains("testpeer"))
        .unwrap_or_else(|| panic!("no testpeer row in: {rows:?}"));
    // `"18 6 testpeer 127.0.0.1 port <p> <opts-hex> <fd> <status>"`.
    // The hostname is FUSED (one %s in the daemon, two %s + lit on
    // CLI parse). We just substring-check for now; `tinc-tools::
    // dump::ConnRow::parse` is the real parser.
    assert!(
        peer_row.starts_with("18 6 testpeer 127.0.0.1 port "),
        "peer row: {peer_row}"
    );
    // options: after PMTU intersection + OR (`ack_h:996-1001`).
    // Both sides sent `0x0700000c`; intersection keeps PMTU; OR is
    // idempotent. `c->options` = `0x0700000c`. Hex unpadded.
    assert!(peer_row.contains(" 700000c "), "peer row: {peer_row}");

    // ─── chunk 5: ADD_SUBNET / dump subnets / dedup / DEL ──────
    // C `add_subnet_h` (`protocol_subnet.c:43-140`). Send an
    // ADD_SUBNET via SPTPS record, daemon parses + inserts into
    // SubnetTree, `dump subnets` over the control socket shows it.
    //
    // Record body format: `"10 <nonce-hex> <owner> <netstr>\n"`
    // (`protocol_subnet.c:40`: `"%d %x %s %s"`). The `\n` is
    // appended by `send_request:120`; daemon's `record_body`
    // strips it (`meta.c:156`).
    //
    // `192.168.99.0/24#10`: weight 10 is the default —
    // `Subnet::Display` omits `#10`, so the dump row reads
    // `192.168.99.0/24`. Match the dump format, not the wire.
    let add_subnet = b"10 deadbeef testpeer 192.168.99.0/24#10\n";
    let outs = sptps.send_record(0, add_subnet).expect("post-handshake");
    for o in outs {
        if let Output::Wire { bytes, .. } = o {
            (&stream).write_all(&bytes).expect("send ADD_SUBNET");
        }
    }

    // Daemon doesn't reply to ADD_SUBNET. `forward_request` skips
    // `from` (us) and there are no OTHER active conns. The skip-
    // from logic is the loop break; this WouldBlock proves it.
    match (&stream).read(&mut tmp_buf) {
        Ok(0) => {
            let _ = child.kill();
            let out = child.wait_with_output().unwrap();
            panic!(
                "daemon closed after ADD_SUBNET; stderr:\n{}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        Ok(n) => panic!("daemon replied {n} bytes to ADD_SUBNET (should forward, not reply)"),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(e) => panic!("read error after ADD_SUBNET: {e}"),
    }

    // `dump subnets` (`subnet.c:395-410`). REQ_DUMP_SUBNETS = 5.
    // Format: `"18 5 <netstr> <owner>"` per row, terminator `"18 5"`.
    // C `:404`: `"%d %d %s %s"`. With one subnet: one row.
    //
    // Helper closure: send REQ_DUMP_SUBNETS, collect rows. Called
    // three times below (after ADD, after dup-ADD, after DEL).
    let dump_subnets = |ctl_r: &mut BufReader<&UnixStream>, ctl_w: &mut &UnixStream| {
        writeln!(ctl_w, "18 5").unwrap();
        let mut rows = Vec::new();
        loop {
            let mut line = String::new();
            ctl_r.read_line(&mut line).expect("dump subnet row");
            let line = line.trim_end().to_owned();
            if line == "18 5" {
                break;
            }
            rows.push(line);
        }
        rows
    };

    let rows = dump_subnets(&mut ctl_r, &mut ctl_w);
    assert_eq!(rows.len(), 1, "dump subnets after ADD: {rows:?}");
    // C `subnet.c:404`: `netstr owner`. `net2str` omits `#10`
    // (default weight). `Subnet::Display` matches.
    assert_eq!(
        rows[0], "18 5 192.168.99.0/24 testpeer",
        "subnet row: {rows:?}"
    );

    // Send the SAME ADD_SUBNET again. `seen.check` dup-drops it
    // (`protocol.c:234-249`). The full body string (incl nonce)
    // is the cache key — same nonce → same key → hit.
    let outs = sptps.send_record(0, add_subnet).expect("dup send");
    for o in outs {
        if let Output::Wire { bytes, .. } = o {
            (&stream).write_all(&bytes).expect("send dup ADD_SUBNET");
        }
    }
    // No reply (dup-dropped silently).
    match (&stream).read(&mut tmp_buf) {
        Ok(0) => panic!("daemon closed after dup ADD_SUBNET"),
        Ok(n) => panic!("daemon replied {n} bytes to dup ADD_SUBNET"),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(e) => panic!("read error after dup: {e}"),
    }
    // Still ONE row — dedup proved.
    let rows = dump_subnets(&mut ctl_r, &mut ctl_w);
    assert_eq!(rows.len(), 1, "dump after dup ADD (seen.check): {rows:?}");

    // DEL_SUBNET. `protocol_subnet.c:163-261`. Same wire shape,
    // reqno 11. DIFFERENT nonce (the dup ADD_SUBNET above already
    // primed `seen` with `deadbeef` — but on a different reqno
    // string, so it wouldn't collide. Distinct nonce anyway for
    // realism: each flood is fresh `prng()` output).
    let del_subnet = b"11 cafef00d testpeer 192.168.99.0/24#10\n";
    let outs = sptps.send_record(0, del_subnet).expect("del send");
    for o in outs {
        if let Output::Wire { bytes, .. } = o {
            (&stream).write_all(&bytes).expect("send DEL_SUBNET");
        }
    }
    match (&stream).read(&mut tmp_buf) {
        Ok(0) => {
            let _ = child.kill();
            let out = child.wait_with_output().unwrap();
            panic!(
                "daemon closed after DEL_SUBNET; stderr:\n{}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        Ok(n) => panic!("daemon replied {n} bytes to DEL_SUBNET"),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(e) => panic!("read error after DEL: {e}"),
    }
    // Zero rows — deleted.
    let rows = dump_subnets(&mut ctl_r, &mut ctl_w);
    assert_eq!(rows.len(), 0, "dump after DEL_SUBNET: {rows:?}");

    // ─── stderr: prove the daemon's path ─────────────────────────
    // Hold `stream` until here — dropping it would let the daemon's
    // ping-timeout sweep close the conn before we dump.
    drop(stream);
    let _ = child.kill();
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("SPTPS handshake completed with testpeer"),
        "stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("Connection with testpeer") && stderr.contains("activated"),
        "daemon didn't log activation; stderr:\n{stderr}"
    );
    // The chunk-4a placeholder warning is GONE.
    assert!(
        !stderr.contains("send_ack not implemented"),
        "chunk-4a placeholder leaked; stderr:\n{stderr}"
    );
    // Chunk 5: on_ack → graph.add_edge → run_graph → BecameReachable.
    // C `graph.c:261`: `"Node %s became reachable"`. Our log says
    // `"Node testpeer became reachable"`. THIS is the proof that
    // graph_glue::run_graph fired and the diff produced a transition.
    assert!(
        stderr.contains("Node testpeer became reachable"),
        "on_ack graph bridge didn't fire BecameReachable; stderr:\n{stderr}"
    );
}

/// ADD_EDGE for a transitive node triggers `BecameReachable` for
/// that node. Proves `on_add_edge` → `graph.add_edge` → `run_graph`
/// → `Transition::BecameReachable` → log.
///
/// Same setup as `peer_ack_exchange` (handshake + ACK), then send
/// `ADD_EDGE testpeer faraway` plus the reverse `faraway testpeer`.
/// `sssp` only follows bidi edges (`graph.c:159`: `if(!e->reverse)
/// continue`); both directions are needed for the transition to
/// fire. The C peer would send both (each side's `ack_h` adds its
/// `c->edge`, then broadcasts).
///
/// `dump connections` STILL shows one row (testpeer): faraway has
/// no direct connection — graph-only.
#[test]
fn peer_edge_triggers_reachable() {
    use rand_core::OsRng;
    use std::io::Read;
    use std::net::TcpStream;
    use tinc_crypto::sign::SigningKey;
    use tinc_sptps::{Framing, Output, Role, Sptps};

    let tmp = tmp("peer-edge");
    let confbase = tmp.path().join("vpn");
    let pidfile = tmp.path().join("tinc.pid");
    let socket = tmp.path().join("tinc.socket");

    let daemon_pub = write_config(&confbase);
    let our_key = SigningKey::from_seed(&[0x77; 32]);
    let our_pub = *our_key.public_key();
    let b64 = tinc_crypto::b64::encode(&our_pub);
    std::fs::write(
        confbase.join("hosts").join("testpeer"),
        format!("Ed25519PublicKey = {b64}\n"),
    )
    .unwrap();

    let mut child = Command::new(tincd_bin())
        .arg("-c")
        .arg(&confbase)
        .arg("--pidfile")
        .arg(&pidfile)
        .arg("--socket")
        .arg(&socket)
        // INFO captures the "became reachable" line. graph_glue
        // logs at `tincd::graph` target.
        .env("RUST_LOG", "tincd=info")
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tincd");

    assert!(wait_for_file(&socket), "tincd setup failed; stderr: {}", {
        let _ = child.kill();
        let out = child.wait_with_output().unwrap();
        String::from_utf8_lossy(&out.stderr).into_owned()
    });

    let tcp_addr = read_tcp_addr(&pidfile);
    let stream = TcpStream::connect(tcp_addr).expect("TCP connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    writeln!(&stream, "0 testpeer 17.7").unwrap();

    // ─── ID line + SPTPS pump (same as peer_ack_exchange) ────────
    let mut buf = Vec::with_capacity(256);
    let mut tmp_buf = [0u8; 256];
    let id_end = loop {
        let n = (&stream).read(&mut tmp_buf).expect("recv");
        if n == 0 {
            panic!("daemon closed before ID");
        }
        buf.extend_from_slice(&tmp_buf[..n]);
        if let Some(pos) = buf.iter().position(|&b| b == b'\n') {
            break pos;
        }
    };
    assert_eq!(&buf[..id_end], b"0 testnode 17.7");

    let mut label = b"tinc TCP key expansion testpeer testnode".to_vec();
    label.push(0);
    let (mut sptps, init) = Sptps::start(
        Role::Initiator,
        Framing::Stream,
        our_key,
        daemon_pub,
        label,
        0,
        &mut OsRng,
    );
    for o in init {
        if let Output::Wire { bytes, .. } = o {
            (&stream).write_all(&bytes).expect("send KEX");
        }
    }

    // Minimal pump: feed until HandshakeDone + daemon's ACK record.
    // Same NoRng idiom as peer_ack_exchange.
    struct NoRng;
    impl rand_core::RngCore for NoRng {
        fn next_u32(&mut self) -> u32 {
            unreachable!()
        }
        fn next_u64(&mut self) -> u64 {
            unreachable!()
        }
        fn fill_bytes(&mut self, _: &mut [u8]) {
            unreachable!()
        }
        fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), rand_core::Error> {
            unreachable!()
        }
    }

    let mut pending: Vec<u8> = buf[id_end + 1..].to_vec();
    let mut handshake_done = false;
    let mut got_ack = false;
    let deadline = Instant::now() + Duration::from_secs(5);
    while !(handshake_done && got_ack) {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("handshake timeout");
        }
        let mut off = 0;
        while off < pending.len() {
            let (n, outs) = sptps.receive(&pending[off..], &mut NoRng).expect("sptps");
            off += n;
            for o in outs {
                match o {
                    Output::Wire { bytes, .. } => {
                        (&stream).write_all(&bytes).expect("send");
                    }
                    Output::HandshakeDone => handshake_done = true,
                    Output::Record { .. } => got_ack = true,
                }
            }
            if n == 0 {
                break;
            }
        }
        pending.clear();
        if handshake_done && got_ack {
            break;
        }
        let n = (&stream).read(&mut tmp_buf).expect("read");
        if n == 0 {
            let _ = child.kill();
            let out = child.wait_with_output().unwrap();
            panic!(
                "daemon EOF before handshake; stderr:\n{}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        pending.extend_from_slice(&tmp_buf[..n]);
    }

    // Send our ACK. Daemon activates + adds myself→testpeer edge
    // + runs graph. Then our ADD_EDGE (testpeer→testnode) gives
    // the daemon's edge its reverse; THAT graph() fires
    // BecameReachable. (Real peers' on_ack sends both in one
    // burst; chunk-9b removed the daemon's synthesized reverse.)
    let outs = sptps.send_record(0, b"4 0 1 700000c\n").expect("ack");
    for o in outs {
        if let Output::Wire { bytes, .. } = o {
            (&stream).write_all(&bytes).expect("send ACK");
        }
    }
    let our_edge = b"12 deadbeef testpeer testnode 127.0.0.1 655 700000c 1\n";
    let outs = sptps.send_record(0, our_edge).expect("our edge");
    for o in outs {
        if let Output::Wire { bytes, .. } = o {
            (&stream).write_all(&bytes).expect("send our ADD_EDGE");
        }
    }

    // Chunk 6: daemon's `on_ack` now calls `send_everything` +
    // `send_add_edge(everyone)`. We get 1-2 ADD_EDGE records for
    // testnode→testpeer. Drain them. Helper closure: pump records
    // out of `pending` + socket until WouldBlock with no partial.
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let drain_records =
        |sptps: &mut Sptps, stream: &TcpStream, pending: &mut Vec<u8>| -> Vec<Vec<u8>> {
            let mut recs = Vec::new();
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut tmp_buf = [0u8; 256];
            loop {
                if Instant::now() > deadline {
                    panic!("drain timeout");
                }
                let mut off = 0;
                while off < pending.len() {
                    let (n, outs) = sptps.receive(&pending[off..], &mut NoRng).expect("sptps");
                    if n == 0 {
                        break;
                    }
                    off += n;
                    for o in outs {
                        if let Output::Record { bytes, .. } = o {
                            recs.push(bytes);
                        }
                    }
                }
                pending.drain(..off);
                match (&*stream).read(&mut tmp_buf) {
                    Ok(0) => panic!("daemon EOF mid-drain"),
                    Ok(n) => pending.extend_from_slice(&tmp_buf[..n]),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        // No more bytes AND no partial buffered.
                        if pending.is_empty() {
                            return recs;
                        }
                    }
                    Err(e) => panic!("read error: {e}"),
                }
            }
        };
    pending.clear();
    let post_ack = drain_records(&mut sptps, &stream, &mut pending);
    // 1-2 ADD_EDGE records for testnode→testpeer.
    assert!(
        !post_ack.is_empty(),
        "expected ADD_EDGE from send_everything"
    );
    for rec in &post_ack {
        let s = std::str::from_utf8(rec).unwrap();
        assert!(
            s.starts_with("12 ") && s.contains(" testnode testpeer "),
            "unexpected post-ACK record: {s:?}"
        );
    }
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();

    // ─── ADD_EDGE: testpeer → faraway, both directions ───────────
    // C `protocol_edge.c:29-62`: `"%d %x %s %s %s %s %x %d"`.
    // `12 <nonce> <from> <to> <addr> <port> <opts> <weight>`.
    // No local-addr suffix (6-token form, pre-1.0.24 compat).
    //
    // `sssp` follows edges only if `e->reverse` is set (`graph.c:
    // 159`). `Graph::add_edge` auto-links the reverse if it exists.
    // So: send BOTH directions. The C peer would do the same (each
    // side's `ack_h` adds its `c->edge` and broadcasts; testpeer
    // sends `testpeer→faraway`, faraway sends `faraway→testpeer`).
    //
    // Different nonces — each is a separate `prng()` in C.
    // Addresses are arbitrary tokens (Phase-1 finding: `AddrStr`
    // is opaque, `str2sockaddr` accepts anything).
    let fwd = b"12 11111111 testpeer faraway 10.99.0.2 655 0 50\n";
    let rev = b"12 22222222 faraway testpeer 10.99.0.1 655 0 50\n";
    for body in [fwd.as_slice(), rev.as_slice()] {
        let outs = sptps.send_record(0, body).expect("add_edge");
        for o in outs {
            if let Output::Wire { bytes, .. } = o {
                (&stream).write_all(&bytes).expect("send ADD_EDGE");
            }
        }
    }

    // Daemon's `forward_request` skips `from` (us). No other active
    // conns. Drain: should be empty (proves the from-skip).
    let after_edge = drain_records(&mut sptps, &stream, &mut pending);
    assert!(
        after_edge.is_empty(),
        "forward_request should skip from-conn; got: {after_edge:?}"
    );

    // ─── dump connections: STILL one peer row ───────────────────
    // faraway is graph-only (no NodeState, no Connection).
    // `dump_connections` walks `conns`, not `node_ids`.
    let cookie = read_cookie(&pidfile);
    let ctl = UnixStream::connect(&socket).expect("ctl connect");
    let mut ctl_r = BufReader::new(&ctl);
    let mut ctl_w = &ctl;
    writeln!(ctl_w, "0 ^{cookie} 0").unwrap();
    let mut greet = String::new();
    ctl_r.read_line(&mut greet).unwrap();
    let mut ack = String::new();
    ctl_r.read_line(&mut ack).unwrap();

    writeln!(ctl_w, "18 6").unwrap();
    let mut rows = Vec::new();
    loop {
        let mut line = String::new();
        ctl_r.read_line(&mut line).expect("dump row");
        let line = line.trim_end().to_owned();
        if line == "18 6" {
            break;
        }
        rows.push(line);
    }
    // testpeer + <control>. NOT faraway.
    assert_eq!(rows.len(), 2, "dump connections: {rows:?}");
    assert!(
        rows.iter().any(|r| r.contains("testpeer")),
        "no testpeer: {rows:?}"
    );
    assert!(
        !rows.iter().any(|r| r.contains("faraway")),
        "faraway shouldn't have a connection: {rows:?}"
    );

    // ─── dump nodes: 3 rows, all reachable ─────────────────────
    // C `node.c:201-223`. Walks the graph (NOT `nodes`/`conns`).
    // After ACK + bidi ADD_EDGE: testnode (myself), testpeer
    // (direct), faraway (transitive). All reachable (status bit
    // 4 set; `node.h:38` field 4, GCC LSB-first → 0x10).
    //
    // REQ_DUMP_NODES = 3. Format: `"18 3 <name> <id> <host> port
    // <port> <cipher> <digest> <maclen> <comp> <opts:x> <stat:x>
    // <nexthop> <via> <dist> <mtu> <minmtu> <maxmtu> <ts> <rtt>
    // <in_p> <in_b> <out_p> <out_b>"`. CLI parser: `tinc-tools::
    // cmd::dump::NodeRow::parse`.
    writeln!(ctl_w, "18 3").unwrap();
    let mut node_rows = Vec::new();
    loop {
        let mut line = String::new();
        ctl_r.read_line(&mut line).expect("dump node row");
        let line = line.trim_end().to_owned();
        if line == "18 3" {
            break;
        }
        node_rows.push(line);
    }
    assert_eq!(node_rows.len(), 3, "dump nodes: {node_rows:?}");

    // Find each node's row. Body starts after `"18 3 "`; first
    // token is the name. Don't pin slot order (graph slot order
    // = insertion order, but be robust).
    let find_row = |name: &str| -> &str {
        node_rows
            .iter()
            .find(|r| {
                r.strip_prefix("18 3 ")
                    .and_then(|b| b.split(' ').next())
                    .is_some_and(|n| n == name)
            })
            .unwrap_or_else(|| panic!("no {name} row in: {node_rows:?}"))
    };
    let myself_row = find_row("testnode");
    let peer_row = find_row("testpeer");
    let far_row = find_row("faraway");

    // status field is the 11th body field (`%x`), right after
    // options (`%x`). Bit 4 = reachable = 0x10. Chunk-7 also sets
    // bit 6 (`sptps`) for nodes that became reachable (`graph.c:
    // 192-195` reads `e->options >> 24 >= 2` from the prevedge;
    // we set it unconditionally in `BecameReachable` since the
    // Rust port is SPTPS-only).
    //
    // myself: never transitions BecameReachable (set reachable at
    // setup) → status = 0x10 (reachable only).
    // testpeer/faraway: 0x50 = reachable | sptps.
    //
    // Parse the status hex from the row (token at index 10 of the
    // body) and check bit 4.
    let parse_status = |row: &str| -> u32 {
        row.strip_prefix("18 3 ")
            .and_then(|b| b.split_whitespace().nth(10))
            .and_then(|s| u32::from_str_radix(s, 16).ok())
            .unwrap_or_else(|| panic!("can't parse status from row: {row}"))
    };
    for (name, row) in [
        ("testnode", myself_row),
        ("testpeer", peer_row),
        ("faraway", far_row),
    ] {
        let status = parse_status(row);
        assert!(
            status & 0x10 != 0,
            "{name} not reachable (status={status:x}); row: {row}"
        );
    }
    // testpeer/faraway: sptps bit set (chunk-7's BecameReachable).
    assert!(
        parse_status(peer_row) & 0x40 != 0,
        "testpeer sptps bit; row: {peer_row}"
    );
    assert!(
        parse_status(far_row) & 0x40 != 0,
        "faraway sptps bit; row: {far_row}"
    );

    // myself: hostname is `"MYSELF port <udp>"` (`net_setup.c:
    // 1199`). nexthop/via are itself (sssp seeds `myself` with
    // `nexthop=myself, via=myself`, `graph.c:138-145`).
    // distance=0.
    assert!(
        myself_row.contains(" MYSELF port "),
        "myself hostname; row: {myself_row}"
    );
    assert!(
        myself_row.contains(" testnode testnode 0 "),
        "myself nexthop/via/dist; row: {myself_row}"
    );

    // testpeer: directly connected. hostname is the rewritten
    // `c->address` with `his_udp_port=0` (we sent `"4 0 1 ..."`
    // — first field is hisport=0). nexthop=testpeer, via=
    // testpeer, distance=1 (one hop).
    assert!(
        peer_row.contains(" 127.0.0.1 port 0 "),
        "testpeer hostname (edge_addr, port=his_udp_port=0); row: {peer_row}"
    );
    assert!(
        peer_row.contains(" testpeer testpeer 1 "),
        "testpeer nexthop/via/dist; row: {peer_row}"
    );

    // faraway: transitive (no NodeState). hostname is the
    // literal `"unknown port unknown"` (`node.c:211`). nexthop
    // =testpeer (first hop), via=faraway (direct — no INDIRECT
    // option set), distance=2.
    assert!(
        far_row.contains(" unknown port unknown "),
        "faraway hostname (transitive, no NodeState); row: {far_row}"
    );
    assert!(
        far_row.contains(" testpeer faraway 2 "),
        "faraway nexthop/via/dist; row: {far_row}"
    );
    // udp_ping_rtt = -1 (init value), traffic counters = 0.
    assert!(
        far_row.ends_with(" -1 0 0 0 0"),
        "faraway tail (rtt=-1, counters=0); row: {far_row}"
    );

    // ─── dump edges: 4 rows (2 bidi pairs) ─────────────────────
    // C `edge.c:123-137`. Nested per-node walk. After ACK + the
    // two ADD_EDGE bodies: testnode↔testpeer (from `on_ack`, both
    // halves) + testpeer↔faraway (from the wire, both halves).
    //
    // REQ_DUMP_EDGES = 4. Format: `"18 4 <from> <to> <addr> port
    // <p> <local> port <lp> <opts:x> <weight>"`. CLI: `EdgeRow::
    // parse` (8 fields, two `" port "` re-splits).
    writeln!(ctl_w, "18 4").unwrap();
    let mut edge_rows = Vec::new();
    loop {
        let mut line = String::new();
        ctl_r.read_line(&mut line).expect("dump edge row");
        let line = line.trim_end().to_owned();
        if line == "18 4" {
            break;
        }
        edge_rows.push(line);
    }
    // 4 directed edges. Order: per-node (slot order), then per-
    // edge (sorted by to-name). Don't pin global order.
    assert_eq!(edge_rows.len(), 4, "dump edges: {edge_rows:?}");

    // testnode→testpeer: `on_ack` populated `edge_addrs` from
    // `conn.address` (127.0.0.1) + `his_udp_port` (0). Local addr
    // is the `getsockname` result with port rewritten to `myport.
    // udp` (`ack_h:1040-1045`). The TCP socket's local addr is
    // `127.0.0.1` (we connected to a 127.0.0.1 listener); the
    // port is the daemon's UDP port (kernel-assigned, varies).
    let fwd = edge_rows
        .iter()
        .find(|r| r.starts_with("18 4 testnode testpeer "))
        .unwrap_or_else(|| panic!("no testnode→testpeer: {edge_rows:?}"));
    assert!(
        fwd.contains(" 127.0.0.1 port 0 127.0.0.1 port "),
        "forward edge addr (remote=conn.address+hisport, local=getsockname+myudp); row: {fwd}"
    );

    // testpeer→testnode: synthesized reverse from `on_ack`.
    // chunk-5 left this with NO `edge_addrs` entry (rendered
    // as `"unknown port unknown"`). chunk-9b fixed the
    // idempotence check in `on_add_edge`: the test's `our_edge`
    // ADD_EDGE (line ~154) now falls through to update (was
    // early-returning on weight+options match without checking
    // address) and populates `edge_addrs` with the wire body's
    // `127.0.0.1` `655`. The `three_daemon_relay` test depends
    // on this fall-through for hub-spoke topology.
    let rev = edge_rows
        .iter()
        .find(|r| r.starts_with("18 4 testpeer testnode "))
        .unwrap_or_else(|| panic!("no testpeer→testnode: {edge_rows:?}"));
    assert!(
        rev.contains(" 127.0.0.1 port 655 "),
        "reverse edge addr should be populated by ADD_EDGE; row: {rev}"
    );

    // testpeer→faraway: from the ADD_EDGE wire body. Addr tokens
    // round-tripped verbatim (`10.99.0.2` `655` from the `fwd`
    // body above). 6-token form (no local-addr suffix) → local
    // is `"unspec port unspec"` (`netutl.c:159-160`: `AF_UNSPEC`
    // case of `sockaddr2hostname`). options=0, weight=50.
    let tf = edge_rows
        .iter()
        .find(|r| r.starts_with("18 4 testpeer faraway "))
        .unwrap_or_else(|| panic!("no testpeer→faraway: {edge_rows:?}"));
    assert_eq!(
        tf, "18 4 testpeer faraway 10.99.0.2 port 655 unspec port unspec 0 50",
        "transitive edge: AddrStr round-trip from ADD_EDGE wire body"
    );

    // faraway→testpeer: same shape, addr from the `rev` body.
    let ft = edge_rows
        .iter()
        .find(|r| r.starts_with("18 4 faraway testpeer "))
        .unwrap_or_else(|| panic!("no faraway→testpeer: {edge_rows:?}"));
    assert_eq!(
        ft, "18 4 faraway testpeer 10.99.0.1 port 655 unspec port unspec 0 50",
        "transitive reverse: AddrStr round-trip"
    );

    // ─── update_edge: same edge, different weight ────────────
    // C `protocol_edge.c:159-183` in-place update path. Send the
    // SAME `testpeer→faraway` edge with weight 99 (was 50). Same
    // addr tokens — the addr in the dump row must stay identical
    // (proves `edge_addrs` key stability: `update_edge` keeps the
    // EdgeId slot, the HashMap entry was overwritten in place).
    //
    // Different nonce: `seen_request` would dedup an exact resend.
    let upd = b"12 33333333 testpeer faraway 10.99.0.2 655 0 99\n";
    let outs = sptps.send_record(0, upd).expect("add_edge update");
    for o in outs {
        if let Output::Wire { bytes, .. } = o {
            (&stream).write_all(&bytes).expect("send ADD_EDGE update");
        }
    }
    // No reply: forward_request skips us. Drain empty.
    let after_upd = drain_records(&mut sptps, &stream, &mut pending);
    assert!(
        after_upd.is_empty(),
        "forward_request should skip from-conn; got: {after_upd:?}"
    );

    // dump edges again: still 4 rows, testpeer→faraway has weight
    // 99, addr UNCHANGED.
    writeln!(ctl_w, "18 4").unwrap();
    let mut edge_rows2 = Vec::new();
    loop {
        let mut line = String::new();
        ctl_r.read_line(&mut line).expect("dump edge row 2");
        let line = line.trim_end().to_owned();
        if line == "18 4" {
            break;
        }
        edge_rows2.push(line);
    }
    assert_eq!(
        edge_rows2.len(),
        4,
        "dump edges post-update: {edge_rows2:?}"
    );
    let tf2 = edge_rows2
        .iter()
        .find(|r| r.starts_with("18 4 testpeer faraway "))
        .unwrap_or_else(|| panic!("no testpeer→faraway post-update: {edge_rows2:?}"));
    // (a) new weight; (b) addr identical to first dump. The addr
    // column proves `edge_addrs[existing]` was overwritten, not
    // re-keyed: del+add with a slot drift would lose the entry
    // and dump would show `"unknown port unknown"`.
    assert_eq!(
        tf2, "18 4 testpeer faraway 10.99.0.2 port 655 unspec port unspec 0 99",
        "update_edge: weight changed, addr preserved (EdgeId stable)"
    );

    // ─── stderr: BecameReachable fired for faraway ──────────────
    drop(stream);
    let _ = child.kill();
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    // The on_ack graph bridge fires testpeer-reachable first.
    assert!(
        stderr.contains("Node testpeer became reachable"),
        "on_ack reachable; stderr:\n{stderr}"
    );
    // THE PROOF: on_add_edge → run_graph → BecameReachable for the
    // TRANSITIVE node. C `graph.c:261`: `"Node %s became reachable"`.
    assert!(
        stderr.contains("Node faraway became reachable"),
        "on_add_edge didn't fire BecameReachable for transitive node; \
         stderr:\n{stderr}"
    );
}

/// Wrong key: the daemon has a DIFFERENT pubkey on file for us.
/// SIG verify fails → daemon drops the connection. Proves the
/// SPTPS auth actually authenticates (it's not just key exchange).
///
/// Same setup as `peer_handshake_reaches_done` but we register a
/// FAKE pubkey for ourselves in `hosts/testpeer`. The daemon's
/// SPTPS receive_sig step computes the transcript with that fake
/// pubkey, our SIG was made with the real one → BadSig.
#[test]
fn peer_wrong_key_fails_sig() {
    use rand_core::OsRng;
    use std::io::Read;
    use std::net::TcpStream;
    use tinc_crypto::sign::SigningKey;
    use tinc_sptps::{Framing, Output, Role, Sptps};

    let tmp = tmp("peer-wrong-key");
    let confbase = tmp.path().join("vpn");
    let pidfile = tmp.path().join("tinc.pid");
    let socket = tmp.path().join("tinc.socket");

    let daemon_pub = write_config(&confbase);
    // OUR real key (we sign with this).
    let our_key = SigningKey::from_seed(&[0x77; 32]);
    // FAKE pubkey we register at the daemon. Daemon will try to
    // verify our SIG with THIS → fail.
    let fake_pub = *SigningKey::from_seed(&[0x88; 32]).public_key();
    let b64 = tinc_crypto::b64::encode(&fake_pub);
    std::fs::write(
        confbase.join("hosts").join("testpeer"),
        format!("Ed25519PublicKey = {b64}\n"),
    )
    .unwrap();

    let mut child = Command::new(tincd_bin())
        .arg("-c")
        .arg(&confbase)
        .arg("--pidfile")
        .arg(&pidfile)
        .arg("--socket")
        .arg(&socket)
        .env("RUST_LOG", "tincd=info")
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    assert!(wait_for_file(&socket));
    let tcp_addr = read_tcp_addr(&pidfile);

    let stream = TcpStream::connect(tcp_addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    writeln!(&stream, "0 testpeer 17.7").unwrap();

    // Read past ID line, find KEX bytes.
    let mut buf = Vec::with_capacity(256);
    let mut tmp_buf = [0u8; 256];
    let id_end = loop {
        let n = (&stream).read(&mut tmp_buf).unwrap();
        if n == 0 {
            panic!("daemon closed early");
        }
        buf.extend_from_slice(&tmp_buf[..n]);
        if let Some(pos) = buf.iter().position(|&b| b == b'\n') {
            break pos;
        }
    };

    let mut label = b"tinc TCP key expansion testpeer testnode".to_vec();
    label.push(0);
    let (mut sptps, init) = Sptps::start(
        Role::Initiator,
        Framing::Stream,
        our_key,
        daemon_pub,
        label,
        0,
        &mut OsRng,
    );
    for o in init {
        if let Output::Wire { bytes, .. } = o {
            (&stream).write_all(&bytes).unwrap();
        }
    }

    // Feed daemon's KEX, send our SIG. The daemon's SIG verify
    // FAILS (wrong pubkey). Daemon terminates the connection.
    // We see EOF (or possibly OUR receive fails first if the
    // daemon's SIG also doesn't verify on our side — we have the
    // RIGHT daemon_pub so OUR side should be fine; the failure is
    // unidirectional).
    let mut pending: Vec<u8> = buf[id_end + 1..].to_vec();
    let deadline = Instant::now() + Duration::from_secs(5);
    let saw_eof = loop {
        if Instant::now() > deadline {
            break false;
        }
        let mut off = 0;
        while off < pending.len() {
            // OUR receive might also fail — the daemon's SIG was
            // made with the daemon's real private key, and we have
            // the matching daemon_pub, so OUR receive should
            // succeed. The failure is on the DAEMON's side.
            // But if it does fail: that's also a stop condition
            // (and the stderr check below disambiguates).
            match sptps.receive(&pending[off..], &mut OsRng) {
                Ok((0, _)) => break,
                Ok((n, outs)) => {
                    off += n;
                    for o in outs {
                        if let Output::Wire { bytes, .. } = o {
                            // Might fail if daemon already RST'd
                            // — ignore. The point is to send our
                            // SIG so the daemon's verify fires.
                            let _ = (&stream).write_all(&bytes);
                        }
                    }
                }
                Err(_) => break,
            }
        }
        pending.clear();

        // Read more (or detect EOF).
        match (&stream).read(&mut tmp_buf) {
            Ok(0) => break true, // EOF — daemon dropped us. EXPECTED.
            Ok(n) => pending.extend_from_slice(&tmp_buf[..n]),
            Err(_) => break false,
        }
    };

    // ─── the daemon's stderr says BadSig ─────────────────────────
    let _ = child.kill();
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);

    // Either saw_eof (daemon closed) OR the test loop timed out
    // (less likely). Either way: stderr is the proof.
    assert!(
        saw_eof,
        "expected daemon to close connection on bad SIG; stderr:\n{stderr}"
    );
    // The exact error variant from `feed_sptps`'s log line.
    // `SptpsError::BadSig` debug-formatted.
    assert!(
        stderr.contains("BadSig"),
        "expected BadSig in daemon stderr; stderr:\n{stderr}"
    );
    // And NOT the success line.
    assert!(
        !stderr.contains("SPTPS handshake completed"),
        "daemon should NOT have completed; stderr:\n{stderr}"
    );
}
