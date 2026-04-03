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
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Hand-rolled tempdir guard. Same pattern as the rest of the
/// workspace: thread id in name, cleanup on drop, no `tempfile` dep.
struct TmpGuard(PathBuf);

impl TmpGuard {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "tincd-stop-{}-{:?}",
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

/// Find the tincd binary cargo built. `CARGO_BIN_EXE_tincd` is set
/// by cargo for THIS crate's integration tests. Same pattern as
/// `tinc-tools/tests/self_roundtrip.rs::bin`.
fn tincd_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tincd"))
}

/// Write a minimal config: `tinc.conf` (Name, DeviceType, AddressFamily)
/// plus `hosts/testnode` (Port = 0).
///
/// `Port = 0` is critical: the daemon binds TCP+UDP listeners now.
/// Port 655 would clash between parallel test threads (and might be
/// taken by something else on the build host). Port 0 = kernel picks.
/// Each test gets its own port. The pidfile contains the assigned
/// port, so tests that need TCP can read it from there.
///
/// `AddressFamily = ipv4` reduces to one listener. v6 might be
/// disabled in the build sandbox; v4 is universal. Tests that
/// specifically want dual-stack can override.
///
/// `Port` is HOST-tagged (per `tincctl.c:1751`). Goes in `hosts/
/// testnode`, not tinc.conf. The daemon's `read_host_config` step
/// merges it into the same lookup tree.
fn write_config(confbase: &std::path::Path) {
    std::fs::create_dir_all(confbase.join("hosts")).unwrap();
    std::fs::write(
        confbase.join("tinc.conf"),
        "Name = testnode\nDeviceType = dummy\nAddressFamily = ipv4\n",
    )
    .unwrap();
    std::fs::write(confbase.join("hosts").join("testnode"), "Port = 0\n").unwrap();
}

/// Poll for a file to appear. The daemon writes the pidfile in
/// `setup()`; we don't know exactly when. Timeout 5s.
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

/// Read the cookie from the pidfile. Same format as
/// `tinc-tools::Pidfile::read` parses: `<pid> <cookie> <host> port <port>\n`.
fn read_cookie(pidfile: &std::path::Path) -> String {
    let content = std::fs::read_to_string(pidfile).unwrap();
    // Second whitespace-delimited token.
    content
        .split_whitespace()
        .nth(1)
        .expect("pidfile has cookie")
        .to_owned()
}

/// Read the TCP address from the pidfile. The daemon writes
/// `<pid> <cookie> <host> port <port>` (`control.c:178`, our
/// `pidfile_addr`). With `AddressFamily = ipv4` and the unspec→
/// loopback mapping, this is `127.0.0.1 port <kernel-port>`.
///
/// Returns a `SocketAddr` (the parser fuses host+port). v6 hosts
/// don't have brackets in the pidfile (see `listen::fmt_addr_v6_
/// no_brackets`), but `SocketAddr::from_str` wants brackets. So:
/// only works for v4. Our tests use `AddressFamily = ipv4`.
fn read_tcp_addr(pidfile: &std::path::Path) -> std::net::SocketAddr {
    let content = std::fs::read_to_string(pidfile).unwrap();
    // Format: `<pid> <cookie> <host> port <port>\n`.
    // `" port "` is the literal separator (`sockaddr2hostname`).
    let after_cookie = content.splitn(3, ' ').nth(2).expect("pidfile has addr");
    // Now: `"127.0.0.1 port 50123\n"`.
    let mut parts = after_cookie.trim_end().split(" port ");
    let host = parts.next().expect("host");
    let port: u16 = parts.next().expect("port").parse().expect("port is num");
    // v4 only — see doc comment.
    format!("{host}:{port}").parse().expect("parseable v4 addr")
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
    let tmp = TmpGuard::new("connect-stop");
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
    let tmp = TmpGuard::new("sigterm");
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
    let tmp = TmpGuard::new("second");
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
    let tmp = TmpGuard::new("alive");
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
    let tmp = TmpGuard::new("noconfig");
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
    let tmp = TmpGuard::new("noname");
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
    let tmp = TmpGuard::new("badcookie");
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

    let tmp = TmpGuard::new("tcp-stop");
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
    let tmp = TmpGuard::new("nohosts");
    let confbase = tmp.path().join("vpn");
    let pidfile = tmp.path().join("tinc.pid");
    let socket = tmp.path().join("tinc.socket");

    // tinc.conf ONLY. No hosts/ dir at all. Port goes here — see doc.
    std::fs::create_dir_all(&confbase).unwrap();
    std::fs::write(
        confbase.join("tinc.conf"),
        "Name = testnode\nDeviceType = dummy\nAddressFamily = ipv4\nPort = 0\n",
    )
    .unwrap();
    // Precondition: hosts/ doesn't exist.
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

    let tmp = TmpGuard::new("udp-stray");
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
