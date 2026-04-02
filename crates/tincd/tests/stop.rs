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

/// Write a minimal `tinc.conf`. Just `Name` + `DeviceType=dummy`.
fn write_config(confbase: &std::path::Path) {
    std::fs::create_dir_all(confbase).unwrap();
    std::fs::write(
        confbase.join("tinc.conf"),
        "Name = testnode\nDeviceType = dummy\n",
    )
    .unwrap();
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
/// `tinc-tools::Pidfile::read` parses: `<pid> <cookie> <addr>\n`.
fn read_cookie(pidfile: &std::path::Path) -> String {
    let content = std::fs::read_to_string(pidfile).unwrap();
    // Second whitespace-delimited token.
    content
        .split_whitespace()
        .nth(1)
        .expect("pidfile has cookie")
        .to_owned()
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

    // Sleep across at least one timer tick. pingtimeout=5s default;
    // 6s ensures one tick. (Slow, but proves the re-arm. Chunk 3
    // makes this configurable.)
    std::thread::sleep(Duration::from_secs(6));

    // Daemon should still be alive (no panic, no exit).
    assert!(
        child.try_wait().unwrap().is_none(),
        "tincd died during sleep"
    );

    // And still responsive: connect succeeds.
    let _stream = UnixStream::connect(&socket).expect("daemon still listening after 6s");

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
