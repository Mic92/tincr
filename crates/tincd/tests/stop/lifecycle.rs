use std::ffi::OsStr;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::process::Stdio;
use std::time::{Duration, Instant};

use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;

use super::common::*;
use super::write_config;

/// RAII env-var setter. `set_var`/`remove_var` are unsafe in edition
/// 2024 (multi-threaded env-mutation race). Consolidate the unsafe
/// here so call sites are safe and cleanup is panic-safe.
struct EnvGuard(&'static str);
impl EnvGuard {
    #[allow(unsafe_code)]
    fn set(k: &'static str, v: impl AsRef<OsStr>) -> Self {
        // SAFETY: nextest runs each test in its own process; no
        // env-mutation race with parallel tests.
        unsafe { std::env::set_var(k, v) };
        Self(k)
    }
}
impl Drop for EnvGuard {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: same as `set` — single-threaded test process.
        unsafe { std::env::remove_var(self.0) }
    }
}

fn tmp(tag: &str) -> super::common::TmpGuard {
    super::common::TmpGuard::new("stop", tag)
}

/// THE walking-skeleton proof. Spawn tincd, connect to its control
/// socket, do the greeting dance, send `REQ_STOP`, daemon exits 0.
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
    let mut child = tincd_cmd()
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

    // The ack `"18 0 0"` MAY OR MAY NOT arrive. The CLI does
    // `while(recvline()) {}` — drain until EOF, ignoring contents.
    // The daemon QUEUES the ack but
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

/// `tinc start` umbilical handshake. The full cross-crate proof:
/// `tinc-tools::cmd::start::start()` forks, exec's the real tincd
/// with `TINC_UMBILICAL=<fd>` set, tincd's `cut_umbilical()` writes
/// the nul byte after `Daemon::setup` returns, `start()` reads it
/// and returns Ok.
///
/// This is the test that proves both halves of the umbilical agree
/// on the protocol. The unit tests in `cmd::start` only prove the
/// negative cases (no nul byte → error); THIS proves the positive.
///
/// We call `tinc_tools::cmd::start::start()` in-process (not via
/// the `tinc` binary) so we can point `TINCD_PATH` at our
/// just-built tincd. The forked child IS a separate process; only
/// the `start()` parent half runs in the test process.
#[test]
fn umbilical_ready_signal() {
    let tmp = tmp("umbilical");
    let confbase = tmp.path().join("vpn");
    let pidfile = tmp.path().join("tinc.pid");

    write_config(&confbase);

    // ─── Paths setup
    // `start()` needs `pidfile()` and `unix_socket()` resolved —
    // it passes them as `--pidfile`/`--socket` to the spawned
    // tincd. Explicit pidfile means `unix_socket()` derives
    // `tinc.socket` (the `.pid` → `.socket` substitution).
    let input = tinc_tools::names::PathsInput {
        confbase: Some(confbase.clone()),
        pidfile: Some(pidfile.clone()),
        ..Default::default()
    };
    let mut paths = tinc_tools::names::Paths::for_cli(&input);
    paths.resolve_runtime(&input);
    let socket = paths.unix_socket();

    // ─── point start() at our tincd
    // `find_tincd` checks TINCD_PATH first. CARGO_BIN_EXE_tincd
    // is the binary cargo just built for THIS crate.
    let _env = EnvGuard::set("TINCD_PATH", env!("CARGO_BIN_EXE_tincd"));

    // ─── the call under test
    // `start()` forks, child exec's tincd, tincd detaches (default
    // do_detach=true), the original child exits 0, tincd writes the
    // nul byte, parent reads it + waitpid succeeds. Ok(()).
    //
    // No `-D` in extra_args — we WANT detach, that's the production
    // shape. The detached daemon keeps running after `start()`
    // returns; we connect-and-stop it below.
    let result = tinc_tools::cmd::start::start(&paths, &[]);

    // The umbilical handshake itself. If the nul byte didn't
    // arrive (cut_umbilical didn't fire, or fired before setup
    // succeeded somehow), this is `Err("Error starting …")`.
    if let Err(e) = &result {
        panic!("tinc start failed: {e}");
    }

    // ─── daemon is actually ready
    // The whole point of the umbilical: by the time `start()`
    // returns, the daemon's control socket is bound. No
    // `wait_for_file` needed — if we needed it, the umbilical
    // would be lying.
    assert!(
        socket.exists(),
        "socket should exist immediately after start() returns; \
         umbilical fired before Daemon::setup finished?"
    );
    assert!(pidfile.exists(), "pidfile should exist after start()");

    // ─── idempotent start
    // Second `start` with daemon running is a no-op success. `CtlSocket::connect` succeeds → early
    // return Ok with the "already running" message.
    let second = tinc_tools::cmd::start::start(&paths, &[]);
    assert!(second.is_ok(), "second start should be idempotent Ok");

    // ─── stop it
    // Via the same control socket. `cmd::ctl_simple::stop` is the
    // production stop path; using it here proves `start && stop`
    // works end-to-end (the canonical sysadmin sequence).
    tinc_tools::cmd::ctl_simple::stop(&paths).expect("stop after start");

    // The detached daemon's exit doesn't surface as a Child we can
    // waitpid (it double-forked away from us). Best we can do:
    // poll for the pidfile to disappear (Daemon::drop unlinks it).
    let deadline = Instant::now() + Duration::from_secs(5);
    while pidfile.exists() {
        assert!(
            Instant::now() < deadline,
            "daemon didn't unlink pidfile after stop"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Daemon-side half in isolation: spawn tincd with `TINC_UMBILICAL`
/// pointing at a socketpair we control, read the nul byte ourselves.
/// Proves `cut_umbilical` does the right thing without involving
/// `tinc-tools::cmd::start` at all.
///
/// This is the cheaper test — no fork-from-the-test, just
/// `Command::spawn` with an inherited fd. If the cross-crate test
/// above breaks, this one tells you which half is at fault.
#[test]
fn umbilical_daemon_side() {
    use std::os::fd::AsRawFd;

    let tmp = tmp("umbilical-daemon");
    let confbase = tmp.path().join("vpn");
    let pidfile = tmp.path().join("tinc.pid");
    let socket = tmp.path().join("tinc.socket");

    write_config(&confbase);

    // socketpair. We keep `ours`, the child inherits `theirs`.
    // UnixStream::pair is the safe wrapper around socketpair(
    // AF_UNIX, SOCK_STREAM).
    let (mut ours, theirs) = UnixStream::pair().unwrap();

    // The child's fd number for `theirs` is stable across spawn
    // ONLY if we don't set CLOEXEC on it. UnixStream::pair sets
    // CLOEXEC by default (Rust's std does for everything). We
    // need it inherited, so clear CLOEXEC. nix::fcntl on RawFd is
    // a safe wrapper — it's a probe-style call, not ownership.
    let theirs_fd = theirs.as_raw_fd();
    nix::fcntl::fcntl(
        &theirs,
        nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty()),
    )
    .unwrap();

    // -D so the child doesn't detach — we want to waitpid it
    // directly. (The cross-crate test above does detach; this
    // one is the simpler shape.)
    let mut child = tincd_cmd()
        .arg("-c")
        .arg(&confbase)
        .arg("--pidfile")
        .arg(&pidfile)
        .arg("--socket")
        .arg(&socket)
        .env("TINC_UMBILICAL", format!("{theirs_fd} 0"))
        .env("RUST_LOG", "tincd=debug")
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tincd");

    // CRITICAL: drop `theirs` in the parent so we see EOF when the
    // child closes its copy. Same as `close(pfd[1])`.
    drop(theirs);

    // Read the umbilical. cut_umbilical writes exactly 1 nul byte
    // then closes. We don't tee logs, so 1 byte then EOF is the
    // whole conversation.
    ours.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut buf = [0u8; 16];
    let n = std::io::Read::read(&mut ours, &mut buf).expect("read umbilical");
    assert_eq!(n, 1, "expected exactly 1 byte (the nul)");
    assert_eq!(buf[0], 0, "expected nul byte, got {:#04x}", buf[0]);

    // Second read: EOF (cut_umbilical closed).
    let n = std::io::Read::read(&mut ours, &mut buf).expect("read for EOF");
    assert_eq!(n, 0, "expected EOF after nul byte");

    // The daemon is still running (foreground, -D). The umbilical
    // signal arrived, which means setup succeeded — the socket is
    // bound. Connect and stop.
    assert!(socket.exists(), "socket bound after umbilical signal");

    let cookie = read_cookie(&pidfile);
    let stream = UnixStream::connect(&socket).expect("connect to tincd");
    let mut reader = BufReader::new(&stream);
    let mut writer = &stream;
    writeln!(writer, "0 ^{cookie} 0").unwrap();
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    line.clear();
    reader.read_line(&mut line).unwrap();
    writeln!(writer, "18 0").unwrap(); // REQ_STOP
    while reader.read_line(&mut line).unwrap() > 0 {}

    let status = child.wait().unwrap();
    assert!(status.success(), "tincd exit: {status:?}");
}

/// SIGTERM also stops the daemon. Proves the `SelfPipe` + signal
/// handler path. Same setup; instead of sending `REQ_STOP`, send a
/// signal.
#[test]
fn sigterm_stops() {
    let tmp = tmp("sigterm");
    let confbase = tmp.path().join("vpn");
    let pidfile = tmp.path().join("tinc.pid");
    let socket = tmp.path().join("tinc.socket");

    write_config(&confbase);

    let mut child = tincd_cmd()
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

    #[allow(clippy::cast_possible_wrap)] // pid_t fits a child PID
    let pid = Pid::from_raw(pid as i32);
    kill(pid, Signal::SIGTERM).expect("kill SIGTERM");

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

/// SIGUSR1/SIGUSR2/SIGWINCH must NOT terminate the daemon. C tinc
/// sets these to `SIG_IGN` in `detach()` (process.c:205-207). Older
/// 1.0.x tincd dumped state on USR1/USR2; in 1.1 that moved to the
/// control socket and the signals are simply ignored. A monitoring
/// script that still sends USR1 expecting a stats dump should be
/// harmless, not fatal.
///
/// Regression: the Rust port left these at default disposition
/// (terminate), so `kill -USR1` killed the daemon.
#[test]
fn sigusr_ignored() {
    let tmp = tmp("sigusr");
    let confbase = tmp.path().join("vpn");
    let pidfile = tmp.path().join("tinc.pid");
    let socket = tmp.path().join("tinc.socket");

    write_config(&confbase);

    let mut child = tincd_cmd()
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

    #[allow(clippy::cast_possible_wrap)] // pid_t fits a child PID
    let pid = Pid::from_raw(child.id() as i32);

    // Fire each signal, give the daemon a moment, assert it's still
    // alive. If any disposition is default, the process is gone and
    // try_wait() returns Some with a signal-terminated status.
    for &sig in &[Signal::SIGUSR1, Signal::SIGUSR2, Signal::SIGWINCH] {
        assert!(kill(pid, sig).is_ok(), "kill({sig}) failed");
        std::thread::sleep(Duration::from_millis(100));
        if let Some(status) = child.try_wait().unwrap() {
            panic!("tincd terminated by signal {sig}: {status:?}");
        }
    }

    // Now SIGTERM should still cleanly stop it (proves the signal
    // machinery wasn't broken by the SIG_IGN installs).
    kill(pid, Signal::SIGTERM).expect("kill SIGTERM");
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        assert!(Instant::now() < deadline, "tincd didn't exit on SIGTERM");
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(status.success(), "tincd should exit cleanly on SIGTERM");
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

    let mut first = tincd_cmd()
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
    let second = tincd_cmd()
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
/// skeleton doesn't read `PingTimeout`. Ugh.)
///
/// What we CAN test: the daemon stays alive for several seconds
/// without crashing. If `on_ping_tick` forgot to re-arm, `tick()`
/// returns `None` next time → `turn(None)` blocks forever → daemon
/// is unresponsive. Connect after 2s to prove it's still listening.
///
/// (Weaker than a direct timer-fired check but proves the loop
/// stays alive across multiple iterations. The `pingtimeout=5s`
/// means the timer fires once at most in this test. Chunk 3 reads
/// `PingTimeout` from config and we can set it to 1s.)
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

    let mut child = tincd_cmd()
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

/// Bad cookie in greeting → connection dropped. Proves the
/// `handle_id` cookie check + `terminate` path.
#[test]
fn bad_cookie_dropped() {
    let tmp = tmp("badcookie");
    let confbase = tmp.path().join("vpn");
    let pidfile = tmp.path().join("tinc.pid");
    let socket = tmp.path().join("tinc.socket");

    write_config(&confbase);

    let mut child = tincd_cmd()
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

/// TCP meta listener bring-up. Proves:
///
/// - `open_listeners` actually binds (port in pidfile is real)
/// - `pidfile_addr` writes a connectable addr (the unspec→loopback
///   mapping; THIS is the test for `init_control:164-173`)
/// - `IoWhat::Tcp(i)` arm dispatches to `on_tcp_accept`
/// - Tarpit doesn't fire (peer is `127.0.0.1`, `is_local` exempts)
/// - The `^cookie` control branch is rejected on TCP (unix-only)
///
/// What this DOESN'T prove: tarpit firing (loopback is exempt). The
/// `listen.rs::tarpit_*` unit tests cover the bucket arithmetic.
#[test]
fn tcp_listener_accepts_and_rejects_control() {
    use std::net::TcpStream;

    let tmp = tmp("tcp-stop");
    let confbase = tmp.path().join("vpn");
    let pidfile = tmp.path().join("tinc.pid");
    let socket = tmp.path().join("tinc.socket");

    write_config(&confbase);

    let mut child = tincd_cmd()
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

    // ─── ^cookie over TCP → dropped, no reply ────────────────
    writeln!(writer, "0 ^{cookie} 0").unwrap();
    let mut line1 = String::new();
    let n = reader.read_line(&mut line1).unwrap();
    assert_eq!(
        n, 0,
        "daemon must drop ^cookie over TCP without replying; got {line1:?}"
    );
    drop(stream);

    // ─── STOP via unix socket ─────────────────────────────────
    let ustream = UnixStream::connect(&socket).expect("unix connect");
    let mut reader = BufReader::new(&ustream);
    let mut writer = &ustream;
    writeln!(writer, "0 ^{cookie} 0").unwrap();
    let mut g1 = String::new();
    reader.read_line(&mut g1).unwrap();
    assert_eq!(g1, "0 testnode 17.7\n", "daemon greeting (unix)");
    let mut g2 = String::new();
    reader.read_line(&mut g2).unwrap();
    assert!(g2.starts_with("4 0 "), "ACK line: {g2:?}");
    writeln!(writer, "18 0").unwrap();
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break,
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
