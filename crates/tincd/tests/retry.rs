//! `retry()`: the "network came back, reconnect NOW" button.
//! Triggered by SIGALRM and `tinc retry` (`REQ_RETRY`). Also
//! `REQ_DISCONNECT`.
//!
//! ## What's proven
//!
//! Without `retry()`, an outgoing in backoff waits the full backoff
//! period before re-dialing. With it, the timer is reset to fire-now
//! and the backoff seconds zeroed. The test sets up an outgoing to a
//! port nobody's listening on, lets the daemon hit ECONNREFUSED →
//! `retry_outgoing` (5s backoff), then sends SIGALRM (or `REQ_RETRY`)
//! and asserts the next dial attempt arrives in well under 5s.
//!
//! `REQ_DISCONNECT` we test the not-found path (`"18 12 -2"`) — the
//! found path needs a real second daemon, which is `two_daemons.rs`
//! territory (off-limits for this commit).

use std::io::{BufRead, Read, Write};
use std::process::Stdio;
use std::time::{Duration, Instant};

mod common;
use common::{
    Ctl, TmpGuard, alloc_port, drain_stderr, read_cookie, tincd_cmd, wait_for_file,
    write_ed25519_privkey,
};

fn tmp(tag: &str) -> TmpGuard {
    TmpGuard::new("retry", tag)
}

/// Minimal config: `ConnectTo` a peer whose Address points at a port
/// nobody's listening on. `do_outgoing_connection` → ECONNREFUSED →
/// addr cache exhausted (one Address) → `retry_outgoing` → 5s backoff.
fn write_config_dead_peer(confbase: &std::path::Path, dead_port: u16) {
    std::fs::create_dir_all(confbase.join("hosts")).unwrap();
    std::fs::write(
        confbase.join("tinc.conf"),
        "Name = testnode\nDeviceType = dummy\nAddressFamily = ipv4\n\
         ConnectTo = deadpeer\nPingTimeout = 3\n",
    )
    .unwrap();
    std::fs::write(confbase.join("hosts").join("testnode"), "Port = 0\n").unwrap();

    // hosts/deadpeer: pubkey (any) + Address pointing at the dead
    // port. The daemon never gets past TCP connect, so the pubkey is
    // never checked — but `read_ecdsa_public_key` (called from id_h
    // setup, not here) needs the line to exist for ConnectTo's
    // `lookup_or_add_node` graph entry to not warn. Harmless dummy.
    let dummy_pub = tinc_crypto::b64::encode(&common::pubkey_from_seed(&[0xDE; 32]));
    std::fs::write(
        confbase.join("hosts").join("deadpeer"),
        format!("Ed25519PublicKey = {dummy_pub}\nAddress = 127.0.0.1 {dead_port}\n"),
    )
    .unwrap();

    write_ed25519_privkey(confbase, &[0x42; 32]);
}

/// Background stderr drain. Same shape as `common::linux::ChildWithLog`
/// but not linux-gated and exposes a snapshot read (so we can poll
/// for log lines without killing the child first).
struct LogReader {
    log: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    _drain: std::thread::JoinHandle<()>,
}

impl LogReader {
    fn spawn(stderr: std::process::ChildStderr) -> Self {
        let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let log2 = std::sync::Arc::clone(&log);
        let drain = std::thread::spawn(move || {
            let mut r = stderr;
            let mut buf = [0u8; 4096];
            while let Ok(n) = r.read(&mut buf) {
                if n == 0 {
                    break;
                }
                log2.lock().unwrap().extend_from_slice(&buf[..n]);
            }
        });
        Self { log, _drain: drain }
    }

    fn snapshot(&self) -> String {
        String::from_utf8_lossy(&self.log.lock().unwrap()).into_owned()
    }
}

/// Count occurrences of `needle` in the live log. Polled.
fn count_in_log(log: &LogReader, needle: &str) -> usize {
    log.snapshot().matches(needle).count()
}

// ═══════════════════════════════════════════════════════════════════

/// SIGALRM → `on_retry()` → retry timer fires NOW. The proof: the
/// second `Trying to connect` log line arrives well before the 5s
/// backoff would have expired naturally.
#[test]
fn sigalrm_retries_now() {
    let tmp = tmp("sigalrm");
    let confbase = tmp.path().join("vpn");
    let pidfile = tmp.path().join("tinc.pid");
    let socket = tmp.path().join("tinc.socket");

    // alloc_port reserves a port and immediately frees it. Nothing
    // re-binds it; connect() gets ECONNREFUSED. Same trick as
    // two_daemons::outgoing_retry_after_refused but we never start
    // the listener — backoff stays armed.
    let dead_port = alloc_port();
    write_config_dead_peer(&confbase, dead_port);

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
    let log = LogReader::spawn(child.stderr.take().unwrap());

    if !wait_for_file(&socket) {
        let _ = child.kill();
        panic!("tincd setup failed; stderr:\n{}", log.snapshot());
    }

    // ─── wait for first connect attempt + 5s backoff arm ────────
    // First failure backs off 5s.
    let deadline = Instant::now() + Duration::from_secs(5);
    while count_in_log(&log, "Trying to connect to deadpeer") < 1 {
        assert!(Instant::now() < deadline, "no first connect attempt");
        std::thread::sleep(Duration::from_millis(20));
    }
    while !log
        .snapshot()
        .contains("re-establish outgoing connection in 5 seconds")
    {
        assert!(Instant::now() < deadline, "no backoff log");
        std::thread::sleep(Duration::from_millis(20));
    }
    // Backoff armed at 5s. Mark time.
    let armed_at = Instant::now();

    // ─── SIGALRM ────────────────────────────────────────────────
    #[allow(clippy::cast_possible_wrap)] // child.id() is a real PID (< pid_max ≤ 2^22)
    let pid = nix::unistd::Pid::from_raw(child.id() as i32);
    nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGALRM).expect("kill SIGALRM");

    // ─── second connect attempt arrives FAST ────────────────────
    // `on_retry()` sets the timer to Duration::ZERO; next turn() it
    // fires → setup_outgoing_connection → dial. Should take a few
    // ticks at most. 2s is generous; 5s would be the natural
    // backoff (test would pass without on_retry if we waited that
    // long — so the upper bound IS the assertion).
    let retry_deadline = armed_at + Duration::from_secs(2);
    while count_in_log(&log, "Trying to connect to deadpeer") < 2 {
        assert!(
            Instant::now() < retry_deadline,
            "SIGALRM didn't trigger retry within 2s (backoff still 5s?); \
             stderr:\n{}",
            log.snapshot()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let elapsed = armed_at.elapsed();
    assert!(
        elapsed < Duration::from_secs(2),
        "retry took {elapsed:?} — should be near-instant after SIGALRM"
    );

    // ─── stderr: the SIGALRM handler log ────────────────────────
    let snap = log.snapshot();
    assert!(
        snap.contains("Got SIGALRM, retrying outgoing connections"),
        "SIGALRM handler log missing; stderr:\n{snap}"
    );
    // Backoff was zeroed: the SECOND retry_outgoing log says 5s
    // again (0 + 5), not 10s (5 + 5). Proves `outgoing.timeout = 0`.
    assert_eq!(
        snap.matches("re-establish outgoing connection in 5 seconds")
            .count(),
        2,
        "second backoff should also be 5s (timeout zeroed); stderr:\n{snap}"
    );
    assert!(
        !snap.contains("re-establish outgoing connection in 10 seconds"),
        "backoff bumped to 10s — outgoing.timeout NOT zeroed; stderr:\n{snap}"
    );

    let _ = child.kill();
    let _ = child.wait();
}

/// `REQ_RETRY` (`"18 10"`) → same `on_retry()` path. Ack `"18 10 0"`.
#[test]
fn req_retry_retries_now() {
    let tmp = tmp("req-retry");
    let confbase = tmp.path().join("vpn");
    let pidfile = tmp.path().join("tinc.pid");
    let socket = tmp.path().join("tinc.socket");

    let dead_port = alloc_port();
    write_config_dead_peer(&confbase, dead_port);

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
    let log = LogReader::spawn(child.stderr.take().unwrap());

    if !wait_for_file(&socket) {
        let _ = child.kill();
        panic!("tincd setup failed; stderr:\n{}", log.snapshot());
    }

    // Wait for first attempt + backoff arm. Same as above.
    let deadline = Instant::now() + Duration::from_secs(5);
    while !log
        .snapshot()
        .contains("re-establish outgoing connection in 5 seconds")
    {
        assert!(Instant::now() < deadline, "no backoff log");
        std::thread::sleep(Duration::from_millis(20));
    }
    let armed_at = Instant::now();

    // ─── send REQ_RETRY over ctl socket ─────────────────────────
    // `Ctl::connect` does the greeting dance.
    let mut ctl = Ctl::connect(&socket, &pidfile);
    writeln!(ctl.w, "18 10").unwrap();

    // `control_ok` → `"%d %d %d", CONTROL, type, 0` → `"18 10 0\n"`.
    let mut ack = String::new();
    ctl.r.read_line(&mut ack).expect("retry ack");
    assert_eq!(ack.trim_end(), "18 10 0", "REQ_RETRY ack");

    // ─── second connect attempt arrives FAST ────────────────────
    let retry_deadline = armed_at + Duration::from_secs(2);
    while count_in_log(&log, "Trying to connect to deadpeer") < 2 {
        assert!(
            Instant::now() < retry_deadline,
            "REQ_RETRY didn't trigger retry within 2s; stderr:\n{}",
            log.snapshot()
        );
        std::thread::sleep(Duration::from_millis(20));
    }

    drop(ctl);
    let _ = child.kill();
    let _ = child.wait();
}

/// `REQ_DISCONNECT` not-found (`"18 12 nobody"` → `"18 12 -2"`) and
/// malformed (`"18 12"` → `"18 12 -1"`).
///
/// The found path (terminate a real conn) needs a second daemon —
/// covered by `two_daemons.rs` infrastructure, off-limits here.
/// The protocol parse + reply codes are what's new.
#[test]
fn req_disconnect_replies() {
    let tmp = tmp("disconnect");
    let confbase = tmp.path().join("vpn");
    let pidfile = tmp.path().join("tinc.pid");
    let socket = tmp.path().join("tinc.socket");

    // No ConnectTo. Just the daemon + ctl conn.
    std::fs::create_dir_all(confbase.join("hosts")).unwrap();
    std::fs::write(
        confbase.join("tinc.conf"),
        "Name = testnode\nDeviceType = dummy\nAddressFamily = ipv4\n",
    )
    .unwrap();
    std::fs::write(confbase.join("hosts").join("testnode"), "Port = 0\n").unwrap();
    write_ed25519_privkey(&confbase, &[0x42; 32]);

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

    assert!(wait_for_file(&socket), "tincd setup failed; stderr: {}", {
        drain_stderr(child)
    });

    let cookie = read_cookie(&pidfile);
    let stream = std::os::unix::net::UnixStream::connect(&socket).expect("ctl connect");
    let mut r = std::io::BufReader::new(&stream);
    let mut w = &stream;
    writeln!(w, "0 ^{cookie} 0").unwrap();
    let mut greet = String::new();
    r.read_line(&mut greet).unwrap();
    let mut ack = String::new();
    r.read_line(&mut ack).unwrap();

    // ─── not found: `"18 12 nobody"` → `"18 12 -2"` ─────────────
    // Only conn is us (`<control>`); no `nobody` conn exists.
    writeln!(w, "18 12 nobody").unwrap();
    let mut reply = String::new();
    r.read_line(&mut reply).unwrap();
    assert_eq!(reply.trim_end(), "18 12 -2", "not-found reply");

    // ─── malformed: `"18 12"` (no name) → `"18 12 -1"` ──────────
    writeln!(w, "18 12").unwrap();
    let mut reply = String::new();
    r.read_line(&mut reply).unwrap();
    assert_eq!(reply.trim_end(), "18 12 -1", "malformed reply");

    // ─── ctl conn still alive after both ────────────────────────
    // `control_return` always returns true; conn stays.
    // REQ_DUMP_CONNECTIONS proves we can still talk.
    writeln!(w, "18 6").unwrap();
    let mut rows = Vec::new();
    loop {
        let mut line = String::new();
        r.read_line(&mut line).expect("dump row");
        let line = line.trim_end().to_owned();
        if line == "18 6" {
            break;
        }
        rows.push(line);
    }
    // Only us (the ctl conn).
    assert_eq!(rows.len(), 1, "dump connections after disconnect attempts");

    let _ = child.kill();
    let _ = child.wait();
}
