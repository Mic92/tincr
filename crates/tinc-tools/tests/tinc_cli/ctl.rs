use super::{bare_dir, tinc};

/// `tinc pid` with no daemon running. The pidfile doesn't exist;
/// `Pidfile::read` returns `PidfileMissing`; binary prints C's
/// message and exits 1. The `--pidfile` override is what makes this
/// deterministic — we point at a path that definitely doesn't exist,
/// rather than depending on whether `/var/run/tinc.pid` happens to.
#[test]
fn ctl_pidfile_missing() {
    let dir = tempfile::tempdir().unwrap();
    let cb = dir.path().to_str().unwrap();
    let pidfile = dir.path().join("nope.pid");
    let pidfile_s = pidfile.to_str().unwrap();

    let out = tinc(&["-c", cb, "--pidfile", pidfile_s, "pid"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    // C phrasing: "Could not open pid file %s: %s"
    assert!(stderr.contains("Could not open pid file"), "{stderr}");
    assert!(stderr.contains("nope.pid"), "{stderr}");
}

/// `tinc reload` with malformed pidfile. The file exists but doesn't
/// parse — `Pidfile::read` returns `PidfileMalformed`. Exercises the
/// stricter-than-C cookie validation.
#[test]
fn ctl_pidfile_malformed() {
    let dir = tempfile::tempdir().unwrap();
    let cb = dir.path().to_str().unwrap();
    let pidfile = dir.path().join("bad.pid");
    // Missing fields. C `fscanf` returns < 4.
    std::fs::write(&pidfile, "1234 toolittle\n").unwrap();
    let pidfile_s = pidfile.to_str().unwrap();

    let out = tinc(&["-c", cb, "--pidfile", pidfile_s, "reload"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("Could not parse pid file"), "{stderr}");
}

/// `tinc disconnect` arity: missing arg. The arity check runs
/// BEFORE connect (it's in the binary adapter). No socket touched.
#[test]
fn ctl_disconnect_missing_arg() {
    let (_dir, cb) = bare_dir();
    // Don't bother with --pidfile; arity fails before resolve.
    let out = tinc(&["-c", &cb, "disconnect"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("No node name given"), "{stderr}");
}

/// `tinc disconnect bad/name` → check_id fails before connect.
/// Same preflight property as join's tinc.conf-exists check.
#[test]
fn ctl_disconnect_bad_name() {
    let (_dir, cb) = bare_dir();
    // Point pidfile somewhere it'll fail to read — if we *reach*
    // it, the test fails with "could not open pid file" instead of
    // "invalid name", proving check_id didn't run first.
    let out = tinc(&[
        "-c",
        &cb,
        "--pidfile",
        "/nonexistent/pid",
        "disconnect",
        "bad/name",
    ]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("Invalid name"), "{stderr}");
    // NOT the pidfile error. check_id ran first.
    assert!(!stderr.contains("pid file"), "{stderr}");
}

/// The full connect path against a real fake-daemon. This is the
/// integration test that `ctl.rs::connect()` couldn't have — it
/// needs a real listening unix socket and a real pidfile.
///
/// The fake daemon is a thread. It binds a unix socket, writes a
/// pidfile pointing at *our own pid* (so kill(pid, 0) succeeds),
/// accepts one connection, does the greeting, serves one CONTROL
/// request, drops. The binary connects to it through the same
/// `CtlSocket::connect()` it would use against real tincd.
///
/// What this proves that the unit tests don't: `Pidfile::read` →
/// `kill(pid, 0)` → `UnixStream::connect` → `handshake()` chain works
/// with real fs paths and real syscalls. The unit tests use
/// `UnixStream::pair()` which skips the bind/connect/filesystem half.
///
/// Why this is parallel-safe: tempdir is unique, socket path inside
/// it is unique, pidfile inside it is unique. The pid we write IS
/// our test process's pid (so `kill(pid, 0)` doesn't ESRCH). Multiple
/// test threads using their own pid for their own pidfile is fine —
/// they're all checking "is *something* alive at this pid", and
/// something is (us).
#[test]
#[cfg(unix)]
fn ctl_full_connect_against_fake_daemon() {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;

    let dir = tempfile::tempdir().unwrap();
    let cb = dir.path().to_str().unwrap();
    let pidfile = dir.path().join("tinc.pid");
    let sock = dir.path().join("tinc.socket");

    // ─── Set up the fake daemon's state ────────────────────────────────
    let cookie = "0123456789abcdef".repeat(4);
    // Our own pid — so kill(pid, 0) returns 0. Pid type: u32 fits.
    let our_pid = std::process::id();
    std::fs::write(&pidfile, format!("{our_pid} {cookie} 127.0.0.1 port 655\n")).unwrap();

    // ─── Fake daemon thread: listen, accept, greet, serve ──────────
    let listener = UnixListener::bind(&sock).unwrap();
    let cookie_thr = cookie.clone();
    let daemon = std::thread::spawn(move || {
        let (stream, _addr) = listener.accept().unwrap();
        let mut br = BufReader::new(&stream);
        let mut w = &stream;

        // Recv ID, check cookie. C `id_h:325`.
        let mut line = String::new();
        br.read_line(&mut line).unwrap();
        assert!(line.contains(&format!("^{cookie_thr}")));

        // Greeting line 1 (send_id) + line 2 (ACK ctl-ver pid).
        // The pid in line 2 is what `cmd_pid` will print — we send
        // a *different* pid here than the one in the pidfile to
        // prove the printed pid comes from the greeting, not the
        // pidfile. (C `tincctl.c:891` overwrites `pid` from line 2.)
        writeln!(w, "0 fakedaemon 17.7").unwrap();
        writeln!(w, "4 0 99999").unwrap();

        // No CONTROL line for `pid` — it's just the connect side
        // effect. Drop.
    });

    // ─── Run the binary ─────────────────────────────────────────────
    // `tinc.pid` → `tinc.socket` via the .pid → .socket suffix
    // surgery in `unix_socket()`. The fake bound to `tinc.socket`
    // above; the binary derives the same path.
    let pidfile_s = pidfile.to_str().unwrap();
    let out = tinc(&["-c", cb, "--pidfile", pidfile_s, "pid"]);

    daemon.join().unwrap();

    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(out.status.success(), "stderr: {stderr}");
    // The pid from greeting line 2, NOT from the pidfile. C
    // `tincctl.c:891`: `sscanf("%d %d %d", ..., &pid)` — line 2
    // overwrites the pid that was read from the pidfile. The
    // pidfile's pid is for the kill(2) probe; the greeting's pid
    // is the truth.
    assert_eq!(stdout.trim(), "99999");
}

/// Same as above but with `reload` — a real CONTROL line round-trip.
/// Proves the post-greeting send/ack works through the binary.
#[test]
#[cfg(unix)]
fn ctl_reload_against_fake_daemon() {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;

    let dir = tempfile::tempdir().unwrap();
    let cb = dir.path().to_str().unwrap();
    let pidfile = dir.path().join("tinc.pid");
    let sock = dir.path().join("tinc.socket");

    let cookie = "fedcba9876543210".repeat(4);
    let our_pid = std::process::id();
    std::fs::write(&pidfile, format!("{our_pid} {cookie} 127.0.0.1 port 655\n")).unwrap();

    let listener = UnixListener::bind(&sock).unwrap();
    let cookie_thr = cookie.clone();
    let daemon = std::thread::spawn(move || {
        let (stream, _addr) = listener.accept().unwrap();
        let mut br = BufReader::new(&stream);
        let mut w = &stream;

        let mut line = String::new();
        br.read_line(&mut line).unwrap();
        assert!(line.contains(&format!("^{cookie_thr}")));
        writeln!(w, "0 fakedaemon 17.7").unwrap();
        writeln!(w, "4 0 1").unwrap();

        // Receive REQ_RELOAD.
        let mut req = String::new();
        br.read_line(&mut req).unwrap();
        // Exact wire shape: "18 1\n". CONTROL=18, REQ_RELOAD=1.
        // This is the assertion that makes this test more than a
        // smoke test: the binary sent the *right ints*, in the
        // *right format*, that a real daemon's `control_h` would
        // accept. Not just "something arrived".
        assert_eq!(req.trim_end(), "18 1");

        // Ack: success.
        writeln!(w, "18 1 0").unwrap();
    });

    let pidfile_s = pidfile.to_str().unwrap();
    let out = tinc(&["-c", cb, "--pidfile", pidfile_s, "reload"]);

    daemon.join().unwrap();

    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(out.status.success(), "stderr: {stderr}");
    // No output on success. C `cmd_reload` returns 0 silently.
    assert!(out.stdout.is_empty());
}

// ────────────────────────────────────────────────────────────────────
