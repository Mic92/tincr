//! Regression tests that began life as bug-hunt repros.

#[path = "../common/mod.rs"]
#[macro_use]
pub mod common;

mod gossip_edges;

use common::*;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::process::Stdio;
use std::time::Duration;

/// Same minimal config as `tests/stop`.
fn write_config(confbase: &std::path::Path) {
    std::fs::create_dir_all(confbase.join("hosts")).unwrap();
    std::fs::write(
        confbase.join("tinc.conf"),
        "Name = testnode\nDeviceType = dummy\nAddressFamily = ipv4\n",
    )
    .unwrap();
    std::fs::write(confbase.join("hosts").join("testnode"), "Port = 0\n").unwrap();
    write_ed25519_privkey(confbase, &[0x42; 32]);
}

fn spawn(tmp: &TmpGuard) -> (std::process::Child, std::path::PathBuf, std::path::PathBuf) {
    let (confbase, pidfile, socket) = tmp.std_paths();
    write_config(&confbase);
    let child = tincd_at(&confbase, &pidfile, &socket)
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    assert!(wait_for_file(&socket), "daemon didn't bind socket");
    (child, pidfile, socket)
}

/// Connect + greeting; returns a reader past the two greeting lines.
fn auth(stream: &UnixStream, cookie: &str) -> BufReader<UnixStream> {
    let mut r = BufReader::new(stream.try_clone().unwrap());
    writeln!(&mut &*stream, "0 ^{cookie} 0").unwrap();
    let mut l = String::new();
    r.read_line(&mut l).unwrap();
    assert!(l.starts_with("0 "), "no ID greeting; got {l:?}");
    l.clear();
    r.read_line(&mut l).unwrap();
    assert!(l.starts_with("4 "), "no ACK; got {l:?}");
    r
}

// ══════════════════════════════════════════════════════════════════════
// BUG REPRO
// ══════════════════════════════════════════════════════════════════════

/// `tinc purge` before any peer/SSSP run must ack and keep the daemon
/// alive (snapshot-refresh path before first `run_graph_and_log`).
#[test]
fn req_purge_on_fresh_daemon() {
    let tmp = tmp!("ctl-purge");
    let (mut child, pidfile, socket) = spawn(&tmp);
    let cookie = read_cookie(&pidfile);

    let s = UnixStream::connect(&socket).unwrap();
    let mut r = auth(&s, &cookie);

    // CONTROL REQ_PURGE
    writeln!(&s, "18 8").unwrap();

    // Expected: `"18 8 0\n"` ack, conn stays open, daemon alive.
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut line = String::new();
    let n = r.read_line(&mut line).unwrap_or(0);

    // Reap the daemon and grab stderr for diagnostics regardless of
    // outcome (so the panic message shows in the failure output).
    let _ = child.kill();
    let stderr = drain_stderr(std::mem::replace(
        &mut child,
        std::process::Command::new("true").spawn().unwrap(),
    ));

    assert_eq!(
        line.trim_end(),
        "18 8 0",
        "expected purge ack; got {n} bytes {line:?}\nstderr:\n{stderr}"
    );
    assert!(!stderr.contains("panicked"), "daemon panicked:\n{stderr}");
}

// ══════════════════════════════════════════════════════════════════════
// PROBE (negative results — passes)
// ══════════════════════════════════════════════════════════════════════

/// Exercise the corners listed in the bug-hunt brief: every control
/// verb with bad args, oversized request, request before auth, partial
/// cookie, disconnect mid-reply. The daemon must stay alive and keep
/// serving throughout. Kept as a passing test so the suite covers
/// these paths going forward.
#[test]
fn control_abuse_probe() {
    let tmp = tmp!("ctl-abuse");
    let (mut child, pidfile, socket) = spawn(&tmp);
    let cookie = read_cookie(&pidfile);

    // ── 1. CONTROL before auth → conn terminated, no reply ──
    {
        let s = UnixStream::connect(&socket).unwrap();
        (&s).write_all(b"18 0\n").unwrap();
        let mut buf = Vec::new();
        BufReader::new(&s).read_to_end(&mut buf).unwrap();
        assert!(buf.is_empty(), "pre-auth CONTROL should yield bare EOF");
    }

    // ── 2. partial / wrong / empty cookie → conn terminated ──
    for bad in [&cookie[..32], "deadbeef", ""] {
        let s = UnixStream::connect(&socket).unwrap();
        writeln!(&s, "0 ^{bad} 0").unwrap();
        let mut buf = Vec::new();
        BufReader::new(&s).read_to_end(&mut buf).unwrap();
        assert!(buf.is_empty(), "bad cookie {bad:?} should yield bare EOF");
    }

    // ── 3. oversized request line (>MAXBUFSIZE) → conn terminated ──
    {
        let s = UnixStream::connect(&socket).unwrap();
        let mut r = auth(&s, &cookie);
        // 4000 bytes, no newline anywhere → inbuf overflow → Dead.
        (&s).write_all(&vec![b'x'; 4000]).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut buf = Vec::new();
        // EOF (or ECONNRESET on some kernels) once the daemon drops us.
        let _ = r.read_to_end(&mut buf);
    }

    // ── 4. every verb with garbage 3rd token, conn survives ──
    {
        let s = UnixStream::connect(&socket).unwrap();
        let mut r = auth(&s, &cookie);
        // Excluded: 0 (STOP — would shut the daemon down),
        // 9 (SET_DEBUG — terminates the conn on unparseable level by
        //    design, matching C `control.c:82`).
        for sub in [1, 3, 4, 5, 6, 8, 10, 12, 13, 14, 15, 99, -1] {
            writeln!(&s, "18 {sub} !!garbage!!").unwrap();
        }
        // Conn must still be alive: a DUMP_CONNECTIONS round-trips.
        writeln!(&s, "18 6").unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut seen_term = false;
        let mut line = String::new();
        for _ in 0..200 {
            line.clear();
            if r.read_line(&mut line).unwrap() == 0 {
                break;
            }
            if line.trim_end() == "18 6" {
                seen_term = true;
                break;
            }
        }
        assert!(seen_term, "daemon stopped responding after verb fuzz");
    }

    // ── 5. disconnect mid-reply: ask for dumps, drop without reading ──
    for _ in 0..10 {
        let s = UnixStream::connect(&socket).unwrap();
        let _r = auth(&s, &cookie);
        (&s).write_all(b"18 3\n18 4\n18 5\n18 6\n18 13\n").unwrap();
        drop(s);
    }

    // ── daemon still alive and serving ──
    let mut ctl = Ctl::connect(&socket, &pidfile);
    let rows = ctl.dump(3);
    assert!(!rows.is_empty(), "daemon dead after abuse");

    let _ = child.kill();
    let _ = child.wait();
}
