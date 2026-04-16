use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::process::Stdio;
use std::time::Duration;

use super::common::*;
use super::write_config;

fn tmp(tag: &str) -> super::common::TmpGuard {
    super::common::TmpGuard::new("stop", tag)
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
            .filter_map(Result::ok)
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

/// `REQ_LOG`: live log streaming over the ctl socket. The control
/// arm flags the conn; the logger walks log conns on each
/// `logger()` call. Our tap pushes to a thread-local buffer drained
/// once per event-loop turn.
///
/// Test shape: connect ctl#1, send `REQ_LOG`. Connect ctl#2 — the
/// daemon's `on_unix_accept` logs "Connection from ... (control)"
/// at Debug level. ctl#1 receives that line as `"18 15 <len>\n"` +
/// `<len>` raw bytes (no trailing `\n`, `send_meta`).
#[test]
fn req_log_streams() {
    use std::io::Read;

    let tmp = tmp("req-log");
    let confbase = tmp.path().join("vpn");
    let pidfile = tmp.path().join("tinc.pid");
    let socket = tmp.path().join("tinc.socket");
    write_config(&confbase);

    // RUST_LOG=warn: prove the tap raises max_level INDEPENDENTLY of
    // the stderr filter. The "Connection from" log is Debug; stderr
    // won't print it but the tap MUST capture it (set_active bumps
    // max_level to Trace).
    let mut child = tincd_cmd()
        .arg("-c")
        .arg(&confbase)
        .arg("--pidfile")
        .arg(&pidfile)
        .arg("--socket")
        .arg(&socket)
        .env("RUST_LOG", "warn")
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    assert!(wait_for_file(&socket), "tincd didn't start; stderr: {}", {
        let _ = child.kill();
        let out = child.wait_with_output().unwrap();
        String::from_utf8_lossy(&out.stderr).into_owned()
    });

    let cookie = read_cookie(&pidfile);

    // ─── ctl#1: greeting + REQ_LOG ────────────────────────────────
    let log_stream = UnixStream::connect(&socket).unwrap();
    log_stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut log_r = BufReader::new(&log_stream);
    let mut log_w = &log_stream;
    writeln!(log_w, "0 ^{cookie} 0").unwrap();
    let mut greet = String::new();
    log_r.read_line(&mut greet).unwrap();
    assert_eq!(greet, "0 testnode 17.7\n");
    let mut ack = String::new();
    log_r.read_line(&mut ack).unwrap();
    assert!(ack.starts_with("4 0 "));

    // `"18 15 <level> <use_color>"`. level=2 maps
    // to Debug on the daemon side; the "Connection from" log we'll
    // trigger is Debug. use_color=0 (ignored anyway).
    writeln!(log_w, "18 15 2 0").unwrap();
    // No reply (`return true` without control_ok).

    // ─── ctl#2: trigger an Info-level log inside the daemon ────
    // `on_unix_accept` logs "Connection from localhost port unix
    // (control)" at Debug. That happens INSIDE the event loop turn
    // that processes the accept; flush_log_tap drains it at the
    // bottom of the same turn.
    let trigger = UnixStream::connect(&socket).unwrap();
    let mut trig_r = BufReader::new(&trigger);
    let mut trig_w = &trigger;
    writeln!(trig_w, "0 ^{cookie} 0").unwrap();
    // Drain the greeting so this conn is fully established (the
    // daemon's accept is async; reading proves the round trip).
    let mut t1 = String::new();
    trig_r.read_line(&mut t1).unwrap();
    let mut t2 = String::new();
    trig_r.read_line(&mut t2).unwrap();

    // ─── read on ctl#1: framed log line ────────────────────────────
    // Format: `"18 15 <len>\n"` then `<len>` raw bytes. There may
    // be MULTIPLE log lines (the REQ_LOG arm itself doesn't log,
    // but the trigger conn's accept + greeting may produce >1).
    // Read until we find the "Connection from" message.
    let mut found = false;
    for _ in 0..10 {
        let mut header = String::new();
        let n = log_r.read_line(&mut header).expect("log header read");
        assert_ne!(n, 0, "EOF before log line; header: {header:?}");
        let header = header.trim_end();
        let mut parts = header.split_whitespace();
        assert_eq!(parts.next(), Some("18"), "CONTROL: {header:?}");
        assert_eq!(parts.next(), Some("15"), "REQ_LOG: {header:?}");
        let len: usize = parts
            .next()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| panic!("len field: {header:?}"));

        // Body: `len` raw bytes, NO newline (`send_meta`).
        let mut body = vec![0u8; len];
        log_r.read_exact(&mut body).expect("log body read");
        let msg = String::from_utf8_lossy(&body);

        // The bare `args()` from the log macro — no env_logger
        // timestamp/level prefix (log_tap pushes `r.args().to_string()`).
        if msg.contains("Connection from") && msg.contains("(control)") {
            found = true;
            break;
        }
    }
    assert!(
        found,
        "never received 'Connection from ... (control)' log line"
    );

    // ─── cleanup ─────────────────────────────────────────────────
    drop(trigger);
    drop(log_stream);
    let _ = child.kill();
    let _ = child.wait();
}

/// `REQ_SET_DEBUG` round-trip. Reply with the PREVIOUS level (sent
/// BEFORE the assignment), then update if
/// `level >= 0`. Negative → query-only.
///
/// This is the `tinc debug N` operator workflow: "daemon's
/// misbehaving, crank up logging without restart". Before this
/// arm existed, the daemon fell through to `REQ_INVALID` and the
/// CLI's `recv_ack(SetDebug)` failed the ack-shape check.
#[test]
fn set_debug_level_roundtrip() {
    let tmp = tmp("set-debug");
    let confbase = tmp.path().join("vpn");
    let pidfile = tmp.path().join("tinc.pid");
    let socket = tmp.path().join("tinc.socket");

    write_config(&confbase);

    // No -d flag, no RUST_LOG → debug_level seeds at 0.
    let mut child = tincd_cmd()
        .arg("-c")
        .arg(&confbase)
        .arg("--pidfile")
        .arg(&pidfile)
        .arg("--socket")
        .arg(&socket)
        .env_remove("RUST_LOG")
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tincd");

    assert!(wait_for_file(&socket), "tincd didn't bind socket");

    // ─── connect + greeting ──────────────────────────────────
    let cookie = read_cookie(&pidfile);
    let stream = UnixStream::connect(&socket).expect("connect to tincd");
    let mut reader = BufReader::new(&stream);
    let mut writer = &stream;
    writeln!(writer, "0 ^{cookie} 0").unwrap();
    let mut greet = String::new();
    reader.read_line(&mut greet).unwrap();
    assert_eq!(greet, "0 testnode 17.7\n");
    let mut ack = String::new();
    reader.read_line(&mut ack).unwrap(); // "4 0 <pid>"

    // ─── set debug 5 → reply previous (0) ────────────────────
    // `send_request(..., debug_level)` BEFORE the assignment.
    // Startup level was 0 (no -d).
    writeln!(writer, "18 9 5").unwrap();
    let mut reply = String::new();
    reader.read_line(&mut reply).unwrap();
    assert_eq!(reply, "18 9 0\n", "reply with PREVIOUS level (0)");

    // ─── query (-1) → reply current (5), no change ───────────
    // `if(new_level >= 0)` — negative is query-only.
    writeln!(writer, "18 9 -1").unwrap();
    let mut reply = String::new();
    reader.read_line(&mut reply).unwrap();
    assert_eq!(reply, "18 9 5\n", "query reads back the set value");

    // ─── set debug 2 → reply previous (5) ────────────────────
    // Proves the i32 actually updated (lossless: not derived
    // from log::max_level() inverse-mapping).
    writeln!(writer, "18 9 2").unwrap();
    let mut reply = String::new();
    reader.read_line(&mut reply).unwrap();
    assert_eq!(reply, "18 9 5\n", "previous was 5");

    // ─── query again → 2 ────────────────────────────────────
    writeln!(writer, "18 9 -1").unwrap();
    let mut reply = String::new();
    reader.read_line(&mut reply).unwrap();
    assert_eq!(reply, "18 9 2\n");

    // ─── malformed (no level) → conn dropped ─────────────────
    // `if(sscanf(...) != 1) return false`. The ONLY ctl arm that
    // does this (others reply REQ_INVALID and stay up). `return
    // false` → `receive_request` → "Bogus data" + terminate.
    writeln!(writer, "18 9").unwrap();
    let mut reply = String::new();
    let n = reader.read_line(&mut reply).unwrap();
    assert_eq!(n, 0, "EOF: daemon dropped the conn (`return false`)");

    // ─── reconnect: level was restored on close ────────────
    let stream = UnixStream::connect(&socket).expect("reconnect");
    let mut reader = BufReader::new(&stream);
    let mut writer = &stream;
    writeln!(writer, "0 ^{cookie} 0").unwrap();
    reader.read_line(&mut String::new()).unwrap();
    reader.read_line(&mut String::new()).unwrap();
    writeln!(writer, "18 9 -1").unwrap();
    let mut reply = String::new();
    reader.read_line(&mut reply).unwrap();
    assert_eq!(reply, "18 9 0\n", "debug level restored after conn close");

    // ─── cleanup ─────────────────────────────────────────────
    let _ = child.kill();
    let _ = child.wait();
}

/// `chdir(confbase)` before everything else. Script execution does
/// no chdir of its own — scripts inherit the
/// daemon's cwd. A `tinc-up` doing `cat hosts/$NODE` (relative)
/// works under C only because of that early chdir.
///
/// We launch tincd from `/` (NOT confbase) to make the test
/// meaningful: without the fix, `pwd` in tinc-up would print `/`.
#[test]
fn tinc_up_runs_with_confbase_cwd() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tmp("tinc-up-cwd");
    let confbase = tmp.path().join("vpn");
    let pidfile = tmp.path().join("tinc.pid");
    let socket = tmp.path().join("tinc.socket");
    write_config(&confbase);

    // Probe file OUTSIDE confbase (absolute path) so the
    // relative-vs-absolute question doesn't taint the test.
    let probe = tmp.path().join("cwd.txt");
    let tinc_up = confbase.join("tinc-up");
    std::fs::write(
        &tinc_up,
        format!("#!/bin/sh\npwd > '{}'\n", probe.display()),
    )
    .unwrap();
    std::fs::set_permissions(&tinc_up, std::fs::Permissions::from_mode(0o755)).unwrap();

    let mut child = tincd_cmd()
        .arg("-D")
        .arg("-c")
        .arg(&confbase)
        .arg("--pidfile")
        .arg(&pidfile)
        .arg("--socket")
        .arg(&socket)
        // Launch from a DIFFERENT cwd. Without the fix, pwd would
        // print THIS, not confbase.
        .current_dir("/")
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tincd");

    assert!(wait_for_file(&socket), "tincd should start; stderr: {}", {
        let _ = child.kill();
        let out = child.wait_with_output().unwrap();
        String::from_utf8_lossy(&out.stderr).into_owned()
    });

    let _ = child.kill();
    let _ = child.wait();

    let got = std::fs::read_to_string(&probe).expect("tinc-up should have run and written its cwd");
    let want = confbase.canonicalize().unwrap();
    let got = std::path::Path::new(got.trim()).canonicalize().unwrap();
    assert_eq!(got, want, "tinc-up cwd should be confbase");
}

/// fd-leak guard: open+close N control connections, assert
/// `/proc/PID/fd` count returns to baseline. Covers `terminate()`'s
/// `conns`/`conn_io`/`ev.del` coherence and `OwnedFd` drop.
///
#[cfg(target_os = "linux")]
#[test]
fn control_conn_churn_no_fd_leak() {
    let tmp = tmp("fd-churn");
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

    let pid_str = std::fs::read_to_string(&pidfile).unwrap();
    let daemon_pid: u32 = pid_str.split_whitespace().next().unwrap().parse().unwrap();
    let fd_dir = format!("/proc/{daemon_pid}/fd");
    let count_fds = || std::fs::read_dir(&fd_dir).unwrap().count();
    let baseline = count_fds();

    let cookie = read_cookie(&pidfile);
    for _ in 0..100 {
        let mut s = UnixStream::connect(&socket).unwrap();
        // Greeting so on_unix_accept's read path runs (not just
        // accept+EOF).
        writeln!(s, "0 ^{cookie} 0").unwrap();
        let mut r = BufReader::new(&s);
        let mut line = String::new();
        let _ = r.read_line(&mut line);
        let _ = r.read_line(&mut line);
        // drop(s) → daemon sees EOF → terminate()
    }

    // Daemon needs a turn to reap each EOF; poll.
    let after = poll_until(Duration::from_secs(5), || {
        let n = count_fds();
        // Allow +1 slack: read_dir on /proc/self/fd races with the
        // dirfd it opens; daemon-side has no such race but be lenient.
        (n <= baseline + 1).then_some(n)
    });
    assert!(
        after <= baseline + 1,
        "fd leak: baseline={baseline} after-100-churn={after}"
    );

    let _ = child.kill();
    let _ = child.wait();
}
