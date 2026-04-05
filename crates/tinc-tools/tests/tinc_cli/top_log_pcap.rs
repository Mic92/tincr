#![cfg(unix)]

use super::fake_daemon::{fake_daemon_setup, serve_greeting};
use super::tinc;

#[test]
fn top_too_many_args() {
    let out = tinc(&["top", "extra"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("Too many arguments"), "stderr: {stderr}");
}

/// `top::run` connects FIRST, then enters raw mode. Under cargo
/// test, stdin is a pipe, so `RawMode::enter` fails with "stdin is
/// not a terminal". We assert that:
///
///   - The connect SUCCEEDS (fake daemon's greeting is exchanged).
///   - The error is the tty error, not a daemon error.
///   - The fake daemon's socket is read for greeting and then
///     dropped (NO `DUMP_TRAFFIC` request — raw mode failed first).
///
/// This pins the connect-before-raw order: "daemon not running"
/// is more useful on a
/// sane terminal.
#[test]
fn top_stdin_not_tty_fails_after_connect() {
    use std::io::Read;

    let (_dir, cb, pf, listener, cookie) = fake_daemon_setup();

    let daemon = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let (mut br, _w) = serve_greeting(&stream, &cookie);

        // After greeting, the client should DROP the connection
        // (RawMode::enter failed, top::run returns Err, the
        // CtlSocket is dropped). We assert NO data after
        // greeting — specifically, no "18 13" DUMP_TRAFFIC
        // request.
        let mut buf = String::new();
        // read_to_string blocks until EOF. EOF arrives when the
        // client drops. Timeout via the join below if it hangs.
        br.read_to_string(&mut buf).unwrap();
        // "18 13" is `CONTROL REQ_DUMP_TRAFFIC`. Asserting it's NOT
        // here proves raw-mode-failed-first.
        assert!(
            !buf.contains("18 13"),
            "daemon got DUMP_TRAFFIC; raw mode should have failed first. got: {buf:?}"
        );
        // The buf SHOULD be empty (greeting consumed by serve_
        // greeting, then nothing). Assert that too.
        assert_eq!(buf, "", "expected EOF after greeting, got: {buf:?}");
    });

    // Stdin redirected to /dev/null (a pipe under cargo test
    // anyway, but explicit). RawMode::enter → isatty(stdin) →
    // false → "stdin is not a terminal".
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_tinc"))
        .args(["-c", &cb, "--pidfile", &pf, "top"])
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();

    daemon.join().unwrap();

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    // The exact phrasing from `tui.rs::RawMode::enter`'s preflight.
    // Wrapped by `top::run`: "cannot enter raw mode: stdin is not
    // a terminal".
    assert!(
        stderr.contains("stdin is not a terminal"),
        "expected tty error; got stderr: {stderr}"
    );
    // And NOT a daemon error — connect succeeded.
    assert!(
        !stderr.contains("Could not"),
        "unexpected daemon error in stderr: {stderr}"
    );
}

// ════════════════════════════════════════════════════════════════════
// `tinc log`, `tinc pcap` against a fake daemon
// ════════════════════════════════════════════════════════════════════
//
// Unlike `top`, these don't need a tty. The fake daemon can drive
// the full path: subscribe, push records, close. Client should
// produce exactly what upstream `tinc log` / `tinc pcap` would.
//
// THE seam: subscribe wire → daemon, header wire ← daemon.
// Both halves of the wire-compat are pinned.

/// Full `tinc log` end-to-end. Daemon pushes two log lines.
///
/// Subscribe wire: `"18 15 -1 0\n"`. `-1` is `DEBUG_UNSET` (no
/// level arg). The `0` is `use_color`: cargo
/// test's stdout is a pipe, `is_terminal()` false, no color.
///
/// Daemon push wire: `"18 15 N\n"` then N raw bytes. NO `\n`
/// after data — the CLI adds it.
///
/// Stdout: `"Hello\nWorld\n"`. The two log lines, each with the
/// CLI-added trailing newline.
#[test]
fn log_against_fake() {
    use std::io::{BufRead, Write};

    let (_dir, cb, pf, listener, cookie) = fake_daemon_setup();

    let daemon = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let (mut br, mut w) = serve_greeting(&stream, &cookie);

        // ─── Receive subscription ─────────────────────────────────
        // We assert the EXACT wire — no parsing slack here, this
        // is the C-compat seam.
        let mut req = String::new();
        br.read_line(&mut req).unwrap();
        // `sendline("%d %d %d %d", CONTROL, REQ_LOG, level,
        // use_color)`. CONTROL=18, REQ_LOG=15,
        // level=-1 (DEBUG_UNSET, no arg), use_color=0 (stdout is
        // a pipe under cargo test — `is_terminal()` returns
        // false). EXACT wire match.
        assert_eq!(req, "18 15 -1 0\n", "subscribe wire mismatch");

        // ─── Push two records ─────────────────────────────────────
        // `send_request(c, "%d %d %lu", CONTROL, REQ_LOG, msglen)`
        // then `send_meta(c, pretty, msglen)`.
        // `send_meta` is RAW bytes, no \n.
        //
        // Single write per record (header + data) to exercise the
        // BufReader-shared-buffer path. The C daemon would do TWO
        // writes (`send_request` then `send_meta`); TCP can
        // coalesce. Either way the BufReader handles it.
        w.write_all(b"18 15 5\nHello").unwrap();
        w.write_all(b"18 15 5\nWorld").unwrap();

        // ─── Close ───────────────────────────────────────────────
        // Dropping `stream` closes. Client's `recv_line` returns
        // `None`, loop exits, `Ok(())`.
        //
        // Explicit shutdown so the client sees EOF promptly.
        // Dropping the stream does the same but `shutdown` is
        // explicit about "no more data coming."
        stream.shutdown(std::net::Shutdown::Write).unwrap();

        // Drain any remaining input (there shouldn't be any).
        let mut tail = String::new();
        br.read_line(&mut tail).ok();
        // Client doesn't send anything else after subscribe.
        assert_eq!(tail, "", "unexpected trailing client send");
    });

    let out = tinc(&["-c", &cb, "--pidfile", &pf, "log"]);
    daemon.join().unwrap();

    // ─── Exit code ───────────────────────────────────────────────
    // Daemon closed cleanly → client exits Ok.
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // ─── Stdout ──────────────────────────────────────────────────
    // EXACT bytes: "Hello\nWorld\n". The trailing \n is added by
    // the CLI, not the daemon.
    assert_eq!(
        out.stdout,
        b"Hello\nWorld\n",
        "stdout: {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
}

/// `tinc log 5` — level arg forwarded. Subscribe wire is
/// `"18 15 5 0\n"`. The real daemon would clamp the level; our
/// fake just asserts the wire.
#[test]
fn log_level_arg_forwarded_against_fake() {
    use std::io::BufRead;

    let (_dir, cb, pf, listener, cookie) = fake_daemon_setup();

    let daemon = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let (mut br, _w) = serve_greeting(&stream, &cookie);

        let mut req = String::new();
        br.read_line(&mut req).unwrap();
        // Level 5, color 0. `tinc log 5` → `Some(5)`.
        assert_eq!(req, "18 15 5 0\n");

        // Close immediately. No records.
        stream.shutdown(std::net::Shutdown::Write).unwrap();
    });

    let out = tinc(&["-c", &cb, "--pidfile", &pf, "log", "5"]);
    daemon.join().unwrap();

    assert!(out.status.success());
    assert_eq!(out.stdout, b"");
}

/// `tinc log abc` — garbage level rejected. atoi-style `"abc"`
/// would silently use 0; we error. STRICTER. Daemon never sees a
/// request.
#[test]
fn log_garbage_level_rejected() {
    let out = tinc(&["log", "abc"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("Invalid debug level"), "stderr: {stderr}");
}

/// Full `tinc pcap` end-to-end. Daemon pushes one packet.
///
/// Subscribe wire: `"18 14 0\n"` (snaplen=0).
///
/// Stdout: 24-byte global header + 16-byte packet header + N
/// data bytes. The libpcap savefile format. We assert the magic,
/// the snaplen (defaults to 9018 when 0), the data passthrough.
/// The TIMESTAMP we don't pin (real wall clock).
#[test]
fn pcap_against_fake() {
    use std::io::{BufRead, Write};

    let (_dir, cb, pf, listener, cookie) = fake_daemon_setup();

    let daemon = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let (mut br, mut w) = serve_greeting(&stream, &cookie);

        let mut req = String::new();
        br.read_line(&mut req).unwrap();
        // snaplen=0 (no arg). CONTROL=18, REQ_PCAP=14.
        assert_eq!(req, "18 14 0\n");

        // `send_request(c, "%d %d %d", CONTROL, REQ_PCAP, len)`
        // then `send_meta(c, DATA(packet), len)`.
        // 4-byte fake "packet" — not a real Ethernet frame, but
        // the format doesn't care (length-framed raw bytes).
        w.write_all(b"18 14 4\nABCD").unwrap();

        stream.shutdown(std::net::Shutdown::Write).unwrap();
    });

    let out = tinc(&["-c", &cb, "--pidfile", &pf, "pcap"]);
    daemon.join().unwrap();

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = &out.stdout;

    // ─── Global header (24 bytes) ─────────────────────────────────
    // The pcap magic identifies endianness; the test runs on
    // x86_64 (LE) so it's `d4 c3 b2 a1`. (BE CI
    // would see `a1 b2 c3 d4`; both are valid pcap.)
    #[cfg(target_endian = "little")]
    {
        assert_eq!(&stdout[0..4], &[0xd4, 0xc3, 0xb2, 0xa1], "magic");
        // Snaplen at [16..20]: 0 → 9018 default.
        assert_eq!(
            u32::from_ne_bytes([stdout[16], stdout[17], stdout[18], stdout[19]]),
            9018,
            "snaplen default"
        );
        // ll_type at [20..24] = 1.
        assert_eq!(&stdout[20..24], &[1, 0, 0, 0], "ll_type");
    }

    // ─── Packet header (16 bytes at [24..40]) ────────────────────
    // tv_sec/tv_usec at [24..32]: real wall clock, can't pin.
    // Just sanity: tv_sec > 0 (we're past 1970).
    let tv_sec = u32::from_ne_bytes([stdout[24], stdout[25], stdout[26], stdout[27]]);
    assert!(tv_sec > 1_000_000_000, "tv_sec sanity (past 2001)");

    // len at [32..36] = 4, origlen at [36..40] = 4.
    // Both set to received len (no truncation at snaplen=0).
    assert_eq!(
        u32::from_ne_bytes([stdout[32], stdout[33], stdout[34], stdout[35]]),
        4,
        "packet len"
    );
    assert_eq!(
        u32::from_ne_bytes([stdout[36], stdout[37], stdout[38], stdout[39]]),
        4,
        "packet origlen"
    );

    // ─── Data (4 bytes at [40..44]) ───────────────────────────────
    // Passed through verbatim.
    assert_eq!(&stdout[40..44], b"ABCD", "packet data");

    // Total: 24 + 16 + 4 = 44 bytes, no more.
    assert_eq!(stdout.len(), 44);
}

/// `tinc pcap -5` — negative snaplen rejected. C's `atoi("-5")`
/// is `-5` cast to `uint32_t` (huge); we error.
#[test]
fn pcap_negative_snaplen_rejected() {
    let out = tinc(&["pcap", "-5"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    // `-5` is flag-shaped: the argv parser may eat it as a short
    // flag ("Unknown option") before pcap sees it ("Invalid
    // snaplen"). Either rejection is correct — the C's silent
    // wraparound is what we forbid.
    assert!(
        stderr.contains("Invalid") || stderr.contains("Unknown"),
        "stderr: {stderr}"
    );
}
