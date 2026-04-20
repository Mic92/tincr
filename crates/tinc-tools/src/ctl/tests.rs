use super::*;
use std::io::Write;
use std::thread;

/// Round-trip through `from_i32`. Unknown → None.
#[test]
fn request_from_i32() {
    for i in 0..16 {
        let r = CtlRequest::from_i32(i).unwrap();
        assert_eq!(r as i32, i);
    }
    assert_eq!(CtlRequest::from_i32(-1), None);
    assert_eq!(CtlRequest::from_i32(16), None);
    assert_eq!(CtlRequest::from_i32(999), None);
}

/// Pidfile parse, happy path. `"<pid> <cookie> <host> port <port>\n"`.
#[test]
fn pidfile_parse() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pid");
    let cookie = "a".repeat(64);
    std::fs::write(&path, format!("12345 {cookie} 127.0.0.1 port 655\n")).unwrap();

    let pf = Pidfile::read(&path).unwrap();
    assert_eq!(pf.pid, 12345);
    assert_eq!(pf.cookie, cookie);
    assert_eq!(pf.port, "655");
}

/// Pidfile validation: cookie must be exactly 64 hex chars.
/// We tighten over upstream here.
#[test]
fn pidfile_cookie_validated() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pid");

    // Too short.
    std::fs::write(&path, "1 abc 127.0.0.1 port 655\n").unwrap();
    assert!(matches!(
        Pidfile::read(&path),
        Err(CtlError::PidfileMalformed)
    ));

    // Non-hex.
    let bad = "z".repeat(64);
    std::fs::write(&path, format!("1 {bad} 127.0.0.1 port 655\n")).unwrap();
    assert!(matches!(
        Pidfile::read(&path),
        Err(CtlError::PidfileMalformed)
    ));

    // Exactly right (lowercase hex, 64 chars).
    let good = "0123456789abcdef".repeat(4);
    std::fs::write(&path, format!("1 {good} 127.0.0.1 port 655\n")).unwrap();
    assert!(Pidfile::read(&path).is_ok());

    // Uppercase hex also passes — `is_ascii_hexdigit` accepts
    // both. The daemon writes lowercase, but a hand-edited
    // pidfile shouldn't be rejected on case. The greeting compare
    // is case-sensitive, so uppercase would *fail auth* — but
    // that's a different, more useful error.
    let upper = "0123456789ABCDEF".repeat(4);
    std::fs::write(&path, format!("1 {upper} 127.0.0.1 port 655\n")).unwrap();
    assert!(Pidfile::read(&path).is_ok());
}

/// Pidfile shape: missing fields fail.
#[test]
fn pidfile_shape_enforced() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pid");
    let cookie = "f".repeat(64);

    // Missing port: only 3 tokens after pid.
    std::fs::write(&path, format!("1 {cookie} 127.0.0.1\n")).unwrap();
    assert!(matches!(
        Pidfile::read(&path),
        Err(CtlError::PidfileMalformed)
    ));

    // `port` literal wrong.
    std::fs::write(&path, format!("1 {cookie} 127.0.0.1 prt 655\n")).unwrap();
    assert!(matches!(
        Pidfile::read(&path),
        Err(CtlError::PidfileMalformed)
    ));

    // pid not a number.
    std::fs::write(&path, format!("notapid {cookie} 127.0.0.1 port 655\n")).unwrap();
    assert!(matches!(
        Pidfile::read(&path),
        Err(CtlError::PidfileMalformed)
    ));
}

/// Pidfile missing → distinct error.
#[test]
fn pidfile_missing() {
    let err = Pidfile::read(std::path::Path::new("/nonexistent/pidfile")).unwrap_err();
    assert!(matches!(err, CtlError::PidfileMissing { .. }));
    assert!(err.to_string().contains("Could not open pid file"));
}

// The fake daemon. A thread doing the greeting dance + canned
// responses on a UnixStream::pair() half.
//
// Why a thread, not an in-process pump like join's: the control
// protocol is *blocking* — handshake() blocks on recv until the
// greeting arrives. The SPTPS pump worked because Sptps::receive
// returns "consumed 0, no progress" on partial input. read_line
// doesn't; it blocks. So: thread.
//
// Why this is fine: UnixStream::pair() is in-process (no socket
// file, no port, no race with parallel tests). The thread is
// joined before the test returns (no leak).

/// Spawn a fake daemon on `theirs`. Reads the ID line (asserts
/// the cookie), sends greeting line 1 + 2, then runs `serve` to
/// handle whatever the test sends.
///
/// `serve` gets a `BufReader` and the raw write half. It can do
/// `read_line` and `writeln!`. When it returns, the daemon side
/// drops, closing the socket — the CLI side sees EOF.
pub(crate) fn fake_daemon<F>(
    theirs: UnixStream,
    expected_cookie: &str,
    daemon_pid: u32,
    serve: F,
) -> thread::JoinHandle<()>
where
    F: FnOnce(&mut BufReader<&UnixStream>, &mut &UnixStream) + Send + 'static,
{
    let expected_cookie = expected_cookie.to_owned();
    thread::spawn(move || {
        // `&UnixStream` is `Read + Write` (the impl is on the
        // reference, not the owned type — same trick as `&File`).
        // Two `&theirs` borrows are fine because they're both
        // shared. The `&mut &UnixStream` for the writer is a
        // mutable binding holding a shared reference; `writeln!`
        // needs `&mut impl Write`, and `impl Write` is the
        // `&UnixStream`, not `UnixStream`.
        let read = &theirs;
        let mut write = &theirs;
        let mut br = BufReader::new(read);

        // ─── Recv ID, check cookie
        let mut line = String::new();
        br.read_line(&mut line).unwrap();
        // Shape: "0 ^COOKIE 0\n".
        let trimmed = line.trim_end();
        let parts: Vec<_> = trimmed.split(' ').collect();
        assert_eq!(parts.len(), 3, "ID line: {trimmed:?}");
        assert_eq!(parts[0], "0");
        assert_eq!(parts[1], format!("^{expected_cookie}"));
        assert_eq!(parts[2], "0");

        // ─── Send greeting line 1 (send_id)
        // The CLI ignores everything after the first int.
        writeln!(write, "0 fakedaemon 17.7").unwrap();

        // ─── Send greeting line 2 (ACK + ctl-ver + pid)
        writeln!(write, "4 0 {daemon_pid}").unwrap();

        // ─── Hand off to test-specific serving
        serve(&mut br, &mut write);
        // Drop closes.
    })
}

/// Handshake against the fake daemon. The minimum: connect,
/// greet, check pid. No commands sent.
#[test]
fn handshake_smoke() {
    let cookie = "0123456789abcdef".repeat(4);
    let (ours, theirs) = UnixStream::pair().unwrap();

    let daemon = fake_daemon(theirs, &cookie, 9999, |_br, _w| {
        // No serving — drop immediately after greeting.
    });

    let ctl = CtlSocket::handshake(ours, &cookie).unwrap();
    assert_eq!(ctl.pid, 9999);

    daemon.join().unwrap();
}

/// Wrong cookie → daemon thread panics (assert fails). In a
/// real daemon, `id_h` would `return false` and the meta loop
/// drops the connection; CLI side sees EOF on recv → Greeting
/// error. We test the latter by having the fake just drop.
#[test]
fn handshake_bad_cookie_eof() {
    let real_cookie = "a".repeat(64);
    let wrong_cookie = "b".repeat(64);
    let (ours, theirs) = UnixStream::pair().unwrap();

    // Fake checks for `wrong_cookie`, we send `real_cookie`.
    // The fake's assert_eq on the cookie panics; thread dies;
    // socket closes; our recv sees EOF.
    //
    // We *want* the panic — that's the test's "daemon rejected
    // us" signal. `join().unwrap_err()` checks it happened.
    let daemon = fake_daemon(theirs, &wrong_cookie, 1, |_, _| {});

    let Err(err) = CtlSocket::handshake(ours, &real_cookie) else {
        panic!("expected handshake to fail");
    };
    assert!(matches!(err, CtlError::Greeting(_)));
    assert!(err.to_string().contains("Cannot read greeting"));

    // The fake panicked on the assert. Expected.
    assert!(daemon.join().is_err());
}

/// Malformed greeting line 1 → Greeting error. Daemon speaking
/// wrong protocol (or it's not tincd).
#[test]
fn handshake_bad_line1() {
    let cookie = "c".repeat(64);
    let (ours, theirs) = UnixStream::pair().unwrap();

    let daemon = thread::spawn(move || {
        let mut br = BufReader::new(&theirs);
        let mut line = String::new();
        br.read_line(&mut line).unwrap();
        // Send a non-ID first int.
        let mut w = &theirs;
        writeln!(w, "999 garbage").unwrap();
    });

    let Err(err) = CtlSocket::handshake(ours, &cookie) else {
        panic!("expected handshake to fail");
    };
    assert!(matches!(err, CtlError::Greeting(_)));

    daemon.join().unwrap();
}

/// One-shot RPC: send a request, get an ack. The reload pattern.
#[test]
fn send_and_ack() {
    let cookie = "d".repeat(64);
    let (ours, theirs) = UnixStream::pair().unwrap();

    let daemon = fake_daemon(theirs, &cookie, 1, |br, w| {
        let mut line = String::new();
        br.read_line(&mut line).unwrap();
        // Expect "18 1\n" (CONTROL REQ_RELOAD).
        assert_eq!(line.trim_end(), "18 1");
        // Ack: "18 1 0\n" (errcode 0).
        writeln!(w, "18 1 0").unwrap();
    });

    let mut ctl = CtlSocket::handshake(ours, &cookie).unwrap();
    ctl.send(CtlRequest::Reload).unwrap();
    let result = ctl.recv_ack(CtlRequest::Reload).unwrap();
    assert_eq!(result, 0);

    daemon.join().unwrap();
}

/// Ack with nonzero result. `REQ_RELOAD` when reload failed.
/// The CLI doesn't error here — `recv_ack` returns the result,
/// caller decides.
#[test]
fn ack_nonzero_result() {
    let cookie = "e".repeat(64);
    let (ours, theirs) = UnixStream::pair().unwrap();

    let daemon = fake_daemon(theirs, &cookie, 1, |br, w| {
        let mut line = String::new();
        br.read_line(&mut line).unwrap();
        // Daemon-side reload failed → errcode 1.
        writeln!(w, "18 1 1").unwrap();
    });

    let mut ctl = CtlSocket::handshake(ours, &cookie).unwrap();
    ctl.send(CtlRequest::Reload).unwrap();
    let result = ctl.recv_ack(CtlRequest::Reload).unwrap();
    // Nonzero — caller handles.
    assert_eq!(result, 1);

    daemon.join().unwrap();
}

/// `send_int`: `REQ_SET_DEBUG` with the level argument.
#[test]
fn send_with_int_arg() {
    let cookie = "f".repeat(64);
    let (ours, theirs) = UnixStream::pair().unwrap();

    let daemon = fake_daemon(theirs, &cookie, 1, |br, w| {
        let mut line = String::new();
        br.read_line(&mut line).unwrap();
        // "18 9 5\n" — CONTROL SET_DEBUG level=5.
        assert_eq!(line.trim_end(), "18 9 5");
        // Ack with previous level (3). REQ_SET_DEBUG repurposes
        // the result field: send old level *before* updating.
        writeln!(w, "18 9 3").unwrap();
    });

    let mut ctl = CtlSocket::handshake(ours, &cookie).unwrap();
    ctl.send_int(CtlRequest::SetDebug, 5).unwrap();
    let prev = ctl.recv_ack(CtlRequest::SetDebug).unwrap();
    assert_eq!(prev, 3);

    daemon.join().unwrap();
}

/// `send_str`: `REQ_DISCONNECT` with a node name.
#[test]
fn send_with_str_arg() {
    let cookie = "0".repeat(64);
    let (ours, theirs) = UnixStream::pair().unwrap();

    let daemon = fake_daemon(theirs, &cookie, 1, |br, w| {
        let mut line = String::new();
        br.read_line(&mut line).unwrap();
        // "18 12 alice\n" — CONTROL DISCONNECT name=alice.
        assert_eq!(line.trim_end(), "18 12 alice");
        // Ack: 0 = found and disconnected. -2 would be not-found.
        writeln!(w, "18 12 0").unwrap();
    });

    let mut ctl = CtlSocket::handshake(ours, &cookie).unwrap();
    ctl.send_str(CtlRequest::Disconnect, "alice").unwrap();
    let result = ctl.recv_ack(CtlRequest::Disconnect).unwrap();
    assert_eq!(result, 0);

    daemon.join().unwrap();
}

/// `recv_line` raw: the dump-style multi-line response. Read
/// until 2-int terminator, then EOF.
#[test]
fn recv_lines_until_eof() {
    let cookie = "1".repeat(64);
    let (ours, theirs) = UnixStream::pair().unwrap();

    let daemon = fake_daemon(theirs, &cookie, 1, |br, w| {
        let mut line = String::new();
        br.read_line(&mut line).unwrap();
        assert_eq!(line.trim_end(), "18 3"); // DUMP_NODES
        // Three nodes, then terminator. Field content is
        // arbitrary — we're testing the line-at-a-time machinery,
        // not the parse (that's per-dump-type, lands later).
        writeln!(w, "18 3 alice somefield").unwrap();
        writeln!(w, "18 3 bob otherfield").unwrap();
        writeln!(w, "18 3 carol third").unwrap();
        writeln!(w, "18 3").unwrap(); // 2-int terminator
        // Drop → EOF.
    });

    let mut ctl = CtlSocket::handshake(ours, &cookie).unwrap();
    ctl.send(CtlRequest::DumpNodes).unwrap();

    // Collect until terminator. Same loop shape as cmd_dump.
    let mut rows = Vec::new();
    loop {
        let line = ctl.recv_line().unwrap().expect("daemon dropped early");
        let n_tokens = line.split_ascii_whitespace().count();
        if n_tokens == 2 {
            break; // terminator
        }
        rows.push(line);
    }
    assert_eq!(rows.len(), 3);
    assert!(rows[0].contains("alice"));

    // Next recv → EOF (daemon dropped).
    assert_eq!(ctl.recv_line().unwrap(), None);

    daemon.join().unwrap();
}

/// `recv_ack` rejects mismatched request echo. Daemon sent ack
/// for `REQ_PURGE`, we expected `REQ_RELOAD`. Either a daemon bug
/// or response interleaving (which doesn't happen in the
/// strictly-alternating protocol, but defense).
#[test]
fn recv_ack_wrong_type() {
    let cookie = "2".repeat(64);
    let (ours, theirs) = UnixStream::pair().unwrap();

    let daemon = fake_daemon(theirs, &cookie, 1, |br, w| {
        let mut line = String::new();
        br.read_line(&mut line).unwrap();
        // Ack PURGE (8), not RELOAD (1).
        writeln!(w, "18 8 0").unwrap();
    });

    let mut ctl = CtlSocket::handshake(ours, &cookie).unwrap();
    ctl.send(CtlRequest::Reload).unwrap();
    let err = ctl.recv_ack(CtlRequest::Reload).unwrap_err();
    assert!(matches!(err, CtlError::Greeting(_)));

    daemon.join().unwrap();
}

/// The stop pattern: send `REQ_STOP`, drain until EOF. The daemon
/// acks then exits, closing the socket.
#[test]
fn stop_drains_to_eof() {
    let cookie = "3".repeat(64);
    let (ours, theirs) = UnixStream::pair().unwrap();

    let daemon = fake_daemon(theirs, &cookie, 1, |br, w| {
        let mut line = String::new();
        br.read_line(&mut line).unwrap();
        assert_eq!(line.trim_end(), "18 0"); // STOP
        // Ack, then drop. The ack is sent, then the event loop
        // exits, connections close.
        writeln!(w, "18 0 0").unwrap();
        // Thread returns → `theirs` drops → EOF.
    });

    let mut ctl = CtlSocket::handshake(ours, &cookie).unwrap();
    ctl.send(CtlRequest::Stop).unwrap();

    // Drain. We see the ack line, then EOF. Read until None.
    let mut drained = 0;
    while ctl.recv_line().unwrap().is_some() {
        drained += 1;
    }
    assert_eq!(drained, 1); // the ack

    daemon.join().unwrap();
}

// ─── recv_row: the dump prefix-strip + terminator detect
//
// Same harness as `recv_lines_until_eof`, but using the typed
// `recv_row` instead of hand-tokenizing. The parse step (body →
// NodeRow etc.) lives in cmd::dump tests; this is just the
// "18 N " prefix and the End vs Row distinction.

/// Three rows, terminator. The body is byte-exact: spaces inside
/// `"10.0.0.1 port 655"` survive.
#[test]
fn recv_row_basic() {
    let cookie = "2".repeat(64);
    let (ours, theirs) = UnixStream::pair().unwrap();

    let daemon = fake_daemon(theirs, &cookie, 1, |br, w| {
        let mut line = String::new();
        br.read_line(&mut line).unwrap();
        assert_eq!(line.trim_end(), "18 3");
        // Body with embedded `port` literal — `recv_row` must
        // NOT touch it. The cmd::dump parse re-tokenizes.
        writeln!(w, "18 3 alice 10.0.0.1 port 655 fields").unwrap();
        writeln!(w, "18 3 bob unknown port unknown fields").unwrap();
        writeln!(w, "18 3").unwrap();
    });

    let mut ctl = CtlSocket::handshake(ours, &cookie).unwrap();
    ctl.send(CtlRequest::DumpNodes).unwrap();

    // Row 1: kind = DumpNodes, body byte-exact.
    let r1 = ctl.recv_row().unwrap();
    assert_eq!(
        r1,
        DumpRow::Row(
            CtlRequest::DumpNodes,
            "alice 10.0.0.1 port 655 fields".into()
        )
    );
    // Row 2: same. The double-space wouldn't survive a
    // re-tokenize-then-join; but recv_row slices, doesn't
    // tokenize, so single spaces stay single spaces. (The
    // body never HAS double spaces — daemon's printf has
    // single — but the slicing approach is correct anyway.)
    let r2 = ctl.recv_row().unwrap();
    assert_eq!(
        r2,
        DumpRow::Row(
            CtlRequest::DumpNodes,
            "bob unknown port unknown fields".into()
        )
    );
    // Terminator.
    let r3 = ctl.recv_row().unwrap();
    assert_eq!(r3, DumpRow::End(CtlRequest::DumpNodes));

    daemon.join().unwrap();
}

/// EOF before terminator → error. Daemon crashed.
#[test]
fn recv_row_eof_mid_dump() {
    let cookie = "3".repeat(64);
    let (ours, theirs) = UnixStream::pair().unwrap();

    let daemon = fake_daemon(theirs, &cookie, 1, |br, w| {
        let mut line = String::new();
        br.read_line(&mut line).unwrap();
        // One row, then DROP without terminator.
        writeln!(w, "18 3 alice partial").unwrap();
        // ← no "18 3\n". Socket closes when |br, w| returns.
    });

    let mut ctl = CtlSocket::handshake(ours, &cookie).unwrap();
    ctl.send(CtlRequest::DumpNodes).unwrap();

    // First recv: the partial row. Fine.
    let r1 = ctl.recv_row().unwrap();
    assert!(matches!(r1, DumpRow::Row(CtlRequest::DumpNodes, _)));
    // Second: EOF → error, not Ok(None).
    let err = ctl.recv_row().unwrap_err();
    assert!(matches!(err, CtlError::Greeting(m) if m.contains("Error receiving dump")));

    daemon.join().unwrap();
}

/// Wrong code (`"19 3 ..."`) → error. We tighten over upstream:
/// a non-18 prefix is corruption.
#[test]
fn recv_row_bad_code() {
    let cookie = "4".repeat(64);
    let (ours, theirs) = UnixStream::pair().unwrap();

    let daemon = fake_daemon(theirs, &cookie, 1, |br, w| {
        let mut line = String::new();
        br.read_line(&mut line).unwrap();
        // 19 is not CONTROL.
        writeln!(w, "19 3 garbage").unwrap();
    });

    let mut ctl = CtlSocket::handshake(ours, &cookie).unwrap();
    ctl.send(CtlRequest::DumpNodes).unwrap();

    let err = ctl.recv_row().unwrap_err();
    assert!(matches!(err, CtlError::Greeting(m) if m.contains("Unable to parse dump")));

    daemon.join().unwrap();
}

/// Graph mode: TWO sends, TWO terminators. The first End
/// (`DumpNodes`) doesn't end the loop — caller checks which kind.
/// `recv_row` itself doesn't track state; it just hands back
/// (kind, body) per row. The CALLER's loop knows graph mode
/// continues past the first End. This test is the daemon side
/// of that contract: send both responses, both terminators.
#[test]
fn recv_row_graph_two_terminators() {
    let cookie = "5".repeat(64);
    let (ours, theirs) = UnixStream::pair().unwrap();

    let daemon = fake_daemon(theirs, &cookie, 1, |br, w| {
        let mut line = String::new();
        br.read_line(&mut line).unwrap();
        assert_eq!(line.trim_end(), "18 3"); // DUMP_NODES
        line.clear();
        br.read_line(&mut line).unwrap();
        assert_eq!(line.trim_end(), "18 4"); // DUMP_EDGES

        // Daemon responds in order. First nodes (1 row + term):
        writeln!(w, "18 3 alice fields").unwrap();
        writeln!(w, "18 3").unwrap();
        // Then edges (1 row + term):
        writeln!(w, "18 4 alice bob fields").unwrap();
        writeln!(w, "18 4").unwrap();
    });

    let mut ctl = CtlSocket::handshake(ours, &cookie).unwrap();
    // Graph mode sends BOTH. The daemon doesn't pipeline
    // (strictly request-response), but TCP buffers the second
    // send while the daemon is still writing the first response.
    ctl.send(CtlRequest::DumpNodes).unwrap();
    ctl.send(CtlRequest::DumpEdges).unwrap();

    // Row, End(Nodes), Row, End(Edges) — in that order.
    assert!(matches!(
        ctl.recv_row().unwrap(),
        DumpRow::Row(CtlRequest::DumpNodes, _)
    ));
    assert_eq!(ctl.recv_row().unwrap(), DumpRow::End(CtlRequest::DumpNodes));
    assert!(matches!(
        ctl.recv_row().unwrap(),
        DumpRow::Row(CtlRequest::DumpEdges, _)
    ));
    assert_eq!(ctl.recv_row().unwrap(), DumpRow::End(CtlRequest::DumpEdges));

    daemon.join().unwrap();
}

/// `"18 3 "` with trailing space (daemon never emits) →
/// terminator. Empty body → End.
#[test]
fn recv_row_trailing_space_is_terminator() {
    let cookie = "6".repeat(64);
    let (ours, theirs) = UnixStream::pair().unwrap();

    let daemon = fake_daemon(theirs, &cookie, 1, |_br, w| {
        // Trailing space after the type. Daemon's printf doesn't
        // emit this; defensive against hand-crafted socket input.
        writeln!(w, "18 3 ").unwrap();
    });

    let mut ctl = CtlSocket::handshake(ours, &cookie).unwrap();
    // No send needed — we're just reading what's in the buffer.
    // (Real usage would send first, but recv_row doesn't track
    // that.)
    let r = ctl.recv_row().unwrap();
    assert_eq!(r, DumpRow::End(CtlRequest::DumpNodes));

    daemon.join().unwrap();
}

/// `recv_data` after `recv_line`: the shared-buffer concern.
///
/// Daemon writes header + data in ONE syscall (it doesn't, but
/// TCP can coalesce). `BufReader` reads it ALL into its 8KiB
/// buffer on the first `read_line`. The data is now in the
/// `BufReader`'s buffer, not the socket. `recv_data` must see it.
///
/// THE test for the plan's "blocked on draining `buffer()`".
/// `BufReader<T>: Read` is what makes this work — `read_exact`
/// drains the buffer first. The test pins it: if someone
/// "optimizes" `recv_data` to `self.reader.get_mut().0.borrow_
/// mut().read_exact()` (bypassing `BufReader`), this fails.
///
/// `Cursor<Vec<u8>>` is the in-memory stream. ONE buffer, two
/// records (header + data each), back-to-back, no separator.
/// Exactly what TCP coalescing gives.
#[test]
fn recv_data_after_recv_line_shared_buffer() {
    // Record 1: "18 15 7\n" + 7 bytes "LOGDATA"
    // Record 2: "18 15 5\n" + 5 bytes "HELLO"
    // No newline after data — the daemon doesn't add one
    // (header via `send_request`, raw bytes via `send_meta`).
    let mut wire = Vec::new();
    wire.extend_from_slice(b"18 15 7\n");
    wire.extend_from_slice(b"LOGDATA");
    wire.extend_from_slice(b"18 15 5\n");
    wire.extend_from_slice(b"HELLO");

    // Cursor is Read+Write but we only read. Direct CtlSocket
    // construction (bypass connect/handshake). The greeting
    // exchange isn't under test; the buffer behavior is.
    let stream = std::io::Cursor::new(wire);
    let shared = Rc::new(RefCell::new(stream));
    let mut ctl = CtlSocket {
        reader: BufReader::new(ReadHalf(Rc::clone(&shared))),
        writer: WriteHalf(shared),
        pid: 0,
    };

    // ─── Record 1
    // `recv_line` reads through '\n'. BufReader's first read
    // pulls EVERYTHING (Cursor returns it all). 'LOGDATA' is
    // now in BufReader's buffer.
    let line = ctl.recv_line().unwrap().unwrap();
    assert_eq!(line, "18 15 7");

    // 7 bytes. They're in BufReader's buffer, NOT the Cursor.
    // `read_exact` on BufReader drains buffer first.
    let mut data = [0u8; 7];
    ctl.recv_data(&mut data).unwrap();
    assert_eq!(&data, b"LOGDATA");

    // ─── Record 2
    // STILL in BufReader's buffer (Cursor returned everything
    // on the first read).
    let line = ctl.recv_line().unwrap().unwrap();
    assert_eq!(line, "18 15 5");

    let mut data2 = [0u8; 5];
    ctl.recv_data(&mut data2).unwrap();
    assert_eq!(&data2, b"HELLO");

    // ─── EOF
    let line = ctl.recv_line().unwrap();
    assert_eq!(line, None);
}

/// `recv_data` with daemon EOF mid-data: header said 100 bytes,
/// daemon dies after 50. `read_exact` returns `UnexpectedEof`.
#[test]
fn recv_data_short_is_error() {
    let wire = b"18 15 100\nshort".to_vec();
    let stream = std::io::Cursor::new(wire);
    let shared = Rc::new(RefCell::new(stream));
    let mut ctl = CtlSocket {
        reader: BufReader::new(ReadHalf(Rc::clone(&shared))),
        writer: WriteHalf(shared),
        pid: 0,
    };

    let line = ctl.recv_line().unwrap().unwrap();
    assert_eq!(line, "18 15 100");

    let mut data = [0u8; 100];
    let err = ctl.recv_data(&mut data).unwrap_err();
    // The Display path: `CtlError::Io(UnexpectedEof)`. We don't
    // pattern-match the kind (CtlError::Io carries a generic
    // io::Error); the message contains it. `tinc log` doesn't
    // surface this anyway (silent loop exit), but the test
    // pins the type.
    let CtlError::Io(io) = err else {
        panic!("expected Io, got {err}")
    };
    assert_eq!(io.kind(), std::io::ErrorKind::UnexpectedEof);
}

/// `send_int2` wire shape: `"18 15 -1 1\n"`. The `REQ_LOG`
/// request: level=-1 (`DEBUG_UNSET`), color=1.
#[test]
fn send_int2_wire() {
    let buf: Vec<u8> = Vec::new();
    let stream = std::io::Cursor::new(buf);
    let shared = Rc::new(RefCell::new(stream));
    let mut ctl = CtlSocket {
        reader: BufReader::new(ReadHalf(Rc::clone(&shared))),
        writer: WriteHalf(Rc::clone(&shared)),
        pid: 0,
    };

    ctl.send_int2(CtlRequest::Log, -1, 1).unwrap();

    let written = shared.borrow().get_ref().clone();
    // `"18 15 -1 1\n"`. CONTROL=18, REQ_LOG=15, level=-1, color=1.
    assert_eq!(written, b"18 15 -1 1\n");
}
