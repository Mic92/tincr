#![cfg(unix)]

use super::fake_daemon::{fake_daemon_setup, serve_greeting};
use super::tinc;

/// Helper: init a confbase, return its dir + a --pidfile pointing
/// at nothing (so the post-edit reload silently fails).
fn config_init(name: &str) -> (tempfile::TempDir, String, String) {
    let dir = tempfile::tempdir().unwrap();
    let cb = dir.path().join("vpn");
    let cb_s = cb.to_str().unwrap().to_owned();
    let pidfile = dir.path().join("nope.pid");
    let pidfile_s = pidfile.to_str().unwrap().to_owned();

    let out = tinc(&["-c", &cb_s, "init", name]);
    assert!(out.status.success(), "{:?}", out.stderr);
    (dir, cb_s, pidfile_s)
}

/// Helper: spawn `tinc` with `TZ=UTC` so `fmt_localtime` is
/// deterministic. The unit tests can't safely `setenv("TZ")` (cargo
/// test threads share process state); subprocess env is per-process.
fn tinc_utc(args: &[&str]) -> std::process::Output {
    use std::process::Command;
    Command::new(env!("CARGO_BIN_EXE_tinc"))
        .args(args)
        .env("TZ", "UTC")
        .output()
        .unwrap()
}

/// `tinc info bob` against a fake daemon serving 3 nodes (bob is the
/// 2nd — exercises both pre-match-skip and post-match-drain), 4
/// edges (2 from bob — exercises filter), 3 subnets (1 owned by bob).
///
/// THE three-dump-sequence test. The daemon must see THREE `"18 N
/// item"` requests in order (the dead-third-arg compat check is the
/// `assert_eq!` on the request lines).
///
/// `clippy::too_many_lines`: it's a fake-daemon script + a golden
/// output check. One scenario, end-to-end. Splitting would mean
/// helpers that wrap helpers.
#[test]
#[allow(clippy::too_many_lines)]
fn info_node_against_fake() {
    use std::io::{BufRead, Write};

    let (_dir, cb, pf, listener, cookie) = fake_daemon_setup();

    let daemon = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let (mut br, mut w) = serve_greeting(&stream, &cookie);

        // ─── Round 1: DUMP_NODES ────────────────────────────────
        // Request includes `bob` as the dead third arg. C `info.c
        // :53`. Daemon doesn't read it (`control.c:63`: just `case
        // REQ_DUMP_NODES: return dump_nodes(c)`). We assert it
        // arrives anyway — wire-compat with what C `tinc info`
        // sends.
        let mut req = String::new();
        br.read_line(&mut req).unwrap();
        assert_eq!(req.trim_end(), "18 3 bob", "dead third arg should be sent");

        // Three node rows. bob is #2 (so the match-loop skips alice,
        // matches bob, then DRAINS carol). All 22 wire fields per
        // `node.c:210`.
        //
        // bob's row: reachable+validkey+sptps (status=0x52),
        // direct UDP (minmtu>0), version 7 (options=0x07000004 =
        // PMTU_DISCOVERY|ver7). last_state_change = 1700000000
        // (2023-11-14 22:13:20 UTC).
        writeln!(
            w,
            "18 3 alice 0 1.1.1.1 port 655 0 0 0 0 0 12 - alice 1 0 0 0 0 -1 0 0 0 0"
        )
        .unwrap();
        writeln!(
            w,
            "18 3 bob 0a1b2c3d4e5f 10.0.0.2 port 655 \
             0 0 0 0 7000004 52 alice bob 1 1518 1400 1518 \
             1700000000 1500 100 50000 200 100000"
        )
        .unwrap();
        writeln!(
            w,
            "18 3 carol 0 unknown port unknown 0 0 0 0 0 0 - - 99 0 0 0 0 -1 0 0 0 0"
        )
        .unwrap();
        writeln!(w, "18 3").unwrap(); // terminator

        // ─── Round 2: DUMP_EDGES ────────────────────────────────
        // Only fires AFTER the nodes terminator (sequential, not
        // pipelined — `info.c:201` is after the drain loop). The
        // dead third arg again.
        req.clear();
        br.read_line(&mut req).unwrap();
        assert_eq!(req.trim_end(), "18 4 bob");

        // 4 edges. Two have from=bob → collected. The other two
        // are filtered out. C `info.c:214`: `if(!strcmp(from, item))`.
        //
        // Full 8-field rows BUT the parse only reads the first two
        // strings. The trailing junk after `to` proves that:
        // "18 4 bob alice GARBAGE GARBAGE" would still parse
        // (first 2 strings = bob, alice). We send well-formed rows
        // because that's what the daemon does, but the partial-
        // parse is what's exercised.
        writeln!(
            w,
            "18 4 alice bob 1.1.1.2 port 655 unspec port unspec 0 100"
        )
        .unwrap();
        writeln!(
            w,
            "18 4 bob alice 1.1.1.1 port 655 unspec port unspec 0 100"
        )
        .unwrap();
        writeln!(
            w,
            "18 4 bob carol 1.1.1.3 port 655 unspec port unspec 0 200"
        )
        .unwrap();
        writeln!(
            w,
            "18 4 carol bob 1.1.1.2 port 655 unspec port unspec 0 200"
        )
        .unwrap();
        writeln!(w, "18 4").unwrap();

        // ─── Round 3: DUMP_SUBNETS ──────────────────────────────
        req.clear();
        br.read_line(&mut req).unwrap();
        assert_eq!(req.trim_end(), "18 5 bob");

        // 3 subnets. One owned by bob.
        writeln!(w, "18 5 10.0.0.0/24 alice").unwrap();
        writeln!(w, "18 5 10.0.1.0/24 bob").unwrap();
        writeln!(w, "18 5 ff:ff:ff:ff:ff:ff (broadcast)").unwrap();
        writeln!(w, "18 5").unwrap();
    });

    let out = tinc_utc(&["-c", &cb, "--pidfile", &pf, "info", "bob"]);
    daemon.join().unwrap();

    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(out.status.success(), "stderr: {stderr}");

    let stdout = String::from_utf8(out.stdout).unwrap();

    // ─── Assert: byte-for-byte golden ──────────────────────────────
    // status=0x52 = bit 1 (validkey) | bit 4 (reachable) | bit 6
    // (sptps). NOT visited/indirect/udp_confirmed.
    // options=0x07000004 = PMTU_DISCOVERY (bit 2) | version 7.
    // 1700000000 in UTC = 2023-11-14 22:13:20.
    // 1500us → "RTT: 1.500".
    let expected = "\
Node:         bob
Node ID:      0a1b2c3d4e5f
Address:      10.0.0.2 port 655
Online since: 2023-11-14 22:13:20
Status:       validkey reachable sptps
Options:      pmtu_discovery
Protocol:     17.7
Reachability: directly with UDP
PMTU:         1518
RTT:          1.500
RX:           100 packets  50000 bytes
TX:           200 packets  100000 bytes
Edges:        alice carol
Subnets:      10.0.1.0/24
";
    assert_eq!(stdout, expected);
}

/// `tinc info dave` (nonexistent): NODES dump runs, no match,
/// terminator, error. EDGES/SUBNETS NEVER sent. C `info.c:97-100`:
/// `if(!found) { fprintf(stderr, "Unknown node"); return 1; }`
/// — BEFORE the second sendline.
///
/// The fake daemon asserts NO second request arrives (read_line
/// would block; we drop the socket after the nodes terminator and
/// the test thread's daemon-side join confirms it returned).
#[test]
fn info_node_not_found_short_circuits() {
    use std::io::{BufRead, Write};

    let (_dir, cb, pf, listener, cookie) = fake_daemon_setup();

    let daemon = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let (mut br, mut w) = serve_greeting(&stream, &cookie);

        let mut req = String::new();
        br.read_line(&mut req).unwrap();
        assert_eq!(req.trim_end(), "18 3 dave");

        // One node, NOT dave. Then terminator.
        writeln!(
            w,
            "18 3 alice 0 1.1.1.1 port 655 0 0 0 0 0 12 - alice 0 0 0 0 0 -1 0 0 0 0"
        )
        .unwrap();
        writeln!(w, "18 3").unwrap();

        // ─── Assert: NO second request ─────────────────────────
        // The CLI errors after the nodes terminator without sending
        // the EDGES request. If it DID send, this read would get
        // "18 4 dave\n". Instead the CLI's socket drops → EOF →
        // read_line returns 0 bytes.
        //
        // The C: `info.c:97` returns 1 BEFORE `info.c:202`'s
        // sendline. If our impl pipelined or didn't short-circuit,
        // this assert catches it.
        req.clear();
        let n = br.read_line(&mut req).unwrap();
        assert_eq!(n, 0, "expected EOF, got second request: {req:?}");
    });

    let out = tinc(&["-c", &cb, "--pidfile", &pf, "info", "dave"]);
    daemon.join().unwrap();

    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    // C `info.c:98`: `"Unknown node %s.\n"`.
    assert!(stderr.contains("Unknown node dave."));
    assert!(out.stdout.is_empty());
}

/// `tinc info 10.0.0.5` (address mode): which subnets contain it?
/// The /24 does, the /16 does, the unrelated /24 doesn't. ALL
/// matches printed (no longest-prefix selection — `info_subnet`
/// shows everything that matches, the daemon's routing table picks
/// longest at PACKET time).
#[test]
fn info_subnet_address_mode() {
    use std::io::{BufRead, Write};

    let (_dir, cb, pf, listener, cookie) = fake_daemon_setup();

    let daemon = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let (mut br, mut w) = serve_greeting(&stream, &cookie);

        let mut req = String::new();
        br.read_line(&mut req).unwrap();
        // Dead third arg: the address itself.
        assert_eq!(req.trim_end(), "18 5 10.0.0.5");

        // 4 subnets. Two contain 10.0.0.5.
        writeln!(w, "18 5 10.0.0.0/24 alice").unwrap();
        writeln!(w, "18 5 10.0.0.0/16 bob").unwrap();
        writeln!(w, "18 5 192.168.0.0/24 carol").unwrap();
        // (broadcast) MAC → type mismatch → filtered.
        writeln!(w, "18 5 ff:ff:ff:ff:ff:ff (broadcast)").unwrap();
        writeln!(w, "18 5").unwrap();
    });

    let out = tinc(&["-c", &cb, "--pidfile", &pf, "info", "10.0.0.5"]);
    daemon.join().unwrap();

    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();

    // C `info.c:325-327`: `"Subnet: %s\nOwner:  %s\n"`. Two spaces
    // after `Owner:` (column alignment). Per match.
    let expected = "\
Subnet: 10.0.0.0/24
Owner:  alice
Subnet: 10.0.0.0/16
Owner:  bob
";
    assert_eq!(stdout, expected);
    // 192.168 NOT in output (didn't match).
    assert!(!stdout.contains("carol"));
    // (broadcast) NOT in output (type mismatch).
    assert!(!stdout.contains("broadcast"));
}

/// `tinc info 99.99.99.99` (no match): "Unknown address". C `info.c
/// :333`. The wording differs from "Unknown subnet" (which is the
/// `/`-present case at :336).
#[test]
fn info_subnet_no_match() {
    use std::io::{BufRead, Write};

    let (_dir, cb, pf, listener, cookie) = fake_daemon_setup();

    let daemon = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let (mut br, mut w) = serve_greeting(&stream, &cookie);

        let mut req = String::new();
        br.read_line(&mut req).unwrap();
        // One subnet that doesn't contain 99.99.99.99.
        writeln!(w, "18 5 10.0.0.0/24 alice").unwrap();
        writeln!(w, "18 5").unwrap();
    });

    let out = tinc(&["-c", &cb, "--pidfile", &pf, "info", "99.99.99.99"]);
    daemon.join().unwrap();

    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    // No `/` → "address" wording. C `info.c:333`.
    assert!(stderr.contains("Unknown address 99.99.99.99."));
    assert!(out.stdout.is_empty());
}

/// `tinc info @!$` (neither node name nor subnet): the dispatch
/// rejects before connect. C `info.c:355`. Daemon never accepts.
#[test]
fn info_invalid_arg() {
    let (_d, cb, pf) = config_init("alice");
    let out = tinc(&["-c", &cb, "--pidfile", &pf, "info", "@!$"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    // C `info.c:355`: exact string.
    assert!(stderr.contains("Argument is not a node name, subnet or address."));
}
