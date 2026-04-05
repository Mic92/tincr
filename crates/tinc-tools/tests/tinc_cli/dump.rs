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

/// `tinc dump nodes` against a fake daemon. The daemon sends a
/// 22-field row exactly as C `node.c:210` would. Our binary parses
/// it and prints exactly what C `tinc dump nodes` would.
///
/// THE seam: this is C-daemon-compat. If `dump_nodes_against_fake`
/// passes and `node.c:210` hasn't changed, Rust `tinc` works against
/// C `tincd`.
#[test]
fn dump_nodes_against_fake() {
    use std::io::{BufRead, Write};

    let (_dir, cb, pf, listener, cookie) = fake_daemon_setup();

    let daemon = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let (mut br, mut w) = serve_greeting(&stream, &cookie);

        // Receive DUMP_NODES.
        let mut req = String::new();
        br.read_line(&mut req).unwrap();
        assert_eq!(req.trim_end(), "18 3");

        // ─── Send: TWO node rows + terminator ──────────────────
        // Format: `node.c:210`.
        // `%d %d %s %s %s %d %d %lu %d %x %x %s %s %d %d %d %d
        //  %ld %d %llu %llu %llu %llu`
        //
        // The `%s` for hostname is `"10.0.0.1 port 655"` — ONE
        // printf conversion, three tokens. The CLI sscanf has
        // `%s port %s` to re-split.
        //
        // Node 1: alice. Reachable + validkey (status=0x12).
        // udp_ping_rtt=1500 → "rtt 1.500" suffix.
        writeln!(
            w,
            "18 3 alice 0a1b2c3d4e5f 10.0.0.1 port 655 \
             0 0 0 0 1000000c 12 bob alice 1 1518 1400 1518 \
             1700000000 1500 100 50000 200 100000"
        )
        .unwrap();
        // Node 2: carol. Unreachable (status=0). rtt=-1 → no suffix.
        // hostname "unknown port unknown" (NULL hostname case).
        writeln!(
            w,
            "18 3 carol 000000000000 unknown port unknown \
             0 0 0 0 0 0 - - 99 0 0 0 0 -1 0 0 0 0"
        )
        .unwrap();
        // Terminator.
        writeln!(w, "18 3").unwrap();
    });

    let out = tinc(&["-c", &cb, "--pidfile", &pf, "dump", "nodes"]);
    daemon.join().unwrap();

    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(out.status.success(), "stderr: {stderr}");

    let stdout = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 2, "stdout: {stdout:?}");

    // ─── Assert: byte-for-byte what C `tinc dump nodes` prints ──
    // C `tincctl.c:1310` printf format. `status %04x` (0x12 → "0012").
    // The `rtt 1.500` suffix because udp_ping_rtt != -1.
    assert_eq!(
        lines[0],
        "alice id 0a1b2c3d4e5f at 10.0.0.1 port 655 cipher 0 digest 0 \
         maclength 0 compression 0 options 1000000c status 0012 \
         nexthop bob via alice distance 1 pmtu 1518 (min 1400 max 1518) \
         rx 100 50000 tx 200 100000 rtt 1.500"
    );
    // carol: no rtt suffix (rtt=-1). status 0000 (padded).
    assert_eq!(
        lines[1],
        "carol id 000000000000 at unknown port unknown cipher 0 digest 0 \
         maclength 0 compression 0 options 0 status 0000 \
         nexthop - via - distance 99 pmtu 0 (min 0 max 0) \
         rx 0 0 tx 0 0"
    );
}

/// `tinc dump reachable nodes`: same fetch, filtered. carol (status=0,
/// bit 4 clear) is dropped. C `tincctl.c:1306`.
#[test]
fn dump_reachable_nodes_filters() {
    use std::io::{BufRead, Write};

    let (_dir, cb, pf, listener, cookie) = fake_daemon_setup();

    let daemon = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let (mut br, mut w) = serve_greeting(&stream, &cookie);

        let mut req = String::new();
        br.read_line(&mut req).unwrap();
        assert_eq!(req.trim_end(), "18 3");

        // alice: status=0x12 (bit 4 set → reachable).
        writeln!(
            w,
            "18 3 alice 0 1.1.1.1 port 1 0 0 0 0 0 12 - alice 0 0 0 0 0 -1 0 0 0 0"
        )
        .unwrap();
        // carol: status=0 (bit 4 clear → unreachable). FILTERED OUT.
        writeln!(
            w,
            "18 3 carol 0 unknown port unknown 0 0 0 0 0 0 - - 0 0 0 0 0 -1 0 0 0 0"
        )
        .unwrap();
        writeln!(w, "18 3").unwrap();
    });

    let out = tinc(&["-c", &cb, "--pidfile", &pf, "dump", "reachable", "nodes"]);
    daemon.join().unwrap();

    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    // Only alice survived.
    assert_eq!(lines.len(), 1);
    assert!(lines[0].starts_with("alice "));
    assert!(!stdout.contains("carol"));
}

/// `tinc dump subnets`: simplest dump. `strip_weight` is in the path.
#[test]
fn dump_subnets_against_fake() {
    use std::io::{BufRead, Write};

    let (_dir, cb, pf, listener, cookie) = fake_daemon_setup();

    let daemon = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let (mut br, mut w) = serve_greeting(&stream, &cookie);

        let mut req = String::new();
        br.read_line(&mut req).unwrap();
        assert_eq!(req.trim_end(), "18 5"); // DUMP_SUBNETS

        // `subnet.c:403`: `%d %d %s %s` → netstr, owner.
        // Daemon's net2str already strips #10, so "10.0.0.0/24"
        // not "10.0.0.0/24#10". But we test strip_weight too:
        writeln!(w, "18 5 10.0.0.0/24 alice").unwrap();
        writeln!(w, "18 5 192.168.0.0/16#5 bob").unwrap();
        // (broadcast) literal — `subnet.c:406`.
        writeln!(w, "18 5 ff:ff:ff:ff:ff:ff (broadcast)").unwrap();
        // Hypothetical old daemon sending #10 — strip_weight strips.
        writeln!(w, "18 5 172.16.0.0/12#10 carol").unwrap();
        writeln!(w, "18 5").unwrap();
    });

    let out = tinc(&["-c", &cb, "--pidfile", &pf, "dump", "subnets"]);
    daemon.join().unwrap();

    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 4);
    // C `tincctl.c:1352`: `"%s owner %s"`.
    assert_eq!(lines[0], "10.0.0.0/24 owner alice");
    // #5 (non-default) survives.
    assert_eq!(lines[1], "192.168.0.0/16#5 owner bob");
    assert_eq!(lines[2], "ff:ff:ff:ff:ff:ff owner (broadcast)");
    // #10 stripped.
    assert_eq!(lines[3], "172.16.0.0/12 owner carol");
}

/// `tinc dump digraph`: TWO sends (nodes+edges), DOT output, two
/// terminators. The first End(DumpNodes) doesn't exit the loop.
/// C `tincctl.c:1247`: `if(do_graph && req == REQ_DUMP_NODES) continue;`.
///
/// This is the trickiest dump: pipelined sends, interleaved recv,
/// per-row format dispatch, undirected dedup (for `graph`).
#[test]
fn dump_digraph_against_fake() {
    use std::io::{BufRead, Write};

    let (_dir, cb, pf, listener, cookie) = fake_daemon_setup();

    let daemon = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let (mut br, mut w) = serve_greeting(&stream, &cookie);

        // ─── Receive BOTH requests ────────────────────────────
        // The CLI sends DUMP_NODES then DUMP_EDGES back-to-back.
        // TCP buffers; we read both before responding.
        let mut req1 = String::new();
        br.read_line(&mut req1).unwrap();
        assert_eq!(req1.trim_end(), "18 3"); // NODES
        let mut req2 = String::new();
        br.read_line(&mut req2).unwrap();
        assert_eq!(req2.trim_end(), "18 4"); // EDGES

        // ─── Nodes response ───────────────────────────────────
        // self (MYSELF → green, filled):
        writeln!(
            w,
            "18 3 alice 0 MYSELF port 655 0 0 0 0 0 1f - alice 0 1500 1500 1500 0 -1 0 0 0 0"
        )
        .unwrap();
        // bob (reachable, validkey, minmtu>0 → green):
        writeln!(
            w,
            "18 3 bob 0 1.1.1.2 port 655 0 0 0 0 0 12 alice bob 1 1500 1400 1500 0 -1 0 0 0 0"
        )
        .unwrap();
        writeln!(w, "18 3").unwrap(); // FIRST terminator

        // ─── Edges response ───────────────────────────────────
        // `edge.c:128`: `%d %d %s %s %s %s %x %d`.
        // Both addresses fused (sockaddr2hostname).
        // Digraph emits both directions.
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
        writeln!(w, "18 4").unwrap(); // SECOND terminator — exits loop
    });

    let out = tinc(&["-c", &cb, "--pidfile", &pf, "dump", "digraph"]);
    daemon.join().unwrap();

    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(out.status.success(), "stderr: {stderr}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();

    // ─── Assert: DOT structure ──────────────────────────────────
    // C `tincctl.c:1238`: `printf("digraph {\n")`. Then per-node
    // DOT lines (`tincctl.c:1303`), per-edge DOT lines (1334-1336),
    // then `printf("}\n")` (1250).
    assert_eq!(lines[0], "digraph {");
    assert_eq!(lines.last().unwrap(), &"}");
    assert_eq!(lines.len(), 6); // header + 2 nodes + 2 edges + footer

    // alice (MYSELF): green + filled. C `tincctl.c:1303`.
    assert_eq!(
        lines[1],
        " \"alice\" [label = \"alice\", color = \"green\", style = \"filled\"];"
    );
    // bob: green (UDP works), no filled.
    assert_eq!(lines[2], " \"bob\" [label = \"bob\", color = \"green\"];");
    // Edges: both directions (digraph). `->` arrow.
    // weight=100 → w = 1+65536/100 = 656.36 → f32 → 656.359985.
    assert_eq!(
        lines[3],
        " \"alice\" -> \"bob\" [w = 656.359985, weight = 656.359985];"
    );
    assert_eq!(
        lines[4],
        " \"bob\" -> \"alice\" [w = 656.359985, weight = 656.359985];"
    );
}

/// `tinc dump graph` (undirected): same as digraph, but only ONE
/// edge survives (the from < to one). bob → alice has bob > alice
/// (strcmp), suppressed. C `tincctl.c:1332`.
#[test]
fn dump_graph_dedups_edges() {
    use std::io::{BufRead, Write};

    let (_dir, cb, pf, listener, cookie) = fake_daemon_setup();

    let daemon = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let (mut br, mut w) = serve_greeting(&stream, &cookie);

        let mut buf = String::new();
        br.read_line(&mut buf).unwrap(); // 18 3
        buf.clear();
        br.read_line(&mut buf).unwrap(); // 18 4

        // Minimal: one node, two edges (both directions).
        writeln!(
            w,
            "18 3 a 0 MYSELF port 1 0 0 0 0 0 1f - a 0 0 0 0 0 -1 0 0 0 0"
        )
        .unwrap();
        writeln!(w, "18 3").unwrap();
        // a→b: a < b, emitted.
        writeln!(w, "18 4 a b 1.1.1.1 port 1 unspec port unspec 0 100").unwrap();
        // b→a: b > a, SUPPRESSED in undirected.
        writeln!(w, "18 4 b a 1.1.1.1 port 1 unspec port unspec 0 100").unwrap();
        writeln!(w, "18 4").unwrap();
    });

    let out = tinc(&["-c", &cb, "--pidfile", &pf, "dump", "graph"]);
    daemon.join().unwrap();

    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();

    // header, 1 node, 1 edge (the other suppressed), footer.
    assert_eq!(lines.len(), 4, "stdout: {stdout}");
    assert_eq!(lines[0], "graph {"); // not "digraph"
    // Edge: `--` arrow (undirected). a→b emitted (a < b).
    assert!(lines[2].contains("\"a\" -- \"b\""));
    // b→a NOT emitted.
    assert!(!stdout.contains("\"b\" -- \"a\""));
    assert!(!stdout.contains("\"b\" -> \"a\""));
    assert_eq!(lines[3], "}");
}

/// `tinc list nodes` is `tinc dump nodes`. C `tincctl.c:3010`.
#[test]
fn dump_list_alias() {
    use std::io::{BufRead, Write};

    let (_dir, cb, pf, listener, cookie) = fake_daemon_setup();

    let daemon = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let (mut br, mut w) = serve_greeting(&stream, &cookie);
        let mut req = String::new();
        br.read_line(&mut req).unwrap();
        // The wire is the same regardless of which verb. Proof.
        assert_eq!(req.trim_end(), "18 3");
        writeln!(w, "18 3 x 0 h port p 0 0 0 0 0 0 - - 0 0 0 0 0 -1 0 0 0 0").unwrap();
        writeln!(w, "18 3").unwrap();
    });

    // `list` not `dump`.
    let out = tinc(&["-c", &cb, "--pidfile", &pf, "list", "nodes"]);
    daemon.join().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.starts_with("x id 0"));
}

/// `tinc dump invitations` works WITHOUT daemon. Real `tinc invite`
/// writes a file; `dump invitations` finds it. The pidfile points at
/// nothing — daemon down.
#[test]
fn dump_invitations_no_daemon() {
    let (_d, cb, pf) = config_init("alice");
    // pf is nope.pid (nonexistent). Daemon not running.

    // Need Address for invite (HTTP probe was dropped).
    let host = std::path::Path::new(&cb).join("hosts/alice");
    let prev = std::fs::read_to_string(&host).unwrap();
    std::fs::write(&host, format!("Address = 192.0.2.1\n{prev}")).unwrap();

    // Create an invitation.
    let out = tinc(&["-c", &cb, "invite", "bob"]);
    assert!(out.status.success(), "{:?}", out.stderr);

    // Now dump. With daemon DOWN — pf doesn't exist.
    let out = tinc(&["-c", &cb, "--pidfile", &pf, "dump", "invitations"]);
    assert!(out.status.success(), "{:?}", out.stderr);

    let stdout = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 1);
    // C `tincctl.c:1170`: `"%s %s"` — cookie-hash space invitee.
    let parts: Vec<&str> = lines[0].split(' ').collect();
    assert_eq!(parts.len(), 2);
    assert_eq!(parts[0].len(), 24); // the b64 cookie hash
    assert_eq!(parts[1], "bob");

    // No daemon-connect noise. We DID resolve_runtime (one
    // access(2) probe — see the table-entry comment), but never
    // tried to actually connect.
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(!stderr.contains("pid file"));
    assert!(!stderr.contains("connect"));
}

/// `tinc dump invitations` with NONE outstanding: stderr message,
/// exit 0. C `tincctl.c:1116,1176`.
#[test]
fn dump_invitations_none() {
    let (_d, cb, pf) = config_init("alice");
    // No invite. Dir might not even exist (init doesn't create it).

    let out = tinc(&["-c", &cb, "--pidfile", &pf, "dump", "invitations"]);
    assert!(out.status.success()); // exit 0
    assert!(out.stdout.is_empty()); // nothing to stdout
    // The message goes to STDERR (script-friendly: stdout is data only).
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert_eq!(stderr.trim(), "No outstanding invitations.");
}

/// `tinc dump lasers` → "Unknown dump type 'lasers'."
#[test]
fn dump_unknown_type() {
    let (_d, cb, pf) = config_init("alice");
    let out = tinc(&["-c", &cb, "--pidfile", &pf, "dump", "lasers"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    // The single-quote and period are the C's.
    assert!(stderr.contains("Unknown dump type 'lasers'."));
}
