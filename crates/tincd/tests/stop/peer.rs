use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::process::Stdio;
use std::time::{Duration, Instant};

use super::common::{self, *};
use super::write_config;

fn tmp(tag: &str) -> super::common::TmpGuard {
    super::common::TmpGuard::new("stop", tag)
}

// ════════════════════════════════════════════════════════════════════
// SPTPS peer handshake → ACK exchange (chunk 4b)
//
// THE TEST IS THE INITIATOR. We don't have outgoing connections
// (`do_outgoing_connection` is chunk 6). So: we drive the initiator
// side from the test process using `tinc-sptps::Sptps` directly.
// Same shape as `tinc-tools/cmd/join.rs`'s pump loop.
//
// Chunk 4a stopped at `HandshakeDone`. Chunk 4b CONTINUES:
//   - daemon's HandshakeDone arm calls send_ack (NOT terminate)
//   - the ACK arrives as a SPTPS Record (encrypted)
//   - we send our ACK back (also encrypted)
//   - daemon's Record arm → check_gate → ack_h → "activated"
//   - connection STAYS UP (allow_request = ALL)
//   - `tinc dump connections` over control socket shows the row
//
// The label-NUL caveat from 4a still applies: this test uses the
// same construction on both sides; can't distinguish "both wrong".
// `proto::tests::tcp_label_has_trailing_nul` pins gcc bytes.

/// SPTPS handshake → ACK exchange → connection activated. The
/// daemon's `HandshakeDone` arm queues `send_ack`; we receive it as
/// an SPTPS `Record`, parse `"%d %s %d %x"`, send our ACK, daemon
/// activates. `tinc dump connections` then shows ONE peer row.
#[test]
fn peer_ack_exchange() {
    use std::io::Read;
    use tinc_sptps::Output;

    let mut fx = PeerFixture::spawn("peer-handshake");
    let pidfile = fx.pidfile.clone();
    let socket = fx.socket.clone();
    let mut tmp_buf = [0u8; 256];

    // ─── parse the daemon's ACK ─────────────────────────────────
    // `"%d %s %d %x"` = `"4 <udp-port> <weight> <opts>"`.
    // Record body has trailing `\n` (`send_request:120` appends).
    let ack = &fx.daemon_ack;
    let body = ack.strip_suffix(b"\n").unwrap_or(ack);
    let body = std::str::from_utf8(body).expect("ACK is ASCII");
    let mut t = body.split_whitespace();
    assert_eq!(t.next(), Some("4"), "ACK reqno: {body:?}");
    // UDP port: kernel-assigned (Port=0). Just: it's a valid u16,
    // and ≠ the TCP port (`bind_reusing_port` not yet — chunk 10).
    let daemon_udp_port: u16 = t.next().unwrap().parse().expect("udp port");
    assert_ne!(daemon_udp_port, 0);
    // Weight: RTT in ms. Localhost handshake is fast; >= 0, < some
    // sane bound. `(now - c->start)` ms.
    let daemon_weight: i32 = t.next().unwrap().parse().expect("weight");
    assert!(
        (0..5000).contains(&daemon_weight),
        "weight: {daemon_weight}"
    );
    // Options hex: `myself_options_default()` = `0x0700000c` (PMTU
    // + CLAMP + PROT_MINOR=7 in top byte). The `& 0xffffff` mask
    // doesn't change it (low 24 bits already include PMTU+CLAMP);
    // the `| PROT_MINOR<<24` re-adds the top byte. Same value.
    let daemon_opts = u32::from_str_radix(t.next().unwrap(), 16).expect("opts hex");
    assert_eq!(daemon_opts, 0x0700_000c, "options: {body:?}");

    // ─── send OUR ACK ─────────────────────────────────────────────
    // INITIATOR side: `if(allow == ACK) send_ack(c)`.
    // The initiator's HandshakeDone fires the SAME arm. We model
    // that here. Port 0 (we have no UDP listener); weight 1ms
    // (fake); same default options. The `\n` is required (`meta.c:
    // 156` strips it; daemon's `record_body`).
    fx.send_record(b"4 0 1 700000c\n");
    // `send_add_edge(everyone, c->edge)`: a real peer's `on_ack`
    // broadcasts ITS edge (testpeer→testnode). The daemon's SSSP
    // only follows edges with `e->reverse` set; without this
    // gossip, the daemon's testnode→
    // testpeer edge has no twin and `BecameReachable` never fires.
    // (chunk-9b removed the synthesized reverse from `on_ack` —
    // it broke 3-node relay forwarding. Tests that drive the
    // daemon manually now must send what a real peer sends.)
    fx.send_record(b"12 deadbeef testpeer testnode 127.0.0.1 655 700000c 1\n");

    // ─── daemon activates: send_everything + send_add_edge ─────
    // Log: "Connection with X (Y) activated". Then
    // `send_everything(c)` walks the world model. With zero
    // subnets and ONE edge (testnode→testpeer, just added with an
    // addr entry), we get 1 ADD_EDGE record. Then `:1058 send_add_
    // edge(everyone, c->edge)` broadcasts the same edge — we ARE
    // the only active conn, so we get a SECOND ADD_EDGE for the
    // same edge with a DIFFERENT nonce. Both pass `seen.check`;
    // the second hits `lookup_edge`-exists-same-weight → idempotent.
    //
    // The synthesized reverse (testpeer→testnode) has NO `edge_
    // addrs` entry (chunk-5 STUB), so `fmt_add_edge` skips it.
    //
    // Receive both records. Parse the first; assert it's `ADD_EDGE
    // testnode testpeer`. Then drain until WouldBlock — proves the
    // skip-from logic for `forward_request` (we ARE `from` for any
    // ADD_SUBNET we send below; broadcast skips us).
    let post_ack_records = fx.drain_records(500);
    // At least 1 ADD_EDGE (send_everything). Possibly 2 (the
    // `send_add_edge(everyone)` broadcast).
    assert!(
        !post_ack_records.is_empty(),
        "expected ADD_EDGE from send_everything"
    );
    // Parse first: `"12 <nonce> testnode testpeer 127.0.0.1 <port> <opts> <weight>"`.
    let first = std::str::from_utf8(&post_ack_records[0])
        .unwrap()
        .trim_end();
    let mut t = first.split_whitespace();
    assert_eq!(t.next(), Some("12"), "ADD_EDGE reqno: {first:?}");
    let _nonce = t.next().unwrap();
    assert_eq!(t.next(), Some("testnode"), "from: {first:?}");
    assert_eq!(t.next(), Some("testpeer"), "to: {first:?}");
    assert_eq!(t.next(), Some("127.0.0.1"), "addr: {first:?}");
    // port: his_udp_port from our ACK = 0. options + weight follow.
    assert_eq!(t.next(), Some("0"), "port (his_udp_port=0): {first:?}");
    // All records are ADD_EDGE for testnode→testpeer (the only
    // edge with an addr entry).
    for rec in &post_ack_records {
        let s = std::str::from_utf8(rec).unwrap();
        assert!(
            s.starts_with("12 ") && s.contains(" testnode testpeer "),
            "unexpected post-ACK record: {s:?}"
        );
    }
    // Short timeout for subsequent no-reply checks. The drain
    // above already set 500ms; tighten to 100ms so the WouldBlock
    // assertions below are fast.
    fx.stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    // Destructure: the rest of the test does raw stream reads (the
    // "no reply" WouldBlock checks). Can't use fx.send_record for
    // those without re-borrowing fx every time; pull out the parts.
    let PeerFixture {
        mut child,
        stream,
        mut sptps,
        ..
    } = fx;

    // ─── dump connections over control socket ────────────────────
    // Walk connection_list, format `"%d %d %s %s %x %d %x"` per
    // row, then terminator `"%d %d"`. With
    // ONE peer + ONE control conn (us), we get 2 rows.
    //
    // The peer row's name is `testpeer`, hostname is `127.0.0.1
    // port <some-port>` (the FUSED string — see dump.rs's `" port "`
    // literal note). options is the OR'd value (PMTU intersection
    // applied: both sides had it, so it sticks).
    let cookie = read_cookie(&pidfile);
    let ctl = UnixStream::connect(&socket).expect("control connect");
    let mut ctl_r = BufReader::new(&ctl);
    let mut ctl_w = &ctl;
    writeln!(ctl_w, "0 ^{cookie} 0").unwrap();
    let mut greet = String::new();
    ctl_r.read_line(&mut greet).unwrap();
    assert_eq!(greet, "0 testnode 17.7\n");
    let mut ack = String::new();
    ctl_r.read_line(&mut ack).unwrap(); // "4 0 <pid>"

    // REQ_DUMP_CONNECTIONS = 6.
    writeln!(ctl_w, "18 6").unwrap();
    let mut rows = Vec::new();
    loop {
        let mut line = String::new();
        ctl_r.read_line(&mut line).expect("dump row");
        let line = line.trim_end().to_owned();
        // Terminator: `"18 6"` (no body). Row: `"18 6 <body>"`.
        if line == "18 6" {
            break;
        }
        rows.push(line);
    }
    // 2 conns: testpeer (TCP) + <control> (this unix socket).
    // Order is slotmap-iteration (insertion order). Don't pin order;
    // find the testpeer row.
    assert_eq!(rows.len(), 2, "dump rows: {rows:?}");
    let peer_row = rows
        .iter()
        .find(|r| r.contains("testpeer"))
        .unwrap_or_else(|| panic!("no testpeer row in: {rows:?}"));
    // `"18 6 testpeer 127.0.0.1 port <p> <opts-hex> <fd> <status>"`.
    // The hostname is FUSED (one %s in the daemon, two %s + lit on
    // CLI parse). We just substring-check for now; `tinc-tools::
    // dump::ConnRow::parse` is the real parser.
    assert!(
        peer_row.starts_with("18 6 testpeer 127.0.0.1 port "),
        "peer row: {peer_row}"
    );
    // options: after PMTU intersection + OR (`ack_h:996-1001`).
    // Both sides sent `0x0700000c`; intersection keeps PMTU; OR is
    // idempotent. `c->options` = `0x0700000c`. Hex unpadded.
    assert!(peer_row.contains(" 700000c "), "peer row: {peer_row}");

    // ─── chunk 5: ADD_SUBNET / dump subnets / dedup / DEL ──────
    // `add_subnet_h`. Send an ADD_SUBNET via SPTPS record, daemon
    // parses + inserts into
    // SubnetTree, `dump subnets` over the control socket shows it.
    //
    // Record body format: `"10 <nonce-hex> <owner> <netstr>\n"`
    // (`"%d %x %s %s"`). The `\n` is appended by `send_request`;
    // daemon's `record_body` strips it.
    //
    // `192.168.99.0/24#10`: weight 10 is the default —
    // `Subnet::Display` omits `#10`, so the dump row reads
    // `192.168.99.0/24`. Match the dump format, not the wire.
    let add_subnet = b"10 deadbeef testpeer 192.168.99.0/24#10\n";
    for o in sptps.send_record(0, add_subnet).expect("post-handshake") {
        if let Output::Wire { bytes, .. } = o {
            (&stream).write_all(&bytes).expect("send ADD_SUBNET");
        }
    }

    // Daemon doesn't reply to ADD_SUBNET. `forward_request` skips
    // `from` (us) and there are no OTHER active conns. The skip-
    // from logic is the loop break; this WouldBlock proves it.
    match (&stream).read(&mut tmp_buf) {
        Ok(0) => {
            let _ = child.kill();
            let out = child.wait_with_output().unwrap();
            panic!(
                "daemon closed after ADD_SUBNET; stderr:\n{}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        Ok(n) => panic!("daemon replied {n} bytes to ADD_SUBNET (should forward, not reply)"),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(e) => panic!("read error after ADD_SUBNET: {e}"),
    }

    // `dump subnets`. REQ_DUMP_SUBNETS = 5. Format: `"18 5
    // <netstr> <owner>"` per row, terminator `"18 5"`. With one
    // subnet: one row.
    //
    // Helper closure: send REQ_DUMP_SUBNETS, collect rows. Called
    // three times below (after ADD, after dup-ADD, after DEL).
    let dump_subnets = |ctl_r: &mut BufReader<&UnixStream>, ctl_w: &mut &UnixStream| {
        writeln!(ctl_w, "18 5").unwrap();
        let mut rows = Vec::new();
        loop {
            let mut line = String::new();
            ctl_r.read_line(&mut line).expect("dump subnet row");
            let line = line.trim_end().to_owned();
            if line == "18 5" {
                break;
            }
            rows.push(line);
        }
        rows
    };

    let rows = dump_subnets(&mut ctl_r, &mut ctl_w);
    assert_eq!(rows.len(), 1, "dump subnets after ADD: {rows:?}");
    // `netstr owner`. `net2str` omits `#10` (default weight).
    // `Subnet::Display` matches.
    assert_eq!(
        rows[0], "18 5 192.168.99.0/24 testpeer",
        "subnet row: {rows:?}"
    );

    // Send the SAME ADD_SUBNET again. `seen.check` dup-drops it.
    // The full body string (incl nonce)
    // is the cache key — same nonce → same key → hit.
    for o in sptps.send_record(0, add_subnet).expect("dup send") {
        if let Output::Wire { bytes, .. } = o {
            (&stream).write_all(&bytes).expect("send dup ADD_SUBNET");
        }
    }
    // No reply (dup-dropped silently).
    match (&stream).read(&mut tmp_buf) {
        Ok(0) => panic!("daemon closed after dup ADD_SUBNET"),
        Ok(n) => panic!("daemon replied {n} bytes to dup ADD_SUBNET"),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(e) => panic!("read error after dup: {e}"),
    }
    // Still ONE row — dedup proved.
    let rows = dump_subnets(&mut ctl_r, &mut ctl_w);
    assert_eq!(rows.len(), 1, "dump after dup ADD (seen.check): {rows:?}");

    // DEL_SUBNET. Same wire shape,
    // reqno 11. DIFFERENT nonce (the dup ADD_SUBNET above already
    // primed `seen` with `deadbeef` — but on a different reqno
    // string, so it wouldn't collide. Distinct nonce anyway for
    // realism: each flood is fresh `prng()` output).
    let del_subnet = b"11 cafef00d testpeer 192.168.99.0/24#10\n";
    for o in sptps.send_record(0, del_subnet).expect("del send") {
        if let Output::Wire { bytes, .. } = o {
            (&stream).write_all(&bytes).expect("send DEL_SUBNET");
        }
    }
    match (&stream).read(&mut tmp_buf) {
        Ok(0) => {
            let _ = child.kill();
            let out = child.wait_with_output().unwrap();
            panic!(
                "daemon closed after DEL_SUBNET; stderr:\n{}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        Ok(n) => panic!("daemon replied {n} bytes to DEL_SUBNET"),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(e) => panic!("read error after DEL: {e}"),
    }
    // Zero rows — deleted.
    let rows = dump_subnets(&mut ctl_r, &mut ctl_w);
    assert_eq!(rows.len(), 0, "dump after DEL_SUBNET: {rows:?}");

    // ─── stderr: prove the daemon's path ─────────────────────────
    // Hold `stream` until here — dropping it would let the daemon's
    // ping-timeout sweep close the conn before we dump.
    drop(stream);
    let _ = child.kill();
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("SPTPS handshake completed with testpeer"),
        "stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("Connection with testpeer") && stderr.contains("activated"),
        "daemon didn't log activation; stderr:\n{stderr}"
    );
    // The chunk-4a placeholder warning is GONE.
    assert!(
        !stderr.contains("send_ack not implemented"),
        "chunk-4a placeholder leaked; stderr:\n{stderr}"
    );
    // Chunk 5: `on_ack` → `graph.add_edge` → `run_graph` → `BecameReachable`.
    // `"Node %s became reachable"`. Our log says `"Node testpeer
    // became reachable"`. THIS is the proof that
    // graph_glue::run_graph fired and the diff produced a transition.
    assert!(
        stderr.contains("Node testpeer became reachable"),
        "on_ack graph bridge didn't fire BecameReachable; stderr:\n{stderr}"
    );
}

/// `ADD_EDGE` for a transitive node triggers `BecameReachable` for
/// that node. Proves `on_add_edge` → `graph.add_edge` → `run_graph`
/// → `Transition::BecameReachable` → log.
///
/// Same setup as `peer_ack_exchange` (handshake + ACK), then send
/// `ADD_EDGE testpeer faraway` plus the reverse `faraway testpeer`.
/// `sssp` only follows bidi edges (`if(!e->reverse) continue`);
/// both directions are needed for the transition to
/// fire. The C peer would send both (each side's `ack_h` adds its
/// `c->edge`, then broadcasts).
///
/// `dump connections` STILL shows one row (testpeer): faraway has
/// no direct connection — graph-only.
//
// helper for peer_edge_triggers_reachable: dump-nodes phase.
//
// Walks the graph (NOT `nodes`/`conns`). After ACK + bidi ADD_EDGE:
// testnode (myself), testpeer (direct), faraway (transitive). All
// reachable (status bit 4 set; `node.h:38` field 4, GCC LSB-first
// → 0x10).
//
// REQ_DUMP_NODES = 3. Format: `"18 3 <name> <id> <host> port <port>
// <cipher> <digest> <maclen> <comp> <opts:x> <stat:x> <nexthop> <via>
// <dist> <mtu> <minmtu> <maxmtu> <ts> <rtt> <in_p> <in_b> <out_p>
// <out_b>"`. CLI parser: `tinc-tools::cmd::dump::NodeRow::parse`.
fn assert_dump_nodes_reachable(ctl_r: &mut BufReader<&UnixStream>, mut ctl_w: &UnixStream) {
    writeln!(ctl_w, "18 3").unwrap();
    let mut node_rows = Vec::new();
    loop {
        let mut line = String::new();
        ctl_r.read_line(&mut line).expect("dump node row");
        let line = line.trim_end().to_owned();
        if line == "18 3" {
            break;
        }
        node_rows.push(line);
    }
    assert_eq!(node_rows.len(), 3, "dump nodes: {node_rows:?}");

    // Find each node's row. Body starts after `"18 3 "`; first
    // token is the name. Don't pin slot order (graph slot order
    // = insertion order, but be robust).
    let find_row = |name: &str| -> &str {
        node_rows
            .iter()
            .find(|r| {
                r.strip_prefix("18 3 ")
                    .and_then(|b| b.split(' ').next())
                    .is_some_and(|n| n == name)
            })
            .unwrap_or_else(|| panic!("no {name} row in: {node_rows:?}"))
    };
    let myself_row = find_row("testnode");
    let peer_row = find_row("testpeer");
    let far_row = find_row("faraway");

    // status field is the 11th body field (`%x`), right after
    // options (`%x`). Bit 4 = reachable = 0x10. Chunk-7 also sets
    // bit 6 (`sptps`) for nodes that became reachable (`graph.c:
    // 192-195` reads `e->options >> 24 >= 2` from the prevedge;
    // we set it unconditionally in `BecameReachable` since the
    // Rust port is SPTPS-only).
    //
    // myself: never transitions BecameReachable (set reachable at
    // setup) → status = 0x10 (reachable only).
    // testpeer/faraway: 0x50 = reachable | sptps.
    //
    // Parse the status hex from the row (token at index 10 of the
    // body) and check bit 4.
    let parse_status = |row: &str| -> u32 {
        row.strip_prefix("18 3 ")
            .and_then(|b| b.split_whitespace().nth(10))
            .and_then(|s| u32::from_str_radix(s, 16).ok())
            .unwrap_or_else(|| panic!("can't parse status from row: {row}"))
    };
    for (name, row) in [
        ("testnode", myself_row),
        ("testpeer", peer_row),
        ("faraway", far_row),
    ] {
        let status = parse_status(row);
        assert!(
            status & 0x10 != 0,
            "{name} not reachable (status={status:x}); row: {row}"
        );
    }
    // testpeer/faraway: sptps bit set (chunk-7's BecameReachable).
    assert!(
        parse_status(peer_row) & 0x40 != 0,
        "testpeer sptps bit; row: {peer_row}"
    );
    assert!(
        parse_status(far_row) & 0x40 != 0,
        "faraway sptps bit; row: {far_row}"
    );

    // myself: hostname is `"MYSELF port <udp>"` (`net_setup.c:
    // `). nexthop/via are itself (sssp seeds `myself` with
    // `nexthop=myself, via=myself`).
    // distance=0.
    assert!(
        myself_row.contains(" MYSELF port "),
        "myself hostname; row: {myself_row}"
    );
    assert!(
        myself_row.contains(" testnode testnode 0 "),
        "myself nexthop/via/dist; row: {myself_row}"
    );

    // testpeer: directly connected. hostname is the rewritten
    // `c->address` with `his_udp_port=0` (we sent `"4 0 1 ..."`
    // — first field is hisport=0). nexthop=testpeer, via=
    // testpeer, distance=1 (one hop).
    assert!(
        peer_row.contains(" 127.0.0.1 port 0 "),
        "testpeer hostname (edge_addr, port=his_udp_port=0); row: {peer_row}"
    );
    assert!(
        peer_row.contains(" testpeer testpeer 1 "),
        "testpeer nexthop/via/dist; row: {peer_row}"
    );

    // faraway: transitive (no NodeState). hostname is the
    // prevedge address seeded by `BecameReachable`. The
    // ADD_EDGE wire body said `testpeer faraway 10.99.0.2
    // 655` — that's faraway's addr as seen by testpeer.
    // Regression: was `"unknown port unknown"` (udp_addr never
    // seeded for transitives → choose_udp_address returned
    // None → direct UDP probes silently dropped).
    // nexthop=testpeer (first hop), via=faraway (direct — no
    // INDIRECT option set), distance=2.
    assert!(
        far_row.contains(" 10.99.0.2 port 655 "),
        "faraway hostname (prevedge-seeded udp_addr); row: {far_row}"
    );
    assert!(
        far_row.contains(" testpeer faraway 2 "),
        "faraway nexthop/via/dist; row: {far_row}"
    );
    // udp_ping_rtt = -1 (init value), traffic counters = 0.
    assert!(
        far_row.ends_with(" -1 0 0 0 0"),
        "faraway tail (rtt=-1, counters=0); row: {far_row}"
    );
}

// helper for peer_edge_triggers_reachable: dump-edges phase.
//
// Nested per-node walk. After ACK + the two ADD_EDGE bodies:
// testnode↔testpeer (from `on_ack`, both halves) + testpeer↔faraway
// (from the wire, both halves).
//
// REQ_DUMP_EDGES = 4. Format: `"18 4 <from> <to> <addr> port <p>
// <local> port <lp> <opts:x> <weight>"`. CLI: `EdgeRow::parse`
// (8 fields, two `" port "` re-splits).
fn assert_dump_edges_four(ctl_r: &mut BufReader<&UnixStream>, mut ctl_w: &UnixStream) {
    writeln!(ctl_w, "18 4").unwrap();
    let mut edge_rows = Vec::new();
    loop {
        let mut line = String::new();
        ctl_r.read_line(&mut line).expect("dump edge row");
        let line = line.trim_end().to_owned();
        if line == "18 4" {
            break;
        }
        edge_rows.push(line);
    }
    // 4 directed edges. Order: per-node (slot order), then per-
    // edge (sorted by to-name). Don't pin global order.
    assert_eq!(edge_rows.len(), 4, "dump edges: {edge_rows:?}");

    // testnode→testpeer: `on_ack` populated `edge_addrs` from
    // `conn.address` (127.0.0.1) + `his_udp_port` (0). Local addr
    // is the `getsockname` result with port rewritten to `myport.
    // udp` (`ack_h:1040-1045`). The TCP socket's local addr is
    // `127.0.0.1` (we connected to a 127.0.0.1 listener); the
    // port is the daemon's UDP port (kernel-assigned, varies).
    let fwd = edge_rows
        .iter()
        .find(|r| r.starts_with("18 4 testnode testpeer "))
        .unwrap_or_else(|| panic!("no testnode→testpeer: {edge_rows:?}"));
    assert!(
        fwd.contains(" 127.0.0.1 port 0 127.0.0.1 port "),
        "forward edge addr (remote=conn.address+hisport, local=getsockname+myudp); row: {fwd}"
    );

    // testpeer→testnode: synthesized reverse from `on_ack`.
    // chunk-5 left this with NO `edge_addrs` entry (rendered
    // as `"unknown port unknown"`). chunk-9b fixed the
    // idempotence check in `on_add_edge`: the test's `our_edge`
    // ADD_EDGE (line ~154) now falls through to update (was
    // early-returning on weight+options match without checking
    // address) and populates `edge_addrs` with the wire body's
    // `127.0.0.1` `655`. The `three_daemon_relay` test depends
    // on this fall-through for hub-spoke topology.
    let rev = edge_rows
        .iter()
        .find(|r| r.starts_with("18 4 testpeer testnode "))
        .unwrap_or_else(|| panic!("no testpeer→testnode: {edge_rows:?}"));
    assert!(
        rev.contains(" 127.0.0.1 port 655 "),
        "reverse edge addr should be populated by ADD_EDGE; row: {rev}"
    );

    // testpeer→faraway: from the ADD_EDGE wire body. Addr tokens
    // round-tripped verbatim (`10.99.0.2` `655` from the `fwd`
    // body above). 6-token form (no local-addr suffix) → local
    // is `"unspec port unspec"` (`AF_UNSPEC` case of
    // `sockaddr2hostname`). options=0, weight=50.
    let tf = edge_rows
        .iter()
        .find(|r| r.starts_with("18 4 testpeer faraway "))
        .unwrap_or_else(|| panic!("no testpeer→faraway: {edge_rows:?}"));
    assert_eq!(
        tf, "18 4 testpeer faraway 10.99.0.2 port 655 unspec port unspec 0 50",
        "transitive edge: AddrStr round-trip from ADD_EDGE wire body"
    );

    // faraway→testpeer: same shape, addr from the `rev` body.
    let ft = edge_rows
        .iter()
        .find(|r| r.starts_with("18 4 faraway testpeer "))
        .unwrap_or_else(|| panic!("no faraway→testpeer: {edge_rows:?}"));
    assert_eq!(
        ft, "18 4 faraway testpeer 10.99.0.1 port 655 unspec port unspec 0 50",
        "transitive reverse: AddrStr round-trip"
    );
}

#[test]
fn peer_edge_triggers_reachable() {
    let mut fx = PeerFixture::spawn("peer-edge");
    let pidfile = fx.pidfile.clone();
    let socket = fx.socket.clone();

    // Send our ACK. Daemon activates + adds myself→testpeer edge
    // + runs graph. Then our ADD_EDGE (testpeer→testnode) gives
    // the daemon's edge its reverse; THAT graph() fires
    // BecameReachable. (Real peers' on_ack sends both in one
    // burst; chunk-9b removed the daemon's synthesized reverse.)
    fx.send_record(b"4 0 1 700000c\n");
    fx.send_record(b"12 deadbeef testpeer testnode 127.0.0.1 655 700000c 1\n");

    // Chunk 6: daemon's `on_ack` now calls `send_everything` +
    // `send_add_edge(everyone)`. We get 1-2 ADD_EDGE records for
    // testnode→testpeer. Drain them.
    let post_ack = fx.drain_records(500);
    // 1-2 ADD_EDGE records for testnode→testpeer.
    assert!(
        !post_ack.is_empty(),
        "expected ADD_EDGE from send_everything"
    );
    for rec in &post_ack {
        let s = std::str::from_utf8(rec).unwrap();
        assert!(
            s.starts_with("12 ") && s.contains(" testnode testpeer "),
            "unexpected post-ACK record: {s:?}"
        );
    }

    // ─── ADD_EDGE: testpeer → faraway, both directions ───────────
    // `"%d %x %s %s %s %s %x %d"`.
    // `12 <nonce> <from> <to> <addr> <port> <opts> <weight>`.
    // No local-addr suffix (6-token form, pre-1.0.24 compat).
    //
    // `sssp` follows edges only if `e->reverse` is set (`graph.c:
    // 159`). `Graph::add_edge` auto-links the reverse if it exists.
    // So: send BOTH directions. The C peer would do the same (each
    // side's `ack_h` adds its `c->edge` and broadcasts; testpeer
    // sends `testpeer→faraway`, faraway sends `faraway→testpeer`).
    //
    // Different nonces — each is a separate `prng()` in C.
    // Addresses are arbitrary tokens (Phase-1 finding: `AddrStr`
    // is opaque, `str2sockaddr` accepts anything).
    fx.send_record(b"12 11111111 testpeer faraway 10.99.0.2 655 0 50\n");
    fx.send_record(b"12 22222222 faraway testpeer 10.99.0.1 655 0 50\n");

    // Daemon's `forward_request` skips `from` (us). No other active
    // conns. Drain: should be empty (proves the from-skip).
    let after_edge = fx.drain_records(100);
    assert!(
        after_edge.is_empty(),
        "forward_request should skip from-conn; got: {after_edge:?}"
    );

    // ─── dump connections: STILL one peer row ───────────────────
    // faraway is graph-only (no NodeState, no Connection).
    // `dump_connections` walks `conns`, not `node_ids`.
    let cookie = read_cookie(&pidfile);
    let ctl = UnixStream::connect(&socket).expect("ctl connect");
    let mut ctl_r = BufReader::new(&ctl);
    let mut ctl_w = &ctl;
    writeln!(ctl_w, "0 ^{cookie} 0").unwrap();
    let mut greet = String::new();
    ctl_r.read_line(&mut greet).unwrap();
    let mut ack = String::new();
    ctl_r.read_line(&mut ack).unwrap();

    writeln!(ctl_w, "18 6").unwrap();
    let mut rows = Vec::new();
    loop {
        let mut line = String::new();
        ctl_r.read_line(&mut line).expect("dump row");
        let line = line.trim_end().to_owned();
        if line == "18 6" {
            break;
        }
        rows.push(line);
    }
    // testpeer + <control>. NOT faraway.
    assert_eq!(rows.len(), 2, "dump connections: {rows:?}");
    assert!(
        rows.iter().any(|r| r.contains("testpeer")),
        "no testpeer: {rows:?}"
    );
    assert!(
        !rows.iter().any(|r| r.contains("faraway")),
        "faraway shouldn't have a connection: {rows:?}"
    );

    // ─── dump nodes: 3 rows, all reachable ─────────────────────
    assert_dump_nodes_reachable(&mut ctl_r, ctl_w);

    // ─── dump edges: 4 rows (2 bidi pairs) ─────────────────────
    assert_dump_edges_four(&mut ctl_r, ctl_w);

    // ─── update_edge: same edge, different weight ────────────
    // In-place update path. Send the
    // SAME `testpeer→faraway` edge with weight 99 (was 50). Same
    // addr tokens — the addr in the dump row must stay identical
    // (proves `edge_addrs` key stability: `update_edge` keeps the
    // EdgeId slot, the HashMap entry was overwritten in place).
    //
    // Different nonce: `seen_request` would dedup an exact resend.
    fx.send_record(b"12 33333333 testpeer faraway 10.99.0.2 655 0 99\n");
    // No reply: forward_request skips us. Drain empty.
    let after_upd = fx.drain_records(100);
    assert!(
        after_upd.is_empty(),
        "forward_request should skip from-conn; got: {after_upd:?}"
    );

    // dump edges again: still 4 rows, testpeer→faraway has weight
    // 99, addr UNCHANGED.
    writeln!(ctl_w, "18 4").unwrap();
    let mut edge_rows2 = Vec::new();
    loop {
        let mut line = String::new();
        ctl_r.read_line(&mut line).expect("dump edge row 2");
        let line = line.trim_end().to_owned();
        if line == "18 4" {
            break;
        }
        edge_rows2.push(line);
    }
    assert_eq!(
        edge_rows2.len(),
        4,
        "dump edges post-update: {edge_rows2:?}"
    );
    let tf2 = edge_rows2
        .iter()
        .find(|r| r.starts_with("18 4 testpeer faraway "))
        .unwrap_or_else(|| panic!("no testpeer→faraway post-update: {edge_rows2:?}"));
    // (a) new weight; (b) addr identical to first dump. The addr
    // column proves `edge_addrs[existing]` was overwritten, not
    // re-keyed: del+add with a slot drift would lose the entry
    // and dump would show `"unknown port unknown"`.
    assert_eq!(
        tf2, "18 4 testpeer faraway 10.99.0.2 port 655 unspec port unspec 0 99",
        "update_edge: weight changed, addr preserved (EdgeId stable)"
    );

    // ─── stderr: BecameReachable fired for faraway ──────────────
    let stderr = fx.kill_and_stderr();
    // The on_ack graph bridge fires testpeer-reachable first.
    assert!(
        stderr.contains("Node testpeer became reachable"),
        "on_ack reachable; stderr:\n{stderr}"
    );
    // THE PROOF: on_add_edge → run_graph → BecameReachable for the
    // TRANSITIVE node. `"Node %s became reachable"`.
    assert!(
        stderr.contains("Node faraway became reachable"),
        "on_add_edge didn't fire BecameReachable for transitive node; \
         stderr:\n{stderr}"
    );
}

/// Wrong key: the daemon has a DIFFERENT pubkey on file for us.
/// SIG verify fails → daemon drops the connection. Proves the
/// SPTPS auth actually authenticates (it's not just key exchange).
///
/// Same setup as `peer_handshake_reaches_done` but we register a
/// FAKE pubkey for ourselves in `hosts/testpeer`. The daemon's
/// SPTPS `receive_sig` step computes the transcript with that fake
/// pubkey, our SIG was made with the real one → `BadSig`.
#[test]
fn peer_wrong_key_fails_sig() {
    use rand_core::OsRng;
    use std::io::Read;
    use std::net::TcpStream;
    use tinc_crypto::sign::SigningKey;
    use tinc_sptps::{Framing, Output, Role, Sptps};

    let tmp = tmp("peer-wrong-key");
    let confbase = tmp.path().join("vpn");
    let pidfile = tmp.path().join("tinc.pid");
    let socket = tmp.path().join("tinc.socket");

    let daemon_pub = write_config(&confbase);
    // OUR real key (we sign with this).
    let our_key = SigningKey::from_seed(&[0x77; 32]);
    // FAKE pubkey we register at the daemon. Daemon will try to
    // verify our SIG with THIS → fail.
    let fake_pub = *SigningKey::from_seed(&[0x88; 32]).public_key();
    let b64 = tinc_crypto::b64::encode(&fake_pub);
    std::fs::write(
        confbase.join("hosts").join("testpeer"),
        format!("Ed25519PublicKey = {b64}\n"),
    )
    .unwrap();

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
        .unwrap();

    assert!(wait_for_file(&socket));
    let tcp_addr = read_tcp_addr(&pidfile);

    let stream = TcpStream::connect(tcp_addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    writeln!(&stream, "0 testpeer 17.7").unwrap();

    // Read past ID line, find KEX bytes.
    let mut buf = Vec::with_capacity(256);
    let mut tmp_buf = [0u8; 256];
    let id_end = loop {
        let n = (&stream).read(&mut tmp_buf).unwrap();
        assert_ne!(n, 0, "daemon closed early");
        buf.extend_from_slice(&tmp_buf[..n]);
        if let Some(pos) = buf.iter().position(|&b| b == b'\n') {
            break pos;
        }
    };

    let mut label = b"tinc TCP key expansion testpeer testnode".to_vec();
    label.push(0);
    let (mut sptps, init) = Sptps::start(
        Role::Initiator,
        Framing::Stream,
        our_key,
        daemon_pub,
        label,
        0,
        &mut OsRng,
    );
    for o in init {
        if let Output::Wire { bytes, .. } = o {
            (&stream).write_all(&bytes).unwrap();
        }
    }

    // Feed daemon's KEX, send our SIG. The daemon's SIG verify
    // FAILS (wrong pubkey). Daemon terminates the connection.
    // We see EOF (or possibly OUR receive fails first if the
    // daemon's SIG also doesn't verify on our side — we have the
    // RIGHT daemon_pub so OUR side should be fine; the failure is
    // unidirectional).
    let mut pending: Vec<u8> = buf[id_end + 1..].to_vec();
    let deadline = Instant::now() + Duration::from_secs(5);
    let saw_eof = loop {
        if Instant::now() > deadline {
            break false;
        }
        let mut off = 0;
        while off < pending.len() {
            // OUR receive might also fail — the daemon's SIG was
            // made with the daemon's real private key, and we have
            // the matching daemon_pub, so OUR receive should
            // succeed. The failure is on the DAEMON's side.
            // But if it does fail: that's also a stop condition
            // (and the stderr check below disambiguates).
            match sptps.receive(&pending[off..], &mut OsRng) {
                #[allow(clippy::match_same_arms)] // Ok(0)/Err: same break, different why
                Ok((0, _)) => break,
                Ok((n, outs)) => {
                    off += n;
                    for o in outs {
                        if let Output::Wire { bytes, .. } = o {
                            // Might fail if daemon already RST'd
                            // — ignore. The point is to send our
                            // SIG so the daemon's verify fires.
                            let _ = (&stream).write_all(&bytes);
                        }
                    }
                }
                Err(_) => break,
            }
        }
        pending.clear();

        // Read more (or detect EOF).
        match (&stream).read(&mut tmp_buf) {
            Ok(0) => break true, // EOF — daemon dropped us. EXPECTED.
            Ok(n) => pending.extend_from_slice(&tmp_buf[..n]),
            Err(_) => break false,
        }
    };

    // ─── the daemon's stderr says BadSig ─────────────────────────
    let _ = child.kill();
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);

    // Either saw_eof (daemon closed) OR the test loop timed out
    // (less likely). Either way: stderr is the proof.
    assert!(
        saw_eof,
        "expected daemon to close connection on bad SIG; stderr:\n{stderr}"
    );
    // The exact error variant from `feed_sptps`'s log line.
    // `SptpsError::BadSig` debug-formatted.
    assert!(
        stderr.contains("BadSig"),
        "expected BadSig in daemon stderr; stderr:\n{stderr}"
    );
    // And NOT the success line.
    assert!(
        !stderr.contains("SPTPS handshake completed"),
        "daemon should NOT have completed; stderr:\n{stderr}"
    );
}

/// `REQ_PCAP` arm + `send_pcap` end-to-end. Proves the wire format
/// the CLI's `tinc pcap` decoder reads (`stream.rs::pcap_loop`).
///
/// Format-is-contract: the CLI does `recv_line()` (reads to `\n`)
/// then `recv_data(LEN)` (reads exactly LEN bytes). Packet body MAY
/// contain `\n` — the length prefix makes that safe. We deliberately
/// inject a frame with `0x0a` mid-body to prove this.
///
/// `Mode = switch`: no subnet/ARP/reachability dance — unknown dst
/// MAC → `route_mac` returns `Broadcast` → packet visits `route_
/// packet` → `send_pcap` fires. The broadcast itself goes nowhere
/// (no other peers); we only care that the tap saw it.
///
/// `PACKET 17` injection (not UDP) because the test has no UDP
/// listener. Direct neighbors short-circuit to TCP; the tcplen path (`metaconn.rs` Record arm) calls `route_packet`
/// directly with the frame body.
#[test]
#[allow(clippy::similar_names)] // ctl/ctl2 distinguish first/second control conns
fn pcap_captures_tcp_packet() {
    use std::io::Read;

    // ─── config: Mode=switch so route_packet_mac broadcasts ───
    // The default `write_config` is router mode; we need switch.
    let mut fx = PeerFixture::spawn_with_config("pcap", |confbase| {
        std::fs::create_dir_all(confbase.join("hosts")).unwrap();
        std::fs::write(
            confbase.join("tinc.conf"),
            "Name = testnode\nDeviceType = dummy\nAddressFamily = ipv4\nMode = switch\n",
        )
        .unwrap();
        std::fs::write(confbase.join("hosts").join("testnode"), "Port = 0\n").unwrap();
        let seed = [0x42; 32];
        write_ed25519_privkey(confbase, &seed);
        common::pubkey_from_seed(&seed)
    });
    let pidfile = fx.pidfile.clone();
    let socket = fx.socket.clone();

    // ACK + reverse edge (so on_ack completes; conn.active = true).
    fx.send_record(b"4 0 1 700000c\n");
    fx.send_record(b"12 deadbeef testpeer testnode 127.0.0.1 655 700000c 1\n");

    // Drain post-ACK ADD_EDGE gossip (don't care, just clear the pipe).
    let _ = fx.drain_records(300);

    // ─── arm pcap on the control socket ────────────────────────
    // `"18 14 0"`: REQ_PCAP, snaplen=0 (full packet). NO ack
    // (`return true` not `control_ok`). The CLI
    // (`stream.rs:540`) sends this then immediately starts reading
    // `"18 14 LEN"` lines.
    let cookie = read_cookie(&pidfile);
    let ctl = UnixStream::connect(&socket).expect("ctl connect");
    ctl.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut ctl_r = BufReader::new(&ctl);
    let mut ctl_w = &ctl;
    writeln!(ctl_w, "0 ^{cookie} 0").unwrap();
    let mut greet = String::new();
    ctl_r.read_line(&mut greet).unwrap();
    let mut ack = String::new();
    ctl_r.read_line(&mut ack).unwrap();
    writeln!(ctl_w, "18 14 0").unwrap();

    // ─── inject a frame via PACKET 17 ─────────────────────────
    // 60-byte minimal ethernet frame. dst MAC unknown → switch-mode
    // `route_mac` floods (Broadcast). `0x0a` at byte 5 of dst MAC:
    // the pcap body MAY contain `\n`; the length-prefix framing must
    // tolerate it (BufReader::read_line on the ctl socket would
    // misframe if we'd put a `\n` in the HEADER, but the body is
    // length-read).
    let frame: Vec<u8> = {
        let mut f = Vec::with_capacity(60);
        f.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x0a]); // dst (0x0a = '\n')
        f.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]); // src
        f.extend_from_slice(&0x0800u16.to_be_bytes()); // ethertype IPv4 (ignored in switch)
        f.resize(60, 0xee); // pad to min eth frame
        f
    };
    assert_eq!(frame.len(), 60);

    // `"%d %d", PACKET, len`. Then `send_meta(c, DATA(packet),
    // len)` → SPTPS record type 0 with
    // raw body. `metaconn.rs` Record arm: tcplen=60 set; NEXT record is the
    // blob. Two records: header line, then frame.
    let pkt_hdr = format!("17 {}\n", frame.len());
    fx.send_record(pkt_hdr.as_bytes());
    fx.send_record(&frame);

    // ─── read pcap header + body from ctl socket ─────────────
    // `"%d %d %d"` = `"18 14 60"`. Then `send_meta(c,
    // DATA(packet), len)` = 60 raw bytes. Control
    // conn is plaintext: `send` appends `\n`, `send_raw` doesn't.
    let mut hdr = String::new();
    match ctl_r.read_line(&mut hdr) {
        Ok(0) | Err(_) => {
            panic!(
                "ctl read failed waiting for pcap header; stderr:\n{}",
                fx.kill_and_stderr()
            );
        }
        Ok(_) => {}
    }
    assert_eq!(hdr, "18 14 60\n", "pcap header line");

    // Body: exactly 60 bytes, byte-for-byte the frame we sent.
    // BufReader::read_exact: reads from buffered + underlying.
    // The 0x0a in the body must NOT have been consumed by the
    // read_line above (it wasn't — read_line stopped at the
    // header's `\n`, body is still buffered/on the socket).
    let mut body = [0u8; 60];
    ctl_r.read_exact(&mut body).expect("read pcap body");
    assert_eq!(&body[..], &frame[..], "pcap body byte-for-byte");

    // ─── snaplen clip: re-arm with snaplen=20, send again ────
    // Second ctl conn (the first is still subscribed at snaplen=0;
    // a fresh conn is the simpler test path). `if(c->outmaclength
    // && c->outmaclength < len) len = c->
    // outmaclength`. snaplen=20 < 60 → clip to 20.
    drop(ctl_r);
    drop(ctl);
    let ctl2 = UnixStream::connect(&socket).expect("ctl2 connect");
    ctl2.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut ctl2_r = BufReader::new(&ctl2);
    let mut ctl2_w = &ctl2;
    writeln!(ctl2_w, "0 ^{cookie} 0").unwrap();
    let mut greet = String::new();
    ctl2_r.read_line(&mut greet).unwrap();
    let mut ack = String::new();
    ctl2_r.read_line(&mut ack).unwrap();
    writeln!(ctl2_w, "18 14 20").unwrap();

    // The first ctl conn was dropped → daemon's send_pcap walk on
    // the next packet finds only ctl2. (any_pcap may be re-derived
    // lazily on the first walk; the test doesn't care — it just
    // works either way.)
    fx.send_record(pkt_hdr.as_bytes());
    fx.send_record(&frame);

    let mut hdr2 = String::new();
    ctl2_r.read_line(&mut hdr2).expect("read pcap header 2");
    assert_eq!(hdr2, "18 14 20\n", "snaplen clip: header says 20");
    let mut body2 = [0u8; 20];
    ctl2_r.read_exact(&mut body2).expect("read pcap body 2");
    assert_eq!(&body2[..], &frame[..20], "snaplen clip: first 20 bytes");

    // ─── cleanup ─────────────────────────────────────────────
    let _ = fx.child.kill();
    let _ = fx.child.wait();
}
