use std::time::{Duration, Instant};

use super::common::*;
use super::node::*;

fn tmp(tag: &str) -> TmpGuard {
    TmpGuard::new("2d", tag)
}

/// Two real daemons. Alice has `ConnectTo = bob`. Full handshake →
/// ACK → both reachable. Then stop alice; bob sees the disconnect,
/// edge gone, alice unreachable.
///
/// ## What's proven (per step)
///
/// 1. **`do_outgoing_connection` + async-connect probe**: alice
///    connects to bob's port. The probe succeeds (loopback).
/// 2. **Initiator-side `id_h`**: alice's `finish_connecting` sends
///    ID first; bob's `id_h` fires (responder); bob's ID reply fires
///    alice's `id_h` (with `outgoing.is_some()` → name check + `Role::`
///    Initiator). Label arg order is swapped; both sides agree.
/// 3. **SPTPS handshake**: both reach `HandshakeDone`. The trailing-NUL
///    label is the same construction on both sides (still can't catch
///    "both wrong"; the `tcp_label_has_trailing_nul` unit test pins
///    gcc bytes).
/// 4. **ACK exchange + `on_ack`**: both add `myself→peer` edges +
///    synthesized reverses. `conn.active = true`. `dump connections`
///    shows status bit 1 set (`0x2`).
/// 5. **`send_everything` + `send_add_edge(everyone)`**: each sends
///    its forward edge. The `seen.check` dedup makes the double-send
///    (one from `send_everything`, one from broadcast) harmless.
/// 6. **`dump nodes` 2 rows, both reachable**: `run_graph_and_log`
///    fired on both sides. Status bit 4 (reachable) = `0x10`.
/// 7. **Stop alice → bob's `terminate`**: bob's `dump connections`
///    drops to 1 (control only). `dump nodes` shows alice with
///    status `0x0` (unreachable). Proves `terminate` → `del_edge`
///    → `graph()` → `BecameUnreachable`.
#[test]
fn two_daemons_connect_and_reach() {
    let tmp = tmp("connect");
    let alice = Node::new(tmp.path(), "alice", 0xAA);
    let bob = Node::new(tmp.path(), "bob", 0xBB);

    // ─── configs: alice initiates, bob accepts ──────────────────
    bob.write_config(&alice, false);
    alice.write_config(&bob, true);

    // ─── spawn bob first ────────────────────────────────────────
    // Bob has no ConnectTo; he just listens. Spawn order matters:
    // if alice starts first, her `do_outgoing_connection` tries to
    // connect before bob is bound → ECONNREFUSED → `retry_outgoing`
    // arms a 5s backoff. Would still work, but slow.
    let mut bob_child = bob.spawn();
    assert!(
        wait_for_file(&bob.socket),
        "bob setup failed; stderr:\n{}",
        drain_stderr(bob_child)
    );

    let mut alice_child = alice.spawn();
    if !wait_for_file(&alice.socket) {
        let _ = bob_child.kill();
        panic!("alice setup failed; stderr:\n{}", drain_stderr(alice_child));
    }

    // ─── poll: both have an active peer connection ──────────────
    // `dump connections` (subtype 6). Alice should have ONE peer
    // row (bob) with status bit 1 set (`active`, our `c->edge` proxy
    // — `0x2`). Same for bob. The control conn is also a row; it
    // has status `0x200` (bit 9). Filter on bit 1.
    let mut alice_ctl = alice.ctl();
    let mut bob_ctl = bob.ctl();

    poll_until(Duration::from_secs(10), || {
        let a_conns = alice_ctl.dump(6);
        let b_conns = bob_ctl.dump(6);
        if has_active_peer(&a_conns, "bob") && has_active_peer(&b_conns, "alice") {
            Some(())
        } else {
            None
        }
    });

    // ─── dump nodes: 2 rows, both reachable ─────────────────────
    // Row format: 23 fields. Status is field 11
    // (`%x`). Bit 4 = reachable = `0x10`.
    let node_reachable = |rows: &[String], name: &str| -> bool {
        rows.iter().any(|r| {
            let Some(body) = r.strip_prefix("18 3 ") else {
                return false;
            };
            let toks: Vec<&str> = body.split_whitespace().collect();
            // toks[0] = name, toks[10] = status hex (after: id,
            // host, "port", port, cipher, digest, maclen, comp,
            // opts, status). That's index 10 — wait, hostname is
            // FUSED ("HOST port PORT") = 3 tokens, so the count
            // shifts. Re-count: name(0), id(1), host(2), "port"(3),
            // port(4), cipher(5), digest(6), maclen(7), comp(8),
            // opts(9), status(10). Index 10.
            toks.first() == Some(&name)
                && toks
                    .get(10)
                    .and_then(|s| u32::from_str_radix(s, 16).ok())
                    .is_some_and(|s| s & 0x10 != 0)
        })
    };

    let a_nodes = alice_ctl.dump(3);
    let b_nodes = bob_ctl.dump(3);
    assert_eq!(a_nodes.len(), 2, "alice nodes: {a_nodes:?}");
    assert_eq!(b_nodes.len(), 2, "bob nodes: {b_nodes:?}");
    assert!(
        node_reachable(&a_nodes, "alice") && node_reachable(&a_nodes, "bob"),
        "alice's view: {a_nodes:?}"
    );
    assert!(
        node_reachable(&b_nodes, "alice") && node_reachable(&b_nodes, "bob"),
        "bob's view: {b_nodes:?}"
    );

    // ─── dump edges: both see myself→peer ───────────────────────
    // Each daemon's `on_ack` added `myself→peer` (with addr) +
    // synthesized reverse (no addr). Then `send_everything` sent
    // the forward edge to the peer. So each side has FOUR edges:
    // its own pair + the peer's forward (received via ADD_EDGE) +
    // ... wait. Let me trace.
    //
    // Alice's graph: alice→bob (on_ack fwd, has addr), bob→alice
    // (on_ack synthesized reverse, no addr). Then bob's send_
    // everything sends bob's `bob→alice` (which has bob's addr) —
    // arrives as ADD_EDGE on alice. Alice's `on_add_edge` does
    // `lookup_edge(bob, alice)` → finds the synthesized reverse →
    // weight/options compare (probably same) → idempotent return
    // (no addr update because we return early on weight+options
    // match without updating address).
    //
    // So alice's graph has 2 edges. Same for bob. Both see both
    // directions; the synthesized reverse has no `edge_addrs` entry
    // (chunk-5 STUB) so dumps as "unknown port unknown".
    //
    // Just count rows. The exact addr semantics are pinned by
    // `peer_edge_triggers_reachable` in stop.rs.
    let a_edges = alice_ctl.dump(4);
    let b_edges = bob_ctl.dump(4);
    assert_eq!(a_edges.len(), 2, "alice edges: {a_edges:?}");
    assert_eq!(b_edges.len(), 2, "bob edges: {b_edges:?}");
    // Alice has alice→bob with a real addr (127.0.0.1).
    assert!(
        a_edges
            .iter()
            .any(|r| r.starts_with("18 4 alice bob 127.0.0.1 port ")),
        "alice→bob fwd edge missing: {a_edges:?}"
    );

    // ─── stop alice → bob sees the disconnect ───────────────────
    // Alice exits. Bob's read on the meta connection gets EOF →
    // `FeedResult::Dead` → `terminate` → `del_edge` → `graph()`.
    // Bob's `dump connections` drops to 1 (control only); `dump
    // nodes` shows alice status `0x0` (unreachable).
    drop(alice_ctl); // close alice's ctl conn first
    let _ = alice_child.kill();
    let _ = alice_child.wait();

    poll_until(Duration::from_secs(10), || {
        let b_conns = bob_ctl.dump(6);
        // Only the ctl conn (us) left. No peer with name "alice".
        let has_alice = b_conns.iter().any(|r| {
            r.strip_prefix("18 6 ")
                .and_then(|b| b.split_whitespace().next())
                == Some("alice")
        });
        if has_alice { None } else { Some(()) }
    });

    // dump nodes: alice still THERE (graph keeps the node), but
    // unreachable (status bit 4 clear).
    let b_nodes_after = bob_ctl.dump(3);
    assert_eq!(b_nodes_after.len(), 2, "bob nodes after: {b_nodes_after:?}");
    assert!(
        !node_reachable(&b_nodes_after, "alice"),
        "alice should be unreachable; bob's view: {b_nodes_after:?}"
    );
    assert!(
        node_reachable(&b_nodes_after, "bob"),
        "bob (myself) should stay reachable: {b_nodes_after:?}"
    );

    // dump edges: bob's terminate did `del_edge` for `bob→alice`
    // AND the synthesized reverse `alice→bob`. Zero edges left.
    let b_edges_after = bob_ctl.dump(4);
    assert_eq!(
        b_edges_after.len(),
        0,
        "edges should be gone; bob's view: {b_edges_after:?}"
    );

    // ─── stderr: bob's reachability transitions ─────────────────
    drop(bob_ctl);
    let bob_stderr = drain_stderr(bob_child);
    assert!(
        bob_stderr.contains("Node alice became reachable"),
        "bob's on_ack → graph() → BecameReachable; stderr:\n{bob_stderr}"
    );
    assert!(
        bob_stderr.contains("Node alice became unreachable"),
        "bob's terminate → del_edge → graph() → BecameUnreachable; stderr:\n{bob_stderr}"
    );
    assert!(
        bob_stderr.contains("Connection with alice") && bob_stderr.contains("activated"),
        "bob's on_ack activation log; stderr:\n{bob_stderr}"
    );
}

/// Retry-backoff: alice's `ConnectTo = bob` but bob ISN'T running.
/// Alice's `do_outgoing_connection` gets ECONNREFUSED → addr cache
/// exhausted (only one Address) → `retry_outgoing` arms the 5s
/// backoff. Then we start bob; alice's `RetryOutgoing` timer fires →
/// `setup_outgoing_connection` → connects.
///
/// The 5s wait makes this slower than the happy-path test. Tag
/// `#[ignore]` if CI is impatient; un-ignore once confident.
#[test]
fn outgoing_retry_after_refused() {
    let tmp = tmp("retry");
    // PingTimeout=3 (not the default `write_config` PingTimeout=1):
    // alice's connect arrives mid-`turn()` on bob's side, so bob's
    // `Connection::new_meta` stamps `last_ping_time` from the
    // CACHED `timers.now()` — up to ~1s stale (the sweep ticks at
    // 1s). With PingTimeout=1 the conn is born already-stale and
    // the next sweep reaps it before `id_h` even runs. PingTimeout=1
    // is just an unrealistic config. 3s gives the handshake room.
    let alice = Node::new(tmp.path(), "alice", 0xA1).with_conf("PingTimeout = 3\n");
    let bob = Node::new(tmp.path(), "bob", 0xB1).with_conf("PingTimeout = 3\n");

    bob.write_config(&alice, false);
    alice.write_config(&bob, true);

    // ─── spawn alice FIRST. Bob isn't running. ─────────────────
    let mut alice_child = alice.spawn();
    assert!(
        wait_for_file(&alice.socket),
        "alice setup failed; stderr:\n{}",
        drain_stderr(alice_child)
    );

    // Alice tries to connect immediately in setup(). ECONNREFUSED
    // → retry_outgoing arms +5s. Prove no active conn yet.
    let mut alice_ctl = alice.ctl();
    let conns = alice_ctl.dump(6);
    // Only the ctl conn. No "bob" row.
    assert!(
        !conns.iter().any(|r| r.contains(" bob ")),
        "alice connected before bob is up?? {conns:?}"
    );

    // ─── start bob ─────────────────────────────────────────────
    let mut bob_child = bob.spawn();
    if !wait_for_file(&bob.socket) {
        let _ = alice_child.kill();
        panic!("bob setup failed; stderr:\n{}", drain_stderr(bob_child));
    }

    // ─── wait for alice's retry timer to fire (~5s) ────────────
    // `retry_outgoing` set timeout=5; the next `setup_outgoing_
    // connection` runs in ~5s + tick slop. Poll with a generous
    // timeout (15s) for slow CI.
    let has_active_peer = |rows: &[String], peer_name: &str| -> bool {
        rows.iter().any(|r| {
            let Some(body) = r.strip_prefix("18 6 ") else {
                return false;
            };
            let mut t = body.split_whitespace();
            t.next() == Some(peer_name)
                && t.last()
                    .and_then(|s| u32::from_str_radix(s, 16).ok())
                    .is_some_and(|s| s & 0x2 != 0)
        })
    };

    poll_until(Duration::from_secs(15), || {
        let a_conns = alice_ctl.dump(6);
        if has_active_peer(&a_conns, "bob") {
            Some(())
        } else {
            None
        }
    });

    // ─── stderr: prove the retry path fired ─────────────────────
    drop(alice_ctl);
    let _ = bob_child.kill();
    let _ = bob_child.wait();
    let alice_stderr = drain_stderr(alice_child);
    // "Trying to re-establish outgoing connection in N seconds".
    assert!(
        alice_stderr.contains("Trying to re-establish outgoing connection in 5 seconds"),
        "retry_outgoing log missing; stderr:\n{alice_stderr}"
    );
    // The eventual success.
    assert!(
        alice_stderr.contains("Connected to bob"),
        "finish_connecting log; stderr:\n{alice_stderr}"
    );
    assert!(
        alice_stderr.contains("Connection with bob") && alice_stderr.contains("activated"),
        "alice's on_ack activation; stderr:\n{alice_stderr}"
    );
}

/// PING/PONG keepalive. `PingInterval=1` so the sweep sends PING
/// every second; the peer's `ping_h` replies PONG; `pong_h` clears
/// the bit; the conn survives `PingTimeout`.
///
/// Then SIGSTOP one daemon. The other side's PING goes unanswered
/// (the stopped process doesn't `recv()`). After `PingTimeout`, the
/// `pinged` bit is still set → "didn't respond to PING" →
/// terminate. SIGCONT → the stopped daemon wakes, sees EOF
/// on its socket (the OTHER side closed it), terminates, and its
/// outgoing retry kicks in. `PingTimeout=3` gives the stopped
/// daemon room to NOT trigger its OWN sweep on wake (it was asleep
/// for ~5s but `last_periodic_run_time` updates on the first tick
/// post-wake — wait, no, the suspend detector triggers if the GAP
/// is >60s. SIGSTOP for 5s doesn't trigger it).
///
/// Exercises PING/PONG and the pinged-but-no-pong terminate path.
#[test]
fn ping_pong_keepalive() {
    let tmp = tmp("pingpong");
    // PingInterval=1 makes PING observable in a 5s window.
    // PingTimeout=3 gives the SIGSTOP phase room: the stopped
    // daemon is paused for ~5s, the OTHER daemon's sweep needs
    // pingtimeout (3s) to elapse after the unanswered PING.
    let alice =
        Node::new(tmp.path(), "alice", 0xA8).with_conf("PingInterval = 1\nPingTimeout = 3\n");
    let bob = Node::new(tmp.path(), "bob", 0xB8).with_conf("PingInterval = 1\nPingTimeout = 3\n");

    bob.write_config(&alice, false);
    alice.write_config(&bob, true);

    let mut bob_child = bob.spawn();
    assert!(
        wait_for_file(&bob.socket),
        "bob setup failed; stderr:\n{}",
        drain_stderr(bob_child)
    );
    let mut alice_child = alice.spawn();
    if !wait_for_file(&alice.socket) {
        let _ = bob_child.kill();
        panic!("alice setup failed; stderr:\n{}", drain_stderr(alice_child));
    }

    let mut alice_ctl = alice.ctl();
    let mut bob_ctl = bob.ctl();

    // ─── wait for ACK on both sides ─────────────────────────────
    poll_until(Duration::from_secs(10), || {
        let a = alice_ctl.dump(6);
        let b = bob_ctl.dump(6);
        (has_active_peer(&a, "bob") && has_active_peer(&b, "alice")).then_some(())
    });

    // ─── keepalive phase: hold for 5s, conn must survive ──────
    // PingInterval=1, PingTimeout=3. Five 1s ticks. Each tick
    // sends PING; the PONG arrives <100ms later (loopback); the
    // bit clears before the next sweep checks it. If PONG handling
    // is broken, the conn dies at ~tick 3.
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(500));
        let b = bob_ctl.dump(6);
        assert!(
            has_active_peer(&b, "alice"),
            "conn died during keepalive; PONG not clearing pinged bit?"
        );
    }

    // ─── SIGSTOP alice; bob's PING goes unanswered ─────────────
    // Bob sends PING, alice doesn't `recv()`, `pingtimeout` (3s)
    // elapses with `pinged` still set → "didn't respond to PING"
    // → terminate. The TCP socket stays open (kernel buffers the
    // PING bytes until alice wakes); only the application-layer
    // timeout fires.
    // SAFETY: kill() with SIGSTOP on a valid pid. The child is
    // alive (we just polled it).
    let alice_pid = alice_child.id() as libc::pid_t;
    assert_eq!(unsafe { libc::kill(alice_pid, libc::SIGSTOP) }, 0);

    // PingTimeout=3 + 2s slop. Bob's sweep needs: one tick to
    // notice idle (>pinginterval since last_ping_time) and send
    // PING, then >pingtimeout for the stale check to fire.
    poll_until(Duration::from_secs(10), || {
        let b = bob_ctl.dump(6);
        (!has_active_peer(&b, "alice")).then_some(())
    });

    // ─── SIGCONT alice; she sees EOF, retries, reconnects ──────
    // Alice wakes. Bob already closed his side; alice's next read
    // sees EOF → terminate → outgoing retry. The retry connects; the handshake runs; ACK; both active
    // again. The retry is immediate (`timeout = 0` after a conn
    // that reached ACK).
    assert_eq!(unsafe { libc::kill(alice_pid, libc::SIGCONT) }, 0);

    poll_until(Duration::from_secs(10), || {
        let b = bob_ctl.dump(6);
        has_active_peer(&b, "alice").then_some(())
    });

    let _ = alice_child.kill();
    let _ = alice_child.wait();
    let _ = bob_child.kill();
    let _ = bob_child.wait();
}

/// `tinc-up` runs at setup. Write a script that touches a marker;
/// spawn the daemon; assert the marker exists. Also covers the
/// `INTERFACE` env var: the script reads it and
/// echoes into the marker.
///
/// Shebang required: `Command::status` is direct `execve()`, not
/// `sh -c`. A shebang-less script fails `ENOEXEC`. Doc'd in
/// `script.rs` module comment.
#[test]
fn tinc_up_runs() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tmp("tincup");
    let alice = Node::new(tmp.path(), "alice", 0xA9);
    let bob = Node::new(tmp.path(), "bob", 0xB9);

    bob.write_config(&alice, false);
    alice.write_config(&bob, false);

    let marker = tmp.path().join("tinc-up-ran");
    // `#!/bin/sh` shebang. The C uses `system()` (= `sh -c`) which
    // would also work without; we don't (see script.rs doc).
    // `INTERFACE` for `DeviceType=dummy` is `"dummy"` (`tinc-
    // device::Dummy::iface`).
    let script = format!(
        "#!/bin/sh\necho \"iface=$INTERFACE name=$NAME\" > '{}'\n",
        marker.display()
    );
    let script_path = alice.confbase.join("tinc-up");
    std::fs::write(&script_path, script).unwrap();
    let mut perm = std::fs::metadata(&script_path).unwrap().permissions();
    perm.set_mode(0o755);
    std::fs::set_permissions(&script_path, perm).unwrap();

    let mut alice_child = alice.spawn();
    assert!(
        wait_for_file(&alice.socket),
        "alice setup failed; stderr:\n{}",
        drain_stderr(alice_child)
    );

    // `ControlSocket::bind` runs ~220 lines BEFORE `run_script("tinc-up")`
    // in `Daemon::setup`. `wait_for_file(socket)` proves the daemon is
    // past the bind, NOT past the script. Under parallel load the gap is
    // observable. Poll for the marker (same shape as every other
    // event-wait in this file).
    assert!(
        wait_for_file(&marker),
        "tinc-up didn't run; stderr:\n{}",
        drain_stderr(alice_child)
    );
    let got = std::fs::read_to_string(&marker).unwrap();
    assert_eq!(got.trim(), "iface=dummy name=alice");

    let _ = alice_child.kill();
    let _ = alice_child.wait();
}

/// `load_all_nodes` populates `has_address` AND adds hosts/-only
/// names to the graph. Alice has a `hosts/
/// carol` file with `Address =` but NO `ConnectTo = carol` and
/// carol never runs. After spawn, `dump nodes` shows carol as a
/// row — proves `lookup_or_add_node` ran for hosts/-file-only
/// names. Carol stays unreachable (status bit 4 clear).
///
/// `AutoConnect = no`: don't let the periodic tick try to dial
/// carol (her port is bogus, the connect would just ECONNREFUSED
/// and clutter stderr).
#[test]
fn load_all_nodes_populates_graph() {
    let tmp = tmp("loadall");
    let alice = Node::new(tmp.path(), "alice", 0xA9).with_conf("AutoConnect = no\n");
    let bob = Node::new(tmp.path(), "bob", 0xB9);

    bob.write_config(&alice, false);
    alice.write_config(&bob, false); // no ConnectTo

    // hosts/carol with Address — NO key, never spawned. Just a
    // file in alice's hosts/ dir. `load_all_nodes` should add
    // "carol" to the graph and `has_address`.
    std::fs::write(
        alice.confbase.join("hosts").join("carol"),
        "Address = 127.0.0.1 1\n",
    )
    .unwrap();

    // hosts/.swp — editor swap file, NOT a valid `check_id`.
    // `load_all_nodes` should skip it (no `.swp` row in dump).
    std::fs::write(alice.confbase.join("hosts").join(".swp"), "garbage\n").unwrap();

    let alice_child = alice.spawn();
    assert!(
        wait_for_file(&alice.socket),
        "alice setup failed: {}",
        drain_stderr(alice_child)
    );

    let mut ctl = alice.ctl();
    let nodes = ctl.dump(3); // REQ_DUMP_NODES

    // Expect 3 rows: alice (myself), bob (hosts/ file), carol
    // (hosts/ file with Address). NOT 4 (.swp filtered).
    let names: Vec<&str> = nodes
        .iter()
        .filter_map(|r| r.strip_prefix("18 3 "))
        .filter_map(|b| b.split_whitespace().next())
        .collect();
    assert_eq!(names.len(), 3, "dump nodes: {nodes:?}");
    assert!(names.contains(&"alice"), "missing alice: {names:?}");
    assert!(names.contains(&"bob"), "missing bob: {names:?}");
    assert!(names.contains(&"carol"), "missing carol: {names:?}");

    // carol's status: bit 4 (reachable) CLEAR. She's in the graph
    // but no edge reaches her. Body token 10 (0-indexed) = status.
    let carol_row = nodes
        .iter()
        .find(|r| {
            r.strip_prefix("18 3 ")
                .is_some_and(|b| b.starts_with("carol "))
        })
        .expect("carol row");
    let status = carol_row
        .strip_prefix("18 3 ")
        .unwrap()
        .split_whitespace()
        .nth(10)
        .and_then(|s| u32::from_str_radix(s, 16).ok())
        .expect("status hex");
    assert_eq!(
        status & 0x10,
        0,
        "carol should be unreachable (no edges); status={status:x}"
    );

    drop(ctl);
    let stderr = drain_stderr(alice_child);
    // No "Autoconnecting" log: AutoConnect = no.
    assert!(
        !stderr.contains("Autoconnecting"),
        "AutoConnect = no should suppress autoconnect; stderr:\n{stderr}"
    );
}

/// `do_autoconnect` `<3 → make_new_connection` loop. Alice has
/// `AutoConnect = yes` (the default) and `hosts/{bob,carol,dave}`
/// all with `Address =`, but ZERO `ConnectTo =` lines. The periodic
/// tick (every 5s) runs `decide_autoconnect`; with `nc=0` it picks
/// one eligible node per tick → `Connect`. Three ticks later (~15s)
/// alice has 3 active connections.
///
/// **Why ~15s and not faster**: `make_new_connection` randomizes
/// over eligible nodes. With 3 eligibles, the first pick is 1/3
/// each. Once one connects, `nc=1`, next tick picks from 2. The
/// `pending_outgoings` check means a re-roll on the SAME node is
/// `Noop` — doesn't burn a tick. With
/// the periodic timer at 5s, worst-case is 3 successful picks =
/// 15s. Add slop for the connect+handshake latency (loopback,
/// ~100ms each).
///
/// **Slow test**: ~15s. The 5s periodic is hardcoded
/// (`{ 5, jitter() }`). Nextest's default slow-timeout is
/// 30s; this fits. The CI profile has 60s.
#[test]
fn autoconnect_converges_to_three() {
    let tmp = tmp("autoconnect");
    // PingTimeout=10 on the peers: an inbound conn arriving at
    // +15s gets stamped with the cached `timers.now()` from the
    // previous event-loop turn (up to 5s stale — the periodic
    // timer is the only thing waking an idle peer). With the
    // `write_config_multi` default PingTimeout=1, the conn is
    // born already-stale and reaped before id_h. Same root cause
    // as `outgoing_retry_after_refused`'s note; bigger window
    // here because the connect lands much later. PingTimeout=10
    // > 5s periodic + handshake. (PingTimeout is clamped to
    // `≤ PingInterval`; default PingInterval=60 leaves room.)
    let alice = Node::new(tmp.path(), "alice", 0xA0).with_conf("PingTimeout = 10\n");
    let peer_conf = "PingTimeout = 10\nAutoConnect = no\n";
    let bob = Node::new(tmp.path(), "bob", 0xB0).with_conf(peer_conf);
    let carol = Node::new(tmp.path(), "carol", 0xC0).with_conf(peer_conf);
    let dave = Node::new(tmp.path(), "dave", 0xD0).with_conf(peer_conf);

    // The peers: just listen, no ConnectTo. AutoConnect=no on
    // them so THEY don't start dialing each other (we only want
    // alice's autoconnect to fire; cross-dialing would muddy the
    // "exactly 3 conns from alice" assertion).
    bob.write_config_multi(&[&alice], &[], None, None);
    carol.write_config_multi(&[&alice], &[], None, None);
    dave.write_config_multi(&[&alice], &[], None, None);

    // alice: NO ConnectTo. Her hosts/ files for bob/carol/dave
    // all need `Address =` so `load_all_nodes` populates
    // `has_address`. `write_config_multi` only writes Address
    // for ConnectTo targets; we write hosts/ manually instead.
    {
        std::fs::create_dir_all(alice.confbase.join("hosts")).unwrap();
        std::fs::write(
            alice.confbase.join("tinc.conf"),
            format!(
                "Name = alice\nDeviceType = dummy\nAddressFamily = ipv4\n{}PingTimeout = 1\n",
                alice.extra_conf
            ),
        )
        .unwrap();
        std::fs::write(
            alice.confbase.join("hosts").join("alice"),
            format!("Port = {}\n", alice.port),
        )
        .unwrap();
        for peer in [&bob, &carol, &dave] {
            let pk = tinc_crypto::b64::encode(&peer.pubkey());
            std::fs::write(
                alice.confbase.join("hosts").join(peer.name),
                format!(
                    "Ed25519PublicKey = {pk}\nAddress = 127.0.0.1 {}\n",
                    peer.port
                ),
            )
            .unwrap();
        }
        write_ed25519_privkey(&alice.confbase, &alice.seed);
    }

    // ─── spawn peers first (so alice's connects succeed) ─────────
    // Stderr → file: this test runs ~15s with 4 daemons cross-
    // gossiping. Piped stderr (~64K buffer) fills and blocks the
    // event loop on `write(2)`. /dev/null discards diagnostics; a
    // tmpfile captures them for the failure dump.
    let spawn_logged = |n: &Node| {
        let log = std::fs::File::create(tmp.path().join(format!("{}.stderr", n.name))).unwrap();
        tincd_cmd()
            .arg("-c")
            .arg(&n.confbase)
            .arg("--pidfile")
            .arg(&n.pidfile)
            .arg("--socket")
            .arg(&n.socket)
            .env("RUST_LOG", "tincd=info")
            .stderr(log)
            .spawn()
            .expect("spawn tincd")
    };
    let mut bob_child = spawn_logged(&bob);
    let mut carol_child = spawn_logged(&carol);
    let mut dave_child = spawn_logged(&dave);
    for (n, child) in [
        (&bob, &mut bob_child),
        (&carol, &mut carol_child),
        (&dave, &mut dave_child),
    ] {
        if !wait_for_file(&n.socket) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{} setup failed", n.name);
        }
    }

    let mut alice_child = alice.spawn();
    if !wait_for_file(&alice.socket) {
        let _ = bob_child.kill();
        let _ = carol_child.kill();
        let _ = dave_child.kill();
        panic!("alice setup failed: {}", drain_stderr(alice_child));
    }

    // ─── poll: alice converges to 3 active peer conns ────────────
    // First periodic tick at +5s; one Connect per tick. 3 ticks
    // ≈ 15s to fill all three slots. 25s timeout for CI slop.
    let mut alice_ctl = alice.ctl();
    let deadline = Instant::now() + Duration::from_secs(25);
    let mut last_conns;
    let mut last_count;
    let converged = loop {
        let conns = alice_ctl.dump(6);
        let active_peers: usize = conns
            .iter()
            .filter(|r| {
                r.strip_prefix("18 6 ").is_some_and(|b| {
                    let mut t = b.split_whitespace();
                    let name = t.next();
                    let status = t.last().and_then(|s| u32::from_str_radix(s, 16).ok());
                    // Active (bit 1) AND not the control conn (bit 9).
                    matches!(name, Some("bob" | "carol" | "dave"))
                        && status.is_some_and(|s| s & 0x2 != 0)
                })
            })
            .count();
        last_count = active_peers;
        last_conns = conns;
        if active_peers == 3 {
            break true;
        }
        if Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(100));
    };

    // ─── collect stderr (also for failure diagnosis) ────────────
    drop(alice_ctl);
    let _ = alice_child.kill();
    let alice_out = alice_child.wait_with_output().unwrap();
    let alice_stderr = String::from_utf8_lossy(&alice_out.stderr);
    let _ = bob_child.kill();
    let _ = carol_child.kill();
    let _ = dave_child.kill();
    let _ = bob_child.wait();
    let _ = carol_child.wait();
    let _ = dave_child.wait();

    if !converged {
        // Dump all peer logs on failure.
        let mut peer_logs = String::new();
        for n in [&bob, &carol, &dave] {
            let path = tmp.path().join(format!("{}.stderr", n.name));
            let _ = std::fmt::Write::write_fmt(
                &mut peer_logs,
                format_args!(
                    "\n--- {} stderr ---\n{}",
                    n.name,
                    std::fs::read_to_string(&path).unwrap_or_default()
                ),
            );
        }
        panic!(
            "timed out waiting for 3 active peer conns; \
             last count={last_count}, last dump conns: {last_conns:?}\n\
             alice stderr:\n{alice_stderr}{peer_logs}"
        );
    }

    // Three Autoconnecting log lines (one per peer).
    let auto_count = alice_stderr.matches("Autoconnecting to ").count();
    assert_eq!(
        auto_count, 3,
        "expected 3 Autoconnecting logs (one per peer), got {auto_count}; \
         stderr:\n{alice_stderr}"
    );
}
