use std::os::fd::AsRawFd;
use std::process::Stdio;
use std::time::{Duration, Instant};

use super::common::*;
use super::fd_tunnel::*;
use super::node::*;

/// **THREE DAEMONS, RELAY PATH.** alice ← mid → bob, NO direct
/// alice↔bob `ConnectTo`. Alice's packet to bob's subnet routes
/// `Forward{to: bob}`; `send_sptps_data`'s relay decision sends
/// it via `mid` (the nexthop). Mid's `on_udp_recv` sees
/// `dst_id == bob`, calls `send_sptps_data_relay(to=bob, from=
/// alice)`. Bob receives, decrypts with the alice↔bob per-tunnel
/// SPTPS, writes to TUN.
///
/// Exercises the full chunk-9b chain:
/// - `REQ_KEY/ANS_KEY` relay (`on_req_key`/`on_ans_key` `to !=
///   myself`): alice's `REQ_KEY` for bob goes via mid's meta-conn.
/// - `send_sptps_data_relay` `:967` `relay = nexthop` (since
///   `via == myself` for alice — bob is reachable but indirect
///   only via the SSSP path through mid).
/// - UDP relay receive (`on_udp_recv` `dst != null && dst !=
///   myself`): mid forwards. The packet carries bob's `dst_id6`.
/// - The `[dst_id6][src_id6]` prefix on the wire (`direct=false`
///   ⇒ `dst = to->id`, not nullid).
///
/// What this DOESN'T test: `via != myself` (the static-relay
/// path, set by `IndirectData = yes`). With three nodes connected
/// linearly, SSSP gives `via=bob` for bob (`via` is the LAST
/// direct node — and bob IS the destination, reached via mid's
/// edge). So `via_nid == myself` is false... actually no, `via`
/// for a node is the last NON-indirect hop. With no `IndirectData`,
/// every edge is direct, so `via == nid` for every node. The relay
/// here happens because `nexthop != to` (mid is the first hop).
///
/// ## TCP-tunneled handshake, possibly TCP-tunneled data
///
/// alice↔bob have no direct TCP connection. Their per-tunnel SPTPS
/// handshake goes via `REQ_KEY/ANS_KEY` relayed by mid. That's the
/// `to != myself` arms in `on_req_key`/`on_ans_key`.
///
/// The DATA path: until `mid`'s `minmtu` is discovered (which
/// requires probes from alice→mid), the `too_big` gate would force
/// TCP. But chunk-9b's gate is `relay_minmtu > 0 && origlen >
/// minmtu` — `minmtu==0` ⇒ go UDP optimistically. So data goes
/// UDP. EMSGSIZE would correct if the loopback MTU is small, but
/// it's 65536 on Linux loopback so no problem.
#[test]
fn three_daemon_relay() {
    let tmp = tmp!("relay3");
    let alice = Node::new(tmp.path(), "alice", 0xA3);
    let mid = Node::new(tmp.path(), "mid", 0xC3);
    let bob = Node::new(tmp.path(), "bob", 0xB3);

    let (alice_tun, alice_far) = sockpair_datagram();
    let (bob_tun, bob_far) = sockpair_datagram();

    // mid is the hub: no device (dummy), no subnet, no ConnectTo.
    // Both alice and bob ConnectTo mid. mid knows everyone's pubkey.
    mid.write_config_multi(&[&alice, &bob], &[], None, None);
    // alice: ConnectTo=mid, owns 10.0.0.1/32. Knows bob's pubkey
    // (needed for the per-tunnel SPTPS handshake).
    alice.write_config_multi(
        &[&mid, &bob],
        &["mid"],
        Some(alice_far.as_raw_fd()),
        Some("10.0.0.1/32"),
    );
    // bob: ConnectTo=mid, owns 10.0.0.2/32. Knows alice's pubkey.
    bob.write_config_multi(
        &[&mid, &alice],
        &["mid"],
        Some(bob_far.as_raw_fd()),
        Some("10.0.0.2/32"),
    );

    // ─── spawn: mid first (the hub everyone connects to) ─────────
    // mid runs at debug-level so we can assert the relay log lines.
    let mut mid_child = tincd_at(&mid.confbase, &mid.pidfile, &mid.socket)
        .env("RUST_LOG", "tincd=debug")
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mid");
    assert!(
        wait_for_file(&mid.socket),
        "mid setup failed; stderr:\n{}",
        drain_stderr(mid_child)
    );

    let mut bob_child = bob.spawn_with_fd(&bob_far);
    if !wait_for_file(&bob.socket) {
        let _ = mid_child.kill();
        panic!("bob setup failed; stderr:\n{}", drain_stderr(bob_child));
    }
    drop(bob_far);

    let alice_child = alice.spawn_with_fd(&alice_far);
    if !wait_for_file(&alice.socket) {
        let _ = mid_child.kill();
        let _ = bob_child.kill();
        panic!("alice setup failed; stderr:\n{}", drain_stderr(alice_child));
    }
    drop(alice_far);

    // ─── wait for full mesh reachability ────────────────────────
    let mut alice_ctl = alice.ctl();
    let mut bob_ctl = bob.ctl();
    let _mid_ctl = mid.ctl();

    // alice must see bob as reachable (transitively, via mid).
    // SSSP: alice—mid edge from alice's ACK; mid—bob edge gossiped
    // via ADD_EDGE from mid. graph() runs, bob becomes reachable.
    let mesh_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        poll_until(Duration::from_secs(10), || {
            let a = alice_ctl.dump(3);
            let b = bob_ctl.dump(3);
            // bit 4 = reachable
            let a_sees_bob = node_status(&a, "bob").is_some_and(|s| s & 0x10 != 0);
            let b_sees_alice = node_status(&b, "alice").is_some_and(|s| s & 0x10 != 0);
            (a_sees_bob && b_sees_alice).then_some(())
        });
    }));
    if mesh_result.is_err() {
        let _ = mid_child.kill();
        let _ = bob_child.kill();
        let ms = drain_stderr(mid_child);
        let bs = drain_stderr(bob_child);
        let asd = drain_stderr(alice_child);
        panic!(
            "mesh reachability timed out;\n=== alice ===\n{asd}\n=== mid ===\n{ms}\n=== bob ===\n{bs}"
        );
    }

    // ─── nexthop check: alice's route to bob goes via mid ────────
    // dump_nodes body tokens 11/12 are nexthop/via. For alice's
    // bob row: nexthop should be "mid".
    let node_nexthop = |rows: &[String], name: &str| -> Option<String> {
        rows.iter().find_map(|r| {
            let body = r.strip_prefix("18 3 ")?;
            let toks: Vec<&str> = body.split_whitespace().collect();
            if toks.first() != Some(&name) {
                return None;
            }
            Some(toks.get(11)?.to_string())
        })
    };
    let a_nodes = alice_ctl.dump(3);
    let nh = node_nexthop(&a_nodes, "bob");
    assert_eq!(
        nh.as_deref(),
        Some("mid"),
        "alice's nexthop for bob should be mid; nodes:\n{a_nodes:#?}"
    );

    // ─── kick the per-tunnel handshake ──────────────────────────
    // alice's REQ_KEY for bob goes via `nexthop->connection` =
    // alice's mid-conn. mid's `on_req_key` sees `to != myself`,
    // forwards verbatim to bob via mid's bob-conn. Bob starts
    // responder SPTPS, ANS_KEY back via mid.
    let kick = mk_ipv4_pkt([10, 0, 0, 1], [10, 0, 0, 2], b"kick");
    write_fd(&alice_tun, &kick);

    let validkey_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        poll_until(Duration::from_secs(10), || {
            let a = alice_ctl.dump(3);
            let b = bob_ctl.dump(3);
            // bit 1 = validkey
            let a_ok = node_status(&a, "bob").is_some_and(|s| s & 0x02 != 0);
            let b_ok = node_status(&b, "alice").is_some_and(|s| s & 0x02 != 0);
            (a_ok && b_ok).then_some(())
        });
    }));
    if validkey_result.is_err() {
        let _ = mid_child.kill();
        let _ = bob_child.kill();
        let ms = drain_stderr(mid_child);
        let bs = drain_stderr(bob_child);
        let asd = drain_stderr(alice_child);
        panic!("validkey timed out;\n=== alice ===\n{asd}\n=== mid ===\n{ms}\n=== bob ===\n{bs}");
    }

    // ─── THE PACKET ─────────────────────────────────────────────
    // alice → mid (UDP, dst_id6=bob) → bob. mid's `on_udp_recv`
    // sees dst != null && dst != myself, calls `send_sptps_data_
    // relay`. The ciphertext is the alice↔bob SPTPS record; mid
    // can't decrypt it (and doesn't try — just re-prefixes and
    // forwards). bob decrypts.
    //
    // Security audit `2f72c2ba` relay gate: mid drops UDP relay
    // packets from senders it hasn't UDP-confirmed. validkey (alice↔bob tunnel) and udp_confirmed
    // (alice@mid) race — the kick above drove `try_tx(bob)` → PMTU
    // probe to mid, but the probe-reply may not have landed yet.
    // Resend the data packet on each poll: each send drives `try_
    // tx` again, and once mid confirms alice (via the probe), the
    // next packet relays. The first ones drop at mid's gate.
    let payload = b"relayed via mid";
    let ip_pkt = mk_ipv4_pkt([10, 0, 0, 1], [10, 0, 0, 2], payload);

    let recv_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        poll_until(Duration::from_secs(5), || {
            // Resend on each poll; drains bob's TUN until match.
            write_fd(&alice_tun, &ip_pkt);
            // May drain stale frames (kick, prior sends). Only
            // accept exact match.
            while let Some(r) = read_fd_nb(&bob_tun) {
                if r == ip_pkt {
                    return Some(r);
                }
            }
            None
        })
    }));
    let Ok(recv) = recv_result else {
        let _ = mid_child.kill();
        let _ = bob_child.kill();
        let ms = drain_stderr(mid_child);
        let bs = drain_stderr(bob_child);
        let asd = drain_stderr(alice_child);
        panic!(
            "packet relay timed out;\n=== alice ===\n{asd}\n=== mid ===\n{ms}\n=== bob ===\n{bs}"
        );
    };

    assert_eq!(
        recv,
        ip_pkt,
        "relay round-trip mismatch; sent {} got {}",
        ip_pkt.len(),
        recv.len()
    );
    assert_eq!(&recv[20..], payload);

    // ─── dump nodes: indirect node shows learned UDP addr ───────
    // bob is NOT a direct meta-neighbor of alice (no NodeState
    // entry), but alice learned bob's UDP address via the relay-
    // appended ANS_KEY field (`tunnels[bob].udp_addr`). Before the
    // fix, dump_nodes_rows only consulted NodeState.edge_addr and
    // printed "unknown port unknown" here despite udp_confirmed.
    let a_nodes = alice_ctl.dump(3);
    let bob_row = a_nodes
        .iter()
        .find(|r| {
            r.strip_prefix("18 3 ")
                .is_some_and(|b| b.split_whitespace().next() == Some("bob"))
        })
        .unwrap_or_else(|| panic!("no bob row; nodes:\n{a_nodes:#?}"));
    assert!(
        bob_row.contains(" 127.0.0.1 port "),
        "alice's bob row should show learned udp_addr (tunnel fallback), \
         not 'unknown port unknown'; row: {bob_row}"
    );

    // ─── mid stderr: the relay log ──────────────────────────────
    drop(alice_ctl);
    drop(bob_ctl);
    drop(alice_tun);
    drop(bob_tun);
    let _ = mid_child.kill();
    let _ = bob_child.kill();
    let mid_stderr = drain_stderr(mid_child);
    let _bob_stderr = drain_stderr(bob_child);
    let _alice_stderr = drain_stderr(alice_child);
    // mid should have logged at least one relay forward. The "via"
    // log line is from `send_sptps_data_relay`; the "Relaying
    // REQ_KEY" / "Relaying ANS_KEY" lines are from the meta-relay.
    assert!(
        mid_stderr.contains("Relaying"),
        "mid should log relay activity; stderr:\n{mid_stderr}"
    );
}

/// Three daemons, hub-and-spoke, with `TunnelServer = yes` on the
/// hub. Same physical setup as `three_daemon_relay` (alice and bob
/// both `ConnectTo = mid`, no direct alice↔bob meta connection).
///
/// The DIFFERENCE: tunnelserver makes mid a router-only hub. mid's
/// `send_everything` sends only its OWN subnets (none here); mid's
/// `on_ack` sends the new edge to the new peer ONLY (`send_add_
/// edge(c, ...)` not `send_add_edge(everyone, ...)`); mid's
/// `on_add_subnet`/`on_add_edge` never `forward_request`. So:
///
/// - alice's `dump nodes` shows bob as **unreachable**. She
///   never received bob's `ADD_EDGE` because mid didn't forward it.
///   (bob IS in alice's graph: `load_all_nodes` walks hosts/ at
///   setup and adds every name. But no edge reaches him.)
/// - bob: same. alice is unreachable from bob's view.
/// - mid: 3 nodes, all REACHABLE. Hub knows spokes; spokes don't
///   know each other's edges.
/// - A packet from alice to `10.0.0.2` (bob's subnet) → alice's
///   `route()` returns `Unreachable` (alice doesn't have bob's
///   subnet — mid didn't forward bob's `ADD_SUBNET`). alice writes
///   ICMP `DEST_UNREACH` back to her own TUN. **This is the
///   operator-visible behavior**: tunnelserver makes mid a router-
///   only hub; alice can't reach bob through it without explicit
///   config.
///
/// `net.py::test_tunnel_server` checks the dump only; asserting
/// the ICMP is BETTER (proves the data-plane consequence, not just
/// the control-plane state).
///
/// Timing: poll until alice sees 2 nodes STABILIZE (poll, sleep
/// 50ms, poll again, same answer) — otherwise we might catch the
/// moment before mid's edge arrives at alice and get a false pass
/// on "only 2 nodes".
#[test]
fn three_daemon_tunnelserver() {
    let tmp = tmp!("tunnelserver3");
    let alice = Node::new(tmp.path(), "alice", 0xA4);
    // mid: TunnelServer = yes. The whole point.
    let mid = Node::new(tmp.path(), "mid", 0xC4).with_conf("TunnelServer = yes\n");
    let bob = Node::new(tmp.path(), "bob", 0xB4);

    let (alice_tun, alice_far) = sockpair_datagram();

    // mid: hub. dummy device, no subnet, no ConnectTo. Knows both
    // spokes' pubkeys (for the meta-SPTPS auth).
    mid.write_config_multi(&[&alice, &bob], &[], None, None);
    // mid: append `Subnet =` to hosts/{alice,bob}. With
    // `:880 strictsubnets|=tunnelserver`, mid's `load_all_nodes`
    // preloads these; bob's gossip'd ADD_SUBNET hits the `:93`
    // lookup-first noop. Without preload, mid hits `:109` ("we
    // should already know all allowed subnets") and DROPS bob's
    // subnet — mid can't route to bob. The C requires this preload
    // for tunnelserver hubs; our pre-strictsubnets code accepted
    // gossip without it (the `:109` gate didn't exist), so the
    // test predates the requirement. `write_config_multi` only
    // writes pubkey to hosts/PEER, so append.
    let mid_hosts = mid.confbase.join("hosts");
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(mid_hosts.join("alice"))
            .unwrap();
        writeln!(f, "Subnet = 10.0.0.1/32").unwrap();
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(mid_hosts.join("bob"))
            .unwrap();
        writeln!(f, "Subnet = 10.0.0.2/32").unwrap();
    }
    // alice: ConnectTo=mid, owns 10.0.0.1/32, fd device. Knows
    // bob's pubkey (irrelevant here — she'll never start a tunnel
    // to bob because she never learns he exists).
    alice.write_config_multi(
        &[&mid, &bob],
        &["mid"],
        Some(alice_far.as_raw_fd()),
        Some("10.0.0.1/32"),
    );
    // bob: ConnectTo=mid, owns 10.0.0.2/32. dummy device (we only
    // assert from alice's side).
    bob.write_config_multi(&[&mid, &alice], &["mid"], None, Some("10.0.0.2/32"));

    // ─── spawn: mid first (the hub) ──────────────────────────────
    let mut mid_child = tincd_at(&mid.confbase, &mid.pidfile, &mid.socket)
        .env("RUST_LOG", "tincd=debug")
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mid");
    assert!(
        wait_for_file(&mid.socket),
        "mid setup failed; stderr:\n{}",
        drain_stderr(mid_child)
    );

    let mut bob_child = bob.spawn();
    if !wait_for_file(&bob.socket) {
        let _ = mid_child.kill();
        panic!("bob setup failed; stderr:\n{}", drain_stderr(bob_child));
    }

    let alice_child = alice.spawn_with_fd(&alice_far);
    if !wait_for_file(&alice.socket) {
        let _ = mid_child.kill();
        let _ = bob_child.kill();
        panic!("alice setup failed; stderr:\n{}", drain_stderr(alice_child));
    }
    drop(alice_far);

    let mut alice_ctl = alice.ctl();
    let mut bob_ctl = bob.ctl();
    let mut mid_ctl = mid.ctl();

    // ─── wait for alice↔mid and bob↔mid to settle ────────────────
    // mid sees both spokes as active connections. Once that's
    // true, all the gossip that's going to happen HAS happened
    // (each ACK fires `send_everything` + `send_add_edge`; with
    // tunnelserver, mid's send_everything is empty and the
    // add_edge goes only to that peer).
    poll_until(Duration::from_secs(10), || {
        let m = mid_ctl.dump(6);
        let a_ok = has_active_peer(&m, "alice");
        let b_ok = has_active_peer(&m, "bob");
        (a_ok && b_ok).then_some(())
    });

    // ─── the count assertions, with stabilization ──────────────
    // alice should see EXACTLY 2 nodes. NOT 3. Poll until stable
    // (two consecutive reads agree) to rule out catching the
    // pre-mid-edge moment.
    let alice_stable = poll_until(Duration::from_secs(5), || {
        let a1 = alice_ctl.dump(3);
        std::thread::sleep(Duration::from_millis(50));
        let a2 = alice_ctl.dump(3);
        (a1.len() == a2.len() && a1.len() >= 2).then_some(a1)
    });

    let node_names = |rows: &[String]| -> Vec<String> {
        rows.iter()
            .filter_map(|r| {
                r.strip_prefix("18 3 ")?
                    .split_whitespace()
                    .next()
                    .map(String::from)
            })
            .collect()
    };

    // `load_all_nodes` adds every hosts/-file name to the graph at
    // setup, so bob IS in
    // alice's `dump nodes` (alice has hosts/bob for the pubkey).
    // The tunnelserver assertion is REACHABILITY, not presence:
    // mid never forwarded bob's ADD_EDGE → no edge to bob →
    // bob unreachable. Status bit 4 (`0x10`) is `reachable`.
    let reachable_names = |rows: &[String]| -> Vec<String> {
        rows.iter()
            .filter_map(|r| {
                let body = r.strip_prefix("18 3 ")?;
                let mut t = body.split_whitespace();
                let name = t.next()?;
                // Body tokens: name id host "port" port cipher
                // digest maclen compression options STATUS …
                let status = u32::from_str_radix(t.nth(9)?, 16).ok()?;
                (status & 0x10 != 0).then(|| name.to_owned())
            })
            .collect()
    };

    let a_names = node_names(&alice_stable);
    let a_reachable = reachable_names(&alice_stable);
    assert_eq!(
        a_reachable.len(),
        2,
        "alice should see exactly 2 REACHABLE nodes (alice, mid) — \
         mid's tunnelserver mode never forwarded bob's ADD_EDGE; \
         all: {a_names:?}, reachable: {a_reachable:?}"
    );
    assert!(
        a_reachable.contains(&"alice".to_string()),
        "{a_reachable:?}"
    );
    assert!(a_reachable.contains(&"mid".to_string()), "{a_reachable:?}");
    assert!(
        !a_reachable.contains(&"bob".to_string()),
        "bob should be UNREACHABLE from alice (no edge gossiped); \
         got reachable: {a_reachable:?}"
    );

    // bob: same. 2 REACHABLE (bob, mid); alice is in graph but
    // unreachable.
    let b_nodes = bob_ctl.dump(3);
    let b_names = node_names(&b_nodes);
    let b_reachable = reachable_names(&b_nodes);
    assert_eq!(
        b_reachable.len(),
        2,
        "bob should see exactly 2 REACHABLE nodes (bob, mid); \
         all: {b_names:?}, reachable: {b_reachable:?}"
    );
    assert!(
        !b_reachable.contains(&"alice".to_string()),
        "alice should be UNREACHABLE from bob; got: {b_reachable:?}"
    );

    // mid: 3 REACHABLE. Hub knows both spokes via direct edges.
    let m_nodes = mid_ctl.dump(3);
    let m_names = node_names(&m_nodes);
    let m_reachable = reachable_names(&m_nodes);
    assert_eq!(
        m_reachable.len(),
        3,
        "mid (the hub) should see all 3 nodes REACHABLE; \
         all: {m_names:?}, reachable: {m_reachable:?}"
    );

    // alice's subnets: she knows her OWN (10.0.0.1/32) and mid's
    // (none). NOT bob's. So `dump subnets` (subtype 5) shows 1.
    let a_subnets = alice_ctl.dump(5);
    assert_eq!(
        a_subnets.len(),
        1,
        "alice should have exactly 1 subnet (her own); mid's \
         tunnelserver send_everything sends only OWN subnets (none) \
         and on_add_subnet doesn't forward bob's; got: {a_subnets:?}"
    );

    // ─── the data-plane consequence: ICMP unreachable ──────────
    // A packet from alice to 10.0.0.2 (bob's subnet) hits alice's
    // `route()` → NO subnet match (alice doesn't have bob's
    // subnet) → `Unreachable{ICMP_DEST_UNREACH, ICMP_NET_UNKNOWN}`
    // → ICMP synth → written BACK to alice's TUN. The TEST end of
    // the socketpair reads it.
    //
    // ICMP layout (FdTun strips/adds ether so we see raw IP):
    // bytes [0..20] = IPv4 header (proto=1 ICMP at byte 9),
    // byte [20] = ICMP type (3 = DEST_UNREACH),
    // byte [21] = ICMP code (6 = NET_UNKNOWN).
    let probe = mk_ipv4_pkt([10, 0, 0, 1], [10, 0, 0, 2], b"nowhere");
    write_fd(&alice_tun, &probe);

    let icmp = poll_until(Duration::from_secs(5), || read_fd_nb(&alice_tun));
    assert!(
        icmp.len() >= 22,
        "expected ICMP reply, got {} bytes: {icmp:02x?}",
        icmp.len()
    );
    assert_eq!(icmp[9], 1, "IP proto should be ICMP; got: {icmp:02x?}");
    assert_eq!(
        icmp[20], 3,
        "ICMP type should be DEST_UNREACH (3); got: {icmp:02x?}"
    );
    assert_eq!(
        icmp[21], 6,
        "ICMP code should be NET_UNKNOWN (6); got: {icmp:02x?}"
    );

    // ─── mid stderr: tunnelserver send_everything log ──────────
    drop(alice_ctl);
    drop(bob_ctl);
    drop(mid_ctl);
    drop(alice_tun);
    let _ = mid_child.kill();
    let _ = bob_child.kill();
    let mid_stderr = drain_stderr(mid_child);
    let _ = drain_stderr(bob_child);
    let _ = drain_stderr(alice_child);
    assert!(
        mid_stderr.contains("tunnelserver"),
        "mid should log tunnelserver-mode send_everything; stderr:\n{mid_stderr}"
    );
}

/// `StrictSubnets = yes`: alice's `hosts/bob` is the AUTHORITY for
/// which subnets bob may claim. bob owns `10.0.0.2/32` in his own
/// config; he gossips `ADD_SUBNET` for it via mid → alice. alice's
/// `hosts/bob` does NOT have `Subnet = 10.0.0.2/32`. The
/// strictsubnets gate fires: alice forwards the gossip (to nobody,
/// no other peers) but does NOT add it locally.
///
/// Unlike `tunnelserver`, `strictsubnets` does NOT filter topology:
/// alice still learns bob exists (mid forwards bob's `ADD_EDGE`). She
/// just won't route to subnets she didn't pre-authorize on disk.
///
/// ## Shape
///
/// - alice: `StrictSubnets = yes`, `ConnectTo = mid`, owns
///   `10.0.0.1/32`. Her `hosts/bob` has the pubkey ONLY — no
///   `Subnet` line.
/// - mid: dumb relay (NOT strictsubnets). `ConnectTo` neither.
///   Forwards gossip both ways.
/// - bob: `ConnectTo = mid`, owns `10.0.0.2/32`. His `ADD_SUBNET`
///   reaches alice via mid's `forward_request`.
///
/// ## Assertions
///
/// 1. alice `dump nodes` shows 3 reachable (topology unfiltered).
/// 2. alice `dump subnets` does NOT have `10.0.0.2` (the gate).
/// 3. mid `dump subnets` DOES have `10.0.0.2` (mid isn't strict).
/// 4. ping `10.0.0.2` from alice → ICMP `NET_UNKNOWN` (no route).
/// 5. Append `Subnet = 10.0.0.2/32` to alice's `hosts/bob`, restart
///    alice → `load_all_nodes` preloads it → `ADD_SUBNET` gossip
///    arrives, `subnets.contains` finds it (the `:93` lookup-first),
///    silent noop → `dump subnets` now shows it. (Restart not
///    SIGHUP; reload diff is `TODO(chunk-12-strictsubnets-reload)`.)
///
/// Regression-first: before the gate exists, step 2 fails (alice
/// wrongly accepts the gossip).
#[test]
fn three_daemon_strictsubnets() {
    let tmp = tmp!("strictsubnets3");
    // alice: StrictSubnets = yes. The RECEIVER of gossip.
    let alice = Node::new(tmp.path(), "alice", 0xA5).with_conf("StrictSubnets = yes\n");
    // mid: plain relay. NOT strict (so we can prove it accepts).
    let mid = Node::new(tmp.path(), "mid", 0xC5);
    let bob = Node::new(tmp.path(), "bob", 0xB5);

    let (alice_tun, alice_far) = sockpair_datagram();

    // mid: hub. dummy device, no subnet, no ConnectTo. Knows both.
    mid.write_config_multi(&[&alice, &bob], &[], None, None);
    // alice: ConnectTo=mid, owns 10.0.0.1/32, fd device. Knows
    // bob's pubkey. CRITICALLY: alice's hosts/bob (written by
    // write_config_multi) has NO `Subnet =` line — see the
    // "no Subnet line needed here" comment in that fn. That's
    // exactly what we want: bob's subnet is unauthorized.
    alice.write_config_multi(
        &[&mid, &bob],
        &["mid"],
        Some(alice_far.as_raw_fd()),
        Some("10.0.0.1/32"),
    );
    // bob: ConnectTo=mid, owns 10.0.0.2/32. dummy device.
    bob.write_config_multi(&[&mid, &alice], &["mid"], None, Some("10.0.0.2/32"));

    // ─── spawn: mid first ────────────────────────────────────────
    let mut mid_child = mid.spawn();
    assert!(
        wait_for_file(&mid.socket),
        "mid setup failed; stderr:\n{}",
        drain_stderr(mid_child)
    );
    let mut bob_child = bob.spawn();
    if !wait_for_file(&bob.socket) {
        let _ = mid_child.kill();
        panic!("bob setup failed; stderr:\n{}", drain_stderr(bob_child));
    }
    let alice_child = alice.spawn_with_fd(&alice_far);
    if !wait_for_file(&alice.socket) {
        let _ = mid_child.kill();
        let _ = bob_child.kill();
        panic!("alice setup failed; stderr:\n{}", drain_stderr(alice_child));
    }
    drop(alice_far);

    let mut alice_ctl = alice.ctl();
    let mut mid_ctl = mid.ctl();

    // ─── wait: mid sees both spokes active ───────────────────────
    poll_until(Duration::from_secs(10), || {
        let m = mid_ctl.dump(6);
        (has_active_peer(&m, "alice") && has_active_peer(&m, "bob")).then_some(())
    });
    // mid forwards bob's ADD_EDGE to alice. Wait for alice to see
    // 3 reachable nodes (proves topology is NOT filtered by
    // strictsubnets — that's tunnelserver's job).
    let alice_nodes = poll_until(Duration::from_secs(10), || {
        let a = alice_ctl.dump(3);
        let reachable = a
            .iter()
            .filter(|r| {
                r.strip_prefix("18 3 ")
                    .and_then(|b| b.split_whitespace().nth(10))
                    .and_then(|s| u32::from_str_radix(s, 16).ok())
                    .is_some_and(|s| s & 0x10 != 0)
            })
            .count();
        (reachable == 3).then_some(a)
    });
    assert_eq!(
        alice_nodes.iter().filter(|r| r.contains(" bob ")).count(),
        1,
        "alice should see bob in node list (topology unfiltered): {alice_nodes:?}"
    );

    // ─── the gate: alice does NOT have bob's subnet ──────────────
    // mid DOES (proves the gossip propagated; alice's gate is
    // alice-local). Wait for mid to receive it first.
    poll_until(Duration::from_secs(5), || {
        let m = mid_ctl.dump(5);
        // `Subnet::Display` omits `/32` (max prefix). `net2str`.
        has_subnet(&m, "10.0.0.2", "bob").then_some(())
    });
    // Stabilize: alice has had time to receive the same gossip.
    // Two consecutive reads agree, neither has 10.0.0.2.
    let a_subnets = poll_until(Duration::from_secs(5), || {
        let a1 = alice_ctl.dump(5);
        std::thread::sleep(Duration::from_millis(50));
        let a2 = alice_ctl.dump(5);
        (a1 == a2).then_some(a1)
    });
    assert!(
        !has_subnet(&a_subnets, "10.0.0.2", "bob"),
        "alice's StrictSubnets gate should reject bob's gossiped \
         10.0.0.2/32 (not in her hosts/bob); got: {a_subnets:?}"
    );
    assert!(
        has_subnet(&a_subnets, "10.0.0.1", "alice"),
        "alice's own subnet should still be there: {a_subnets:?}"
    );

    // ─── data plane: ICMP NET_UNKNOWN ────────────────────────────
    // Same shape as tunnelserver: no route → synth ICMP unreachable.
    let probe = mk_ipv4_pkt([10, 0, 0, 1], [10, 0, 0, 2], b"nowhere");
    write_fd(&alice_tun, &probe);
    let icmp = poll_until(Duration::from_secs(5), || read_fd_nb(&alice_tun));
    assert!(icmp.len() >= 22, "ICMP reply too short: {icmp:02x?}");
    assert_eq!(icmp[9], 1, "IP proto should be ICMP: {icmp:02x?}");
    assert_eq!(icmp[20], 3, "ICMP type DEST_UNREACH: {icmp:02x?}");
    assert_eq!(icmp[21], 6, "ICMP code NET_UNKNOWN: {icmp:02x?}");

    // ─── restart with authorized hosts/bob ────────────────────────
    // Append `Subnet = 10.0.0.2/32` to alice's hosts/bob. Restart
    // alice. `load_all_nodes` preloads it; the ADD_SUBNET gossip
    // hits the `:93` lookup-first → already-have-it → noop. The
    // subnet appears.
    drop(alice_ctl);
    let alice_stderr1 = drain_stderr(alice_child);
    assert!(
        alice_stderr1.contains("Ignoring unauthorized"),
        "alice should have logged the strictsubnets gate firing; stderr:\n{alice_stderr1}"
    );
    drop(alice_tun);

    let bob_hosts = alice.confbase.join("hosts").join("bob");
    let mut bob_cfg = std::fs::read_to_string(&bob_hosts).unwrap();
    bob_cfg.push_str("Subnet = 10.0.0.2/32\n");
    std::fs::write(&bob_hosts, bob_cfg).unwrap();

    // Fresh socketpair for the new alice.
    let (alice_tun2, alice_far2) = sockpair_datagram();
    // Re-write tinc.conf with the new fd (DeviceType=fd / Device=N).
    // hosts/ files persist (we just appended to hosts/bob above).
    alice.write_config_multi(
        &[&mid, &bob],
        &["mid"],
        Some(alice_far2.as_raw_fd()),
        Some("10.0.0.1/32"),
    );
    // write_config_multi re-truncates hosts/bob. Re-append.
    let mut bob_cfg = std::fs::read_to_string(&bob_hosts).unwrap();
    bob_cfg.push_str("Subnet = 10.0.0.2/32\n");
    std::fs::write(&bob_hosts, bob_cfg).unwrap();

    std::fs::remove_file(&alice.socket).ok();
    let alice_child2 = alice.spawn_with_fd(&alice_far2);
    if !wait_for_file(&alice.socket) {
        let _ = mid_child.kill();
        let _ = bob_child.kill();
        panic!(
            "alice respawn failed; stderr:\n{}",
            drain_stderr(alice_child2)
        );
    }
    drop(alice_far2);

    let mut alice_ctl2 = alice.ctl();
    // Wait for alice↔mid handshake; bob's gossip via mid follows.
    // The preloaded subnet is there from cold-start regardless,
    // but wait for full mesh to prove the gossip path doesn't
    // accidentally DELETE it.
    poll_until(Duration::from_secs(10), || {
        let a = alice_ctl2.dump(5);
        has_subnet(&a, "10.0.0.2", "bob").then_some(())
    });

    // ─── cleanup ─────────────────────────────────────────────────
    drop(alice_ctl2);
    drop(mid_ctl);
    drop(alice_tun2);
    let _ = mid_child.kill();
    let _ = bob_child.kill();
    let _ = drain_stderr(mid_child);
    let _ = drain_stderr(bob_child);
    let _ = drain_stderr(alice_child2);
}

/// Find a daemon's UDP listen port by parsing `dump nodes`: the
/// `myself` row has hostname `"MYSELF port <udp_port>"` (`gossip.rs::
/// dump_nodes_rows`). Row format: `18 3 NAME ID6 HOST port PORT ...`.
fn read_udp_port(ctl: &mut Ctl, name: &str) -> u16 {
    let rows = ctl.dump(3);
    for r in &rows {
        let Some(body) = r.strip_prefix("18 3 ") else {
            continue;
        };
        let toks: Vec<&str> = body.split_whitespace().collect();
        if toks.first() == Some(&name) && toks.get(2) == Some(&"MYSELF") {
            // tok[2]="MYSELF" tok[3]="port" tok[4]=port
            return toks[4].parse().expect("udp port");
        }
    }
    panic!("no MYSELF row for {name}; rows: {rows:#?}");
}

/// Security audit `2f72c2ba` regression: `handle_incoming_vpn_packet`
/// must NOT relay a packet from an unauthenticated UDP sender.
///
/// Three-node mesh, mid is the relay hub. After alice/bob both reach
/// validkey via mid, an unauthenticated socket sends a crafted UDP
/// packet to mid's port: `[dst_id6=sha512("bob")[:6]][src_id6=
/// sha512("alice")[:6]][garbage]`. The `if(!n) return` gate drops
/// this; before the fix, our relay branch
/// trusted the SRCID and forwarded the garbage to bob (whose SPTPS
/// rejects it, kicking the `REQ_KEY` restart timer).
///
/// **Assertions**: mid's stderr has "unauthenticated UDP sender";
/// bob's `in_packets` for alice does NOT bump from the garbage
/// (compared before/after the spoofed send).
#[test]
fn udp_relay_gate_unauthenticated_sender() {
    let tmp = tmp!("relay-gate");
    let alice = Node::new(tmp.path(), "alice", 0xA4);
    let mid = Node::new(tmp.path(), "mid", 0xC4);
    let bob = Node::new(tmp.path(), "bob", 0xB4);

    // mid is the hub (no device, no subnet, no ConnectTo).
    mid.write_config_multi(&[&alice, &bob], &[], None, None);
    alice.write_config_multi(&[&mid, &bob], &["mid"], None, Some("10.0.0.1/32"));
    bob.write_config_multi(&[&mid, &alice], &["mid"], None, Some("10.0.0.2/32"));

    // mid runs at debug-level so we can assert the gate log line.
    let mut mid_child = tincd_at(&mid.confbase, &mid.pidfile, &mid.socket)
        .env("RUST_LOG", "tincd=debug")
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mid");
    assert!(
        wait_for_file(&mid.socket),
        "mid setup failed; stderr:\n{}",
        drain_stderr(mid_child)
    );

    let mut bob_child = bob.spawn();
    if !wait_for_file(&bob.socket) {
        let _ = mid_child.kill();
        panic!("bob setup failed; stderr:\n{}", drain_stderr(bob_child));
    }

    let alice_child = alice.spawn();
    if !wait_for_file(&alice.socket) {
        let _ = mid_child.kill();
        let _ = bob_child.kill();
        panic!("alice setup failed; stderr:\n{}", drain_stderr(alice_child));
    }

    // Wait for full mesh reachability (mid knows both, both know
    // each other transitively).
    let alice_ctl = alice.ctl();
    let mut bob_ctl = bob.ctl();
    let mut mid_ctl = mid.ctl();

    poll_until(Duration::from_secs(10), || {
        let m = mid_ctl.dump(3);
        // bit 4 = reachable. mid must see both spokes.
        let m_a = node_status(&m, "alice").is_some_and(|s| s & 0x10 != 0);
        let m_b = node_status(&m, "bob").is_some_and(|s| s & 0x10 != 0);
        (m_a && m_b).then_some(())
    });

    // mid's UDP listen port. The crafted packet goes here.
    let mid_udp_port = read_udp_port(&mut mid_ctl, "mid");

    // Snapshot bob's in-packet counter for alice BEFORE the spoof.
    // dump_nodes row tail: `... in_p in_b out_p out_b`.
    let node_in_packets = |rows: &[String], name: &str| -> u64 {
        rows.iter()
            .find_map(|r| {
                let body = r.strip_prefix("18 3 ")?;
                let toks: Vec<&str> = body.split_whitespace().collect();
                if toks.first() != Some(&name) {
                    return None;
                }
                let n = toks.len();
                toks[n - 4].parse().ok()
            })
            .unwrap_or(0)
    };
    let b_nodes_before = bob_ctl.dump(3);
    let bob_in_before = node_in_packets(&b_nodes_before, "alice");

    // ─── craft the spoofed packet ───────────────────────────────
    // [dst_id6][src_id6][garbage]. dst=bob (relay target), src=alice
    // (a name mid knows from gossip). The 12-byte prefix is what
    // `handle_incoming_vpn_packet` parses. NodeId6 = sha512(name)[:6].
    let dst_id = tincd::node_id::NodeId6::from_name("bob");
    let src_id = tincd::node_id::NodeId6::from_name("alice");
    let mut spoof = Vec::with_capacity(12 + 100);
    spoof.extend_from_slice(dst_id.as_bytes());
    spoof.extend_from_slice(src_id.as_bytes());
    spoof.extend_from_slice(&[0xAA; 100]); // garbage ciphertext

    // Send from a fresh UDP socket — NOT one mid has confirmed.
    // mid's `n` scan (the `lookup_node_udp` equivalent) won't match.
    let attacker = std::net::UdpSocket::bind("127.0.0.1:0").expect("attacker bind");
    attacker
        .send_to(&spoof, ("127.0.0.1", mid_udp_port))
        .expect("spoof send");

    // Give mid a turn to process.
    std::thread::sleep(Duration::from_millis(200));

    // ─── assert: bob's in-packets did NOT bump ──────────────────
    // Before fix: mid relays the garbage; bob's `on_udp_recv` runs,
    // SPTPS decrypt fails, but `in_packets` bumps in `dispatch_
    // tunnel_outputs`? No — `in_packets` bumps only on successful
    // SPTPS Record. BUT: bob's stderr would have "Failed to decode
    // UDP packet from alice" AND mid's stderr would have "Relaying
    // UDP packet from alice to bob" instead of the gate line. The
    // counter check is belt-and-braces; the stderr check is the
    // primary assertion.
    let b_nodes_after = bob_ctl.dump(3);
    let bob_in_after = node_in_packets(&b_nodes_after, "alice");
    assert_eq!(
        bob_in_after, bob_in_before,
        "bob's in-packet count for alice bumped from a spoofed packet; \
         mid relayed unauthenticated traffic"
    );

    // ─── assert: mid logged the gate ────────────────────────────
    drop(alice_ctl);
    drop(bob_ctl);
    drop(mid_ctl);
    let _ = mid_child.kill();
    let _ = bob_child.kill();
    let mid_stderr = drain_stderr(mid_child);
    let _bob_stderr = drain_stderr(bob_child);
    let _alice_stderr = drain_stderr(alice_child);
    assert!(
        mid_stderr.contains("unauthenticated UDP sender"),
        "mid should drop the spoofed relay at the gate; stderr:\n{mid_stderr}"
    );
    // Negative assertion: mid did NOT log a relay forward for the
    // spoof. The `three_daemon_relay` test proves legitimate relay
    // STILL works (the gate doesn't break the happy path).
    // Count "Relaying UDP packet from alice to bob" lines: a
    // legitimate test wouldn't trigger this (alice never sends data
    // here — no device, no kick). Any such line is the spoof.
    assert!(
        !mid_stderr.contains("Relaying UDP packet from alice to bob"),
        "mid relayed the spoofed packet; gate failed; stderr:\n{mid_stderr}"
    );
}

/// Gap audit `bcc5c3e3`: `Forwarding = off` was parsed (`daemon.
/// rs:1244`) but never read in `dispatch_route_result`. An operator
/// who set it to opt out of being a transit relay got transit
/// traffic anyway.
///
/// ## Shape
///
/// alice ── mid ── bob, hub-and-spoke. mid has `Forwarding =
/// off`. alice's `hosts/mid` claims `Subnet = 10.0.0.0/24` (alice
/// is `StrictSubnets` so she ignores bob's gossiped /32 and
/// believes mid owns the whole /24). alice tunnels 10.0.0.2 TO
/// MID. mid decrypts → `route_packet(..., Some(alice))` → routes
/// to bob (mid DOES have bob's /32 from gossip) → the `FMODE_OFF`
/// gate fires.
///
/// Why this contortion: the simpler `three_daemon_relay` shape
/// (alice tunnels TO BOB, mid relays at the UDP layer) never
/// calls mid's `route_packet` — mid forwards opaque ciphertext.
/// The forwarding gate is L3 forwarding ONLY. Forcing alice
/// to encapsulate FOR mid is what makes mid decrypt-then-route.
///
/// Before fix: bob receives the packet (gate never fires).
/// After fix: bob receives nothing; mid logs the drop.
#[test]
fn three_daemon_forwarding_off_drops_transit() {
    let tmp = tmp!("fmode-off");
    // alice: StrictSubnets so she ignores bob's gossiped subnet
    // and routes purely off her hosts/ preloads (mid's /24).
    let alice = Node::new(tmp.path(), "alice", 0xAF).with_conf("StrictSubnets = yes\n");
    // mid: Forwarding = off. The whole point.
    let mid = Node::new(tmp.path(), "mid", 0xCF).with_conf("Forwarding = off\n");
    let bob = Node::new(tmp.path(), "bob", 0xBF);

    let (alice_tun, alice_far) = sockpair_datagram();
    let (bob_tun, bob_far) = sockpair_datagram();

    // mid: hub. dummy device, no subnet, no ConnectTo.
    mid.write_config_multi(&[&alice, &bob], &[], None, None);
    // alice: ConnectTo=mid, owns 10.0.0.1/32, fd device.
    alice.write_config_multi(
        &[&mid, &bob],
        &["mid"],
        Some(alice_far.as_raw_fd()),
        Some("10.0.0.1/32"),
    );
    // bob: ConnectTo=mid, owns 10.0.0.2/32, fd device.
    bob.write_config_multi(
        &[&mid, &alice],
        &["mid"],
        Some(bob_far.as_raw_fd()),
        Some("10.0.0.2/32"),
    );

    // alice's hosts/mid: claim 10.0.0.0/24. With StrictSubnets,
    // `load_all_nodes` preloads this; bob's gossiped /32 is
    // rejected (`:116-122` gate). alice's longest-prefix match
    // for 10.0.0.2 → mid. write_config_multi only writes pubkey,
    // so append.
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(alice.confbase.join("hosts").join("mid"))
            .unwrap();
        writeln!(f, "Subnet = 10.0.0.0/24").unwrap();
        // alice's StrictSubnets needs her OWN subnet authorized
        // too (load_all_nodes preloads from hosts/alice, but
        // write_config_multi already wrote that one).
    }

    // ─── spawn: mid first ────────────────────────────────────────
    // mid runs at debug so we can assert the gate's log line.
    let mut mid_child = tincd_at(&mid.confbase, &mid.pidfile, &mid.socket)
        .env("RUST_LOG", "tincd=debug")
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mid");
    assert!(
        wait_for_file(&mid.socket),
        "mid setup failed; stderr:\n{}",
        drain_stderr(mid_child)
    );
    let mut bob_child = bob.spawn_with_fd(&bob_far);
    if !wait_for_file(&bob.socket) {
        let _ = mid_child.kill();
        panic!("bob setup failed; stderr:\n{}", drain_stderr(bob_child));
    }
    drop(bob_far);
    let alice_child = alice.spawn_with_fd(&alice_far);
    if !wait_for_file(&alice.socket) {
        let _ = mid_child.kill();
        let _ = bob_child.kill();
        panic!("alice setup failed; stderr:\n{}", drain_stderr(alice_child));
    }
    drop(alice_far);

    let mut alice_ctl = alice.ctl();
    let mut mid_ctl = mid.ctl();

    // ─── wait: mesh up, mid knows bob's subnet ───────────────────
    poll_until(Duration::from_secs(10), || {
        let m = mid_ctl.dump(6);
        (has_active_peer(&m, "alice") && has_active_peer(&m, "bob")).then_some(())
    });
    // mid must learn bob's /32 (mid is NOT strictsubnets) so it
    // routes the decrypted packet to bob (otherwise mid would
    // return Unreachable and the gate never fires).
    poll_until(Duration::from_secs(5), || {
        let m = mid_ctl.dump(5);
        has_subnet(&m, "10.0.0.2", "bob").then_some(())
    });
    // alice's view: mid owns the /24, bob's /32 rejected. So
    // 10.0.0.2 → Forward{to: mid}. /24 prints with prefix.
    poll_until(Duration::from_secs(5), || {
        let a = alice_ctl.dump(5);
        has_subnet(&a, "10.0.0.0/24", "mid").then_some(())
    });
    let a_subnets = alice_ctl.dump(5);
    assert!(
        !has_subnet(&a_subnets, "10.0.0.2", "bob"),
        "alice's StrictSubnets should reject bob's /32; got: {a_subnets:?}"
    );

    // ─── kick the alice↔mid tunnel ───────────────────────────────
    // alice routes 10.0.0.2 → mid → REQ_KEY for mid → per-tunnel
    // SPTPS handshake. validkey settles.
    let kick = mk_ipv4_pkt([10, 0, 0, 1], [10, 0, 0, 2], b"kick");
    write_fd(&alice_tun, &kick);
    poll_until(Duration::from_secs(10), || {
        let a = alice_ctl.dump(3);
        node_status(&a, "mid")
            .is_some_and(|s| s & 0x02 != 0)
            .then_some(())
    });

    // ─── THE PROBE ────────────────────────────────────────────────
    // alice encrypts for mid → mid decrypts → route_packet(...,
    // Some(alice)) → route_ipv4 → Forward{to: bob} → gate fires.
    // Spam (each iteration drives try_tx); drain bob's TUN. The
    // negative assertion: bob NEVER sees the payload.
    let payload = b"transit-forbidden";
    let probe = mk_ipv4_pkt([10, 0, 0, 1], [10, 0, 0, 2], payload);
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut bob_got_transit = false;
    let mut alice_got_unreach = false;
    while Instant::now() < deadline {
        write_fd(&alice_tun, &probe);
        while let Some(r) = read_fd_nb(&bob_tun) {
            // Any frame on bob's TUN ending in our payload ⇒
            // mid forwarded transit traffic. Gate failed.
            if r.ends_with(payload) {
                bob_got_transit = true;
            }
        }
        // mid's ICMP DEST_UNREACH must come back over the mesh to
        // alice. FdTun strips eth: [0]=0x45, [9]=1 (ICMP), [20]=3.
        while let Some(r) = read_fd_nb(&alice_tun) {
            if r.first() == Some(&0x45) && r.get(9) == Some(&1) && r.get(20) == Some(&3) {
                alice_got_unreach = true;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    drop(alice_ctl);
    drop(mid_ctl);
    drop(alice_tun);
    drop(bob_tun);
    let _ = mid_child.kill();
    let _ = bob_child.kill();
    let mid_stderr = drain_stderr(mid_child);
    let _ = drain_stderr(bob_child);
    let _ = drain_stderr(alice_child);

    assert!(
        !bob_got_transit,
        "Forwarding=off failed: bob received transit traffic via mid; \
         mid stderr:\n{mid_stderr}"
    );
    // mid should have logged the gate firing. The kick + probes
    // both hit it (≥2 sends post-validkey).
    assert!(
        mid_stderr.contains("Forwarding=off"),
        "mid should log the FMODE_OFF gate firing; stderr:\n{mid_stderr}"
    );
    assert!(
        alice_got_unreach,
        "alice should receive mid's ICMP DEST_UNREACH; mid stderr:\n{mid_stderr}"
    );
}
