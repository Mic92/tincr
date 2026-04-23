use std::os::fd::AsRawFd;
use std::time::Duration;

use super::common::*;
use super::fd_tunnel::*;
use super::node::*;

/// **THE FIRST PACKET.** End-to-end: alice's TUN → bob's TUN.
///
/// Full chain: `IoWhat::Device` → `route()` → `Forward{to: bob}`
/// → `send_sptps_packet` → (no validkey yet) `send_req_key` →
/// `REQ_KEY` over the meta-conn SPTPS → bob's `on_req_key` →
/// responder `Sptps::start` → `ANS_KEY` back → alice's `on_ans_key`
/// → `HandshakeDone` → validkey set. Then alice's NEXT TUN read →
/// `send_sptps_packet` → `sptps.send_record(0, ip_bytes)` →
/// `Output::Wire` → `send_sptps_data` UDP branch → `[nullid][src]
/// [ct]` → `sendto(bob_udp)`. Bob's `on_udp_recv` → strip prefix →
/// `lookup_node_id(src)` = alice → `sptps.receive(ct)` → `Output::
/// Record{type=0, ip_bytes}` → `receive_sptps_record` → re-prepend
/// ethertype → `route()` → `Forward{to: myself}` → `device.write`.
///
/// ## The device rig
///
/// `socketpair(AF_UNIX, SOCK_SEQPACKET)` for each daemon. SEQPACKET
/// gives datagram semantics (one `read()` = one packet, like a real
/// TUN fd) over a connection-oriented unix socket. The test holds
/// one end; the daemon's `FdTun` wraps the other. `FdTun::read()`
/// does the `+14` ethernet-header synthesis from the IP version
/// nibble, so we write RAW IP bytes and the daemon's `route()` sees
/// a proper ethernet frame.
///
/// `O_NONBLOCK` on the daemon's end: `FdTun` doesn't set it; the
/// daemon's `on_device_read` loops until `WouldBlock`, so blocking
/// fds would hang the loop. We set it in the test before passing
/// the fd in. (C tincd's TUN open does `O_NONBLOCK` via the `ioctl`
/// flow; the fd-device path doesn't — the parent is supposed to.
/// We're the parent.)
///
/// ## The first packet is dropped
///
/// `send_sptps_packet:684` (`if(!validkey) return`). The C buffers
/// nothing; the first packet kicks `send_req_key` and is dropped. We
/// wait for `validkey` (poll `dump nodes` for status bit 1), THEN
/// send the packet that actually crosses.
#[test]
#[expect(clippy::similar_names)] // at_out_* vs bt_in_*: parallel names, test compares them
fn first_packet_across_tunnel() {
    let tmp = tmp!("first-pkt");
    let alice = Node::new(tmp.path(), "alice", 0xA7);
    let bob = Node::new(tmp.path(), "bob", 0xB7);

    // ─── socketpairs: one per daemon ────────────────────────────
    // [0] = test end (we read/write IP packets), [1] = daemon end
    // (FdTun wraps it). SOCK_SEQPACKET for datagram boundaries.
    let (alice_tun, alice_far) = sockpair_datagram();
    let (bob_tun, bob_far) = sockpair_datagram();

    // ─── configs: subnets pin route() decisions ────────────────
    // alice owns 10.0.0.1/32; bob owns 10.0.0.2/32. A packet to
    // 10.0.0.2 routes Forward{to: bob} on alice's side, then
    // Forward{to: myself} on bob's side.
    let bob = bob.fd(bob_far.as_raw_fd()).subnet("10.0.0.2/32");
    let alice = alice.fd(alice_far.as_raw_fd()).subnet("10.0.0.1/32");
    bob.write_config(&alice, false);
    alice.write_config(&bob, true);

    // ─── spawn ──────────────────────────────────────────────────
    let mut bob_child = bob.spawn_with_fd(&bob_far);
    assert!(
        wait_for_file(&bob.socket),
        "bob setup failed; stderr:\n{}",
        drain_stderr(bob_child)
    );
    // Close OUR copy of bob's daemon-end fd. The child has its own
    // (dup'd by fork). If we keep ours open, bob's read() never
    // sees EOF and the test process leaks an fd. Same for alice.
    drop(bob_far);

    let alice_child = alice.spawn_with_fd(&alice_far);
    if !wait_for_file(&alice.socket) {
        let _ = bob_child.kill();
        panic!("alice setup failed; stderr:\n{}", drain_stderr(alice_child));
    }
    drop(alice_far);

    // ─── wait for meta-conn handshake (chunk-6 milestone) ────────
    let mut alice_ctl = alice.ctl();
    let mut bob_ctl = bob.ctl();

    // Status bit 4 (reachable) = both daemons completed ACK +
    // graph(). `dump nodes` row format: status is body token 10.
    poll_until(Duration::from_secs(10), || {
        let a = alice_ctl.dump(3);
        let b = bob_ctl.dump(3);
        let a_ok = node_status(&a, "bob").is_some_and(|s| s & 0x10 != 0);
        let b_ok = node_status(&b, "alice").is_some_and(|s| s & 0x10 != 0);
        if a_ok && b_ok { Some(()) } else { None }
    });

    // ─── kick the per-tunnel handshake ──────────────────────────
    // Send one packet to alice's TUN. `route()` says Forward{to:
    // bob}; `send_sptps_packet`'s PACKET 17 short-circuit fires
    // (direct conn, minmtu=0) so the kick is DELIVERED, not dropped.
    // `!validkey && !connection`; with a direct conn validkey
    // doesn't matter. The follow-up `try_tx` kicks
    // `send_req_key` for the UDP path.
    //
    // Packet shape for FdTun: RAW IPv4 bytes (no ether header,
    // no tun_pi). `FdTun::read` writes them at `+14` and sets
    // ethertype from byte-0 nibble. dst at IP header offset 16.
    let kick_pkt = mk_ipv4_pkt([10, 0, 0, 1], [10, 0, 0, 2], b"kick");
    write_fd(&alice_tun, &kick_pkt);

    // ─── wait for validkey ──────────────────────────────────────
    // Status bit 1 (validkey) = per-tunnel SPTPS handshake done.
    // BOTH sides need it (bob is responder; his `HandshakeDone`
    // fires when he gets alice's SIG via ANS_KEY). The handshake
    // is 3 round-trips over the meta-conn SPTPS; loopback is
    // sub-millisecond per RTT.
    // catch_unwind: on timeout, dump BOTH daemons' stderr. Without
    // this, the test panics with "poll timed out" and the captured
    // stderr is lost (Child::stderr is piped, never read).
    let validkey_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        poll_until(Duration::from_secs(5), || {
            let a = alice_ctl.dump(3);
            let b = bob_ctl.dump(3);
            let a_ok = node_status(&a, "bob").is_some_and(|s| s & 0x02 != 0);
            let b_ok = node_status(&b, "alice").is_some_and(|s| s & 0x02 != 0);
            if a_ok && b_ok { Some(()) } else { None }
        });
    }));
    if validkey_result.is_err() {
        let _ = bob_child.kill();
        let bs = drain_stderr(bob_child);
        let asd = drain_stderr(alice_child);
        panic!("validkey timed out;\n=== alice ===\n{asd}\n=== bob ===\n{bs}");
    }

    // Drain the kick: PACKET 17 delivered it (direct conn bypasses
    // validkey). Don't let it shadow THE PACKET assert below.
    let kicked = poll_until(Duration::from_secs(5), || read_fd_nb(&bob_tun));
    assert_eq!(kicked, kick_pkt, "kick packet went via PACKET 17");

    // ─── THE PACKET ─────────────────────────────────────────────
    // Now validkey is set. Send a packet; it crosses.
    let payload = b"hello from alice";
    let ip_pkt = mk_ipv4_pkt([10, 0, 0, 1], [10, 0, 0, 2], payload);
    write_fd(&alice_tun, &ip_pkt);

    // Read from bob's TUN. `FdTun::write` strips the 14-byte
    // ether header (writes `data[14..]`); we get RAW IP bytes.
    let recv = poll_until(Duration::from_secs(5), || read_fd_nb(&bob_tun));

    // The IP packet round-trips byte-exact (the 14-byte ether
    // header is added by alice's FdTun::read, stripped by
    // alice's `send_sptps_packet`, re-added by bob's `receive_
    // sptps_record`, stripped by bob's `FdTun::write`).
    assert_eq!(
        recv,
        ip_pkt,
        "packet body mismatch; sent {} bytes, got {} bytes",
        ip_pkt.len(),
        recv.len()
    );
    // The payload is at the IP-header offset (20 bytes).
    assert_eq!(&recv[20..], payload);

    // ─── traffic counters bumped ────────────────────────────────
    // alice: out_packets/out_bytes for bob ≥ 1. bob: in_packets/
    // in_bytes for alice ≥ 1. The kick packet also counts (it was
    // counted at `send_packet:1582` BEFORE the validkey gate at
    // `send_sptps_packet:684`). Row tail: `... in_p in_b out_p out_b`.
    let node_traffic = |rows: &[String], name: &str| -> Option<(u64, u64, u64, u64)> {
        rows.iter().find_map(|r| {
            let body = r.strip_prefix("18 3 ")?;
            let toks: Vec<&str> = body.split_whitespace().collect();
            if toks.first() != Some(&name) {
                return None;
            }
            let n = toks.len();
            Some((
                toks[n - 4].parse().ok()?,
                toks[n - 3].parse().ok()?,
                toks[n - 2].parse().ok()?,
                toks[n - 1].parse().ok()?,
            ))
        })
    };
    let a_nodes = alice_ctl.dump(3);
    let b_nodes = bob_ctl.dump(3);
    let (_, _, a_out_p, a_out_b) = node_traffic(&a_nodes, "bob").expect("alice's bob row");
    let (b_in_p, b_in_b, _, _) = node_traffic(&b_nodes, "alice").expect("bob's alice row");
    assert!(
        a_out_p >= 1 && a_out_b >= ip_pkt.len() as u64,
        "alice out counters: {a_out_p}/{a_out_b}; nodes: {a_nodes:?}"
    );
    assert!(
        b_in_p >= 1 && b_in_b >= ip_pkt.len() as u64,
        "bob in counters: {b_in_p}/{b_in_b}; nodes: {b_nodes:?}"
    );

    // ─── REQ_DUMP_TRAFFIC ────────────────────────────────────────
    // Format-is-contract: `"18 13 NAME in_p in_b out_p out_b"`. Same counters as the dump-nodes tail
    // (both read `n->in_packets` etc) so cross-check exact values.
    // Row count = node count (C iterates `node_tree`: includes
    // myself).
    let traffic_row = |rows: &[String], name: &str| -> Option<(u64, u64, u64, u64)> {
        rows.iter().find_map(|r| {
            let body = r.strip_prefix("18 13 ")?;
            let toks: Vec<&str> = body.split_whitespace().collect();
            if toks.len() != 5 || toks[0] != name {
                return None;
            }
            Some((
                toks[1].parse().ok()?,
                toks[2].parse().ok()?,
                toks[3].parse().ok()?,
                toks[4].parse().ok()?,
            ))
        })
    };
    let a_traffic = alice_ctl.dump(13);
    let b_traffic = bob_ctl.dump(13);
    assert_eq!(a_traffic.len(), 2, "alice traffic rows: {a_traffic:?}");
    assert_eq!(b_traffic.len(), 2, "bob traffic rows: {b_traffic:?}");
    let (_, _, at_out_p, at_out_b) = traffic_row(&a_traffic, "bob").expect("alice traffic bob");
    let (bt_in_p, bt_in_b, _, _) = traffic_row(&b_traffic, "alice").expect("bob traffic alice");
    assert_eq!(
        (at_out_p, at_out_b),
        (a_out_p, a_out_b),
        "dump_traffic == dump_nodes tail"
    );
    assert_eq!((bt_in_p, bt_in_b), (b_in_p, b_in_b));
    // myself row: alice's `in_packets` = TUN reads. She read the
    // kick + the real packet → ≥2. bob's `out_packets` = TUN
    // writes; he wrote at least the real packet.
    let (am_in_p, _, _, _) = traffic_row(&a_traffic, "alice").expect("alice myself");
    assert!(am_in_p >= 2, "alice myself in: {am_in_p}; {a_traffic:?}");
    let (_, _, bm_out_p, _) = traffic_row(&b_traffic, "bob").expect("bob myself");
    assert!(bm_out_p >= 1, "bob myself out: {bm_out_p}; {b_traffic:?}");

    // udp_confirmed (bit 7) is NOT asserted: with the
    // `data.len() > minmtu(=0)` gate now wired, → PACKET 17 over
    // the meta-conn, not UDP. minmtu only goes nonzero after PMTU
    // converges (separate from validkey). The C would do the same.
    // The previous assert relied on the PACKET 17 send path being
    // stubbed (every pre-PMTU packet went UDP-SPTPS instead).

    // ─── stderr: the SPTPS-key-exchange-successful log ──────────
    drop(alice_ctl);
    drop(bob_ctl);
    drop(alice_tun);
    drop(bob_tun);
    let _ = bob_child.kill();
    let bob_stderr = drain_stderr(bob_child);
    let alice_stderr = drain_stderr(alice_child);
    assert!(
        alice_stderr.contains("SPTPS key exchange with bob successful"),
        "alice's per-tunnel HandshakeDone; stderr:\n{alice_stderr}"
    );
    assert!(
        bob_stderr.contains("SPTPS key exchange with alice successful"),
        "bob's per-tunnel HandshakeDone; stderr:\n{bob_stderr}"
    );
}

/// Per-tunnel compression negotiation. alice asks for zlib-6, bob
/// for LZ4. Each advertises its level in `ANS_KEY` (`net_packet.c:
/// 996`); the peer stores it as `outcompression` (`protocol_key.c:
/// 545`) and compresses TOWARDS them at that level. The compressed
/// SPTPS record carries `PKT_COMPRESSED`; receiver decompresses at
/// `incompression` (its OWN level, copied at handshake).
///
/// Asymmetry is the point: alice→bob traffic is LZ4-compressed (bob
/// asked for 12); bob→alice is zlib-6 (alice asked for 6). Proves
/// the per-tunnel level is read from the right field on each path.
///
/// Compressible payload: 200 bytes of zeros. Both zlib and LZ4
/// crush this; `compressed.len() < payload.len()` triggers and
/// `PKT_COMPRESSED` is set. With an incompressible payload (random
/// bytes), compression backs off to raw and the bit stays clear —
/// also valid, but doesn't exercise the decompress path. The KAT in
/// `compress.rs` proves codec correctness; THIS proves negotiation
/// + bit handling + per-tunnel level dispatch.
#[test]
fn compression_roundtrip() {
    let tmp = tmp!("compress");
    // Compression is HOST-tagged but our `setup` reads from the
    // merged config tree (host file is merged into tinc.conf at
    // setup). Put it in tinc.conf via `with_conf`.
    let alice = Node::new(tmp.path(), "alice", 0xAC).with_conf("Compression = 6\n");
    let bob = Node::new(tmp.path(), "bob", 0xBC).with_conf("Compression = 12\n");

    let (alice_tun, alice_far) = sockpair_datagram();
    let (bob_tun, bob_far) = sockpair_datagram();

    let bob = bob.fd(bob_far.as_raw_fd()).subnet("10.0.0.2/32");
    let alice = alice.fd(alice_far.as_raw_fd()).subnet("10.0.0.1/32");
    bob.write_config(&alice, false);
    alice.write_config(&bob, true);

    let mut bob_child = bob.spawn_with_fd(&bob_far);
    assert!(
        wait_for_file(&bob.socket),
        "bob setup failed; stderr:\n{}",
        drain_stderr(bob_child)
    );
    drop(bob_far);

    let alice_child = alice.spawn_with_fd(&alice_far);
    if !wait_for_file(&alice.socket) {
        let _ = bob_child.kill();
        panic!("alice setup failed; stderr:\n{}", drain_stderr(alice_child));
    }
    drop(alice_far);

    let mut alice_ctl = alice.ctl();
    let mut bob_ctl = bob.ctl();

    // ─── reachable + validkey, same dance as first_packet ────────
    poll_until(Duration::from_secs(10), || {
        let a = alice_ctl.dump(3);
        let b = bob_ctl.dump(3);
        let a_ok = node_status(&a, "bob").is_some_and(|s| s & 0x10 != 0);
        let b_ok = node_status(&b, "alice").is_some_and(|s| s & 0x10 != 0);
        if a_ok && b_ok { Some(()) } else { None }
    });

    let kick_pkt = mk_ipv4_pkt([10, 0, 0, 1], [10, 0, 0, 2], b"kick");
    write_fd(&alice_tun, &kick_pkt);
    // The kick goes via PACKET 17 (direct conn, minmtu=0). Drain it
    // so it doesn't shadow the round-trip read below. Compression
    // doesn't apply on PACKET 17 (raw frame, no PKT_COMPRESSED bit).
    let _ = poll_until(Duration::from_secs(5), || read_fd_nb(&bob_tun));

    let validkey_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        poll_until(Duration::from_secs(5), || {
            let a = alice_ctl.dump(3);
            let b = bob_ctl.dump(3);
            let a_ok = node_status(&a, "bob").is_some_and(|s| s & 0x02 != 0);
            let b_ok = node_status(&b, "alice").is_some_and(|s| s & 0x02 != 0);
            if a_ok && b_ok { Some(()) } else { None }
        });
    }));
    if validkey_result.is_err() {
        let _ = bob_child.kill();
        let bs = drain_stderr(bob_child);
        let asd = drain_stderr(alice_child);
        panic!("validkey timed out;\n=== alice ===\n{asd}\n=== bob ===\n{bs}");
    }

    // ─── negotiated levels in dump_nodes ──────────────────────────
    // The `compression` column (body token 8) is `n->outcompression`
    // — the level the PEER asked for. alice's row for bob = 12 (LZ4,
    // bob's `Compression = 12`); bob's row for alice = 6 (zlib).
    let node_compression = |rows: &[String], name: &str| -> Option<u8> {
        rows.iter().find_map(|r| {
            let body = r.strip_prefix("18 3 ")?;
            let toks: Vec<&str> = body.split_whitespace().collect();
            if toks.first() != Some(&name) {
                return None;
            }
            // Body tokens: name id host "port" port cipher digest
            // maclen compression(idx 8) options status ...
            toks.get(8)?.parse().ok()
        })
    };
    let a_nodes = alice_ctl.dump(3);
    let b_nodes = bob_ctl.dump(3);
    assert_eq!(
        node_compression(&a_nodes, "bob"),
        Some(12),
        "alice should compress towards bob at LZ4 (bob's ask); rows:\n{a_nodes:#?}"
    );
    assert_eq!(
        node_compression(&b_nodes, "alice"),
        Some(6),
        "bob should compress towards alice at zlib-6; rows:\n{b_nodes:#?}"
    );

    // ─── alice → bob: LZ4-compressed on the wire ──────────────────
    // 200 zeros: LZ4 crushes to ~20 bytes. `compressed.len() <
    // origlen` triggers; PKT_COMPRESSED is set; bob decompresses
    // at incompression=12.
    let payload = vec![0u8; 200];
    let ip_pkt = mk_ipv4_pkt([10, 0, 0, 1], [10, 0, 0, 2], &payload);
    write_fd(&alice_tun, &ip_pkt);

    let recv = poll_until(Duration::from_secs(5), || read_fd_nb(&bob_tun));
    assert_eq!(
        recv,
        ip_pkt,
        "LZ4 round-trip mismatch; sent {} bytes, got {} bytes",
        ip_pkt.len(),
        recv.len()
    );

    // ─── bob → alice: zlib-6 compressed on the wire ───────────────
    // The reverse direction. Bob compresses at 6 (alice's ask);
    // alice decompresses at incompression=6.
    let ip_pkt2 = mk_ipv4_pkt([10, 0, 0, 2], [10, 0, 0, 1], &payload);
    write_fd(&bob_tun, &ip_pkt2);

    let recv2 = poll_until(Duration::from_secs(5), || read_fd_nb(&alice_tun));
    assert_eq!(
        recv2,
        ip_pkt2,
        "zlib round-trip mismatch; sent {} bytes, got {} bytes",
        ip_pkt2.len(),
        recv2.len()
    );

    drop(alice_ctl);
    drop(bob_ctl);
    drop(alice_tun);
    drop(bob_tun);
    let _ = bob_child.kill();
    let _ = drain_stderr(bob_child);
    let _ = drain_stderr(alice_child);
}

/// Bug audit `deef1268` regression: `RouteResult::Unreachable` for
/// an IPv6 destination must build an `ICMPv6` packet, not `ICMPv4`.
///
/// Single-daemon test: alice with NO IPv6 subnet, send an IPv6
/// packet to her TUN, read back the ICMP unreachable. Before fix:
/// `dispatch_route_result::Unreachable` unconditionally called
/// `build_v4_unreachable`, producing an ICMPv4-shaped frame with
/// type=1 (unassigned in v4) and bytes from the IPv6 header
/// reinterpreted as IPv4. After fix: ethertype-dispatched, gets
/// proper `ICMPv6` (next-header=58, type=1 `DST_UNREACH`).
#[test]
fn ipv6_unreachable_builds_icmpv6() {
    let tmp = tmp!("v6-unreach");
    let alice = Node::new(tmp.path(), "alice", 0xA5);
    let bob = Node::new(tmp.path(), "bob", 0xB5);

    let (alice_tun, alice_far) = sockpair_datagram();

    // alice has NO IPv6 subnet — any IPv6 dst routes Unreachable.
    // bob is just here so alice has a peer (config requires it).
    let alice = alice.fd(alice_far.as_raw_fd()).subnet("10.0.0.1/32");
    bob.write_config(&alice, false);
    alice.write_config(&bob, true);

    let mut bob_child = bob.spawn();
    assert!(
        wait_for_file(&bob.socket),
        "bob setup failed; stderr:\n{}",
        drain_stderr(bob_child)
    );

    let alice_child = alice.spawn_with_fd(&alice_far);
    if !wait_for_file(&alice.socket) {
        let _ = bob_child.kill();
        panic!("alice setup failed; stderr:\n{}", drain_stderr(alice_child));
    }
    drop(alice_far);

    // ─── craft a minimal IPv6 packet ───────────────────────────
    // FdTun reads RAW IP bytes (no ether, no tun_pi); it synthesizes
    // the ether header from byte 0's version nibble. So we send a
    // 40-byte IPv6 header + payload.
    //
    // `route_ipv6` reads dst at IP6 hdr offset 24..40.
    // No subnet for `fd00::99` → Unreachable{ICMP6_DST_UNREACH=1,
    // ICMP6_DST_UNREACH_ADDR=3}.
    let mut ipv6 = Vec::with_capacity(40 + 8);
    ipv6.push(0x60); // version=6, traffic class hi nibble=0
    ipv6.extend_from_slice(&[0, 0, 0]); // tc lo + flow label
    ipv6.extend_from_slice(&8u16.to_be_bytes()); // payload len
    ipv6.push(17); // next header = UDP (arbitrary)
    ipv6.push(64); // hop limit
    // src: fd00::1
    ipv6.extend_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    // dst: fd00::99 (no owner)
    ipv6.extend_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99]);
    ipv6.extend_from_slice(&[0; 8]); // payload

    write_fd(&alice_tun, &ipv6);

    // ─── read back the ICMP reply ──────────────────────────────
    // FdTun::write strips the 14-byte ether header. We get raw IP.
    let reply = poll_until(Duration::from_secs(5), || read_fd_nb(&alice_tun));

    // ─── assert: it's ICMPv6 ───────────────────────────────────
    // IPv6 header: byte 0 = 0x6?, byte 6 = next-header.
    // ICMPv6 next-header = 58 (RFC 4443).
    // ICMPv6 message starts at byte 40: type, code, checksum.
    assert!(
        reply.len() >= 48,
        "reply too short for IPv6 + ICMPv6: {} bytes",
        reply.len()
    );
    assert_eq!(
        reply[0] >> 4,
        6,
        "reply is not IPv6; got version nibble {} (full: {:02x?})",
        reply[0] >> 4,
        &reply[..reply.len().min(16)]
    );
    assert_eq!(
        reply[6], 58,
        "reply next-header is not ICMPv6 (58); got {} \
         (before fix: ICMPv4-shaped garbage)",
        reply[6]
    );
    // ICMPv6 type 1 = DST_UNREACH (RFC 4443).
    assert_eq!(
        reply[40], 1,
        "ICMPv6 type should be DST_UNREACH (1); got {}",
        reply[40]
    );
    // ICMPv6 code 3 = ADDR (no subnet found).
    assert_eq!(
        reply[41], 3,
        "ICMPv6 code should be DST_UNREACH_ADDR (3); got {}",
        reply[41]
    );
    // The reply's dst should be the original src (fd00::1).
    assert_eq!(
        &reply[24..40],
        &[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        "reply dst should be original src"
    );

    drop(alice_tun);
    let _ = bob_child.kill();
    let _ = bob_child.wait();
    let _alice_stderr = drain_stderr(alice_child);
}

/// **`KeyExpire` timer forces SPTPS rekey.** Gap-audit `bcc5c3e3`:
/// timer was defined
/// (`TimerWhat::KeyExpire`) but never armed; `unreachable!()` in the
/// dispatch arm. SPTPS sessions lived forever on one key. The
/// ChaCha20-Poly1305 nonce is `outseqno: u32` with no wrap check
/// (`state.rs:403`); at sustained throughput nonce
/// reuse is hours away.
///
/// `KeyExpire = 1` so the timer fires in-test. After the rekey, send
/// a packet and prove it still crosses (the new key works).
///
/// C-nolegacy has the same bug (`timeout_add` is `#ifndef
/// DISABLE_LEGACY`). This test would fail against `.#tincd-c` too.
#[test]
fn keyexpire_forces_rekey() {
    let tmp = tmp!("keyexpire");
    let alice = Node::new(tmp.path(), "alice", 0xAE).with_conf("KeyExpire = 1\n");
    let bob = Node::new(tmp.path(), "bob", 0xBE).with_conf("KeyExpire = 1\n");

    let (alice_tun, alice_far) = sockpair_datagram();
    let (bob_tun, bob_far) = sockpair_datagram();

    let bob = bob.fd(bob_far.as_raw_fd()).subnet("10.0.0.2/32");
    let alice = alice.fd(alice_far.as_raw_fd()).subnet("10.0.0.1/32");
    bob.write_config(&alice, false);
    alice.write_config(&bob, true);

    let mut bob_child = bob.spawn_with_fd(&bob_far);
    assert!(
        wait_for_file(&bob.socket),
        "bob setup failed; stderr:\n{}",
        drain_stderr(bob_child)
    );
    drop(bob_far);

    let alice_child = alice.spawn_with_fd(&alice_far);
    if !wait_for_file(&alice.socket) {
        let _ = bob_child.kill();
        panic!("alice setup failed; stderr:\n{}", drain_stderr(alice_child));
    }
    drop(alice_far);

    let mut alice_ctl = alice.ctl();
    let mut bob_ctl = bob.ctl();

    // Wait for reachable.
    poll_until(Duration::from_secs(10), || {
        let a = alice_ctl.dump(3);
        let b = bob_ctl.dump(3);
        let a_ok = node_status(&a, "bob").is_some_and(|s| s & 0x10 != 0);
        let b_ok = node_status(&b, "alice").is_some_and(|s| s & 0x10 != 0);
        if a_ok && b_ok { Some(()) } else { None }
    });

    // Kick the per-tunnel handshake (first packet starts REQ_KEY).
    let kick = mk_ipv4_pkt([10, 0, 0, 1], [10, 0, 0, 2], b"kick");
    write_fd(&alice_tun, &kick);

    // Wait for validkey both sides.
    let vk = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        poll_until(Duration::from_secs(5), || {
            let a = alice_ctl.dump(3);
            let b = bob_ctl.dump(3);
            let a_ok = node_status(&a, "bob").is_some_and(|s| s & 0x02 != 0);
            let b_ok = node_status(&b, "alice").is_some_and(|s| s & 0x02 != 0);
            if a_ok && b_ok { Some(()) } else { None }
        });
    }));
    if vk.is_err() {
        let _ = bob_child.kill();
        panic!(
            "validkey timed out;\nalice:\n{}\nbob:\n{}",
            drain_stderr(alice_child),
            drain_stderr(bob_child)
        );
    }

    // Drain the kick (PACKET 17 delivers it via meta-conn).
    let _ = poll_until(Duration::from_secs(5), || read_fd_nb(&bob_tun));

    // ─── wait past KeyExpire (1s) + rekey RTT ──────────────────
    // Timer fires at +1s; `on_keyexpire` → `send_req_key` (fresh
    // handshake, ~ms on loopback).
    std::thread::sleep(Duration::from_secs(2));

    // ─── packet crosses under the NEW key ──────────────────────
    // KeyExpire=1 keeps re-firing; retry the write so it can't land
    // in the brief `!validkey` window.
    let pkt = mk_ipv4_pkt([10, 0, 0, 1], [10, 0, 0, 2], b"post-rekey");
    let recv = poll_until(Duration::from_secs(5), || {
        write_fd(&alice_tun, &pkt);
        read_fd_nb(&bob_tun)
    });
    assert_eq!(recv, pkt, "post-rekey packet body mismatch");

    // ─── stderr: the timer fired, the rekey happened ───────────
    drop(alice_ctl);
    drop(bob_ctl);
    drop(alice_tun);
    drop(bob_tun);
    let _ = bob_child.kill();
    let bob_stderr = drain_stderr(bob_child);
    let alice_stderr = drain_stderr(alice_child);

    // The on_keyexpire log. Proves the timer was armed and fired.
    assert!(
        alice_stderr.contains("Expiring symmetric keys"),
        "alice's keyexpire timer never fired; stderr:\n{alice_stderr}"
    );
    assert!(
        bob_stderr.contains("Expiring symmetric keys"),
        "bob's keyexpire timer never fired; stderr:\n{bob_stderr}"
    );
    assert!(
        alice_stderr
            .matches("SPTPS key exchange with bob successful")
            .count()
            >= 2,
        "alice did not complete a second handshake; stderr:\n{alice_stderr}"
    );
}
