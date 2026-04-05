use std::process::{Command, Stdio};
use std::time::Duration;

use super::common::linux::*;
use super::common::*;
use super::rig::*;

fn tmp(tag: &str) -> TmpGuard {
    TmpGuard::new("netns", tag)
}

/// Real kernel TUN, real ping. Kernel→daemon→SPTPS→UDP→daemon→kernel.
///
/// ## What's proven (vs `first_packet_across_tunnel`)
///
/// 1. **`LinuxTun::open()` TUNSETIFF**: the daemon attaches to a
///    precreated persistent device. Carrier flips from `NO-CARRIER`
///    to `LOWER_UP`. `wait_for_carrier` pins it.
/// 2. **The `vnet_hdr` drain path**: `linux.rs::Tun::drain` reads
///    `[virtio_net_hdr(10)][raw IP]` (`IFF_NO_PI | IFF_VNET_HDR`);
///    no eth header from the kernel. ICMP echo is `gso_type=NONE`,
///    so `drain()` strips the `vnet_hdr` and synthesizes the eth
///    header from the IP version nibble (`0x45` → `ETH_P_IP =
///    0x0800`); `route()` reads that ethertype and dispatches to
///    `route_ipv4`. The socketpair test used `FdTun` which reads at
///    `+14` and synthesizes the same way — but never touches the
///    `Tun::drain` override or the `vnet_hdr` layout.
/// 3. **Kernel checksums + TTL**: ping's ICMP echo has a real
///    checksum; the daemon doesn't touch it (just the route lookup
///    on `dst`); bob's kernel verifies it on receipt and replies.
///    The reply's checksum is also kernel-computed. The socketpair
///    test had a zero checksum that nothing verified.
/// 4. **fd→device binding survives netns move**: bob's daemon stays
///    in the outer netns (127.0.0.1 listeners), bob's TUN moves to
///    the child netns. Daemon writes to its fd; packets land in
///    child kernel's IP stack. The proof-of-concept during dev proved
///    this; the test pins it (ping wouldn't reply otherwise).
#[test]
fn real_tun_ping() {
    let Some(netns) = enter_netns("ping::real_tun_ping") else {
        return;
    };

    let tmp = tmp("ping");
    let alice = Node::new(tmp.path(), "alice", 0xA8, "tinc0", "10.42.0.1/32");
    let bob = Node::new(tmp.path(), "bob", 0xB8, "tinc1", "10.42.0.2/32");

    bob.write_config(&alice, false);
    alice.write_config(&bob, true);

    // ─── spawn ──────────────────────────────────────────────────
    // Bob first (listener); alice has ConnectTo. Same ordering
    // rationale as two_daemons.rs (avoid the 5s retry backoff).
    let mut bob_child = bob.spawn();
    assert!(
        wait_for_file(&bob.socket),
        "bob setup failed; stderr:\n{}",
        drain_stderr(bob_child)
    );

    let alice_child = alice.spawn();
    if !wait_for_file(&alice.socket) {
        let _ = bob_child.kill();
        panic!("alice setup failed; stderr:\n{}", drain_stderr(alice_child));
    }

    // ─── wait for carrier (proves TUNSETIFF fired) ──────────────
    // The precreated devices are `NO-CARRIER` until TUNSETIFF.
    // Daemon's `Tun::open` runs in `Daemon::setup` which finishes
    // before the socket file appears, so usually carrier is
    // already up by now — but the carrier event is async (kernel
    // queues a netlink notification). Poll to be safe.
    assert!(
        wait_for_carrier("tinc0", Duration::from_secs(2)),
        "alice TUNSETIFF didn't bring carrier up; stderr:\n{}",
        drain_stderr(alice_child)
    );
    assert!(
        wait_for_carrier("tinc1", Duration::from_secs(2)),
        "bob TUNSETIFF didn't bring carrier up"
    );

    // ─── move bob's TUN, configure addresses ────────────────────
    // AFTER both daemons attached. The fd binding survives the
    // move; bob's daemon doesn't notice (no event on the fd).
    netns.place_devices();

    // ─── meta-conn handshake ────────────────────────────────────
    // Status bit 4 (reachable) on both → ACK + graph() done. Same
    // poll as first_packet_across_tunnel.
    let mut alice_ctl = alice.ctl();
    let mut bob_ctl = bob.ctl();

    poll_until(Duration::from_secs(10), || {
        let a = alice_ctl.dump(3);
        let b = bob_ctl.dump(3);
        let a_ok = node_status(&a, "bob").is_some_and(|s| s & 0x10 != 0);
        let b_ok = node_status(&b, "alice").is_some_and(|s| s & 0x10 != 0);
        if a_ok && b_ok { Some(()) } else { None }
    });

    // ─── kick the per-tunnel handshake ──────────────────────────
    // First packet hits `send_sptps_packet` with `!validkey` →
    // dropped, but kicks `send_req_key`. ICMP echo is the kick:
    // `ping -c 1 -W 1` sends one, waits 1s, fails. We don't care
    // about THIS ping's exit; it's the validkey trigger.
    let _ = Command::new("ping")
        .args(["-c", "1", "-W", "1", "10.42.0.2"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    // ─── wait for validkey (status bit 1) ───────────────────────
    // Per-tunnel SPTPS done on BOTH sides. catch_unwind: on
    // timeout, dump both daemons' captured stderr (it's piped;
    // never read otherwise).
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

    // ─── THE PING ───────────────────────────────────────────────
    // validkey set. `ping -c 3` sends three echo requests; each
    // one: kernel writes `[vnet_hdr][ICMP]` into tinc0 → alice's
    // `Tun::drain` (gso_type=NONE: strip vnet_hdr, synth eth header
    // from IP version nibble → ethertype 0x0800) → `route()` reads
    // dst=10.42.0.2, finds bob's /32 → `Forward{to: bob}` →
    // `send_sptps_packet` → SPTPS record → UDP sendto(bob's
    // 127.0.0.1:PORT) → bob's `on_udp_recv` → SPTPS receive →
    // `route()` reads dst=10.42.0.2, finds OWN subnet →
    // `Forward{to: myself}` → `Tun::write` (stomps ethertype to a
    // zero vnet_hdr at `buf[4..]`, writes `[vnet_hdr=0][IP]`) →
    // bobside kernel ICMP layer → reply with dst=10.42.0.1 → back.
    //
    // `-W 2`: per-packet timeout. Loopback RTT is microseconds;
    // 2s is slack for CI scheduler jitter.
    let ping = Command::new("ping")
        .args(["-c", "3", "-W", "2", "10.42.0.2"])
        .output()
        .expect("spawn ping");

    if !ping.status.success() {
        let _ = bob_child.kill();
        let bs = drain_stderr(bob_child);
        let asd = drain_stderr(alice_child);
        panic!(
            "ping failed: {:?}\nstdout: {}\nstderr: {}\n\
             === alice ===\n{asd}\n=== bob ===\n{bs}",
            ping.status,
            String::from_utf8_lossy(&ping.stdout),
            String::from_utf8_lossy(&ping.stderr),
        );
    }

    // Show the ping output even on success (--nocapture).
    eprintln!("{}", String::from_utf8_lossy(&ping.stdout));

    // ─── traffic counters ───────────────────────────────────────
    // alice: out_packets ≥ 3 for bob (the kick ping + 3 echoes;
    // counted at `send_packet` BEFORE the validkey gate, so the
    // dropped kick still counts). bob: in_packets ≥ 3 for alice.
    let node_traffic = |rows: &[String], name: &str| -> Option<(u64, u64)> {
        rows.iter().find_map(|r| {
            let body = r.strip_prefix("18 3 ")?;
            let toks: Vec<&str> = body.split_whitespace().collect();
            if toks.first() != Some(&name) {
                return None;
            }
            let n = toks.len();
            Some((toks[n - 4].parse().ok()?, toks[n - 2].parse().ok()?))
        })
    };
    let a_nodes = alice_ctl.dump(3);
    let b_nodes = bob_ctl.dump(3);
    let (_, a_out_p) = node_traffic(&a_nodes, "bob").expect("alice's bob row");
    let (b_in_p, _) = node_traffic(&b_nodes, "alice").expect("bob's alice row");
    assert!(
        a_out_p >= 3,
        "alice out_packets={a_out_p}; nodes: {a_nodes:?}"
    );
    assert!(b_in_p >= 3, "bob in_packets={b_in_p}; nodes: {b_nodes:?}");

    // ─── stderr: TUNSETIFF success log + SPTPS handshake ────────
    drop(alice_ctl);
    drop(bob_ctl);
    let _ = bob_child.kill();
    let bob_stderr = drain_stderr(bob_child);
    let alice_stderr = drain_stderr(alice_child);

    // `Tun::open` doesn't log itself, but daemon::setup does:
    // "Device mode: Tun, interface: tinc0". Proves the kernel-
    // assigned name matched what we requested (TUNSETIFF wrote
    // it back into ifr_name; `Tun::open` read it).
    assert!(
        alice_stderr.contains("interface: tinc0"),
        "alice's TUNSETIFF; stderr:\n{alice_stderr}"
    );
    assert!(
        bob_stderr.contains("interface: tinc1"),
        "bob's TUNSETIFF; stderr:\n{bob_stderr}"
    );
    assert!(
        alice_stderr.contains("SPTPS key exchange with bob successful"),
        "alice's per-tunnel HandshakeDone; stderr:\n{alice_stderr}"
    );

    drop(netns);
}

/// Ping a destination NO daemon owns. The kernel route gets it INTO
/// tinc0 (it's in 10.42.0.0/24); alice's `route()` finds no subnet
/// → `RouteResult::Unreachable{ICMP_DEST_UNREACH, ICMP_NET_UNKNOWN}`
/// → `icmp::build_v4_unreachable` synthesizes the ICMP error →
/// `device.write` puts it BACK into tinc0 → kernel parses it,
/// matches the quoted IP header to ping's socket → ping prints
/// "Destination Net Unknown" (or similar; the exact string varies
/// by ping implementation — iputils vs busybox).
///
/// **THIS PROVES THE WIRE IS CORRECT.** The kernel's ICMP receive
/// path is strict: bad checksum → silently dropped, wrong quoted
/// header → no socket match → ping just times out. Ping printing
/// the error means our `inet_checksum` is right, our ip header is
/// right, our quoted-original is right, our MAC swap is right.
///
/// Single daemon (alice only): the unreachable path doesn't need a
/// peer. The ICMP synth fires BEFORE `send_sptps_packet`. No SPTPS
/// handshake, no validkey wait — just `route()` → Unreachable →
/// device.write. Faster + less moving parts than `real_tun_ping`.
#[test]
fn real_tun_unreachable() {
    let Some(netns) = enter_netns("ping::real_tun_unreachable") else {
        return;
    };

    let tmp = tmp("unreach");
    let alice = Node::new(tmp.path(), "alice", 0xA9, "tinc0", "10.42.0.1/32");
    // Bob's TUN exists (NetNs::setup precreated it) but no daemon
    // attaches. We need `bob` only for `write_config`'s pubkey/
    // hosts cross-registration; alice's id_h reads `hosts/bob` if
    // bob ever connects (it won't here).
    let bob = Node::new(tmp.path(), "bob", 0xB9, "tinc1", "10.42.0.2/32");

    // alice has NO ConnectTo. She just listens. The unreachable
    // path is local: TUN read → route() → Unreachable → TUN write.
    alice.write_config(&bob, false);

    let alice_child = alice.spawn();
    assert!(
        wait_for_file(&alice.socket),
        "alice setup failed; stderr:\n{}",
        drain_stderr(alice_child)
    );

    assert!(
        wait_for_carrier("tinc0", Duration::from_secs(2)),
        "alice TUNSETIFF didn't bring carrier up; stderr:\n{}",
        drain_stderr(alice_child)
    );

    // ─── configure tinc0 only (no bob, no child netns move) ────
    // /24 on the device → kernel route for 10.42.0.0/24 via tinc0.
    // 10.42.0.99 is in that /24 but NOT in any daemon Subnet.
    run_ip(&["addr", "add", "10.42.0.1/24", "dev", "tinc0"]);
    run_ip(&["link", "set", "tinc0", "up"]);

    // ─── THE PING ────────────────────────────────────────────────
    // `-c 2`: send 2 echoes. Stay under the 3/sec ICMP rate limit;
    // a 4th would silently time out instead of getting ICMP back.
    // `-W 2`: 2s per-packet timeout. The ICMP error is synchronous
    // (TUN write → kernel ICMP rcv is in-process); 2s is just CI
    // slack. WITHOUT our synth, ping would block for the full 2s
    // and exit with NO ICMP message — just "packet loss". WITH it,
    // ping immediately prints the error (and still exits non-zero;
    // unreachable is a failure to ping(1)).
    let ping = Command::new("ping")
        .args(["-c", "2", "-W", "2", "10.42.0.99"])
        .output()
        .expect("spawn ping");

    let stdout = String::from_utf8_lossy(&ping.stdout);
    let stderr = String::from_utf8_lossy(&ping.stderr);
    eprintln!("ping stdout:\n{stdout}\nping stderr:\n{stderr}");

    // Ping exits non-zero (no replies). That's expected.
    assert!(
        !ping.status.success(),
        "ping should fail (no route to 10.42.0.99); stdout: {stdout}"
    );

    // The ICMP error surfaces in ping's output. iputils-ping
    // prints "Destination Net Unknown" for ICMP type=3 code=6;
    // busybox ping prints "No route to host" (it lumps codes).
    // Match the common substring. WITHOUT the synth, neither
    // appears — ping just says "100% packet loss".
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("Unreachable")
            || combined.contains("Unknown")
            || combined.contains("No route"),
        "ping should surface the synthesized ICMP error; got:\n{combined}"
    );

    // ─── daemon stderr: the synth log ────────────────────────────
    let alice_stderr = drain_stderr(alice_child);
    assert!(
        alice_stderr.contains("unreachable, sending ICMP"),
        "alice should log the ICMP synth; stderr:\n{alice_stderr}"
    );

    drop(netns);
}

/// TSO ingest integrity gate. `RUST_REWRITE_10G.md`.
///
/// Linux TUN unconditionally sets `IFF_VNET_HDR` (since `5cf9b12d`);
/// `Tun::open` then issues `TUNSETOFFLOAD(TUN_F_TSO4|6)`. Kernel TCP stops segmenting at the
/// TUN MTU; it hands the daemon ≤64KB super-segments. The daemon's
/// `tso_split` re-segments them with re-synthesized TCP headers
/// (seqno arithmetic, csum recompute, IPv4 ID++).
///
/// **The risk: get TCP seqno wrong → silent stream corruption.**
/// The receiving kernel reassembles by seqno; off-by-one means
/// wrong bytes in the right place, no error visible. Only a
/// sha256-of-stream catches it.
///
/// ## What this proves
///
/// 1. **Seqno arithmetic**: 8 MiB of TCP at MSS ≈1400 = ~6000
///    segments. Each segment's seqno = first + i*`gso_size`. If the
///    arithmetic is off (e.g. `*` vs `+`, or `i` vs `i+1`), the
///    sha256 differs.
/// 2. **IPv4 csum recompute**: bob's kernel verifies the IP header
///    csum on receipt (`ip_rcv` → `ip_fast_csum`). Bad csum →
///    silently dropped → TCP retransmit storm → transfer either
///    hangs (timeout) or completes via retransmit (which proves
///    nothing). Either way, sha256 differs OR test times out.
/// 3. **TCP csum recompute**: same, but `tcp_v4_rcv` →
///    `tcp_checksum_complete`. The pseudo-header chaining must be
///    correct.
/// 4. **PSH/FIN flag clearing**: PSH on a non-last segment makes
///    bob's kernel deliver early (cosmetic; doesn't corrupt). FIN
///    on a non-last segment closes the connection mid-stream —
///    `socat` exits early, sha256 differs.
/// 5. **`gso_none_checksum`**: the FIN/ACK and bare-ACK frames at
///    the end of the transfer are `GSO_NONE` with `NEEDS_CSUM`. If we
///    don't complete the partial csum, bob drops the FIN → socat
///    waits for FIN → timeout.
///
/// ## Why 8 MiB
///
/// Large enough that the kernel definitely batches into super-
/// segments (it batches once cwnd opens, after ~10 RTTs of slow
/// start). At 8 MiB, ~5800 full-MSS frames + a short tail —
/// exercises both the even-split and short-tail paths in `tso_split`.
/// Small enough to finish in <2s on loopback (no `ChaCha20` release
/// build needed; dev profile is fine).
///
/// ## Why socat not iperf3
///
/// iperf3 measures throughput; we want INTEGRITY. socat pipes raw
/// bytes: `dd if=/dev/urandom | socat - TCP:bob` on one side,
/// `socat TCP-LISTEN | sha256sum` on the other. Compare hashes.
/// One process either side, no JSON parsing, deterministic.
#[test]
fn tso_ingest_stream_integrity() {
    let Some(netns) = enter_netns("ping::tso_ingest_stream_integrity") else {
        return;
    };

    let tmp = tmp("tso");
    let alice = Node::new(tmp.path(), "alice", 0xA7, "tinc0", "10.42.0.1/32");
    let bob = Node::new(tmp.path(), "bob", 0xB7, "tinc1", "10.42.0.2/32");

    bob.write_config(&alice, false);
    alice.write_config(&bob, true);

    // ─── spawn (same dance as real_tun_ping) ────────────────────
    // `info` not `debug`: 8 MiB at MSS 1400 = ~6000 frames; the
    // per-packet `debug!("Sending packet of {len} bytes")` floods
    // the 64 KiB stderr pipe. The `tinc_device=info` part lets the
    // "TSO ingest enabled" log through (it's at info level).
    let mut bob_child = bob.spawn_with_log("tincd=info");
    assert!(
        wait_for_file(&bob.socket),
        "bob setup failed; stderr:\n{}",
        drain_stderr(bob_child)
    );
    let alice_child = alice.spawn_with_log("info");
    if !wait_for_file(&alice.socket) {
        let _ = bob_child.kill();
        panic!("alice setup failed; stderr:\n{}", drain_stderr(alice_child));
    }

    assert!(
        wait_for_carrier("tinc0", Duration::from_secs(2)),
        "alice TUNSETIFF; stderr:\n{}",
        drain_stderr(alice_child)
    );
    assert!(wait_for_carrier("tinc1", Duration::from_secs(2)));

    netns.place_devices();

    // ─── handshake ──────────────────────────────────────────────
    let mut alice_ctl = alice.ctl();
    let mut bob_ctl = bob.ctl();
    poll_until(Duration::from_secs(10), || {
        let a = alice_ctl.dump(3);
        let b = bob_ctl.dump(3);
        let a_ok = node_status(&a, "bob").is_some_and(|s| s & 0x10 != 0);
        let b_ok = node_status(&b, "alice").is_some_and(|s| s & 0x10 != 0);
        if a_ok && b_ok { Some(()) } else { None }
    });

    // Kick validkey (same as real_tun_ping).
    let _ = Command::new("ping")
        .args(["-c", "1", "-W", "1", "10.42.0.2"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let validkey = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        poll_until(Duration::from_secs(5), || {
            let a = alice_ctl.dump(3);
            let b = bob_ctl.dump(3);
            let a_ok = node_status(&a, "bob").is_some_and(|s| s & 0x02 != 0);
            let b_ok = node_status(&b, "alice").is_some_and(|s| s & 0x02 != 0);
            if a_ok && b_ok { Some(()) } else { None }
        });
    }));
    if validkey.is_err() {
        let _ = bob_child.kill();
        let bs = drain_stderr(bob_child);
        let asd = drain_stderr(alice_child);
        panic!("validkey timed out;\n=== alice ===\n{asd}\n=== bob ===\n{bs}");
    }

    // ─── generate test data + reference hash ────────────────────
    // 8 MiB of random bytes. Written to a temp file so we can hash
    // it once and pipe it once (urandom would give different bytes
    // on each read).
    let data_path = tmp.path().join("stream.bin");
    let dd = Command::new("dd")
        .args(["if=/dev/urandom", "bs=1M", "count=8"])
        .arg(format!("of={}", data_path.display()))
        .stderr(Stdio::null())
        .status()
        .expect("spawn dd");
    assert!(dd.success(), "dd: {dd:?}");

    let ref_hash = Command::new("sha256sum")
        .arg(&data_path)
        .output()
        .expect("spawn sha256sum");
    let ref_hash = String::from_utf8_lossy(&ref_hash.stdout)
        .split_whitespace()
        .next()
        .expect("sha256sum output")
        .to_owned();
    eprintln!("reference sha256: {ref_hash}");

    // ─── receiver: socat TCP-LISTEN | sha256sum (in bobside) ───
    // The hash is written to a file because piping back across
    // `ip netns exec` is finicky. We read the file after.
    let rx_hash_path = tmp.path().join("rx.sha256");
    let rx = Command::new("ip")
        .args(["netns", "exec", "bobside", "sh", "-c"])
        .arg(format!(
            "socat -u TCP-LISTEN:18099,reuseaddr - | sha256sum > '{}'",
            rx_hash_path.display()
        ))
        .spawn()
        .expect("spawn rx socat");
    // Wait for the listener to bind. socat doesn't have a
    // ready-signal; poll for the socket via `ss` or just sleep.
    // 200ms is generous on loopback.
    std::thread::sleep(Duration::from_millis(200));

    // ─── sender: socat FILE TCP (in outer netns / alice's side) ─
    // This is THE test. The kernel TCP stack writes data into
    // tinc0; with TSO advertised it writes ≤64KB super-segments.
    // alice's daemon `drain()` returns `Super{..}`, `tso_split`
    // re-segments. If seqno is off, bob's kernel reassembles
    // wrong-order bytes → sha256 differs. If csum is off, bob's
    // kernel drops segments → TCP retransmit storm → timeout.
    // `connect-timeout=5`: the SYN/SYN-ACK handshake should
    // complete in microseconds on loopback. If it doesn't, the
    // GSO_NONE csum-completion path is wrong (SYN gets dropped).
    // No data-phase timeout: socat blocks until FIN; the nextest
    // slow-timeout (30s) catches a hang.
    let tx = Command::new("socat")
        .arg("-u")
        .arg(format!("FILE:{}", data_path.display()))
        .arg("TCP:10.42.0.2:18099,connect-timeout=5")
        .output()
        .expect("spawn tx socat");
    if !tx.status.success() {
        let _ = bob_child.kill();
        let bs = drain_stderr(bob_child);
        let asd = drain_stderr(alice_child);
        panic!(
            "socat tx failed: {:?}\nstderr: {}\n\
             The TCP connect either timed out (csum bug → SYN dropped) \
             or RST mid-stream (FIN-on-non-last in tso_split).\n\
             === alice ===\n{asd}\n=== bob ===\n{bs}",
            tx.status,
            String::from_utf8_lossy(&tx.stderr),
        );
    }

    // ─── wait for rx + compare hashes ──────────────────────────
    // socat exits when it sees FIN. sha256sum exits when its stdin
    // closes. The rx Child completes when both are done.
    let rx_status = rx.wait_with_output().expect("wait for rx socat").status;
    assert!(rx_status.success(), "rx socat: {rx_status:?}");

    let rx_hash = std::fs::read_to_string(&rx_hash_path)
        .expect("read rx hash")
        .split_whitespace()
        .next()
        .expect("sha256sum output format")
        .to_owned();
    eprintln!("received  sha256: {rx_hash}");

    drop(alice_ctl);
    drop(bob_ctl);
    let _ = bob_child.kill();
    let bob_stderr = drain_stderr(bob_child);
    let alice_stderr = drain_stderr(alice_child);

    // The TSO-enabled log line. Proves the feature actually fired
    // (TUNSETOFFLOAD succeeded). Without this, a green hash could
    // mean the kernel rejected the offload ioctl and we never saw
    // a super-segment (everything went through the GSO_NONE arm). The `tinc_device` log target
    // surfaces with `RUST_LOG=info` (no target filter → all crates).
    assert!(
        alice_stderr.contains("TSO ingest enabled"),
        "alice should log TUNSETOFFLOAD success. \
         If the assert fires but sha256 below matches anyway, the \
         feature works — just the log target/level is wrong. \
         stderr:\n{alice_stderr}"
    );
    // No `tso_split` warnings: every super-segment was successfully
    // re-segmented. A `TooManySegments` or `BadTcpHlen` warn here
    // means some traffic took the drop path (and TCP retransmitted
    // around it, masking the error). Zero warns = every packet went
    // through tso_split cleanly.
    assert!(
        !alice_stderr.contains("tso_split"),
        "tso_split logged a warning (some segment was dropped); \
         stderr:\n{alice_stderr}"
    );

    // THE ASSERT.
    assert_eq!(
        ref_hash, rx_hash,
        "sha256 mismatch — tso_split CORRUPTED THE STREAM. \
         Check seqno arithmetic (is it first_seq + i*gso_size?), \
         IPv4 totlen/csum (off-by-ETH_HLEN?), TCP csum (pseudo-header \
         length = tcp_hlen + payload, NOT including IP header).\n\
         === alice ===\n{alice_stderr}\n=== bob ===\n{bob_stderr}"
    );

    drop(netns);
}
