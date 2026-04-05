use std::process::Command;
use std::time::Duration;

use super::common::linux::*;
use super::common::*;
use super::rig::*;

fn tmp(tag: &str) -> TmpGuard {
    TmpGuard::new("netns", tag)
}

// ═══════════════════════════ DNS stub ══════════════════════════════════════
//
// `dig @<magic-ip> bob.tinc.internal` against a real kernel.
//
// Same single-daemon shape as `real_tun_unreachable`: TUN read →
// intercept → TUN write, no peer needed. The kernel verifies the
// IPv4 header checksum AND the UDP checksum on the reply (silently
// drops if either is wrong); dig then verifies the DNS wire format.
// If `dig +short` prints `10.42.0.2`, the whole stack is correct.
//
// Subnet preload: `load_all_nodes` only adds other-node subnets to
// the tree under `StrictSubnets=yes` (no gossip to verify against
// here — single daemon). The rest of `dns.rs` is unit-tested; THIS
// test pins the IP/UDP wrap + the TUN-intercept hook + the kernel-
// level checksum verification.

#[test]
fn dns_stub_dig() {
    let Some(_netns) = enter_netns("dns_stub_dig") else {
        return;
    };

    // dig might not be in the bwrap'd PATH on minimal systems. SKIP
    // not FAIL — the unit tests cover the wire format already.
    if Command::new("dig").arg("-v").output().is_err() {
        eprintln!("SKIP dns_stub_dig: dig not found");
        return;
    }

    let tmp = tmp("dns");
    let alice = Node::new(tmp.path(), "alice", 0xAD, "tinc0", "10.42.0.1/32");
    let bob = Node::new(tmp.path(), "bob", 0xBD, "tinc1", "10.42.0.2/32");

    // Single daemon, no ConnectTo — same as real_tun_unreachable.
    // `StrictSubnets=yes` forces `load_all_nodes` to preload bob's
    // /32 from `hosts/bob` (no gossip without a peer).
    // Magic IP: `10.42.0.53` — in the /24 the kernel routes to
    // tinc0, NOT any node's /32.
    alice.write_config_with(
        &bob,
        false,
        "StrictSubnets = yes\nDNSAddress = 10.42.0.53\nDNSSuffix = tinc.internal\n",
    );
    // hosts/bob: pubkey + Subnet so load_all_nodes picks up the /32.
    // The default write_config only puts Subnet in hosts/SELF.
    let bob_pub = tinc_crypto::b64::encode(&bob.pubkey());
    std::fs::write(
        alice.confbase.join("hosts").join("bob"),
        format!("Ed25519PublicKey = {bob_pub}\nSubnet = 10.42.0.2/32\n"),
    )
    .unwrap();

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

    // /24 → kernel routes 10.42.0.53 to tinc0. We DON'T add
    // 10.42.0.53 itself (the daemon answers for it via intercept;
    // adding it would make the kernel claim it locally and
    // shortcut via lo, never entering the TUN).
    run_ip(&["addr", "add", "10.42.0.1/24", "dev", "tinc0"]);
    run_ip(&["link", "set", "tinc0", "up"]);

    // ─── A query ─────────────────────────────────────────────────
    // `+short`: just the answer RDATA, no banner. `+tries=1
    // +timeout=2`: dig defaults to 3 tries × 5s; we want fast
    // fail. `+ignore`: don't retry over TCP if TC bit set (it
    // won't be — our answers are tiny — but belt and braces).
    let dig = Command::new("dig")
        .args([
            "@10.42.0.53",
            "+short",
            "+tries=1",
            "+timeout=2",
            "+ignore",
            "bob.tinc.internal",
            "A",
        ])
        .output()
        .expect("spawn dig");

    let stdout = String::from_utf8_lossy(&dig.stdout);
    let stderr = String::from_utf8_lossy(&dig.stderr);
    eprintln!("dig A stdout: {stdout:?}\ndig A stderr: {stderr:?}");

    // dig exits 0 when it gets ANY response (including NXDOMAIN);
    // exit 9 = no reply at all (timeout). The latter means our
    // checksums are wrong — kernel dropped the reply silently.
    assert!(
        dig.status.success(),
        "dig timed out — reply never reached the kernel. \
         Either the IP checksum is wrong (ip_rcv drops silently), \
         the UDP checksum is wrong (udp_rcv drops silently), or \
         the intercept never matched (check the `tincd::dns` debug \
         log line). dig stderr: {stderr}\n\
         === alice ===\n{}",
        drain_stderr(alice_child)
    );
    assert_eq!(
        stdout.trim(),
        "10.42.0.2",
        "expected bob's /32; got {stdout:?}. \
         === alice ===\n{}",
        drain_stderr(alice_child)
    );

    // ─── PTR query ───────────────────────────────────────────────
    // `dig -x 10.42.0.2` is sugar for `2.0.42.10.in-addr.arpa PTR`.
    let dig_ptr = Command::new("dig")
        .args([
            "@10.42.0.53",
            "+short",
            "+tries=1",
            "+timeout=2",
            "-x",
            "10.42.0.2",
        ])
        .output()
        .expect("spawn dig -x");

    let ptr_out = String::from_utf8_lossy(&dig_ptr.stdout);
    eprintln!("dig PTR stdout: {ptr_out:?}");
    assert!(dig_ptr.status.success(), "dig PTR timed out");
    // Trailing dot: dig prints FQDN form.
    assert_eq!(ptr_out.trim(), "bob.tinc.internal.");

    // ─── NXDOMAIN: name not in our suffix ────────────────────────
    // `+short` is empty for NXDOMAIN; check via the rcode in full
    // output. This proves we don't forward (forwarding would block
    // — there's no upstream resolver in the netns).
    let dig_nx = Command::new("dig")
        .args(["@10.42.0.53", "+tries=1", "+timeout=2", "google.com", "A"])
        .output()
        .expect("spawn dig nx");

    let nx_out = String::from_utf8_lossy(&dig_nx.stdout);
    assert!(dig_nx.status.success(), "dig NX timed out");
    assert!(
        nx_out.contains("NXDOMAIN"),
        "expected NXDOMAIN for non-suffix name (no forwarding); \
         got:\n{nx_out}"
    );

    // ─── daemon log: confirm the intercept fired ────────────────
    let alice_stderr = drain_stderr(alice_child);
    let dns_replies = alice_stderr.matches("tincd::dns").count();
    assert!(
        dns_replies >= 3,
        "expected ≥3 DNS log lines (A + PTR + NX); got {dns_replies}.\n\
         stderr:\n{alice_stderr}"
    );
}

/// IPv6: AAAA query over an IPv6 transport. Proves the v6 wrap
/// (mandatory UDP checksum, RFC 8200 §8.1 — kernel rejects zero).
///
/// Single daemon again. The TUN gets an `fd00::/8` ULA prefix; the
/// magic DNS IP is `fd00::53`. Same kernel-verifies-checksum proof
/// as the v4 test, but the v6 UDP-over-pseudo-header sum is the
/// fiddly one (`dns.rs::wrap_v6` — the v4 sum is optional and
/// Linux accepts zero, so `wrap_v4_shape` could be silently wrong
/// and the v4 test would still pass).
#[test]
fn dns_stub_dig_v6() {
    let Some(_netns) = enter_netns("dns_stub_dig_v6") else {
        return;
    };

    if Command::new("dig").arg("-v").output().is_err() {
        eprintln!("SKIP dns_stub_dig_v6: dig not found");
        return;
    }

    let tmp = tmp("dns6");
    // The v4 /32 in the Node struct is unused here (the TUN gets
    // a v6 prefix only); we set it because `Node::new` wants one.
    let alice = Node::new(tmp.path(), "alice", 0xAE, "tinc0", "10.42.0.1/32");
    let bob = Node::new(tmp.path(), "bob", 0xBE, "tinc1", "10.42.0.2/32");

    alice.write_config_with(
        &bob,
        false,
        "StrictSubnets = yes\nDNSAddress = fd00::53\nDNSSuffix = tinc.internal\n",
    );
    // hosts/bob: v6 /128. load_all_nodes preloads it.
    let bob_pub = tinc_crypto::b64::encode(&bob.pubkey());
    std::fs::write(
        alice.confbase.join("hosts").join("bob"),
        format!("Ed25519PublicKey = {bob_pub}\nSubnet = fd00::2/128\n"),
    )
    .unwrap();

    let alice_child = alice.spawn();
    assert!(
        wait_for_file(&alice.socket),
        "alice setup failed; stderr:\n{}",
        drain_stderr(alice_child)
    );
    assert!(
        wait_for_carrier("tinc0", Duration::from_secs(2)),
        "carrier; stderr:\n{}",
        drain_stderr(alice_child)
    );

    // ULA /64. fd00::53 falls inside; kernel routes it to tinc0.
    // `nodad`: skip Duplicate Address Detection (~1s probe before
    // the address goes ACTIVE); we own the netns, no neighbors.
    run_ip(&["addr", "add", "fd00::1/64", "dev", "tinc0", "nodad"]);
    run_ip(&["link", "set", "tinc0", "up"]);

    // ─── AAAA query, IPv6 transport ──────────────────────────────
    // The `@fd00::53` server address forces the v6 transport;
    // `match_v6` has to fire, `wrap_v6` has to checksum correctly.
    let dig = Command::new("dig")
        .args([
            "@fd00::53",
            "+short",
            "+tries=1",
            "+timeout=2",
            "+ignore",
            "bob.tinc.internal",
            "AAAA",
        ])
        .output()
        .expect("spawn dig");

    let stdout = String::from_utf8_lossy(&dig.stdout);
    let stderr = String::from_utf8_lossy(&dig.stderr);
    eprintln!("dig AAAA stdout: {stdout:?}\nstderr: {stderr:?}");

    assert!(
        dig.status.success(),
        "dig timed out — v6 UDP checksum is mandatory (RFC 8200 \
         §8.1); the kernel drops zero or wrong sum SILENTLY. \
         wrap_v6's pseudo-header chaining is the suspect. \
         dig stderr: {stderr}\n=== alice ===\n{}",
        drain_stderr(alice_child)
    );
    // dig may print compressed (`fd00::2`) or expanded; normalize.
    let got: std::net::Ipv6Addr = stdout
        .trim()
        .parse()
        .unwrap_or_else(|_| panic!("dig output not an IPv6 addr: {stdout:?}"));
    let want: std::net::Ipv6Addr = "fd00::2".parse().unwrap();
    assert_eq!(got, want, "=== alice ===\n{}", drain_stderr(alice_child));

    // ─── v6 PTR (32-nibble ip6.arpa) ─────────────────────────────
    let dig_ptr = Command::new("dig")
        .args([
            "@fd00::53",
            "+short",
            "+tries=1",
            "+timeout=2",
            "-x",
            "fd00::2",
        ])
        .output()
        .expect("spawn dig -x v6");

    let ptr_out = String::from_utf8_lossy(&dig_ptr.stdout);
    eprintln!("dig PTR v6 stdout: {ptr_out:?}");
    assert!(dig_ptr.status.success(), "dig PTR v6 timed out");
    assert_eq!(ptr_out.trim(), "bob.tinc.internal.");

    drop(drain_stderr(alice_child));
}
