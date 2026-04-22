//! Portable DNS-stub test (no netns, no `dig`).
//!
//! Same coverage as `netns/dns.rs::dns_stub_dig{,_v6}` but driven
//! through `DeviceType = fd`: we hand-craft the UDP-in-IP DNS query
//! on our end of the socketpair, the daemon's TUN-intercept hook
//! (`try_dns_intercept`) matches `dst == DNSAddress && dport == 53`,
//! builds the reply, and writes it straight back to the device fd.
//! `FdTun` strips the 14-byte ether header on write, so we read raw
//! IP back.
//!
//! Proves over the `dns.rs` unit tests: the intercept is wired into
//! `on_device_read`, `DnsConfig` parses from `tinc.conf`, and
//! `load_all_nodes` (`StrictSubnets`) preloaded bob's subnets into the
//! live tree. Does NOT prove kernel checksum verify — netns test +
//! `wrap_v{4,6}` unit tests cover that.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;
use std::time::Duration;

use super::common::*;
use super::fd_tunnel::*;
use super::node::*;

// ── tiny DNS wire helpers (RFC 1035) ────────────────────────────────
// Duplicated from the `dns.rs` unit-test helpers on purpose: those
// are `#[cfg(test)]`-private to the lib crate, and re-exporting test
// scaffolding through the public API just for an integration test
// is worse than ~20 LOC of copy.

const TYPE_A: u16 = 1;
const TYPE_PTR: u16 = 12;
const TYPE_AAAA: u16 = 28;

fn encode_name(name: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(name.len() + 2);
    for label in name.split('.') {
        out.push(u8::try_from(label.len()).unwrap());
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

/// Hand-craft a DNS query (header + 1 question, RD set). Same bytes
/// `dig +noedns` would emit.
fn mk_query(name: &str, qtype: u16) -> Vec<u8> {
    let mut q = Vec::new();
    q.extend_from_slice(&0xBEEFu16.to_be_bytes()); // ID
    q.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD
    q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    q.extend_from_slice(&[0u8; 6]); // AN/NS/AR = 0
    q.extend_from_slice(&encode_name(name));
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes()); // CLASS_IN
    q
}

/// Wrap `dns` in UDP (sport→53). No checksum — `match_v4` / `_v6`
/// don't verify it (the kernel would, but `FdTun` is userspace-only).
fn mk_udp(sport: u16, dns: &[u8]) -> Vec<u8> {
    let len = u16::try_from(8 + dns.len()).unwrap();
    let mut u = Vec::with_capacity(len as usize);
    u.extend_from_slice(&sport.to_be_bytes());
    u.extend_from_slice(&53u16.to_be_bytes());
    u.extend_from_slice(&len.to_be_bytes());
    u.extend_from_slice(&[0, 0]); // checksum: optional in v4, ignored by intercept in v6
    u.extend_from_slice(dns);
    u
}

/// Minimal IPv6 header (no extensions) + payload. Only the fields
/// `match_v6` reads: version nibble (for `FdTun`'s ethertype synth),
/// `nxt`, src, dst.
fn mk_ipv6_pkt(src: Ipv6Addr, dst: Ipv6Addr, payload: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(40 + payload.len());
    p.push(0x60);
    p.extend_from_slice(&[0, 0, 0]); // tc lo + flow
    p.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
    p.push(17); // nxt = UDP
    p.push(64); // hlim
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&dst.octets());
    p.extend_from_slice(payload);
    p
}

/// Write raw IP into the daemon's TUN fd, poll for the reply.
/// Single daemon, no peer → first datagram back is the DNS reply
/// (or ICMP if the intercept missed; IP-header asserts catch that).
fn roundtrip(tun: &std::os::fd::OwnedFd, frame: &[u8]) -> Vec<u8> {
    write_fd(tun, frame);
    poll_until(Duration::from_secs(5), || read_fd_nb(tun))
}

#[test]
fn dns_stub_fd() {
    let tmp = tmp!("dns-fd");
    // Single daemon. bob is just a hosts/ entry so `load_all_nodes`
    // (under `StrictSubnets=yes`) preloads his /32 + /128 into the
    // subnet tree — no peer, no gossip. Mirrors the netns test.
    let alice = Node::new(tmp.path(), "alice", 0xAD).with_conf(
        "StrictSubnets = yes\n\
         DNSAddress = 10.42.0.53\n\
         DNSAddress = fd00::53\n\
         DNSSuffix = tinc.internal\n",
    );
    let bob = Node::new(tmp.path(), "bob", 0xBD);

    let (tun, far) = sockpair_datagram();

    // connect_to=false: no outgoing, bob never runs.
    let alice = alice.fd(far.as_raw_fd()).subnet("10.42.0.1/32");
    alice.write_config(&bob, false);
    // `write_config_multi` wrote hosts/bob with pubkey only.
    // Re-write it with Subnet lines so `load_all_nodes` picks them
    // up (the netns test does the same).
    let bob_pub = tinc_crypto::b64::encode(&bob.pubkey());
    std::fs::write(
        alice.confbase.join("hosts").join("bob"),
        format!(
            "Ed25519PublicKey = {bob_pub}\n\
             Subnet = 10.42.0.2/32\n\
             Subnet = fd00::2/128\n"
        ),
    )
    .unwrap();

    let alice_child = alice.spawn_with_fd(&far);
    assert!(
        wait_for_file(&alice.socket),
        "alice setup failed; stderr:\n{}",
        drain_stderr(alice_child)
    );
    drop(far);

    let dns4 = Ipv4Addr::new(10, 42, 0, 53);
    let me4 = [10, 42, 0, 1];
    let dns6: Ipv6Addr = "fd00::53".parse().unwrap();
    let me6: Ipv6Addr = "fd00::1".parse().unwrap();

    // ═══ A: bob.tinc.internal → 10.42.0.2 ════════════════════════
    let q = mk_query("bob.tinc.internal", TYPE_A);
    let frame = mk_ipv4_pkt(me4, dns4.octets(), &mk_udp(54321, &q));
    let reply = roundtrip(&tun, &frame);

    // FdTun::write strips ether → raw IPv4 from `wrap_v4`.
    assert_eq!(reply[0], 0x45, "not IPv4/ihl=5: {:02x?}", &reply[..20]);
    assert_eq!(reply[9], 17, "not UDP (intercept missed → ICMP?)");
    assert_eq!(&reply[12..16], &dns4.octets(), "src != DNSAddress");
    assert_eq!(&reply[16..20], &me4, "dst != query src");
    assert_eq!(u16::from_be_bytes([reply[20], reply[21]]), 53);
    assert_eq!(u16::from_be_bytes([reply[22], reply[23]]), 54321);

    let dns = &reply[28..];
    assert_eq!(&dns[0..2], &[0xBE, 0xEF], "ID echoed");
    let flags = u16::from_be_bytes([dns[2], dns[3]]);
    assert_eq!(
        flags & 0x800F,
        0x8000,
        "QR set, rcode NOERROR; got {flags:#x}"
    );
    assert_eq!(u16::from_be_bytes([dns[6], dns[7]]), 1, "ANCOUNT");
    // A rdata is the trailing 4 bytes (no compression, single RR).
    assert_eq!(&dns[dns.len() - 4..], &[10, 42, 0, 2], "A rdata = bob /32");

    // ═══ PTR: 2.0.42.10.in-addr.arpa → bob.tinc.internal. ════════
    let q = mk_query("2.0.42.10.in-addr.arpa", TYPE_PTR);
    let frame = mk_ipv4_pkt(me4, dns4.octets(), &mk_udp(54322, &q));
    let reply = roundtrip(&tun, &frame);
    let dns = &reply[28..];
    assert_eq!(u16::from_be_bytes([dns[2], dns[3]]) & 0x000F, 0, "NOERROR");
    assert_eq!(u16::from_be_bytes([dns[6], dns[7]]), 1, "ANCOUNT");
    let want = encode_name("bob.tinc.internal");
    assert_eq!(&dns[dns.len() - want.len()..], &want[..], "PTR rdata");

    // ═══ NXDOMAIN: wrong suffix, no forwarding ═══════════════════
    let q = mk_query("google.com", TYPE_A);
    let frame = mk_ipv4_pkt(me4, dns4.octets(), &mk_udp(54323, &q));
    let reply = roundtrip(&tun, &frame);
    let dns = &reply[28..];
    assert_eq!(
        u16::from_be_bytes([dns[2], dns[3]]) & 0x000F,
        3,
        "rcode NXDOMAIN"
    );
    assert_eq!(u16::from_be_bytes([dns[6], dns[7]]), 0, "ANCOUNT=0");

    // ═══ AAAA over IPv6 transport: bob → fd00::2 ═════════════════
    let q = mk_query("bob.tinc.internal", TYPE_AAAA);
    let frame = mk_ipv6_pkt(me6, dns6, &mk_udp(54324, &q));
    let reply = roundtrip(&tun, &frame);

    assert_eq!(reply[0] >> 4, 6, "not IPv6: {:02x?}", &reply[..40]);
    assert_eq!(reply[6], 17, "nxt != UDP");
    assert_eq!(&reply[8..24], &dns6.octets(), "v6 src != DNSAddress");
    assert_eq!(&reply[24..40], &me6.octets(), "v6 dst != query src");
    assert_eq!(u16::from_be_bytes([reply[40], reply[41]]), 53);

    let dns = &reply[48..];
    assert_eq!(u16::from_be_bytes([dns[2], dns[3]]) & 0x000F, 0, "NOERROR");
    assert_eq!(u16::from_be_bytes([dns[6], dns[7]]), 1, "ANCOUNT");
    let want: Ipv6Addr = "fd00::2".parse().unwrap();
    assert_eq!(&dns[dns.len() - 16..], &want.octets(), "AAAA rdata");

    // ═══ PTR over IPv6: 32-nibble ip6.arpa → bob ═════════════════
    let arpa = "2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa";
    let q = mk_query(arpa, TYPE_PTR);
    let frame = mk_ipv6_pkt(me6, dns6, &mk_udp(54325, &q));
    let reply = roundtrip(&tun, &frame);
    let dns = &reply[48..];
    assert_eq!(u16::from_be_bytes([dns[2], dns[3]]) & 0x000F, 0, "NOERROR");
    let want = encode_name("bob.tinc.internal");
    assert_eq!(&dns[dns.len() - want.len()..], &want[..], "v6 PTR rdata");

    // ═══ log: intercept fired ════════════════════════════════════
    drop(tun);
    let stderr = drain_stderr(alice_child);
    let hits = stderr.matches("tincd::dns").count();
    assert!(
        hits >= 5,
        "expected ≥5 `tincd::dns` debug lines (A+PTR+NX+AAAA+PTR6); got {hits}.\n\
         stderr:\n{stderr}"
    );
}
