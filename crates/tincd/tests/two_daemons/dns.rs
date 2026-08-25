//! DNS stub driven through `DeviceType = fd` (no netns, no `dig`):
//! hand-made UDP/IP queries go into the socketpair and the intercept
//! writes raw IP replies straight back. Covers what the `dns.rs` unit
//! tests can't: wiring into the device read path, `DNSAddress` config
//! parsing, and `StrictSubnets` preloading bob's subnets from hosts/.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;
use std::time::Duration;

use super::common::{Node, poll_until};
use super::fd_tunnel::{mk_ipv4_pkt, read_fd_nb, sockpair_datagram, write_fd};
use std::fs;
use std::os::fd::OwnedFd;

// RFC 1035 helpers; the lib's copies are `#[cfg(test)]`-private.
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

/// Header + one question with RD set, as `dig +noedns` would send.
fn mk_query(name: &str, qtype: u16) -> Vec<u8> {
    let mut q = Vec::new();
    q.extend_from_slice(&0xBEEFu16.to_be_bytes());
    q.extend_from_slice(&0x0100u16.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes());
    q.extend_from_slice(&[0u8; 6]);
    q.extend_from_slice(&encode_name(name));
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes());
    q
}

/// UDP to port 53 without checksum; the intercept doesn't verify it.
fn mk_udp(sport: u16, dns: &[u8]) -> Vec<u8> {
    let len = u16::try_from(8 + dns.len()).unwrap();
    let mut u = Vec::with_capacity(len as usize);
    u.extend_from_slice(&sport.to_be_bytes());
    u.extend_from_slice(&53u16.to_be_bytes());
    u.extend_from_slice(&len.to_be_bytes());
    u.extend_from_slice(&[0, 0]);
    u.extend_from_slice(dns);
    u
}

fn mk_ipv6_pkt(src: Ipv6Addr, dst: Ipv6Addr, payload: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(40 + payload.len());
    p.push(0x60);
    p.extend_from_slice(&[0, 0, 0]);
    p.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
    p.push(17);
    p.push(64);
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&dst.octets());
    p.extend_from_slice(payload);
    p
}

/// No peer, so the first datagram back is the reply (or an ICMP error
/// if the intercept missed, which the IP header asserts catch).
fn roundtrip(device: &OwnedFd, packet: &[u8]) -> Vec<u8> {
    write_fd(device, packet);
    poll_until(Duration::from_secs(5), || read_fd_nb(device))
}

fn rcode(dns: &[u8]) -> u16 {
    u16::from_be_bytes([dns[2], dns[3]]) & 0x000F
}

fn ancount(dns: &[u8]) -> u16 {
    u16::from_be_bytes([dns[6], dns[7]])
}

#[test]
fn dns_stub_answers_a_ptr_aaaa_and_nxdomain() {
    let tmp = tmp!("dns-fd");
    let (tun, daemon_end) = sockpair_datagram();
    let mut alice = Node::new(tmp.path(), "alice", 0xAD)
        .with_conf(
            "StrictSubnets = yes\nDNSAddress = 10.42.0.53\nDNSAddress = fd00::53\n\
             DNSSuffix = tinc.internal\n",
        )
        .fd(daemon_end.as_raw_fd())
        .subnet("10.42.0.1/32")
        .log_level("tincd=debug");
    let bob = Node::new(tmp.path(), "bob", 0xBD);
    alice.write_config(&bob, false);
    // bob never runs; his subnets come from hosts/ via StrictSubnets.
    let bob_pub = tinc_crypto::b64::encode(&bob.pubkey());
    fs::write(
        alice.confbase.join("hosts").join("bob"),
        format!(
            "Ed25519PublicKey = {bob_pub}\n\
             Subnet = 10.42.0.2/32\n\
             Subnet = fd00::2/128\n"
        ),
    )
    .unwrap();

    alice.start_with_fd(&daemon_end);
    drop(daemon_end);

    let dns4 = Ipv4Addr::new(10, 42, 0, 53);
    let me4 = [10, 42, 0, 1];
    let dns6: Ipv6Addr = "fd00::53".parse().unwrap();
    let me6: Ipv6Addr = "fd00::1".parse().unwrap();

    // A: bob.tinc.internal → 10.42.0.2
    let q = mk_query("bob.tinc.internal", TYPE_A);
    let frame = mk_ipv4_pkt(me4, dns4.octets(), &mk_udp(54321, &q));
    let reply = roundtrip(&tun, &frame);

    assert_eq!(reply[0], 0x45, "not IPv4/ihl=5: {:02x?}", &reply[..20]);
    assert_eq!(reply[9], 17, "not UDP; intercept missed?");
    assert_eq!(&reply[12..16], &dns4.octets(), "src != DNSAddress");
    assert_eq!(&reply[16..20], &me4, "dst != query src");
    assert_eq!(u16::from_be_bytes([reply[20], reply[21]]), 53);
    assert_eq!(u16::from_be_bytes([reply[22], reply[23]]), 54321);

    let dns = &reply[28..];
    assert_eq!(&dns[0..2], &[0xBE, 0xEF], "ID echoed");
    assert_eq!(
        u16::from_be_bytes([dns[2], dns[3]]) & 0x800F,
        0x8000,
        "QR, NOERROR"
    );
    assert_eq!(ancount(dns), 1);
    assert_eq!(&dns[dns.len() - 4..], &[10, 42, 0, 2], "A rdata = bob /32");

    // PTR: 2.0.42.10.in-addr.arpa → bob.tinc.internal.
    let q = mk_query("2.0.42.10.in-addr.arpa", TYPE_PTR);
    let frame = mk_ipv4_pkt(me4, dns4.octets(), &mk_udp(54322, &q));
    let reply = roundtrip(&tun, &frame);
    let dns = &reply[28..];
    assert_eq!(rcode(dns), 0);
    assert_eq!(ancount(dns), 1);
    let want = encode_name("bob.tinc.internal");
    assert_eq!(&dns[dns.len() - want.len()..], &want[..], "PTR rdata");

    // NXDOMAIN: wrong suffix, no forwarding
    let q = mk_query("google.com", TYPE_A);
    let frame = mk_ipv4_pkt(me4, dns4.octets(), &mk_udp(54323, &q));
    let reply = roundtrip(&tun, &frame);
    let dns = &reply[28..];
    assert_eq!(rcode(dns), 3, "NXDOMAIN");
    assert_eq!(ancount(dns), 0);

    // AAAA over IPv6 transport: bob → fd00::2
    let q = mk_query("bob.tinc.internal", TYPE_AAAA);
    let frame = mk_ipv6_pkt(me6, dns6, &mk_udp(54324, &q));
    let reply = roundtrip(&tun, &frame);

    assert_eq!(reply[0] >> 4, 6, "not IPv6: {:02x?}", &reply[..40]);
    assert_eq!(reply[6], 17, "nxt != UDP");
    assert_eq!(&reply[8..24], &dns6.octets(), "v6 src != DNSAddress");
    assert_eq!(&reply[24..40], &me6.octets(), "v6 dst != query src");
    assert_eq!(u16::from_be_bytes([reply[40], reply[41]]), 53);

    let dns = &reply[48..];
    assert_eq!(rcode(dns), 0);
    assert_eq!(ancount(dns), 1);
    let want: Ipv6Addr = "fd00::2".parse().unwrap();
    assert_eq!(&dns[dns.len() - 16..], &want.octets(), "AAAA rdata");

    // PTR over IPv6: 32-nibble ip6.arpa → bob
    let arpa = "2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa";
    let q = mk_query(arpa, TYPE_PTR);
    let frame = mk_ipv6_pkt(me6, dns6, &mk_udp(54325, &q));
    let reply = roundtrip(&tun, &frame);
    let dns = &reply[48..];
    assert_eq!(rcode(dns), 0);
    let want = encode_name("bob.tinc.internal");
    assert_eq!(&dns[dns.len() - want.len()..], &want[..], "v6 PTR rdata");

    let log = alice.stop();
    assert!(log.matches("tincd::dns").count() >= 5, "{log}");
}
