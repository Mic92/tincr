//! macOS utun `recvmsg_x`/`sendmsg_x` batch path against a real
//! kernel utun. Exercises `UTUN_OPT_MAX_PENDING_PACKETS` (without it
//! `drain()` could never return >1 frame), the eth-header synthesis
//! inside the batch drain, and the `write_stage`/`write_flush` inject
//! path.
//!
//! Root-only (utun open + ifconfig). The macOS test runner re-execs
//! under sudo when a credential is cached; otherwise self-skips.
#![cfg(target_os = "macos")]

use std::net::UdpSocket;
use std::process::Command;
use std::time::{Duration, Instant};

use tinc_device::{BsdTun, Device, DeviceArena, DrainResult};

fn ifconfig(iface: &str, local: &str, peer: &str) {
    let s = Command::new("ifconfig")
        .args([iface, "inet", local, peer, "mtu", "1500", "up"])
        .status()
        .expect("ifconfig");
    assert!(s.success(), "ifconfig {iface} failed");
}

/// Drain until `want` frames seen or timeout. The kernel may slip an
/// MLD/ND6 packet in ahead of ours right after `up`; filter to the
/// frames whose IP dst matches `PEER`.
fn drain_until(dev: &mut BsdTun, want: usize) -> Vec<Vec<u8>> {
    let mut got = Vec::new();
    let mut a = DeviceArena::new(32);
    let deadline = Instant::now() + Duration::from_secs(2);
    while got.len() < want && Instant::now() < deadline {
        match dev.drain(&mut a, 32).unwrap() {
            DrainResult::Frames { count } => {
                // count>1 here proves both MAX_PENDING_PACKETS and
                // recvmsg_x batching work.
                for i in 0..count {
                    let s = a.slot(i);
                    if s.len() >= 34 && s[14] == 0x45 && s[30..34] == [10, 98, 1, 2] {
                        got.push(s.to_vec());
                    }
                }
            }
            DrainResult::Empty => std::thread::sleep(Duration::from_millis(5)),
            r => panic!("unexpected {r:?}"),
        }
    }
    got
}

#[test]
fn utun_recvmsg_x_drain() {
    if !nix::unistd::geteuid().is_root() {
        eprintln!("SKIP utun_recvmsg_x_drain: needs root");
        return;
    }
    // Distinct /30 from the inject test so the two can run in
    // parallel without fighting over the host route.
    let (local, peer) = ("10.98.1.1", "10.98.1.2");
    let mut dev = BsdTun::open_utun(None).expect("open_utun");
    ifconfig(dev.iface(), local, peer);

    // Kernel routes PEER via this utun (point-to-point dstaddr); a
    // plain UDP send to PEER lands on the utun read side.
    let tx = UdpSocket::bind((local, 0)).expect("bind");
    let n = 8usize;
    for i in 0..n {
        tx.send_to(&[0xA0 + u8::try_from(i).unwrap(); 32], (peer, 40000))
            .unwrap();
    }

    let got = drain_until(&mut dev, n);
    assert_eq!(got.len(), n, "recvmsg_x should surface all {n} frames");
    for (i, f) in got.iter().enumerate() {
        assert_eq!(&f[12..14], &0x0800u16.to_be_bytes(), "ethertype");
        assert_eq!(f[14], 0x45, "IPv4");
        assert_eq!(f[14 + 28], 0xA0 + u8::try_from(i).unwrap(), "payload");
    }
}

#[test]
fn utun_sendmsg_x_inject() {
    if !nix::unistd::geteuid().is_root() {
        eprintln!("SKIP utun_sendmsg_x_inject: needs root");
        return;
    }
    let (local, peer) = ("10.98.2.1", "10.98.2.2");
    let mut dev = BsdTun::open_utun(None).expect("open_utun");
    ifconfig(dev.iface(), local, peer);

    // Receiver on the local utun address; staged frames with
    // dst=LOCAL are injected → kernel delivers to this socket.
    let rx = UdpSocket::bind((local, 0)).expect("bind");
    rx.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let port = rx.local_addr().unwrap().port();

    let n = 6usize;
    for i in 0..n {
        let mut f = ip4_udp_frame([10, 98, 2, 2], [10, 98, 2, 1], 50000, port, 24 + i);
        dev.write_stage(&mut f).expect("stage");
    }
    dev.write_flush().expect("flush");

    let mut buf = [0u8; 256];
    for i in 0..n {
        let (len, from) = rx.recv_from(&mut buf).expect("recv staged inject");
        assert_eq!(len, 24 + i);
        assert_eq!(from.ip().to_string(), peer);
    }
}

/// `[eth(14)][IPv4(20)][UDP(8)][payload]` with valid IP checksum
/// (kernel input path verifies it; UDP cksum 0 = unchecked).
fn ip4_udp_frame(src: [u8; 4], dst: [u8; 4], sp: u16, dp: u16, paylen: usize) -> Vec<u8> {
    let ip_tot = 20 + 8 + paylen;
    let mut f = vec![0u8; 14 + ip_tot];
    f[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    let ip = &mut f[14..];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&u16::try_from(ip_tot).unwrap().to_be_bytes());
    ip[8] = 64;
    ip[9] = 17;
    ip[12..16].copy_from_slice(&src);
    ip[16..20].copy_from_slice(&dst);
    let mut sum = 0u32;
    for c in ip[..20].chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([c[0], c[1]]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    ip[10..12].copy_from_slice(&(!u16::try_from(sum).unwrap()).to_be_bytes());
    ip[20..22].copy_from_slice(&sp.to_be_bytes());
    ip[22..24].copy_from_slice(&dp.to_be_bytes());
    ip[24..26].copy_from_slice(&u16::try_from(8 + paylen).unwrap().to_be_bytes());
    f
}
