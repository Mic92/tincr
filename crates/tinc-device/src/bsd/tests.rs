use super::*;

// ─── to_af_prefix — the inverse map

/// `0x0800` → `htonl(AF_INET)`. `AF_INET = 2` everywhere
/// (4.2BSD legacy). Bytes are `[0, 0, 0, 2]` ON ALL
/// PLATFORMS — this one we CAN pin literally.
#[test]
fn prefix_ipv4_is_af_inet_be() {
    let prefix = to_af_prefix(ETH_P_IP).unwrap();
    // The structure: big-endian u32 of the libc constant.
    #[allow(clippy::cast_sign_loss)] // libc::AF_INET is a small positive int
    let want = (libc::AF_INET as u32).to_be_bytes();
    assert_eq!(prefix, want);
    // The literal: AF_INET is 2 everywhere (verified vs
    // libc bsd/apple/mod.rs:2776, freebsdlike/mod.rs:821,
    // netbsdlike/mod.rs:443, linux_like/mod.rs:641).
    assert_eq!(prefix, [0, 0, 0, 2]);
}

/// `0x86DD` → `htonl(AF_INET6)`. `AF_INET6` varies per platform, so
/// pin the structure (`(libc::AF_INET6 as u32).to_be_bytes()`), not
/// literal bytes.
#[test]
fn prefix_ipv6_is_libc_af_inet6_be() {
    let prefix = to_af_prefix(ETH_P_IPV6).unwrap();
    #[allow(clippy::cast_sign_loss)] // libc::AF_INET6 is a small positive int
    let want = (libc::AF_INET6 as u32).to_be_bytes();
    assert_eq!(prefix, want);
    // High three bytes always zero (AF values are small).
    assert_eq!(&prefix[..3], &[0, 0, 0]);
    assert!(prefix[3] > 0);
}

/// Unknown ethertype → None.
#[test]
fn prefix_unknown() {
    assert!(to_af_prefix(0x0806).is_none()); // ARP
    assert!(to_af_prefix(0x0000).is_none());
    assert!(to_af_prefix(0xFFFF).is_none());
}

/// `from_ip_nibble` → `to_af_prefix` composition is the utun
/// read-then-write path.
#[test]
fn nibble_then_prefix_roundtrip() {
    let et = from_ip_nibble(0x45).unwrap();
    assert_eq!(et, ETH_P_IP);
    let prefix = to_af_prefix(et).unwrap();
    assert_eq!(prefix[3], 2); // AF_INET = 2

    // IPv6.
    let et = from_ip_nibble(0x60).unwrap();
    assert_eq!(et, ETH_P_IPV6);
    let prefix = to_af_prefix(et).unwrap();
    #[allow(clippy::cast_sign_loss)] // libc::AF_INET6 is a small positive int
    let af6_low = (libc::AF_INET6 as u32).to_be_bytes()[3];
    assert_eq!(prefix[3], af6_low);
}

// ─── Fixtures

/// Construct a `BsdTun` directly. Can't use `open()` (cfg-
/// gated to BSD targets). Module-private fields.
fn fake_bsd(fd: OwnedFd, variant: BsdVariant) -> BsdTun {
    BsdTun {
        fd,
        variant,
        iface: format!("fake-{variant:?}"),
    }
}

fn pipe() -> (OwnedFd, OwnedFd) {
    nix::unistd::pipe().unwrap()
}

/// Returns `(device_write_end, test_read_end)`.
fn pipe_rev() -> (OwnedFd, OwnedFd) {
    let (r, w) = nix::unistd::pipe().unwrap();
    (w, r)
}

/// Datagram socketpair for Tap tests. SEQPACKET on Linux,
/// DGRAM on macOS (which lacks SEQPACKET for `AF_UNIX`).
fn dgram_pair() -> (OwnedFd, OwnedFd) {
    #[cfg(target_os = "linux")]
    let sock_type = nix::sys::socket::SockType::SeqPacket;
    #[cfg(not(target_os = "linux"))]
    let sock_type = nix::sys::socket::SockType::Datagram;
    nix::sys::socket::socketpair(
        nix::sys::socket::AddressFamily::Unix,
        sock_type,
        None,
        nix::sys::socket::SockFlag::empty(),
    )
    .unwrap()
}

/// Read all bytes from a fd until EOF. For checking what
/// the device wrote.
fn drain(fd: &OwnedFd) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 256];
    loop {
        let n = nix::unistd::read(fd, &mut buf).unwrap();
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    out
}

// ─── Tun: +14 (= fd.rs)

/// Tun read: feed an IPv4 packet to the pipe; the device
/// reads at +14, synthesizes the ether header. Byte-
/// identical behavior to `fd.rs::read_ipv4_via_pipe`.
#[test]
fn tun_read_ipv4_via_pipe() {
    // A minimal IPv4 packet: just the first byte matters
    // for synthesis. `0x45` = version 4, IHL 5.
    let ip = [0x45u8, 0x00, 0x00, 0x14, 0, 0, 0, 0];

    let (r, w) = pipe();
    nix::unistd::write(&w, &ip).unwrap();
    drop(w); // close write end so a second read would EOF

    let mut bsd = fake_bsd(r, BsdVariant::Tun);
    let mut buf = [0xAAu8; MTU];
    let n = bsd.read(&mut buf).unwrap();

    // Length: IP bytes + 14 synthetic ether bytes.
    assert_eq!(n, ip.len() + ETH_HLEN);
    // Ether header: zero MACs.
    assert_eq!(&buf[0..12], &[0u8; 12]);
    // Ethertype: IPv4 BE.
    assert_eq!(&buf[12..14], &[0x08, 0x00]);
    // IP packet at +14, verbatim.
    assert_eq!(&buf[14..14 + ip.len()], &ip);

    assert_eq!(bsd.mode(), Mode::Tun);
}

/// Tun write: full ether frame in; IP packet out (header
/// stripped). Byte-identical to `fd.rs`.
#[test]
fn tun_write_strips_ether() {
    // Full frame: 14-byte ether header + payload.
    let mut frame = [
        0, 0, 0, 0, 0, 0, // dhost
        0, 0, 0, 0, 0, 0, // shost
        0x08, 0x00, // ethertype IPv4
        0x45, 0x00, 0xDE, 0xAD, // IP-ish payload
    ];

    let (dev, test_r) = pipe_rev();
    let mut bsd = fake_bsd(dev, BsdVariant::Tun);
    let n = bsd.write(&mut frame).unwrap();

    // Wrote len-14. NOT the full frame.
    assert_eq!(n, frame.len() - ETH_HLEN);

    drop(bsd); // close write end → drain hits EOF
    let got = drain(&test_r);
    // Just the IP payload. Ether header stripped.
    assert_eq!(&got, &[0x45, 0x00, 0xDE, 0xAD]);
}

// ─── Utun: +10, IGNORE prefix (read), SYNTHESIZE (write)

/// Utun read ignores the AF prefix: feed a garbage `[0xFF;4]`
/// prefix + valid IPv4. If read decoded the prefix it would error;
/// instead it synthesizes from the IP nibble at `[14]` and
/// `set_etherheader` overwrites the garbage.
#[test]
fn utun_read_ignores_prefix() {
    let kernel_wrote = [
        0xFF, 0xFF, 0xFF, 0xFF, // garbage prefix
        0x45, 0x00, 0x00, 0x14, // IPv4, IHL=5, len=20
        0xDE, 0xAD, 0xBE, 0xEF, // ...rest
    ];

    let (r, w) = pipe();
    nix::unistd::write(&w, &kernel_wrote).unwrap();
    drop(w);

    let mut bsd = fake_bsd(r, BsdVariant::Utun);
    let mut buf = [0xAAu8; MTU];
    let n = bsd.read(&mut buf).unwrap();

    // +10, not +14: the 4-byte prefix is already counted in `n`.
    assert_eq!(n, kernel_wrote.len() + 10);
    // Garbage prefix at [10..14] fully overwritten by set_etherheader.
    assert_eq!(&buf[0..12], &[0u8; 12]);
    assert_eq!(&buf[12..14], &[0x08, 0x00]); // IPv4
    assert_eq!(&buf[14..14 + 8], &kernel_wrote[4..]);
}

/// Utun write: ether frame in → AF prefix synthesized →
/// `[prefix][IP]` out at +10. THE NOVEL CODE PATH.
#[test]
fn utun_write_synthesizes_prefix() {
    // Full ether frame as route.c would emit: zero MACs
    // (synthetic), real ethertype, IP payload.
    let mut frame = [
        0, 0, 0, 0, 0, 0, // dhost (synthetic, zero)
        0, 0, 0, 0, 0, 0, // shost (synthetic, zero)
        0x08, 0x00, // ethertype: IPv4
        0x45, 0x00, 0xBE, 0xEF, // IP
    ];

    let (dev, test_r) = pipe_rev();
    let mut bsd = fake_bsd(dev, BsdVariant::Utun);
    let n = bsd.write(&mut frame).unwrap();

    // Wrote len-10. (4 prefix bytes + IP. Ether MACs at
    // [0..10] stripped.)
    assert_eq!(n, frame.len() - 10);

    drop(bsd);
    let got = drain(&test_r);

    // htonl(AF_INET) = [0,0,0,2] (AF_INET=2 everywhere).
    assert_eq!(&got[..4], &[0, 0, 0, 2]);
    assert_eq!(&got[4..], &[0x45, 0x00, 0xBE, 0xEF]);

    // [10..14] clobbered by the prefix write (the trait's `&mut`).
    assert_eq!(&frame[10..14], &[0, 0, 0, 2]);
    assert_eq!(&frame[14..], &[0x45, 0x00, 0xBE, 0xEF]);
}

/// Utun write IPv6: prefix is `htonl(AF_INET6)`. CAN'T
/// pin literal bytes (per-platform). Pin structure.
#[test]
fn utun_write_synthesizes_ipv6_prefix() {
    let mut frame = [
        0, 0, 0, 0, 0, 0, // dhost
        0, 0, 0, 0, 0, 0, // shost
        0x86, 0xDD, // ethertype: IPv6
        0x60, 0x00, // IPv6 first bytes
    ];

    let (dev, test_r) = pipe_rev();
    let mut bsd = fake_bsd(dev, BsdVariant::Utun);
    bsd.write(&mut frame).unwrap();

    drop(bsd);
    let got = drain(&test_r);

    // The structure: htonl(AF_INET6) for THIS platform.
    #[allow(clippy::cast_sign_loss)] // libc::AF_INET6 is a small positive int
    let want = (libc::AF_INET6 as u32).to_be_bytes();
    assert_eq!(&got[..4], &want);
    // High three bytes always zero (AF values are small).
    assert_eq!(&got[..3], &[0, 0, 0]);
    // Then IPv6.
    assert_eq!(&got[4..], &[0x60, 0x00]);
}

/// Utun write unknown ethertype → error. The error mentions
/// the ethertype.
#[test]
fn utun_write_unknown_ethertype_errors() {
    let mut frame = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x08, 0x06, // ethertype: ARP
        0x00, 0x01,
    ];

    // Doesn't matter what fd; we error before write.
    // Use a real pipe anyway so the OwnedFd is valid.
    let (dev, _test_r) = pipe_rev();
    let mut bsd = fake_bsd(dev, BsdVariant::Utun);
    let e = bsd.write(&mut frame).unwrap_err();

    assert_eq!(e.kind(), io::ErrorKind::InvalidData);
    let msg = e.to_string();
    assert!(msg.contains("0x0806"), "msg: {msg}");
    // Buffer untouched: errored before the prefix write.
    assert_eq!(&frame[10..14], &[0, 0, 0x08, 0x06]);
}

// ─── Tap: +0 (= raw.rs)

/// Tap read: ethernet in, ethernet out. `raw.rs` verbatim.
#[test]
fn tap_read_ether_via_seqpacket() {
    let frame = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // dhost
        0x52, 0x54, 0x00, 0x12, 0x34, 0x56, // shost
        0x08, 0x00, // IPv4
        0xCA, 0xFE,
    ];

    let (peer, sock) = dgram_pair();
    nix::unistd::write(&peer, &frame).unwrap();

    let mut bsd = fake_bsd(sock, BsdVariant::Tap);
    let mut buf = [0u8; MTU];
    let n = bsd.read(&mut buf).unwrap();

    // +0: same length, same bytes.
    assert_eq!(n, frame.len());
    assert_eq!(&buf[..n], &frame);

    assert_eq!(bsd.mode(), Mode::Tap);
}

/// Tap write: full frame, no munging. `raw.rs` verbatim.
#[test]
fn tap_write_ether_via_seqpacket() {
    let mut frame = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x86, 0xDD, 0xAA,
    ];
    let len = frame.len();

    let (peer, sock) = dgram_pair();
    let mut bsd = fake_bsd(sock, BsdVariant::Tap);
    let n = bsd.write(&mut frame).unwrap();

    assert_eq!(n, len);
    let mut recv = [0u8; 64];
    let rn = nix::unistd::read(&peer, &mut recv).unwrap();
    assert_eq!(rn, len);
    assert_eq!(&recv[..rn], &frame);
    // Tap doesn't mutate the buffer (no prefix write).
    assert_eq!(frame[10], 0x0B); // shost[4], untouched
}

// ─── EOF + error paths

/// EOF → `UnexpectedEof`.
#[test]
#[cfg(target_os = "linux")] // SEQPACKET signals EOF on peer close; DGRAM on macOS doesn't
fn read_eof_via_seqpacket() {
    let (peer, sock) = dgram_pair();
    drop(peer);
    let mut bsd = fake_bsd(sock, BsdVariant::Tap);
    let mut buf = [0u8; MTU];
    let e = bsd.read(&mut buf).unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
    let msg = e.to_string();
    // Mentions the variant.
    assert!(msg.contains("Tap"), "msg: {msg}");
}

/// Unknown IP nibble (Tun and Utun) → `InvalidData`.
/// Feed a packet with version=5 (ST-II, dead).
#[test]
fn tun_read_unknown_nibble_errors() {
    let ip = [0x50u8, 0x00]; // version=5

    let (r, w) = pipe();
    nix::unistd::write(&w, &ip).unwrap();
    drop(w);

    let mut bsd = fake_bsd(r, BsdVariant::Tun);
    let mut buf = [0u8; MTU];
    let e = bsd.read(&mut buf).unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::InvalidData);
    let msg = e.to_string();
    // Mentions the nibble (5).
    assert!(msg.contains("0x5"), "msg: {msg}");
}

/// Same for Utun. The garbage prefix doesn't matter
/// (ignored); the bad nibble does.
#[test]
fn utun_read_unknown_nibble_errors() {
    // Garbage prefix + IP with version=7.
    let kernel_wrote = [0xFF, 0xFF, 0xFF, 0xFF, 0x70, 0x00];

    let (r, w) = pipe();
    nix::unistd::write(&w, &kernel_wrote).unwrap();
    drop(w);

    let mut bsd = fake_bsd(r, BsdVariant::Utun);
    let mut buf = [0u8; MTU];
    let e = bsd.read(&mut buf).unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::InvalidData);
    let msg = e.to_string();
    assert!(msg.contains("0x7"), "msg: {msg}");
}

// ─── Device trait surface
