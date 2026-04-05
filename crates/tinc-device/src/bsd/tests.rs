use super::*;

// ─── Constants

/// `AF_PREFIX_LEN = 4`. The arithmetic that gives offset 10.
/// C uses literal `10` everywhere; we name the prefix length.
#[test]
fn af_prefix_len_4() {
    assert_eq!(AF_PREFIX_LEN, 4);
    // The +10 offset arithmetic.
    assert_eq!(ETH_HLEN - AF_PREFIX_LEN, 10);
    // sizeof(uint32_t). The prefix is `htonl(AF_*)`.
    assert_eq!(AF_PREFIX_LEN, std::mem::size_of::<u32>());
}

/// Verify the read offsets match the C's literals.
#[test]
fn read_offsets() {
    assert_eq!(BsdVariant::Tun.read_offset(), 14);
    assert_eq!(BsdVariant::Utun.read_offset(), 10);
    assert_eq!(BsdVariant::Tap.read_offset(), 0);
}

/// Mode mapping. `:206` in C checks switch-mode-needs-TAP.
#[test]
fn variant_mode() {
    assert_eq!(BsdVariant::Tun.mode(), Mode::Tun);
    assert_eq!(BsdVariant::Utun.mode(), Mode::Tun);
    assert_eq!(BsdVariant::Tap.mode(), Mode::Tap);
}

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

/// `0x86DD` → `htonl(AF_INET6)`. `AF_INET6` VARIES:
/// Linux 10, FreeBSD 28, macOS 30. **CAN'T pin literal
/// bytes.** Pin the STRUCTURE: it's `(libc::AF_INET6 as
/// u32).to_be_bytes()`. On whichever platform this runs,
/// the bytes are right for THAT platform. The kernel
/// reading them is the same platform. Correct.
///
/// (On Linux, where these tests run in CI, this is
/// `[0, 0, 0, 10]`. On macOS it'd be `[0, 0, 0, 30]`.
/// The TEST passes on both because both sides reference
/// `libc::AF_INET6`.)
#[test]
fn prefix_ipv6_is_libc_af_inet6_be() {
    let prefix = to_af_prefix(ETH_P_IPV6).unwrap();
    #[allow(clippy::cast_sign_loss)] // libc::AF_INET6 is a small positive int
    let want = (libc::AF_INET6 as u32).to_be_bytes();
    assert_eq!(prefix, want);
    // NOT: `assert_eq!(prefix, [0, 0, 0, 0x1e])`. That's
    // macOS-only. The test would FAIL on Linux/FreeBSD.
    // The structure-test above is correct everywhere.

    // What we CAN assert: high three bytes are zero (the
    // AF values are all small).
    assert_eq!(&prefix[..3], &[0, 0, 0]);
    // And: the value is small positive (sanity).
    assert!(prefix[3] > 0);
}

/// Unknown ethertype → None. ARP (`0x0806`) is the realistic
/// "this could happen" case:
/// `route.c` shouldn't emit ARP in TUN mode (no ARP in
/// L3-only routing) but a confused config might. The C
/// errors; so do we.
#[test]
fn prefix_unknown() {
    assert!(to_af_prefix(0x0806).is_none()); // ARP
    assert!(to_af_prefix(0x0000).is_none());
    assert!(to_af_prefix(0xFFFF).is_none());
}

/// Round-trip: `from_ip_nibble` → `to_af_prefix`. Not an
/// inverse (different domains: nibble→ethertype vs
/// ethertype→AF) but the COMPOSITION is the BSD utun read-
/// then-write path. IPv4 in, IPv4 prefix out.
#[test]
fn nibble_then_prefix_roundtrip() {
    // IPv4 packet first byte → ETH_P_IP → AF_INET prefix.
    let et = from_ip_nibble(0x45).unwrap();
    assert_eq!(et, ETH_P_IP);
    let prefix = to_af_prefix(et).unwrap();
    assert_eq!(prefix[3], 2); // AF_INET = 2

    // IPv6.
    let et = from_ip_nibble(0x60).unwrap();
    assert_eq!(et, ETH_P_IPV6);
    let prefix = to_af_prefix(et).unwrap();
    // Can't pin the byte; pin that it's the libc value.
    // The cast goes c_int (signed 32-bit) → u32 (lossless
    // for the small positive AF values) → to_be_bytes →
    // last byte.
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

/// `pipe()` for Tun/Utun read tests. Stream-ish is fine
/// (we feed one packet, read once). nix wraps it.
/// Returns `(read_end, write_end)`.
fn pipe() -> (OwnedFd, OwnedFd) {
    nix::unistd::pipe().unwrap()
}

/// Reverse-direction pipe for write tests: device writes,
/// test reads. Returns `(device_side, test_side)`. The
/// device gets the WRITE end of a pipe; the test reads
/// from the READ end.
fn pipe_rev() -> (OwnedFd, OwnedFd) {
    let (r, w) = nix::unistd::pipe().unwrap();
    (w, r)
}

/// `socketpair(SEQPACKET)` for Tap (same as `raw.rs`).
fn seqpacket_pair() -> (OwnedFd, OwnedFd) {
    nix::sys::socket::socketpair(
        nix::sys::socket::AddressFamily::Unix,
        nix::sys::socket::SockType::SeqPacket,
        None,
        nix::sys::socket::SockFlag::SOCK_CLOEXEC,
    )
    .unwrap()
}

/// Read all bytes from a fd until EOF. For checking what
/// the device wrote.
fn drain(fd: &OwnedFd) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 256];
    loop {
        let n = nix::unistd::read(fd.as_raw_fd(), &mut buf).unwrap();
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

/// Utun read: feed `[garbage prefix ×4][IPv4]`. The device
/// reads at +10, IGNORES the prefix, synthesizes ether from
/// the IP nibble. Prefix bytes are CLOBBERED by
/// `set_etherheader`.
///
/// THE TEST OF THE IGNORED-PREFIX OBSERVATION. The garbage
/// `[0xFF; 4]` would be a NONSENSE AF value (`htonl(0xFF)` =
/// `0x000000ff` which is no AF). If the device were
/// decoding the prefix it'd error. It doesn't. It reads
/// `buf[14] >> 4` = `4`, gets `ETH_P_IP`, writes the
/// synthesized header.
#[test]
fn utun_read_ignores_prefix() {
    // What the kernel would write: 4-byte prefix + IP.
    // We feed GARBAGE prefix (all 0xFF) + valid IPv4.
    // If the read path looked at the prefix: it'd error
    // (0xFFFFFFFF is no AF). It doesn't.
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

    // Length: kernel bytes + 10. (NOT +14: the 4-byte
    // prefix is INCLUDED in what the kernel wrote, so it's
    // already in `n` from the read. `inlen + 10`, not
    // `inlen + 14`.)
    assert_eq!(n, kernel_wrote.len() + 10);
    // Ether header: synthesized. The garbage prefix at
    // [10..14] is GONE — set_etherheader's [..12].fill(0)
    // zeroed [10..12]; the ethertype write at [12..14]
    // clobbered [12..14].
    assert_eq!(&buf[0..12], &[0u8; 12]);
    assert_eq!(&buf[12..14], &[0x08, 0x00]); // IPv4
    // IP packet at +14, verbatim.
    assert_eq!(&buf[14..14 + 8], &kernel_wrote[4..]);
    // The garbage 0xFF prefix is NOWHERE in the output.
    // (Well, the high bytes WERE 0xFF — they're now 0x00
    // and 0x08, 0x00. The clobber.)
}

/// Utun read with a REALISTIC prefix: `htonl(AF_INET)`.
/// Same result — prefix still ignored, still clobbered.
/// This is the "well-behaved sender" path; the garbage
/// test above is the "prefix is ignored either way" path.
#[test]
fn utun_read_with_real_prefix() {
    // What a real BSD kernel writes: `htonl(AF_INET)` =
    // [0, 0, 0, 2] (AF_INET=2 everywhere) + IPv4.
    let kernel_wrote = [
        0x00, 0x00, 0x00, 0x02, // htonl(AF_INET)
        0x45, 0x00, 0xCA, 0xFE,
    ];

    let (r, w) = pipe();
    nix::unistd::write(&w, &kernel_wrote).unwrap();
    drop(w);

    let mut bsd = fake_bsd(r, BsdVariant::Utun);
    let mut buf = [0u8; MTU];
    let n = bsd.read(&mut buf).unwrap();

    assert_eq!(n, kernel_wrote.len() + 10);
    // Same synthesis. The fact that the prefix WAS valid
    // doesn't change the output — we never looked at it.
    assert_eq!(&buf[12..14], &[0x08, 0x00]);
    assert_eq!(&buf[14..18], &[0x45, 0x00, 0xCA, 0xFE]);
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

    // First 4 bytes: htonl(AF_INET) = [0, 0, 0, 2].
    // (AF_INET=2 everywhere; this literal is safe.)
    assert_eq!(&got[..4], &[0, 0, 0, 2]);
    // Then the IP payload, verbatim.
    assert_eq!(&got[4..], &[0x45, 0x00, 0xBE, 0xEF]);

    // The frame buffer: bytes [10..14] CLOBBERED by the prefix
    // write. The clobber is observable to the caller (the
    // trait's `&mut [u8]`).
    assert_eq!(&frame[10..14], &[0, 0, 0, 2]);
    // [0..10] untouched (we never wrote there; was already
    // zero).
    // [14..] untouched (the IP payload).
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
    // The frame buffer: UNTOUCHED. We errored before
    // the prefix write.
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

    let (peer, sock) = seqpacket_pair();
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

    let (peer, sock) = seqpacket_pair();
    let mut bsd = fake_bsd(sock, BsdVariant::Tap);
    let n = bsd.write(&mut frame).unwrap();

    assert_eq!(n, len);
    let mut recv = [0u8; 64];
    let rn = nix::unistd::read(peer.as_raw_fd(), &mut recv).unwrap();
    assert_eq!(rn, len);
    assert_eq!(&recv[..rn], &frame);
    // Tap doesn't mutate the buffer (no prefix write).
    assert_eq!(frame[10], 0x0B); // shost[4], untouched
}

// ─── EOF + error paths

/// EOF on any variant → `UnexpectedEof`. Seqpacket gives
/// EOF on close; pipe also gives EOF on close (read
/// returns 0). Both work.
#[test]
fn read_eof_via_seqpacket() {
    let (peer, sock) = seqpacket_pair();
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

/// `mac()` always None (`open()` stub doesn't read it).
/// `fd()` always Some. Surface accessors don't panic.
#[test]
fn device_surface() {
    let (r, _w) = pipe();
    let bsd = fake_bsd(r, BsdVariant::Utun);
    assert!(bsd.mac().is_none());
    assert!(bsd.fd().is_some());
    assert_eq!(bsd.iface(), "fake-Utun");
    assert_eq!(bsd.mode(), Mode::Tun);
}
