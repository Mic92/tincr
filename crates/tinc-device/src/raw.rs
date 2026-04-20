//! `raw_socket_device.c` (145 LOC) — the `PF_PACKET` backend.
//!
//! Bridges tinc onto an existing physical interface (`Interface =
//! eth0`). TAP-only; reads at `+0` since `SOCK_RAW` on `AF_PACKET`
//! delivers the link-layer header directly.
//!
//! ```text
//!   linux:  read vnet_hdr+IP via drain(),         synthesize ether
//!   fd:     read at +14, Android wrote raw IP,      synthesize ether
//!   raw:    read at +0,  kernel wrote raw ethernet, nothing to do
//! ```
//!
//! `routing_mode != RMODE_SWITCH` isn't explicitly rejected (it
//! probably should be). We document via `mode() → Tap`.
//!
//! ## Unsafe-shim matrix
//!
//! ```text
//!   #2 TIOCGWINSZ:   same syscall, nix macro, encoding honest → use
//!   #3 TUNSETIFF:    same syscall, nix macro, encoding lies   → bypass
//!   #4 SCM_RIGHTS:   same syscall, nix safe API, POSIX-clean  → use
//!   #5 SIOCGIFINDEX: different syscall same job, POSIX std    → substitute
//! ```
//!
//! Shim #5: `if_nametoindex(3)` (POSIX 2001) replaces `SIOCGIFINDEX`.
//! STRICTER: errors on overlong names instead of truncating. nix
//! `socket()` handles creation and atomic CLOEXEC; `bind(sockaddr_ll)`
//! is hand-rolled (shim #6) since nix's `LinkAddr` is getters-only.

use std::io;
use std::os::unix::io::{AsFd, AsRawFd, BorrowedFd, OwnedFd};

use crate::{Device, MTU, Mac, Mode, assert_read_buf, read_fd, write_fd};

// Constants — kernel ABI, sed-verified

/// `ETH_P_ALL` — `<linux/if_ether.h>`. gcc-verified `0x0003`.
/// nix's `SockProtocol::EthAll` does the htons for `socket()`;
/// we do it ourselves for `sll_protocol`.
const ETH_P_ALL: u16 = 0x0003;

// RawSocket — the Device impl

/// `PF_PACKET` raw socket device. TAP-only.
///
/// No `mac` field: `SIOCGIFHWADDR` isn't queried here. `raw_socket`
/// attaches to an EXISTING interface (sniffing, not hosting); the
/// daemon doesn't originate ARP replies on a real segment.
/// `mac() → None` is correct despite TAP mode — `linux::Tun` in TAP
/// creates a NEW interface and IS the host, hence the difference.
#[derive(Debug)]
pub struct RawSocket {
    /// `PF_PACKET` socket, `SOCK_RAW`, bound to `iface`. `OwnedFd`
    /// not `File`: this came from `socket()`, not `open()`.
    fd: OwnedFd,

    /// Interface name (validated: `if_nametoindex` succeeded).
    iface: String,
}

impl RawSocket {
    /// Create the `PF_PACKET` socket, look up the interface index,
    /// bind. Config parsing is the daemon's job.
    ///
    /// # Errors
    /// - `PermissionDenied`: `PF_PACKET` needs `CAP_NET_RAW`.
    /// - `NotFound`: no such interface (STRICTER: 16+ byte names
    ///   error here, not silently truncated like C's `strncpy`).
    pub fn open(iface: &str) -> io::Result<Self> {
        use nix::sys::socket::{AddressFamily, SockFlag, SockProtocol, SockType, socket};

        // `socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))`. nix's
        // `EthAll` does the htons; `SOCK_CLOEXEC` is atomic.
        let fd = socket(
            AddressFamily::Packet,
            SockType::Raw,
            SockFlag::SOCK_CLOEXEC,
            SockProtocol::EthAll,
        )?;

        // `if_nametoindex` (POSIX) instead of `SIOCGIFINDEX`: same
        // mapping, but errors on overlong names instead of strncpy-
        // truncating into the wrong interface.
        let ifindex = nix::net::if_::if_nametoindex(iface)?;

        // nix `LinkAddr` is getters-only → raw `libc::bind`.
        bind_packet(fd.as_fd(), ifindex)?;

        Ok(RawSocket {
            fd,
            iface: iface.to_owned(),
        })
    }
}

// bind_packet — shim #6, hand-rolled, trivial

/// Build `sockaddr_ll`, bind the `PF_PACKET` socket to the
/// interface. nix's `LinkAddr` is getters-only (no constructor),
/// so this goes through raw libc.
///
/// SAFETY argument:
/// - `sockaddr_ll` is `repr(C)`, no niche, all fields integers.
///   `mem::zeroed` is sound (same as `linux.rs::ifreq`). The C
///   `struct sockaddr_ll sa = {0}` (`:38`).
/// - We write three fields. The unwritten fields (`sll_hatype`,
///   `sll_pkttype`, `sll_halen`, `sll_addr`) stay zero. The
///   kernel ignores them for `bind` (man 7 packet: "For
///   purposes of binding, only `sll_protocol` and `sll_ifindex`
///   are used." `sll_family` is the discriminant). Zero is a
///   valid don't-care.
/// - `bind` reads exactly `addrlen` bytes from the pointer.
///   `size_of::<sockaddr_ll>()` is 20 (gcc-verified). We pass
///   `&raw const sa` cast to `*const sockaddr` (the kernel
///   discriminates on `sa_family`, finds `AF_PACKET`, reads as
///   `sockaddr_ll`).
#[allow(unsafe_code)]
fn bind_packet(fd: BorrowedFd<'_>, ifindex: libc::c_uint) -> io::Result<()> {
    let sa = sockaddr_ll_packet(ifindex);

    // SAFETY: `sa` is fully initialized (zeroed + 3 writes); `bind`
    // reads exactly `addrlen` (= 20) bytes from a valid stack
    // pointer; the cast is standard sockaddr type-erasure.
    #[allow(clippy::cast_possible_truncation)]
    let addrlen = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
    let ret = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&raw const sa).cast::<libc::sockaddr>(),
            addrlen,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Build a `sockaddr_ll` for `bind`: `{AF_PACKET, htons(ETH_P_ALL),
/// ifindex, 0..}`. Pure; the one `unsafe` is the `mem::zeroed`
/// (sound: `sockaddr_ll` is `repr(C)`, no niche, all integers/
/// bytes — zero is valid for every field). Split from `bind_packet`
/// so the struct construction is independently inspectable and the
/// syscall shim stays one-unsafe.
// ifindex: c_uint→c_int glibc signedness quirk; kernel allocs small positive ints
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
#[allow(unsafe_code)]
fn sockaddr_ll_packet(ifindex: libc::c_uint) -> libc::sockaddr_ll {
    // SAFETY: see fn comment.
    let mut sa: libc::sockaddr_ll = unsafe { std::mem::zeroed() };

    #[allow(clippy::cast_sign_loss)] // AF_PACKET=17 (c_int→c_ushort, fits trivially)
    {
        sa.sll_family = libc::AF_PACKET as libc::c_ushort;
    }
    // Kernel reads `sll_protocol` as `__be16`.
    sa.sll_protocol = ETH_P_ALL.to_be();
    sa.sll_ifindex = ifindex as libc::c_int;

    sa
}

// Device impl — the +0 read/write

impl Device for RawSocket {
    /// The +0 read. Kernel writes ethernet at offset 0; we read at
    /// offset 0. No offset arithmetic. The simplest backend.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        assert_read_buf(buf, "raw_socket");
        // Cap at MTU (jumbo frames on the iface would truncate).
        let n = read_fd(self.fd.as_fd(), &mut buf[..MTU])?;

        // PF_PACKET EOFs when the interface goes down.
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "PF_PACKET socket on {} returned EOF (interface down?)",
                    self.iface
                ),
            ));
        }
        Ok(n)
    }

    /// +0 write. Doesn't mutate `buf`; the trait's `&mut` is for
    /// the linux backend's header stomp.
    fn write(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        write_fd(self.fd.as_fd(), buf)
    }

    /// TAP-only. C doesn't check (probably should — see crate
    /// doc); we DOCUMENT via the unconditional return.
    fn mode(&self) -> Mode {
        Mode::Tap
    }

    fn iface(&self) -> &str {
        &self.iface
    }

    /// No MAC — sniffing an existing iface, not hosting one.
    fn mac(&self) -> Option<Mac> {
        None
    }

    /// The fd, for the daemon's poll loop.
    fn fd(&self) -> Option<BorrowedFd<'_>> {
        Some(self.fd.as_fd())
    }
}

// Tests — +0 via SEQPACKET socketpair (PF_PACKET writes raw
// ethernet, so the read/write logic is fd-agnostic). open() can't be
// driven end-to-end without CAP_NET_RAW + a real interface.

#[cfg(test)]
mod tests {
    use super::*;

    /// `open()` on a bad interface name errors (EPERM/EACCES if no
    /// `CAP_NET_RAW`, else ENODEV/EINVAL from `if_nametoindex`)
    /// instead of panicking.
    ///
    /// The 23-char case proves "no truncation" implicitly — the full
    /// name reaches `if_nametoindex` (C would truncate to 15). The
    /// empty case mirrors the C ioctl path; glibc's
    /// `if_nametoindex("")` sometimes returns EINVAL instead of ENODEV.
    #[test]
    fn open_bad_iface_errors() {
        use io::ErrorKind as K;
        for (name, allowed) in [
            (
                "nonexistent_iface_23chr",
                &[K::PermissionDenied, K::NotFound][..],
            ),
            ("", &[K::PermissionDenied, K::NotFound, K::InvalidInput][..]),
        ] {
            let e = RawSocket::open(name).unwrap_err();
            let ek = e.kind();
            assert!(
                allowed.contains(&ek),
                "open({name:?}): unexpected error kind: {ek:?} ({e})"
            );
        }
    }

    // SEQPACKET (not STREAM/DGRAM): preserves datagram boundary like
    // PF_PACKET AND EOFs on peer close (DGRAM blocks instead, which
    // hung the eof test on first try).

    /// `RawSocket` wrapping one end of a SEQPACKET socketpair; can't
    /// go through `open()` without `CAP_NET_RAW`.
    fn fake_raw(fd: OwnedFd) -> RawSocket {
        RawSocket {
            fd,
            iface: "fake0".to_owned(),
        }
    }

    fn seqpacket_pair() -> (OwnedFd, OwnedFd) {
        nix::sys::socket::socketpair(
            nix::sys::socket::AddressFamily::Unix,
            nix::sys::socket::SockType::SeqPacket,
            None,
            nix::sys::socket::SockFlag::SOCK_CLOEXEC,
        )
        .unwrap()
    }

    /// Read at +0: write an ethernet frame to one end, read it
    /// from the other. Verbatim, byte-for-byte. No offset, no
    /// synthesis. The simplest backend.
    #[test]
    fn read_ether_via_seqpacket() {
        // A minimal ethernet frame: dhost(6) + shost(6) +
        // type(2) + payload. 14-byte header + arbitrary body.
        let frame = [
            // dhost: broadcast
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // shost: arbitrary
            0x52, 0x54, 0x00, 0x12, 0x34, 0x56, // ethertype: IPv4
            0x08, 0x00,
            // payload: 8 bytes (would be IP header in reality;
            // we don't care, the backend doesn't parse)
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        ];
        assert_eq!(frame.len(), 14 + 8);

        let (peer, sock) = seqpacket_pair();
        // Write the frame to `peer`.
        let n = nix::unistd::write(&peer, &frame).unwrap();
        assert_eq!(n, frame.len());

        // Read via the Device impl.
        let mut raw = fake_raw(sock);
        let mut buf = [0u8; MTU];
        let n = raw.read(&mut buf).unwrap();

        // +0: same length, same bytes, no offset.
        assert_eq!(n, frame.len());
        assert_eq!(&buf[..n], &frame);
        // Past n: untouched (zero from init).
        assert_eq!(buf[n], 0);

        // mode/mac/iface as documented.
        assert_eq!(raw.mode(), Mode::Tap);
        assert!(raw.mac().is_none());
        assert_eq!(raw.iface(), "fake0");
        assert!(raw.fd().is_some());
    }

    /// Write at +0: hand the Device a frame, it writes the
    /// whole thing. No strip, no header munging.
    #[test]
    fn write_ether_via_seqpacket() {
        let mut frame = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // dhost
            0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, // shost
            0x86, 0xDD, // ethertype: IPv6
            0xAA, 0xBB, // payload stub
        ];
        let frame_len = frame.len();

        let (peer, sock) = seqpacket_pair();
        let mut raw = fake_raw(sock);

        let n = raw.write(&mut frame).unwrap();
        // Wrote ALL of it. NOT len-14 (that's `fd.rs`). +0.
        assert_eq!(n, frame_len);

        // Read from peer. Same frame, byte-for-byte.
        let mut recv = [0u8; 64];
        let rn = nix::unistd::read(&peer, &mut recv).unwrap();
        assert_eq!(rn, frame_len);
        assert_eq!(&recv[..rn], &frame);

        // The frame buffer is UNCHANGED. `linux.rs::write` zeroes
        // `buf[12..14]` (ethertype → vnet_hdr layout); BSD `Utun`
        // zeroes `buf[10..12]`. We don't. This impl doesn't mutate.
        assert_eq!(frame[10], 0x0B); // shost byte 5, untouched
        assert_eq!(frame[11], 0x0C); // shost byte 6, untouched
    }

    /// EOF: SEQPACKET returns 0 on peer close, triggering the
    /// `n == 0` → `UnexpectedEof` path.
    #[test]
    fn read_eof_via_seqpacket() {
        let (peer, sock) = seqpacket_pair();
        drop(peer); // close write end → EOF on read end

        let mut raw = fake_raw(sock);
        let mut buf = [0u8; MTU];
        let e = raw.read(&mut buf).unwrap_err();

        assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
        // Our error message mentions the iface ("fake0").
        let msg = e.to_string();
        assert!(msg.contains("fake0"), "msg: {msg}");
    }
}
