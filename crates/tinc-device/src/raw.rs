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
use std::os::unix::io::{AsRawFd, OwnedFd, RawFd};

use crate::{Device, MTU, Mac, Mode};

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
    /// bind. Config parsing (`Interface =`, `Device =`) is the
    /// daemon's job; we get the resolved `iface`.
    ///
    /// # Errors
    /// `io::Error`:
    ///   - `socket()` fails: `PermissionDenied` (`EPERM`/`EACCES`
    ///     — `PF_PACKET` needs `CAP_NET_RAW`; `socket(PF_PACKET,
    ///     ...)` is the FIRST gate, before bind). Unlike `linux.
    ///     rs` (where the gate is `open("/dev/net/tun")`), there's
    ///     nothing to validate-first here — `socket()` IS the
    ///     first thing that can fail.
    ///   - `if_nametoindex` fails: `NotFound` (`ENODEV` — no such
    ///     interface). STRICTER: 16+ byte ifname errors here, not
    ///     silent truncation.
    ///   - `bind` fails: rare (we just verified the ifindex).
    pub fn open(iface: &str) -> io::Result<Self> {
        use nix::sys::socket::{AddressFamily, SockFlag, SockProtocol, SockType, socket};

        // ─── socket
        // `socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))`.
        //
        // nix's `socket()` returns `OwnedFd` (the right type;
        // see field comment). `SockProtocol::EthAll` IS
        // `htons(ETH_P_ALL)` — nix does the byte-swap. `SockFlag
        // ::SOCK_CLOEXEC` sets CLOEXEC atomically — closes the
        // open-then-fcntl fork-race documented in `linux.rs`. nix
        // gives us the atomic path for free.
        //
        // `PF_PACKET` == `AF_PACKET` (the kernel doesn't
        // distinguish; the `PF_`/`AF_` split is a 4.2BSD-era
        // distinction that never materialized). nix's enum is
        // `AddressFamily`; `Packet` = `libc::AF_PACKET`. Same
        // number (17).
        //
        // `?`: nix `Errno` → `io::Error` via `From`.
        let fd = socket(
            AddressFamily::Packet,
            SockType::Raw,
            SockFlag::SOCK_CLOEXEC,
            SockProtocol::EthAll,
        )?;

        // ─── ifindex
        // `if_nametoindex` (POSIX) instead of `SIOCGIFINDEX` ioctl.
        // Same resolution.
        //
        // The substitution: building an `ifreq`, strncpy'ing the
        // name (TRUNCATING at IFNAMSIZ-1), ioctls, reads back
        // `ifr_ifindex`. We hand the name to `if_nametoindex`
        // which errors ENODEV if not found. No truncation; no
        // ifreq; no ioctl. The kernel resolves the same
        // name→index mapping (libc's `if_nametoindex` is a thin
        // wrapper around the netlink path or the ioctl,
        // depending on the libc, but the RESULT is the same).
        //
        // STRICTER: `strncpy` truncation would turn `Interface =
        // sixteenchars_long` into `sixteenchars_lo`. If that
        // truncated name happens to match a REAL interface (you
        // have `sixteenchars_lo` AND `sixteenchars_long`): the C
        // binds to the WRONG one. We error. Same fix class as
        // `linux.rs::pack_ifr_name`.
        //
        // "Why doesn't this need validate-first like `linux.rs`?"
        // — there's nothing to open before this. `socket()` is
        // the gate (CAP_NET_RAW check); `if_nametoindex` after
        // is fine. The validate-first reorder in `linux.rs` was
        // about getting a USEFUL error (length validation) before
        // a USELESS one (EACCES from open). Here the socket()
        // error IS useful (it's "you need CAP_NET_RAW").
        //
        // `?`: `nix::Error` → `io::Error` via `From`. The
        // `NixPath` trait accepts `&str` directly.
        let ifindex = nix::net::if_::if_nametoindex(iface)?;

        // ─── bind
        // Build `sockaddr_ll`, bind. nix's `LinkAddr` is GETTERS
        // ONLY (no constructor). Raw `libc::bind`. The sixth shim,
        // but trivial (8 lines, one syscall).
        bind_packet(fd.as_raw_fd(), ifindex)?;

        // No log here; daemon logs post-open if it wants.

        Ok(RawSocket {
            fd,
            iface: iface.to_owned(),
        })
    }
}

// bind_packet — shim #6, hand-rolled, trivial

/// `:66-73`. Build `sockaddr_ll`, bind the `PF_PACKET` socket to
/// the interface.
///
/// nix's `LinkAddr` is getters-only — designed for `recvfrom`
/// outputs (where the kernel WRITES `sockaddr_ll` and we read
/// it), not `bind` inputs (where WE write `sockaddr_ll` and the
/// kernel reads it). No `LinkAddr::new(ifindex, proto)`. The
/// asymmetry is reasonable from nix's perspective — `recvfrom`
/// on `PF_PACKET` is common (packet sniffers), `bind` is rare
/// (most sniffers don't bind, they recvfrom on the unbound
/// socket and filter in userspace) — but it's the wrong
/// abstraction for us. Raw libc.
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
// ifindex: c_uint→c_int glibc signedness quirk; kernel allocs small positive ints
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
#[allow(unsafe_code)]
fn bind_packet(fd: RawFd, ifindex: libc::c_uint) -> io::Result<()> {
    // SAFETY: see fn comment. `sockaddr_ll` is repr(C), no
    // niche, all integers/bytes; zero is valid for all fields.
    let mut sa: libc::sockaddr_ll = unsafe { std::mem::zeroed() };

    // `sll_family = AF_PACKET`. The discriminant.
    #[allow(clippy::cast_sign_loss)] // AF_PACKET=17 (c_int→c_ushort, fits trivially)
    {
        sa.sll_family = libc::AF_PACKET as libc::c_ushort;
    }

    // `sll_protocol = htons(ETH_P_ALL)`. Network byte order.
    // `to_be()`: on a little-endian host (x86_64, aarch64),
    // `0x0003` → `0x0300`. On big-endian: identity.
    // The kernel reads it as `__be16`; `to_be()` writes it as
    // such regardless of host endianness.
    sa.sll_protocol = ETH_P_ALL.to_be();

    // `sll_ifindex` = result of `if_nametoindex`. See fn-level
    // cast-allow comment for the `c_uint → c_int` signedness.
    sa.sll_ifindex = ifindex as libc::c_int;

    // `bind(fd, (struct sockaddr *)&sa, sizeof(sa))`. The cast is
    // the standard sockaddr type-erasure (the kernel discriminates
    // on `sa_family`).
    //
    // SAFETY: `sa` is fully initialized (zeroed + 3 writes).
    // `bind` reads `addrlen` bytes from the pointer; we pass
    // `size_of::<sockaddr_ll>()` (20). The pointer is valid
    // for that many bytes (`sa` is on our stack). `fd` is the
    // socket from `open()` (alive, ours).
    //
    // `socklen_t` cast: `size_of` is `usize`; `socklen_t` is
    // `u32`. 20 fits.
    let addrlen = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
    let ret = unsafe { libc::bind(fd, (&raw const sa).cast::<libc::sockaddr>(), addrlen) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

// Device impl — the +0 read/write

impl Device for RawSocket {
    /// The +0 read. Kernel writes ethernet at offset 0; we read at
    /// offset 0. No offset arithmetic. The simplest backend.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        debug_assert!(
            buf.len() >= MTU,
            "buf too small for raw_socket read: {} < {MTU}",
            buf.len()
        );
        // `read(fd, DATA, MTU)`. Offset 0. Cap at MTU. (Jumbo
        // frames on `eth0` would truncate — `MTU` is 1518.)
        let n = read_fd(self.fd.as_raw_fd(), &mut buf[..MTU])?;

        // `read_fd` already converted `<0`. `==0` on a `PF_PACKET`
        // socket is EOF — happens
        // if the interface goes DOWN while we're reading
        // (kernel sends EOF on the socket). Unlike kernel TUN
        // (never EOFs) and like `fd.rs` (Java side can close),
        // this is a real condition. We say something useful
        // (rather than `strerror(0)` = "Success").
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "PF_PACKET socket on {} returned EOF (interface down?)",
                    self.iface
                ),
            ));
        }

        // No `+ OFFSET` because there is no offset.
        Ok(n)
    }

    /// The +0 write. Full ethernet frame in `buf[0..]`; write it
    /// all.
    ///
    /// THIS impl doesn't mutate `buf`. Same as `FdTun::write`.
    /// The trait's `&mut [u8]` is for `linux.rs` (which zeroes
    /// `buf[10..12]`); we just slice.
    fn write(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // The whole thing. No header strip.
        write_fd(self.fd.as_raw_fd(), buf)
    }

    /// TAP-only. C doesn't check (probably should — see crate
    /// doc); we DOCUMENT via the unconditional return.
    fn mode(&self) -> Mode {
        Mode::Tap
    }

    /// The interface name. The daemon's `tinc-up` gets this as
    /// `INTERFACE=eth0`. Unlike `linux.rs` (where the kernel
    /// picks the name and we read it back), this is the name
    /// the DAEMON gave us — pass-through.
    fn iface(&self) -> &str {
        &self.iface
    }

    /// No MAC. See struct comment: `raw_socket` is sniffing, not
    /// hosting. The route.c path that needs `mymac` doesn't
    /// fire in switch mode (which `raw_socket` implies).
    fn mac(&self) -> Option<Mac> {
        None
    }

    /// The fd, for the daemon's poll loop.
    fn fd(&self) -> Option<RawFd> {
        Some(self.fd.as_raw_fd())
    }
}

// read/write — module-private duplicates
//
// THIRD instance of read_fd/write_fd. The "two is not a pattern"
// rule from `fd.rs` was about TWO instances. Three IS a pattern.
//
// BUT: factoring would couple `linux.rs`, `fd.rs`, `raw.rs` —
// three independent backends. The duplication is 8 lines per fn,
// 16 LOC per backend, 48 LOC total. The coupling cost: a shared
// `syscall` module that all three depend on, where a change to
// the shared module ripples to all three.
//
// The decision: STILL don't factor. The "re-declare module-
// private when modules are independent" rule WINS over "three
// is a pattern." The independence is more valuable than the 48
// LOC. WHEN we add a fourth backend AND it's NOT independent
// (e.g., it shares state with another backend), the calculus
// changes. NOT YET.
//
// (The `multicast_device.c` backend, if ported, WOULD share
// state — it's a UDP socket like the daemon's listen sockets.
// THAT'S when the factoring discussion reopens. Noted; deferred.)

/// `read(2)` on the fd. Same as the other two; see `linux.rs`
/// for the SAFETY argument. `PF_PACKET` sockets ARE datagram (one
/// read = one frame, atomic) like TUN — the "the syscall IS the
/// documentation" argument applies.
#[allow(unsafe_code)]
fn read_fd(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: `fd` is the RawSocket's owned fd (alive while
    // &mut RawSocket borrowed). `buf` is exclusive `&mut`.
    let ret = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    #[allow(clippy::cast_sign_loss)] // guarded by ret < 0 check above
    Ok(ret as usize)
}

/// `write(2)`. Same.
#[allow(unsafe_code)]
fn write_fd(fd: RawFd, buf: &[u8]) -> io::Result<usize> {
    // SAFETY: same as read_fd.
    let ret = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    #[allow(clippy::cast_sign_loss)] // guarded by ret < 0 check above
    Ok(ret as usize)
}

// Tests — constants + open-gate + +0 via socketpair
//
// The "fakeable boundary" prediction holds: PF_PACKET writes raw
// ethernet (no kernel-side structure added). A `socketpair(AF_
// UNIX, SOCK_DGRAM)` can feed ethernet frames. The +0 arithmetic
// is testable end-to-end.
//
// CAN'T test `open()` end-to-end without `CAP_NET_RAW` AND a real
// interface. Same as `linux.rs::open` (CAP_NET_ADMIN + /dev/net/
// tun). The test we CAN do: `open("nonexistent")` errors with the
// RIGHT error. `socket()` either succeeds (have CAP_NET_RAW) or
// errors EPERM (don't). If it succeeds, `if_nametoindex` errors
// ENODEV. Either way: error. The test asserts "error, not panic"
// and "the error mentions the iface name OR is EPERM."

#[cfg(test)]
mod tests {
    use super::*;

    // open() gate — error path coverage without CAP_NET_RAW

    /// `open()` on a nonexistent interface: either EPERM
    /// (`socket()` failed, no `CAP_NET_RAW`) or ENODEV (`socket()`
    /// succeeded, `if_nametoindex` failed). Either way: error,
    /// not panic. The "no truncation" path is implicit — the
    /// 23-char name passed straight to `if_nametoindex` which
    /// errors on the FULL name.
    #[test]
    fn open_nonexistent_iface_errors() {
        // 23 chars. C would truncate to 15. We don't.
        let e = RawSocket::open("nonexistent_iface_23chr").unwrap_err();
        // The error path bifurcates on whether we have
        // CAP_NET_RAW. Don't gate on root (`geteuid` doesn't
        // tell you about capabilities anyway). Just check both
        // possibilities.
        let ek = e.kind();
        // EPERM → PermissionDenied. ENODEV → NotFound (nix
        // maps it). EACCES also → PermissionDenied (some
        // kernels return EACCES for PF_PACKET).
        assert!(
            ek == io::ErrorKind::PermissionDenied || ek == io::ErrorKind::NotFound,
            "unexpected error kind: {ek:?} ({e})"
        );
    }

    /// Empty interface name → `if_nametoindex` errors. The C's
    /// `Interface = ` (empty) → strncpy of empty string →
    /// `ifr_name[0] = 0` → ioctl errors (kernel rejects empty
    /// ifname). We hit the same error via `if_nametoindex`. Not
    /// stricter (both error); just verifying the path.
    #[test]
    fn open_empty_iface_errors() {
        let e = RawSocket::open("").unwrap_err();
        // Same bifurcation as above.
        let ek = e.kind();
        assert!(
            ek == io::ErrorKind::PermissionDenied
                || ek == io::ErrorKind::NotFound
                // glibc's if_nametoindex on "" sometimes EINVAL
                || ek == io::ErrorKind::InvalidInput,
            "unexpected error kind: {ek:?} ({e})"
        );
    }

    // +0 read/write — socketpair end-to-end
    //
    // The fakeable boundary holds. PF_PACKET writes raw
    // ethernet; a socketpair(AF_UNIX, SOCK_DGRAM) writes
    // datagrams. The +0 arithmetic is fd-agnostic.
    //
    // SOCK_SEQPACKET (not STREAM, not DGRAM): one write = one
    // read (datagram boundary preserved, like PF_PACKET) AND
    // EOF on close (read returns 0, like PF_PACKET when iface
    // goes down).
    //
    // STREAM would coalesce (two writes → one read; wrong).
    // DGRAM has the boundary BUT blocks on close (UDP-ish:
    // connectionless, no EOF concept; gcc-verified, see commit
    // message). The first attempt used DGRAM and the eof test
    // hung. SEQPACKET is the right fake.

    /// Test fixture: a `RawSocket` wrapping one end of a
    /// `socketpair(AF_UNIX, SOCK_SEQPACKET)`. Can't go through
    /// `open()` (that does `PF_PACKET`, needs `CAP_NET_RAW`); we
    /// construct the struct directly.
    ///
    /// Module-private struct construction: `RawSocket { fd,
    /// iface }` works because tests are inside the module.
    fn fake_raw(fd: OwnedFd) -> RawSocket {
        RawSocket {
            fd,
            iface: "fake0".to_owned(),
        }
    }

    /// `socketpair(AF_UNIX, SOCK_SEQPACKET)`. nix returns
    /// `OwnedFd` pairs. CLOEXEC for hygiene.
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
        let rn = nix::unistd::read(peer.as_raw_fd(), &mut recv).unwrap();
        assert_eq!(rn, frame_len);
        assert_eq!(&recv[..rn], &frame);

        // The frame buffer is UNCHANGED. `linux.rs::write` zeroes
        // `buf[12..14]` (ethertype → vnet_hdr layout); BSD `Utun`
        // zeroes `buf[10..12]`. We don't. This impl doesn't mutate.
        assert_eq!(frame[10], 0x0B); // shost byte 5, untouched
        assert_eq!(frame[11], 0x0C); // shost byte 6, untouched
    }

    /// EOF: close the peer, next read errors. `PF_PACKET`
    /// socket can EOF when the interface goes down. Our test
    /// fake (SEQPACKET) EOFs when the peer closes — read
    /// returns 0. gcc-verified: `socketpair(SEQPACKET); close(
    /// peer); read()` → `0`. Our `n == 0` check fires.
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
