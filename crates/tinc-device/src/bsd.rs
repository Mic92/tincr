//! BSD/macOS device backend.
//!
//! Three backends dispatched by variant (`offset = ETH_HLEN
//! − len(prefix)`):
//!
//! ```text
//!   TUN/TUNEMU:      +14, raw IP, no prefix       (= fd.rs)
//!   UTUN/TUNIFHEAD:  +10, 4-byte AF prefix        (= linux.rs offset, fd.rs synthesis)
//!   TAP/VMNET:       +0,  raw ethernet            (= raw.rs)
//! ```
//!
//! ## Read ignores the AF prefix
//!
//! Ethertype is synthesized from the IP nibble at `[14]`, ignoring
//! the AF prefix the kernel wrote at `[10..14]`. Decoding the prefix
//! instead would be a behavior change (the nibble is trusted if they
//! ever disagree).
//!
//! ## Write synthesizes the AF prefix
//!
//! Read ethertype from `[12..14]`, map to `htonl(AF_*)`, overwrite
//! `[10..14]`, write at `+10`. `to_af_prefix` is the dual of
//! `from_ip_nibble`.
//!
//! ## `AF_INET6` is platform-varying
//!
//! ```text
//!   Linux:    AF_INET6 = 10  →  prefix bytes 00 00 00 0a
//!   FreeBSD:  AF_INET6 = 28  →  prefix bytes 00 00 00 1c
//!   macOS:    AF_INET6 = 30  →  prefix bytes 00 00 00 1e
//! ```
//!
//! `AF_INET = 2` everywhere. We use `libc::AF_INET6`; tests pin
//! `(libc::AF_INET6 as u32).to_be_bytes()` (structure, not bytes).
//! `0x86DD` is wire-format truth; `AF_INET6` is local convention.
//!
//! ## Compile-on-Linux
//!
//! Read/write logic is fd-agnostic; tested via `pipe()`/seqpacket
//! fakes. `open()` constructors are BSD-gated stubs. TUNEMU/VMNET
//! dropped (external library deps).

use std::io;
use std::os::unix::io::{AsFd, BorrowedFd, OwnedFd};

use crate::ether::{ETH_HLEN, ETH_P_IP, ETH_P_IPV6, from_ip_nibble, set_etherheader};
use crate::{Device, MTU, Mac, Mode, read_fd, write_fd};

// Constants — the +10 prefix length

/// 4-byte AF prefix for utun/tunifhead. C uses literal `10`
/// (`:451`); `ETH_HLEN - AF_PREFIX_LEN = 10` is the read offset.
/// Contents: `htonl(AF_*)` — same SIZE/OFFSET as Linux `tun_pi`
/// (our linux.rs uses `vnet_hdr` instead); different contents (and
/// ignored on read anyway).
const AF_PREFIX_LEN: usize = 4;

// BsdVariant — the offset dispatch

/// BSD device variant. Upstream has six values (four open paths ×
/// three offset behaviors); we carry the three offset behaviors.
/// `TUNEMU`/`VMNET` dropped (lib deps); `UTUN`/`TUNIFHEAD` share
/// the same write path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BsdVariant {
    /// `+14`, raw IP, no prefix. Reads at `+ETH_HLEN`; synthesizes
    /// ethertype from IP nibble. Byte-identical to `fd.rs`.
    Tun,

    /// `+10`, 4-byte AF prefix. Reads at `+10`; the kernel wrote
    /// `htonl(AF_*)` at `[10..14]` then IP at `[14..]`. We IGNORE
    /// the prefix on read (synthesize from IP nibble at `[14]`).
    /// We SYNTHESIZE the prefix on write (read ethertype from
    /// `[12..14]`, map to AF, write at `[10..14]`).
    Utun,

    /// `+0`, raw ethernet. Full frames, nothing to synthesize.
    /// Byte-identical to `raw.rs`.
    Tap,
}

impl BsdVariant {
    /// The read offset. `read(fd, buf + offset, MTU - offset)`.
    /// What route.c expects at `buf[0..14]`: ethernet header.
    /// What the kernel writes at `buf[offset..]`: prefix (if any)
    /// then IP, or full ethernet.
    /// `offset = ETH_HLEN - prefix_len - (does kernel write ether? ETH_HLEN : 0)`.
    ///
    /// `const fn` so the test can `assert_eq!` at compile-time
    /// shape if it wants. `#[inline]` because it's a leaf called
    /// in the hot read loop.
    #[inline]
    #[must_use]
    pub const fn read_offset(self) -> usize {
        match self {
            // Kernel writes raw IP. Room for full ether header.
            BsdVariant::Tun => ETH_HLEN,
            // Kernel writes 4-byte AF prefix then IP. Room for
            // ether header MINUS prefix (which lands in [10..14]
            // and gets overwritten by set_etherheader anyway).
            BsdVariant::Utun => ETH_HLEN - AF_PREFIX_LEN,
            // Kernel writes ethernet. No room needed.
            BsdVariant::Tap => 0,
        }
    }

    /// L2 vs L3. `Tun`/`Utun` → `Mode::Tun` (we route by IP);
    /// `Tap` → `Mode::Tap` (we switch by MAC).
    ///
    /// `RMODE_SWITCH` requires `Tap`. The check goes one direction
    /// (switch needs TAP) but not the other
    /// (router with TAP is allowed in C — `route.c` strips the
    /// ether header). We expose Mode; the daemon picks. Same as
    /// every other backend.
    #[inline]
    #[must_use]
    pub const fn mode(self) -> Mode {
        match self {
            BsdVariant::Tun | BsdVariant::Utun => Mode::Tun,
            BsdVariant::Tap => Mode::Tap,
        }
    }
}

// to_af_prefix — the inverse map (write side, Utun only)

/// Ethertype → 4-byte AF prefix. The dual of `from_ip_nibble`.
///
/// `route.c` always writes a 14-byte ether header (even in TUN
/// mode — the daemon's packet builder doesn't know about offset
/// tricks; the device backend strips on write). The ethertype is
/// at `[12..14]`, big-endian. Read it, map to `AF_*`, `htonl`,
/// memcpy 4 bytes to `[10..14]`. OVERWRITES bytes 12-13
/// (the ethertype slot) — fine, the kernel reconstructs ethertype
/// from AF on its end.
///
/// `None` for unknown ethertype. The caller errors (NOT silent
/// drop). Shouldn't happen (`route.c` only emits IPv4/IPv6 in TUN
/// mode), but defensive.
///
/// **Why `[u8; 4]` not `u32`**: the caller does `buf[10..14].
/// copy_from_slice(&prefix)`. Giving back bytes saves a
/// `to_be_bytes()` at the call site AND makes the test cleaner
/// (compare bytes, not a host-order u32 that you have to think
/// about).
///
/// **The `libc::AF_INET6` per-platform thing**: `AF_INET6` is
/// `10` on Linux, `28` on FreeBSD, `30` on macOS. The bytes this
/// fn returns DIFFER per platform. That's CORRECT — the kernel
/// reading them is the same platform. The test can pin the
/// STRUCTURE (`(libc::AF_INET6 as u32).to_be_bytes()`) but not
/// literal bytes. See `prefix_ipv6_is_libc_af_inet6_be` test.
#[must_use]
#[allow(clippy::cast_sign_loss)] // libc::AF_* are small positive c_ints; as u32 exact
pub(crate) const fn to_af_prefix(ethertype: u16) -> Option<[u8; 4]> {
    // We get the ethertype already host-order from the caller
    // (who read it via `u16::from_be_bytes`).
    let af = match ethertype {
        ETH_P_IP => libc::AF_INET,
        ETH_P_IPV6 => libc::AF_INET6,
        _ => return None,
    };
    // `htonl(AF_*)`. `htonl` of a u32 is `to_be_bytes()` if you
    // want bytes, `.to_be()` if you want a swapped u32. We want
    // bytes for `copy_from_slice`.
    Some((af as u32).to_be_bytes())
}

// BsdTun — the Device impl

/// The variant-dispatched BSD backend.
///
/// `fd`: `OwnedFd` (not `File`): two of the three open paths
/// are sockets (`utun` is `socket(PF_SYSTEM, ...)`; old TUN is
/// `open("/dev/tun*")`). `OwnedFd` is the lowest common
/// denominator. Same `Drop` semantics. Same as `raw.rs`.
///
/// `iface`: stored as resolved by `open()`. For `/dev/tunN` it's
/// `tunN` (strip `/dev/`). For utun it's `utunN` (the kernel
/// picks N; read back via `getsockopt(UTUN_OPT_IFNAME)`). For
/// TAP it's the `TAPGIFNAME` ioctl result. `Open()` stubs fill
/// this; tests use a literal.
///
/// `mac`: NOT stored. `SIOCGIFADDR` (note: not `SIOCGIFHWADDR`;
/// BSD-specific behavior on TAP fds) is queried ONLY if
/// `overwrite_mac` config is set. The default
/// is don't-read. We return `None` (same as `RawSocket`, same
/// rationale: TAP-mode bridging doesn't need `mymac` for ARP
/// because real hosts answer their own ARP). When `overwrite_
/// mac` lands with the `open()` stubs, it becomes an `Option<Mac>`
/// field. NOT YET.
#[derive(Debug)]
pub struct BsdTun {
    /// The device fd. `/dev/tun*` device node OR utun
    /// `PF_SYSTEM` socket. `Drop` closes.
    fd: OwnedFd,

    /// Which offset behavior. Chosen at `open()` time, never
    /// changes.
    variant: BsdVariant,

    /// Interface name as resolved by `open()`. For `iface()`.
    iface: String,
}

// `open()` constructors are `cfg`-gated below. The Device impl
// compiles everywhere; the constructors don't.

// Device impl — variant-dispatched read/write

impl Device for BsdTun {
    /// Read a packet. Three variant arms.
    ///
    /// `clippy::too_many_lines`: this matches the C's three-arm
    /// switch in one fn. Splitting would obscure the parallel
    /// structure (the three arms are MEANT to look similar;
    /// that's the point — they're the SAME logic at three
    /// offsets).
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        debug_assert!(
            buf.len() >= MTU,
            "buf too small for bsd read: {} < {MTU}",
            buf.len()
        );

        let offset = self.variant.read_offset();
        // The slice does the offset arithmetic.
        let n = read_fd(self.fd.as_fd(), &mut buf[offset..MTU])?;

        // `read_fd` already converted `<0`. `==0` is EOF. BSD
        // TUN/utun: doesn't EOF in normal operation (like Linux
        // TUN). BUT: the device CAN be destroyed underneath us
        // (`ifconfig tun0 destroy`). We say something useful
        // (rather than `strerror(0)` = "Success").
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "{} ({:?}) returned EOF (device destroyed?)",
                    self.iface, self.variant
                ),
            ));
        }

        match self.variant {
            // ─── TUN: +14, synthesize
            // Byte-identical to fd.rs.
            BsdVariant::Tun => {
                // IP first byte at `buf[ETH_HLEN]`. Kernel
                // wrote IP at `[14..]`.
                let Some(ethertype) = from_ip_nibble(buf[ETH_HLEN]) else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "{}: unknown IP version nibble {:#x}",
                            self.iface,
                            buf[ETH_HLEN] >> 4
                        ),
                    ));
                };
                set_etherheader(buf, ethertype);
                Ok(n + ETH_HLEN)
            }

            // ─── UTUN: +10, IGNORE prefix, synthesize
            // This arm is the SAME as the TUN arm. The kernel wrote
            // `htonl(AF_*)` at `[10..14]`; we don't read those
            // bytes. The IP first byte is STILL at `[14]` (=
            // `[offset + AF_PREFIX_LEN]` = `[10 + 4]`). The
            // synthesis is identical to the Tun arm.
            //
            // We could merge this with the Tun match arm above.
            // We DON'T — the merge would obscure the
            // IGNORED-prefix observation (the comment above is
            // the value).
            BsdVariant::Utun => {
                // The prefix at `buf[10..14]` is already there
                // (kernel wrote it). We don't read it. The IP
                // first byte is at `[14]` — same as Tun.
                let Some(ethertype) = from_ip_nibble(buf[ETH_HLEN]) else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "{}: unknown IP version nibble {:#x}",
                            self.iface,
                            buf[ETH_HLEN] >> 4
                        ),
                    ));
                };
                // The memset zeroes `[..12]` — that INCLUDES
                // `[10..12]`, the high two bytes of the AF
                // prefix. The
                // ethertype write at `:459-460` clobbers
                // `[12..14]`, the LOW two bytes. The prefix is
                // FULLY overwritten. Wasted I/O on the kernel's
                // part; harmless.
                set_etherheader(buf, ethertype);
                // `inlen + 10`. NOT +14. The 4-byte prefix
                // counted in `inlen` (it's
                // part of what the kernel wrote). +10 not +14
                // because `inlen` already includes 4 bytes of
                // the would-be ether header position.
                Ok(n + offset)
            }

            // ─── TAP: +0, nothing to do
            // Kernel wrote ethernet; route.c wants ethernet.
            // `raw.rs` body verbatim.
            BsdVariant::Tap => Ok(n),
        }
    }

    /// Write a packet. Three arms.
    fn write(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.variant {
            // ─── TUN: write at +14, strip ether
            // The daemon wrote a full ether header (route.c always
            // does); we strip it. Byte-identical to `fd.rs`.
            BsdVariant::Tun => write_fd(self.fd.as_fd(), &buf[ETH_HLEN..]),

            // ─── UTUN: synthesize prefix, write at +10
            // The novel arm. Read ethertype from `[12..14]`, map
            // to AF, write 4-byte prefix at `[10..14]` (CLOBBERING
            // ethertype — fine, kernel
            // reconstructs), write at +10.
            BsdVariant::Utun => {
                let ethertype = u16::from_be_bytes([buf[12], buf[13]]);
                let Some(prefix) = to_af_prefix(ethertype) else {
                    // NOT silent drop. The error message is
                    // "Unknown address family %x" — it calls the
                    // ethertype an "address family" which is a
                    // bit confused (it's an ETHERTYPE, not an
                    // AF; the AF is what we're MAPPING TO). We
                    // say "ethertype" because that's what it is.
                    // The format `%x` is unprefixed hex; we use
                    // `{:#06x}` (prefixed, zero-padded).
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "{}: unknown ethertype {ethertype:#06x} (route.c emitted non-IPv4/IPv6 in TUN mode?)",
                            self.iface
                        ),
                    ));
                };
                // Clobbers `[10..14]`: the high two bytes of
                // ether shost + the ethertype slot. The daemon's
                // route.c filled those with zeros (synthetic
                // header) and the real ethertype respectively;
                // both are throwaway now.
                let offset = ETH_HLEN - AF_PREFIX_LEN; // = 10
                buf[offset..ETH_HLEN].copy_from_slice(&prefix);
                write_fd(self.fd.as_fd(), &buf[offset..])
            }

            // ─── TAP: +0, write all
            // `raw.rs` verbatim.
            BsdVariant::Tap => write_fd(self.fd.as_fd(), buf),
        }
    }

    fn mode(&self) -> Mode {
        self.variant.mode()
    }

    fn iface(&self) -> &str {
        &self.iface
    }

    /// No MAC. `SIOCGIFADDR` is read only if `overwrite_mac`
    /// config is set; default is don't-read. The MAC
    /// query ioctl is BSD-specific (`SIOCGIFADDR` on a TAP fd
    /// gives the link-layer addr; on Linux it gives the IP
    /// addr — DIFFERENT meaning). Stubbed `None` until `open()`
    /// lands.
    fn mac(&self) -> Option<Mac> {
        None
    }

    fn fd(&self) -> Option<BorrowedFd<'_>> {
        Some(self.fd.as_fd())
    }
}

impl AsFd for BsdTun {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

// open() — stubbed, cfg-gated
//
// THREE constructors, all `cfg`-gated to BSD targets. The Linux
// build doesn't see them. Tests construct `BsdTun { fd, variant,
// iface }` directly (module-private fields).
//
// What goes here when stubs become real:
//
//   `open_tun(device: &str) -> io::Result<BsdTun>`
//     `open(device, O_RDWR | O_NONBLOCK)`. The `device` is
//     `/dev/tun0`, `/dev/tun1`, etc. FreeBSD/NetBSD/OpenBSD all
//     have these. `TUNSIFHEAD` ioctl toggles tunifhead mode
//     (4-byte AF prefix); `TUNSIFMODE` sets broadcast/multicast.
//     Shim #7 candidate — ioctls again. Same matrix question as
//     TUNSETIFF. `cfg(any(target_os = "freebsd", "netbsd",
//     "openbsd", "dragonfly"))`.
//
//   `open_utun(unit: Option<u32>) -> io::Result<BsdTun>`
//     `socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)` then
//     `ioctl(CTLIOCGINFO)` to resolve the utun control ID, then
//     `connect(sockaddr_ctl{...})` with the unit number.
//     macOS-specific. `getsockopt(UTUN_OPT_IFNAME)` reads back
//     the kernel-chosen `utunN` name. Shim #8 — the
//     `PF_SYSTEM`/`sockaddr_ctl` types are Apple-only; nix has
//     nothing for these. Hand-rolled. `cfg(target_os = "macos")`.
//
//   `open_tap(device: &str) -> io::Result<BsdTun>`
//     `open(device)` then `TAPGIFNAME` ioctl to read the iface
//     name back. `cfg(any(freebsd, ...))`.
//
// The stubs aren't TODO comments — they're an ACTUAL plan with
// the shim-matrix questions noted. When CI gets a BSD runner,
// this is the worklist.

#[cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]
impl BsdTun {
    /// PLACEHOLDER: BSD open paths land when CI has a BSD
    /// runner. See the block comment above.
    ///
    /// # Errors
    /// Always errors `Unsupported`.
    pub fn open(_variant: BsdVariant) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "BsdTun::open: BSD open paths not yet implemented (read/write logic is; \
             see bsd.rs block comment for the per-variant plan)",
        ))
    }
}

// macOS utun constructor via SYSPROTO_CONTROL socket.
//
// `socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)` then
// `ioctl(CTLIOCGINFO)` to resolve the utun control ID, then
// `connect(sockaddr_ctl{...})` with the unit number.
// `getsockopt(UTUN_OPT_IFNAME)` reads back the kernel-chosen name.
//
// nix wraps every step: `SysControlAddr::from_name` does the
// CTLIOCGINFO ioctl + sockaddr_ctl construction internally,
// `sockopt::UtunIfname` does the `UTUN_OPT_IFNAME` getsockopt, and
// `nix::fcntl` handles O_NONBLOCK/CLOEXEC. The original "nix has
// nothing for these" claim predated nix 0.27.
#[cfg(target_os = "macos")]
mod utun {
    use std::io;
    use std::os::fd::AsRawFd;

    use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
    use nix::sys::socket::{
        AddressFamily, SockFlag, SockProtocol, SockType, SysControlAddr, connect, getsockopt,
        socket, sockopt,
    };

    use super::{BsdTun, BsdVariant};

    const UTUN_CONTROL_NAME: &str = "com.apple.net.utun_control";

    impl BsdTun {
        /// Open a macOS utun device. `unit` is the utun unit number
        /// (0 → utun0, etc.). `None` lets the kernel pick.
        ///
        /// Requires root or appropriate entitlements.
        ///
        /// # Errors
        /// I/O errors from socket/ioctl/connect/getsockopt.
        pub fn open_utun(unit: Option<u32>) -> io::Result<Self> {
            // socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL).
            // macOS has no SOCK_CLOEXEC/SOCK_NONBLOCK type bits; set
            // them via fcntl below (no fork race here — startup-only).
            let fd = socket(
                AddressFamily::System,
                SockType::Datagram,
                SockFlag::empty(),
                SockProtocol::KextControl,
            )?;
            let prev = OFlag::from_bits_retain(fcntl(&fd, FcntlArg::F_GETFL)?);
            fcntl(&fd, FcntlArg::F_SETFL(prev | OFlag::O_NONBLOCK))?;
            fcntl(&fd, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;

            // CTLIOCGINFO + sockaddr_ctl{sc_unit}. Kernel uses
            // 1-based unit: sc_unit=0 means "pick for me",
            // sc_unit=N+1 means utunN.
            let sc_unit = unit.map_or(0, |u| u + 1);
            let addr = SysControlAddr::from_name(fd.as_raw_fd(), UTUN_CONTROL_NAME, sc_unit)?;
            connect(fd.as_raw_fd(), &addr)?;

            // getsockopt(SYSPROTO_CONTROL, UTUN_OPT_IFNAME).
            let iface = getsockopt(&fd, sockopt::UtunIfname)?
                .to_string_lossy()
                .into_owned();

            Ok(BsdTun {
                fd,
                variant: BsdVariant::Utun,
                iface,
            })
        }
    }
}

// Tests — three offsets, on Linux
//
// All three variants tested via fakes. Tun/Utun via `pipe()`
// (stream-ish is fine; we feed one packet at a time). Tap via
// `socketpair(SEQPACKET)` (datagram boundary + EOF, like
// `raw.rs`).
//
// The Utun tests are the interesting ones: the prefix is INERT
// on read (we feed garbage prefix bytes, verify they're
// overwritten by set_etherheader), and SYNTHESIZED on write
// (we verify the bytes match `(libc::AF_INET as u32).
// to_be_bytes()` — structure-test, not byte-literal-test).

#[cfg(test)]
mod tests;
