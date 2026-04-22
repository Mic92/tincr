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
use crate::{Device, MTU, Mac, Mode, assert_read_buf, read_fd, write_fd};

// Constants — the +10 prefix length

/// 4-byte `htonl(AF_*)` prefix for utun/tunifhead.
/// `ETH_HLEN - AF_PREFIX_LEN = 10` is the read offset.
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

    /// `+10`, 4-byte `htonl(AF_*)` prefix. Ignored on read
    /// (ethertype synthesized from IP nibble); synthesized on write.
    Utun,

    /// `+0`, raw ethernet. Full frames, nothing to synthesize.
    /// Byte-identical to `raw.rs`.
    Tap,
}

impl BsdVariant {
    /// `read(fd, buf + offset, MTU - offset)`: leave room for the
    /// synthetic ether header in front of what the kernel writes.
    #[inline]
    const fn read_offset(self) -> usize {
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

    /// L2 vs L3. The daemon enforces `RMODE_SWITCH` ⇒ `Tap`; we
    /// just report.
    #[inline]
    const fn mode(self) -> Mode {
        match self {
            BsdVariant::Tun | BsdVariant::Utun => Mode::Tun,
            BsdVariant::Tap => Mode::Tap,
        }
    }
}

// to_af_prefix — the inverse map (write side, Utun only)

/// Ethertype → `htonl(AF_*)` 4-byte prefix (utun write side; dual of
/// `from_ip_nibble`). `AF_INET6` varies per platform, so bytes differ
/// — correct, because the same kernel reads them back.
#[expect(clippy::cast_sign_loss)] // libc::AF_* are small positive c_ints; as u32 exact
const fn to_af_prefix(ethertype: u16) -> Option<[u8; 4]> {
    let af = match ethertype {
        ETH_P_IP => libc::AF_INET,
        ETH_P_IPV6 => libc::AF_INET6,
        _ => return None,
    };
    Some((af as u32).to_be_bytes())
}

// BsdTun — the Device impl

/// The variant-dispatched BSD backend. `OwnedFd` not `File`: utun is
/// a `PF_SYSTEM` socket, old TUN/TAP are device nodes.
#[derive(Debug)]
pub struct BsdTun {
    fd: OwnedFd,
    variant: BsdVariant,
    iface: String,
}

// Device impl — variant-dispatched read/write

impl Device for BsdTun {
    /// Read a packet. Three variant arms; same logic at three offsets.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        assert_read_buf(buf, "bsd");

        let offset = self.variant.read_offset();
        // The slice does the offset arithmetic.
        let n = read_fd(self.fd.as_fd(), &mut buf[offset..MTU])?;

        // EOF only happens if the device was destroyed underneath us
        // (`ifconfig tun0 destroy`); say so rather than "Success".
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
            // TUN +14 / UTUN +10 share this arm: IP first byte is at
            // `[14]` either way (UTUN's prefix landed at `[10..14]`
            // and is overwritten by `set_etherheader`). Return
            // `n + offset` — for UTUN the 4-byte prefix is already
            // counted in `n`.
            BsdVariant::Tun | BsdVariant::Utun => {
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
                Ok(n + offset)
            }

            // TAP +0: kernel wrote ethernet; route.c wants ethernet.
            BsdVariant::Tap => Ok(n),
        }
    }

    /// Write a packet. Three arms.
    fn write(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.variant {
            // TUN +14: route.c wrote a full ether header; strip it.
            BsdVariant::Tun => write_fd(self.fd.as_fd(), &buf[ETH_HLEN..]),

            // UTUN +10: map ethertype → AF prefix at `[10..14]`
            // (clobbers the ethertype slot; kernel reconstructs).
            BsdVariant::Utun => {
                let ethertype = u16::from_be_bytes([buf[12], buf[13]]);
                let Some(prefix) = to_af_prefix(ethertype) else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "{}: unknown ethertype {ethertype:#06x} (route.c emitted non-IPv4/IPv6 in TUN mode?)",
                            self.iface
                        ),
                    ));
                };
                let offset = ETH_HLEN - AF_PREFIX_LEN; // = 10
                buf[offset..ETH_HLEN].copy_from_slice(&prefix);
                write_fd(self.fd.as_fd(), &buf[offset..])
            }

            BsdVariant::Tap => write_fd(self.fd.as_fd(), buf),
        }
    }

    fn mode(&self) -> Mode {
        self.variant.mode()
    }

    fn iface(&self) -> &str {
        &self.iface
    }

    /// No MAC — `SIOCGIFADDR` is only queried under `overwrite_mac`;
    /// stubbed `None` until the BSD `open()` paths land.
    fn mac(&self) -> Option<Mac> {
        None
    }

    fn fd(&self) -> Option<BorrowedFd<'_>> {
        Some(self.fd.as_fd())
    }
}

// open() constructors are cfg-gated per target. Tests construct
// `BsdTun { fd, variant, iface }` directly (module-private fields).
//
// FreeBSD/NetBSD/OpenBSD/DragonFly `/dev/tun*` + `TUNSIFHEAD` and
// `/dev/tap*` + `TAPGIFNAME` open paths are not yet wired — they
// land with a BSD CI runner. The variant-dispatched read/write above
// is fd-agnostic and already covered by the pipe/seqpacket tests.

// macOS utun constructor via SYSPROTO_CONTROL socket. nix wraps
// every step (`SysControlAddr::from_name`, `sockopt::UtunIfname`).
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

// Tests — three offsets via pipe/seqpacket fakes; runnable on Linux.
#[cfg(test)]
mod tests;
