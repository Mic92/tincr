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

#![allow(clippy::doc_markdown)]

use std::io;
use std::os::unix::io::{AsRawFd, OwnedFd, RawFd};

use crate::ether::{ETH_HLEN, ETH_P_IP, ETH_P_IPV6, from_ip_nibble, set_etherheader};
use crate::{Device, MTU, Mac, Mode};

// Constants — the +10 prefix length

/// 4-byte AF prefix for utun/tunifhead. C uses literal `10`
/// (`:451`); `ETH_HLEN - AF_PREFIX_LEN = 10` is the read offset.
/// Contents: `htonl(AF_*)` — same SIZE/OFFSET as Linux `tun_pi`
/// (our linux.rs uses vnet_hdr instead); different contents (and
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
    /// then IP, or full ethernet. `offset = ETH_HLEN - prefix_len
    /// - (does kernel write ether? ETH_HLEN : 0)`.
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
///
/// `clippy::cast_sign_loss`: `libc::AF_INET` is `c_int` (signed)
/// but the value is small positive. The `as u32` is exact.
#[must_use]
#[allow(clippy::cast_sign_loss)]
pub(crate) fn to_af_prefix(ethertype: u16) -> Option<[u8; 4]> {
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
/// `iface`: stored as resolved by open(). For `/dev/tunN` it's
/// `tunN` (strip `/dev/`). For utun it's `utunN` (the kernel
/// picks N; read back via `getsockopt(UTUN_OPT_IFNAME)`). For
/// TAP it's the `TAPGIFNAME` ioctl result. Open() stubs fill
/// this; tests use a literal.
///
/// `mac`: NOT stored. `SIOCGIFADDR` (note: not `SIOCGIFHWADDR`;
/// BSD-specific behavior on TAP fds) is queried ONLY if
/// `overwrite_mac` config is set. The default
/// is don't-read. We return `None` (same as `RawSocket`, same
/// rationale: TAP-mode bridging doesn't need `mymac` for ARP
/// because real hosts answer their own ARP). When `overwrite_
/// mac` lands with the open() stubs, it becomes an `Option<Mac>`
/// field. NOT YET.
#[derive(Debug)]
pub struct BsdTun {
    /// The device fd. `/dev/tun*` device node OR utun
    /// `PF_SYSTEM` socket. `Drop` closes.
    fd: OwnedFd,

    /// Which offset behavior. Chosen at open() time, never
    /// changes.
    variant: BsdVariant,

    /// Interface name as resolved by open(). For `iface()`.
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
    #[allow(clippy::too_many_lines)]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        debug_assert!(
            buf.len() >= MTU,
            "buf too small for bsd read: {} < {MTU}",
            buf.len()
        );

        let offset = self.variant.read_offset();
        // The slice does the offset arithmetic.
        let n = read_fd(self.fd.as_raw_fd(), &mut buf[offset..MTU])?;

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
            BsdVariant::Tun => write_fd(self.fd.as_raw_fd(), &buf[ETH_HLEN..]),

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
                write_fd(self.fd.as_raw_fd(), &buf[offset..])
            }

            // ─── TAP: +0, write all
            // `raw.rs` verbatim.
            BsdVariant::Tap => write_fd(self.fd.as_raw_fd(), buf),
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
    /// addr — DIFFERENT meaning). Stubbed `None` until open()
    /// lands.
    fn mac(&self) -> Option<Mac> {
        None
    }

    fn fd(&self) -> Option<RawFd> {
        Some(self.fd.as_raw_fd())
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
    target_os = "macos",
))]
impl BsdTun {
    /// PLACEHOLDER: BSD open paths land when CI has a BSD
    /// runner. The Device impl above is fully tested on Linux
    /// via fakes; only the open() ioctl/socket paths need a
    /// BSD box. See the block comment above for the per-variant
    /// plan.
    ///
    /// # Errors
    /// Always errors `Unsupported`. The real impls replace
    /// this.
    pub fn open(_variant: BsdVariant) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "BsdTun::open: BSD open paths not yet implemented (read/write logic is; \
             see bsd.rs block comment for the per-variant plan)",
        ))
    }
}

// read/write — module-private, the FOURTH instance
//
// Fourth `read_fd`/`write_fd`. `linux.rs`, `fd.rs`, `raw.rs` are
// `cfg(linux)`; this is `cfg(unix)` (compiles on Linux for tests
// AND on BSD for production). The cfg-boundary rule from `ed9af4fb`
// said "they never compile together" — that was true for raw vs
// linux/fd. NOT TRUE for bsd vs the other three: this file
// compiles on Linux (for the tests).
//
// SO: this IS the file where the cfg boundary doesn't separate.
// On a Linux build, `linux::read_fd`, `fd::read_fd`, `raw::
// read_fd`, `bsd::read_fd` ALL exist.
//
// Still don't factor. Four 8-line fns, all module-private, all
// SAFETY-argued in their own context. The factoring would be a
// `#[allow(unsafe_code)] fn` in `lib.rs` that EVERY backend
// reaches — the `forbid(unsafe_code)` boundary becomes "the
// whole crate." Right now the unsafe is scoped to each backend
// module. The 32 LOC of duplication BUYS that scoping. Worth it.
//
// (When `lib.rs` itself needs raw read/write — say, a benchmark
// harness or a `Dummy` variant that actually does I/O — THAT'S
// the factoring trigger. Not "fourth instance.")

/// `read(2)`. BSD TUN/utun fds are datagram (one read = one
/// frame). Same as the other three; same SAFETY argument.
#[allow(unsafe_code)]
fn read_fd(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: `fd` is the BsdTun's owned fd (alive while &mut
    // BsdTun borrowed). `buf` is exclusive `&mut`.
    let ret = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    #[allow(clippy::cast_sign_loss)]
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
    #[allow(clippy::cast_sign_loss)]
    Ok(ret as usize)
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
mod tests {
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
        #[allow(clippy::cast_sign_loss)]
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
        #[allow(clippy::cast_sign_loss)]
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
        #[allow(clippy::cast_sign_loss)]
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
        #[allow(clippy::cast_sign_loss)]
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
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x86, 0xDD,
            0xAA,
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

    /// EOF on any variant → UnexpectedEof. Seqpacket gives
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

    /// Unknown IP nibble (Tun and Utun) → InvalidData.
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

    /// `mac()` always None (open() stub doesn't read it).
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
}
