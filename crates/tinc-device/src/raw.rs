//! `raw_socket_device.c` (145 LOC) — the `PF_PACKET` backend.
//!
//! ──────────── Why this exists ──────────────────────────────────────
//!
//! Bridge tinc onto a REAL ethernet segment without TAP. The kernel
//! TAP backend creates a virtual interface; the daemon writes
//! ethernet frames in, they appear on the virtual NIC. THIS backend
//! attaches to an EXISTING physical interface: `Interface = eth0`,
//! daemon reads/writes raw ethernet frames straight off the wire.
//!
//! Use case: tinc as a layer-2 bridge between sites. The daemon
//! sniffs all traffic on `eth0`, encrypts it, ships it to peers,
//! who write it onto THEIR `eth0`. Transparent ethernet extension.
//! Niche (most setups use TAP + bridge utils), but the C supports
//! it since 2002.
//!
//! ──────────── The +0 trick — there ISN'T one ───────────────────────
//!
//! `linux.rs` reads at +10 (kernel writes `tun_pi`). `fd.rs`
//! reads at +14 (Android writes raw IP). THIS reads at +0 (kernel
//! writes raw ethernet — `SOCK_RAW` on `AF_PACKET` means "give me
//! the link-layer header"). `route.c` wants ethernet at offset 0;
//! the kernel writes ethernet at offset 0. No synthesis. No offset
//! arithmetic. The simplest backend.
//!
//! ```text
//!   linux:  read at +10, kernel wrote tun_pi(4)+IP, synthesize ether
//!   fd:     read at +14, Android wrote raw IP,      synthesize ether
//!   raw:    read at +0,  kernel wrote raw ethernet, NOTHING TO DO
//! ```
//!
//! Consequence: TAP-only. C `:45` doesn't check `routing_mode` (it
//! SHOULD — using raw_socket with `Mode = router` is nonsense, you
//! get IP packets that route.c misinterprets as ethernet). Our
//! `mode()` returns `Mode::Tap` unconditionally. **C-is-WRONG
//! finding (mild): the C should reject `routing_mode != RMODE_
//! SWITCH` like `fd_device.c` does. We don't check either (daemon's
//! job) but we DOCUMENT it via the `Tap`-only return.**
//!
//! ──────────── Shim #5 SUBSTITUTES the syscall ──────────────────────
//!
//! New row class for the unsafe-shim matrix.
//!
//! C does `SIOCGIFINDEX` ioctl (`:60-68`): take an iface name,
//! get back the kernel's interface index (the integer that
//! `sockaddr_ll.sll_ifindex` wants for bind). The ioctl works.
//! BUT: `if_nametoindex(3)` is the POSIX function (since 2001,
//! IEEE 1003.1) that does the SAME RESOLUTION. The C uses the
//! ioctl because it's 2002 code — `if_nametoindex` was brand-new
//! at the time, glibc support was spotty. By 2026 it's everywhere.
//!
//! `nix::net::if_::if_nametoindex` wraps it. We use the wrapper.
//!
//! This is a DIFFERENT shim decision than #2-4. The matrix so far:
//!
//!   #2 TIOCGWINSZ:  same syscall, nix macro,     encoding honest → use
//!   #3 TUNSETIFF:   same syscall, nix macro,     encoding lies   → bypass
//!   #4 SCM_RIGHTS:  same syscall, nix safe API,  POSIX-clean     → use
//!   #5 SIOCGIFINDEX: DIFFERENT syscall does same job, POSIX std  → substitute
//!
//! "Does the wrapper match the kernel's actual contract?" was the
//! decision criterion for #2-4. For #5 the criterion is broader:
//! "is there a HIGHER-LEVEL primitive that does the same job?"
//! `if_nametoindex` IS that primitive. The C's choice was
//! historical; the kernel doesn't care which path you take to get
//! the ifindex.
//!
//! **STRICTER than C**: `if_nametoindex` takes the string as-is
//! and errors `ENODEV` if not found. The C truncates (`strncpy +
//! [IFNAMSIZ-1]=0`, lines 60-61, same as `linux/device.c`) THEN
//! ioctls — `Interface = sixteenchars_long` becomes `sixteenchars
//! _lo`, ioctl finds nothing OR finds the WRONG interface if the
//! truncated name happens to match something. Our path: error
//! immediately. Same fix class as `linux.rs::pack_ifr_name`.
//!
//! ──────────── nix HALF-works for the rest ──────────────────────────
//!
//! `socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))` (`:45`): nix's
//! `socket()` takes `AddressFamily::Packet`, `SockType::Raw`,
//! `SockProtocol::EthAll`. The `EthAll` enum value IS `(ETH_P_ALL
//! as u16).to_be() as i32` — nix did the htons for us. AND:
//! `SockFlag::SOCK_CLOEXEC` sets CLOEXEC atomically. C does open-
//! then-fcntl (`:53-55`), the race we documented in `linux.rs`.
//! nix gives us the better primitive for free.
//!
//! `bind(sockaddr_ll)` (`:70`): nix has `LinkAddr` BUT it's
//! getters-only (designed for `recvfrom` outputs, not `bind`
//! inputs). No constructor that takes `(ifindex, protocol)`. We'd
//! need `unsafe { transmute }` or `from_raw` shenanigans. Raw
//! `libc::bind` with `sockaddr_ll` is cleaner. Shim #6, hand-
//! rolled — but trivial (zeroed struct, three field writes, one
//! syscall, eight lines).
//!
//! So this file is the FIRST hybrid: nix for socket creation +
//! ifindex (the parts where nix is GOOD), libc for bind (the part
//! where nix is half-baked). Three deps, three decisions.

#![allow(clippy::doc_markdown)]

use std::io;
use std::os::unix::io::{AsRawFd, OwnedFd, RawFd};

use crate::{Device, MTU, Mac, Mode};

// ═══════════════════════════════════════════════════════════════════
// Constants — kernel ABI, sed-verified
// ═══════════════════════════════════════════════════════════════════

/// `ETH_P_ALL` — `<linux/if_ether.h>`. "All protocols." Passing
/// this as the socket protocol means "give me every frame on this
/// interface, regardless of ethertype." gcc-verified: `printf("%d",
/// ETH_P_ALL)` → `3` (`0x0003`). Used as `htons(ETH_P_ALL)` in the
/// socket call (C `:45`) AND in `sll_protocol` (C `:67`). nix's
/// `SockProtocol::EthAll` does the htons for the socket call; for
/// `sll_protocol` we do it ourselves.
const ETH_P_ALL: u16 = 0x0003;

// ═══════════════════════════════════════════════════════════════════
// RawSocket — the Device impl
// ═══════════════════════════════════════════════════════════════════

/// `raw_socket_devops` (`raw_socket_device.c:112-117`). The
/// `PF_PACKET` backend. TAP-only.
///
/// `iface`: the interface name as RESOLVED. The C reads it from
/// `Interface =` config (default `"eth0"`, `:40-42`). The daemon
/// does the config read; we get the resolved name. `Interface`
/// is mandatory for this backend (unlike `linux.rs` where the
/// kernel picks `tun0` if you don't say); `eth0` default is the
/// daemon's job.
///
/// No `mac` field: the C doesn't query SIOCGIFHWADDR for raw_
/// socket. The route.c ARP-reply path needs `mymac` for TAP, but
/// raw_socket is bridging — the daemon doesn't ORIGINATE arp
/// replies on a real ethernet segment (the real hosts do). The
/// `mymac` global stays `{0}` in C. We return `None`. Same as
/// `FdTun`.
///
/// (Is `None` correct for a TAP-mode backend? `linux.rs::Tun`
/// in TAP mode returns `Some(mac)`. The difference: TAP creates
/// a NEW interface — the daemon IS the host on that interface,
/// so it needs a MAC. raw_socket attaches to an EXISTING
/// interface — the daemon is sniffing, not hosting. The route.c
/// path that uses `mymac` checks `routing_mode` first; in switch
/// mode (which is what raw_socket implies) the path that needs
/// `mymac` doesn't fire. So `None` is correct. The `linux::Tap`
/// vs `raw::RawSocket` MAC difference is a real semantic
/// distinction, not an inconsistency.)
#[derive(Debug)]
pub struct RawSocket {
    /// `PF_PACKET` socket, `SOCK_RAW`, bound to `iface`.
    /// `OwnedFd` not `File`: this is a SOCKET, not a file. Same
    /// `Drop` semantics (close on drop), but `OwnedFd` is the
    /// honest type. `linux.rs` uses `File` because `/dev/net/tun`
    /// IS a device file you `open()`. `socket()` returns a
    /// socket; `OwnedFd` (Rust 1.63+) is the generic owner.
    fd: OwnedFd,

    /// The interface name. For `iface()` and error messages.
    /// Stored as resolved by the daemon — already validated
    /// (`if_nametoindex` succeeded with it).
    iface: String,
}

impl RawSocket {
    /// `setup_device` (`raw_socket_device.c:36-78`). Create the
    /// `PF_PACKET` socket, look up the interface index, bind.
    ///
    /// The C ALSO reads `Interface =` and `Device =` config
    /// (`:40-46`). NOT here: daemon's job. We get the resolved
    /// `iface`. The C's `Device = ` for raw_socket is just a
    /// label (it doesn't `open()` it like `linux.rs` opens
    /// `/dev/net/tun`); we don't carry it.
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
    ///     interface; the C ioctl errors the same). The "STRICTER
    ///     than C" path: 16+ byte ifname errors here, not silent
    ///     truncation.
    ///   - `bind` fails: rare (we just verified the ifindex). The
    ///     C check `:70` covers it.
    pub fn open(iface: &str) -> io::Result<Self> {
        use nix::sys::socket::{AddressFamily, SockFlag, SockProtocol, SockType, socket};

        // ─── socket ─────────────────────────────────────────────────
        // C `:45`: `socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))`.
        //
        // nix's `socket()` returns `OwnedFd` (the right type;
        // see field comment). `SockProtocol::EthAll` IS
        // `htons(ETH_P_ALL)` — nix does the byte-swap. `SockFlag
        // ::SOCK_CLOEXEC` sets CLOEXEC atomically — the C does
        // open-then-fcntl (`:53-55`), which has the fork-race we
        // documented in `linux.rs`. nix gives us the atomic path
        // for free.
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

        // ─── ifindex ────────────────────────────────────────────────
        // C `:60-68`: SIOCGIFINDEX ioctl. We use `if_nametoindex`
        // instead — the POSIX function, same resolution.
        //
        // The substitution: C builds an `ifreq`, strncpy's the
        // name (TRUNCATING at IFNAMSIZ-1), ioctls, reads back
        // `ifr_ifindex`. We hand the name to `if_nametoindex`
        // which errors ENODEV if not found. No truncation; no
        // ifreq; no ioctl. The kernel resolves the same
        // name→index mapping (libc's `if_nametoindex` is a thin
        // wrapper around the netlink path or the ioctl,
        // depending on the libc, but the RESULT is the same).
        //
        // STRICTER: C `:60-61` truncates `Interface =
        // sixteenchars_long` to `sixteenchars_lo`. If that
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

        // ─── bind ───────────────────────────────────────────────────
        // C `:66-73`: build `sockaddr_ll`, bind. nix's `LinkAddr`
        // is GETTERS ONLY (no constructor). Raw `libc::bind`.
        // The sixth shim, but trivial (8 lines, one syscall).
        bind_packet(fd.as_raw_fd(), ifindex)?;

        // C `:75`: `logger(LOG_INFO, "%s is a %s")`. Not here;
        // daemon logs post-open if it wants.

        Ok(RawSocket {
            fd,
            iface: iface.to_owned(),
        })
    }
}

// ═══════════════════════════════════════════════════════════════════
// bind_packet — shim #6, hand-rolled, trivial
// ═══════════════════════════════════════════════════════════════════

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
///
/// `clippy::cast_possible_truncation` for `ifindex as i32`:
/// `if_nametoindex` returns `c_uint` (unsigned); `sll_ifindex`
/// is `c_int` (signed). Kernel ifindexes are small positive
/// integers (1-based, allocated sequentially); 2 billion
/// interfaces would overflow. The C does the same implicit
/// conversion (`:68`: `ifr.ifr_ifindex` is `int`, no cast).
/// libc's signedness mismatch is a historical glibc quirk.
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
#[allow(unsafe_code)]
fn bind_packet(fd: RawFd, ifindex: libc::c_uint) -> io::Result<()> {
    // SAFETY: see fn comment. `sockaddr_ll` is repr(C), no
    // niche, all integers/bytes; zero is valid for all fields.
    let mut sa: libc::sockaddr_ll = unsafe { std::mem::zeroed() };

    // C `:66`: `sa.sll_family = AF_PACKET`. The discriminant.
    // `c_ushort` cast: `AF_PACKET` is `c_int` in libc; the
    // struct field is `c_ushort`. Value is 17, fits trivially.
    #[allow(clippy::cast_sign_loss)]
    {
        sa.sll_family = libc::AF_PACKET as libc::c_ushort;
    }

    // C `:67`: `sa.sll_protocol = htons(ETH_P_ALL)`. Network
    // byte order. `to_be()`: on a little-endian host (x86_64,
    // aarch64), `0x0003` → `0x0300`. On big-endian: identity.
    // The kernel reads it as `__be16`; `to_be()` writes it as
    // such regardless of host endianness.
    sa.sll_protocol = ETH_P_ALL.to_be();

    // C `:68`: `sa.sll_ifindex = ifr.ifr_ifindex`. The result
    // of our `if_nametoindex`. See fn-level cast-allow comment
    // for the `c_uint → c_int` signedness.
    sa.sll_ifindex = ifindex as libc::c_int;

    // C `:70`: `bind(device_fd, (struct sockaddr *)&sa,
    // sizeof(sa))`. The cast is the standard sockaddr type-
    // erasure (the kernel discriminates on `sa_family`).
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

// ═══════════════════════════════════════════════════════════════════
// Device impl — the +0 read/write
// ═══════════════════════════════════════════════════════════════════

impl Device for RawSocket {
    /// `read_packet` (`raw_socket_device.c:88-100`). The +0 read.
    /// Kernel writes ethernet at offset 0; we read at offset 0.
    /// No offset arithmetic. The simplest backend.
    ///
    /// `clippy::missing_errors_doc`: documented in trait.
    #[allow(clippy::missing_errors_doc)]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        debug_assert!(
            buf.len() >= MTU,
            "buf too small for raw_socket read: {} < {MTU}",
            buf.len()
        );
        // C `:89`: `read(device_fd, DATA, MTU)`. Offset 0. Cap at
        // MTU. (Jumbo frames on `eth0` would truncate. The C
        // doesn't handle jumbo here either — `MTU` is 1518.)
        let n = read_fd(self.fd.as_raw_fd(), &mut buf[..MTU])?;

        // C `:91`: `if(inlen <= 0)`. `read_fd` already converted
        // `<0`. `==0` on a `PF_PACKET` socket is EOF — happens
        // if the interface goes DOWN while we're reading
        // (kernel sends EOF on the socket). Unlike kernel TUN
        // (never EOFs) and like `fd.rs` (Java side can close),
        // this is a real condition. The C errors `strerror(
        // errno)` which is "Success" for `==0` — same UGLY as
        // `linux/device.c`. We say something useful.
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "PF_PACKET socket on {} returned EOF (interface down?)",
                    self.iface
                ),
            ));
        }

        // C `:95`: `packet->len = inlen`. No `+ OFFSET` because
        // there is no offset.
        Ok(n)
    }

    /// `write_packet` (`raw_socket_device.c:102-111`). The +0
    /// write. Full ethernet frame in `buf[0..]`; write it all.
    ///
    /// THIS impl doesn't mutate `buf`. Same as `FdTun::write`.
    /// The trait's `&mut [u8]` is for `linux.rs` (which zeroes
    /// `buf[10..12]`); we just slice.
    ///
    /// `clippy::missing_errors_doc`: documented in trait.
    #[allow(clippy::missing_errors_doc)]
    fn write(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // C `:106`: `write(device_fd, DATA, packet->len)`. The
        // whole thing. No header strip.
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

    /// No MAC. See struct comment: raw_socket is sniffing, not
    /// hosting. The route.c path that needs `mymac` doesn't
    /// fire in switch mode (which raw_socket implies).
    fn mac(&self) -> Option<Mac> {
        None
    }

    /// The fd, for the daemon's poll loop.
    fn fd(&self) -> Option<RawFd> {
        Some(self.fd.as_raw_fd())
    }
}

// ═══════════════════════════════════════════════════════════════════
// read/write — module-private duplicates
// ═══════════════════════════════════════════════════════════════════
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
/// for the SAFETY argument. PF_PACKET sockets ARE datagram (one
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

// ═══════════════════════════════════════════════════════════════════
// Tests — constants + open-gate + +0 via socketpair
// ═══════════════════════════════════════════════════════════════════
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

    // ─────────────────────────────────────────────────────────────────
    // Constants — gcc-verified
    // ─────────────────────────────────────────────────────────────────

    /// `ETH_P_ALL = 0x0003` per `<linux/if_ether.h>`. gcc-
    /// verified.
    #[test]
    fn eth_p_all_is_3() {
        assert_eq!(ETH_P_ALL, 0x0003);
        // libc should agree (it does; same kernel header).
        // libc declares it `c_int` but the kernel value is a
        // 16-bit ethertype; the i32 → u16 cast is exact.
        assert_eq!(libc::ETH_P_ALL, i32::from(ETH_P_ALL));
    }

    /// `htons(ETH_P_ALL)` on little-endian = 0x0300. The byte-
    /// swap that goes into `sll_protocol`. C `:67`.
    #[test]
    fn eth_p_all_htons() {
        // `to_be()` on LE host: swap. On BE host: identity.
        // Either way the BYTES are [0x00, 0x03]. The u16
        // value-after-swap is host-dependent; the on-wire bytes
        // are not.
        let be = ETH_P_ALL.to_be();
        let bytes = be.to_ne_bytes();
        // On the wire (and in `sll_protocol`): big-endian =
        // [high, low] = [0x00, 0x03]. `to_ne_bytes` of the
        // already-swapped value gives us those bytes in order.
        assert_eq!(bytes, [0x00, 0x03]);
    }

    /// `sizeof(sockaddr_ll) = 20`. gcc-verified. Matches libc.
    /// The `addrlen` we pass to `bind`.
    #[test]
    fn sockaddr_ll_size_20() {
        assert_eq!(std::mem::size_of::<libc::sockaddr_ll>(), 20);
        // Sanity: 2 (family) + 2 (proto) + 4 (ifindex) +
        //         2 (hatype) + 1 (pkttype) + 1 (halen) +
        //         8 (addr) = 20. No padding (largest member is
        //         the i32 ifindex, aligned at offset 4, which
        //         it already is).
    }

    /// `AF_PACKET = PF_PACKET = 17`. The kernel doesn't
    /// distinguish; libc has both defined to the same value.
    #[test]
    fn af_pf_packet_same() {
        assert_eq!(libc::AF_PACKET, libc::PF_PACKET);
        assert_eq!(libc::AF_PACKET, 17);
    }

    /// nix's `SockProtocol::EthAll` should be `htons(ETH_P_
    /// ALL)`. Verify our understanding of what nix did.
    #[test]
    fn nix_ethall_is_htons_ethpall() {
        use nix::sys::socket::SockProtocol;
        // nix defines: `EthAll = (libc::ETH_P_ALL as u16).
        // to_be() as i32`. On LE x86_64: (3).to_be() = 0x0300
        // = 768.
        let want = i32::from(ETH_P_ALL.to_be());
        assert_eq!(SockProtocol::EthAll as i32, want);
    }

    // ─────────────────────────────────────────────────────────────────
    // open() gate — error path coverage without CAP_NET_RAW
    // ─────────────────────────────────────────────────────────────────

    /// `open()` on a nonexistent interface: either EPERM
    /// (socket() failed, no CAP_NET_RAW) or ENODEV (socket()
    /// succeeded, if_nametoindex failed). Either way: error,
    /// not panic. The "no truncation" path is implicit — the
    /// 23-char name passed straight to if_nametoindex which
    /// errors on the FULL name.
    ///
    /// `clippy::similar_names`: `e`/`ek` is fine.
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

    /// Empty interface name → if_nametoindex errors. The C's
    /// `Interface = ` (empty) → strncpy of empty string →
    /// `ifr_name[0] = 0` → ioctl errors (kernel rejects empty
    /// ifname). We hit the same error via if_nametoindex. Not
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

    // ─────────────────────────────────────────────────────────────────
    // bind_packet — sockaddr_ll layout
    // ─────────────────────────────────────────────────────────────────

    /// The `sockaddr_ll` we'd pass to bind: zeroed except
    /// family/protocol/ifindex. Verify the layout matches what
    /// the kernel expects (man 7 packet: "only sll_protocol and
    /// sll_ifindex are used" + sll_family discriminant).
    ///
    /// We can't actually CALL bind (need CAP_NET_RAW + a real
    /// socket). But we can inspect the struct we'd pass.
    #[test]
    #[allow(unsafe_code)]
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    fn sockaddr_ll_layout() {
        // SAFETY: same as `bind_packet` — zeroed sockaddr_ll
        // is sound.
        let mut sa: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        // `AF_PACKET` is `c_int` but the value is 17; the
        // c_ushort cast is exact (matches `bind_packet`).
        sa.sll_family = libc::AF_PACKET as libc::c_ushort;
        sa.sll_protocol = ETH_P_ALL.to_be();
        sa.sll_ifindex = 42; // arbitrary

        assert_eq!(sa.sll_family, 17);
        // The protocol bytes, interpreted as native-endian
        // u16, are htons(3). On LE: 0x0300 = 768.
        assert_eq!(sa.sll_protocol.to_ne_bytes(), [0x00, 0x03]);
        assert_eq!(sa.sll_ifindex, 42);
        // Unwritten fields stay zero. Kernel ignores them.
        assert_eq!(sa.sll_hatype, 0);
        assert_eq!(sa.sll_pkttype, 0);
        assert_eq!(sa.sll_halen, 0);
        assert_eq!(sa.sll_addr, [0; 8]);
    }

    // ─────────────────────────────────────────────────────────────────
    // +0 read/write — socketpair end-to-end
    // ─────────────────────────────────────────────────────────────────
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
    /// `open()` (that does PF_PACKET, needs CAP_NET_RAW); we
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

        // The frame buffer is UNCHANGED. `linux.rs` zeroes
        // `buf[10..12]` (the tun_pi.flags overwrite). We don't.
        // This impl doesn't mutate.
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
