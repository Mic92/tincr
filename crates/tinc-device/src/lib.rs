//! TUN/TAP device backends. C `devops_t` (`device.h:32-40`) is a
//! vtable of fn pointers; here it's a trait, daemon stores
//! `Box<dyn Device>`. C `setup`/`close` become constructor + `Drop`.
//!
//! ## The TUN-mode offset trick (`linux/device.c:148-167`)
//!
//! Read at `+10` so `tun_pi.proto` lands on the ethertype slot,
//! then memset the MACs. `+10 = 14 (ether header) − 4 (tun_pi)`.
//!
//! ```text
//!   12-17  dst MAC    = 00:00:00:00:00:00  (memset)
//!   18-23  src MAC    = 00:00:00:00:00:00  (memset, overwrites tun_pi.flags)
//!   24-25  ethertype  = tun_pi.proto       (kernel wrote, we kept)
//!   26..   payload    = IP packet
//! ```
//!
//! TAP mode reads at `+0` (`IFF_NO_PI`, real frames). Write path is
//! the inverse: TUN zeroes `tun_pi.flags` then writes from `+10`.
//!
//! ## Not ported
//!
//! - Config-tree reads: daemon's job; we take `DeviceConfig`.
//! - `IFF_ONE_QUEUE`: no-op since kernel `5d09710` (2.6.27, 2008).
//! - `EBADFD` → `event_exit()` (`d73cdee5`): policy belongs in the
//!   daemon; we surface a regular `io::Error`.
//!
//! ## API
//!
//! Backends take `&mut [u8]` slices, not `vpn_packet_t *`. The
//! TUN-mode `+10` is the backend's concern (kernel interface); the
//! `+12` packet offset is the daemon's. Linux-gated; `Dummy` is
//! unconditional for tests.

#![deny(unsafe_code)]
#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]

use std::io;

// Types

/// `MTU` — `net.h:36`. 1500 payload + 14 ethernet header + 4 VLAN
/// tag. `pub` because the daemon's `MAXSIZE` arithmetic includes it.
pub const MTU: usize = 1518;

/// `MTU` for the jumbo build. The daemon picks; we accept either.
pub const MTU_JUMBO: usize = 9018;

// RFC 894 / IANA wire constants — NOT cfg-gated, same everywhere.
// pub(crate): backends synthesize headers; the daemon doesn't.
mod ether;

/// L2 vs L3 device. C `device_type_t` (`linux/device.c:33-36`).
/// The daemon resolves `DeviceType` config + `routing_mode` into
/// this; we get the resolved value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Layer-3 (IP). `IFF_TUN`, `tun_pi` prefix, +10 offset.
    Tun,
    /// Layer-2 (Ethernet). `IFF_TAP | IFF_NO_PI`, raw frames.
    Tap,
}

/// MAC address (C `mac_t = uint8_t[6]`). TAP reads the kernel-
/// assigned MAC via `SIOCGIFHWADDR` (`device.c:121-126`); TUN
/// has none (`route.c` never reads `mymac` in router mode). We
/// model that as `Option<Mac>`.
pub type Mac = [u8; 6];

/// What the daemon needs to open a device. C reads these from
/// `config_tree`; the daemon maps that to this struct.
#[derive(Debug, Default)]
pub struct DeviceConfig {
    /// `Device` config var. C default `/dev/net/tun` (`linux/
    /// device.c:24`); `None` defers to the consumer.
    pub device: Option<String>,

    /// `Interface` config var (`device.c:50-52`). `None`: kernel
    /// picks (`tun0`, `tun1`, ...). The netname-default is the
    /// daemon's job.
    pub iface: Option<String>,

    /// Resolved mode (`device.c:77-89`). NOT `Option`: an unset
    /// `ifr_flags` is `EINVAL` on `TUNSETIFF`.
    pub mode: Mode,
}

impl Default for Mode {
    /// `RMODE_ROUTER` is the daemon default; router mode picks TUN.
    fn default() -> Self {
        Mode::Tun
    }
}

// `EBADFD` is a regular `io::Error`, not a separate signal: the
// errno is already carried; the daemon's `event_exit()` fast-path
// (`device.c:155-157`, commit `d73cdee5`) checks `raw_os_error()`.
// `Result<usize, io::Error>` is the trait return; no new type.

// Trait

/// `devops_t` — the read/write vtable. `device.h:32-40`.
///
/// C `setup`/`close` become constructor + `Drop`; not trait methods.
/// `Send` but not `Sync`: `read`/`write` take `&mut self`.
pub trait Device: Send {
    /// Read a packet. C `devops.read(packet)` → bool (`device.h:
    /// 35`); we return the length.
    ///
    /// `buf` is the daemon's `data[offset..]` slice (≥ `MTU`). TUN
    /// writes at `buf[10..]` then zeroes `buf[0..12]`; returned
    /// length is `kernel_len + 10`. TAP writes at `buf[0..]`.
    /// Kernel `read() <= 0` → `Err` (C `device.c:149`).
    ///
    /// # Errors
    /// `io::Error` from `read(2)`. `EAGAIN` if `O_NONBLOCK` with
    /// no packet ready. `EBADFD` if the TUN device went away
    /// (commit `d73cdee5`: network restart).
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>;

    /// Write a packet. C `devops.write(packet)` → bool (`device.h:
    /// 36`).
    ///
    /// `buf` is `data[offset..offset+len]`. TUN zeroes `buf[10..12]`
    /// (`tun_pi.flags`) then writes `buf[10..]`; TAP writes `buf`
    /// directly. The TUN zero MUTATES `buf` (`device.c:188` does
    /// too); those bytes are always zero anyway (synthetic src-MAC),
    /// so idempotent. `&mut` is honest about the mutation.
    ///
    /// # Errors
    /// `io::Error` from `write(2)`. `ENOBUFS` if the kernel TX
    /// queue is full (TAP only, TUN doesn't queue at the device
    /// layer). The C logs and returns false; daemon drops the
    /// packet. We return `Err`; daemon does the same.
    fn write(&mut self, buf: &mut [u8]) -> io::Result<usize>;

    /// `device_type` for logging. C: `device_type` global (`:35`).
    /// `route.c` branches on `routing_mode`, not this.
    fn mode(&self) -> Mode;

    /// Kernel-chosen interface name. C `iface` global (`:41`), set
    /// post-TUNSETIFF. Daemon passes it as `INTERFACE=` to scripts.
    fn iface(&self) -> &str;

    /// `mymac` — TAP only (`SIOCGIFHWADDR`, `:121-126`). `None`
    /// for TUN.
    fn mac(&self) -> Option<Mac>;

    /// Raw fd for `mio::Poll::register`. C `device_fd` global
    /// (`:39`). `Dummy` returns `None`; daemon skips the register.
    fn fd(&self) -> Option<std::os::unix::io::RawFd>;
}

// Dummy — `dummy_device.c` (58 LOC)

/// `dummy_devops` (`dummy_device.c:53-58`). Read fails, write
/// drops. `DeviceType = dummy` runs the daemon as a pure relay
/// and lets tests avoid `CAP_NET_ADMIN`.
#[derive(Debug, Default)]
pub struct Dummy;

impl Device for Dummy {
    /// C `dummy_device.c:43-46`: `return false`. `WouldBlock` is
    /// the closest semantic. (Poll loop never calls us anyway: no
    /// fd → no readable event.)
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::ErrorKind::WouldBlock.into())
    }

    /// C `dummy_device.c:48-51`: `return true`. Silent drop;
    /// return `len` so the daemon's stats counters tick.
    fn write(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        Ok(buf.len())
    }

    /// Arbitrary; C dummy doesn't set `device_type`. TUN matches
    /// the default.
    fn mode(&self) -> Mode {
        Mode::Tun
    }

    /// C `dummy_device.c:31`: `iface = "dummy"`.
    ///
    /// `clippy::unnecessary_literal_bound`: trait signature is
    /// `&str` borrowed from `&self`; `Tun::iface` returns
    /// `&self.iface` (not static). Can't widen without diverging
    /// from the trait.
    #[allow(clippy::unnecessary_literal_bound)]
    fn iface(&self) -> &str {
        "dummy"
    }

    /// No MAC. `None` is more honest than `Some([0; 6])`.
    fn mac(&self) -> Option<Mac> {
        None
    }

    /// No fd. C leaves `device_fd = -1`; `None` here.
    fn fd(&self) -> Option<std::os::unix::io::RawFd> {
        None
    }
}

// Linux TUN/TAP — `linux/device.c` (225 LOC)

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::Tun;

// fd — `fd_device.c` (Android backend). Linux-only: abstract
// socket namespace and `MSG_ERRQUEUE` are Linux-specific.

#[cfg(target_os = "linux")]
mod fd;
#[cfg(target_os = "linux")]
pub use fd::{FdSource, FdTun};

// raw — `raw_socket_device.c` (PF_PACKET backend). Linux-only.

#[cfg(target_os = "linux")]
mod raw;
#[cfg(target_os = "linux")]
pub use raw::RawSocket;

// bsd — `bsd/device.c` (three backends in one file). `cfg(unix)`
// not `cfg(any(freebsd, ...))`: the variant-dispatched read/write
// logic is fd-agnostic and tested on Linux via pipe()/seqpacket
// fakes. Only open() constructors are BSD-gated (inside the file).

#[cfg(unix)]
mod bsd;
#[cfg(unix)]
pub use bsd::{BsdTun, BsdVariant};

// Tests — Dummy only (Tun needs CAP_NET_ADMIN, separate integration)

#[cfg(test)]
mod tests {
    use super::*;

    /// `dummy_device.c:43-46`. Read fails. The C returns `false`;
    /// we return `WouldBlock`. The daemon never actually calls
    /// this (no fd to poll).
    #[test]
    fn dummy_read_would_block() {
        let mut d = Dummy;
        let mut buf = [0u8; 64];
        let e = d.read(&mut buf).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::WouldBlock);
    }

    /// `dummy_device.c:48-51`. Write succeeds, drops. Returns the
    /// length so daemon stats count "bytes that would have gone
    /// out."
    #[test]
    fn dummy_write_drops() {
        let mut d = Dummy;
        let mut buf = [0x42u8; 100];
        let n = d.write(&mut buf).unwrap();
        assert_eq!(n, 100);
        // Buffer unchanged (drop = don't mutate). The TUN write
        // mutates (zeroes [10..12]); dummy doesn't.
        assert_eq!(buf[0], 0x42);
        assert_eq!(buf[99], 0x42);
    }

    /// `dummy_device.c:31`: `iface = "dummy"`. The daemon's tinc-
    /// up script gets `INTERFACE=dummy`.
    #[test]
    fn dummy_iface_string() {
        assert_eq!(Dummy.iface(), "dummy");
    }

    /// No fd, no MAC. The C leaves `device_fd = -1`, `mymac =
    /// {0}`. We model as `None` for both.
    #[test]
    fn dummy_no_fd_no_mac() {
        let d = Dummy;
        assert!(d.fd().is_none());
        assert!(d.mac().is_none());
    }

    /// `Mode::default()` is TUN. `route.c` defaults to RMODE_
    /// ROUTER, which picks TUN. The DeviceConfig default builder
    /// chains through this.
    #[test]
    fn mode_default_tun() {
        assert_eq!(Mode::default(), Mode::Tun);
        let cfg = DeviceConfig::default();
        assert_eq!(cfg.mode, Mode::Tun);
        assert!(cfg.device.is_none());
        assert!(cfg.iface.is_none());
    }

    /// `MTU = 1518` per `net.h:36`. sed-verifiable. The arithmetic:
    /// `1500 + 14 + 4` (payload + ether header + VLAN tag).
    ///
    /// `sed -n '36p' src/net.h` → `#define MTU 1518`. Pin the
    /// constant; future-us bumping it for jumbo gets a test fail
    /// pointing here.
    #[test]
    fn mtu_matches_c() {
        assert_eq!(MTU, 1518);
        assert_eq!(MTU, 1500 + 14 + 4);
        assert_eq!(MTU_JUMBO, 9018);
        assert_eq!(MTU_JUMBO, 9000 + 14 + 4);
    }
}
