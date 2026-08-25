//! TUN/TAP device backends behind a single [`Device`] read/write
//! trait that the daemon stores as `Box<dyn Device>`. Setup happens
//! in the constructor, teardown in `Drop`, and a `Dummy` backend is
//! always available for tests.
//!
//! Backends take `&mut [u8]` slices and own their kernel-side framing:
//! Linux TUN uses `IFF_TUN | IFF_NO_PI | IFF_VNET_HDR`, so reads come
//! in as a `virtio_net_hdr` followed by a raw IP packet and the
//! Ethernet header is synthesized by `drain()` / `tso_split`; TAP and
//! the non-Linux backends use `IFF_NO_PI` and present raw frames
//! starting at offset zero. Configuration is taken as a
//! `DeviceConfig` value supplied by the caller — the device layer
//! does no config-file parsing and no daemon-policy decisions, errors
//! surface as ordinary `io::Error`s.

#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
#![cfg_attr(not(target_os = "linux"), expect(unused_imports))]

use std::io;
use std::os::fd::BorrowedFd;

// Types

/// 1500 payload + 14 ethernet header + 4 VLAN
/// tag. `pub` because the daemon's `MAXSIZE` arithmetic includes it.
pub const MTU: usize = 1518;

// RFC 894 / IANA wire constants — not cfg-gated, same everywhere.
// pub(crate): backends synthesize headers; the daemon doesn't.
mod ether;

// Slot arena + DrainResult for the 10G datapath. Not cfg-gated:
// the arena is portable (it's just memory layout), and the default
// `drain()` is the BSD/macOS path — they inherit it for free.
mod arena;
pub(crate) use arena::GsoType;
pub use arena::{DeviceArena, DrainResult};

// Userspace TSO split. Portable: same `virtio_net_hdr` on Linux
// `IFF_VNET_HDR`, FreeBSD `TAPSVNETHDR`, Windows NDIS LSO. The
// device backends produce `DrainResult::Super`; the daemon calls
// `tso_split` on it. Not cfg-gated: the function is pure header
// arithmetic on `&[u8]`, runs anywhere.
mod tso;
pub use tso::{
    GroBucket, GroVerdict, TsoError, VNET_HDR_LEN, VirtioNetHdr, gso_none_checksum, tso_split,
};

/// L2 vs L3 device. The daemon resolves `DeviceType` config +
/// `routing_mode` into this; we get the resolved value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Layer-3 (IP). On Linux: `IFF_TUN | IFF_NO_PI | IFF_VNET_HDR`;
    /// `drain()` synthesizes the eth header. On BSD: AF prefix, +10.
    Tun,
    /// Layer-2 (Ethernet). `IFF_TAP | IFF_NO_PI`, raw frames.
    Tap,
}

/// MAC address. TAP reads the kernel-assigned MAC via
/// `SIOCGIFHWADDR`; TUN has none (`route.c` never reads `mymac`
/// in router mode). We model that as `Option<Mac>`.
pub type Mac = [u8; 6];

/// What the daemon needs to open a device. C reads these from
/// `config_tree`; the daemon maps that to this struct.
#[derive(Debug, Default)]
pub struct DeviceConfig {
    /// `Device` config var. Default is `/dev/net/tun` on Linux;
    /// `None` defers to the consumer.
    pub device: Option<String>,

    /// `Interface` config var. `None`: kernel picks (`tun0`,
    /// `tun1`, ...). The netname-default is the daemon's job.
    pub iface: Option<String>,

    /// Resolved mode. Not `Option`: an unset `ifr_flags` is
    /// `EINVAL` on `TUNSETIFF`.
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
// (commit `d73cdee5`) checks `raw_os_error()`. `Result<usize,
// io::Error>` is the trait return; no new type.

// Trait

/// The read/write vtable. Setup/close are constructor + `Drop`, not
/// trait methods. `Send` but not `Sync`: `read`/`write` take `&mut self`.
pub trait Device: Send {
    /// Read one packet into `buf` (the daemon's `data[offset..]`, ≥ `MTU`),
    /// returning its length. BSD `Utun` writes at `buf[10..]` and zeroes
    /// `buf[0..12]`; TAP/raw write at `buf[0..]`; Linux TUN overrides `drain()`
    /// instead.
    ///
    /// # Errors
    /// `read(2)`: `EAGAIN` when empty, `EBADFD` if the TUN device went away.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>;

    /// Write one packet from `buf` (`data[offset..offset+len]`). Linux TUN zeroes
    /// `buf[12..14]` and writes `buf[4..]` as `[vnet_hdr=0][IP]`; BSD `Utun` zeroes
    /// `buf[10..12]` and writes `buf[10..]`; TAP writes `buf` as is — hence `&mut`.
    ///
    /// # Errors
    /// `write(2)` errors, e.g. `ENOBUFS` on a full TAP TX queue; the daemon drops
    /// the packet.
    fn write(&mut self, buf: &mut [u8]) -> io::Result<usize>;

    /// GRO super write: pass `[vnet_hdr(10)][IP super]` straight to the TUN fd, no
    /// eth-header munging. Only Linux `Tun` (the one `IFF_VNET_HDR` backend)
    /// overrides; the daemon gates on `Mode::Tun`, so the default `Unsupported` is
    /// a don't-panic guard that degrades to per-packet `write()`.
    ///
    /// # Errors
    /// `write(2)` errors, or `Unsupported` for backends without `vnet_hdr`.
    fn write_super(&mut self, _buf: &[u8]) -> io::Result<usize> {
        Err(io::ErrorKind::Unsupported.into())
    }

    /// L2 (TAP) vs L3 (TUN) mode, mainly for logging; routing
    /// decisions branch on the daemon's routing mode, not this.
    fn mode(&self) -> Mode;

    /// Kernel-chosen interface name, set post-TUNSETIFF. Daemon
    /// passes it as `INTERFACE=` to scripts.
    fn iface(&self) -> &str;

    /// The device MAC — TAP only (`SIOCGIFHWADDR`). `None` for TUN.
    fn mac(&self) -> Option<Mac>;

    /// Borrowed fd for `EventLoop::add`. `Dummy` returns `None`;
    /// daemon skips the register. `BorrowedFd` ties the lifetime to
    /// `&self` so callers cannot outlive the backing `OwnedFd`.
    fn fd(&self) -> Option<BorrowedFd<'_>>;

    /// Drain available frames into the arena. Default: loop `self.read()` into
    /// slots until EAGAIN or `cap` (clamped to `arena.cap()`, typically
    /// `DEVICE_DRAIN_CAP`; over-draining starves TUN TX). Never returns `Super`;
    /// that is the Linux `vnet_hdr` override.
    ///
    /// # Errors
    /// `read(2)` errors other than EAGAIN, which just ends the loop.
    fn drain(&mut self, arena: &mut DeviceArena, cap: usize) -> io::Result<DrainResult> {
        drain_via_read(self, arena, cap)
    }

    /// Stage one frame for a later [`write_flush`]. Batch backends (Darwin utun
    /// `sendmsg_x`) copy into a ring; the default is plain [`write`]. Flush every
    /// burst before yielding; ordering against a direct `write` isn't kept across a
    /// pending stage.
    ///
    /// # Errors
    /// As [`write`]; batching backends may defer errors to [`write_flush`].
    fn write_stage(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.write(buf)
    }

    /// Ship anything queued by [`write_stage`]. Default: nothing to
    /// do (the default `write_stage` already wrote).
    ///
    /// # Errors
    /// `io::Error` from the batch syscall. Backends are expected to
    /// swallow `ENOBUFS`/`EAGAIN` (best-effort inject; inner
    /// transport retransmits) and replay-then-latch on `ENOSYS`.
    fn write_flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// `read()`-in-a-loop drain body. Hoisted out of the trait default so
/// overrides (linux TAP arm) can delegate to it without re-inlining.
pub(crate) fn drain_via_read<D: Device + ?Sized>(
    d: &mut D,
    arena: &mut DeviceArena,
    cap: usize,
) -> io::Result<DrainResult> {
    let cap = cap.min(arena.cap());
    let mut n = 0;
    while n < cap {
        match d.read(arena.slot_mut(n)) {
            Ok(len) => {
                arena.set_len(n, len);
                n += 1;
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e),
        }
    }
    Ok(if n == 0 {
        DrainResult::Empty
    } else {
        DrainResult::Frames { count: n }
    })
}

// Dummy — `dummy_device.c` (58 LOC)

/// Read fails, write drops. `DeviceType = dummy` runs the daemon
/// as a pure relay and lets tests avoid `CAP_NET_ADMIN`.
#[derive(Debug, Default)]
pub struct Dummy;

impl Device for Dummy {
    /// `WouldBlock`. (Poll loop never calls us anyway: no fd → no
    /// readable event.)
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::ErrorKind::WouldBlock.into())
    }

    /// Silent drop; return `len` so the daemon's stats counters tick.
    fn write(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        Ok(buf.len())
    }

    /// Arbitrary; C dummy doesn't set `device_type`. TUN matches
    /// the default.
    fn mode(&self) -> Mode {
        Mode::Tun
    }

    #[expect(clippy::unnecessary_literal_bound)] // trait method: can't return &'static str when trait says &str
    fn iface(&self) -> &str {
        "dummy"
    }

    /// No MAC. `None` is more honest than `Some([0; 6])`.
    fn mac(&self) -> Option<Mac> {
        None
    }

    /// No fd. C leaves `device_fd = -1`; `None` here.
    fn fd(&self) -> Option<BorrowedFd<'_>> {
        None
    }
}

// Thin `read(2)`/`write(2)` wrappers. All backends are datagram-
// style (one read = one packet), so no short-read handling here.

/// Backend `read()` precondition: caller's buffer must hold a full
/// frame. Shared so the four backends don't each repeat the format.
#[inline]
#[track_caller]
pub(crate) fn assert_read_buf(buf: &[u8], who: &str) {
    debug_assert!(
        buf.len() >= MTU,
        "buf too small for {who} read: {} < {MTU}",
        buf.len()
    );
}

/// `read(2)`. Datagram semantics: one call = one packet.
#[inline]
#[cfg(unix)]
pub(crate) fn read_fd(fd: BorrowedFd<'_>, buf: &mut [u8]) -> io::Result<usize> {
    nix::unistd::read(fd, buf).map_err(Into::into)
}

/// `write(2)`. Datagram semantics: one call = one packet.
#[inline]
#[cfg(unix)]
pub(crate) fn write_fd(fd: BorrowedFd<'_>, buf: &[u8]) -> io::Result<usize> {
    nix::unistd::write(fd, buf).map_err(Into::into)
}

// Linux TUN/TAP — `linux/device.c` (225 LOC)

#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use linux::Tun;

// fd — `fd_device.c` (Android backend).

#[cfg(unix)]
mod fd;
#[cfg(unix)]
pub use fd::{FdSource, FdTun};

// raw — `raw_socket_device.c` (PF_PACKET backend). Linux-only.

#[cfg(any(target_os = "linux", target_os = "android"))]
mod raw;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use raw::RawSocket;

// bsd — `bsd/device.c` (three backends in one file). `cfg(unix)`
// not `cfg(any(freebsd, ...))`: the variant-dispatched read/write
// logic is fd-agnostic and tested on Linux via pipe()/seqpacket
// fakes. Only open() constructors are BSD-gated (inside the file).

#[cfg(unix)]
mod bsd;
#[cfg(unix)]
pub use bsd::{BsdTun, BsdVariant};

// Tests — Dummy only (Tun needs CAP_NET_ADMIN, separate integration).
// drain() default-impl tests use a closure-backed mock so we test the
// trait body without platform devices.

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::BorrowedFd;
    use std::vec::IntoIter;

    /// Mock for the default `drain()` (the BSD/macOS path): returns scripted
    /// `read()` outcomes. `Ok(bytes)` writes the pattern at `buf[0..]`, `Err(kind)`
    /// returns the error, exhausted → `WouldBlock`.
    struct ScriptedDev {
        script: IntoIter<Result<Vec<u8>, io::ErrorKind>>,
    }
    impl ScriptedDev {
        fn new(s: Vec<Result<Vec<u8>, io::ErrorKind>>) -> Self {
            Self {
                script: s.into_iter(),
            }
        }
    }
    impl Device for ScriptedDev {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self.script.next() {
                Some(Ok(bytes)) => {
                    buf[..bytes.len()].copy_from_slice(&bytes);
                    Ok(bytes.len())
                }
                Some(Err(k)) => Err(k.into()),
                None => Err(io::ErrorKind::WouldBlock.into()),
            }
        }
        fn write(&mut self, _: &mut [u8]) -> io::Result<usize> {
            unreachable!("read-path test double")
        }
        fn mode(&self) -> Mode {
            Mode::Tun
        }
        #[expect(clippy::unnecessary_literal_bound)] // trait method: can't return &'static str when trait says &str
        fn iface(&self) -> &str {
            "mock"
        }
        fn mac(&self) -> Option<Mac> {
            None
        }
        fn fd(&self) -> Option<BorrowedFd<'_>> {
            None
        }
    }

    /// `Dummy::read` returns `WouldBlock` → drain returns Empty. The
    /// daemon's `IoWhat::Device` arm never fires for Dummy (no fd),
    /// but if it did, this is the right answer.
    #[test]
    fn drain_dummy_is_empty() {
        let mut d = Dummy;
        let mut a = DeviceArena::new(8);
        assert_eq!(d.drain(&mut a, 8).unwrap(), DrainResult::Empty);
    }

    /// Three frames then EAGAIN → Frames{3}. The bytes land in
    /// slots 0..3 in order; slot lengths match. This is the common
    /// case under normal load (less than `DEVICE_DRAIN_CAP` available).
    #[test]
    fn drain_frames_until_eagain() {
        let mut d = ScriptedDev::new(vec![
            Ok(b"first".to_vec()),
            Ok(b"second one".to_vec()),
            Ok(b"3rd".to_vec()),
            // implicit EAGAIN after exhaustion
        ]);
        let mut a = DeviceArena::new(8);
        assert_eq!(
            d.drain(&mut a, 8).unwrap(),
            DrainResult::Frames { count: 3 }
        );
        assert_eq!(a.slot(0), b"first");
        assert_eq!(a.slot(1), b"second one");
        assert_eq!(a.slot(2), b"3rd");
        assert_eq!(&a.lens()[..3], &[5, 10, 3]);
    }

    /// More frames available than `cap` → stop at `cap` (over-
    /// draining starves TX; daemon re-arms next wake).
    #[test]
    fn drain_respects_cap() {
        let mut d = ScriptedDev::new(vec![
            Ok(vec![0xaa; 100]),
            Ok(vec![0xbb; 100]),
            Ok(vec![0xcc; 100]), // never read — cap=2
        ]);
        let mut a = DeviceArena::new(8);
        assert_eq!(
            d.drain(&mut a, 2).unwrap(),
            DrainResult::Frames { count: 2 }
        );
        assert_eq!(a.slot(0)[0], 0xaa);
        assert_eq!(a.slot(1)[0], 0xbb);
        // The third frame is still in the device; next drain gets it.
        assert_eq!(
            d.drain(&mut a, 2).unwrap(),
            DrainResult::Frames { count: 1 }
        );
        assert_eq!(a.slot(0)[0], 0xcc);
    }

    /// EAGAIN on the first read → Empty, not Frames{0}.
    #[test]
    fn drain_immediate_eagain_is_empty() {
        let mut d = ScriptedDev::new(vec![Err(io::ErrorKind::WouldBlock)]);
        let mut a = DeviceArena::new(8);
        assert_eq!(d.drain(&mut a, 8).unwrap(), DrainResult::Empty);
    }

    /// Non-EAGAIN error mid-batch propagates (daemon counts these).
    #[test]
    fn drain_propagates_real_error() {
        let mut d = ScriptedDev::new(vec![Ok(b"ok".to_vec()), Err(io::ErrorKind::BrokenPipe)]);
        let mut a = DeviceArena::new(8);
        let e = d.drain(&mut a, 8).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::BrokenPipe);
    }

    /// `cap` is clamped to `arena.cap()` so a bad cap can't write
    /// past the arena.
    #[test]
    fn drain_clamps_cap_to_arena() {
        let mut d = ScriptedDev::new((0..10).map(|i| Ok(vec![i; 50])).collect());
        let mut a = DeviceArena::new(4); // arena smaller than script
        assert_eq!(
            d.drain(&mut a, 64).unwrap(),
            DrainResult::Frames { count: 4 }
        );
    }
}
