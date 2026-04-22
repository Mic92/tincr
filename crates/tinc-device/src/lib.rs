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
#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]

use std::io;

// Types

/// `MTU` — `net.h:36`. 1500 payload + 14 ethernet header + 4 VLAN
/// tag. `pub` because the daemon's `MAXSIZE` arithmetic includes it.
pub const MTU: usize = 1518;

// RFC 894 / IANA wire constants — NOT cfg-gated, same everywhere.
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
// `tso_split` on it. NOT cfg-gated: the function is pure header
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

    /// Resolved mode. NOT `Option`: an unset `ifr_flags` is
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
    /// Read a packet. Returns the length.
    ///
    /// `buf` is the daemon's `data[offset..]` slice (≥ `MTU`). Linux
    /// TUN doesn't go through here (`drain()` overrides and reads
    /// `vnet_hdr` layout directly). BSD `Utun` writes at `buf[10..]`
    /// then zeroes `buf[0..12]`; TAP/raw writes at `buf[0..]`.
    /// Kernel `read() <= 0` → `Err`.
    ///
    /// # Errors
    /// `io::Error` from `read(2)`. `EAGAIN` if `O_NONBLOCK` with
    /// no packet ready. `EBADFD` if the TUN device went away
    /// (commit `d73cdee5`: network restart).
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>;

    /// Write a packet.
    ///
    /// `buf` is `data[offset..offset+len]`. Linux TUN zeroes
    /// `buf[12..14]` (the synthetic ethertype) and writes `buf[4..]`
    /// = `[vnet_hdr=0][IP]`; BSD `Utun` zeroes `buf[10..12]` and
    /// writes `buf[10..]`; TAP writes `buf` directly. The zero
    /// MUTATES `buf`; `&mut` is honest about the mutation.
    ///
    /// # Errors
    /// `io::Error` from `write(2)`. `ENOBUFS` if the kernel TX
    /// queue is full (TAP only, TUN doesn't queue at the device
    /// layer). The C logs and returns false; daemon drops the
    /// packet. We return `Err`; daemon does the same.
    fn write(&mut self, buf: &mut [u8]) -> io::Result<usize>;

    /// GRO super write: pass `[vnet_hdr(10)][IP super]` straight to
    /// the TUN fd. Unlike [`write`], no eth-header munging — the
    /// GRO bucket already builds the kernel's `tun_get_user` shape.
    ///
    /// Default = unsupported. Only the Linux `Tun` backend overrides
    /// (it's the only one with `IFF_VNET_HDR`). The daemon gates on
    /// `Mode::Tun` so it never calls this on TAP/BSD/FdTun. The
    /// `Err(Unsupported)` here is the unreachable-but-don't-panic
    /// guard — if it fires, the gate is wrong, but the daemon falls
    /// back to per-packet `write()` and the inner TCP just sees a
    /// retransmit.
    ///
    /// # Errors
    /// `io::Error` from `write(2)`. `Unsupported` for backends
    /// without `vnet_hdr`.
    fn write_super(&mut self, _buf: &[u8]) -> io::Result<usize> {
        Err(io::ErrorKind::Unsupported.into())
    }

    /// `device_type` for logging. C: `device_type` global (`:35`).
    /// `route.c` branches on `routing_mode`, not this.
    fn mode(&self) -> Mode;

    /// Kernel-chosen interface name, set post-TUNSETIFF. Daemon
    /// passes it as `INTERFACE=` to scripts.
    fn iface(&self) -> &str;

    /// `mymac` — TAP only (`SIOCGIFHWADDR`, `:121-126`). `None`
    /// for TUN.
    fn mac(&self) -> Option<Mac>;

    /// Borrowed fd for `EventLoop::add`. `Dummy` returns `None`;
    /// daemon skips the register. `BorrowedFd` ties the lifetime to
    /// `&self` so callers cannot outlive the backing `OwnedFd`.
    fn fd(&self) -> Option<std::os::fd::BorrowedFd<'_>>;

    /// Drain available frames into the arena. The 10G ingest seam.
    ///
    /// Default: loop `self.read()` into arena slots until EAGAIN or
    /// `cap`. Never returns `Super` — that's the Linux `vnet_hdr`
    /// override. The default IS the BSD/macOS/mock path: their
    /// existing byte-pipe `read()` is the building block.
    ///
    /// `cap` clamps to `arena.cap()`. Typically `DEVICE_DRAIN_CAP=64`
    /// (`daemon/net.rs` — over-draining starves TUN of TX time, see
    /// commit `0f120b11`).
    ///
    /// # Errors
    /// `io::Error` from the underlying `read(2)`. EAGAIN is consumed
    /// (it's the loop terminator, not an error). EBADFD etc. surface
    /// to the daemon.
    fn drain(&mut self, arena: &mut DeviceArena, cap: usize) -> io::Result<DrainResult> {
        drain_via_read(self, arena, cap)
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
    fn fd(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
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
pub(crate) fn read_fd(fd: std::os::fd::BorrowedFd<'_>, buf: &mut [u8]) -> io::Result<usize> {
    nix::unistd::read(fd, buf).map_err(Into::into)
}

/// `write(2)`. Datagram semantics: one call = one packet.
#[inline]
#[cfg(unix)]
pub(crate) fn write_fd(fd: std::os::fd::BorrowedFd<'_>, buf: &[u8]) -> io::Result<usize> {
    nix::unistd::write(fd, buf).map_err(Into::into)
}

// Linux TUN/TAP — `linux/device.c` (225 LOC)

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::Tun;

// fd — `fd_device.c` (Android backend).

#[cfg(unix)]
mod fd;
#[cfg(unix)]
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

// Tests — Dummy only (Tun needs CAP_NET_ADMIN, separate integration).
// drain() default-impl tests use a closure-backed mock so we test the
// trait body without platform devices.

#[cfg(test)]
mod tests {
    use super::*;

    // ─── default drain()
    //
    // The default impl is the BSD/macOS path. Test it with a mock that
    // returns a scripted sequence of read() outcomes; the trait body
    // does the rest. This is the seam — if the default is right,
    // every byte-pipe backend is right.

    /// Mock device: returns scripted `read()` outcomes. Each `Ok(bytes)`
    /// writes the byte pattern at `buf[0..]` and returns its length;
    /// `Err(kind)` returns the error. Exhausted → `WouldBlock`.
    struct ScriptedDev {
        script: std::vec::IntoIter<Result<Vec<u8>, io::ErrorKind>>,
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
            unimplemented!()
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
        fn fd(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
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
