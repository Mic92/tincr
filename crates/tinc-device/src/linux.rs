//! Linux TUN/TAP.
//!
//! # ioctl approach: not the nix macros
//!
//! `TUNSETIFF` is encoded as `_IOW` (us → kernel) but the kernel
//! WRITES BACK `ifr_name` after the ioctl — the encoding lies about
//! the direction. `nix::ioctl_write_ptr_bad!` generates
//! `unsafe fn(fd, *const T)`, documenting the wrong contract (the
//! kernel also writes). So we call `libc::ioctl(fd, req, *mut ifreq)`
//! directly, with a scoped `#[expect(unsafe_code)]` and a SAFETY
//! comment stating what the kernel reads/writes/locks.
//!
//! # `libc::ifreq` layout
//!
//! `ifr_name: [c_char; 16]` + 24-byte `ifr_ifru` union. `ifr_flags`
//! is `ifr_ifru.ifru_flags: c_short` (2 bytes at offset 16).
//!
//! # Why `O_CLOEXEC` matters here more than usual
//!
//! The daemon spawns `tinc-up`, `tinc-down`, `host-NAME-up` scripts.
//! Without CLOEXEC, the script inherits the TUN fd.
//! The device survives a child closing its inherited fd (refcounted),
//! but the script could write garbage to the TUN. CLOEXEC: defense.
//!
//! We use `OpenOptions::custom_flags(O_CLOEXEC)` — atomic at open,
//! one syscall instead of open+fcntl, no race window where a fork
//! between open and fcntl inherits a non-CLOEXEC fd.

use std::ffi::CStr;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::io::{AsFd, AsRawFd, BorrowedFd};

use crate::assert_read_buf;
use crate::drain_via_read;
use crate::ether::{ETH_HLEN, from_ip_nibble, set_etherheader};
use crate::tso::{VNET_HDR_LEN, VirtioNetHdr, gso_none_checksum};
use crate::{
    Device, DeviceArena, DeviceConfig, DrainResult, GsoType, MTU, Mac, Mode, read_fd, write_fd,
};
use std::mem;
use std::os::unix::fs::OpenOptionsExt;

/// The kernel's TUN/TAP multiplexer. Opening it doesn't give you a
/// device; `TUNSETIFF` does. The fd is just a handle into the driver until then.
const DEFAULT_DEVICE: &str = "/dev/net/tun";

/// Linux device. Owns the fd; `Drop` closes it (via `File::drop`,
/// which is `close(2)`).
///
/// Not `Clone`: there's one TUN fd per daemon. Cloning would
/// either dup the fd (two fds, same device — confusing) or share
/// it (then who closes?). The daemon stores `Box<dyn Device>`.
#[derive(Debug)]
pub struct Tun {
    /// The opened `/dev/net/tun` fd, post-`TUNSETIFF`. Reads and
    /// writes go here. `O_NONBLOCK` set: the daemon's poll loop
    /// only calls `read` when readable, but races (packet consumed
    /// between poll-return and read) → `EAGAIN`, not block.
    fd: File,

    /// Kernel-assigned interface name, read back from `ifr.ifr_name`
    /// after the ioctl (the kernel writes the actual name back, even
    /// if we requested one — it might've truncated or appended a
    /// number).
    iface: String,

    /// L2 vs L3. Set at open, never changes. The read/write paths
    /// branch on this.
    mode: Mode,

    /// TAP only: kernel-assigned MAC. Read via `SIOCGIFHWADDR`
    /// post-TUNSETIFF. For TUN: `None`.
    mac: Option<Mac>,
}

impl Tun {
    /// Open `/dev/net/tun`, `TUNSETIFF` to instantiate, optionally `SIOCGIFHWADDR`
    /// for the TAP MAC.
    ///
    /// # Errors
    /// `PermissionDenied` (no `CAP_NET_ADMIN`, the common CI case), `NotFound` (no
    /// `/dev/net/tun`), `InvalidInput` on TUNSETIFF (bad flags/name),
    /// `AlreadyExists` (name taken).
    pub fn open(cfg: &DeviceConfig) -> io::Result<Self> {
        let device = cfg.device.as_deref().unwrap_or(DEFAULT_DEVICE);

        // Pack ifr_name before open: validation is pure; open needs
        // CAP_NET_ADMIN. Validate first so tests can hit the error
        // path without root.
        let ifr_name = pack_ifr_name(cfg.iface.as_deref())?;

        // TUN: `IFF_VNET_HDR | IFF_NO_PI`, reads are `[vnet_hdr(10)][raw IP]` and the
        // eth header is synthesized in `drain()`/`tso_split`. TAP: `IFF_NO_PI` only
        // (vnet_hdr would need `tso_split` to keep the real eth header). Must be set
        // on the first TUNSETIFF: the kernel's flag-update path (`tun.c:2744`)
        // re-attaches, which fails on an attached fd.
        #[expect(clippy::cast_possible_truncation)] // IFF_* flags fit i16 (max 0x5001)
        let flags = match cfg.mode {
            Mode::Tun => libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_VNET_HDR,
            Mode::Tap => libc::IFF_TAP | libc::IFF_NO_PI,
        } as i16;

        // `iface = None` → ifr_name zeroed → kernel picks `tun0` /
        // `tap0` / first free; the chosen name is read back.
        // EINVAL retry: a persistent multi-queue device rejects a
        // plain attach; re-attach with the MQ flag (1 queue is legal).
        let (fd, iface) = match open_queue(device, ifr_name, flags) {
            Err(e)
                if cfg.mode == Mode::Tun
                    && cfg.iface.is_some()
                    && e.kind() == io::ErrorKind::InvalidInput =>
            {
                #[expect(clippy::cast_possible_truncation)]
                let mq_flags = flags | libc::IFF_MULTI_QUEUE as i16;
                open_queue(device, ifr_name, mq_flags)?
            }
            r => r?,
        };

        // SIOCGIFHWADDR (TAP only): the MAC is kernel-generated
        // (random with the locally-administered bit set); switch mode
        // uses it for ARP replies. Failure is non-fatal — continue
        // with `None`.
        let mac = match cfg.mode {
            Mode::Tap => siocgifhwaddr(fd.as_fd()).ok(),
            Mode::Tun => None,
        };

        // TUNSETOFFLOAD (TUN only). `EINVAL` for unknown flags is the kernel's feature
        // test (`tun.c:2886`); `TUN_F_TSO4/6` dates from 2.6.27. Should it fail
        // anyway, IFF_VNET_HDR is already set so reads carry the 10-byte prefix with
        // gso_type=NONE and drain() degrades to single frames.
        if cfg.mode == Mode::Tun {
            match tunsetoffload(fd.as_fd()) {
                Ok(()) => {
                    log::info!(target: "tinc_device",
                               "TSO ingest enabled: IFF_VNET_HDR + TUNSETOFFLOAD");
                }
                Err(e) => {
                    log::warn!(target: "tinc_device",
                               "TUNSETOFFLOAD failed: {e}; \
                                vnet_hdr active but no TSO");
                }
            }
        }

        Ok(Tun {
            fd,
            iface,
            mode: cfg.mode,
            mac,
        })
    }

    /// `IFF_MULTI_QUEUE` open: `n` fds on one TUN device. The kernel hashes the
    /// inner flow to a queue (`tun_automq_select_queue`, `tun.c:474`), so one flow
    /// → one reader thread. `n == 1` is plain `Tun::open`.
    ///
    /// # Errors
    /// `InvalidInput` for `n` outside `1..=256` (`MAX_TAP_QUEUES`), `n>1` with TAP,
    /// or a ≥16-byte name; otherwise as `open`.
    pub fn open_mq(cfg: &DeviceConfig, n: usize) -> io::Result<Vec<Tun>> {
        if n == 0 || n > 256 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("queue count {n} out of [1, 256]"),
            ));
        }

        if n == 1 {
            // One queue: no MQ flag. Exact same fd shape as before
            // open_mq existed. The daemon's single-shard path is
            // bit-identical.
            return Tun::open(cfg).map(|t| vec![t]);
        }

        // n > 1: TUN-only
        if cfg.mode != Mode::Tun {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "multiqueue requires Mode::Tun (sharding is router-mode \
                 only; TAP path has no IFF_VNET_HDR)",
            ));
        }

        let device = cfg.device.as_deref().unwrap_or(DEFAULT_DEVICE);
        // No name: queue 0 lets the kernel pick, the rest attach to
        // the reported name (subsequent TUNSETIFF matches by name).
        let mut ifr_name = pack_ifr_name(cfg.iface.as_deref())?;

        // 0x5101. The MQ bit must be set on every TUNSETIFF —
        // tun.c:2719 rejects mismatch. Same vnet_hdr handling as
        // single-queue (drain/write_super are unchanged).
        #[expect(clippy::cast_possible_truncation)]
        let flags =
            (libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_MULTI_QUEUE | libc::IFF_VNET_HDR) as i16;

        let mut queues = Vec::with_capacity(n);
        for k in 0..n {
            let (fd, iface) = open_queue(device, ifr_name, flags)?;
            if k == 0 && cfg.iface.is_none() {
                ifr_name = pack_ifr_name(Some(&iface))?;
            }

            // Offload is per-netdev. Once. Same feature-detect
            // warning as Tun::open: failure means vnet_hdr is on
            // but gso_type stays NONE — drain handles that.
            if k == 0
                && let Err(e) = tunsetoffload(fd.as_fd())
            {
                log::warn!(target: "tinc_device",
                           "TUNSETOFFLOAD failed on multiqueue: {e}; \
                            vnet_hdr active but no TSO");
            }

            queues.push(Tun {
                fd,
                iface,
                mode: Mode::Tun,
                mac: None,
            });
        }
        Ok(queues)
    }
}

/// `[c_char; IFNAMSIZ]` from `Option<&str>`, validated before
/// `open(/dev/net/tun)` so it needs no `CAP_NET_ADMIN`. `None` → zeros → kernel
/// picks; `len >= 16` is an error rather than a truncation that surfaces later
/// as `ENODEV`.
///
/// # Errors
/// `InvalidInput` naming the interface and the limit.
fn pack_ifr_name(iface: Option<&str>) -> io::Result<[libc::c_char; libc::IFNAMSIZ]> {
    let mut buf = [0; libc::IFNAMSIZ];
    let Some(name) = iface else {
        // Empty → kernel picks.
        return Ok(buf);
    };
    let bytes = name.as_bytes();
    // `< IFNAMSIZ` not `<=`: room for NUL. The kernel reads a
    // C string; 16 chars + no NUL = unterminated. Reject instead of
    // truncating.
    if bytes.len() >= libc::IFNAMSIZ {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "interface name {name:?} too long (max {} bytes)",
                libc::IFNAMSIZ - 1
            ),
        ));
    }
    // `c_char` is `i8` on x86_64, `u8` on aarch64.
    for (dst, src) in buf.iter_mut().zip(bytes) {
        *dst = libc::c_char::from_ne_bytes([*src]);
    }
    Ok(buf)
}

// One hand-rolled `ioctl(fd, req, *mut ifreq)` shim serves `TUNSETIFF` and
// `SIOCGIFHWADDR`; nix's `ioctl_*!` macros would not reduce the unsafe
// surface.

/// Zeroed `struct ifreq` with `ifr_name` set, shared by both ioctl shims.
/// `libc::ifreq` has no `Default` (union member), so zero-then-assign. SAFETY:
/// `ifreq` is `repr(C)`, all integers/arrays/nullable pointers; all-zero is
/// valid.
#[expect(unsafe_code)]
fn ifreq_with_name(ifr_name: [libc::c_char; libc::IFNAMSIZ]) -> libc::ifreq {
    // SAFETY: see fn comment.
    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    ifr.ifr_name = ifr_name;
    ifr
}

/// The single `libc::ioctl(fd, req, struct ifreq *)` call site.
/// `TUNSETIFF` and `SIOCGIFHWADDR` both go through here so the
/// unsafe surface is one audited block, not one per ioctl.
#[expect(unsafe_code)]
fn ioctl_ifreq(fd: BorrowedFd<'_>, req: libc::Ioctl, ifr: &mut libc::ifreq) -> io::Result<()> {
    // SAFETY: `fd` is a live borrowed fd; both callers pass a request whose
    // argument is `struct ifreq *`, and `ifr` is an initialized, aligned,
    // exclusively borrowed `ifreq` the kernel may read and write.
    let ret = unsafe { libc::ioctl(fd.as_raw_fd(), req, &raw mut *ifr) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Open `/dev/net/tun` (`O_RDWR | O_NONBLOCK | O_CLOEXEC`) and issue
/// `TUNSETIFF` with `flags`/`ifr_name`. Returns the fd and the
/// kernel-assigned interface name. Shared by `Tun::open` and the
/// per-queue loop in `Tun::open_mq`.
fn open_queue(
    device: &str,
    ifr_name: [libc::c_char; libc::IFNAMSIZ],
    flags: i16,
) -> io::Result<(File, String)> {
    // CLOEXEC atomically in the open flags closes the open→fcntl
    // race window. `custom_flags` ORs into the underlying `open(2)`
    // flags; `OpenOptions` already sets `O_RDWR` from
    // `.read(true).write(true)`.
    let fd = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(device)?;
    let iface = tunsetiff(fd.as_fd(), flags, ifr_name)?;
    Ok((fd, iface))
}

/// `TUNSETIFF`: instantiate a TUN/TAP device. Kernel reads `ifr_flags` and
/// `ifr_name` (may be empty) and writes back the assigned name, NUL-terminated
/// within `IFNAMSIZ`. `libc::TUNSETIFF` is `_IOW('T', 202, int)`; the `int`
/// size is historical, the argument is really `struct ifreq *`.
fn tunsetiff(
    fd: BorrowedFd<'_>,
    flags: i16,
    ifr_name: [libc::c_char; libc::IFNAMSIZ],
) -> io::Result<String> {
    let mut ifr = ifreq_with_name(ifr_name);
    // Union WRITE is safe in Rust; only reads need `unsafe`. The
    // kernel reads via `copy_from_user` (byte copy) and doesn't
    // care about Rust's active-variant rules.
    ifr.ifr_ifru.ifru_flags = flags;

    // Kernel reads `ifr_flags` + `ifr_name`, writes `ifr_name`
    // back. See module doc for why this isn't a nix macro (the
    // `_IOW` encoding lies about direction). `tun_chr_ioctl`
    // takes `rtnl_lock` for `TUNSETIFF`; we don't observe.
    ioctl_ifreq(fd, libc::TUNSETIFF, &mut ifr)?;

    // Read back ifr_name. The kernel `strscpy`s into it,
    // NUL-terminated; `from_bytes_until_nul` finds the NUL or fails.
    // If it fails (kernel bug, no NUL in 16 bytes), error out.
    //
    // `to_string_lossy`: never lossy in practice, but forward-
    // compatible (kernel might relax someday) and avoids the
    // `into_string().unwrap()` panic-on-non-UTF8.
    let bytes = ifr.ifr_name.map(|c| c.to_ne_bytes()[0]);
    let name = CStr::from_bytes_until_nul(&bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "kernel returned unterminated ifr_name",
        )
    })?;
    Ok(name.to_string_lossy().into_owned())
}

/// `TUNSETOFFLOAD` (`_IOW('T', 208, unsigned int)`, not in libc):
/// `TUN_F_TSO4|6` sets `NETIF_F_TSO*` on the netdev (`tun.c:2842`) so the TCP
/// stack hands us ≤64KB skbs. The flag word is passed by value (`tun.c:3213`).
const TUNSETOFFLOAD: libc::Ioctl = 0x4004_54d0;

/// `TUN_F_*` flags for `TUNSETOFFLOAD`. `if_tun.h:88-90`.
/// `TUN_F_CSUM` is required for `TUN_F_TSO*` (`tun.c:2850`: TSO
/// flags only checked inside the `if (arg & TUN_F_CSUM)` block).
const TUN_F_CSUM: libc::c_uint = 0x01;
const TUN_F_TSO4: libc::c_uint = 0x02;
const TUN_F_TSO6: libc::c_uint = 0x04;

#[expect(unsafe_code)]
fn tunsetoffload(fd: BorrowedFd<'_>) -> io::Result<()> {
    let flags = TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6;
    // SAFETY: `fd` is the post-TUNSETIFF TUN fd; the third argument is the flag
    // word by value (`tun.c:3213`), so nothing is dereferenced or written back.
    // `EINVAL` only for unknown bits (`tun.c:2886`); ours date from 2.6.27.
    let ret = unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETOFFLOAD, libc::c_ulong::from(flags)) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `SIOCGIFHWADDR` — read the device's MAC.
///
/// Uses `ifr_ifru.ifru_hwaddr: sockaddr`. The MAC is in `sa_data
/// [0..6]` (the rest of `sockaddr` is unused/garbage for hwaddr).
#[expect(unsafe_code)]
fn siocgifhwaddr(fd: BorrowedFd<'_>) -> io::Result<Mac> {
    // `SIOCGIFHWADDR` on a TUN/TAP fd ignores `ifr_name` (the fd is already bound
    // to one interface post-TUNSETIFF); zeroing is hygiene.
    let mut ifr = ifreq_with_name([0; libc::IFNAMSIZ]);

    // Kernel reads NOTHING (TUN/TAP fd path; see above), WRITES
    // `ifr_ifru.ifru_hwaddr` (a `sockaddr`, 16 bytes at offset 16).
    ioctl_ifreq(fd, libc::SIOCGIFHWADDR as libc::Ioctl, &mut ifr)?;

    // SAFETY (union read): the kernel wrote `ifru_hwaddr`, so it is the active
    // variant. `sa_data[0..6]` is the MAC (`ARPHRD_ETHER`); the remaining bytes
    // are undefined and unread.
    let sa_data = unsafe { ifr.ifr_ifru.ifru_hwaddr }
        .sa_data
        .map(|c| c.to_ne_bytes()[0]);
    let mac: Mac = sa_data[..6].try_into().expect("sa_data is 14 bytes");
    Ok(mac)
}

// Device trait — read/write with the offset trick

impl Device for Tun {
    /// Read a packet. TAP only — the vnet `drain()` override reads
    /// the TUN fd directly, so `Mode::Tun` never reaches here.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        debug_assert_eq!(
            self.mode,
            Mode::Tap,
            "Tun::read on Mode::Tun; vnet drain() should read \
             directly. Is drain() still overridden?"
        );

        // `IFF_NO_PI` → no `tun_pi` prefix; raw ethernet at [0..].
        assert_read_buf(buf, "TAP");
        let dst = &mut buf[..MTU];
        let n = read_fd(self.fd.as_fd(), dst)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "TAP device returned EOF",
            ));
        }
        Ok(n)
    }

    fn write(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.mode {
            // TUN with `IFF_NO_PI | IFF_VNET_HDR`: the kernel wants `[vnet_hdr(10)][raw
            // IP]` (`tun_get_user`, `tun.c:1731`). `buf` is `[synthetic eth(14)][IP]`,
            // zero except the ethertype at [12..14], so zero that and write `buf[4..]` —
            // ten zero bytes are a gso_type=NONE header. The daemon never reads `buf` back
            // after write. GRO-coalesced supers go through `write_super` with a real
            // vnet_hdr instead.
            Mode::Tun => {
                debug_assert!(buf.len() > ETH_HLEN, "vnet write buf too short");
                // Ethertype → 0. Bytes [4..12] are already 0
                // (synth MACs); [12..14] is ethertype.
                buf[12] = 0;
                buf[13] = 0;
                // `4 = ETH_HLEN - VNET_HDR_LEN`. Write from there:
                // 10 zero bytes (vnet_hdr) + IP packet.
                write_fd(self.fd.as_fd(), &buf[ETH_HLEN - VNET_HDR_LEN..])
            }

            // TAP: direct write.
            Mode::Tap => write_fd(self.fd.as_fd(), buf),
        }
    }

    /// GRO super write: `buf` is `[vnet_hdr(10)][IP ≤65535]` from
    /// `GroBucket::flush`, already in `tun_get_user` shape (`tun.c:1731`). The
    /// daemon only calls this in `Mode::Tun`, where `IFF_VNET_HDR` is always on;
    /// the TAP arm degrades rather than panics.
    fn write_super(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.mode {
            Mode::Tun => write_fd(self.fd.as_fd(), buf),
            Mode::Tap => Err(io::ErrorKind::Unsupported.into()),
        }
    }

    fn mode(&self) -> Mode {
        self.mode
    }

    fn iface(&self) -> &str {
        &self.iface
    }

    fn mac(&self) -> Option<Mac> {
        self.mac
    }

    fn fd(&self) -> Option<BorrowedFd<'_>> {
        Some(self.fd.as_fd())
    }

    /// `vnet_hdr` drain; delegates to the default loop when `IFF_VNET_HDR` is off.
    /// One read = one skb shaped `[virtio_net_hdr(10)][raw IP ≤65535]`
    /// (`tun_put_user`, `tun.c:2064`). `gso_type == NONE`: strip the header,
    /// complete a partial csum, synthesize the eth header, return `Frames{1}`.
    /// `TCPV4/6`: strip the header and return `Super{..}` for the daemon to
    /// `tso_split`.
    fn drain(&mut self, arena: &mut DeviceArena, cap: usize) -> io::Result<DrainResult> {
        if self.mode == Mode::Tap {
            // TAP has no vnet_hdr (see `Tun::open` flags) — use the
            // trait-default read()-loop body.
            return drain_via_read(self, arena, cap);
        }

        // TUN vnet_hdr path: one read into the contiguous arena (65545 bytes max,
        // `cap*STRIDE` fits). Under EPOLLET returning with a non-empty queue loses the
        // wake, and a Super fills the whole output budget, so the daemon's
        // `on_device_read` loops `drain` until `Empty`.
        let buf = arena.as_contiguous_mut();
        let n = match read_fd(self.fd.as_fd(), buf) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "TUN device returned EOF",
                ));
            }
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                return Ok(DrainResult::Empty);
            }
            Err(e) => return Err(e),
        };

        // Decode the vnet_hdr prefix.
        let Some(hdr) = VirtioNetHdr::decode(&buf[..n]) else {
            // n < 10. Kernel always writes the full header; this is
            // a contract violation. Log + drop (return Empty so the
            // daemon doesn't count it as a real frame).
            log::warn!(target: "tinc_device",
                       "vnet_hdr read returned {n} < {VNET_HDR_LEN} bytes");
            return Ok(DrainResult::Empty);
        };
        let pkt_len = n - VNET_HDR_LEN;
        if pkt_len == 0 {
            // Empty packet after header. Shouldn't happen.
            return Ok(DrainResult::Empty);
        }

        match hdr.gso() {
            Some(GsoType::None) | None => {
                // Non-GSO frame: single IP packet. In slot 0, `[vnet_hdr(10)][IP]` becomes
                // `[eth(14)][IP]` in place (IP shifts right by 4); fix the partial csum before
                // the shift since csum_start is relative to the current IP start.
                if hdr.needs_csum() {
                    gso_none_checksum(&mut buf[VNET_HDR_LEN..n], hdr.csum_start, hdr.csum_offset);
                }
                // Ethertype from IP version nibble. Same as fd.rs.
                // `None` for unknown (→ drop, the kernel handed us
                // garbage — we only advertised IP offloads).
                let Some(ethertype) = from_ip_nibble(buf[VNET_HDR_LEN]) else {
                    log::debug!(target: "tinc_device",
                                "vnet_hdr GSO_NONE: unknown IP ver {:#x}",
                                buf[VNET_HDR_LEN] >> 4);
                    return Ok(DrainResult::Empty);
                };
                // Shift IP packet right by 4 bytes: 10 → 14.
                // `copy_within` handles overlap. The 4-byte gap at
                // [10..14] is overwritten by `set_etherheader` next.
                buf.copy_within(VNET_HDR_LEN..n, ETH_HLEN);
                set_etherheader(buf, ethertype);
                let frame_len = ETH_HLEN + pkt_len;
                // We've written into slot 0's STRIDE region (frame
                // is < MTU+14 < STRIDE). Record the length.
                arena.set_len(0, frame_len);
                Ok(DrainResult::Frames { count: 1 })
            }
            Some(gso_type @ (GsoType::TcpV4 | GsoType::TcpV6)) => {
                // TCP super-segment
                // Shift IP packet to offset 0 so the daemon's
                // `tso_split` call sees `as_contiguous()[..len]`
                // without an offset. 10 bytes left, in place.
                buf.copy_within(VNET_HDR_LEN..n, 0);
                Ok(DrainResult::Super {
                    len: pkt_len,
                    gso_size: hdr.gso_size,
                    gso_type,
                    csum_start: hdr.csum_start,
                    csum_offset: hdr.csum_offset,
                })
            }
        }
    }
}

// Tests — what we CAN test without CAP_NET_ADMIN

#[cfg(test)]
mod tests {
    use super::*;

    /// `open_mq(n>1)` validation happens before open (no
    /// `CAP_NET_ADMIN` needed): rejects TAP (router-mode only).
    /// `iface = None` is allowed — queue 0 takes the kernel name.
    #[test]
    fn open_mq_validation() {
        let tap = DeviceConfig {
            iface: Some("shard0".to_owned()),
            mode: Mode::Tap,
            ..DeviceConfig::default()
        };
        let e = Tun::open_mq(&tap, 2).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        assert!(e.to_string().contains("Mode::Tun"), "got: {e}");
    }

    // pack_ifr_name — the testable seam

    /// Ok-path: `None` → all zeros (kernel picks). `Some` → packed,
    /// NUL-padded. The boundary: `< IFNAMSIZ`
    /// accepts 15, rejects 16. `as u8` cast for x86_64-vs-aarch64
    /// `c_char` signedness; values are ASCII either way.
    #[test]
    fn pack_ifr_name_ok() {
        #[rustfmt::skip]
        let cases: &[(Option<&str>, &[u8])] = &[
            // None → all zeros → kernel picks.
            (None,                    b""),
            // Short → packed.
            (Some("tun0"),            b"tun0"),
            // Exactly 15: the boundary. Last byte is NUL.
            (Some("fifteen_chars_!"), b"fifteen_chars_!"),
        ];
        for (i, (input, prefix)) in cases.iter().enumerate() {
            let buf = pack_ifr_name(*input).unwrap();
            // First `prefix.len()` bytes match the input.
            for (j, &b) in prefix.iter().enumerate() {
                assert_eq!(buf[j].to_ne_bytes()[0], b, "case {i}: byte {j}");
            }
            // Rest (NUL terminator + padding) is zero.
            assert!(
                buf[prefix.len()..].iter().all(|&b| b == 0),
                "case {i}: tail not zeroed"
            );
        }
        // Explicit: the boundary case keeps byte 15 NUL.
        assert_eq!("fifteen_chars_!".len(), 15);
    }

    /// Exactly 16 bytes → Err (no silent truncation). The error
    /// message names the limit.
    #[test]
    fn pack_ifr_name_exactly_16_err() {
        let name = "sixteen_chars_!!"; // 16 bytes
        assert_eq!(name.len(), 16);
        let e = pack_ifr_name(Some(name)).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        let msg = e.to_string();
        assert!(msg.contains("too long"), "msg: {msg}");
        assert!(msg.contains("15"), "msg should name limit: {msg}");
    }

    /// `Tun::open` with too-long iface → `Err` before open. The
    /// reordering (validate first, open second) is the testability
    /// fix. Without it, CI without `/dev/net/tun` would ENOENT
    /// before reaching the validation.
    ///
    /// This test doesn't need `/dev/net/tun` to exist. Works
    /// everywhere.
    #[test]
    fn open_too_long_iface_err_before_open() {
        let cfg = DeviceConfig {
            iface: Some("way_too_long_for_kernel".to_owned()),
            ..DeviceConfig::default()
        };
        let e = Tun::open(&cfg).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        // Not NotFound (which would mean we hit open() first).
        // Not PermissionDenied (same). The validation fired.
    }

    /// `Tun::open` with valid config but no `CAP_NET_ADMIN` yields an `Err` from
    /// the syscall (EACCES/ENOENT), not `InvalidInput`. Skipped under root, where
    /// open would succeed and leave a TUN device behind.
    #[test]
    fn open_non_root_err() {
        if nix::unistd::geteuid().is_root() {
            eprintln!("(skipping open_non_root_err: root would actually open a TUN)");
            return;
        }
        let cfg = DeviceConfig::default();
        let e = Tun::open(&cfg).unwrap_err();
        // EACCES (no CAP_NET_ADMIN) or ENOENT (no /dev/net/tun).
        // Either is a syscall failure, not our validation.
        assert_ne!(
            e.kind(),
            io::ErrorKind::InvalidInput,
            "validation should pass for default config; got: {e}"
        );
    }
}
