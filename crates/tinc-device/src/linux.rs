//! Linux TUN/TAP.
//!
//! ──────────── ioctl approach: NOT the nix macro ────────────────────
//!
//! `tui.rs` uses `nix::ioctl_read_bad!` for `TIOCGWINSZ`. That works
//! because `TIOCGWINSZ` only writes (kernel → us). `TUNSETIFF` is
//! encoded as `_IOW` (us → kernel) but the kernel WRITES BACK
//! `ifr_name` after the ioctl. The ioctl encoding lies about the
//! direction.
//!
//! `nix::ioctl_write_ptr_bad!` generates `unsafe fn(fd, *const T)`.
//! We'd need `*mut T` to soundly let the kernel write. Casting
//! `*mut → *const` for the call is sound (the kernel side takes
//! `void __user *` and ignores const), but it documents the WRONG
//! contract — `*const` says "kernel reads this" when it also writes.
//!
//! So: bypass the macro. Direct `libc::ioctl(fd, req, *mut ifreq)`.
//! The macro's value was `if ret < 0 { Err(Errno::last()) }` — three
//! lines we can write ourselves. We get the right pointer type AND
//! the third-instance pattern (tui ioctl, info `localtime_r`, this)
//! still holds: scoped `#[allow(unsafe_code)]`, SAFETY comment that
//! says what the kernel reads/writes/locks.
//!
//! ──────────── `libc::ifreq` layout ─────────────────────────────────
//!
//! Smoke-verified `sizeof(struct ifreq) == 40` on `x86_64` glibc, and
//! `libc::ifreq` matches. Layout: `ifr_name: [c_char; 16]` + 24-byte
//! `ifr_ifru` union (largest members are 16 bytes, padded to 24).
//!
//! `ifr_flags` is `ifr_ifru.ifru_flags: c_short` (2 bytes at offset
//! 16). C code typically uses `ifr.ifr_flags` (a `#define` alias
//! into the union); we write `ifr.ifr_ifru.ifru_flags`.
//!
//! ──────────── Why `O_CLOEXEC` matters here more than usual ──────────
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
use std::os::unix::io::{AsRawFd, RawFd};

use crate::ether::{ETH_HLEN, from_ip_nibble, set_etherheader};
use crate::tso::{VNET_HDR_LEN, VirtioNetHdr, gso_none_checksum};
use crate::{
    Device, DeviceArena, DeviceConfig, DrainResult, GsoType, MTU, Mac, Mode, read_fd, write_fd,
};

/// The kernel's TUN/TAP multiplexer. Opening it doesn't give you a
/// device; `TUNSETIFF` does. The fd is just a handle into the driver until then.
const DEFAULT_DEVICE: &str = "/dev/net/tun";

/// Linux device. Owns the fd; `Drop` closes it (via `File::drop`,
/// which is `close(2)`).
///
/// NOT `Clone`: there's one TUN fd per daemon. Cloning would
/// either dup the fd (two fds, same device — confusing) or share
/// it (then who closes?). The daemon stores `Box<dyn Device>`.
#[derive(Debug)]
pub struct Tun {
    /// The opened `/dev/net/tun` fd, post-`TUNSETIFF`. Reads and
    /// writes go here. `O_NONBLOCK` set: the daemon's poll loop
    /// only calls `read` when readable, but races (packet consumed
    /// between poll-return and read) → `EAGAIN`, not block.
    fd: File,

    /// Kernel-assigned interface name. C: `iface` global. Set
    /// post-ioctl from `ifr.ifr_name` (kernel writes the actual
    /// name back, even if we requested one — it might've truncated
    /// or appended a number).
    iface: String,

    /// L2 vs L3. Set at open, never changes. The read/write paths
    /// branch on this.
    mode: Mode,

    /// TAP only: kernel-assigned MAC. Read via `SIOCGIFHWADDR`
    /// post-TUNSETIFF. For TUN: `None`.
    mac: Option<Mac>,
}

impl Tun {
    /// Open `/dev/net/tun`, `TUNSETIFF` to instantiate, optionally
    /// `SIOCGIFHWADDR` to read the TAP MAC.
    ///
    /// # Errors
    /// `io::Error`:
    ///   - `PermissionDenied` (EACCES/EPERM) on open: missing
    ///     `CAP_NET_ADMIN`. Most common error in CI.
    ///   - `NotFound` on open: `/dev/net/tun` doesn't exist (kernel
    ///     built without `CONFIG_TUN`, or container without it
    ///     mounted).
    ///   - `InvalidInput` (EINVAL) on TUNSETIFF: bad flags, bad
    ///     ifname. Shouldn't happen with our construction.
    ///   - `AlreadyExists` (EBUSY) on TUNSETIFF: interface name
    ///     taken by another process. C commit `a7e906d2` (since
    ///     reverted by ethertap-drop, but the EBUSY case is real).
    pub fn open(cfg: &DeviceConfig) -> io::Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;

        let device = cfg.device.as_deref().unwrap_or(DEFAULT_DEVICE);

        // ─── ifr_name pack — BEFORE open
        // Validation is pure; open needs CAP_NET_ADMIN. Validate
        // first so tests can hit the error path without root.
        let ifr_name = pack_ifr_name(cfg.iface.as_deref())?;

        // ─── open
        // `O_RDWR | O_NONBLOCK | O_CLOEXEC`. CLOEXEC atomically in
        // the open flags closes the open→fcntl race window.
        // `custom_flags` ORs into the underlying `open(2)` flags;
        // `OpenOptions` already sets `O_RDWR` from
        // `.read(true).write(true)`.
        let fd = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(device)?;

        // ─── ifr_flags
        // `as i16`: constants fit (1, 2, 0x1000, 0x4000).
        // `IFF_ONE_QUEUE` NOT set: no-op since kernel `5d09710`
        // (2.6.27).
        //
        // TUN: `IFF_VNET_HDR | IFF_NO_PI`. Reads are
        // `[vnet_hdr(10)][raw IP]`; eth header synthesized in
        // `drain()` or by `tso_split`. Same approach as wg-go
        // (`tun_linux.go:566`).
        //
        // TAP: `IFF_NO_PI` only. vnet_hdr would need `tso_split`
        // to preserve the real eth header instead of synthesizing
        // one. Widen when switch-mode throughput matters.
        //
        // Set on the FIRST TUNSETIFF: the kernel's flag-update
        // path on a second TUNSETIFF (`tun.c:2744`) requires
        // re-attach (`:2729`) which fails on an already-attached
        // fd — there's no "change flags only" ioctl.
        #[allow(clippy::cast_possible_truncation)] // IFF_* flags fit i16 (max 0x5001)
        let flags = match cfg.mode {
            Mode::Tun => libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_VNET_HDR,
            Mode::Tap => libc::IFF_TAP | libc::IFF_NO_PI,
        } as i16;

        // ─── ifr_name
        // `iface = None` → leave name zeroed → kernel picks `tun0`
        // / `tap0` / first free.
        //
        // (ifr_name packed above, before open)

        // ─── TUNSETIFF
        // The ioctl. See module doc for why direct `libc::ioctl`
        // not `nix::ioctl_write_ptr_bad!` (the encoding is _IOW
        // but the kernel writes ifr_name back; the macro generates
        // `*const` which documents the wrong contract).
        //
        // Returns the kernel-chosen `ifr_name` (read back post-ioctl).
        let iface = tunsetiff(fd.as_raw_fd(), flags, ifr_name)?;

        // ─── SIOCGIFHWADDR (TAP only)
        // The MAC is kernel-generated (random with the locally-
        // administered bit set). The daemon's `route.c` uses it
        // for ARP replies in switch mode.
        //
        // Failure (`:125`: `LOG_WARNING`, not error) → C continues
        // with `mymac = {0}`. We `None`. The ARP path with `None`
        // would send all-zeros source MAC, which is invalid but
        // Port the warning-not-error.
        let mac = match cfg.mode {
            Mode::Tap => siocgifhwaddr(fd.as_raw_fd()).ok(),
            Mode::Tun => None,
        };

        // ─── TUNSETOFFLOAD (TUN only) ──────────────────────────
        // Feature-detect: `TUNSETOFFLOAD` returns `EINVAL` for
        // unknown flags (`tun.c:2886` "gives the user a way to test
        // for new features"). `TUN_F_TSO4/6` is kernel 2.6.27 —
        // never fails in practice. If it did (custom kernel without
        // `CONFIG_TUN` offload), IFF_VNET_HDR is already set so
        // reads HAVE the 10-byte prefix, just always gso_type=NONE.
        // drain() handles that: strip header, single frame. Degrades
        // gracefully.
        if cfg.mode == Mode::Tun {
            match tunsetoffload(fd.as_raw_fd()) {
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

    /// `IFF_MULTI_QUEUE` open: N fds attached to one TUN device.
    ///
    /// Kernel `tun_automq_select_queue` (`tun.c:474`) hashes the inner
    /// flow's 4-tuple to pick a queue. One TCP connection → one queue →
    /// one reader thread, no eBPF prog needed. The kernel's flow learning
    /// IS the steering: 1024 distinct flows across 2 queues showed a
    /// 354k/402k split (1.1× balance ratio) in the prototype.
    ///
    /// `n=1` → calls `Tun::open` (no `IFF_MULTI_QUEUE` flag, exact same
    /// fd as today). The flag forces the kernel to alloc 256 tx queues
    /// even at n=1 (`MAX_TAP_QUEUES`); waste it doesn't need.
    ///
    /// `n>1` requirements:
    ///   - `cfg.iface` set: the second `TUNSETIFF` finds the device by
    ///     name. Auto-pick (`tun%d`) would create N independent devices.
    ///   - `Mode::Tun`: TAP has no `IFF_VNET_HDR` here, and sharding is
    ///     router-mode only (switch mode's `mac_table` is shared mutable
    ///     on the data path — MAC learning).
    ///
    /// `TUNSETIFF` flags = `IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE |
    /// IFF_VNET_HDR` = `0x5101`. The `IFF_MULTI_QUEUE` bit must be set
    /// on EVERY call; `tun.c:2719` rejects the second call if the bit
    /// doesn't match the first (`EINVAL`).
    ///
    /// `TUNSETOFFLOAD` once on fd[0]: offload bits live on the netdev
    /// (`tun_struct.features`), not per-`tun_file`. One call arms TSO
    /// for all queues.
    ///
    /// # Errors
    /// `InvalidInput`: `n>1` with `cfg.iface = None` or `Mode::Tap`, or
    /// iface name ≥ 16 bytes. `PermissionDenied`/`NotFound`: same as
    /// `open`. `EINVAL` on `TUNSETIFF`: kernel rejected the flag combo
    /// (kernel <3.8 — ancient; `IFF_MULTI_QUEUE`+`IFF_VNET_HDR` proven
    /// to compose on 6.19.9).
    ///
    /// # Panics
    /// `n == 0` or `n > 256` (kernel `MAX_TAP_QUEUES`).
    pub fn open_mq(cfg: &DeviceConfig, n: usize) -> io::Result<Vec<Tun>> {
        use std::os::unix::fs::OpenOptionsExt;
        assert!(n > 0 && n <= 256, "queue count {n} out of [1, 256]");

        if n == 1 {
            // One queue: no MQ flag. Exact same fd shape as before
            // open_mq existed. The daemon's single-shard path is
            // bit-identical.
            return Tun::open(cfg).map(|t| vec![t]);
        }

        // ─── n > 1: explicit name + TUN-only ───────────────────────────
        let Some(name) = cfg.iface.as_deref() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "multiqueue requires explicit iface name \
                 (kernel matches subsequent TUNSETIFF by name; \
                 auto-pick would create N independent devices)",
            ));
        };
        if cfg.mode != Mode::Tun {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "multiqueue requires Mode::Tun (sharding is router-mode \
                 only; TAP path has no IFF_VNET_HDR)",
            ));
        }

        let device = cfg.device.as_deref().unwrap_or(DEFAULT_DEVICE);
        let ifr_name = pack_ifr_name(Some(name))?;

        // 0x5101. The MQ bit must be set on every TUNSETIFF —
        // tun.c:2719 rejects mismatch. Same vnet_hdr handling as
        // single-queue (drain/write_super are unchanged).
        #[allow(clippy::cast_possible_truncation)]
        let flags =
            (libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_MULTI_QUEUE | libc::IFF_VNET_HDR) as i16;

        let mut queues = Vec::with_capacity(n);
        for k in 0..n {
            let fd = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
                .open(device)?;

            let iface = tunsetiff(fd.as_raw_fd(), flags, ifr_name)?;

            // Offload is per-netdev. Once. Same feature-detect
            // warning as Tun::open: failure means vnet_hdr is on
            // but gso_type stays NONE — drain handles that.
            if k == 0
                && let Err(e) = tunsetoffload(fd.as_raw_fd())
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

// ifr_name packing — the testable seam

/// `[c_char; IFNAMSIZ]` from `Option<&str>`. Called BEFORE
/// `open(/dev/net/tun)` so length validation fires without
/// `CAP_NET_ADMIN`.
///
/// `None` → zeros → kernel picks. `len >= 16` → `Err`. STRICTER
/// than `strncpy + [15]=0` truncation (which fails three steps
/// later as `ENODEV` in the
/// user's `ip addr add`). `c_char` sign varies by arch; cast is
/// sound (kernel reads bytes).
///
/// # Errors
/// `InvalidInput` for too-long name. The error message includes
/// the name and the limit.
#[allow(clippy::cast_possible_wrap)] // ASCII bytes → c_char (sign is platform noise)
fn pack_ifr_name(iface: Option<&str>) -> io::Result<[libc::c_char; libc::IFNAMSIZ]> {
    let mut buf = [0; libc::IFNAMSIZ];
    let Some(name) = iface else {
        // Empty → kernel picks. C: `if(iface)` skips the strncpy.
        return Ok(buf);
    };
    let bytes = name.as_bytes();
    // `< IFNAMSIZ` not `<=`: room for NUL. The kernel reads as a
    // C string; 16 chars + no NUL = unterminated. C's `[15]=0`
    // forces termination by truncation; we reject instead.
    if bytes.len() >= libc::IFNAMSIZ {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "interface name {name:?} too long (max {} bytes)",
                libc::IFNAMSIZ - 1
            ),
        ));
    }
    // `as c_char`: x86_64 `i8`, aarch64 `u8`. Kernel ifnames are
    // `[A-Za-z0-9._-]` (`dev_valid_name`); ASCII; cast preserves.
    for (dst, src) in buf.iter_mut().zip(bytes) {
        *dst = *src as libc::c_char;
    }
    Ok(buf)
}

// ioctls — the third-instance unsafe shims

/// `TUNSETIFF` — instantiate a TUN/TAP device. Kernel reads `ifr_
/// flags` and `ifr_name` (may be empty), writes `ifr_name` back
/// (the actually-assigned name).
///
/// `libc::TUNSETIFF` = `0x400454ca` = `_IOW('T', 202, int)`. The
/// `int` size encoding is a historical accident (the ioctl predates
/// the size-in-ioctl-number convention); kernel treats the third
/// arg as `struct ifreq *` regardless.
///
/// Returns the assigned interface name as a `String`. The kernel
/// always NUL-terminates within `IFNAMSIZ` (it `strscpy`s); we
/// `CStr::from_bytes_until_nul` and convert.
#[allow(unsafe_code)]
fn tunsetiff(
    fd: RawFd,
    flags: i16,
    ifr_name: [libc::c_char; libc::IFNAMSIZ],
) -> io::Result<String> {
    // `libc::ifreq` construction. `MaybeUninit::zeroed()` because
    // the union has a `*mut c_char` member (`ifru_data`); zeroing
    // it gives a NULL pointer, which is valid. Can't `Default`
    // (libc doesn't impl it for unions); can't struct-literal
    // (union member needs to be set, but which one?). Zeroed-
    // then-field-assign is the standard `struct ifreq ifr = {0}`
    // pattern.
    //
    // SAFETY (zeroed): `ifreq` is `repr(C)` with no niche. All
    // fields are integers, byte arrays, or pointers (NULL valid).
    // All-bits-zero is a valid representation.
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    ifr.ifr_name = ifr_name;
    // SAFETY (union write): writing `ifru_flags` initializes the
    // union to that variant. Subsequent reads of OTHER variants
    // would be UB; we don't do that. The kernel reads via
    // `copy_from_user` (byte copy), doesn't care about Rust's
    // active-variant rules.
    ifr.ifr_ifru.ifru_flags = flags;

    // SAFETY (ioctl):
    //   - `fd` is the open `/dev/net/tun` fd. Valid (just opened
    //     it; not closed; not racing).
    //   - `TUNSETIFF` expects `struct ifreq *`. `&raw mut ifr` is
    //     a valid aligned pointer to an initialized `ifreq` of the
    //     right size (smoke-verified 40 bytes both sides).
    //   - The kernel READS `ifr_flags` (offset 16, 2 bytes) and
    //     `ifr_name` (offset 0, 16 bytes including NUL). Both
    //     initialized above.
    //   - The kernel WRITES `ifr_name` (the assigned name). We
    //     read it post-call. Our `ifr` is `mut`; the pointer is
    //     `*mut`; the kernel writing through it is sound.
    //   - NOT thread-safe in a useful sense (TUNSETIFF on the
    //     same fd twice is EBUSY). But this fn is called once
    //     from `Tun::open` which the daemon calls once. No race.
    //   - Locking: kernel `tun_chr_ioctl` takes `rtnl_lock` for
    //     TUNSETIFF. We don't observe; just FYI.
    //
    // `&raw mut` not `&mut`: same `clippy::borrow_as_ptr` as
    // `tui.rs`'s `winsize`. Explicit place-to-pointer.
    let ret = unsafe { libc::ioctl(fd, libc::TUNSETIFF, &raw mut ifr) };
    if ret < 0 {
        // `from_raw_os_error(errno)`. `last_os_error()` reads
        // `errno` (thread-local on Linux glibc, process-global
        // on musl-nope-also-thread-local). The `ret < 0` means
        // errno was set; reading it now is correct (no syscalls
        // between the ioctl and here).
        return Err(io::Error::last_os_error());
    }

    // ─── Read back ifr_name
    //
    // The kernel `strscpy`s into `ifr_name`, NUL-terminated. The
    // C's defensive `[15]=0` is belt-and-suspenders (kernel always
    // terminates). We trust the kernel: `from_bytes_until_nul`
    // finds the NUL or fails. If it fails (kernel bug, no NUL in
    // 16 bytes), we error out — STRICTER than C (which would
    // produce a 15-byte string of garbage).
    //
    // `CStr::from_ptr` on `ifr_name.as_ptr()` sidesteps the
    // arch-variable `c_char` signedness entirely.
    // SAFETY: kernel wrote a NUL-terminated string into the
    // buffer; reading until NUL is sound. The buffer is 16 bytes;
    // the kernel never writes past 15 (IFNAMSIZ-1) + NUL.
    //
    // `to_string_lossy`: kernel ifnames are ASCII (`[A-Za-z0-9.
    // _-]` — `dev_valid_name` in `net/core/dev.c`). Never lossy
    // in practice. But lossy is forward-compatible (kernel might
    // relax someday) and avoids the `into_string().unwrap()`
    // panic-on-non-UTF8.
    let name = unsafe { CStr::from_ptr(ifr.ifr_name.as_ptr()) };
    Ok(name.to_string_lossy().into_owned())
}

/// `TUNSETOFFLOAD` — advertise offload capabilities to the kernel
/// TCP stack. `tun.c:2842` `set_offload`: `TUN_F_TSO4|6` sets
/// `NETIF_F_TSO|NETIF_F_TSO6` on the netdev → the TCP stack stops
/// segmenting at MTU, hands us ≤64KB skbs.
///
/// `_IOW('T', 208, unsigned int)`. The arg is the flag word, passed
/// BY VALUE (`tun.c:3213`: `set_offload(tun, arg)` — no pointer
/// dereference). Unlike `TUNSETIFF`, the encoding is honest.
///
/// Not in the `libc` crate. Kernel ABI; can't change.
const TUNSETOFFLOAD: libc::c_ulong = 0x4004_54d0;

/// `TUN_F_*` flags for `TUNSETOFFLOAD`. `if_tun.h:88-90`.
/// `TUN_F_CSUM` is required for `TUN_F_TSO*` (`tun.c:2850`: TSO
/// flags only checked inside the `if (arg & TUN_F_CSUM)` block).
const TUN_F_CSUM: libc::c_uint = 0x01;
const TUN_F_TSO4: libc::c_uint = 0x02;
const TUN_F_TSO6: libc::c_uint = 0x04;

#[allow(unsafe_code)]
fn tunsetoffload(fd: RawFd) -> io::Result<()> {
    let flags = TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6;
    // SAFETY:
    //   - `fd` is the post-TUNSETIFF TUN fd. Valid.
    //   - `TUNSETOFFLOAD` takes the flag word BY VALUE as the third
    //     ioctl arg (`tun.c:3213`: `set_offload(tun, arg)`). NOT a
    //     pointer. The `_IOW(..., unsigned int)` size encoding is
    //     for the value; the kernel reads it directly from the
    //     varargs slot. Passing `flags as c_ulong` matches what
    //     glibc's `ioctl(fd, req, ...)` expects.
    //   - Kernel writes nothing back (no pointer to write to).
    //   - `EINVAL` if any unknown flag bit is set (`tun.c:2886`).
    //     Our three flags are kernel 2.6.27.
    let ret = unsafe { libc::ioctl(fd, TUNSETOFFLOAD, libc::c_ulong::from(flags)) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `SIOCGIFHWADDR` — read the device's MAC.
///
/// Uses `ifr_ifru.ifru_hwaddr: sockaddr`. The MAC is in `sa_data
/// [0..6]` (the rest of `sockaddr` is unused/garbage for hwaddr).
#[allow(unsafe_code)]
fn siocgifhwaddr(fd: RawFd) -> io::Result<Mac> {
    // The kernel reads NOTHING from this ifreq — `SIOCGIFHWADDR`
    // on a TUN/TAP fd
    // ignores `ifr_name` (the fd already names the device). Zeroed
    // is just hygiene.
    //
    // (On a regular socket, `SIOCGIFHWADDR` reads `ifr_name` to
    // pick which interface. TUN/TAP fd is already bound to one
    // interface post-TUNSETIFF; the name is implicit.)
    //
    // SAFETY (zeroed): same as `tunsetiff`. All-zero `ifreq` is
    // valid.
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };

    // SAFETY (ioctl):
    //   - `fd` is the post-TUNSETIFF fd. Valid.
    //   - `SIOCGIFHWADDR` expects `struct ifreq *`. Same shape as
    //     above.
    //   - Kernel reads NOTHING (TUN/TAP fd path; see above).
    //   - Kernel WRITES `ifr_ifru.ifru_hwaddr` (a `sockaddr`, 16
    //     bytes at offset 16). Our `ifr` is `mut`; sound.
    //   - Thread-safe: read-only from the kernel's perspective
    //     (reading the MAC doesn't lock). Concurrent calls on the
    //     same fd would race-read the same MAC → same result.
    //     Doesn't happen (called once from `Tun::open`).
    let ret = unsafe { libc::ioctl(fd, libc::SIOCGIFHWADDR, &raw mut ifr) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    // `sockaddr.sa_data` is `[c_char; 14]`. First 6 bytes are the
    // MAC (ETH_ALEN=6).
    //
    // SAFETY (union read): the kernel wrote `ifru_hwaddr`. Reading
    // it now is sound (it's the active variant from the kernel's
    // write). The 14 bytes are: `[0..6]` MAC, `[6..14]` undefined
    // (kernel only sets the first 6 for `ARPHRD_ETHER`). We only
    // read `[0..6]`.
    #[allow(clippy::cast_sign_loss)] // c_char→u8: raw MAC bytes, sign is platform noise
    let mac: Mac = {
        let sa_data = unsafe { ifr.ifr_ifru.ifru_hwaddr }.sa_data;
        [
            sa_data[0] as u8,
            sa_data[1] as u8,
            sa_data[2] as u8,
            sa_data[3] as u8,
            sa_data[4] as u8,
            sa_data[5] as u8,
        ]
    };
    Ok(mac)
}

// Device trait — read/write with the offset trick

impl Device for Tun {
    /// Read a packet. TAP only.
    ///
    /// TUN doesn't go through here: `drain()` is overridden and
    /// reads directly via `read_fd` (`vnet_hdr` layout). The trait
    /// default `drain` calls `self.read()`, but our override
    /// doesn't.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // TUN: dead path — the vnet drain override bypasses this.
        // If this fires, drain() got de-overridden.
        debug_assert_eq!(
            self.mode,
            Mode::Tap,
            "Tun::read on Mode::Tun; vnet drain() should read \
             directly. Is drain() still overridden?"
        );

        // ─── TAP ───────────────────────────────────────────────
        // `IFF_NO_PI` → no `tun_pi` prefix; raw ethernet. Direct
        // read, no offset, no memset.
        debug_assert!(
            buf.len() >= MTU,
            "buf too small for TAP read: {} < {MTU}",
            buf.len()
        );
        let dst = &mut buf[..MTU];
        let n = read_fd(self.fd.as_raw_fd(), dst)?;
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
            // ─── TUN (vnet_hdr) ────────────────────────────────
            // `IFF_NO_PI | IFF_VNET_HDR`: kernel expects
            // `[vnet_hdr(10)][raw IP]` on write (`tun_get_user`
            // at `tun.c:1731`). The daemon's `buf` is
            // `[synthetic eth(14)][IP]` — the synth header is all
            // zeros except ethertype at [12..14]. We need 10 zero
            // bytes (a `gso_type=NONE` vnet_hdr means "just inject
            // this skb, no offload") followed by the IP packet.
            //
            // Layout trick: `buf[4..14]` is the synth eth header
            // tail (zeros + ethertype). Stomp it to all-zeros and
            // write `buf[4..]` — that's `[10 zeros][IP]`. The
            // ethertype at [12..14] is the only non-zero region
            // we clobber, and it's `&mut` so allowed. The daemon
            // never reads buf back after write (it's a synthesized
            // ICMP reply or a forwarded inbound packet, both done
            // after write returns).
            //
            // The GRO coalesce path fills a real vnet_hdr via
            // `write_super`; THIS path (per-packet write) always
            // sends gso_type=NONE.
            Mode::Tun => {
                debug_assert!(buf.len() > ETH_HLEN, "vnet write buf too short");
                // Ethertype → 0. Bytes [4..12] are already 0
                // (synth MACs); [12..14] is ethertype.
                buf[12] = 0;
                buf[13] = 0;
                // `4 = ETH_HLEN - VNET_HDR_LEN`. Write from there:
                // 10 zero bytes (vnet_hdr) + IP packet.
                write_fd(self.fd.as_raw_fd(), &buf[ETH_HLEN - VNET_HDR_LEN..])
            }

            // ─── TAP
            // Direct write.
            Mode::Tap => write_fd(self.fd.as_raw_fd(), buf),
        }
    }

    /// GRO super write. `buf` is `[vnet_hdr(10)][IP
    /// ≤65535]` from `GroBucket::flush` — already in `tun_get_user`'s
    /// expected shape (`tun.c:1731`). Just `write()`.
    ///
    /// `IFF_VNET_HDR` is unconditionally on for `Mode::Tun` since
    /// `5cf9b12d`; the daemon's `gro_enabled` gate checks mode
    /// before calling, so the TAP arm is unreachable. Belt-and-
    /// braces with the same "degrade not crash" guard as the trait
    /// default.
    fn write_super(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.mode {
            Mode::Tun => write_fd(self.fd.as_raw_fd(), buf),
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

    fn fd(&self) -> Option<RawFd> {
        Some(self.fd.as_raw_fd())
    }

    /// `vnet_hdr` drain. Overrides the default `read()`-loop only
    /// when `IFF_VNET_HDR` is on; otherwise delegates.
    ///
    /// Read shape with `vnet_hdr` (`tun_put_user`, `tun.c:2064`):
    /// `[virtio_net_hdr(10)][raw IP packet (≤65535)]`. NO `tun_pi`
    /// (`IFF_NO_PI` set), NO eth header (TUN mode). One read = one
    /// skb. For `gso_type==TCPV4/6`, the IP packet is a super-
    /// segment (`totlen > MTU`).
    ///
    /// `gso_type==NONE` (the common case for non-TCP, ARP, ICMP,
    /// short TCP): strip the `vnet_hdr`, complete partial csum if
    /// `NEEDS_CSUM`, synthesize eth header, return as single
    /// `Frames{count: 1}`. Same wire result as the non-vnet path.
    ///
    /// `gso_type==TCPV4/6`: strip `vnet_hdr`, return `Super{..}`.
    /// The daemon calls `tso_split` on the contiguous buffer.
    fn drain(&mut self, arena: &mut DeviceArena, cap: usize) -> io::Result<DrainResult> {
        if self.mode == Mode::Tap {
            // TAP: no vnet_hdr (see `flags` in `Tun::open`). The
            // trait default's `read()`-in-a-loop is the right
            // shape, but we can't call the trait default from an
            // override. Inline it. Same loop the BSD/mock paths
            // inherit for free.
            let cap = cap.min(arena.cap());
            let mut n = 0;
            while n < cap {
                match self.read(arena.slot_mut(n)) {
                    Ok(len) => {
                        arena.set_len(n, len);
                        n += 1;
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e),
                }
            }
            return Ok(if n == 0 {
                DrainResult::Empty
            } else {
                DrainResult::Frames { count: n }
            });
        }

        // ─── TUN: vnet_hdr path ──────────────────────────────
        // ONE read into the contiguous arena. A super-packet can be
        // 65535 + 10 bytes; `as_contiguous_mut` is `cap*STRIDE` =
        // 64*1600 = 102400 bytes. Fits.
        //
        // EPOLLET: returning while the queue is non-empty loses the
        // wake. The daemon's `on_device_read` must call `drain` in a
        // loop until `Empty`. The default `Frames` path doesn't need
        // this because it loops INTERNALLY here; the Super path
        // can't (one super-segment fills the output budget). The
        // daemon side handles the loop — see the `Super` arm in
        // `net.rs::on_device_read`.
        let buf = arena.as_contiguous_mut();
        let n = match read_fd(self.fd.as_raw_fd(), buf) {
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
                // ─── Non-GSO frame: pass-through ─────────────
                // Single IP packet. Complete partial csum, synth
                // eth header, return as `Frames{1}`. wg-go
                // `tun_linux.go:382-397` `gsoNoneChecksum` path.
                //
                // Layout transform IN PLACE in slot 0:
                //   before: [vnet_hdr(10)][IP pkt]
                //   after:  [eth(14)][IP pkt]
                // The IP packet shifts right by 4. Do the csum fix
                // BEFORE the shift (csum_start is relative to IP
                // start, currently at +10).
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
                // ─── TCP super-segment ──────────────────────
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

    /// `open_mq(n>1)` rejects `iface = None`. Validation BEFORE
    /// open (no `CAP_NET_ADMIN` needed). Same shape as
    /// `open_too_long_iface_err_before_open`.
    #[test]
    fn open_mq_requires_iface() {
        let cfg = DeviceConfig {
            iface: None,
            ..DeviceConfig::default()
        };
        let e = Tun::open_mq(&cfg, 2).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        assert!(e.to_string().contains("explicit iface name"));
    }

    /// `open_mq(n>1)` rejects TAP. Router-mode only.
    #[test]
    fn open_mq_requires_tun_mode() {
        let cfg = DeviceConfig {
            iface: Some("shard0".to_owned()),
            mode: Mode::Tap,
            ..DeviceConfig::default()
        };
        let e = Tun::open_mq(&cfg, 2).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        assert!(e.to_string().contains("Mode::Tun"));
    }

    // pack_ifr_name — the testable seam

    /// Ok-path: `None` → all zeros (kernel picks). `Some` → packed,
    /// NUL-padded. The boundary: `< IFNAMSIZ`
    /// accepts 15, rejects 16. `as u8` cast for x86_64-vs-aarch64
    /// `c_char` signedness; values are ASCII either way.
    #[test]
    #[allow(clippy::cast_sign_loss)] // c_char→u8: ASCII test bytes
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
                assert_eq!(buf[j] as u8, b, "case {i}: byte {j}");
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

    /// Exactly 16 bytes → Err. STRICTER than C (which truncates
    /// to 15). The error message names the limit.
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

    /// `Tun::open` with too-long iface → `Err` BEFORE open. The
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
        // NOT NotFound (which would mean we hit open() first).
        // NOT PermissionDenied (same). The validation fired.
    }

    /// `Tun::open` with valid config but no `CAP_NET_ADMIN` → some
    /// `Err` (EACCES on open, or ENOENT if /dev/net/tun missing).
    /// NOT `InvalidInput` — the validation passed, the syscall
    /// failed.
    ///
    /// SKIP under root: open might actually succeed, and then
    /// we've created a TUN device that lingers until process
    /// exit. Don't.
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
