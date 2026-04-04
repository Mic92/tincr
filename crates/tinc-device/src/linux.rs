//! Linux TUN/TAP — `linux/device.c` (225 LOC, 1.1 branch HEAD).
//!
//! ──────────── ioctl approach: NOT the nix macro ────────────────────
//!
//! `tui.rs` uses `nix::ioctl_read_bad!` for `TIOCGWINSZ`. That works
//! because `TIOCGWINSZ` only writes (kernel → us). `TUNSETIFF` is
//! encoded as `_IOW` (us → kernel) but the kernel WRITES BACK `ifr_
//! name` (`linux/device.c:108-111`: `strncpy(ifrname, ifr.ifr_name)`
//! AFTER the ioctl). The ioctl encoding lies about the direction.
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
//! the third-instance pattern (tui ioctl, info localtime_r, this)
//! still holds: scoped `#[allow(unsafe_code)]`, SAFETY comment that
//! says what the kernel reads/writes/locks.
//!
//! ──────────── `libc::ifreq` layout ─────────────────────────────────
//!
//! Smoke-verified `sizeof(struct ifreq) == 40` on x86_64 glibc, and
//! `libc::ifreq` matches. Layout: `ifr_name: [c_char; 16]` + 24-byte
//! `ifr_ifru` union (largest members are 16 bytes, padded to 24).
//!
//! `ifr_flags` is `ifr_ifru.ifru_flags: c_short` (2 bytes at offset
//! 16). The C uses `ifr.ifr_flags` (a `#define` alias into the
//! union); we write `ifr.ifr_ifru.ifru_flags`.
//!
//! ──────────── Why O_CLOEXEC matters here more than usual ──────────
//!
//! C `device.c:63`: `fcntl(device_fd, F_SETFD, FD_CLOEXEC)`. The
//! daemon spawns `tinc-up`, `tinc-down`, `host-NAME-up` scripts
//! (`script.c`). Without CLOEXEC, the script inherits the TUN fd.
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
use crate::{Device, DeviceArena, DeviceConfig, DrainResult, GsoType, MTU, Mac, Mode};

/// `DEFAULT_DEVICE` — `linux/device.c:24`. The kernel's TUN/TAP
/// multiplexer. Opening it doesn't give you a device; `TUNSETIFF`
/// does. The fd is just a handle into the driver until then.
const DEFAULT_DEVICE: &str = "/dev/net/tun";

/// `os_devops` for Linux. Owns the fd; `Drop` closes it (via
/// `File::drop`, which is `close(2)`). C `close_device` (`:132-
/// 142`) does `close(device_fd)` then frees the strings; we get
/// both for free.
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
    /// post-TUNSETIFF (`device.c:121-126`). For TUN: `None`.
    mac: Option<Mac>,

    /// `IFF_VNET_HDR + TUNSETOFFLOAD` succeeded — the kernel
    /// prepends a 10-byte `virtio_net_hdr` to every read and
    /// hands us ≤64KB TCP super-segments. The `drain()` override
    /// branches on this. Set ONCE at open; never changes.
    ///
    /// `RUST_REWRITE_10G.md` Phase 2a. Feature-gated by
    /// `DeviceConfig::vnet_hdr` (`-o ExperimentalGSO=yes`). The
    /// sha256-of-stream gate (`netns::tso_ingest_stream_integrity`)
    /// is green; the gate stays until 2a + 2b ship together and
    /// we re-profile against the recalibrated Phase 3 ceiling.
    /// Flipping default-on changes the device's wire shape (no
    /// tun_pi, vnet_hdr on writes) — do it once, not piecemeal.
    vnet_hdr: bool,
}

impl Tun {
    /// `setup_device` (`linux/device.c:46-130`). Open `/dev/net/
    /// tun`, `TUNSETIFF` to instantiate, optionally `SIOCGIFHWADDR`
    /// to read the TAP MAC.
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
        // C `device.c:56`: `open(device, O_RDWR | O_NONBLOCK)`.
        // C `:63`: `fcntl(device_fd, F_SETFD, FD_CLOEXEC)` — race
        // window between open and fcntl. We close the window with
        // `O_CLOEXEC` in the open flags. `custom_flags` ORs into
        // the underlying `open(2)` flags; `OpenOptions` already
        // sets `O_RDWR` from `.read(true).write(true)`.
        let fd = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(device)?;

        // ─── ifr_flags (C `device.c:77-89`)
        // `IFF_NO_PI` only on TAP; TUN keeps `tun_pi` for the
        // ethertype-slot trick. `as i16`: constants fit (1, 2,
        // 0x1000). `IFF_ONE_QUEUE` NOT set: no-op since kernel
        // `5d09710` (2.6.27); C `:93-98` still sets it, we don't.
        //
        // `cfg.vnet_hdr` (`ExperimentalGSO=on`): add `IFF_VNET_HDR
        // | IFF_NO_PI`. The vnet_hdr path drops the +10 tun_pi
        // trick — reads are `[vnet_hdr(10)][raw IP]`, the eth
        // header is synthesized in `drain()` (or by `tso_split` for
        // super-packets). Same approach as wg-go (`tun_linux.go:
        // 566`: `IFF_TUN | IFF_NO_PI | IFF_VNET_HDR`).
        //
        // Set on the FIRST TUNSETIFF. The kernel's flag-update
        // path on a second TUNSETIFF (`tun.c:2744`) requires
        // re-attach (`:2729`) which fails on an already-attached
        // fd — there's no "change flags only" ioctl.
        let want_vnet = cfg.vnet_hdr && cfg.mode == Mode::Tun;
        #[allow(clippy::cast_possible_truncation)]
        let flags = match cfg.mode {
            Mode::Tun if want_vnet => libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_VNET_HDR,
            Mode::Tun => libc::IFF_TUN,
            Mode::Tap => libc::IFF_TAP | libc::IFF_NO_PI,
        } as i16;

        // ─── ifr_name
        // C `device.c:103-105`: `strncpy(ifr.ifr_name, iface,
        // IFNAMSIZ); ifr.ifr_name[IFNAMSIZ-1] = 0`.
        //
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
        // Returns the kernel-chosen `ifr_name`. We read it post-
        // ioctl (`device.c:108-111`).
        let iface = tunsetiff(fd.as_raw_fd(), flags, ifr_name)?;

        // ─── SIOCGIFHWADDR (TAP only)
        // C `device.c:119-127`: `if(ifr.ifr_flags & IFF_TAP)` then
        // `ioctl(SIOCGIFHWADDR)` into a fresh `ifreq`, `memcpy` 6
        // bytes from `ifr_hwaddr.sa_data`.
        //
        // The MAC is kernel-generated (random with the locally-
        // administered bit set). The daemon's `route.c` uses it
        // for ARP replies in switch mode.
        //
        // Failure (`:125`: `LOG_WARNING`, not error) → C continues
        // with `mymac = {0}`. We `None`. The ARP path with `None`
        // would send all-zeros source MAC, which is invalid but
        // the C does the same thing. Port the warning-not-error.
        let mac = match cfg.mode {
            Mode::Tap => siocgifhwaddr(fd.as_raw_fd()).ok(),
            Mode::Tun => None,
        };

        // ─── TUNSETOFFLOAD (Phase 2a) ──────────────────────────
        // Only on TUN (router mode). TAP would work too (kernel
        // supports it) but `tso_split` synthesizes an eth header,
        // which is wrong for TAP (real eth already there). Widen
        // when switch mode matters — it doesn't today (the gate is
        // iperf3 over routed v4).
        //
        // Feature-detect: `TUNSETOFFLOAD` returns `EINVAL` for
        // unknown flags (`tun.c:2886` "gives the user a way to test
        // for new features"). `TUN_F_TSO4/6` is kernel 2.6.27, so
        // this never fails in practice on the kernels we support —
        // but if it does (custom kernel without `CONFIG_TUN`
        // offload), the kernel still prepends a 10-byte all-zero
        // vnet_hdr (IFF_VNET_HDR is set) but never GSOs. The
        // drain() override handles this: gso_type=NONE → strip
        // header, single frame. Degrades gracefully.
        let vnet_hdr = if want_vnet {
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
            // `vnet_hdr` is true regardless of TUNSETOFFLOAD result:
            // IFF_VNET_HDR is already set on the device (the first
            // TUNSETIFF above), so reads HAVE the 10-byte prefix.
            // The drain() override must run.
            true
        } else {
            false
        };

        Ok(Tun {
            fd,
            iface,
            mode: cfg.mode,
            mac,
            vnet_hdr,
        })
    }
}

// ifr_name packing — the testable seam

/// `[c_char; IFNAMSIZ]` from `Option<&str>`. Called BEFORE
/// `open(/dev/net/tun)` so length validation fires without
/// CAP_NET_ADMIN.
///
/// `None` → zeros → kernel picks (C `:103` `if(iface)`).
/// `len >= 16` → `Err`. STRICTER than C's `strncpy + [15]=0`
/// truncation (which fails three steps later as `ENODEV` in the
/// user's `ip addr add`). `c_char` sign varies by arch; cast is
/// sound (kernel reads bytes).
///
/// # Errors
/// `InvalidInput` for too-long name. The error message includes
/// the name and the limit.
#[allow(clippy::cast_possible_wrap)]
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
    // then-field-assign is the C `struct ifreq ifr = {0}` pattern.
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
    // C `device.c:108-110`: `strncpy(ifrname, ifr.ifr_name,
    // IFNAMSIZ); ifrname[IFNAMSIZ-1] = 0; iface = xstrdup(ifrname)`.
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

/// `SIOCGIFHWADDR` — read the device's MAC. C `device.c:121-126`.
///
/// Uses `ifr_ifru.ifru_hwaddr: sockaddr`. The MAC is in `sa_data
/// [0..6]` (the rest of `sockaddr` is unused/garbage for hwaddr).
#[allow(unsafe_code)]
fn siocgifhwaddr(fd: RawFd) -> io::Result<Mac> {
    // C `:120`: `struct ifreq ifr_mac = {0}`. The kernel reads
    // NOTHING from this ifreq — `SIOCGIFHWADDR` on a TUN/TAP fd
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
    // MAC. C `:124`: `memcpy(mymac.x, ifr.ifr_hwaddr.sa_data,
    // ETH_ALEN)` where ETH_ALEN=6.
    //
    // SAFETY (union read): the kernel wrote `ifru_hwaddr`. Reading
    // it now is sound (it's the active variant from the kernel's
    // write). The 14 bytes are: `[0..6]` MAC, `[6..14]` undefined
    // (kernel only sets the first 6 for `ARPHRD_ETHER`). We only
    // read `[0..6]`.
    //
    // `c_char → u8`: same `as u8` cast as above. Bytes are bytes.
    #[allow(clippy::cast_sign_loss)]
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
    /// `read_packet` (`linux/device.c:144-183`). The +10 offset
    /// trick for TUN. See lib.rs module doc for the full layout
    /// explanation.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.mode {
            // ─── TUN
            // C `:146-165`. Read at +10, memset 0..12, return +10.
            Mode::Tun => {
                // `MTU - 10` is the C's `read(fd, buf+10, MTU-10)`.
                // We slice `buf[10..]` and let `read()` fill what
                // it fills. The slice MUST be at least `MTU` long
                // for the C-compat read length cap. Daemon's
                // `data[MAXSIZE]` is 1673; `1673 - 12 (offset) =
                // 1661 > 1518`. Fine.
                //
                // `debug_assert` not `assert`: the daemon owns the
                // buffer; this is a contract violation if it's too
                // short, not a runtime error. Debug catches it.
                debug_assert!(
                    buf.len() >= MTU,
                    "buf too small for TUN read: {} < {MTU}",
                    buf.len()
                );

                // `min(MTU - 10)` caps the read. The kernel's TUN
                // driver returns one packet per read (datagram
                // semantics — it's `read` not `recv` but TUN
                // behaves like a datagram socket). A packet larger
                // than the read buffer is TRUNCATED by the kernel
                // (`tun_put_user` clips). C reads `MTU-10` so
                // packets > MTU-10+4 (the tun_pi header counts)
                // truncate. We match.
                //
                // `..MTU` upper bound on the slice — the read
                // can't write past `buf[MTU-1]`. Same cap.
                let dst = &mut buf[10..MTU];
                let n = read_fd(self.fd.as_raw_fd(), dst)?;

                // C `:149`: `if(inlen <= 0)`. `read_fd` already
                // converted `<0` to Err. `0` is EOF — TUN never
                // EOFs (the device is always there until close,
                // and we'd have closed it ourselves). C errors on
                // `==0` too (the `<=0` test); we match. STRICTER
                // would be a distinct error message ("unexpected
                // EOF"); C just `strerror(errno)` which is
                // "Success" for `inlen==0`, ugly. We say so.
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "TUN device returned EOF (this shouldn't happen)",
                    ));
                }

                // C `:162`: `memset(DATA, 0, 12)`. Src-MAC zeroing
                // overwrites `tun_pi.flags` at [10..12] (always 0
                // on rx anyway). Bytes [0..10] hold the previous
                // packet's data (`vpn_packet_t` reused); memset
                // matters.
                buf[..12].fill(0);

                // C `:163`: `packet->len = inlen + 10`. The 10 is
                // the synthetic-header bytes (well, 14, but the
                // ethertype 2 bytes were inside `inlen` as
                // `tun_pi.proto`). 10 = 14 (ether) - 4 (tun_pi).
                Ok(n + 10)
            }

            // ─── TAP
            // C `:167-179`. Direct read, no offset, no memset.
            // `IFF_NO_PI` means no `tun_pi` prefix; the kernel
            // hands us raw ethernet.
            Mode::Tap => {
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
        }
    }

    /// `write_packet` (`linux/device.c:185-211`). The inverse of
    /// the +10 trick for TUN.
    fn write(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.mode {
            // ─── TUN with vnet_hdr (Phase 2a) ──────────────────
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
            // Phase 2b (GRO TUN write) will fill in a real vnet_hdr
            // here for coalesced ACK bursts. For now: zeros.
            Mode::Tun if self.vnet_hdr => {
                debug_assert!(buf.len() > ETH_HLEN, "vnet write buf too short");
                // Ethertype → 0. Bytes [4..12] are already 0
                // (synth MACs); [12..14] is ethertype.
                buf[12] = 0;
                buf[13] = 0;
                // `4 = ETH_HLEN - VNET_HDR_LEN`. Write from there:
                // 10 zero bytes (vnet_hdr) + IP packet.
                write_fd(self.fd.as_raw_fd(), &buf[ETH_HLEN - VNET_HDR_LEN..])
            }
            // ─── TUN
            // C `:188-196`. Zero `buf[10..12]` (`tun_pi.flags`),
            // write `buf[10..]`.
            Mode::Tun => {
                // C `:188`: zero `tun_pi.flags` at [10..12].
                // Ethertype at [12..14] left alone (`route.c` set
                // it). Idempotent for read-then-write; matters for
                // synthesized ICMP/ARP. Hence `&mut [u8]`.
                debug_assert!(buf.len() > 12, "TUN write buf too short");
                buf[10] = 0;
                buf[11] = 0;

                // C `:190`: write at +10; ethertype passes through
                // as `tun_pi.proto`. TUN write is datagram-atomic.
                // Returned count is kernel write count, NOT `+10`
                // (stats want "bytes to kernel").
                let n = write_fd(self.fd.as_raw_fd(), &buf[10..])?;
                Ok(n)
            }

            // ─── TAP
            // C `:198-204`. Direct write.
            Mode::Tap => write_fd(self.fd.as_raw_fd(), buf),
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

    /// vnet_hdr drain. Overrides the default `read()`-loop only
    /// when `IFF_VNET_HDR` is on; otherwise delegates.
    ///
    /// Read shape with vnet_hdr (`tun_put_user`, `tun.c:2064`):
    /// `[virtio_net_hdr(10)][raw IP packet (≤65535)]`. NO tun_pi
    /// (`IFF_NO_PI` set), NO eth header (TUN mode). One read = one
    /// skb. For `gso_type==TCPV4/6`, the IP packet is a super-
    /// segment (`totlen > MTU`).
    ///
    /// `gso_type==NONE` (the common case for non-TCP, ARP, ICMP,
    /// short TCP): strip the vnet_hdr, complete partial csum if
    /// `NEEDS_CSUM`, synthesize eth header, return as single
    /// `Frames{count: 1}`. Same wire result as the non-vnet path.
    ///
    /// `gso_type==TCPV4/6`: strip vnet_hdr, return `Super{..}`.
    /// The daemon calls `tso_split` on the contiguous buffer.
    fn drain(&mut self, arena: &mut DeviceArena, cap: usize) -> io::Result<DrainResult> {
        if !self.vnet_hdr {
            // Non-vnet path: the default `read()`-in-a-loop. The
            // explicit body (instead of calling some `default_drain`
            // helper) is intentional: the trait default IS the
            // shared code, but we can't call it from an override.
            // This is the same loop, copied. Low-risk: it's been
            // exercised by every test since Phase 0.
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

        // ─── vnet_hdr path ───────────────────────────────────
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

// read/write — direct syscalls, not File::read

// Direct `libc::read`/`write` instead of `File::read`: TUN is a
// datagram device (one read = one packet, no retry on short read).
// `File::read` is correct (thin `read(2)` wrapper) but doesn't
// document the datagram semantics. The syscall IS the documentation.

/// `read(2)` on the TUN fd. Datagram semantics: one read = one
/// packet, atomic. Kernel-side `tun_chr_read_iter` dequeues one
/// `skb`, copies, returns. Never short except on truncation
/// (packet > buf, then `len` returned but only `buf.len()` copied
/// — that's `MSG_TRUNC` semantics without the flag).
#[allow(unsafe_code)]
fn read_fd(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY:
    //   - `fd` is a valid open fd (the `Tun` struct owns the
    //     `File`; `File`'s drop closes; we're called from `&mut
    //     Tun` so the `File` is alive).
    //   - `buf.as_mut_ptr()` points to `buf.len()` writable bytes.
    //     The slice borrow is exclusive (`&mut`); no aliasing.
    //   - Kernel writes at most `buf.len()` bytes (the third arg
    //     is the cap).
    //   - Thread-safety: `read(2)` is atomic per call. Concurrent
    //     reads on the same fd would each get a packet (kernel
    //     locks the queue). We're `&mut self`, so no concurrent
    //     calls from Rust. (Another process with a dup'd fd could
    //     race; not our problem.)
    let ret = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    // `ret` is `isize` (`ssize_t`). Non-negative; `as usize` is
    // value-preserving.
    #[allow(clippy::cast_sign_loss)]
    Ok(ret as usize)
}

/// `write(2)` on the TUN fd. Datagram: one write = one packet.
/// Kernel `tun_chr_write_iter` allocs an `skb`, copies, queues.
/// Atomic; never short (`EFAULT` on bad pointer, `EINVAL` on too-
/// large; whole-packet or error).
#[allow(unsafe_code)]
fn write_fd(fd: RawFd, buf: &[u8]) -> io::Result<usize> {
    // SAFETY: same as `read_fd`, but the kernel READS from us.
    //   - `buf.as_ptr()` points to `buf.len()` readable bytes.
    //   - Kernel reads exactly `buf.len()` (third arg).
    //   - No mutation; `&[u8]` is correct.
    let ret = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    #[allow(clippy::cast_sign_loss)]
    Ok(ret as usize)
}

// Tests — what we CAN test without CAP_NET_ADMIN

#[cfg(test)]
mod tests {
    use super::*;

    /// `DEFAULT_DEVICE` matches C. sed-verifiable: `sed -n '24p'
    /// src/linux/device.c` → `#define DEFAULT_DEVICE "/dev/net/tun"`.
    #[test]
    fn default_device_matches_c() {
        assert_eq!(DEFAULT_DEVICE, "/dev/net/tun");
    }

    /// `IFF_TUN`/`IFF_TAP`/`IFF_NO_PI` from libc match the kernel
    /// header values. Smoke-verified via gcc earlier; pin them so
    /// libc upgrade noise gets caught.
    ///
    /// These are kernel ABI constants — they CAN'T change. The
    /// test pins our DEPENDENCY on libc having them right.
    #[test]
    fn iff_flags_match_kernel() {
        // From `cat > /tmp/iff.c ... gcc /tmp/iff.c && /tmp/iff`:
        //   IFF_TUN = 0x1, IFF_TAP = 0x2, IFF_NO_PI = 0x1000
        assert_eq!(libc::IFF_TUN, 0x1);
        assert_eq!(libc::IFF_TAP, 0x2);
        assert_eq!(libc::IFF_NO_PI, 0x1000);
    }

    /// `TUNSETIFF` ioctl number. Kernel ABI; can't change.
    /// Smoke-verified `0x400454ca` from gcc.
    #[test]
    fn tunsetiff_value() {
        // libc::TUNSETIFF type is `Ioctl` which is `c_ulong` on
        // Linux; the cast normalizes for assert.
        // `libc::TUNSETIFF` is `c_ulong` on Linux (= `u64` on
        // x86_64). `u64::from` is a no-op there. The cast
        // documents the intent (compare as u64) but clippy
        // catches the no-op. Direct compare; the literal type
        // suffix matches.
        #[allow(clippy::unreadable_literal)]
        let want: libc::c_ulong = 0x400454ca;
        assert_eq!(libc::TUNSETIFF, want);
    }

    /// `SIOCGIFHWADDR` ioctl number. Smoke-verified `0x8927`.
    #[test]
    fn siocgifhwaddr_value() {
        assert_eq!(libc::SIOCGIFHWADDR, 0x8927);
    }

    /// `libc::ifreq` is 40 bytes. Smoke-verified both via gcc
    /// `sizeof(struct ifreq)` AND via the `/tmp/smoke_ifreq`
    /// crate. The kernel and libc must agree; pin our dependency.
    #[test]
    fn ifreq_size_40() {
        assert_eq!(std::mem::size_of::<libc::ifreq>(), 40);
    }

    /// `IFNAMSIZ = 16`. The `ifr_name` buffer length. Kernel ABI.
    #[test]
    fn ifnamsiz_16() {
        assert_eq!(libc::IFNAMSIZ, 16);
    }

    /// Tun mode flags match C `device.c:78`: `ifr.ifr_flags =
    /// IFF_TUN`. JUST IFF_TUN, no IFF_NO_PI — we want the tun_pi
    /// prefix for the ethertype-slot trick.
    ///
    /// Tap mode flags match `:86`: `IFF_TAP | IFF_NO_PI`. Don't
    /// want tun_pi, do want raw ethernet.
    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn mode_flags_match_c() {
        // The flags computation from `Tun::open`, factored as a
        // local fn for testability. (The actual `open` inlines
        // it; this is the test seam.)
        // `match` as expression: parens for the `as` cast.
        let flags_for = |mode: Mode| -> i16 {
            (match mode {
                Mode::Tun => libc::IFF_TUN,
                Mode::Tap => libc::IFF_TAP | libc::IFF_NO_PI,
            }) as i16
        };
        assert_eq!(flags_for(Mode::Tun), 0x1);
        assert_eq!(flags_for(Mode::Tap), 0x1002);
    }

    // pack_ifr_name — the testable seam

    /// Ok-path: `None` → all zeros (C `if(iface)` guard skips the
    /// strncpy; kernel picks). `Some` → packed, NUL-padded (C
    /// `strncpy` zero-fills the rest). The boundary: `< IFNAMSIZ`
    /// accepts 15, rejects 16. `as u8` cast for x86_64-vs-aarch64
    /// c_char signedness; values are ASCII either way.
    #[test]
    #[allow(clippy::cast_sign_loss)]
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

    /// `TUNSETOFFLOAD` ioctl number. `_IOW('T', 208, unsigned int)`.
    /// Computed: `(1<<30)|(4<<16)|('T'<<8)|208 = 0x400454d0`.
    /// Not in libc; pin our local constant.
    #[test]
    fn tunsetoffload_value() {
        let want: libc::c_ulong = 0x4004_54d0;
        assert_eq!(TUNSETOFFLOAD, want);
    }

    /// `TUN_F_*` flags. `if_tun.h:88-90`. Kernel ABI; can't change.
    #[test]
    fn tun_f_flags_match_kernel() {
        assert_eq!(TUN_F_CSUM, 0x01);
        assert_eq!(TUN_F_TSO4, 0x02);
        assert_eq!(TUN_F_TSO6, 0x04);
    }

    /// `IFF_VNET_HDR` from libc matches `if_tun.h:75`.
    #[test]
    fn iff_vnet_hdr_value() {
        assert_eq!(libc::IFF_VNET_HDR, 0x4000);
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

    /// `Tun::open` with valid config but no CAP_NET_ADMIN → some
    /// `Err` (EACCES on open, or ENOENT if /dev/net/tun missing).
    /// NOT InvalidInput — the validation passed, the syscall
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

    // The +10 offset trick — testable without a TUN device

    /// The TUN-mode "+10" offset. `14 (ethernet header) - 4 (tun_
    /// pi)`. The arithmetic is the documentation; pin it.
    ///
    /// `tun_pi { u16 flags; be16 proto }` = 4 bytes.
    /// `ether_header { u8 dhost[6]; u8 shost[6]; u16 type }` = 14.
    /// Reading at +10 puts `tun_pi.proto` at byte 12, which is
    /// `ether_header.type` from byte 0. Same field, different
    /// name.
    #[test]
    fn tun_offset_arithmetic() {
        const TUN_PI: usize = 4;
        const ETHER_HEADER: usize = 14;
        const ETHERTYPE_OFFSET: usize = 12; // dhost(6) + shost(6)
        assert_eq!(ETHER_HEADER - TUN_PI, 10);
        // Reading at +10 means byte 0 of read is byte 10 of buf.
        // tun_pi.proto is at byte 2 of read (after flags).
        // 10 + 2 = 12 = ethertype slot.
        assert_eq!(10 + 2, ETHERTYPE_OFFSET);
    }

    /// The TUN-mode memset bound. `memset(DATA, 0, 12)` zeroes
    /// dhost(6) + shost(6) but NOT ethertype(2). The C wants to
    /// keep ethertype (it's the kernel-provided `tun_pi.proto`).
    /// Zeroing 12, not 14, is the keep.
    #[test]
    fn tun_memset_bound() {
        // Dhost + shost, NOT ethertype.
        assert_eq!(12, 6 + 6);
        // If it were 14, we'd zero ethertype too. Bad.
    }
}
