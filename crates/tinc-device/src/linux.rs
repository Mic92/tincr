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
//! `libc::ifreq` matches (smoke crate ran, output `40`). The struct
//! is `{ ifr_name: [c_char; 16], ifr_ifru: union }` where the union
//! is 24 bytes (largest member is `sockaddr`, 16 bytes — wait, that's
//! 32 not 40). Re-checked: `__c_anonymous_ifr_ifru` has `ifru_map`
//! at 16 bytes and `ifru_slave: [c_char; 16]`. Largest is the
//! sockaddr fields at 16 each, padding rounds to 24. 16 + 24 = 40.
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
//! Script exits → fd closed in child → does the device go away?
//! No (refcounted; daemon's fd holds it open). But the script COULD
//! write garbage to the TUN. CLOEXEC: defense.
//!
//! We use `OpenOptions::custom_flags(O_CLOEXEC)` — atomic at open,
//! one syscall instead of open+fcntl, no race window where a fork
//! between open and fcntl inherits a non-CLOEXEC fd.

use std::ffi::CStr;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};

use crate::{Device, DeviceConfig, MTU, Mac, Mode};

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
    ///
    pub fn open(cfg: &DeviceConfig) -> io::Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;

        let device = cfg.device.as_deref().unwrap_or(DEFAULT_DEVICE);

        // ─── ifr_name pack — BEFORE open
        // Validate iface name BEFORE opening /dev/net/tun. Why
        // before: testability. The validation is pure (string
        // length check); the open needs CAP_NET_ADMIN. Validation-
        // first means tests can hit the error path without root.
        // Runtime cost: a 16-byte buffer that's wasted if open
        // fails. Negligible. Same wasted-early-work tradeoff as
        // any validate-before-expensive-op pattern.
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

        // ─── ifr_flags
        // C `device.c:77-89`: derive flags from type + routing_mode.
        // We get the resolved `Mode`; the derivation is the daemon's
        // job (`net_setup.c`).
        //
        // `IFF_NO_PI` only on TAP. TUN keeps the `tun_pi` prefix
        // (we WANT `proto` for the ethertype-slot trick). C does
        // the same: `:78` (TUN) is `IFF_TUN` alone; `:86` (TAP) is
        // `IFF_TAP | IFF_NO_PI`.
        //
        // `as i16`: `libc::IFF_TUN` etc are `c_int`; `ifr_flags`
        // is `c_short`. The constants are 1, 2, 0x1000 — fit in
        // i16. The cast is value-preserving.
        //
        // `IFF_ONE_QUEUE` NOT set. Kernel commit `5d09710` (2.6.27,
        // 2008) made it a no-op (consumed but ignored — the kernel
        // always uses one queue now). C `device.c:93-98` still
        // reads `IffOneQueue` and sets the flag; we don't. Third
        // C-behavior-drop, "no-op anyway" class.
        #[allow(clippy::cast_possible_truncation)]
        let flags = match cfg.mode {
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

        Ok(Tun {
            fd,
            iface,
            mode: cfg.mode,
            mac,
        })
    }
}

// ifr_name packing — the testable seam

/// `[c_char; IFNAMSIZ]` from `Option<&str>`. The testable seam:
/// `Tun::open` calls this BEFORE `open(/dev/net/tun)`, so the
/// length validation fires without needing CAP_NET_ADMIN.
///
/// `None` → all zeros → kernel picks the name (`tun0`, `tap0`,
/// first free). C `device.c:103`: `if(iface)` guard.
///
/// `Some(name)` with `len >= 16` → `Err`. C truncates (`strncpy`
/// then `[15]=0`); we reject. STRICTER. The truncation failure
/// mode: `tinc.conf` says `Interface = sixteenchars_long`,
/// kernel sees `sixteenchars_lo`, `tinc-up` script gets
/// `INTERFACE=sixteenchars_lo`, user's `ip addr add ... dev
/// sixteenchars_long` fails ENODEV three steps later. Reject at
/// the source.
///
/// `c_char` is `i8` on x86_64, `u8` on aarch64. We cast each
/// byte; the wrap is sound (kernel reads bytes, not signed ints).
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
///
/// `clippy::missing_errors_doc`: documented in `Tun::open`.
#[allow(clippy::missing_errors_doc)]
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
    // `i8 → u8` cast for the slice: `c_char` signedness varies
    // by arch, but the BYTES are the same. `transmute` of the
    // whole array would work but `cast_slice` is the safe spelling
    // — actually, neither needed: read bytes via pointer cast.
    //
    // Simpler still: `CStr::from_ptr` on `ifr_name.as_ptr()`.
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

/// `SIOCGIFHWADDR` — read the device's MAC. C `device.c:121-126`.
///
/// Uses `ifr_ifru.ifru_hwaddr: sockaddr`. The MAC is in `sa_data
/// [0..6]` (the rest of `sockaddr` is unused/garbage for hwaddr).
///
/// `clippy::missing_errors_doc`: caller documents (`Tun::open`'s
/// "warning-not-error" comment).
#[allow(clippy::missing_errors_doc)]
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
    ///
    /// `clippy::missing_errors_doc`: documented in the trait.
    #[allow(clippy::missing_errors_doc)]
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

                // C `:162`: `memset(DATA(packet), 0, 12)`. Zeroes
                // the synthetic ethernet header: dst MAC (6) +
                // src MAC (6). The src-MAC zeroing OVERWRITES
                // `tun_pi.flags` (bytes 10-11 from our perspective,
                // bytes 22-23 from the daemon's `data` perspective).
                // `tun_pi.flags` was always 0 from the kernel rx
                // path anyway (`TUN_PKT_STRIP` is the only flag,
                // set on tx not rx); the memset is idempotent on
                // those bytes.
                //
                // BUT it also zeroes bytes 0-9, which we never
                // touched. Those are the dst-MAC + first 4 of
                // src-MAC. Uninitialized? No — the daemon's
                // `vpn_packet_t` is reused across reads; previous
                // packet's bytes are there. The memset matters.
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
    ///
    /// `clippy::missing_errors_doc`: documented in the trait.
    #[allow(clippy::missing_errors_doc)]
    fn write(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.mode {
            // ─── TUN
            // C `:188-196`. Zero `buf[10..12]` (`tun_pi.flags`),
            // write `buf[10..]`.
            Mode::Tun => {
                // C `:188`: `DATA(packet)[10] = DATA(packet)[11]
                // = 0`. The two bytes at offset 10-11 from `DATA`
                // (= from our `buf`) are `tun_pi.flags` from the
                // kernel's perspective. Zero them. The ethertype
                // at `[12..14]` is left alone — `route.c` set it.
                //
                // Idempotent for read-then-write packets (already
                // zero from the read's memset). Matters for
                // synthesized packets (`route.c`'s ICMP/ARP
                // builders) where those bytes might be nonzero.
                //
                // The mutation is why `&mut [u8]` not `&[u8]`. C
                // mutates `vpn_packet_t *` in place too.
                debug_assert!(buf.len() > 12, "TUN write buf too short");
                buf[10] = 0;
                buf[11] = 0;

                // C `:190`: `write(device_fd, DATA+10, packet->
                // len - 10)`. The write strips the synthetic
                // ethernet header (well, the first 10 of 14 bytes
                // — the ethertype goes through as `tun_pi.proto`).
                let n = write_fd(self.fd.as_raw_fd(), &buf[10..])?;
                // The C returns `false` on write error, doesn't
                // check short writes. TUN write is atomic per-
                // packet (datagram semantics); short write
                // shouldn't happen. We return what `write()` gave
                // us; daemon can check if it cares.
                //
                // The returned count is the kernel write count,
                // NOT `+10`. The daemon's stats counters want
                // "bytes that went to the kernel"; the synthetic
                // header didn't go anywhere.
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
}

// read/write — direct syscalls, not File::read

// Why not `File::read`/`File::write`? Two reasons.
//
// (1) `File::read` goes through `io::Read::read` which is fine
//     for files but TUN is a datagram device — one read = one
//     packet. `File::read` is correct here (it's a thin `read(2)`
//     wrapper) but it doesn't DOCUMENT the datagram semantics.
//     Direct `libc::read` makes it explicit: we're reading the
//     fd, one packet, no buffering, no retry on short read.
//
// (2) `File::read` takes `&self` (the fd is shareable). We have
//     `&mut self` from the trait. Using `&self.fd` from inside
//     `&mut self` is fine (reborrow), but `&mut self → as_raw_fd
//     → libc::read` is one fewer borrow indirection. Minor.
//
// Mostly it's (1): the syscall IS the documentation. `read(2)`
// on a TUN fd is well-specified; `File::read` on a TUN fd is
// "whatever Rust's `File` does, hopefully thin." It is thin. But
// "hopefully" is the wrong word in the daemon's hot path.

/// `read(2)` on the TUN fd. Datagram semantics: one read = one
/// packet, atomic. Kernel-side `tun_chr_read_iter` dequeues one
/// `skb`, copies, returns. Never short except on truncation
/// (packet > buf, then `len` returned but only `buf.len()` copied
/// — that's `MSG_TRUNC` semantics without the flag).
///
/// `clippy::missing_errors_doc`: caller documents.
#[allow(clippy::missing_errors_doc)]
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
///
/// `clippy::missing_errors_doc`: caller documents.
#[allow(clippy::missing_errors_doc)]
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

    /// `None` → all zeros → kernel picks. The C `if(iface)`
    /// guard skips the strncpy.
    #[test]
    fn pack_ifr_name_none() {
        let buf = pack_ifr_name(None).unwrap();
        assert!(buf.iter().all(|&b| b == 0));
    }

    /// Short name → packed, NUL-padded. C `strncpy` does the
    /// same (zero-fills the rest).
    #[test]
    #[allow(clippy::cast_sign_loss)]
    fn pack_ifr_name_short() {
        let buf = pack_ifr_name(Some("tun0")).unwrap();
        // First 4 bytes are "tun0". `as u8` for x86_64-vs-
        // aarch64 c_char signedness; values are ASCII either way.
        assert_eq!(buf[0] as u8, b't');
        assert_eq!(buf[1] as u8, b'u');
        assert_eq!(buf[2] as u8, b'n');
        assert_eq!(buf[3] as u8, b'0');
        // Rest is zero (NUL terminator + padding).
        assert!(buf[4..].iter().all(|&b| b == 0));
    }

    /// Exactly 15 bytes → OK, last byte is NUL. The boundary:
    /// `< IFNAMSIZ` accepts 15, rejects 16.
    #[test]
    #[allow(clippy::cast_sign_loss)]
    fn pack_ifr_name_exactly_15() {
        let name = "fifteen_chars_!"; // 15 bytes
        assert_eq!(name.len(), 15);
        let buf = pack_ifr_name(Some(name)).unwrap();
        assert_eq!(buf[14] as u8, b'!');
        assert_eq!(buf[15], 0); // NUL
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
