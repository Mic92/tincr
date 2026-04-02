//! TUN/TAP device — `linux/device.c` (225 LOC, branch 1.1, NOT the
//! async-pool side branch `cc5e809b`).
//!
//! ──────────── The interface ────────────────────────────────────────
//!
//! C: `devops_t` (`device.h:32-40`) is a vtable of fn pointers.
//! Seven backends in C (`os_devops`, `dummy_devops`, `raw_socket`,
//! `multicast`, `fd`, `uml`, `vde`); five behind `#ifdef`. The
//! daemon picks one at startup (`net_setup.c:1061-1091`) by string-
//! matching the `DeviceType` config var, never changes it.
//!
//! Rust: a trait. The dispatch is monomorphized at the choose-once
//! site (the daemon stores `Box<dyn Device>`; the read/write hot
//! path goes through one vtable indirection, same as the C fn
//! pointer). The C `devops` global becomes the daemon's owned `Box`.
//!
//! `setup`/`close` are NOT trait methods. C `setup` is a constructor
//! (reads config, opens fd, ioctls, returns bool); Rust does that as
//! `Tun::open(&DeviceConfig) -> io::Result<Tun>`. C `close` is a
//! destructor; Rust `Drop`. `enable`/`disable` (`device.h:37-38`)
//! are optional in C (only `multicast_device.c` and Windows set
//! them), NULL on Linux; we don't model them yet.
//!
//! ──────────── The TUN-mode offset trick ────────────────────────────
//!
//! `linux/device.c:148-167` (TUN read):
//!
//! ```c
//!   inlen = read(device_fd, DATA(packet) + 10, MTU - 10);
//!   memset(DATA(packet), 0, 12);
//!   packet->len = inlen + 10;
//! ```
//!
//! `DATA(packet)` is `data + offset` where `offset = 12` (`net.h:95`,
//! `DEFAULT_PACKET_OFFSET`). The read goes to byte 22 of the buffer.
//! What the kernel writes there:
//!
//! ```text
//!   bytes 22-23:  tun_pi.flags (u16, always 0 from kernel rx path)
//!   bytes 24-25:  tun_pi.proto (be16, the ethertype: 0x0800=IPv4,
//!                               0x86dd=IPv6, etc — kernel writes
//!                               this in NETWORK byte order)
//!   bytes 26..:   the IP packet
//! ```
//!
//! Then `memset(DATA, 0, 12)` zeroes bytes 12-23. After:
//!
//! ```text
//!   12-17  dst MAC      = 00:00:00:00:00:00  (memset)
//!   18-23  src MAC      = 00:00:00:00:00:00  (memset, OVERWRITES tun_pi.flags)
//!   24-25  ethertype    = tun_pi.proto       (kernel wrote, we kept)
//!   26..   payload      = IP packet
//! ```
//!
//! This is a synthetic ethernet frame. `route.c` looks at bytes
//! 24-25 (the ethertype slot) to decide IPv4/IPv6/ARP. The TUN
//! kernel driver gave us exactly that field, just under a different
//! name. The layout pun avoids reformatting: we don't unpack `tun_
//! pi`, decide ethertype, then repack — we read into the right slot
//! and zero around it. The "+10" is `14 (ethernet header) - 4 (tun_
//! pi)`: where to start the read so `tun_pi.proto` lands on the
//! ethertype slot.
//!
//! TAP mode (`:170-179`) doesn't need this — the kernel hands us a
//! real ethernet frame, MACs and all. `IFF_NO_PI` skips the `tun_
//! pi` prefix. Read at `DATA(packet)` directly, no memset.
//!
//! Write path (`:188-211`) is the inverse. TUN: `DATA[10] = DATA[11]
//! = 0` (zero `tun_pi.flags`; ethertype was already in slot 12-13
//! relative to `DATA+10`, i.e. bytes 24-25, set by `route.c`), write
//! from `DATA+10`. TAP: write `DATA` directly.
//!
//! ──────────── What we DON'T port ───────────────────────────────────
//!
//! The C `setup_device` reads `config_tree` (`Device`, `Interface`,
//! `DeviceType`, `IffOneQueue`) and `routing_mode`, writes `mymac`
//! and `overwrite_mac` globals. We take those as `DeviceConfig`
//! struct args, return `mymac` as part of `Self`. The config-tree
//! reads are the daemon's job (`tinc-conf` already has the parser).
//! The `routing_mode == RMODE_ROUTER` test is just "am I in TUN or
//! TAP mode" with extra steps — we let the caller pass `Mode`.
//!
//! `IFF_ONE_QUEUE`: kernel commit `5d09710` (2.6.27, 2008) made it a
//! no-op (the flag is consumed but ignored). The C still sets it
//! (`device.c:93-98`, `IffOneQueue` config var). We DON'T port:
//! dead kernel code path. Third deliberate C-behavior-drop, but
//! "no-op anyway" is a weaker class than the readline-loop drops.
//!
//! `EBADFD` → `event_exit()` (`:155-157`, commit `d73cdee5` "Avoid
//! infinite loop on EBADFD"): on `systemctl restart networking` the
//! TUN fd goes bad mid-run. C exits the event loop. We surface the
//! error with `kind() == FdInBadState` (or `Other` with `EBADFD`,
//! whichever maps); the daemon's read loop checks for it and decides.
//! The POLICY (exit) belongs in the daemon, not here.
//!
//! ──────────── Slice API, not packet struct ─────────────────────────
//!
//! C `read_packet`/`write_packet` take `vpn_packet_t *` and reach
//! into `data[offset]`. The struct is the daemon's. We take `&mut
//! [u8]` (read) / `&[u8]` (write); the daemon does the offset math
//! and slices. The TUN-mode +10 is OUR concern (it's the kernel
//! interface); the +12 offset is the DAEMON's concern (it's the
//! `vpn_packet_t` layout). We get `&mut buf[offset..]`, write at
//! `[10..]`, zero `[0..12]`, return length. Daemon doesn't know
//! about `tun_pi`.
//!
//! ──────────── Platform ─────────────────────────────────────────────
//!
//! Linux only. The whole module is `#[cfg(target_os = "linux")]`;
//! the `Dummy` impl is unconditional (it's the test/CI device). BSD
//! `/dev/tun*`, macOS utun, Windows wintun: separate files, later.

#![deny(unsafe_code)]
#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]

use std::io;

// ═══════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════

/// `MTU` — `net.h:36` (the non-jumbo branch). 1500 payload + 14
/// ethernet header + 4 VLAN tag.
///
/// The jumbo branch (`net.h:34`, `ENABLE_JUMBOGRAMS`) uses 9018.
/// We don't gate it behind a feature: it's just a buffer-size
/// constant, and the daemon's `vpn_packet_t` will pick which to
/// use. The device crate only needs it for the read-buffer length
/// CHECK (asserting the slice is big enough); we use the larger
/// value so the check passes for either daemon config.
///
/// `pub` because the daemon's `MAXSIZE` arithmetic includes it.
pub const MTU: usize = 1518;

/// `MTU` for the jumbo build. The daemon picks; we accept either.
pub const MTU_JUMBO: usize = 9018;

/// L2 vs L3 device. C `device_type_t` (`linux/device.c:33-36`).
///
/// TUN: kernel hands us IP packets prefixed with `tun_pi`. We
///      synthesize fake ethernet headers (the +10 offset trick).
///      Chosen when `routing_mode == RMODE_ROUTER` (the daemon
///      routes by IP, doesn't need real L2).
///
/// TAP: kernel hands us full ethernet frames, MACs and all. No
///      synthesis. Chosen for `RMODE_SWITCH`/`RMODE_HUB` (the
///      daemon switches by MAC, needs real L2).
///
/// The C also lets `DeviceType = tun` / `tap` config override the
/// routing-mode default (`device.c:71-89`). The daemon resolves
/// that; we just get the resolved `Mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Layer-3 (IP). `IFF_TUN`, `tun_pi` prefix, +10 offset.
    Tun,
    /// Layer-2 (Ethernet). `IFF_TAP | IFF_NO_PI`, raw frames.
    Tap,
}

/// MAC address. C `mac_t` is just `uint8_t x[6]` (somewhere in
/// `subnet.h` or `ethernet.h`). For TAP mode we read the kernel-
/// assigned MAC via `SIOCGIFHWADDR` (`device.c:121-126`); the
/// daemon stores it as `mymac` and `route.c` uses it for ARP
/// replies.
///
/// For TUN mode the C leaves `mymac` at its zero-initialized
/// default; `route.c`'s ARP path checks `routing_mode` first and
/// never reads `mymac` in router mode. We `Option` it: `None` for
/// TUN (semantically "no MAC, this is L3"), `Some` for TAP.
pub type Mac = [u8; 6];

/// What the daemon needs to open a device. C reads these from
/// `config_tree` (`get_config_string`); we take them as plain
/// args. The config-tree-to-this mapping is the daemon's job.
///
/// All `Option`: every field has a default in C.
///
/// `clippy::struct_excessive_bools`: doesn't fire (no bools).
#[derive(Debug, Default)]
pub struct DeviceConfig {
    /// `Device` config var. C default: `/dev/net/tun` (`linux/
    /// device.c:24`). `None` → we default the same.
    ///
    /// Why not bake the default? Some test setups bind-mount
    /// `/dev/net/tun` elsewhere. The C lets you override; we
    /// match. The default lives next to the consumer (the open
    /// fn), not here.
    pub device: Option<String>,

    /// `Interface` config var. C default: `netname` if set, else
    /// kernel picks (`device.c:50-52`). The kernel-picks case:
    /// `ifr.ifr_name` left as zeros, kernel writes back `tun0`,
    /// `tun1`, etc — first free.
    ///
    /// `None` here means "let kernel pick" — the netname-default
    /// is the daemon's job (it has `netname`, we don't).
    pub iface: Option<String>,

    /// Resolved mode. The C derives this from `DeviceType` config
    /// var + `routing_mode` (`device.c:77-89`). The daemon does that
    /// derivation; we get the result.
    ///
    /// NOT `Option` — the daemon must decide. There's no kernel
    /// default; an unset `ifr_flags` means neither TUN nor TAP,
    /// which the kernel rejects (`EINVAL` on `TUNSETIFF`).
    pub mode: Mode,
}

impl Default for Mode {
    /// `RMODE_ROUTER` is the daemon default (`route.c`); router
    /// mode picks TUN. So TUN is our default. The `DeviceConfig::
    /// default()` builder needs a value; this is it.
    fn default() -> Self {
        Mode::Tun
    }
}

/// What `read` does after a successful kernel `read()`. The error
/// case is `io::Error`; the OK case carries the byte count AND
/// the `EBADFD` advisory (which the C handles by `event_exit()`,
/// `device.c:155-157`).
///
/// Why not `io::Error` for `EBADFD`: it IS an `io::Error`. But
/// `io::ErrorKind` doesn't have `FdInBadState` (the closest is
/// `Other`). `raw_os_error() == Some(libc::EBADFD)` works but
/// pushes a Linux-specific check into the daemon. We model it
/// here: the daemon checks `Read::Gone`, not errno.
///
/// ACTUALLY: simpler. `EBADFD` is an error, not a partial-success.
/// The C `read()` returns `-1` with `errno == EBADFD`; that's an
/// `Err`. The daemon's read loop already handles `Err` (logs,
/// backs off, eventually exits — `net_packet.c:1930-1937`). The
/// `EBADFD`-specific `event_exit()` is just "skip the backoff,
/// exit immediately" — an optimization on the error path. We
/// surface it as a regular `io::Error`; daemon checks `raw_os_
/// error()` if it wants to fast-path. The error already CARRIES
/// the errno; we don't need a separate signal.
///
/// So: `Result<usize, io::Error>`. Same as `Read::read`. No new
/// type. (Kept the doc above for the archaeology — future-you
/// reading the daemon's `EBADFD` check wants to know why it's
/// not modeled here.)
const _: () = ();

// ═══════════════════════════════════════════════════════════════════
// Trait
// ═══════════════════════════════════════════════════════════════════

/// `devops_t` — the read/write vtable. `device.h:32-40`.
///
/// C has `setup`/`close` in the vtable too. We don't: `setup`
/// is a constructor (`Tun::open`), `close` is `Drop`. The C vtable
/// pattern is "stateless fn pointers + globals"; the Rust pattern
/// is "stateful struct + trait methods". The fn-pointer-shape
/// `setup`/`close` don't survive the translation.
///
/// `Send`: the daemon's event loop is single-threaded but the
/// daemon might be `tokio` later; constraining now is free. The
/// Linux fd is `Send` (it's just an int).
///
/// NOT `Sync`: `read`/`write` take `&mut self`. The fd itself is
/// fine to share (the kernel serializes), but the `BufReader`-
/// shaped state we might add later wouldn't be. `&mut` is honest.
pub trait Device: Send {
    /// Read a packet. C `devops.read(packet)` → bool (`device.h:
    /// 35`); we return `Result<usize>` (the bool was "false on
    /// error, true sets packet->len"; we return the len).
    ///
    /// `buf` is the daemon's `data[offset..]` slice. For TUN mode
    /// we write at `buf[10..]` (kernel) then zero `buf[0..12]` (us);
    /// the returned length is `kernel_len + 10`. For TAP mode we
    /// write at `buf[0..]`, return the kernel length unchanged.
    ///
    /// The slice MUST be at least `MTU` long for TAP, `MTU` for TUN
    /// too (the `+10` is into the buffer, not past it: `read(fd,
    /// buf+10, MTU-10)` writes at most `MTU-10` bytes, fitting in
    /// `buf[10..MTU]`). The daemon's `data[MAXSIZE]` is 1673 bytes
    /// (`net.h:42`), comfortably more.
    ///
    /// `<= 0` from kernel `read()` → `Err`. C `device.c:149`: `if
    /// (inlen <= 0)`. Zero is EOF (TUN: never, the device doesn't
    /// EOF; but defensive); negative is errno. Both are errors.
    ///
    /// # Errors
    /// `io::Error` from `read(2)`. `EAGAIN` for `O_NONBLOCK` with
    /// no packet ready (the daemon's poll loop should only call
    /// us when readable, but races happen). `EBADFD` for "TUN
    /// device went away" (commit `d73cdee5`: network restart).
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>;

    /// Write a packet. C `devops.write(packet)` → bool (`device.h:
    /// 36`).
    ///
    /// `buf` is the daemon's `data[offset..offset+len]` slice. For
    /// TUN mode we zero `buf[10..12]` (the `tun_pi.flags` slot)
    /// then write `buf[10..]`; for TAP we write `buf` directly.
    ///
    /// The TUN zero MUTATES `buf`. C does this too (`device.c:
    /// 188`: `DATA(packet)[10] = DATA(packet)[11] = 0`). The
    /// daemon doesn't care — those bytes were the synthetic
    /// ethernet header's src-MAC byte 4-5, which are zero anyway
    /// from the read path's memset. The mutation is idempotent
    /// on read-then-write packets, only matters for daemon-
    /// originated packets (ICMP replies, ARP replies) where
    /// `route.c` builds the frame from scratch — and there, those
    /// bytes are also zero (synthetic MAC).
    ///
    /// HENCE `&mut [u8]` not `&[u8]`. The C signature is `vpn_
    /// packet_t *` (mutable); we match. Honest about the mutation.
    ///
    /// # Errors
    /// `io::Error` from `write(2)`. `ENOBUFS` if the kernel TX
    /// queue is full (TAP only, TUN doesn't queue at the device
    /// layer). The C logs and returns false; daemon drops the
    /// packet. We return `Err`; daemon does the same.
    fn write(&mut self, buf: &mut [u8]) -> io::Result<usize>;

    /// `device_type` for the daemon's logging + branching. The
    /// C stores it as a static (`device_type` global, `:35`); we
    /// make it a method. The `route.c` fast path doesn't check
    /// this (it branches on `routing_mode`, which the daemon
    /// already knows); only slow-path logging does.
    fn mode(&self) -> Mode;

    /// `iface` — the kernel-chosen interface name. C: `iface`
    /// global (`:41`), set post-TUNSETIFF from `ifr.ifr_name`.
    /// The daemon needs it to spawn `tinc-up` with `INTERFACE=
    /// $iface` in the script env (`script.c`).
    ///
    /// `&str` not `String`: borrowed from `Self`, daemon copies
    /// once at startup.
    fn iface(&self) -> &str;

    /// `mymac` — for TAP only. C: `mymac` global, set post-
    /// `SIOCGIFHWADDR` (`:121-126`). For TUN: `None` (no MAC,
    /// this is L3). The daemon's `route.c` ARP path needs it;
    /// the IP path doesn't.
    fn mac(&self) -> Option<Mac>;

    /// Raw fd, for the daemon's `mio::Poll::register`. C: `device_
    /// fd` global (`:39`), `net_setup.c:1099` does `io_add(device_
    /// fd, IO_READ)`.
    ///
    /// `Dummy` returns `None` (no fd to poll; the daemon skips
    /// the register).
    fn fd(&self) -> Option<std::os::unix::io::RawFd>;
}

// ═══════════════════════════════════════════════════════════════════
// Dummy — `dummy_device.c` (58 LOC)
// ═══════════════════════════════════════════════════════════════════

/// `dummy_devops` (`dummy_device.c:53-58`). Read fails, write
/// succeeds. The daemon's poll loop never calls `read` (no fd to
/// poll); `write` is called from the route path and just drops.
///
/// C use case: `DeviceType = dummy` in config → daemon runs as a
/// pure relay (forwards between peers, never touches a kernel
/// device). Integration tests use this to avoid needing CAP_NET_
/// ADMIN.
///
/// Our use case: same + unit tests for the daemon's route path
/// without root.
#[derive(Debug, Default)]
pub struct Dummy;

impl Device for Dummy {
    /// C `dummy_device.c:43-46`: `(void)packet; return false;`.
    /// `read()` failing means "no packet"; the daemon's poll loop
    /// would back off and retry (`net_packet.c:1930`). Except the
    /// poll loop never calls us (no fd → no readable event).
    ///
    /// `WouldBlock`: closest semantic. The C `false` is ambiguous
    /// (error vs no-packet); the daemon treats it as "log + back
    /// off." `WouldBlock` is "no packet, try later" — the back-
    /// off without the log.
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::ErrorKind::WouldBlock.into())
    }

    /// C `dummy_device.c:48-51`: `(void)packet; return true;`.
    /// Silent drop. We return the slice length (the daemon's
    /// stats counters add it as "bytes written"; for dummy that's
    /// "bytes that WOULD have gone to the kernel"). The C doesn't
    /// distinguish; `write_packet` returning true is enough.
    fn write(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        Ok(buf.len())
    }

    /// Arbitrary. The C dummy doesn't set `device_type` (no TUN/
    /// TAP distinction when there's no kernel). The daemon's
    /// `route.c` branches on `routing_mode`, not this; doesn't
    /// matter. TUN because it's the default.
    fn mode(&self) -> Mode {
        Mode::Tun
    }

    /// C `dummy_device.c:31`: `iface = xstrdup(DEVICE_DUMMY)` =
    /// `"dummy"`. The daemon's `tinc-up` script gets `INTERFACE=
    /// dummy`; the script presumably checks for it and skips `ip
    /// addr add`.
    ///
    /// `clippy::unnecessary_literal_bound`: clippy wants `'static`
    /// since the string IS static. But the trait signature says
    /// `&str` (borrowed from `&self`), and `Tun::iface` returns
    /// `&self.iface` (NOT static). The trait constrains; this
    /// impl can't widen to `'static` without diverging from the
    /// trait. The lint is wrong about trait impls.
    #[allow(clippy::unnecessary_literal_bound)]
    fn iface(&self) -> &str {
        "dummy"
    }

    /// No MAC. C dummy doesn't touch `mymac` (stays zero). `None`
    /// is more honest than `Some([0; 6])` (which is a valid if
    /// weird MAC).
    fn mac(&self) -> Option<Mac> {
        None
    }

    /// No fd. C `dummy_device.c` doesn't set `device_fd` (stays
    /// -1). `net_setup.c:1099`: `if(device_fd >= 0) io_add(...)`.
    /// The -1 sentinel is `None` here.
    fn fd(&self) -> Option<std::os::unix::io::RawFd> {
        None
    }
}

// ═══════════════════════════════════════════════════════════════════
// Linux TUN/TAP — `linux/device.c` (225 LOC)
// ═══════════════════════════════════════════════════════════════════

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::Tun;

// ═══════════════════════════════════════════════════════════════════
// Tests — Dummy only (Tun needs CAP_NET_ADMIN, separate integration)
// ═══════════════════════════════════════════════════════════════════

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
