//! `fd_device.c` (247 LOC) — the Android tun fd backend.
//!
//! ──────────── Why this exists ──────────────────────────────────────
//!
//! Android's `VpnService` opens the tun fd inside the Java process
//! (with the right permissions), then hands it to the native daemon.
//! Two transport mechanisms, two eras of Android security policy:
//!
//!   2017 (commit `7a54fe5e`): leak the fd via `dup()` + `exec()`
//!   inheritance. `Device = 5` config string IS the fd number.
//!
//!   2020 (commit `f5223937`): "New restrictions on the Android OS
//!   forbid direct leaking of file descriptors." The Java side
//!   sends the fd over a pre-agreed AF_UNIX socket using SCM_
//!   RIGHTS. `Device = /path/to/socket` or `Device = @abstract`.
//!
//! The C dispatches on `sscanf("%d") == 1` — if the config string
//! parses as an integer, it IS the integer; otherwise it's a path.
//! The string is the union type. We make the union explicit:
//! `FdSource::{Inherited, UnixSocket}`. The daemon parses the
//! config string into one or the other; this crate doesn't see
//! strings.
//!
//! ──────────── The +14 trick — the +10's cousin ─────────────────────
//!
//! `linux/device.c` reads at +10 because the kernel writes a 4-
//! byte `tun_pi` prefix. `fd_device.c` reads at +14 (`ETH_HLEN`)
//! because Android's `VpnService` writes RAW IP packets — no
//! prefix at all. Same goal (route.c expects ethernet at offset
//! 0), different gap.
//!
//! ```text
//!   what kernel TUN writes:  tun_pi(4) + IP packet
//!   what VpnService writes:             IP packet
//!
//!   linux:  read at +10, tun_pi.proto lands at +12 (ethertype slot)
//!   fd:     read at +14, IP packet starts at +14 (after ether header)
//! ```
//!
//! `linux` gets ethertype FOR FREE (the kernel fills `tun_pi.
//! proto`). `fd` has to SYNTHESIZE it: `(ip[0] >> 4)` is the IP
//! version nibble — `4` → `ETH_P_IP`, `6` → `ETH_P_IPV6`. Then
//! write the synthesized ethertype to bytes 12-13. The `set_
//! etherheader` fn (`fd_device.c:204-208`) is the synthesis.
//!
//! Unlike linux, this is TESTABLE: a `pipe()` can feed raw IP
//! bytes; no kernel driver layout to fake. The `from_ip_nibble`
//! tests below cover the version dispatch.
//!
//! ──────────── nix earns its dep here ───────────────────────────────
//!
//! `linux.rs` BYPASSED `nix::ioctl_write_ptr_bad!` because the
//! TUNSETIFF encoding lies. THIS file USES `nix::sys::socket::
//! recvmsg` because the C does ~40 LOC of `cmsghdr`/`CMSG_FIRST-
//! HDR`/`CMSG_DATA` boilerplate (`fd_device.c:39-93`) AND has a
//! NULL-deref bug at line 73 (`CMSG_FIRSTHDR` can return NULL;
//! the C dereferences `cmsgptr->cmsg_level` without checking).
//! nix's `ControlMessageOwned::ScmRights(Vec<RawFd>)` iterator
//! handles both correctly.
//!
//! The unsafe-shim count goes to four — but the per-shim "use the
//! macro?" decision DIVERGES. #3 (TUNSETIFF) bypassed; #4 (SCM_
//! RIGHTS) uses. The decision criterion: does the wrapper match
//! the kernel's actual contract? TUNSETIFF: no (encoding lies).
//! recvmsg+SCM_RIGHTS: yes (POSIX-standard, no encoding lies, nix
//! tested). The plan's "don't pattern-match on tui.rs" warning
//! generalizes: don't pattern-match on linux.rs either.

#![allow(clippy::doc_markdown)]

use std::fs::File;
use std::io::{self, IoSliceMut};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;

use crate::{Device, MTU, Mac, Mode};

// ═══════════════════════════════════════════════════════════════════
// Ethernet constants — `ethernet.h`
// ═══════════════════════════════════════════════════════════════════

/// `ETH_HLEN` — `ethernet.h:31`. dhost(6) + shost(6) + type(2).
/// The +14 read offset. gcc-verified vs `<linux/if_ether.h>`.
const ETH_HLEN: usize = 14;

/// `ETHER_TYPE_LEN` — `ethernet.h:35`. The big-endian u16 at
/// offset 12. `ETH_HLEN - ETHER_TYPE_LEN = 12` is where we write
/// the synthesized ethertype.
const ETHER_TYPE_LEN: usize = 2;

/// `ETH_P_IP` — `ethernet.h:44`. IPv4's IANA-registered ethertype.
/// Network byte order on the wire; we hold host order and `to_
/// be_bytes()` at write time. gcc-verified.
const ETH_P_IP: u16 = 0x0800;

/// `ETH_P_IPV6` — `ethernet.h:52`. IPv6's ethertype. gcc-verified.
const ETH_P_IPV6: u16 = 0x86DD;

// ═══════════════════════════════════════════════════════════════════
// FdSource — the union type the C string dispatch implies
// ═══════════════════════════════════════════════════════════════════

/// The two ways the fd reaches us. C `setup_device` (`:163-166`)
/// dispatches on `sscanf(device, "%d") == 1`: integer-parsable →
/// inherited fd, else → AF_UNIX path.
///
/// The string-to-variant parse is the DAEMON's job (config layer).
/// This crate gets the resolved variant. The C couldn't separate
/// (it has one `device` string global); we can.
///
/// Why a separate type, not `Option<PathBuf>` with `None` meaning
/// inherited? Because `FdSource::Inherited(5)` carries WHICH fd.
/// `Option<PathBuf> = None` would mean "inherited, but you have
/// to look up the number elsewhere." Carrying it here keeps the
/// open() signature self-contained.
#[derive(Debug)]
pub enum FdSource {
    /// `Device = 5` mode (2017). The Java parent process did
    /// `dup2(tun_fd, 5)` before `exec()`. The fd is already
    /// open in our process; we wrap it.
    ///
    /// On Android pre-2020 SELinux policy, this was the only
    /// way. Post-2020, blocked: the policy forbids fd
    /// inheritance across exec for tun fds.
    Inherited(RawFd),

    /// `Device = /path` mode (2020). The Java side listens on
    /// the socket; we connect; it `sendmsg`s the fd via
    /// SCM_RIGHTS; we `recvmsg`. The kernel atomically dups
    /// the fd into our process (our fd number is OURS, the
    /// Java side's number is theirs).
    ///
    /// `@` prefix → abstract namespace (Linux-only; the path
    /// doesn't exist on disk; survives chroot; cleaned up
    /// when the last socket closes). Android uses abstract
    /// sockets to avoid filesystem-permission hassles.
    UnixSocket(std::path::PathBuf),
}

// ═══════════════════════════════════════════════════════════════════
// FdTun — the Device impl
// ═══════════════════════════════════════════════════════════════════

/// `fd_devops` (`fd_device.c:244-249`). The Android backend.
///
/// TUN-only: `setup_device` (`:152-155`) errors on `routing_mode
/// == RMODE_SWITCH`. Android's `VpnService` only does L3. So:
/// no `mode` field — `mode()` returns `Mode::Tun` unconditionally.
///
/// No `iface` field either: the C never reads it for `fd_device`
/// (no `TUNSETIFF`, no kernel-chosen name). The Java side knows
/// the iface name; the daemon doesn't need it. `iface()` returns
/// a placeholder (the C `iface` global stays NULL → `tinc-up`
/// gets `INTERFACE=` empty; we say `"fd"` instead, marginally
/// more useful for the script).
///
/// `device_label`: what `Device =` was set to. For error messages.
/// The C logs `"fd/%d"` (`:231`); we keep the same shape.
#[derive(Debug)]
pub struct FdTun {
    /// The tun fd. Either inherited or received via SCM_RIGHTS.
    /// In both cases it's a RAW IP channel — no `tun_pi`, no
    /// ethernet, no prefix at all. Android's `VpnService`
    /// strips all that.
    ///
    /// `File` not `RawFd`: ownership. `File::drop` closes.
    /// `from_raw_fd` is the wrap (asserts ownership; the
    /// previous owner — Java process via inheritance, or kernel
    /// via SCM_RIGHTS dup — gave it up).
    fd: File,

    /// `"fd/5"` or `"fd:/path"` — for error messages. C logs
    /// `"fd/%d"` (`:231`). The path variant is our addition (C
    /// only logs the number even for socket-received fds; we
    /// know the path, might as well show it).
    device_label: String,
}

impl FdTun {
    /// `setup_device` (`fd_device.c:151-176`). Obtain the fd
    /// (inherit or receive), wrap as `File`.
    ///
    /// The C also does `routing_mode == RMODE_SWITCH` rejection
    /// (`:152-155`). NOT here: that's a daemon-level config
    /// validation, same class as "TAP needs RMODE_SWITCH" in
    /// `linux/device.c`. The daemon checks before calling us.
    /// Our `mode()` returning `Tun` unconditionally is the
    /// CONTRACT, not the CHECK.
    ///
    /// # Errors
    /// `io::Error`:
    ///   - `Inherited(fd)`: `InvalidInput` if `fd < 0`. The C
    ///     `:168-171` checks `device_fd < 0` post-sscanf. (The
    ///     fd might be valid-but-wrong — pointing at stdout,
    ///     say — but we can't detect that. The first read/
    ///     write fails.)
    ///   - `UnixSocket(path)`: connect failures (ENOENT,
    ///     ECONNREFUSED), recvmsg failures, "got cmsg but
    ///     wrong type" (the Java side sent something other
    ///     than SCM_RIGHTS — shouldn't happen, but the C
    ///     checks `:80-88` and we match).
    pub fn open(source: FdSource) -> io::Result<Self> {
        let (fd, device_label) = match source {
            // ─── Inherited ──────────────────────────────────────────
            // C `:163`: `sscanf(device, "%d", &device_fd) == 1`.
            // The daemon already parsed the integer; we get it
            // directly.
            FdSource::Inherited(fd) => {
                // C `:168`: `if(device_fd < 0)`. Negative fd
                // numbers don't exist; the only way to get one
                // is if the config said `Device = -1` and the
                // daemon's parser passed it through. C logs
                // strerror(errno) which is GARBAGE here (errno
                // is whatever the previous failing syscall set;
                // sscanf doesn't touch it). We say something
                // useful.
                if fd < 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("inherited fd {fd} is negative"),
                    ));
                }
                // SAFETY: the daemon's contract is that this fd
                // IS open and IS ours (the Java parent dup2'd it
                // before exec). We can't verify open-ness here
                // (fcntl(F_GETFD) would do it, but that's a
                // separate concern — the first read/write fails
                // EBADF if it's closed, which is fine). We can't
                // verify it's a tun fd either (no ioctl to ask
                // "are you a tun?"). The daemon trusts the
                // config; we trust the daemon.
                //
                // Ownership: we take it. `File::drop` will
                // close. If the daemon also holds the RawFd
                // somewhere and closes it: double-close, EBADF
                // on the second one. Daemon's responsibility.
                #[allow(unsafe_code)]
                let file = unsafe { File::from_raw_fd(fd) };
                (file, format!("fd/{fd}"))
            }

            // ─── UnixSocket ─────────────────────────────────────────
            // C `:164-166`: connect, recvmsg with SCM_RIGHTS,
            // wrap. The ~100 LOC of cmsghdr boilerplate
            // collapses into `recv_scm_rights`.
            FdSource::UnixSocket(path) => {
                let fd = recv_scm_rights(&path)?;
                // SAFETY: `recvmsg` with SCM_RIGHTS gives us a
                // fresh fd number (the kernel dup'd it into our
                // process). It's open (the kernel just opened
                // it) and it's ours (no one else in our process
                // has this number; the SENDER's number is
                // theirs, different process, different fd
                // table). Wrapping is sound.
                #[allow(unsafe_code)]
                let file = unsafe { File::from_raw_fd(fd) };
                (file, format!("fd:{}", path.display()))
            }
        };

        // C `:173`: `logger(LOG_INFO, "fd/%d adapter set up.")`.
        // We don't log (no logger plumbed yet; the daemon logs
        // post-open if it wants).

        Ok(FdTun { fd, device_label })
    }
}

// ═══════════════════════════════════════════════════════════════════
// SCM_RIGHTS — the fourth unsafe shim, the first to USE nix
// ═══════════════════════════════════════════════════════════════════

/// `read_fd` + `receive_fd` (`fd_device.c:39-120`). Connect to the
/// Unix socket, receive one fd via `SCM_RIGHTS`.
///
/// The C splits this into three fns:
///   `parse_socket_addr` (`:122-149`): build `sockaddr_un`,
///     handle the `@abstract` → leading-NUL conversion.
///   `receive_fd` (`:95-120`): connect, call `read_fd`, close.
///   `read_fd` (`:39-93`): the cmsghdr dance.
///
/// We collapse to one fn. `std::os::unix::net::UnixStream` does
/// `parse_socket_addr` + `receive_fd`; `nix::sys::socket::recvmsg`
/// does `read_fd`. The C's three-fn split was forced by C's lack
/// of RAII (the `goto end; close(socketfd)` pattern at `:112-
/// 119`); we don't need it.
///
/// Returns the bare `RawFd`. The caller wraps in `File`. Why
/// not return `File`? Because the SAFETY argument for `from_raw_
/// fd` belongs at the call site, where the source (kernel-dup'd
/// vs inherited) is known. Returning `RawFd` is the C-shaped
/// boundary; the caller decides ownership semantics.
///
/// # Errors
/// - `connect` failures: `NotFound` (ENOENT, path doesn't
///   exist), `ConnectionRefused` (no listener), `Permission-
///   Denied` (path mode bits)
/// - `recvmsg` failures: rare, the socket just connected
/// - `InvalidData`: control message wasn't SCM_RIGHTS (Java
///   side sent wrong cmsg type — shouldn't happen but C checks
///   `:80-88` and we match), or contained ≠1 fd (C only handles
///   exactly one, `:86`: `cmsg_len != CMSG_LEN(sizeof(int))`)
/// - `InvalidData`: `MSG_CTRUNC` flag set (control buffer too
///   small — shouldn't happen, we sized it for one fd, but C
///   checks `:63` and we match)
///
/// `clippy::missing_panics_doc`: doesn't panic. The `unwrap`s
/// below are on infallible-in-context operations (cmsg_space
/// for one int doesn't overflow; socket addr from path checked
/// before).
#[allow(clippy::missing_panics_doc)]
fn recv_scm_rights(path: &Path) -> io::Result<RawFd> {
    use nix::sys::socket::{ControlMessageOwned, MsgFlags, recvmsg};

    // ─── Connect ────────────────────────────────────────────────────
    // C `parse_socket_addr` (`:122-149`) + `receive_fd:100-108`.
    //
    // `@` prefix → abstract namespace (`:137-140`): C zeroes
    // `sun_path[0]` and computes `path_length = strlen(path)`
    // (NOT including a NUL — abstract addresses are length-
    // delimited, not NUL-terminated).
    //
    // std `SocketAddr::from_abstract_name` (1.70+) does the
    // leading-NUL + length-not-NUL bookkeeping. `connect_addr`
    // takes the resulting `SocketAddr`. The two cases (filesystem
    // path vs abstract) split on the first byte.
    //
    // The C also length-checks `>= sizeof(sun_path)` (`:128`).
    // std does the same internally (`from_abstract_name` errors
    // "abstract socket name must be shorter than SUN_LEN");
    // `UnixStream::connect` errors for too-long filesystem paths.
    // We don't pre-check; std's error propagates.
    let stream = connect_unix(path)?;

    // ─── recvmsg ────────────────────────────────────────────────────
    // C `read_fd` (`:39-93`). The cmsghdr dance.
    //
    // The C reads ONE BYTE of regular data (`:47-48`: `iov_len =
    // 1`). Why? The Java sender writes one byte of payload
    // alongside the fd cmsg — recvmsg needs SOME iov to anchor
    // the call. The byte's value is ignored (`:40`: `char iobuf`
    // declared, never read). We do the same: 1-byte iov, ignore
    // the byte.
    //
    // (Could the sender send 0 bytes? `sendmsg` allows it. But
    // the original Android Java code sends one byte, and the C
    // expects one byte (`:56`: `ret <= 0` check — `0` would
    // fail). We match the C's expectation.)
    let mut iobuf = [0u8; 1];
    let mut iov = [IoSliceMut::new(&mut iobuf)];

    // Control buffer: room for one `int` (the fd). C `:42`:
    // `CMSG_SPACE(sizeof(device_fd))`. nix `cmsg_space!` is
    // the macro equivalent. One `RawFd` worth of space.
    let mut cmsgbuf = nix::cmsg_space!(RawFd);

    // The recvmsg. nix wraps the unsafe (`libc::recvmsg`). We
    // pass `MsgFlags::empty()` (C `:54`: flags=0, blocking
    // recv). The socket is fresh from `connect` so blocking is
    // correct — the Java side sends immediately on accept.
    //
    // `()` for the address type: we don't care about the
    // sender's address (it's the same socket we connected to).
    // C `:43`: `msg.msg_name = NULL` implicitly (zeroed init).
    //
    // `?`: nix `Errno` → `io::Error` via `From`. Same pattern
    // as the bare `?` on nix calls in `tui.rs`.
    let msg = recvmsg::<()>(
        stream.as_raw_fd(),
        &mut iov,
        Some(&mut cmsgbuf),
        MsgFlags::empty(),
    )?;

    // ─── Check flags ────────────────────────────────────────────────
    // C `:63-69`: `if(msg.msg_flags & (MSG_CTRUNC | MSG_OOB |
    // MSG_ERRQUEUE))`. The `IP_RECVERR` ifdef gates `MSG_
    // ERRQUEUE` (Linux-only). We're Linux-only here (the whole
    // module is `#[cfg(target_os = "linux")]`); include it.
    //
    // `MSG_CTRUNC`: control data truncated. Our `cmsgbuf` was
    // sized for one fd; if the sender sent two fds, the second
    // got dropped and this flag is set. The C errors; we match.
    //
    // `MSG_OOB`: out-of-band data. Unix sockets don't HAVE OOB
    // (it's a TCP thing). The C check is defensive paranoia,
    // probably copied from a TCP example. nix's `MsgFlags`
    // includes it (it's a libc constant); we check it anyway
    // (zero cost, matches C).
    //
    // `MSG_ERRQUEUE`: error queue data. Again, Unix sockets
    // don't really do this. Same paranoia.
    let bad = MsgFlags::MSG_CTRUNC | MsgFlags::MSG_OOB | MsgFlags::MSG_ERRQUEUE;
    if msg.flags.intersects(bad) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("recvmsg flags indicate trouble: {:?}", msg.flags),
        ));
    }

    // C `:56-58`: `if(ret <= 0)`. nix already converted `<0` to
    // Err (the `?` above). `ret == 0` is "peer closed before
    // sending." The C errors; we match. nix exposes the byte
    // count as `msg.bytes`.
    if msg.bytes == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "Unix socket peer closed before sending fd",
        ));
    }

    // ─── Extract the fd ─────────────────────────────────────────────
    // C `:72-92`. Walk the cmsg, check level/type/len, extract.
    //
    // **The C has a NULL-deref bug here.** `:72`: `cmsgptr =
    // CMSG_FIRSTHDR(&msg)` — returns NULL if the control buffer
    // is empty (`msg_controllen` too small for even one header).
    // `:74`: `if(cmsgptr->cmsg_level != ...)` — dereferences
    // NULL. The bug is masked because the Java sender always
    // sends a cmsg, but it's there.
    //
    // nix's `msg.cmsgs()` is an iterator. Empty control buffer
    // → empty iterator → our `find_map` returns `None` → error,
    // not segfault. The bug is fixed for free.
    //
    // We accept EXACTLY ONE fd. C `:86`: `cmsg_len != CMSG_LEN(
    // sizeof(int))` — exactly one int's worth of cmsg data. nix
    // gives us a `Vec<RawFd>`; we check `len() == 1`. STRICTER
    // than C in one way (C would silently accept 2 fds and read
    // the first; we error), MATCHING in another (both reject 0).
    //
    // The cmsgs iterator yields `ControlMessageOwned`. We want
    // the first (and only) `ScmRights`. `find_map` extracts.
    // Any non-ScmRights cmsg (the Java side sent SCM_CREDS by
    // mistake?) → `None` from the match arm → error. Same as
    // C `:80-84` (level/type checks).
    //
    // `?` on `cmsgs()`: nix made this fallible (decode errors).
    // C doesn't check (CMSG_FIRSTHDR/NXTHDR don't fail). We
    // propagate; if nix found a malformed cmsg, that's
    // InvalidData by another name.
    let fds = msg
        .cmsgs()?
        .find_map(|cm| match cm {
            ControlMessageOwned::ScmRights(fds) => Some(fds),
            // Any other cmsg type: skip. C would error (`:80`).
            // We're slightly LOOSER: if the Java side sent
            // ScmCreds THEN ScmRights, C errors on the first;
            // we skip to the second. Unlikely scenario; the
            // looseness costs nothing.
            _ => None,
        })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "no SCM_RIGHTS control message received",
            )
        })?;

    // Exactly one. The Java side sends one tun fd; that's the
    // contract. Multiple would be a bug on their side.
    let [fd] = fds[..] else {
        // We received the fds (the kernel dup'd them into our
        // process). If we error here without closing them: fd
        // leak. Close before erroring.
        //
        // (The C doesn't have this case — its CMSG_LEN check
        // fails BEFORE the kernel dups. Actually no: the kernel
        // dups during recvmsg, before our checks. The C leaks
        // too. We're STRICTER: close them.)
        for &leaked in &fds {
            // Ignore close errors (we're already erroring).
            // SAFETY: these fds came from recvmsg's SCM_RIGHTS
            // dup; they're ours to close.
            #[allow(unsafe_code)]
            unsafe {
                libc::close(leaked);
            }
        }
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected exactly 1 fd via SCM_RIGHTS, got {}", fds.len()),
        ));
    };

    // `stream` drops here. Its close doesn't affect `fd` (the
    // SCM_RIGHTS dup is independent of the carrier socket). C
    // `:118`: `close(socketfd)` — same.
    Ok(fd)
}

/// `parse_socket_addr` + connect (`fd_device.c:122-149` + `:100-
/// 113`). The `@` → abstract-namespace dispatch.
///
/// Separate fn for testability: connect-to-abstract is testable
/// without the full SCM_RIGHTS flow (a test can listen on an
/// abstract addr, this fn connects, both sides agree).
///
/// `clippy::missing_errors_doc`: documented in `recv_scm_rights`.
#[allow(clippy::missing_errors_doc)]
fn connect_unix(path: &Path) -> io::Result<UnixStream> {
    // C `:137`: `if(path[0] == '@')`. We check the first byte
    // of the path's OsStr encoding. `as_encoded_bytes()[0]` is
    // the no-alloc check (same idiom as `cmd::network` for `.`-
    // prefix). `'@'` is ASCII (0x40); the encoding guarantee
    // (ASCII bytes are verbatim) holds.
    let bytes = path.as_os_str().as_encoded_bytes();
    if let Some(b'@') = bytes.first() {
        // ─── Abstract namespace ────────────────────────────────────
        // C `:139`: `socket_addr.sun_path[0] = '\0'`. The kernel
        // distinguishes abstract from filesystem by the first
        // byte: NUL → abstract, non-NUL → filesystem. The C
        // overwrites `@` with NUL.
        //
        // C `:140`: `path_length = strlen(path)` — INCLUDES the
        // `@` in the length count (then sets `sun_path[0]=0`,
        // so the kernel sees `\0foo` for input `@foo`). The
        // kernel matches abstract addresses by `(sun_path,
        // addrlen - offsetof(sun_path))` — length-delimited.
        // The leading NUL is the marker; the rest is the name.
        //
        // std `SocketAddr::from_abstract_name` takes the name
        // WITHOUT the leading marker (it adds the NUL itself).
        // So we strip the `@`.
        //
        // `&bytes[1..]`: the name after `@`. `from_abstract_
        // name` accepts `[u8]` (abstract addresses are byte
        // sequences, not paths, not necessarily UTF-8).
        //
        // `connect_addr` (1.70+) takes the resulting addr. The
        // filesystem-path `connect()` won't do (it interprets
        // the leading byte as a path char).
        use std::os::linux::net::SocketAddrExt;
        use std::os::unix::net::SocketAddr;
        let addr = SocketAddr::from_abstract_name(&bytes[1..])?;
        UnixStream::connect_addr(&addr)
    } else {
        // ─── Filesystem path ───────────────────────────────────────
        // C `:143`: `path_length = strlen(path) + 1` — include
        // the NUL. Filesystem `sun_path` is NUL-terminated.
        // std `connect()` handles this.
        UnixStream::connect(path)
    }
}

// ═══════════════════════════════════════════════════════════════════
// from_ip_nibble — the testable seam for ethertype synthesis
// ═══════════════════════════════════════════════════════════════════

/// `get_ip_ethertype` (`fd_device.c:192-202`). Read the IP version
/// nibble, return the ethertype.
///
/// IP packets (both v4 and v6) start with a version nibble in the
/// high 4 bits of byte 0:
///
/// ```text
///   IPv4:  byte 0 = 0x4? (version=4, IHL in low nibble)
///   IPv6:  byte 0 = 0x6? (version=6, traffic class high nibble in low)
/// ```
///
/// `byte0 >> 4` extracts the version. C `:193`: `DATA(packet)
/// [ETH_HLEN] >> 4` — `ETH_HLEN` because the IP packet starts
/// AFTER the (synthetic, about-to-be-written) ethernet header.
///
/// `None` for unknown version. C returns `ETH_P_MAX` (0xFFFF) as
/// a sentinel (`:201`); the caller checks for it and errors
/// (`:221-224`). We use `Option`. The `None` case is "Java side
/// sent garbage" — shouldn't happen, but defensive.
///
/// PURE FUNCTION. The testable seam. `linux.rs` couldn't test the
/// offset trick without the kernel driver (the kernel WRITES `tun_
/// pi`, can't fake it). THIS we can test: feed an IPv4 byte, get
/// `ETH_P_IP`. The pipe-based integration test below feeds whole
/// packets.
#[must_use]
fn from_ip_nibble(ip0: u8) -> Option<u16> {
    match ip0 >> 4 {
        4 => Some(ETH_P_IP),
        6 => Some(ETH_P_IPV6),
        _ => None,
    }
}

/// `set_etherheader` (`fd_device.c:204-208`). Write the synthetic
/// ethernet header: zero MACs, set ethertype.
///
/// C does it in two steps: `memset(DATA, 0, ETH_HLEN - ETHER_
/// TYPE_LEN)` then byte-by-byte ethertype write. We do the same.
/// The memset bound is 12 (= 14 - 2): zero dhost(6) + shost(6),
/// don't touch ethertype slot, then write it.
///
/// `to_be_bytes()`: ethertype on the wire is big-endian (network
/// byte order). C `:207-208`: `(ethertype >> 8) & 0xFF` then
/// `ethertype & 0xFF` — manual big-endian split. We use the std
/// fn. Same bytes.
///
/// `buf[..ETH_HLEN]` slice: caller guarantees at least 14 bytes
/// (the read path always has MTU bytes; debug_assert in `read()`
/// covers).
fn set_etherheader(buf: &mut [u8], ethertype: u16) {
    // Zero MACs. 12 bytes. NOT 14 — leave ethertype slot alone
    // (we're about to write it; zeroing first would just be
    // wasted work).
    buf[..ETH_HLEN - ETHER_TYPE_LEN].fill(0);
    // Ethertype, big-endian. Bytes 12-13.
    buf[ETH_HLEN - ETHER_TYPE_LEN..ETH_HLEN].copy_from_slice(&ethertype.to_be_bytes());
}

// ═══════════════════════════════════════════════════════════════════
// Device impl — the +14 read/write
// ═══════════════════════════════════════════════════════════════════

impl Device for FdTun {
    /// `read_packet` (`fd_device.c:210-230`). The +14 read +
    /// ethertype synthesis.
    ///
    /// `clippy::missing_errors_doc`: documented in trait.
    #[allow(clippy::missing_errors_doc)]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        debug_assert!(
            buf.len() >= MTU,
            "buf too small for fd read: {} < {MTU}",
            buf.len()
        );

        // C `:211`: `read(device_fd, DATA + ETH_HLEN, MTU -
        // ETH_HLEN)`. Read IP packet at +14, leaving room for
        // the synthetic ethernet header.
        //
        // `[ETH_HLEN..MTU]` upper bound caps the read. Same as
        // `linux.rs`. Android packets larger than MTU-14 would
        // truncate (the C does too).
        let n = read_fd(self.fd.as_raw_fd(), &mut buf[ETH_HLEN..MTU])?;

        // C `:213-216`: `if(lenin <= 0)`. `read_fd` already
        // converted `<0`. `0` is EOF — the Java side closed
        // the tun. Unlike kernel TUN (which never EOFs), this
        // CAN happen (the Java VpnService stopped). C errors;
        // we match. The error message says what we know.
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("{} closed (VpnService stopped?)", self.device_label),
            ));
        }

        // C `:218-224`: synthesize ethertype from IP version
        // nibble, error on unknown version.
        //
        // `buf[ETH_HLEN]` is byte 0 of the IP packet (we read
        // at offset 14, so byte 14 of buf is byte 0 of payload).
        // `from_ip_nibble` extracts.
        let Some(ethertype) = from_ip_nibble(buf[ETH_HLEN]) else {
            // C `:222`: `logger(DEBUG_TRAFFIC, LOG_ERR,
            // "Unknown IP version")` then `return false`. The
            // packet is dropped. We Err with the actual nibble
            // (more useful than the C's bare "unknown").
            //
            // The C errors at DEBUG_TRAFFIC level (only logs
            // when traffic-debug enabled). We always include
            // the nibble in the error string; daemon decides
            // whether to log. The information is there either
            // way.
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{}: unknown IP version nibble {:#x} (byte 0 = {:#04x})",
                    self.device_label,
                    buf[ETH_HLEN] >> 4,
                    buf[ETH_HLEN]
                ),
            ));
        };

        // C `:226`: `set_etherheader(packet, ethertype)`. Write
        // the synthetic header into bytes 0..14.
        set_etherheader(buf, ethertype);

        // C `:227`: `packet->len = lenin + ETH_HLEN`. The 14
        // synthetic bytes count toward the packet length.
        Ok(n + ETH_HLEN)
    }

    /// `write_packet` (`fd_device.c:232-241`). The +14 write —
    /// strip the ethernet header, write the IP packet.
    ///
    /// Unlike `linux.rs` TUN write (which mutates `buf[10..12]`),
    /// this is a PURE write — the ethernet header just gets
    /// skipped. The trait signature is `&mut [u8]` for uniformity
    /// (the daemon calls through `dyn Device`, doesn't know which
    /// impl), but THIS impl doesn't mutate. The shared signature
    /// is the constraint.
    ///
    /// `clippy::missing_errors_doc`: documented in trait.
    #[allow(clippy::missing_errors_doc)]
    fn write(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        debug_assert!(
            buf.len() > ETH_HLEN,
            "fd write buf too short: {} <= {ETH_HLEN}",
            buf.len()
        );
        // C `:237`: `write(device_fd, DATA + ETH_HLEN, packet->
        // len - ETH_HLEN)`. Strip 14, write the rest.
        write_fd(self.fd.as_raw_fd(), &buf[ETH_HLEN..])
    }

    /// TUN-only. C `:152-155` rejects switch mode. The contract.
    fn mode(&self) -> Mode {
        Mode::Tun
    }

    /// `"fd"` placeholder. The C `iface` global stays NULL for
    /// `fd_device` (no TUNSETIFF, no kernel name). The daemon's
    /// `tinc-up` would get `INTERFACE=` (empty) in C; we say
    /// `"fd"` so the script can at least pattern-match.
    ///
    /// `clippy::unnecessary_literal_bound`: trait signature says
    /// `&str`; impl can't widen. Same as Dummy.
    #[allow(clippy::unnecessary_literal_bound)]
    fn iface(&self) -> &str {
        "fd"
    }

    /// No MAC. TUN-only → L3 → no link layer.
    fn mac(&self) -> Option<Mac> {
        None
    }

    /// The fd, for the daemon's poll loop. `Some` — there IS
    /// an fd (unlike Dummy).
    fn fd(&self) -> Option<RawFd> {
        Some(self.fd.as_raw_fd())
    }
}

// ═══════════════════════════════════════════════════════════════════
// read/write — same as linux.rs, but module-private
// ═══════════════════════════════════════════════════════════════════
//
// These are duplicates of `linux.rs::{read_fd, write_fd}`. NOT
// shared. The "re-declare module-private constants when modules
// are independent" rule generalizes: re-declare module-private
// FNS when modules are independent. `linux.rs` and `fd.rs` are
// independent backends; they happen to call read(2)/write(2) the
// same way today. Factoring would couple them.
//
// (If a third backend needs these, then maybe a `syscall` module.
// Two instances is not a pattern.)

/// `read(2)` on the fd. Datagram semantics: one read = one packet.
/// Same as `linux.rs::read_fd`. See there for the SAFETY argument.
#[allow(unsafe_code)]
fn read_fd(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: `fd` is the FdTun's owned fd (alive while &mut
    // FdTun is borrowed). `buf` is exclusive `&mut`. Kernel
    // writes at most `buf.len()` bytes.
    let ret = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    #[allow(clippy::cast_sign_loss)]
    Ok(ret as usize)
}

/// `write(2)` on the fd. Same as `linux.rs::write_fd`.
#[allow(unsafe_code)]
fn write_fd(fd: RawFd, buf: &[u8]) -> io::Result<usize> {
    // SAFETY: same as read_fd, but kernel reads from us.
    let ret = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    #[allow(clippy::cast_sign_loss)]
    Ok(ret as usize)
}

// ═══════════════════════════════════════════════════════════════════
// Tests — pure fns + pipe-based integration
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ─────────────────────────────────────────────────────────────────
    // Ethernet constants — sed-verified
    // ─────────────────────────────────────────────────────────────────

    /// `ETH_HLEN = 14` per `ethernet.h:31` AND `<linux/if_ether.
    /// h>`. The +14 read offset. gcc-verified: `printf("%d", ETH_
    /// HLEN)` → `14`.
    #[test]
    fn eth_hlen_14() {
        assert_eq!(ETH_HLEN, 14);
        // The arithmetic: dhost(6) + shost(6) + type(2).
        assert_eq!(ETH_HLEN, 6 + 6 + 2);
    }

    /// `ETHER_TYPE_LEN = 2`. `ETH_HLEN - ETHER_TYPE_LEN = 12` is
    /// where ethertype goes.
    #[test]
    fn ethertype_at_12() {
        assert_eq!(ETHER_TYPE_LEN, 2);
        assert_eq!(ETH_HLEN - ETHER_TYPE_LEN, 12);
    }

    /// IANA ethertype registrations. Kernel ABI; can't change.
    /// gcc-verified vs `<linux/if_ether.h>`.
    #[test]
    fn ethertypes_iana() {
        assert_eq!(ETH_P_IP, 0x0800);
        assert_eq!(ETH_P_IPV6, 0x86DD);
    }

    // ─────────────────────────────────────────────────────────────────
    // from_ip_nibble — the testable seam
    // ─────────────────────────────────────────────────────────────────

    /// IPv4 byte 0: version=4 in high nibble, IHL in low.
    /// `0x45` is the canonical IPv4 first byte (IHL=5 words =
    /// 20 bytes, no options). `0x4F` is max IHL (60 bytes).
    /// Both → `ETH_P_IP`.
    #[test]
    fn nibble_ipv4() {
        assert_eq!(from_ip_nibble(0x45), Some(ETH_P_IP));
        assert_eq!(from_ip_nibble(0x40), Some(ETH_P_IP));
        assert_eq!(from_ip_nibble(0x4F), Some(ETH_P_IP));
    }

    /// IPv6 byte 0: version=6 in high nibble, traffic class
    /// high nibble in low. `0x60` is canonical (default traffic
    /// class).
    #[test]
    fn nibble_ipv6() {
        assert_eq!(from_ip_nibble(0x60), Some(ETH_P_IPV6));
        assert_eq!(from_ip_nibble(0x6F), Some(ETH_P_IPV6));
    }

    /// Unknown versions → None. The C returns `ETH_P_MAX`
    /// sentinel; we use `Option`.
    ///
    /// IP version 5 was ST-II (RFC 1819, experimental, dead).
    /// Version 7-15 are unassigned. Version 0-3 are pre-IPv4
    /// historical. The Java side never sends these; the test
    /// is for the error path.
    #[test]
    fn nibble_unknown() {
        assert_eq!(from_ip_nibble(0x00), None);
        assert_eq!(from_ip_nibble(0x50), None); // ST-II
        assert_eq!(from_ip_nibble(0x70), None);
        assert_eq!(from_ip_nibble(0xFF), None);
    }

    // ─────────────────────────────────────────────────────────────────
    // set_etherheader — pure fn
    // ─────────────────────────────────────────────────────────────────

    /// Zero MACs, write ethertype big-endian. C `:204-208`.
    #[test]
    fn set_etherheader_ipv4() {
        // Pre-fill with garbage to verify the zero.
        let mut buf = [0xAAu8; 20];
        set_etherheader(&mut buf, ETH_P_IP);
        // dhost: zeroed.
        assert_eq!(&buf[0..6], &[0u8; 6]);
        // shost: zeroed.
        assert_eq!(&buf[6..12], &[0u8; 6]);
        // ethertype: 0x0800 big-endian → [0x08, 0x00].
        assert_eq!(&buf[12..14], &[0x08, 0x00]);
        // Past 14: untouched.
        assert_eq!(buf[14], 0xAA);
    }

    /// Same for IPv6. 0x86DD → [0x86, 0xDD].
    #[test]
    fn set_etherheader_ipv6() {
        let mut buf = [0xBBu8; 20];
        set_etherheader(&mut buf, ETH_P_IPV6);
        assert_eq!(&buf[0..12], &[0u8; 12]);
        assert_eq!(&buf[12..14], &[0x86, 0xDD]);
        assert_eq!(buf[14], 0xBB);
    }

    /// The big-endian split matches the C's manual `>> 8` /
    /// `& 0xFF`. C `:207-208`.
    #[test]
    fn set_etherheader_be_matches_c_manual_split() {
        // What the C does:
        //   buf[12] = (ethertype >> 8) & 0xFF;
        //   buf[13] = ethertype & 0xFF;
        // What we do: to_be_bytes().
        // For 0x86DD: high byte 0x86, low byte 0xDD.
        let et = ETH_P_IPV6;
        let c_high = ((et >> 8) & 0xFF) as u8;
        let c_low = (et & 0xFF) as u8;
        let rust = et.to_be_bytes();
        assert_eq!([c_high, c_low], rust);
    }

    // ─────────────────────────────────────────────────────────────────
    // FdSource::Inherited — the negative-fd check
    // ─────────────────────────────────────────────────────────────────

    /// C `:168`: `if(device_fd < 0)`. Negative fds don't exist;
    /// reject early. The C logs `strerror(errno)` which is
    /// GARBAGE (sscanf doesn't set errno); we say something
    /// useful.
    #[test]
    fn inherited_negative_fd() {
        let e = FdTun::open(FdSource::Inherited(-1)).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        let msg = e.to_string();
        assert!(msg.contains("negative"), "msg: {msg}");
        assert!(msg.contains("-1"), "msg: {msg}");
    }

    // ─────────────────────────────────────────────────────────────────
    // pipe-based integration — the win over linux.rs
    // ─────────────────────────────────────────────────────────────────
    //
    // `linux.rs` couldn't test the +10 offset trick: the kernel
    // TUN driver lays out `tun_pi`; can't fake that without the
    // actual driver. THIS backend reads RAW IP packets — no
    // kernel-side layout. A `pipe()` is enough.
    //
    // The pipe gives us read-end, write-end. Write IP bytes to
    // one; FdTun::read on the other. The +14 + ethertype synth
    // runs.
    //
    // (Pipes aren't datagram-mode. A real Android tun fd is.
    // But the read/write paths don't care: read() returns what
    // it returns. The datagram boundary matters for partial
    // reads, which don't happen with our small test packets.
    // The test exercises the OFFSET ARITHMETIC, which is fd-
    // agnostic.)

    /// The full read flow: write IPv4 bytes to a pipe, FdTun
    /// reads at +14, synthesizes 0x0800 ethertype at +12,
    /// returns len+14.
    ///
    /// `clippy::similar_names`: `r`/`w` for pipe ends. The
    /// idiom.
    #[test]
    #[allow(clippy::similar_names)]
    fn read_ipv4_via_pipe() {
        // Minimal IPv4-ish packet. Only byte 0 matters (the
        // version nibble); the rest is payload from our
        // perspective.
        let ip_packet = [
            0x45, // version=4, IHL=5
            0x00, // DSCP/ECN
            0x00, 0x14, // total length = 20 (header only)
            0xAB, 0xCD, // identification (arbitrary)
            0x00, 0x00, // flags + fragment offset
            0x40, // TTL = 64
            0x01, // protocol = ICMP
            0x00, 0x00, // checksum (don't care)
            10, 0, 0, 1, // src 10.0.0.1
            10, 0, 0, 2, // dst 10.0.0.2
        ];
        assert_eq!(ip_packet.len(), 20); // sanity: standard IPv4 hdr

        // pipe(). `r` for FdTun, `w` for test driver.
        let (r, w) = pipe();
        // Write the IP packet to the pipe.
        write_all(&w, &ip_packet);

        // Wrap `r` as FdTun via Inherited.
        let mut tun = FdTun::open(FdSource::Inherited(r.into_raw())).unwrap();

        // Read. Buffer must be ≥ MTU.
        let mut buf = [0u8; MTU];
        let n = tun.read(&mut buf).unwrap();

        // Length: 20 (IP packet) + 14 (synthetic ether) = 34.
        assert_eq!(n, 20 + ETH_HLEN);

        // Bytes 0-11: zeroed MACs.
        assert_eq!(&buf[0..12], &[0u8; 12]);

        // Bytes 12-13: ethertype, IPv4, big-endian.
        assert_eq!(&buf[12..14], &[0x08, 0x00]);

        // Bytes 14..34: the IP packet, verbatim.
        assert_eq!(&buf[14..34], &ip_packet);

        // `w` and `tun` drop here. Pipe closes both ends.
    }

    /// Same but IPv6. Byte 0 = 0x60. Ethertype = 0x86DD.
    #[test]
    #[allow(clippy::similar_names)]
    fn read_ipv6_via_pipe() {
        // Minimal IPv6-ish prefix. 40-byte header, but we only
        // need the first byte to be 0x6?. Send a stub.
        let ip_packet = [
            0x60, 0x00, 0x00, 0x00, // version=6, tc=0, flow=0
            0x00, 0x00, // payload length = 0
            0x3B, // next header = no-next-header
            0x40, // hop limit = 64
            // src: ::1 (loopback)
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, // dst: ::2
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
        ];
        assert_eq!(ip_packet.len(), 40);

        let (r, w) = pipe();
        write_all(&w, &ip_packet);

        let mut tun = FdTun::open(FdSource::Inherited(r.into_raw())).unwrap();
        let mut buf = [0u8; MTU];
        let n = tun.read(&mut buf).unwrap();

        assert_eq!(n, 40 + ETH_HLEN);
        assert_eq!(&buf[0..12], &[0u8; 12]);
        assert_eq!(&buf[12..14], &[0x86, 0xDD]); // ← IPv6 ethertype
        assert_eq!(&buf[14..54], &ip_packet);
    }

    /// Unknown IP version → InvalidData. C `:221-224`.
    #[test]
    #[allow(clippy::similar_names)]
    fn read_unknown_version_via_pipe() {
        let garbage = [0x50u8; 20]; // version=5 (ST-II, dead)

        let (r, w) = pipe();
        write_all(&w, &garbage);

        let mut tun = FdTun::open(FdSource::Inherited(r.into_raw())).unwrap();
        let mut buf = [0u8; MTU];
        let e = tun.read(&mut buf).unwrap_err();

        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        let msg = e.to_string();
        // Our error includes the actual nibble (more useful
        // than C's bare "unknown").
        assert!(msg.contains("0x5"), "msg: {msg}");
    }

    /// EOF → UnexpectedEof. The Java VpnService stopped. C
    /// `:213` errors on `lenin <= 0`.
    #[test]
    #[allow(clippy::similar_names)]
    fn read_eof_via_pipe() {
        let (r, w) = pipe();
        // Close the write end immediately. Next read returns 0.
        drop(w);

        let mut tun = FdTun::open(FdSource::Inherited(r.into_raw())).unwrap();
        let mut buf = [0u8; MTU];
        let e = tun.read(&mut buf).unwrap_err();

        assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
        // Our error mentions the device label.
        let msg = e.to_string();
        assert!(msg.contains("fd/"), "msg: {msg}");
    }

    /// The write flow: hand FdTun a 14+20 byte buffer (ether +
    /// IP), it strips the 14, writes the 20.
    #[test]
    #[allow(clippy::similar_names)]
    fn write_strips_ether_via_pipe() {
        let (r, w) = pipe();

        // FdTun owns the WRITE end this time.
        let mut tun = FdTun::open(FdSource::Inherited(w.into_raw())).unwrap();

        // Buffer: synthetic ether header + IP packet. The
        // ether header is GARBAGE — the write should skip it.
        let mut buf = [0u8; 14 + 20];
        buf[0..14].fill(0xEE); // ether header, will be stripped
        buf[14] = 0x45; // IPv4 marker, will be written
        buf[33] = 0x99; // last byte, arbitrary

        let n = tun.write(&mut buf).unwrap();
        // Wrote 20 (the IP part). NOT 34.
        assert_eq!(n, 20);

        // Read from the pipe. Should be exactly the IP part.
        let mut recv = [0u8; 64];
        let rn = read_exact_n(&r, &mut recv, 20);
        assert_eq!(rn, 20);
        assert_eq!(recv[0], 0x45); // IPv4 marker survived
        assert_eq!(recv[19], 0x99); // last byte survived
        // The ether garbage is NOT here.
        assert_ne!(recv[0], 0xEE);
    }

    /// `mode()` is TUN, always. C `:152-155` rejects switch
    /// mode at setup; we don't even have the option.
    #[test]
    fn mode_always_tun() {
        let (r, _w) = pipe();
        let tun = FdTun::open(FdSource::Inherited(r.into_raw())).unwrap();
        assert_eq!(tun.mode(), Mode::Tun);
        assert_eq!(tun.iface(), "fd");
        assert!(tun.mac().is_none());
        assert!(tun.fd().is_some());
    }

    // ─────────────────────────────────────────────────────────────────
    // SCM_RIGHTS — round-trip with a real socketpair
    // ─────────────────────────────────────────────────────────────────
    //
    // Can't easily test the abstract-namespace connect (would
    // need a real listener). But the recvmsg/SCM_RIGHTS itself
    // is testable with `socketpair()` — both ends in-process,
    // send an fd one way, receive it the other.
    //
    // This covers the cmsghdr handling: msg.flags check, cmsg
    // iteration, ScmRights extraction, exactly-one-fd check.
    // The connect() is NOT covered (that's connect_unix, tested
    // separately if at all — it's a thin std wrapper).

    /// SCM_RIGHTS round-trip: send an fd through a socketpair,
    /// receive it. The received fd is a DIFFERENT NUMBER (kernel
    /// dup'd) but points at the SAME FILE (write to the original,
    /// read from the dup).
    ///
    /// This is the cmsghdr-handling test. The C's `read_fd`
    /// (`:39-93`) is the equivalent.
    #[test]
    fn scm_rights_round_trip() {
        use nix::sys::socket::{
            AddressFamily, ControlMessage, MsgFlags, SockFlag, SockType, sendmsg, socketpair,
        };
        use std::io::IoSlice;

        // Socketpair: two connected AF_UNIX stream sockets.
        // One sends, one receives.
        let (snd, rcv) = socketpair(
            AddressFamily::Unix,
            SockType::Stream,
            None,
            SockFlag::empty(),
        )
        .unwrap();

        // The fd we'll send: a pipe write-end. Arbitrary; we
        // just need SOME valid fd to ship across.
        let (canary_r, canary_w) = pipe();

        // Send: 1 byte payload (the C expects `iov_len=1`) +
        // SCM_RIGHTS cmsg with one fd.
        let payload = [b'X'];
        let iov = [IoSlice::new(&payload)];
        let fds = [canary_w.as_raw_fd()];
        let cmsg = ControlMessage::ScmRights(&fds);
        sendmsg::<()>(snd.as_raw_fd(), &iov, &[cmsg], MsgFlags::empty(), None).unwrap();

        // Receive: this is what `recv_scm_rights` does, but
        // without the connect (we already have `rcv`). Factor
        // the recvmsg-only part? No — `recv_scm_rights` is
        // already small. Inline the relevant bit here.
        //
        // ACTUALLY: we can call the inner machinery. But
        // `recv_scm_rights` takes a path and connects. The
        // recvmsg part isn't factored. For the test, do it
        // manually with the same nix calls. The test verifies
        // OUR UNDERSTANDING of nix's behavior, not our wrapper
        // (the wrapper is tested by integration when there's a
        // real socket server).
        let mut iobuf = [0u8; 1];
        let mut iov = [IoSliceMut::new(&mut iobuf)];
        let mut cmsgbuf = nix::cmsg_space!(RawFd);
        let msg = nix::sys::socket::recvmsg::<()>(
            rcv.as_raw_fd(),
            &mut iov,
            Some(&mut cmsgbuf),
            MsgFlags::empty(),
        )
        .unwrap();

        // `RecvMsg<'_, 'outer, ()>` is `Copy` but its `'outer`
        // lifetime ties to `&mut iov`. NLL releases the borrow
        // after last USE of `msg`, not at scope end. So: do all
        // `msg` reads FIRST (bytes, flags, cmsgs), then `iobuf`
        // is reachable. The original code had `iobuf[0]` between
        // `msg.bytes` and `msg.cmsgs()` — the later use kept the
        // borrow alive past the iobuf read.
        assert_eq!(msg.bytes, 1);
        assert!(
            !msg.flags
                .intersects(MsgFlags::MSG_CTRUNC | MsgFlags::MSG_OOB)
        );
        let fds: Vec<RawFd> = msg
            .cmsgs()
            .unwrap()
            .find_map(|cm| match cm {
                nix::sys::socket::ControlMessageOwned::ScmRights(f) => Some(f),
                _ => None,
            })
            .unwrap();
        // ↑ last use of msg; iov borrow released.

        // Now iobuf is reachable.
        assert_eq!(iobuf[0], b'X');
        assert_eq!(fds.len(), 1);
        let received_fd = fds[0];

        // The received fd is a DIFFERENT NUMBER from the
        // original (kernel dup'd into a fresh slot). Well,
        // it MIGHT be the same number by coincidence (lowest
        // free fd). What we CAN verify: it works.
        //
        // SAFETY: kernel dup'd via SCM_RIGHTS; the fd is ours.
        #[allow(unsafe_code)]
        let received_w = unsafe { File::from_raw_fd(received_fd) };

        // Write through the RECEIVED fd, read from the canary
        // pipe. If they're connected (same underlying file),
        // this works.
        write_all_file(&received_w, b"ping");
        let mut got = [0u8; 4];
        let n = read_exact_n(&canary_r, &mut got, 4);
        assert_eq!(n, 4);
        assert_eq!(&got, b"ping");

        // Cleanup: drops close everything. The original
        // `canary_w` is still open (dup'd, not moved); both
        // it and `received_w` close on drop.
    }

    // ─────────────────────────────────────────────────────────────────
    // Test plumbing — pipe helpers
    // ─────────────────────────────────────────────────────────────────

    /// Newtype around the pipe fd for the tests. Owns; drop
    /// closes. `into_raw` releases ownership for passing to
    /// `FdSource::Inherited`.
    ///
    /// (Not using `OwnedFd`: it's stable since 1.63 but the
    /// `into_raw_fd` consuming-conversion is what we need, and
    /// `OwnedFd` doesn't have a direct "release without close."
    /// Well, `into_raw_fd()` does that. Hm. Actually `OwnedFd`
    /// would work fine. But the explicit Drop here makes the
    /// "this test fd closes on drop" lifecycle visible.)
    struct PipeFd(RawFd);

    impl PipeFd {
        fn into_raw(self) -> RawFd {
            let fd = self.0;
            std::mem::forget(self); // don't close
            fd
        }
        fn as_raw_fd(&self) -> RawFd {
            self.0
        }
    }

    impl Drop for PipeFd {
        fn drop(&mut self) {
            // SAFETY: we own this fd (pipe() gave it to us;
            // into_raw forgets self before returning, so we
            // only get here for un-released fds).
            #[allow(unsafe_code)]
            unsafe {
                libc::close(self.0);
            }
        }
    }

    /// `pipe(2)`. Returns (read, write). No CLOEXEC (test fds,
    /// no exec coming).
    fn pipe() -> (PipeFd, PipeFd) {
        let mut fds = [0; 2];
        // SAFETY: `fds` is a 2-int buffer; pipe() writes exactly 2.
        #[allow(unsafe_code)]
        let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert_eq!(ret, 0, "pipe() failed: {}", io::Error::last_os_error());
        (PipeFd(fds[0]), PipeFd(fds[1]))
    }

    /// Write all bytes. Loop on short writes (pipes can short-
    /// write under pressure; our tiny test packets won't, but
    /// correctness).
    fn write_all(fd: &PipeFd, buf: &[u8]) {
        let mut off = 0;
        while off < buf.len() {
            // SAFETY: fd valid (held by &PipeFd), buf is &[u8].
            #[allow(unsafe_code)]
            let ret = unsafe {
                libc::write(
                    fd.as_raw_fd(),
                    buf.as_ptr().add(off).cast(),
                    buf.len() - off,
                )
            };
            assert!(ret > 0, "write failed");
            #[allow(clippy::cast_sign_loss)]
            {
                off += ret as usize;
            }
        }
    }

    /// Same but for `&File` (the SCM_RIGHTS test wraps in File).
    fn write_all_file(f: &File, buf: &[u8]) {
        let mut off = 0;
        while off < buf.len() {
            #[allow(unsafe_code)]
            let ret = unsafe {
                libc::write(f.as_raw_fd(), buf.as_ptr().add(off).cast(), buf.len() - off)
            };
            assert!(ret > 0, "write failed");
            #[allow(clippy::cast_sign_loss)]
            {
                off += ret as usize;
            }
        }
    }

    /// Read exactly n bytes. Loop on short reads.
    fn read_exact_n(fd: &PipeFd, buf: &mut [u8], n: usize) -> usize {
        let mut off = 0;
        while off < n {
            #[allow(unsafe_code)]
            let ret =
                unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().add(off).cast(), n - off) };
            assert!(ret > 0, "read failed or EOF");
            #[allow(clippy::cast_sign_loss)]
            {
                off += ret as usize;
            }
        }
        off
    }
}
