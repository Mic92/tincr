//! Android tun fd backend.
//!
//! Android's `VpnService` opens the tun fd in the Java process and
//! hands it over. Two transports: fd inheritance (2017, `7a54fe5e`,
//! `Device = 5`) and `SCM_RIGHTS` over `AF_UNIX` (2020, `f5223937`,
//! `Device = /path` or `@abstract`). C dispatches on `sscanf("%d")`;
//! we make the union explicit as `FdSource`.
//!
//! ## The +14 offset (`offset = ETH_HLEN − 0`)
//!
//! ```text
//!   linux:  read vnet_hdr+IP via drain(), synth eth from IP nibble
//!   fd:     read at +14, IP packet starts at +14 (after ether header)
//! ```
//!
//! `VpnService` writes raw IP with no prefix, so we synthesize the
//! ethertype from the IP version nibble (`set_etherheader`). Testable
//! with `pipe()` — no kernel driver layout to fake.
//!
//! ## nix earns its dep here
//!
//! Uses `nix::sys::socket::recvmsg` for `SCM_RIGHTS`: hand-rolling is
//! ~40 LOC of `cmsghdr` boilerplate with a NULL-deref trap (`CMSG_
//! FIRSTHDR` returns NULL on empty buffer; easy to dereference
//! unchecked). Shim #4 uses the wrapper (POSIX-clean, no encoding
//! lies), unlike #3 TUNSETIFF which bypassed it.

use std::fs::File;
use std::io::{self, IoSliceMut};
use std::os::unix::io::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;

use crate::ether::{ETH_HLEN, from_ip_nibble, set_etherheader};
use crate::{Device, MTU, Mac, Mode, read_fd, write_fd};

// FdSource — the union type the config-string dispatch implies

/// The two ways the fd reaches us. The daemon parses the config
/// string (`sscanf("%d")` to detect a bare integer); we get the
/// resolved variant.
#[derive(Debug)]
pub enum FdSource {
    /// `Device = 5` mode (2017). The Java parent process did
    /// `dup2(tun_fd, 5)` before `exec()`. The fd is already
    /// open in our process; the caller wraps it at the moment it
    /// parses the config integer (`daemon/setup.rs`) so ownership
    /// is established immediately, not deferred to `open()`. If
    /// setup bails between parsing and `open()`, `OwnedFd::drop`
    /// closes it.
    ///
    /// On Android pre-2020 `SELinux` policy, this was the only
    /// way. Post-2020, blocked: the policy forbids fd
    /// inheritance across exec for tun fds.
    Inherited(OwnedFd),

    /// `Device = /path` mode (2020). Java side listens; we connect;
    /// fd arrives via `SCM_RIGHTS`. `@` prefix → abstract namespace.
    UnixSocket(std::path::PathBuf),
}

// FdTun — the Device impl

/// TUN-only (Android's `VpnService` only does L3; switch mode is
/// rejected at setup). No real `iface` name; we say `"fd"`.
#[derive(Debug)]
pub struct FdTun {
    /// The tun fd. Raw IP channel — no `tun_pi`, no prefix.
    /// `File` for ownership; `from_raw_fd` asserts the previous
    /// owner (Java process or kernel `SCM_RIGHTS` dup) gave it up.
    fd: File,

    /// `"fd/5"` or `"fd:/path"` for error messages. C logs
    /// `"fd/%d"` (`:231`); path variant is our addition.
    device_label: String,
}

impl FdTun {
    /// Open the device. The `RMODE_SWITCH` rejection is the daemon's
    /// job; `mode() → Tun` is the contract, not the check.
    ///
    /// # Errors
    /// - `UnixSocket(path)`: connect failures, recvmsg failures,
    ///   wrong cmsg type.
    /// - `Inherited(_)` is infallible (already owned).
    pub fn open(source: FdSource) -> io::Result<Self> {
        let (fd, device_label) = match source {
            // ─── Inherited
            // The daemon already parsed the integer and wrapped it;
            // we just rehome the OwnedFd into a File. The unsafe
            // (and the negative-fd check) live at the parse site,
            // not here — ownership is held continuously from parse
            // onward.
            FdSource::Inherited(fd) => {
                let raw = fd.as_raw_fd();
                (File::from(fd), format!("fd/{raw}"))
            }

            // ─── UnixSocket
            // Connect, recvmsg with SCM_RIGHTS, wrap. The cmsghdr
            // boilerplate collapses into `recv_scm_rights`.
            FdSource::UnixSocket(path) => {
                let fd = recv_scm_rights(&path)?;
                (File::from(fd), format!("fd:{}", path.display()))
            }
        };

        // No log here; daemon logs post-open if it wants.

        Ok(FdTun { fd, device_label })
    }
}

// SCM_RIGHTS — the fourth unsafe shim, the first to USE nix

/// Connect to the Unix socket, receive one fd via `SCM_RIGHTS`.
///
/// `UnixStream` + `nix::recvmsg` collapse what would otherwise be
/// three functions of `goto end; close()` RAII. Returns `OwnedFd`:
/// the kernel dup'd the fd into our table during `recvmsg`, so it's
/// freshly ours; ownership is established here, not at the call site.
///
/// # Errors
/// - `connect`: `NotFound`, `ConnectionRefused`, `PermissionDenied`
/// - `InvalidData`: cmsg wasn't `SCM_RIGHTS`, ≠1 fd, or `MSG_CTRUNC`
///   set
fn recv_scm_rights(path: &Path) -> io::Result<OwnedFd> {
    use nix::sys::socket::{ControlMessageOwned, MsgFlags, recvmsg};

    // ─── Connect
    // `@` prefix → abstract namespace; std handles the leading-NUL
    // + length bookkeeping.
    let stream = connect_unix(path)?;

    // ─── recvmsg
    // The cmsghdr dance.
    //
    // ONE BYTE of regular data is read. Why? The Java sender writes
    // one byte of payload alongside the fd cmsg — recvmsg needs SOME
    // iov to anchor the call. The byte's value is ignored
    // declared, never read). We do the same: 1-byte iov, ignore
    // the byte.
    //
    // (Could the sender send 0 bytes? `sendmsg` allows it. But
    // the original Android Java code sends one byte, and the C
    // expects one byte (`:56`: `ret <= 0` check — `0` would
    // fail). We match the C's expectation.)
    let mut iobuf = [0u8; 1];
    let mut iov = [IoSliceMut::new(&mut iobuf)];

    // Control buffer: room for one `int` (the fd). nix
    // `cmsg_space!` is the `CMSG_SPACE` macro equivalent. One
    // `RawFd` worth of space.
    let mut cmsgbuf = nix::cmsg_space!(RawFd);

    // The recvmsg. nix wraps the unsafe (`libc::recvmsg`). We
    // pass `MsgFlags::empty()` (blocking recv). The socket is fresh
    // from `connect` so blocking is correct — the Java side sends
    // immediately on accept.
    //
    // `()` for the address type: we don't care about the
    // sender's address (it's the same socket we connected to).
    //
    // `?`: nix `Errno` → `io::Error` via `From`. Same pattern
    // as the bare `?` on nix calls in `tui.rs`.
    let msg = recvmsg::<()>(
        stream.as_raw_fd(),
        &mut iov,
        Some(&mut cmsgbuf),
        MsgFlags::empty(),
    )?;

    // ─── Check flags
    // `MSG_CTRUNC | MSG_OOB | MSG_ERRQUEUE`. We're Linux-only
    // here (the whole
    // module is `#[cfg(target_os = "linux")]`); include it.
    //
    // `MSG_CTRUNC`: control data truncated. Our `cmsgbuf` was
    // sized for one fd; if the sender sent two fds, the second
    // got dropped and this flag is set. Error.
    //
    // `MSG_OOB`: out-of-band data. Unix sockets don't HAVE OOB
    // (it's a TCP thing). The check is defensive paranoia,
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

    // nix already converted `<0` to Err (the `?` above). `ret == 0`
    // is "peer closed before sending" — error. nix exposes the byte
    // count as `msg.bytes`.
    if msg.bytes == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "Unix socket peer closed before sending fd",
        ));
    }

    // ─── Extract the fd
    // `CMSG_FIRSTHDR` returns NULL on empty buffer; easy to deref
    // unchecked when hand-rolling. nix's
    // iterator returns `None` → error, not segfault.
    //
    // Accept exactly one fd. STRICTER: silently reading the first
    // of 2+ fds is a bug; we error. Non-ScmRights cmsg → error.
    // `?` on `cmsgs()` propagates nix decode errors.
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

    // Wrap as owned IMMEDIATELY: the kernel dup'd these into our
    // fd table during recvmsg (before any of our checks ran). If we
    // error below, `Vec<OwnedFd>::drop` closes them — no leak.
    // SAFETY: SCM_RIGHTS dup; each fd is open and exclusively ours.
    #[allow(unsafe_code)]
    let mut fds: Vec<OwnedFd> = fds
        .into_iter()
        .map(|fd| unsafe { OwnedFd::from_raw_fd(fd) })
        .collect();

    // Exactly one. The Java side sends one tun fd; that's the
    // contract. Multiple would be a bug on their side.
    if fds.len() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected exactly 1 fd via SCM_RIGHTS, got {}", fds.len()),
        ));
    }

    // `stream` drops here. Its close doesn't affect `fd` (the
    // SCM_RIGHTS dup is independent of the carrier socket).
    Ok(fds.pop().unwrap())
}

/// The `@` → abstract-namespace dispatch.
///
/// Separate fn for testability: connect-to-abstract is testable
/// without the full `SCM_RIGHTS` flow (a test can listen on an
/// abstract addr, this fn connects, both sides agree).
fn connect_unix(path: &Path) -> io::Result<UnixStream> {
    // Check the first byte of the path's OsStr encoding.
    // `as_encoded_bytes()[0]` is the no-alloc check (same idiom as
    // `cmd::network` for `.`-prefix). `'@'` is ASCII (0x40); the
    // encoding guarantee (ASCII bytes are verbatim) holds.
    let bytes = path.as_os_str().as_encoded_bytes();
    if matches!(bytes.first(), Some(b'@')) {
        // ─── Abstract namespace
        // Kernel distinguishes by leading NUL byte. std
        // `from_abstract_name` adds the NUL itself, so strip the
        // `@`. Abstract addrs are length-delimited bytes.
        use std::os::linux::net::SocketAddrExt;
        use std::os::unix::net::SocketAddr;
        let addr = SocketAddr::from_abstract_name(&bytes[1..])?;
        UnixStream::connect_addr(&addr)
    } else {
        // ─── Filesystem path
        // Filesystem `sun_path` is NUL-terminated. std `connect()`
        // handles this.
        UnixStream::connect(path)
    }
}

// (`from_ip_nibble` + `set_etherheader` hoisted to `crate::ether`
// when BSD became the second consumer. The fns themselves are
// pure; the move preserves byte-identical behavior.)
// Device impl — the +14 read/write

impl Device for FdTun {
    /// The +14 read + ethertype synthesis.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        debug_assert!(
            buf.len() >= MTU,
            "buf too small for fd read: {} < {MTU}",
            buf.len()
        );

        // Read IP packet at +14, leaving room for the synthetic
        // ethernet header.
        //
        // `[ETH_HLEN..MTU]` upper bound caps the read. Same as
        // `linux.rs`. Android packets larger than MTU-14 would
        // truncate.
        let n = read_fd(self.fd.as_fd(), &mut buf[ETH_HLEN..MTU])?;

        // `read_fd` already converted `<0`. `0` is EOF — the Java
        // side closed the tun. Unlike kernel TUN (which never EOFs),
        // this
        // CAN happen (the Java VpnService stopped). C errors;
        // we match. The error message says what we know.
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("{} closed (VpnService stopped?)", self.device_label),
            ));
        }

        // Synthesize ethertype from IP version nibble, error on
        // unknown version.
        //
        // `buf[ETH_HLEN]` is byte 0 of the IP packet (we read
        // at offset 14, so byte 14 of buf is byte 0 of payload).
        // `from_ip_nibble` extracts.
        let Some(ethertype) = from_ip_nibble(buf[ETH_HLEN]) else {
            // The packet is dropped. We Err with the actual nibble
            // (more useful than the C's bare "unknown").
            //
            // Logged at DEBUG_TRAFFIC level upstream (only logs
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

        // Write the synthetic header into bytes 0..14.
        set_etherheader(buf, ethertype);

        // The 14 synthetic bytes count toward the packet length.
        Ok(n + ETH_HLEN)
    }

    /// The +14 write — strip the ethernet header, write the IP
    /// packet.
    ///
    /// Unlike `linux.rs` TUN write (which mutates `buf[10..12]`),
    /// this is a PURE write — the ethernet header just gets
    /// skipped. The trait signature is `&mut [u8]` for uniformity
    /// (the daemon calls through `dyn Device`, doesn't know which
    /// impl), but THIS impl doesn't mutate. The shared signature
    /// is the constraint.
    fn write(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        debug_assert!(
            buf.len() > ETH_HLEN,
            "fd write buf too short: {} <= {ETH_HLEN}",
            buf.len()
        );
        // Strip 14, write the rest.
        write_fd(self.fd.as_fd(), &buf[ETH_HLEN..])
    }

    /// TUN-only. The contract.
    fn mode(&self) -> Mode {
        Mode::Tun
    }

    /// `"fd"` placeholder. There's no TUNSETIFF here, so no kernel
    /// name. We say `"fd"` so the daemon's `tinc-up` script can at
    /// least pattern-match on `INTERFACE=`.
    ///
    /// `clippy::unnecessary_literal_bound`: trait signature says
    /// `&str`; impl can't widen. Same as Dummy.
    #[allow(clippy::unnecessary_literal_bound)] // trait method: can't return &'static str when trait says &str
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

impl AsFd for FdTun {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

// Tests — pure fns + pipe-based integration

#[cfg(test)]
mod tests {
    use super::*;

    // (Ethernet constant tests + nibble tests + set_etherheader
    // tests hoisted to `crate::ether::tests` with their subjects.
    // Same assertions; the diff is location.)

    // pipe-based integration — the win over linux.rs
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

    /// The full read flow: write IPv4 bytes to a pipe, `FdTun`
    /// reads at +14, synthesizes 0x0800 ethertype at +12,
    /// returns len+14.
    ///
    /// idiom.
    #[test]
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
        let mut tun = FdTun::open(FdSource::Inherited(r)).unwrap();

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

        let mut tun = FdTun::open(FdSource::Inherited(r)).unwrap();
        let mut buf = [0u8; MTU];
        let n = tun.read(&mut buf).unwrap();

        assert_eq!(n, 40 + ETH_HLEN);
        assert_eq!(&buf[0..12], &[0u8; 12]);
        assert_eq!(&buf[12..14], &[0x86, 0xDD]); // ← IPv6 ethertype
        assert_eq!(&buf[14..54], &ip_packet);
    }

    /// Unknown IP version → `InvalidData`.
    #[test]
    fn read_unknown_version_via_pipe() {
        let garbage = [0x50u8; 20]; // version=5 (ST-II, dead)

        let (r, w) = pipe();
        write_all(&w, &garbage);

        let mut tun = FdTun::open(FdSource::Inherited(r)).unwrap();
        let mut buf = [0u8; MTU];
        let e = tun.read(&mut buf).unwrap_err();

        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        let msg = e.to_string();
        // Our error includes the actual nibble (more useful
        // than C's bare "unknown").
        assert!(msg.contains("0x5"), "msg: {msg}");
    }

    /// EOF → `UnexpectedEof`. The Java `VpnService` stopped. C
    /// `:213` errors on `lenin <= 0`.
    #[test]
    fn read_eof_via_pipe() {
        let (r, w) = pipe();
        // Close the write end immediately. Next read returns 0.
        drop(w);

        let mut tun = FdTun::open(FdSource::Inherited(r)).unwrap();
        let mut buf = [0u8; MTU];
        let e = tun.read(&mut buf).unwrap_err();

        assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
        // Our error mentions the device label.
        let msg = e.to_string();
        assert!(msg.contains("fd/"), "msg: {msg}");
    }

    /// The write flow: hand `FdTun` a 14+20 byte buffer (ether +
    /// IP), it strips the 14, writes the 20.
    #[test]
    fn write_strips_ether_via_pipe() {
        let (r, w) = pipe();

        // FdTun owns the WRITE end this time.
        let mut tun = FdTun::open(FdSource::Inherited(w)).unwrap();

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

    // SCM_RIGHTS — round-trip with a real socketpair
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

    /// `SCM_RIGHTS` round-trip: send an fd through a socketpair,
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

        // Send: 1 byte payload (the receiver expects `iov_len=1`) +
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
        write_all(&received_w, b"ping");
        let mut got = [0u8; 4];
        let n = read_exact_n(&canary_r, &mut got, 4);
        assert_eq!(n, 4);
        assert_eq!(&got, b"ping");

        // Cleanup: drops close everything. The original
        // `canary_w` is still open (dup'd, not moved); both
        // it and `received_w` close on drop.
    }

    // Test plumbing — pipe helpers

    /// `pipe(2)`. Returns (read, write) as `OwnedFd` — drop closes.
    fn pipe() -> (OwnedFd, OwnedFd) {
        let mut fds = [0; 2];
        // SAFETY: `fds` is a 2-int buffer; pipe() writes exactly 2.
        #[allow(unsafe_code)]
        let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert_eq!(ret, 0, "pipe() failed: {}", io::Error::last_os_error());
        // SAFETY: pipe() returned 0; both fds are fresh and ours.
        #[allow(unsafe_code)]
        unsafe {
            (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1]))
        }
    }

    /// Write all bytes. Loop on short writes (pipes can short-
    /// write under pressure; our tiny test packets won't, but
    /// correctness).
    fn write_all(fd: &impl AsFd, buf: &[u8]) {
        let mut off = 0;
        while off < buf.len() {
            let ret = write_fd(fd.as_fd(), &buf[off..]).expect("write failed");
            assert!(ret > 0, "write failed");
            off += ret;
        }
    }

    /// Read exactly n bytes. Loop on short reads.
    fn read_exact_n(fd: &impl AsFd, buf: &mut [u8], n: usize) -> usize {
        let mut off = 0;
        while off < n {
            let ret = read_fd(fd.as_fd(), &mut buf[off..n]).expect("read failed");
            assert!(ret > 0, "read EOF");
            off += ret;
        }
        off
    }
}
