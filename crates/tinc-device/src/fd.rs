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
//! `SCM_RIGHTS` goes through `nix::sys::socket::recvmsg` — hand-
//! rolled `cmsghdr` walking has a `CMSG_FIRSTHDR`-returns-NULL trap
//! that the safe wrapper avoids.

use std::fs::File;
use std::io::{self, IoSliceMut};
use std::os::unix::io::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;

use crate::ether::{ETH_HLEN, from_ip_nibble, set_etherheader};
use crate::{Device, MTU, Mac, Mode, assert_read_buf, read_fd, write_fd};

// FdSource — the union type the config-string dispatch implies

/// The two ways the fd reaches us. The daemon parses the config
/// string (`sscanf("%d")` to detect a bare integer); we get the
/// resolved variant.
#[derive(Debug)]
pub enum FdSource {
    /// `Device = 5` mode (2017): fd inherited across `exec()`.
    /// `OwnedFd` not `RawFd` so the single `from_raw_fd` lives at
    /// the daemon's parse site, which alone can vouch for ownership.
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
            FdSource::Inherited(fd) => {
                let raw = fd.as_raw_fd();
                (File::from(fd), format!("fd/{raw}"))
            }
            FdSource::UnixSocket(path) => {
                let fd = recv_scm_rights(&path)?;
                (File::from(fd), format!("fd:{}", path.display()))
            }
        };
        Ok(FdTun { fd, device_label })
    }
}

// SCM_RIGHTS — the fourth unsafe shim, the first to USE nix

/// Connect to the Unix socket, receive one fd via `SCM_RIGHTS`.
fn recv_scm_rights(path: &Path) -> io::Result<OwnedFd> {
    let stream = connect_unix(path)?;
    // Dropping `stream` doesn't affect the SCM_RIGHTS dup.
    recv_one_fd(&stream)
}

/// Receive exactly one fd via `SCM_RIGHTS` on an already-connected
/// socket. Factored out so the test can drive it on a `socketpair`
/// without the `connect_unix` step.
fn recv_one_fd(stream: &impl AsRawFd) -> io::Result<OwnedFd> {
    use nix::sys::socket::{ControlMessageOwned, MsgFlags, recvmsg};

    // 1-byte iov: the Java sender writes one payload byte alongside
    // the fd cmsg, and the C `:56` `ret <= 0` check requires it.
    let mut iobuf = [0u8; 1];
    let mut iov = [IoSliceMut::new(&mut iobuf)];

    // Control buffer sized for one fd.
    let mut cmsgbuf = nix::cmsg_space!(RawFd);

    // Blocking recv is correct: the Java side sends immediately on
    // accept. `()` address type — we connected, so sender is known.
    let msg = recvmsg::<()>(
        stream.as_raw_fd(),
        &mut iov,
        Some(&mut cmsgbuf),
        MsgFlags::empty(),
    )?;

    // `MSG_CTRUNC` = control data truncated (sender shipped >1 fd
    // and our cmsgbuf was sized for one). `MSG_OOB`/`MSG_ERRQUEUE`
    // can't happen on a Unix socket; checked to match C, zero cost.
    let bad = MsgFlags::MSG_CTRUNC | MsgFlags::MSG_OOB | MsgFlags::MSG_ERRQUEUE;
    if msg.flags.intersects(bad) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("recvmsg flags indicate trouble: {:?}", msg.flags),
        ));
    }

    if msg.bytes == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "Unix socket peer closed before sending fd",
        ));
    }

    // Accept exactly one fd. STRICTER than C: 2+ fds is an error,
    // not "silently take the first".
    let fds = msg
        .cmsgs()?
        .find_map(|cm| match cm {
            ControlMessageOwned::ScmRights(fds) => Some(fds),
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
        .map(|fd| unsafe { <OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd) })
        .collect();

    // Exactly one. The Java side sends one tun fd; that's the
    // contract. Multiple would be a bug on their side.
    if fds.len() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected exactly 1 fd via SCM_RIGHTS, got {}", fds.len()),
        ));
    }

    Ok(fds.pop().unwrap())
}

/// The `@` → abstract-namespace dispatch. Split out for testability.
fn connect_unix(path: &Path) -> io::Result<UnixStream> {
    let bytes = path.as_os_str().as_encoded_bytes();
    if matches!(bytes.first(), Some(b'@')) {
        // Abstract namespace: std adds the leading NUL, so strip `@`.
        use std::os::linux::net::SocketAddrExt;
        use std::os::unix::net::SocketAddr;
        let addr = SocketAddr::from_abstract_name(&bytes[1..])?;
        UnixStream::connect_addr(&addr)
    } else {
        UnixStream::connect(path)
    }
}

// Device impl — the +14 read/write

impl Device for FdTun {
    /// The +14 read + ethertype synthesis.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        assert_read_buf(buf, "fd");

        // Read at +14, leaving room for the synthetic eth header.
        let n = read_fd(self.fd.as_fd(), &mut buf[ETH_HLEN..MTU])?;

        // EOF is real here (unlike kernel TUN): the Java VpnService
        // closed its end.
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("{} closed (VpnService stopped?)", self.device_label),
            ));
        }

        let Some(ethertype) = from_ip_nibble(buf[ETH_HLEN]) else {
            // Include the actual nibble (C's message is bare
            // "unknown"); daemon decides whether to log it.
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

        set_etherheader(buf, ethertype);
        Ok(n + ETH_HLEN)
    }

    /// +14 write — skip the synthetic eth header. Doesn't actually
    /// mutate `buf`; the `&mut` is the `dyn Device` shared signature
    /// (linux TUN write does mutate).
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

    /// `"fd"` placeholder — no TUNSETIFF here, so no kernel name.
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
    fn fd(&self) -> Option<BorrowedFd<'_>> {
        Some(self.fd.as_fd())
    }
}

// Tests — pure fns + pipe-based integration

#[cfg(test)]
mod tests {
    use super::*;

    // pipe-based integration: this backend reads raw IP (no kernel-
    // side layout to fake), so a `pipe()` is enough to exercise the
    // +14 offset arithmetic and ethertype synthesis.

    /// Write IPv4 bytes to a pipe, `FdTun` reads at +14, synthesizes
    /// 0x0800 ethertype at +12, returns len+14.
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

    /// `SCM_RIGHTS` round-trip via the production `recv_one_fd`
    /// path: send an fd through a socketpair, receive it, verify
    /// the dup points at the same open file description.
    #[test]
    fn scm_rights_round_trip() {
        use nix::sys::socket::{
            AddressFamily, ControlMessage, MsgFlags, SockFlag, SockType, sendmsg, socketpair,
        };
        use std::io::IoSlice;

        let (snd, rcv) = socketpair(
            AddressFamily::Unix,
            SockType::Stream,
            None,
            SockFlag::empty(),
        )
        .unwrap();

        // The fd we'll ship: a pipe write-end.
        let (canary_r, canary_w) = pipe();

        // Send: 1 byte payload (receiver expects iov_len=1) +
        // SCM_RIGHTS cmsg with one fd.
        let iov = [IoSlice::new(b"X")];
        let fds = [canary_w.as_raw_fd()];
        let cmsg = ControlMessage::ScmRights(&fds);
        sendmsg::<()>(snd.as_raw_fd(), &iov, &[cmsg], MsgFlags::empty(), None).unwrap();

        // Receive via the production cmsghdr handling.
        let received_w = recv_one_fd(&rcv).unwrap();

        // Write through the RECEIVED fd, read from the canary pipe:
        // proves the dup points at the same file description.
        write_all(&received_w, b"ping");
        let mut got = [0u8; 4];
        let n = read_exact_n(&canary_r, &mut got, 4);
        assert_eq!(n, 4);
        assert_eq!(&got, b"ping");
    }

    // Test plumbing — pipe helpers

    /// `pipe(2)`. Returns (read, write) as `OwnedFd` — drop closes.
    fn pipe() -> (OwnedFd, OwnedFd) {
        nix::unistd::pipe().expect("pipe() failed")
    }

    /// Write all bytes (loop on short writes).
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
