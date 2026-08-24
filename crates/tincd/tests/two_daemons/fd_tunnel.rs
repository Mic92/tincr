use std::os::fd::{AsRawFd, OwnedFd};

use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};

/// `socketpair` with datagram semantics (one write = one read),
/// faking a TUN fd. `SEQPACKET` on Linux, `DGRAM` on macOS (no
/// `SEQPACKET` for `AF_UNIX`). Both ends set `O_NONBLOCK`.
pub(crate) fn sockpair_datagram() -> (OwnedFd, OwnedFd) {
    #[cfg(target_os = "linux")]
    let sock_type = SockType::SeqPacket;
    #[cfg(not(target_os = "linux"))]
    let sock_type = SockType::Datagram;

    let (a, b) =
        socketpair(AddressFamily::Unix, sock_type, None, SockFlag::empty()).expect("socketpair");
    for fd in [&a, &b] {
        let flags = nix::fcntl::OFlag::from_bits_retain(
            nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_GETFL).expect("fcntl F_GETFL"),
        );
        nix::fcntl::fcntl(
            fd,
            nix::fcntl::FcntlArg::F_SETFL(flags | nix::fcntl::OFlag::O_NONBLOCK),
        )
        .expect("fcntl F_SETFL O_NONBLOCK");
    }
    (a, b)
}

pub(crate) fn write_fd(fd: &OwnedFd, buf: &[u8]) {
    // Datagram sockets are one-shot (no short writes for in-flight datagrams).
    let wrote =
        nix::unistd::write(fd, buf).unwrap_or_else(|e| panic!("write fd={}: {e}", fd.as_raw_fd()));
    assert_eq!(wrote, buf.len(), "short write fd={}", fd.as_raw_fd());
}

/// Non-blocking read; `None` on EAGAIN. The poll loop wraps this.
pub(crate) fn read_fd_nb(fd: &OwnedFd) -> Option<Vec<u8>> {
    let raw = fd.as_raw_fd();
    let mut buf = vec![0u8; 2048];
    match nix::unistd::read(fd, &mut buf) {
        Ok(0) => panic!("read fd={raw}: EOF (peer closed)"),
        Ok(n) => {
            buf.truncate(n);
            Some(buf)
        }
        Err(nix::errno::Errno::EAGAIN) => None,
        Err(e) => panic!("read fd={raw}: {e}"),
    }
}

/// Minimal IPv4 packet: 20-byte header + payload. Only the fields
/// `route_ipv4` reads (version nibble for `FdTun`'s ethertype synth,
/// dst addr for the subnet lookup). Checksum/len are filled but
/// nothing checks them (`route_ipv4` doesn't, and the packet never
/// hits a kernel IP stack).
pub(crate) fn mk_ipv4_pkt(src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let total_len = u16::try_from(20 + payload.len()).expect("payload too big for IPv4");
    let mut p = Vec::with_capacity(20 + payload.len());
    p.push(0x45); // version=4, IHL=5
    p.push(0); // DSCP/ECN
    p.extend_from_slice(&total_len.to_be_bytes());
    p.extend_from_slice(&[0, 0]); // ident
    p.extend_from_slice(&[0, 0]); // flags+fragoff
    p.push(64); // TTL
    p.push(17); // proto (UDP, arbitrary)
    p.extend_from_slice(&[0, 0]); // checksum (don't care)
    p.extend_from_slice(&src);
    p.extend_from_slice(&dst);
    p.extend_from_slice(payload);
    p
}

use std::time::Duration;

use super::common::node::Node;
use super::common::{node_status, poll_until};

/// alice (10.0.0.1) dials bob (10.0.0.2), both on socketpair devices.
pub(crate) struct FdPair {
    pub alice: Node,
    pub bob: Node,
    pub alice_dev: OwnedFd,
    pub bob_dev: OwnedFd,
    daemon_ends: Option<(OwnedFd, OwnedFd)>,
}

impl FdPair {
    /// Configs written, bob started (alice needs his port), alice not
    /// yet — so callers can drop scripts into her confbase first.
    pub(crate) fn new(dir: &std::path::Path, alice_conf: &str, bob_conf: &str) -> Self {
        let (alice_dev, alice_daemon_end) = sockpair_datagram();
        let (bob_dev, bob_daemon_end) = sockpair_datagram();
        let alice = Node::new(dir, "alice", 0xA7)
            .with_conf(alice_conf)
            .fd(alice_daemon_end.as_raw_fd())
            .subnet("10.0.0.1/32");
        let mut bob = Node::new(dir, "bob", 0xB7)
            .with_conf(bob_conf)
            .fd(bob_daemon_end.as_raw_fd())
            .subnet("10.0.0.2/32");
        bob.write_config(&alice, false);
        bob.start_with_fd(&bob_daemon_end);
        alice.write_config(&bob, true);
        Self {
            alice,
            bob,
            alice_dev,
            bob_dev,
            daemon_ends: Some((alice_daemon_end, bob_daemon_end)),
        }
    }

    /// Start alice and wait until both see each other reachable.
    pub(crate) fn start(mut self) -> Self {
        let (alice_daemon_end, _bob_daemon_end) = self.daemon_ends.take().unwrap();
        self.alice.start_with_fd(&alice_daemon_end);
        drop(alice_daemon_end);
        self.wait_status(0x10, "reachable");
        self
    }

    pub(crate) fn logs(&self) -> String {
        format!(
            "=== alice ===\n{}\n=== bob ===\n{}",
            self.alice.log(),
            self.bob.log()
        )
    }

    fn wait_status(&self, bit: u32, what: &str) {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let alice_ok =
                node_status(&self.alice.ctl().dump(3), "bob").is_some_and(|s| s & bit != 0);
            let bob_ok =
                node_status(&self.bob.ctl().dump(3), "alice").is_some_and(|s| s & bit != 0);
            if alice_ok && bob_ok {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "not {what};\n{}",
                self.logs()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Nothing is buffered before validkey: the first packet only
    /// triggers `REQ_KEY` (and reaches bob over the meta connection).
    /// Send one, wait for the key, and drain it from bob's side.
    pub(crate) fn establish_udp_key(&self) {
        let kick = mk_ipv4_pkt([10, 0, 0, 1], [10, 0, 0, 2], b"kick");
        write_fd(&self.alice_dev, &kick);
        self.wait_status(0x02, "validkey");
        assert_eq!(
            poll_until(Duration::from_secs(5), || read_fd_nb(&self.bob_dev)),
            kick
        );
    }

    pub(crate) fn alice_to_bob(&self, payload: &[u8]) -> Vec<u8> {
        let packet = mk_ipv4_pkt([10, 0, 0, 1], [10, 0, 0, 2], payload);
        write_fd(&self.alice_dev, &packet);
        assert_eq!(
            poll_until(Duration::from_secs(5), || read_fd_nb(&self.bob_dev)),
            packet
        );
        packet
    }

    pub(crate) fn bob_to_alice(&self, payload: &[u8]) {
        let packet = mk_ipv4_pkt([10, 0, 0, 2], [10, 0, 0, 1], payload);
        write_fd(&self.bob_dev, &packet);
        assert_eq!(
            poll_until(Duration::from_secs(5), || read_fd_nb(&self.alice_dev)),
            packet
        );
    }
}
