use std::os::fd::{AsRawFd, OwnedFd};

use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};

/// `socketpair(AF_UNIX, SOCK_SEQPACKET)`. SEQPACKET = datagram
/// boundaries (one read = one packet) on a connection-oriented unix
/// socket. Exactly the semantics a real TUN fd has.
///
/// Returns `(test_end, daemon_end)` as `OwnedFd`s with `O_NONBLOCK`
/// already set on both (every caller needs that: the daemon end
/// because `on_device_read` loops to `EAGAIN`, the test end because
/// `read_fd_nb` polls). Dropping an end closes it.
pub(crate) fn sockpair_seqpacket() -> (OwnedFd, OwnedFd) {
    socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_NONBLOCK,
    )
    .expect("socketpair")
}

pub(crate) fn write_fd(fd: &OwnedFd, buf: &[u8]) {
    // SEQPACKET is one-shot (no short writes for in-flight datagrams).
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
