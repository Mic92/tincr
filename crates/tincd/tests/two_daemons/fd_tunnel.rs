use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// `socketpair(AF_UNIX, SOCK_SEQPACKET)`. SEQPACKET = datagram
/// boundaries (one read = one packet) on a connection-oriented unix
/// socket. Exactly the semantics a real TUN fd has.
///
/// Returns `(test_end, daemon_end)` as `OwnedFd`s with `O_NONBLOCK`
/// already set on both (every caller needs that: the daemon end
/// because `on_device_read` loops to `EAGAIN`, the test end because
/// `read_fd_nb` polls). Dropping an end closes it.
pub(crate) fn sockpair_seqpacket() -> (OwnedFd, OwnedFd) {
    let mut fds = [0i32; 2];
    // SAFETY: `socketpair` writes 2 ints. AF_UNIX/SOCK_SEQPACKET is
    // standard on Linux.
    let ret = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0, fds.as_mut_ptr()) };
    assert_eq!(ret, 0, "socketpair: {}", std::io::Error::last_os_error());
    // SAFETY: socketpair just handed us two fresh, open, owned fds.
    let (a, b) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    set_nonblocking(&a);
    set_nonblocking(&b);
    (a, b)
}

fn set_nonblocking(fd: &OwnedFd) {
    let fd = fd.as_raw_fd();
    // SAFETY: fcntl on a valid fd.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        assert!(flags >= 0);
        assert_eq!(libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK), 0);
    }
}

pub(crate) fn write_fd(fd: &OwnedFd, buf: &[u8]) {
    let fd = fd.as_raw_fd();
    // SAFETY: write(2) on a valid fd. SEQPACKET is one-shot (no
    // short writes for in-flight datagrams).
    let ret = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
    assert!(
        ret >= 0,
        "write fd={fd}: {}",
        std::io::Error::last_os_error()
    );
    #[allow(clippy::cast_sign_loss)] // guarded by ret >= 0 above
    let wrote = ret as usize;
    assert_eq!(wrote, buf.len(), "short write fd={fd}");
}

/// Non-blocking read; `None` on EAGAIN. The poll loop wraps this.
pub(crate) fn read_fd_nb(fd: &OwnedFd) -> Option<Vec<u8>> {
    let fd = fd.as_raw_fd();
    let mut buf = vec![0u8; 2048];
    // SAFETY: read(2) on a valid fd into our buffer.
    let ret = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if ret < 0 {
        let e = std::io::Error::last_os_error();
        if e.kind() == std::io::ErrorKind::WouldBlock {
            return None;
        }
        panic!("read fd={fd}: {e}");
    }
    assert!(ret != 0, "read fd={fd}: EOF (peer closed)");
    #[allow(clippy::cast_sign_loss)] // guarded by ret < 0 check above
    buf.truncate(ret as usize);
    Some(buf)
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
