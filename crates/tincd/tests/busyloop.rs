//! Regression: a pre-ACK connect timeout leaked the poll registration
//! and spun the CPU. `ConnectTo` points at a local listener with a
//! saturated accept queue so the connect hangs (TEST-NET-1 gets ICMP
//! unreachable on many networks).

#[path = "common/mod.rs"]
#[macro_use]
mod common;

use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use common::*;

/// Loopback listener with backlog 0 and a saturated accept queue.
fn blackhole() -> (socket2::Socket, Vec<TcpStream>, SocketAddr) {
    let listener =
        socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
    listener
        .bind(&SocketAddr::from(([127, 0, 0, 1], 0)).into())
        .unwrap();
    listener.listen(0).unwrap();
    let addr = listener.local_addr().unwrap().as_socket().unwrap();
    // macOS rounds the backlog up (somaxconn default 128), so keep
    // connecting until the queue is actually full.
    let mut held = Vec::new();
    for _ in 0..1024 {
        match TcpStream::connect_timeout(&addr, Duration::from_millis(250)) {
            Ok(conn) => held.push(conn),
            Err(_) => break,
        }
    }
    (listener, held, addr)
}

#[test]
fn outgoing_timeout_no_busy_loop() {
    let tmp = tmp!("outgoing_timeout");
    let (_listener, _held, addr) = blackhole();
    let mut blackhole_peer = Node::new(tmp.path(), "blackhole", 0xDE);
    blackhole_peer.port = addr.port();
    let mut node = Node::new(tmp.path(), "testnode", 0x42).with_conf("PingTimeout = 2");
    node.write_config(&blackhole_peer, true);
    node.start();

    let deadline = Instant::now() + Duration::from_secs(15);
    while !node.log().contains("Timeout while connecting to blackhole") {
        assert!(
            Instant::now() < deadline,
            "no connect timeout:\n{}",
            node.log()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    std::thread::sleep(Duration::from_secs(3));
    node.signal(nix::sys::signal::Signal::SIGTERM);
    assert!(node.wait_exit().success(), "{}", node.log());
    // The daemon is this process's only reaped child (nextest runs a
    // process per test). Spinning for those 3s would show as ~3s CPU;
    // startup plus idle is well under half a second.
    let usage =
        nix::sys::resource::getrusage(nix::sys::resource::UsageWho::RUSAGE_CHILDREN).unwrap();
    let timeval = |tv: nix::sys::time::TimeVal| {
        Duration::new(
            tv.tv_sec().unsigned_abs(),
            u32::try_from(tv.tv_usec()).unwrap() * 1000,
        )
    };
    let cpu = timeval(usage.user_time()) + timeval(usage.system_time());
    assert!(cpu < Duration::from_secs(1), "{cpu:?} CPU:\n{}", node.log());
}
