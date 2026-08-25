//! Kernel steering: `SO_REUSEPORT` cBPF picks the socket from the
//! packet's src id6, and multiqueue TUN (automq) sends a flow to the
//! queue we last wrote it from. No daemon; just the kernel and the
//! `tincd::shard::bpf` / `tinc_device` openers inside bwrap.

use std::io::Read;
use std::net::IpAddr;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

use tinc_device::{Device, DeviceConfig, Mode, Tun, VNET_HDR_LEN};
use tincd::shard::bpf::{open_reuseport_group, tunsetsteeringebpf};

use super::common::linux::run_ip;
use super::rig::enter_bwrap;
use std::io;
use std::net;
use std::net::Ipv4Addr;
use std::net::Shutdown;
use std::net::TcpListener;
use std::net::TcpStream;
use std::net::UdpSocket;
use std::thread;
use std::thread::JoinHandle;

/// The attached program is `ntohl(*(u32*)(payload+6)) % N`, i.e. the
/// first four bytes of `src_id6` in `[dst_id6][src_id6]...`. With those
/// bytes `[0,0,0,i]` packet `i` must land on socket `i % N`; the
/// remaining id6 bytes are non-zero to show they are not read.
#[test]
fn cbpf_steers_by_src_id6() {
    const SOCKETS: u32 = 4;
    const PORT: u16 = 17777;
    const PACKETS: u8 = 100;
    if !enter_bwrap("bpf_steer::cbpf_steers_by_src_id6") {
        return;
    }

    let group = open_reuseport_group(IpAddr::V4(Ipv4Addr::LOCALHOST), PORT, SOCKETS)
        .expect("open_reuseport_group");
    assert_eq!(group.socks.len(), SOCKETS as usize);

    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    sender.connect(("127.0.0.1", PORT)).unwrap();
    for i in 0..PACKETS {
        let mut packet = [0u8; 13];
        packet[0..6].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE]);
        packet[6..12].copy_from_slice(&[0, 0, 0, i, 0xAA, 0xBB]);
        packet[12] = i;
        sender.send(&packet).unwrap();
    }
    thread::sleep(Duration::from_millis(50));

    let mut total = 0;
    let mut misrouted = Vec::new();
    let mut buf = [0u8; 64];
    for (index, sock) in group.socks.iter().enumerate() {
        // Non-blocking: Err(EAGAIN) once drained.
        while let Ok(len) = nix::sys::socket::recv(
            sock.as_raw_fd(),
            &mut buf,
            nix::sys::socket::MsgFlags::empty(),
        ) {
            if len == 0 {
                break;
            }
            total += 1;
            let expected = (u32::from(buf[9]) % SOCKETS) as usize;
            if expected != index {
                misrouted.push((buf[9], index, expected));
            }
        }
    }
    assert_eq!(total, usize::from(PACKETS), "lost packets");
    assert!(
        misrouted.is_empty(),
        "(steering byte, got socket, expected): {misrouted:?}"
    );
}

/// One TUN, no peer: 10.77.0.0/24 is routed into it and a userspace
/// echo swaps IPv4 src/dst and TCP ports (checksums are invariant
/// under that) so a listener on .1 and a connect to .2 talk to each
/// other. The echo reads from both queues but writes to
/// `write_queue` (or back to the queue it read from if `None`), which
/// is what teaches the kernel's flow table.
struct HairpinEcho {
    stop: Arc<AtomicBool>,
    reads_per_queue: Arc<[AtomicU32; 2]>,
    thread: Option<JoinHandle<()>>,
}

impl HairpinEcho {
    fn spawn(queues: &[Tun], write_queue: Option<usize>) -> Self {
        let queues: Vec<OwnedFd> = queues
            .iter()
            .map(|queue| nix::unistd::dup(queue.fd().unwrap()).unwrap())
            .collect();
        let stop = Arc::new(AtomicBool::new(false));
        let reads_per_queue = Arc::new([AtomicU32::new(0), AtomicU32::new(0)]);
        let thread = {
            let stop = stop.clone();
            let reads_per_queue = reads_per_queue.clone();
            thread::spawn(move || {
                let mut buf = vec![0u8; 70_000];
                while !stop.load(Ordering::Relaxed) {
                    for (index, fd) in queues.iter().enumerate() {
                        let Ok(len) = nix::unistd::read(fd.as_fd(), &mut buf) else {
                            continue;
                        };
                        let ip = VNET_HDR_LEN;
                        // Skip IPv6 chatter from link-up.
                        if len < ip + 20 || buf[ip] >> 4 != 4 {
                            continue;
                        }
                        reads_per_queue[index].fetch_add(1, Ordering::Relaxed);
                        let (src, dst) = buf[ip + 12..ip + 20].split_at_mut(4);
                        src.swap_with_slice(dst);
                        let tcp = ip + usize::from(buf[ip] & 0x0F) * 4;
                        if tcp + 4 <= len {
                            let (sport, dport) = buf[tcp..tcp + 4].split_at_mut(2);
                            sport.swap_with_slice(dport);
                        }
                        let out = &queues[write_queue.unwrap_or(index)];
                        let _ = nix::unistd::write(out, &buf[..len]);
                    }
                    thread::sleep(Duration::from_micros(50));
                }
            })
        };
        Self {
            stop,
            reads_per_queue,
            thread: Some(thread),
        }
    }

    fn counts(&self) -> [u32; 2] {
        [0, 1].map(|index| self.reads_per_queue[index].load(Ordering::Relaxed))
    }
}

impl Drop for HairpinEcho {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn open_tun_mq(iface: &str) -> Vec<Tun> {
    let config = DeviceConfig {
        iface: Some(iface.to_owned()),
        mode: Mode::Tun,
        ..DeviceConfig::default()
    };
    let queues = Tun::open_mq(&config, 2).expect("open_mq(2)");
    // No-op on a fresh device; exercises the detach the daemon does.
    tunsetsteeringebpf(queues[0].fd().unwrap(), -1).expect("detach steering prog");
    run_ip(&["addr", "add", "10.77.0.1/24", "dev", iface]);
    run_ip(&["link", "set", iface, "up"]);
    queues
}

/// Push `bytes` over TCP from a connect to .2:`port` into a listener on
/// .1:`port` through the hairpin.
fn drive_tcp(port: u16, bytes: usize) {
    let listener = TcpListener::bind(("10.77.0.1", port)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let acceptor = {
        let stop = stop.clone();
        thread::spawn(move || {
            let mut buf = [0u8; 8192];
            while !stop.load(Ordering::Relaxed) {
                if let Ok((mut stream, _)) = listener.accept() {
                    let _ = stream.set_nonblocking(false);
                    while stream.read(&mut buf).is_ok_and(|len| len > 0) {}
                }
                thread::sleep(Duration::from_millis(5));
            }
        })
    };
    thread::sleep(Duration::from_millis(50));
    let mut stream = TcpStream::connect_timeout(
        &net::SocketAddr::from(([10, 77, 0, 2], port)),
        Duration::from_secs(3),
    )
    .expect("TCP handshake through hairpin");
    let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));
    let _ = io::Write::write_all(&mut stream, &vec![0xABu8; bytes]);
    thread::sleep(Duration::from_millis(150));
    let _ = stream.shutdown(Shutdown::Both);
    stop.store(true, Ordering::Relaxed);
    acceptor.join().unwrap();
}

/// Echo always writes via queue 1, so after each flow's first
/// round-trip the kernel must deliver it on queue 1. The threshold
/// leaves room for those cold SYN/SYN-ACKs landing on `hash % 2`.
#[test]
fn automq_learns_from_write() {
    if !enter_bwrap("bpf_steer::automq_learns_from_write") {
        return;
    }
    let queues = open_tun_mq("steer0");
    let echo = HairpinEcho::spawn(&queues, Some(1));
    drive_tcp(19991, 64 * 1024);
    // TSO collapses 64K into few segments; a second flow pads the
    // sample.
    drive_tcp(19994, 256 * 1024);
    thread::sleep(Duration::from_millis(100));
    let [on_queue0, on_queue1] = echo.counts();
    drop(echo);

    let total = on_queue0 + on_queue1;
    assert!(total >= 30, "too few packets ({total})");
    let fraction = f64::from(on_queue1) / f64::from(total);
    assert!(fraction > 0.85, "queue 1 got {on_queue1}/{total}");
}

/// Echo writes back on the queue it read from (what a shard does).
/// Each fresh flow's first packet lands anywhere, after that it must
/// stick to that queue.
#[test]
fn automq_cold_miss_converges() {
    if !enter_bwrap("bpf_steer::automq_cold_miss_converges") {
        return;
    }
    let queues = open_tun_mq("steer1");
    let echo = HairpinEcho::spawn(&queues, None);
    drive_tcp(19992, 32 * 1024);
    let flow_a = echo.counts();
    drive_tcp(19993, 32 * 1024);
    thread::sleep(Duration::from_millis(100));
    let total = echo.counts();
    drop(echo);
    let flow_b = [total[0] - flow_a[0], total[1] - flow_a[1]];

    for (label, [on_queue0, on_queue1]) in [("A", flow_a), ("B", flow_b)] {
        let total = on_queue0 + on_queue1;
        assert!(total >= 10, "flow {label}: too few packets ({total})");
        let dominant = f64::from(on_queue0.max(on_queue1)) / f64::from(total);
        assert!(
            dominant > 0.90,
            "flow {label} not sticky: q0={on_queue0} q1={on_queue1}"
        );
    }
}
