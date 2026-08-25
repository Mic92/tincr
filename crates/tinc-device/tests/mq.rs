//! `Tun::open_mq`: N queues with `IFF_VNET_HDR` armed on all of them.
//!
//! One TUN in a bwrap netns, no peer. Traffic to 10.77.0.2 is routed
//! into the TUN; an echo thread swaps IPv4 src/dst and TCP ports
//! (checksums are invariant under that) and writes it back, so a local
//! TCP listener and connector talk to each other through the device and
//! the kernel emits checksum-offloaded and TSO frames.

#![cfg(target_os = "linux")]

use std::io::Read;
use std::os::fd::{AsFd, OwnedFd};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use std::env;
use std::fs;
use std::io;
use std::net::Shutdown;
use std::net::TcpListener;
use std::net::TcpStream;
use std::path::Path;
use std::thread;
use std::thread::JoinHandle;
use tinc_device::{Device, DeviceConfig, Mode, Tun, VNET_HDR_LEN};

const GSO_NONE: u8 = 0;
const GSO_TCPV4: u8 = 1;

/// See `tincd/tests/netns/rig.rs` for the flag rationale; copied
/// because test helpers cannot be shared across crates.
fn enter_netns(test_name: &str) -> bool {
    if env::var_os("BWRAP_INNER").is_some() {
        run_ip(&["link", "set", "lo", "up"]);
        return true;
    }
    let probe = Command::new("bwrap")
        .args(["--unshare-user", "--bind", "/", "/", "true"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output();
    match probe {
        Err(e) => {
            eprintln!("SKIP {test_name}: bwrap not found ({e})");
            return false;
        }
        Ok(out) if !out.status.success() => {
            eprintln!(
                "SKIP {test_name}: bwrap probe failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
            return false;
        }
        Ok(_) => {}
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!("SKIP {test_name}: /dev/net/tun missing");
        return false;
    }
    let self_exe = fs::read_link("/proc/self/exe").unwrap();
    let status = Command::new("bwrap")
        .args(["--unshare-net", "--unshare-user"])
        .args(["--cap-add", "CAP_NET_ADMIN", "--cap-add", "CAP_NET_RAW"])
        .args(["--uid", "0", "--gid", "0"])
        .args(["--bind", "/", "/", "--tmpfs", "/dev"])
        .args(["--dev-bind", "/dev/net/tun", "/dev/net/tun"])
        .args(["--dev-bind", "/dev/null", "/dev/null"])
        .args(["--dev-bind", "/dev/urandom", "/dev/urandom"])
        .args(["--proc", "/proc", "--tmpfs", "/run"])
        .args(if Path::new("/run/current-system").exists() {
            &["--ro-bind", "/run/current-system", "/run/current-system"][..]
        } else {
            &[]
        })
        .arg("--")
        .arg(self_exe)
        .args(["--exact", test_name, "--nocapture", "--test-threads=1"])
        .env("BWRAP_INNER", "1")
        .status()
        .expect("spawn bwrap");
    assert!(status.success(), "inner test failed: {status:?}");
    false
}

fn run_ip(args: &[&str]) {
    let status = Command::new("ip").args(args).status().expect("spawn ip");
    assert!(status.success(), "ip {args:?}: {status:?}");
}

fn config(iface: &str) -> DeviceConfig {
    DeviceConfig {
        iface: Some(iface.to_owned()),
        mode: Mode::Tun,
        ..DeviceConfig::default()
    }
}

/// `(gso_type, gso_size, csum_start, ip_version, frame_len)` per frame.
type Capture = Arc<Mutex<Vec<(u8, u16, u16, u8, usize)>>>;

fn spawn_echo(fds: Vec<OwnedFd>, stop: Arc<AtomicBool>, capture: Capture) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut buf = vec![0u8; 70_000];
        while !stop.load(Ordering::Relaxed) {
            for fd in &fds {
                let Ok(len) = nix::unistd::read(fd.as_fd(), &mut buf) else {
                    continue;
                };
                if len < VNET_HDR_LEN + 20 {
                    continue;
                }
                let ip_version = buf[VNET_HDR_LEN] >> 4;
                capture.lock().unwrap().push((
                    buf[1],
                    u16::from_le_bytes([buf[4], buf[5]]),
                    u16::from_le_bytes([buf[6], buf[7]]),
                    ip_version,
                    len,
                ));
                if ip_version != 4 {
                    continue;
                }
                let ip = VNET_HDR_LEN;
                let mut addr = [0u8; 4];
                addr.copy_from_slice(&buf[ip + 12..ip + 16]);
                buf.copy_within(ip + 16..ip + 20, ip + 12);
                buf[ip + 16..ip + 20].copy_from_slice(&addr);
                let tcp = ip + usize::from(buf[ip] & 0x0F) * 4;
                if tcp + 4 <= len {
                    let mut port = [0u8; 2];
                    port.copy_from_slice(&buf[tcp..tcp + 2]);
                    buf.copy_within(tcp + 2..tcp + 4, tcp);
                    buf[tcp + 2..tcp + 4].copy_from_slice(&port);
                }
                let _ = nix::unistd::write(fd, &buf[..len]);
            }
            thread::sleep(Duration::from_micros(100));
        }
    })
}

/// A misplaced or missing vnet header would put garbage in the IP
/// version nibble; an all-zero one would show no checksum offload.
/// TSO frames depend on timing and are not required.
#[test]
fn mq_vnet_hdr_on_all_queues() {
    if !enter_netns("mq_vnet_hdr_on_all_queues") {
        return;
    }
    let queues = Tun::open_mq(&config("shard0"), 4).expect("open_mq");
    assert_eq!(queues.len(), 4);
    run_ip(&["addr", "add", "10.77.0.1/24", "dev", "shard0"]);
    run_ip(&["link", "set", "shard0", "up"]);

    // Duplicates, so dropping `queues` and the echo thread are independent.
    let echo_fds = queues
        .iter()
        .map(|queue| nix::unistd::dup(queue.fd().unwrap()).unwrap())
        .collect();
    let stop = Arc::new(AtomicBool::new(false));
    let capture = Capture::default();
    let echo = spawn_echo(echo_fds, stop.clone(), capture.clone());

    let listener = TcpListener::bind("10.77.0.1:19999").unwrap();
    listener.set_nonblocking(true).unwrap();
    let listener_stop = stop.clone();
    let listener_thread = thread::spawn(move || {
        let mut buf = [0u8; 8192];
        while !listener_stop.load(Ordering::Relaxed) {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = stream.set_nonblocking(false);
                while stream.read(&mut buf).is_ok_and(|n| n > 0) {}
            }
            thread::sleep(Duration::from_millis(10));
        }
    });

    thread::sleep(Duration::from_millis(100));
    if let Ok(mut stream) =
        TcpStream::connect_timeout(&"10.77.0.2:19999".parse().unwrap(), Duration::from_secs(3))
    {
        let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));
        let _ = io::Write::write_all(&mut stream, &vec![0xAB; 64 * 1024]);
        thread::sleep(Duration::from_millis(200));
        let _ = stream.shutdown(Shutdown::Write);
        thread::sleep(Duration::from_millis(100));
    }
    stop.store(true, Ordering::Relaxed);
    echo.join().unwrap();
    listener_thread.join().unwrap();
    drop(queues);

    let capture = capture.lock().unwrap();
    assert!(!capture.is_empty(), "no frames on any queue");
    let mut offload_seen = false;
    for &(gso_type, gso_size, csum_start, ip_version, len) in capture.iter() {
        assert!(
            ip_version == 4 || ip_version == 6,
            "vnet_hdr misplaced: {ip_version}"
        );
        offload_seen |= gso_type == GSO_NONE && (20..=60).contains(&csum_start);
        offload_seen |= gso_type == GSO_TCPV4 && gso_size > 0 && len > 1600;
    }
    assert!(offload_seen, "vnet_hdr always zero: {capture:?}");
}

/// The n = 1 branch is plain `Tun::open`; that it does not set
/// `IFF_MULTI_QUEUE` is a unit test, here only that it works.
#[test]
fn mq_one_queue_is_plain_open() {
    if !enter_netns("mq_one_queue_is_plain_open") {
        return;
    }
    assert_eq!(Tun::open_mq(&config("shard1"), 1).unwrap().len(), 1);
}
