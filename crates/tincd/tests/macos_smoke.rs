//! macOS real-utun smoke test.
//!
//! `two_daemons/*` runs on macOS but uses `DeviceType=fd` socketpair
//! — the `BsdTun` Utun read/write arms never execute. macOS has no
//! netns, so two real utuns would fight over one routing table; the
//! single-daemon unreachable path (mirrors
//! `netns/ping.rs::real_tun_unreachable`) still proves both halves:
//!
//!   - **read**: kernel writes `[4-byte AF prefix][IP]` at +10;
//!     nibble→ethertype synth; `route()` dispatches v4.
//!   - **write**: ethertype→`htonl(AF_INET)` prefix, write at +10.
//!     Kernel ICMP rcv is strict — bad checksum/prefix/quoted-hdr
//!     → silent drop → ping just says "100% packet loss". Ping
//!     printing the unreachable means the wire is correct.
//!
//! utun needs root; `scripts/macos-test-runner.sh` re-execs under
//! sudo when cached. Otherwise: SKIP.

#![cfg(target_os = "macos")]

#[path = "common/mod.rs"]
#[macro_use]
mod common;

use common::*;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;

/// High unit number to dodge VPN clients / leftover devices.
const IFACE: &str = "utun200";

fn write_utun_config(confbase: &std::path::Path) {
    std::fs::create_dir_all(confbase.join("hosts")).unwrap();
    std::fs::write(
        confbase.join("tinc.conf"),
        format!(
            "Name = smoketest\n\
             DeviceType = tun\n\
             AddressFamily = ipv4\n\
             Interface = {IFACE}\n"
        ),
    )
    .unwrap();
    // Own /32 only; the p2p peer (10.88.0.2) is unowned → route()
    // returns Unreachable.
    std::fs::write(
        confbase.join("hosts").join("smoketest"),
        "Port = 0\nSubnet = 10.88.0.1/32\n",
    )
    .unwrap();
    write_ed25519_privkey(confbase, &[0xAA; 32]);
}

#[test]
fn utun_icmp_unreachable() {
    if !nix::unistd::geteuid().is_root() {
        eprintln!("SKIP: utun_icmp_unreachable requires root");
        return;
    }

    let tmp = tmp!("unreach");
    let (confbase, pidfile, socket) = tmp.std_paths();
    write_utun_config(&confbase);

    // `tincd::net=debug` for the "unreachable, sending ICMP" line.
    let mut child = tincd_at(&confbase, &pidfile, &socket)
        .env("RUST_LOG", "tincd=info,tincd::net=debug")
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tincd");

    assert!(
        wait_for_file(&socket),
        "tincd didn't start; stderr:\n{}",
        drain_stderr(child)
    );

    // p2p config installs a host route for 10.88.0.2 via utun200.
    // No tinc-up script — inline so failures show ifconfig stderr.
    let ifc = Command::new("ifconfig")
        .args([IFACE, "10.88.0.1", "10.88.0.2", "up"])
        .output()
        .expect("spawn ifconfig");
    assert!(
        ifc.status.success(),
        "ifconfig {IFACE} failed (device not opened?); stderr: {}\n\
         daemon stderr:\n{}",
        String::from_utf8_lossy(&ifc.stderr),
        drain_stderr(child)
    );

    // `-t 2` = macOS ping wall-clock deadline (TTL is `-m`). One
    // echo is enough; the ICMP error is synchronous.
    let ping = Command::new("ping")
        .args(["-c", "1", "-t", "2", "10.88.0.2"])
        .output()
        .expect("spawn ping");

    let stdout = String::from_utf8_lossy(&ping.stdout);
    let stderr = String::from_utf8_lossy(&ping.stderr);
    eprintln!("ping stdout:\n{stdout}\nping stderr:\n{stderr}");

    assert!(
        !ping.status.success(),
        "ping should fail (no node owns 10.88.0.2); stdout: {stdout}"
    );
    // Kernel parsed our ICMP and matched it to ping's socket.
    // Without correct AF prefix / checksum this never appears.
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("nreachable") || combined.contains("Unknown"),
        "ping should surface the synthesized ICMP error \
         (proves utun write path); got:\n{combined}\n\
         daemon stderr:\n{}",
        drain_stderr(child)
    );

    // SIGTERM → clean shutdown after real traffic.
    #[expect(clippy::cast_possible_wrap)]
    let pid = Pid::from_raw(child.id() as i32);
    kill(pid, Signal::SIGTERM).expect("kill SIGTERM");

    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        assert!(Instant::now() < deadline, "tincd didn't exit on SIGTERM");
        std::thread::sleep(Duration::from_millis(10));
    };
    let out = child.wait_with_output().unwrap();
    let daemon_stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        daemon_stderr.contains("unreachable, sending ICMP"),
        "daemon should log the ICMP synth (proves utun read path); stderr:\n{daemon_stderr}"
    );
    assert!(status.success(), "tincd exit status: {status:?}");
    assert!(!pidfile.exists(), "pidfile should be cleaned up");
    assert!(!socket.exists(), "socket should be cleaned up");
}
