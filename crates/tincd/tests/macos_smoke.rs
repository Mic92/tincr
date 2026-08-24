//! macOS real-utun smoke test. `two_daemons/*` uses `DeviceType = fd`
//! there, so this single-daemon unreachable path is what exercises the
//! utun AF-prefix read and write arms: the kernel only turns our
//! synthesized ICMP into a ping error if prefix and checksums are
//! right. Needs root (`scripts/macos-test-runner.sh` re-execs under
//! sudo); otherwise SKIP.

#![cfg(target_os = "macos")]

#[path = "common/mod.rs"]
#[macro_use]
mod common;

use common::*;
use std::process::Command;

use nix::sys::signal::Signal;

/// High unit number to dodge VPN clients / leftover devices.
const IFACE: &str = "utun200";

#[test]
fn utun_icmp_unreachable() {
    if !nix::unistd::geteuid().is_root() {
        eprintln!("SKIP: utun_icmp_unreachable requires root");
        return;
    }
    let tmp = tmp!("unreach");
    // Owns 10.88.0.1 only, so the p2p peer address is unowned.
    let mut node = Node::new(tmp.path(), "smoketest", 0xAA)
        .iface(IFACE)
        .subnet("10.88.0.1/32")
        .log_level("tincd=info,tincd::net=debug");
    node.write_config_multi(&[], &[]);
    node.start();

    // p2p config installs a host route for 10.88.0.2 via the utun.
    let ifconfig = Command::new("ifconfig")
        .args([IFACE, "10.88.0.1", "10.88.0.2", "up"])
        .output()
        .expect("spawn ifconfig");
    assert!(
        ifconfig.status.success(),
        "ifconfig: {}\ndaemon:\n{}",
        String::from_utf8_lossy(&ifconfig.stderr),
        node.stop()
    );

    // `-t` is the deadline on macOS ping.
    let ping = Command::new("ping")
        .args(["-c", "1", "-t", "2", "10.88.0.2"])
        .output()
        .expect("spawn ping");
    let output = String::from_utf8_lossy(&ping.stdout) + String::from_utf8_lossy(&ping.stderr);
    assert!(!ping.status.success(), "{output}");
    assert!(
        output.contains("nreachable") || output.contains("Unknown"),
        "no ICMP error surfaced:\n{output}\ndaemon:\n{}",
        node.log()
    );

    node.signal(Signal::SIGTERM);
    assert!(node.wait_exit().success());
    let log = node.log();
    assert!(log.contains("unreachable, sending ICMP"), "{log}");
    assert!(!node.pidfile.exists() && !node.socket.exists());
}
