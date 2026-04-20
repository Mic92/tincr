//! macOS smoke test: daemon start → utun open → SIGTERM → clean shutdown.
//!
//! utun requires root. The cargo test runner (`scripts/macos-test-runner.sh`)
//! re-execs under sudo when passwordless sudo is available. Without it,
//! the test prints SKIP and passes.

#![cfg(target_os = "macos")]

#[path = "common/mod.rs"]
mod common;

use common::*;
use std::process::Stdio;
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;

/// Write minimal utun config. `Interface = utun99` to avoid conflicts.
fn write_utun_config(confbase: &std::path::Path) {
    std::fs::create_dir_all(confbase.join("hosts")).unwrap();
    std::fs::write(
        confbase.join("tinc.conf"),
        "Name = smoketest\n\
         DeviceType = tun\n\
         AddressFamily = ipv4\n\
         Interface = utun99\n",
    )
    .unwrap();
    std::fs::write(confbase.join("hosts").join("smoketest"), "Port = 0\n").unwrap();
    let seed = [0xAA; 32];
    write_ed25519_privkey(confbase, &seed);
}

#[test]
fn utun_start_sigterm_shutdown() {
    if !nix::unistd::geteuid().is_root() {
        eprintln!("SKIP: utun smoke test requires root (no passwordless sudo)");
        return;
    }

    let tmp = TmpGuard::new("macos-smoke", "utun");
    let (confbase, pidfile, socket) = tmp.std_paths();

    write_utun_config(&confbase);

    let mut child = tincd_at(&confbase, &pidfile, &socket)
        .env("RUST_LOG", "tincd=info")
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tincd");

    assert!(
        wait_for_file(&socket),
        "tincd didn't start; stderr: {}",
        drain_stderr(child)
    );

    // Verify utun99 exists via ifconfig
    let ifconfig = std::process::Command::new("ifconfig")
        .arg("utun99")
        .output()
        .expect("ifconfig");
    assert!(
        ifconfig.status.success(),
        "utun99 not found after daemon start; ifconfig stderr: {}",
        String::from_utf8_lossy(&ifconfig.stderr)
    );

    // SIGTERM → clean shutdown
    #[allow(clippy::cast_possible_wrap)]
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
    assert!(status.success(), "tincd exit status: {status:?}");
    assert!(!pidfile.exists(), "pidfile should be cleaned up");
    assert!(!socket.exists(), "socket should be cleaned up");
}
