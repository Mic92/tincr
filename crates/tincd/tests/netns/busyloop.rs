//! Regression: pre-ACK connect timeout leaked the epoll registration.
//!
//! `do_outgoing_connection` dup()s the connecting socket: dup goes on
//! `Connection.fd` (epoll-registered), original into `connecting_socks`.
//! Both fds key the SAME open-file-description in epoll's interest list.
//!
//! `on_ping_tick` → `terminate()` (the pre-ACK timeout path) used to:
//!   1. `drop(conn)` (closes the dup) BEFORE `ev.del()` → `epoll_ctl(DEL,
//!      dup_fd)` got EBADF, silently swallowed.
//!   2. never `connecting_socks.remove(id)` (only `on_connecting` /
//!      `finish_connecting` did, and this path bypasses those).
//!
//! So the original socket kept the file description — and the epoll
//! interest — alive. Once the kernel-side connect finally failed
//! (RST/ETIMEDOUT) the description went `ERR|HUP` and level-triggered
//! epoll fired forever into a freed `IoId` slot, which `turn()` skips
//! → empty out vec → daemon dispatches nothing → tight busy-loop, 100%
//! CPU.
//!
//! Repro needs a connect that HANGS (no RST — RST takes the
//! `on_connecting` Err path which always cleaned up). That's a
//! filtered port: `iptables -j DROP` on the SYN. Hence netns.

use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::common::*;
use super::rig::enter_netns;

fn tmp(tag: &str) -> TmpGuard {
    TmpGuard::new("netns", tag)
}

/// Background stderr drain with live snapshot. Same as
/// `retry.rs::LogReader`; netns's `ChildWithLog` only exposes
/// `kill_and_log`, we need to poll while the child is alive.
struct LogReader {
    log: Arc<Mutex<Vec<u8>>>,
    _drain: std::thread::JoinHandle<()>,
}

impl LogReader {
    fn spawn(stderr: std::process::ChildStderr) -> Self {
        let log = Arc::new(Mutex::new(Vec::new()));
        let log2 = Arc::clone(&log);
        let drain = std::thread::spawn(move || {
            let mut r = stderr;
            let mut buf = [0u8; 4096];
            while let Ok(n) = r.read(&mut buf) {
                if n == 0 {
                    break;
                }
                log2.lock().unwrap().extend_from_slice(&buf[..n]);
            }
        });
        Self { log, _drain: drain }
    }
    fn snapshot(&self) -> String {
        String::from_utf8_lossy(&self.log.lock().unwrap()).into_owned()
    }
}

/// `/proc/PID/stat` fields 14+15 (utime+stime, clock ticks). The
/// `comm` field (2) is parenthesized and may contain spaces; split
/// on the closing `)` first.
fn cpu_ticks(pid: u32) -> u64 {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).expect("read /proc/PID/stat");
    let after = stat.rsplit_once(')').expect("stat has comm").1;
    let mut t = after.split_whitespace();
    // after `)`: state pid ppid pgrp sess tty tpgid flags minflt
    // cminflt majflt cmajflt utime stime ... — utime is the 12th
    // token AFTER the `)` (state is 1st).
    let utime: u64 = t.nth(11).expect("utime").parse().expect("utime num");
    let stime: u64 = t.next().expect("stime").parse().expect("stime num");
    utime + stime
}

#[test]
fn outgoing_timeout_no_busy_loop() {
    const PORT: u16 = 45913;

    let Some(_netns) = enter_netns("busyloop::outgoing_timeout_no_busy_loop") else {
        return;
    };

    // ─── filtered port: iptables DROP on lo ─────────────────────
    // SYN never leaves → connect() stays in SYN_SENT, no EPOLLOUT,
    // no RST. The daemon's `on_ping_tick` reaps it at pingtimeout.
    // Feature-detect iptables (nft backend needs CONFIG_NF_TABLES;
    // present on any reasonable kernel, but the BINARY might not be
    // in a minimal CI rootfs).
    let ipt = Command::new("iptables")
        .args([
            "-I", "OUTPUT", "-o", "lo", "-p", "tcp", "--dport", "45913", "-j", "DROP",
        ])
        .output();
    match ipt {
        Err(e) => {
            eprintln!("SKIP outgoing_timeout_no_busy_loop: iptables not found ({e})");
            return;
        }
        Ok(out) if !out.status.success() => {
            eprintln!(
                "SKIP outgoing_timeout_no_busy_loop: iptables failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
            return;
        }
        Ok(_) => {}
    }

    // ─── config: ConnectTo = blackhole, PingTimeout = 2 ─────────
    let tmp = tmp("busyloop");
    let confbase = tmp.path().join("vpn");
    let pidfile = tmp.path().join("tinc.pid");
    let socket = tmp.path().join("tinc.socket");
    std::fs::create_dir_all(confbase.join("hosts")).unwrap();
    std::fs::write(
        confbase.join("tinc.conf"),
        "Name = testnode\nDeviceType = dummy\nAddressFamily = ipv4\n\
         ConnectTo = blackhole\nPingTimeout = 2\n",
    )
    .unwrap();
    std::fs::write(confbase.join("hosts").join("testnode"), "Port = 0\n").unwrap();
    let dummy_pub = tinc_crypto::b64::encode(&pubkey_from_seed(&[0xDE; 32]));
    std::fs::write(
        confbase.join("hosts").join("blackhole"),
        format!("Ed25519PublicKey = {dummy_pub}\nAddress = 127.0.0.1 {PORT}\n"),
    )
    .unwrap();
    write_ed25519_privkey(&confbase, &[0x42; 32]);

    // ─── spawn ──────────────────────────────────────────────────
    let mut child = tincd_cmd()
        .arg("-c")
        .arg(&confbase)
        .arg("--pidfile")
        .arg(&pidfile)
        .arg("--socket")
        .arg(&socket)
        .env("RUST_LOG", "tincd=info")
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tincd");
    let log = LogReader::spawn(child.stderr.take().unwrap());

    if !wait_for_file(&socket) {
        let _ = child.kill();
        panic!("tincd setup failed; stderr:\n{}", log.snapshot());
    }

    // ─── wait for the pre-ACK timeout terminate ─────────────────
    // pingtimer first fires at +pingtimeout (2s), re-arms +1s; the
    // sweep needs stale > pingtimeout, so the t≈3s sweep reaps it.
    let deadline = Instant::now() + Duration::from_secs(10);
    while !log
        .snapshot()
        .contains("Timeout while connecting to blackhole")
    {
        assert!(
            Instant::now() < deadline,
            "no connect-timeout log in 10s; stderr:\n{}",
            log.snapshot()
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    // ─── unblock: remove rule → next SYN retransmit gets RST ────
    // terminate() ran; the leaked sock (pre-fix) is still SYN_SENT
    // with the SYN dropped. Kernel retransmits at t≈1,3,7s. Removing
    // the DROP rule now lets the t≈7s retransmit reach a closed port
    // → RST → ECONNREFUSED → the leaked file-description goes
    // ERR|HUP and level-triggered epoll starts firing into the
    // freed slot. Pre-fix: 100% CPU from here. Post-fix: socket was
    // already closed in terminate(), nothing registered, idle.
    let out = Command::new("iptables")
        .args([
            "-D", "OUTPUT", "-o", "lo", "-p", "tcp", "--dport", "45913", "-j", "DROP",
        ])
        .output()
        .expect("iptables -D");
    assert!(
        out.status.success(),
        "iptables -D: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Wait past the t≈7s SYN retransmit (timeout log was t≈3s).
    std::thread::sleep(Duration::from_secs(5));

    // ─── CPU-time delta over a 2s window ────────────────────────
    // CONFIG_HZ=100 is the lowest common tick rate → 2s pegged is
    // ≥200 ticks. Idle daemon does ~1 tick/s (the 1s ping sweep).
    // 50 is a wide margin both ways.
    let pid = child.id();
    let before = cpu_ticks(pid);
    std::thread::sleep(Duration::from_secs(2));
    let after = cpu_ticks(pid);
    let delta = after - before;
    let snap = log.snapshot();

    // SIGTERM for clean exit (not SIGKILL: prove the loop isn't
    // wedged so hard it can't see the self-pipe — it isn't, the
    // signalfd IS in the same epoll set, but pre-fix it never gets
    // dispatched because turn() returns empty before the daemon
    // matches on it … actually it does: turn() drains ALL ready
    // events into `out`, the freed-slot continue only skips THAT
    // entry. So SIGTERM still works pre-fix; the assert below is
    // the real check).
    #[allow(clippy::cast_possible_wrap)]
    let pid = nix::unistd::Pid::from_raw(pid as i32);
    nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGTERM).expect("kill SIGTERM");
    let wait_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(s) = child.try_wait().unwrap() {
            assert!(s.success(), "daemon exit: {s:?}; stderr:\n{snap}");
            break;
        }
        assert!(
            Instant::now() < wait_deadline,
            "daemon didn't exit on SIGTERM; stderr:\n{snap}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }

    assert!(
        delta < 50,
        "busy-loop: {delta} CPU ticks in 2s (epoll spinning on \
         leaked connecting_socks fd after pre-ACK timeout). \
         stderr:\n{snap}"
    );
}
