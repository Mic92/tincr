//! Regression: pre-ACK connect timeout must not cause a CPU busy-loop.
//!
//! Portable version of `netns/busyloop.rs` — no iptables, no netns.
//! Uses `ConnectTo` pointing at `192.0.2.1:1` (RFC 5737 TEST-NET-1,
//! non-routable) so the TCP SYN hangs without RST. The daemon's
//! `on_ping_tick` fires `terminate()` on the pre-ACK timeout path;
//! the regression was a leaked epoll/kqueue registration causing
//! 100% CPU after that.
//!
//! Works on Linux and macOS.

#[path = "common/mod.rs"]
mod common;

use std::io::Read;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::*;

fn tmp(tag: &str) -> TmpGuard {
    TmpGuard::new("busyloop", tag)
}

/// Background stderr drain with live snapshot.
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

/// CPU time (user + system). Linux: clock ticks. macOS: centiseconds.
fn cpu_time(pid: u32) -> u64 {
    #[cfg(target_os = "linux")]
    {
        let stat =
            std::fs::read_to_string(format!("/proc/{pid}/stat")).expect("read /proc/PID/stat");
        let after = stat.rsplit_once(')').expect("stat has comm").1;
        let mut t = after.split_whitespace();
        let utime: u64 = t.nth(11).expect("utime").parse().expect("utime num");
        let stime: u64 = t.next().expect("stime").parse().expect("stime num");
        utime + stime
    }
    #[cfg(target_os = "macos")]
    {
        // `ps -p PID -o cputime=` gives MM:SS.xx — parse to centiseconds.
        let out = std::process::Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "cputime="])
            .output()
            .expect("ps");
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        // Format: "M:SS.xx" or "MM:SS.xx"
        let (min_s, rest) = s.split_once(':').expect("cputime has ':'");
        let (sec_s, cs_s) = rest.split_once('.').unwrap_or((rest, "0"));
        let min: u64 = min_s.parse().unwrap_or(0);
        let sec: u64 = sec_s.parse().unwrap_or(0);
        let cs: u64 = cs_s.parse().unwrap_or(0);
        min * 6000 + sec * 100 + cs
    }
}

#[test]
fn outgoing_timeout_no_busy_loop() {
    let tmp = tmp("outgoing_timeout");
    let (confbase, pidfile, socket) = tmp.std_paths();
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
        format!("Ed25519PublicKey = {dummy_pub}\nAddress = 192.0.2.1 1\n"),
    )
    .unwrap();
    write_ed25519_privkey(&confbase, &[0x42; 32]);

    let mut child = tincd_at(&confbase, &pidfile, &socket)
        .env("RUST_LOG", "tincd=info")
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tincd");
    let log = LogReader::spawn(child.stderr.take().unwrap());

    if !wait_for_file(&socket) {
        let _ = child.kill();
        panic!("tincd setup failed; stderr:\n{}", log.snapshot());
    }

    // Wait for pre-ACK timeout.
    let deadline = Instant::now() + Duration::from_secs(15);
    while !log
        .snapshot()
        .contains("Timeout while connecting to blackhole")
    {
        assert!(
            Instant::now() < deadline,
            "no connect-timeout log in 15s; stderr:\n{}",
            log.snapshot()
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    // Let post-timeout activity settle, then measure CPU over 2s.
    std::thread::sleep(Duration::from_secs(1));

    let pid = child.id();
    let before = cpu_time(pid);
    std::thread::sleep(Duration::from_secs(2));
    let after = cpu_time(pid);
    let delta = after - before;
    let snap = log.snapshot();

    #[allow(clippy::cast_possible_wrap)]
    let nix_pid = nix::unistd::Pid::from_raw(pid as i32);
    nix::sys::signal::kill(nix_pid, nix::sys::signal::Signal::SIGTERM).expect("kill SIGTERM");
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

    // 2s pegged ≈ 200 units; idle ≈ 0–2. Threshold 50.
    assert!(
        delta < 50,
        "busy-loop: {delta} CPU-time units in 2s (leaked fd after \
         pre-ACK timeout). stderr:\n{snap}"
    );
}
