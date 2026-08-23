//! Regression: pre-ACK connect timeout must not cause a CPU busy-loop
//! (leaked epoll/kqueue registration). Portable version of
//! `netns/busyloop.rs`: `ConnectTo` points at a local listener with a
//! saturated accept queue so the connect hangs. TEST-NET-1 was not
//! reliable — many networks answer it with ICMP unreachable.

#[path = "common/mod.rs"]
#[macro_use]
mod common;

use std::net::{SocketAddr, TcpStream};
use std::process::Stdio;
use std::time::{Duration, Instant};

use common::*;

/// Loopback listener with backlog 0 and a saturated accept queue.
fn blackhole() -> (socket2::Socket, Vec<TcpStream>, SocketAddr) {
    let s = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
    s.bind(&SocketAddr::from(([127, 0, 0, 1], 0)).into())
        .unwrap();
    s.listen(0).unwrap();
    let addr = s.local_addr().unwrap().as_socket().unwrap();
    // macOS rounds the backlog up (somaxconn default 128), so keep
    // connecting until the queue is actually full.
    let mut held = Vec::new();
    for _ in 0..1024 {
        match TcpStream::connect_timeout(&addr, Duration::from_millis(250)) {
            Ok(c) => held.push(c),
            Err(_) => break,
        }
    }
    (s, held, addr)
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
        // proc_pid_rusage instead of ps: the nix sandbox has no ps.
        // Times are in mach ticks. Convert to centiseconds.
        let mut info: libc::rusage_info_v2 = unsafe { std::mem::zeroed() };
        let ret = unsafe {
            libc::proc_pid_rusage(
                pid as i32,
                libc::RUSAGE_INFO_V2,
                std::ptr::from_mut(&mut info).cast(),
            )
        };
        assert_eq!(ret, 0, "proc_pid_rusage({pid})");
        let mut tb = libc::mach_timebase_info { numer: 0, denom: 0 };
        unsafe { libc::mach_timebase_info(&mut tb) };
        let ns =
            (info.ri_user_time + info.ri_system_time) * u64::from(tb.numer) / u64::from(tb.denom);
        ns / 10_000_000
    }
}

#[test]
fn outgoing_timeout_no_busy_loop() {
    let tmp = tmp!("outgoing_timeout");
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
    let (_listener, _held, addr) = blackhole();
    std::fs::write(
        confbase.join("hosts").join("blackhole"),
        format!(
            "Ed25519PublicKey = {dummy_pub}\nAddress = 127.0.0.1 {}\n",
            addr.port()
        ),
    )
    .unwrap();
    write_ed25519_privkey(&confbase, &[0x42; 32]);

    let mut log = ChildWithLog::spawn(
        tincd_at(&confbase, &pidfile, &socket)
            .env("RUST_LOG", "tincd=info")
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn tincd"),
    );

    assert!(
        wait_for_file(&socket),
        "tincd setup failed; stderr:\n{}",
        log.kill_and_log()
    );

    // Wait for pre-ACK timeout.
    let deadline = Instant::now() + Duration::from_secs(15);
    while !log
        .log_snapshot()
        .contains("Timeout while connecting to blackhole")
    {
        assert!(
            Instant::now() < deadline,
            "no connect-timeout log in 15s; stderr:\n{}",
            log.log_snapshot()
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    // Let post-timeout activity settle, then measure CPU over 2s.
    std::thread::sleep(Duration::from_secs(1));

    let pid = log.pid();
    let before = cpu_time(pid);
    std::thread::sleep(Duration::from_secs(2));
    let after = cpu_time(pid);
    let delta = after - before;
    let snap = log.log_snapshot();

    #[expect(clippy::cast_possible_wrap)]
    let nix_pid = nix::unistd::Pid::from_raw(pid as i32);
    nix::sys::signal::kill(nix_pid, nix::sys::signal::Signal::SIGTERM).expect("kill SIGTERM");
    let wait_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(s) = log.child.try_wait().unwrap() {
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
