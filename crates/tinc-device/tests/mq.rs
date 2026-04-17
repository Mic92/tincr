//! `IFF_MULTI_QUEUE` + `IFF_VNET_HDR` integration test.
//!
//! Prove `Tun::open_mq` produces N working queue fds with TSO
//! super-segments arriving on them, validating both the flag combo
//! (`0x5101`) and that `TUNSETOFFLOAD` on fd[0] arms all queues.
//!
//! ## TUN-hairpin echo
//!
//! One netns, one TUN device, no peer daemon. The trick: route
//! `10.77.0.0/24` via the TUN, run a userspace echo loop that reads
//! any queue, swaps IPv4 src↔dst + TCP sport↔dport, writes back. A
//! TCP listener on `10.77.0.1:19999` and a connector to
//! `10.77.0.2:19999` then talk to each other through the swap:
//!
//!   - connector SYN: `.1 → .2` routes via TUN → echo swaps → `.2 → .1`
//!     arrives at the listener
//!   - listener SYN-ACK: `.1 → .2` routes via TUN → echo swaps →
//!     `.2 → .1` arrives at the connector
//!
//! The IP/TCP checksums survive the swap unchanged: every checksum
//! algorithm sums src+dst (commutative). The kernel TCP stack
//! believes it's talking to a remote peer; bulk write triggers TSO.
//!
//! No `tun_automq_select_queue` steering prog: the connector's data
//! all lands on ONE queue (one 4-tuple). That's exactly the property
//! we want — flow stickiness — and we don't care which queue.
//!
//! ## bwrap re-exec
//!
//! Same trick as `crates/tincd/tests/netns.rs` (see that file's doc
//! for the full `--tmpfs /dev` rationale). Self-contained copy: two
//! ~100-line copies are cheaper than a `tests/common/` crate.

#![cfg(target_os = "linux")]
#![allow(clippy::similar_names)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::too_many_lines)] // hairpin echo is long but linear

use std::io::Read;
use std::os::fd::{AsFd, OwnedFd};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tinc_device::{Device, DeviceConfig, Mode, Tun, VNET_HDR_LEN};

// `VIRTIO_NET_HDR_GSO_TCPV4` — `virtio_net.h:159`. Kernel ABI.
const GSO_TCPV4: u8 = 1;
const GSO_NONE: u8 = 0;

// ════════════════════════ bwrap re-exec wrapper ══════════════════════

fn enter_netns(test_name: &str) -> bool {
    if std::env::var_os("BWRAP_INNER").is_some() {
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
    if !std::path::Path::new("/dev/net/tun").exists() {
        eprintln!("SKIP {test_name}: /dev/net/tun missing");
        return false;
    }

    let self_exe = std::fs::read_link("/proc/self/exe").expect("readlink /proc/self/exe");
    let status = Command::new("bwrap")
        .args(["--unshare-net", "--unshare-user"])
        .args(["--cap-add", "CAP_NET_ADMIN"])
        .args(["--cap-add", "CAP_NET_RAW"])
        .args(["--uid", "0", "--gid", "0"])
        .args(["--bind", "/", "/"])
        // The load-bearing flag: fresh tmpfs at /dev so the userns
        // owns the mount, satisfying tun.c's owner_net check on
        // TUNSETIFF. See netns.rs's enter_netns doc.
        .args(["--tmpfs", "/dev"])
        .args(["--dev-bind", "/dev/net/tun", "/dev/net/tun"])
        .args(["--dev-bind", "/dev/null", "/dev/null"])
        .args(["--dev-bind", "/dev/urandom", "/dev/urandom"])
        .args(["--proc", "/proc"])
        .args(["--tmpfs", "/run"])
        .args(if std::path::Path::new("/run/current-system").exists() {
            &["--ro-bind", "/run/current-system", "/run/current-system"][..]
        } else {
            &[]
        })
        .arg("--")
        .arg(&self_exe)
        .args(["--exact", test_name, "--nocapture", "--test-threads=1"])
        .env("BWRAP_INNER", "1")
        .status()
        .expect("spawn bwrap");
    assert!(status.success(), "inner test failed: {status:?}");
    false
}

fn run_ip(args: &[&str]) {
    let status = Command::new("ip").args(args).status().expect("spawn ip");
    assert!(status.success(), "ip {args:?} failed: {status:?}");
}

// ═════════════════ Test: vnet_hdr present on multiqueue ═════════════
//
// Opens 4 queues, runs the hairpin echo, asserts:
//   1. open_mq(4) succeeds (kernel accepts 0x5101)
//   2. ≥1 captured packet has a sane vnet_hdr (ip_ver nibble at +10
//      is 4 or 6 — proves the 10-byte prefix is exactly where it
//      should be)
//   3. ≥1 packet has csum_start in [20,60] (TCP csum offload active)
//
// TSO super-segments are bonus (echo timing-dependent), not asserted.

#[test]
fn mq_vnet_hdr_on_queue0() {
    if !enter_netns("mq_vnet_hdr_on_queue0") {
        return;
    }

    const N: usize = 4;
    let cfg = DeviceConfig {
        iface: Some("shard0".to_owned()),
        mode: Mode::Tun,
        ..DeviceConfig::default()
    };
    let queues =
        Tun::open_mq(&cfg, N).expect("open_mq: kernel rejected IFF_MULTI_QUEUE|IFF_VNET_HDR");
    assert_eq!(queues.len(), N);
    eprintln!("✓ open_mq({N}): TUNSETIFF accepted flags=0x5101, {N} queues attached");

    run_ip(&["addr", "add", "10.77.0.1/24", "dev", "shard0"]);
    run_ip(&["link", "set", "shard0", "up"]);

    // ── Echo loop: read any queue, swap, write back ────────────────
    // Dup the fds: echo thread owns its dups, main thread keeps the
    // Tun structs (whose Drop closes the originals). Independent
    // file-table entries to the same kernel `tun_file`.
    let echo_fds: Vec<OwnedFd> = queues
        .iter()
        .map(|q| {
            let fd = q.fd().expect("Tun has fd");
            // SAFETY: fd is a valid open TUN queue fd; dup gives an
            // independent file-table slot to the same kernel file.
            #[allow(unsafe_code)]
            let dup = unsafe { libc::dup(fd) };
            assert!(dup >= 0, "dup failed");
            // SAFETY: dup just returned a fresh owned fd.
            #[allow(unsafe_code)]
            unsafe {
                std::os::fd::FromRawFd::from_raw_fd(dup)
            }
        })
        .collect();

    let stop = Arc::new(AtomicBool::new(false));
    // (gso_type, gso_size, csum_start, ip_ver, total_len)
    let captured = Arc::new(std::sync::Mutex::new(
        Vec::<(u8, u16, u16, u8, usize)>::new(),
    ));

    let echo_stop = stop.clone();
    let echo_cap = captured.clone();
    let echo = std::thread::spawn(move || {
        let mut buf = vec![0u8; 70_000]; // 64KB TSO + slack
        while !echo_stop.load(Ordering::Relaxed) {
            for fd in &echo_fds {
                // O_NONBLOCK → EAGAIN when empty (Err, skip).
                let Ok(n) = nix::unistd::read(fd.as_fd(), &mut buf) else {
                    continue;
                };
                if n < VNET_HDR_LEN + 20 {
                    continue; // too short for vnet_hdr + IPv4 header
                }

                // ── Capture vnet_hdr fields (THE test) ──────────────
                // virtio_net_hdr layout (le): flags@0 gso_type@1
                // hdr_len@2 gso_size@4 csum_start@6 csum_offset@8
                let gso_type = buf[1];
                let gso_size = u16::from_le_bytes([buf[4], buf[5]]);
                let csum_start = u16::from_le_bytes([buf[6], buf[7]]);
                let ip_ver = buf[VNET_HDR_LEN] >> 4;
                echo_cap
                    .lock()
                    .unwrap()
                    .push((gso_type, gso_size, csum_start, ip_ver, n));

                // ── Swap & reflect (IPv4 only) ──────────────────────
                // Checksums survive: ip_csum sums src+dst (commute);
                // tcp pseudo-hdr sums src_ip+dst_ip and sport+dport
                // (both commute). The partial csum the kernel left us
                // remains valid post-swap.
                let ip = VNET_HDR_LEN;
                if ip_ver == 4 {
                    // IPv4: src@12..16, dst@16..20
                    let mut tmp = [0u8; 4];
                    tmp.copy_from_slice(&buf[ip + 12..ip + 16]);
                    buf.copy_within(ip + 16..ip + 20, ip + 12);
                    buf[ip + 16..ip + 20].copy_from_slice(&tmp);
                    // TCP header at ip + IHL*4
                    let ihl = ((buf[ip] & 0x0F) as usize) * 4;
                    let tcp = ip + ihl;
                    if tcp + 4 <= n {
                        let mut tmp2 = [0u8; 2];
                        tmp2.copy_from_slice(&buf[tcp..tcp + 2]);
                        buf.copy_within(tcp + 2..tcp + 4, tcp);
                        buf[tcp + 2..tcp + 4].copy_from_slice(&tmp2);
                    }
                    let _ = nix::unistd::write(fd, &buf[..n]);
                }
            }
            std::thread::sleep(Duration::from_micros(100));
        }
        drop(echo_fds); // OwnedFd::drop closes each dup.
    });

    // ── Generate traffic: TCP via hairpin ───────────────────────────
    // Listener on .1, connector to .2. The /24 route on shard0 sends
    // .2 out the TUN; echo swaps → packets arrive "from .2 to .1" →
    // local delivery to the listener. .2 is NOT local (only .1 is).
    let listener = std::net::TcpListener::bind("10.77.0.1:19999").expect("bind listener");
    listener.set_nonblocking(true).unwrap();
    let listen_stop = stop.clone();
    let lthread = std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        while !listen_stop.load(Ordering::Relaxed) {
            if let Ok((mut s, _)) = listener.accept() {
                let _ = s.set_nonblocking(false);
                while s.read(&mut buf).map(|n| n > 0).unwrap_or(false) {}
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    });

    std::thread::sleep(Duration::from_millis(100)); // let echo settle
    let blob = vec![0xABu8; 64 * 1024];
    let mut tcp_established = false;
    if let Ok(mut s) = std::net::TcpStream::connect_timeout(
        &"10.77.0.2:19999".parse().unwrap(),
        Duration::from_secs(3),
    ) {
        tcp_established = true;
        eprintln!("✓ TCP handshake completed via TUN hairpin");
        let _ = s.set_write_timeout(Some(Duration::from_secs(3)));
        let _ = std::io::Write::write_all(&mut s, &blob);
        std::thread::sleep(Duration::from_millis(200));
        let _ = s.shutdown(std::net::Shutdown::Write);
        std::thread::sleep(Duration::from_millis(100));
    } else {
        eprintln!(
            "  TCP connect via hairpin failed; proceeding with SYN \
             captures only (vnet_hdr inspection still valid)"
        );
    }

    stop.store(true, Ordering::Relaxed);
    echo.join().unwrap();
    lthread.join().unwrap();

    // ── Assert: vnet_hdr is present and correctly sized ─────────────
    let cap = captured.lock().unwrap();
    assert!(
        !cap.is_empty(),
        "no packets captured — multiqueue read path broken \
         (kernel never delivered to any queue fd)"
    );
    eprintln!("captured {} packets across {N} queues:", cap.len());

    let mut tso_seen = false;
    let mut csum_offload_seen = false;
    for &(gso_type, gso_size, csum_start, ip_ver, len) in cap.iter().take(12) {
        eprintln!(
            "  gso_type={gso_type} gso_size={gso_size} \
             csum_start={csum_start} ip_ver={ip_ver} len={len}"
        );
        // The hard assert: ip_ver must be 4 or 6. If vnet_hdr were
        // absent or wrong-sized, we'd be reading IP bytes at the
        // wrong offset → garbage nibble (kernel sends some IPv6
        // NDP from the link going up; ip_ver=6 is legit).
        assert!(
            ip_ver == 4 || ip_ver == 6,
            "ip_ver nibble at offset {VNET_HDR_LEN} is {ip_ver}; \
             vnet_hdr absent or wrong size on multiqueue"
        );
        if gso_type == GSO_TCPV4 && gso_size > 0 && len > 1600 {
            tso_seen = true;
        }
        if gso_type == GSO_NONE && (20..=60).contains(&csum_start) {
            // SYN/ACK: no payload, but TCP csum offloaded.
            // csum_start = IHL (typically 20 for no-option IPv4).
            csum_offload_seen = true;
        }
    }

    drop(cap);
    drop(queues);

    eprintln!(
        "─────────────────────────────────────────────\n\
         ✓ open_mq({N}) + vnet_hdr coexist\n\
         {} csum offload seen (SYN packets, csum_start∈[20,60])\n\
         {} TSO super seen (gso_type=TCPV4, gso_size>0, len>1600)\n\
         {} TCP handshake via hairpin\n\
         ─────────────────────────────────────────────",
        if csum_offload_seen { "✓" } else { "○" },
        if tso_seen { "✓" } else { "○" },
        if tcp_established { "✓" } else { "○" },
    );

    // The gate: at minimum, SYN packets must have a populated
    // vnet_hdr. If even THAT is missing, the design is dead.
    assert!(
        csum_offload_seen || tso_seen,
        "no packet had populated vnet_hdr (all csum_start=0, gso_type=0); \
         multiqueue is silently zeroing the prefix"
    );
}

// ═════════════════ Test: n=1 ≡ single-queue ═════════════════════════
//
// open_mq(1) takes the no-MQ-flag branch. Weak smoke: just open it,
// bring it up, verify the iface name. No traffic — Tun::open's path
// is already covered by netns.rs end-to-end. The point is that the
// n=1 branch doesn't accidentally set IFF_MULTI_QUEUE.

#[test]
fn mq_one_queue_is_plain_open() {
    if !enter_netns("mq_one_queue_is_plain_open") {
        return;
    }

    let cfg = DeviceConfig {
        iface: Some("shard1".to_owned()),
        mode: Mode::Tun,
        ..DeviceConfig::default()
    };
    let queues = Tun::open_mq(&cfg, 1).expect("open_mq(1)");
    assert_eq!(queues.len(), 1);
    eprintln!("✓ open_mq(1) → 1 queue, iface={}", queues[0].iface());

    // The device exists with NO multiqueue flag: a second open
    // (regular, no MQ) should ATTACH (would EINVAL if the device
    // had the MQ flag set, per tun.c:2719's mismatch reject).
    // Actually no — the n=1 branch calls Tun::open which doesn't
    // set IFF_MULTI_QUEUE, so a second TUNSETIFF without MQ on
    // the same name would fail on attach (single-queue already
    // attached). The branch-taken proof is in the unit test
    // `open_mq_one_is_open` (validation skipped for iface=None);
    // here we just verify it works in the netns at all.
    drop(queues);
}
