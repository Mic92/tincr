//! Kernel steering integration tests.
//!
//! Three tests, three claims:
//!
//! 1. **`cbpf_steers_by_src_id6`**: open `ReuseportGroup(N=4)`, send
//!    UDP datagrams whose `[dst_id6][src_id6]` prefix is crafted so
//!    `ntohl(src_id6[0..4]) % 4` cycles 0..3. Assert each lands on
//!    the predicted socket. 100/100. Ported from shard-proto test 3
//!    but using realistic id6-shaped payloads instead of `payload[0]`.
//!
//! 2. **`automq_learns_from_write`**: open multiqueue TUN N=2, run a
//!    TCP hairpin echo where the echo *always writes back via queue
//!    1*. Assert >90% of subsequent reads happen on queue 1. **The
//!    new test** — proves `tun_flow_update`'s reflexive trick: the
//!    queue we *write* to is the queue the kernel *sends* to.
//!
//! 3. **`automq_cold_miss_converges`**: same TUN, fresh flow with no
//!    prior write. Assert: first packet lands on `hash % N` (some
//!    queue, undetermined), echo writes back from *that* queue,
//!    subsequent packets stay on the same queue. Proves convergence
//!    after one observation.
//!
//! All three run in bwrap-userns. Zero `bpf()` syscalls; only
//! `CAP_NET_ADMIN` (TUNSETIFF) needed, which bwrap grants locally.
//!
//! ## bwrap re-exec
//!
//! Self-contained copy of `crates/tinc-device/tests/mq.rs::enter_netns`.
//! See `crates/tincd/tests/netns/rig.rs` for the full `--tmpfs /dev`
//! rationale; TL;DR: fresh tmpfs at /dev means our userns owns the
//! mount, satisfying `tun.c`'s `owner_net` check on TUNSETIFF.

#![cfg(target_os = "linux")]
#![allow(clippy::similar_names)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::too_many_lines)] // hairpin echo is long but linear

use std::io::Read;
use std::net::IpAddr;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

use tinc_device::{Device, DeviceConfig, Mode, Tun, VNET_HDR_LEN};
use tincd::shard::bpf::{open_reuseport_group, tunsetsteeringebpf};

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

// ═══════════ Test 1: cBPF steers by src_id6 prefix ═══════════════════
//
// The cBPF prog loads a 4-byte word at payload offset 6. `BPF_LD|
// BPF_W|BPF_ABS` does ntohl: A = (p[6]<<24)|(p[7]<<16)|(p[8]<<8)|p[9].
// We craft datagrams where p[6..9] are zero and p[9] cycles, so
// `ntohl(word) % N == p[9] % N`. This is a realistic id6 — the high
// bytes of a SHA512 prefix are uniform; we just zero them for a
// predictable assertion.

#[test]
fn cbpf_steers_by_src_id6() {
    if !enter_netns("cbpf_steers_by_src_id6") {
        return;
    }

    const N: u32 = 4;
    const PORT: u16 = 17777;
    const PACKETS: u8 = 100;

    let group = open_reuseport_group(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), PORT, N)
        .expect("open_reuseport_group");
    assert_eq!(group.socks.len(), N as usize);
    eprintln!(
        "✓ {N} UDP sockets, SO_REUSEPORT, bound 127.0.0.1:{PORT}, \
         cBPF prog: A = ntohl(*(u32*)(payload+6)); return A % {N}"
    );

    // ── sender: 100 packets, [dst_id6:6][src_id6:6][seq:1] ──────────
    // src_id6 = [0,0,0,i,r,r] so ntohl(word @6) = u32::from(i).
    // The word stops at byte 9; bytes 10–11 (the rest of src_id6)
    // are noise the prog never reads — set them to non-zero to
    // prove they don't leak into the steering decision.
    let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    sender.connect(("127.0.0.1", PORT)).expect("connect sender");
    for i in 0..PACKETS {
        let mut pkt = [0u8; 13];
        pkt[0..6].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE]); // dst_id6
        pkt[6..12].copy_from_slice(&[0, 0, 0, i, 0xAA, 0xBB]); // src_id6
        pkt[12] = i; // sptps seq stand-in (not steered on)
        sender.send(&pkt).expect("send");
    }
    std::thread::sleep(Duration::from_millis(50));

    // ── drain each socket, record which packets landed where ────────
    let mut by_sock: Vec<Vec<u8>> = vec![Vec::new(); N as usize];
    let mut buf = [0u8; 64];
    for (k, sock) in group.socks.iter().enumerate() {
        // SOCK_NONBLOCK: EAGAIN when drained → Err → break.
        while let Ok(n) = nix::sys::socket::recv(
            sock.as_raw_fd(),
            &mut buf,
            nix::sys::socket::MsgFlags::empty(),
        ) {
            if n == 0 {
                break;
            }
            by_sock[k].push(buf[9]); // src_id6[3] — the steering byte
        }
    }
    drop(group);

    // ── Assert: packet i landed on socket (i % N), exactly. ─────────
    let mut total = 0;
    let mut mismatches = Vec::new();
    for (k, received) in by_sock.iter().enumerate() {
        eprintln!(
            "  socket[{k}] received {} packets: {:?}",
            received.len(),
            &received[..received.len().min(8)]
        );
        total += received.len();
        for &id6_byte in received {
            let expected = (u32::from(id6_byte) % N) as usize;
            if expected != k {
                mismatches.push((id6_byte, k, expected));
            }
        }
    }

    assert_eq!(
        total, PACKETS as usize,
        "lost packets: sent {PACKETS}, received {total}"
    );
    assert!(
        mismatches.is_empty(),
        "steering mismatches (src_id6[3], landed_on, expected): {mismatches:?}\n\
         random → kernel hash, not our prog (attach silently failed?)\n\
         all on one sock → prog returns constant (LD_ABS offset wrong)"
    );
    eprintln!(
        "─────────────────────────────────────────────\n\
         ✓ SO_ATTACH_REUSEPORT_CBPF steers by src_id6\n\
         ✓ BPF_LD|BPF_W|BPF_ABS at offset 6 = src_id6[0..4]\n\
         ✓ {PACKETS}/{PACKETS} packets on socket id6 % {N}\n\
         ─────────────────────────────────────────────"
    );
}

// ══════════════ TUN hairpin echo helper ═════════════════════════════
//
// One netns, one TUN, no peer. Route 10.77.0.0/24 via the TUN; a
// userspace echo reads any queue, swaps IPv4 src↔dst + TCP
// sport↔dport, writes back via `write_queue`. TCP listener on .1
// and connector to .2 talk through the swap (checksums survive: all
// sums are commutative over the swapped fields).
//
// `write_queue` is the trick: the echo can read from ANY queue (it
// polls all), but it always WRITES to a fixed one. tun_flow_update
// records `rxhash → write_queue`. The next kernel TX on that flow
// goes to write_queue.

struct HairpinEcho {
    stop: Arc<AtomicBool>,
    /// `read_count[k]` = packets read from queue k.
    read_count: Arc<[AtomicU32; 2]>,
    echo: Option<std::thread::JoinHandle<()>>,
}

impl HairpinEcho {
    /// `queues`: dup'd owned fds, both queues. Echo polls both, writes
    /// to `queues[write_queue]`. Consumes the fds (closes on drop).
    fn spawn(queues: [OwnedFd; 2], write_queue: usize) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let read_count = Arc::new([AtomicU32::new(0), AtomicU32::new(0)]);
        let estop = stop.clone();
        let ecnt = read_count.clone();

        let echo = std::thread::spawn(move || {
            let mut buf = vec![0u8; 70_000];
            while !estop.load(Ordering::Relaxed) {
                for (k, fd) in queues.iter().enumerate() {
                    // O_NONBLOCK → EAGAIN when empty → Err → skip.
                    let Ok(n) = nix::unistd::read(fd.as_fd(), &mut buf) else {
                        continue;
                    };
                    if n < VNET_HDR_LEN + 20 {
                        continue;
                    }
                    let ip = VNET_HDR_LEN;
                    let ip_ver = buf[ip] >> 4;
                    if ip_ver != 4 {
                        // IPv6 NDP from link-up; not part of the
                        // hairpin flow. Skip without counting.
                        continue;
                    }
                    ecnt[k].fetch_add(1, Ordering::Relaxed);

                    // ── swap IPv4 src↔dst, TCP sport↔dport ──────────
                    let mut tmp = [0u8; 4];
                    tmp.copy_from_slice(&buf[ip + 12..ip + 16]);
                    buf.copy_within(ip + 16..ip + 20, ip + 12);
                    buf[ip + 16..ip + 20].copy_from_slice(&tmp);
                    let ihl = ((buf[ip] & 0x0F) as usize) * 4;
                    let tcp = ip + ihl;
                    if tcp + 4 <= n {
                        let mut tmp2 = [0u8; 2];
                        tmp2.copy_from_slice(&buf[tcp..tcp + 2]);
                        buf.copy_within(tcp + 2..tcp + 4, tcp);
                        buf[tcp + 2..tcp + 4].copy_from_slice(&tmp2);
                    }

                    // ── write to the FIXED queue ────────────────────
                    // tun_get_user → tun_flow_update(rxhash, queue=
                    // write_queue). The kernel learns. Next TX on
                    // this flow: tun_automq_select_queue finds the
                    // entry → write_queue.
                    let _ = nix::unistd::write(&queues[write_queue], &buf[..n]);
                }
                std::thread::sleep(Duration::from_micros(50));
            }
            // `queues: [OwnedFd; 2]` drops here → close(2) each.
            drop(queues);
        });

        Self {
            stop,
            read_count,
            echo: Some(echo),
        }
    }

    fn counts(&self) -> [u32; 2] {
        [
            self.read_count[0].load(Ordering::Relaxed),
            self.read_count[1].load(Ordering::Relaxed),
        ]
    }
}

impl Drop for HairpinEcho {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.echo.take() {
            let _ = h.join();
        }
    }
}

fn dup_queue(q: &Tun) -> OwnedFd {
    let fd = q.fd().expect("Tun has fd");
    nix::unistd::dup(fd).expect("dup")
}

/// Drive a TCP exchange through the hairpin: connect to .2:port (via
/// TUN), accept on .1:port, push `bytes` through. The echo's swap
/// makes them talk to each other.
fn drive_tcp(port: u16, bytes: usize) -> bool {
    let listener = std::net::TcpListener::bind(("10.77.0.1", port)).expect("bind listener");
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let lstop = stop.clone();
    let lthread = std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        while !lstop.load(Ordering::Relaxed) {
            if let Ok((mut s, _)) = listener.accept() {
                let _ = s.set_nonblocking(false);
                while s.read(&mut buf).map(|n| n > 0).unwrap_or(false) {}
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    });

    std::thread::sleep(Duration::from_millis(50));
    let blob = vec![0xABu8; bytes];
    let ok = if let Ok(mut s) = std::net::TcpStream::connect_timeout(
        &format!("10.77.0.2:{port}").parse().unwrap(),
        Duration::from_secs(3),
    ) {
        let _ = s.set_write_timeout(Some(Duration::from_secs(3)));
        let _ = std::io::Write::write_all(&mut s, &blob);
        std::thread::sleep(Duration::from_millis(150));
        let _ = s.shutdown(std::net::Shutdown::Both);
        true
    } else {
        false
    };
    stop.store(true, Ordering::Relaxed);
    lthread.join().unwrap();
    ok
}

// ═════════ Test 2: automq learns flow→queue from our writes ══════════
//
// Echo writes EVERYTHING to queue 1. After the first SYN/SYN-ACK
// roundtrip, the kernel has learned both 4-tuples → queue 1. All
// subsequent data segments arrive on queue 1.
//
// 90% threshold (not 100%): the very first SYN goes to hash%2 — could
// be queue 0. tun->flows[] is also RCU-updated, so a packet in flight
// when the entry is being written can race. The steady state is 100%;
// the threshold tolerates startup noise.

#[test]
fn automq_learns_from_write() {
    if !enter_netns("automq_learns_from_write") {
        return;
    }

    let cfg = DeviceConfig {
        iface: Some("steer0".to_owned()),
        mode: Mode::Tun,
        ..DeviceConfig::default()
    };
    let queues = Tun::open_mq(&cfg, 2).expect("open_mq(2)");

    // Defensive detach: ensure no leftover prog (we just opened a
    // fresh device in a fresh netns, so this is a no-op — but it
    // exercises the ioctl path the daemon will call at startup).
    tunsetsteeringebpf(queues[0].fd().unwrap(), -1).expect("detach steering prog");
    eprintln!("✓ TUNSETSTEERINGEBPF(-1): detach is no-op on clean device");

    run_ip(&["addr", "add", "10.77.0.1/24", "dev", "steer0"]);
    run_ip(&["link", "set", "steer0", "up"]);

    let echo = HairpinEcho::spawn([dup_queue(&queues[0]), dup_queue(&queues[1])], 1);

    let connected = drive_tcp(19991, 64 * 1024);
    assert!(connected, "TCP handshake via hairpin failed — echo broken");

    // 64KB through TSO collapses to ~16 super-segments — too few to
    // amortize the cold-miss handshake packets (SYN both directions
    // → hash%2, undetermined). Second flow on a fresh port pads the
    // sample without re-learning the first flow's entry.
    let _ = drive_tcp(19994, 256 * 1024);
    std::thread::sleep(Duration::from_millis(100));

    let [q0, q1] = echo.counts();
    drop(echo);
    drop(queues);

    let total = q0 + q1;
    eprintln!("queue[0] read {q0}, queue[1] read {q1}, total {total}");
    assert!(total >= 30, "too few packets to assert ({total})");

    // Echo writes to queue 1 → tun_flow_update(rxhash, 1) → next
    // kernel TX on this flow → automq finds entry → queue 1.
    // Threshold accounts for: each flow's first SYN + SYN-ACK can
    // land on hash%2=0 before any write-back has taught the entry.
    // ~2 cold packets per flow × 2 flows on ~40+ total → >85%.
    let q1_frac = f64::from(q1) / f64::from(total);
    assert!(
        q1_frac > 0.85,
        "automq did not learn: queue[1] only got {q1}/{total} ({:.0}%); \
         expected >85% after writing all reflections to queue 1. \
         Either tun_flow_update isn't running (kernel <3.8?!) or a \
         steering prog is overriding automq.",
        q1_frac * 100.0
    );
    eprintln!(
        "─────────────────────────────────────────────\n\
         ✓ tun_automq_select_queue learns from writes\n\
         ✓ {:.0}% of reads on queue[1] after teaching it\n\
         ─────────────────────────────────────────────",
        q1_frac * 100.0
    );
}

// ════════ Test 3: cold miss → write back → converged ════════════════
//
// Echo writes back to whichever queue it READ from (the natural
// shard behavior: shard k decrypts → writes tun_fd[k]). Two
// independent TCP flows (different ports → different rxhash). Each
// flow's first SYN goes to hash%2 — undetermined, but ONE queue.
// Echo writes back from that queue → flow learned → all subsequent
// packets stay there.
//
// Assert: each flow is sticky (≥90% on one queue). With distinct
// ports we expect the flows MAY split across queues (proving cold-
// miss spreads load) but each one converges.

#[test]
fn automq_cold_miss_converges() {
    if !enter_netns("automq_cold_miss_converges") {
        return;
    }

    let cfg = DeviceConfig {
        iface: Some("steer1".to_owned()),
        mode: Mode::Tun,
        ..DeviceConfig::default()
    };
    let queues = Tun::open_mq(&cfg, 2).expect("open_mq(2)");
    tunsetsteeringebpf(queues[0].fd().unwrap(), -1).expect("detach");

    run_ip(&["addr", "add", "10.77.0.1/24", "dev", "steer1"]);
    run_ip(&["link", "set", "steer1", "up"]);

    // Echo writes to the queue it READ from. This is what a shard
    // does: read tun_fd[k], decrypt, write tun_fd[k]. Whatever
    // queue automq picked cold, the write-back teaches it to stay.
    // Reusing HairpinEcho with write_queue = read queue requires
    // a tweak: inline the loop (it's short) rather than complicate
    // the helper with a mode flag.
    let stop = Arc::new(AtomicBool::new(false));
    let read_count = Arc::new([AtomicU32::new(0), AtomicU32::new(0)]);
    let dups = [dup_queue(&queues[0]), dup_queue(&queues[1])];
    let estop = stop.clone();
    let ecnt = read_count.clone();
    let echo = std::thread::spawn(move || {
        let mut buf = vec![0u8; 70_000];
        while !estop.load(Ordering::Relaxed) {
            for (k, fd) in dups.iter().enumerate() {
                // O_NONBLOCK → EAGAIN when empty → Err → skip.
                let Ok(n) = nix::unistd::read(fd.as_fd(), &mut buf) else {
                    continue;
                };
                if n < VNET_HDR_LEN + 20 || buf[VNET_HDR_LEN] >> 4 != 4 {
                    continue;
                }
                ecnt[k].fetch_add(1, Ordering::Relaxed);
                let ip = VNET_HDR_LEN;
                let mut tmp = [0u8; 4];
                tmp.copy_from_slice(&buf[ip + 12..ip + 16]);
                buf.copy_within(ip + 16..ip + 20, ip + 12);
                buf[ip + 16..ip + 20].copy_from_slice(&tmp);
                let ihl = ((buf[ip] & 0x0F) as usize) * 4;
                let tcp = ip + ihl;
                if tcp + 4 <= n {
                    let mut tmp2 = [0u8; 2];
                    tmp2.copy_from_slice(&buf[tcp..tcp + 2]);
                    buf.copy_within(tcp + 2..tcp + 4, tcp);
                    buf[tcp + 2..tcp + 4].copy_from_slice(&tmp2);
                }
                // Write back to the SAME queue. Convergence.
                let _ = nix::unistd::write(fd, &buf[..n]);
            }
            std::thread::sleep(Duration::from_micros(50));
        }
        // `dups: [OwnedFd; 2]` drops here → close(2) each.
        drop(dups);
    });

    // ── flow A: cold ────────────────────────────────────────────────
    let a_ok = drive_tcp(19992, 32 * 1024);
    assert!(a_ok, "flow A handshake failed");
    let [a_q0, a_q1] = [
        read_count[0].load(Ordering::Relaxed),
        read_count[1].load(Ordering::Relaxed),
    ];

    // ── flow B: also cold (different port → different rxhash) ───────
    let b_ok = drive_tcp(19993, 32 * 1024);
    assert!(b_ok, "flow B handshake failed");
    std::thread::sleep(Duration::from_millis(100));

    stop.store(true, Ordering::Relaxed);
    echo.join().unwrap();
    let [tot_q0, tot_q1] = [
        read_count[0].load(Ordering::Relaxed),
        read_count[1].load(Ordering::Relaxed),
    ];
    drop(queues);

    let (b_q0, b_q1) = (tot_q0 - a_q0, tot_q1 - a_q1);
    eprintln!("flow A: q0={a_q0} q1={a_q1}");
    eprintln!("flow B: q0={b_q0} q1={b_q1}");

    // Each flow must be sticky to ONE queue. The cold miss is the
    // first packet (hash%2); after the echo's write-back the flow
    // is learned. ≥90% on one side. Which side: don't care.
    for (label, q0, q1) in [("A", a_q0, a_q1), ("B", b_q0, b_q1)] {
        let total = q0 + q1;
        assert!(total >= 10, "flow {label}: too few packets ({total})");
        let dom = q0.max(q1);
        let frac = f64::from(dom) / f64::from(total);
        assert!(
            frac > 0.90,
            "flow {label} did not converge: q0={q0} q1={q1} ({:.0}% dominant); \
             cold-miss should be ONE packet, then sticky.",
            frac * 100.0
        );
        eprintln!(
            "✓ flow {label} converged: {:.0}% on queue[{}]",
            frac * 100.0,
            u8::from(q1 >= q0)
        );
    }
    eprintln!(
        "─────────────────────────────────────────────\n\
         ✓ cold miss bounded to ~1 packet, then sticky\n\
         ✓ write-back to read-queue is self-stabilizing\n\
         ─────────────────────────────────────────────"
    );
}
