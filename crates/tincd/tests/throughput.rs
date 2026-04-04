//! Throughput regression gate. S3 (bwrap netns + real TUN) + S4
//! (against C tincd as the baseline). `#[ignore]` — run on demand:
//!
//! ```sh
//! cargo nextest run --run-ignored ignored-only -E 'test(throughput)'
//! ```
//!
//! ## What it measures
//!
//! `iperf3 -c 10.44.0.2 -t 5 --json` from the outer netns to a server
//! in the child netns. Packets traverse the full daemon stack: TUN
//! read → route → SPTPS encrypt → UDP sendto → loopback → recvfrom →
//! SPTPS decrypt → route → TUN write. Same path as `netns.rs::
//! real_tun_ping` but at line rate instead of 3 echoes.
//!
//! ## What it asserts
//!
//! Rust↔Rust throughput ≥ 95% of C↔C throughput on the same machine,
//! same run. Absolute numbers are meaningless across machines; the
//! RATIO is the gate. 5% slop is generous — single-threaded ChaCha20-
//! Poly1305 should be within noise. A 50% regression means there's
//! an O(N) per-packet copy hiding somewhere.
//!
//! ## Why a release gate, not a CI test
//!
//! The 28-module daemon decomposition has ~5 places a `Vec<u8>`
//! clone-per-packet could creep in. None of the functional tests
//! catch that. This does, BEFORE we tag a release and someone runs
//! production traffic through it.
//!
//! ## Three configurations
//!
//! 1. **C↔C** — the baseline (what tinc 1.1pre18 does)
//! 2. **Rust↔Rust** — what we ship
//! 3. **Rust↔C** — interop overhead; should ≈ Rust↔Rust. Catches
//!    direction-asymmetric perf bugs (Rust receive path slow vs
//!    Rust send path slow).
//!
//! ## Dev-vs-release bias
//!
//! `cargo nextest run` builds the `dev` profile. The C tincd from
//! `.#tincd-c` is a meson `release` build. This biases the
//! comparison AGAINST us — if we beat 95% in dev mode, release
//! beats it harder. The bias is intentional safety margin.
//!
//! ## Mechanics
//!
//! Same bwrap-reexec as `netns.rs` / `crossimpl.rs` (read those
//! module docs first). One re-exec for the whole test; the three
//! tunnel configs run sequentially inside it, each one creating
//! fresh persistent TUN devices and tearing them down on drop.
//! Different device/netns names (`tincT0/tincT1`, `tbobside`,
//! 10.44.0.0/24) so this file doesn't collide with the others under
//! parallel nextest.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

mod common;
use common::linux::{ChildWithLog, run_ip, wait_for_carrier};
use common::{
    Ctl, TmpGuard, alloc_port, node_status, poll_until, pubkey_from_seed, wait_for_file,
    write_ed25519_privkey,
};

fn tmp(tag: &str) -> TmpGuard {
    TmpGuard::new("thr", tag)
}

// ═════════════════════════════ gates ═══════════════════════════════════════

fn c_tincd_bin() -> Option<PathBuf> {
    std::env::var_os("TINC_C_TINCD").map(PathBuf::from)
}

/// Probe iperf3 by spawning `iperf3 --version`. Cheaper than pulling
/// in the `which` crate for one PATH lookup; also actually checks the
/// binary runs (not just exists).
fn iperf3_available() -> bool {
    Command::new("iperf3")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

// ═════════════════════════ bwrap re-exec ═══════════════════════════════════
// Copy of crossimpl.rs::enter_netns. See netns.rs module doc for the
// flag-by-flag explanation. The `#[ignore]` on the test fn means
// libtest skips it by default; `--run-ignored ignored-only` enables
// it. The inner re-exec passes `--ignored` so the inner libtest
// invocation also runs the ignored test (otherwise the `--exact`
// match would find a test it then refuses to run).

fn enter_netns(test_name: &str) -> Option<NetNs> {
    if std::env::var_os("BWRAP_INNER").is_some() {
        return Some(NetNs::setup());
    }

    // Env gates BEFORE the bwrap probe — common skip path is
    // "TINC_C_TINCD unset" or "iperf3 not in PATH".
    if c_tincd_bin().is_none() {
        eprintln!(
            "SKIP {test_name}: TINC_C_TINCD not set. \
             `nix develop` sets it; outside nix: \
             `nix build .#tincd-c` then \
             `TINC_C_TINCD=$PWD/result/sbin/tincd`."
        );
        return None;
    }
    if !iperf3_available() {
        eprintln!("SKIP {test_name}: iperf3 not on PATH (nix develop provides it)");
        return None;
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
            return None;
        }
        Ok(out) if !out.status.success() => {
            eprintln!(
                "SKIP {test_name}: bwrap probe failed (unprivileged userns disabled?): {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
            return None;
        }
        Ok(_) => {}
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!("SKIP {test_name}: /dev/net/tun missing");
        return None;
    }

    let self_exe = std::fs::read_link("/proc/self/exe").expect("readlink /proc/self/exe");
    let status = Command::new("bwrap")
        .args(["--unshare-net", "--unshare-user"])
        .args(["--cap-add", "CAP_NET_ADMIN"])
        .args(["--cap-add", "CAP_NET_RAW"])
        .args(["--cap-add", "CAP_SYS_ADMIN"])
        .args(["--uid", "0", "--gid", "0"])
        .args(["--bind", "/", "/"])
        .args(["--tmpfs", "/dev"])
        .args(["--dev-bind", "/dev/net/tun", "/dev/net/tun"])
        .args(["--dev-bind", "/dev/null", "/dev/null"])
        .args(["--dev-bind", "/dev/urandom", "/dev/urandom"])
        .args(["--proc", "/proc"])
        .args(["--tmpfs", "/run"])
        .arg("--")
        .arg(&self_exe)
        // `--ignored` so the inner libtest runs the ignored test that
        // `--exact` selects. Without this the inner pass finds 0 tests
        // and exits 0 — outer passes spuriously.
        .args([
            "--exact",
            test_name,
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("BWRAP_INNER", "1")
        .status()
        .expect("spawn bwrap");
    assert!(status.success(), "inner test failed: {status:?}");
    None
}

/// Base netns state: `lo` up, child netns mounted at `/run/netns/
/// tbobside`. Created ONCE for the whole test; the three tunnel
/// configs share it. TUN devices are NOT created here — `Tunnel
/// Handle` does that per-config so each config gets fresh devices.
struct NetNs {
    sleeper: Child,
}

impl NetNs {
    fn setup() -> Self {
        run_ip(&["link", "set", "lo", "up"]);

        std::fs::create_dir_all("/run/netns").expect("mkdir /run/netns");
        let sleeper = Command::new("unshare")
            .args(["-n", "sleep", "3600"])
            .spawn()
            .expect("spawn unshare sleeper");
        std::thread::sleep(Duration::from_millis(100));
        std::fs::write("/run/netns/tbobside", b"").expect("touch nsfd target");
        let status = Command::new("mount")
            .args(["--bind"])
            .arg(format!("/proc/{}/ns/net", sleeper.id()))
            .arg("/run/netns/tbobside")
            .status()
            .expect("spawn mount");
        assert!(status.success(), "mount --bind nsfd: {status:?}");
        run_ip(&["netns", "exec", "tbobside", "ip", "link", "set", "lo", "up"]);

        Self { sleeper }
    }
}

impl Drop for NetNs {
    fn drop(&mut self) {
        let _ = self.sleeper.kill();
        let _ = self.sleeper.wait();
    }
}

// ═════════════════════════ daemon plumbing ═════════════════════════════════

/// Which binary backs this node. `Rust` is `CARGO_BIN_EXE_tincd`;
/// `C(path)` is the env-gated C tincd.
#[derive(Clone)]
enum Impl {
    Rust,
    C(PathBuf),
}

struct Node {
    name: &'static str,
    seed: [u8; 32],
    confbase: PathBuf,
    pidfile: PathBuf,
    socket: PathBuf,
    port: u16,
    iface: &'static str,
    subnet: &'static str,
    which: Impl,
}

impl Node {
    fn new(
        tmp: &Path,
        name: &'static str,
        seed_byte: u8,
        iface: &'static str,
        subnet: &'static str,
        which: Impl,
    ) -> Self {
        Self {
            name,
            seed: [seed_byte; 32],
            confbase: tmp.join(name),
            pidfile: tmp.join(format!("{name}.pid")),
            socket: tmp.join(format!("{name}.socket")),
            port: alloc_port(),
            iface,
            subnet,
            which,
        }
    }

    fn pubkey(&self) -> [u8; 32] {
        pubkey_from_seed(&self.seed)
    }

    fn ctl(&self) -> Ctl {
        Ctl::connect(&self.socket, &self.pidfile)
    }

    fn write_config(&self, other: &Node, connect_to: bool) {
        std::fs::create_dir_all(self.confbase.join("hosts")).unwrap();

        let mut tinc_conf = format!(
            "Name = {}\nDeviceType = tun\nInterface = {}\nAddressFamily = ipv4\n",
            self.name, self.iface
        );
        if connect_to {
            tinc_conf.push_str(&format!("ConnectTo = {}\n", other.name));
        }
        // Tight ping for fast detection of a hung daemon, but bumped
        // when profiling bob: two perf samplers + saturated receiver
        // can lose a ping under load.
        let pingtimeout = if std::env::var_os("TINCD_PERF_BOB").is_some() {
            5
        } else {
            1
        };
        tinc_conf.push_str(&format!("PingTimeout = {pingtimeout}\n"));
        std::fs::write(self.confbase.join("tinc.conf"), tinc_conf).unwrap();

        std::fs::write(
            self.confbase.join("hosts").join(self.name),
            format!("Port = {}\nSubnet = {}\n", self.port, self.subnet),
        )
        .unwrap();

        let other_pub = tinc_crypto::b64::encode(&other.pubkey());
        let mut other_cfg = format!("Ed25519PublicKey = {other_pub}\n");
        if connect_to {
            other_cfg.push_str(&format!("Address = 127.0.0.1 {}\n", other.port));
        }
        std::fs::write(self.confbase.join("hosts").join(other.name), other_cfg).unwrap();

        write_ed25519_privkey(&self.confbase, &self.seed);
    }

    /// Spawn with stderr piped to a background drain thread. The
    /// throughput test runs daemons for ~7s each at full debug log
    /// volume; the 64 KiB pipe buffer fills and `write(2, ...)` to
    /// stderr blocks the daemon's event loop. Same fix as crossimpl.
    fn spawn(&self) -> ChildWithLog {
        let child = match &self.which {
            Impl::Rust => Command::new(env!("CARGO_BIN_EXE_tincd"))
                // Rust tincd now detaches by default (C compat).
                // -D keeps it foreground so ChildWithLog can drain
                // stderr and kill it on drop.
                .arg("-D")
                .arg("-c")
                .arg(&self.confbase)
                .arg("--pidfile")
                .arg(&self.pidfile)
                .arg("--socket")
                .arg(&self.socket)
                // `info` not `debug`: at line rate, `debug` per-packet
                // logging IS the bottleneck (a fmt::Write per packet
                // shows up in the profile). The C at `-d0` is silent;
                // keep parity.
                .env("RUST_LOG", "tincd=info")
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn rust tincd"),
            Impl::C(bin) => Command::new(bin)
                .arg("-D")
                // `-d0`: no per-packet logs. The C's `-d5` floods at
                // line rate same as our `debug`.
                .arg("-d0")
                .arg("-c")
                .arg(&self.confbase)
                .arg("--pidfile")
                .arg(&self.pidfile)
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn C tincd"),
        };
        ChildWithLog::spawn(child)
    }
}

/// Read `minmtu` from a `dump nodes` row. Index 15 in the C
/// `node.c:210` format: `name id host "port" PORT cipher digest
/// maclen comp options status nexthop via distance mtu minmtu ...`.
/// PMTU discovery converges `minmtu` toward the path MTU; until it
/// reaches ≥1500, full-MSS packets fall back to TCP-tunnelled
/// SPTPS_PACKET (b64 over the meta-conn) which is ~100x slower.
fn node_minmtu(rows: &[String], name: &str) -> Option<u16> {
    rows.iter().find_map(|r| {
        let body = r.strip_prefix("18 3 ")?;
        let toks: Vec<&str> = body.split_whitespace().collect();
        if toks.first() != Some(&name) {
            return None;
        }
        toks.get(15)?.parse().ok()
    })
}

// ═══════════════════════════ tunnel lifecycle ══════════════════════════════

/// One alice↔bob tunnel: persistent TUN devices, two daemons, the
/// netns move, addresses, full handshake. Drop tears it ALL down so
/// the next config can reuse the same device names.
struct TunnelHandle {
    _tmp: TmpGuard,
    alice: Option<ChildWithLog>,
    bob: Option<ChildWithLog>,
    /// Alice's daemon PID. Captured for `perf record -p PID`.
    /// Alice is the iperf3 CLIENT side: TUN read, route, encrypt,
    /// sendto. Receiver does the inverse. Both touch the same
    /// modules at the same packet rate; profiling one side covers
    /// 90%. The Rust↔C config DOES distinguish: alice is always
    /// the Rust side there, so we always profile Rust.
    alice_pid: u32,
    /// Bob's daemon PID. Bob is the iperf3 SERVER side: recvfrom,
    /// decrypt, route, write to TUN. Send-side and recv-side
    /// optimizations show up on opposite ends; profile both.
    bob_pid: u32,
}

impl TunnelHandle {
    fn alice_log(&mut self) -> String {
        self.alice
            .take()
            .map(|c| c.kill_and_log())
            .unwrap_or_default()
    }
    fn bob_log(&mut self) -> String {
        self.bob
            .take()
            .map(|c| c.kill_and_log())
            .unwrap_or_default()
    }
}

impl Drop for TunnelHandle {
    fn drop(&mut self) {
        // Daemons first — their TUNSETIFF holds carrier; deleting
        // an attached device works but better to be tidy.
        if let Some(c) = self.alice.take() {
            let _ = c.kill_and_log();
        }
        if let Some(c) = self.bob.take() {
            let _ = c.kill_and_log();
        }
        // tincT0 stayed in the outer ns; tincT1 was moved into
        // tbobside. Delete each in its own ns. Best-effort: a
        // panic during setup may have left only one created.
        let _ = Command::new("ip")
            .args(["link", "del", "tincT0"])
            .stderr(Stdio::null())
            .status();
        let _ = Command::new("ip")
            .args(["netns", "exec", "tbobside", "ip", "link", "del", "tincT1"])
            .stderr(Stdio::null())
            .status();
    }
}

/// Build a tunnel with the given (alice, bob) implementations.
/// Returns once both sides have `validkey | udp_confirmed` set —
/// i.e. UDP data path is hot, no TCP-fallback packets in flight
/// (PACKET 17 routes now, but iperf3 wants the UDP path measured).
fn setup_tunnel(tag: &str, alice_impl: Impl, bob_impl: Impl) -> TunnelHandle {
    // ─── fresh persistent TUN devices ──────────────────────────
    run_ip(&["tuntap", "add", "mode", "tun", "name", "tincT0"]);
    run_ip(&["tuntap", "add", "mode", "tun", "name", "tincT1"]);
    run_ip(&["link", "set", "tincT0", "up"]);
    run_ip(&["link", "set", "tincT1", "up"]);

    let tmp = tmp(tag);
    let alice = Node::new(
        tmp.path(),
        "alice",
        0xAC,
        "tincT0",
        "10.44.0.1/32",
        alice_impl,
    );
    let bob = Node::new(tmp.path(), "bob", 0xBC, "tincT1", "10.44.0.2/32", bob_impl);

    bob.write_config(&alice, false);
    alice.write_config(&bob, true);

    // ─── spawn ──────────────────────────────────────────────────
    let bob_child = bob.spawn();
    let bob_pid = bob_child.pid();
    if !wait_for_file(&bob.socket) {
        panic!("bob setup failed; stderr:\n{}", bob_child.kill_and_log());
    }
    let alice_child = alice.spawn();
    let alice_pid = alice_child.pid();
    if !wait_for_file(&alice.socket) {
        let bs = bob_child.kill_and_log();
        panic!(
            "alice setup failed; stderr:\n{}\n=== bob ===\n{bs}",
            alice_child.kill_and_log()
        );
    }

    // From this point on we have a TunnelHandle so drop cleans up
    // the TUN devices even if a later poll panics.
    let mut handle = TunnelHandle {
        _tmp: tmp,
        alice: Some(alice_child),
        bob: Some(bob_child),
        alice_pid,
        bob_pid,
    };

    // ─── carrier, move, addresses ───────────────────────────────
    if !wait_for_carrier("tincT0", Duration::from_secs(2)) {
        let a = handle.alice_log();
        let b = handle.bob_log();
        panic!("alice TUNSETIFF;\n=== alice ===\n{a}\n=== bob ===\n{b}");
    }
    assert!(
        wait_for_carrier("tincT1", Duration::from_secs(2)),
        "bob TUNSETIFF"
    );

    run_ip(&["link", "set", "tincT1", "netns", "tbobside"]);
    run_ip(&["addr", "add", "10.44.0.1/24", "dev", "tincT0"]);
    run_ip(&["link", "set", "tincT0", "up"]);
    run_ip(&[
        "netns",
        "exec",
        "tbobside",
        "ip",
        "addr",
        "add",
        "10.44.0.2/24",
        "dev",
        "tincT1",
    ]);
    run_ip(&[
        "netns", "exec", "tbobside", "ip", "link", "set", "tincT1", "up",
    ]);

    // ─── handshake ──────────────────────────────────────────────
    let mut alice_ctl = alice.ctl();
    let mut bob_ctl = bob.ctl();

    // Reachable (status bit 4): meta-SPTPS done, graph() ran.
    let meta = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        poll_until(Duration::from_secs(10), || {
            let a = alice_ctl.dump(3);
            let b = bob_ctl.dump(3);
            let a_ok = node_status(&a, "bob").is_some_and(|s| s & 0x10 != 0);
            let b_ok = node_status(&b, "alice").is_some_and(|s| s & 0x10 != 0);
            if a_ok && b_ok { Some(()) } else { None }
        });
    }));
    if meta.is_err() {
        let a = handle.alice_log();
        let b = handle.bob_log();
        panic!("meta handshake timed out;\n=== alice ===\n{a}\n=== bob ===\n{b}");
    }

    // Kick the per-tunnel handshake. First packet hits send_sptps_
    // packet with !validkey → dropped, but triggers REQ_KEY.
    let _ = Command::new("ping")
        .args(["-c", "1", "-W", "1", "10.44.0.2"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    // validkey (bit 1) + udp_confirmed (bit 7). Both bits, both
    // sides. Without udp_confirmed the C falls back to TCP-
    // tunnelled PACKET frames; the Rust daemon drops those, so
    // the iperf3 stream would crater immediately.
    const VALIDKEY: u32 = 0x02;
    const UDP_CONFIRMED: u32 = 0x80;
    let validkey = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        poll_until(Duration::from_secs(10), || {
            let a = alice_ctl.dump(3);
            let b = bob_ctl.dump(3);
            let want = VALIDKEY | UDP_CONFIRMED;
            let a_ok = node_status(&a, "bob").is_some_and(|s| s & want == want);
            let b_ok = node_status(&b, "alice").is_some_and(|s| s & want == want);
            if a_ok && b_ok { Some(()) } else { None }
        });
    }));
    if validkey.is_err() {
        let a = handle.alice_log();
        let b = handle.bob_log();
        panic!("validkey/udp_confirmed timed out;\n=== alice ===\n{a}\n=== bob ===\n{b}");
    }

    // PMTU convergence: wait for `minmtu ≥ 1500` so full-MSS TCP
    // segments (1500-byte IP packets) take the UDP path. Without
    // this, `send_sptps_data`'s `origlen > relay->minmtu` gate
    // sends them via TCP-tunnelled SPTPS_PACKET (b64 over the
    // meta-conn) at ~10 Mbps instead of ~1 Gbps.
    //
    // The C avoids this wait via `choose_initial_maxmtu` (`net_
    // packet.c:1249`): `getsockopt(IP_MTU)` on a connected socket
    // returns the kernel's PMTU cache; on loopback that's 65536,
    // clamped to MTU=1518, and the very first probe at maxmtu
    // confirms in one round-trip. We `STUB(chunk-9c)` that
    // getsockopt, seed `maxmtu=MTU`, and walk the exponential probe
    // ladder (1329, 1407, ...) at 333ms intervals: ~2-3s to 1500.
    //
    // `try_tx` (which calls `pmtu.tick()`) only fires on VPN packet
    // egress — not ctl-dump traffic. Ping inside the poll loop.
    let pmtu = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        poll_until(Duration::from_secs(10), || {
            // One ping drives one `try_tx` per side. The 333ms
            // probe cadence is the bottleneck, not ping rate.
            let _ = Command::new("ping")
                .args(["-c", "1", "-W", "1", "10.44.0.2"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            let a = alice_ctl.dump(3);
            let b = bob_ctl.dump(3);
            let a_ok = node_minmtu(&a, "bob").is_some_and(|m| m >= 1500);
            let b_ok = node_minmtu(&b, "alice").is_some_and(|m| m >= 1500);
            if a_ok && b_ok { Some(()) } else { None }
        });
    }));
    if pmtu.is_err() {
        let a = handle.alice_log();
        let b = handle.bob_log();
        panic!("PMTU convergence (minmtu>=1500) timed out;\n=== alice ===\n{a}\n=== bob ===\n{b}");
    }

    handle
}

// ═══════════════════════════ iperf3 measurement ════════════════════════════

#[derive(Debug, serde::Deserialize)]
struct IperfResult {
    end: IperfEnd,
}
#[derive(Debug, serde::Deserialize)]
struct IperfEnd {
    /// Server-side received throughput. The client-side `sum_sent`
    /// can include bytes still in flight; `sum_received` is what
    /// actually made it through the tunnel + got ACKed.
    sum_received: IperfSum,
}
#[derive(Debug, serde::Deserialize)]
struct IperfSum {
    bits_per_second: f64,
}

/// Run iperf3 server in tbobside, client in the outer ns. 5s, JSON.
///
/// The mechanics: the test process IS in the outer netns (alice's
/// side). `ip netns exec tbobside ...` works because `NetNs::setup`
/// bind-mounted the sleeper's nsfd at `/run/netns/tbobside` — `ip
/// netns exec NAME` is just `setns(open("/run/netns/NAME"))` + exec.
/// `--bind / /` in the bwrap args means the nix-store iperf3 binary
/// is visible at the same path inside.
///
/// `--one-off`: server exits after one client. Otherwise it leaks
/// across the three configs and the second `iperf3 -s` gets EADDRINUSE.
fn measure(handle: &mut TunnelHandle) -> f64 {
    // ─── server in bob's netns ─────────────────────────────────
    let mut server = Command::new("ip")
        .args(["netns", "exec", "tbobside", "iperf3", "-s", "--one-off"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn iperf3 server");

    // Server bind is asynchronous. Poll for the listener — iperf3's
    // default port is 5201. We can't `TcpStream::connect` from the
    // outer ns to check (that would go through the TUNNEL, before
    // we know it works). Instead: just sleep. iperf3 binds in <10ms;
    // 200ms is generous and dwarfed by the 5s measurement.
    std::thread::sleep(Duration::from_millis(200));

    // ─── client in outer ns (= test process's ns) ──────────────
    // `-t 5`: 5 seconds. Short enough for fast turnaround, long
    // enough for ChaCha20 to warm caches and TCP to ramp up. If
    // variance is too high on a loaded CI box, bump to `-t 10` or
    // median-of-3; the 95% gate has slop for now.
    let client = Command::new("iperf3")
        .args(["-c", "10.44.0.2", "-t", "5", "--json"])
        .output()
        .expect("spawn iperf3 client");

    // Reap the server. `--one-off` means it exited when the client
    // disconnected; `wait` is just zombie cleanup.
    let _ = server.wait();

    if !client.status.success() {
        let mut srv_err = String::new();
        if let Some(mut e) = server.stderr.take() {
            use std::io::Read;
            let _ = e.read_to_string(&mut srv_err);
        }
        let a = handle.alice_log();
        let b = handle.bob_log();
        panic!(
            "iperf3 client failed: {:?}\n\
             client stdout: {}\nclient stderr: {}\n\
             server stderr: {}\n\
             === alice ===\n{a}\n=== bob ===\n{b}",
            client.status,
            String::from_utf8_lossy(&client.stdout),
            String::from_utf8_lossy(&client.stderr),
            srv_err,
        );
    }

    let parsed: IperfResult = serde_json::from_slice(&client.stdout).unwrap_or_else(|e| {
        panic!(
            "iperf3 JSON parse: {e}\nstdout: {}",
            String::from_utf8_lossy(&client.stdout)
        )
    });
    parsed.end.sum_received.bits_per_second
}

// ═══════════════════════════ perf record ═══════════════════════════════════

/// `perf trace -s -p PID`: exact syscall counts and per-call latency,
/// RAII-stopped. Unlike `perf record` (statistical sampling, output
/// shape depends on unwinder quality) this uses kernel tracepoints —
/// every syscall enter/exit is recorded. The summary lists call
/// COUNT, total time, and avg/max latency per syscall name. This is
/// the ground truth for "do we issue more syscalls per packet than
/// C, or does each one cost more".
///
/// Gated on `TINCD_TRACE=1`. Needs root or `CAP_PERFMON` (tracefs
/// `events/raw_syscalls/sys_{enter,exit}` is `0640 root:root` by
/// default; remountable with `mount -o remount,mode=755 /sys/kernel/
/// tracing` but that's a host-wide change). Run the test under sudo
/// for one-off measurements:
///
/// ```sh
/// sudo -E env PATH=$PATH TINCD_TRACE=1 cargo nextest run -p tincd \
///   --release -E 'test(/throughput/)' --run-ignored ignored-only
/// ```
///
/// Tracepoint overhead is much lower than `strace -c` (no ptrace
/// stops, no context switch per syscall — just a ringbuffer write).
/// Still nonzero; throughput under trace is comparable but not
/// identical to a clean run. Use the COUNTS, not the wall time.
struct PerfTrace {
    child: Option<Child>,
    out: PathBuf,
}

impl PerfTrace {
    fn start(pid: u32, out: &Path) -> Self {
        if std::env::var_os("TINCD_TRACE").is_none() {
            return Self {
                child: None,
                out: out.into(),
            };
        }
        // -s: summary only at exit (not per-syscall lines, which
        //   would be millions at line rate).
        // -o: file, not stderr. We're already piping daemon stderr
        //   for the failure log; mixing them is unreadable.
        // No -e filter: we want ALL syscalls. The summary is short.
        let child = Command::new("perf")
            .args(["trace", "-s", "-p"])
            .arg(pid.to_string())
            .arg("-o")
            .arg(out)
            .stderr(Stdio::null())
            .spawn()
            .ok();
        match &child {
            Some(c) => eprintln!(
                "perf trace -s -p {pid} -> {} (pid {})",
                out.display(),
                c.id()
            ),
            None => eprintln!(
                "perf trace unavailable (needs root/CAP_PERFMON for tracefs; \
                 run test under `sudo -E env PATH=$PATH TINCD_TRACE=1 ...`)"
            ),
        }
        Self {
            child,
            out: out.into(),
        }
    }
}

impl Drop for PerfTrace {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            // Same SIGINT-then-wait as PerfRecord. perf trace flushes
            // the summary on SIGINT.
            // SAFETY: see PerfRecord::drop.
            unsafe {
                libc::kill(child.id() as i32, libc::SIGINT);
            }
            let _ = child.wait();
        }
        // Dump the summary inline. It's short (~20 lines, one per
        // syscall). The whole point is to read it side-by-side with
        // the C run in test output.
        if let Ok(s) = std::fs::read_to_string(&self.out) {
            // perf trace -s output starts with a blank line + a
            // "Summary of events:" header. Keep it; the formatting
            // is already a nice table.
            if !s.trim().is_empty() {
                eprintln!("--- syscall trace ({}) ---", self.out.display());
                for line in s.lines() {
                    eprintln!("  {line}");
                }
            }
        }
    }
}

/// `perf record -p PID -g -F 999`, RAII-stopped. Drop → SIGINT →
/// wait. SIGINT is the documented "finish writing, exit cleanly"
/// signal for `perf record`; SIGTERM/SIGKILL would truncate.
///
/// `.spawn().ok()` not `.unwrap()`: perf-unavailable degrades to
/// throughput-only. The 95% gate doesn't NEED the profile; the
/// profile is for the human reading the failure.
///
/// Gated on `TINCD_PERF=1`: perf record adds measurable overhead
/// (kernel sampling interrupts, ring buffer copies) that skews the
/// very throughput we're measuring. Default-off keeps the gate
/// clean; opt-in when you need to know WHERE the cycles go.
struct PerfRecord {
    child: Option<Child>,
}

impl PerfRecord {
    fn start(pid: u32, out: &Path) -> Self {
        if std::env::var_os("TINCD_PERF").is_none() {
            return Self { child: None };
        }
        // -g: call graphs. Without this you get the leaf only —
        //   "80% in chacha20_avx2" doesn't say whether that's
        //   encrypt-on-send or decrypt-on-recv. With -g you get
        //   the chain back through send_sptps_data / on_udp_recv.
        //
        // -F 999: 999 Hz, not 1000 — stay off any kernel periodic
        //   tick alignment. 5s × 999/s ≈ 5k samples per CPU,
        //   enough resolution for anything ≥ 1% of time.
        //
        // No --call-graph=dwarf: dev profile has frame pointers
        //   (Cargo default in debug). dwarf is more accurate but
        //   perf has to capture stacks on-the-fly — measurable
        //   overhead. fp is fine.
        //
        // perf_event_open(2) is gated by `kernel.perf_event_
        // paranoid` (host-wide sysctl, the bwrap userns doesn't
        // help). `<= 1` lets unprivileged users record their own
        // processes; Debian defaults to `2`. We can't fix the
        // sysctl from inside the test — feature-detect and degrade.
        let child = Command::new("perf")
            .args(["record", "-g", "-F", "999", "-p"])
            .arg(pid.to_string())
            .arg("-o")
            .arg(out)
            .stderr(Stdio::null())
            .spawn()
            .ok();
        match &child {
            Some(c) => eprintln!("perf record -p {pid} -> {} (pid {})", out.display(), c.id()),
            None => eprintln!(
                "perf record unavailable; throughput measured without profile \
                 (perf not on PATH, or kernel.perf_event_paranoid >= 2 — \
                 `sysctl kernel.perf_event_paranoid=1` to enable)"
            ),
        }
        Self { child }
    }
}

impl Drop for PerfRecord {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            // SAFETY: `kill(2)` is async-signal-safe and has no
            // preconditions on a valid PID. The PID is ours (we
            // spawned it, haven't waited it yet). Worst case the
            // PID was reused — but we hold the Child, so it
            // hasn't been reaped, so the PID is still ours.
            unsafe {
                libc::kill(child.id() as i32, libc::SIGINT);
            }
            let _ = child.wait();
        }
    }
}

/// Top self-time symbols to stderr. Runs even on the green path —
/// the profile is the baseline for the NEXT regression.
///
/// `--no-children`: without it perf attributes a callee's time to
/// ALL its callers, so `Daemon::run` shows 99%. We want SELF time —
/// where the cycles actually burn.
///
/// A HEALTHY profile (Rust within noise of C) looks like ~35%
/// chacha20/poly1305, ~15% `[k] copy_user_*` (kernel↔userspace
/// copies for TUN+UDP — same on both impls), ~10% syscall+UDP
/// stack, <5% anything in `tincd::`. If `_ZN5alloc7raw_vec...` is
/// at 20% there's a per-packet `Vec::clone` somewhere — check
/// `on_udp_recv`/`route_ipv4` for `.to_vec()`.
fn report_hot_symbols(data: &Path) {
    if !data.exists() {
        return; // perf didn't run
    }
    let out = Command::new("perf")
        .args([
            "report",
            "--stdio",
            "--no-children",
            "-g",
            "none",
            "--sort",
            "overhead,symbol",
            "--percent-limit",
            "1.0",
            "-i",
        ])
        .arg(data)
        .output();
    let Ok(out) = out else { return };
    eprintln!("--- top symbols ({}) ---", data.display());
    // Skip the # comment header. First 10 data lines. perf doesn't
    // demangle Rust v0 symbols; `_ZN5tincd6daemon...` is mostly
    // readable anyway (the module path is in there). Not pulling
    // a demangling crate for this.
    for line in String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| !l.trim_start().starts_with('#') && !l.trim().is_empty())
        .take(10)
    {
        eprintln!("  {line}");
    }
    eprintln!("  full report: perf report -i {}", data.display());
}

// ═══════════════════════════════ the test ══════════════════════════════════

#[test]
#[ignore = "throughput gate — run on demand: \
            cargo nextest run --run-ignored ignored-only -E 'test(throughput)'"]
fn rust_vs_c_throughput() {
    let Some(netns) = enter_netns("rust_vs_c_throughput") else {
        return;
    };

    let c_bin = c_tincd_bin().expect("gate checked in enter_netns");
    let perf_on = std::env::var_os("TINCD_PERF").is_some();
    let trace_on = std::env::var_os("TINCD_TRACE").is_some();
    let perf_out = std::env::var_os("TINCD_PERF_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp/tincd-perf"));
    if perf_on || trace_on {
        std::fs::create_dir_all(&perf_out).ok();
    } else {
        eprintln!("(set TINCD_PERF=1 for sampling profile, TINCD_TRACE=1 for syscall counts)");
    }

    // ─── 1. C↔C baseline ───────────────────────────────────────
    eprintln!("--- C↔C baseline ---");
    let mut cc = setup_tunnel("cc", Impl::C(c_bin.clone()), Impl::C(c_bin.clone()));
    // TINCD_PERF profiles alice (sender). TINCD_PERF_BOB additionally
    // profiles bob (receiver) — opt-in because two `perf -F 999`
    // samplers + PingTimeout=1 + a saturated receiver is enough
    // overhead to flap the meta-conn on slow hosts. Set both envs.
    let perf_bob = std::env::var_os("TINCD_PERF_BOB").is_some();
    let c_perf_path = perf_out.join("c-alice.perf.data");
    let c_bob_perf_path = perf_out.join("c-bob.perf.data");
    let baseline = {
        let _perf_a = PerfRecord::start(cc.alice_pid, &c_perf_path);
        let _perf_b = perf_bob.then(|| PerfRecord::start(cc.bob_pid, &c_bob_perf_path));
        let _trace_a = PerfTrace::start(cc.alice_pid, &perf_out.join("c-alice.trace"));
        let _trace_b = PerfTrace::start(cc.bob_pid, &perf_out.join("c-bob.trace"));
        measure(&mut cc)
        // _perf drops here → SIGINT → perf flushes + exits
    };
    drop(cc);
    eprintln!("C↔C: {:.1} Mbps", baseline / 1e6);

    // ─── 2. Rust↔Rust ──────────────────────────────────────────
    eprintln!("--- Rust↔Rust ---");
    let mut rr = setup_tunnel("rr", Impl::Rust, Impl::Rust);
    let r_perf_path = perf_out.join("rust-alice.perf.data");
    let r_bob_perf_path = perf_out.join("rust-bob.perf.data");
    let rust = {
        let _perf_a = PerfRecord::start(rr.alice_pid, &r_perf_path);
        let _perf_b = perf_bob.then(|| PerfRecord::start(rr.bob_pid, &r_bob_perf_path));
        let _trace_a = PerfTrace::start(rr.alice_pid, &perf_out.join("rust-alice.trace"));
        let _trace_b = PerfTrace::start(rr.bob_pid, &perf_out.join("rust-bob.trace"));
        measure(&mut rr)
    };
    drop(rr);
    eprintln!("Rust↔Rust: {:.1} Mbps", rust / 1e6);

    // ─── 3. Rust↔C ─────────────────────────────────────────────
    // Alice is Rust (so `alice_pid` is the Rust daemon — that's
    // what we'd want to profile here too, but two profiles is
    // enough; the interesting one is Rust↔Rust).
    eprintln!("--- Rust↔C ---");
    let mut rc = setup_tunnel("rc", Impl::Rust, Impl::C(c_bin));
    let mixed = measure(&mut rc);
    drop(rc);
    eprintln!("Rust↔C: {:.1} Mbps", mixed / 1e6);

    // ─── ratio ──────────────────────────────────────────────────
    let ratio = rust / baseline;
    eprintln!("Rust/C ratio: {:.1}%", ratio * 100.0);

    // Hot-symbol report before the assert. If the gate fails, the
    // next thing anyone does is open the profile; if it passes,
    // the profile is the baseline for the next regression. Only
    // when perf actually ran — `report_hot_symbols` checks file
    // existence too, but skip the noise entirely when off.
    if perf_on {
        report_hot_symbols(&r_perf_path);
        if perf_bob {
            report_hot_symbols(&r_bob_perf_path);
        }
        report_hot_symbols(&c_perf_path);
        if perf_bob {
            report_hot_symbols(&c_bob_perf_path);
        }
        eprintln!("perf data: {}", perf_out.display());
    }

    // ─── the gate ───────────────────────────────────────────────
    // Profile-aware. `cfg!(debug_assertions)` is true for the
    // `dev` profile, false for `release`. `CARGO_BIN_EXE_tincd`
    // is built with the same profile as this test binary, so the
    // check correctly reflects which daemon we spawned.
    //
    // RELEASE: 95% is the real gate. The chunk-11-perf STUBs
    //   (recvmmsg, per-packet Vec allocs in send_record_priv,
    //   maybe_set_write_any walking all conns) cost ~15-20%
    //   today — see the perf profile. STUB(chunk-11-perf): close
    //   that gap, then this gate passes.
    //
    // DEV: 1% catches deadlocks, drain-loop starvation, the
    //   tunnel-goes-dark class of bugs. The edge-triggered
    //   meta-conn read deadlock (0.0 Mbps, fixed in this commit)
    //   would still fail it; a per-packet copy regression
    //   wouldn't. Unoptimized chacha20+poly1305 plus malloc-per-
    //   packet is ~50x slower than C release — not a regression,
    //   just the dev profile.
    let (gate, profile) = if cfg!(debug_assertions) {
        (0.01, "dev")
    } else {
        (0.95, "release")
    };
    eprintln!("gate: {:.0}% ({profile} profile)", gate * 100.0);
    assert!(
        ratio >= gate,
        "Rust throughput is {:.1}% of C baseline — below 95% gate. \
         Baseline {:.1} Mbps, Rust {:.1} Mbps. \
         Check the hot-symbol report above for per-packet allocations \
         (_ZN5alloc...) or extra copies (memcpy at higher % than C). \
         For the real gate, run with --release.",
        ratio * 100.0,
        baseline / 1e6,
        rust / 1e6
    );

    // Mixed-mode sanity. If Rust↔C << Rust↔Rust there's a wire-
    // format inefficiency (extra round-trips, padding mismatch).
    let mixed_ratio = mixed / rust;
    assert!(
        mixed_ratio >= 0.90,
        "Rust↔C is {:.1}% of Rust↔Rust — interop overhead. \
         Rust↔Rust {:.1} Mbps, Rust↔C {:.1} Mbps.",
        mixed_ratio * 100.0,
        rust / 1e6,
        mixed / 1e6
    );

    drop(netns);
}
