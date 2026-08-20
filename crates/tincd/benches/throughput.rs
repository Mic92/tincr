//! Throughput benchmark: iperf3 through two real daemons over real
//! TUNs in a bwrap netns, C tincd as the baseline.
//!
//! ```sh
//! cargo bench --bench throughput --profile profiling
//! cargo bench --bench throughput -- rust_rust   # one pairing only
//! cargo bench --bench throughput -- latency     # latency only (idle + load)
//! ```
//!
//! Runs C↔C, Rust↔Rust and Rust↔C sequentially and reports the
//! Rust/C ratio — absolute numbers are machine-specific, the ratio
//! is what you compare across commits. Same bwrap re-exec as
//! `netns.rs`/`crossimpl.rs`; distinct device/netns names so nextest
//! parallelism doesn't collide.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!(
        "SKIP throughput: linux-only (needs netns + TUN); \
         on macOS use `cargo bench --bench throughput_macos`"
    );
}

#[cfg(target_os = "linux")]
fn main() {
    bench::main();
}

// Benches can't `mod common;` from tests/; `#[path]` is less churn
// than promoting common/ to a crate.
#[cfg(target_os = "linux")]
#[path = "../tests/common/mod.rs"]
mod common;

#[cfg(target_os = "linux")]
mod bench {

    use std::fmt::Write as _;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::time::Duration;

    use super::common;
    use common::bench::{
        Impl, IperfResult, PingStats, c_tincd_bin, iperf3_available, node_minmtu, parse_iperf,
    };
    use common::linux::{run_ip, wait_for_carrier};
    use common::{
        ChildWithLog, Ctl, TmpGuard, alloc_port, node_status, poll_until, pubkey_from_seed,
        wait_for_file, write_ed25519_privkey,
    };

    fn tmp(tag: &str) -> TmpGuard {
        TmpGuard::new("thr", tag)
    }

    // bwrap re-exec: copy of crossimpl.rs::enter_netns (see netns.rs
    // for the flag-by-flag explanation).

    fn enter_netns() -> Option<NetNs> {
        if std::env::var_os("BWRAP_INNER").is_some() {
            return Some(NetNs::setup());
        }

        // Env gates BEFORE the bwrap probe — common skip path is
        // "TINC_C_TINCD unset" or "iperf3 not in PATH".
        if c_tincd_bin().is_none() {
            eprintln!(
                "SKIP throughput: TINC_C_TINCD not set. \
             `nix develop` sets it; outside nix: \
             `nix build .#tincd-c` then \
             `TINC_C_TINCD=$PWD/result/sbin/tincd`."
            );
            return None;
        }
        if !iperf3_available() {
            eprintln!("SKIP throughput: iperf3 not on PATH (nix develop provides it)");
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
                eprintln!("SKIP throughput: bwrap not found ({e})");
                return None;
            }
            Ok(out) if !out.status.success() => {
                eprintln!(
                    "SKIP throughput: bwrap probe failed (unprivileged userns disabled?): {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                );
                return None;
            }
            Ok(_) => {}
        }
        if !Path::new("/dev/net/tun").exists() {
            eprintln!("SKIP throughput: /dev/net/tun missing");
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
            // Forward filter args so `cargo bench -- rust_rust`
            // survives the re-exec.
            .args(std::env::args_os().skip(1))
            .env("BWRAP_INNER", "1")
            .status()
            .expect("spawn bwrap");
        std::process::exit(status.code().unwrap_or(1));
    }

    /// Base netns state, created once and shared by all configs:
    /// `lo` up, child netns mounted at `/run/netns/tbobside`.
    /// TUN devices are per-config (`TunnelHandle`).
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

    // daemon plumbing

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
            // Same env knob as throughput_macos.rs.
            let sptps_cipher = std::env::var("TINCD_BENCH_SPTPS_CIPHER")
                .map(|c| format!("SPTPSCipher = {c}\n"))
                .unwrap_or_default();

            let mut tinc_conf = format!(
                "Name = {}\nDeviceType = tun\nInterface = {}\nAddressFamily = ipv4\n",
                self.name, self.iface
            );
            if connect_to {
                let _ = writeln!(tinc_conf, "ConnectTo = {}", other.name);
            }
            // Tight ping to detect a hung daemon fast; looser under
            // TINCD_PERF (samplers can delay a ping cycle).
            let pingtimeout = if std::env::var_os("TINCD_PERF").is_some() {
                5
            } else {
                1
            };
            let _ = writeln!(tinc_conf, "PingTimeout = {pingtimeout}");
            tinc_conf.push_str(&sptps_cipher);
            std::fs::write(self.confbase.join("tinc.conf"), tinc_conf).unwrap();

            std::fs::write(
                self.confbase.join("hosts").join(self.name),
                format!("Port = {}\nSubnet = {}\n", self.port, self.subnet),
            )
            .unwrap();

            let other_pub = tinc_crypto::b64::encode(&other.pubkey());
            let mut other_cfg = format!("Ed25519PublicKey = {other_pub}\n");
            if connect_to {
                let _ = writeln!(other_cfg, "Address = 127.0.0.1 {}", other.port);
            }
            std::fs::write(self.confbase.join("hosts").join(other.name), other_cfg).unwrap();

            write_ed25519_privkey(&self.confbase, &self.seed);
        }

        /// Spawn with stderr piped to a background drain thread so a
        /// full pipe never blocks the daemon (same fix as crossimpl).
        fn spawn(&self) -> ChildWithLog {
            let child = match &self.which {
                Impl::Rust => Command::new(env!("CARGO_BIN_EXE_tincd"))
                    // -D: stay foreground for ChildWithLog.
                    .arg("-D")
                    .arg("-c")
                    .arg(&self.confbase)
                    .arg("--pidfile")
                    .arg(&self.pidfile)
                    .arg("--socket")
                    .arg(&self.socket)
                    // info, not debug: per-packet logging would be
                    // the bottleneck. C runs -d0; keep parity.
                    .env("RUST_LOG", "tincd=info")
                    // Non-dumpable targets fail perf attach (EACCES).
                    .envs(std::env::var_os("TINCD_PERF").map(|_| ("TINCR_ALLOW_COREDUMP", "1")))
                    .stderr(Stdio::piped())
                    .spawn()
                    .expect("spawn rust tincd"),
                Impl::C(bin) => Command::new(bin)
                    .arg("-D")
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

    // tunnel lifecycle

    /// One alice↔bob tunnel: persistent TUN devices, two daemons, the
    /// netns move, addresses, full handshake. Drop tears it ALL down so
    /// the next config can reuse the same device names.
    struct TunnelHandle {
        _tmp: TmpGuard,
        alice: Option<ChildWithLog>,
        bob: Option<ChildWithLog>,
        /// For `perf record -p`. Alice = iperf3 client side (encrypt
        /// heavy), bob = server side (decrypt heavy); profile both.
        alice_pid: u32,
        bob_pid: u32,
    }

    impl TunnelHandle {
        fn alice_log(&mut self) -> String {
            self.alice
                .take()
                .map(ChildWithLog::kill_and_log)
                .unwrap_or_default()
        }
        fn bob_log(&mut self) -> String {
            self.bob
                .take()
                .map(ChildWithLog::kill_and_log)
                .unwrap_or_default()
        }
    }

    impl Drop for TunnelHandle {
        fn drop(&mut self) {
            // Daemons first, then devices (each in its own netns).
            if let Some(c) = self.alice.take() {
                let _ = c.kill_and_log();
            }
            if let Some(c) = self.bob.take() {
                let _ = c.kill_and_log();
            }
            // Best-effort: setup may have panicked mid-way.
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
    /// Returns once both sides have `validkey | udp_confirmed` — the
    /// UDP data path is hot, no TCP fallback in flight.
    fn setup_tunnel(tag: &str, alice_impl: Impl, bob_impl: Impl) -> TunnelHandle {
        // Node status bits (`node.h:41`).
        const VALIDKEY: u32 = 0x02;
        const UDP_CONFIRMED: u32 = 0x80;

        // multi_queue only for Rust ends; C tinc needs a plain device.
        let add_tun = |name: &str, is_rust: bool| {
            if is_rust {
                run_ip(&["tuntap", "add", "mode", "tun", "multi_queue", "name", name]);
            } else {
                run_ip(&["tuntap", "add", "mode", "tun", "name", name]);
            }
        };
        add_tun("tincT0", matches!(alice_impl, Impl::Rust));
        add_tun("tincT1", matches!(bob_impl, Impl::Rust));
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

        // spawn
        let bob_child = bob.spawn();
        let bob_pid = bob_child.pid();
        assert!(
            wait_for_file(&bob.socket),
            "bob setup failed; stderr:\n{}",
            bob_child.kill_and_log()
        );
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

        // carrier, move, addresses
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

        // handshake
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

        // Kick the per-tunnel handshake (first packet triggers REQ_KEY).
        let _ = Command::new("ping")
            .args(["-c", "1", "-W", "1", "10.44.0.2"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        // Both bits on both sides; without udp_confirmed traffic
        // would take the TCP fallback and crater the measurement.
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

        // PMTU convergence: minmtu ≥ 1500 so full-MSS segments take
        // the UDP path instead of the ~10 Mbps TCP fallback. The ping
        // inside the loop drives `pmtu.tick()` (VPN egress only);
        // loopback converges in ~1s.
        let pmtu = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            poll_until(Duration::from_secs(10), || {
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
            panic!(
                "PMTU convergence (minmtu>=1500) timed out;\n=== alice ===\n{a}\n=== bob ===\n{b}"
            );
        }

        handle
    }

    // iperf3 measurement

    /// iperf3 server in tbobside, client in the outer ns; 5s, JSON.
    /// `--one-off` so the next config's server doesn't hit EADDRINUSE.
    fn measure(handle: &mut TunnelHandle) -> f64 {
        let mut server = Command::new("ip")
            .args(["netns", "exec", "tbobside", "iperf3", "-s", "--one-off"])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn iperf3 server");

        // Server bind is async; can't connect-probe from this ns
        // (that would go through the tunnel). 200ms is generous.
        std::thread::sleep(Duration::from_millis(200));

        let client = Command::new("iperf3")
            .args(["-c", "10.44.0.2", "-t", "5", "--json"])
            .output()
            .expect("spawn iperf3 client");

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

        parse_iperf(&client.stdout).end.sum_received.bits_per_second
    }

    // Latency: batching cost is tail latency, invisible to
    // throughput. Ping under iperf3 load, report percentiles.

    /// `ping -c COUNT -i 0.01 -D`, parse per-packet RTTs. Loss is
    /// reported, not asserted — drops under saturation are normal.
    fn ping_rtts(count: u32) -> PingStats {
        let out = Command::new("ping")
            .arg("-c")
            .arg(count.to_string())
            .args(["-i", "0.01", "-D", "10.44.0.2"])
            .output()
            .expect("spawn ping");
        // ping exits non-zero on any loss; parse what we got.
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stats = PingStats::parse(&stdout, count);
        assert!(
            !stats.rtts_ms.is_empty(),
            "ping got zero replies (tunnel dead?):\nstdout:\n{stdout}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        stats
    }

    /// Idle RTT baseline: nothing flowing but the pings.
    fn measure_latency_idle(_handle: &mut TunnelHandle) -> PingStats {
        ping_rtts(100)
    }

    /// RTT under iperf3 load — the queueing delay batching adds.
    /// `-t 3`: load just needs to outlast the ~1s ping run.
    fn measure_latency_load(handle: &mut TunnelHandle) -> (f64, PingStats) {
        let mut server = Command::new("ip")
            .args(["netns", "exec", "tbobside", "iperf3", "-s", "--one-off"])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn iperf3 server");
        std::thread::sleep(Duration::from_millis(200));

        // Backgrounded so ping runs concurrently; --json to report
        // the Mbps the latency was measured at.
        let client = Command::new("iperf3")
            .args(["-c", "10.44.0.2", "-t", "3", "--json"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn iperf3 client");

        // TCP slow-start ramp before measuring.
        std::thread::sleep(Duration::from_millis(500));

        let ping = ping_rtts(100);

        let client_out = client.wait_with_output().expect("wait iperf3 client");
        let _ = server.wait();

        if !client_out.status.success() {
            let mut srv_err = String::new();
            if let Some(mut e) = server.stderr.take() {
                use std::io::Read;
                let _ = e.read_to_string(&mut srv_err);
            }
            let a = handle.alice_log();
            let b = handle.bob_log();
            panic!(
                "iperf3 client (latency-load) failed: {:?}\n\
                 client stderr: {}\nserver stderr: {}\n\
                 === alice ===\n{a}\n=== bob ===\n{b}",
                client_out.status,
                String::from_utf8_lossy(&client_out.stderr),
                srv_err,
            );
        }

        let parsed: IperfResult = parse_iperf(&client_out.stdout);
        (parsed.end.sum_received.bits_per_second, ping)
    }

    /// One latency pairing: idle then under-load on the same tunnel,
    /// so the only variable is the load.
    fn run_latency(
        p: &Pairing,
        do_idle: bool,
        do_load: bool,
    ) -> (Option<PingStats>, Option<(f64, PingStats)>) {
        eprintln!("--- latency {} ---", p.label);
        // Distinct tmpdir from the throughput run of the same pairing.
        let mut tunnel = setup_tunnel(&format!("lat-{}", p.tag), p.alice.clone(), p.bob.clone());

        let idle = do_idle.then(|| {
            let s = measure_latency_idle(&mut tunnel);
            eprintln!(
                "  idle:  p50={:>7.3}ms  p99={:>7.3}ms  max={:>7.3}ms  ({}/{} recv)",
                s.p50(),
                s.p99(),
                s.max(),
                s.recv(),
                s.sent
            );
            s
        });

        let load = do_load.then(|| {
            let (bps, s) = measure_latency_load(&mut tunnel);
            eprintln!(
                "  load:  p50={:>7.3}ms  p99={:>7.3}ms  max={:>7.3}ms  ({}/{} recv, {:.0} Mbps)",
                s.p50(),
                s.p99(),
                s.max(),
                s.recv(),
                s.sent,
                bps / 1e6
            );
            (bps, s)
        });

        // No per-pairing gate: the load/idle ratio is dominated by
        // how good idle is. The cross-impl Δ at the end is the signal.
        drop(tunnel);
        (idle, load)
    }

    // perf record

    /// `perf trace -s -p PID`: exact per-syscall counts and latency,
    /// RAII-stopped. Gated on `TINCD_TRACE=1`; needs root/`CAP_PERFMON`
    /// (`sudo -E env PATH=$PATH TINCD_TRACE=1 cargo bench ...`).
    /// Tracepoint overhead is small but nonzero — use the counts,
    /// not the wall time.
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
            // -s: summary only; -o: keep it out of daemon stderr.
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
                // perf trace flushes the summary on SIGINT.
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(child.id().cast_signed()),
                    nix::sys::signal::Signal::SIGINT,
                );
                let _ = child.wait();
            }
            // Dump the short summary inline, side-by-side with the C run.
            if let Ok(s) = std::fs::read_to_string(&self.out)
                && !s.trim().is_empty()
            {
                eprintln!("--- syscall trace ({}) ---", self.out.display());
                for line in s.lines() {
                    eprintln!("  {line}");
                }
            }
        }
    }

    /// `perf record -p PID`, RAII-stopped via SIGINT (SIGTERM would
    /// truncate). Gated on `TINCD_PERF=1` — sampling overhead skews
    /// the throughput being measured. Unavailable perf degrades to
    /// throughput-only.
    struct PerfRecord {
        child: Option<Child>,
    }

    impl PerfRecord {
        fn start(pid: u32, out: &Path) -> Self {
            if std::env::var_os("TINCD_PERF").is_none() {
                return Self { child: None };
            }
            // -g: call graphs (fp-based; dwarf costs too much here).
            // -F 499: off tick alignment; two samplers at 999 Hz
            // starved the meta-conn under saturation.
            // Degrades silently when kernel.perf_event_paranoid
            // forbids attach.
            let child = Command::new("perf")
                .args(["record", "-g", "-F", "499", "-p"])
                .arg(pid.to_string())
                .arg("-o")
                .arg(out)
                .stderr(Stdio::inherit())
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
                // The PID is ours (we spawned it, haven't waited it
                // yet, so it hasn't been reaped/reused).
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(child.id().cast_signed()),
                    nix::sys::signal::Signal::SIGINT,
                );
                let _ = child.wait();
            }
        }
    }

    /// Top self-time symbols (`--no-children`) to stderr — the
    /// baseline for the next regression. Healthy: crypto dominates,
    /// <5% in `tincd::`; an `alloc::raw_vec` entry means a per-packet
    /// clone crept in.
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
        for line in String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter(|l| !l.trim_start().starts_with('#') && !l.trim().is_empty())
            .take(10)
        {
            eprintln!("  {line}");
        }
        eprintln!("  full report: perf report -i {}", data.display());
    }

    // pairings

    /// One named pairing. `name` is the `cargo bench -- <substr>`
    /// filter target; `perf_tag` names the perf.data/trace files
    /// (Rust↔C isn't profiled — it's the interop sanity check).
    struct Pairing {
        name: &'static str,
        label: &'static str,
        tag: &'static str,
        perf_tag: Option<&'static str>,
        alice: Impl,
        bob: Impl,
    }

    /// Spawn alice+bob, iperf3, teardown. Returns received bps.
    /// Perf/trace recorders bracket the measurement window only — not
    /// the handshake/PMTU convergence (`setup_tunnel`).
    fn run_pairing(p: &Pairing, perf_out: &Path) -> f64 {
        eprintln!("--- {} ---", p.label);
        let mut tunnel = setup_tunnel(p.tag, p.alice.clone(), p.bob.clone());

        let bps = if let Some(tag) = p.perf_tag {
            let alice_perf = perf_out.join(format!("{tag}-alice.perf.data"));
            let bob_perf = perf_out.join(format!("{tag}-bob.perf.data"));
            // Both ends: send- and recv-side costs show up on
            // opposite sides.
            let _pa = PerfRecord::start(tunnel.alice_pid, &alice_perf);
            let _pb = PerfRecord::start(tunnel.bob_pid, &bob_perf);
            let _ta = PerfTrace::start(
                tunnel.alice_pid,
                &perf_out.join(format!("{tag}-alice.trace")),
            );
            let _tb = PerfTrace::start(tunnel.bob_pid, &perf_out.join(format!("{tag}-bob.trace")));
            measure(&mut tunnel)
            // _pa/_pb drop here → SIGINT → perf flushes + exits
        } else {
            measure(&mut tunnel)
        };
        drop(tunnel);

        eprintln!("{}: {:.1} Mbps", p.label, bps / 1e6);
        bps
    }

    // main

    pub fn main() {
        // Substring filters after `--`; skip cargo's `--bench`
        // sentinel (anything starting with `-`).
        let filters: Vec<String> = std::env::args()
            .skip(1)
            .filter(|a| !a.starts_with('-'))
            .collect();
        let matches = |name: &str| filters.is_empty() || filters.iter().any(|f| name.contains(f));

        let Some(netns) = enter_netns() else {
            return; // SKIP printed already
        };

        let c_bin = c_tincd_bin().expect("gate checked in enter_netns");
        let perf_on = std::env::var_os("TINCD_PERF").is_some();
        let trace_on = std::env::var_os("TINCD_TRACE").is_some();
        let perf_out = std::env::var_os("TINCD_PERF_DIR")
            .map_or_else(|| PathBuf::from("/tmp/tincd-perf"), PathBuf::from);
        if perf_on || trace_on {
            std::fs::create_dir_all(&perf_out).ok();
        } else {
            eprintln!("(set TINCD_PERF=1 for sampling profile, TINCD_TRACE=1 for syscall counts)");
        }

        // C↔C first: the healthy-profile baseline to diff against.
        let pairings = [
            Pairing {
                name: "c_c",
                label: "C↔C",
                tag: "cc",
                perf_tag: Some("c"),
                alice: Impl::C(c_bin.clone()),
                bob: Impl::C(c_bin.clone()),
            },
            Pairing {
                name: "rust_rust",
                label: "Rust↔Rust",
                tag: "rr",
                perf_tag: Some("rust"),
                alice: Impl::Rust,
                bob: Impl::Rust,
            },
            Pairing {
                name: "rust_c",
                label: "Rust↔C",
                tag: "rc",
                perf_tag: None,
                alice: Impl::Rust,
                bob: Impl::C(c_bin),
            },
        ];

        let mut results: [Option<f64>; 3] = [None; 3];
        // (idle_p99, load_p99) per pairing, for the cross-impl summary.
        let mut lat_results: [Option<(Option<f64>, Option<f64>)>; 3] = [None, None, None];
        let mut ran_any = false;
        for (i, p) in pairings.iter().enumerate() {
            // Throughput: bare pairing name ("rust_rust").
            if matches(p.name) {
                results[i] = Some(run_pairing(p, &perf_out));
                ran_any = true;
            }
            // Latency: "latency_{idle,load}_<pairing>". The guard
            // stops a bare `-- rust_rust` from matching
            // `latency_load_rust_rust` by substring.
            let want_latency = filters.is_empty() || filters.iter().any(|f| f.contains("latency"));
            let lat_idle = want_latency && matches(&format!("latency_idle_{}", p.name));
            let lat_load = want_latency && matches(&format!("latency_load_{}", p.name));
            if lat_idle || lat_load {
                let (idle, load) = run_latency(p, lat_idle, lat_load);
                lat_results[i] = Some((idle.map(|s| s.p99()), load.map(|(_, s)| s.p99())));
                ran_any = true;
            }
        }
        if !ran_any {
            eprintln!(
                "no pairing matched filter(s) {filters:?}; \
             available: c_c, rust_rust, rust_c, \
             latency_{{idle,load}}_{{c_c,rust_rust,rust_c}}"
            );
            std::process::exit(1);
        }

        let [baseline, rust, mixed] = results;

        if perf_on {
            if rust.is_some() {
                report_hot_symbols(&perf_out.join("rust-alice.perf.data"));
                report_hot_symbols(&perf_out.join("rust-bob.perf.data"));
            }
            if baseline.is_some() {
                report_hot_symbols(&perf_out.join("c-alice.perf.data"));
                report_hot_symbols(&perf_out.join("c-bob.perf.data"));
            }
            eprintln!("perf data: {}", perf_out.display());
        }

        // No pass/fail gate on the ratio — compare across commits by
        // eye. A drop to ~50% of C usually means a per-packet clone
        // (alloc::raw_vec high in the hot-symbol report).
        if let (Some(baseline), Some(rust)) = (baseline, rust) {
            eprintln!("Rust/C ratio: {:.1}%", rust / baseline * 100.0);
            // Mixed compares against the slower endpoint — that's
            // its bottleneck.
            if let Some(mixed) = mixed {
                let slower = rust.min(baseline);
                eprintln!(
                    "Rust↔C / min(Rust↔Rust, C↔C): {:.1}%",
                    mixed / slower * 100.0
                );
            }
        }

        // Latency summary: diagnostic, not a gate — absolute numbers
        // vary wildly across machines.
        let [lat_c, lat_r, _] = lat_results;
        if let (Some((_, Some(c_load))), Some((_, Some(r_load)))) = (lat_c, lat_r) {
            eprintln!(
                "latency p99 under load: Rust {:.3}ms vs C {:.3}ms (Δ {:+.3}ms)",
                r_load,
                c_load,
                r_load - c_load
            );
        }

        drop(netns);
    }
} // mod bench
