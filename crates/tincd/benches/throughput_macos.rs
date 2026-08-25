//! macOS throughput: two tincd on real utuns, iperf3 between them.
//!
//! ```sh
//! scripts/macos-bench-runner.sh [-- rust_rust]   # TINCD_PERF=1 adds sample(1)
//! ```
//!
//! Both tunnel addresses are local to the one routing table, so left
//! alone the kernel would deliver over `lo0`. The bench replaces each
//! address's `RTF_LOCAL` host route with one via the *peer's* utun and
//! afterwards checks the daemons' traffic counters against iperf3's
//! byte count, failing rather than reporting a loopback number.
//! C pairings run when `TINC_C_TINCD` is set.

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("SKIP throughput_macos: macOS-only (use `cargo bench --bench throughput` on Linux)");
}

#[cfg(target_os = "macos")]
#[path = "../tests/common/mod.rs"]
mod common;

#[cfg(target_os = "macos")]
fn main() {
    bench::main();
}

#[cfg(target_os = "macos")]
mod bench {
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::time::Duration;

    use super::common::bench::{
        Impl, PingStats, Tunnel, bench_conf, c_tincd_bin, iperf3_available, iperf3_client,
        perf_enabled,
    };
    use super::common::macos::{route_del_host, run, wait_for_utun};
    use super::common::{Node, TmpGuard, node_traffic};

    // High utun unit numbers: dodge VPN clients / leftover devices.
    const ALICE_IFACE: &str = "utun210";
    const BOB_IFACE: &str = "utun211";
    const ALICE_IP: &str = "10.44.0.1";
    const BOB_IP: &str = "10.44.1.1";
    // POINTOPOINT ifconfig wants a destination address; never used.
    const ALICE_DST: &str = "10.44.0.2";
    const BOB_DST: &str = "10.44.1.2";

    fn ping_once() {
        let _ = Command::new("/sbin/ping")
            .args(["-c", "1", "-t", "1", BOB_IP])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    /// Killing the daemons (closing the kern-control fd) removes the
    /// utuns and their routes; the host routes we crossed by hand are
    /// swept here.
    struct MacTunnel(Tunnel);

    impl Drop for MacTunnel {
        fn drop(&mut self) {
            self.0.alice.stop();
            self.0.bob.stop();
            for ip in [BOB_IP, ALICE_IP, BOB_DST, ALICE_DST] {
                route_del_host(ip);
            }
        }
    }

    fn setup_tunnel(tag: &str, alice_impl: &Impl, bob_impl: &Impl) -> MacTunnel {
        let tmp = TmpGuard::new("thrmac", tag);
        // PingTimeout 2: a saturated single utun thread can miss a 1s tick.
        let node = |name, seed, iface, ip| {
            Node::new(tmp.path(), name, seed)
                .iface(iface)
                .subnet(&format!("{ip}/32"))
                .with_conf(&bench_conf(2))
        };
        let alice = node("alice", 0xAC, ALICE_IFACE, ALICE_IP);
        let bob = node("bob", 0xBC, BOB_IFACE, BOB_IP);
        let tunnel = MacTunnel(Tunnel::start(tmp, alice, bob, (alice_impl, bob_impl)));

        for iface in [ALICE_IFACE, BOB_IFACE] {
            assert!(
                wait_for_utun(iface, Duration::from_secs(3)),
                "{iface} never appeared\n{}",
                tunnel.0.logs()
            );
        }
        run(&["/sbin/ifconfig", ALICE_IFACE, ALICE_IP, ALICE_DST, "up"]);
        run(&["/sbin/ifconfig", BOB_IFACE, BOB_IP, BOB_DST, "up"]);
        // See module doc: replace the RTF_LOCAL /32 with one via the
        // peer's utun so traffic actually enters the tunnel.
        route_del_host(BOB_IP);
        route_del_host(ALICE_IP);
        #[rustfmt::skip]
        run(&["/sbin/route", "-qn", "add", "-host", BOB_IP, "-interface", ALICE_IFACE]);
        #[rustfmt::skip]
        run(&["/sbin/route", "-qn", "add", "-host", ALICE_IP, "-interface", BOB_IFACE]);

        tunnel.0.wait_data_path(ping_once);
        tunnel
    }

    /// Killed on drop: `--one-off` only exits if a client connected.
    struct IperfServer(Child);

    impl Drop for IperfServer {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// `-B` pins the source so replies follow the crossed route.
    /// Returns `(bps, bytes)` as received by the server.
    fn measure(tunnel: &MacTunnel) -> (f64, u64) {
        let _server = IperfServer(
            Command::new("iperf3")
                .args(["-s", "--one-off", "-B", BOB_IP])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn iperf3 server"),
        );
        std::thread::sleep(Duration::from_millis(200));
        let sum = iperf3_client(&tunnel.0, &["-c", BOB_IP, "-B", ALICE_IP, "-t", "5"]);
        (sum.bits_per_second, sum.bytes)
    }

    /// alice's bytes sent to bob per `dump traffic`.
    fn alice_out_bytes(tunnel: &MacTunnel) -> u64 {
        let rows = tunnel.0.alice.ctl().dump(13);
        node_traffic(&rows, "bob")
            .unwrap_or_else(|| panic!("no bob row: {rows:?}"))
            .1
    }

    /// The short-circuit guard: if the kernel delivered over `lo0`
    /// after all, iperf3 reports multi-Gbps while the daemons counted
    /// nothing. Upper bound catches accounting bugs; ACKs, retransmits
    /// and framing stay far below 4×.
    fn assert_went_through_daemons(tunnel: &MacTunnel, iperf_bytes: u64) {
        let alice_out = alice_out_bytes(tunnel);
        let bob_in = node_traffic(&tunnel.0.bob.ctl().dump(13), "alice").map_or(0, |t| t.0);
        eprintln!("  daemon counters: alice out={alice_out} bob in={bob_in} iperf={iperf_bytes}");
        assert!(
            alice_out >= iperf_bytes && bob_in >= iperf_bytes,
            "daemons saw less than iperf3 transferred: traffic bypassed the utuns"
        );
        let cap = iperf_bytes.saturating_mul(4).max(1 << 20);
        assert!(
            alice_out <= cap && bob_in <= cap,
            "daemon counters exceed 4× iperf3 bytes"
        );
    }

    /// `sample PID SECS -f OUT` under `TINCD_PERF=1`; exits by itself.
    struct Sampler {
        child: Option<Child>,
        out: PathBuf,
    }

    impl Sampler {
        fn start(pid: nix::unistd::Pid, secs: u32, out: &Path) -> Self {
            let child = perf_enabled()
                .then(|| {
                    Command::new("/usr/bin/sample")
                        .arg(pid.to_string())
                        .arg(secs.to_string())
                        .arg("-f")
                        .arg(out)
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .spawn()
                        .ok()
                })
                .flatten();
            Self {
                child,
                out: out.to_owned(),
            }
        }

        fn finish(mut self) {
            if let Some(mut child) = self.child.take() {
                let _ = child.wait();
                eprintln!("  sample report: {}", self.out.display());
            }
        }
    }

    impl Drop for Sampler {
        fn drop(&mut self) {
            if let Some(mut child) = self.child.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    struct Pairing {
        name: &'static str,
        label: &'static str,
        profiled: bool,
        alice: Impl,
        bob: Impl,
    }

    fn run_throughput(pairing: &Pairing, perf_out: &Path) -> f64 {
        eprintln!("--- {} ---", pairing.label);
        let tunnel = setup_tunnel(pairing.name, &pairing.alice, &pairing.bob);
        let samplers: Vec<Sampler> = if pairing.profiled {
            [("alice", &tunnel.0.alice), ("bob", &tunnel.0.bob)]
                .into_iter()
                .map(|(side, node)| {
                    let out = perf_out.join(format!("{}-{side}.sample.txt", pairing.name));
                    Sampler::start(node.pid(), 5, &out)
                })
                .collect()
        } else {
            Vec::new()
        };
        let (bps, bytes) = measure(&tunnel);
        samplers.into_iter().for_each(Sampler::finish);
        assert_went_through_daemons(&tunnel, bytes);
        eprintln!("{}: {:.1} Mbps", pairing.label, bps / 1e6);
        bps
    }

    /// macOS ping has no `-D`; `-i` below 1s needs root, which we are.
    fn run_latency(pairing: &Pairing) {
        eprintln!("--- latency {} ---", pairing.label);
        let tunnel = setup_tunnel(
            &format!("lat-{}", pairing.name),
            &pairing.alice,
            &pairing.bob,
        );
        // Setup's own pings already moved the counter, so compare
        // before/after rather than against zero.
        let before = alice_out_bytes(&tunnel);
        let stats = PingStats::measure(&["-S", ALICE_IP, "-i", "0.01"], BOB_IP, 100);
        eprintln!("  idle: {}", stats.summary());
        assert!(
            alice_out_bytes(&tunnel) > before,
            "latency pings bypassed the utuns"
        );
    }

    pub fn main() {
        let filters: Vec<String> = std::env::args()
            .skip(1)
            .filter(|a| !a.starts_with('-'))
            .collect();
        let selected =
            |name: &str| filters.is_empty() || filters.iter().any(|f| name.contains(f.as_str()));

        if !nix::unistd::geteuid().is_root() {
            eprintln!("SKIP throughput_macos: utun needs root (scripts/macos-bench-runner.sh)");
            return;
        }
        if !iperf3_available() {
            eprintln!("SKIP throughput_macos: iperf3 not on PATH (nix develop provides it)");
            return;
        }
        let perf_out = std::env::var_os("TINCD_PERF_DIR")
            .map_or_else(|| PathBuf::from("/tmp/tincd-perf"), PathBuf::from);
        if perf_enabled() {
            std::fs::create_dir_all(&perf_out).unwrap();
        } else {
            eprintln!("(set TINCD_PERF=1 for sample(1) profile)");
        }

        let mut pairings = vec![Pairing {
            name: "rust_rust",
            label: "Rust↔Rust",
            profiled: true,
            alice: Impl::Rust,
            bob: Impl::Rust,
        }];
        if let Some(c_bin) = c_tincd_bin() {
            pairings.insert(
                0,
                Pairing {
                    name: "c_c",
                    label: "C↔C",
                    profiled: true,
                    alice: Impl::C(c_bin.clone()),
                    bob: Impl::C(c_bin.clone()),
                },
            );
            pairings.push(Pairing {
                name: "rust_c",
                label: "Rust↔C",
                profiled: false,
                alice: Impl::Rust,
                bob: Impl::C(c_bin),
            });
        } else {
            eprintln!("(TINC_C_TINCD unset: Rust↔Rust only, no C baseline)");
        }

        let mut results: Vec<(&str, f64)> = Vec::new();
        let mut ran_any = false;
        let want_latency = filters.is_empty() || filters.iter().any(|f| f.contains("latency"));
        for pairing in &pairings {
            if selected(pairing.name) {
                results.push((pairing.name, run_throughput(pairing, &perf_out)));
                ran_any = true;
            }
            if want_latency && selected(&format!("latency_{}", pairing.name)) {
                run_latency(pairing);
                ran_any = true;
            }
        }
        if !ran_any {
            let names: Vec<&str> = pairings.iter().map(|p| p.name).collect();
            eprintln!(
                "no pairing matched {filters:?}; available: {}, latency_<pairing>",
                names.join(", ")
            );
            std::process::exit(1);
        }
        let bps = |name: &str| results.iter().find(|(n, _)| *n == name).map(|r| r.1);
        if let (Some(rust), Some(c)) = (bps("rust_rust"), bps("c_c")) {
            eprintln!("Rust/C ratio: {:.1}%", rust / c * 100.0);
        }
    }
}
