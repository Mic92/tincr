//! iperf3 through two daemons on real TUNs in a bwrap netns, with C
//! tincd as the baseline. Absolute numbers are machine-specific; the
//! Rust/C ratio is what to compare across commits.
//!
//! ```sh
//! cargo bench --bench throughput [-- rust_rust | latency | mesh]
//! TINCD_PERF=1 …    # perf record;  TINCD_TRACE=1 … # perf trace (root)
//! ```

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("SKIP throughput: linux-only; on macOS use `cargo bench --bench throughput_macos`");
}

#[cfg(target_os = "linux")]
fn main() {
    bench::main();
}

#[cfg(target_os = "linux")]
#[path = "../tests/common/mod.rs"]
mod common;

#[cfg(target_os = "linux")]
mod bench {
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::time::Duration;

    use super::common::bench::{
        Impl, PingStats, Tunnel, bench_conf, c_tincd_bin, iperf3_available, iperf3_client,
        node_minmtu, parse_iperf, perf_enabled, ping_once,
    };
    use super::common::linux::{
        ChildNetNs, bwrap_inner_init, bwrap_reexec, bwrap_usable, run_ip, run_ip_in,
        wait_for_carrier,
    };
    use super::common::{Node, TmpGuard, node_status, poll_until};
    use std::env;
    use std::fs;
    use std::panic;
    use std::panic::AssertUnwindSafe;
    use std::process;
    use std::thread;

    const BOB_IP: &str = "10.44.0.2";

    /// Outer pass re-execs inside bwrap and exits; inner pass returns.
    fn enter_netns() -> Option<ChildNetNs> {
        if env::var_os("BWRAP_INNER").is_some() {
            bwrap_inner_init();
            return Some(ChildNetNs::new("bobside"));
        }
        if c_tincd_bin().is_none() {
            eprintln!(
                "SKIP throughput: TINC_C_TINCD not set (`nix develop` sets it, or \
                 `nix build .#tincd-c` and TINC_C_TINCD=$PWD/result/sbin/tincd)"
            );
            return None;
        }
        if !iperf3_available() {
            eprintln!("SKIP throughput: iperf3 not on PATH (nix develop provides it)");
            return None;
        }
        if !bwrap_usable("throughput") {
            return None;
        }
        let status = bwrap_reexec()
            .args(env::args_os().skip(1))
            .status()
            .expect("spawn bwrap");
        process::exit(status.code().unwrap_or(1));
    }

    /// C tincd cannot attach to a `multi_queue` TUN. Deleted on drop.
    struct TunDev {
        name: String,
        netns: Option<String>,
    }

    impl TunDev {
        fn add(name: &str, which: &Impl) -> Self {
            let mut args = vec!["tuntap", "add", "mode", "tun", "name", name];
            if matches!(which, Impl::Rust) {
                args.push("multi_queue");
            }
            run_ip(&args);
            run_ip(&["link", "set", name, "up"]);
            Self {
                name: name.to_owned(),
                netns: None,
            }
        }

        /// After the daemon attached; addresses do not survive a move.
        fn place(&mut self, netns: Option<&str>, addr: &str, routes: &[&str]) {
            assert!(
                wait_for_carrier(&self.name, Duration::from_secs(2)),
                "{} has no carrier",
                self.name
            );
            let name = self.name.as_str();
            let ip = |args: &[&str]| match netns {
                Some(ns) => run_ip_in(ns, args),
                None => run_ip(args),
            };
            if let Some(ns) = netns {
                run_ip(&["link", "set", name, "netns", ns]);
                self.netns = Some(ns.to_owned());
            }
            ip(&["addr", "add", addr, "dev", name]);
            ip(&["link", "set", name, "up"]);
            for route in routes {
                ip(&["route", "add", route, "dev", name]);
            }
        }
    }

    impl Drop for TunDev {
        fn drop(&mut self) {
            let mut cmd = Command::new("ip");
            if let Some(ns) = &self.netns {
                cmd.args(["netns", "exec", ns, "ip"]);
            }
            let _ = cmd
                .args(["link", "del", &self.name])
                .stderr(Stdio::null())
                .status();
        }
    }

    fn bench_node(dir: &Path, name: &str, seed: u8, iface: &str, subnet: &str) -> Node {
        Node::new(dir, name, seed)
            .iface(iface)
            .subnet(subnet)
            .with_conf(&bench_conf(1))
    }

    /// Field order: daemons drop before their devices.
    struct LinuxTunnel {
        tunnel: Tunnel,
        _devices: [TunDev; 2],
    }

    fn setup_tunnel(tag: &str, alice_impl: &Impl, bob_impl: &Impl) -> LinuxTunnel {
        let mut devices = [
            TunDev::add("tincT0", alice_impl),
            TunDev::add("tincT1", bob_impl),
        ];
        let tmp = TmpGuard::new("thr", tag);
        let alice = bench_node(tmp.path(), "alice", 0xAC, "tincT0", "10.44.0.1/32");
        let bob = bench_node(tmp.path(), "bob", 0xBC, "tincT1", "10.44.0.2/32");
        let tunnel = Tunnel::start(tmp, alice, bob, (alice_impl, bob_impl));
        devices[0].place(None, "10.44.0.1/24", &[]);
        devices[1].place(Some("bobside"), "10.44.0.2/24", &[]);
        tunnel.wait_data_path(|| ping_once(BOB_IP));
        LinuxTunnel {
            tunnel,
            _devices: devices,
        }
    }

    /// The bind cannot be probed from here (that would go through the
    /// tunnel), hence the sleep. Killed on drop.
    struct IperfServer(Child);

    impl IperfServer {
        fn start(netns: &str) -> Self {
            let child = Command::new("ip")
                .args(["netns", "exec", netns, "iperf3", "-s", "--one-off"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn iperf3 server");
            thread::sleep(Duration::from_millis(200));
            Self(child)
        }
    }

    impl Drop for IperfServer {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn measure(tunnel: &LinuxTunnel) -> f64 {
        let _server = IperfServer::start("bobside");
        iperf3_client(&tunnel.tunnel, &["-c", BOB_IP, "-t", "5"]).bits_per_second
    }

    fn ping_rtts() -> PingStats {
        PingStats::measure(&["-i", "0.01", "-D"], BOB_IP, 100)
    }

    /// The queueing delay batching adds is invisible in throughput.
    fn measure_latency_under_load(tunnel: &LinuxTunnel) -> (f64, PingStats) {
        let _server = IperfServer::start("bobside");
        let client = Command::new("iperf3")
            .args(["-c", BOB_IP, "-t", "3", "--json"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn iperf3 client");
        thread::sleep(Duration::from_millis(500));
        let ping = ping_rtts();
        let out = client.wait_with_output().expect("wait iperf3 client");
        assert!(
            out.status.success(),
            "iperf3 (latency load): {:?}\n{}\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr),
            tunnel.tunnel.logs()
        );
        let bps = parse_iperf(&out.stdout).end.sum_received.bits_per_second;
        (bps, ping)
    }

    /// Stopped with SIGINT on drop (SIGTERM truncates perf output).
    struct Perf {
        child: Option<Child>,
        summary: Option<PathBuf>,
    }

    impl Perf {
        /// 999 Hz on two daemons starved the meta connection.
        fn record(pid: nix::unistd::Pid, out: &Path) -> Self {
            if !perf_enabled() {
                return Self {
                    child: None,
                    summary: None,
                };
            }
            let child = Command::new("perf")
                .args(["record", "-g", "-F", "499", "-p"])
                .arg(pid.to_string())
                .arg("-o")
                .arg(out)
                .spawn()
                .ok();
            match &child {
                Some(_) => eprintln!("perf record -p {pid} -> {}", out.display()),
                None => eprintln!(
                    "perf record unavailable (perf missing or kernel.perf_event_paranoid >= 2)"
                ),
            }
            Self {
                child,
                summary: None,
            }
        }

        /// Needs root or `CAP_PERFMON`.
        fn trace(pid: nix::unistd::Pid, out: &Path) -> Self {
            if env::var_os("TINCD_TRACE").is_none() {
                return Self {
                    child: None,
                    summary: None,
                };
            }
            let child = Command::new("perf")
                .args(["trace", "-s", "-p"])
                .arg(pid.to_string())
                .arg("-o")
                .arg(out)
                .stderr(Stdio::null())
                .spawn()
                .ok();
            if child.is_none() {
                eprintln!("perf trace unavailable (needs root/CAP_PERFMON)");
            }
            Self {
                child,
                summary: Some(out.to_owned()),
            }
        }
    }

    impl Drop for Perf {
        fn drop(&mut self) {
            let Some(mut child) = self.child.take() else {
                return;
            };
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(child.id().cast_signed()),
                nix::sys::signal::Signal::SIGINT,
            );
            let _ = child.wait();
            if let Some(path) = &self.summary
                && let Ok(text) = fs::read_to_string(path)
            {
                eprintln!("--- syscall trace ({}) ---", path.display());
                for line in text.lines() {
                    eprintln!("  {line}");
                }
            }
        }
    }

    /// Healthy: crypto dominates; `alloc::raw_vec` means a per-packet clone.
    fn report_hot_symbols(data: &Path) {
        if !data.exists() {
            return;
        }
        let Ok(out) = Command::new("perf")
            .args(["report", "--stdio", "--no-children", "-g", "none"])
            .args(["--sort", "overhead,symbol", "--percent-limit", "1.0", "-i"])
            .arg(data)
            .output()
        else {
            return;
        };
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
        let bps = {
            let _profilers: Vec<Perf> = if pairing.profiled {
                [("alice", &tunnel.tunnel.alice), ("bob", &tunnel.tunnel.bob)]
                    .into_iter()
                    .flat_map(|(side, node)| {
                        let stem = format!("{}-{side}", pairing.name);
                        [
                            Perf::record(node.pid(), &perf_out.join(format!("{stem}.perf.data"))),
                            Perf::trace(node.pid(), &perf_out.join(format!("{stem}.trace"))),
                        ]
                    })
                    .collect()
            } else {
                Vec::new()
            };
            measure(&tunnel)
        };
        eprintln!("{}: {:.1} Mbps", pairing.label, bps / 1e6);
        bps
    }

    /// Returns the under-load p99.
    fn run_latency(pairing: &Pairing, idle: bool, load: bool) -> Option<f64> {
        eprintln!("--- latency {} ---", pairing.label);
        let tunnel = setup_tunnel(
            &format!("lat-{}", pairing.name),
            &pairing.alice,
            &pairing.bob,
        );
        if idle {
            eprintln!("  idle:  {}", ping_rtts().summary());
        }
        load.then(|| {
            let (bps, stats) = measure_latency_under_load(&tunnel);
            eprintln!("  load:  {} at {:.0} Mbps", stats.summary(), bps / 1e6);
            stats.percentile(99.0)
        })
    }

    /// N bobs (distinct id6, so RX spreads over alice's shards), each
    /// TUN in its own netns so return routes don't collide.
    struct Mesh {
        alice: Node,
        bobs: Vec<Node>,
        _devices: Vec<TunDev>,
        _netns: Vec<ChildNetNs>,
        _tmp: TmpGuard,
    }

    fn setup_mesh(peers: usize, single_shard: bool) -> Mesh {
        let tmp = TmpGuard::new("thr", if single_shard { "mesh1" } else { "mesh" });
        let mut devices: Vec<TunDev> = (0..=peers)
            .map(|k| TunDev::add(&format!("tincT{k}"), &Impl::Rust))
            .collect();
        let netns: Vec<ChildNetNs> = (1..=peers)
            .map(|k| ChildNetNs::new(&format!("tmesh{k}")))
            .collect();

        let mut bobs: Vec<Node> = (1..=peers)
            .map(|k| {
                let seed = 0xB0 + u8::try_from(k).unwrap();
                Node::new(tmp.path(), &format!("bob{k}"), seed)
                    .iface(&format!("tincT{k}"))
                    .subnet(&format!("10.44.{k}.0/24"))
                    .with_conf(&bench_conf(5))
            })
            .collect();
        let mut alice = Node::new(tmp.path(), "alice", 0xA1)
            .iface("tincT0")
            .subnet("10.44.0.0/24")
            .with_conf(&bench_conf(5))
            .with_conf(if single_shard { "Shards = 1" } else { "" });
        for bob in &mut bobs {
            bob.write_config(&alice, false);
            Impl::Rust.start(bob);
        }
        let bob_refs: Vec<&Node> = bobs.iter().collect();
        alice.write_config_multi(&bob_refs, &bob_refs);
        Impl::Rust.start(&mut alice);

        let bob_routes: Vec<String> = (1..=peers).map(|k| format!("10.44.{k}.0/24")).collect();
        let bob_routes: Vec<&str> = bob_routes.iter().map(String::as_str).collect();
        devices[0].place(None, "10.44.0.1/24", &bob_routes);
        for (k, device) in devices.iter_mut().enumerate().skip(1) {
            device.place(
                Some(&format!("tmesh{k}")),
                &format!("10.44.{k}.1/24"),
                &["10.44.0.0/24"],
            );
        }

        for (k, bob) in bobs.iter().enumerate() {
            let ip = format!("10.44.{}.1", k + 1);
            let ready = panic::catch_unwind(AssertUnwindSafe(|| {
                poll_until(Duration::from_secs(15), || {
                    ping_once(&ip);
                    let nodes = alice.ctl().dump(3);
                    let udp = node_status(&nodes, &bob.name).is_some_and(|s| s & 0x82 == 0x82);
                    let pmtu = node_minmtu(&nodes, &bob.name).is_some_and(|m| m >= 1500);
                    (udp && pmtu).then_some(())
                });
            }));
            assert!(
                ready.is_ok(),
                "{} data path\n=== alice ===\n{}\n=== {0} ===\n{}",
                bob.name,
                alice.log(),
                bob.log()
            );
        }
        Mesh {
            alice,
            bobs,
            _devices: devices,
            _netns: netns,
            _tmp: tmp,
        }
    }

    fn measure_mesh(mesh: &Mesh) -> f64 {
        let peers = mesh.bobs.len();
        let _servers: Vec<IperfServer> = (1..=peers)
            .map(|k| IperfServer::start(&format!("tmesh{k}")))
            .collect();
        let clients: Vec<Child> = (1..=peers)
            .map(|k| {
                Command::new("iperf3")
                    .args(["-c", &format!("10.44.{k}.1"), "-t", "5", "--json"])
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("iperf3 client")
            })
            .collect();
        clients
            .into_iter()
            .map(|client| {
                let out = client.wait_with_output().expect("iperf3 client");
                assert!(out.status.success(), "iperf3 client:\n{}", mesh.alice.log());
                parse_iperf(&out.stdout).end.sum_received.bits_per_second
            })
            .sum()
    }

    fn run_mesh(peers: usize) {
        for single_shard in [false, true] {
            let label = if single_shard {
                "Shards=1"
            } else {
                "Shards=auto"
            };
            eprintln!("--- mesh {peers} peers, {label} ---");
            let mesh = setup_mesh(peers, single_shard);
            let bps = measure_mesh(&mesh);
            eprintln!(
                "mesh {peers} peers, {label}: {:.1} Mbps aggregate",
                bps / 1e6
            );
        }
    }

    pub fn main() {
        let filters: Vec<String> = env::args()
            .skip(1)
            .filter(|a| !a.starts_with('-'))
            .collect();
        let selected =
            |name: &str| filters.is_empty() || filters.iter().any(|f| name.contains(f.as_str()));

        let Some(_netns) = enter_netns() else {
            return;
        };
        let c_bin = c_tincd_bin().expect("checked in enter_netns");
        let perf_out = env::var_os("TINCD_PERF_DIR")
            .map_or_else(|| PathBuf::from("/tmp/tincd-perf"), PathBuf::from);
        if perf_enabled() || env::var_os("TINCD_TRACE").is_some() {
            fs::create_dir_all(&perf_out).unwrap();
        } else {
            eprintln!("(set TINCD_PERF=1 for sampling profile, TINCD_TRACE=1 for syscall counts)");
        }

        if filters.iter().any(|f| f == "mesh") {
            run_mesh(4);
            return;
        }

        let pairings = [
            Pairing {
                name: "c_c",
                label: "C↔C",
                profiled: true,
                alice: Impl::C(c_bin.clone()),
                bob: Impl::C(c_bin.clone()),
            },
            Pairing {
                name: "rust_rust",
                label: "Rust↔Rust",
                profiled: true,
                alice: Impl::Rust,
                bob: Impl::Rust,
            },
            Pairing {
                name: "rust_c",
                label: "Rust↔C",
                profiled: false,
                alice: Impl::Rust,
                bob: Impl::C(c_bin),
            },
        ];

        let mut throughput = [None; 3];
        let mut load_p99 = [None; 3];
        let want_latency = filters.is_empty() || filters.iter().any(|f| f.contains("latency"));
        for (i, pairing) in pairings.iter().enumerate() {
            if selected(pairing.name) {
                throughput[i] = Some(run_throughput(pairing, &perf_out));
            }
            let idle = want_latency && selected(&format!("latency_idle_{}", pairing.name));
            let load = want_latency && selected(&format!("latency_load_{}", pairing.name));
            if idle || load {
                load_p99[i] = run_latency(pairing, idle, load);
            }
        }
        if throughput.iter().all(Option::is_none) && load_p99.iter().all(Option::is_none) {
            eprintln!(
                "no pairing matched {filters:?}; available: c_c, rust_rust, rust_c, \
                 latency_{{idle,load}}_<pairing>, mesh"
            );
            process::exit(1);
        }

        let [c, rust, mixed] = throughput;
        if perf_enabled() {
            for (ran, name) in [(rust, "rust_rust"), (c, "c_c")] {
                if ran.is_some() {
                    report_hot_symbols(&perf_out.join(format!("{name}-alice.perf.data")));
                    report_hot_symbols(&perf_out.join(format!("{name}-bob.perf.data")));
                }
            }
        }
        if let (Some(c), Some(rust)) = (c, rust) {
            eprintln!("Rust/C ratio: {:.1}%", rust / c * 100.0);
            if let Some(mixed) = mixed {
                eprintln!(
                    "Rust↔C / min(Rust↔Rust, C↔C): {:.1}%",
                    mixed / rust.min(c) * 100.0
                );
            }
        }
        if let [Some(c), Some(rust), _] = load_p99 {
            eprintln!(
                "latency p99 under load: Rust {rust:.3}ms vs C {c:.3}ms (Δ {:+.3}ms)",
                rust - c
            );
        }
    }
}
