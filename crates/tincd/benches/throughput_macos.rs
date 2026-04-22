//! macOS-native throughput benchmark: two real utun devices on the
//! single host routing table, two `tincd` daemons, `iperf3` between
//! their tunnel addresses. The Linux `throughput` bench's bwrap+netns
//! re-exec doesn't port (no namespaces on Darwin); this is the
//! closest equivalent that still pushes packets through the kernel
//! utun read/write path — NOT `DeviceType=fd`/socketpair, which
//! bypasses exactly the code we want to measure (`BsdTun` AF-prefix
//! framing, kqueue dispatch, the per-packet `read`/`write` syscall).
//!
//! ```sh
//! scripts/macos-bench-runner.sh                 # all (sudo internal)
//! scripts/macos-bench-runner.sh -- rust_rust    # filter
//! TINCD_PERF=1 scripts/macos-bench-runner.sh    # + sample(1)
//! ```
//!
//! ## Short-circuit guard
//!
//! Both tunnel endpoints are local addresses on one routing table.
//! Left alone the kernel resolves `10.44.1.1` as local-via-`lo0` and
//! never touches a utun. iperf3 on Darwin has no `--bind-dev`
//! (`SO_BINDTODEVICE` is Linux-only), so we instead **rewrite the
//! host routes**: delete the auto-installed `RTF_LOCAL` /32 for each
//! tunnel IP and re-add it pointing at the *peer's* utun. Output
//! routing now sends `BOB_IP` into `utun210`; input delivery still
//! works because `ip_input` matches local addresses via the
//! interface-address list, not the routing table. After the run we
//! read each daemon's `REQ_DUMP_TRAFFIC` counters and hard-assert
//! they roughly match iperf3's transferred bytes — if the kernel
//! ever short-circuits past the utun, the bench FAILS instead of
//! printing a loopback number.
//!
//! ## What it reports
//!
//! Rust↔Rust only by default; Rust↔C and C↔C if `TINC_C_TINCD` is
//! set (the devshell sets it). Same ratio interpretation as the
//! Linux bench — absolute Mbps is machine-local, the Rust/C ratio is
//! what you compare across commits.

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
    use std::fmt::Write as _;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::time::Duration;

    use super::common;
    use common::bench::{Impl, PingStats, c_tincd_bin, iperf3_available, node_minmtu, parse_iperf};
    use common::macos::{route_del_host, run, wait_for_utun};
    use common::node::Node;
    use common::{
        ChildWithLog, Ctl, TmpGuard, node_status, node_traffic, poll_until, wait_for_file,
        write_ed25519_privkey,
    };

    // High utun unit numbers: dodge VPN clients / leftover devices.
    const ALICE_IFACE: &str = "utun210";
    const BOB_IFACE: &str = "utun211";
    const ALICE_IP: &str = "10.44.0.1";
    const BOB_IP: &str = "10.44.1.1";
    // Phantom p2p dstaddrs (POINTOPOINT ifconfig wants one). Unused.
    const ALICE_DST: &str = "10.44.0.2";
    const BOB_DST: &str = "10.44.1.2";

    // node.h:41 status bits.
    const VALIDKEY: u32 = 0x02;
    const REACHABLE: u32 = 0x10;
    const UDP_CONFIRMED: u32 = 0x80;

    fn tmp(tag: &str) -> TmpGuard {
        TmpGuard::new("thrmac", tag)
    }

    // ═══════════════════════════ daemon plumbing ═════════════════════════════

    /// Config both impls accept on Darwin: C `bsd/device.c` needs
    /// `DeviceType = utun` + `Device = utunN` (else falls through to
    /// `/dev/tun0`); Rust's `parse_utun` reads either `Device` or
    /// `Interface`. `Node::write_config` would emit `DeviceType=tun`
    /// which only Rust accepts.
    fn write_macos_config(me: &Node, peer: &Node, iface: &str, subnet: &str, connect_to: bool) {
        std::fs::create_dir_all(me.confbase.join("hosts")).unwrap();
        // Bumped under TINCD_PERF: sample(1) + saturation can starve a tick.
        let ping = if std::env::var_os("TINCD_PERF").is_some() {
            5
        } else {
            2
        };
        let mut conf = format!(
            "Name = {}\nAddressFamily = ipv4\n\
             DeviceType = utun\nDevice = {iface}\nInterface = {iface}\n\
             PingTimeout = {ping}\n",
            me.name
        );
        if connect_to {
            let _ = writeln!(conf, "ConnectTo = {}", peer.name);
        }
        std::fs::write(me.confbase.join("tinc.conf"), conf).unwrap();
        std::fs::write(
            me.confbase.join("hosts").join(me.name),
            format!("Port = {}\nSubnet = {subnet}\n", me.port),
        )
        .unwrap();
        let pk = tinc_crypto::b64::encode(&peer.pubkey());
        let mut peer_cfg = format!("Ed25519PublicKey = {pk}\n");
        if connect_to {
            let _ = writeln!(peer_cfg, "Address = 127.0.0.1 {}", peer.port);
        }
        std::fs::write(me.confbase.join("hosts").join(peer.name), peer_cfg).unwrap();
        write_ed25519_privkey(&me.confbase, &me.seed);
    }

    fn spawn(node: &Node, which: &Impl) -> ChildWithLog {
        let child = match which {
            // `info`: per-packet `debug` logging is itself the bottleneck.
            Impl::Rust => common::tincd_at(&node.confbase, &node.pidfile, &node.socket)
                .env("RUST_LOG", "tincd=info")
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn rust tincd"),
            Impl::C(bin) => Command::new(bin)
                .arg("-D")
                .arg("-d0")
                .arg("-c")
                .arg(&node.confbase)
                .arg("--pidfile")
                .arg(&node.pidfile)
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn C tincd"),
        };
        ChildWithLog::spawn(child)
    }

    // ═══════════════════════════ tunnel lifecycle ════════════════════════════

    /// Two daemons + two configured utuns. Drop kills daemons
    /// (closing the kern-control fd reaps utun + its routes) and
    /// best-effort sweeps any leftover host routes.
    struct TunnelHandle {
        _tmp: TmpGuard,
        alice: Option<ChildWithLog>,
        bob: Option<ChildWithLog>,
        alice_ctl: Ctl,
        bob_ctl: Ctl,
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
            if let Some(c) = self.alice.take() {
                let _ = c.kill_and_log();
            }
            if let Some(c) = self.bob.take() {
                let _ = c.kill_and_log();
            }
            route_del_host(BOB_IP);
            route_del_host(ALICE_IP);
            route_del_host(BOB_DST);
            route_del_host(ALICE_DST);
        }
    }

    fn setup_tunnel(tag: &str, alice_impl: &Impl, bob_impl: &Impl) -> TunnelHandle {
        let tmp = tmp(tag);

        let alice = Node::new(tmp.path(), "alice", 0xAC);
        let bob = Node::new(tmp.path(), "bob", 0xBC);
        write_macos_config(&bob, &alice, BOB_IFACE, &format!("{BOB_IP}/32"), false);
        write_macos_config(&alice, &bob, ALICE_IFACE, &format!("{ALICE_IP}/32"), true);

        // ─── spawn ──────────────────────────────────────────────────
        let bob_child = spawn(&bob, bob_impl);
        let bob_pid = bob_child.pid();
        assert!(
            wait_for_file(&bob.socket),
            "bob setup failed; stderr:\n{}",
            bob_child.kill_and_log()
        );
        let alice_child = spawn(&alice, alice_impl);
        let alice_pid = alice_child.pid();
        if !wait_for_file(&alice.socket) {
            let bs = bob_child.kill_and_log();
            panic!(
                "alice setup failed; stderr:\n{}\n=== bob ===\n{bs}",
                alice_child.kill_and_log()
            );
        }

        let mut handle = TunnelHandle {
            _tmp: tmp,
            alice_ctl: alice.ctl(),
            bob_ctl: bob.ctl(),
            alice: Some(alice_child),
            bob: Some(bob_child),
            alice_pid,
            bob_pid,
        };

        // ─── utun up + addresses + crossed host routes ─────────────
        if !wait_for_utun(ALICE_IFACE, Duration::from_secs(3)) {
            let a = handle.alice_log();
            let b = handle.bob_log();
            panic!("alice utun never appeared;\n=== alice ===\n{a}\n=== bob ===\n{b}");
        }
        if !wait_for_utun(BOB_IFACE, Duration::from_secs(3)) {
            let a = handle.alice_log();
            let b = handle.bob_log();
            panic!("bob utun never appeared;\n=== alice ===\n{a}\n=== bob ===\n{b}");
        }
        run(&["/sbin/ifconfig", ALICE_IFACE, ALICE_IP, ALICE_DST, "up"]);
        run(&["/sbin/ifconfig", BOB_IFACE, BOB_IP, BOB_DST, "up"]);
        // Cross the host routes (see module doc): drop the RTF_LOCAL
        // /32 ifconfig just installed, re-add via the PEER's utun.
        route_del_host(BOB_IP);
        route_del_host(ALICE_IP);
        #[rustfmt::skip]
        run(&["/sbin/route", "-qn", "add", "-host", BOB_IP, "-interface", ALICE_IFACE]);
        #[rustfmt::skip]
        run(&["/sbin/route", "-qn", "add", "-host", ALICE_IP, "-interface", BOB_IFACE]);

        // ─── handshake: reachable → validkey+udp_confirmed ──────────
        let meta = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            poll_until(Duration::from_secs(10), || {
                let a = handle.alice_ctl.dump(3);
                let b = handle.bob_ctl.dump(3);
                let a_ok = node_status(&a, "bob").is_some_and(|s| s & REACHABLE != 0);
                let b_ok = node_status(&b, "alice").is_some_and(|s| s & REACHABLE != 0);
                (a_ok && b_ok).then_some(())
            });
        }));
        if meta.is_err() {
            let a = handle.alice_log();
            let b = handle.bob_log();
            panic!("meta handshake timed out;\n=== alice ===\n{a}\n=== bob ===\n{b}");
        }

        // Kick REQ_KEY (first packet hits send_sptps_packet with
        // !validkey → dropped, but triggers the key request).
        let _ = Command::new("/sbin/ping")
            .args(["-c", "1", "-t", "1", BOB_IP])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        let want = VALIDKEY | UDP_CONFIRMED;
        let validkey = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            poll_until(Duration::from_secs(10), || {
                let a = handle.alice_ctl.dump(3);
                let b = handle.bob_ctl.dump(3);
                let a_ok = node_status(&a, "bob").is_some_and(|s| s & want == want);
                let b_ok = node_status(&b, "alice").is_some_and(|s| s & want == want);
                (a_ok && b_ok).then_some(())
            });
        }));
        if validkey.is_err() {
            let a = handle.alice_log();
            let b = handle.bob_log();
            panic!("validkey/udp_confirmed timed out;\n=== alice ===\n{a}\n=== bob ===\n{b}");
        }

        // ─── PMTU convergence ──────────────────────────────────────
        // Until `minmtu` clears the full-MSS threshold, big packets
        // fall back to TCP-tunnelled SPTPS_PACKET (~100× slower).
        // utun MTU is 1500 → the synthetic eth frame the daemon
        // routes is 1514B; `send_sptps_packet`'s PACKET-17 gate is
        // `data.len() > minmtu` (frame-level), so until minmtu≥1514
        // every full-MSS segment double-encrypts via the meta-conn.
        // Discovery probes (333ms cadence, 0.97-multiplier sweep)
        // asymptote at ~1472; only the post-Fix Steady probe at
        // maxmtu=1518 lifts past 1514. Waiting for ≥1500 catches
        // that final jump and removes the run-to-run variance from
        // "how far had PMTU got when iperf3 connected".
        let pmtu = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            poll_until(Duration::from_secs(20), || {
                let _ = Command::new("/sbin/ping")
                    .args(["-c", "1", "-t", "1", BOB_IP])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
                let a = handle.alice_ctl.dump(3);
                let b = handle.bob_ctl.dump(3);
                let a_ok = node_minmtu(&a, "bob").is_some_and(|m| m >= 1500);
                let b_ok = node_minmtu(&b, "alice").is_some_and(|m| m >= 1500);
                (a_ok && b_ok).then_some(())
            });
        }));
        if pmtu.is_err() {
            let a = handle.alice_log();
            let b = handle.bob_log();
            panic!("PMTU convergence timed out;\n=== alice ===\n{a}\n=== bob ===\n{b}");
        }

        handle
    }

    // ═══════════════════════════ iperf3 measurement ═══════════════════════════

    /// Returns `(received_bps, received_bytes)`. `-B` pins the source
    /// so the return path matches the crossed route; the host-route
    /// swap (not `--bind-dev`, unavailable on Darwin) steers output.
    fn measure(handle: &mut TunnelHandle) -> (f64, u64) {
        let mut server = Command::new("iperf3")
            .args(["-s", "--one-off", "-B", BOB_IP])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn iperf3 server");
        std::thread::sleep(Duration::from_millis(200));

        let client = Command::new("iperf3")
            .args(["-c", BOB_IP, "-B", ALICE_IP, "-t", "5", "--json"])
            .output()
            .expect("spawn iperf3 client");

        // `--one-off` exits the server after one client; but if the
        // client never connected (tunnel broken), it's still listening
        // and `wait()` would hang. kill() is a no-op if already gone.
        let _ = server.kill();
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
                 client stdout: {}\nclient stderr: {}\nserver stderr: {}\n\
                 === alice ===\n{a}\n=== bob ===\n{b}",
                client.status,
                String::from_utf8_lossy(&client.stdout),
                String::from_utf8_lossy(&client.stderr),
                srv_err,
            );
        }

        let parsed = parse_iperf(&client.stdout);
        (
            parsed.end.sum_received.bits_per_second,
            parsed.end.sum_received.bytes,
        )
    }

    /// Correctness gate: `REQ_DUMP_TRAFFIC` (subtype 13) byte counters
    /// must bracket the iperf3 payload. Lower bound: ≥ received bytes.
    /// Upper bound: ≤ 4× (ACKs, retransmits, framing, probes — small
    /// vs 5 s bulk). If the kernel short-circuits over `lo0`, iperf3
    /// reports multi-Gbps and both daemons report 0.
    fn assert_traffic_through_daemons(handle: &mut TunnelHandle, iperf_bytes: u64) {
        let a_rows = handle.alice_ctl.dump(13);
        let b_rows = handle.bob_ctl.dump(13);
        let (a_in, a_out) =
            node_traffic(&a_rows, "bob").unwrap_or_else(|| panic!("alice dump: {a_rows:?}"));
        let (b_in, b_out) =
            node_traffic(&b_rows, "alice").unwrap_or_else(|| panic!("bob dump: {b_rows:?}"));

        eprintln!(
            "  daemon counters: alice→bob out={a_out} in={a_in}  \
             bob→alice out={b_out} in={b_in}  iperf_recv={iperf_bytes}"
        );

        assert!(
            a_out > 0 && a_in > 0 && b_out > 0 && b_in > 0,
            "daemon traffic counters are ZERO — kernel short-circuited past utun \
             (host-route swap defeated?). iperf3 number is BOGUS.\n\
             alice rows: {a_rows:?}\nbob rows: {b_rows:?}"
        );
        // alice is the sender → its out_bytes toward bob must cover
        // the received payload; bob's in_bytes likewise.
        assert!(
            a_out >= iperf_bytes && b_in >= iperf_bytes,
            "daemon byte counters ({a_out}/{b_in}) below iperf3 received bytes \
             ({iperf_bytes}) — traffic partially bypassed the tunnel"
        );
        let cap = iperf_bytes.saturating_mul(4).max(1 << 20);
        assert!(
            a_out <= cap && b_in <= cap,
            "daemon byte counters ({a_out}/{b_in}) wildly exceed iperf3 bytes \
             ({iperf_bytes}) — accounting bug?"
        );
    }

    // ═══════════════════════════ latency (optional) ═══════════════════════════

    /// `/sbin/ping -c N -i 0.01`. macOS ping has no `-D`; `-i <1s`
    /// needs root (which we are).
    fn ping_rtts(count: u32) -> PingStats {
        let out = Command::new("/sbin/ping")
            .args(["-S", ALICE_IP, "-i", "0.01", "-c"])
            .arg(count.to_string())
            .arg(BOB_IP)
            .output()
            .expect("spawn ping");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stats = PingStats::parse(&stdout, count);
        assert!(
            !stats.rtts_ms.is_empty(),
            "ping got zero replies (tunnel dead / utun bypass?):\n{stdout}\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        stats
    }

    // ═══════════════════════════ sample(1) profiler ═══════════════════════════

    /// `sample PID SECS -f OUT`. Runs for a fixed duration then exits
    /// on its own (no SIGINT dance like `perf record`). `TINCD_PERF=1`.
    struct Sampler {
        child: Option<Child>,
        out: PathBuf,
    }
    impl Sampler {
        fn start(pid: u32, secs: u32, out: &Path) -> Self {
            if std::env::var_os("TINCD_PERF").is_none() {
                return Self {
                    child: None,
                    out: out.into(),
                };
            }
            let child = Command::new("/usr/bin/sample")
                .arg(pid.to_string())
                .arg(secs.to_string())
                .arg("-f")
                .arg(out)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .ok();
            if child.is_some() {
                eprintln!("sample {pid} {secs}s -> {}", out.display());
            } else {
                eprintln!("sample(1) unavailable; throughput measured without profile");
            }
            Self {
                child,
                out: out.into(),
            }
        }
        fn finish(mut self) {
            if let Some(mut c) = self.child.take() {
                let _ = c.wait();
                eprintln!("  sample report: open {}", self.out.display());
            }
        }
    }
    impl Drop for Sampler {
        fn drop(&mut self) {
            if let Some(mut c) = self.child.take() {
                let _ = c.kill();
                let _ = c.wait();
            }
        }
    }

    // ═══════════════════════════ pairings ════════════════════════════════════

    struct Pairing {
        name: &'static str,
        label: &'static str,
        tag: &'static str,
        sample_tag: Option<&'static str>,
        alice: Impl,
        bob: Impl,
    }

    fn run_pairing(p: &Pairing, perf_out: &Path) -> f64 {
        eprintln!("--- {} ---", p.label);
        let mut tunnel = setup_tunnel(p.tag, &p.alice, &p.bob);

        let (bps, bytes) = if let Some(tag) = p.sample_tag {
            let sa = Sampler::start(
                tunnel.alice_pid,
                5,
                &perf_out.join(format!("{tag}-alice.sample.txt")),
            );
            let sb = Sampler::start(
                tunnel.bob_pid,
                5,
                &perf_out.join(format!("{tag}-bob.sample.txt")),
            );
            let r = measure(&mut tunnel);
            sa.finish();
            sb.finish();
            r
        } else {
            measure(&mut tunnel)
        };

        assert_traffic_through_daemons(&mut tunnel, bytes);
        eprintln!("{}: {:.1} Mbps ({:.1} MB/s)", p.label, bps / 1e6, bps / 8e6);
        drop(tunnel);
        bps
    }

    fn run_latency(p: &Pairing) {
        eprintln!("--- latency {} ---", p.label);
        let mut tunnel = setup_tunnel(&format!("lat-{}", p.tag), &p.alice, &p.bob);
        // Snapshot before/after: setup's PMTU pings already bumped
        // the counter, so a bare `> 0` wouldn't catch a bypass.
        let (_, before) = node_traffic(&tunnel.alice_ctl.dump(13), "bob").unwrap_or((0, 0));
        let s = ping_rtts(100);
        eprintln!(
            "  idle: p50={:>7.3}ms p99={:>7.3}ms max={:>7.3}ms ({}/{} recv)",
            s.p50(),
            s.p99(),
            s.max(),
            s.recv(),
            s.sent
        );
        let (_, after) = node_traffic(&tunnel.alice_ctl.dump(13), "bob").unwrap_or((0, 0));
        assert!(
            after > before,
            "latency pings bypassed utun (out_bytes {before} -> {after})"
        );
        drop(tunnel);
    }

    // ═══════════════════════════ main ════════════════════════════════════════

    pub fn main() {
        let filters: Vec<String> = std::env::args()
            .skip(1)
            .filter(|a| !a.starts_with('-'))
            .collect();
        let matches = |name: &str| filters.is_empty() || filters.iter().any(|f| name.contains(f));

        if !nix::unistd::geteuid().is_root() {
            eprintln!(
                "SKIP throughput_macos: requires root for utun \
                 (run via `scripts/macos-bench-runner.sh`)"
            );
            return;
        }
        if !iperf3_available() {
            eprintln!("SKIP throughput_macos: iperf3 not on PATH (nix develop provides it)");
            return;
        }
        if std::env::var_os("TINCD_TRACE").is_some() {
            eprintln!("(TINCD_TRACE ignored on macOS — no perf-trace equivalent)");
        }

        let perf_out = std::env::var_os("TINCD_PERF_DIR")
            .map_or_else(|| PathBuf::from("/tmp/tincd-perf"), PathBuf::from);
        if std::env::var_os("TINCD_PERF").is_some() {
            std::fs::create_dir_all(&perf_out).ok();
        } else {
            eprintln!("(set TINCD_PERF=1 for sample(1) profile)");
        }

        let c_bin = c_tincd_bin();
        let mut pairings = vec![Pairing {
            name: "rust_rust",
            label: "Rust↔Rust",
            tag: "rr",
            sample_tag: Some("rust"),
            alice: Impl::Rust,
            bob: Impl::Rust,
        }];
        if let Some(c) = c_bin {
            pairings.insert(
                0,
                Pairing {
                    name: "c_c",
                    label: "C↔C",
                    tag: "cc",
                    sample_tag: Some("c"),
                    alice: Impl::C(c.clone()),
                    bob: Impl::C(c.clone()),
                },
            );
            pairings.push(Pairing {
                name: "rust_c",
                label: "Rust↔C",
                tag: "rc",
                sample_tag: None,
                alice: Impl::Rust,
                bob: Impl::C(c),
            });
        } else {
            eprintln!("(TINC_C_TINCD unset — Rust↔Rust only, no C baseline ratio)");
        }

        let mut results: Vec<(&'static str, f64)> = Vec::new();
        let mut ran_any = false;
        for p in &pairings {
            if matches(p.name) {
                results.push((p.name, run_pairing(p, &perf_out)));
                ran_any = true;
            }
            let want_latency = filters.is_empty() || filters.iter().any(|f| f.contains("latency"));
            if want_latency && matches(&format!("latency_{}", p.name)) {
                run_latency(p);
                ran_any = true;
            }
        }
        if !ran_any {
            eprintln!(
                "no pairing matched {filters:?}; available: {}, latency_<pairing>",
                pairings
                    .iter()
                    .map(|p| p.name)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            std::process::exit(1);
        }

        let r = results.iter().find(|(n, _)| *n == "rust_rust").map(|x| x.1);
        let c = results.iter().find(|(n, _)| *n == "c_c").map(|x| x.1);
        if let (Some(r), Some(c)) = (r, c) {
            eprintln!("Rust/C ratio: {:.1}%", r / c * 100.0);
        }
    }
}
