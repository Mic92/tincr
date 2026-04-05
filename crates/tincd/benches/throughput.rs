//! Throughput benchmark. S3 (bwrap netns + real TUN) + S4
//! (against C tincd as the baseline). Run on demand:
//!
//! ```sh
//! cargo bench --bench throughput --profile profiling
//! cargo bench --bench throughput -- rust_rust   # one pairing only
//! cargo bench --bench throughput -- latency     # latency only (idle + load)
//! ```
//!
//! `harness = false` — this isn't a microbenchmark, the netns +
//! daemons + iperf3 setup IS the benchmark. Positional args after
//! `--` are substring filters (cargo bench convention). No filter
//! runs all three pairings + the ratio summary.
//!
//! ## What it measures
//!
//! `iperf3 -c 10.44.0.2 -t 5 --json` from the outer netns to a server
//! in the child netns. Packets traverse the full daemon stack: TUN
//! read → route → SPTPS encrypt → UDP sendto → loopback → recvfrom →
//! SPTPS decrypt → route → TUN write. Same path as `netns.rs::
//! real_tun_ping` but at line rate instead of 3 echoes.
//!
//! ## What it reports
//!
//! Rust↔Rust / C↔C throughput ratio on the same machine, same run.
//! Absolute numbers are meaningless across machines; the RATIO is what
//! you compare across commits. Single-threaded ChaCha20-Poly1305
//! should be within noise of C. A 50% regression means there's an
//! O(N) per-packet copy hiding somewhere.
//!
//! ## Why pre-tag, not CI
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
//! `cargo bench` defaults to `release`. The C tincd from
//! `.#tincd-c` is a meson `release` build — apples to apples. Use
//! `--profile profiling` for `TINCD_PERF=1` (same opt-level, adds
//! debuginfo + frame pointers so perf can unwind).
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

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("SKIP throughput: linux-only (needs netns + TUN)");
}

#[cfg(target_os = "linux")]
fn main() {
    bench::main();
}

// Benches can't `mod common;` from tests/. Nine other test files
// pull from common/ — promoting it to a dev-dep crate is more churn
// than this `#[path]` ugliness. CARGO_BIN_EXE_tincd in there works
// for benches same as tests (cargo sets it for any artifact that
// depends on the bin). Hoisted out of `mod bench` because `#[path]`
// resolves relative to a virtual `bench/` subdir inside an inline
// mod — which doesn't physically exist, so `..` traversal fails.
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
    // flag-by-flag explanation. No libtest — the inner re-exec just
    // forwards argv so the filter survives the bwrap boundary.

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
            // Forward filter args so `cargo bench -- rust_rust` survives
            // the re-exec. cargo bench passes `--bench` as a sentinel
            // (libtest convention) before user args; harmless here, we
            // skip non-matching tokens in the filter logic.
            .args(std::env::args_os().skip(1))
            .env("BWRAP_INNER", "1")
            .status()
            .expect("spawn bwrap");
        // Outer process is just a shell. Propagate the inner's exit
        // code so `cargo bench` sees setup panics.
        std::process::exit(status.code().unwrap_or(1));
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
                let _ = writeln!(tinc_conf, "ConnectTo = {}", other.name);
            }
            // Tight ping for fast detection of a hung daemon, but bumped
            // when profiling bob: two perf samplers + saturated receiver
            // can lose a ping under load.
            let pingtimeout = if std::env::var_os("TINCD_PERF_BOB").is_some() {
                5
            } else {
                1
            };
            let _ = writeln!(tinc_conf, "PingTimeout = {pingtimeout}");
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

    /// Read `minmtu` from a `dump nodes` row. Index 15 in the row
    /// format: `name id host "port" PORT cipher digest maclen comp
    /// options status nexthop via distance mtu minmtu ...`.
    /// PMTU discovery converges `minmtu` toward the path MTU; until it
    /// reaches ≥1500, full-MSS packets fall back to TCP-tunnelled
    /// `SPTPS_PACKET` (b64 over the meta-conn) which is ~100x slower.
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
    #[allow(clippy::too_many_lines)] // linear setup script; splitting hurts readability
    fn setup_tunnel(tag: &str, alice_impl: Impl, bob_impl: Impl) -> TunnelHandle {
        // Node status bits (`node.h:41`).
        const VALIDKEY: u32 = 0x02;
        const UDP_CONFIRMED: u32 = 0x80;

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
        // The C tincd avoids this wait via `choose_initial_maxmtu`:
        // `getsockopt(IP_MTU)` on a connected socket returns the
        // kernel's PMTU cache; on loopback that's 65536, clamped to
        // MTU=1518, and the very first probe at maxmtu
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
            panic!(
                "PMTU convergence (minmtu>=1500) timed out;\n=== alice ===\n{a}\n=== bob ===\n{b}"
            );
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
        /// actually made it through the tunnel + got `ACKed`.
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
        // median-of-3; the ratio comparison has slop for now.
        // -Z (sendfile zero-copy) tested at HEAD 7d47fdd1: no measurable
        // delta. iperf3 isn't the wall — bob's decrypt is. Leaving -Z
        // out keeps the test closer to the realistic case (apps that
        // tunnel through tinc do write(), not sendfile).
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

    // ═══════════════════════════ latency measurement ══════════════════════════════
    // Phase 3 (par-crypto) batches decrypts: frame 0 waits for the
    // whole batch before route fires. Throughput doesn't see that —
    // it's a tail-latency cost. Idle ping won't trigger batching
    // either (threshold is ~8 frames in flight). So: ping under
    // iperf3 load, report percentiles. The interesting number is
    // p99-under-load vs p99-idle, and Rust↔Rust vs C↔C under load.

    /// Per-packet RTTs in milliseconds, sorted. Derived from `ping -D`
    /// output — each reply line has `time=X ms`. The summary line's
    /// `min/avg/max/mdev` doesn't give percentiles; for tail latency
    /// (the par-crypto batching cost) we need the distribution.
    ///
    /// Sample input (iputils-20250605, captured against loopback):
    /// ```text
    /// [1775318329.288389] 64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.021 ms
    /// ...
    /// rtt min/avg/max/mdev = 0.018/0.027/0.053/0.014 ms
    /// ```
    /// `rsplit_once("time=")` skips the summary's `time 45ms` (no `=`).
    #[derive(Debug)]
    struct PingStats {
        rtts_ms: Vec<f64>,
        sent: u32,
    }

    impl PingStats {
        fn percentile(&self, p: f64) -> f64 {
            if self.rtts_ms.is_empty() {
                return f64::NAN;
            }
            // Nearest-rank. 100 samples → p99 is the 99th value;
            // good enough for a diagnostic. Not interpolating.
            // Casts: p ∈ [0,100], len ≤ 100 (we send 100 pings) so the
            // f64 product is well within both usize and f64 precision.
            #[allow(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                clippy::cast_precision_loss
            )]
            let idx = ((p / 100.0) * (self.rtts_ms.len() - 1) as f64).round() as usize;
            self.rtts_ms[idx.min(self.rtts_ms.len() - 1)]
        }
        fn p50(&self) -> f64 {
            self.percentile(50.0)
        }
        fn p99(&self) -> f64 {
            self.percentile(99.0)
        }
        fn max(&self) -> f64 {
            self.rtts_ms.last().copied().unwrap_or(f64::NAN)
        }
        fn recv(&self) -> usize {
            self.rtts_ms.len()
        }
    }

    /// `ping -c COUNT -i 0.01 -D 10.44.0.2`, parse per-packet RTTs.
    /// 10ms interval × 100 = ~1s wall time. `-D` adds timestamps but
    /// we don't use them — it's there to match the format we tested
    /// the parser against; the `time=` field is what we read.
    ///
    /// Loss is reported but not asserted on: under saturating iperf3
    /// load a few ICMP drops are normal (bob's recv buffer fills,
    /// kernel drops). The latency of the packets that DID make it is
    /// what shows the batching delay.
    fn ping_rtts(count: u32) -> PingStats {
        let out = Command::new("ping")
            .arg("-c")
            .arg(count.to_string())
            .args(["-i", "0.01", "-D", "10.44.0.2"])
            .output()
            .expect("spawn ping");
        // ping exits non-zero if ANY packets are lost. Under load
        // that's not a failure mode we care about; parse what we got.
        let stdout = String::from_utf8_lossy(&out.stdout);
        let mut rtts: Vec<f64> = stdout
            .lines()
            .filter_map(|l| {
                // `[1775318329.288389] 64 bytes from ...: ... time=0.021 ms`
                let t = l.rsplit_once("time=")?.1;
                let ms = t.split_ascii_whitespace().next()?;
                ms.parse().ok()
            })
            .collect();
        rtts.sort_by(|a, b| a.partial_cmp(b).unwrap());
        assert!(
            !rtts.is_empty(),
            "ping got zero replies (tunnel dead?):\nstdout:\n{stdout}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        PingStats {
            rtts_ms: rtts,
            sent: count,
        }
    }

    /// Idle RTT: tunnel is up, nothing flowing through it but the
    /// pings themselves. Baseline. Par-crypto batching shouldn't kick
    /// in here (1 packet every 10ms is far below the threshold).
    fn measure_latency_idle(_handle: &mut TunnelHandle) -> PingStats {
        ping_rtts(100)
    }

    /// RTT under throughput load: THE measurement for par-crypto.
    /// iperf3 saturates bob's decrypt path; concurrent pings see the
    /// queueing delay that batching introduces. Returns (mbps, ping).
    ///
    /// The iperf3 here uses `-t 3` not `-t 5`: ping does 100 × 10ms =
    /// ~1s of work; we ramp 500ms, ping ~1s, and want the load to
    /// outlast the ping. 3s covers it with margin. Shorter than the
    /// throughput-only `measure()` because here Mbps is context, not
    /// the headline number.
    fn measure_latency_load(handle: &mut TunnelHandle) -> (f64, PingStats) {
        let mut server = Command::new("ip")
            .args(["netns", "exec", "tbobside", "iperf3", "-s", "--one-off"])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn iperf3 server");
        std::thread::sleep(Duration::from_millis(200));

        // Client backgrounded so ping runs concurrently. --json so
        // we can report the Mbps that the latency was measured AT —
        // "p99=2ms under 800Mbps" reads differently than under 80.
        let client = Command::new("iperf3")
            .args(["-c", "10.44.0.2", "-t", "3", "--json"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn iperf3 client");

        // Ramp: TCP slow-start + first batch of full-MSS frames.
        // Without this the first ~20 pings see an idle-ish tunnel.
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

        let parsed: IperfResult = serde_json::from_slice(&client_out.stdout).unwrap_or_else(|e| {
            panic!(
                "iperf3 JSON parse: {e}\nstdout: {}",
                String::from_utf8_lossy(&client_out.stdout)
            )
        });
        (parsed.end.sum_received.bits_per_second, ping)
    }

    /// One latency pairing: idle, then under-load, on the same tunnel.
    /// Reusing the tunnel between idle and load means the PMTU/handshake
    /// state is identical for both — the only variable is the load.
    /// Returns (idle, `load_mbps`, load) for the cross-pairing summary.
    fn run_latency(
        p: &Pairing,
        do_idle: bool,
        do_load: bool,
    ) -> (Option<PingStats>, Option<(f64, PingStats)>) {
        eprintln!("--- latency {} ---", p.label);
        // "lat-" tag prefix → distinct tmpdir from the throughput run
        // of the same pairing (matters when both run in one invocation).
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

        // No per-pairing gate. Tried `load.p99 > 5× idle.p99` — fires
        // on Rust↔Rust (0.26ms idle → 18× ratio) but not C↔C (1.76ms
        // idle → 4.8×) despite Rust having LOWER absolute load p99.
        // The ratio is dominated by how good idle is, not how bad
        // load is. The cross-impl Δ at the end is the real signal.

        drop(tunnel);
        (idle, load)
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
    /// tracing` but that's a host-wide change). Run under sudo for
    /// one-off measurements:
    ///
    /// ```sh
    /// sudo -E env PATH=$PATH TINCD_TRACE=1 \
    ///   cargo bench --bench throughput --profile profiling
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
                // PIDs are < 2^22 on Linux; never wraps.
                #[allow(clippy::cast_possible_wrap)] // PID < pid_max ≤ 2^22
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
    /// throughput-only. The ratio doesn't NEED the profile; the
    /// profile is for the human reading a regression.
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
                // PIDs are < 2^22 on Linux; never wraps.
                #[allow(clippy::cast_possible_wrap)] // PID < pid_max ≤ 2^22
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

    // ═══════════════════════════════ pairings ══════════════════════════════════

    /// One named pairing. `name` is what `cargo bench -- <substr>`
    /// matches against. `perf_tag` names the perf.data / trace files
    /// (only the C↔C and Rust↔Rust pairings get profiled — see the
    /// `profile` field; Rust↔C is the interop sanity check, not the
    /// thing you'd open in perf).
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
    fn run_pairing(p: &Pairing, perf_out: &Path, perf_bob: bool) -> f64 {
        eprintln!("--- {} ---", p.label);
        let mut tunnel = setup_tunnel(p.tag, p.alice.clone(), p.bob.clone());

        let bps = if let Some(tag) = p.perf_tag {
            let alice_perf = perf_out.join(format!("{tag}-alice.perf.data"));
            let bob_perf = perf_out.join(format!("{tag}-bob.perf.data"));
            let _pa = PerfRecord::start(tunnel.alice_pid, &alice_perf);
            // TINCD_PERF profiles alice (sender). TINCD_PERF_BOB
            // additionally profiles bob (receiver) — opt-in because two
            // `perf -F 999` samplers + PingTimeout=1 + a saturated
            // receiver is enough overhead to flap the meta-conn on slow
            // hosts. Set both envs.
            let _pb = perf_bob.then(|| PerfRecord::start(tunnel.bob_pid, &bob_perf));
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

    // ═════════════════════════════════ main ════════════════════════════════════

    #[allow(clippy::too_many_lines)] // top-level bench harness wiring
    pub fn main() {
        // Substring filter, cargo bench convention. `cargo bench --bench
        // throughput -- rust_rust` → argv = [self, "--bench", "rust_rust"].
        // `--bench` is the libtest sentinel cargo always passes; we have
        // no libtest, so just skip anything starting with `-`. Everything
        // else is a filter; a pairing runs if its name contains ANY filter
        // (or if no filters were given).
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
        let perf_bob = std::env::var_os("TINCD_PERF_BOB").is_some();
        let perf_out = std::env::var_os("TINCD_PERF_DIR")
            .map_or_else(|| PathBuf::from("/tmp/tincd-perf"), PathBuf::from);
        if perf_on || trace_on {
            std::fs::create_dir_all(&perf_out).ok();
        } else {
            eprintln!("(set TINCD_PERF=1 for sampling profile, TINCD_TRACE=1 for syscall counts)");
        }

        // Order matters for the perf workflow: C↔C first establishes the
        // "healthy profile" shape to diff Rust↔Rust against. Rust↔C last
        // — alice is Rust there too, but Rust↔Rust is the interesting
        // profile and two are enough.
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
                results[i] = Some(run_pairing(p, &perf_out, perf_bob));
                ran_any = true;
            }
            // Latency: "latency_{idle,load}_<pairing>". Substring filter
            // means `-- latency` runs all six, `-- latency_idle` runs
            // three, `-- latency_load_rust_rust` runs one. The
            // `want_latency` guard stops a bare `-- rust_rust` from
            // also matching `latency_load_rust_rust` (substring would).
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

        // ─── hot-symbol report ─────────────────────────────────────
        // Before the gate. If it fails, the next thing anyone does is
        // open the profile; if it passes, the profile is the baseline
        // for the next regression. Only when perf actually ran —
        // `report_hot_symbols` checks file existence too, but skip the
        // noise entirely when off.
        if perf_on {
            if rust.is_some() {
                report_hot_symbols(&perf_out.join("rust-alice.perf.data"));
                if perf_bob {
                    report_hot_symbols(&perf_out.join("rust-bob.perf.data"));
                }
            }
            if baseline.is_some() {
                report_hot_symbols(&perf_out.join("c-alice.perf.data"));
                if perf_bob {
                    report_hot_symbols(&perf_out.join("c-bob.perf.data"));
                }
            }
            eprintln!("perf data: {}", perf_out.display());
        }

        // ─── ratios ────────────────────────────────────────────────
        // No exit(1) gate: we're already at ~135% of C; a hard 95%
        // threshold would never fire and the dev-profile 1% "is the
        // tunnel dead" check is better caught by netns.rs::ping.
        // Compare ratios across commits by eye. If Rust/C drops to
        // ~50%, look for per-packet Vec::clone (_ZN5alloc... high in
        // the hot-symbol report). The chunk-11-perf STUBs (per-packet
        // Vec allocs in send_record_priv, maybe_set_write_any walking
        // all conns) cost ~15-20% — STUB(chunk-11-perf): close those
        // and we should be further ahead.
        if let (Some(baseline), Some(rust)) = (baseline, rust) {
            eprintln!("Rust/C ratio: {:.1}%", rust / baseline * 100.0);
            // Mixed against the SLOWER endpoint: a mixed pair is
            // bottlenecked by whichever side lacks the optimization.
            // GSO put Rust ahead of C, so comparing against Rust↔Rust
            // measures "how slow is C", not "is interop broken".
            if let Some(mixed) = mixed {
                let slower = rust.min(baseline);
                eprintln!(
                    "Rust↔C / min(Rust↔Rust, C↔C): {:.1}%",
                    mixed / slower * 100.0
                );
            }
        }

        // ─── latency summary ───────────────────────────────────────
        // The Rust-vs-C p99-under-load delta is the par-crypto cost
        // isolated: same kernel, same iperf3, only the daemon differs.
        // Diagnostic, not a gate — absolute latency varies wildly
        // across machines (loopback netns on a laptop vs a CI VM).
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
