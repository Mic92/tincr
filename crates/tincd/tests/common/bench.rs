//! Shared by `benches/throughput{,_macos}.rs`; topology stays per-platform.

#![allow(
    clippy::allow_attributes,
    reason = "shared by several test binaries, each uses a subset"
)]
#![allow(dead_code)] // each bench uses a subset

use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use super::node::Node;
use super::{TmpGuard, node_status, tincd_at};

pub fn c_tincd_bin() -> Option<PathBuf> {
    std::env::var_os("TINC_C_TINCD").map(PathBuf::from)
}

pub fn iperf3_available() -> bool {
    Command::new("iperf3")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

pub fn perf_enabled() -> bool {
    std::env::var_os("TINCD_PERF").is_some()
}

#[derive(Clone)]
pub enum Impl {
    Rust,
    C(PathBuf),
}

impl Impl {
    /// Per-packet debug logging would be the bottleneck.
    pub fn start(&self, node: &mut Node) {
        let mut cmd = match self {
            Self::Rust => {
                let mut cmd = tincd_at(&node.confbase, &node.pidfile, &node.socket);
                cmd.env("RUST_LOG", "tincd=info");
                // Non-dumpable processes refuse `perf record -p`.
                if perf_enabled() {
                    cmd.env("TINCR_ALLOW_COREDUMP", "1");
                }
                cmd
            }
            Self::C(bin) => {
                let mut cmd = Command::new(bin);
                cmd.args(["-D", "-d0", "-c"])
                    .arg(&node.confbase)
                    .arg("--pidfile")
                    .arg(&node.pidfile);
                cmd
            }
        };
        cmd.stderr(Stdio::piped());
        node.start_command(cmd);
    }
}

/// A sampling profiler can stall a ping cycle, hence the looser timeout.
pub fn bench_conf(ping_timeout: u32) -> String {
    let ping_timeout = if perf_enabled() { 5 } else { ping_timeout };
    let mut conf = format!("PingTimeout = {ping_timeout}\n");
    if let Ok(cipher) = std::env::var("TINCD_BENCH_SPTPS_CIPHER") {
        writeln!(conf, "SPTPSCipher = {cipher}").unwrap();
    }
    conf
}

/// alice dials bob.
pub struct Tunnel {
    pub tmp: TmpGuard,
    pub alice: Node,
    pub bob: Node,
}

impl Tunnel {
    pub fn start(tmp: TmpGuard, mut alice: Node, mut bob: Node, impls: (&Impl, &Impl)) -> Self {
        bob.write_config(&alice, false);
        impls.1.start(&mut bob);
        alice.write_config(&bob, true);
        impls.0.start(&mut alice);
        Self { tmp, alice, bob }
    }

    pub fn logs(&self) -> String {
        format!(
            "=== alice ===\n{}\n=== bob ===\n{}",
            self.alice.log(),
            self.bob.log()
        )
    }

    /// `check(alice_nodes, bob_nodes)`; panics with both logs.
    pub fn wait_for(
        &self,
        what: &str,
        timeout: Duration,
        mut check: impl FnMut(&[String], &[String]) -> bool,
    ) {
        let deadline = std::time::Instant::now() + timeout;
        while !check(&self.alice.ctl().dump(3), &self.bob.ctl().dump(3)) {
            assert!(
                std::time::Instant::now() < deadline,
                "{what} timed out\n{}",
                self.logs()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Until minmtu ≥ 1500, full segments take the TCP fallback. PMTU
    /// probing is demand-driven, hence `kick`.
    pub fn wait_data_path(&self, kick: impl Fn()) {
        const REACHABLE: u32 = 0x10;
        const VALIDKEY_UDP: u32 = 0x02 | 0x80;
        let both = |alice: &[String], bob: &[String], want: u32| {
            node_status(alice, "bob").is_some_and(|s| s & want == want)
                && node_status(bob, "alice").is_some_and(|s| s & want == want)
        };
        self.wait_for("meta handshake", Duration::from_secs(10), |a, b| {
            both(a, b, REACHABLE)
        });
        kick();
        self.wait_for("validkey/udp_confirmed", Duration::from_secs(10), |a, b| {
            both(a, b, VALIDKEY_UDP)
        });
        self.wait_for("PMTU convergence", Duration::from_secs(20), |a, b| {
            kick();
            node_minmtu(a, "bob").is_some_and(|m| m >= 1500)
                && node_minmtu(b, "alice").is_some_and(|m| m >= 1500)
        });
    }
}

/// `dump nodes` row → `minmtu` (token 15).
pub fn node_minmtu(rows: &[String], name: &str) -> Option<u16> {
    rows.iter().find_map(|r| {
        let toks: Vec<&str> = r.strip_prefix("18 3 ")?.split_whitespace().collect();
        if toks.first() != Some(&name) {
            return None;
        }
        toks.get(15)?.parse().ok()
    })
}

pub fn ping_once(dest: &str) {
    #[cfg(target_os = "macos")]
    let args = ["-c", "1", "-t", "1"];
    #[cfg(not(target_os = "macos"))]
    let args = ["-c", "1", "-W", "1"];
    let _ = Command::new("ping")
        .args(args)
        .arg(dest)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

pub fn iperf3_client(tunnel: &Tunnel, args: &[&str]) -> IperfSum {
    let out = Command::new("iperf3")
        .args(args)
        .arg("--json")
        .output()
        .expect("spawn iperf3 client");
    assert!(
        out.status.success(),
        "iperf3 {args:?}: {:?}\nstdout: {}\nstderr: {}\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
        tunnel.logs()
    );
    parse_iperf(&out.stdout).end.sum_received
}

#[derive(Debug, serde::Deserialize)]
pub struct IperfResult {
    pub end: IperfEnd,
}
#[derive(Debug, serde::Deserialize)]
pub struct IperfEnd {
    /// `sum_sent` may include bytes still in flight.
    pub sum_received: IperfSum,
}
#[derive(Debug, serde::Deserialize)]
pub struct IperfSum {
    pub bits_per_second: f64,
    #[serde(default)]
    pub bytes: u64,
}

pub fn parse_iperf(stdout: &[u8]) -> IperfResult {
    serde_json::from_slice(stdout).unwrap_or_else(|e| {
        panic!(
            "iperf3 JSON parse: {e}\nstdout: {}",
            String::from_utf8_lossy(stdout)
        )
    })
}

/// Sorted RTTs from `time=X` lines (iputils and BSD alike).
#[derive(Debug)]
pub struct PingStats {
    pub rtts_ms: Vec<f64>,
    pub sent: u32,
}

impl PingStats {
    pub fn parse(stdout: &str, sent: u32) -> Self {
        let mut rtts: Vec<f64> = stdout
            .lines()
            .filter_map(|l| {
                let t = l.rsplit_once("time=")?.1;
                t.split_ascii_whitespace().next()?.parse().ok()
            })
            .collect();
        rtts.sort_by(|a, b| a.partial_cmp(b).unwrap());
        Self {
            rtts_ms: rtts,
            sent,
        }
    }

    /// ping exits non-zero on any loss, so the status is ignored.
    pub fn measure(args: &[&str], dest: &str, count: u32) -> Self {
        let out = Command::new("ping")
            .args(args)
            .arg("-c")
            .arg(count.to_string())
            .arg(dest)
            .output()
            .expect("spawn ping");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stats = Self::parse(&stdout, count);
        assert!(
            !stats.rtts_ms.is_empty(),
            "ping got zero replies:\n{stdout}\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        stats
    }

    pub fn percentile(&self, p: f64) -> f64 {
        if self.rtts_ms.is_empty() {
            return f64::NAN;
        }
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            clippy::cast_precision_loss
        )]
        let idx = ((p / 100.0) * (self.rtts_ms.len() - 1) as f64).round() as usize;
        self.rtts_ms[idx.min(self.rtts_ms.len() - 1)]
    }

    pub fn summary(&self) -> String {
        format!(
            "p50={:>7.3}ms  p99={:>7.3}ms  max={:>7.3}ms  ({}/{} recv)",
            self.percentile(50.0),
            self.percentile(99.0),
            self.rtts_ms.last().copied().unwrap_or(f64::NAN),
            self.rtts_ms.len(),
            self.sent
        )
    }
}
