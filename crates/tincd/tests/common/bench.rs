//! Platform-neutral helpers shared by `benches/throughput{,_macos}.rs`.
//! Only pure parsers / serde structs / tiny probes; `setup_tunnel`/
//! `measure` stay per-platform (netns re-exec vs host-route swap vs
//! `perf`/`sample` don't share control flow).

use std::path::PathBuf;
use std::process::{Command, Stdio};

// ═══════════════════════════ env / tool gates ══════════════════════

/// `TINC_C_TINCD` — path to the C `tincd` (devshell sets it).
pub fn c_tincd_bin() -> Option<PathBuf> {
    std::env::var_os("TINC_C_TINCD").map(PathBuf::from)
}

pub fn iperf3_available() -> bool {
    Command::new("iperf3")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// `Rust` = `CARGO_BIN_EXE_tincd`; `C(path)` = `TINC_C_TINCD`.
#[derive(Clone)]
pub enum Impl {
    Rust,
    C(PathBuf),
}

// ═══════════════════════════ ctl-dump parsers ══════════════════════

/// `dump nodes` row → `minmtu` (body token 15). Row: `name id host
/// "port" PORT cipher digest maclen comp opts status nexthop via
/// distance mtu MINMTU maxmtu ...`. Until PMTU discovery lifts this
/// past full-MSS, big packets fall back to TCP-tunnelled
/// `SPTPS_PACKET` and the bench measures the wrong path.
pub fn node_minmtu(rows: &[String], name: &str) -> Option<u16> {
    rows.iter().find_map(|r| {
        let body = r.strip_prefix("18 3 ")?;
        let toks: Vec<&str> = body.split_whitespace().collect();
        if toks.first() != Some(&name) {
            return None;
        }
        toks.get(15)?.parse().ok()
    })
}

// ═══════════════════════════ iperf3 JSON ═══════════════════════════

#[derive(Debug, serde::Deserialize)]
pub struct IperfResult {
    pub end: IperfEnd,
}
#[derive(Debug, serde::Deserialize)]
pub struct IperfEnd {
    /// Server-side received: what actually crossed the tunnel and got
    /// acked (`sum_sent` may include bytes still in flight).
    pub sum_received: IperfSum,
}
#[derive(Debug, serde::Deserialize)]
pub struct IperfSum {
    pub bits_per_second: f64,
    /// Feeds the macOS short-circuit assert; Linux ignores it.
    #[serde(default)]
    pub bytes: u64,
}

/// Panics with the raw JSON on failure (usual cause: iperf3 emitted
/// an `{"error": ...}` object).
pub fn parse_iperf(stdout: &[u8]) -> IperfResult {
    serde_json::from_slice(stdout).unwrap_or_else(|e| {
        panic!(
            "iperf3 JSON parse: {e}\nstdout: {}",
            String::from_utf8_lossy(stdout)
        )
    })
}

// ═══════════════════════════ ping percentiles ══════════════════════

/// Per-packet RTTs (ms), sorted. Parsed from `time=X` reply lines;
/// works for both iputils and BSD ping (neither summary line has
/// `time=` with `=`).
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
    pub fn p50(&self) -> f64 {
        self.percentile(50.0)
    }
    pub fn p99(&self) -> f64 {
        self.percentile(99.0)
    }
    pub fn max(&self) -> f64 {
        self.rtts_ms.last().copied().unwrap_or(f64::NAN)
    }
    pub const fn recv(&self) -> usize {
        self.rtts_ms.len()
    }
}
