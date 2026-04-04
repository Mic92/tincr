//! Shared test fixtures. Each `tests/*.rs` is a separate crate;
//! `mod common;` includes this. Compiled once per test binary —
//! that's 8× compile of ~200 LOC, cheap. Cargo skips `tests/common/`
//! itself as a test target (no top-level `.rs`).
//!
//! ## What's here
//!
//! Only the bits that were **byte-identical** (or trivially
//! parametrizable) across files: `TmpGuard`, polling helpers,
//! pidfile parsers, `Ctl` (control-socket client), `node_status`,
//! and the 13-line ed25519 PEM-write block that every `write_config`
//! variant ended with.
//!
//! ## What's NOT here
//!
//! `struct Node` and `write_config`. The variants diverge on
//! load-bearing fields (`extra_conf` vs `iface`/`subnet` vs
//! `which: Impl`) and on spawn shape (`Child` vs `ChildWithLog`,
//! Rust vs C tincd). One union struct with `Option<_>` extras would
//! make every callsite uglier than the duplication it removes.
//! Tests do share `write_ed25519_privkey()` and `pubkey_from_seed()`
//! to gut the bulk of each `write_config`.
//!
//! `enter_netns` / `NetNs`. The bwrap re-exec is parametrized by
//! test name (the `--exact` arg), device names, env gates (TINC_C_
//! TINCD vs iperf3), and `--ignored` for throughput. The crossimpl.rs
//! comment is right: "Two ~100-line copies are cheaper than the
//! plumbing."

#![allow(dead_code)] // not every test file uses every helper

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::time::{Duration, Instant};

// ═══════════════════════════ tempdir ═══════════════════════════════

/// Hand-rolled tempdir. Thread id + PID in the name → parallel
/// tests (across threads AND across `cargo nextest`'s per-test
/// processes) don't collide. Cleanup on drop. No `tempfile` dep.
///
/// `prefix` namespaces by test FILE so `ls /tmp/tincd-*` is
/// readable in debug. Each file used to bake in a different prefix
/// (`tincd-2d-`, `tincd-stop-`, …); now it's an arg.
pub struct TmpGuard(PathBuf);

impl TmpGuard {
    pub fn new(prefix: &str, tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "tincd-{prefix}-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TmpGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ═══════════════════════════ tiny utilities ════════════════════════

/// `CARGO_BIN_EXE_tincd` — the binary cargo just built.
pub fn tincd_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tincd"))
}

/// Pre-allocate a TCP port: bind to 0, read it back, drop the
/// listener. Race window between drop and the daemon's re-bind is
/// sub-millisecond on loopback; fine in practice.
pub fn alloc_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind 0")
        .local_addr()
        .unwrap()
        .port()
}

/// Kill the child, wait, return its captured stderr. For panic
/// messages (`"setup failed; stderr: {}"`).
pub fn drain_stderr(mut child: Child) -> String {
    let _ = child.kill();
    let out = child.wait_with_output().unwrap();
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Pidfile format (`control.c:178`): `<pid> <cookie> <host> port <port>\n`.
/// Second whitespace token is the cookie.
pub fn read_cookie(pidfile: &Path) -> String {
    std::fs::read_to_string(pidfile)
        .unwrap()
        .split_whitespace()
        .nth(1)
        .expect("pidfile has cookie")
        .to_owned()
}

/// Parse the TCP listen address from the pidfile. v4 only — v6
/// hosts in the pidfile have no brackets (`listen::fmt_addr_v6_
/// no_brackets`) but `SocketAddr::from_str` wants brackets. All
/// tests set `AddressFamily = ipv4`.
pub fn read_tcp_addr(pidfile: &Path) -> std::net::SocketAddr {
    let content = std::fs::read_to_string(pidfile).unwrap();
    // `<pid> <cookie> <host> port <port>\n`; split off pid+cookie.
    let after_cookie = content.splitn(3, ' ').nth(2).expect("pidfile has addr");
    let mut parts = after_cookie.trim_end().split(" port ");
    let host = parts.next().expect("host");
    let port: u16 = parts.next().expect("port").parse().expect("port is num");
    format!("{host}:{port}").parse().expect("parseable v4 addr")
}

// ═══════════════════════════ polling ═══════════════════════════════

/// Poll for a file to exist. The daemon writes the control socket
/// in `setup()`; this is the readiness signal. 5s default — typical
/// setup is <100ms; the slack is for loaded CI boxes.
pub fn wait_for_file(path: &Path) -> bool {
    wait_for_file_with(path, Duration::from_secs(5))
}

pub fn wait_for_file_with(path: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}

/// Spinloop until `f` returns `Some` or `timeout` elapses. Panics
/// on timeout (so the failing assertion shows in the test output,
/// not just a hang → nextest SIGKILL).
pub fn poll_until<T>(timeout: Duration, mut f: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(v) = f() {
            return v;
        }
        assert!(
            Instant::now() < deadline,
            "poll timed out after {timeout:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

// ═══════════════════════════ crypto bits ═══════════════════════════

/// Derive the public key from a seed without keeping a `SigningKey`
/// around. The cross-registration in every `write_config` does
/// exactly this.
pub fn pubkey_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    use tinc_crypto::sign::SigningKey;
    *SigningKey::from_seed(seed).public_key()
}

/// Write `CONFBASE/ed25519_key.priv` with mode 0600. The 13-line
/// PEM-write block that every `write_config` variant ended with.
pub fn write_ed25519_privkey(confbase: &Path, seed: &[u8; 32]) {
    use std::os::unix::fs::OpenOptionsExt;
    use tinc_crypto::sign::SigningKey;
    let sk = SigningKey::from_seed(seed);
    let f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(confbase.join("ed25519_key.priv"))
        .unwrap();
    let mut w = std::io::BufWriter::new(f);
    tinc_conf::write_pem(&mut w, "ED25519 PRIVATE KEY", &sk.to_blob()).unwrap();
}

// ═══════════════════════════ control client ════════════════════════

/// Control-socket client. Same wire protocol both Rust and C tincd
/// (ours was transcribed from the C's `control.c`).
///
/// Decoupled from any `Node` struct: each test file has a different
/// `Node`, but they all expose `socket: PathBuf` and `pidfile:
/// PathBuf`. Pass those.
pub struct Ctl {
    pub r: BufReader<UnixStream>,
    pub w: UnixStream,
}

impl Ctl {
    /// Connect + greeting dance. Greeting: `"0 ^COOKIE 0\n"`, then
    /// two reply lines (`"0 NAME 17.7\n"` ID echo, `"4 0 PID\n"` ACK).
    pub fn connect(socket: &Path, pidfile: &Path) -> Self {
        let cookie = read_cookie(pidfile);
        let stream = UnixStream::connect(socket).expect("ctl connect");
        let r = BufReader::new(stream.try_clone().unwrap());
        let mut ctl = Self { r, w: stream };
        writeln!(ctl.w, "0 ^{cookie} 0").unwrap();
        let mut line = String::new();
        ctl.r.read_line(&mut line).unwrap();
        line.clear();
        ctl.r.read_line(&mut line).unwrap();
        ctl
    }

    /// `REQ_DUMP_*`: send `"18 SUBTYPE\n"`, collect rows until the
    /// bare `"18 SUBTYPE"` terminator.
    pub fn dump(&mut self, subtype: u8) -> Vec<String> {
        writeln!(self.w, "18 {subtype}").unwrap();
        let term = format!("18 {subtype}");
        let mut rows = Vec::new();
        loop {
            let mut line = String::new();
            self.r.read_line(&mut line).expect("dump row");
            let line = line.trim_end().to_owned();
            if line == term {
                break;
            }
            rows.push(line);
        }
        rows
    }
}

/// `dump nodes` row → status hex (body token 10). Row format
/// (`node.c:210` / our `dump_nodes_rows`): `name id host "port"
/// PORT cipher digest maclen comp opts STATUS nexthop ...`. Status
/// bits: `0x10` reachable, `0x02` validkey.
pub fn node_status(rows: &[String], name: &str) -> Option<u32> {
    rows.iter().find_map(|r| {
        let body = r.strip_prefix("18 3 ")?;
        let toks: Vec<&str> = body.split_whitespace().collect();
        if toks.first() != Some(&name) {
            return None;
        }
        u32::from_str_radix(toks.get(10)?, 16).ok()
    })
}

// ═══════════════════════════ linux netns helpers ═══════════════════
// Only used by netns/crossimpl/throughput, all of which are already
// `#![cfg(target_os = "linux")]`. cfg-gating here too keeps the
// compile clean if someone ever drops the file-level cfg.

#[cfg(target_os = "linux")]
pub mod linux {
    use std::io::Read;
    use std::process::{Child, Command};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    /// `ip <args...>` and assert success. Stderr in the panic
    /// message — `ip` errors are the kind that say "Cannot find
    /// device tincX0" and you want to see that.
    pub fn run_ip(args: &[&str]) {
        let out = Command::new("ip").args(args).output().expect("spawn ip");
        assert!(
            out.status.success(),
            "ip {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// Poll `ip link show DEV` for `LOWER_UP`. Precreated persistent
    /// TUN devices show `NO-CARRIER` until a daemon TUNSETIFF-
    /// attaches (`tun_set_iff` → `netif_carrier_on`). This is the
    /// "daemon opened its TUN" signal.
    pub fn wait_for_carrier(dev: &str, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            let out = Command::new("ip")
                .args(["-o", "link", "show", dev])
                .output()
                .expect("ip link show");
            if String::from_utf8_lossy(&out.stdout).contains("LOWER_UP") {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Child + background stderr drain. The C tincd at `-d5` floods
    /// stderr; with `PingTimeout = 1` it logs the full SPTPS dump
    /// every second. The 64 KiB pipe buffer fills in ~2s, the next
    /// `fprintf(stderr, ...)` blocks, the daemon's event loop
    /// freezes mid-handshake. Symptom: `Ctl::dump` blocks forever.
    /// Found the very first time crossimpl.rs ran for real.
    pub struct ChildWithLog {
        pub child: Child,
        log: Arc<Mutex<Vec<u8>>>,
        drain: Option<std::thread::JoinHandle<()>>,
    }

    impl ChildWithLog {
        pub fn spawn(mut child: Child) -> Self {
            let stderr = child.stderr.take().expect("stderr piped");
            let log = Arc::new(Mutex::new(Vec::new()));
            let log2 = Arc::clone(&log);
            let drain = std::thread::spawn(move || {
                let mut r = stderr;
                let mut buf = [0u8; 4096];
                while let Ok(n) = r.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    log2.lock().unwrap().extend_from_slice(&buf[..n]);
                }
            });
            Self {
                child,
                log,
                drain: Some(drain),
            }
        }

        pub fn pid(&self) -> u32 {
            self.child.id()
        }

        pub fn kill_and_log(mut self) -> String {
            let _ = self.child.kill();
            let _ = self.child.wait();
            if let Some(h) = self.drain.take() {
                let _ = h.join();
            }
            String::from_utf8_lossy(&self.log.lock().unwrap()).into_owned()
        }
    }
}
