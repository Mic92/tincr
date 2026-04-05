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
//! test name (the `--exact` arg), device names, env gates
//! (`TINC_C_TINCD` vs `iperf3`), and `--ignored` for throughput. The crossimpl.rs
//! comment is right: "Two ~100-line copies are cheaper than the
//! plumbing."

#![allow(dead_code)] // not every test file uses every helper

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
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

/// `Command::new(tincd_bin())` with `-D` (no-detach) pre-added.
///
/// `do_detach` defaults true; the Rust binary matches. A detached child
/// double-forks out from under `Child` — the test sees the original
/// parent exit 0 immediately, `wait_for_file` races a process that
/// isn't ours, and `child.kill()` is a no-op. Every test that
/// observes the daemon must keep it foreground.
///
/// Tests that DON'T spawn (the `.output()` ones that just check
/// argv-parse errors) don't need `-D` — the daemon errors out
/// before `detach()` is reached — but they get it anyway via this
/// helper. Harmless.
pub fn tincd_cmd() -> Command {
    let mut c = Command::new(tincd_bin());
    c.arg("-D");
    c
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

/// Pidfile format: `<pid> <cookie> <host> port <port>\n`.
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

/// `dump nodes` row → status hex (body token 10). Row format (see
/// `dump_nodes_rows`): `name id host "port" PORT cipher digest
/// maclen comp opts STATUS nexthop ...`. Status bits: `0x10`
/// reachable, `0x02` validkey.
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

// ═══════════════════════════ SPTPS peer fixture ═══════════════════
//
// Shared by `stop.rs::{peer_ack_exchange, peer_edge_triggers_
// reachable, pcap_captures_tcp_packet}`. The first ~130 lines of
// those tests were byte-identical: paths → config → spawn → wait →
// TCP connect → send ID → read daemon's ID (raw, find '\n') → SPTPS
// start → pump until HandshakeDone + first Record (the daemon's ACK).
//
// Tests that DON'T fit:
//   - `peer_wrong_key_fails_sig`: registers a FAKE pubkey for
//     testpeer (negative test — the pump must NOT complete).
//   - `security.rs::splice_mitm_rejected`: two daemons, the test
//     process is a relay not an SPTPS peer.
//
// `our_key` seed is `[0x77; 32]` everywhere; that's baked in.
// Daemon name is `testnode`, peer name is `testpeer`. The label
// (`"tinc TCP key expansion testpeer testnode\0"`) follows. If a
// future test needs different names, parametrize then — not now.

/// `RngCore` that asserts it's never touched. The initiator's
/// `Sptps::receive` doesn't generate randomness during the initial
/// handshake (only `start` does, for KEX); after `HandshakeDone`,
/// `receive` decrypts (no RNG). If this ever fires, the SPTPS state
/// machine changed — the test should know.
pub struct NoRng;
impl rand_core::RngCore for NoRng {
    fn next_u32(&mut self) -> u32 {
        unreachable!("RNG touched")
    }
    fn next_u64(&mut self) -> u64 {
        unreachable!("RNG touched")
    }
    fn fill_bytes(&mut self, _: &mut [u8]) {
        unreachable!("RNG touched")
    }
    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), rand_core::Error> {
        unreachable!("RNG touched")
    }
}

/// One spawned daemon + an active SPTPS peer connection from the
/// test process. Handshake is COMPLETE; the daemon's ACK record is
/// captured.
///
/// Dropping this kills the child (via `Child`'s drop … actually
/// `Child` doesn't kill on drop; tests must call `child.kill()`
/// explicitly when they're done. Same as before the fixture.)
pub struct PeerFixture {
    pub tmp: TmpGuard,
    pub confbase: PathBuf,
    pub pidfile: PathBuf,
    pub socket: PathBuf,
    pub child: Child,
    /// TCP stream to the daemon. Read/Write impls on `&TcpStream`
    /// (the duplex shared-ref trick). 5s read timeout set.
    pub stream: std::net::TcpStream,
    /// SPTPS session. Past `HandshakeDone`; ready for `send_record`.
    pub sptps: tinc_sptps::Sptps,
    /// The daemon's first post-handshake record (its ACK:
    /// `"4 <udp-port> <weight> <opts-hex>\n"`). `peer_ack_exchange`
    /// parses this; other tests ignore it.
    pub daemon_ack: Vec<u8>,
}

impl PeerFixture {
    /// Standard setup: router-mode config (`write_config_default`),
    /// our pubkey registered as `hosts/testpeer`.
    pub fn spawn(tag: &str) -> Self {
        Self::spawn_with_config(tag, |confbase| {
            // Same body as `stop.rs::write_config`: minimal
            // router-mode config, seed `[0x42; 32]`.
            std::fs::create_dir_all(confbase.join("hosts")).unwrap();
            std::fs::write(
                confbase.join("tinc.conf"),
                "Name = testnode\nDeviceType = dummy\nAddressFamily = ipv4\n",
            )
            .unwrap();
            std::fs::write(confbase.join("hosts").join("testnode"), "Port = 0\n").unwrap();
            let seed = [0x42; 32];
            write_ed25519_privkey(confbase, &seed);
            pubkey_from_seed(&seed)
        })
    }

    /// Custom config: caller writes `tinc.conf` + `hosts/testnode` +
    /// `ed25519_key.priv`, returns the daemon's pubkey. The fixture
    /// writes `hosts/testpeer` and does the rest.
    ///
    /// `pcap_captures_tcp_packet` uses this for `Mode = switch`.
    #[allow(clippy::too_many_lines)] // linear setup script; splitting hides the sequence
    pub fn spawn_with_config(tag: &str, write_conf: impl FnOnce(&Path) -> [u8; 32]) -> Self {
        use rand_core::OsRng;
        use std::io::{Read, Write};
        use tinc_crypto::sign::SigningKey;
        use tinc_sptps::{Framing, Output, Role, Sptps};

        let tmp = TmpGuard::new("stop", tag);
        let confbase = tmp.path().join("vpn");
        let pidfile = tmp.path().join("tinc.pid");
        let socket = tmp.path().join("tinc.socket");

        // ─── config: daemon's tinc.conf + our hosts/testpeer ───
        let daemon_pub = write_conf(&confbase);
        let our_key = SigningKey::from_seed(&[0x77; 32]);
        let our_pub = *our_key.public_key();
        let b64 = tinc_crypto::b64::encode(&our_pub);
        std::fs::write(
            confbase.join("hosts").join("testpeer"),
            format!("Ed25519PublicKey = {b64}\n"),
        )
        .unwrap();

        // ─── spawn daemon (RUST_LOG=tincd=info captures the
        //     "handshake completed" / "became reachable" lines) ───
        let mut child = tincd_cmd()
            .arg("-c")
            .arg(&confbase)
            .arg("--pidfile")
            .arg(&pidfile)
            .arg("--socket")
            .arg(&socket)
            .env("RUST_LOG", "tincd=info")
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn tincd");

        assert!(wait_for_file(&socket), "tincd setup failed; stderr: {}", {
            let _ = child.kill();
            let out = child.wait_with_output().unwrap();
            String::from_utf8_lossy(&out.stderr).into_owned()
        });

        let tcp_addr = read_tcp_addr(&pidfile);

        // ─── TCP connect + send ID line ───────────────────────────
        // `"%d %s %d.%d"` — we are testpeer, version 17.7. The
        // `&TcpStream` Read+Write impls handle the duplex; bind
        // immutable, use `(&stream).read()` / `(&stream).write_all()`.
        let stream = std::net::TcpStream::connect(tcp_addr).expect("TCP connect to tincd");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        writeln!(&stream, "0 testpeer 17.7").unwrap();

        // ─── recv daemon's ID line ────────────────────────────────
        // CAN'T use BufReader.read_line: it buffers PAST the `\n`
        // and swallows the daemon's KEX bytes. Read raw, find `\n`.
        let mut buf = Vec::with_capacity(256);
        let mut tmp_buf = [0u8; 256];
        let id_end = loop {
            let n = (&stream).read(&mut tmp_buf).expect("recv from daemon");
            assert_ne!(n, 0, "daemon closed before sending ID line; got: {buf:?}");
            buf.extend_from_slice(&tmp_buf[..n]);
            if let Some(pos) = buf.iter().position(|&b| b == b'\n') {
                break pos;
            }
        };
        assert_eq!(&buf[..id_end], b"0 testnode 17.7", "daemon ID reply");

        // ─── SPTPS start: WE are the initiator ───────────────────
        // Label: `"tinc TCP key expansion <initiator> <responder>\0"`.
        // We connected (outgoing) → we are the initiator. The NUL
        // terminator matters — same construction as `proto::tcp_label`.
        let mut label = b"tinc TCP key expansion testpeer testnode".to_vec();
        label.push(0);

        let (mut sptps, init) = Sptps::start(
            Role::Initiator,
            Framing::Stream,
            our_key,
            daemon_pub,
            label,
            0,
            &mut OsRng,
        );
        for o in init {
            if let Output::Wire { bytes, .. } = o {
                (&stream).write_all(&bytes).expect("send KEX");
            }
        }

        // ─── pump: feed daemon ↔ sptps until HandshakeDone + ACK ──
        // Daemon's SIG arrives in the same flush as its `send_ack`;
        // both might land in one read or two. Loop until we have
        // BOTH `HandshakeDone` AND the first `Record` (the ACK).
        let mut pending: Vec<u8> = buf[id_end + 1..].to_vec();
        let mut handshake_done = false;
        let mut daemon_ack: Option<Vec<u8>> = None;
        let deadline = Instant::now() + Duration::from_secs(5);

        while !(handshake_done && daemon_ack.is_some()) {
            if Instant::now() > deadline {
                let _ = child.kill();
                let out = child.wait_with_output().unwrap();
                panic!(
                    "handshake didn't complete in 5s; stderr:\n{}",
                    String::from_utf8_lossy(&out.stderr)
                );
            }
            let mut off = 0;
            while off < pending.len() {
                let (n, outs) = match sptps.receive(&pending[off..], &mut NoRng) {
                    Ok(r) => r,
                    Err(e) => {
                        let _ = child.kill();
                        let out = child.wait_with_output().unwrap();
                        panic!(
                            "SPTPS receive failed: {e:?}; stderr:\n{}",
                            String::from_utf8_lossy(&out.stderr)
                        );
                    }
                };
                off += n;
                for o in outs {
                    match o {
                        Output::Wire { bytes, .. } => {
                            // Our SIG (initiator sends after recv'ing
                            // responder's KEX).
                            (&stream).write_all(&bytes).expect("send Wire");
                        }
                        Output::HandshakeDone => handshake_done = true,
                        Output::Record { bytes, .. } => {
                            // First (and only) post-handshake record
                            // before we ACK back: the daemon's ACK.
                            daemon_ack = Some(bytes);
                        }
                    }
                }
                if n == 0 {
                    break;
                }
            }
            pending.clear();
            if handshake_done && daemon_ack.is_some() {
                break;
            }
            match (&stream).read(&mut tmp_buf) {
                Ok(0) => {
                    let _ = child.kill();
                    let out = child.wait_with_output().unwrap();
                    panic!(
                        "daemon EOF before HandshakeDone; stderr:\n{}",
                        String::from_utf8_lossy(&out.stderr)
                    );
                }
                Ok(n) => pending.extend_from_slice(&tmp_buf[..n]),
                Err(e) => {
                    let _ = child.kill();
                    let out = child.wait_with_output().unwrap();
                    panic!(
                        "read error: {e}; stderr:\n{}",
                        String::from_utf8_lossy(&out.stderr)
                    );
                }
            }
        }

        Self {
            tmp,
            confbase,
            pidfile,
            socket,
            child,
            stream,
            sptps,
            daemon_ack: daemon_ack.expect("loop exited with daemon_ack set"),
        }
    }

    /// Send an SPTPS record body to the daemon. Wraps the
    /// `sptps.send_record(0, body)` + `for Wire { write_all }` boilerplate.
    pub fn send_record(&mut self, body: &[u8]) {
        use std::io::Write;
        use tinc_sptps::Output;
        let outs = self.sptps.send_record(0, body).expect("send_record");
        for o in outs {
            if let Output::Wire { bytes, .. } = o {
                (&self.stream).write_all(&bytes).expect("send Wire");
            }
        }
    }

    /// Drain SPTPS records from the daemon until the socket would
    /// block AND there's no partial buffered. Sets a short read
    /// timeout (`timeout_ms`) and pumps until WouldBlock with an
    /// empty buffer.
    ///
    /// Returns all `Record` bodies seen. Used to drain the
    /// post-ACK `send_everything` gossip and to verify
    /// `forward_request`'s skip-from logic (we are `from`, so an
    /// empty result proves the broadcast skipped us).
    pub fn drain_records(&mut self, timeout_ms: u64) -> Vec<Vec<u8>> {
        use std::io::Read;
        use tinc_sptps::Output;
        self.stream
            .set_read_timeout(Some(Duration::from_millis(timeout_ms)))
            .unwrap();
        let mut pending = Vec::new();
        let mut recs = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut tmp_buf = [0u8; 256];
        loop {
            assert!(Instant::now() <= deadline, "drain timeout");
            let mut off = 0;
            while off < pending.len() {
                let (n, outs) = self
                    .sptps
                    .receive(&pending[off..], &mut NoRng)
                    .expect("sptps");
                if n == 0 {
                    break;
                }
                off += n;
                for o in outs {
                    if let Output::Record { bytes, .. } = o {
                        recs.push(bytes);
                    }
                }
            }
            pending.drain(..off);
            match (&self.stream).read(&mut tmp_buf) {
                Ok(0) => panic!("daemon EOF mid-drain"),
                Ok(n) => pending.extend_from_slice(&tmp_buf[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if pending.is_empty() {
                        return recs;
                    }
                }
                Err(e) => panic!("read error: {e}"),
            }
        }
    }

    /// Kill the daemon and return its stderr. Consumes the fixture
    /// (the `Child` is gone after `wait_with_output`).
    pub fn kill_and_stderr(mut self) -> String {
        let _ = self.child.kill();
        let out = self.child.wait_with_output().unwrap();
        String::from_utf8_lossy(&out.stderr).into_owned()
    }
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
