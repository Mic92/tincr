//! Cross-implementation testing: Rust tincd ↔ C tincd.
//!
//! **THE wire-compat proof.** Every other test in the suite proves
//! "consistent with ourselves". `netns.rs` proves Rust↔Rust ping
//! works; `tinc-sptps`'s KAT vectors prove our crypto matches the C
//! crypto byte-for-byte. None of that proves the WHOLE stack —
//! ID/SPTPS-meta/ACK/ADD_EDGE/REQ_KEY/ANS_KEY/per-tunnel-SPTPS/
//! UDP-packet-format — speaks the C's dialect end to end. This does.
//!
//! ## Gate
//!
//! `TINC_C_TINCD` must point at a C `tincd` binary. Unset → tests
//! print `SKIP:` to stderr and pass as no-ops. Same env-gate pattern
//! as `tinc-tools/tests/self_roundtrip.rs::TINC_C_SPTPS_TEST`. CI
//! sets it; local dev opts in.
//!
//! ```sh
//! nix build .#tincd-c
//! TINC_C_TINCD=$PWD/result/sbin/tincd cargo nextest run -p tincd crossimpl
//! ```
//!
//! Why a separate file from `netns.rs`: nextest's per-file isolation
//! means this doesn't fight `netns.rs` for ports / TUN device names /
//! `/run/netns/bobside`. Both can run in the same `cargo nextest run`.
//!
//! ## Mechanics
//!
//! Same bwrap-reexec trick as `netns.rs` (read that module doc first).
//! Differences:
//!
//! - One daemon is the C binary instead of `CARGO_BIN_EXE_tincd`.
//!   The C takes `-D` (no-detach), `-d5` (debug level), `-c`,
//!   `--pidfile`. NO `--socket` flag — `names.c:152-160` derives the
//!   socket path from the pidfile by `s/\.pid$/.socket/`. Our `Node`
//!   already names them `NAME.pid` / `NAME.socket`, so the derived
//!   path matches.
//!
//! - The C reads the SAME config format (`tinc.conf`, `hosts/NAME`,
//!   `ed25519_key.priv`). The PEM blob is the SAME 96 bytes
//!   (`ecdsa.c:26`: `uint8_t private[64]; uint8_t public[32];` —
//!   our `SigningKey::to_blob()` is exactly that). `Node::write_
//!   config` is verbatim from `netns.rs`.
//!
//! - The C's control protocol is the SAME (it's where ours was
//!   transcribed FROM). `Ctl::connect` against the C's socket works:
//!   same `0 ^COOKIE 0` greeting, same `18 SUBTYPE` dump request,
//!   same `18 SUBTYPE` terminator. The dump-node ROW format is also
//!   identical (`node.c:dump_nodes` — we wire-match it).
//!
//! ## What `rust_dials_c` proves
//!
//! Alice (Rust) initiates. Bob (C) listens. Ping works.
//!
//! 1. **ID exchange**: our greeting line, their `id_h` parses it.
//!    Their greeting, our `id_h` parses it. The `^` for control vs
//!    `0` for protocol-17.x — all matches.
//! 2. **Meta-SPTPS handshake**: the NUL byte in the TCP label
//!    (`conn.c::SPTPS_LABEL` is `b"tinc TCP key exchange\0"` — the
//!    C's `sptps_start` includes the NUL because it's `sizeof`, not
//!    `strlen`). Our `tinc-sptps` byte-identical-wire-output test
//!    pinned this in isolation; THIS pins it through the full conn
//!    setup with all the framing.
//! 3. **ACK + graph**: ACK fields parse on both sides. `ADD_EDGE`/
//!    `ADD_SUBNET` flood. Our `dump nodes` shows bob reachable
//!    (status bit 4).
//! 4. **REQ_KEY/ANS_KEY**: the SPTPS-handshake-via-ANS_KEY path.
//!    THE PARSER FIX: `net_packet.c:996` sends literal `"-1 -1 -1"`
//!    for cipher/digest/maclen. Our `Tok::lu` was strict-u64 and
//!    rejected `-1`. Now it's glibc-strtoul-compatible (negate as
//!    unsigned → `u64::MAX`). Without that fix, this test would die
//!    right after the per-tunnel SPTPS record exchange.
//! 5. **Per-tunnel SPTPS**: the data-channel handshake. Label is
//!    `b"tinc UDP key exchange\0"` (also with the NUL). Status bit 1
//!    (validkey) flips on both.
//! 6. **UDP packet format**: the id6-prefix, the SPTPS-record-in-
//!    UDP framing. Ping echo goes alice→bob, reply comes back.
//!    Kernel computes/verifies all checksums; if our wire bytes
//!    were off by one anywhere, ping would silently time out.
//!
//! `c_dials_rust` is the inverse: tests our LISTENER paths.

#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ═════════════════════════ the env gate ══════════════════════════════════
// Separate from the bwrap re-exec gate. The env var has to survive
// the re-exec (bwrap passes the parent env through `--bind / /`
// doesn't filter it; we don't `.env_clear()`). Checked AFTER
// `enter_netns` so the SKIP message comes from the OUTER process
// only (the inner one already knows it's set — outer wouldn't have
// re-execed otherwise).

fn c_tincd_bin() -> Option<PathBuf> {
    std::env::var_os("TINC_C_TINCD").map(PathBuf::from)
}

// ═════════════════════════ bwrap re-exec ═════════════════════════════════
// Same as netns.rs::enter_netns. Can't factor into tests/common/ —
// the `--exact <test_name>` re-exec means the test name has to be
// known statically, and the SKIP messages want the test name too.
// Two ~100-line copies are cheaper than the plumbing. The device
// names and netns name are DIFFERENT (`tincX0/tincX1`, `xbobside`)
// so the two test files don't collide if nextest runs them in
// parallel (they each get their own bwrap → own netns → own /run,
// so it'd be fine anyway, but defense in depth).

/// Device type for the test's two TUN/TAP interfaces. Each bwrap
/// re-exec is its own netns, so device-name collisions across
/// parallel tests don't happen — but we still namespace by suffix
/// to make `ip link` output readable in debug.
#[derive(Clone, Copy)]
enum DevMode {
    /// `mode tun`, devices `tincX0/tincX1`, netns `xbobside`.
    Tun,
    /// `mode tap`, devices `tincS0/tincS1`, netns `xbobside_s`.
    Tap,
}

impl DevMode {
    fn dev0(self) -> &'static str {
        match self {
            DevMode::Tun => "tincX0",
            DevMode::Tap => "tincS0",
        }
    }
    fn dev1(self) -> &'static str {
        match self {
            DevMode::Tun => "tincX1",
            DevMode::Tap => "tincS1",
        }
    }
    fn ns(self) -> &'static str {
        match self {
            DevMode::Tun => "xbobside",
            DevMode::Tap => "xbobside_s",
        }
    }
    fn tuntap_mode(self) -> &'static str {
        match self {
            DevMode::Tun => "tun",
            DevMode::Tap => "tap",
        }
    }
}

fn enter_netns(test_name: &str) -> Option<NetNs> {
    enter_netns_with(test_name, DevMode::Tun)
}

fn enter_netns_with(test_name: &str, mode: DevMode) -> Option<NetNs> {
    if std::env::var_os("BWRAP_INNER").is_some() {
        return Some(NetNs::setup(mode));
    }

    // Gate the env var BEFORE the bwrap probe. No point probing
    // bwrap if we're going to skip anyway. The env-skip is the
    // common path (most `cargo nextest run` invocations don't set
    // TINC_C_TINCD); the bwrap-skip is the unusual one.
    if c_tincd_bin().is_none() {
        eprintln!(
            "SKIP {test_name}: TINC_C_TINCD not set. \
             `nix develop` sets it automatically; \
             outside nix: `nix build .#tincd-c` then \
             `TINC_C_TINCD=$PWD/result/sbin/tincd`."
        );
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
    if !std::path::Path::new("/dev/net/tun").exists() {
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
        .args(["--exact", test_name, "--nocapture", "--test-threads=1"])
        .env("BWRAP_INNER", "1")
        .status()
        .expect("spawn bwrap");
    assert!(status.success(), "inner test failed: {status:?}");
    None
}

struct NetNs {
    sleeper: Child,
    mode: DevMode,
}

impl NetNs {
    fn setup(mode: DevMode) -> Self {
        run_ip(&["link", "set", "lo", "up"]);
        // Different device names from netns.rs — see module doc.
        run_ip(&[
            "tuntap",
            "add",
            "mode",
            mode.tuntap_mode(),
            "name",
            mode.dev0(),
        ]);
        run_ip(&[
            "tuntap",
            "add",
            "mode",
            mode.tuntap_mode(),
            "name",
            mode.dev1(),
        ]);
        // TAP: DO NOT bring up here. TAP devices emit spontaneous
        // traffic (IPv6 router solicits, mDNS) the moment they go
        // up, even with no address assigned. If both sides' kernels
        // emit simultaneously while the per-tunnel SPTPS handshake
        // is in flight, both daemons fire REQ_KEY at the same time
        // and the handshake restarts in a loop. TUN doesn't have
        // this problem (no L2 → no spontaneous frames). The TAP
        // tests bring devices up in `place_devices()` AFTER the
        // meta handshake completes; the directional kick-ping then
        // ensures one side initiates REQ_KEY first.
        //
        // TUN: harmless either way; bring up early so the existing
        // carrier wait works unchanged.
        if matches!(mode, DevMode::Tun) {
            run_ip(&["link", "set", mode.dev0(), "up"]);
            run_ip(&["link", "set", mode.dev1(), "up"]);
        }

        std::fs::create_dir_all("/run/netns").expect("mkdir /run/netns");
        let sleeper = Command::new("unshare")
            .args(["-n", "sleep", "3600"])
            .spawn()
            .expect("spawn unshare sleeper");
        std::thread::sleep(Duration::from_millis(100));
        let ns_path = format!("/run/netns/{}", mode.ns());
        std::fs::write(&ns_path, b"").expect("touch nsfd target");
        let status = Command::new("mount")
            .args(["--bind"])
            .arg(format!("/proc/{}/ns/net", sleeper.id()))
            .arg(&ns_path)
            .status()
            .expect("spawn mount");
        assert!(status.success(), "mount --bind nsfd: {status:?}");
        run_ip(&["netns", "exec", mode.ns(), "ip", "link", "set", "lo", "up"]);

        Self { sleeper, mode }
    }

    fn place_devices(&self) {
        let m = self.mode;
        run_ip(&["link", "set", m.dev1(), "netns", m.ns()]);
        run_ip(&["addr", "add", "10.43.0.1/24", "dev", m.dev0()]);
        run_ip(&["link", "set", m.dev0(), "up"]);
        run_ip(&[
            "netns",
            "exec",
            m.ns(),
            "ip",
            "addr",
            "add",
            "10.43.0.2/24",
            "dev",
            m.dev1(),
        ]);
        run_ip(&["netns", "exec", m.ns(), "ip", "link", "set", m.dev1(), "up"]);
    }
}

impl Drop for NetNs {
    fn drop(&mut self) {
        let _ = self.sleeper.kill();
        let _ = self.sleeper.wait();
    }
}

fn run_ip(args: &[&str]) {
    let out = Command::new("ip").args(args).output().expect("spawn ip");
    assert!(
        out.status.success(),
        "ip {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn wait_for_carrier(dev: &str, timeout: Duration) -> bool {
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

// ═══════════════════════════ daemon plumbing ═══════════════════════════════

struct TmpGuard(PathBuf);
impl TmpGuard {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("tincd-xi-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}
impl Drop for TmpGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn rust_tincd_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tincd"))
}

fn alloc_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Which daemon implementation backs this node. Everything else
/// (config layout, key format, control protocol) is identical.
#[derive(Clone, Copy)]
enum Impl {
    Rust,
    C,
}

struct Node {
    name: &'static str,
    seed: [u8; 32],
    confbase: PathBuf,
    pidfile: PathBuf,
    /// For `Impl::C`, this is DERIVED, not passed: `names.c:157`
    /// does `s/\.pid$/.socket/` on the pidfile path. We name them
    /// `NAME.pid` / `NAME.socket` so the derivation lands here.
    socket: PathBuf,
    port: u16,
    iface: &'static str,
    subnet: &'static str,
    which: Impl,
}

impl Node {
    fn new(
        tmp: &std::path::Path,
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
        use tinc_crypto::sign::SigningKey;
        *SigningKey::from_seed(&self.seed).public_key()
    }

    /// Same on-disk layout for both impls. The C `read_ecdsa_
    /// private_key` (`keys.c:108`) defaults to `CONFBASE/
    /// ed25519_key.priv` and reads a 96-byte PEM body — exactly
    /// `SigningKey::to_blob()`. The C's `linux/device.c` honors
    /// `Interface = ...` for TUNSETIFF the same way ours does.
    fn write_config(&self, other: &Node, connect_to: bool) {
        std::fs::create_dir_all(self.confbase.join("hosts")).unwrap();

        let mut tinc_conf = format!(
            "Name = {}\nDeviceType = tun\nInterface = {}\nAddressFamily = ipv4\n",
            self.name, self.iface
        );
        if connect_to {
            tinc_conf.push_str(&format!("ConnectTo = {}\n", other.name));
        }
        tinc_conf.push_str("PingTimeout = 1\n");
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

        self.write_privkey();
    }

    /// Switch-mode variant of `write_config`. Differences from the
    /// router-mode form above:
    ///
    /// - `Mode = switch` in `tinc.conf` (→ `RoutingMode::Switch`).
    /// - `DeviceType = tap` (full eth frames; the C
    ///   `linux/device.c:76-91` would derive this from
    ///   `Mode = switch` when DeviceType is unset, but our Rust
    ///   currently requires it explicit).
    /// - NO `Subnet =` line in `hosts/SELF`. Switch mode learns MAC
    ///   subnets dynamically (`route.c:524-556 learn_mac`); pre-
    ///   declared MAC subnets would never expire (`:553`) and we
    ///   want to test the learning path.
    fn write_config_switch(&self, other: &Node, connect_to: bool) {
        std::fs::create_dir_all(self.confbase.join("hosts")).unwrap();

        let mut tinc_conf = format!(
            "Name = {}\nDeviceType = tap\nMode = switch\nInterface = {}\nAddressFamily = ipv4\n",
            self.name, self.iface
        );
        if connect_to {
            tinc_conf.push_str(&format!("ConnectTo = {}\n", other.name));
        }
        tinc_conf.push_str("PingTimeout = 1\n");
        std::fs::write(self.confbase.join("tinc.conf"), tinc_conf).unwrap();

        // hosts/SELF: just Port. No Subnet — learned dynamically.
        std::fs::write(
            self.confbase.join("hosts").join(self.name),
            format!("Port = {}\n", self.port),
        )
        .unwrap();

        let other_pub = tinc_crypto::b64::encode(&other.pubkey());
        let mut other_cfg = format!("Ed25519PublicKey = {other_pub}\n");
        if connect_to {
            other_cfg.push_str(&format!("Address = 127.0.0.1 {}\n", other.port));
        }
        std::fs::write(self.confbase.join("hosts").join(other.name), other_cfg).unwrap();

        self.write_privkey();
    }

    fn write_privkey(&self) {
        use std::os::unix::fs::OpenOptionsExt;
        use tinc_crypto::sign::SigningKey;
        let sk = SigningKey::from_seed(&self.seed);
        let f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(self.confbase.join("ed25519_key.priv"))
            .unwrap();
        let mut w = std::io::BufWriter::new(f);
        tinc_conf::write_pem(&mut w, "ED25519 PRIVATE KEY", &sk.to_blob()).unwrap();
    }

    fn spawn(&self) -> ChildWithLog {
        let child = match self.which {
            Impl::Rust => Command::new(rust_tincd_bin())
                .arg("-c")
                .arg(&self.confbase)
                .arg("--pidfile")
                .arg(&self.pidfile)
                .arg("--socket")
                .arg(&self.socket)
                .env("RUST_LOG", "tincd=debug")
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn rust tincd"),
            // C: `-D` no-detach (foreground, stderr logging); `-d5`
            // debug level (max useful — d6+ is just hex dumps).
            // No `--socket`: derived from pidfile, see Node::socket
            // doc. The C's `tincd.c:572` opens LOGMODE_STDERR when
            // not using syslog/logfile, which `-D` implies.
            Impl::C => Command::new(c_tincd_bin().expect("gate checked"))
                .arg("-D")
                .arg("-d5")
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

struct Ctl {
    r: BufReader<UnixStream>,
    w: UnixStream,
}

impl Ctl {
    /// Same protocol both impls. The C's `control.c::control_h`
    /// is what ours was transcribed from. `0 ^COOKIE 0` greeting,
    /// two-line ack (ID echo + ACK).
    fn connect(node: &Node) -> Self {
        let cookie = std::fs::read_to_string(&node.pidfile)
            .unwrap()
            .split_whitespace()
            .nth(1)
            .expect("pidfile has cookie")
            .to_owned();
        let stream = UnixStream::connect(&node.socket).expect("ctl connect");
        let r = BufReader::new(stream.try_clone().unwrap());
        let mut ctl = Self { r, w: stream };
        writeln!(ctl.w, "0 ^{cookie} 0").unwrap();
        let mut line = String::new();
        ctl.r.read_line(&mut line).unwrap();
        line.clear();
        ctl.r.read_line(&mut line).unwrap();
        ctl
    }

    fn dump(&mut self, subtype: u8) -> Vec<String> {
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

fn wait_for_file(path: &std::path::Path) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}

fn poll_until<T>(timeout: Duration, mut f: impl FnMut() -> Option<T>) -> T {
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

/// Spawn child with `Stdio::piped()` stderr, then immediately hand the
/// pipe to a background drain thread. Why: the C tincd at `-d5` floods
/// stderr; `PingTimeout = 1` makes it retry the meta handshake every
/// second, each retry logging the full SPTPS state dump. The 64 KiB
/// pipe buffer fills in ~2s, the next `fprintf(stderr, ...)` blocks,
/// and the C event loop freezes mid-handshake. Symptom: `Ctl::dump`
/// blocks forever on `read_line` because the daemon can't reach the
/// control-socket handler. (Found the very first time these tests
/// ran for real — they had only ever been SKIPs.)
struct ChildWithLog {
    child: Child,
    log: Arc<Mutex<Vec<u8>>>,
    drain: Option<std::thread::JoinHandle<()>>,
}

impl ChildWithLog {
    fn spawn(mut child: Child) -> Self {
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

    fn kill_and_log(mut self) -> String {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(h) = self.drain.take() {
            let _ = h.join();
        }
        String::from_utf8_lossy(&self.log.lock().unwrap()).into_owned()
    }
}

/// Dump-node row → status hex. The C `node.c:dump_nodes` and our
/// `Daemon::dump_nodes` emit the SAME row format (we wire-match it).
/// Body token 10 = status bitfield, hex.
fn node_status(rows: &[String], name: &str) -> Option<u32> {
    rows.iter().find_map(|r| {
        let body = r.strip_prefix("18 3 ")?;
        let toks: Vec<&str> = body.split_whitespace().collect();
        if toks.first() != Some(&name) {
            return None;
        }
        u32::from_str_radix(toks.get(10)?, 16).ok()
    })
}

// ═══════════════════════════════ the tests ═════════════════════════════════

/// Shared body. `alice_impl` dials `bob_impl`. Asserts: handshake,
/// validkey, ping. The two `#[test]` fns below just permute who's
/// who. Factored out because the assertions are identical and 200
/// lines duplicated would rot.
fn run_crossimpl(tag: &str, alice_impl: Impl, bob_impl: Impl, netns: NetNs) {
    let tmp = TmpGuard::new(tag);
    let alice = Node::new(
        tmp.path(),
        "alice",
        0xAA,
        "tincX0",
        "10.43.0.1/32",
        alice_impl,
    );
    let bob = Node::new(tmp.path(), "bob", 0xBB, "tincX1", "10.43.0.2/32", bob_impl);

    bob.write_config(&alice, false);
    alice.write_config(&bob, true);

    // ─── spawn ──────────────────────────────────────────────────
    // Bob (listener) first. The C tincd writes pidfile + socket
    // during `setup_network` before entering the event loop, same
    // as ours; `wait_for_file(socket)` is the readiness signal for
    // both impls.
    let bob_child = bob.spawn();
    if !wait_for_file(&bob.socket) {
        panic!("bob setup failed; stderr:\n{}", bob_child.kill_and_log());
    }

    let alice_child = alice.spawn();
    if !wait_for_file(&alice.socket) {
        let bs = bob_child.kill_and_log();
        panic!(
            "alice setup failed; stderr:\n{}\n=== bob ===\n{bs}",
            alice_child.kill_and_log()
        );
    }

    // ─── carrier (TUNSETIFF fired on both) ──────────────────────
    // The C's `linux/device.c::setup_device` does the same
    // TUNSETIFF as our `LinuxTun::open`. Carrier flips identically.
    if !wait_for_carrier("tincX0", Duration::from_secs(2)) {
        let asd = alice_child.kill_and_log();
        let bs = bob_child.kill_and_log();
        panic!("alice TUNSETIFF;\n=== alice ===\n{asd}\n=== bob ===\n{bs}");
    }
    assert!(
        wait_for_carrier("tincX1", Duration::from_secs(2)),
        "bob TUNSETIFF"
    );

    netns.place_devices();

    // ─── meta handshake ─────────────────────────────────────────
    // PROVES: ID exchange, meta-SPTPS (the NUL!), ACK fields,
    // ADD_EDGE/ADD_SUBNET parse on both sides, graph() runs.
    // Status bit 4 = reachable.
    let mut alice_ctl = Ctl::connect(&alice);
    let mut bob_ctl = Ctl::connect(&bob);

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
        let asd = alice_child.kill_and_log();
        let bs = bob_child.kill_and_log();
        panic!("meta handshake timed out;\n=== alice ===\n{asd}\n=== bob ===\n{bs}");
    }

    // ─── kick the per-tunnel handshake ──────────────────────────
    let _ = Command::new("ping")
        .args(["-c", "1", "-W", "1", "10.43.0.2"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    // ─── validkey ───────────────────────────────────────────────
    // PROVES: REQ_KEY ext (SPTPS init), ANS_KEY parse (THE -1 fix),
    // per-tunnel SPTPS handshake. Status bit 1 = validkey, bit 7 =
    // udp_confirmed (`node.h:41`). The C falls back to TCP-tunnelled
    // `PACKET 17 <len>` for VPN traffic until udp_confirmed flips
    // (`net_packet.c::send_sptps_data`); we DROP those (`STUB(chunk-
    // 12-tcp-fallback)`). Polling for validkey alone races: bob's
    // ICMP echo-reply goes via TCP, alice drops it. Wait for both
    // sides to confirm UDP — the probe round-trip on loopback is
    // ~1ms once validkey is set.
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
        let asd = alice_child.kill_and_log();
        let bs = bob_child.kill_and_log();
        panic!(
            "validkey/udp_confirmed timed out — ANS_KEY, per-tunnel SPTPS, or UDP probe path;\n\
             === alice ===\n{asd}\n=== bob ===\n{bs}"
        );
    }

    // ─── THE PING ───────────────────────────────────────────────
    // PROVES: UDP packet format (id6 prefix), SPTPS record-in-UDP
    // framing, decrypt, route, TUN write, kernel ICMP reply, the
    // whole backflow. Kernel-computed checksums on both ends; off-
    // by-one anywhere → silent timeout, not a malformed-packet log.
    let ping = Command::new("ping")
        .args(["-c", "3", "-W", "2", "10.43.0.2"])
        .output()
        .expect("spawn ping");

    if !ping.status.success() {
        let asd = alice_child.kill_and_log();
        let bs = bob_child.kill_and_log();
        panic!(
            "cross-impl ping failed: {:?}\nstdout: {}\nstderr: {}\n\
             === alice ===\n{asd}\n=== bob ===\n{bs}",
            ping.status,
            String::from_utf8_lossy(&ping.stdout),
            String::from_utf8_lossy(&ping.stderr),
        );
    }

    eprintln!("{}", String::from_utf8_lossy(&ping.stdout));

    drop(alice_ctl);
    drop(bob_ctl);
    let _ = alice_child.kill_and_log();
    let _ = bob_child.kill_and_log();
    drop(netns);
}

/// Rust dials, C listens. Tests our INITIATOR paths against the
/// reference. See module doc for the proof breakdown.
#[test]
fn rust_dials_c() {
    let Some(netns) = enter_netns("rust_dials_c") else {
        return;
    };
    run_crossimpl("rdc", Impl::Rust, Impl::C, netns);
}

/// C dials, Rust listens. Tests our RESPONDER paths. The C's
/// `do_outgoing_connection` (`net_socket.c`) initiates; our `id_h`
/// gets the responder-side SPTPS role; our `req_key_h` parses the
/// C's REQ_KEY ext-SPTPS init; our `ans_key_h` parses the C's
/// `-1 -1 -1` line — THE direct exercise of the `Tok::lu` fix.
#[test]
fn c_dials_rust() {
    let Some(netns) = enter_netns("c_dials_rust") else {
        return;
    };
    run_crossimpl("cdr", Impl::C, Impl::Rust, netns);
}

// ────────────────────────────────────────────────────────────────────
// TODO(chunk-12-tcp-fallback): SPTPS_PACKET 21 cross-impl wire test
//
// Can't be done in 2-node form. The C `net_packet.c:725` `if(n->
// connection && origpkt->len > n->minmtu) send_tcppacket()` short-
// circuits to `PACKET 17` for direct neighbors before reaching
// `sptps_send_record` → `send_sptps_data` → `:975` binary path.
// With `TCPOnly = yes`, `try_tx_sptps:1477` also returns early so
// `minmtu` stays 0 — every packet > 0, always PACKET 17.
//
// `SPTPS_PACKET 21` only fires when `n->connection == NULL` (no
// direct meta-conn), i.e. 3-node alice → mid → bob with bob (C)
// routing to alice through mid. Then bob's `:725` is false, bob's
// `sptps_send_record` runs, the Wire callback hits `send_sptps_data`,
// `:974` go_tcp (minmtu=0 or tcponly), `:975` binary path. Mid (Rust)
// receives `21 LEN` + raw blob — the `feed()` do-while.
//
// The architectural fix (peek for "21 " inside `feed()`, eat raw blob
// before next `sptps.receive()`) is unit-tested in `conn.rs::
// feed_sptpslen_then_record` — the same chunk has [SPTPS-framed
// "21 11\n" | 11 raw bytes | SPTPS-framed PING], asserts events =
// [Blob(11), Record(PING)] without Dead. The wire-compat proof needs
// the 3-node scaffold; same shape as `two_daemons.rs::three_daemon_
// relay` but with C bob.

// ═══════════════════════ RMODE_SWITCH cross-impl ════════════════════════
// `route_mac.rs` daemon wire-up. The C side
// already works: `route.c:1159 case RMODE_SWITCH: route_mac(...)`
// is the reference. This is the wire-compat proof.
//
// What it proves over `rust_dials_c`:
//
// - **MAC learning gossip**: alice's kernel ARPs for 10.43.0.2 over
//   the TAP. Our `route_mac` sees `from_myself=true`, returns
//   `LearnAction::New(alice's-tap-mac)`. Daemon sends `ADD_SUBNET`
//   with `Subnet::Mac{addr: ..., weight: 10}` (`route.c:538`). Bob
//   (C) parses it (`subnet_add.c:add_subnet_h`), routes the ARP
//   reply back to alice by MAC. Without correct `Subnet::Mac` wire
//   format → ARP times out, no ping.
// - **`Broadcast` dispatch**: the FIRST ARP request has dst-MAC
//   ff:ff:ff:ff:ff:ff. `route_mac` returns `RouteResult::Broadcast`.
//   Daemon `broadcast_packet`s it to bob.
// - **TAP device path**: `tinc-device` opened `IFF_TAP`. Full eth
//   header preserved. Switch mode goes straight to `route_mac`
//   (`route.c:1159`); no ARP/NDP intercept.
//
// Both directions: the LEARNING is asymmetric. The dialer's first
// packet (ARP request) triggers the responder's broadcast; the
// responder's reply triggers the dialer's first MAC learn. Either
// side's bug → one-way silence.

fn run_crossimpl_switch(tag: &str, alice_impl: Impl, bob_impl: Impl, netns: NetNs) {
    let tmp = TmpGuard::new(tag);
    // No subnet — switch mode learns. iface = tincS0/tincS1.
    let alice = Node::new(tmp.path(), "alice", 0xAA, "tincS0", "", alice_impl);
    let bob = Node::new(tmp.path(), "bob", 0xBB, "tincS1", "", bob_impl);

    bob.write_config_switch(&alice, false);
    alice.write_config_switch(&bob, true);

    let bob_child = bob.spawn();
    if !wait_for_file(&bob.socket) {
        panic!("bob setup failed; stderr:\n{}", bob_child.kill_and_log());
    }
    let alice_child = alice.spawn();
    if !wait_for_file(&alice.socket) {
        let bs = bob_child.kill_and_log();
        panic!(
            "alice setup failed; stderr:\n{}\n=== bob ===\n{bs}",
            alice_child.kill_and_log()
        );
    }

    // ─── meta handshake (mode-agnostic) ──────────────────────────
    // BEFORE place_devices: TAP devices are still down (see
    // NetNs::setup), so neither kernel is emitting spontaneous
    // traffic. The meta handshake (TCP, ID/SPTPS/ACK/ADD_EDGE)
    // completes in peace.
    let mut alice_ctl = Ctl::connect(&alice);
    let mut bob_ctl = Ctl::connect(&bob);

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
        let asd = alice_child.kill_and_log();
        let bs = bob_child.kill_and_log();
        panic!("meta handshake timed out;\n=== alice ===\n{asd}\n=== bob ===\n{bs}");
    }

    // NOW bring devices up. TUNSETIFF already fired (daemon attached
    // at startup); carrier should flip immediately. place_devices
    // also moves tincS1 into bob's netns and assigns addresses.
    netns.place_devices();
    if !wait_for_carrier("tincS0", Duration::from_secs(2)) {
        let asd = alice_child.kill_and_log();
        let bs = bob_child.kill_and_log();
        panic!("alice carrier;\n=== alice ===\n{asd}\n=== bob ===\n{bs}");
    }

    // ─── kick the per-tunnel handshake ──────────────────────────
    // alice's kernel ARPs for 10.43.0.2 → ARP frame to tincS0 →
    // route_packet → route_mac → Broadcast → try_tx → REQ_KEY.
    // Only alice originates here (bob's TAP just came up in its
    // netns and may emit a router solicit, but the directional
    // ping ensures alice's REQ_KEY wins the race more often than
    // not). The ping itself fails (no key yet); that's fine.
    let _ = Command::new("ping")
        .args(["-c", "1", "-W", "1", "10.43.0.2"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    // ─── validkey + udp_confirmed (mode-agnostic) ───────────────
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
        let asd = alice_child.kill_and_log();
        let bs = bob_child.kill_and_log();
        panic!("validkey/udp_confirmed timed out;\n=== alice ===\n{asd}\n=== bob ===\n{bs}");
    }

    // ─── THE PING ───────────────────────────────────────────────
    // Kernel ARPs (TAP) → route_mac sees ff:ff:ff:ff:ff:ff →
    // Broadcast → bob's kernel replies → ADD_SUBNET gossip →
    // ICMP unicast routes by MAC. Any Subnet::Mac wire mismatch →
    // ARP times out → ping fails.
    let ping = Command::new("ping")
        .args(["-c", "3", "-W", "2", "10.43.0.2"])
        .output()
        .expect("spawn ping");

    if !ping.status.success() {
        // Dump subnets (subtype 5) from alice for diagnosis: empty →
        // learn_mac never fired; alice's MAC only → broadcast
        // worked one-way.
        let alice_subs = alice_ctl.dump(5);
        let asd = alice_child.kill_and_log();
        let bs = bob_child.kill_and_log();
        panic!(
            "switch-mode cross-impl ping failed: {:?}\nstdout: {}\nstderr: {}\n\
             alice subnets (dump 4): {alice_subs:?}\n\
             === alice ===\n{asd}\n=== bob ===\n{bs}",
            ping.status,
            String::from_utf8_lossy(&ping.stdout),
            String::from_utf8_lossy(&ping.stderr),
        );
    }

    eprintln!("{}", String::from_utf8_lossy(&ping.stdout));

    // ─── Prove learn_mac fired ──────────────────────────────────
    // Ctl dump 5 = subnets (`REQ_DUMP_SUBNETS`, `control.c:137`).
    // MAC subnets format with single colons (xx:xx:xx:xx:xx:xx);
    // IPv6 has double-colons. Filter for `:` without `::`. After a
    // successful ping there should be at least one MAC subnet
    // (alice's TAP MAC, learned when the kernel sent the first
    // outbound frame).
    let alice_subs = alice_ctl.dump(5);
    let mac_subs: Vec<&String> = alice_subs
        .iter()
        .filter(|s| s.contains(':') && !s.contains("::"))
        .collect();
    assert!(
        !mac_subs.is_empty(),
        "No MAC subnets after ping (learn_mac didn't fire?): {alice_subs:?}"
    );

    drop(alice_ctl);
    drop(bob_ctl);
    let _ = alice_child.kill_and_log();
    let _ = bob_child.kill_and_log();
    drop(netns);
}

/// Rust dials, C listens. Switch mode. Tests our INITIATOR-side
/// MAC learning + ADD_SUBNET wire format + broadcast against the
/// reference.
#[test]
fn rust_dials_c_switch() {
    let Some(netns) = enter_netns_with("rust_dials_c_switch", DevMode::Tap) else {
        return;
    };
    run_crossimpl_switch("rds", Impl::Rust, Impl::C, netns);
}

/// C dials, Rust listens. Switch mode. Tests our RESPONDER-side
/// route_mac broadcast (the C's first ARP arrives over the wire;
/// our `route_packet` with `from = Some(peer)` must echo to TAP
/// AND forward to the MST — which is just back to C in 2-node).
#[test]
fn c_dials_rust_switch() {
    let Some(netns) = enter_netns_with("c_dials_rust_switch", DevMode::Tap) else {
        return;
    };
    run_crossimpl_switch("cds", Impl::C, Impl::Rust, netns);
}
