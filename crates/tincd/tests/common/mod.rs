//! Shared fixtures for the tincd integration tests. Each `tests/*.rs`
//! is its own crate and includes this via `mod common;`.

#![allow(dead_code)] // not every test binary uses every helper

use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub mod bench;
pub mod node;

pub use node::Node;

/// `tmp!("tag")`: a `TmpGuard` named after the calling module, short
/// enough for macOS' 104-byte `sun_path`.
#[macro_export]
macro_rules! tmp {
    ($tag:expr) => {
        $crate::common::TmpGuard::new(module_path!().rsplit("::").next().unwrap(), $tag)
    };
}

/// Per-test temp directory, removed on drop. PID and thread id in the
/// name keep parallel tests (threads and nextest processes) apart.
pub struct TmpGuard(PathBuf);

impl TmpGuard {
    pub fn new(prefix: &str, tag: &str) -> Self {
        // macOS' default TMPDIR is ~50 chars, too long for sun_path
        // once a socket name is appended.
        #[cfg(target_os = "macos")]
        let base = PathBuf::from("/tmp");
        #[cfg(not(target_os = "macos"))]
        let base = std::env::temp_dir();
        let dir = base.join(format!(
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

    /// `(vpn/, tinc.pid, tinc.socket)` for single-daemon tests.
    pub fn std_paths(&self) -> (PathBuf, PathBuf, PathBuf) {
        (
            self.0.join("vpn"),
            self.0.join("tinc.pid"),
            self.0.join("tinc.socket"),
        )
    }
}

impl Drop for TmpGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn tincd_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tincd"))
}

/// `tincd -D`. Without `-D` the daemon double-forks away from the
/// `Child` handle and can be neither observed nor killed.
pub fn tincd_cmd() -> Command {
    let mut cmd = Command::new(tincd_bin());
    cmd.arg("-D");
    cmd
}

pub fn tincd_at(
    confbase: impl AsRef<std::ffi::OsStr>,
    pidfile: impl AsRef<std::ffi::OsStr>,
    socket: impl AsRef<std::ffi::OsStr>,
) -> Command {
    let mut cmd = tincd_cmd();
    cmd.arg("-c")
        .arg(confbase)
        .arg("--pidfile")
        .arg(pidfile)
        .arg("--socket")
        .arg(socket);
    cmd
}

/// Transitional: a port free on both TCP and UDP right now. Racy by
/// construction (freed before the daemon binds it); new tests should
/// let the daemon bind `Port = 0` and use [`Node::port`] /
/// [`read_tcp_addr`] instead. The pid-seeded counter over
/// `[12000, 28000)` just makes collisions between parallel test
/// processes unlikely.
pub fn alloc_port() -> u16 {
    use std::sync::atomic::{AtomicU32, Ordering};

    const BASE: u32 = 12000;
    const SPAN: u32 = 16000;
    static NEXT: AtomicU32 = AtomicU32::new(u32::MAX);

    if NEXT.load(Ordering::Relaxed) == u32::MAX {
        let seed = std::process::id().wrapping_mul(2_654_435_761) % SPAN;
        let _ = NEXT.compare_exchange(u32::MAX, seed, Ordering::Relaxed, Ordering::Relaxed);
    }
    for _ in 0..512 {
        #[expect(clippy::cast_possible_truncation)] // BASE + SPAN < u16::MAX
        let port = (BASE + NEXT.fetch_add(1, Ordering::Relaxed) % SPAN) as u16;
        if let (Ok(_tcp), Ok(_udp)) = (
            std::net::TcpListener::bind(("127.0.0.1", port)),
            std::net::UdpSocket::bind(("0.0.0.0", port)),
        ) {
            return port;
        }
    }
    panic!("alloc_port: no port free on both TCP and UDP after 512 tries");
}

/// A loopback TCP port that answers ECONNREFUSED for as long as the
/// returned socket lives: bound but never `listen()`ed, so no other
/// test can grab it either.
pub fn refusing_port() -> (socket2::Socket, u16) {
    let sock = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
    sock.bind(
        &"127.0.0.1:0"
            .parse::<std::net::SocketAddr>()
            .unwrap()
            .into(),
    )
    .unwrap();
    let port = sock.local_addr().unwrap().as_socket().unwrap().port();
    (sock, port)
}

/// Kill, reap, return stderr. Only for children spawned with
/// `Stdio::piped()` and *without* a `ChildWithLog` around them.
pub fn drain_stderr(mut child: Child) -> String {
    let _ = child.kill();
    let out = child.wait_with_output().unwrap();
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// The daemon creates the control socket before writing the pidfile,
/// so poll until the pidfile is complete rather than trusting the
/// socket as a readiness signal for it.
fn read_pidfile(pidfile: &Path) -> String {
    poll_until(Duration::from_secs(5), || {
        std::fs::read_to_string(pidfile)
            .ok()
            .filter(|content| content.contains('\n'))
    })
}

/// Pidfile is `PID COOKIE HOST port PORT\n`.
pub fn read_cookie(pidfile: &Path) -> String {
    read_pidfile(pidfile)
        .split_whitespace()
        .nth(1)
        .expect("pidfile has cookie")
        .to_owned()
}

/// TCP listen address from the pidfile. IPv4 only (tests set
/// `AddressFamily = ipv4`); the daemon writes v6 hosts unbracketed.
pub fn read_tcp_addr(pidfile: &Path) -> std::net::SocketAddr {
    let content = read_pidfile(pidfile);
    let host_and_port = content.splitn(3, ' ').nth(2).expect("pidfile has address");
    let (host, port) = host_and_port
        .trim_end()
        .split_once(" port ")
        .expect("`HOST port PORT`");
    format!("{host}:{port}")
        .parse()
        .expect("IPv4 listen address")
}

/// The control socket appearing is the daemon's readiness signal.
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

/// Poll `f` every 20ms until it yields `Some`; panic on timeout so the
/// failure shows up as a test failure rather than a nextest SIGKILL.
pub fn poll_until<T>(timeout: Duration, mut f: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(value) = f() {
            return value;
        }
        assert!(
            Instant::now() < deadline,
            "poll timed out after {timeout:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

pub fn is_timeout(err: &std::io::Error) -> bool {
    matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
}

/// Read until the peer closes. `Ok(bytes)` on EOF/RST, `Err(bytes)` if
/// the socket's read timeout fired first.
pub fn read_to_eof(mut stream: &TcpStream) -> Result<Vec<u8>, Vec<u8>> {
    let mut received = Vec::new();
    let mut buf = [0u8; 512];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => return Ok(received),
            Ok(n) => received.extend_from_slice(&buf[..n]),
            Err(e) if is_timeout(&e) => return Err(received),
            Err(_) => return Ok(received),
        }
    }
}

/// Read up to and including the next `\n`, byte by byte so nothing
/// past it is consumed (a `BufReader` would swallow the SPTPS bytes
/// that follow the daemon's ID line).
pub fn read_line_unbuffered(mut stream: &TcpStream) -> Vec<u8> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(1) => {
                line.push(byte[0]);
                if byte[0] == b'\n' {
                    return line;
                }
            }
            Ok(_) => panic!(
                "peer closed mid-line after {:?}",
                String::from_utf8_lossy(&line)
            ),
            Err(e) => panic!("read: {e}; got {:?}", String::from_utf8_lossy(&line)),
        }
    }
}

pub fn pubkey_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    *tinc_crypto::sign::SigningKey::from_seed(seed).public_key()
}

pub fn write_ed25519_privkey(confbase: &Path, seed: &[u8; 32]) {
    use std::os::unix::fs::OpenOptionsExt;
    let key = tinc_crypto::sign::SigningKey::from_seed(seed);
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(confbase.join("ed25519_key.priv"))
        .unwrap();
    let mut writer = std::io::BufWriter::new(file);
    tinc_conf::write_pem(&mut writer, "ED25519 PRIVATE KEY", &key.to_blob()).unwrap();
}

/// Control-socket client; speaks the same protocol to Rust and C tincd.
pub struct Ctl {
    pub reader: BufReader<UnixStream>,
    pub writer: UnixStream,
}

impl Ctl {
    /// Connect and authenticate with the pidfile cookie. Retries for
    /// ~5s: the socket file can exist before the daemon accepts on
    /// it, and a busy box overflows the listen backlog.
    pub fn connect(socket: &Path, pidfile: &Path) -> Self {
        let mut last_err = None;
        for _ in 0..50 {
            match Self::try_connect(socket, pidfile) {
                Ok(ctl) => return ctl,
                Err(e) => {
                    last_err = Some(e);
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
        panic!(
            "control connect to {} failed after 50 tries: {last_err:?}",
            socket.display()
        );
    }

    fn try_connect(socket: &Path, pidfile: &Path) -> std::io::Result<Self> {
        let cookie = std::fs::read_to_string(pidfile)?
            .split_whitespace()
            .nth(1)
            .ok_or_else(|| std::io::Error::new(ErrorKind::InvalidData, "pidfile without cookie"))?
            .to_owned();
        let stream = UnixStream::connect(socket)?;
        let reader = BufReader::new(stream.try_clone()?);
        let mut ctl = Self {
            reader,
            writer: stream,
        };
        // Greeting `0 ^COOKIE 0` is answered by the daemon's ID line
        // and an ACK line; neither carries anything tests need.
        writeln!(ctl.writer, "0 ^{cookie} 0")?;
        let mut line = String::new();
        ctl.reader.read_line(&mut line)?;
        line.clear();
        ctl.reader.read_line(&mut line)?;
        Ok(ctl)
    }

    /// One-line control request `18 REQ` (reload = 1, purge = 8,
    /// retry = 10); returns the daemon's result code (0 = ok).
    pub fn request(&mut self, request: u8) -> i32 {
        let reply = self.request_line(&format!("18 {request}"));
        reply
            .strip_prefix(&format!("18 {request} "))
            .unwrap_or_else(|| panic!("control ack: {reply:?}"))
            .parse()
            .expect("control result code")
    }

    /// Send one raw line, return the one-line reply (trimmed).
    pub fn request_line(&mut self, line: &str) -> String {
        writeln!(self.writer, "{line}").unwrap();
        let mut reply = String::new();
        self.reader.read_line(&mut reply).expect("control reply");
        reply.trim_end().to_owned()
    }

    /// `REQ_STOP`. The ack may or may not make it out before the
    /// daemon closes; EOF is the contract.
    pub fn stop(mut self) {
        writeln!(self.writer, "18 0").unwrap();
        let mut line = String::new();
        while self.reader.read_line(&mut line).is_ok_and(|n| n > 0) {}
    }

    pub fn reload(&mut self) -> i32 {
        self.request(1)
    }

    pub fn purge(&mut self) -> i32 {
        self.request(8)
    }

    pub fn retry(&mut self) -> i32 {
        self.request(10)
    }

    /// `REQ_DUMP_*`: rows up to the bare `18 SUBTYPE` terminator.
    pub fn dump(&mut self, subtype: u8) -> Vec<String> {
        writeln!(self.writer, "18 {subtype}").unwrap();
        let terminator = format!("18 {subtype}");
        let mut rows = Vec::new();
        loop {
            let mut line = String::new();
            self.reader.read_line(&mut line).expect("dump row");
            let line = line.trim_end();
            if line == terminator {
                return rows;
            }
            rows.push(line.to_owned());
        }
    }
}

/// `dump traffic` row `18 13 NAME in_pkts in_bytes out_pkts out_bytes`
/// → `(in_bytes, out_bytes)`.
pub fn node_traffic(rows: &[String], name: &str) -> Option<(u64, u64)> {
    rows.iter().find_map(|row| {
        let mut fields = row.strip_prefix("18 13 ")?.split_whitespace();
        if fields.next()? != name {
            return None;
        }
        let _in_packets = fields.next()?;
        let in_bytes = fields.next()?.parse().ok()?;
        let _out_packets = fields.next()?;
        let out_bytes = fields.next()?.parse().ok()?;
        Some((in_bytes, out_bytes))
    })
}

/// `dump nodes` status word for `name`. Fields: `name id host "port"
/// PORT cipher digest maclen compression options STATUS …`; bit
/// `0x10` is reachable, `0x02` validkey.
pub fn node_status(rows: &[String], name: &str) -> Option<u32> {
    rows.iter().find_map(|row| {
        let fields: Vec<&str> = row.strip_prefix("18 3 ")?.split_whitespace().collect();
        if fields.first() != Some(&name) {
            return None;
        }
        u32::from_str_radix(fields.get(10)?, 16).ok()
    })
}

pub fn node_reachable(rows: &[String], name: &str) -> bool {
    node_status(rows, name).is_some_and(|status| status & 0x10 != 0)
}

/// RNG that panics if used. After `Sptps::start` the initiator side
/// needs no randomness; if that ever changes the tests should notice.
pub struct NoRng;
impl rand_core::TryCryptoRng for NoRng {}
impl rand_core::TryRng for NoRng {
    type Error = rand_core::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        unreachable!("RNG touched")
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        unreachable!("RNG touched")
    }
    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), Self::Error> {
        unreachable!("RNG touched")
    }
}

/// A daemon `testnode` plus an authenticated SPTPS meta connection to
/// it from this process acting as `testpeer`. The handshake is done and
/// the daemon's ACK record has been received; the test can
/// `send_record` straight away.
pub struct PeerFixture {
    pub tmp: TmpGuard,
    pub node: Node,
    pub stream: TcpStream,
    pub sptps: tinc_sptps::Sptps,
    /// The daemon's `4 PORT WEIGHT OPTIONS` ACK.
    pub daemon_ack: Vec<u8>,
}

const PEER_SEED: u8 = 0x77;

impl PeerFixture {
    pub fn spawn(tag: &str) -> Self {
        Self::spawn_with_conf(tag, "")
    }

    pub fn spawn_with_conf(tag: &str, extra_conf: &str) -> Self {
        use tinc_crypto::sign::SigningKey;
        use tinc_sptps::{Framing, Output, Role, Sptps};

        let tmp = TmpGuard::new("peer", tag);
        let peer = Node::new(tmp.path(), "testpeer", PEER_SEED);
        // We never answer PING, so keep the daemon from reaping us.
        let mut node = Node::new(tmp.path(), "testnode", 0x42)
            .with_conf(extra_conf)
            .with_conf("PingTimeout = 60");
        node.write_config(&peer, false);
        node.start();

        let stream = TcpStream::connect(node.tcp_addr()).expect("TCP connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        writeln!(&stream, "0 testpeer 17.7").unwrap();
        assert_eq!(read_line_unbuffered(&stream), b"0 testnode 17.7\n");

        // We dialled, so we are the SPTPS initiator; the label names
        // initiator first and is NUL-terminated like `proto::tcp_label`.
        let (sptps, init_output) = Sptps::start(
            Role::Initiator,
            Framing::Stream,
            SigningKey::from_seed(&[PEER_SEED; 32]),
            node.pubkey(),
            b"tinc TCP key expansion testpeer testnode\0".to_vec(),
            0,
            &mut tinc_crypto::os_rng(),
        );
        for output in init_output {
            if let Output::Wire { bytes, .. } = output {
                (&stream).write_all(&bytes).expect("send KEX");
            }
        }

        let mut fixture = Self {
            tmp,
            node,
            stream,
            sptps,
            daemon_ack: Vec::new(),
        };
        // The daemon sends SIG and its ACK back to back; the first
        // record after HandshakeDone is that ACK.
        let mut records = fixture.pump(Duration::from_secs(5), |records| !records.is_empty());
        fixture.daemon_ack = records.swap_remove(0);
        fixture
            .stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        fixture
    }

    pub fn send_record(&mut self, body: &[u8]) {
        use tinc_sptps::Output;
        for output in self.sptps.send_record(0, body).expect("send_record") {
            if let Output::Wire { bytes, .. } = output {
                (&self.stream).write_all(&bytes).expect("send record");
            }
        }
    }

    /// Feed socket bytes into SPTPS until `done(records_so_far)` or the
    /// socket read times out with nothing buffered. Handshake `Wire`
    /// output (our SIG) is written back as it appears.
    fn pump(&mut self, timeout: Duration, done: impl Fn(&[Vec<u8>]) -> bool) -> Vec<Vec<u8>> {
        use tinc_sptps::Output;
        let deadline = Instant::now() + timeout;
        let mut pending = Vec::new();
        let mut records = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let mut consumed = 0;
            while consumed < pending.len() {
                let (n, outputs) = match self.sptps.receive(&pending[consumed..], &mut NoRng) {
                    Ok(result) => result,
                    Err(e) => panic!("SPTPS receive: {e:?}; stderr:\n{}", self.node.stop()),
                };
                if n == 0 {
                    break; // partial record, need more bytes
                }
                consumed += n;
                for output in outputs {
                    match output {
                        Output::Wire { bytes, .. } => {
                            (&self.stream).write_all(&bytes).expect("send handshake");
                        }
                        Output::Record { bytes, .. } => records.push(bytes),
                        Output::HandshakeDone => {}
                    }
                }
            }
            pending.drain(..consumed);
            if done(&records) {
                return records;
            }
            assert!(
                Instant::now() < deadline,
                "pump timed out; stderr:\n{}",
                self.node.stop()
            );
            match (&self.stream).read(&mut buf) {
                Ok(0) => panic!(
                    "daemon closed meta connection; stderr:\n{}",
                    self.node.stop()
                ),
                Ok(n) => pending.extend_from_slice(&buf[..n]),
                Err(e) if is_timeout(&e) && pending.is_empty() => return records,
                Err(e) if is_timeout(&e) => {}
                Err(e) => panic!("read: {e}; stderr:\n{}", self.node.stop()),
            }
        }
    }

    /// All records the daemon sends until it goes quiet for `quiet_ms`.
    pub fn drain_records(&mut self, quiet_ms: u64) -> Vec<Vec<u8>> {
        self.stream
            .set_read_timeout(Some(Duration::from_millis(quiet_ms)))
            .unwrap();
        self.pump(Duration::from_secs(5), |_| false)
    }

    pub fn kill_and_stderr(mut self) -> String {
        self.node.stop()
    }
}

/// `Child` plus a thread draining its stderr into memory. Without the
/// drain a verbose daemon fills the 64 KiB pipe and blocks in
/// `write(2)`, freezing its event loop. Kills and reaps on drop.
pub struct ChildWithLog {
    pub child: Child,
    log: Arc<Mutex<Vec<u8>>>,
    drain: Option<std::thread::JoinHandle<()>>,
}

impl ChildWithLog {
    pub fn spawn(mut child: Child) -> Self {
        let mut stderr = child.stderr.take().expect("stderr piped");
        let log = Arc::new(Mutex::new(Vec::new()));
        let log_writer = Arc::clone(&log);
        let drain = std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = stderr.read(&mut buf) {
                if n == 0 {
                    break;
                }
                log_writer.lock().unwrap().extend_from_slice(&buf[..n]);
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

    /// Stderr so far; child keeps running.
    pub fn log_snapshot(&self) -> String {
        String::from_utf8_lossy(&self.log.lock().unwrap()).into_owned()
    }

    /// Wait for the child to exit on its own (e.g. after SIGTERM).
    pub fn wait_exit(&mut self, timeout: Duration) -> Option<std::process::ExitStatus> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return Some(status);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn kill_and_log(mut self) -> String {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(drain) = self.drain.take() {
            let _ = drain.join();
        }
        self.log_snapshot()
    }
}

impl Drop for ChildWithLog {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(target_os = "linux")]
pub mod linux {
    use std::process::Command;
    use std::time::{Duration, Instant};

    pub fn run_ip(args: &[&str]) {
        let out = Command::new("ip").args(args).output().expect("spawn ip");
        assert!(
            out.status.success(),
            "ip {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// A persistent TUN shows `NO-CARRIER` until a daemon attaches;
    /// `LOWER_UP` means tincd opened it.
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
}

#[cfg(target_os = "macos")]
pub mod macos {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    pub fn run(argv: &[&str]) {
        let out = Command::new(argv[0])
            .args(&argv[1..])
            .output()
            .unwrap_or_else(|e| panic!("spawn {argv:?}: {e}"));
        assert!(
            out.status.success(),
            "{argv:?} failed: {}{}",
            String::from_utf8_lossy(&out.stderr),
            String::from_utf8_lossy(&out.stdout),
        );
    }

    /// utun creation is synchronous with the daemon's kern-control
    /// connect, so the interface existing means it is up.
    pub fn wait_for_utun(dev: &str, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            let exists = Command::new("/sbin/ifconfig")
                .arg(dev)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|s| s.success());
            if exists {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    pub fn route_del_host(dst: &str) {
        let _ = Command::new("/sbin/route")
            .args(["-n", "delete", "-host", dst])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}
