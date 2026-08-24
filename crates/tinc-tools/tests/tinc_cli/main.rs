//! The `tinc` and `tinc-auth` binaries as subprocesses: argv parsing,
//! dispatch, exit codes and stderr, plus the control-socket wire
//! format against a scripted fake daemon. The command implementations
//! themselves are unit-tested in `src/cmd/`.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

mod argv;
mod auth_http;
mod config;
mod ctl;
mod dump;
mod edit;
mod export_import;
mod fsck;
mod genkey;
mod idp_http;
mod info;
mod init;
mod invite_join;
mod sign_verify;
mod top_log_pcap;

pub(crate) fn bin(name: &str) -> PathBuf {
    let var = match name {
        "tinc" => option_env!("CARGO_BIN_EXE_tinc"),
        "tinc-auth" => option_env!("CARGO_BIN_EXE_tinc-auth"),
        "sptps_test" => option_env!("CARGO_BIN_EXE_sptps_test"),
        _ => panic!("unknown bin {name}"),
    };
    var.map_or_else(
        // target/{profile}/deps/<test> → target/{profile}/<name>
        || {
            let exe = std::env::current_exe().unwrap();
            exe.parent().unwrap().parent().unwrap().join(name)
        },
        PathBuf::from,
    )
}

pub(crate) struct Run {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
    pub raw_stdout: Vec<u8>,
}

impl Run {
    fn new(out: Output) -> Self {
        Self {
            success: out.status.success(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            raw_stdout: out.stdout,
        }
    }

    /// Asserts exit 0; returns stdout.
    #[track_caller]
    pub fn ok(self) -> String {
        assert!(self.success, "failed: {}", self.stderr);
        self.stdout
    }

    /// Asserts exit 0; returns stderr (warnings).
    #[track_caller]
    pub fn ok_stderr(self) -> String {
        assert!(self.success, "failed: {}", self.stderr);
        self.stderr
    }

    /// Asserts a non-zero exit; returns stderr.
    #[track_caller]
    pub fn fails(self) -> String {
        assert!(!self.success, "unexpectedly succeeded: {}", self.stdout);
        self.stderr
    }

    /// Asserts a non-zero exit with `needle` in stderr.
    #[track_caller]
    pub fn fails_with(self, needle: &str) -> String {
        let stderr = self.fails();
        assert!(stderr.contains(needle), "expected {needle:?} in: {stderr}");
        stderr
    }
}

/// `tinc ARGS` with `NETNAME` removed from the environment so the
/// caller's shell cannot change confbase resolution.
pub(crate) fn tinc(args: &[&str]) -> Run {
    tinc_stdin(args, b"")
}

pub(crate) fn tinc_stdin(args: &[&str], stdin: &[u8]) -> Run {
    tinc_with(args, stdin, |_| {})
}

pub(crate) fn tinc_with(args: &[&str], stdin: &[u8], tweak: impl FnOnce(&mut Command)) -> Run {
    let mut cmd = Command::new(bin("tinc"));
    cmd.args(args)
        .env_remove("NETNAME")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    tweak(&mut cmd);
    let mut child = cmd.spawn().expect("spawn tinc");
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    Run::new(child.wait_with_output().unwrap())
}

/// A temp directory holding `vpn/` as confbase and `tinc.pid` /
/// `tinc.socket` for the (optional) fake daemon.
pub(crate) struct Conf {
    dir: tempfile::TempDir,
}

impl Conf {
    /// Empty confbase; the pidfile does not exist.
    pub fn bare() -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("vpn")).unwrap();
        Self { dir }
    }

    /// After `tinc init NAME`.
    pub fn init(name: &str) -> Self {
        let conf = Self::bare();
        conf.tinc(&["init", name]).ok();
        conf
    }

    pub fn dir(&self) -> &Path {
        self.dir.path()
    }

    pub fn base(&self) -> PathBuf {
        self.dir.path().join("vpn")
    }

    /// confbase as an argv string.
    pub fn arg(&self) -> String {
        self.base().to_str().unwrap().to_owned()
    }

    pub fn pidfile(&self) -> PathBuf {
        self.dir.path().join("tinc.pid")
    }

    pub fn host(&self, name: &str) -> PathBuf {
        self.base().join("hosts").join(name)
    }

    pub fn read(&self, relative: &str) -> String {
        std::fs::read_to_string(self.base().join(relative))
            .unwrap_or_else(|e| panic!("{relative}: {e}"))
    }

    pub fn write(&self, relative: &str, contents: &str) {
        std::fs::write(self.base().join(relative), contents).unwrap();
    }

    /// `tinc -c BASE --pidfile PIDFILE ARGS`.
    pub fn tinc(&self, args: &[&str]) -> Run {
        self.tinc_stdin(args, b"")
    }

    pub fn tinc_stdin(&self, args: &[&str], stdin: &[u8]) -> Run {
        let base = self.arg();
        let pidfile = self.pidfile();
        let mut full = vec!["-c", &base, "--pidfile", pidfile.to_str().unwrap()];
        full.extend_from_slice(args);
        tinc_stdin(&full, stdin)
    }

    /// Write a pidfile naming this process (so `kill(pid, 0)`
    /// succeeds) and bind the control socket next to it.
    fn listen(&self) -> (std::os::unix::net::UnixListener, String) {
        let cookie = format!("{:064x}", rand_cookie());
        std::fs::write(
            self.pidfile(),
            format!("{} {cookie} 127.0.0.1 port 655\n", std::process::id()),
        )
        .unwrap();
        let socket = self.dir.path().join("tinc.socket");
        let _ = std::fs::remove_file(&socket);
        (
            std::os::unix::net::UnixListener::bind(socket).unwrap(),
            cookie,
        )
    }

    /// Fake daemon serving one control connection with `script` after
    /// the greeting. `finish()` joins it and propagates its panics.
    pub fn serve(&self, script: impl FnOnce(&mut CtlConn) + Send + 'static) -> FakeDaemon {
        let (listener, cookie) = self.listen();
        let thread = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut conn = CtlConn::greet(stream, &cookie);
            script(&mut conn);
        });
        FakeDaemon(Some(thread))
    }

    /// Fake daemon serving every connection with `script`, for the
    /// long-running `tinc-auth` tests. Detached; dies with the test.
    pub fn serve_forever(&self, script: impl Fn(&mut CtlConn) + Send + Sync + 'static) {
        let (listener, cookie) = self.listen();
        let script = std::sync::Arc::new(script);
        std::thread::spawn(move || {
            while let Ok((stream, _)) = listener.accept() {
                let cookie = cookie.clone();
                let script = script.clone();
                std::thread::spawn(move || script(&mut CtlConn::greet(stream, &cookie)));
            }
        });
    }
}

fn rand_cookie() -> u128 {
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u32(std::process::id());
    u128::from(hasher.finish())
}

pub(crate) struct FakeDaemon(Option<std::thread::JoinHandle<()>>);

impl FakeDaemon {
    pub fn finish(mut self) {
        if let Err(panic) = self.0.take().unwrap().join() {
            std::panic::resume_unwind(panic);
        }
    }
}

/// The daemon side of one control connection.
pub(crate) struct CtlConn {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
}

impl CtlConn {
    /// Check the client's `0 ^COOKIE 0` and answer like tincd:
    /// `0 NAME 17.7` then `4 0 PID`.
    fn greet(stream: UnixStream, cookie: &str) -> Self {
        let mut conn = Self {
            writer: stream.try_clone().unwrap(),
            reader: BufReader::new(stream),
        };
        let id = conn.recv().expect("ID line");
        assert!(id.contains(&format!("^{cookie}")), "bad cookie: {id}");
        conn.send("0 fakedaemon 17.7");
        conn.send("4 0 1");
        conn
    }

    /// Next request line without the newline; `None` at EOF.
    pub fn recv(&mut self) -> Option<String> {
        let mut line = String::new();
        match self.reader.read_line(&mut line).unwrap() {
            0 => None,
            _ => Some(line.trim_end_matches('\n').to_owned()),
        }
    }

    #[track_caller]
    pub fn expect(&mut self, line: &str) {
        assert_eq!(self.recv().as_deref(), Some(line));
    }

    #[track_caller]
    pub fn expect_eof(&mut self) {
        let mut rest = String::new();
        self.reader.read_to_string(&mut rest).unwrap();
        assert_eq!(rest, "", "client sent more");
    }

    pub fn send(&mut self, line: &str) {
        self.writer.write_all(line.as_bytes()).unwrap();
        self.writer.write_all(b"\n").unwrap();
    }

    pub fn send_raw(&mut self, bytes: &[u8]) {
        self.writer.write_all(bytes).unwrap();
    }

    /// Half-close so the client sees EOF while we can still read.
    pub fn close(&mut self) {
        self.writer.shutdown(std::net::Shutdown::Write).unwrap();
    }
}

/// `tinc-auth` child, killed on drop.
pub(crate) struct AuthDaemon(std::process::Child);

impl Drop for AuthDaemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl AuthDaemon {
    /// `tinc-auth -c BASE -n mesh --pidfile PIDFILE ARGS` with socket
    /// activation variables removed.
    pub fn spawn(conf: &Conf, args: &[&str]) -> Self {
        let child = Command::new(bin("tinc-auth"))
            .arg("-c")
            .arg(conf.base())
            .args(["-n", "mesh", "--pidfile"])
            .arg(conf.pidfile())
            .args(args)
            .env_remove("LISTEN_PID")
            .env_remove("LISTEN_FDS")
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        Self(child)
    }

    /// Read stderr up to the `listening` line; returns the `IdP` port if
    /// one was announced. Panics with stderr if the process exits.
    pub fn wait_ready(&mut self) -> Option<u16> {
        let stderr = self.0.stderr.take().unwrap();
        let mut idp_port = None;
        let mut seen = String::new();
        for line in BufReader::new(stderr).lines() {
            let line = line.unwrap();
            seen.push_str(&line);
            seen.push('\n');
            if let Some(addr) = line.strip_prefix("tinc-auth: IdP listening on ") {
                idp_port = Some(addr.rsplit_once(':').unwrap().1.parse().unwrap());
            }
            if line.starts_with("tinc-auth: listening") {
                return idp_port;
            }
        }
        panic!("tinc-auth exited: {seen}");
    }

    pub fn wait_output(mut self) -> Run {
        let mut stderr = String::new();
        self.0
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .unwrap();
        let status = self.0.wait().unwrap();
        Run {
            success: status.success(),
            stdout: String::new(),
            stderr,
            raw_stdout: Vec::new(),
        }
    }
}

pub(crate) struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// Parse a `Connection: close` response.
    pub fn read(stream: impl Read) -> Self {
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let status = line.split_whitespace().nth(1).unwrap().parse().unwrap();
        let mut headers = Vec::new();
        loop {
            line.clear();
            reader.read_line(&mut line).unwrap();
            if line.trim_end().is_empty() {
                break;
            }
            let (name, value) = line.split_once(':').unwrap();
            headers.push((name.trim().to_owned(), value.trim().to_owned()));
        }
        let mut body = Vec::new();
        reader.read_to_end(&mut body).unwrap();
        Self {
            status,
            headers,
            body,
        }
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&self.body)))
    }
}
