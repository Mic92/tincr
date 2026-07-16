//! Control socket transport. The CLI ↔ daemon channel.
//!
//! ## Shape of the protocol
//!
//! The control socket is a **regular meta connection** that took the
//! `^` branch in `id_h`. Same `\n`-delimited lines, same request-
//! type-first-int convention. The control conversation looks like:
//!
//! ```text
//!   C → D:  "0 ^<64-hex-cookie> 0\n"       ID, ^prefix, ctl-ver=0
//!   D → C:  "0 <daemon-name> 17.7\n"       send_id() — daemon's greeting
//!   D → C:  "4 0 <pid>\n"                  ACK, ctl-ver=0, daemon pid
//!   ----- connected -----
//!   C → D:  "18 1\n"                       CONTROL REQ_RELOAD
//!   D → C:  "18 1 0\n"                     CONTROL REQ_RELOAD errcode=0
//! ```
//!
//! Dump commands return one line per item then a 2-int terminator:
//!
//! ```text
//!   C → D:  "18 3\n"                       CONTROL REQ_DUMP_NODES
//!   D → C:  "18 3 alice 7e3f... ...\n"     22 fields per node
//!   D → C:  "18 3 bob   8c1a... ...\n"
//!   D → C:  "18 3\n"                       terminator (just 2 ints)
//! ```
//!
//! ## Compat notes
//!
//! CLI and daemon ship together, so the positional row bodies are a
//! private channel between the two halves of one release; only the
//! request enum, framing, cookie auth, and unix-socket transport are a
//! stable surface.
//!
//! ## Why `Read + Write` not `UnixStream`
//!
//! Tests pass a `UnixStream::pair()` half. `connect()` does the OS bits
//! and delegates to `handshake()`; the split is the testable seam.
//!
//! Unix-only; no reconnect logic (one command per process).

use std::io::{BufRead, BufReader, Read, Write};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::path::Path;

use crate::names::Paths;

pub mod rows;

/// Control request type: the second int after `CONTROL` in every control
/// line. The numeric values are a closed set shared with the daemon;
/// new values are added at the end, never reordered.
///
/// The daemon's `REQ_INVALID = -1` error response is represented as
/// `Option<CtlRequest>::None` on parse. `Restart`, `DumpGraph`, and
/// `Connect` are never sent, but keeping them avoids surprising gaps in
/// the discriminant sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CtlRequest {
    Stop = 0,
    Reload = 1,
    /// Never sent; the daemon does not handle it.
    Restart = 2,
    DumpNodes = 3,
    DumpEdges = 4,
    DumpSubnets = 5,
    DumpConnections = 6,
    /// Never sent; graph output is synthesized from nodes+edges.
    DumpGraph = 7,
    Purge = 8,
    SetDebug = 9,
    Retry = 10,
    /// Never sent; the daemon does not handle it.
    Connect = 11,
    Disconnect = 12,
    DumpTraffic = 13,
    Pcap = 14,
    Log = 15,
}

impl CtlRequest {
    /// Parse the second int. `None` for unknown / `REQ_INVALID`.
    /// Permissive: anything not in the enum is `None`, not a
    /// protocol error.
    #[must_use]
    pub const fn from_i32(n: i32) -> Option<Self> {
        Some(match n {
            0 => Self::Stop,
            1 => Self::Reload,
            2 => Self::Restart,
            3 => Self::DumpNodes,
            4 => Self::DumpEdges,
            5 => Self::DumpSubnets,
            6 => Self::DumpConnections,
            7 => Self::DumpGraph,
            8 => Self::Purge,
            9 => Self::SetDebug,
            10 => Self::Retry,
            11 => Self::Connect,
            12 => Self::Disconnect,
            13 => Self::DumpTraffic,
            14 => Self::Pcap,
            15 => Self::Log,
            _ => return None,
        })
    }
}

/// Derived from the canonical `tinc_proto::Request` enum so the
/// numeric values can't drift.
const CONTROL: u8 = tinc_proto::Request::Control as u8;
const ID: u8 = tinc_proto::Request::Id as u8;
const ACK: u8 = tinc_proto::Request::Ack as u8;
/// Control protocol version, checked by the daemon during the greeting.
/// Unchanged since 2007.
const CTL_VERSION: u8 = 0;

/// Contents of the pidfile. The host field (only used for a TCP
/// fallback) is skipped during parse but not stored.
///
/// `cookie` is the bearer token: 32 random bytes, hex-encoded. The
/// pidfile is mode 0600, so being able to read the cookie IS the
/// authorization.
#[derive(Debug)]
pub struct Pidfile {
    pub pid: u32,
    /// Hex string, 64 chars. Kept as the string: it goes back on the wire
    /// verbatim, and round-tripping through bytes could change the case.
    pub cookie: String,
    /// The port the daemon is listening on. String, not u16 — `Port
    /// = 655/udp` is valid config syntax (parsed via `getaddrinfo`).
    /// This is the *runtime* port (the daemon resolved `Port = 0` to
    /// a real port and wrote it here).
    pub port: String,
}

impl Pidfile {
    /// Format: `"<pid> <cookie> <host> port <port>\n"`.
    ///
    /// # Errors
    /// File open failed, or contents don't match the expected shape.
    pub fn read(path: &Path) -> Result<Self, CtlError> {
        let s = std::fs::read_to_string(path).map_err(|e| CtlError::PidfileMissing {
            path: path.to_path_buf(),
            err: e,
        })?;

        let mut tok = s.split_whitespace();
        let pid_s = tok.next().ok_or(CtlError::PidfileMalformed)?;
        let cookie = tok.next().ok_or(CtlError::PidfileMalformed)?;
        // host is unused, but a truncated pidfile (daemon crashed
        // mid-write?) should fail here rather than connect with a
        // half-read cookie.
        let _host = tok.next().ok_or(CtlError::PidfileMalformed)?;
        let port_lit = tok.next().ok_or(CtlError::PidfileMalformed)?;
        let port = tok.next().ok_or(CtlError::PidfileMalformed)?;
        if port_lit != "port" {
            return Err(CtlError::PidfileMalformed);
        }

        // u32 covers all real pids; the check for negative is free.
        let pid: u32 = pid_s.parse().map_err(|_| CtlError::PidfileMalformed)?;

        // The daemon writes exactly 64 hex chars; anything else would be a
        // silent auth failure later, so fail here.
        if cookie.len() != 64 || !cookie.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(CtlError::PidfileMalformed);
        }

        Ok(Self {
            pid,
            cookie: cookie.to_owned(),
            port: port.to_owned(),
        })
    }
}

/// Errors from connecting to or talking with the daemon. Distinct from
/// `cmd::CmdError` because recoverability differs — "pidfile missing"
/// means "daemon isn't running", which best-effort callers (e.g. the
/// post-invite reload) treat as a soft no-op.
///
/// Errors carry their message; the caller decides whether to print.
// Message wording matches C tinc where it exists — users grep for these.
#[derive(Debug, thiserror::Error)]
pub enum CtlError {
    /// ENOENT or EACCES. The daemon isn't running, or never wrote a
    /// pidfile, or you can't read it.
    #[error("Could not open pid file {}: {err}", path.display())]
    PidfileMissing {
        path: std::path::PathBuf,
        #[source]
        err: std::io::Error,
    },
    /// Pidfile exists but doesn't parse: daemon crashed mid-write, or
    /// it's from a different tinc version.
    #[error("Could not parse pid file")]
    PidfileMalformed,
    /// `kill(pid, 0)` returned ESRCH: pidfile is stale. The stale files
    /// are left in place; the daemon's next start overwrites them.
    #[error("Could not find tincd running at pid {pid}")]
    DaemonDead { pid: u32 },
    /// `connect(AF_UNIX)` failed. Socket file gone, or daemon not
    /// listening.
    #[error("Cannot connect to UNIX socket {}: {err}", path.display())]
    SocketConnect {
        path: std::path::PathBuf,
        #[source]
        err: std::io::Error,
    },
    /// Greeting exchange failed. Wrong cookie, daemon spoke wrong
    /// protocol, EOF mid-greeting.
    #[error("{0}")]
    Greeting(String),
    /// Socket I/O after greeting. Daemon closed, write failed.
    #[error("Connection to tincd lost: {0}")]
    Io(#[source] std::io::Error),
}

/// The connected control socket, plus the daemon's pid (from greeting
/// line 2).
///
/// Generic over the stream so tests can pass `UnixStream::pair()` halves;
/// in production it's always `UnixStream`.
///
/// The reader half is a `BufReader`, which is essential: `recv_line` may
/// over-read past the `\n` into a following raw data block, and a later
/// `recv_data` (`read_exact` on the same `BufReader`) drains that internal
/// buffer first, so no bytes are lost.
///
/// Writes are unbuffered: control commands are one line each, so a
/// `BufWriter` would only add a mandatory flush after every send.
///
/// Not `Debug` — that would require `S: Debug` for no benefit.
pub struct CtlSocket<S: Read + Write> {
    /// Reader half. Buffered for `read_line`.
    reader: BufReader<ReadHalf<S>>,
    /// Writer half. Unbuffered.
    writer: WriteHalf<S>,
    /// Daemon's pid, from greeting line 2. `cmd_pid` prints this;
    /// nothing else uses it.
    pub pid: u32,
}

/// Read/write halves share the stream via `Rc<RefCell<S>>` because generic
/// `S` has no `try_clone` and `BufReader` needs to own its reader.
/// Control I/O is strictly alternating (send a line, recv a line), so the
/// borrows never overlap; a `RefCell` panic would indicate a bug worth
/// knowing about.
use std::cell::RefCell;
use std::rc::Rc;

struct ReadHalf<S>(Rc<RefCell<S>>);
struct WriteHalf<S>(Rc<RefCell<S>>);

impl<S: Read> Read for ReadHalf<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.borrow_mut().read(buf)
    }
}
impl<S: Write> Write for WriteHalf<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.borrow_mut().write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.borrow_mut().flush()
    }
}

impl<S: Read + Write> CtlSocket<S> {
    /// Test seam: wrap an existing stream without doing the handshake, so
    /// tests can feed canned daemon output into a `CtlSocket` without
    /// mocking the greeting each time.
    ///
    /// `pid` is set to 0 (only `cmd_pid` reads it). Taking the
    /// `Rc<RefCell<S>>` lets the test keep a clone and inspect what was
    /// written. `pub(crate)` + `#[cfg(test)]` so test modules in `cmd::*`
    /// can call it while it's compiled out of release builds.
    #[cfg(test)]
    pub(crate) fn wrap(shared: Rc<RefCell<S>>) -> Self {
        Self {
            reader: BufReader::new(ReadHalf(Rc::clone(&shared))),
            writer: WriteHalf(shared),
            pid: 0,
        }
    }

    /// Do the greeting exchange over an already-connected stream.
    ///
    /// Separate from `connect()` (which does the pidfile read, liveness
    /// check, and socket connect) so tests can pass a mock stream and a
    /// synthesized cookie.
    ///
    /// # Errors
    /// `Greeting` if the daemon's response doesn't match the
    /// expected shape. Wrong cookie → daemon closes after our send,
    /// next recv returns 0 → `Greeting("Cannot read greeting...")`.
    pub fn handshake(stream: S, cookie: &str) -> Result<Self, CtlError> {
        let shared = Rc::new(RefCell::new(stream));
        let mut reader = BufReader::new(ReadHalf(Rc::clone(&shared)));
        let mut writer = WriteHalf(shared);

        // The `^` prefix routes this to the daemon's control path; without
        // it the cookie would be parsed as a node name.
        writeln!(writer, "{ID} ^{cookie} {CTL_VERSION}").map_err(CtlError::Io)?;

        // Line 1: the daemon's ID, "0 <daemon-name> <maj>.<min>". Nothing
        // in it is used; only the shape is checked.
        let line1 = recv_one(&mut reader, "Cannot read greeting from control socket")?;
        let mut t1 = line1.split_ascii_whitespace();
        if t1.next() != Some("0") {
            // Wrong protocol, or the socket isn't tincd at all.
            return Err(CtlError::Greeting(format!(
                "Cannot read greeting from control socket: unexpected response {line1:?}"
            )));
        }

        // Line 2: ACK with control version and pid, "4 0 <pid>".
        let line2 = recv_one(
            &mut reader,
            "Could not fully establish control socket connection",
        )?;
        let mut t2 = line2.split_ascii_whitespace();
        let code = t2.next().and_then(|s| s.parse::<u8>().ok());
        let ver = t2.next().and_then(|s| s.parse::<u8>().ok());
        let pid = t2.next().and_then(|s| s.parse::<u32>().ok());

        let (Some(ACK), Some(CTL_VERSION), Some(pid)) = (code, ver, pid) else {
            return Err(CtlError::Greeting(format!(
                "Could not fully establish control socket connection: \
                 unexpected response {line2:?}"
            )));
        };

        Ok(Self {
            reader,
            writer,
            pid,
        })
    }

    /// Send a CONTROL request with no arguments. The common case
    /// (reload, purge, retry, stop, all the dumps).
    ///
    /// # Errors
    /// `Io` if the write fails. Socket closed, daemon dead.
    pub fn send(&mut self, req: CtlRequest) -> Result<(), CtlError> {
        writeln!(self.writer, "{CONTROL} {}", req as u8).map_err(CtlError::Io)
    }

    /// Send with one int argument. `REQ_SET_DEBUG`, `REQ_PCAP`
    /// (snaplen). NOT `REQ_LOG`: that's two ints, see `send_int2`.
    ///
    /// # Errors
    /// Same as `send`.
    pub fn send_int(&mut self, req: CtlRequest, arg: i32) -> Result<(), CtlError> {
        writeln!(self.writer, "{CONTROL} {} {arg}", req as u8).map_err(CtlError::Io)
    }

    /// Send with two int arguments. The ONLY consumer is `REQ_LOG`:
    /// `level` then `use_color` (a 0/1 boolean printed as int).
    ///
    /// `i32` × 2 keeps the wire shape symmetric with `send_int`.
    ///
    /// # Errors
    /// Same as `send`.
    pub fn send_int2(&mut self, req: CtlRequest, a: i32, b: i32) -> Result<(), CtlError> {
        writeln!(self.writer, "{CONTROL} {} {a} {b}", req as u8).map_err(CtlError::Io)
    }

    /// Send with one string argument. `REQ_DISCONNECT` (node name).
    ///
    /// `arg` should be a single token (no spaces) — the daemon reads
    /// one word. Node names pass `check_id` so this holds; we don't
    /// re-validate (caller's job).
    ///
    /// # Errors
    /// Same as `send`.
    pub fn send_str(&mut self, req: CtlRequest, arg: &str) -> Result<(), CtlError> {
        writeln!(self.writer, "{CONTROL} {} {arg}", req as u8).map_err(CtlError::Io)
    }

    /// Receive and parse a one-shot ack.
    ///
    /// Returns the `result` int: 0 = success, anything else = daemon-side
    /// failure — except `REQ_SET_DEBUG`, which repurposes it as "previous
    /// debug level", so callers must interpret per request.
    ///
    /// # Errors
    /// `Io` if recv fails. `Greeting` (variant reused for shape errors) if
    /// the response has the wrong code, echoes the wrong request, or
    /// doesn't parse.
    pub fn recv_ack(&mut self, expected: CtlRequest) -> Result<i32, CtlError> {
        let line = recv_one(&mut self.reader, "lost connection to tincd")?;
        let mut t = line.split_ascii_whitespace();
        let code = t.next().and_then(|s| s.parse::<u8>().ok());
        let req = t.next().and_then(|s| s.parse::<i32>().ok());
        let result = t.next().and_then(|s| s.parse::<i32>().ok());

        match (code, req, result) {
            (Some(CONTROL), Some(r), Some(res)) if CtlRequest::from_i32(r) == Some(expected) => {
                Ok(res)
            }
            _ => Err(CtlError::Greeting(format!(
                "Unexpected response from tincd: {line:?}"
            ))),
        }
    }

    /// Receive one raw line. Returns `Ok(None)` on clean EOF (which the
    /// stop command's "wait for daemon to close" loop expects) and `Err`
    /// on I/O failure.
    ///
    /// # Errors
    /// `Io` on read failure (not EOF).
    pub fn recv_line(&mut self) -> Result<Option<String>, CtlError> {
        let mut buf = String::new();
        match self.reader.read_line(&mut buf) {
            Ok(0) => Ok(None),
            Ok(_) => {
                if buf.ends_with('\n') {
                    buf.pop();
                }
                Ok(Some(buf))
            }
            Err(e) => Err(CtlError::Io(e)),
        }
    }

    /// Receive one dump row: parse the `"18 N"` prefix and hand back
    /// `(kind, body)`. A line with no body is the dump terminator (`End`).
    ///
    /// `Row` carries the request type because graph mode fires two dumps
    /// (nodes then edges) and reads both responses in one loop.
    ///
    /// `body` is an owned `String`: a borrow into the `BufReader` buffer
    /// couldn't outlive the next `read_line`. Dump output is dozens of
    /// rows, so the per-row allocation is fine.
    ///
    /// # Errors
    /// `Io` on read failure. `Greeting` if EOF before terminator.
    /// The daemon closing the socket mid-dump is daemon-crashed; we
    /// don't try to use partial results.
    pub fn recv_row(&mut self) -> Result<DumpRow, CtlError> {
        let line = self
            .recv_line()?
            // EOF mid-dump = daemon crashed.
            .ok_or_else(|| CtlError::Greeting("Error receiving dump.".to_owned()))?;

        // The body must stay byte-exact: it gets re-tokenized later, and a
        // hostname like "unknown port unknown" contains the literal `port`.
        // Slice past the two prefix ints; don't collapse spaces.
        let bad = || CtlError::Greeting("Unable to parse dump from tincd.".to_owned());

        let (code_s, after_code) = line.split_once(' ').ok_or_else(bad)?;
        if code_s.parse::<u8>().ok() != Some(CONTROL) {
            // A wrong reply code is a row-level protocol violation.
            return Err(bad());
        }

        // Second space absent → terminator.
        let (req_s, body) = after_code.split_once(' ').unwrap_or((after_code, ""));
        let req = req_s.parse::<i32>().map_err(|_| bad())?;
        let kind = CtlRequest::from_i32(req).ok_or_else(bad)?;
        Ok(if body.is_empty() {
            DumpRow::End(kind)
        } else {
            DumpRow::Row(kind, body.to_owned())
        })
    }

    /// Drain a dump response, invoking `f` for every `Row` until the
    /// `End` terminator. The closure sees the per-row `CtlRequest`
    /// and the body string; most callers ignore the former.
    ///
    /// Generic over the error type so callers can return their own
    /// `CmdError` from the closure while `recv_row`'s `CtlError`
    /// still propagates via `From`.
    ///
    /// # Errors
    /// Whatever `recv_row` or `f` returns.
    pub fn for_each_row<E: From<CtlError>>(
        &mut self,
        mut f: impl FnMut(CtlRequest, &str) -> Result<(), E>,
    ) -> Result<(), E> {
        loop {
            match self.recv_row()? {
                DumpRow::End(_) => return Ok(()),
                DumpRow::Row(kind, body) => f(kind, &body)?,
            }
        }
    }

    /// Receive exactly `buf.len()` raw bytes after a header line.
    ///
    /// `read_exact` on the shared `BufReader` first drains any bytes the
    /// previous `read_line` over-read (see struct doc). The caller sizes
    /// and reuses `buf` to avoid per-packet allocation in the log/pcap
    /// stream loops.
    ///
    /// # Errors
    /// `Io` on read failure or unexpected EOF mid-data (daemon died
    /// between the header and the data).
    pub fn recv_data(&mut self, buf: &mut [u8]) -> Result<(), CtlError> {
        self.reader.read_exact(buf).map_err(CtlError::Io)
    }
}

/// One line from a dump response; row vs terminator as a type so the
/// caller's loop is a `match`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DumpRow {
    /// `"18 N FIELDS"` — one item, body byte-exact. The `CtlRequest` is
    /// for graph mode where node and edge rows interleave; single-type
    /// dumps can ignore it.
    Row(CtlRequest, String),

    /// `"18 N"` — terminator, per dump type: graph mode sees two of these
    /// and exits on the second.
    End(CtlRequest),
}

/// Read one line, error if EOF. The greeting recvs and `recv_ack`
/// want EOF-is-error semantics; only `recv_line` wants EOF-is-end.
fn recv_one<R: BufRead>(r: &mut R, eof_msg: &str) -> Result<String, CtlError> {
    let mut buf = String::new();
    match r.read_line(&mut buf) {
        Ok(0) => Err(CtlError::Greeting(eof_msg.to_owned())),
        Ok(_) => {
            if buf.ends_with('\n') {
                buf.pop();
            }
            Ok(buf)
        }
        Err(e) => Err(CtlError::Io(e)),
    }
}

#[cfg(unix)]
impl CtlSocket<UnixStream> {
    /// The full OS-side connect: read the pidfile, check the daemon is
    /// alive, connect the unix socket, do the greeting. Each failure has
    /// its own `CtlError` variant.
    ///
    /// `paths` must have had `resolve_runtime()` called; `pidfile()`
    /// panics otherwise.
    ///
    /// # Errors
    /// See `CtlError` variants.
    pub fn connect(paths: &Paths) -> Result<Self, CtlError> {
        let pidfile_path = paths.pidfile();
        let pf = Pidfile::read(pidfile_path)?;

        // Liveness check via kill(pid, 0). A pid of 0 would signal our own
        // process group and mask "no daemon" as "daemon alive", so treat
        // it (and pids that don't fit i32) as dead.
        let raw_pid = i32::try_from(pf.pid).unwrap_or(0);
        if raw_pid == 0 {
            return Err(CtlError::DaemonDead { pid: pf.pid });
        }
        // Only ESRCH is fatal. EPERM means something is at that pid
        // (daemon running as another user) — alive enough to attempt the
        // connect, which fails more usefully if it's wrong.
        if let Err(nix::errno::Errno::ESRCH) = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(raw_pid),
            None, // sig=0, the probe signal
        ) {
            return Err(CtlError::DaemonDead { pid: pf.pid });
        }

        let sock_path = paths.unix_socket();
        let stream = UnixStream::connect(&sock_path).map_err(|e| CtlError::SocketConnect {
            path: sock_path,
            err: e,
        })?;

        // SIGPIPE is not ignored: the daemon dying mid-conversation kills
        // this one-command-per-process CLI, which is acceptable.

        Self::handshake(stream, &pf.cookie)
    }
}

#[cfg(test)]
pub(crate) mod tests;
