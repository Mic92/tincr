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
//!   ───── connected, c->status.control=true on daemon side ─────
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
//! ## The compat-freedom lever
//!
//! CLI and daemon ship together. The 22-field positional sscanf format
//! is NOT wire-locked — it's a private channel between two halves of
//! one release. The `CtlRequest` enum and framing stay; line bodies
//! are ours. The cookie mechanism (capability auth via fs perms),
//! unix-socket transport, and line-based framing are all kept.
//!
//! ## Why `Read + Write` not `UnixStream`
//!
//! Tests pass a `UnixStream::pair()` half. `connect()` does the OS
//! bits and delegates to `handshake()`; the split is the testable seam.
//!
//! ## Not here
//!
//! Windows TCP fallback: Unix-only for now. Reconnect-on-dead: the
//! readline shell reuses one fd; we're one command per process.

use std::io::{BufRead, BufReader, Read, Write};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::path::Path;

use crate::names::Paths;

/// `request_type` enum. The second int after `CONTROL` in every
/// control line.
///
/// Ints not strings: cheap to format/parse, no compat constraint to
/// change them. The numbers are stable across releases because
/// they're a closed set — new values added at the end, never reordered.
///
/// `REQ_INVALID = -1` is the daemon's error response, not a request
/// the CLI sends. Represented as `Option<CtlRequest>::None` on parse.
///
/// `Restart` and `DumpGraph` are **never sent** and never matched.
/// Dead values. We include them anyway: zero cost, and the gap in
/// the discriminant sequence (2→3, 7→8) would be more surprising
/// than the dead variants.
///
/// `Connect` is dead-on-arrival upstream: the CLI sends it but the
/// daemon has no case for it (falls through to `REQ_INVALID`). We
/// don't bother sending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CtlRequest {
    Stop = 0,
    Reload = 1,
    /// Dead upstream. Daemon never matches it.
    Restart = 2,
    DumpNodes = 3,
    DumpEdges = 4,
    DumpSubnets = 5,
    DumpConnections = 6,
    /// Dead upstream. The CLI synthesizes graph from nodes+edges instead.
    DumpGraph = 7,
    Purge = 8,
    SetDebug = 9,
    Retry = 10,
    /// Dead-on-arrival upstream: daemon has no case — replies `REQ_INVALID`.
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
    pub fn from_i32(n: i32) -> Option<Self> {
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

/// `CONTROL` request type = 18 (count from `ID = 0` through `PACKET`).
///
/// `tinc_proto::request::Request::Control` is the canonical place.
/// We re-declare here because `ctl.rs` doesn't otherwise use
/// `tinc-proto` and one constant isn't worth the dependency edge.
const CONTROL: u8 = 18;
/// `ID` — the greeting opener.
const ID: u8 = 0;
/// `ACK` — the greeting closer.
const ACK: u8 = 4;
/// `TINC_CTL_VERSION_CURRENT`. Hasn't changed since 2007. We send it
/// (the upstream daemon checks it, for as long as we care about
/// cross-compat during transition); our own daemon will check it too.
const CTL_VERSION: u8 = 0;

/// Contents of the pidfile.
///
/// `host` is dropped (Windows TCP fallback); Unix-only daemon path.
/// When/if Windows lands, this grows; the parse already skips it.
///
/// `cookie` is the bearer token. 32 random bytes, hex-encoded. The
/// pidfile is mode 0600 so only the daemon's UID can read it; the
/// cookie is auth-via-fs-perms.
#[derive(Debug)]
pub struct Pidfile {
    pub pid: u32,
    /// Hex string, 64 chars. We *could* decode to `[u8; 32]` but
    /// nothing uses the raw bytes — it goes back on the wire as
    /// the same hex string. Round-tripping through bytes would just
    /// be an opportunity to disagree on case.
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
    /// We're stricter than upstream in one place: `parse::<u32>`
    /// doesn't accept leading `+`/`-`. The daemon never emits `+`,
    /// so the only source of a leading sign is hand-editing.
    /// Stricter is fine.
    ///
    /// # Errors
    /// File open failed, or contents don't match the expected shape.
    /// The C returns `NULL` for both; we distinguish in the message.
    pub fn read(path: &Path) -> Result<Self, CtlError> {
        // Same `read_to_string` shape as everywhere else. The pidfile
        // is one line, ~100 bytes; no streaming needed.
        let s = std::fs::read_to_string(path).map_err(|e| CtlError::PidfileMissing {
            path: path.to_path_buf(),
            err: e,
        })?;

        // Tokenize on whitespace. The literal `port` is checked at
        // token 3.
        let mut tok = s.split_whitespace();
        let pid_s = tok.next().ok_or(CtlError::PidfileMalformed)?;
        let cookie = tok.next().ok_or(CtlError::PidfileMalformed)?;
        // host, "port", port: we don't use them but we *do* check
        // shape. A truncated pidfile (daemon crashed mid-write?)
        // should fail here, not connect with a half-read cookie.
        let _host = tok.next().ok_or(CtlError::PidfileMalformed)?;
        let port_lit = tok.next().ok_or(CtlError::PidfileMalformed)?;
        let port = tok.next().ok_or(CtlError::PidfileMalformed)?;
        if port_lit != "port" {
            return Err(CtlError::PidfileMalformed);
        }

        // u32 covers all real pids; the check for negative is free.
        let pid: u32 = pid_s.parse().map_err(|_| CtlError::PidfileMalformed)?;

        // Cookie length: the daemon *writes* exact-64 (`bin2hex` of
        // 32 bytes); length disagreement = silent auth failure later.
        // Better here. Hex-only check: same reasoning. Non-hex =
        // corruption or hand-editing.
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

/// Errors from connecting to or talking with the daemon. Distinct
/// from `cmd::CmdError` because the messages and recoverability
/// differ — `pidfile missing` means "daemon isn't running", which
/// some callers (`cmd_invite`'s best-effort reload) want to treat
/// as a soft no-op.
///
/// Errors always carry the message; the *caller* decides whether to
/// print (`cmd_reload` prints, `cmd_invite`'s opportunistic reload
/// swallows). Matches call-site control without threading a
/// `verbose` arg through.
// Upstream phrasing where it exists — users grep for these.
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
    /// Pidfile exists but doesn't parse. Daemon crashed mid-write,
    /// or it's from a different tinc version. Upstream conflates this
    /// with missing; we distinguish for hand-crafted-bad-pidfile tests.
    #[error("Could not parse pid file")]
    PidfileMalformed,
    /// `kill(pid, 0)` returned ESRCH. Daemon was running, isn't now,
    /// pidfile is stale. Upstream also unlinks the stale pidfile and
    /// socket here; we don't — the daemon's next start overwrites
    /// the pidfile anyway.
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

/// The connected control socket, plus the daemon's pid (from
/// greeting line 2).
///
/// Generic over the stream so tests can pass `UnixStream::pair()`
/// halves. In production it's always `UnixStream`.
///
/// `BufReader` wraps the reader half. `recvline` and `recvdata`
/// share a buffer: `recvline` might over-read past the `\n` into
/// the start of the next data block. **`BufReader` already solves
/// this** — it IS that shared buffer. `read_line` over-reads into
/// its internal 8KiB; then `read_exact` on the `BufReader` (NOT the
/// inner stream — `BufReader<T>: Read`) drains the internal buffer
/// FIRST. Verified by smoke: `Cursor::new("18 15 7\nLOGDATA")`, one
/// `read_line`, one `read_exact(7)`, both correct.
///
/// Why not `BufWriter`: control commands are fire-and-forget —
/// send one line, expect a response. Buffering would just need a
/// `flush()` after every send. Unbuffered writes are correct.
///
/// Not `Debug` — wrapping arbitrary `S` would need `S: Debug`,
/// and you don't usefully `{:?}` a socket anyway. Tests use
/// `unwrap_err()` (which needs `Debug` on the *error* type, not
/// this).
pub struct CtlSocket<S: Read + Write> {
    /// Reader half. Buffered for `read_line`.
    reader: BufReader<ReadHalf<S>>,
    /// Writer half. Unbuffered.
    writer: WriteHalf<S>,
    /// Daemon's pid, from greeting line 2. `cmd_pid` prints this;
    /// nothing else uses it.
    pub pid: u32,
}

/// Split a `Read + Write` into halves without `try_clone` (which
/// `UnixStream` has but generic `S` doesn't). The trick: store the
/// stream in an `Rc<RefCell<S>>` and have both halves borrow it.
///
/// Why not `&mut S` for both: `BufReader` wants to own its inner
/// reader. Why not `try_clone`: tests pass non-`UnixStream` mocks.
///
/// Why this works for our use: control I/O is strictly alternating
/// (send a line, recv a line). Never concurrent borrow. The
/// `RefCell` panic-on-conflict is unreachable in correct code; if
/// it fires, the code is wrong, and we want to know.
///
/// (The `tokio` answer is `split()`. We're sync.)
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
    /// Test seam: wrap an existing stream WITHOUT doing the
    /// handshake. The unit tests for `cmd::stream` (and `cmd::top`
    /// later, if `handle_key` becomes testable) want to feed
    /// canned daemon-output into a `CtlSocket` and observe the
    /// loop's behavior. They don't want to mock the greeting
    /// exchange every time.
    ///
    /// `pid` is set to 0 (meaningless; only `cmd_pid` reads it).
    ///
    /// `pub(crate)` so test modules in `cmd::*` can call it. The
    /// `Rc<RefCell<S>>` is threaded through so the test can ALSO
    /// hold a clone and inspect what was written (`shared.borrow().
    /// wr` for a `Duplex`-shaped `S`). The OWNERSHIP transfer:
    /// the caller makes the `Rc`, passes a clone here, keeps a
    /// clone. Both halves see the same stream.
    ///
    /// `#[cfg(test)]` because the consumer is `cmd::stream::tests`
    /// — a DIFFERENT module's test sub-module. `cfg(test)` applies
    /// to the whole CRATE under `cargo test`, not just `mod tests`,
    /// so this is visible from `cmd::stream::tests` but compiled
    /// out of release builds. `pub(crate)` for cross-module reach.
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
    /// Separate from `connect()` because tests pass a mock stream.
    /// The OS bits (pidfile read, kill check, socket connect) live
    /// in `connect()`; this is just the protocol.
    ///
    /// The cookie is passed in (not read from a `Paths`) because
    /// tests synthesize it. In production `connect()` reads it from
    /// the pidfile and forwards.
    ///
    /// # Errors
    /// `Greeting` if the daemon's response doesn't match the
    /// expected shape. Wrong cookie → daemon closes after our send,
    /// next recv returns 0 → `Greeting("Cannot read greeting...")`.
    pub fn handshake(stream: S, cookie: &str) -> Result<Self, CtlError> {
        let shared = Rc::new(RefCell::new(stream));
        let mut reader = BufReader::new(ReadHalf(Rc::clone(&shared)));
        let mut writer = WriteHalf(shared);

        // ─── Send ID
        // The `^` prefix is what routes this to the control path in
        // `id_h`. Without it, the daemon would try to parse `cookie`
        // as a node name.
        writeln!(writer, "{ID} ^{cookie} {CTL_VERSION}").map_err(CtlError::Io)?;

        // ─── Recv line 1: daemon's send_id()
        // `"0 <daemon-name> <maj>.<min>"`. The daemon sends this
        // *after* our ID arrives — the unix-socket connection has no
        // outgoing flag set, so the daemon's ID is reactive. The
        // version field is `protocol_major.protocol_minor`, not the
        // control version — that's in line 2.
        //
        // We don't *use* anything from line 1. Just check shape.
        let line1 = recv_one(&mut reader, "Cannot read greeting from control socket")?;
        let mut t1 = line1.split_ascii_whitespace();
        if t1.next() != Some("0") {
            // Not an ID. Daemon speaking wrong protocol, or we
            // connected to something that isn't tincd.
            return Err(CtlError::Greeting(format!(
                "Cannot read greeting from control socket: unexpected response {line1:?}"
            )));
        }
        // Name and version ignored — the next line is where the action is.

        // ─── Recv line 2: ACK with control-ver and pid
        // Shape: `"4 0 <pid>"`. The `4` is ACK; `0` is control-ver
        // (the daemon sends its own `TINC_CTL_VERSION_CURRENT`).
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

    /// Receive and parse a one-shot ack. The pattern every simple
    /// command does.
    ///
    /// Returns the `result` int. `0` = success, anything else =
    /// daemon-side failure. `REQ_SET_DEBUG` repurposes `result` as
    /// "previous debug level" (always succeeds), so callers shouldn't
    /// blindly `if result != 0 { fail }` — check the meaning per req.
    ///
    /// # Errors
    /// `Io` if recv fails. `Greeting` (reusing the variant) if the
    /// response doesn't have the right shape — wrong code, wrong
    /// request echoed back, can't parse. The variant name is
    /// imperfect ("greeting" for a post-greeting error) but adding
    /// `BadResponse(String)` would be a fourth string-carrying
    /// variant doing the same thing. The Display impl carries the
    /// distinction.
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

    /// Receive one line, raw. For dump commands where the parsing is
    /// per-type and lives in the caller. Returns `None` on EOF (daemon
    /// closed cleanly — `cmd_stop` expects this).
    ///
    /// We distinguish `Ok(None)` for EOF (clean) from `Err` for I/O.
    /// The `cmd_stop` "wait for daemon to close" loop wants the
    /// former; everything else wants the latter to surface.
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

    /// Receive one dump row: read a line, parse the `"18 N"` prefix,
    /// check for the 2-int terminator, hand back `(kind, body)`.
    ///
    /// Daemon-side dump functions all share one shape:
    ///
    /// ```text
    ///   for x in tree {
    ///     send_request(c, "18 N <fields>")    // one row
    ///   }
    ///   send_request(c, "18 N")               // terminator
    /// ```
    ///
    /// The terminator is the SAME prefix with NO body. We're
    /// explicit: empty body → `End`.
    ///
    /// `Row(kind, body)` carries the request type because graph mode
    /// fires TWO dumps (`DUMP_NODES` then `DUMP_EDGES`) and reads
    /// both responses with one loop, dispatching per-row.
    ///
    /// `body` is a `String`, not `&str`, because the caller passes
    /// it to `Tok::new` which borrows for the parse lifetime, and
    /// we can't return a borrow into our `BufReader`'s buffer
    /// across `read_line` calls. The allocation is per-row but
    /// dump output is dozens of rows, not millions.
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

        // ─── Prefix: `18 N`
        // The body MUST stay byte-exact: `Tok` will re-tokenize it,
        // and a hostname like `unknown port unknown` has the literal
        // `port` as a token. Don't collapse spaces; slice past the
        // second one.
        let bad = || CtlError::Greeting("Unable to parse dump from tincd.".to_owned());

        let (code_s, after_code) = line.split_once(' ').ok_or_else(bad)?;
        if code_s.parse::<u8>().ok() != Some(CONTROL) {
            // We tighten over upstream: wrong code → row-level
            // failure (upstream would fall into the per-type switch
            // with whatever `req` parsed as).
            return Err(bad());
        }

        // ─── Request type, then body or terminator
        // `split_once` for the SECOND space. None → no body →
        // terminator. Some("") (trailing space) → also terminator.
        match after_code.split_once(' ') {
            None => {
                // "18 3\n" — the trailing \n is already stripped.
                // Just the type. Terminator.
                let req = after_code.parse::<i32>().map_err(|_| bad())?;
                let kind = CtlRequest::from_i32(req).ok_or_else(bad)?;
                Ok(DumpRow::End(kind))
            }
            Some((req_s, "")) => {
                // "18 3 " — trailing space. Daemon doesn't emit
                // this. Same as terminator.
                let req = req_s.parse::<i32>().map_err(|_| bad())?;
                let kind = CtlRequest::from_i32(req).ok_or_else(bad)?;
                Ok(DumpRow::End(kind))
            }
            Some((req_s, body)) => {
                let req = req_s.parse::<i32>().map_err(|_| bad())?;
                let kind = CtlRequest::from_i32(req).ok_or_else(bad)?;
                // body is the rest of the line, byte-exact. The
                // caller hands it to `Tok::new`.
                Ok(DumpRow::Row(kind, body.to_owned()))
            }
        }
    }

    /// Receive exactly `len` raw bytes after a header line.
    ///
    /// `BufReader<T>: Read`, and its `read` impl drains the internal
    /// buffer before touching `T`. `read_exact` on a `BufReader` IS
    /// the shared-buffer semantics. (See the struct doc-comment.)
    ///
    /// `buf.len()` IS the requested length — the caller sizes it.
    /// Mirrors `read_exact`'s contract.
    ///
    /// Why not return `Vec<u8>`: `cmd_log` and `cmd_pcap` both
    /// write-and-discard. A reused `Vec` avoids per-packet alloc.
    ///
    /// EINTR retry: `read_exact` already loops on `Interrupted`.
    ///
    /// # Errors
    /// `Io` on read failure or unexpected EOF mid-data. `read_exact`
    /// returns `UnexpectedEof` if the daemon dies between the header
    /// and the data; we surface it as `Io` like every other socket
    /// error.
    pub fn recv_data(&mut self, buf: &mut [u8]) -> Result<(), CtlError> {
        self.reader.read_exact(buf).map_err(CtlError::Io)
    }
}

/// One line from a dump response. We make the row/terminator
/// distinction a type so the caller's loop is `match` not `if`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DumpRow {
    /// `"18 N FIELDS"` — one item. Body is `FIELDS` exactly as
    /// written, ready for `Tok::new`. The `CtlRequest` is for the
    /// graph-mode loop where nodes and edges interleave; single-type
    /// dumps can ignore it (or assert it's the expected one).
    Row(CtlRequest, String),

    /// `"18 N"` — terminator. Per-dump-type, so graph mode (which
    /// fires NODES then EDGES) sees TWO of these and exits on the
    /// second. The caller checks which `End` it got.
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
    /// The full OS-side connect.
    ///
    /// Reads the pidfile, checks the daemon is alive, connects the
    /// unix socket, does the greeting. The four points of failure
    /// each have their own `CtlError` variant.
    ///
    /// Upstream also unlinks stale pidfile + socket on `DaemonDead`.
    /// We don't — the daemon's next start overwrites the pidfile
    /// anyway. If we add it, it's a separate `cleanup_stale` fn.
    ///
    /// `paths` must have had `resolve_runtime()` called. The panic
    /// from `pidfile()` is the assertion.
    ///
    /// # Errors
    /// See `CtlError` variants. Each failure mode has its own.
    pub fn connect(paths: &Paths) -> Result<Self, CtlError> {
        // ─── Read pidfile
        let pidfile_path = paths.pidfile();
        let pf = Pidfile::read(pidfile_path)?;

        // ─── kill(pid, 0) liveness check
        // `pid == 0`: `kill(0, 0)` would signal our own process
        // group, masking "no daemon" as "daemon alive". A zero pid
        // in the pidfile means corrupted write.
        //
        // `kill` can also fail with EPERM (daemon running as a
        // different user). EPERM means *something* is at that pid —
        // "alive enough" for the connect attempt. Only ESRCH →
        // DaemonDead. Pid range: `try_from` rather than `as` so a
        // corrupted pidfile with pid > 2^31 lands on the `== 0`
        // check instead of wrapping negative and probing some
        // unrelated process.
        let raw_pid = i32::try_from(pf.pid).unwrap_or(0);
        if raw_pid == 0 {
            return Err(CtlError::DaemonDead { pid: pf.pid });
        }
        // EPERM → something's there, proceed. Other errors are
        // exotic (EINVAL on a bad signal? we sent None). Proceed
        // either way; the socket connect will fail more usefully.
        // Hence: only ESRCH is fatal.
        if let Err(nix::errno::Errno::ESRCH) = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(raw_pid),
            None, // sig=0, the probe signal
        ) {
            return Err(CtlError::DaemonDead { pid: pf.pid });
        }

        // ─── Connect socket
        // UnixStream::connect surfaces ENAMETOOLONG (path-too-long
        // for the sockaddr) as an io::Error; wrapped in SocketConnect.
        let sock_path = paths.unix_socket();
        let stream = UnixStream::connect(&sock_path).map_err(|e| CtlError::SocketConnect {
            path: sock_path,
            err: e,
        })?;

        // ─── SO_NOSIGPIPE (NOT done)
        // The daemon dying mid-conversation → our write returns
        // EPIPE → SIGPIPE → we exit. That's fine for a CLI tool
        // (one command per process). Upstream handles it for the
        // readline shell mode; if shell mode lands, `signal(SIGPIPE,
        // SIG_IGN)` at binary startup. Not here.

        // ─── Greeting
        Self::handshake(stream, &pf.cookie)
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::thread;

    /// `CtlRequest` discriminants. Verified against upstream at
    /// commit time.
    #[test]
    fn request_discriminants() {
        assert_eq!(CtlRequest::Stop as u8, 0);
        assert_eq!(CtlRequest::Reload as u8, 1);
        assert_eq!(CtlRequest::Restart as u8, 2);
        assert_eq!(CtlRequest::DumpNodes as u8, 3);
        assert_eq!(CtlRequest::DumpEdges as u8, 4);
        assert_eq!(CtlRequest::DumpSubnets as u8, 5);
        assert_eq!(CtlRequest::DumpConnections as u8, 6);
        assert_eq!(CtlRequest::DumpGraph as u8, 7);
        assert_eq!(CtlRequest::Purge as u8, 8);
        assert_eq!(CtlRequest::SetDebug as u8, 9);
        assert_eq!(CtlRequest::Retry as u8, 10);
        assert_eq!(CtlRequest::Connect as u8, 11);
        assert_eq!(CtlRequest::Disconnect as u8, 12);
        assert_eq!(CtlRequest::DumpTraffic as u8, 13);
        assert_eq!(CtlRequest::Pcap as u8, 14);
        assert_eq!(CtlRequest::Log as u8, 15);
    }

    /// Round-trip through `from_i32`. Unknown → None.
    #[test]
    fn request_from_i32() {
        for i in 0..16 {
            let r = CtlRequest::from_i32(i).unwrap();
            assert_eq!(r as i32, i);
        }
        assert_eq!(CtlRequest::from_i32(-1), None);
        assert_eq!(CtlRequest::from_i32(16), None);
        assert_eq!(CtlRequest::from_i32(999), None);
    }

    /// Pidfile parse, happy path. `"<pid> <cookie> <host> port <port>\n"`.
    #[test]
    fn pidfile_parse() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pid");
        let cookie = "a".repeat(64);
        std::fs::write(&path, format!("12345 {cookie} 127.0.0.1 port 655\n")).unwrap();

        let pf = Pidfile::read(&path).unwrap();
        assert_eq!(pf.pid, 12345);
        assert_eq!(pf.cookie, cookie);
        assert_eq!(pf.port, "655");
    }

    /// Pidfile validation: cookie must be exactly 64 hex chars.
    /// We tighten over upstream here.
    #[test]
    fn pidfile_cookie_validated() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pid");

        // Too short.
        std::fs::write(&path, "1 abc 127.0.0.1 port 655\n").unwrap();
        assert!(matches!(
            Pidfile::read(&path),
            Err(CtlError::PidfileMalformed)
        ));

        // Non-hex.
        let bad = "z".repeat(64);
        std::fs::write(&path, format!("1 {bad} 127.0.0.1 port 655\n")).unwrap();
        assert!(matches!(
            Pidfile::read(&path),
            Err(CtlError::PidfileMalformed)
        ));

        // Exactly right (lowercase hex, 64 chars).
        let good = "0123456789abcdef".repeat(4);
        std::fs::write(&path, format!("1 {good} 127.0.0.1 port 655\n")).unwrap();
        assert!(Pidfile::read(&path).is_ok());

        // Uppercase hex also passes — `is_ascii_hexdigit` accepts
        // both. The daemon writes lowercase, but a hand-edited
        // pidfile shouldn't be rejected on case. The greeting compare
        // is case-sensitive, so uppercase would *fail auth* — but
        // that's a different, more useful error.
        let upper = "0123456789ABCDEF".repeat(4);
        std::fs::write(&path, format!("1 {upper} 127.0.0.1 port 655\n")).unwrap();
        assert!(Pidfile::read(&path).is_ok());
    }

    /// Pidfile shape: missing fields fail.
    #[test]
    fn pidfile_shape_enforced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pid");
        let cookie = "f".repeat(64);

        // Missing port: only 3 tokens after pid.
        std::fs::write(&path, format!("1 {cookie} 127.0.0.1\n")).unwrap();
        assert!(matches!(
            Pidfile::read(&path),
            Err(CtlError::PidfileMalformed)
        ));

        // `port` literal wrong.
        std::fs::write(&path, format!("1 {cookie} 127.0.0.1 prt 655\n")).unwrap();
        assert!(matches!(
            Pidfile::read(&path),
            Err(CtlError::PidfileMalformed)
        ));

        // pid not a number.
        std::fs::write(&path, format!("notapid {cookie} 127.0.0.1 port 655\n")).unwrap();
        assert!(matches!(
            Pidfile::read(&path),
            Err(CtlError::PidfileMalformed)
        ));
    }

    /// Pidfile missing → distinct error.
    #[test]
    fn pidfile_missing() {
        let err = Pidfile::read(std::path::Path::new("/nonexistent/pidfile")).unwrap_err();
        assert!(matches!(err, CtlError::PidfileMissing { .. }));
        assert!(err.to_string().contains("Could not open pid file"));
    }

    // The fake daemon. A thread doing the greeting dance + canned
    // responses on a UnixStream::pair() half.
    //
    // Why a thread, not an in-process pump like join's: the control
    // protocol is *blocking* — handshake() blocks on recv until the
    // greeting arrives. The SPTPS pump worked because Sptps::receive
    // returns "consumed 0, no progress" on partial input. read_line
    // doesn't; it blocks. So: thread.
    //
    // Why this is fine: UnixStream::pair() is in-process (no socket
    // file, no port, no race with parallel tests). The thread is
    // joined before the test returns (no leak).

    /// Spawn a fake daemon on `theirs`. Reads the ID line (asserts
    /// the cookie), sends greeting line 1 + 2, then runs `serve` to
    /// handle whatever the test sends.
    ///
    /// `serve` gets a `BufReader` and the raw write half. It can do
    /// `read_line` and `writeln!`. When it returns, the daemon side
    /// drops, closing the socket — the CLI side sees EOF.
    fn fake_daemon<F>(
        theirs: UnixStream,
        expected_cookie: &str,
        daemon_pid: u32,
        serve: F,
    ) -> thread::JoinHandle<()>
    where
        F: FnOnce(&mut BufReader<&UnixStream>, &mut &UnixStream) + Send + 'static,
    {
        let expected_cookie = expected_cookie.to_owned();
        thread::spawn(move || {
            // `&UnixStream` is `Read + Write` (the impl is on the
            // reference, not the owned type — same trick as `&File`).
            // Two `&theirs` borrows are fine because they're both
            // shared. The `&mut &UnixStream` for the writer is a
            // mutable binding holding a shared reference; `writeln!`
            // needs `&mut impl Write`, and `impl Write` is the
            // `&UnixStream`, not `UnixStream`.
            let read = &theirs;
            let mut write = &theirs;
            let mut br = BufReader::new(read);

            // ─── Recv ID, check cookie
            let mut line = String::new();
            br.read_line(&mut line).unwrap();
            // Shape: "0 ^COOKIE 0\n".
            let trimmed = line.trim_end();
            let parts: Vec<_> = trimmed.split(' ').collect();
            assert_eq!(parts.len(), 3, "ID line: {trimmed:?}");
            assert_eq!(parts[0], "0");
            assert_eq!(parts[1], format!("^{expected_cookie}"));
            assert_eq!(parts[2], "0");

            // ─── Send greeting line 1 (send_id)
            // The CLI ignores everything after the first int.
            writeln!(write, "0 fakedaemon 17.7").unwrap();

            // ─── Send greeting line 2 (ACK + ctl-ver + pid)
            writeln!(write, "4 0 {daemon_pid}").unwrap();

            // ─── Hand off to test-specific serving
            serve(&mut br, &mut write);
            // Drop closes.
        })
    }

    /// Handshake against the fake daemon. The minimum: connect,
    /// greet, check pid. No commands sent.
    #[test]
    fn handshake_smoke() {
        let cookie = "0123456789abcdef".repeat(4);
        let (ours, theirs) = UnixStream::pair().unwrap();

        let daemon = fake_daemon(theirs, &cookie, 9999, |_br, _w| {
            // No serving — drop immediately after greeting.
        });

        let ctl = CtlSocket::handshake(ours, &cookie).unwrap();
        assert_eq!(ctl.pid, 9999);

        daemon.join().unwrap();
    }

    /// Wrong cookie → daemon thread panics (assert fails). In a
    /// real daemon, `id_h` would `return false` and the meta loop
    /// drops the connection; CLI side sees EOF on recv → Greeting
    /// error. We test the latter by having the fake just drop.
    #[test]
    fn handshake_bad_cookie_eof() {
        let real_cookie = "a".repeat(64);
        let wrong_cookie = "b".repeat(64);
        let (ours, theirs) = UnixStream::pair().unwrap();

        // Fake checks for `wrong_cookie`, we send `real_cookie`.
        // The fake's assert_eq on the cookie panics; thread dies;
        // socket closes; our recv sees EOF.
        //
        // We *want* the panic — that's the test's "daemon rejected
        // us" signal. `join().unwrap_err()` checks it happened.
        let daemon = fake_daemon(theirs, &wrong_cookie, 1, |_, _| {});

        let Err(err) = CtlSocket::handshake(ours, &real_cookie) else {
            panic!("expected handshake to fail");
        };
        assert!(matches!(err, CtlError::Greeting(_)));
        assert!(err.to_string().contains("Cannot read greeting"));

        // The fake panicked on the assert. Expected.
        assert!(daemon.join().is_err());
    }

    /// Malformed greeting line 1 → Greeting error. Daemon speaking
    /// wrong protocol (or it's not tincd).
    #[test]
    fn handshake_bad_line1() {
        let cookie = "c".repeat(64);
        let (ours, theirs) = UnixStream::pair().unwrap();

        let daemon = thread::spawn(move || {
            let mut br = BufReader::new(&theirs);
            let mut line = String::new();
            br.read_line(&mut line).unwrap();
            // Send a non-ID first int.
            let mut w = &theirs;
            writeln!(w, "999 garbage").unwrap();
        });

        let Err(err) = CtlSocket::handshake(ours, &cookie) else {
            panic!("expected handshake to fail");
        };
        assert!(matches!(err, CtlError::Greeting(_)));

        daemon.join().unwrap();
    }

    /// One-shot RPC: send a request, get an ack. The reload pattern.
    #[test]
    fn send_and_ack() {
        let cookie = "d".repeat(64);
        let (ours, theirs) = UnixStream::pair().unwrap();

        let daemon = fake_daemon(theirs, &cookie, 1, |br, w| {
            let mut line = String::new();
            br.read_line(&mut line).unwrap();
            // Expect "18 1\n" (CONTROL REQ_RELOAD).
            assert_eq!(line.trim_end(), "18 1");
            // Ack: "18 1 0\n" (errcode 0).
            writeln!(w, "18 1 0").unwrap();
        });

        let mut ctl = CtlSocket::handshake(ours, &cookie).unwrap();
        ctl.send(CtlRequest::Reload).unwrap();
        let result = ctl.recv_ack(CtlRequest::Reload).unwrap();
        assert_eq!(result, 0);

        daemon.join().unwrap();
    }

    /// Ack with nonzero result. `REQ_RELOAD` when reload failed.
    /// The CLI doesn't error here — `recv_ack` returns the result,
    /// caller decides.
    #[test]
    fn ack_nonzero_result() {
        let cookie = "e".repeat(64);
        let (ours, theirs) = UnixStream::pair().unwrap();

        let daemon = fake_daemon(theirs, &cookie, 1, |br, w| {
            let mut line = String::new();
            br.read_line(&mut line).unwrap();
            // Daemon-side reload failed → errcode 1.
            writeln!(w, "18 1 1").unwrap();
        });

        let mut ctl = CtlSocket::handshake(ours, &cookie).unwrap();
        ctl.send(CtlRequest::Reload).unwrap();
        let result = ctl.recv_ack(CtlRequest::Reload).unwrap();
        // Nonzero — caller handles.
        assert_eq!(result, 1);

        daemon.join().unwrap();
    }

    /// `send_int`: `REQ_SET_DEBUG` with the level argument.
    #[test]
    fn send_with_int_arg() {
        let cookie = "f".repeat(64);
        let (ours, theirs) = UnixStream::pair().unwrap();

        let daemon = fake_daemon(theirs, &cookie, 1, |br, w| {
            let mut line = String::new();
            br.read_line(&mut line).unwrap();
            // "18 9 5\n" — CONTROL SET_DEBUG level=5.
            assert_eq!(line.trim_end(), "18 9 5");
            // Ack with previous level (3). REQ_SET_DEBUG repurposes
            // the result field: send old level *before* updating.
            writeln!(w, "18 9 3").unwrap();
        });

        let mut ctl = CtlSocket::handshake(ours, &cookie).unwrap();
        ctl.send_int(CtlRequest::SetDebug, 5).unwrap();
        let prev = ctl.recv_ack(CtlRequest::SetDebug).unwrap();
        assert_eq!(prev, 3);

        daemon.join().unwrap();
    }

    /// `send_str`: `REQ_DISCONNECT` with a node name.
    #[test]
    fn send_with_str_arg() {
        let cookie = "0".repeat(64);
        let (ours, theirs) = UnixStream::pair().unwrap();

        let daemon = fake_daemon(theirs, &cookie, 1, |br, w| {
            let mut line = String::new();
            br.read_line(&mut line).unwrap();
            // "18 12 alice\n" — CONTROL DISCONNECT name=alice.
            assert_eq!(line.trim_end(), "18 12 alice");
            // Ack: 0 = found and disconnected. -2 would be not-found.
            writeln!(w, "18 12 0").unwrap();
        });

        let mut ctl = CtlSocket::handshake(ours, &cookie).unwrap();
        ctl.send_str(CtlRequest::Disconnect, "alice").unwrap();
        let result = ctl.recv_ack(CtlRequest::Disconnect).unwrap();
        assert_eq!(result, 0);

        daemon.join().unwrap();
    }

    /// `recv_line` raw: the dump-style multi-line response. Read
    /// until 2-int terminator, then EOF.
    #[test]
    fn recv_lines_until_eof() {
        let cookie = "1".repeat(64);
        let (ours, theirs) = UnixStream::pair().unwrap();

        let daemon = fake_daemon(theirs, &cookie, 1, |br, w| {
            let mut line = String::new();
            br.read_line(&mut line).unwrap();
            assert_eq!(line.trim_end(), "18 3"); // DUMP_NODES
            // Three nodes, then terminator. Field content is
            // arbitrary — we're testing the line-at-a-time machinery,
            // not the parse (that's per-dump-type, lands later).
            writeln!(w, "18 3 alice somefield").unwrap();
            writeln!(w, "18 3 bob otherfield").unwrap();
            writeln!(w, "18 3 carol third").unwrap();
            writeln!(w, "18 3").unwrap(); // 2-int terminator
            // Drop → EOF.
        });

        let mut ctl = CtlSocket::handshake(ours, &cookie).unwrap();
        ctl.send(CtlRequest::DumpNodes).unwrap();

        // Collect until terminator. Same loop shape as cmd_dump.
        let mut rows = Vec::new();
        loop {
            let line = ctl.recv_line().unwrap().expect("daemon dropped early");
            let n_tokens = line.split_ascii_whitespace().count();
            if n_tokens == 2 {
                break; // terminator
            }
            rows.push(line);
        }
        assert_eq!(rows.len(), 3);
        assert!(rows[0].contains("alice"));

        // Next recv → EOF (daemon dropped).
        assert_eq!(ctl.recv_line().unwrap(), None);

        daemon.join().unwrap();
    }

    /// `recv_ack` rejects mismatched request echo. Daemon sent ack
    /// for `REQ_PURGE`, we expected `REQ_RELOAD`. Either a daemon bug
    /// or response interleaving (which doesn't happen in the
    /// strictly-alternating protocol, but defense).
    #[test]
    fn recv_ack_wrong_type() {
        let cookie = "2".repeat(64);
        let (ours, theirs) = UnixStream::pair().unwrap();

        let daemon = fake_daemon(theirs, &cookie, 1, |br, w| {
            let mut line = String::new();
            br.read_line(&mut line).unwrap();
            // Ack PURGE (8), not RELOAD (1).
            writeln!(w, "18 8 0").unwrap();
        });

        let mut ctl = CtlSocket::handshake(ours, &cookie).unwrap();
        ctl.send(CtlRequest::Reload).unwrap();
        let err = ctl.recv_ack(CtlRequest::Reload).unwrap_err();
        assert!(matches!(err, CtlError::Greeting(_)));

        daemon.join().unwrap();
    }

    /// The stop pattern: send `REQ_STOP`, drain until EOF. The daemon
    /// acks then exits, closing the socket.
    #[test]
    fn stop_drains_to_eof() {
        let cookie = "3".repeat(64);
        let (ours, theirs) = UnixStream::pair().unwrap();

        let daemon = fake_daemon(theirs, &cookie, 1, |br, w| {
            let mut line = String::new();
            br.read_line(&mut line).unwrap();
            assert_eq!(line.trim_end(), "18 0"); // STOP
            // Ack, then drop. The ack is sent, then the event loop
            // exits, connections close.
            writeln!(w, "18 0 0").unwrap();
            // Thread returns → `theirs` drops → EOF.
        });

        let mut ctl = CtlSocket::handshake(ours, &cookie).unwrap();
        ctl.send(CtlRequest::Stop).unwrap();

        // Drain. We see the ack line, then EOF. Read until None.
        let mut drained = 0;
        while ctl.recv_line().unwrap().is_some() {
            drained += 1;
        }
        assert_eq!(drained, 1); // the ack

        daemon.join().unwrap();
    }

    // ─── recv_row: the dump prefix-strip + terminator detect
    //
    // Same harness as `recv_lines_until_eof`, but using the typed
    // `recv_row` instead of hand-tokenizing. The parse step (body →
    // NodeRow etc.) lives in cmd::dump tests; this is just the
    // "18 N " prefix and the End vs Row distinction.

    /// Three rows, terminator. The body is byte-exact: spaces inside
    /// `"10.0.0.1 port 655"` survive.
    #[test]
    fn recv_row_basic() {
        let cookie = "2".repeat(64);
        let (ours, theirs) = UnixStream::pair().unwrap();

        let daemon = fake_daemon(theirs, &cookie, 1, |br, w| {
            let mut line = String::new();
            br.read_line(&mut line).unwrap();
            assert_eq!(line.trim_end(), "18 3");
            // Body with embedded `port` literal — `recv_row` must
            // NOT touch it. The cmd::dump parse re-tokenizes.
            writeln!(w, "18 3 alice 10.0.0.1 port 655 fields").unwrap();
            writeln!(w, "18 3 bob unknown port unknown fields").unwrap();
            writeln!(w, "18 3").unwrap();
        });

        let mut ctl = CtlSocket::handshake(ours, &cookie).unwrap();
        ctl.send(CtlRequest::DumpNodes).unwrap();

        // Row 1: kind = DumpNodes, body byte-exact.
        let r1 = ctl.recv_row().unwrap();
        assert_eq!(
            r1,
            DumpRow::Row(
                CtlRequest::DumpNodes,
                "alice 10.0.0.1 port 655 fields".into()
            )
        );
        // Row 2: same. The double-space wouldn't survive a
        // re-tokenize-then-join; but recv_row slices, doesn't
        // tokenize, so single spaces stay single spaces. (The
        // body never HAS double spaces — daemon's printf has
        // single — but the slicing approach is correct anyway.)
        let r2 = ctl.recv_row().unwrap();
        assert_eq!(
            r2,
            DumpRow::Row(
                CtlRequest::DumpNodes,
                "bob unknown port unknown fields".into()
            )
        );
        // Terminator.
        let r3 = ctl.recv_row().unwrap();
        assert_eq!(r3, DumpRow::End(CtlRequest::DumpNodes));

        daemon.join().unwrap();
    }

    /// EOF before terminator → error. Daemon crashed.
    #[test]
    fn recv_row_eof_mid_dump() {
        let cookie = "3".repeat(64);
        let (ours, theirs) = UnixStream::pair().unwrap();

        let daemon = fake_daemon(theirs, &cookie, 1, |br, w| {
            let mut line = String::new();
            br.read_line(&mut line).unwrap();
            // One row, then DROP without terminator.
            writeln!(w, "18 3 alice partial").unwrap();
            // ← no "18 3\n". Socket closes when |br, w| returns.
        });

        let mut ctl = CtlSocket::handshake(ours, &cookie).unwrap();
        ctl.send(CtlRequest::DumpNodes).unwrap();

        // First recv: the partial row. Fine.
        let r1 = ctl.recv_row().unwrap();
        assert!(matches!(r1, DumpRow::Row(CtlRequest::DumpNodes, _)));
        // Second: EOF → error, not Ok(None).
        let err = ctl.recv_row().unwrap_err();
        assert!(matches!(err, CtlError::Greeting(m) if m.contains("Error receiving dump")));

        daemon.join().unwrap();
    }

    /// Wrong code (`"19 3 ..."`) → error. We tighten over upstream:
    /// a non-18 prefix is corruption.
    #[test]
    fn recv_row_bad_code() {
        let cookie = "4".repeat(64);
        let (ours, theirs) = UnixStream::pair().unwrap();

        let daemon = fake_daemon(theirs, &cookie, 1, |br, w| {
            let mut line = String::new();
            br.read_line(&mut line).unwrap();
            // 19 is not CONTROL.
            writeln!(w, "19 3 garbage").unwrap();
        });

        let mut ctl = CtlSocket::handshake(ours, &cookie).unwrap();
        ctl.send(CtlRequest::DumpNodes).unwrap();

        let err = ctl.recv_row().unwrap_err();
        assert!(matches!(err, CtlError::Greeting(m) if m.contains("Unable to parse dump")));

        daemon.join().unwrap();
    }

    /// Graph mode: TWO sends, TWO terminators. The first End
    /// (`DumpNodes`) doesn't end the loop — caller checks which kind.
    /// `recv_row` itself doesn't track state; it just hands back
    /// (kind, body) per row. The CALLER's loop knows graph mode
    /// continues past the first End. This test is the daemon side
    /// of that contract: send both responses, both terminators.
    #[test]
    fn recv_row_graph_two_terminators() {
        let cookie = "5".repeat(64);
        let (ours, theirs) = UnixStream::pair().unwrap();

        let daemon = fake_daemon(theirs, &cookie, 1, |br, w| {
            let mut line = String::new();
            br.read_line(&mut line).unwrap();
            assert_eq!(line.trim_end(), "18 3"); // DUMP_NODES
            line.clear();
            br.read_line(&mut line).unwrap();
            assert_eq!(line.trim_end(), "18 4"); // DUMP_EDGES

            // Daemon responds in order. First nodes (1 row + term):
            writeln!(w, "18 3 alice fields").unwrap();
            writeln!(w, "18 3").unwrap();
            // Then edges (1 row + term):
            writeln!(w, "18 4 alice bob fields").unwrap();
            writeln!(w, "18 4").unwrap();
        });

        let mut ctl = CtlSocket::handshake(ours, &cookie).unwrap();
        // Graph mode sends BOTH. The daemon doesn't pipeline
        // (strictly request-response), but TCP buffers the second
        // send while the daemon is still writing the first response.
        ctl.send(CtlRequest::DumpNodes).unwrap();
        ctl.send(CtlRequest::DumpEdges).unwrap();

        // Row, End(Nodes), Row, End(Edges) — in that order.
        assert!(matches!(
            ctl.recv_row().unwrap(),
            DumpRow::Row(CtlRequest::DumpNodes, _)
        ));
        assert_eq!(ctl.recv_row().unwrap(), DumpRow::End(CtlRequest::DumpNodes));
        assert!(matches!(
            ctl.recv_row().unwrap(),
            DumpRow::Row(CtlRequest::DumpEdges, _)
        ));
        assert_eq!(ctl.recv_row().unwrap(), DumpRow::End(CtlRequest::DumpEdges));

        daemon.join().unwrap();
    }

    /// `"18 3 "` with trailing space (daemon never emits) →
    /// terminator. Empty body → End.
    #[test]
    fn recv_row_trailing_space_is_terminator() {
        let cookie = "6".repeat(64);
        let (ours, theirs) = UnixStream::pair().unwrap();

        let daemon = fake_daemon(theirs, &cookie, 1, |_br, w| {
            // Trailing space after the type. Daemon's printf doesn't
            // emit this; defensive against hand-crafted socket input.
            writeln!(w, "18 3 ").unwrap();
        });

        let mut ctl = CtlSocket::handshake(ours, &cookie).unwrap();
        // No send needed — we're just reading what's in the buffer.
        // (Real usage would send first, but recv_row doesn't track
        // that.)
        let r = ctl.recv_row().unwrap();
        assert_eq!(r, DumpRow::End(CtlRequest::DumpNodes));

        daemon.join().unwrap();
    }

    /// `recv_data` after `recv_line`: the shared-buffer concern.
    ///
    /// Daemon writes header + data in ONE syscall (it doesn't, but
    /// TCP can coalesce). `BufReader` reads it ALL into its 8KiB
    /// buffer on the first `read_line`. The data is now in the
    /// `BufReader`'s buffer, not the socket. `recv_data` must see it.
    ///
    /// THE test for the plan's "blocked on draining `buffer()`".
    /// `BufReader<T>: Read` is what makes this work — `read_exact`
    /// drains the buffer first. The test pins it: if someone
    /// "optimizes" `recv_data` to `self.reader.get_mut().0.borrow_
    /// mut().read_exact()` (bypassing `BufReader`), this fails.
    ///
    /// `Cursor<Vec<u8>>` is the in-memory stream. ONE buffer, two
    /// records (header + data each), back-to-back, no separator.
    /// Exactly what TCP coalescing gives.
    #[test]
    fn recv_data_after_recv_line_shared_buffer() {
        // Record 1: "18 15 7\n" + 7 bytes "LOGDATA"
        // Record 2: "18 15 5\n" + 5 bytes "HELLO"
        // No newline after data — the daemon doesn't add one
        // (header via `send_request`, raw bytes via `send_meta`).
        let mut wire = Vec::new();
        wire.extend_from_slice(b"18 15 7\n");
        wire.extend_from_slice(b"LOGDATA");
        wire.extend_from_slice(b"18 15 5\n");
        wire.extend_from_slice(b"HELLO");

        // Cursor is Read+Write but we only read. Direct CtlSocket
        // construction (bypass connect/handshake). The greeting
        // exchange isn't under test; the buffer behavior is.
        let stream = std::io::Cursor::new(wire);
        let shared = Rc::new(RefCell::new(stream));
        let mut ctl = CtlSocket {
            reader: BufReader::new(ReadHalf(Rc::clone(&shared))),
            writer: WriteHalf(shared),
            pid: 0,
        };

        // ─── Record 1
        // `recv_line` reads through '\n'. BufReader's first read
        // pulls EVERYTHING (Cursor returns it all). 'LOGDATA' is
        // now in BufReader's buffer.
        let line = ctl.recv_line().unwrap().unwrap();
        assert_eq!(line, "18 15 7");

        // 7 bytes. They're in BufReader's buffer, NOT the Cursor.
        // `read_exact` on BufReader drains buffer first.
        let mut data = [0u8; 7];
        ctl.recv_data(&mut data).unwrap();
        assert_eq!(&data, b"LOGDATA");

        // ─── Record 2
        // STILL in BufReader's buffer (Cursor returned everything
        // on the first read).
        let line = ctl.recv_line().unwrap().unwrap();
        assert_eq!(line, "18 15 5");

        let mut data2 = [0u8; 5];
        ctl.recv_data(&mut data2).unwrap();
        assert_eq!(&data2, b"HELLO");

        // ─── EOF
        let line = ctl.recv_line().unwrap();
        assert_eq!(line, None);
    }

    /// `recv_data` with daemon EOF mid-data: header said 100 bytes,
    /// daemon dies after 50. `read_exact` returns `UnexpectedEof`.
    #[test]
    fn recv_data_short_is_error() {
        let wire = b"18 15 100\nshort".to_vec();
        let stream = std::io::Cursor::new(wire);
        let shared = Rc::new(RefCell::new(stream));
        let mut ctl = CtlSocket {
            reader: BufReader::new(ReadHalf(Rc::clone(&shared))),
            writer: WriteHalf(shared),
            pid: 0,
        };

        let line = ctl.recv_line().unwrap().unwrap();
        assert_eq!(line, "18 15 100");

        let mut data = [0u8; 100];
        let err = ctl.recv_data(&mut data).unwrap_err();
        // The Display path: `CtlError::Io(UnexpectedEof)`. We don't
        // pattern-match the kind (CtlError::Io carries a generic
        // io::Error); the message contains it. `tinc log` doesn't
        // surface this anyway (silent loop exit), but the test
        // pins the type.
        let CtlError::Io(io) = err else {
            panic!("expected Io, got {err}")
        };
        assert_eq!(io.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    /// `send_int2` wire shape: `"18 15 -1 1\n"`. The `REQ_LOG`
    /// request: level=-1 (`DEBUG_UNSET`), color=1.
    #[test]
    fn send_int2_wire() {
        let buf: Vec<u8> = Vec::new();
        let stream = std::io::Cursor::new(buf);
        let shared = Rc::new(RefCell::new(stream));
        let mut ctl = CtlSocket {
            reader: BufReader::new(ReadHalf(Rc::clone(&shared))),
            writer: WriteHalf(Rc::clone(&shared)),
            pid: 0,
        };

        ctl.send_int2(CtlRequest::Log, -1, 1).unwrap();

        let written = shared.borrow().get_ref().clone();
        // `"18 15 -1 1\n"`. CONTROL=18, REQ_LOG=15, level=-1, color=1.
        assert_eq!(written, b"18 15 -1 1\n");
    }
}
