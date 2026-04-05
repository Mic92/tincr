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
mod tests;
