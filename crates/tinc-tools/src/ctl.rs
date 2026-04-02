//! Control socket transport. The CLI ↔ daemon channel.
//!
//! `tincctl.c::connect_tincd` (lines 747-902) + `recvline`/`sendline`
//! (499-588), as a struct holding the socket. Replaces a global `int
//! fd` + `char buffer[4096]` + `size_t blen`.
//!
//! ## Shape of the protocol
//!
//! The control socket is a **regular meta connection** that took the
//! `^` branch in `id_h` (`protocol_auth.c:325`). Same `\n`-delimited
//! lines, same request-type-first-int convention, same `connection_t`
//! on the daemon side. The control conversation looks like:
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
//! Per the rewrite plan: **CLI and daemon ship together**. Nobody
//! expects `tinc-rust dump nodes` to work against a C daemon. The
//! 22-field positional sscanf format is **not** wire-locked — it's a
//! private channel between two halves of one release.
//!
//! What that buys us: when our daemon's `Node` struct exists, its
//! `dump_nodes` can emit whatever fields it has, in whatever order,
//! and `cmd_dump` parses to match. We're not held to `cipher digest
//! maclength compression options` from a `node_t` we don't have. The
//! `CtlRequest` enum and the framing stay; line *bodies* are ours.
//!
//! What that doesn't change: the *cookie* mechanism is right
//! (capability auth via fs perms on the pidfile), the unix-socket
//! transport is right (no TCP fallback to maintain), the line-based
//! framing is right (`nc -U /var/run/tinc.socket` debuggability).
//! We keep the architecture, drop the format obligations.
//!
//! ## Why `Read + Write` not `UnixStream`
//!
//! Tests pass a `UnixStream::pair()` half. Same in-process pattern
//! as `cmd::join`'s SPTPS pump, but simpler: no SPTPS, just lines.
//! The fake daemon does the greeting dance, serves canned responses,
//! drops. Tests don't need root, don't need a pidfile, don't race
//! with parallel runs.
//!
//! `connect()` does the OS bits (read pidfile, connect socket) and
//! delegates to `handshake()`. The split is the testable seam.
//!
//! ## What's NOT here
//!
//! `recvdata` (`tincctl.c:536`): raw byte reads for `pcap`. Only
//! consumer is `cmd_pcap`, which streams forever. When that lands,
//! `recv_exact(&mut self, n)` reading from `leftover` first.
//!
//! Windows TCP fallback (`tincctl.c:817-869`): we're Unix-only for
//! the daemon path. The fallback exists because Windows doesn't have
//! AF_UNIX in C tinc's vintage. `#[cfg(windows)]` stub when needed.
//!
//! Reconnect-on-dead (`tincctl.c:748-760`): the C reuses `fd` across
//! commands in the readline shell. We're one command per process; no
//! reuse, no need to detect dead `fd`.

#![allow(clippy::doc_markdown)]

use std::io::{BufRead, BufReader, Read, Write};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::path::Path;

use crate::names::Paths;

/// `request_type` enum from `control_common.h`. The second int after
/// `CONTROL` in every control line.
///
/// Why a `u8`-newtype-ish enum and not strings: the C uses ints
/// (cheap to format/parse), and we have no compat constraint to
/// change them. The numbers are also stable across our releases
/// because they're a closed set — `REQ_FOO` is added at the end,
/// never reordered.
///
/// `REQ_INVALID = -1` is the daemon's error response, not a request
/// the CLI sends. Represented as `Option<CtlRequest>::None` on parse.
///
/// `REQ_RESTART` and `REQ_DUMP_GRAPH` exist in the enum but are
/// **never sent** by `tincctl.c` and never matched by `control_h`.
/// Dead values. We include them anyway: zero cost, and the gap in
/// the discriminant sequence (2→3, 7→8) would be more surprising
/// than the dead variants.
///
/// `REQ_CONNECT` similarly: enum value exists, no `cmd_connect` in
/// the C, no case in `control_h`. The asymmetry with `REQ_DISCONNECT`
/// suggests it was planned and never finished. Same treatment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CtlRequest {
    Stop = 0,
    Reload = 1,
    /// Dead in C. Daemon never matches it.
    Restart = 2,
    DumpNodes = 3,
    DumpEdges = 4,
    DumpSubnets = 5,
    DumpConnections = 6,
    /// Dead in C. The CLI synthesizes graph from nodes+edges instead.
    DumpGraph = 7,
    Purge = 8,
    SetDebug = 9,
    Retry = 10,
    /// Dead in C. No `cmd_connect`, no daemon handler.
    Connect = 11,
    Disconnect = 12,
    DumpTraffic = 13,
    Pcap = 14,
    Log = 15,
}

impl CtlRequest {
    /// Parse the second int. `None` for unknown / `REQ_INVALID`.
    /// We're permissive: anything not in the enum is `None`, not a
    /// protocol error. The C's `default:` case in `control_h` does
    /// the same.
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

/// `CONTROL` request type from `protocol.h:52`. Count from `ID = 0`:
/// ID/METAKEY/CHALLENGE/CHAL_REPLY/ACK/STATUS/ERROR/TERMREQ/PING/PONG/
/// ADD_SUBNET/DEL_SUBNET/ADD_EDGE/DEL_EDGE/KEY_CHANGED/REQ_KEY/ANS_KEY/
/// PACKET → 18.
///
/// `tinc_proto::request::Request::Control` is the canonical place for
/// this. We re-declare here because `ctl.rs` doesn't otherwise use
/// `tinc-proto` and one constant isn't worth the dependency edge.
/// Same call as `SEPARATOR` redeclared in invite.rs/exchange.rs.
const CONTROL: u8 = 18;
/// `ID` from `protocol.h:44`. The greeting opener.
const ID: u8 = 0;
/// `ACK` from `protocol.h:44`. The greeting closer.
const ACK: u8 = 4;
/// `TINC_CTL_VERSION_CURRENT` from `control_common.h:46`. Hasn't
/// changed since 2007. We send it (because the C daemon checks it,
/// for as long as we care about C-daemon compat during transition);
/// our own daemon will check it too (cheap, and lets us bump if we
/// ever change the framing).
const CTL_VERSION: u8 = 0;

/// Contents of the pidfile. `pidfile_t` (`pidfile.h`).
///
/// The C also has `host` and `port` fields (for the Windows TCP
/// fallback). We drop them — Unix-only daemon path. When/if Windows
/// lands, this grows; the parse already skips them.
///
/// `cookie` is the bearer token. `controlcookie[65]` in C is 32
/// random bytes, hex-encoded. The pidfile is mode 0600 (`pidfile.c:28`
/// `umask(mask | 077)`) so only the daemon's UID can read it; the
/// cookie is auth-via-fs-perms.
#[derive(Debug)]
pub struct Pidfile {
    pub pid: u32,
    /// Hex string, 64 chars. We *could* decode to `[u8; 32]` but
    /// nothing uses the raw bytes — it goes back on the wire as
    /// the same hex string. Round-tripping through bytes would just
    /// be an opportunity to disagree on case.
    pub cookie: String,
}

impl Pidfile {
    /// `read_pidfile` (`pidfile.c:6-23`). Format:
    /// `"<pid> <cookie> <host> port <port>\n"`.
    ///
    /// C `fscanf(f, "%20d %64s %128s port %128s")`. The `%20d` width
    /// limit is overflow paranoia (20 digits fits `u64`); the `%64s`
    /// is exactly the cookie length; `%128s` is "more than enough".
    ///
    /// We're stricter than the C in one place: `%d` accepts leading
    /// whitespace and `+`/`-`; `parse::<u32>` doesn't. A pidfile
    /// with `+123` would parse in C and fail here. The pidfile is
    /// written by `fprintf(f, "%d ...")` which never emits `+`, so
    /// the only source of a leading sign is hand-editing or a buggy
    /// daemon. Stricter is fine.
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

        // C parses with fscanf. We tokenize on whitespace — `%s` is
        // "read non-whitespace", so split_whitespace is the moral
        // equivalent. The literal `port` in the format string is
        // matched by checking-then-skipping, not by sscanf doing it
        // (C `%128s port %128s` reads, skips ws, expects literal
        // `port`, skips ws, reads). We just check token 3.
        let mut tok = s.split_whitespace();
        let pid_s = tok.next().ok_or(CtlError::PidfileMalformed)?;
        let cookie = tok.next().ok_or(CtlError::PidfileMalformed)?;
        // host, "port", port: we don't use them but we *do* check
        // shape. C `if(read != 4)` — fscanf must consume all four.
        // A truncated pidfile (daemon crashed mid-write?) should
        // fail here, not connect with a half-read cookie.
        let _host = tok.next().ok_or(CtlError::PidfileMalformed)?;
        let port_lit = tok.next().ok_or(CtlError::PidfileMalformed)?;
        let _port = tok.next().ok_or(CtlError::PidfileMalformed)?;
        if port_lit != "port" {
            return Err(CtlError::PidfileMalformed);
        }

        // C `%20d`. u32 covers all real pids. The C reads into `int`
        // and never checks for negative; we get the check for free.
        let pid: u32 = pid_s.parse().map_err(|_| CtlError::PidfileMalformed)?;

        // Cookie length: the C reads into a `[65]` buffer with `%64s`.
        // If the cookie is somehow longer, fscanf truncates; if
        // shorter, no problem. We check exact-64 because the daemon
        // *writes* exact-64 (`bin2hex` of 32 bytes), and length
        // disagreement = silent auth failure later. Better here.
        //
        // Hex-only check: same reasoning. The daemon writes lowercase
        // hex (`bin2hex` uses `"0123456789abcdef"`, `utils.c:43`).
        // Non-hex = corruption or hand-editing.
        if cookie.len() != 64 || !cookie.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(CtlError::PidfileMalformed);
        }

        Ok(Self {
            pid,
            cookie: cookie.to_owned(),
        })
    }
}

/// Errors from connecting to or talking with the daemon. Distinct
/// from `cmd::CmdError` because the messages and recoverability
/// differ — `pidfile missing` means "daemon isn't running", which
/// some callers (`cmd_invite`'s best-effort reload) want to treat
/// as a soft no-op.
///
/// The C's `verbose` parameter to `connect_tincd` controls whether
/// these print to stderr. We model that as: errors always carry the
/// message, the *caller* decides whether to print (`cmd_reload`
/// prints, `cmd_invite`'s opportunistic reload swallows). Matches
/// the call-site control without a `verbose` arg threading through.
#[derive(Debug)]
pub enum CtlError {
    /// `read_pidfile` returned NULL (ENOENT or EACCES). The daemon
    /// isn't running, or never wrote a pidfile, or you can't read
    /// it. C: `"Could not open pid file %s: %s\n"` (`tincctl.c:767`).
    PidfileMissing {
        path: std::path::PathBuf,
        err: std::io::Error,
    },
    /// Pidfile exists but doesn't parse. Daemon crashed mid-write,
    /// or it's a stale pidfile from a different tinc version. C:
    /// `read_pidfile` returns NULL on parse failure too, undifferentiated;
    /// we distinguish for the test that hand-crafts bad pidfiles.
    PidfileMalformed,
    /// `kill(pid, 0)` returned ESRCH. Daemon was running, isn't now,
    /// pidfile is stale. C: `"Could not find tincd running at pid %d"`.
    ///
    /// The C also unlinks the stale pidfile and socket here. We don't
    /// — that's a side effect across the `Paths` boundary, and the
    /// daemon's next start overwrites the pidfile anyway. If we add
    /// it, it's a separate `cleanup_stale` fn the caller invokes.
    DaemonDead { pid: u32 },
    /// `connect(AF_UNIX)` failed. Socket file gone, or daemon not
    /// listening. C: `"Cannot connect to UNIX socket %s: %s\n"`.
    SocketConnect {
        path: std::path::PathBuf,
        err: std::io::Error,
    },
    /// Greeting exchange failed. Wrong cookie, daemon spoke wrong
    /// protocol, EOF mid-greeting. C: `"Cannot read greeting from
    /// control socket"` or `"Could not fully establish control
    /// socket connection"`. Both messages, depending on which line.
    Greeting(String),
    /// Socket I/O after greeting. Daemon closed, write failed.
    /// The C doesn't distinguish — `recvline` returns false, caller
    /// prints "could not X". We name it for the test.
    Io(std::io::Error),
}

impl std::fmt::Display for CtlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // C phrasing where it exists. The daemon's down — these go
        // to stderr in `cmd_reload` etc., users grep for them.
        match self {
            CtlError::PidfileMissing { path, err } => {
                write!(f, "Could not open pid file {}: {err}", path.display())
            }
            CtlError::PidfileMalformed => {
                // C doesn't have this message (it conflates with
                // missing). Ours is new but follows the pattern.
                write!(f, "Could not parse pid file")
            }
            CtlError::DaemonDead { pid } => {
                write!(f, "Could not find tincd running at pid {pid}")
            }
            CtlError::SocketConnect { path, err } => {
                write!(f, "Cannot connect to UNIX socket {}: {err}", path.display())
            }
            CtlError::Greeting(msg) => write!(f, "{msg}"),
            CtlError::Io(e) => write!(f, "Connection to tincd lost: {e}"),
        }
    }
}

impl std::error::Error for CtlError {}

/// The connected control socket. `int fd` + `buffer`/`blen` from
/// `tincctl.c`, plus the daemon's pid (set by greeting line 2).
///
/// Generic over the stream so tests can pass `UnixStream::pair()`
/// halves. In production it's always `UnixStream`.
///
/// `BufReader` wraps the reader half. The C hand-rolls a buffer
/// because `recvline` and `recvdata` share it (line read might
/// over-read into the next packet). We split: `recv_line` is
/// `BufRead::read_line`, and `recvdata` (when it lands for pcap)
/// will be `read_exact` on the underlying stream after draining
/// `BufReader::buffer()`. The shared-buffer concern is real but
/// `BufReader` already solves it.
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
    /// nothing else uses it. C: global `pid`.
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
    /// Do the greeting exchange over an already-connected stream.
    /// `tincctl.c:876-900`.
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
    /// (The C daemon doesn't actually close on bad cookie — `id_h`
    /// returns `false` which falls through to the `check_id` check
    /// which also fails on `^hex...` because `^` isn't alnum. The
    /// connection then gets dropped by the meta loop. Same outcome.)
    pub fn handshake(stream: S, cookie: &str) -> Result<Self, CtlError> {
        let shared = Rc::new(RefCell::new(stream));
        let mut reader = BufReader::new(ReadHalf(Rc::clone(&shared)));
        let mut writer = WriteHalf(shared);

        // ─── Send ID ────────────────────────────────────────────────
        // C: `sendline(fd, "%d ^%s %d", ID, controlcookie,
        //     TINC_CTL_VERSION_CURRENT)`.
        // The `^` prefix is what routes this to the control path in
        // `id_h`. Without it, the daemon would try to parse `cookie`
        // as a node name, fail `check_id` (hex chars are fine but a
        // 64-char name is unusual enough to maybe-fail something
        // downstream — actually no, check_id only checks charset.
        // Doesn't matter: the `^` is the intent.).
        writeln!(writer, "{ID} ^{cookie} {CTL_VERSION}").map_err(CtlError::Io)?;

        // ─── Recv line 1: daemon's send_id() ────────────────────────
        // C: `recvline(); sscanf("%d %4095s %d") == 3 && code == 0`.
        // We get `"0 <daemon-name> <maj>.<min>"`. The daemon sends
        // this *after* our ID arrives (`if(!c->outgoing) send_id(c)`
        // in `id_h:333`) — the unix-socket connection has no
        // outgoing flag set, so the daemon's ID is reactive, not
        // proactive. The version field is `protocol_major.protocol_minor`,
        // not the control version — that's in line 2.
        //
        // We don't *use* anything from line 1. Just check shape.
        // The C checks `code == 0` (it's an ID) and ignores the rest.
        let line1 = recv_one(&mut reader, "Cannot read greeting from control socket")?;
        let mut t1 = line1.split_ascii_whitespace();
        if t1.next() != Some("0") {
            // Not an ID. Daemon speaking wrong protocol, or we
            // connected to something that isn't tincd.
            return Err(CtlError::Greeting(format!(
                "Cannot read greeting from control socket: unexpected response {line1:?}"
            )));
        }
        // Name and version ignored. The C `%4095s %d` consumes them
        // but never reads `data` or `version` afterward. We don't
        // even consume — the next line is where the action is.

        // ─── Recv line 2: ACK with control-ver and pid ──────────────
        // C: `recvline(); sscanf("%d %d %d") == 3 && code == 4 &&
        //     version == TINC_CTL_VERSION_CURRENT`.
        // Shape: `"4 0 <pid>"`. The `4` is ACK; `0` is control-ver
        // (the daemon echoes what we sent, sort of — it sends its
        // own `TINC_CTL_VERSION_CURRENT`, which equals ours).
        let line2 = recv_one(
            &mut reader,
            "Could not fully establish control socket connection",
        )?;
        let mut t2 = line2.split_ascii_whitespace();
        let code = t2.next().and_then(|s| s.parse::<u8>().ok());
        let ver = t2.next().and_then(|s| s.parse::<u8>().ok());
        let pid = t2.next().and_then(|s| s.parse::<u32>().ok());

        // All three checks at once. C does them sequentially with
        // one error message; we match.
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

    /// Send a CONTROL request with no arguments. `sendline(fd,
    /// "%d %d", CONTROL, type)`. The common case (reload, purge,
    /// retry, stop, all the dumps).
    ///
    /// # Errors
    /// `Io` if the write fails. Socket closed, daemon dead.
    pub fn send(&mut self, req: CtlRequest) -> Result<(), CtlError> {
        writeln!(self.writer, "{CONTROL} {}", req as u8).map_err(CtlError::Io)
    }

    /// Send with one int argument. `sendline(fd, "%d %d %d", CONTROL,
    /// type, arg)`. `REQ_SET_DEBUG`, `REQ_PCAP` (snaplen).
    ///
    /// # Errors
    /// Same as `send`.
    pub fn send_int(&mut self, req: CtlRequest, arg: i32) -> Result<(), CtlError> {
        writeln!(self.writer, "{CONTROL} {} {arg}", req as u8).map_err(CtlError::Io)
    }

    /// Send with one string argument. `sendline(fd, "%d %d %s", ...)`.
    /// `REQ_DISCONNECT` (the node name).
    ///
    /// `arg` should be a single token (no spaces) — the daemon's
    /// `sscanf MAX_STRING` reads one word. Node names pass `check_id`
    /// so this holds; we don't re-validate (caller's job).
    ///
    /// # Errors
    /// Same as `send`.
    pub fn send_str(&mut self, req: CtlRequest, arg: &str) -> Result<(), CtlError> {
        writeln!(self.writer, "{CONTROL} {} {arg}", req as u8).map_err(CtlError::Io)
    }

    /// Receive and parse a one-shot ack. `recvline(); sscanf("%d %d
    /// %d") && code==CONTROL && req==X && result==0`. The pattern
    /// every simple command does.
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
        // C: `sscanf(line, "%d %d %d", &code, &req, &result) == 3 &&
        //     code == CONTROL && req == REQ_X && !result`.
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
    /// The C `recvline` returns `false` on EOF and on error
    /// undifferentiated. We distinguish: `Ok(None)` for EOF (clean),
    /// `Err` for I/O. The `cmd_stop` "wait for daemon to close" loop
    /// wants the former; everything else wants the latter to surface.
    ///
    /// # Errors
    /// `Io` on read failure (not EOF).
    pub fn recv_line(&mut self) -> Result<Option<String>, CtlError> {
        let mut buf = String::new();
        match self.reader.read_line(&mut buf) {
            Ok(0) => Ok(None),
            Ok(_) => {
                // Strip the trailing \n. C `recvline` does this:
                // `len = newline - buffer; line[len] = 0`.
                if buf.ends_with('\n') {
                    buf.pop();
                }
                Ok(Some(buf))
            }
            Err(e) => Err(CtlError::Io(e)),
        }
    }
}

/// Read one line, error if EOF. The greeting recvs and `recv_ack`
/// want EOF-is-error semantics; only `recv_line` (the raw one) wants
/// EOF-is-end. Factored out so the error message is parameterized
/// (greeting line 1 and 2 have different C messages).
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
    /// `connect_tincd` — the full OS-side connect. `tincctl.c:747-902`.
    ///
    /// Reads the pidfile, checks the daemon is alive, connects the
    /// unix socket, does the greeting. The four points of failure
    /// each have their own `CtlError` variant.
    ///
    /// The C also unlinks stale pidfile + socket on `DaemonDead`
    /// (`tincctl.c:781-783`). We don't — that's a side effect across
    /// the `Paths` boundary, and `cmd_stop` (the only legitimate
    /// "daemon should be down" caller) wants different handling
    /// anyway. Stale pidfile cleanup is the daemon's job (next start
    /// overwrites it). If we add it, it's a separate `cleanup_stale`
    /// fn the caller invokes after seeing `DaemonDead`.
    ///
    /// `paths` must have had `resolve_runtime()` called. The panic
    /// from `pidfile()` is the assertion.
    ///
    /// # Errors
    /// See `CtlError` variants. Each failure mode has its own.
    pub fn connect(paths: &Paths) -> Result<Self, CtlError> {
        // ─── Read pidfile ───────────────────────────────────────────
        let pidfile_path = paths.pidfile();
        let pf = Pidfile::read(pidfile_path)?;

        // ─── kill(pid, 0) liveness check ────────────────────────────
        // C: `if((pid == 0) || (kill(pid, 0) && errno == ESRCH))`.
        // The `pid == 0` check: `kill(0, 0)` would signal our own
        // process group, which is a non-error and would mask "no
        // daemon" as "daemon alive". A zero pid in the pidfile
        // means corrupted write.
        //
        // `kill` can also fail with EPERM (daemon running as a
        // different user). The C only checks ESRCH — EPERM means
        // *something* is at that pid, which is "alive enough" for
        // the connect attempt. We replicate: only ESRCH → DaemonDead.
        // Pid range: real pids fit in i32 (`/proc/sys/kernel/pid_max`
        // defaults to 4M and can't exceed 2^22). The pidfile parse
        // already bounds it to u32 (no negatives). `try_from` rather
        // than `as` so a corrupted pidfile with pid > 2^31 lands on
        // the `pid == 0` check below instead of wrapping to a
        // negative i32 and probing some unrelated process.
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

        // ─── Connect socket ─────────────────────────────────────────
        // C: socket(AF_UNIX), connect. UnixStream::connect does both.
        // The C also checks `strlen(unixsocketname) >= sun_path` —
        // path-too-long for the sockaddr. UnixStream::connect surfaces
        // this as an io::Error with ENAMETOOLONG; same outcome,
        // wrapped in our SocketConnect.
        let sock_path = paths.unix_socket();
        let stream = UnixStream::connect(&sock_path).map_err(|e| CtlError::SocketConnect {
            path: sock_path,
            err: e,
        })?;

        // ─── SO_NOSIGPIPE (best-effort, macOS only) ─────────────────
        // C: `setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, ...)`.
        // Linux doesn't have it (uses MSG_NOSIGNAL per-send). The C
        // also passes MSG_NOSIGNAL to send() (`tincctl.c:576`); we
        // don't have per-write control with `Write::write_all`, so
        // SIGPIPE → process death.
        //
        // BUT: this is a CLI tool. The daemon dying mid-conversation
        // → our write returns EPIPE → SIGPIPE → we exit. That's…
        // fine? The C goes to lengths to handle it because of the
        // readline shell mode where one failed command shouldn't
        // kill the shell. We're one command per process. If we
        // need it later (shell mode lands), `signal(SIGPIPE,
        // SIG_IGN)` at binary startup. Not here.

        // ─── Greeting ───────────────────────────────────────────────
        Self::handshake(stream, &pf.cookie)
    }
}

// ════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::thread;

    /// `CtlRequest` discriminants match `control_common.h` exactly.
    /// Hand-transcribed table — verify against the C at commit time
    /// per the constraint (sed-diff'd, see commit message).
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

    /// Pidfile parse, happy path. Format from `pidfile.c::write_pidfile`:
    /// `"<pid> <cookie> <host> port <port>\n"`.
    #[test]
    fn pidfile_parse() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pid");
        let cookie = "a".repeat(64);
        std::fs::write(&path, format!("12345 {cookie} 127.0.0.1 port 655\n")).unwrap();

        let pf = Pidfile::read(&path).unwrap();
        assert_eq!(pf.pid, 12345);
        assert_eq!(pf.cookie, cookie);
    }

    /// Pidfile validation: cookie must be exactly 64 hex chars.
    /// Neither check is in the C (it just `%64s`-reads); we tighten.
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
        // both. The C `bin2hex` writes lowercase, but a hand-edited
        // pidfile (debugging, testing) shouldn't be rejected on case.
        // The greeting comparison on the daemon side is `strcmp`
        // (case-sensitive), so uppercase here would *fail auth* —
        // but that's a different, more useful error than "malformed
        // pidfile".
        let upper = "0123456789ABCDEF".repeat(4);
        std::fs::write(&path, format!("1 {upper} 127.0.0.1 port 655\n")).unwrap();
        assert!(Pidfile::read(&path).is_ok());
    }

    /// Pidfile shape: missing fields fail. C `if(read != 4)`.
    /// All four sscanf conversions must succeed.
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

        // `port` literal wrong. C fscanf would fail the literal match.
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

    /// Pidfile missing → distinct error. C: `fopen` returns NULL,
    /// `read_pidfile` returns NULL, caller prints `"Could not open
    /// pid file %s: %s"`.
    #[test]
    fn pidfile_missing() {
        let err = Pidfile::read(std::path::Path::new("/nonexistent/pidfile")).unwrap_err();
        assert!(matches!(err, CtlError::PidfileMissing { .. }));
        // The Display matches C phrasing.
        assert!(err.to_string().contains("Could not open pid file"));
    }

    // ────────────────────────────────────────────────────────────────
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
    // ────────────────────────────────────────────────────────────────

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

            // ─── Recv ID, check cookie ──────────────────────────────
            // C `id_h:325`: `if(name[0] == '^' && !strcmp(name+1,
            // controlcookie))`. The whole `^cookie` is in the `%s`
            // field after `ID`.
            let mut line = String::new();
            br.read_line(&mut line).unwrap();
            // Shape: "0 ^COOKIE 0\n".
            let trimmed = line.trim_end();
            let parts: Vec<_> = trimmed.split(' ').collect();
            assert_eq!(parts.len(), 3, "ID line: {trimmed:?}");
            assert_eq!(parts[0], "0");
            assert_eq!(parts[1], format!("^{expected_cookie}"));
            assert_eq!(parts[2], "0");

            // ─── Send greeting line 1 (send_id) ─────────────────────
            // C `protocol_auth.c::send_id`: `"%d %s %d.%d", ID,
            // myself->name, PROT_MAJOR, PROT_MINOR` (modulo the
            // experimental `^` prefix on minor, which doesn't matter
            // for control connections — the CLI ignores everything
            // after the first int). We send a plausible name and
            // version.
            writeln!(write, "0 fakedaemon 17.7").unwrap();

            // ─── Send greeting line 2 (ACK + ctl-ver + pid) ─────────
            // C `id_h:337`: `send_request(c, "%d %d %d", ACK,
            // TINC_CTL_VERSION_CURRENT, getpid())`.
            writeln!(write, "4 0 {daemon_pid}").unwrap();

            // ─── Hand off to test-specific serving ──────────────────
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

    /// `send_int`: REQ_SET_DEBUG with the level argument.
    #[test]
    fn send_with_int_arg() {
        let cookie = "f".repeat(64);
        let (ours, theirs) = UnixStream::pair().unwrap();

        let daemon = fake_daemon(theirs, &cookie, 1, |br, w| {
            let mut line = String::new();
            br.read_line(&mut line).unwrap();
            // "18 9 5\n" — CONTROL SET_DEBUG level=5.
            assert_eq!(line.trim_end(), "18 9 5");
            // Ack with previous level (3, say). REQ_SET_DEBUG
            // repurposes the result field — `control.c:86`:
            // `send_request(c, "%d %d %d", CONTROL, REQ_SET_DEBUG,
            // debug_level)` *before* updating it.
            writeln!(w, "18 9 3").unwrap();
        });

        let mut ctl = CtlSocket::handshake(ours, &cookie).unwrap();
        ctl.send_int(CtlRequest::SetDebug, 5).unwrap();
        let prev = ctl.recv_ack(CtlRequest::SetDebug).unwrap();
        assert_eq!(prev, 3);

        daemon.join().unwrap();
    }

    /// `send_str`: REQ_DISCONNECT with a node name.
    #[test]
    fn send_with_str_arg() {
        let cookie = "0".repeat(64);
        let (ours, theirs) = UnixStream::pair().unwrap();

        let daemon = fake_daemon(theirs, &cookie, 1, |br, w| {
            let mut line = String::new();
            br.read_line(&mut line).unwrap();
            // "18 12 alice\n" — CONTROL DISCONNECT name=alice.
            assert_eq!(line.trim_end(), "18 12 alice");
            // Ack: 0 = found and disconnected. C `control.c:122`:
            // `found ? 0 : -2`.
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
    /// for REQ_PURGE, we expected REQ_RELOAD. Either a daemon bug
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

    /// The stop pattern: send REQ_STOP, drain until EOF. The daemon
    /// acks then exits, closing the socket. C `tincctl.c:677-684`:
    /// `sendline(STOP); while(recvline()) {} closesocket(fd)`.
    #[test]
    fn stop_drains_to_eof() {
        let cookie = "3".repeat(64);
        let (ours, theirs) = UnixStream::pair().unwrap();

        let daemon = fake_daemon(theirs, &cookie, 1, |br, w| {
            let mut line = String::new();
            br.read_line(&mut line).unwrap();
            assert_eq!(line.trim_end(), "18 0"); // STOP
            // Ack, then drop. C `control.c:61`: `event_exit();
            // return control_ok(c, REQ_STOP)`. The ack is sent,
            // then the event loop exits, connections close.
            writeln!(w, "18 0 0").unwrap();
            // Thread returns → `theirs` drops → EOF.
        });

        let mut ctl = CtlSocket::handshake(ours, &cookie).unwrap();
        ctl.send(CtlRequest::Stop).unwrap();

        // Drain. We see the ack line, then EOF. The C loop is
        // `while(recvline())` — discards the ack, just waits for
        // close. We replicate: read until None.
        let mut drained = 0;
        while ctl.recv_line().unwrap().is_some() {
            drained += 1;
        }
        assert_eq!(drained, 1); // the ack

        daemon.join().unwrap();
    }
}
