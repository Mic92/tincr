//! `connection_t` (`connection.h:86-127`) + `buffer_t` (`buffer.c`).
//!
//! ## What `Connection` is in this chunk
//!
//! C `connection_t` has 25 fields. For control connections (`status.
//! control = true`), most are dead: no `node`, no `edge`, no SPTPS,
//! no legacy crypto. The active fields are:
//!
//! | C field | Rust | Why |
//! |---|---|---|
//! | `socket` | `OwnedFd` | the unix stream fd |
//! | `inbuf` / `outbuf` | `LineBuf` ×2 | line buffering |
//! | `allow_request` | `Option<Request>` | gate (ID → CONTROL → ALL) |
//! | `status.control` | `bool` | control vs peer |
//! | `name` | `String` | "<control>" placeholder, for logs |
//! | `last_ping_time` | `Instant` | timeout sweep |
//! | `io` | `IoId` | held by daemon, NOT here |
//!
//! The peer fields (`node`, `edge`, `sptps`, `protocol_minor`,
//! `tcplen`, `sptpslen`) come in chunk 4 when the meta connection
//! state machine lands. The struct grows then.
//!
//! ## `LineBuf` vs C `buffer_t`
//!
//! `buffer.c` is a `Vec<u8>` with a consume cursor (`offset`). The
//! 87.5%-consumed compact heuristic (`offset/7 > len/8`) is the
//! amortized memmove. The Rust `Vec` already amortizes — but only on
//! growth. We still need the cursor (consuming from the front of a
//! `Vec` is O(n)).
//!
//! The C `buffer_readline` returns `char*` into the buffer's storage,
//! NUL-terminated in place. That's a borrow that's invalidated by the
//! next `buffer_add`. We can't return `&str` from `&mut self` then
//! call `feed` again; the borrow checker says no. So `read_line`
//! returns `Range<usize>` indices; caller slices `inbuf.bytes()` with
//! it. Same data, owned-reference-shaped.
//!
//! ## The `feed` / `flush` split
//!
//! C `receive_meta` (`meta.c:164`) does: recv → buffer_add → loop
//! readline → dispatch. We split: `feed` does recv + buffer_add,
//! caller loops `read_line` + dispatch. The split is the testable
//! seam — `feed` reads a real fd, `read_line` is pure, dispatch is
//! pure.
//!
//! C `send_meta` + `handle_meta_write`: write to outbuf, register
//! IO_WRITE; on writable, `send()`, advance cursor; when empty, drop
//! IO_WRITE. We do the same. `queue` writes to outbuf and returns
//! whether outbuf is now non-empty (caller registers IO_WRITE).
//! `flush` does the `send()` and returns whether outbuf is now empty
//! (caller drops IO_WRITE).

use std::fmt::Write as _;
use std::io;
use std::ops::Range;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::time::Instant;

use tinc_proto::Request;

/// `fmt::Write` adapter for `Vec<u8>`. `Vec<u8>` impls `io::Write`
/// but not `fmt::Write`; `format_args!` wants `fmt::Write`. The
/// bridge is one impl. Module-private because it's an implementation
/// detail of `Connection::send`.
struct VecFmt<'a>(&'a mut Vec<u8>);
impl std::fmt::Write for VecFmt<'_> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        self.0.extend_from_slice(s.as_bytes());
        Ok(())
    }
}

/// `MAXBUFSIZE` from `net.h:45`. The cap on `inbuf` — if a single
/// line exceeds this, the peer is misbehaving.
///
/// `((MAXSIZE > 2048 ? MAXSIZE : 2048) + 128)` where `MAXSIZE = 1673`
/// (no jumbo). So `2048 + 128 = 2176`.
///
/// (When jumbo frames land, `MAXSIZE = 9163` and this becomes
/// `9163 + 128 = 9291`. Recompute then.)
pub const MAXBUFSIZE: usize = 2176;

// ═══════════════════════════════════════════════════════════════════
// LineBuf

/// `buffer_t`. `Vec<u8>` with a consume cursor. Ports `buffer.c` (110
/// LOC) minus `buffer_prepare` (only used by legacy crypto's
/// in-place decrypt) and `buffer_clear` (Drop is fine).
///
/// `data[offset..len]` is the live region. `data[..offset]` is
/// consumed-but-not-yet-compacted.
#[derive(Default)]
pub struct LineBuf {
    data: Vec<u8>,
    /// `buffer_t.offset`. Index of first unconsumed byte.
    offset: usize,
}

impl LineBuf {
    /// `buffer_add`. C: `memcpy(buffer_prepare(size), data, size)`.
    /// Compacts before extending if doing so avoids a realloc — same
    /// as `buffer_prepare`'s `if(offset && len + size > maxlen)` at
    /// `buffer.c:40-43`.
    pub fn add(&mut self, bytes: &[u8]) {
        // Compact opportunistically. C's heuristic at `buffer.c:26`
        // is `offset/7 > len/8` (consumed > ~87.5% of len). We use
        // a simpler one: compact if it would let us avoid a realloc.
        // Same effect (amortize the memmove against the realloc
        // savings). The C heuristic is from when realloc was scarier.
        if self.offset > 0 && self.data.len() + bytes.len() > self.data.capacity() {
            self.data.drain(..self.offset);
            self.offset = 0;
        }
        self.data.extend_from_slice(bytes);
    }

    /// `buffer_readline`. Find `\n` in the live region. If found,
    /// return the byte range `[offset, newline)` (excluding `\n`)
    /// and advance `offset` past it. If not found, return `None`
    /// (incomplete line, need more data).
    ///
    /// The returned range indexes `self.bytes_raw()`. The caller
    /// slices, parses, dispatches. The range stays valid until the
    /// next `add`, `consume`, or `read_line` call.
    ///
    /// C `buffer_readline` returns `char*` and writes a NUL where
    /// `\n` was. We don't NUL — caller gets a `[u8]` slice, doesn't
    /// need it. The C NUL is for `sscanf` to stop on.
    ///
    /// C `buffer_consume` (`buffer.c:71-74`) resets `offset=0, len=0`
    /// when offset catches len. We DON'T do that here — the returned
    /// range would be into a cleared buffer. C's pointer stays valid
    /// because reset doesn't free `data` (just zeros the indices).
    /// Our `data.clear()` drops bytes. The reset lives in `add()`
    /// (compact-on-growth) and `consume()` (where there's no
    /// outstanding range). Next `add()` after the buffer went empty
    /// will compact (`offset > 0 && would-realloc` → drain), so the
    /// memory waste is bounded by one read's worth of slack.
    pub fn read_line(&mut self) -> Option<Range<usize>> {
        let live = &self.data[self.offset..];
        // C `memchr(data + offset, '\n', len - offset)`.
        let nl = live.iter().position(|&b| b == b'\n')?;
        let start = self.offset;
        let end = start + nl;
        // C `buffer_consume(len)`: advance offset past the newline.
        // NO reset here — see doc.
        self.offset = end + 1;
        Some(start..end)
    }

    /// Live region length. C: `buffer->len - buffer->offset`.
    /// Used for the `MAXBUFSIZE` check in `feed`.
    #[must_use]
    pub fn live_len(&self) -> usize {
        self.data.len() - self.offset
    }

    /// True when there's nothing to flush. `handle_meta_write`
    /// returns early if `outbuf.len <= outbuf.offset`
    /// (`net_socket.c:487`).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.offset >= self.data.len()
    }

    /// The full backing slice. Index with a range from `read_line`.
    /// We can't return the live slice and then mutate — the range
    /// indirection breaks the borrow.
    #[must_use]
    pub fn bytes_raw(&self) -> &[u8] {
        &self.data
    }

    /// Live bytes for `flush()`. C: `data + offset, len - offset`.
    #[must_use]
    pub fn live(&self) -> &[u8] {
        &self.data[self.offset..]
    }

    /// `buffer_read(buffer, n)` — advance the cursor by `n`. C uses
    /// this in `handle_meta_write` after a partial `send()`
    /// (`net_socket.c:507`).
    pub fn consume(&mut self, n: usize) {
        self.offset += n;
        if self.offset >= self.data.len() {
            self.data.clear();
            self.offset = 0;
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// Connection

/// `connection_t`. The control-connection slice; peer fields come
/// later. C `connection.c::new_connection` is `xzalloc(sizeof)` —
/// our `accept_control` builds one inline.
pub struct Connection {
    /// `c->socket`. C uses raw `int`; we own it. Drop closes.
    fd: OwnedFd,
    /// `c->inbuf`. Bytes read but not yet parsed into lines.
    pub inbuf: LineBuf,
    /// `c->outbuf`. Bytes queued for `send()`.
    pub outbuf: LineBuf,
    /// `c->allow_request`. The state-machine gate. Starts at `Some(
    /// Id)` (`net_socket.c:811` `c->allow_request = ID`); `id_h` sets
    /// it to `Some(Control)` for control conns. `None` means `ALL`
    /// (any request accepted) — peers reach this after the auth
    /// handshake. Control conns never do.
    pub allow_request: Option<Request>,
    /// `c->status.control`. `true` after `id_h` sees `^<cookie>`.
    pub control: bool,
    /// `c->name`. `"<control>"` literal for control conns. Appears
    /// in log lines.
    pub name: String,
    /// `c->last_ping_time`. C uses `time_t` (seconds); we use
    /// `Instant`. The pingtimer sweep checks `now - last_ping > timeout`.
    /// Control conns get a 1-hour bump (`protocol_auth.c:328`) so
    /// they're effectively exempt.
    pub last_ping_time: Instant,
}

/// Result of `feed()`. C `receive_meta` returns `bool`; we
/// disambiguate `false` into "would block" vs "drop me".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedResult {
    /// Data buffered; caller should drain `read_line`.
    Data,
    /// `recv()` returned `EWOULDBLOCK` — spurious wakeup. Level-
    /// triggered epoll can do this. C `meta.c:192`: `return true`.
    /// Caller does nothing; next turn re-fires if still readable.
    WouldBlock,
    /// `recv()` returned 0 (EOF) or a real error. Connection is
    /// dead. Caller calls `terminate`.
    Dead,
}

impl Connection {
    /// `new_connection()` + the field init from `handle_new_unix_
    /// connection` (`net_socket.c:798-811`). The fd just came from
    /// `accept()`.
    #[must_use]
    pub fn new_control(fd: OwnedFd, now: Instant) -> Self {
        Self {
            fd,
            inbuf: LineBuf::default(),
            outbuf: LineBuf::default(),
            // `c->allow_request = ID`. The first thing the client
            // sends MUST be an ID line; anything else is a protocol
            // violation.
            allow_request: Some(Request::Id),
            control: false,
            // `c->name = xstrdup("<control>")`. Placeholder until
            // we know who they are. id_h overwrites it for peers
            // (with their actual node name); for control it stays.
            name: "<control>".to_string(),
            last_ping_time: now,
        }
    }

    /// Raw fd for `EventLoop::add`.
    #[must_use]
    pub fn fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// `receive_meta`'s recv-and-buffer half. C `meta.c:185`:
    /// `inlen = recv(c->socket, inbuf, sizeof inbuf - inbuf.len, 0)`.
    ///
    /// One `recv()` call. Non-blocking (the fd is set non-blocking by
    /// `accept_control`). Returns `WouldBlock` for `EAGAIN`, `Dead`
    /// for EOF/error, `Data` if bytes were buffered.
    ///
    /// The MAXBUFSIZE check (`meta.c:180-183`) — if `inbuf` is
    /// already at cap before `recv`, something is wrong (a single
    /// line longer than 2KB is a protocol violation; control lines
    /// are 80 chars at most). C: `return false`.
    pub fn feed(&mut self) -> FeedResult {
        if self.inbuf.live_len() >= MAXBUFSIZE {
            log::error!(target: "tincd::meta",
                        "Input buffer full for {} — protocol violation", self.name);
            return FeedResult::Dead;
        }

        // Stack buffer same as C `char inbuf[MAXBUFSIZE]`. The cap
        // on read size is `MAXBUFSIZE - inbuf.len` so we never
        // overrun the limit on a single feed. C does the same
        // (`sizeof inbuf - c->inbuf.len`).
        let mut stack = [0u8; MAXBUFSIZE];
        let cap = MAXBUFSIZE - self.inbuf.live_len();
        let buf = &mut stack[..cap];

        // SAFETY: `read(2)` on a valid fd. fd is owned by self,
        // non-blocking. buf is stack-allocated. read returns the
        // number of bytes written into buf, or -1 with errno.
        //
        // Why raw `libc::read` not `std::io::Read`: control conns
        // are unix stream sockets; `OwnedFd` doesn't impl Read (it's
        // just an fd, not a stream — could be a regular file). We
        // could `UnixStream::from(fd)` but then UnixStream owns
        // the fd and Drop double-closes. `ManuallyDrop` works around
        // that but the dance is more code than one libc call. Same
        // shim shape as `read_fd`/`write_fd` in tinc-device.
        #[allow(unsafe_code)]
        let n = unsafe { libc::read(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };

        if n < 0 {
            let err = io::Error::last_os_error();
            // C `sockwouldblock`: EWOULDBLOCK || EINTR. EINTR
            // shouldn't happen (SA_RESTART) but defensive.
            if matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) {
                return FeedResult::WouldBlock;
            }
            log::error!(target: "tincd::meta",
                        "Metadata socket read error for {}: {}", self.name, err);
            return FeedResult::Dead;
        }
        if n == 0 {
            // EOF. Client closed. C `meta.c:188-190`: `if(!inlen ||
            // !sockerrno)` log NOTICE "Connection closed by".
            log::info!(target: "tincd::conn",
                       "Connection closed by {}", self.name);
            return FeedResult::Dead;
        }

        // n > 0: that many bytes are now in `buf`. Append to inbuf.
        #[allow(clippy::cast_sign_loss)] // n > 0 checked
        self.inbuf.add(&buf[..n as usize]);
        FeedResult::Data
    }

    /// `send_request` (`protocol.c:97-132`) → `send_meta` plaintext
    /// path (`meta.c:91`). Format the line, append `\n`, push to
    /// outbuf. Returns `true` if outbuf went from empty to non-empty
    /// — caller registers `IO_WRITE` interest.
    ///
    /// C `send_request` does `vsnprintf` into a stack buffer then
    /// `request[len++] = '\n'` then `send_meta(c, request, len)`. We
    /// `write!` directly into `outbuf` (no intermediate stack copy).
    /// `format_args!` doesn't allocate; the bytes land in `outbuf.
    /// data` directly.
    ///
    /// `send_meta` for plaintext-non-SPTPS (which is what control
    /// conns are: `protocol_minor=0` so the `>= 2` check at
    /// `meta.c:65` is false; `encryptout` is false): `buffer_add(&c->
    /// outbuf, buffer, length)` then `io_set(READ | WRITE)`. Our
    /// `bool` return is the `io_set` signal.
    pub fn send(&mut self, args: std::fmt::Arguments<'_>) -> bool {
        let was_empty = self.outbuf.is_empty();
        // Append directly into outbuf. The C uses a stack buffer
        // because varargs formatting needs a destination; we don't
        // have that constraint — `format_args!` writes straight in.
        write!(VecFmt(&mut self.outbuf.data), "{args}").expect("Vec<u8> write infallible");
        self.outbuf.data.push(b'\n');

        // C `meta.c:95`: io_set(&c->io, IO_READ | IO_WRITE).
        // We can't reach the IoId from here (Daemon owns it); return
        // the trigger condition instead.
        was_empty
    }

    /// `handle_meta_write` (`net_socket.c:486-511`). Send from
    /// outbuf. One `send()` call (non-blocking). Advance the cursor
    /// by however many bytes the kernel took. Returns:
    ///
    /// - `Ok(true)`: outbuf now empty, caller drops `IO_WRITE`
    /// - `Ok(false)`: more to send, stay registered for `IO_WRITE`
    /// - `Err`: connection dead, caller terminates
    ///
    /// C: `outlen <= 0` → if EWOULDBLOCK do nothing (return), if
    /// EPIPE log NOTICE, else log ERR; both real-error cases call
    /// `terminate_connection`. The `outlen == 0` check at line 494
    /// — `send()` returning 0 doesn't actually happen for non-zero
    /// length on stream sockets, but C is defensive.
    ///
    /// # Errors
    /// `io::Error` from `send()`. `EPIPE` (peer closed read end),
    /// `ECONNRESET`, `EBADF` if we somehow got here with a closed
    /// fd. The error kind discriminates for logging but the caller's
    /// action is the same: drop the connection.
    pub fn flush(&mut self) -> io::Result<bool> {
        if self.outbuf.is_empty() {
            return Ok(true);
        }

        let live = self.outbuf.live();
        // SAFETY: `send(2)` on a valid fd. live is the live region
        // of outbuf. flags=0. Same shim shape as `read_fd`/`write_fd`.
        // We use `send` not `write` because the C does (`net_socket.c
        // :491`) — for stream sockets they're the same when flags=0,
        // but `send` returns ENOTSOCK if the fd isn't a socket,
        // which is a useful sanity check.
        #[allow(unsafe_code)]
        let n = unsafe { libc::send(self.fd.as_raw_fd(), live.as_ptr().cast(), live.len(), 0) };

        if n < 0 {
            let err = io::Error::last_os_error();
            if matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) {
                // C `net_socket.c:494-496`: log DEBUG, do nothing.
                // Not actually empty, still want IO_WRITE.
                return Ok(false);
            }
            // EPIPE, ECONNRESET, etc. C logs at different levels
            // (`net_socket.c:497-501`); we let the caller log on
            // terminate.
            return Err(err);
        }

        // n >= 0. n == 0 "shouldn't happen" for stream sockets with
        // non-zero send; C treats it as would-block (`outlen == 0`
        // hits the `outlen <= 0 && (sockwouldblock || ...)` check
        // since `sockerrno` is whatever it was before, probably 0,
        // and `!sockerrno` is true on the first arm — wait, no, C
        // checks `outlen == 0` but then `sockwouldblock(sockerrno)`
        // — if errno is 0, that's `EWOULDBLOCK==0? no` so it falls
        // through to the error log. Mismatch with the comment.
        // ANYWAY: we treat n==0 as "made no progress, try again".)
        #[allow(clippy::cast_sign_loss)] // n >= 0
        self.outbuf.consume(n as usize);

        Ok(self.outbuf.is_empty())
    }

    /// Construct an already-buffered connection for unit tests. The
    /// fd is a pipe write-end (so `flush()` writes work) or
    /// `/dev/null` (when flush isn't tested). `feed()` is bypassed —
    /// tests `inbuf.add()` directly.
    #[cfg(test)]
    pub(crate) fn test_with_fd(fd: OwnedFd) -> Self {
        Self::new_control(fd, Instant::now())
    }
}

// ═══════════════════════════════════════════════════════════════════
// tests

#[cfg(test)]
mod tests {
    use super::*;

    // ─── LineBuf ──────────────────────────────────────────────

    #[test]
    fn linebuf_one_full_line() {
        let mut b = LineBuf::default();
        b.add(b"hello world\n");
        let r = b.read_line().unwrap();
        assert_eq!(&b.bytes_raw()[r], b"hello world");
        // Buffer is empty (offset caught len) but data isn't cleared
        // — the range we just used points into it. Next add() compacts.
        assert!(b.is_empty());
        assert_eq!(b.live_len(), 0);
        // Second read_line: None (nothing live).
        assert!(b.read_line().is_none());
    }

    #[test]
    fn linebuf_partial_then_complete() {
        let mut b = LineBuf::default();
        b.add(b"hello ");
        assert!(b.read_line().is_none()); // no \n yet
        b.add(b"world\n");
        let r = b.read_line().unwrap();
        assert_eq!(&b.bytes_raw()[r], b"hello world");
    }

    #[test]
    fn linebuf_two_lines_one_feed() {
        let mut b = LineBuf::default();
        b.add(b"first\nsecond\n");
        let r1 = b.read_line().unwrap();
        assert_eq!(&b.bytes_raw()[r1], b"first");
        // After first read_line, more data is live.
        let r2 = b.read_line().unwrap();
        // r2 indexes into the SAME bytes_raw — no compact between
        // read_line calls (compact only in add/consume).
        assert_eq!(&b.bytes_raw()[r2], b"second");
        assert!(b.is_empty());
    }

    /// The use case: a line, then a partial. After consuming the
    /// line, the partial's bytes are still there. C `receive_meta`'s
    /// inner loop hits this — recv brings "REQ\nPAR", dispatches
    /// REQ, breaks out of inner loop with PAR buffered, outer loop
    /// `inlen` exhausted, return; next epoll wake brings the rest.
    #[test]
    fn linebuf_line_then_partial() {
        let mut b = LineBuf::default();
        b.add(b"full\npartial");
        let r = b.read_line().unwrap();
        assert_eq!(&b.bytes_raw()[r], b"full");
        // partial still buffered
        assert_eq!(b.live_len(), 7);
        assert!(b.read_line().is_none());
        // complete it
        b.add(b" done\n");
        let r2 = b.read_line().unwrap();
        assert_eq!(&b.bytes_raw()[r2], b"partial done");
    }

    /// Empty line (`"\n"` alone). Range is `start..start` — zero
    /// length. `meta.c` handles this: `receive_request` gets an
    /// empty string, `atoi("")` returns 0, the `*request == '0'`
    /// check is false (empty string's first byte is NUL), falls
    /// through to "Bogus data". Works.
    #[test]
    fn linebuf_empty_line() {
        let mut b = LineBuf::default();
        b.add(b"\n");
        let r = b.read_line().unwrap();
        assert_eq!(r.len(), 0);
        assert!(b.is_empty());
    }

    /// The bug `read_line`'s old reset would have caused: read the
    /// last line, buffer goes "empty" (offset==len), THEN slice with
    /// the returned range. With the reset, `data.clear()` would have
    /// run between return and slice; the range is dangling.
    ///
    /// This test is the SAME assertion as `linebuf_one_full_line` but
    /// makes the ordering explicit: range obtained, THEN sliced.
    #[test]
    fn linebuf_range_survives_going_empty() {
        let mut b = LineBuf::default();
        b.add(b"only\n");
        let r = b.read_line().unwrap();
        // is_empty() is now true. Old code would have cleared `data`
        // by this point. The slice MUST still work.
        assert!(b.is_empty());
        assert_eq!(&b.bytes_raw()[r], b"only");
    }

    /// `consume` — the partial-send case. Queue 10 bytes, kernel
    /// takes 3, consume(3), 7 bytes still live, next flush sends
    /// from byte 3.
    #[test]
    fn linebuf_consume_partial() {
        let mut b = LineBuf::default();
        b.add(b"0123456789");
        b.consume(3);
        assert_eq!(b.live(), b"3456789");
        assert_eq!(b.live_len(), 7);
        assert!(!b.is_empty());
    }

    #[test]
    fn linebuf_consume_all_resets() {
        let mut b = LineBuf::default();
        b.add(b"hello");
        b.consume(5);
        assert!(b.is_empty());
        assert_eq!(b.live_len(), 0);
        // Internal: data was cleared, offset reset.
        assert_eq!(b.offset, 0);
        assert_eq!(b.data.len(), 0);
    }

    /// The compact-on-add path. Fill, consume most, add more — the
    /// add should drain the consumed region instead of growing.
    #[test]
    fn linebuf_compact_avoids_realloc() {
        let mut b = LineBuf::default();
        // Prime with capacity for 100 bytes.
        b.add(&[b'x'; 100]);
        let cap = b.data.capacity();
        // Consume 90.
        b.consume(90);
        // 10 live. Add 80 more. Without compact: len 180 > cap 100
        // → realloc. With compact: drain 90, len becomes 10, then
        // add 80 → len 90 < cap 100, no realloc.
        b.add(&[b'y'; 80]);
        // Can't strictly assert "no realloc" (Vec is allowed to
        // overallocate). But: live_len is exactly 90, and the live
        // bytes are 10 x's then 80 y's.
        assert_eq!(b.live_len(), 90);
        assert_eq!(b.live()[..10], [b'x'; 10]);
        assert_eq!(b.live()[10..], [b'y'; 80]);
        // The interesting part: cap didn't grow (compact worked).
        // This is best-effort; if Vec's growth policy changed,
        // this assertion is what tells us.
        assert_eq!(b.data.capacity(), cap, "compact should reuse capacity");
    }

    /// `MAXBUFSIZE` pins `net.h:45`: `(2048 + 128)` because
    /// `MAXSIZE = 1673 < 2048`. If MAXSIZE bumps (jumbo frames),
    /// this fails and we recompute.
    #[test]
    fn maxbufsize_matches_c() {
        // C: ((1673 > 2048 ? 1673 : 2048) + 128)
        const MAXSIZE: usize = 1673; // net.h:42, no-jumbo
        let expected = (if MAXSIZE > 2048 { MAXSIZE } else { 2048 }) + 128;
        assert_eq!(MAXBUFSIZE, expected);
    }

    // ─── Connection::send ─────────────────────────────────────
    // feed/flush need a real fd (read/send syscalls); tested via
    // socketpair in daemon.rs tests. send() is pure (just outbuf
    // formatting) — testable here.

    fn devnull() -> OwnedFd {
        use std::os::fd::IntoRawFd;
        let f = std::fs::File::open("/dev/null").unwrap();
        let fd = f.into_raw_fd();
        // SAFETY: fd is valid, just from File. We give ownership
        // to OwnedFd; File no longer owns it (into_raw_fd).
        #[allow(unsafe_code)]
        unsafe {
            std::os::fd::FromRawFd::from_raw_fd(fd)
        }
    }

    /// `send_request(c, "%d %s %d.%d", ID, name, major, minor)`.
    /// The daemon's `send_id` greeting. Exact bytes including \n.
    #[test]
    fn send_formats_id_greeting() {
        let mut c = Connection::test_with_fd(devnull());
        let was_empty = c.send(format_args!("0 testnode 17.7"));
        assert!(was_empty); // outbuf was empty, now has 1 line
        assert_eq!(c.outbuf.live(), b"0 testnode 17.7\n");
    }

    /// Two sends back-to-back: second returns `false` (outbuf was
    /// already non-empty). Caller doesn't double-register IO_WRITE.
    #[test]
    fn send_second_doesnt_signal() {
        let mut c = Connection::test_with_fd(devnull());
        assert!(c.send(format_args!("0 a 17.7")));
        assert!(!c.send(format_args!("4 0 99")));
        assert_eq!(c.outbuf.live(), b"0 a 17.7\n4 0 99\n");
    }

    /// `new_control` sets the C defaults. `net_socket.c:811` `c->
    /// allow_request = ID`.
    #[test]
    fn new_control_defaults() {
        let c = Connection::test_with_fd(devnull());
        assert_eq!(c.allow_request, Some(Request::Id));
        assert!(!c.control);
        assert_eq!(c.name, "<control>");
    }
}
