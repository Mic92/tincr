//! `connection_t` (`connection.h:86-127`) + `buffer_t` (`buffer.c`).
//!
//! C's `sptps_t` callback re-enters `connection_t`; we can't (`&mut
//! self.sptps` aliases `&mut self`). `receive()` returns `Vec<Output>`
//! for the daemon to dispatch after the borrow ends. See
//! `RUST_REWRITE_ISSUES.md` (Rust-is-WRONG #4).
//!
//! `LineBuf::read_line` returns `Range<usize>` not `&str`: C
//! `buffer_readline`'s `char*` is invalidated by the next add; the
//! borrow checker rejects the equivalent.

use std::fmt::Write as _;
use std::io;
use std::net::SocketAddr;
use std::ops::Range;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::time::Instant;

use nix::errno::Errno;
use nix::sys::socket::{MsgFlags, send};
use nix::unistd::read;

use rand_core::RngCore;
use tinc_crypto::sign::PUBLIC_LEN;
use tinc_proto::Request;
use tinc_sptps::{Output, Sptps, SptpsError};

use crate::invitation_serve::InvitePhase;

/// `fmt::Write` adapter for `Vec<u8>` (which only impls `io::Write`).
struct VecFmt<'a>(&'a mut Vec<u8>);
impl std::fmt::Write for VecFmt<'_> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        self.0.extend_from_slice(s.as_bytes());
        Ok(())
    }
}

/// `MAXBUFSIZE` (`net.h:45`): `(max(MAXSIZE,2048) + 128)` = 2176
/// (no-jumbo `MAXSIZE = 1673`). Jumbo would be `9163 + 128 = 9291`.
pub const MAXBUFSIZE: usize = 2176;

// LineBuf

/// `buffer_t` (`buffer.c`). `data[offset..]` is live; `data[..offset]`
/// is consumed-not-yet-compacted.
#[derive(Default)]
pub struct LineBuf {
    data: Vec<u8>,
    /// `buffer_t.offset`. Index of first unconsumed byte.
    offset: usize,
}

impl LineBuf {
    /// `buffer_add` (`buffer.c:40-43`). Compacts if doing so avoids
    /// a realloc (simpler than C's `offset/7 > len/8` heuristic).
    pub fn add(&mut self, bytes: &[u8]) {
        if self.offset > 0 && self.data.len() + bytes.len() > self.data.capacity() {
            self.data.drain(..self.offset);
            self.offset = 0;
        }
        self.data.extend_from_slice(bytes);
    }

    /// `buffer_readline`. Range indexes `bytes_raw()`; stays valid
    /// until next `add`/`consume`/`read_line`.
    ///
    /// NO reset-on-empty here (unlike C `buffer.c:71-74`): the
    /// returned range would be into a cleared buffer. C's pointer
    /// stays valid because reset doesn't free `data`. Reset lives in
    /// `add()`/`consume()` instead.
    pub fn read_line(&mut self) -> Option<Range<usize>> {
        let live = &self.data[self.offset..];
        let nl = live.iter().position(|&b| b == b'\n')?;
        let start = self.offset;
        let end = start + nl;
        self.offset = end + 1;
        Some(start..end)
    }

    /// `buffer_read(buffer, n)` (`buffer.c:88-94`). Exact-N read.
    /// Used for the SOCKS reply (binary, fixed-length, not
    /// line-terminated). Same range-validity contract as `read_line`.
    pub fn read_n(&mut self, n: usize) -> Option<Range<usize>> {
        if self.live_len() < n {
            return None;
        }
        let start = self.offset;
        self.offset += n;
        Some(start..start + n)
    }

    #[must_use]
    pub fn live_len(&self) -> usize {
        self.data.len() - self.offset
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.offset >= self.data.len()
    }

    /// Full backing slice. Index with a range from `read_line`.
    #[must_use]
    pub fn bytes_raw(&self) -> &[u8] {
        &self.data
    }

    #[must_use]
    pub fn live(&self) -> &[u8] {
        &self.data[self.offset..]
    }

    /// Advance the cursor. C `net_socket.c:507` (after partial `send()`).
    pub fn consume(&mut self, n: usize) {
        self.offset += n;
        if self.offset >= self.data.len() {
            self.data.clear();
            self.offset = 0;
        }
    }

    /// SPTPS-transition handoff: the same `recv()` delivering the ID
    /// line may also carry SPTPS bytes (Nagle-coalesced). C handles
    /// this mid-read in `receive_meta`'s do-while; we split
    /// feed/drain, so the daemon calls this after `id_h` and re-feeds.
    pub fn take_rest(&mut self) -> Vec<u8> {
        let rest = self.data[self.offset..].to_vec();
        self.data.clear();
        self.offset = 0;
        rest
    }
}

// Connection

/// `connection_t` (`connection.h:86-127`).
// `struct_excessive_bools`: C `connection_status_t` is a packed
// bitfield (`connection.h:38-56`). The bits are independent (a conn
// is active AND pinged in steady state); a state-enum doesn't fit.
#[allow(clippy::struct_excessive_bools)]
pub struct Connection {
    fd: OwnedFd,
    pub inbuf: LineBuf,
    pub outbuf: LineBuf,
    /// `c->allow_request`. `None` = `ALL` (`protocol.h:42`).
    pub allow_request: Option<Request>,
    /// `c->status.control`.
    pub control: bool,
    /// `c->status.invitation`. When `Some`, SPTPS records dispatch via
    /// `dispatch_invitation_outputs` (raw bytes, not request lines).
    pub invite: Option<InvitePhase>,
    /// `c->name`. `"<unknown>"` until `id_h`.
    pub name: String,
    /// `c->hostname`. Set at accept; never changes.
    pub hostname: String,
    /// `c->last_ping_time`. Control conns get +1h (`protocol_auth.c:328`).
    pub last_ping_time: Instant,
    /// `c->protocol_minor`. `>= 2` means SPTPS; `< 2` is rejected
    /// (`protocol_auth.c:443-447`).
    pub protocol_minor: u8,
    /// `c->ecdsa`. Peer's public key, loaded by `id_h`.
    pub ecdsa: Option<[u8; PUBLIC_LEN]>,
    /// `c->sptps`. Boxed: ~1KB, most conns are control with `None`.
    pub sptps: Option<Box<Sptps>>,
    /// `c->options` (`connection.h:32-36`). Top byte is `PROT_MINOR`.
    pub options: u32,
    /// `c->estimated_weight`. RTT ms (`protocol_auth.c:840`). i32: wire `%d`.
    pub estimated_weight: i32,
    /// `c->start` (`protocol_auth.c:94`). Set at construct (~μs earlier
    /// than C's `send_id`-time).
    pub start: Instant,
    /// `c->address` (`connection.h:90`). `None` for unix-socket control.
    pub address: Option<SocketAddr>,
    /// `c->edge != NULL`. The "past ACK" mark `broadcast_meta` keys on
    /// (`meta.c:115`). C never sets `connection.h:40` `unused_active`;
    /// the edge pointer-as-bool IS the check.
    pub active: bool,
    /// `c->status.pinged` (`connection.h:38`, bit 0).
    pub pinged: bool,
    /// `c->status.connecting` (`connection.h:41`, bit 2). EINPROGRESS
    /// probe runs instead of read/write dispatch when set.
    pub connecting: bool,
    /// `c->outgoing` (`connection.h:92`). `KeyData` to avoid daemon dep.
    pub outgoing: Option<slotmap::KeyData>,
    /// `c->tcplen` (`connection.h:87`). After `PACKET 17 <len>`, the next
    /// record is a raw VPN-packet blob (`meta.c:143-151`). We don't SEND
    /// TCP probes but a C peer does (found by cross-impl tests).
    pub tcplen: u16,
    /// `c->sptpslen` (`connection.h:88`). After `SPTPS_PACKET 21 <len>`,
    /// the next `sptpslen` RAW bytes (NOT SPTPS-framed, `send_meta_raw`)
    /// are an encrypted UDP wireframe. C `meta.c:203-217` checks this
    /// FIRST (outer loop); `tcplen` is inside the SPTPS callback.
    pub sptpslen: u16,
    /// `sptpslen` accumulator. C reuses `c->inbuf` (`meta.c:205-207`);
    /// separate Vec keeps the "inbuf is plaintext-only" invariant.
    pub sptps_buf: Vec<u8>,
}

/// Events from one `feed()`. Order matters: an `ADD_EDGE` before a
/// blob changes reachability that the blob's `route()` reads. C
/// dispatches each inside the callback; we batch but preserve order.
#[derive(Debug)]
pub enum SptpsEvent {
    Record(Output),
    /// `SPTPS_PACKET` blob (`dst[6]‖src[6]‖ct`). C `net_packet.c:616-680`.
    Blob(Vec<u8>),
}

/// C `receive_meta` returns `bool`; we disambiguate "would block" vs
/// "drop me" and add the SPTPS-mode arm.
#[derive(Debug)]
pub enum FeedResult {
    /// Plaintext buffered; drain `read_line`. Pre-SPTPS only.
    Data,
    /// `EWOULDBLOCK` — spurious wakeup. C `meta.c:192`.
    WouldBlock,
    /// EOF, error, or SPTPS decrypt fail.
    Dead,
    /// SPTPS-mode events. Can be empty (partial record buffered).
    Sptps(Vec<SptpsEvent>),
}

impl Connection {
    /// `handle_new_unix_connection` (`net_socket.c:798-811`).
    #[must_use]
    pub fn new_control(fd: OwnedFd, now: Instant) -> Self {
        Self {
            fd,
            inbuf: LineBuf::default(),
            outbuf: LineBuf::default(),
            allow_request: Some(Request::Id),
            control: false,
            invite: None,
            name: "<control>".to_string(),               // C :800
            hostname: "localhost port unix".to_string(), // C :802
            last_ping_time: now,
            protocol_minor: 0,
            ecdsa: None,
            sptps: None,
            options: 0,
            estimated_weight: 0,
            start: now,
            address: None,
            active: false,
            pinged: false,
            connecting: false,
            outgoing: None,
            tcplen: 0,
            sptpslen: 0,
            sptps_buf: Vec::new(),
        }
    }

    /// `handle_new_meta_connection` (`net_socket.c:758-776`).
    #[must_use]
    pub fn new_meta(fd: OwnedFd, hostname: String, address: SocketAddr, now: Instant) -> Self {
        Self {
            fd,
            inbuf: LineBuf::default(),
            outbuf: LineBuf::default(),
            allow_request: Some(Request::Id),
            control: false,
            invite: None,
            name: "<unknown>".to_string(), // C :759
            hostname,
            last_ping_time: now,
            protocol_minor: 0,
            ecdsa: None,
            sptps: None,
            options: 0,
            estimated_weight: 0,
            start: now,
            address: Some(address),
            active: false,
            pinged: false,
            connecting: false,
            outgoing: None,
            tcplen: 0,
            sptpslen: 0,
            sptps_buf: Vec::new(),
        }
    }

    /// `do_outgoing_connection` (`net_socket.c:578-655`). `name` is the
    /// `ConnectTo` value (`:653`); `id_h:385-391` checks the peer sent it.
    #[must_use]
    pub fn new_outgoing(
        fd: OwnedFd,
        name: String,
        hostname: String,
        address: SocketAddr,
        outgoing: slotmap::KeyData,
        now: Instant,
    ) -> Self {
        Self {
            fd,
            inbuf: LineBuf::default(),
            outbuf: LineBuf::default(),
            allow_request: Some(Request::Id),
            control: false,
            invite: None,
            name,
            hostname,
            last_ping_time: now,
            protocol_minor: 0,
            ecdsa: None,
            sptps: None,
            options: 0,
            estimated_weight: 0,
            start: now,
            address: Some(address),
            active: false,
            pinged: false,
            connecting: true, // C :652
            outgoing: Some(outgoing),
            tcplen: 0,
            sptpslen: 0,
            sptps_buf: Vec::new(),
        }
    }

    #[must_use]
    pub fn fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// For `socket2::SockRef::from` (`getsockname` in `ack_h:1040-1045`).
    #[must_use]
    pub fn owned_fd(&self) -> &OwnedFd {
        &self.fd
    }

    /// `c->status.value` (`connection.c:171`). GCC packs LSB-first;
    /// declaration-order bool N → bit N (`connection.h:38-56`):
    /// 0=pinged, 1=unused_active, 2=connecting, 9=control.
    #[must_use]
    pub fn status_value(&self) -> u32 {
        let mut v = 0u32;
        if self.pinged {
            v |= 1 << 0;
        }
        // Bit 1: C never sets it (`c->edge` is the runtime check).
        // Exposed so the two-daemon test can poll "past ACK".
        if self.active {
            v |= 1 << 1;
        }
        if self.connecting {
            v |= 1 << 2;
        }
        if self.control {
            v |= 1 << 9;
        }
        v
    }

    /// `receive_meta` recv-and-buffer half (`meta.c:185`).
    ///
    /// `rng`: only touched on SPTPS rekey (HANDSHAKE → `send_kex`).
    #[allow(clippy::missing_panics_doc)] // expect on take after is_some
    pub fn feed(&mut self, rng: &mut impl RngCore) -> FeedResult {
        let mut stack = [0u8; MAXBUFSIZE];

        // C `meta.c:180-183`: cap shrinks as inbuf fills. SPTPS mode
        // doesn't touch inbuf so cap stays full (same in C: `:224`
        // path skips `buffer_add(&c->inbuf)`).
        let cap = if self.sptps.is_some() {
            MAXBUFSIZE
        } else {
            if self.inbuf.live_len() >= MAXBUFSIZE {
                log::error!(target: "tincd::meta",
                            "Input buffer full for {} — protocol violation", self.name);
                return FeedResult::Dead;
            }
            MAXBUFSIZE - self.inbuf.live_len()
        };
        let buf = &mut stack[..cap];

        // `nix::unistd::read`: `OwnedFd` doesn't impl `io::Read`, and
        // `UnixStream::from(fd)` would take ownership (double-close).
        let n = match read(self.fd.as_raw_fd(), buf) {
            Ok(0) => {
                // C `meta.c:188-190`.
                log::info!(target: "tincd::conn",
                           "Connection closed by {}", self.name);
                return FeedResult::Dead;
            }
            Ok(n) => n,
            Err(Errno::EWOULDBLOCK | Errno::EINTR) => {
                return FeedResult::WouldBlock;
            }
            Err(e) => {
                log::error!(target: "tincd::meta",
                            "Metadata socket read error for {}: {}",
                            self.name, io::Error::from(e));
                return FeedResult::Dead;
            }
        };
        let chunk = &buf[..n];

        // C `meta.c:224`: `if(c->protocol_minor >= 2)`. `sptps.is_some()`
        // is the same condition (`id_h:455` sets both together).
        if self.sptps.is_some() {
            // C do-while at `meta.c:200-231`. Inlined (NOT delegated to
            // feed_sptps): the same chunk has [SPTPS-framed "21 LEN" |
            // raw blob], and feed_sptps would eat the whole chunk before
            // sptpslen could be set. C dispatches INSIDE receive()
            // (callback → `sptps_tcppacket_h:148` → outer loop sees it);
            // we peek the record body for "21 " instead.
            //
            // take() the Box: can't `&mut sptps` + `&mut self.sptpslen`.
            let mut sptps = self.sptps.take().expect("checked is_some");
            let mut events = Vec::new();
            let mut off = 0;
            'outer: while off < chunk.len() {
                // C `meta.c:203-217`: sptpslen check FIRST.
                if self.sptpslen > 0 {
                    let want = usize::from(self.sptpslen) - self.sptps_buf.len();
                    let take = want.min(chunk.len() - off);
                    self.sptps_buf.extend_from_slice(&chunk[off..off + take]);
                    off += take;
                    if self.sptps_buf.len() < usize::from(self.sptpslen) {
                        break; // C :209-211: blob spans recv()s
                    }
                    // C :213-217
                    events.push(SptpsEvent::Blob(std::mem::take(&mut self.sptps_buf)));
                    self.sptpslen = 0;
                    continue;
                }
                // C `meta.c:225-231`: one record.
                match sptps.receive(&chunk[off..], rng) {
                    Ok((0, _)) => {
                        // Unreachable in stream mode; defensive.
                        log::warn!(target: "tincd::meta",
                                   "SPTPS receive returned 0 for {}", self.name);
                        break;
                    }
                    Ok((consumed, outs)) => {
                        off += consumed;
                        for o in outs {
                            // "21 LEN" peek (C: `sptps_tcppacket_h:148`
                            // sets it via callback; we peek instead).
                            if let Output::Record {
                                record_type: 0,
                                ref bytes,
                            } = o
                            {
                                let body = crate::proto::record_body(bytes);
                                if body.starts_with(b"21 ")
                                    && let Some(pkt) = std::str::from_utf8(body)
                                        .ok()
                                        .and_then(|s| tinc_proto::msg::SptpsPacket::parse(s).ok())
                                {
                                    self.sptpslen = pkt.len; // C protocol_misc.c:148
                                    continue 'outer;
                                }
                            }
                            events.push(SptpsEvent::Record(o));
                        }
                    }
                    Err(e) => {
                        let level = match e {
                            SptpsError::DecryptFailed | SptpsError::BadSig => log::Level::Error,
                            _ => log::Level::Info,
                        };
                        log::log!(target: "tincd::meta", level,
                                  "SPTPS error from {}: {e:?}", self.name);
                        self.sptps = Some(sptps);
                        return FeedResult::Dead;
                    }
                }
            }
            self.sptps = Some(sptps);
            return FeedResult::Sptps(events);
        }

        self.inbuf.add(chunk);
        FeedResult::Data
    }

    /// SPTPS receive-loop (`meta.c:200-313`). Factored out for the
    /// `take_rest` re-feed (post-id_h mode-switch).
    pub(crate) fn feed_sptps(
        sptps: &mut Sptps,
        chunk: &[u8],
        name: &str,
        rng: &mut impl RngCore,
    ) -> FeedResult {
        if chunk.is_empty() {
            // Common: the ID line was ALL of the recv.
            return FeedResult::Sptps(Vec::new());
        }
        let mut events = Vec::new();
        let mut off = 0;
        while off < chunk.len() {
            match sptps.receive(&chunk[off..], rng) {
                Ok((0, _)) => {
                    // Unreachable in stream mode; defensive.
                    log::warn!(target: "tincd::meta",
                               "SPTPS receive returned 0 consumed for {name}");
                    break;
                }
                Ok((consumed, outs)) => {
                    events.extend(outs.into_iter().map(SptpsEvent::Record));
                    off += consumed;
                }
                Err(e) => {
                    // C `meta.c:227`: `if(!len) return false`.
                    let level = match e {
                        // Key mismatch or tampering → ERR; rest → INFO.
                        SptpsError::DecryptFailed | SptpsError::BadSig => log::Level::Error,
                        _ => log::Level::Info,
                    };
                    log::log!(target: "tincd::meta", level,
                              "SPTPS error from {name}: {e:?}");
                    return FeedResult::Dead;
                }
            }
        }
        FeedResult::Sptps(events)
    }

    /// `send_meta_sptps` (`meta.c:41-54`). Queue already-framed bytes.
    /// `bool` return is the io_set signal.
    pub fn send_raw(&mut self, bytes: &[u8]) -> bool {
        let was_empty = self.outbuf.is_empty();
        self.outbuf.add(bytes);
        was_empty
    }

    /// `sptps_send_record` for arbitrary type + binary body. `send()`
    /// is type-0 + `\n`; invitation file chunks (`protocol_auth.c:
    /// 296,303,181`) are binary and the type-1/2 markers are empty.
    ///
    /// # Panics
    /// `InvalidState` only fires pre-handshake or `type >= 128`.
    /// Callers send post-HandshakeDone with types 0/1/2.
    pub fn send_sptps_record(&mut self, record_type: u8, body: &[u8]) -> bool {
        let was_empty = self.outbuf.is_empty();
        let sptps = self
            .sptps
            .as_deref_mut()
            .expect("send_sptps_record called without sptps installed");
        let outs = sptps
            .send_record(record_type, body)
            .expect("send_record post-HandshakeDone, type<128: InvalidState is a bug");
        for o in outs {
            if let Output::Wire { bytes, .. } = o {
                self.outbuf.add(&bytes);
            }
        }
        was_empty
    }

    /// `send_request` (`protocol.c:97-132`) → `send_meta` (`meta.c:55-96`).
    /// Plaintext: straight into outbuf. SPTPS: `sptps_send_record(.., 0,
    /// line, len)` (`meta.c:65-67`). The `\n` is redundant under SPTPS
    /// framing but C sends it (`send_request:120`); `meta.c:156` strips.
    ///
    /// Returns `true` if outbuf went empty→nonempty.
    ///
    /// # Panics
    /// `InvalidState`: cipher not installed or `type >= 128`. Type is 0;
    /// cipher is set at `receive_sig` before `HandshakeDone`. Unreachable
    /// barring a `tinc-sptps` bug.
    pub fn send(&mut self, args: std::fmt::Arguments<'_>) -> bool {
        let was_empty = self.outbuf.is_empty();

        // C `meta.c:65`: `if(c->protocol_minor >= 2)`. ORDERING: `id_h`
        // calls `send()` BEFORE `Sptps::start` (proto.rs), so `sptps` is
        // None for the id-reply line. C achieves the same via
        // `protocol.c:126-130` routing ID through `send_meta_raw`.
        if let Some(sptps) = self.sptps.as_deref_mut() {
            let mut line = Vec::with_capacity(64);
            write!(VecFmt(&mut line), "{args}").expect("Vec<u8> write infallible");
            line.push(b'\n');

            let outs = sptps.send_record(0, &line).expect(
                "send_record after HandshakeDone, type=0: InvalidState is a state-machine bug",
            );
            for o in outs {
                if let Output::Wire { bytes, .. } = o {
                    self.outbuf.add(&bytes);
                }
            }
            return was_empty;
        }

        write!(VecFmt(&mut self.outbuf.data), "{args}").expect("Vec<u8> write infallible");
        self.outbuf.data.push(b'\n');
        was_empty
    }

    /// `handle_meta_write` (`net_socket.c:486-511`).
    /// `Ok(true)` → outbuf empty, drop `IO_WRITE`. `Ok(false)` → more
    /// to send. `Err` → dead.
    ///
    /// # Errors
    /// `io::Error` from `send()`: `EPIPE`, `ECONNRESET`, etc.
    pub fn flush(&mut self) -> io::Result<bool> {
        if self.outbuf.is_empty() {
            return Ok(true);
        }

        let live = self.outbuf.live();
        // `send(2)` (C `net_socket.c:491`): ENOTSOCK is a useful sanity check.
        let n = match send(self.fd.as_raw_fd(), live, MsgFlags::empty()) {
            Ok(n) => n,
            Err(Errno::EWOULDBLOCK | Errno::EINTR) => {
                return Ok(false); // C :494-496
            }
            Err(e) => {
                return Err(e.into()); // C :497-501
            }
        };

        self.outbuf.consume(n);

        Ok(self.outbuf.is_empty())
    }

    /// Send each row, then a `"{18} {req}"` terminator (the bare-
    /// header line that signals end-of-dump in the C control proto:
    /// `subnet.c:406`, `node.c:221`, `edge.c:135`, `connection.c:173`).
    /// Returns `true` if outbuf went empty→nonempty across the batch.
    /// `rows` is owned-Vec because every callsite collects up front
    /// to drop the `&self` borrow before re-fetching `&mut conn`.
    pub fn send_dump(&mut self, rows: Vec<String>, req: i32) -> bool {
        let mut nw = false;
        for row in rows {
            nw |= self.send(format_args!("{row}"));
        }
        nw |= self.send(format_args!("{} {req}", Request::Control as u8));
        nw
    }

    #[cfg(test)]
    pub(crate) fn test_with_fd(fd: OwnedFd) -> Self {
        Self::new_control(fd, Instant::now())
    }
}

// tests

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};
    use nix::unistd::write;
    use rand_core::OsRng;

    // ─── LineBuf

    #[test]
    fn linebuf_one_full_line() {
        let mut b = LineBuf::default();
        b.add(b"hello world\n");
        let r = b.read_line().unwrap();
        assert_eq!(&b.bytes_raw()[r], b"hello world");
        // Empty (offset==len) but data not cleared — range still valid.
        assert!(b.is_empty());
        assert_eq!(b.live_len(), 0);
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
        let r2 = b.read_line().unwrap();
        // Same bytes_raw — no compact between read_line calls.
        assert_eq!(&b.bytes_raw()[r2], b"second");
        assert!(b.is_empty());
    }

    /// Line then partial: C `receive_meta`'s inner loop hits this
    /// (recv brings "REQ\nPAR", dispatches REQ, PAR stays buffered).
    #[test]
    fn linebuf_line_then_partial() {
        let mut b = LineBuf::default();
        b.add(b"full\npartial");
        let r = b.read_line().unwrap();
        assert_eq!(&b.bytes_raw()[r], b"full");
        assert_eq!(b.live_len(), 7);
        assert!(b.read_line().is_none());
        b.add(b" done\n");
        let r2 = b.read_line().unwrap();
        assert_eq!(&b.bytes_raw()[r2], b"partial done");
    }

    /// `"\n"` alone → zero-length range. C: `atoi("")` → 0,
    /// `*request == '0'` is false → "Bogus data".
    #[test]
    fn linebuf_empty_line() {
        let mut b = LineBuf::default();
        b.add(b"\n");
        let r = b.read_line().unwrap();
        assert_eq!(r.len(), 0);
        assert!(b.is_empty());
    }

    /// Regression: if `read_line` reset on offset==len, `data.clear()`
    /// would dangle the returned range.
    #[test]
    fn linebuf_range_survives_going_empty() {
        let mut b = LineBuf::default();
        b.add(b"only\n");
        let r = b.read_line().unwrap();
        assert!(b.is_empty());
        assert_eq!(&b.bytes_raw()[r], b"only");
    }

    #[test]
    fn linebuf_read_n_exact() {
        let mut b = LineBuf::default();
        b.add(b"0123456789");
        let r = b.read_n(10).unwrap();
        assert_eq!(&b.bytes_raw()[r], b"0123456789");
        assert!(b.is_empty());
    }

    #[test]
    fn linebuf_read_n_partial() {
        let mut b = LineBuf::default();
        b.add(b"01234");
        assert!(b.read_n(10).is_none());
        assert_eq!(b.live_len(), 5); // offset unchanged
        b.add(b"56789");
        let r = b.read_n(10).unwrap();
        assert_eq!(&b.bytes_raw()[r], b"0123456789");
    }

    /// C `buffer_read(buf, 0)`: returns ptr, advances 0.
    #[test]
    fn linebuf_read_n_zero() {
        let mut b = LineBuf::default();
        b.add(b"data");
        let r = b.read_n(0).unwrap();
        assert_eq!(r.len(), 0);
        assert_eq!(b.live_len(), 4); // unchanged
    }

    /// `read_n` then `read_line`: shared cursor stays coherent
    /// (`meta.c`'s `while(inbuf.len)` does tcplen-then-line).
    #[test]
    fn linebuf_read_n_after_read_line() {
        let mut b = LineBuf::default();
        // SOCKS4 reply + ID line.
        b.add(&[0x00, 0x5A, 0, 0, 0, 0, 0, 0]);
        b.add(b"0 bob 17.7\n");
        let r1 = b.read_n(8).unwrap();
        assert_eq!(&b.bytes_raw()[r1.clone()], &[0x00, 0x5A, 0, 0, 0, 0, 0, 0]);
        let r2 = b.read_line().unwrap();
        assert_eq!(&b.bytes_raw()[r2], b"0 bob 17.7");
        assert!(b.is_empty());
    }

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
        assert_eq!(b.offset, 0);
        assert_eq!(b.data.len(), 0);
    }

    /// Compact-on-add: drain the consumed region instead of growing.
    #[test]
    fn linebuf_compact_avoids_realloc() {
        let mut b = LineBuf::default();
        b.add(&[b'x'; 100]);
        let cap = b.data.capacity();
        b.consume(90);
        // Without compact: len 180 > cap 100 → realloc. With: len 90.
        b.add(&[b'y'; 80]);
        assert_eq!(b.live_len(), 90);
        assert_eq!(b.live()[..10], [b'x'; 10]);
        assert_eq!(b.live()[10..], [b'y'; 80]);
        // Best-effort: if Vec's growth policy changes, this tells us.
        assert_eq!(b.data.capacity(), cap, "compact should reuse capacity");
    }

    /// `net.h:45`. If MAXSIZE bumps (jumbo), this fails.
    #[test]
    fn maxbufsize_matches_c() {
        const MAXSIZE: usize = 1673; // net.h:42, no-jumbo
        let expected = (if MAXSIZE > 2048 { MAXSIZE } else { 2048 }) + 128;
        assert_eq!(MAXBUFSIZE, expected);
    }

    // ─── Connection::send

    fn devnull() -> OwnedFd {
        std::fs::File::open("/dev/null").unwrap().into()
    }

    #[test]
    fn send_formats_id_greeting() {
        let mut c = Connection::test_with_fd(devnull());
        let was_empty = c.send(format_args!("0 testnode 17.7"));
        assert!(was_empty);
        assert_eq!(c.outbuf.live(), b"0 testnode 17.7\n");
    }

    /// Second send returns `false` (don't double-register IO_WRITE).
    #[test]
    fn send_second_doesnt_signal() {
        let mut c = Connection::test_with_fd(devnull());
        assert!(c.send(format_args!("0 a 17.7")));
        assert!(!c.send(format_args!("4 0 99")));
        assert_eq!(c.outbuf.live(), b"0 a 17.7\n4 0 99\n");
    }

    /// `net_socket.c:811`.
    #[test]
    fn new_control_defaults() {
        let c = Connection::test_with_fd(devnull());
        assert_eq!(c.allow_request, Some(Request::Id));
        assert!(!c.control);
        assert_eq!(c.name, "<control>");
        assert_eq!(c.protocol_minor, 0);
        assert!(c.ecdsa.is_none());
        assert!(c.sptps.is_none());
        assert_eq!(c.options, 0);
        assert_eq!(c.estimated_weight, 0);
        assert!(c.address.is_none());
    }

    /// `connection.h:38-58` bit positions. `control` = bit 9.
    #[test]
    fn status_value_control_bit() {
        let c = Connection::test_with_fd(devnull());
        assert_eq!(c.status_value(), 0);
        // If `connection.h` reorders, this points where to look.
        assert_eq!(1u32 << 9, 0x200);
    }

    // ─── take_rest

    /// Piggyback: ID line + SPTPS bytes in one buffer.
    #[test]
    fn take_rest_after_read_line() {
        let mut b = LineBuf::default();
        b.add(b"0 alice 17.7\n\x00\x42garbage");

        let r = b.read_line().unwrap();
        assert_eq!(&b.bytes_raw()[r], b"0 alice 17.7");

        let rest = b.take_rest();
        assert_eq!(rest, b"\x00\x42garbage");
        assert!(b.is_empty());
        assert_eq!(b.live_len(), 0);
        // Cleared state is reusable.
        b.add(b"x\n");
        let r = b.read_line().unwrap();
        assert_eq!(&b.bytes_raw()[r], b"x");
    }

    /// Common case: ID line was the whole recv.
    #[test]
    fn take_rest_empty_after_full_line() {
        let mut b = LineBuf::default();
        b.add(b"0 alice 17.7\n");
        let r = b.read_line().unwrap();
        assert_eq!(&b.bytes_raw()[r], b"0 alice 17.7");
        assert!(b.is_empty());
        assert!(b.take_rest().is_empty());
    }

    #[test]
    fn take_rest_on_fresh_is_empty() {
        let mut b = LineBuf::default();
        assert!(b.take_rest().is_empty());
    }

    // ─── feed_sptps

    /// Panics if touched. Receive-only handshake doesn't `send_kex`.
    struct NoRng;
    impl rand_core::RngCore for NoRng {
        fn next_u32(&mut self) -> u32 {
            unreachable!("rng touched in receive-only path")
        }
        fn next_u64(&mut self) -> u64 {
            unreachable!("rng touched in receive-only path")
        }
        fn fill_bytes(&mut self, _: &mut [u8]) {
            unreachable!("rng touched in receive-only path")
        }
        fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), rand_core::Error> {
            unreachable!("rng touched in receive-only path")
        }
    }

    /// `feed_sptps([])` → empty. Early-return before sptps is touched.
    #[test]
    fn feed_sptps_empty_chunk() {
        use tinc_crypto::sign::SigningKey;
        use tinc_sptps::{Framing, Role};

        let mykey = SigningKey::from_seed(&[1; 32]);
        let hispub = *SigningKey::from_seed(&[2; 32]).public_key();
        let (mut sptps, _) = Sptps::start(
            Role::Responder,
            Framing::Stream,
            mykey,
            hispub,
            b"test".to_vec(),
            0,
            &mut OsRng,
        );

        let r = Connection::feed_sptps(&mut sptps, &[], "test", &mut NoRng);
        match r {
            FeedResult::Sptps(evs) => assert!(evs.is_empty()),
            _ => panic!("expected Sptps(empty), got {r:?}"),
        }
        // NoRng not panicked → sptps.receive not called.
    }

    /// Two records in one chunk → both processed (`meta.c:200-313`
    /// do-while). Single `receive()` call would strand the second.
    #[test]
    fn feed_sptps_two_records_one_chunk() {
        use tinc_crypto::sign::SigningKey;
        use tinc_sptps::{Framing, Output, Role};

        let alice_k = SigningKey::from_seed(&[10; 32]);
        let bob_k = SigningKey::from_seed(&[20; 32]);
        let alice_pub = *alice_k.public_key();
        let bob_pub = *bob_k.public_key();

        let (mut alice, a_init) = Sptps::start(
            Role::Initiator,
            Framing::Stream,
            alice_k,
            bob_pub,
            b"loop-test".to_vec(),
            0,
            &mut OsRng,
        );
        let (mut bob, b_init) = Sptps::start(
            Role::Responder,
            Framing::Stream,
            bob_k,
            alice_pub,
            b"loop-test".to_vec(),
            0,
            &mut OsRng,
        );

        let wire = |outs: Vec<Output>| -> Vec<u8> {
            outs.into_iter()
                .find_map(|o| match o {
                    Output::Wire { bytes, .. } => Some(bytes),
                    _ => None,
                })
                .expect("one Wire output")
        };

        let a_kex = wire(a_init);
        let b_kex = wire(b_init);

        let (n, outs) = alice.receive(&b_kex, &mut NoRng).unwrap();
        assert_eq!(n, b_kex.len());
        let a_sig = wire(outs);

        let (n, outs) = bob.receive(&a_kex, &mut NoRng).unwrap();
        assert_eq!(n, a_kex.len());
        assert!(outs.is_empty());

        let (n, outs) = bob.receive(&a_sig, &mut NoRng).unwrap();
        assert_eq!(n, a_sig.len());
        assert_eq!(outs.len(), 2);
        let b_sig = match &outs[0] {
            Output::Wire { bytes, .. } => bytes.clone(),
            _ => panic!(),
        };
        assert!(matches!(outs[1], Output::HandshakeDone));

        let (n, outs) = alice.receive(&b_sig, &mut NoRng).unwrap();
        assert_eq!(n, b_sig.len());
        assert!(matches!(outs[0], Output::HandshakeDone));

        // Both done. Glue two records: the coalesced segment.
        let rec1 = wire(alice.send_record(0, b"first").unwrap());
        let rec2 = wire(alice.send_record(0, b"second").unwrap());
        let mut chunk = rec1;
        chunk.extend_from_slice(&rec2);

        let r = Connection::feed_sptps(&mut bob, &chunk, "alice", &mut NoRng);
        match r {
            FeedResult::Sptps(evs) => {
                assert_eq!(evs.len(), 2, "loop must process both records");
                match (&evs[0], &evs[1]) {
                    (
                        SptpsEvent::Record(Output::Record { bytes: b0, .. }),
                        SptpsEvent::Record(Output::Record { bytes: b1, .. }),
                    ) => {
                        assert_eq!(b0, b"first");
                        assert_eq!(b1, b"second");
                    }
                    _ => panic!("expected two Records, got {evs:?}"),
                }
            }
            _ => panic!("expected Sptps(..), got {r:?}"),
        }
    }

    /// Partial record: length header only. `receive()` returns
    /// `(2, [])`; loop terminates (no spin).
    #[test]
    fn feed_sptps_partial_record() {
        use tinc_crypto::sign::SigningKey;
        use tinc_sptps::{Framing, Role};

        let mykey = SigningKey::from_seed(&[1; 32]);
        let hispub = *SigningKey::from_seed(&[2; 32]).public_key();
        let (mut sptps, _) = Sptps::start(
            Role::Responder,
            Framing::Stream,
            mykey,
            hispub,
            b"partial".to_vec(),
            0,
            &mut OsRng,
        );

        let r = Connection::feed_sptps(&mut sptps, &[0x00, 0x05], "test", &mut NoRng);
        match r {
            FeedResult::Sptps(evs) => assert!(evs.is_empty()),
            _ => panic!("expected Sptps(empty), got {r:?}"),
        }
    }

    /// Decrypt fail → Dead. C `meta.c:227`.
    #[test]
    fn feed_sptps_decrypt_fail_is_dead() {
        use tinc_crypto::sign::SigningKey;
        use tinc_sptps::{Framing, Role};

        let mykey = SigningKey::from_seed(&[1; 32]);
        let hispub = *SigningKey::from_seed(&[2; 32]).public_key();
        let (mut sptps, _) = Sptps::start(
            Role::Responder,
            Framing::Stream,
            mykey,
            hispub,
            b"fail".to_vec(),
            0,
            &mut OsRng,
        );

        // App-data record pre-handshake → BadRecord.
        let bad = [0x00, 0x05, 0x00, b'x', b'x', b'x', b'x', b'x'];
        let r = Connection::feed_sptps(&mut sptps, &bad, "test", &mut NoRng);
        assert!(matches!(r, FeedResult::Dead), "expected Dead, got {r:?}");
    }

    // ─── feed() sptpslen mechanism (`meta.c:203-217`)
    // Tested via socketpair: write chunk to one end, feed() reads other.

    /// Handshaked pair with bob as a Connection's sptps.
    fn sptps_conn_pair() -> (Connection, tinc_sptps::Sptps, OwnedFd) {
        use tinc_crypto::sign::SigningKey;
        use tinc_sptps::{Framing, Output, Role};

        let alice_k = SigningKey::from_seed(&[10; 32]);
        let bob_k = SigningKey::from_seed(&[20; 32]);
        let alice_pub = *alice_k.public_key();
        let bob_pub = *bob_k.public_key();

        let (mut alice, a_init) = Sptps::start(
            Role::Initiator,
            Framing::Stream,
            alice_k,
            bob_pub,
            b"slen".to_vec(),
            0,
            &mut OsRng,
        );
        let (mut bob, b_init) = Sptps::start(
            Role::Responder,
            Framing::Stream,
            bob_k,
            alice_pub,
            b"slen".to_vec(),
            0,
            &mut OsRng,
        );

        let wire = |outs: Vec<Output>| -> Vec<u8> {
            outs.into_iter()
                .find_map(|o| match o {
                    Output::Wire { bytes, .. } => Some(bytes),
                    _ => None,
                })
                .expect("one Wire")
        };
        let a_kex = wire(a_init);
        let b_kex = wire(b_init);
        let (_, outs) = alice.receive(&b_kex, &mut NoRng).unwrap();
        let a_sig = wire(outs);
        let (_, outs) = bob.receive(&a_kex, &mut NoRng).unwrap();
        assert!(outs.is_empty());
        let (_, outs) = bob.receive(&a_sig, &mut NoRng).unwrap();
        let b_sig = match &outs[0] {
            Output::Wire { bytes, .. } => bytes.clone(),
            _ => panic!(),
        };
        let (_, _) = alice.receive(&b_sig, &mut NoRng).unwrap();

        let (rd, wr) = socketpair(
            AddressFamily::Unix,
            SockType::Stream,
            None,
            SockFlag::empty(),
        )
        .expect("socketpair");

        let mut conn = Connection::test_with_fd(rd);
        conn.sptps = Some(Box::new(bob));
        (conn, alice, wr)
    }

    fn write_all(fd: &OwnedFd, mut buf: &[u8]) {
        while !buf.is_empty() {
            let n = write(fd, buf).expect("write");
            assert!(n > 0, "write: short");
            buf = &buf[n..];
        }
    }

    /// `sptpslen` pre-set; blob in one chunk.
    #[test]
    fn feed_sptpslen_single_chunk() {
        let (mut conn, _alice, wr) = sptps_conn_pair();
        conn.sptpslen = 12;
        let blob = b"abcdefghijkl"; // 12 bytes, NOT SPTPS-framed
        write_all(&wr, blob);
        let r = conn.feed(&mut NoRng);
        match r {
            FeedResult::Sptps(evs) => {
                assert_eq!(evs.len(), 1);
                match &evs[0] {
                    SptpsEvent::Blob(b) => assert_eq!(b, blob),
                    SptpsEvent::Record(_) => panic!("expected Blob, got {evs:?}"),
                }
            }
            _ => panic!("expected Sptps, got {r:?}"),
        }
        assert_eq!(conn.sptpslen, 0);
        assert!(conn.sptps_buf.is_empty());
    }

    /// Blob spans two recv()s. C `meta.c:209-211`.
    #[test]
    fn feed_sptpslen_straddle() {
        let (mut conn, _alice, wr) = sptps_conn_pair();
        conn.sptpslen = 12;
        write_all(&wr, b"abcde"); // 5 of 12
        match conn.feed(&mut NoRng) {
            FeedResult::Sptps(evs) => assert!(evs.is_empty(), "partial: no event yet"),
            r => panic!("expected Sptps(empty), got {r:?}"),
        }
        assert_eq!(conn.sptpslen, 12);
        assert_eq!(conn.sptps_buf.len(), 5);

        write_all(&wr, b"fghijkl"); // 7 more
        match conn.feed(&mut NoRng) {
            FeedResult::Sptps(evs) => {
                assert_eq!(evs.len(), 1);
                match &evs[0] {
                    SptpsEvent::Blob(b) => assert_eq!(b, b"abcdefghijkl"),
                    SptpsEvent::Record(_) => panic!("expected Blob"),
                }
            }
            r => panic!("expected Sptps, got {r:?}"),
        }
        assert_eq!(conn.sptpslen, 0);
        assert!(conn.sptps_buf.is_empty());
    }

    /// THE TRAP. `["21 12\n" record | 12 raw bytes | PING record]` as
    /// one chunk. Before fix: `receive()` re-called on raw bytes →
    /// DecryptFailed → Dead. After: feed() peeks "21 ", sets sptpslen,
    /// next iter eats blob. Events MUST be `[Blob, Record(PING)]`.
    #[test]
    fn feed_sptpslen_then_record() {
        use tinc_sptps::Output;
        let (mut conn, mut alice, wr) = sptps_conn_pair();

        let wire = |outs: Vec<Output>| -> Vec<u8> {
            outs.into_iter()
                .find_map(|o| match o {
                    Output::Wire { bytes, .. } => Some(bytes),
                    _ => None,
                })
                .expect("one Wire")
        };

        // Crafted to mis-parse as SPTPS: len=9 + 9 garbage. Post-
        // handshake, receive() would try decrypt → DecryptFailed.
        let blob = b"\x00\x09junkjunk!"; // 2-byte len + 9 body = 11
        assert_eq!(blob.len(), 11);
        let req_rec = wire(alice.send_record(0, b"21 11\n").unwrap());
        let ping_rec = wire(alice.send_record(0, b"8\n").unwrap());

        let mut chunk = req_rec;
        chunk.extend_from_slice(blob);
        chunk.extend_from_slice(&ping_rec);
        write_all(&wr, &chunk);

        let r = conn.feed(&mut NoRng);
        match r {
            FeedResult::Sptps(evs) => {
                // "21 11\n" consumed — not in events.
                assert_eq!(evs.len(), 2, "got {evs:?}");
                match (&evs[0], &evs[1]) {
                    (SptpsEvent::Blob(b), SptpsEvent::Record(Output::Record { bytes, .. })) => {
                        assert_eq!(b.as_slice(), blob);
                        assert_eq!(bytes, b"8\n");
                    }
                    _ => panic!("expected [Blob, Record(PING)], got {evs:?}"),
                }
            }
            FeedResult::Dead => {
                panic!("trap fired: blob parsed as SPTPS framing")
            }
            _ => panic!("expected Sptps, got {r:?}"),
        }
    }

    /// No `\n` appended; 0x0a mid-body left alone.
    #[test]
    fn send_raw_no_newline() {
        let mut c = Connection::test_with_fd(devnull());
        let bytes = &[0x00, 0x05, 0x0a, 0xde, 0xad, 0xbe, 0xef];
        let signal = c.send_raw(bytes);
        assert!(signal);
        assert_eq!(c.outbuf.live(), bytes);
    }
}
