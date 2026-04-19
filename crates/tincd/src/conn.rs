//! `connection_t` (`connection.h:86-127`) + `buffer_t` (`buffer.c`).
//!
//! C's `sptps_t` callback re-enters `connection_t`; we can't (`&mut
//! self.sptps` aliases `&mut self`). `receive()` returns `Vec<Output>`
//! for the daemon to dispatch after the borrow ends.
//!
//! `LineBuf::read_line` returns `Range<usize>` not `&str`: C
//! `buffer_readline`'s `char*` is invalidated by the next add; the
//! borrow checker rejects the equivalent.

use std::fmt::Write as _;
use std::io;
use std::net::SocketAddr;
use std::ops::Range;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::time::Instant;

use nix::errno::Errno;
use nix::sys::socket::send;
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
    /// Compacts if doing so avoids a realloc (simpler than the
    /// `offset/7 > len/8` heuristic).
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
    /// NO reset-on-empty here: the returned range would be into a
    /// cleared buffer. Reset lives in
    /// `add()`/`consume()` instead.
    pub fn read_line(&mut self) -> Option<Range<usize>> {
        let live = &self.data[self.offset..];
        let nl = live.iter().position(|&b| b == b'\n')?;
        let start = self.offset;
        let end = start + nl;
        self.offset = end + 1;
        Some(start..end)
    }

    /// `buffer_read(buffer, n)`. Exact-N read. Used for the SOCKS
    /// reply (binary, fixed-length, not
    /// line-terminated). Same range-validity contract as `read_line`.
    pub const fn read_n(&mut self, n: usize) -> Option<Range<usize>> {
        if self.live_len() < n {
            return None;
        }
        let start = self.offset;
        self.offset += n;
        Some(start..start + n)
    }

    #[must_use]
    pub const fn live_len(&self) -> usize {
        self.data.len() - self.offset
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
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

    /// Advance the cursor (after partial `send()`).
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

/// `connection_t`.
// `struct_excessive_bools`: `connection_status_t` is a packed
// bitfield. The bits are independent (a conn is active AND pinged
// in steady state); a state-enum doesn't fit.
#[allow(clippy::struct_excessive_bools)] // mirrors C bitfield: independent bits, not a state enum
pub struct Connection {
    fd: OwnedFd,
    pub inbuf: LineBuf,
    pub outbuf: LineBuf,
    /// `c->allow_request`. `None` = `ALL` (`protocol.h:42`).
    pub allow_request: Option<Request>,
    /// `c->status.control`.
    pub control: bool,
    /// Set only by `new_control` (unix-socket accept). Gates the
    /// `^cookie` branch in `handle_id` — control is local-only.
    pub is_unix_ctl: bool,
    /// `c->status.pcap` (bit 10). Set by `REQ_PCAP`; read by
    /// `send_pcap`.
    pub pcap: bool,
    /// `c->outmaclength` repurposed. Legacy MAC length field reused
    /// as pcap snaplen — pcap subscribers don't use legacy crypto so
    /// the field was free. 0 = full packet (`if(c->outmaclength &&
    /// c->outmaclength < len)`). We use u16: MTU is 1518, snaplen >
    /// that captures everything anyway.
    pub pcap_snaplen: u16,
    /// `c->status.invitation`. When `Some`, SPTPS records dispatch via
    /// `dispatch_invitation_outputs` (raw bytes, not request lines).
    pub invite: Option<InvitePhase>,
    /// `c->name`. `"<unknown>"` until `id_h`.
    pub name: String,
    /// `c->hostname`. Set at accept; never changes.
    pub hostname: String,
    /// `c->last_ping_time`. Control conns get +1h, refreshed on stream writes.
    pub last_ping_time: Instant,
    /// `c->protocol_minor`. `>= 2` means SPTPS; `< 2` is rejected.
    pub protocol_minor: u8,
    /// `c->ecdsa`. Peer's public key, loaded by `id_h`.
    pub ecdsa: Option<[u8; PUBLIC_LEN]>,
    /// `c->sptps`. Boxed: ~1KB, most conns are control with `None`.
    pub sptps: Option<Box<Sptps>>,
    /// `c->options` (`connection.h:32-36`). Top byte is `PROT_MINOR`.
    pub options: crate::proto::ConnOptions,
    /// `c->estimated_weight`. RTT ms. i32: wire `%d`.
    pub estimated_weight: i32,
    /// `c->start`. Set at construct (~μs earlier than upstream's
    /// `send_id`-time).
    pub start: Instant,
    /// `c->address` (`connection.h:90`). `None` for unix-socket control.
    pub address: Option<SocketAddr>,
    /// `c->edge != NULL`. The "past ACK" mark `broadcast_meta` keys
    /// on. Upstream never sets `unused_active`; the edge
    /// pointer-as-bool IS the check.
    pub active: bool,
    /// When `active` flipped true (`on_ack`). `None` pre-ACK. Read by
    /// the autoconnect snapshot builder so a freshly-activated
    /// shortcut conn isn't reaped before `min_hold`.
    pub activated_at: Option<Instant>,
    /// `c->status.pinged` (`connection.h:38`, bit 0).
    pub pinged: bool,
    /// Send-time of the in-flight meta `PING`. `None` once `PONG`
    /// arrives. Separate from `last_ping_time` (that field is
    /// overloaded as a generic activity stamp).
    pub last_ping_sent: Option<Instant>,
    /// Last meta `PING`→`PONG` round-trip, ms. 0 = unmeasured.
    pub ping_rtt_ms: u32,
    /// RFC 6298 SRTT (α=1/8) over `ping_rtt_ms`. Seeded at `on_ack`
    /// from the connect-time weight so the first few pings can pull
    /// an inflated handshake sample down. 0 = unseeded.
    pub srtt_ms: u32,
    /// Last time this conn re-gossiped its own edge weight. Gates
    /// the 5·PingInterval re-advertise floor.
    pub last_weight_gossip: Option<Instant>,
    /// `c->status.connecting` (`connection.h:41`, bit 2). EINPROGRESS
    /// probe runs instead of read/write dispatch when set.
    pub connecting: bool,
    /// `c->outgoing` (`connection.h:92`). `KeyData` to avoid daemon dep.
    pub outgoing: Option<slotmap::KeyData>,
    /// `c->tcplen`. After `PACKET 17 <len>`, the next record is a
    /// raw VPN-packet blob. We don't SEND TCP probes but a C peer
    /// does (found by cross-impl tests).
    pub tcplen: u16,
    /// `c->sptpslen` (`connection.h:88`). After `SPTPS_PACKET 21 <len>`,
    /// the next `sptpslen` RAW bytes (NOT SPTPS-framed,
    /// `send_meta_raw`) are an encrypted UDP wireframe. Checked
    /// FIRST (outer loop); `tcplen` is inside the SPTPS callback.
    pub sptpslen: u16,
    /// `sptpslen` accumulator. Upstream reuses `c->inbuf`; separate
    /// Vec keeps the "inbuf is plaintext-only" invariant.
    pub sptps_buf: Vec<u8>,

    // ─── Per-host config extracted at id_h. Upstream retains the
    // whole `c->config_tree`; we extract just the keys send_ack/ack_h
    // read. None = absent.
    /// `hosts/NAME` `IndirectData`.
    pub host_indirect: Option<bool>,
    /// `hosts/NAME` `TCPOnly`.
    pub host_tcponly: Option<bool>,
    /// `hosts/NAME` `ClampMSS`.
    pub host_clamp_mss: Option<bool>,
    /// `hosts/NAME` `Weight`.
    pub host_weight: Option<i32>,
    /// PMTU clamp. MIN of per-host
    /// `PMTU` and global tinc.conf `PMTU` — both clamp, both `&& mtu
    /// < n->mtu`. `None` = neither set. Named `cap` not `host_` since
    /// the value may come from the global config.
    pub pmtu_cap: Option<u16>,
    /// `c->status.log` + `c->log_level` (`connection.h:51,112`). When
    /// `Some`, this conn receives `REQ_LOG` records for messages at or
    /// above the level. C uses C debug-level ints (`-1..=10`); we map
    /// to `log::Level` at the `REQ_LOG` arm. `c->status.log_color` is
    /// not stored: we don't ANSI-format (`env_logger` does, but we
    /// send the bare `args()` — see `log_tap.rs`).
    pub log_level: Option<log::Level>,
    /// Debug level before this conn's `REQ_SET_DEBUG`; restored on close.
    pub prev_debug_level: Option<i32>,
}

/// Events from one `feed()`. Order matters: an `ADD_EDGE` before a
/// blob changes reachability that the blob's `route()` reads. C
/// dispatches each inside the callback; we batch but preserve order.
#[derive(Debug)]
pub enum SptpsEvent {
    Record(Output),
    /// `SPTPS_PACKET` blob (`dst[6]‖src[6]‖ct`).
    Blob(Vec<u8>),
}

/// `receive_meta` returns `bool`; we disambiguate "would block" vs
/// "drop me" and add the SPTPS-mode arm.
#[derive(Debug)]
pub enum FeedResult {
    /// Plaintext buffered; drain `read_line`. Pre-SPTPS only.
    Data,
    /// `EWOULDBLOCK` — spurious wakeup.
    WouldBlock,
    /// EOF, error, or SPTPS decrypt fail.
    Dead,
    /// SPTPS-mode events. Can be empty (partial record buffered).
    Sptps(Vec<SptpsEvent>),
}

impl Connection {
    /// Shared field defaults for the three constructors. Everything
    /// the variants don't care about lives here so adding a new
    /// `Connection` field touches one place, not three 40-line
    /// literals.
    fn new_base(fd: OwnedFd, name: String, hostname: String, now: Instant) -> Self {
        Self {
            fd,
            inbuf: LineBuf::default(),
            outbuf: LineBuf::default(),
            allow_request: Some(Request::Id),
            control: false,
            is_unix_ctl: false,
            pcap: false,
            pcap_snaplen: 0,
            invite: None,
            name,
            hostname,
            last_ping_time: now,
            protocol_minor: 0,
            ecdsa: None,
            sptps: None,
            options: crate::proto::ConnOptions::empty(),
            estimated_weight: 0,
            start: now,
            address: None,
            active: false,
            activated_at: None,
            pinged: false,
            last_ping_sent: None,
            ping_rtt_ms: 0,
            srtt_ms: 0,
            last_weight_gossip: None,
            connecting: false,
            outgoing: None,
            tcplen: 0,
            sptpslen: 0,
            sptps_buf: Vec::new(),
            host_indirect: None,
            host_tcponly: None,
            host_clamp_mss: None,
            host_weight: None,
            pmtu_cap: None,
            log_level: None,
            prev_debug_level: None,
        }
    }

    /// `handle_new_unix_connection`.
    #[must_use]
    pub fn new_control(fd: OwnedFd, now: Instant) -> Self {
        Self {
            is_unix_ctl: true,
            ..Self::new_base(
                fd,
                "<control>".to_string(),           // C :800
                "localhost port unix".to_string(), // C :802
                now,
            )
        }
    }

    /// `handle_new_meta_connection`.
    #[must_use]
    pub fn new_meta(fd: OwnedFd, hostname: String, address: SocketAddr, now: Instant) -> Self {
        Self {
            address: Some(address),
            ..Self::new_base(fd, "<unknown>".to_string() /* C :759 */, hostname, now)
        }
    }

    /// `do_outgoing_connection`. `name` is the `ConnectTo` value;
    /// `id_h` checks the peer sent it.
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
            address: Some(address),
            connecting: true, // C :652
            outgoing: Some(outgoing),
            ..Self::new_base(fd, name, hostname, now)
        }
    }
}

impl AsFd for Connection {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl Connection {
    /// For `socket2::SockRef::from` (`getsockname` in `ack_h:1040-1045`).
    #[must_use]
    pub const fn owned_fd(&self) -> &OwnedFd {
        &self.fd
    }

    /// `c->status.value`. GCC packs LSB-first; declaration-order
    /// bool N → bit N: 0=pinged, `1=unused_active`, 2=connecting,
    /// 9=control.
    #[must_use]
    pub const fn status_value(&self) -> u32 {
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
        // Bit 11: `status.log` (`connection.h:51`).
        if self.log_level.is_some() {
            v |= 1 << 11;
        }
        if self.pcap {
            v |= 1 << 10;
        }
        v
    }

    /// `receive_meta` recv-and-buffer half.
    ///
    /// `rng`: only touched on SPTPS rekey (HANDSHAKE → `send_kex`).
    #[allow(clippy::missing_panics_doc)] // expect on take after is_some
    pub fn feed(&mut self, rng: &mut impl RngCore) -> FeedResult {
        let mut stack = [0u8; MAXBUFSIZE];

        // Cap shrinks as inbuf fills. SPTPS mode doesn't touch inbuf
        // so cap stays full (the SPTPS path skips `buffer_add`).
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
        let n = match read(&self.fd, buf) {
            Ok(0) => {
                if self.control {
                    log::debug!(target: "tincd::conn",
                                "Connection closed by {}", self.name);
                } else {
                    log::info!(target: "tincd::conn",
                               "Connection closed by {}", self.name);
                }
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

        // `if(c->protocol_minor >= 2)`. `sptps.is_some()` is the
        // same condition (`id_h` sets both together).
        if self.sptps.is_some() {
            // do-while. Inlined (NOT delegated to
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
                // sptpslen check FIRST.
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
                // One record.
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
                                // Same gate check_gate would apply.
                                if self.allow_request.is_none()
                                    && body.starts_with(b"21 ")
                                    && let Some(pkt) = std::str::from_utf8(body)
                                        .ok()
                                        .and_then(|s| tinc_proto::msg::SptpsPacket::parse(s).ok())
                                {
                                    self.sptpslen = pkt.len;
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

    /// SPTPS receive-loop. Factored out for the `take_rest` re-feed (post-id_h mode-switch).
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
                    // `if(!len) return false`.
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

    /// `send_meta_sptps`. Queue already-framed bytes.
    /// `bool` return is the `io_set` signal.
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

    /// `send_request` → `send_meta`. Plaintext: straight into
    /// outbuf. SPTPS: `sptps_send_record(.., 0, line, len)`. The
    /// `\n` is redundant under SPTPS framing but upstream sends it;
    /// the receive side strips.
    ///
    /// Returns `true` if outbuf went empty→nonempty.
    ///
    /// # Panics
    /// `InvalidState`: cipher not installed or `type >= 128`. Type is 0;
    /// cipher is set at `receive_sig` before `HandshakeDone`. Unreachable
    /// barring a `tinc-sptps` bug.
    pub fn send(&mut self, args: std::fmt::Arguments<'_>) -> bool {
        let was_empty = self.outbuf.is_empty();

        // `if(c->protocol_minor >= 2)`. ORDERING: `id_h` calls
        // `send()` BEFORE `Sptps::start` (proto.rs), so `sptps` is
        // None for the id-reply line. Upstream achieves the same by
        // routing ID through `send_meta_raw`.
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

    /// `handle_meta_write`.
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
        // `send(2)`: ENOTSOCK is a useful sanity check.
        let n = match send(self.fd.as_raw_fd(), live, crate::msg_nosignal()) {
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
    /// header line that signals end-of-dump in the control proto).
    /// Returns `true` if outbuf went empty→nonempty across the batch.
    /// `rows` is owned-Vec because every callsite collects up front
    /// to drop the `&self` borrow before re-fetching `&mut conn`.
    pub(crate) fn send_dump(&mut self, rows: Vec<String>, req: crate::proto::CtlReq) -> bool {
        let mut nw = false;
        for row in rows {
            nw |= self.send(format_args!("{row}"));
        }
        nw |= self.send(format_args!("{} {req}", Request::Control));
        nw
    }

    #[cfg(test)]
    pub(crate) fn test_with_fd(fd: OwnedFd) -> Self {
        Self::new_control(fd, Instant::now())
    }
}

#[cfg(test)]
mod tests;
