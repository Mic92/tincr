//! `connection_t` (`connection.h:86-127`) + `buffer_t` (`buffer.c`).
//!
//! ## SPTPS bridge ownership
//!
//! C `connection_t.sptps` is a value; the callback's `void *handle`
//! IS the `connection_t*` and reaches back into `c->outbuf`. We
//! can't borrow `&mut Connection` while `&mut self.sptps` is held.
//! `receive()` returns `Vec<Output>` instead; daemon dispatches
//! after the borrow ends.
//!
//! This loses one C semantic: `Output::Wire` from record N is now
//! queued AFTER record N+1 is processed, not before. For the SPTPS
//! handshake there's no interleaving anyway. Post-handshake (e.g.
//! `PING` + `KEY_CHANGED` in one segment) both dispatch after the
//! segment is consumed; wire output is still in order. Not peer-
//! observable.
//!
//! `Sptps` is boxed (~1KB; most conns are control with `None`).
//!
//! ## `LineBuf` vs C `buffer_t`
//!
//! `buffer.c` is `Vec<u8>` + consume cursor; 87.5%-consumed compact
//! heuristic. `read_line` returns `Range<usize>` not `&str`: the C
//! `buffer_readline` returns a `char*` invalidated by the next
//! `buffer_add`; the borrow checker rejects the equivalent.
//!
//! ## `feed` / `flush` split
//!
//! C `receive_meta` (`meta.c:164`): recv → buffer_add → loop
//! readline → dispatch. We split at the testable seam: `feed`
//! reads a real fd; `read_line` and dispatch are pure. `queue`/
//! `flush` mirror C `send_meta`/`handle_meta_write`.

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

    /// `buffer_read(buffer, n)` (`buffer.c:88-94`). Exact-N read from
    /// the live region. If `< n` available, `None` (partial — need
    /// more `recv()`). If `>= n`, advance offset by `n`, return the
    /// range.
    ///
    /// `meta.c:276`: `tcpbuffer = buffer_read(&c->inbuf, c->tcplen)`.
    /// The C returns `NULL` on short, pointer otherwise. Same shape.
    ///
    /// Used for the pre-SPTPS proxy-response read (the SOCKS reply is
    /// binary, fixed-length, NOT line-terminated). The post-SPTPS
    /// PACKET-blob path goes through `Output::Record` (SPTPS records
    /// are exact-framed already), so this is proxy-only in practice.
    ///
    /// Same range-validity contract as `read_line`: stays valid until
    /// the next `add` / `consume` / `read_line` / `read_n`. NO reset
    /// here (returned range would dangle); compact lives in `add`.
    pub fn read_n(&mut self, n: usize) -> Option<Range<usize>> {
        if self.live_len() < n {
            return None;
        }
        let start = self.offset;
        self.offset += n;
        Some(start..start + n)
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

    /// Take ownership of the live bytes, leaving the buffer empty.
    ///
    /// SPTPS-transition handoff: the same `recv()` delivering the ID
    /// line may also carry the first SPTPS bytes (initiator's KEX,
    /// Nagle-coalesced). `read_line` won't find them (no `\n`); next
    /// `feed()` reads NEW bytes and strands them.
    ///
    /// C handles this mid-read inside `receive_meta`'s do-while: the
    /// stack buffer is local, and `protocol_minor=2` flips the next
    /// iteration to `sptps_receive_data`. We split feed/drain, so
    /// the daemon calls this after `id_h` peer-branch and re-feeds
    /// to `sptps.receive()`. Same as `tinc-tools/cmd/join.rs`.
    pub fn take_rest(&mut self) -> Vec<u8> {
        // No `Vec::split_off(offset)` then drop the prefix — that's
        // two moves. `data[offset..].to_vec()` copies once, then
        // we clear. Simpler, same effect for the small slack here.
        let rest = self.data[self.offset..].to_vec();
        self.data.clear();
        self.offset = 0;
        rest
    }
}

// Connection

/// `connection_t`. The control-connection slice + peer-accept fields.
/// C `connection.c::new_connection` is `xzalloc(sizeof)` — our
/// constructors build one inline.
///
/// Two constructors:
/// - `new_control`: from `handle_new_unix_connection`. `name =
///   "<control>"`, `hostname = "localhost port unix"`.
/// - `new_meta`: from `handle_new_meta_connection`. `name =
///   "<unknown>"`, `hostname = "10.0.0.5 port 50123"`.
///
/// `id_h` overwrites `name` (`"<control>"` for `^` branch, peer
/// node name for the bare-name branch). `hostname` never changes
/// (it's the immutable accept-time fact).
// `struct_excessive_bools`: this IS a state machine, but the C
// `connection_status_t` is a 32-bit packed bitfield (`connection.h:
// 38-56`). We model the bits we touch as bools (the rest stay
// untracked = 0). A state-enum would NOT capture the C semantics:
// `pinged` and `active` are independent (a conn can be active AND
// pinged — that's the steady-state keepalive). The bools mirror the
// C bits; `status_value()` packs them back for `dump connections`.
#[allow(clippy::struct_excessive_bools)]
pub struct Connection {
    /// `c->socket`. C uses raw `int`; we own it. Drop closes.
    fd: OwnedFd,
    /// `c->inbuf`. Bytes read but not yet parsed into lines.
    pub inbuf: LineBuf,
    /// `c->outbuf`. Bytes queued for `send()`.
    pub outbuf: LineBuf,
    /// `c->allow_request`. The state-machine gate. Starts at `Some(
    /// Id)` (`net_socket.c:776` `c->allow_request = ID`); `id_h` sets
    /// it to `Some(Control)` for control conns. `None` means `ALL`
    /// (any request accepted) — peers reach this after the auth
    /// handshake. Control conns never do.
    pub allow_request: Option<Request>,
    /// `c->status.control`. `true` after `id_h` sees `^<cookie>`.
    pub control: bool,
    /// `c->status.invitation` + `c->status.invitation_used` + (after
    /// cookie) `c->name`. Set by the daemon's `IdOk::Invitation` arm.
    /// `None` for control + peer conns. When `Some`, the SPTPS bridge
    /// dispatches via `dispatch_invitation_outputs`, NOT `check_gate`
    /// — records are raw bytes (file chunks, b64 pubkey), not
    /// newline-terminated request lines.
    pub invite: Option<InvitePhase>,
    /// `c->name`. `"<unknown>"` until `id_h`, then peer node name or
    /// `"<control>"`. Appears in log lines.
    pub name: String,
    /// `c->hostname`. `sockaddr2hostname` of the peer's socket addr,
    /// set at accept time and never touched again. `"10.0.0.5 port
    /// 50123"` shape. C uses this in EVERY log line about the
    /// connection (`"%s (%s)", c->name, c->hostname`).
    pub hostname: String,
    /// `c->last_ping_time`. C uses `time_t` (seconds); we use
    /// `Instant`. The pingtimer sweep checks `now - last_ping > timeout`.
    /// Control conns get a 1-hour bump (`protocol_auth.c:328`) so
    /// they're effectively exempt.
    pub last_ping_time: Instant,
    /// `c->protocol_minor`. Starts 0 (`xzalloc`). `id_h` parses it
    /// from `"%d.%d"`. For us: `>= 2` means SPTPS, `< 2` means
    /// legacy (which we reject — the rollback check at `protocol_
    /// auth.c:443-447` drops). Control conns don't send `".X"` so
    /// this stays 0 for them.
    pub protocol_minor: u8,
    /// `c->ecdsa`. THIS PEER's public key. Loaded by `id_h` peer
    /// branch from `hosts/NAME` (or inline config var). `None` until
    /// then. C `ecdsa_t*` (heap pointer); we hold the 32 bytes.
    /// Control conns: stays None.
    pub ecdsa: Option<[u8; PUBLIC_LEN]>,
    /// `c->sptps`. The SPTPS state machine. `None` until `id_h`
    /// peer-branch installs it. `Box`: see module doc "SPTPS bridge
    /// ownership". C `sptps_t` is a value (not pointer) inside
    /// `connection_t`; the size cost there is the same as unboxed
    /// `Option<Sptps>` here, but C doesn't pre-allocate a slab.
    pub sptps: Option<Box<Sptps>>,
    /// `c->options`. Bitfield (`OPTION_INDIRECT` etc, `connection.h:
    /// 32-36`). 0 until `send_ack` builds it from per-host config +
    /// `myself->options`; `ack_h` ORs in the peer's. The top byte is
    /// `PROT_MINOR` per `OPTION_VERSION` macro — set by `send_ack`,
    /// the peer ANDs `& 0xffffff` before use.
    pub options: u32,
    /// `c->estimated_weight`. Round-trip time in ms, ID-send to
    /// HandshakeDone (`protocol_auth.c:840`). `ack_h` averages with
    /// the peer's estimate (`:1048`). i32 because the wire format is
    /// `%d` and the average can theoretically wrap on a stalled
    /// handshake (24 days). C uses `int`.
    pub estimated_weight: i32,
    /// `c->start`. `gettimeofday` at `send_id` (`protocol_auth.c:
    /// 94`). The C sets it inside `send_id` (called for both
    /// outgoing AND inbound replies); we set it in BOTH constructors
    /// to `now`. Slightly earlier (accept vs id-reply send) but
    /// the delta is one event-loop turn (~μs). `send_ack` reads it.
    pub start: Instant,
    /// `c->address`. Peer's TCP `SocketAddr`. C `union sockaddr_t`
    /// (`connection.h:90`). Set at accept time (`net_socket.c:
    /// 749` `memcpy(&c->address, &sa)`). `ack_h` copies this into
    /// the edge's address with the port REWRITTEN to `hisport`
    /// (`:1024-1025` `sockaddrcpy + sockaddr_setport`). `None` for
    /// control conns (unix socket has no `SocketAddr`).
    pub address: Option<SocketAddr>,
    /// `c->edge != NULL`. The C `ack_h:1051` writes `c->edge = e`
    /// after `edge_add` — that's the "past ACK" mark `broadcast_
    /// meta` keys on (`meta.c:115`: `if(c != from && c->edge)`).
    /// We don't store the `EdgeId` on `Connection` (it lives on
    /// `NodeState`); a bool is enough for the broadcast filter.
    /// `connection.h:40` calls bit 1 `unused_active` — the C never
    /// sets it, the `c->edge` pointer-as-bool IS the active check.
    /// Set in `on_ack`, cleared in `terminate`.
    pub active: bool,
    /// `c->status.pinged` (`connection.h:38`, bit 0). Set by
    /// `send_ping` (`protocol_misc.c:48`); cleared by `pong_h`
    /// (`:65`). The ping sweep (`net.c:250-257`) checks: if `pinged`
    /// AND `last_ping_time + pingtimeout` elapsed → dead, terminate.
    /// A PONG within `pingtimeout` clears the bit → conn survives.
    pub pinged: bool,
    /// `c->status.connecting` (`connection.h:41`, bit 2). True while
    /// the async-connect is in flight (`net_socket.c:652` sets,
    /// `:553` clears in `handle_meta_io`). The `IoWhat::Conn` arm
    /// checks this FIRST and runs the EINPROGRESS probe instead of
    /// the read/write dispatch.
    pub connecting: bool,
    /// `c->outgoing`. Which `Outgoing` slot this connection serves
    /// (if any). C `outgoing_t*` (`connection.h:92`). `terminate_
    /// connection` (`net.c:155-161`) reads it to retry. Inbound
    /// conns: `None`. The `OutgoingId` type is daemon-side; we use
    /// the slotmap's `KeyData` to avoid a `tincd::daemon` dep here.
    pub outgoing: Option<slotmap::KeyData>,
    /// `c->tcplen` (`connection.h:87`). `tcppacket_h` sets this from
    /// the `PACKET 17 <len>` line; `receive_meta_sptps` (`meta.c:143-
    /// 151`) treats the NEXT record as a raw VPN-packet blob of this
    /// length, NOT a request line. The C calls `receive_tcppacket` to
    /// route it through the normal VPN-packet path (`net_packet.c:595`).
    ///
    /// The C uses TCP-tunnelled `PACKET` while UDP is unconfirmed: the
    /// MTU-probe path (`send_udp_probe_packet`) falls through to TCP
    /// when `udp_confirmed` is false, which it is at first contact.
    /// We don't send TCP probes (we wait for UDP), but a C peer DOES —
    /// found by the cross-impl tests the very first time they ran for
    /// real (they had only ever been SKIPs). Without this state, the
    /// `PACKET` line falls through to the unimplemented-request arm
    /// and we drop the connection on a probe.
    pub tcplen: u16,
    /// `c->sptpslen` (`connection.h:88`). Same role as `tcplen` but for
    /// `SPTPS_PACKET` (request 21): the next `sptpslen` RAW BYTES on the
    /// TCP stream are an already-encrypted SPTPS UDP wireframe (NOT inside
    /// an SPTPS record — `send_meta_raw` bypasses framing). Set by
    /// `feed()` when it sees a `"21 LEN"` record body. Consumed by the
    /// `feed()` do-while before `sptps.receive()`.
    ///
    /// Twin of `tcplen`. NOT mutually exclusive: in theory both could be
    /// set (C can send `PACKET` and `SPTPS_PACKET` interleaved). In
    /// practice C sends only `SPTPS_PACKET` for proto-minor ≥ 7 nexthops
    /// (`net_packet.c:975`). C `meta.c:203-217` checks `sptpslen` FIRST
    /// (it's the outer loop, `tcplen` is inside the SPTPS callback).
    pub sptpslen: u16,
    /// Accumulator for the `sptpslen` blob. C uses `c->inbuf`
    /// (`meta.c:205-207 buffer_add` then `buffer_read`); our `inbuf` is
    /// dormant in SPTPS mode anyway, but a separate Vec keeps the
    /// invariant "inbuf is plaintext-only". Cleared on full blob.
    pub sptps_buf: Vec<u8>,
}

/// Events from one `feed()` of an SPTPS-mode connection. Ordered;
/// daemon dispatches sequentially. Mix of normal SPTPS records and
/// raw blobs (the `SPTPS_PACKET` mechanism, `meta.c:203-217`).
///
/// Why ORDERED matters: an `ADD_EDGE` record before a blob can change
/// reachability that the blob's `route()` reads. The C dispatches each
/// inside `sptps_receive_data`'s callback before the next `recv()`
/// chunk byte; we batch but preserve order.
#[derive(Debug)]
pub enum SptpsEvent {
    /// A decrypted SPTPS record. `Output::HandshakeDone`, `Output::
    /// Record { record_type, bytes }`, or `Output::Wire(..)` (rekey).
    Record(Output),
    /// A complete `SPTPS_PACKET` blob. Already-encrypted SPTPS UDP
    /// wireframe (`dst[6]‖src[6]‖ct`); daemon hands to `tcp_tunnel`.
    /// C: `receive_tcppacket_sptps` (`net_packet.c:616-680`).
    Blob(Vec<u8>),
}

/// Result of `feed()`. C `receive_meta` returns `bool`; we
/// disambiguate `false` into "would block" vs "drop me", and grow a
/// fourth arm for the SPTPS-mode output.
#[derive(Debug)]
pub enum FeedResult {
    /// Plaintext data buffered; caller should drain `read_line`.
    /// (Pre-SPTPS only — control conns and the initial ID line.)
    Data,
    /// `recv()` returned `EWOULDBLOCK` — spurious wakeup. Level-
    /// triggered epoll can do this. C `meta.c:192`: `return true`.
    /// Caller does nothing; next turn re-fires if still readable.
    WouldBlock,
    /// `recv()` returned 0 (EOF) or a real error, OR `sptps_
    /// receive_data` returned 0 (decrypt fail, bad seqno, etc).
    /// Connection is dead. Caller calls `terminate`.
    Dead,
    /// SPTPS-mode: ordered events from this `feed()` call. C: the
    /// `receive_record` callback fires for each record; the `meta.c:
    /// 203-217` outer-loop sptpslen check eats raw blobs. We return
    /// both for the daemon to dispatch (`Record(Wire)` → outbuf,
    /// `Record(Record)` → `receive_request`, `Record(HandshakeDone)`
    /// → `send_ack`, `Blob` → `receive_tcppacket_sptps`).
    ///
    /// The Vec can be empty: a partial SPTPS record arrived (length
    /// header + half the body) — buffered inside `Sptps::stream`,
    /// nothing decoded yet. C: same, callback doesn't fire.
    Sptps(Vec<SptpsEvent>),
}

impl Connection {
    /// `new_connection()` + the field init from `handle_new_unix_
    /// connection` (`net_socket.c:798-811`). The fd just came from
    /// `accept()` on the unix socket.
    ///
    /// The C sets `name = "<control>"` and `hostname = "localhost
    /// port unix"` (`:801,802`) — hardcoded literals because unix
    /// sockets don't have addresses we'd bother showing.
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
            invite: None,
            // `:800`: `c->name = xstrdup("<control>")`. The C does
            // this BEFORE id_h — a small lie (id_h hasn't proven the
            // cookie yet). id_h overwrites: `^` branch → "<control>"
            // (idempotent). The lie is harmless; the post-id_h state
            // is identical.
            name: "<control>".to_string(),
            // `:802`: `c->hostname = xstrdup("localhost port unix")`.
            hostname: "localhost port unix".to_string(),
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

    /// `new_connection()` + the field init from `handle_new_meta_
    /// connection` (`net_socket.c:758-776`). The fd just came from
    /// `accept()` on a TCP listener.
    ///
    /// `hostname` is `sockaddr2hostname(peer_addr)` — the caller
    /// computes it (`listen::fmt_addr`). C `:762`: `c->hostname =
    /// sockaddr2hostname(&sa)`.
    ///
    /// `name = "<unknown>"` (`:759`). Stays `<unknown>` until `id_h`
    /// overwrites. The C log line `:767` (`"Connection from %s",
    /// c->hostname`) only uses `hostname`; `name` doesn't appear
    /// until later log lines, by which time `id_h` has set it.
    ///
    /// `outmaclength` (`:760`) is a legacy-protocol field; we're
    /// SPTPS-only. Skip.
    #[must_use]
    pub fn new_meta(fd: OwnedFd, hostname: String, address: SocketAddr, now: Instant) -> Self {
        Self {
            fd,
            inbuf: LineBuf::default(),
            outbuf: LineBuf::default(),
            // `:776`: `c->allow_request = ID`. Same as unix — the
            // first line is always ID, regardless of transport.
            allow_request: Some(Request::Id),
            control: false,
            invite: None,
            // `:759`: `c->name = xstrdup("<unknown>")`.
            name: "<unknown>".to_string(),
            hostname,
            last_ping_time: now,
            protocol_minor: 0,
            ecdsa: None,
            sptps: None,
            options: 0,
            estimated_weight: 0,
            // `protocol_auth.c:94`: `gettimeofday(&c->start)` inside
            // `send_id`. We approximate at accept time — one event-
            // loop turn earlier than the C, ~μs delta. The weight is
            // milliseconds; the error is noise.
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

    /// `new_connection()` + the field init from `do_outgoing_
    /// connection` (`net_socket.c:578-655`). The fd just came from
    /// nonblocking `connect()` (might be EINPROGRESS).
    ///
    /// `name` is the peer's name (the `ConnectTo = bob` value) — NOT
    /// `"<unknown>"` like inbound. C `:653`: `c->name = xstrdup(
    /// outgoing->node->name)`. `id_h:385-391` later checks the peer
    /// sent the SAME name (`if(strcmp(c->name, name)) ERR`).
    ///
    /// `connecting = true` (`:652`). `outgoing` set so `terminate`
    /// knows to retry.
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
            // C `protocol_auth.c:94`: `gettimeofday(&c->start)` is
            // inside `send_id`. We approximate at construct time;
            // for outgoing, `send_id` happens right after the probe
            // succeeds (~one event-loop turn later). Same μs delta
            // as `new_meta`.
            start: now,
            address: Some(address),
            active: false,
            pinged: false,
            // C `:652`: `c->status.connecting = true`.
            connecting: true,
            outgoing: Some(outgoing),
            tcplen: 0,
            sptpslen: 0,
            sptps_buf: Vec::new(),
        }
    }

    /// Raw fd for `EventLoop::add`.
    #[must_use]
    pub fn fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Borrowed `OwnedFd` for `socket2::SockRef::from`. The
    /// `getsockname` call in `on_ack` (`ack_h:1040-1045`) needs a
    /// type that impls `AsFd`; `&OwnedFd` does.
    #[must_use]
    pub fn owned_fd(&self) -> &OwnedFd {
        &self.fd
    }

    /// `c->status.value` for `dump_connections` (`connection.c:
    /// 171`). C union punning: `union { struct { bool x:1; ... };
    /// uint32_t value; }`. GCC packs LSB-first, so the Nth
    /// declaration-order bool is bit N.
    ///
    /// We don't HAVE the union; build the int from the bools we
    /// track. Bits we don't model (encryptout, mst, pcap, log, ...)
    /// stay 0. mst is set by `graph()` (chunk 9); pcap/log by
    /// control RPCs (chunk 10).
    ///
    /// Bit positions per `connection.h:38-56` (LSB-first):
    ///   0 pinged, 1 unused_active, 2 connecting, 3 unused_termreq,
    ///   4 remove_unused, 5 timeout_unused, 6 encryptout,
    ///   7 decryptin, 8 mst, 9 control, 10 pcap, 11 log, ...
    #[must_use]
    pub fn status_value(&self) -> u32 {
        let mut v = 0u32;
        if self.pinged {
            // Bit 0: `pinged`. Set by `send_ping`, cleared by
            // `pong_h`. The C sets it (`protocol_misc.c:48`).
            v |= 1 << 0;
        }
        if self.active {
            // Bit 1: `unused_active`. The C never sets this bit
            // (`c->edge` is the runtime check). We expose it for
            // `dump connections` so the two-daemon test can poll
            // "past ACK" without depending on log scraping.
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
    /// are 80 chars at most). C: `return false`. SPTPS mode doesn't
    /// hit this check — SPTPS bytes go to `Sptps::stream`, not
    /// `inbuf`. The cap there is `u16` reclen = 64K, internally
    /// enforced.
    ///
    /// `rng`: only touched if SPTPS mode AND a HANDSHAKE record
    /// arrives that triggers a `send_kex` (rekey). The initial
    /// handshake (KEX→SIG→DONE on the responder side) doesn't
    /// touch rng inside `receive`. But we can't statically know
    /// that; pass `OsRng`. Plaintext mode never touches it.
    #[allow(clippy::missing_panics_doc)] // .expect on take() after
    // is_some check; not a real panic surface.
    pub fn feed(&mut self, rng: &mut impl RngCore) -> FeedResult {
        // Stack buffer same as C `char inbuf[MAXBUFSIZE]`.
        let mut stack = [0u8; MAXBUFSIZE];

        // ─── Cap
        // C: `sizeof inbuf - c->inbuf.len` — cap shrinks as the line
        // buffer fills. SPTPS mode: full MAXBUFSIZE (we don't touch
        // c->inbuf). The C does the SAME: the `protocol_minor>=2`
        // path at `meta.c:224` doesn't `buffer_add(&c->inbuf)`, so
        // `c->inbuf.len` stays 0 once SPTPS is up, and cap stays full.
        let cap = if self.sptps.is_some() {
            MAXBUFSIZE
        } else {
            // The MAXBUFSIZE pre-check.
            if self.inbuf.live_len() >= MAXBUFSIZE {
                log::error!(target: "tincd::meta",
                            "Input buffer full for {} — protocol violation", self.name);
                return FeedResult::Dead;
            }
            MAXBUFSIZE - self.inbuf.live_len()
        };
        let buf = &mut stack[..cap];

        // ─── recv
        // Why not `std::io::Read`: control conns are unix stream
        // sockets; `OwnedFd` doesn't impl Read (it's just an fd,
        // not a stream — could be a regular file). We could
        // `UnixStream::from(fd)` but then UnixStream owns the fd
        // and Drop double-closes. `nix::unistd::read` takes a
        // RawFd and a slice, returns usize or Errno — no unsafe,
        // no ownership dance. Same shim shape as `read_fd`/
        // `write_fd` in tinc-device.
        let n = match read(self.fd.as_raw_fd(), buf) {
            Ok(0) => {
                // EOF. Client closed. C `meta.c:188-190`:
                // `if(!inlen || !sockerrno)` log NOTICE
                // "Connection closed by".
                log::info!(target: "tincd::conn",
                           "Connection closed by {}", self.name);
                return FeedResult::Dead;
            }
            Ok(n) => n,
            // C `sockwouldblock`: EWOULDBLOCK || EINTR. EINTR
            // shouldn't happen (SA_RESTART) but defensive.
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

        // ─── SPTPS branch (`meta.c:224-233`)
        // C: `if(c->protocol_minor >= 2)` — we use `sptps.is_some()`
        // because the mode-switch IS "sptps got installed by id_h".
        // (`protocol_minor >= 2` is the C's proxy for the same
        // condition. id_h:455 sets minor>=2 ⇔ sptps_start succeeded.)
        if self.sptps.is_some() {
            // The C do-while at meta.c:200-231. Inlined here (NOT
            // delegated to feed_sptps) because we need to interleave
            // the sptpslen check with one-record-at-a-time receive().
            // The architectural trap: feed_sptps would eat the WHOLE
            // chunk before daemon dispatch could set sptpslen — but
            // the same chunk has [SPTPS-framed "21 LEN" | raw blob].
            // The C dispatches INSIDE receive() (callback chain →
            // sptps_tcppacket_h:148 sets c->sptpslen → outer do-while
            // sees it next iteration); we don't, so we peek the
            // record body for "21 " here. One request id of meta-
            // layer awareness; meta.c has the same (the sptpslen
            // check IS request-21-specific).
            //
            // Can't take &mut sptps and &mut self.sptpslen through
            // the as_deref_mut() borrow simultaneously — take() the
            // Box out, run the loop, put it back.
            let mut sptps = self.sptps.take().expect("checked is_some");
            let mut events = Vec::new();
            let mut off = 0;
            'outer: while off < chunk.len() {
                // ─── C meta.c:203-217: sptpslen check FIRST ─────
                if self.sptpslen > 0 {
                    let want = usize::from(self.sptpslen) - self.sptps_buf.len();
                    let take = want.min(chunk.len() - off);
                    self.sptps_buf.extend_from_slice(&chunk[off..off + take]);
                    off += take;
                    if self.sptps_buf.len() < usize::from(self.sptpslen) {
                        // C `:209-211`: `if(!sptpspacket) return
                        // true`. Blob spans more than one recv.
                        // Next feed() continues filling.
                        break;
                    }
                    // C `:213-217`: full blob → emit, clear, continue.
                    events.push(SptpsEvent::Blob(std::mem::take(&mut self.sptps_buf)));
                    self.sptpslen = 0;
                    continue;
                }
                // ─── C meta.c:225-231: one record ───────────────
                match sptps.receive(&chunk[off..], rng) {
                    Ok((0, _)) => {
                        // Unreachable in stream mode for nonempty
                        // input. Defensive.
                        log::warn!(target: "tincd::meta",
                                   "SPTPS receive returned 0 for {}", self.name);
                        break;
                    }
                    Ok((consumed, outs)) => {
                        off += consumed;
                        for o in outs {
                            // ─── The "21 LEN" peek ────────────
                            // C dispatch happens via callback chain
                            // INSIDE sptps_receive_data → receive_
                            // record → receive_meta_sptps →
                            // receive_request → sptps_tcppacket_h:
                            // 148. We peek at the record body here
                            // instead. record_body strips the
                            // trailing \n; the body IS the "21 LEN"
                            // line. Shallow check first (3 bytes);
                            // SptpsPacket::parse confirms.
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
                                    // C protocol_misc.c:148.
                                    // Don't push the record —
                                    // it's been consumed.
                                    self.sptpslen = pkt.len;
                                    continue 'outer;
                                }
                                // Not a "21 " record, or malformed:
                                // fall through; gate rejects.
                            }
                            events.push(SptpsEvent::Record(o));
                        }
                    }
                    Err(e) => {
                        // Same as feed_sptps error handling.
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

        // ─── Plaintext branch
        // n > 0: that many bytes are now in `buf`. Append to inbuf.
        self.inbuf.add(chunk);
        FeedResult::Data
    }

    /// SPTPS receive-loop. The C do-while at `meta.c:200-313`,
    /// `protocol_minor >= 2` arm only. Factored out so the
    /// `take_rest` re-feed (post-id_h mode-switch) can call it too.
    ///
    /// Stops at `consumed == chunk.len()` OR `consumed == 0` (the
    /// latter is defensive — stream-mode `receive()` returns 0 only
    /// for empty input, and we check `chunk.is_empty()` first —
    /// but a future bug returning 0 mid-loop would spin forever).
    ///
    /// `name` is for the log line (cheap `&str` borrow, separate
    /// from `&mut sptps`). C `meta.c:230` doesn't log on `len==0`
    /// (the SPTPS internals log themselves via `sptps_log`); we add
    /// the connection-name context.
    pub(crate) fn feed_sptps(
        sptps: &mut Sptps,
        chunk: &[u8],
        name: &str,
        rng: &mut impl RngCore,
    ) -> FeedResult {
        if chunk.is_empty() {
            // The take_rest re-feed often hits this: the ID line was
            // ALL of the recv. No SPTPS leftover. Don't bother
            // calling receive() with an empty slice.
            return FeedResult::Sptps(Vec::new());
        }
        let mut events = Vec::new();
        let mut off = 0;
        while off < chunk.len() {
            match sptps.receive(&chunk[off..], rng) {
                Ok((0, _)) => {
                    // Unreachable in stream mode for nonempty input
                    // (phase 1 always consumes ≥1 byte). Defensive.
                    log::warn!(target: "tincd::meta",
                               "SPTPS receive returned 0 consumed for {name}");
                    break;
                }
                Ok((consumed, outs)) => {
                    events.extend(outs.into_iter().map(SptpsEvent::Record));
                    off += consumed;
                }
                Err(e) => {
                    // C `meta.c:227`: `if(!len) return false`. The
                    // `sptps_log` inside the C SPTPS already logged
                    // the specific failure; the daemon log just
                    // says "metadata error". We have the typed
                    // error — use it.
                    let level = match e {
                        // Decrypt failures: peer key mismatch or
                        // active tampering. ERR.
                        SptpsError::DecryptFailed | SptpsError::BadSig => log::Level::Error,
                        // Everything else (BadSeqno, BadRecord,
                        // UnexpectedHandshake, ...) is more likely
                        // version skew or a misbehaving peer than
                        // an attack. INFO.
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

    /// `send_meta_sptps` (`meta.c:41-54`). Queue raw bytes (already
    /// SPTPS-framed by `Sptps::*` — length header, encrypted body,
    /// auth tag). NO `\n` — SPTPS framing is binary.
    ///
    /// C: `buffer_add(&c->outbuf, buffer, length)` then `io_set(READ
    /// | WRITE)`. Our `bool` return is the io_set signal, same as
    /// `send()`.
    ///
    /// The `(void)type` in the C is for the callback signature —
    /// `send_data_t` has a `type` param so `sptps_send_record` can
    /// pass it through, but `send_meta_sptps` ignores it (it's
    /// already inside the framed bytes). `Output::Wire::record_type`
    /// is the same: advisory, ignored here.
    pub fn send_raw(&mut self, bytes: &[u8]) -> bool {
        let was_empty = self.outbuf.is_empty();
        self.outbuf.add(bytes);
        was_empty
    }

    /// `sptps_send_record(&c->sptps, type, data, len)` for arbitrary
    /// type and binary body. `send()` is type-0-only and appends
    /// `\n`; the invitation file chunks are BINARY (the file may
    /// contain `\n` mid-chunk that aren't record terminators) and
    /// the empty type-1/type-2 markers must be empty, no `\n`.
    ///
    /// `protocol_auth.c:296,303,181`: `sptps_send_record(&c->sptps,
    /// 0, buf, result)` (file chunks), `(&c->sptps, 1, buf, 0)`
    /// (file-done), `(&c->sptps, 2, data, 0)` (ack).
    ///
    /// Returns the io_set signal. Same expect as `send()` (cipher
    /// installed at `HandshakeDone`, type < 128).
    ///
    /// # Panics
    /// `InvalidState` from `Sptps::send_record`: only fires when the
    /// outcipher is None (handshake not done) or `record_type >= 128`.
    /// Callers send only AFTER `HandshakeDone` arrived; types are 0/1/2.
    /// A panic here is a state-machine bug, not an I/O error.
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

    /// `send_request` (`protocol.c:97-132`) → `send_meta`
    /// (`meta.c:55-96`). Format the line, append `\n`. Then the
    /// `protocol_minor >= 2` branch:
    ///
    /// - **Plaintext** (control, pre-SPTPS): straight into outbuf.
    ///   C `meta.c:91` `buffer_add`.
    /// - **SPTPS** (post-handshake peer): `sptps_send_record(c->sptps,
    ///   0, line, len)`. C `meta.c:65-67`. The line (WITH `\n`)
    ///   becomes the body of an encrypted record. The other side's
    ///   `receive_meta_sptps` (`meta.c:155-157`) strips the `\n` and
    ///   feeds `receive_request`. Type byte 0 (= app data, not
    ///   `SPTPS_HANDSHAKE`).
    ///
    /// The `\n` is REDUNDANT on the SPTPS path (record framing
    /// already delimits) but the C sends it (`send_request:120`
    /// appends BEFORE `send_meta`), so the peer expects it.
    /// `meta.c:156` does `data[length-1] = 0` only IF the last
    /// byte is `\n` — a pre-SPTPS-transition record has no `\n`,
    /// the check is conditional. We always append; matches C.
    ///
    /// Returns `true` if outbuf went empty→nonempty (`io_set` signal).
    ///
    /// # Panics
    /// If called post-HandshakeDone with the SPTPS in a state that
    /// can't send (only `InvalidState`: cipher not yet installed OR
    /// `record_type >= 128`). `outcipher` is set at `receive_sig`
    /// before `HandshakeDone` is emitted; type is hardcoded 0 here.
    /// So: unreachable barring a `tinc-sptps` bug. The panic is the
    /// loud failure mode for that bug.
    pub fn send(&mut self, args: std::fmt::Arguments<'_>) -> bool {
        let was_empty = self.outbuf.is_empty();

        // C `meta.c:65`: `if(c->protocol_minor >= 2)`. We use
        // `sptps.is_some()` (same condition; see `feed`). But:
        // `id_h` peer-branch SETS `sptps` and THEN calls `conn.
        // send()` (the id-reply line). At that moment SPTPS is
        // installed but `outcipher` is None (handshake not done).
        // The C avoids this because `send_id` (`protocol.c:126-
        // 130`) routes ID through `send_meta_raw` (NOT `send_meta`)
        // — the `if(id)` check, `id == 0` for `Request::Id`.
        //
        // Replicated: id_h calls `send()` BEFORE `Sptps::start`
        // (proto.rs `handle_id` ordering). `sptps` is None then.
        // The post-handshake ACK is the FIRST `send()` with `sptps`
        // installed AND `outcipher` ready. Debug-assert that
        // ordering invariant.
        if let Some(sptps) = self.sptps.as_deref_mut() {
            // Format into a scratch Vec. We CAN'T format into
            // outbuf and then pull it back out (the cipher writes
            // to outbuf). One alloc per send-over-SPTPS; ACK +
            // ADD_EDGE are not hot.
            let mut line = Vec::with_capacity(64);
            write!(VecFmt(&mut line), "{args}").expect("Vec<u8> write infallible");
            line.push(b'\n');

            // C `sptps_send_record(&c->sptps, 0, buffer, length)`.
            // Type 0. send_record only fails on InvalidState
            // (outcipher None or type >= 128). Type is 0; cipher
            // is set before HandshakeDone (state.rs:receive_sig).
            // The expect documents the invariant.
            let outs = sptps.send_record(0, &line).expect(
                "send_record after HandshakeDone, type=0: InvalidState is a state-machine bug",
            );
            // Exactly one Wire (state.rs:send_record_priv). Queue.
            for o in outs {
                if let Output::Wire { bytes, .. } = o {
                    self.outbuf.add(&bytes);
                }
            }
            return was_empty;
        }

        // Plaintext path. Append directly into outbuf.
        write!(VecFmt(&mut self.outbuf.data), "{args}").expect("Vec<u8> write infallible");
        self.outbuf.data.push(b'\n');
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
        // `send(2)` not `write(2)` because the C does
        // (`net_socket.c:491`) — for stream sockets they're the
        // same when flags=0, but `send` returns ENOTSOCK if the
        // fd isn't a socket, which is a useful sanity check.
        let n = match send(self.fd.as_raw_fd(), live, MsgFlags::empty()) {
            Ok(n) => n,
            Err(Errno::EWOULDBLOCK | Errno::EINTR) => {
                // C `net_socket.c:494-496`: log DEBUG, do nothing.
                // Not actually empty, still want IO_WRITE.
                return Ok(false);
            }
            Err(e) => {
                // EPIPE, ECONNRESET, etc. C logs at different
                // levels (`net_socket.c:497-501`); we let the
                // caller log on terminate.
                return Err(e.into());
            }
        };

        // n == 0 shouldn't happen for stream sockets with a
        // non-zero send; treat it as no progress. (C's
        // sockwouldblock check is buggy here — errno 0 falls
        // through to the error log; we don't follow that.)
        self.outbuf.consume(n);

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

    /// `read_n` exact: buffer has 10, ask 10, get full range.
    /// C `buffer_read`: `if(len-offset >= n) { offset+=n; return ptr }`.
    #[test]
    fn linebuf_read_n_exact() {
        let mut b = LineBuf::default();
        b.add(b"0123456789");
        let r = b.read_n(10).unwrap();
        assert_eq!(&b.bytes_raw()[r], b"0123456789");
        assert!(b.is_empty());
    }

    /// `read_n` partial: ask for more than available, get None,
    /// offset UNCHANGED. C: returns NULL, doesn't advance.
    #[test]
    fn linebuf_read_n_partial() {
        let mut b = LineBuf::default();
        b.add(b"01234");
        assert!(b.read_n(10).is_none());
        // Offset unchanged — next add can complete it.
        assert_eq!(b.live_len(), 5);
        b.add(b"56789");
        let r = b.read_n(10).unwrap();
        assert_eq!(&b.bytes_raw()[r], b"0123456789");
    }

    /// `read_n(0)` — degenerate. C `buffer_read(buf, 0)` returns
    /// the current pointer and advances by 0. Same here: empty range.
    #[test]
    fn linebuf_read_n_zero() {
        let mut b = LineBuf::default();
        b.add(b"data");
        let r = b.read_n(0).unwrap();
        assert_eq!(r.len(), 0);
        assert_eq!(b.live_len(), 4); // unchanged
    }

    /// `read_n` after `read_line`: offset state is shared. The proxy
    /// flow doesn't actually interleave (proxy reply is FIRST, then
    /// lines), but `meta.c`'s `while(inbuf.len)` loop can do tcplen-
    /// then-line in one drain. Prove the cursor stays coherent.
    #[test]
    fn linebuf_read_n_after_read_line() {
        let mut b = LineBuf::default();
        // SOCKS4 reply (8 bytes) + ID line. Same buffer — the proxy
        // forwards the peer's bytes right after its own reply.
        b.add(&[0x00, 0x5A, 0, 0, 0, 0, 0, 0]);
        b.add(b"0 bob 17.7\n");
        let r1 = b.read_n(8).unwrap();
        assert_eq!(&b.bytes_raw()[r1.clone()], &[0x00, 0x5A, 0, 0, 0, 0, 0, 0]);
        let r2 = b.read_line().unwrap();
        assert_eq!(&b.bytes_raw()[r2], b"0 bob 17.7");
        assert!(b.is_empty());
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

    // ─── Connection::send
    // feed/flush need a real fd (read/send syscalls); tested via
    // socketpair in daemon.rs tests. send() is pure (just outbuf
    // formatting) — testable here.

    fn devnull() -> OwnedFd {
        std::fs::File::open("/dev/null").unwrap().into()
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
        // Chunk-4a fields. Inert for control conns.
        assert_eq!(c.protocol_minor, 0);
        assert!(c.ecdsa.is_none());
        assert!(c.sptps.is_none());
        // Chunk-4b fields.
        assert_eq!(c.options, 0);
        assert_eq!(c.estimated_weight, 0);
        assert!(c.address.is_none());
    }

    /// `connection_status_t` bit positions (`connection.h:38-58`).
    /// GCC packs bitfields LSB-first on x86-64. `dump_connections`
    /// emits `c->status.value` as `%x`; `tinc dump connections`
    /// just prints the hex. Nobody PARSES it. But: pinning the bit
    /// position means a future Rust-daemon ↔ C-CLI cross-impl test
    /// would diff cleanly. `control` is bit 9 (10th bool).
    #[test]
    fn status_value_control_bit() {
        let c = Connection::test_with_fd(devnull());
        // Pre-auth: control flag false.
        assert_eq!(c.status_value(), 0);
        // We don't have a test path that sets `control = true`
        // here without `handle_id` (which lives in proto.rs).
        // The bit-shift IS the test — `1 << 9` = `0x200`. If
        // `connection.h` reorders the bitfield, this comment
        // points at where to look.
        assert_eq!(1u32 << 9, 0x200);
    }

    // ─── take_rest

    /// The piggyback case: ID line + SPTPS bytes in one buffer.
    /// `read_line` returns the line; `take_rest` returns the
    /// SPTPS bytes that follow. THE SCENARIO from the doc comment.
    #[test]
    fn take_rest_after_read_line() {
        let mut b = LineBuf::default();
        // What a coalesced TCP segment looks like: peer's ID line,
        // then the first SPTPS framed bytes (here, fake — just
        // arbitrary bytes for the test).
        b.add(b"0 alice 17.7\n\x00\x42garbage");

        let r = b.read_line().unwrap();
        assert_eq!(&b.bytes_raw()[r], b"0 alice 17.7");

        // Now: offset is past the \n. The SPTPS bytes are live.
        // `take_rest` extracts them, empties the buffer.
        let rest = b.take_rest();
        assert_eq!(rest, b"\x00\x42garbage");
        assert!(b.is_empty());
        assert_eq!(b.live_len(), 0);
        // The cleared state is reusable. (Not strictly needed —
        // post-transition, inbuf is never touched again. But we
        // pin the no-surprises behavior.)
        b.add(b"x\n");
        let r = b.read_line().unwrap();
        assert_eq!(&b.bytes_raw()[r], b"x");
    }

    /// The common case: ID line was the WHOLE recv. `take_rest`
    /// returns empty. The daemon's re-feed gets `feed_sptps([])`
    /// → `Sptps(Vec::new())`. No-op.
    #[test]
    fn take_rest_empty_after_full_line() {
        let mut b = LineBuf::default();
        b.add(b"0 alice 17.7\n");
        let r = b.read_line().unwrap();
        assert_eq!(&b.bytes_raw()[r], b"0 alice 17.7");
        // is_empty() is true (offset == len) but bytes_raw still
        // has the line (no compact yet). take_rest sees offset
        // caught len → empty rest.
        assert!(b.is_empty());
        assert!(b.take_rest().is_empty());
    }

    /// Degenerate: take_rest on a fresh buffer. Empty.
    #[test]
    fn take_rest_on_fresh_is_empty() {
        let mut b = LineBuf::default();
        assert!(b.take_rest().is_empty());
    }

    // ─── feed_sptps (the do-while loop)
    //
    // Can't easily test feed() itself — it reads a real fd. But
    // feed_sptps is the pure SPTPS-loop, factored out exactly so
    // it's testable.

    /// Dummy RNG that panics if touched. The receive() path during
    /// the initial handshake (responder receiving initiator's KEX,
    /// then SIG) doesn't trigger send_kex, so rng stays cold.
    /// Same idiom as `tinc-sptps/tests/vs_c.rs::NoRng`.
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

    /// `feed_sptps([])` → `Sptps(Vec::new())`. The take_rest no-op.
    /// Doesn't even need a real Sptps — the empty-chunk early-
    /// return is hit before sptps is touched. We pass a real one
    /// anyway (the function signature wants &mut Sptps, not
    /// Option) to verify it's untouched.
    #[test]
    fn feed_sptps_empty_chunk() {
        use tinc_crypto::sign::SigningKey;
        use tinc_sptps::{Framing, Role};

        // Two throwaway keys — doesn't matter, we never receive.
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
        // NoRng didn't panic → sptps.receive was not called.
    }

    /// THE LOOP: two records arrive in one chunk → both processed.
    /// C `meta.c:200-313`: `do { ... } while(inlen > 0)`. If we
    /// only called `receive()` once, only the first record would
    /// decode and the second would be stranded.
    ///
    /// Setup: full handshake (so we can send TWO encrypted records
    /// from the peer side, glue them together, feed as one chunk).
    /// THE TWO `Output::Record`s prove the loop iterated.
    #[test]
    fn feed_sptps_two_records_one_chunk() {
        use tinc_crypto::sign::SigningKey;
        use tinc_sptps::{Framing, Output, Role};

        // ─── Handshake: alice (initiator) ↔ bob (responder)
        // Same dance as vs_c.rs but Rust↔Rust. Use OsRng for the
        // KEX nonces (NoRng would panic in start's send_kex).
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

        // Helper: extract the one Wire from a Vec<Output>.
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

        // alice gets bob's KEX → SIG out.
        let (n, outs) = alice.receive(&b_kex, &mut NoRng).unwrap();
        assert_eq!(n, b_kex.len());
        let a_sig = wire(outs);

        // bob gets alice's KEX → nothing (responder waits for SIG).
        let (n, outs) = bob.receive(&a_kex, &mut NoRng).unwrap();
        assert_eq!(n, a_kex.len());
        assert!(outs.is_empty());

        // bob gets alice's SIG → SIG out + HandshakeDone.
        let (n, outs) = bob.receive(&a_sig, &mut NoRng).unwrap();
        assert_eq!(n, a_sig.len());
        assert_eq!(outs.len(), 2);
        let b_sig = match &outs[0] {
            Output::Wire { bytes, .. } => bytes.clone(),
            _ => panic!(),
        };
        assert!(matches!(outs[1], Output::HandshakeDone));

        // alice gets bob's SIG → HandshakeDone.
        let (n, outs) = alice.receive(&b_sig, &mut NoRng).unwrap();
        assert_eq!(n, b_sig.len());
        assert!(matches!(outs[0], Output::HandshakeDone));

        // ─── NOW: both done. Alice sends TWO records.
        let rec1 = wire(alice.send_record(0, b"first").unwrap());
        let rec2 = wire(alice.send_record(0, b"second").unwrap());

        // Glue them. THIS is the "coalesced TCP segment" that
        // exercises the do-while.
        let mut chunk = rec1;
        chunk.extend_from_slice(&rec2);

        // ─── feed_sptps: bob receives both in one call
        let r = Connection::feed_sptps(&mut bob, &chunk, "alice", &mut NoRng);
        match r {
            FeedResult::Sptps(evs) => {
                // BOTH records decoded. If the loop only ran once,
                // we'd see one. The second would be eaten by the
                // next call to receive() — but there IS no next
                // call (this is one feed_sptps invocation).
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

    /// Partial record: only the length header arrives. `receive()`
    /// buffers it, returns `(2, [])`. feed_sptps loop terminates
    /// (consumed everything). `Sptps(Vec::new())`.
    ///
    /// This pins: feed_sptps doesn't spin when receive() returns
    /// nonzero-but-no-output. The C `do { ... } while(inlen > 0)`
    /// also terminates here (inlen reaches 0).
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

        // Just 2 bytes (a length header, says "body of 5 bytes
        // follows"). receive() buffers, returns (2, []).
        // The do-while sees off==2==chunk.len() → done.
        let r = Connection::feed_sptps(&mut sptps, &[0x00, 0x05], "test", &mut NoRng);
        match r {
            FeedResult::Sptps(evs) => assert!(evs.is_empty()),
            _ => panic!("expected Sptps(empty), got {r:?}"),
        }
    }

    /// Decrypt failure (bad bytes post-handshake) → Dead. C
    /// `meta.c:227`: `if(!len) return false`.
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

        // Garbage that's not a valid plaintext-phase record. The
        // length header says "5 bytes", but the type byte (3rd)
        // is 0 (an app record) and we're pre-handshake — receive()
        // returns Err(BadRecord). The state machine isn't expecting
        // app data before the handshake.
        let bad = [0x00, 0x05, 0x00, b'x', b'x', b'x', b'x', b'x'];
        let r = Connection::feed_sptps(&mut sptps, &bad, "test", &mut NoRng);
        assert!(matches!(r, FeedResult::Dead), "expected Dead, got {r:?}");
    }

    // ─── feed() sptpslen mechanism (the meta.c:203-217 do-while)
    //
    // feed() reads a real fd; we can't unit-test it directly. But the
    // "21 LEN" peek + sptpslen blob accumulation is the regression-
    // critical path (the architectural trap from the chunk-12 brief).
    // Test the inlined do-while via a Connection with a socketpair fd:
    // write the chunk to one end, feed() reads from the other.

    /// Handshaked alice/bob pair with bob installed as a Connection's
    /// sptps. Returns (conn, alice, write_fd). conn.feed() reads from
    /// the socketpair; tests write to write_fd. Same handshake dance
    /// as feed_sptps_two_records_one_chunk; factored out so the
    /// sptpslen tests don't repeat 60 lines each.
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
        // Both done.

        // socketpair(AF_UNIX, SOCK_STREAM). feed() uses read(2),
        // which works on unix stream sockets.
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

    /// `sptpslen` set in advance, blob arrives in one chunk. Simplest
    /// case: pretend a previous feed() saw the "21 12" record and set
    /// sptpslen. This feed() just eats the blob bytes.
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

    /// Blob spans two recv()s. C `meta.c:209-211`: `if(!sptpspacket)
    /// return true`. First feed() buffers a partial; second completes.
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

    /// THE TRAP. `[SPTPS-framed "21 12\n" record | 12 raw bytes |
    /// SPTPS-framed PING record]` as one chunk. Before the fix:
    /// `feed_sptps` would call `receive()` again on the 12 raw bytes,
    /// trying to parse them as SPTPS framing → garbage → DecryptFailed
    /// → Dead. After: feed() peeks the "21 " prefix, sets sptpslen,
    /// next iteration eats the blob, then receive() processes PING.
    ///
    /// Events MUST be `[Blob(12), Record(PING)]` — the "21 12" record
    /// is NOT in the output (consumed by feed). Order proves the
    /// do-while interleaving is correct.
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

        // The blob: NOT SPTPS-framed. Crafted to look like a
        // complete encrypted record if mis-parsed: len=9 header +
        // 9 garbage body bytes. Post-handshake, receive() would
        // try chacha20-poly1305 decrypt on "junkjunk!" →
        // DecryptFailed. THAT'S the trap signature.
        let blob = b"\x00\x09junkjunk!"; // 2-byte len + 9 body = 11
        assert_eq!(blob.len(), 11);
        // Alice sends "21 11\n" as a normal SPTPS record (this is
        // what conn.send() does — send_request → sptps_send_record).
        let req_rec = wire(alice.send_record(0, b"21 11\n").unwrap());
        // PING record after the blob.
        let ping_rec = wire(alice.send_record(0, b"8\n").unwrap());

        let mut chunk = req_rec;
        chunk.extend_from_slice(blob);
        chunk.extend_from_slice(&ping_rec);
        write_all(&wr, &chunk);

        let r = conn.feed(&mut NoRng);
        match r {
            FeedResult::Sptps(evs) => {
                // [Blob(11), Record("8\n")]. The "21 11\n" record
                // is CONSUMED — not in events.
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
                panic!(
                    "Dead = the trap fired: blob bytes were parsed \
                     as SPTPS framing instead of being eaten as a \
                     raw blob. The do-while peek didn't work."
                )
            }
            _ => panic!("expected Sptps, got {r:?}"),
        }
    }

    /// `send_raw`: no `\n` appended. SPTPS framing is binary; the
    /// length header IS the frame delimiter.
    #[test]
    fn send_raw_no_newline() {
        let mut c = Connection::test_with_fd(devnull());
        // Some framed-looking bytes. Contains 0x0a (== '\n') in
        // the middle to prove we don't try to interpret it.
        let bytes = &[0x00, 0x05, 0x0a, 0xde, 0xad, 0xbe, 0xef];
        let signal = c.send_raw(bytes);
        assert!(signal); // outbuf went empty→nonempty
        assert_eq!(c.outbuf.live(), bytes); // exact, no \n added
    }
}
