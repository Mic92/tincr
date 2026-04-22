//! Parsed rows from the daemon's `dump_*` control responses.
//!
//! These are wire-schema types: the body half of a `"18 <req> ..."`
//! line after [`CtlSocket::recv_row`](super::CtlSocket::recv_row)
//! has stripped the `code req` prefix. Consumed by `cmd::dump`,
//! `cmd::info`, `cmd::top`, and `tinc-auth` — hoisted here so those
//! commands don't import sideways through `cmd::dump`.
//!
//! ## The `" port "` literal — wire vs printf-conversion mismatch
//!
//! `n->hostname` is built by `sockaddr2hostname` as `"10.0.0.1
//! port 655"`. The daemon writes it via ONE `%s`; the CLI reads it
//! back via `%s port %s`. So the daemon's printf has one fewer
//! conversion than the CLI's sscanf, per `" port "` instance:
//!
//! | dump | daemon `%` (after 18 N) | CLI `%` (after `%*d %*d`) | port literals |
//! |---|---|---|---|
//! | nodes | 21 | 22 | 1 |
//! | edges | 6 | 8 | 2 (addr + `local_addr`) |
//! | connections | 5 | 6 | 1 |
//! | subnets | 2 | 2 | 0 |
//! | traffic | 5 | 5 | 0 |
//!
//! Dump uses the fused `sockaddr2hostname` form (the log-message
//! form); the message protocol uses split `sockaddr2str`.
//! `Tok::lit("port")` skips the literal.
//!
//! ## `node_status_t` is a bitfield — bit positions matter
//!
//! `union { struct { bool x:1; ... }; uint32_t value; }`. GCC/Clang
//! on x86-64 pack LSB-first. We only need bit 4 (reachable) and
//! bit 1 (validkey) — named constants, not a struct.
//!
//! ## `strip_weight` — display sugar
//!
//! `"10.0.0.0/24#10"` → `"10.0.0.0/24"` (default weight). The
//! daemon's `net2str` already omits `#10` so this is belt-and-
//! suspenders against older daemons.

use std::fmt::Write as _;

use tinc_proto::{ParseError, Tok};

/// `node_status_t` bit positions: a 13-field `bool:1` bitfield in a
/// `u32` union. GCC packs LSB-first on x86-64 (and every target tinc
/// builds on); bit N is field N counting from 0.
///
/// `dump` needs bits 1+4 (validkey/reachable). `info` needs the six
/// that the `Status:` line prints. The daemon's port will define all
/// 13 in its own `NodeStatus` type; for the CLI these are display-
/// only, so a newtype + `is(bit)` is the lean answer (not
/// `bitflags!` — this is the CLI's view of an opaque hex int, not a
/// shared definition).
///
/// The test `status_bits_match_node_h_order` pins it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusBit(pub u32);

impl StatusBit {
    /// Field 1 (after `unused_active`). Set when we have a working
    /// session key for this node — SPTPS or legacy KEY exchange
    /// completed. The DOT graph greens when validkey AND `minmtu >
    /// 0`; else black.
    pub const VALIDKEY: Self = Self(1 << 1);
    /// Field 3. Set during BFS to mark seen nodes. Transient —
    /// cleared at the start of each graph walk. Appearing in `info`
    /// output means "the daemon's last BFS reached this node", which
    /// is the same thing as `reachable` modulo timing. Mostly noise,
    /// but upstream prints it.
    pub const VISITED: Self = Self(1 << 3);
    /// Field 4. The big one — can we route packets to this node?
    /// `dump reachable nodes` filters on it. `info` switches `Online
    /// since:` / `Last seen:`.
    pub const REACHABLE: Self = Self(1 << 4);
    /// Field 5. `via != self`. UDP traffic to this node is relayed
    /// through another node (typically because of `IndirectData =
    /// yes` in the host file, or because it's behind a NAT we can't
    /// punch).
    pub const INDIRECT: Self = Self(1 << 5);
    /// Field 6. Node speaks the new (1.1+) handshake. Absence means
    /// legacy RSA + AES-CBC-HMAC, which is `DISABLE_LEGACY`-gated in
    /// our build.
    pub const SPTPS: Self = Self(1 << 6);
    /// Field 7. We've SEEN a UDP packet from this address (vs just
    /// sent to it hoping). PMTU discovery sends probes; this bit
    /// means one came back.
    pub const UDP_CONFIRMED: Self = Self(1 << 7);
}

// NodeRow — the 22-field beast

/// One row of `dump nodes`. 22 sscanf fields.
///
/// The daemon-side printf has 21 conversions because `n->hostname`
/// (one `%s`) is `"HOST port PORT"` (three tokens).
#[derive(Debug, Clone)]
pub struct NodeRow {
    /// `%s` — `n->name`. The graph mode's DOT output uses this twice
    /// (label = name, id = name).
    pub name: String,
    /// `%s` — `n->id` as 12 hex chars (6 bytes, `node_id_t`). We
    /// keep it as a string (it's display-only).
    pub id: String,
    /// `%s` — host portion of `n->hostname`. After `Tok::lit("port")`
    /// re-splits the `sockaddr2hostname` output. Values: `"10.0.0.1"`,
    /// `"unknown"` (unreachable), `"unspec"` (`AF_UNSPEC`), `"MYSELF"`
    /// (the running daemon's self-node — graph mode greens it).
    pub host: String,
    /// `port %s` — the port. Same notes as host. `String` not `u16`
    /// because it might be `"unknown"`/`"unspec"`.
    pub port: String,
    /// `%d` — `cipher_get_nid(n->outcipher)`. Always 0 with
    /// `DISABLE_LEGACY`. We don't act on it.
    pub cipher: i32,
    /// `%d` — `digest_get_nid(n->outdigest)`. Always 0 with legacy off.
    pub digest: i32,
    /// `%d` — `digest_length(n->outdigest)`. The daemon writes `%lu`
    /// (it's a `size_t`); the CLI reads `%d`. We follow the daemon:
    /// `u64` parse, stored `i32` because that's what the output
    /// printf expects. The value (HMAC length, max 64) fits.
    pub maclength: i32,
    /// `%d` — `n->outcompression`. 0-11 (zlib levels + lz4).
    pub compression: i32,
    /// `%x` — `n->options`. A bitfield; we don't interpret.
    pub options: u32,
    /// `%x` — `n->status.value`. The bitfield. Bits 1 and 4 matter
    /// for output (validkey, reachable); rest is opaque.
    pub status: u32,
    /// `%s` — `n->nexthop->name`, or `"-"` if NULL. Next hop on the
    /// shortest path.
    pub nexthop: String,
    /// `%s` — `n->via->name`, or `"-"` if NULL. UDP relay.
    pub via: String,
    /// `%d` — `n->distance`. Graph distance (edge count to here).
    pub distance: i32,
    /// `%hd` — `n->mtu`. Path MTU. Values cap at ~9000 (jumbo
    /// frames) so it fits.
    pub pmtu: i16,
    /// `%hd` — `n->minmtu`. Lower bound during PMTU discovery.
    pub minmtu: i16,
    /// `%hd` — `n->maxmtu`. Upper bound during discovery.
    pub maxmtu: i16,
    /// `%ld` — `(long)n->last_state_change`. Unix timestamp. The
    /// daemon casts `time_t → long` which loses on 32-bit-with-64-
    /// bit-time_t. We store i64 (see `Tok::ld` doc).
    pub last_state_change: i64,
    /// `%d` — `n->udp_ping_rtt`. Microseconds, or `-1` for "never
    /// pinged". The output formats this as `rtt %d.%03d` (ms.us)
    /// iff not -1.
    pub udp_ping_rtt: i32,
    /// `%PRIu64` × 4 — traffic counters.
    pub in_packets: u64,
    pub in_bytes: u64,
    pub out_packets: u64,
    pub out_bytes: u64,
}

impl NodeRow {
    /// Parse the body (after `recv_row` strips `"18 3 "`).
    ///
    /// One giant sscanf with 22 conversions. We do one `Tok` walk
    /// with 22 calls. Same shape — first short field errors.
    ///
    /// # Errors
    /// `ParseError` if any field is missing or malformed. We don't
    /// distinguish which field failed (debugging a malformed dump
    /// means looking at the wire).
    pub fn parse(body: &str) -> Result<Self, ParseError> {
        let mut t = Tok::new(body);
        // ─── %s %s %s port %s
        let name = t.s()?.to_owned();
        let id = t.s()?.to_owned();
        // sockaddr2hostname's "HOST port PORT" re-split.
        let host = t.s()?.to_owned();
        t.lit("port")?;
        let port = t.s()?.to_owned();
        // ─── %d %d %d %d
        let cipher = t.d()?;
        let digest = t.d()?;
        // Daemon `%lu`, CLI `%d`. Read as lu, narrow; digest_length < 256 always.
        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        let maclength = t.lu()? as i32;
        let compression = t.d()?;
        // ─── %x %x
        let options = t.x()?;
        let status = t.x()?;
        // ─── %s %s %d
        let nexthop = t.s()?.to_owned();
        let via = t.s()?.to_owned();
        let distance = t.d()?;
        // ─── %hd %hd %hd
        let pmtu = t.hd()?;
        let minmtu = t.hd()?;
        let maxmtu = t.hd()?;
        // ─── %ld %d
        let last_state_change = t.ld()?;
        let udp_ping_rtt = t.d()?;
        // ─── %llu × 4
        let in_packets = t.lu()?;
        let in_bytes = t.lu()?;
        let out_packets = t.lu()?;
        let out_bytes = t.lu()?;

        Ok(Self {
            name,
            id,
            host,
            port,
            cipher,
            digest,
            maclength,
            compression,
            options,
            status,
            nexthop,
            via,
            distance,
            pmtu,
            minmtu,
            maxmtu,
            last_state_change,
            udp_ping_rtt,
            in_packets,
            in_bytes,
            out_packets,
            out_bytes,
        })
    }

    /// Is bit 4 (reachable) set? `dump reachable nodes` filter.
    #[must_use]
    pub const fn reachable(&self) -> bool {
        self.status & StatusBit::REACHABLE.0 != 0
    }

    /// Bit 1 (validkey). Graph mode picks black for !validkey.
    #[must_use]
    pub const fn validkey(&self) -> bool {
        self.status & StatusBit::VALIDKEY.0 != 0
    }

    /// The plain-text output line.
    ///
    /// One `printf` for the body, an OPTIONAL `printf(" rtt ...")`
    /// if `udp_ping_rtt != -1`, then `\n`. We build to a String so
    /// the binary can `print!` once.
    ///
    /// The format string is wire-compatible with upstream `tinc dump
    /// nodes` — scripts that parse it (people DO this) keep working.
    #[must_use]
    pub fn fmt_plain(&self) -> String {
        // The `status %04x` pad is upstream's; we replicate.
        // Everything else is bare. The `(min N max N)` parens are
        // literal.
        let mut s = format!(
            "{} id {} at {} port {} cipher {} digest {} maclength {} \
             compression {} options {:x} status {:04x} nexthop {} via {} \
             distance {} pmtu {} (min {} max {}) rx {} {} tx {} {}",
            self.name,
            self.id,
            self.host,
            self.port,
            self.cipher,
            self.digest,
            self.maclength,
            self.compression,
            self.options,
            self.status,
            self.nexthop,
            self.via,
            self.distance,
            self.pmtu,
            self.minmtu,
            self.maxmtu,
            self.in_packets,
            self.in_bytes,
            self.out_packets,
            self.out_bytes,
        );
        // The value is microseconds; output is `rtt MS.uuu` (millis
        // dot micros-mod-1000). The `%03d` pad makes `1500us` →
        // `1.500`.
        if self.udp_ping_rtt != -1 {
            let _ = write!(
                s,
                " rtt {}.{:03}",
                self.udp_ping_rtt / 1000,
                self.udp_ping_rtt % 1000
            );
        }
        s
    }

    /// The DOT-format node line.
    ///
    /// Five-way color cascade by status:
    ///
    /// | condition (first match wins) | color | meaning |
    /// |---|---|---|
    /// | `host == "MYSELF"` | green + filled | self |
    /// | `!reachable` | red | dead |
    /// | `via != name` | orange | indirect (relayed) |
    /// | `!validkey` | black | reachable but no key yet |
    /// | `minmtu > 0` | green | UDP works (PMTU discovered) |
    /// | (else) | black | TCP-only |
    ///
    /// The `via != node` check means "this node's UDP traffic is
    /// relayed through a different node" — indirect. The `minmtu >
    /// 0` check means PMTU discovery succeeded, i.e. direct UDP
    /// works.
    ///
    /// `style = "filled"` only for MYSELF.
    #[must_use]
    pub fn fmt_dot(&self) -> String {
        let myself = self.host == "MYSELF";
        // ─── Color cascade (first-match-wins)
        // The ORDER matters: a node that's MYSELF and also has
        // minmtu>0 is green-because-self, not green-because-udp.
        let color = if myself {
            "green"
        } else if !self.reachable() {
            "red"
        } else if self.via != self.name {
            "orange"
        } else if !self.validkey() {
            "black"
        } else if self.minmtu > 0 {
            "green"
        } else {
            "black"
        };
        // ─── DOT line
        // The leading space + double-quote escaping is DOT syntax.
        // `label = name` (twice) is redundant in DOT — the node id
        // IS the default label — but upstream does it (probably for
        // names with special chars; quoted DOT id makes them safe).
        let style = if myself { ", style = \"filled\"" } else { "" };
        format!(
            " \"{n}\" [label = \"{n}\", color = \"{color}\"{style}];",
            n = self.name
        )
    }
}

// EdgeRow

/// One row of `dump edges`. 8 fields, two `port` literals (both
/// addr and `local_addr` are `sockaddr2hostname` output).
///
/// Edges are directional in tinc's graph (an edge A→B is distinct
/// from B→A; the daemon stores both). `dump edges` lists them all;
/// graph mode (undirected DOT) deduplicates by `from < to` strcmp.
#[derive(Debug, Clone)]
pub struct EdgeRow {
    pub from: String,
    pub to: String,
    pub host: String,
    pub port: String,
    pub local_host: String,
    pub local_port: String,
    pub options: u32,
    /// `%d` — `e->weight`. Edge cost for shortest-path. The DOT
    /// weight is `1 + 65536/weight` (so high-weight edges look
    /// thinner).
    pub weight: i32,
}

impl EdgeRow {
    /// Parse body.
    ///
    /// # Errors
    /// `ParseError` if short or malformed.
    pub fn parse(body: &str) -> Result<Self, ParseError> {
        let mut t = Tok::new(body);
        let from = t.s()?.to_owned();
        let to = t.s()?.to_owned();
        // First "HOST port PORT" — e->address.
        let host = t.s()?.to_owned();
        t.lit("port")?;
        let port = t.s()?.to_owned();
        // Second one — e->local_address.
        let local_host = t.s()?.to_owned();
        t.lit("port")?;
        let local_port = t.s()?.to_owned();
        let options = t.x()?;
        let weight = t.d()?;
        Ok(Self {
            from,
            to,
            host,
            port,
            local_host,
            local_port,
            options,
            weight,
        })
    }

    /// Plain-text.
    #[must_use]
    pub fn fmt_plain(&self) -> String {
        format!(
            "{} to {} at {} port {} local {} port {} options {:x} weight {}",
            self.from,
            self.to,
            self.host,
            self.port,
            self.local_host,
            self.local_port,
            self.options,
            self.weight,
        )
    }

    /// DOT edge line.
    ///
    /// `directed`: digraph mode (`->`). Graph mode (`--`)
    /// deduplicates by `strcmp(from, to) > 0` — only emit one of
    /// each pair. Returns `None` for the suppressed half in
    /// undirected mode.
    ///
    /// The weight calculation `1 + 65536/weight` makes a weight-1
    /// edge `w = 65537` (very strong) and a weight-500 edge `w =
    /// 132` (weak). DOT layout engines use higher weight to keep
    /// nodes closer.
    #[must_use]
    pub fn fmt_dot(&self, directed: bool) -> Option<String> {
        // ─── Undirected dedup
        // It works because the daemon emits both A→B and B→A;
        // suppressing the half where from > to (strcmp) leaves one
        // per pair. The check is `>`, not `>=` — if from == to
        // (self-loop) both would emit. tinc doesn't have self-edges
        // so it's moot, but `>` is what's written.
        let arrow = if directed {
            "->"
        } else {
            // Undirected: suppress the from > to half.
            // `Ord` on `String` is byte-order, same as `strcmp`.
            if self.from > self.to {
                return None;
            }
            "--"
        };

        // ─── Weight: float
        // `weight` is signed; negative would give negative `w`,
        // weird for DOT but upstream doesn't guard. Neither do we.
        #[allow(clippy::cast_precision_loss)] // weight < 2^24 in sane meshes; exact for f32
        let w = 1.0_f32 + 65536.0_f32 / self.weight as f32;

        // ─── DOT line
        // `%f` is printf default float format: 6 decimal places.
        // Rust `{}` for f32 picks shortest-repr (1.0 → "1"). Use
        // `{:.6}` to match exactly — `dot` itself doesn't care
        // about decimals but downstream scripts might.
        //
        // Why TWO weight attributes (`w` and `weight`)? `weight` is
        // graphviz's edge weight (layout hint). `w` is... not a
        // standard attribute. Probably for some downstream tool.
        // Upstream's been writing it since 2012; keep it.
        Some(format!(
            " \"{from}\" {arrow} \"{to}\" [w = {w:.6}, weight = {w:.6}];",
            from = self.from,
            to = self.to,
        ))
    }
}

// SubnetRow

/// One row of `dump subnets`. 2 fields.
///
/// Simplest of the four. No `port` literal (subnets don't have
/// ports). The subnet string is `net2str` output; `strip_weight`
/// post-processes for display.
#[derive(Debug, Clone)]
pub struct SubnetRow {
    /// `%s` — `net2str(subnet)`. May have `#WEIGHT` suffix (but
    /// not `#10`, the daemon already strips default). The CLI
    /// strips `#10` again anyway (`strip_weight`).
    pub subnet: String,
    /// `%s` — owner name, or `"(broadcast)"` (literal, parens
    /// included) for broadcast subnets.
    pub owner: String,
}

impl SubnetRow {
    /// Parse body.
    ///
    /// # Errors
    /// `ParseError` on malformed.
    pub fn parse(body: &str) -> Result<Self, ParseError> {
        let mut t = Tok::new(body);
        let subnet = t.s()?.to_owned();
        let owner = t.s()?.to_owned();
        Ok(Self { subnet, owner })
    }

    /// Plain-text. `strip_weight` is applied here, not in parse —
    /// so tests can see the raw subnet too.
    #[must_use]
    pub fn fmt_plain(&self) -> String {
        format!("{} owner {}", strip_weight(&self.subnet), self.owner)
    }
}

/// Strip `#10` suffix (default weight).
///
/// The daemon's `net2str` already omits `#10` when `weight ==
/// DEFAULT_WEIGHT`, so this should be a no-op against a same-version
/// daemon. It's defense against:
///
/// 1. Older daemons that didn't have the omit logic.
/// 2. The default ever changing (then old configs with explicit
///    `#10` would surface it).
///
/// `>= 3` not `> 3` means `"#10"` alone (3 chars) → `""`. Probably
/// not what you want, but it's what upstream does. (Never happens —
/// a bare `#10` isn't a valid subnet, daemon won't send it.)
///
/// `tinc_proto::DEFAULT_WEIGHT` is 10 — we're matching the literal
/// `"#10"`, not formatting an int. If `DEFAULT_WEIGHT` ever changes,
/// this needs to change too; the test `strip_weight_tracks_default`
/// notices.
#[must_use]
pub fn strip_weight(s: &str) -> &str {
    s.strip_suffix("#10").unwrap_or(s)
}

// ConnRow

/// One row of `dump connections`. 6 fields, one `port` literal.
///
/// "Connections" are the live meta-connections (the TCP sockets to
/// peers), as opposed to "edges" (the graph edges, which include
/// transitive ones). Connections ⊆ edges, roughly.
#[derive(Debug, Clone)]
pub struct ConnRow {
    pub name: String,
    pub host: String,
    pub port: String,
    pub options: u32,
    /// `%d` — `c->socket`. The fd number.
    pub socket: i32,
    /// `%x` — `c->status.value`. Different bitfield from node
    /// status (`connection.h` has its own). We don't read bits;
    /// it's printed as hex and that's all.
    pub status: u32,
}

impl ConnRow {
    /// Parse body.
    ///
    /// # Errors
    /// `ParseError` on short/malformed.
    pub fn parse(body: &str) -> Result<Self, ParseError> {
        let mut t = Tok::new(body);
        let name = t.s()?.to_owned();
        let host = t.s()?.to_owned();
        t.lit("port")?;
        let port = t.s()?.to_owned();
        let options = t.x()?;
        let socket = t.d()?;
        let status = t.x()?;
        Ok(Self {
            name,
            host,
            port,
            options,
            socket,
            status,
        })
    }

    /// Plain-text. Unpadded hex for both, unlike node's
    /// `status %04x`. Yes upstream is inconsistent. Replicated.
    #[must_use]
    pub fn fmt_plain(&self) -> String {
        format!(
            "{} at {} port {} options {:x} socket {} status {:x}",
            self.name, self.host, self.port, self.options, self.socket, self.status,
        )
    }
}

// TrafficRow

/// One row of `DUMP_TRAFFIC`. Daemon sends `code req name in_packets
/// in_bytes out_packets out_bytes`. `recv_row` strips the first two,
/// so we parse 5 fields.
///
/// Simplest dump format in the codebase: no `" port "` (it's not a
/// hostname), no hex (no status field), just one `%s` then four
/// `%"PRIu64"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrafficRow {
    pub name: String,
    pub in_packets: u64,
    pub in_bytes: u64,
    pub out_packets: u64,
    pub out_bytes: u64,
}

impl TrafficRow {
    /// Parse the body (post-`recv_row`-strip).
    ///
    /// # Errors
    /// `ParseError` if any field is missing or not the right type.
    /// Daemon's `dump_traffic` is broken or the wire's corrupt.
    pub fn parse(body: &str) -> Result<Self, ParseError> {
        let mut t = Tok::new(body);
        // `%s` then 4× `%"PRIu64"`. `lu` is `Tok`'s u64 parser
        // (named for `%lu`, which is what `%"PRIu64"` expands to
        // on every 64-bit platform).
        Ok(Self {
            name: t.s()?.to_owned(),
            in_packets: t.lu()?,
            in_bytes: t.lu()?,
            out_packets: t.lu()?,
            out_bytes: t.lu()?,
        })
        // No `.end()`: sscanf-style doesn't care about trailing
        // garbage. Future daemon versions adding fields wouldn't
        // break us.
    }
}
