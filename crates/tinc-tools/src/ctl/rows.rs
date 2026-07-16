//! Parsed rows from the daemon's `dump_*` control responses.
//!
//! These are wire-schema types: the body half of a `"18 <req> ..."`
//! line after [`CtlSocket::recv_row`](super::CtlSocket::recv_row)
//! has stripped the `code req` prefix. Consumed by `cmd::dump`,
//! `cmd::info`, `cmd::top`, and `tinc-auth` — hoisted here so those
//! commands don't import sideways through `cmd::dump`.
//!
//! ## The `" port "` literal
//!
//! Node/edge/connection addresses arrive as the fused hostname form
//! `"10.0.0.1 port 655"` — written as one field by the daemon but read
//! back as host, literal `port`, port. `Tok::lit("port")` skips the
//! literal. Node and connection rows have one such address; edge rows
//! have two (remote and local).
//!
//! ## Node status is a bitfield
//!
//! The daemon's `node_status_t` is a bit-packed struct exposed as a hex
//! u32; the bit positions are fixed by the daemon's field order (LSB
//! first). Only the bits the CLI displays are named here.
//!
//! ## `strip_weight`
//!
//! `"10.0.0.0/24#10"` → `"10.0.0.0/24"` (default weight). The daemon
//! already omits `#10`, so this is defense against older daemons.

use std::fmt::Write as _;

use tinc_proto::{ParseError, Tok};

/// Node status bit positions: bit N is the daemon's Nth status field,
/// counting from 0. Display-only for the CLI, so a newtype + `is(bit)`
/// rather than a full bitflags definition.
///
/// The test `status_bits_match_node_h_order` pins the positions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusBit(pub u32);

impl StatusBit {
    /// Field 1 (after `unused_active`). Set when we have a working
    /// session key for this node — SPTPS or legacy KEY exchange
    /// completed. The DOT graph greens when validkey AND `minmtu >
    /// 0`; else black.
    pub const VALIDKEY: Self = Self(1 << 1);
    /// Field 3. Set during the daemon's graph BFS to mark seen nodes;
    /// effectively the same as `reachable` modulo timing. Printed on the
    /// `Status:` line for parity with C tinc.
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

/// One row of `dump nodes`: 22 fields.
#[derive(Debug, Clone)]
pub struct NodeRow {
    /// Node name; DOT output uses it as both id and label.
    pub name: String,
    /// Node ID as 12 hex chars. Kept as a string (display-only).
    pub id: String,
    /// Host portion of the address. Values: an address, `"unknown"`
    /// (unreachable), `"unspec"`, or `"MYSELF"` (the daemon's self-node).
    pub host: String,
    /// Port. `String` not `u16` because it may be `"unknown"`/`"unspec"`.
    pub port: String,
    /// Legacy cipher NID; always 0 in legacy-disabled builds.
    pub cipher: i32,
    /// Legacy digest NID; always 0 in legacy-disabled builds.
    pub digest: i32,
    /// HMAC length. Sent unsigned, stored i32 to match the output format.
    pub maclength: i32,
    /// Compression level (0-11).
    pub compression: i32,
    /// Options bitfield; not interpreted here.
    pub options: u32,
    /// Status bitfield; see [`StatusBit`].
    pub status: u32,
    /// Next hop on the shortest path, or `"-"`.
    pub nexthop: String,
    /// UDP relay node, or `"-"`.
    pub via: String,
    /// Graph distance (edge count).
    pub distance: i32,
    /// Path MTU.
    pub pmtu: i16,
    /// Lower bound during PMTU discovery.
    pub minmtu: i16,
    /// Upper bound during PMTU discovery.
    pub maxmtu: i16,
    /// Unix timestamp of the last state change.
    pub last_state_change: i64,
    /// Microseconds, or `-1` for "never pinged".
    pub udp_ping_rtt: i32,
    /// Traffic counters.
    pub in_packets: u64,
    pub in_bytes: u64,
    pub out_packets: u64,
    pub out_bytes: u64,
}

impl NodeRow {
    /// Parse the body (after `recv_row` strips the `"18 3 "` prefix).
    ///
    /// # Errors
    /// `ParseError` if any field is missing or malformed; the failing
    /// field is not identified (debugging a malformed dump means looking
    /// at the wire).
    pub fn parse(body: &str) -> Result<Self, ParseError> {
        let mut t = Tok::new(body);
        let name = t.s()?.to_owned();
        let id = t.s()?.to_owned();
        // Fused "HOST port PORT" address form.
        let host = t.s()?.to_owned();
        t.lit("port")?;
        let port = t.s()?.to_owned();
        let cipher = t.d()?;
        let digest = t.d()?;
        // Sent unsigned; value is an HMAC length (< 256), so the narrowing
        // cast is safe.
        #[expect(clippy::cast_possible_truncation)]
        let maclength = t.lu()? as i32;
        let compression = t.d()?;
        let options = t.x()?;
        let status = t.x()?;
        let nexthop = t.s()?.to_owned();
        let via = t.s()?.to_owned();
        let distance = t.d()?;
        let pmtu = t.hd()?;
        let minmtu = t.hd()?;
        let maxmtu = t.hd()?;
        let last_state_change = t.ld()?;
        let udp_ping_rtt = t.d()?;
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

    /// The plain-text output line, with an optional ` rtt` suffix when
    /// `udp_ping_rtt != -1`.
    ///
    /// The format is byte-compatible with C `tinc dump nodes` — scripts
    /// parse this output.
    #[must_use]
    pub fn fmt_plain(&self) -> String {
        // status is zero-padded to 4 hex digits; everything else is bare.
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
        // Value is microseconds; output is millis.micros (1500us → 1.500).
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
    /// `via != name` means this node's UDP traffic is relayed through
    /// another node; `minmtu > 0` means PMTU discovery succeeded (direct
    /// UDP works). `style = "filled"` only for MYSELF.
    #[must_use]
    pub fn fmt_dot(&self) -> String {
        let myself = self.host == "MYSELF";
        // First match wins; order matters.
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
        // Explicit label is redundant in DOT (the id defaults to the
        // label) but kept for output compatibility.
        let style = if myself { ", style = \"filled\"" } else { "" };
        format!(
            " \"{n}\" [label = \"{n}\", color = \"{color}\"{style}];",
            n = self.name
        )
    }
}

/// One row of `dump edges`: 8 fields, two fused addresses (remote and
/// local), hence two `port` literals.
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
        // Remote address.
        let host = t.s()?.to_owned();
        t.lit("port")?;
        let port = t.s()?.to_owned();
        // Local address.
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
        // Undirected dedup: the daemon emits both A→B and B→A, so
        // suppressing the from > to half leaves one line per pair.
        let arrow = if directed {
            "->"
        } else {
            if self.from > self.to {
                return None;
            }
            "--"
        };

        // A negative weight would give a negative w — odd for DOT, but
        // not guarded against.
        #[expect(clippy::cast_precision_loss)] // weight < 2^24 in sane meshes; exact for f32
        let w = 1.0_f32 + 65536.0_f32 / self.weight as f32;

        // {:.6} matches printf's default %f precision so the output stays
        // byte-identical for downstream scripts. Both `w` (non-standard)
        // and `weight` (graphviz layout hint) are emitted for output
        // compatibility.
        Some(format!(
            " \"{from}\" {arrow} \"{to}\" [w = {w:.6}, weight = {w:.6}];",
            from = self.from,
            to = self.to,
        ))
    }
}

/// One row of `dump subnets`: 2 fields, no `port` literal.
#[derive(Debug, Clone)]
pub struct SubnetRow {
    /// Subnet string, possibly with a `#WEIGHT` suffix. `strip_weight`
    /// post-processes for display.
    pub subnet: String,
    /// Owner name, or the literal `"(broadcast)"` for broadcast subnets.
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

/// Strip a `#10` (default weight) suffix.
///
/// The daemon already omits `#10`, so this is a no-op against a
/// same-version daemon; it defends against older daemons.
///
/// The literal `"#10"` must track `tinc_proto::DEFAULT_WEIGHT`; the test
/// `strip_weight_tracks_default` pins that.
#[must_use]
pub fn strip_weight(s: &str) -> &str {
    s.strip_suffix("#10").unwrap_or(s)
}

/// One row of `dump connections`: 6 fields, one `port` literal.
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
    /// The daemon-side fd number.
    pub socket: i32,
    /// Connection status bitfield (distinct from node status). Printed as
    /// hex; no bits are interpreted here.
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

    /// Plain-text. Status is unpadded hex here (unlike the node row's
    /// zero-padded status) — kept for output compatibility.
    #[must_use]
    pub fn fmt_plain(&self) -> String {
        format!(
            "{} at {} port {} options {:x} socket {} status {:x}",
            self.name, self.host, self.port, self.options, self.socket, self.status,
        )
    }
}

/// One row of `DUMP_TRAFFIC`: name plus four counters (5 fields after
/// `recv_row` strips the prefix). Simplest dump format — no `port`
/// literal, no hex.
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
    pub fn parse(body: &str) -> Result<Self, ParseError> {
        let mut t = Tok::new(body);
        Ok(Self {
            name: t.s()?.to_owned(),
            in_packets: t.lu()?,
            in_bytes: t.lu()?,
            out_packets: t.lu()?,
            out_bytes: t.lu()?,
        })
        // Trailing fields are ignored, so a future daemon adding fields
        // won't break parsing.
    }
}
