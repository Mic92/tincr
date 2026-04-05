//! `cmd_dump` — daemon state and invitation listings.
//!
//! ```text
//!   tinc dump nodes              → list all nodes the daemon knows
//!   tinc dump reachable nodes    → ...filtered to reachable bit
//!   tinc dump edges              → all edges (directed, both halves)
//!   tinc dump subnets            → all advertised subnets
//!   tinc dump connections        → meta-connections (the live sockets)
//!   tinc dump graph              → DOT format, undirected
//!   tinc dump digraph            → DOT format, directed
//!   tinc dump invitations        → outstanding invites (NO daemon)
//!   tinc list ...                → alias
//! ```
//!
//! ## Dump format is a cross-impl seam
//!
//! Format is pinned by the daemon's `dump_*` functions. Rust
//! `tinc dump` ←→ upstream `tincd` is a useful cross-impl test asserting
//! identical output.
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
//!
//! ## What we tighten
//!
//! - `recv_row` validates `code == 18` per row. Upstream checks
//!   `n >= 2` but never checks `code` — a `"19 3 ..."` row would
//!   be dispatched on whatever `req` parsed as. We reject.
//!
//! - `dump invitations` checks `name.len() == 24` BEFORE decode.
//!   Upstream's `b64decode_tinc(..., 24)` reads first 24 chars,
//!   returns 18 on valid. A 25-char name with valid first-24 would
//!   pass; daemon lookup is exact-24 so it'd never match anyway.
//!   We tighten to exact-24. Same as `sweep_expired`.
//!
//! ## What we drop
//!
//! - `usage(true)` calls on bad argument. Upstream dumps the full
//!   help text. We just error; the binary's main can print usage
//!   if it wants.
//!

use std::fmt::Write as _;
use std::fs;
use std::io::{BufRead, BufReader};

use tinc_proto::{ParseError, Tok};

use crate::cmd::{CmdError, io_err};
use crate::ctl::{CtlError, CtlRequest, CtlSocket, DumpRow};
use crate::names::{Paths, check_id};

// Kind: the 7 sub-verbs

/// Which `dump` sub-verb. Upstream uses string matches inline +
/// `do_graph` int + `only_reachable` bool — three local vars
/// threading through one switch. We collapse to one enum because
/// the dispatch is 1:1 (the three-var space has 7 valid points and
/// a lot of impossible ones like `do_graph=1 && only_reachable`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `dump nodes`
    Nodes,
    /// `dump reachable nodes` — same fetch, filtered output.
    ReachableNodes,
    /// `dump edges`
    Edges,
    /// `dump subnets`
    Subnets,
    /// `dump connections`
    Connections,
    /// `dump graph` — DOT, undirected (`--`)
    Graph,
    /// `dump digraph` — DOT, directed (`->`)
    Digraph,
    /// `dump invitations` — NO daemon; readdir.
    Invitations,
}

impl Kind {
    /// Does this sub-verb need to talk to the daemon? The binary's
    /// `cmd_dump` adapter checks this BEFORE `connect()` — so
    /// `dump invitations` works with daemon down.
    #[must_use]
    pub const fn needs_daemon(self) -> bool {
        !matches!(self, Kind::Invitations)
    }
}

/// Parse `argv` → `Kind`.
///
/// The `reachable` shift dance: `dump reachable nodes` is parsed as
/// `dump nodes` with a bool, via `argv++; argc--`. We do the same
/// shape (slice, not pointer arith) so the error messages line up.
///
/// All matches case-insensitive (`strcasecmp`).
///
/// # Errors
/// `BadInput` mirroring upstream's three error strings — `reachable`
/// without `nodes`, wrong arg count, unknown type.
pub fn parse_kind(args: &[String]) -> Result<Kind, CmdError> {
    // ─── `reachable` prefix (only valid before `nodes`)
    // The check is `argc > 2 && !strcasecmp(argv[1], "reachable")` —
    // argc>2 because we need a word AFTER reachable. Then check
    // that word is `nodes`.
    let (only_reachable, args) = match args {
        [first, rest @ ..] if first.eq_ignore_ascii_case("reachable") => {
            // Must have a second arg, and it must be "nodes".
            let Some(second) = rest.first() else {
                // `dump reachable` with nothing after. Upstream
                // checks `argc > 2` before strcasecmp, so it does
                // NOT shift — falls through to "Invalid number of
                // arguments." Match that: bail without shifting.
                return Err(CmdError::BadInput("Invalid number of arguments.".into()));
            };
            if !second.eq_ignore_ascii_case("nodes") {
                // The backtick-apostrophe quoting is 90s GNU style;
                // preserved.
                return Err(CmdError::BadInput(
                    "`reachable' only supported for nodes.".into(),
                ));
            }
            (true, rest)
        }
        _ => (false, args),
    };

    // ─── Arity: exactly one (after the shift)
    let [what] = args else {
        return Err(CmdError::BadInput("Invalid number of arguments.".into()));
    };

    // ─── Dispatch
    // `only_reachable` was already validated to be nodes-only above,
    // but the code structure means we COULD arrive here with
    // only_reachable=true and what=="nodes" (the only valid combo)
    // or only_reachable=false and any what. We just match what; the
    // only_reachable bit only modifies the Nodes arm.
    let kind = if what.eq_ignore_ascii_case("nodes") {
        if only_reachable {
            Kind::ReachableNodes
        } else {
            Kind::Nodes
        }
    } else if what.eq_ignore_ascii_case("edges") {
        Kind::Edges
    } else if what.eq_ignore_ascii_case("subnets") {
        Kind::Subnets
    } else if what.eq_ignore_ascii_case("connections") {
        Kind::Connections
    } else if what.eq_ignore_ascii_case("graph") {
        Kind::Graph
    } else if what.eq_ignore_ascii_case("digraph") {
        Kind::Digraph
    } else if what.eq_ignore_ascii_case("invitations") {
        Kind::Invitations
    } else {
        return Err(CmdError::BadInput(format!("Unknown dump type '{what}'.")));
    };

    Ok(kind)
}

// node_status_t bits — only the two we use
//
// 13 bool:1 fields in a union with uint32_t. GCC packs LSB-first
// on x86-64 (it's "implementation-defined" per C standard; in
// practice GCC and Clang agree). Field N is bit (1<<N).
//
// We only need two for the upstream-compatible output:
//
//   reachable (field 4 → bit 4) — `dump reachable nodes` filter
//   validkey  (field 1 → bit 1) — graph color: black if not validkey
//
// The other 11 are daemon-internal (visited, waitingforkey, etc.).
// The CLI doesn't read them. NOT a `bitflags!` because we use 2 of
// 13 and the daemon's port will define all 13 in its own type —
// these are the CLI's view of an opaque hex int, not a shared
// definition.

/// `node_status_t` bit positions: a 13-field `bool:1` bitfield in a
/// `u32` union. GCC packs LSB-first on x86-64 (and every target tinc
/// builds on); bit N is field N counting from 0.
///
/// `dump` needs bits 1+4 (validkey/reachable). `info` needs the six
/// that the `Status:` line prints. The daemon's port will define all
/// 13 in its own `NodeStatus` type; for the CLI these are display-
/// only, so a `u8` newtype + `is(bit)` is the lean answer. Public so
/// `cmd::info` can share.
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

// Backward-compat aliases for the existing dump.rs callers. Same
// values, just the old names. Module-private — new code uses
// StatusBit.
const STATUS_REACHABLE: u32 = StatusBit::REACHABLE.0;
const STATUS_VALIDKEY: u32 = StatusBit::VALIDKEY.0;

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
        // Daemon `%lu`, CLI `%d`. Read as lu, narrow. The value
        // (digest_length) is < 256 always, narrowing is safe.
        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)] // digest_length<256
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
        self.status & STATUS_REACHABLE != 0
    }

    /// Bit 1 (validkey). Graph mode picks black for !validkey.
    #[must_use]
    pub const fn validkey(&self) -> bool {
        self.status & STATUS_VALIDKEY != 0
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
        //
        // `as f32` from i32 is exact for the values we see (weight
        // is < 2^24 in any sane tinc setup).
        #[allow(clippy::cast_precision_loss)] // weight < 2^24; exact for f32
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

// Dump invitations — pure fs, no daemon

/// One outstanding invitation. We collect so the binary can decide
/// stdout/stderr.
#[derive(Debug, Clone)]
pub struct InviteRow {
    /// The 24-char b64 cookie-hash (the filename).
    pub cookie_hash: String,
    /// The invitee name from the file's first line `Name = X`.
    pub invitee: String,
}

/// Walks `confbase/invitations/`, finds 24-char-b64-named files,
/// reads `Name = ` from line 1, collects. Upstream printf-per-file;
/// we return Vec for the binary to print.
///
/// Upstream has THREE per-file failure modes that warn-and-skip
/// (`fprintf(stderr, ...); continue;`):
///
/// 1. File won't open
/// 2. Empty file
/// 3. First line isn't `Name = VALID_ID`
///
/// We don't `eprintln!` from lib code. The most useful behavior is
/// "show what's valid, skip the rest". So we silently skip. If
/// someone wants the warnings, the seam is here.
///
/// # Errors
/// `Io` if the directory exists but readdir fails (perms?).
/// ENOENT is NOT an error — exit 0 with empty Vec.
pub fn dump_invitations(paths: &Paths) -> Result<Vec<InviteRow>, CmdError> {
    use tinc_crypto::invite::SLUG_PART_LEN;

    let dir = paths.invitations_dir();

    // ─── Open directory
    // ENOENT → empty list, exit 0. Anything else → error.
    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Never created the dir → no invites → not an error.
            return Ok(Vec::new());
        }
        Err(e) => return Err(io_err(dir)(e)),
    };

    let mut out = Vec::new();

    for entry in entries {
        // ─── Per-entry errors are skip, not fail
        // `readdir` doesn't fail per-entry on Linux but it CAN
        // (e.g. NFS weirdness). Upstream doesn't check; we skip.
        let Ok(entry) = entry else { continue };
        let name_os = entry.file_name();

        // ─── 24-char-b64 filter
        // We're stricter than upstream: name must be EXACTLY 24
        // chars AND decode to 18 bytes. Upstream would accept a
        // 25-char name with valid first 24. Daemon lookup is
        // exact-24, so a 25-char file never matches an invite
        // anyway. Same as `sweep_expired`.
        //
        // OsStr::len() is bytes (Unix). 24 bytes is 24 ASCII chars
        // for valid b64; non-ASCII bytes would fail decode anyway.
        if name_os.len() != SLUG_PART_LEN {
            continue;
        }
        // to_str(): non-UTF-8 → skip. b64 alphabet is ASCII so a
        // valid name is always UTF-8; non-UTF-8 means not-a-cookie.
        let Some(name) = name_os.to_str() else {
            continue;
        };
        // Decode-validate. We don't NEED the bytes (we just need to
        // know the name is valid b64), but `decode` is the validator.
        let Some(decoded) = tinc_crypto::b64::decode(name) else {
            continue;
        };
        // 24 b64 chars → 18 bytes always (24 * 6 = 144 bits = 18
        // bytes). The check is mathematically redundant with
        // len()==24-and-decoded; assert it to catch a future b64
        // change.
        debug_assert_eq!(decoded.len(), 18);

        // ─── Read first line
        // We read just enough — the file might have a long body
        // (the host config blob), don't slurp it.
        let path = entry.path();
        let Ok(file) = fs::File::open(&path) else {
            continue;
        };
        let mut first = String::new();
        // BufReader for one line is overhead but cleaner than a
        // hand-rolled byte-by-byte newline scan.
        if BufReader::new(file).read_line(&mut first).is_err() || first.is_empty() {
            continue;
        }

        // ─── Extract `Name = X`
        // The rstrip uses `strchr("\t \r\n", ...)` — strips any
        // combination from the right. We do the same set.
        //
        // The `"Name = "` (7 chars, exact match including spaces)
        // is what `cmd_invite` writes. It's NOT the general config
        // tokenizer — `Name=X` (no spaces) would FAIL here even
        // though it parses fine in `tinc.conf`. This is intentional:
        // the format we wrote is the format we read.
        let first = first.trim_end_matches(['\t', ' ', '\r', '\n']);
        let Some(invitee) = first.strip_prefix("Name = ") else {
            continue;
        };
        if !check_id(invitee) {
            continue;
        }

        out.push(InviteRow {
            cookie_hash: name.to_owned(),
            invitee: invitee.to_owned(),
        });
    }

    Ok(out)
}

// The daemon-backed dumps

/// Adapter: `CtlError → CmdError`. Same shape as `ctl_simple::
/// daemon_err`, re-declared (modules independent).
#[allow(clippy::needless_pass_by_value)] // .map_err(daemon_err) passes by value; |e| daemon_err(&e) is uglier
fn daemon_err(e: CtlError) -> CmdError {
    CmdError::BadInput(e.to_string())
}

/// Result of a daemon dump. Separate type so the binary can route
/// `Ok(DumpOutput::Lines(v))` → `println!` per line and the
/// "no entries" case to stderr (the convention for empty dumps is
/// silence — exit 0, no output).
#[derive(Debug)]
pub enum DumpOutput {
    /// Lines ready for stdout. The binary prints each + `\n`.
    Lines(Vec<String>),
}

/// Run one of the daemon-backed dumps.
///
/// `paths` must be `resolve_runtime()`d (the binary's `needs_daemon`
/// gate handles this).
///
/// The function shape: connect, send 1-2 requests, recv-loop with
/// per-kind parse, format, return lines. Upstream inlines all four
/// parses into one switch inside one loop; we do the same — the
/// graph mode interleaves nodes-then-edges and the loop body
/// dispatches on the row's kind, so per-kind helper functions
/// would NEED a closure or generic anyway. One function, one match.
///
/// `clippy::too_many_lines`: ~165 lines for the same span. Pulling
/// the per-kind parse out would make the graph-mode interleave less
/// obvious. Allowed.
///
/// # Errors
/// Connect failure, recv failure (daemon crashed mid-dump), or
/// row parse failure. Row parse failure SHOULD never happen
/// against same-version daemon — if it does, the format strings
/// drifted, file a bug.
#[cfg(unix)]
pub fn dump(paths: &Paths, kind: Kind) -> Result<DumpOutput, CmdError> {
    debug_assert!(kind.needs_daemon(), "use dump_invitations()");

    let mut ctl = CtlSocket::connect(paths).map_err(daemon_err)?;

    // ─── Send: 1 or 2 requests
    // Graph/digraph send NODES then EDGES; everything else sends
    // one. The daemon responds in order (each ends with its
    // terminator).
    match kind {
        Kind::Nodes | Kind::ReachableNodes => {
            ctl.send(CtlRequest::DumpNodes).map_err(daemon_err)?;
        }
        Kind::Edges => {
            ctl.send(CtlRequest::DumpEdges).map_err(daemon_err)?;
        }
        Kind::Subnets => {
            ctl.send(CtlRequest::DumpSubnets).map_err(daemon_err)?;
        }
        Kind::Connections => {
            ctl.send(CtlRequest::DumpConnections).map_err(daemon_err)?;
        }
        Kind::Graph | Kind::Digraph => {
            // TWO sends. The daemon doesn't pipeline (it's strictly
            // request-response on CONTROL), so the second request
            // actually arrives while the daemon is still SENDING
            // the first response. That's fine — TCP buffers it.
            ctl.send(CtlRequest::DumpNodes).map_err(daemon_err)?;
            ctl.send(CtlRequest::DumpEdges).map_err(daemon_err)?;
        }
        Kind::Invitations => unreachable!("debug_assert above"),
    }

    // ─── Receive loop
    // The big while-recvline-switch.
    //
    // Exit condition: a terminator (2-int row). For graph mode,
    // the FIRST terminator (DUMP_NODES) is a continue, the SECOND
    // (DUMP_EDGES) exits. For everything else, first terminator
    // exits.
    let mut lines = Vec::new();

    // Graph mode header.
    match kind {
        Kind::Graph => lines.push("graph {".to_owned()),
        Kind::Digraph => lines.push("digraph {".to_owned()),
        _ => {}
    }

    let directed = matches!(kind, Kind::Digraph);

    loop {
        match ctl.recv_row().map_err(daemon_err)? {
            // ─── Terminator: maybe done
            DumpRow::End(end_kind) => {
                // Graph mode continues past the NODES terminator,
                // exits on EDGES. Non-graph exits on any terminator.
                if matches!(
                    (kind, end_kind),
                    // Graph mode, first terminator (NODES). Edges
                    // still to come.
                    (Kind::Graph | Kind::Digraph, CtlRequest::DumpNodes)
                ) {
                    // Empty: fall through to next loop iteration.
                } else {
                    // Anything else: done.
                    break;
                }
            }

            // ─── Node row
            // The kind-from-row, NOT the kind-we-asked-for. Graph
            // mode interleaves; the daemon sends `18 3 ...` then
            // `18 4 ...` and we dispatch on the 3/4.
            DumpRow::Row(CtlRequest::DumpNodes, body) => {
                let row = NodeRow::parse(&body).map_err(|_| {
                    // Includes the bad line. Debugging a wire
                    // mismatch needs it.
                    CmdError::BadInput(format!("Unable to parse node dump from tincd: {body}"))
                })?;

                match kind {
                    Kind::Nodes => lines.push(row.fmt_plain()),
                    Kind::ReachableNodes => {
                        if row.reachable() {
                            lines.push(row.fmt_plain());
                        }
                    }
                    Kind::Graph | Kind::Digraph => {
                        lines.push(row.fmt_dot());
                    }
                    // We sent the wrong request?? Daemon bug.
                    // Upstream doesn't check this, just dispatches
                    // on `req`. We tighten — getting NODES when we
                    // asked for EDGES is a protocol violation.
                    _ => {
                        return Err(CmdError::BadInput("Unexpected node row".into()));
                    }
                }
            }

            // ─── Edge row
            DumpRow::Row(CtlRequest::DumpEdges, body) => {
                let row = EdgeRow::parse(&body).map_err(|_| {
                    CmdError::BadInput(format!("Unable to parse edge dump from tincd: {body}"))
                })?;

                match kind {
                    Kind::Edges => lines.push(row.fmt_plain()),
                    Kind::Graph | Kind::Digraph => {
                        // fmt_dot returns None for the suppressed
                        // half (undirected dedup).
                        if let Some(line) = row.fmt_dot(directed) {
                            lines.push(line);
                        }
                    }
                    _ => {
                        return Err(CmdError::BadInput("Unexpected edge row".into()));
                    }
                }
            }

            // ─── Subnet row
            DumpRow::Row(CtlRequest::DumpSubnets, body) => {
                let row = SubnetRow::parse(&body).map_err(|_| {
                    CmdError::BadInput("Unable to parse subnet dump from tincd.".into())
                })?;
                lines.push(row.fmt_plain());
            }

            // ─── Connection row
            DumpRow::Row(CtlRequest::DumpConnections, body) => {
                let row = ConnRow::parse(&body).map_err(|_| {
                    CmdError::BadInput("Unable to parse connection dump from tincd.".into())
                })?;
                lines.push(row.fmt_plain());
            }

            // ─── Unknown row type
            // The daemon sent a row type we didn't ask for and
            // don't know. This is a daemon bug or version skew.
            DumpRow::Row(_, _) => {
                return Err(CmdError::BadInput(
                    "Unable to parse dump from tincd.".into(),
                ));
            }
        }
    }

    // ─── Graph footer
    match kind {
        Kind::Graph | Kind::Digraph => lines.push("}".to_owned()),
        _ => {}
    }

    Ok(DumpOutput::Lines(lines))
}

// Tests
//
// Golden vectors transcribed from the daemon's printf format strings.
// These test inputs are what you'd see on the wire if you `nc -U`
// the control socket.
//
// The fmt_plain output is also pinned — it's a script-compatibility
// surface. If anyone changes the output format, scripts that parse
// `tinc dump nodes | awk` break.

#[cfg(test)]
mod tests;
