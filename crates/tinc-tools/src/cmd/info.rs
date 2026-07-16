//! `cmd_info` — human-readable node/subnet/address summaries.
//!
//! ```text
//!   tinc info alice           → human-readable summary of node alice
//!   tinc info 10.0.0.5        → which subnet(s) route this address?
//!   tinc info 10.0.0.0/24     → who advertises EXACTLY this subnet?
//! ```
//!
//! ## Dispatch by argument shape
//!
//! `check_id()` → node name. Contains `.` or `:` → subnet/address.
//! Else error. `check_id("ff")` is true, so node-mode wins for
//! ambiguous inputs.
//!
//! ## The dead third arg
//!
//! `"18 3 alice"` includes the node name, but the daemon ignores it and
//! dumps everything; filtering is client-side. Sending it anyway keeps
//! the wire traffic identical to the C client.
//!
//! ## Three sequential dumps
//!
//! `info_node` does NODES → match-one-then-drain → EDGES → SUBNETS.
//! Not pipelined: an unknown node short-circuits before EDGES/SUBNETS.
//!
//! ## Partial parses for edges/subnets
//!
//! Only the first two fields of an edge row are read; a full parse would
//! be stricter than the C client (a malformed trailing field would fail
//! here but not there), so we keep the same parse slack.
//!
//! ## `localtime_r`: the one unsafe block
//!
//! `nix` doesn't wrap `localtime_r` (library function, not a syscall) and
//! `chrono` would cost several transitive deps for one strftime, so this
//! module carries the crate's single `#[allow(unsafe_code)]` shim.

#![cfg(unix)]

use std::fmt::{self, Write as _};

use tinc_proto::Subnet;

use crate::cmd::CmdError;
use crate::ctl::rows::{NodeRow, StatusBit, SubnetRow, strip_weight};
use crate::ctl::{CtlRequest, CtlSocket, DumpRow};
use crate::names::{Paths, check_id};

/// Format a Unix timestamp as `"%Y-%m-%d %H:%M:%S"` in local time.
///
/// Uses `localtime_r` (reentrant — cargo test runs threads). Only unsafe
/// block in the crate:
///
///   1. `time_t` is `i64` on all targeted platforms, so the `as` cast is
///      an identity conversion.
///   2. `tm` is `MaybeUninit::zeroed()`: `localtime_r` fully initializes
///      it on success, but zero-init keeps the `tm_zone` pointer valid
///      (null) even before that.
///   3. NULL return (EOVERFLOW for absurd years) maps to `"never"`.
///   4. Only `c_int` fields are read afterwards; no pointer deref.
#[allow(unsafe_code, clippy::cast_sign_loss, clippy::cast_possible_truncation)]
fn fmt_localtime(t: i64) -> String {
    // 0 means "no state change recorded"; guard here so callers don't repeat it.
    if t == 0 {
        return "never".to_owned();
    }

    let time = t as libc::time_t;
    let mut tm = std::mem::MaybeUninit::<libc::tm>::zeroed();
    // SAFETY:
    //   - `&time` is a valid aligned pointer to a live `time_t` for
    //     the call duration. `localtime_r` reads it once.
    //   - `tm.as_mut_ptr()` is a valid aligned `*mut tm` to writable
    //     memory of size `sizeof(tm)`. `localtime_r` writes it.
    //   - No aliasing: both pointers are to locals on this stack.
    //   - Thread-safe: that's the `_r` (caller provides storage).
    //   - POSIX: returns NULL on error, else `result` (the second
    //     arg, echoed). We check NULL.
    //
    // `&raw const time` not `&time`: clippy::borrow_as_ptr. Makes
    // the place-to-pointer explicit (no Rust borrow ever exists;
    // the pointer is consumed by FFI immediately).
    let ok = unsafe { libc::localtime_r(&raw const time, tm.as_mut_ptr()) };
    if ok.is_null() {
        return "never".to_owned();
    }
    // SAFETY: `localtime_r` returned non-NULL → it fully initialized
    // `*result` per POSIX. Every field we read below is `c_int`.
    let tm = unsafe { tm.assume_init() };

    // tm_year is years-since-1900; tm_mon is 0-based.
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec,
    )
}

// Options bits: per-edge config (set in hosts/* files), unlike StatusBit
// which is per-node runtime state.

/// `OPTION_INDIRECT`. `IndirectData = yes` in the host file. Forces
/// all traffic to be relayed via meta connections (no UDP attempts).
/// For nodes behind NATs you can't punch.
const OPTION_INDIRECT: u32 = 0x0001;
/// `TCPOnly = yes`. Same effect as INDIRECT for routing purposes,
/// semantically "don't bother trying UDP".
const OPTION_TCPONLY: u32 = 0x0002;
/// PMTU discovery enabled (the default). When off, MTU stays at the
/// static config value.
const OPTION_PMTU_DISCOVERY: u32 = 0x0004;
/// Clamp TCP MSS option in forwarded packets to fit the discovered
/// PMTU. Avoids fragmentation.
const OPTION_CLAMP_MSS: u32 = 0x0008;

/// Top 8 bits of options carry the protocol minor version. Format
/// is `PROT_MAJOR.minor`.
const fn option_version(options: u32) -> u32 {
    options >> 24
}

/// How can we reach this node? Seven mutually exclusive cases, checked in
/// order (first-match-wins): MYSELF never reaches the unreachable check,
/// unreachable never reaches the indirect check, etc.
/// `reachability_cascade_order` pins the ordering.
///
/// Carries display data inline so `Display` is self-contained (no
/// back-reference to the `NodeRow`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reachability {
    /// `host == "MYSELF"`. The daemon's self-node.
    Myself,
    /// `!status.reachable`. The graph BFS didn't find a path. Node
    /// is offline (or partitioned from us).
    Unreachable,
    /// `via != name`. UDP-relayed through another node. The `via`
    /// is the relay's name.
    Indirect { via: String },
    /// `!status.validkey`. Reachable in the graph, direct, but
    /// SPTPS handshake hasn't completed (or legacy KEY exchange).
    /// We could route to it, but encryption isn't up.
    Unknown,
    /// `minmtu > 0`. UDP works, PMTU discovered. The good case.
    /// The `pmtu` line and (optional) `RTT` line only print here.
    DirectUdp { pmtu: i16, rtt_us: Option<i32> },
    /// `nexthop == name`. We have a direct meta connection (TCP
    /// socket) to this node, but no working UDP. Packets tunnel
    /// over TCP.
    DirectTcp,
    /// Else: reachable, direct, key valid, no UDP, AND nexthop
    /// is someone else. We'd forward via nexthop's TCP. The
    /// "shouldn't normally happen" case (if we're routing through
    /// nexthop, why isn't `via` set?).
    Forwarded { nexthop: String },
}

impl Reachability {
    /// Compute from `NodeRow`. `name` is the queried node name, used for
    /// the `via`/`nexthop` self-compare (same value as `row.name` after
    /// the match).
    fn from_row(row: &NodeRow, name: &str) -> Self {
        // The daemon sets this exact string for the self-node.
        if row.host == "MYSELF" {
            return Self::Myself;
        }
        if !row.is(StatusBit::REACHABLE) {
            return Self::Unreachable;
        }
        if row.via != name {
            return Self::Indirect {
                via: row.via.clone(),
            };
        }
        if !row.is(StatusBit::VALIDKEY) {
            return Self::Unknown;
        }
        if row.minmtu > 0 {
            // -1 means never pinged.
            let rtt_us = (row.udp_ping_rtt != -1).then_some(row.udp_ping_rtt);
            return Self::DirectUdp {
                pmtu: row.pmtu,
                rtt_us,
            };
        }
        if row.nexthop == name {
            return Self::DirectTcp;
        }
        Self::Forwarded {
            nexthop: row.nexthop.clone(),
        }
    }
}

impl fmt::Display for Reachability {
    /// Multi-line for `DirectUdp` (PMTU + optional RTT on their own
    /// lines). No trailing newline — caller adds.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Myself => f.write_str("can reach itself"),
            Self::Unreachable => f.write_str("unreachable"),
            Self::Indirect { via } => write!(f, "indirectly via {via}"),
            Self::Unknown => f.write_str("unknown"),
            Self::DirectUdp { pmtu, rtt_us } => {
                write!(f, "directly with UDP\nPMTU:         {pmtu}")?;
                if let Some(rtt) = rtt_us {
                    // millis.micros, same arithmetic as dump's rtt suffix.
                    write!(f, "\nRTT:          {}.{:03}", rtt / 1000, rtt % 1000)?;
                }
                Ok(())
            }
            Self::DirectTcp => f.write_str("directly with TCP"),
            Self::Forwarded { nexthop } => write!(f, "none, forwarded via {nexthop}"),
        }
    }
}

impl NodeRow {
    /// Check one status bit.
    #[must_use]
    pub const fn is(&self, bit: StatusBit) -> bool {
        self.status & bit.0 != 0
    }
}

/// Everything `info_node` collects for one `tinc info NODE` output.
/// Separate from the I/O so format tests don't need a daemon.
#[derive(Debug)]
pub struct NodeInfo {
    /// The matched row. Carries everything except edges + subnets.
    pub row: NodeRow,
    /// `Edges:` line content — the `to` names of edges where
    /// `from == queried`. Space-joined.
    pub edges_to: Vec<String>,
    /// `Subnets:` line content — subnet strings where `owner ==
    /// queried`, after `strip_weight`.
    pub subnets: Vec<String>,
}

impl NodeInfo {
    /// Render the full output.
    ///
    /// Column alignment is byte-exact with C tinc so
    /// `diff <(tinc-c info alice) <(tinc-rs info alice)` is clean:
    /// labels are 14 chars, except `Status:`/`Options:`/`Edges:`/`Subnets:`
    /// which are one shorter because each value carries its own leading
    /// space — values still start at column 14.
    ///
    /// `name` is the queried name, used for the cascade's via/nexthop
    /// compare (same value as `row.name`).
    #[must_use]
    pub fn format(&self, name: &str) -> String {
        let row = &self.row;
        let mut out = String::with_capacity(512);

        let _ = writeln!(out, "Node:         {name}");
        let _ = writeln!(out, "Node ID:      {}", row.id);
        let _ = writeln!(out, "Address:      {} port {}", row.host, row.port);

        let timestr = fmt_localtime(row.last_state_change);
        if row.is(StatusBit::REACHABLE) {
            let _ = writeln!(out, "Online since: {timestr}");
        } else {
            let _ = writeln!(out, "Last seen:    {timestr}");
        }

        // Flag order matters for byte-exact output.
        out.push_str("Status:      ");
        for (bit, label) in [
            (StatusBit::VALIDKEY, " validkey"),
            (StatusBit::VISITED, " visited"),
            (StatusBit::REACHABLE, " reachable"),
            (StatusBit::INDIRECT, " indirect"),
            (StatusBit::SPTPS, " sptps"),
            (StatusBit::UDP_CONFIRMED, " udp_confirmed"),
        ] {
            if row.is(bit) {
                out.push_str(label);
            }
        }
        out.push('\n');

        out.push_str("Options:     ");
        for (bit, label) in [
            (OPTION_INDIRECT, " indirect"),
            (OPTION_TCPONLY, " tcponly"),
            (OPTION_PMTU_DISCOVERY, " pmtu_discovery"),
            (OPTION_CLAMP_MSS, " clamp_mss"),
        ] {
            if row.options & bit != 0 {
                out.push_str(label);
            }
        }
        out.push('\n');

        // Protocol minor version lives in the top 8 bits of options.
        let _ = writeln!(
            out,
            "Protocol:     {}.{}",
            tinc_proto::request::PROT_MAJOR,
            option_version(row.options)
        );

        let reach = Reachability::from_row(row, name);
        let _ = writeln!(out, "Reachability: {reach}");

        // Double space between count and unit is intentional (byte-exact output).
        let _ = writeln!(
            out,
            "RX:           {} packets  {} bytes",
            row.in_packets, row.in_bytes
        );
        let _ = writeln!(
            out,
            "TX:           {} packets  {} bytes",
            row.out_packets, row.out_bytes
        );

        out.push_str("Edges:       ");
        for edge in &self.edges_to {
            out.push(' ');
            out.push_str(edge);
        }
        out.push('\n');

        // strip_weight was already applied during collect.
        out.push_str("Subnets:     ");
        for subnet in &self.subnets {
            out.push(' ');
            out.push_str(subnet);
        }
        // Trailing newline included; caller uses print! not println!.
        out.push('\n');

        out
    }
}

/// `ParseError → CmdError` with the standard "Unable to parse X dump" message.
fn parse_err(what: &str, body: &str) -> CmdError {
    CmdError::BadInput(format!("Unable to parse {what} dump from tincd.\n{body}"))
}

/// Find one node, drain the rest.
///
/// Sends `DUMP_NODES name` (the daemon ignores the name — see module
/// doc), reads rows until `name` matches or terminator. On match, drains
/// the remaining rows: the daemon sends all nodes regardless, and an
/// unread tail would corrupt the next request's recv.
///
/// Returns `Ok(Some(row))` if found, `Ok(None)` if not.
///
/// Generic over the socket type so unit tests can pass a
/// `UnixStream::pair()` half without `connect()`.
fn find_node<S: std::io::Read + std::io::Write>(
    ctl: &mut CtlSocket<S>,
    name: &str,
) -> Result<Option<NodeRow>, CmdError> {
    // Third arg is dead on the wire — see module doc.
    ctl.send_str(CtlRequest::DumpNodes, name)?;

    let found = loop {
        match ctl.recv_row()? {
            DumpRow::End(_) => return Ok(None),
            DumpRow::Row(_, body) => {
                let row = NodeRow::parse(&body).map_err(|_| parse_err("node", &body))?;
                if row.name == name {
                    break row;
                }
            }
        }
    };

    // Drain: the daemon is still sending the rest of the dump.
    ctl.for_each_row(|_, _| Ok::<_, CmdError>(()))?;

    Ok(Some(found))
}

/// Collect edges from `name`.
///
/// Partial parse: only `from` + `to`; the remaining fields are ignored
/// (see module doc on parse slack).
fn collect_edges<S: std::io::Read + std::io::Write>(
    ctl: &mut CtlSocket<S>,
    name: &str,
) -> Result<Vec<String>, CmdError> {
    ctl.send_str(CtlRequest::DumpEdges, name)?;

    let mut to_names = Vec::new();
    ctl.for_each_row(|_, body| {
        // split_ascii_whitespace (not splitn) so runs of whitespace collapse.
        let mut it = body.split_ascii_whitespace();
        let (Some(from), Some(to)) = (it.next(), it.next()) else {
            return Err(parse_err("edge", body));
        };
        // Only edges FROM the queried node.
        if from == name {
            to_names.push(to.to_owned());
        }
        Ok(())
    })?;
    Ok(to_names)
}

/// Collect subnets owned by `name`, with `strip_weight` applied.
fn collect_subnets<S: std::io::Read + std::io::Write>(
    ctl: &mut CtlSocket<S>,
    name: &str,
) -> Result<Vec<String>, CmdError> {
    ctl.send_str(CtlRequest::DumpSubnets, name)?;

    let mut subnets = Vec::new();
    ctl.for_each_row(|_, body| {
        let row = SubnetRow::parse(body).map_err(|_| parse_err("subnet", body))?;
        if row.owner == name {
            subnets.push(strip_weight(&row.subnet).to_owned());
        }
        Ok::<_, CmdError>(())
    })?;
    Ok(subnets)
}

/// The full `info NODE` flow: three sequential round-trips over one
/// connection. Not pipelined — an unknown node short-circuits before
/// asking for edges/subnets.
///
/// # Errors
/// `BadInput("Unknown node X.")` if not found, or daemon I/O / parse
/// failures.
fn info_node(paths: &Paths, name: &str) -> Result<String, CmdError> {
    let mut ctl = CtlSocket::connect(paths)?;

    let Some(row) = find_node(&mut ctl, name)? else {
        return Err(CmdError::BadInput(format!("Unknown node {name}.")));
    };

    let edges_to = collect_edges(&mut ctl, name)?;
    let subnets = collect_subnets(&mut ctl, name)?;

    Ok(NodeInfo {
        row,
        edges_to,
        subnets,
    }
    .format(name))
}

/// One `Subnet: ... / Owner: ...` block.
#[derive(Debug, PartialEq, Eq)]
pub struct SubnetMatch {
    /// The subnet string, post-`strip_weight`.
    pub subnet: String,
    /// Owner name. `(broadcast)` for broadcast subnets.
    pub owner: String,
}

/// Find which subnet(s) match `item`.
///
/// `item` is the user's input string. We parse it once for the
/// match logic (`find: Subnet`) and ALSO inspect the string for
/// `/` and `#` — those drive the match semantics:
///
///   - No `/` → address mode: find subnets that CONTAIN `item`.
///     Returns possibly many (10.0.0.5 is in /24, /16, /8, /0).
///   - Has `/` → exact mode: prefix and addr must equal.
///   - Has `#` → ALSO match weight. Else weight-agnostic.
///
/// Returns ALL matches. Empty result → caller errors with
/// "Unknown address/subnet".
///
/// # Errors
/// Parse failure on `item` (str2net rejected it), or daemon I/O.
fn info_subnet(paths: &Paths, item: &str) -> Result<Vec<SubnetMatch>, CmdError> {
    let find: Subnet = item
        .parse()
        .map_err(|_| CmdError::BadInput(format!("Could not parse subnet or address '{item}'.")))?;

    // Match mode is decided by the input string, not the parsed Subnet:
    // `10.0.0.5/32` and `10.0.0.5` parse the same, but typing `/32` means
    // "exactly this /32" while a bare address asks "which net routes this".
    let as_address = !item.contains('/');
    let with_weight = item.contains('#');

    let mut ctl = CtlSocket::connect(paths)?;
    // Third arg is dead on the wire — see module doc.
    ctl.send_str(CtlRequest::DumpSubnets, item)?;

    let mut matches = Vec::new();
    ctl.for_each_row(|_, body| {
        let row = SubnetRow::parse(body).map_err(|_| parse_err("subnet", body))?;
        // A parse failure on the daemon's own subnet is corruption — fatal.
        let subnet: Subnet = row.subnet.parse().map_err(|_| parse_err("subnet", body))?;

        // Weight only matters if the user typed `#` (string-shape gate).
        if with_weight && find.weight() != subnet.weight() {
            return Ok(());
        }
        // Argument order matters: subnet.matches(&find, true) uses
        // subnet's own prefix for the containment check.
        if !subnet.matches(&find, as_address) {
            return Ok(());
        }

        matches.push(SubnetMatch {
            subnet: strip_weight(&row.subnet).to_owned(),
            owner: row.owner,
        });
        Ok::<_, CmdError>(())
    })?;

    // Caller turns an empty result into an error, picking the
    // "address" vs "subnet" wording from the input shape it already knows.
    Ok(matches)
}

/// `info` is bimodal — node info (one big block) or subnet matches
/// (zero-to-many blocks). The binary formats them differently.
#[derive(Debug)]
pub enum InfoOutput {
    /// `info_node` output. Ready to `print!` (trailing newline
    /// included).
    Node(String),
    /// `info_subnet` matches. Binary prints `Subnet: %s\nOwner:
    /// %s\n` per match.
    Subnet(Vec<SubnetMatch>),
}

/// Dispatch by argument shape: `check_id` first (node names), then
/// `.` or `:` (subnet/address), else error. Ambiguity goes to node:
/// `ff` is a valid node name and never reaches the subnet check.
///
/// # Errors
/// - `"Argument is not a node name, subnet or address."` if neither
///   check matches (e.g., `tinc info @!$`).
/// - `"Unknown node X."` if name passed `check_id` but daemon
///   doesn't have it.
/// - `"Unknown address X."` / `"Unknown subnet X."` if no match.
/// - `"Could not parse subnet or address 'X'."` if `.`/`:` matched
///   but `str2net` rejected (e.g., `tinc info ...`).
/// - Daemon I/O / parse failures.
pub fn info(paths: &Paths, item: &str) -> Result<InfoOutput, CmdError> {
    if check_id(item) {
        return info_node(paths, item).map(InfoOutput::Node);
    }

    // `:` matches both v6 and MAC (both colon-separated); `.` matches v4.
    if item.contains('.') || item.contains(':') {
        let matches = info_subnet(paths, item)?;
        if matches.is_empty() {
            let what = if item.contains('/') {
                "subnet"
            } else {
                "address"
            };
            return Err(CmdError::BadInput(format!("Unknown {what} {item}.")));
        }
        return Ok(InfoOutput::Subnet(matches));
    }

    Err(CmdError::BadInput(
        "Argument is not a node name, subnet or address.".into(),
    ))
}

#[cfg(test)]
mod tests;
