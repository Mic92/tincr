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
//! Else error. `check_id("ff")` is true so node-mode wins for
//! ambiguous inputs; the order is the spec.
//!
//! ## The dead third arg
//!
//! We send `"18 3 alice"` — three tokens, the node name appended.
//! But the daemon's `case REQ_DUMP_NODES: return dump_nodes(c)`
//! does no `sscanf` of `request` past the type. The daemon doesn't
//! read it. Filtering is **client-side**. We send it anyway (wire-
//! compat — `tcpdump` traces look the same), and filter ourselves.
//!
//! ## Three sequential dumps
//!
//! `info_node` does NODES → match-one-then-drain → EDGES → SUBNETS.
//! The drain reads-and-discards the rest of the dump after we
//! matched. Not pipelined because we short-circuit on unknown-node
//! before sending EDGES/SUBNETS.
//!
//! ## Partial parses for edges/subnets
//!
//! Only the first two STRING fields of the edge row are read. The
//! other 6 (host/port/local/options/weight) are unread. We could
//! use `EdgeRow::parse` (full 8-field) and ignore the tail. But
//! that's stricter: a malformed weight would fail our parse and
//! pass upstream's. Low risk (daemon writes them all), but the
//! principle is "match upstream's parse-slack".
//!
//! ## `localtime_r`: the one unsafe block
//!
//! `nix` doesn't wrap `localtime_r` (it's a libc TZ-file-parsing
//! library function, not a syscall — outside nix's "safe wrappers
//! for syscalls" scope). `chrono` would cost ~6 transitive deps for
//! one strftime. So: one `#[allow(unsafe_code)]` shim around
//! `libc::localtime_r`. See the lib.rs `#![deny]` comment for the
//! tradeoff. The shim is `#[cfg(unix)]`; the whole module is too
//! (info needs the daemon).
//!

#![cfg(unix)]

use std::fmt::{self, Write as _};

use tinc_proto::Subnet;

use crate::cmd::CmdError;
use crate::cmd::dump::{NodeRow, StatusBit, SubnetRow, strip_weight};
use crate::ctl::{CtlError, CtlRequest, CtlSocket, DumpRow};
use crate::names::{Paths, check_id};

// fmt_localtime — the one unsafe block in tinc-tools

/// Format a Unix timestamp as `"%Y-%m-%d %H:%M:%S"` in local time.
///
/// We use `_r` (not the non-reentrant version) to dodge the
/// thread-safety mess (cargo test runs threads). Same output.
///
/// `#[allow(unsafe_code)]`: this is the only unsafe in the crate.
/// `nix` doesn't wrap `localtime_r` because it's a libc library
/// function (parses `/etc/localtime`), not a syscall. The unsafe
/// here is bounded:
///
///   1. `time_t` is created from `i64` via `as` cast. On every
///      platform tinc targets, `time_t` is `i64` (64-bit Linux,
///      macOS, BSDs). The cast is identity. On a 32-bit `time_t`
///      platform (none we care about), values past 2038 would wrap.
///   2. `tm` is `MaybeUninit::zeroed()` — `localtime_r` fully
///      initializes it (POSIX guarantees this on success), but we
///      zero-init anyway because `tm` has a `*const c_char tm_zone`
///      and reading an uninit pointer is UB even if we never deref.
///      Zero is a valid (null) pointer; `localtime_r` overwrites it.
///   3. NULL return means error (per POSIX). The only documented
///      errno is `EOVERFLOW` (year doesn't fit `int`), which for
///      `tm_year` (offset from 1900) means timestamps past year
///      ~2.1 billion. We map NULL → `"never"` (semantically "no
///      useful time to show").
///   4. The fields read after success are `c_int` (initialized).
///      No pointer deref, no slice tricks.
#[allow(unsafe_code, clippy::cast_sign_loss, clippy::cast_possible_truncation)]
fn fmt_localtime(t: i64) -> String {
    // The buffer is initialized to `"never"`; `if(last_state_change)`
    // skips the strftime. The `== 0` guard is here so callers don't
    // repeat it.
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
        // EOVERFLOW. Node last seen in the year 2 billion. Sure.
        return "never".to_owned();
    }
    // SAFETY: `localtime_r` returned non-NULL → it fully initialized
    // `*result` per POSIX. Every field we read below is `c_int`.
    let tm = unsafe { tm.assume_init() };

    // strftime("%Y-%m-%d %H:%M:%S"). `tm_year` is years-since-1900;
    // `tm_mon` is 0-based. Widths: %Y is "at least 4", others
    // zero-pad to 2.
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

// Options bits
//
// Same shape as StatusBit but semantically different: options are
// per-edge config (set in hosts/* files), status is per-node runtime.
// `tinc-graph` already has OPTION_INDIRECT; we re-declare the four
// info needs (modules independent — see Constraints).

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

// Reachability — the 7-way cascade

/// How can we reach this node? Seven mutually exclusive cases,
/// checked in order (first-match-wins, same as the DOT color
/// cascade in `dump`).
///
/// The order is upstream's: a MYSELF node never gets to the
/// unreachable check, an unreachable node never gets to the
/// indirect check, etc. `reachability_cascade_order` pins it.
///
/// Carries display data inline so `Display` is self-contained
/// (no back-reference to the `NodeRow`). The `pmtu`/`rtt` only matter
/// for `DirectUdp` — printed on the next lines, but only in that
/// arm.
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
    /// Compute from `NodeRow`. The cascade.
    ///
    /// `name` is the queried node name (for `via`/`nexthop` self-
    /// compare). It's the function argument, not the parsed field
    /// — same value because the match already happened.
    fn from_row(row: &NodeRow, name: &str) -> Self {
        // Exact string. The daemon sets it for the self-node.
        if row.host == "MYSELF" {
            return Self::Myself;
        }
        if !row.is(StatusBit::REACHABLE) {
            return Self::Unreachable;
        }
        // Compare against the queried `item`, not the struct's
        // `name` field. (Same value here, post-match.)
        if row.via != name {
            return Self::Indirect {
                via: row.via.clone(),
            };
        }
        if !row.is(StatusBit::VALIDKEY) {
            return Self::Unknown;
        }
        if row.minmtu > 0 {
            // Same as dump's `fmt_plain` rtt suffix. -1 → "never
            // pinged".
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
    /// The lines as upstream prints them. Multi-line for `DirectUdp`
    /// (PMTU + optional RTT on their own lines). NO trailing
    /// newline — caller adds.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Myself => f.write_str("can reach itself"),
            Self::Unreachable => f.write_str("unreachable"),
            Self::Indirect { via } => write!(f, "indirectly via {via}"),
            Self::Unknown => f.write_str("unknown"),
            // 1-3 lines. The `\n` between "directly with UDP" and
            // "PMTU:" is in the format string itself — one printf,
            // two lines. We do the same.
            Self::DirectUdp { pmtu, rtt_us } => {
                write!(f, "directly with UDP\nPMTU:         {pmtu}")?;
                if let Some(rtt) = rtt_us {
                    // `RTT: %d.%03d` — millis dot micros-mod-1000.
                    // Same arithmetic as dump's `fmt_plain` rtt.
                    write!(f, "\nRTT:          {}.{:03}", rtt / 1000, rtt % 1000)?;
                }
                Ok(())
            }
            Self::DirectTcp => f.write_str("directly with TCP"),
            Self::Forwarded { nexthop } => write!(f, "none, forwarded via {nexthop}"),
        }
    }
}

// NodeRow extensions — status bit reads

impl NodeRow {
    /// Check one status bit. `info` uses 6 of the 13.
    #[must_use]
    pub fn is(&self, bit: StatusBit) -> bool {
        self.status & bit.0 != 0
    }
}

// NodeInfo — the human-readable formatter

/// One `tinc info NODE` output. Everything `info_node` collects,
/// formatted as upstream would.
///
/// Separate from the I/O so format tests don't need a daemon. The
/// output string is golden-checkable.
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
    /// Returns a `String` with embedded newlines (NOT trailing). The
    /// binary `print!`s it then adds the final `\n`.
    ///
    /// Column alignment is byte-exact: 14 chars for the label
    /// (`"Node:         "` etc.). Literal spaces; the `Status:` and
    /// `Options:` labels are 13+space because the VALUES start with
    /// a space (`printf(" validkey")`). Net effect: values start at
    /// column 14 either way. Replicated exactly so `diff <(tinc-c
    /// info alice) <(tinc-rs info alice)` is clean.
    ///
    /// `name`: the queried name (for the cascade's via/nexthop
    /// compare). Same value as `row.name` (the match guarantees it),
    /// but passed separately because upstream does — using `item`
    /// (the argument) not `node` (the parsed field).
    ///
    /// `clippy::too_many_lines`: ~100 lines of printf for the same
    /// span. Splitting would mean passing `out` around. One
    /// function, one output.
    #[must_use]
    pub fn format(&self, name: &str) -> String {
        let row = &self.row;
        let mut out = String::with_capacity(512);

        // ─── Top: name, ID, address
        let _ = writeln!(out, "Node:         {name}");
        let _ = writeln!(out, "Node ID:      {}", row.id);
        let _ = writeln!(out, "Address:      {} port {}", row.host, row.port);

        // ─── Timestamp
        // `Online since:` if reachable, else `Last seen:`. Label
        // widths differ — 13+1 vs 10+4 — but both end up with
        // values at column 14.
        let timestr = fmt_localtime(row.last_state_change);
        if row.is(StatusBit::REACHABLE) {
            let _ = writeln!(out, "Online since: {timestr}");
        } else {
            let _ = writeln!(out, "Last seen:    {timestr}");
        }

        // ─── Status flags
        // Six bits, printed in declaration order. Each prefixed
        // with a space so the line is `Status:       validkey
        // visited ...`. The label is `"Status:      "` (12+1 chars)
        // — one shorter than the others because each value adds
        // its own leading space. Net column alignment is the same.
        out.push_str("Status:      ");
        // The order is upstream's printf order. NOT bit-position
        // order: validkey (bit 1), visited (bit 3), reachable (4),
        // indirect (5), sptps (6), udp_confirmed (7). It IS
        // `node.h` field-declaration order (skipping the unused/
        // unprinted bits). Preserve.
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

        // ─── Options flags
        // Same shape, 4 OPTION_* bits.
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

        // ─── Protocol version
        // `PROT_MAJOR.OPTION_VERSION(options)`. The minor lives in
        // the top 8 bits of `options` (so a node running 17.7 has
        // `options & 0xff000000 == 0x07000000`). The major is OUR
        // constant (it's the protocol version we speak — same as
        // the daemon's by definition, since we wouldn't have
        // connected otherwise). PROT_MAJOR is 17. Re-declared here
        // — modules independent (Constraints). Three copies of
        // `= 17`, all sed-verifiable, beats one pub-use-chain that
        // ties module visibility together.
        //
        // `clippy::items_after_statements`: a `const` mid-function
        // is hoisted to function scope, but the visual position
        // next to its only use is the point.
        #[allow(clippy::items_after_statements)]
        const PROT_MAJOR: u8 = 17;
        let _ = writeln!(
            out,
            "Protocol:     {PROT_MAJOR}.{}",
            option_version(row.options)
        );

        // ─── Reachability cascade
        // Multi-line for DirectUdp.
        let reach = Reachability::from_row(row, name);
        let _ = writeln!(out, "Reachability: {reach}");

        // ─── Traffic counters
        // Double-space between count and unit. Replicate. (`diff`
        // would notice.)
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

        // ─── Edges
        // `Edges:        node1 node2 ...`. The label is
        // `"Edges:       "` (12+1) — same one-short-because-values-
        // have-leading-space trick as Status.
        out.push_str("Edges:       ");
        for edge in &self.edges_to {
            out.push(' ');
            out.push_str(edge);
        }
        out.push('\n');

        // ─── Subnets
        // Same shape. `strip_weight` already applied during collect.
        out.push_str("Subnets:     ");
        for subnet in &self.subnets {
            out.push(' ');
            out.push_str(subnet);
        }
        // All lines above include their `\n`; this one too. Caller
        // uses `print!` not `println!`.
        out.push('\n');

        out
    }
}

// I/O: the three dump-recv loops

/// Adapter, same as `dump::daemon_err`. Re-declared (modules
/// independent).
#[allow(clippy::needless_pass_by_value)]
fn daemon_err(e: CtlError) -> CmdError {
    CmdError::BadInput(e.to_string())
}

/// `ParseError → CmdError` with upstream's message:
/// `"Unable to parse X dump from tincd."`.
fn parse_err(what: &str, body: &str) -> CmdError {
    // Upstream includes the line for edge dump but not for the
    // others. Inconsistent; we always include (it's useful). The
    // body, not the full `"18 3 ..."` line — recv_row already
    // stripped the prefix.
    CmdError::BadInput(format!("Unable to parse {what} dump from tincd.\n{body}"))
}

/// Find one node, drain the rest.
///
/// Sends `DUMP_NODES name` (the daemon ignores `name` — see module
/// doc), reads rows until `name` matches or terminator. On match,
/// breaks and DRAINS until terminator (the daemon sends all nodes
/// regardless; the unread tail would corrupt the next request's
/// recv).
///
/// Returns `Ok(Some(row))` if found, `Ok(None)` if terminator hit
/// without match. `Err` on I/O or parse failure.
///
/// Generic over the socket type so unit tests can pass a
/// `UnixStream::pair()` half without `connect()`.
fn find_node<S: std::io::Read + std::io::Write>(
    ctl: &mut CtlSocket<S>,
    name: &str,
) -> Result<Option<NodeRow>, CmdError> {
    // The third arg is dead on the wire (daemon doesn't read it)
    // but we send it anyway — wire-compat, tcpdump traces match.
    // `send_str` does `"18 3 alice\n"`.
    ctl.send_str(CtlRequest::DumpNodes, name)
        .map_err(daemon_err)?;

    // ─── Match loop
    // `loop`-with-`break value` not `let mut found = None` — the
    // initial None is dead (clippy noticed); the loop ASSIGNS once
    // then breaks. The break-value form makes that single-assignment
    // structural.
    let found = loop {
        match ctl.recv_row().map_err(daemon_err)? {
            DumpRow::End(_) => {
                // Terminator without match. Caller maps to
                // "Unknown node". No drain needed: terminator IS
                // the end.
                return Ok(None);
            }
            DumpRow::Row(_, body) => {
                // Full 22-field parse.
                let row = NodeRow::parse(&body).map_err(|_| parse_err("node", &body))?;
                if row.name == name {
                    break row;
                }
                // Not it. Next.
            }
        }
    };

    // ─── Drain
    // Found alice on row 3 of 50; daemon's still sending. Read and
    // discard until terminator. We don't even tokenize: recv_row
    // does the End detect for us.
    loop {
        match ctl.recv_row().map_err(daemon_err)? {
            DumpRow::End(_) => break,
            DumpRow::Row(_, _) => {} // discard
        }
    }

    Ok(Some(found))
}

/// Collect edges from `name`.
///
/// Partial parse: only `from` + `to` (first two strings). The
/// other 6 fields are ignored — matching upstream's parse-slack.
/// A malformed `weight` (last field) passes here and would fail
/// `EdgeRow::parse`.
fn collect_edges<S: std::io::Read + std::io::Write>(
    ctl: &mut CtlSocket<S>,
    name: &str,
) -> Result<Vec<String>, CmdError> {
    ctl.send_str(CtlRequest::DumpEdges, name)
        .map_err(daemon_err)?;

    let mut to_names = Vec::new();
    loop {
        match ctl.recv_row().map_err(daemon_err)? {
            DumpRow::End(_) => break,
            DumpRow::Row(_, body) => {
                // Just first two strings — `from` and `to`. We
                // don't parse the tail (`host port host port
                // options weight`). NOT `splitn(3, ' ')` — sscanf
                // collapses runs of whitespace, daemon's printf has
                // single spaces, but match the semantics not the
                // spacing.
                let mut it = body.split_ascii_whitespace();
                let (Some(from), Some(to)) = (it.next(), it.next()) else {
                    return Err(parse_err("edge", &body));
                };
                // Only edges FROM us (TO is the far end of OUR
                // outgoing edges).
                if from == name {
                    to_names.push(to.to_owned());
                }
            }
        }
    }
    Ok(to_names)
}

/// Collect subnets owned by `name`.
///
/// Full `SubnetRow::parse` (it's only 2 fields, partial wouldn't
/// be shorter). `strip_weight` applied here.
fn collect_subnets<S: std::io::Read + std::io::Write>(
    ctl: &mut CtlSocket<S>,
    name: &str,
) -> Result<Vec<String>, CmdError> {
    ctl.send_str(CtlRequest::DumpSubnets, name)
        .map_err(daemon_err)?;

    let mut subnets = Vec::new();
    loop {
        match ctl.recv_row().map_err(daemon_err)? {
            DumpRow::End(_) => break,
            DumpRow::Row(_, body) => {
                let row = SubnetRow::parse(&body).map_err(|_| parse_err("subnet", &body))?;
                if row.owner == name {
                    // Apply strip_weight at collect.
                    subnets.push(strip_weight(&row.subnet).to_owned());
                }
            }
        }
    }
    Ok(subnets)
}

/// The full `info NODE` flow.
///
/// Three round-trips, sequential. Doesn't pipeline because the
/// not-found short-circuit happens after dump 1 — no point asking
/// for alice's edges if alice doesn't exist.
///
/// # Errors
/// `BadInput("Unknown node X.")` if not found, or daemon I/O /
/// parse failures.
fn info_node(paths: &Paths, name: &str) -> Result<String, CmdError> {
    let mut ctl = CtlSocket::connect(paths).map_err(daemon_err)?;

    // ─── 1. Find the node
    let Some(row) = find_node(&mut ctl, name)? else {
        return Err(CmdError::BadInput(format!("Unknown node {name}.")));
    };

    // ─── 2+3. Edges and subnets
    // Done AFTER the not-found check, sequentially. The socket
    // stays open across all three (one connect).
    let edges_to = collect_edges(&mut ctl, name)?;
    let subnets = collect_subnets(&mut ctl, name)?;

    // ─── Format
    Ok(NodeInfo {
        row,
        edges_to,
        subnets,
    }
    .format(name))
}

// info_subnet — route lookup or exact match

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
    // ─── Parse the query
    let find: Subnet = item
        .parse()
        .map_err(|_| CmdError::BadInput(format!("Could not parse subnet or address '{item}'.")))?;

    // Shape inspection by SUBSTRING, not by the parsed Subnet.
    // Lossy: `10.0.0.5/32` is semantically the same as `10.0.0.5`
    // (both /32 v4), but the `/` makes it exact-mode. The user
    // typing `/32` is saying "exactly this /32"; the user typing
    // the bare address is asking "which net routes this". We
    // inspect the STRING.
    let as_address = !item.contains('/');
    let with_weight = item.contains('#');

    // ─── Dump and filter
    let mut ctl = CtlSocket::connect(paths).map_err(daemon_err)?;
    // Third arg is dead, daemon ignores.
    ctl.send_str(CtlRequest::DumpSubnets, item)
        .map_err(daemon_err)?;

    let mut matches = Vec::new();
    loop {
        match ctl.recv_row().map_err(daemon_err)? {
            DumpRow::End(_) => break,
            DumpRow::Row(_, body) => {
                let row = SubnetRow::parse(&body).map_err(|_| parse_err("subnet", &body))?;
                // A parse failure on the DAEMON's subnet is fatal.
                // (Can't compare what we can't parse.) The daemon
                // never sends garbage, so this is corruption.
                let subnet: Subnet = row.subnet.parse().map_err(|_| parse_err("subnet", &body))?;

                // ─── Filters
                // Type mismatch → skip. Handled inside `matches()`
                // (returns false).
                //
                // Weight match, IFF user typed `#`. Outside
                // `matches()` because it's gated by the string-
                // shape, not the parsed value.
                if with_weight && find.weight() != subnet.weight() {
                    continue;
                }
                // The per-type maskcmp/memcmp. Factored into
                // `Subnet::matches`. NB: argument order is
                // `subnet.matches(&find, ...)`, NOT the other way.
                // `subnet.matches(find, true)` uses self's prefix.
                if !subnet.matches(&find, as_address) {
                    continue;
                }

                // We collect; binary prints.
                matches.push(SubnetMatch {
                    subnet: strip_weight(&row.subnet).to_owned(),
                    owner: row.owner,
                });
            }
        }
    }

    // Caller does the `if(!found)` → error (so caller picks the
    // "address" vs "subnet" wording from the shape it already
    // knows).
    Ok(matches)
}

// Dispatch

/// Result: `info` is bimodal — node info (one big block) or subnet
/// matches (zero-to-many blocks). The binary formats differently.
#[derive(Debug)]
pub enum InfoOutput {
    /// `info_node` output. Ready to `print!` (trailing newline
    /// included).
    Node(String),
    /// `info_subnet` matches. Binary prints `Subnet: %s\nOwner:
    /// %s\n` per match.
    Subnet(Vec<SubnetMatch>),
}

/// Dispatch by argument shape.
///
/// The order: `check_id` first (node names are strict alphanum +
/// underscore), then `.` or `:` (subnet/address). Neither → error.
/// Ambiguity goes to node: `ff` is a valid node name, never reaches
/// the subnet check.
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

    // The `:` matches both v6 AND mac (both colon-separated). `.`
    // matches v4. A node name with `.` would be rejected by
    // `check_id` so wouldn't reach here.
    if item.contains('.') || item.contains(':') {
        let matches = info_subnet(paths, item)?;
        if matches.is_empty() {
            // `"Unknown address %s.\n"` if no `/`, `"Unknown
            // subnet %s.\n"` if `/`.
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

// Tests

#[cfg(test)]
mod tests;
