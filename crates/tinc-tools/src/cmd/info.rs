//! `cmd_info` — `info.c`, 356 lines C → ~500 Rust + tests.
//!
//! ```text
//!   tinc info alice           → human-readable summary of node alice
//!   tinc info 10.0.0.5        → which subnet(s) route this address?
//!   tinc info 10.0.0.0/24     → who advertises EXACTLY this subnet?
//! ```
//!
//! ## Dispatch by argument shape
//!
//! `info.c:348-356`: `check_id()` → node name. Contains `.` or `:` →
//! subnet/address. Else "not a node name, subnet or address". Lossy:
//! `info ff` is a valid node name AND a valid v6 address (`::ff`?
//! no, `ff` alone isn't), AND would be a MAC-prefix if MACs had
//! prefixes... but `check_id("ff")` is true (it's `[A-Za-z0-9_]+`),
//! so node-mode wins. The C order is the spec.
//!
//! ## The dead third arg
//!
//! `info.c:53` sends `"18 3 alice"` — three tokens, the node name
//! appended. But `control.c:63` is `case REQ_DUMP_NODES: return
//! dump_nodes(c)` — no `sscanf` of `request` past the type. The
//! daemon doesn't read it. Filtering is **client-side**. Maybe it
//! was a planned daemon-side filter that never landed; maybe a
//! debug breadcrumb. We send it too (wire-compat — `tcpdump`
//! traces look the same), and filter ourselves.
//!
//! ## Three sequential dumps
//!
//! `info_node` does NODES → match-one-then-drain → EDGES → match
//! → SUBNETS → match. Three round-trips. The drain (`info.c:102-
//! 106`) is necessary because the daemon doesn't stop sending nodes
//! when we `break` — we found alice on row 3 of 50, the other 47
//! plus terminator are still coming. The C reads-and-discards.
//!
//! Why not pipeline (send all three, then read three terminators)?
//! Because the C doesn't, and the second/third sends only happen
//! after the first matched (`if(!found) return 1` at `info.c:97`).
//! The error-on-unknown-node short-circuits before EDGES/SUBNETS.
//! We follow.
//!
//! ## Partial parses for edges/subnets
//!
//! `info.c:204` is `sscanf(..., "%d %d %s %s", &code, &req, from,
//! to)` — only the first two STRING fields of the edge row. The
//! other 6 (host/port/local/options/weight) are unread. The C's
//! `if(n != 4)` check counts the conversions, not the wire fields.
//!
//! We could use `EdgeRow::parse` (full 8-field) and ignore the
//! tail. But that's stricter than C: a malformed weight would fail
//! our parse and pass C's. Low risk (daemon writes them all), but
//! the principle is "match C's parse-slack". Tok::s() twice it is.
//!
//! ## `localtime_r`: the one unsafe block
//!
//! `info.c:116`: `strftime("%Y-%m-%d %H:%M:%S", localtime(&time))`.
//! `nix` doesn't wrap `localtime_r` (it's a libc TZ-file-parsing
//! library function, not a syscall — outside nix's "safe wrappers
//! for syscalls" scope). `chrono` would cost ~6 transitive deps for
//! one strftime. So: one `#[allow(unsafe_code)]` shim around
//! `libc::localtime_r`. See the lib.rs `#![deny]` comment for the
//! tradeoff. The shim is `#[cfg(unix)]`; the whole module is too
//! (info needs the daemon).
//!
//! ## Layout
//!
//!  - `fmt_localtime`      — the libc shim (15 LOC, one unsafe)
//!  - `Reachability`       — the 7-way cascade enum
//!  - `NodeInfo`           — formatter struct, takes `NodeRow` + lists
//!  - `find_node`          — recv-loop-match-drain (the I/O)
//!  - `info_node`          — orchestrates the three dumps
//!  - `info_subnet`        — recv-loop, match via `Subnet::matches`
//!  - `info`               — the dispatch
//!
//! Tests: format pieces are pure (golden output strings); the recv
//! loops get fake-daemon integration tests in `tinc_cli.rs`.

#![allow(clippy::doc_markdown)]
#![cfg(unix)]

use std::fmt::{self, Write as _};

use tinc_proto::Subnet;

use crate::cmd::CmdError;
use crate::cmd::dump::{NodeRow, StatusBit, SubnetRow, strip_weight};
use crate::ctl::{CtlError, CtlRequest, CtlSocket, DumpRow};
use crate::names::{Paths, check_id};

// fmt_localtime — the one unsafe block in tinc-tools

/// Format a Unix timestamp as `"%Y-%m-%d %H:%M:%S"` in local time.
/// `info.c:116`: `strftime(timestr, sizeof(timestr), "...",
/// localtime(&lsc_time))`.
///
/// The C uses `localtime` (not `_r`) — we use `_r` to dodge the
/// thread-safety mess (cargo test runs threads). Same output.
///
/// `#[allow(unsafe_code)]`: this is the only unsafe in the crate.
/// `nix` doesn't wrap `localtime_r` because it's a libc library
/// function (parses `/etc/localtime`), not a syscall. The unsafe
/// here is bounded:
///
///   1. `time_t` is created from `i64` via `as` cast. On every
///      platform tinc targets, `time_t` is `i64` (64-bit Linux,
///      macOS, BSDs). The cast is identity. On a 32-bit time_t
///      platform (none we care about), values past 2038 would wrap.
///   2. `tm` is `MaybeUninit::zeroed()` — `localtime_r` fully
///      initializes it (POSIX guarantees this on success), but we
///      zero-init anyway because `tm` has a `*const c_char tm_zone`
///      and reading an uninit pointer is UB even if we never deref.
///      Zero is a valid (null) pointer; localtime_r overwrites it.
///   3. NULL return means error (per POSIX). The only documented
///      errno is `EOVERFLOW` (year doesn't fit `int`), which for
///      `tm_year` (offset from 1900) means timestamps past year
///      ~2.1 billion. We map NULL → `"never"` (same as C's branch
///      for `last_state_change == 0` — semantically "no useful
///      time to show").
///   4. The fields read after success are `c_int` (initialized).
///      No pointer deref, no slice tricks.
///
/// `clippy::cast_sign_loss` for `t as libc::time_t`: time_t IS
/// signed on every Unix; the cast preserves sign. Allowed at item.
#[allow(unsafe_code, clippy::cast_sign_loss, clippy::cast_possible_truncation)]
fn fmt_localtime(t: i64) -> String {
    // C `info.c:112-113,118`: `char timestr[32] = "never"; if
    // (last_state_change) { strftime(...) }`. The `== 0` guard is
    // here so callers don't repeat it.
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
    //     The non-`_r` version uses TLS-or-static; cargo test threads
    //     would race.
    //   - POSIX: returns NULL on error, else `result` (the second
    //     arg, echoed). We check NULL.
    //
    // `&raw const time` not `&time`: clippy::borrow_as_ptr. The `&`
    // form auto-coerces &T → *const T, which is fine but lossy about
    // intent. `&raw const` (Rust 1.82+) makes the place-to-pointer
    // explicit. Same machine code; clearer that no Rust borrow ever
    // exists (the pointer is consumed by FFI immediately).
    let ok = unsafe { libc::localtime_r(&raw const time, tm.as_mut_ptr()) };
    if ok.is_null() {
        // EOVERFLOW. Node last seen in the year 2 billion. Sure.
        return "never".to_owned();
    }
    // SAFETY: `localtime_r` returned non-NULL → it fully initialized
    // `*result` per POSIX. Every field we read below is `c_int`.
    let tm = unsafe { tm.assume_init() };

    // strftime("%Y-%m-%d %H:%M:%S"). `tm_year` is years-since-1900;
    // `tm_mon` is 0-based. The C strftime knows that; we adjust.
    // Widths: %Y is "at least 4", others zero-pad to 2 (%m,%d,%H,...).
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

// Options bits — connection.h:32-36
//
// Same shape as StatusBit but semantically different: options are
// per-edge config (set in hosts/* files), status is per-node runtime.
// `tinc-graph` already has OPTION_INDIRECT; we re-declare the four
// info needs (modules independent — see Constraints). PROT_MAJOR
// re-exported from tinc-proto.

/// `connection.h:32`: `OPTION_INDIRECT`. `IndirectData = yes` in
/// the host file. Forces all traffic to be relayed via meta
/// connections (no UDP attempts). For nodes behind NATs you can't
/// punch.
const OPTION_INDIRECT: u32 = 0x0001;
/// `connection.h:33`. `TCPOnly = yes`. Same effect as INDIRECT
/// for routing purposes, semantically "don't bother trying UDP".
const OPTION_TCPONLY: u32 = 0x0002;
/// `connection.h:34`. PMTU discovery enabled (the default). When
/// off, MTU stays at the static config value.
const OPTION_PMTU_DISCOVERY: u32 = 0x0004;
/// `connection.h:35`. Clamp TCP MSS option in forwarded packets
/// to fit the discovered PMTU. Avoids fragmentation.
const OPTION_CLAMP_MSS: u32 = 0x0008;

/// `connection.h:36`: `(x) >> 24`. Top 8 bits of options carry the
/// protocol minor version. `info.c:173` formats `PROT_MAJOR.minor`.
const fn option_version(options: u32) -> u32 {
    options >> 24
}

// Reachability — the 7-way cascade

/// `info.c:176-195`: how can we reach this node? Seven mutually
/// exclusive cases, checked in order (first-match-wins, same as
/// the DOT color cascade in `dump`).
///
/// The order is the C's: a MYSELF node never gets to the unreachable
/// check, an unreachable node never gets to the indirect check, etc.
/// `reachability_cascade_order` pins it.
///
/// Carries display data inline so `Display` is self-contained
/// (no back-reference to the NodeRow). The `pmtu`/`rtt` only matter
/// for `DirectUdp` — the C prints them on the next lines, but
/// only in that arm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reachability {
    /// `host == "MYSELF"`. The daemon's self-node. C `info.c:178`.
    Myself,
    /// `!status.reachable`. C `info.c:180`. The graph BFS didn't
    /// find a path. Node is offline (or partitioned from us).
    Unreachable,
    /// `via != name`. UDP-relayed through another node. C `info.c
    /// :182`. The `via` is the relay's name.
    Indirect { via: String },
    /// `!status.validkey`. Reachable in the graph, direct, but
    /// SPTPS handshake hasn't completed (or legacy KEY exchange).
    /// We could route to it, but encryption isn't up. C `info.c:184`.
    Unknown,
    /// `minmtu > 0`. UDP works, PMTU discovered. The good case.
    /// C `info.c:186`. The `pmtu` line and (optional) `RTT` line
    /// only print here.
    DirectUdp { pmtu: i16, rtt_us: Option<i32> },
    /// `nexthop == name`. We have a direct meta connection (TCP
    /// socket) to this node, but no working UDP. Packets tunnel
    /// over TCP. C `info.c:192`.
    DirectTcp,
    /// Else: reachable, direct, key valid, no UDP, AND nexthop
    /// is someone else. We'd forward via nexthop's TCP. C `info.c
    /// :194`. The "shouldn't normally happen" case (if we're
    /// routing through nexthop, why isn't `via` set?). The C
    /// doesn't comment, just prints.
    Forwarded { nexthop: String },
}

impl Reachability {
    /// Compute from NodeRow. The cascade. `info.c:176-195`.
    ///
    /// `name` is the queried node name (for `via`/`nexthop` self-
    /// compare). It's `item` in the C (the function argument), not
    /// `node` (the parsed field) — same value because the match
    /// already happened (`!strcmp(node, item)` at `info.c:91`).
    fn from_row(row: &NodeRow, name: &str) -> Self {
        // C `info.c:177`: `!strcmp(host, "MYSELF")`. Exact string.
        // The daemon sets it for the self-node (`node.c:211`: `n->
        // hostname ? n->hostname : "..."` — but for myself,
        // `hostname` is set to `"MYSELF port ..."` somewhere).
        if row.host == "MYSELF" {
            return Self::Myself;
        }
        if !row.is(StatusBit::REACHABLE) {
            return Self::Unreachable;
        }
        // C `info.c:181`: `strcmp(via, item)`. NOT `!=` on the
        // STRUCT's `name` field — the queried `item`. (Same
        // value here, post-match.)
        if row.via != name {
            return Self::Indirect {
                via: row.via.clone(),
            };
        }
        if !row.is(StatusBit::VALIDKEY) {
            return Self::Unknown;
        }
        if row.minmtu > 0 {
            // C `info.c:188-190`: `if(udp_ping_rtt != -1)`. Same as
            // dump's `fmt_plain` rtt suffix. -1 → "never pinged".
            let rtt_us = (row.udp_ping_rtt != -1).then_some(row.udp_ping_rtt);
            return Self::DirectUdp {
                pmtu: row.pmtu,
                rtt_us,
            };
        }
        // C `info.c:191`: `!strcmp(nexthop, item)`.
        if row.nexthop == name {
            return Self::DirectTcp;
        }
        Self::Forwarded {
            nexthop: row.nexthop.clone(),
        }
    }
}

impl fmt::Display for Reachability {
    /// The lines as C prints them. Multi-line for `DirectUdp`
    /// (PMTU + optional RTT on their own lines). NO trailing
    /// newline — caller adds.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Myself => f.write_str("can reach itself"),
            Self::Unreachable => f.write_str("unreachable"),
            // C `info.c:182`: `"indirectly via %s\n"`.
            Self::Indirect { via } => write!(f, "indirectly via {via}"),
            Self::Unknown => f.write_str("unknown"),
            // C `info.c:186-190`: 1-3 lines. The `\n` between
            // "directly with UDP" and "PMTU:" is in the C's format
            // string itself: `"directly with UDP\nPMTU:..."` — one
            // printf, two lines. We do the same.
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

/// `info` reads more status bits than `dump`. Extension trait would
/// be the Java answer; an inherent method on a `dump::` struct from
/// `info::` is the wrong layering. We add a method on NodeRow IN
/// dump.rs... no, that's cross-module coupling for one bit-test.
/// Just match here. NodeRow.status is `pub`.
///
/// Actually: dump.rs already has `reachable()` and `validkey()`
/// methods. The clean answer is one generic `is(bit: StatusBit)`.
/// But that's a dump.rs change. For now, a free fn here.
///
/// (UPDATE: added `NodeRow::is()` in dump.rs — see the impl block
/// addition. Kept this comment for the design note.)
impl NodeRow {
    /// Check one status bit. `info` uses 6 of the 13.
    #[must_use]
    pub fn is(&self, bit: StatusBit) -> bool {
        self.status & bit.0 != 0
    }
}

// NodeInfo — the human-readable formatter

/// One `tinc info NODE` output. Everything `info_node` collects,
/// formatted as `info.c:108-247` would.
///
/// Separate from the I/O so format tests don't need a daemon. The
/// output string is golden-checkable.
///
/// `clippy::struct_excessive_bools`: zero bools, but it's mostly
/// passthrough display data. Allowed thinking.
#[derive(Debug)]
pub struct NodeInfo {
    /// The matched row. Carries everything except edges + subnets.
    pub row: NodeRow,
    /// `Edges:` line content — the `to` names of edges where
    /// `from == queried`. Space-joined. C `info.c:215`.
    pub edges_to: Vec<String>,
    /// `Subnets:` line content — subnet strings where `owner ==
    /// queried`, after `strip_weight`. C `info.c:238`.
    pub subnets: Vec<String>,
}

impl NodeInfo {
    /// Render the full output. `info.c:108-247`.
    ///
    /// Returns a `String` with embedded newlines (NOT trailing). The
    /// binary `print!`s it then adds the final `\n`.
    ///
    /// Column alignment is byte-exact: 14 chars for the label
    /// (`"Node:         "` etc.). The C uses literal spaces; the
    /// `Status:` and `Options:` labels are 13+space because the
    /// VALUES start with a space (`printf(" validkey")`). Net effect:
    /// values start at column 14 either way. We replicate the C's
    /// space-count exactly so `diff <(tinc-c info alice) <(tinc-rs
    /// info alice)` is clean.
    ///
    /// `name`: the queried name (for the cascade's via/nexthop
    /// compare). Same value as `row.name` (the match guarantees it),
    /// but passed separately because the C does — using `item`
    /// (the argument) not `node` (the parsed field) at `info.c:108`.
    ///
    /// `clippy::too_many_lines`: the C is ~100 lines of printf for
    /// the same span. Splitting would mean passing `out` around.
    /// One function, one output.
    #[allow(clippy::too_many_lines)]
    #[must_use]
    pub fn format(&self, name: &str) -> String {
        let row = &self.row;
        let mut out = String::with_capacity(512);

        // ─── Top: name, ID, address
        // C `info.c:108-110`. `item` not `node` (same here).
        let _ = writeln!(out, "Node:         {name}");
        let _ = writeln!(out, "Node ID:      {}", row.id);
        let _ = writeln!(out, "Address:      {} port {}", row.host, row.port);

        // ─── Timestamp
        // C `info.c:112-125`. `Online since:` if reachable, else
        // `Last seen:`. Label widths differ — 13+1 vs 10+4 — but
        // both end up with values at column 14 (C uses `%-12s`-ish
        // implicit alignment via literal spaces).
        let timestr = fmt_localtime(row.last_state_change);
        if row.is(StatusBit::REACHABLE) {
            let _ = writeln!(out, "Online since: {timestr}");
        } else {
            let _ = writeln!(out, "Last seen:    {timestr}");
        }

        // ─── Status flags
        // C `info.c:127-154`. Six bits, printed in C-declaration
        // order (which is bit-position order). Each prefixed with a
        // space so the line is `Status:       validkey visited ...`.
        // The label is `"Status:      "` (12+1 chars) — one shorter
        // than the others because each value adds its own leading
        // space. Net column alignment is the same.
        out.push_str("Status:      ");
        // The order is `info.c:129-152`. NOT bit-position order:
        // validkey (bit 1), visited (bit 3), reachable (bit 4),
        // indirect (bit 5), sptps (bit 6), udp_confirmed (bit 7).
        // It IS `node.h` field-declaration order (bit position
        // skipping the unused/unprinted bits). Preserve.
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
        // C `info.c:156-172`. Same shape, 4 OPTION_* bits.
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
        // C `info.c:173`: `PROT_MAJOR.OPTION_VERSION(options)`.
        // The minor lives in the top 8 bits of `options` (so a node
        // running 17.7 has `options & 0xff000000 == 0x07000000`).
        // The major is OUR constant (it's the protocol version we
        // speak — same as the daemon's by definition, since we
        // wouldn't have connected otherwise).
        // PROT_MAJOR is 17. `protocol.h:29`. Re-declared in
        // `tinc-proto::request` (not re-exported at crate root); also
        // in `cmd::join::PROT_MAJOR` (private). Re-declare here —
        // it's a wire constant; modules independent (Constraints).
        // Three copies of `= 17`, all sed-verifiable, beats one
        // pub-use-chain that ties module visibility together.
        //
        // `clippy::items_after_statements`: a `const` mid-function
        // is hoisted to function scope (exists from `{` open), but
        // the visual position next to its only use is the point.
        // Hoisting to module level would put a printf-format-only
        // constant 300 lines from where it's used. Allowed at item.
        #[allow(clippy::items_after_statements)]
        const PROT_MAJOR: u8 = 17;
        let _ = writeln!(
            out,
            "Protocol:     {PROT_MAJOR}.{}",
            option_version(row.options)
        );

        // ─── Reachability cascade
        // C `info.c:175-195`. Multi-line for DirectUdp.
        let reach = Reachability::from_row(row, name);
        let _ = writeln!(out, "Reachability: {reach}");

        // ─── Traffic counters
        // C `info.c:197-198`. Double-space between count and unit
        // (`%"PRIu64" packets  %"PRIu64" bytes` — two spaces).
        // The C has TWO spaces. Replicate. (`diff` would notice.)
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
        // C `info.c:201-219`. `Edges:        node1 node2 ...`. The
        // label is `"Edges:       "` (12+1) — same one-short-because-
        // values-have-leading-space trick as Status.
        out.push_str("Edges:       ");
        for edge in &self.edges_to {
            out.push(' ');
            out.push_str(edge);
        }
        out.push('\n');

        // ─── Subnets
        // C `info.c:223-241`. Same shape. `strip_weight` already
        // applied during collect.
        out.push_str("Subnets:     ");
        for subnet in &self.subnets {
            out.push(' ');
            out.push_str(subnet);
        }
        // C `info.c:243`: `printf("\n")`. The last newline. We DON'T
        // add it (caller's `println!` does) — keep the contract
        // simple, no trailing newline. Except wait: every other line
        // above DOES have `\n`. The asymmetry would mean the last
        // line is the odd one out. Better: include it, caller uses
        // `print!` not `println!`. Decision: include all newlines,
        // caller `print!`s.
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

/// `ParseError → CmdError` with the C's message. `info.c:87,211,
/// 233`: `"Unable to parse X dump from tincd."`.
fn parse_err(what: &str, body: &str) -> CmdError {
    // C includes the line for edge dump (`info.c:211`: `\n%s`) but
    // not for the others. Inconsistent; we always include (it's
    // useful). The body, not the full `"18 3 ..."` line — recv_row
    // already stripped the prefix.
    CmdError::BadInput(format!("Unable to parse {what} dump from tincd.\n{body}"))
}

/// Find one node, drain the rest. `info.c:79-106`.
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
    // C `info.c:53`: `sendline(fd, "%d %d %s", CONTROL,
    // REQ_DUMP_NODES, item)`. The third arg is dead on the wire
    // (daemon doesn't read it) but we send it anyway — wire-compat,
    // tcpdump traces match. `send_str` does `"18 3 alice\n"`.
    ctl.send_str(CtlRequest::DumpNodes, name)
        .map_err(daemon_err)?;

    // ─── Match loop
    // C `info.c:79-95`: `while(recvline) { if n==2 break; if n!=24
    // err; if !strcmp break; }`.
    //
    // `loop`-with-`break value` not `let mut found = None` — the
    // initial None is dead (clippy noticed); the loop ASSIGNS once
    // then breaks. The break-value form makes that single-assignment
    // structural.
    let found = loop {
        match ctl.recv_row().map_err(daemon_err)? {
            DumpRow::End(_) => {
                // Terminator without match. C `info.c:83` falls out
                // of the while; `if(!found)` at :97 fires. We return
                // None; caller maps to "Unknown node".
                //
                // No drain needed: terminator IS the end.
                return Ok(None);
            }
            DumpRow::Row(_, body) => {
                // Full 22-field parse. C `info.c:80`: 24 conversions
                // (the C counts `code` and `req` too; recv_row
                // already stripped those, so 22).
                let row = NodeRow::parse(&body).map_err(|_| parse_err("node", &body))?;
                // C `info.c:91`: `!strcmp(node, item)`.
                if row.name == name {
                    break row;
                }
                // Not it. Next.
            }
        }
    };

    // ─── Drain
    // C `info.c:102-106`: `while(recvline) { if sscanf == 2 break }`.
    // Found alice on row 3 of 50; daemon's still sending. Read and
    // discard until terminator.
    //
    // The C drain uses a SHORTER sscanf (`%d %d %s` — 3 fields) and
    // checks `== 2` (terminator). We don't even tokenize: recv_row
    // does the End detect for us. The body of non-terminator rows is
    // ignored (the C ignores `node` post-read too).
    loop {
        match ctl.recv_row().map_err(daemon_err)? {
            DumpRow::End(_) => break,
            DumpRow::Row(_, _) => {} // discard
        }
    }

    Ok(Some(found))
}

/// Collect edges from `name`. `info.c:200-219`.
///
/// Partial parse: only `from` + `to` (first two strings). The C's
/// `sscanf("%d %d %s %s")` ignores the other 6 fields. We do too —
/// matching C's parse-slack. A malformed `weight` (last field)
/// passes here and would fail `EdgeRow::parse`; the C's behavior.
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
                // C `info.c:204`: `sscanf("%d %d %s %s")`. Just
                // first two strings — `from` and `to`. We don't
                // parse the tail (`host port host port options
                // weight`); C doesn't either.
                //
                // `Tok::s()` twice would do it, but for two fields
                // the manual split is clearer. `split_ascii_
                // whitespace` is what `Tok::s()` does internally
                // anyway. NOT `splitn(3, ' ')` — sscanf collapses
                // runs of whitespace, daemon's printf has single
                // spaces, but match the semantics not the spacing.
                let mut it = body.split_ascii_whitespace();
                let (Some(from), Some(to)) = (it.next(), it.next()) else {
                    // C `info.c:209`: `if(n != 4)`. (The 4 includes
                    // code+req; we'd check 2 here.) The C ALSO
                    // includes the line in this one — `\n%s\n`.
                    // (Only edge does. node and subnet don't.
                    // Inconsistent in C; we always include.)
                    return Err(parse_err("edge", &body));
                };
                // C `info.c:214`: `if(!strcmp(from, item)) printf
                // (" %s", to)`. Only edges FROM us (TO is the
                // far end of OUR outgoing edges).
                if from == name {
                    to_names.push(to.to_owned());
                }
            }
        }
    }
    Ok(to_names)
}

/// Collect subnets owned by `name`. `info.c:222-241`.
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
                // C `info.c:237`: `if(!strcmp(from, item))`. (`from`
                // there is what we call `owner`.)
                if row.owner == name {
                    // C `info.c:238`: `printf(" %s", strip_weight(
                    // subnet))`. We apply strip_weight at collect.
                    subnets.push(strip_weight(&row.subnet).to_owned());
                }
            }
        }
    }
    Ok(subnets)
}

/// The full `info NODE` flow. `info.c:51-247`.
///
/// Three round-trips, sequential. Doesn't pipeline because the
/// not-found short-circuit happens after dump 1 — no point asking
/// for alice's edges if alice doesn't exist.
///
/// # Errors
/// `BadInput("Unknown node X.")` if not found (the C exit-1 case),
/// or daemon I/O / parse failures.
fn info_node(paths: &Paths, name: &str) -> Result<String, CmdError> {
    let mut ctl = CtlSocket::connect(paths).map_err(daemon_err)?;

    // ─── 1. Find the node
    let Some(row) = find_node(&mut ctl, name)? else {
        // C `info.c:98`: `"Unknown node %s.\n"`.
        return Err(CmdError::BadInput(format!("Unknown node {name}.")));
    };

    // ─── 2+3. Edges and subnets
    // C does these AFTER the not-found check, sequentially. We do
    // too. The socket stays open across all three (one connect).
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

/// `info.c:249-345`. Find which subnet(s) match `item`.
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
/// Returns ALL matches. C prints `Subnet:\nOwner:\n` per match;
/// the binary does that. Empty result → caller errors with
/// "Unknown address/subnet".
///
/// # Errors
/// Parse failure on `item` (str2net rejected it), or daemon I/O.
fn info_subnet(paths: &Paths, item: &str) -> Result<Vec<SubnetMatch>, CmdError> {
    // ─── Parse the query
    // C `info.c:252-255`: `if(!str2net(&find, item))`. The error
    // message has single-quotes: `"Could not parse subnet or
    // address '%s'.\n"`.
    let find: Subnet = item
        .parse()
        .map_err(|_| CmdError::BadInput(format!("Could not parse subnet or address '{item}'.")))?;

    // C `info.c:257-258`: shape inspection by SUBSTRING, not by
    // the parsed Subnet. `!strchr(item, '/')` and `strchr(item,
    // '#')`. Lossy: `10.0.0.5/32` is semantically the same as
    // `10.0.0.5` (both /32 v4), but the `/` makes it exact-mode.
    // The user typing `/32` is saying "exactly this /32"; the user
    // typing the bare address is asking "which net routes this".
    // The C inspects the STRING. We do too.
    let as_address = !item.contains('/');
    let with_weight = item.contains('#');

    // ─── Dump and filter
    let mut ctl = CtlSocket::connect(paths).map_err(daemon_err)?;
    // C `info.c:267` sends `item` as third arg. Dead, daemon ignores.
    ctl.send_str(CtlRequest::DumpSubnets, item)
        .map_err(daemon_err)?;

    let mut matches = Vec::new();
    loop {
        match ctl.recv_row().map_err(daemon_err)? {
            DumpRow::End(_) => break,
            DumpRow::Row(_, body) => {
                let row = SubnetRow::parse(&body).map_err(|_| parse_err("subnet", &body))?;
                // C `info.c:276`: `!str2net(&subnet, netstr)` —
                // a parse failure on the DAEMON's subnet is fatal.
                // (Can't compare what we can't parse.) The daemon
                // never sends garbage, so this is corruption.
                let subnet: Subnet = row.subnet.parse().map_err(|_| parse_err("subnet", &body))?;

                // ─── Filters
                // C `info.c:281`: type mismatch → skip. Handled
                // inside `matches()` (returns false).
                //
                // C `info.c:285-289`: weight match, IFF user typed `#`.
                // Outside `matches()` because it's gated by the
                // string-shape, not the parsed value.
                if with_weight && find.weight() != subnet.weight() {
                    continue;
                }
                // C `info.c:291-322`: the per-type maskcmp/memcmp.
                // Factored into `Subnet::matches`. NB: argument
                // order is `subnet.matches(&find, ...)`, NOT the
                // other way. The C: `maskcmp(&find, &subnet,
                // SUBNET.prefixlength)` — using the SUBNET's prefix.
                // `subnet.matches(find, true)` does that (uses
                // self's prefix).
                if !subnet.matches(&find, as_address) {
                    continue;
                }

                // C `info.c:325-327`: `printf("Subnet: %s\nOwner:
                // %s\n", strip_weight(netstr), owner)`. We collect;
                // binary prints.
                matches.push(SubnetMatch {
                    subnet: strip_weight(&row.subnet).to_owned(),
                    owner: row.owner,
                });
            }
        }
    }

    // C `info.c:329-340`: `if(!found)` → error. Caller does that
    // (so caller picks the "address" vs "subnet" wording from the
    // shape it already knows).
    Ok(matches)
}

// Dispatch — info.c:347-356

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

/// `info.c:347-356`. Dispatch by argument shape.
///
/// The C order: `check_id` first (node names are strict alphanum +
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
    // C `info.c:348`: `if(check_id(item))`.
    if check_id(item) {
        return info_node(paths, item).map(InfoOutput::Node);
    }

    // C `info.c:352`: `if(strchr(item, '.') || strchr(item, ':'))`.
    // The `:` matches both v6 AND mac (both colon-separated). `.`
    // matches v4. A node name with `.` would be rejected by
    // `check_id` so wouldn't reach here.
    if item.contains('.') || item.contains(':') {
        let matches = info_subnet(paths, item)?;
        if matches.is_empty() {
            // C `info.c:331-337`: `"Unknown address %s.\n"` if no
            // `/`, `"Unknown subnet %s.\n"` if `/`.
            let what = if item.contains('/') {
                "subnet"
            } else {
                "address"
            };
            return Err(CmdError::BadInput(format!("Unknown {what} {item}.")));
        }
        return Ok(InfoOutput::Subnet(matches));
    }

    // C `info.c:355`.
    Err(CmdError::BadInput(
        "Argument is not a node name, subnet or address.".into(),
    ))
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    // ─── fmt_localtime

    /// `0` → `"never"`. C `info.c:112-113,118`: the buffer is
    /// initialized to `"never"`, the `if(last_state_change)` skips
    /// the strftime. We've folded the guard into the function.
    #[test]
    fn localtime_zero_is_never() {
        assert_eq!(fmt_localtime(0), "never");
    }

    /// A known timestamp formats to the right SHAPE. Can't assert
    /// the exact string (depends on local TZ), but the structure
    /// is fixed: `YYYY-MM-DD HH:MM:SS`.
    #[test]
    fn localtime_shape() {
        // 1700000000 = 2023-11-14 22:13:20 UTC. In any TZ, that's
        // *some* time on the 14th or 15th of Nov 2023 (offsets are
        // ±14h max). We assert the format, not the values.
        let s = fmt_localtime(1_700_000_000);
        assert_eq!(s.len(), 19, "got {s:?}");
        // Positions: 0123456789012345678
        //            YYYY-MM-DD HH:MM:SS
        let bytes = s.as_bytes();
        assert_eq!(bytes[4], b'-');
        assert_eq!(bytes[7], b'-');
        assert_eq!(bytes[10], b' ');
        assert_eq!(bytes[13], b':');
        assert_eq!(bytes[16], b':');
        // Year 2023 in any sane TZ. (UTC-14 → 2023-11-14 still;
        // UTC+14 → 2023-11-15 still.)
        assert_eq!(&s[..4], "2023");
        // All other positions are digits.
        for &i in &[0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18] {
            assert!(bytes[i].is_ascii_digit(), "pos {i} of {s:?}");
        }
    }

    /// TZ=UTC pin: under UTC, the output is deterministic. We can't
    /// `setenv("TZ")` here (other tests might be touching libc tz
    /// state in parallel; tzset() is process-global). Instead: the
    /// integration test runs with `TZ=UTC` env on the SUBPROCESS,
    /// where it's safe.
    ///
    /// This test just sanity-checks that the epoch (1) gives a 1970
    /// date in any TZ except UTC-12-or-further (which would be Dec
    /// 31 1969). The realistic TZ range is ±14h.
    #[test]
    fn localtime_epoch_is_1970ish() {
        let s = fmt_localtime(86_400); // 1970-01-02 00:00:00 UTC
        // Any TZ within ±24h gives a date in 1970-01-01..03.
        assert_eq!(&s[..7], "1970-01");
    }

    // ─── option_version

    /// `connection.h:36`: top 8 bits. sed-verifiable.
    #[test]
    fn option_version_shifts_24() {
        // 0x07000000 → 7. The 17.7 daemon.
        assert_eq!(option_version(0x0700_0000), 7);
        // Low bits ignored.
        assert_eq!(option_version(0x0700_000f), 7);
        // 0 → 0. (1.0 daemon, or unset.)
        assert_eq!(option_version(0x0000_000c), 0);
    }

    // ─── Reachability::from_row
    //
    // Golden-input tests on hand-built NodeRows. The cascade order
    // is what's pinned: a row that's MYSELF + unreachable = MYSELF
    // (first match wins).

    /// Builder: minimal NodeRow with overridable cascade-relevant
    /// fields. The other 16 fields don't affect `from_row`.
    fn cascade_row(
        host: &str,
        status: u32,
        via: &str,
        minmtu: i16,
        nexthop: &str,
        rtt: i32,
    ) -> NodeRow {
        NodeRow {
            name: "x".into(), // not read by from_row
            id: "0".into(),
            host: host.into(),
            port: "655".into(),
            cipher: 0,
            digest: 0,
            maclength: 0,
            compression: 0,
            options: 0,
            status,
            nexthop: nexthop.into(),
            via: via.into(),
            distance: 0,
            pmtu: 1518, // copied into DirectUdp
            minmtu,
            maxmtu: 1518,
            last_state_change: 0,
            udp_ping_rtt: rtt,
            in_packets: 0,
            in_bytes: 0,
            out_packets: 0,
            out_bytes: 0,
        }
    }

    /// `host == "MYSELF"` → Myself. The first arm; everything else
    /// is don't-care.
    #[test]
    fn cascade_myself() {
        // Even if status says unreachable. MYSELF check is first.
        let r = cascade_row("MYSELF", 0, "-", 0, "-", -1);
        assert_eq!(Reachability::from_row(&r, "alice"), Reachability::Myself);
    }

    /// `!reachable` → Unreachable. Second arm.
    #[test]
    fn cascade_unreachable() {
        // status=0 → bit 4 clear. host != MYSELF.
        let r = cascade_row("1.1.1.1", 0, "alice", 0, "-", -1);
        assert_eq!(
            Reachability::from_row(&r, "alice"),
            Reachability::Unreachable
        );
    }

    /// `via != name` → Indirect. Third arm. Reachable, but routed.
    #[test]
    fn cascade_indirect() {
        // reachable bit set, via=bob != alice.
        let r = cascade_row("1.1.1.1", StatusBit::REACHABLE.0, "bob", 0, "-", -1);
        assert_eq!(
            Reachability::from_row(&r, "alice"),
            Reachability::Indirect { via: "bob".into() }
        );
    }

    /// `!validkey` → Unknown. Fourth arm. Reachable, direct, but
    /// handshake hasn't finished.
    #[test]
    fn cascade_unknown() {
        // reachable, via=alice (direct), validkey CLEAR.
        let r = cascade_row("1.1.1.1", StatusBit::REACHABLE.0, "alice", 0, "alice", -1);
        assert_eq!(Reachability::from_row(&r, "alice"), Reachability::Unknown);
    }

    /// `minmtu > 0` → DirectUdp. Fifth arm. The good case.
    #[test]
    fn cascade_direct_udp() {
        let s = StatusBit::REACHABLE.0 | StatusBit::VALIDKEY.0;
        let r = cascade_row("1.1.1.1", s, "alice", 1400, "alice", 1500);
        assert_eq!(
            Reachability::from_row(&r, "alice"),
            Reachability::DirectUdp {
                pmtu: 1518,
                rtt_us: Some(1500)
            }
        );
        // rtt = -1 → no RTT line.
        let r = cascade_row("1.1.1.1", s, "alice", 1400, "alice", -1);
        assert_eq!(
            Reachability::from_row(&r, "alice"),
            Reachability::DirectUdp {
                pmtu: 1518,
                rtt_us: None
            }
        );
    }

    /// `nexthop == name` → DirectTcp. Sixth arm.
    #[test]
    fn cascade_direct_tcp() {
        let s = StatusBit::REACHABLE.0 | StatusBit::VALIDKEY.0;
        // minmtu=0 (no UDP), nexthop=alice (we have a meta conn).
        let r = cascade_row("1.1.1.1", s, "alice", 0, "alice", -1);
        assert_eq!(Reachability::from_row(&r, "alice"), Reachability::DirectTcp);
    }

    /// Else → Forwarded. The catch-all.
    #[test]
    fn cascade_forwarded() {
        let s = StatusBit::REACHABLE.0 | StatusBit::VALIDKEY.0;
        // minmtu=0, nexthop=bob (NOT alice).
        let r = cascade_row("1.1.1.1", s, "alice", 0, "bob", -1);
        assert_eq!(
            Reachability::from_row(&r, "alice"),
            Reachability::Forwarded {
                nexthop: "bob".into()
            }
        );
    }

    /// THE order test: a row that satisfies MULTIPLE arms picks the
    /// FIRST. Same role as `dump::node_dot_cascade_order`. Five-
    /// for-five on read-the-C-before-coding: the first cut had
    /// `Unreachable` before `Myself` (because "self is reachable
    /// by definition, so the order doesn't matter") — wrong. C does
    /// MYSELF first (`info.c:177` is the first `if`), the strcmp
    /// fires before the bit-read. A self-node WITH the unreachable
    /// bit set (which the daemon should never produce, but) is
    /// MYSELF.
    #[test]
    fn cascade_order_myself_beats_unreachable() {
        // MYSELF + unreachable → still Myself. The C order.
        let r = cascade_row("MYSELF", 0, "alice", 0, "-", -1);
        assert_eq!(Reachability::from_row(&r, "alice"), Reachability::Myself);
        // Unreachable + indirect → still Unreachable.
        let r = cascade_row("1.1.1.1", 0, "bob", 0, "-", -1);
        assert_eq!(
            Reachability::from_row(&r, "alice"),
            Reachability::Unreachable
        );
    }

    // ─── Reachability Display

    /// `DirectUdp` is multi-line. The `\n` is INSIDE the `{}`
    /// expansion. C `info.c:186` puts the `\n` in the format string
    /// itself.
    #[test]
    fn reachability_display_directup_multiline() {
        let r = Reachability::DirectUdp {
            pmtu: 1518,
            rtt_us: Some(1_234),
        };
        // 1234us → 1.234ms. The `%d.%03d`.
        assert_eq!(
            r.to_string(),
            "directly with UDP\nPMTU:         1518\nRTT:          1.234"
        );
        // No RTT.
        let r = Reachability::DirectUdp {
            pmtu: 1400,
            rtt_us: None,
        };
        assert_eq!(r.to_string(), "directly with UDP\nPMTU:         1400");
    }

    /// All single-line variants. Exact strings (the C's printf).
    #[test]
    fn reachability_display_single_line() {
        assert_eq!(Reachability::Myself.to_string(), "can reach itself");
        assert_eq!(Reachability::Unreachable.to_string(), "unreachable");
        assert_eq!(
            Reachability::Indirect { via: "bob".into() }.to_string(),
            "indirectly via bob"
        );
        assert_eq!(Reachability::Unknown.to_string(), "unknown");
        assert_eq!(Reachability::DirectTcp.to_string(), "directly with TCP");
        assert_eq!(
            Reachability::Forwarded {
                nexthop: "bob".into()
            }
            .to_string(),
            "none, forwarded via bob"
        );
    }

    /// `0` rtt: `udp_ping_rtt == 0` is NOT `-1`, so the RTT line
    /// prints. C `info.c:188`: `if(rtt != -1)` not `if(rtt > 0)`.
    /// 0us is a valid (loopback-fast) RTT.
    #[test]
    fn reachability_display_zero_rtt() {
        let r = Reachability::DirectUdp {
            pmtu: 1518,
            rtt_us: Some(0),
        };
        assert!(r.to_string().contains("RTT:          0.000"));
    }

    // ─── NodeInfo::format — the full golden

    /// Build a known NodeRow, assert byte-exact output. This is the
    /// `diff <(tinc-c info bob) <(tinc-rs info bob)` test, in unit
    /// form. The values are chosen to exercise every line.
    ///
    /// `last_state_change = 0` → `"never"`, dodging the TZ question.
    /// The TZ-dependent path is covered by the integration test
    /// (which runs the subprocess under `TZ=UTC`).
    ///
    /// `clippy::too_many_lines`: this is one golden vector. The
    /// width-count comments make it longer. Allowed.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn nodeinfo_format_golden() {
        // alice: reachable, validkey, sptps, udp. minmtu>0 → DirectUdp.
        // options = INDIRECT|PMTU = 0x0001|0x0004 = 0x0005, plus
        // version 7 in top byte = 0x07000005.
        let row = NodeRow {
            name: "alice".into(),
            id: "0a1b2c3d4e5f".into(),
            host: "10.0.0.1".into(),
            port: "655".into(),
            cipher: 0,
            digest: 0,
            maclength: 0,
            compression: 0,
            options: 0x0700_0005, // version 7, indirect+pmtu
            // validkey(1) | visited(3) | reachable(4) | sptps(6) |
            // udp_confirmed(7) = 0x02|0x08|0x10|0x40|0x80 = 0xda
            status: 0x00da,
            nexthop: "alice".into(),
            via: "alice".into(),
            distance: 1,
            pmtu: 1518,
            minmtu: 1400,
            maxmtu: 1518,
            last_state_change: 0, // → "never"
            udp_ping_rtt: 1500,   // → "RTT: 1.500"
            in_packets: 100,
            in_bytes: 50_000,
            out_packets: 200,
            out_bytes: 100_000,
        };
        let info = NodeInfo {
            row,
            edges_to: vec!["bob".into(), "carol".into()],
            subnets: vec!["10.0.0.0/24".into(), "192.168.0.0/16".into()],
        };

        let out = info.format("alice");

        // Byte-exact. The column widths (count the spaces) are the
        // C's. `Status:` and `Options:` and `Edges:`/`Subnets:` are
        // 13 chars (label + spaces); values have leading space.
        // Everything else is 14 chars; values don't.
        //
        // sed-verifiable against `info.c:108-243`.
        //
        // Precondition: status bits are what we said.
        assert_eq!(
            info.row.status,
            StatusBit::VALIDKEY.0
                | StatusBit::VISITED.0
                | StatusBit::REACHABLE.0
                | StatusBit::SPTPS.0
                | StatusBit::UDP_CONFIRMED.0,
            "status hex was hand-computed; this catches drift"
        );

        let expected = "\
Node:         alice
Node ID:      0a1b2c3d4e5f
Address:      10.0.0.1 port 655
Online since: never
Status:       validkey visited reachable sptps udp_confirmed
Options:      indirect pmtu_discovery
Protocol:     17.7
Reachability: directly with UDP
PMTU:         1518
RTT:          1.500
RX:           100 packets  50000 bytes
TX:           200 packets  100000 bytes
Edges:        bob carol
Subnets:      10.0.0.0/24 192.168.0.0/16
";
        assert_eq!(out, expected);
    }

    /// Unreachable: `Last seen:` not `Online since:`, no Status
    /// flags (status=0), `unreachable` reachability, empty edges/
    /// subnets.
    #[test]
    fn nodeinfo_format_unreachable() {
        let row = NodeRow {
            name: "carol".into(),
            id: "000000000000".into(),
            host: "unknown".into(),
            port: "unknown".into(),
            cipher: 0,
            digest: 0,
            maclength: 0,
            compression: 0,
            options: 0,
            status: 0,
            nexthop: "-".into(),
            via: "-".into(),
            distance: 99,
            pmtu: 0,
            minmtu: 0,
            maxmtu: 0,
            last_state_change: 0,
            udp_ping_rtt: -1,
            in_packets: 0,
            in_bytes: 0,
            out_packets: 0,
            out_bytes: 0,
        };
        let info = NodeInfo {
            row,
            edges_to: vec![],
            subnets: vec![],
        };

        let out = info.format("carol");

        // `Status:` line has just the label + newline (no flags).
        // The label is 13 chars (`"Status:      "`, 12+1 because
        // values would add their own space).
        // `Edges:`/`Subnets:` same.
        let expected = "\
Node:         carol
Node ID:      000000000000
Address:      unknown port unknown
Last seen:    never
Status:      \nOptions:     \nProtocol:     17.0
Reachability: unreachable
RX:           0 packets  0 bytes
TX:           0 packets  0 bytes
Edges:       \nSubnets:     \n";
        // The `\n` in the middle of the literal is intentional —
        // `Status:      ` (13 chars, trailing space) then immediately
        // newline (no flags). Hard to read in raw form; explicit
        // line splits would lose the trailing-space visibility.
        // assert_eq! diff makes it clear if wrong.
        assert_eq!(out, expected);
    }

    /// Status bits print in C order (which is `node.h` declaration
    /// order, NOT alphabetical, NOT bit-position-with-gaps).
    /// `info.c:129-152`.
    #[test]
    fn nodeinfo_status_order() {
        // ALL six bits set.
        let row = cascade_row(
            "MYSELF",
            StatusBit::VALIDKEY.0
                | StatusBit::VISITED.0
                | StatusBit::REACHABLE.0
                | StatusBit::INDIRECT.0
                | StatusBit::SPTPS.0
                | StatusBit::UDP_CONFIRMED.0,
            "x",
            0,
            "x",
            -1,
        );
        let info = NodeInfo {
            row,
            edges_to: vec![],
            subnets: vec![],
        };
        let out = info.format("x");
        // The order is the C's printf order. NOT alphabetical.
        // `info.c:129,133,137,141,145,149`.
        assert!(
            out.contains("Status:       validkey visited reachable indirect sptps udp_confirmed\n")
        );
    }

    /// Double-space between `packets` and bytes. C `info.c:197`:
    /// `"%"PRIu64" packets  %"PRIu64" bytes"` — two spaces. (`diff`
    /// against C would catch one space.)
    #[test]
    fn nodeinfo_traffic_double_space() {
        let row = cascade_row("MYSELF", StatusBit::REACHABLE.0, "x", 0, "x", -1);
        let mut info = NodeInfo {
            row,
            edges_to: vec![],
            subnets: vec![],
        };
        info.row.in_packets = 5;
        info.row.in_bytes = 1024;
        let out = info.format("x");
        // Exactly two spaces between "packets" and the bytes count.
        // Not one. Not three.
        assert!(out.contains("RX:           5 packets  1024 bytes\n"));
        assert!(!out.contains("packets 1024")); // not single-space
        assert!(!out.contains("packets   1024")); // not triple
    }

    // ─── StatusBit::REACHABLE etc — sed-verify against node.h

    /// The bit positions are GCC's LSB-first packing of `node.h:33-
    /// 46`. sed-transcribed; this test pins the assignment so a
    /// wrong copy is loud at test time, not at runtime.
    #[test]
    fn status_bits_match_node_h_order() {
        // `node.h:33-46`, in declaration order:
        //   bit 0: unused_active   (not used)
        //   bit 1: validkey
        //   bit 2: waitingforkey   (not printed)
        //   bit 3: visited
        //   bit 4: reachable
        //   bit 5: indirect
        //   bit 6: sptps
        //   bit 7: udp_confirmed
        //   bits 8-12: not printed by info
        assert_eq!(StatusBit::VALIDKEY.0, 1 << 1);
        assert_eq!(StatusBit::VISITED.0, 1 << 3);
        assert_eq!(StatusBit::REACHABLE.0, 1 << 4);
        assert_eq!(StatusBit::INDIRECT.0, 1 << 5);
        assert_eq!(StatusBit::SPTPS.0, 1 << 6);
        assert_eq!(StatusBit::UDP_CONFIRMED.0, 1 << 7);
    }

    /// `connection.h:32-35`: OPTION_* values. sed-verifiable.
    #[test]
    fn option_bits_match_connection_h() {
        assert_eq!(OPTION_INDIRECT, 0x0001);
        assert_eq!(OPTION_TCPONLY, 0x0002);
        assert_eq!(OPTION_PMTU_DISCOVERY, 0x0004);
        assert_eq!(OPTION_CLAMP_MSS, 0x0008);
    }
}
