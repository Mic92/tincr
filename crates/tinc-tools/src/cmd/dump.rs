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
//! identical output. Row schemas (`NodeRow` etc.) live in
//! [`ctl::rows`](crate::ctl::rows); this module is just dispatch +
//! output formatting.
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

use std::fs;
use std::io::{BufRead, BufReader};

use crate::cmd::{CmdError, io_err};
use crate::ctl::{CtlRequest, CtlSocket, DumpRow};
use crate::names::{Paths, check_id};

// Row schemas are wire-level, shared with `info`/`top`/`tinc-auth`.
// Re-exported so the existing `cmd::dump::{NodeRow,…}` paths and
// `dump/tests.rs` (`use super::*`) keep working.
pub use crate::ctl::rows::{ConnRow, EdgeRow, NodeRow, StatusBit, SubnetRow, strip_weight};

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

/// Argv keyword → `Kind`, for `parse_kind`'s case-insensitive lookup.
const KINDS: &[(&str, Kind)] = &[
    ("nodes", Kind::Nodes),
    ("edges", Kind::Edges),
    ("subnets", Kind::Subnets),
    ("connections", Kind::Connections),
    ("graph", Kind::Graph),
    ("digraph", Kind::Digraph),
    ("invitations", Kind::Invitations),
];

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
    let (only_reachable, args) = match args {
        [first, rest @ ..] if first.eq_ignore_ascii_case("reachable") => {
            let Some(second) = rest.first() else {
                // `dump reachable` alone: upstream falls through to
                // "Invalid number of arguments." without shifting.
                return Err(CmdError::BadInput("Invalid number of arguments.".into()));
            };
            if !second.eq_ignore_ascii_case("nodes") {
                return Err(CmdError::BadInput(
                    "`reachable' only supported for nodes.".into(),
                ));
            }
            (true, rest)
        }
        _ => (false, args),
    };

    let [what] = args else {
        return Err(CmdError::BadInput("Invalid number of arguments.".into()));
    };

    // ─── Dispatch
    // `only_reachable` was already validated to be nodes-only above,
    // so it can only pair with `what == "nodes"`; the post-lookup
    // remap covers that one case.
    let kind = KINDS
        .iter()
        .find(|(n, _)| what.eq_ignore_ascii_case(n))
        .map(|&(_, k)| k)
        .ok_or_else(|| CmdError::BadInput(format!("Unknown dump type '{what}'.")))?;

    Ok(if only_reachable {
        Kind::ReachableNodes
    } else {
        kind
    })
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
        // combination from the right. We do the same set, then route
        // through the canonical `split_kv` so a hand-edited
        // `Name=bob` invitation lists the same as `tinc get Name`
        // would read it (P4: one tokenizer for one file format).
        let first = first.trim_end_matches(['\t', ' ', '\r', '\n']);
        let (key, invitee) = tinc_conf::split_kv(first);
        if key != "Name" || !check_id(invitee) {
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

/// Run one of the daemon-backed dumps; returns lines ready for
/// stdout (the binary prints each + `\n`). An empty vec is silence
/// — exit 0, no output.
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
pub fn dump(paths: &Paths, kind: Kind) -> Result<Vec<String>, CmdError> {
    debug_assert!(kind.needs_daemon(), "use dump_invitations()");

    let mut ctl = CtlSocket::connect(paths)?;

    // ─── Send: 1 or 2 requests (graph/digraph send NODES then EDGES)
    match kind {
        Kind::Nodes | Kind::ReachableNodes => {
            ctl.send(CtlRequest::DumpNodes)?;
        }
        Kind::Edges => {
            ctl.send(CtlRequest::DumpEdges)?;
        }
        Kind::Subnets => {
            ctl.send(CtlRequest::DumpSubnets)?;
        }
        Kind::Connections => {
            ctl.send(CtlRequest::DumpConnections)?;
        }
        Kind::Graph | Kind::Digraph => {
            // Two sends; TCP buffers the second while the daemon is
            // still streaming the first response.
            ctl.send(CtlRequest::DumpNodes)?;
            ctl.send(CtlRequest::DumpEdges)?;
        }
        Kind::Invitations => unreachable!("debug_assert above"),
    }

    // ─── Receive loop. Graph mode skips the NODES terminator and
    // exits on the EDGES one; everything else exits on the first.
    let mut lines = Vec::new();

    match kind {
        Kind::Graph => lines.push("graph {".to_owned()),
        Kind::Digraph => lines.push("digraph {".to_owned()),
        _ => {}
    }

    let directed = matches!(kind, Kind::Digraph);

    loop {
        match ctl.recv_row()? {
            DumpRow::End(end_kind) => {
                if matches!(
                    (kind, end_kind),
                    (Kind::Graph | Kind::Digraph, CtlRequest::DumpNodes)
                ) {
                    // Graph mode, first terminator: edges still to come.
                } else {
                    break;
                }
            }

            // Dispatch on the kind-from-row (graph mode interleaves
            // `18 3 ...` then `18 4 ...`).
            DumpRow::Row(CtlRequest::DumpNodes, body) => {
                let row = NodeRow::parse(&body).map_err(|_| {
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
                    // Tighten over upstream: NODES when we asked for
                    // something else is a protocol violation.
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

    Ok(lines)
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
