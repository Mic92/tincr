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
//! The row format is pinned by the daemon's `dump_*` functions and by
//! scripts that parse `tinc dump ... | awk`; output must stay identical
//! to C tinc. Row schemas (`NodeRow` etc.) live in
//! [`ctl::rows`](crate::ctl::rows); this module is dispatch + formatting.
//!
//! Stricter than C tinc: `recv_row` validates the reply code per row,
//! and `dump invitations` requires filenames to be exactly 24 base64
//! chars (the daemon's invite lookup is exact-24 anyway).

use std::fs;
use std::io::{BufRead, BufReader};

use crate::cmd::{CmdError, io_err};
use crate::ctl::{CtlRequest, CtlSocket, DumpRow};
use crate::names::{Paths, check_id};

// Row schemas are wire-level, shared with `info`/`top`/`tinc-auth`.
// Re-exported so existing `cmd::dump::{NodeRow,…}` paths keep working.
pub use crate::ctl::rows::{ConnRow, EdgeRow, NodeRow, StatusBit, SubnetRow, strip_weight};

/// Which `dump` sub-verb.
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
    /// `dump invitations` — no daemon; reads the invitations directory.
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
    /// Does this sub-verb need to talk to the daemon? The binary checks
    /// this before `connect()`, so `dump invitations` works with the
    /// daemon down.
    #[must_use]
    pub const fn needs_daemon(self) -> bool {
        !matches!(self, Kind::Invitations)
    }
}

/// Parse `argv` → `Kind`. All matches are case-insensitive.
///
/// # Errors
/// `BadInput` for `reachable` without `nodes`, wrong arg count, or an
/// unknown dump type.
pub fn parse_kind(args: &[String]) -> Result<Kind, CmdError> {
    // `reachable` prefix is only valid before `nodes`.
    let (only_reachable, args) = match args {
        [first, rest @ ..] if first.eq_ignore_ascii_case("reachable") => {
            let Some(second) = rest.first() else {
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

    // `only_reachable` was already validated to be nodes-only above,
    // so the post-lookup remap covers that one case.
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

/// One outstanding invitation. Collected so the binary can decide
/// stdout/stderr.
#[derive(Debug, Clone)]
pub struct InviteRow {
    /// The 24-char b64 cookie-hash (the filename).
    pub cookie_hash: String,
    /// The invitee name from the file's first line `Name = X`.
    pub invitee: String,
}

/// Walks `confbase/invitations/`, finds 24-char-b64-named files, reads
/// `Name = ` from line 1, collects.
///
/// Per-file problems (unreadable, empty, first line not `Name = VALID_ID`)
/// are silently skipped: lib code doesn't print to stderr, and "show
/// what's valid" is the most useful behavior.
///
/// # Errors
/// `Io` if the directory exists but readdir fails. ENOENT is not an
/// error — exit 0 with empty Vec.
pub fn dump_invitations(paths: &Paths) -> Result<Vec<InviteRow>, CmdError> {
    use tinc_crypto::invite::SLUG_PART_LEN;

    let dir = paths.invitations_dir();

    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Directory never created → no invites → not an error.
            return Ok(Vec::new());
        }
        Err(e) => return Err(io_err(dir)(e)),
    };

    let mut out = Vec::new();

    for entry in entries {
        // Per-entry readdir errors (rare, e.g. NFS) are skip, not fail.
        let Ok(entry) = entry else { continue };
        let name_os = entry.file_name();

        // Filter to exactly 24 base64 chars. The daemon's invite lookup is
        // exact-24; anything else is not an invitation cookie.
        // OsStr::len() is bytes (Unix); non-ASCII bytes fail decode below.
        if name_os.len() != SLUG_PART_LEN {
            continue;
        }
        // Non-UTF-8 can't be valid base64.
        let Some(name) = name_os.to_str() else {
            continue;
        };
        // Decode is only used as a validator; the bytes are unused.
        let Some(decoded) = tinc_crypto::b64::decode(name) else {
            continue;
        };
        // 24 b64 chars always decode to 18 bytes; assert to catch a future
        // b64 change.
        debug_assert_eq!(decoded.len(), 18);

        // Read only the first line — the file body (host config blob)
        // may be long.
        let path = entry.path();
        let Ok(file) = fs::File::open(&path) else {
            continue;
        };
        let mut first = String::new();
        if BufReader::new(file).read_line(&mut first).is_err() || first.is_empty() {
            continue;
        }

        // Route through the canonical split_kv so a hand-edited `Name=bob`
        // invitation lists the same as `tinc get Name` would read it.
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

/// Run one of the daemon-backed dumps; returns lines ready for stdout.
/// An empty vec means no output, exit 0.
///
/// `paths` must be `resolve_runtime()`d (the binary's `needs_daemon`
/// gate handles this).
///
/// One function, one recv loop: graph mode interleaves node and edge rows,
/// so the loop body dispatches on the row's kind rather than per-kind
/// helpers.
///
/// # Errors
/// Connect failure, recv failure (daemon crashed mid-dump), or row parse
/// failure (format drift between client and daemon).
#[cfg(unix)]
pub fn dump(paths: &Paths, kind: Kind) -> Result<Vec<String>, CmdError> {
    debug_assert!(kind.needs_daemon(), "use dump_invitations()");

    let mut ctl = CtlSocket::connect(paths)?;

    // Graph/digraph send NODES then EDGES; everything else sends one request.
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

    // Receive loop. Graph mode skips the NODES terminator and exits on
    // the EDGES one; everything else exits on the first.
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
                    // A node row when we asked for something else is a
                    // protocol violation.
                    _ => {
                        return Err(CmdError::BadInput("Unexpected node row".into()));
                    }
                }
            }

            DumpRow::Row(CtlRequest::DumpEdges, body) => {
                let row = EdgeRow::parse(&body).map_err(|_| {
                    CmdError::BadInput(format!("Unable to parse edge dump from tincd: {body}"))
                })?;

                match kind {
                    Kind::Edges => lines.push(row.fmt_plain()),
                    Kind::Graph | Kind::Digraph => {
                        // fmt_dot returns None for the suppressed half
                        // (undirected dedup).
                        if let Some(line) = row.fmt_dot(directed) {
                            lines.push(line);
                        }
                    }
                    _ => {
                        return Err(CmdError::BadInput("Unexpected edge row".into()));
                    }
                }
            }

            DumpRow::Row(CtlRequest::DumpSubnets, body) => {
                let row = SubnetRow::parse(&body).map_err(|_| {
                    CmdError::BadInput("Unable to parse subnet dump from tincd.".into())
                })?;
                lines.push(row.fmt_plain());
            }

            DumpRow::Row(CtlRequest::DumpConnections, body) => {
                let row = ConnRow::parse(&body).map_err(|_| {
                    CmdError::BadInput("Unable to parse connection dump from tincd.".into())
                })?;
                lines.push(row.fmt_plain());
            }

            // Unknown row type: daemon bug or version skew.
            DumpRow::Row(_, _) => {
                return Err(CmdError::BadInput(
                    "Unable to parse dump from tincd.".into(),
                ));
            }
        }
    }

    match kind {
        Kind::Graph | Kind::Digraph => lines.push("}".to_owned()),
        _ => {}
    }

    Ok(lines)
}

// Tests use golden wire vectors (what `nc -U` on the control socket would
// show) and pin the fmt_plain output, which is a script-compatibility
// surface: changing it breaks `tinc dump nodes | awk` scripts.

#[cfg(test)]
mod tests;
