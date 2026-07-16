//! `cmd_top` — real-time per-node traffic stats.
//!
//! ```text
//!   tinc top                   → real-time per-node traffic stats
//! ```
//!
//! Loop: send `DUMP_TRAFFIC` → recv N rows + terminator → compute
//! per-second rates from delta over previous tick → render → sleep
//! `delay_ms` waiting for a keypress → repeat. The daemon's
//! `dump_traffic` is the simplest dump format: name + 4 u64
//! counters, no `" port "` wrinkle.
//!
//! ## Three layers, two testable
//!
//! | Layer | Touches tty? | Tests |
//! |---|---|---|
//! | `TrafficRow::parse` | no | golden vs daemon's printf |
//! | `Stats::update` (the merge + rate compute) | no | feed two dumps with known dt, assert rates |
//! | `compare` (the 7-way comparator) | no | table-driven |
//! | `render_*` (Row → ANSI String) | no | golden, assert with codes inline |
//! | `run` (the loop) | yes | manual smoke against daemon |
//!
//! `tui.rs` is consumed only by `run`. Everything above it is plain
//! data flow.
//!
//! ## Sort stability
//!
//! `slice::sort_by` is stable, so equal-key entries keep their
//! previous-frame positions as long as `Stats::display_order` is sorted
//! in place (append-only on new nodes; rebuilding from the `BTreeMap`
//! would name-sort and undo that).
//!
//! ## Daemon restart shows a one-tick spike
//!
//! Rates are `current.wrapping_sub(previous) / interval`. When the daemon
//! restarts and its counters reset, the wrap produces a huge spike for one
//! tick, then self-corrects. Intentional: the spike IS the restart signal;
//! saturating would hide it (and matches what C tinc shows).
//!
//! ## First-tick rates are ~zero
//!
//! With no previous tick the interval is taken as seconds-since-epoch, so
//! rates come out near zero (matching C tinc). Tested as
//! `first_tick_rate_is_near_zero`.
//!
//! ## Row clipping is explicit
//!
//! Unlike curses, ANSI `goto` past the last row scrolls or dumps
//! off-screen depending on the emulator, so rendering takes `max_rows`
//! and clips explicitly.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::cmd::CmdError;
use crate::ctl::{CtlError, CtlRequest, CtlSocket};
use crate::names::Paths;
use crate::tui;

// `TrafficRow` lives in `ctl::rows` alongside the other dump-row schemas;
// re-exported for `top/tests.rs`.
pub use crate::ctl::rows::TrafficRow;

/// Per-node accumulator. The name is the `BTreeMap` key, not stored here.
///
/// Rates are `f32` to match C tinc's `float`: rounding of borderline
/// values in the 10.0f columns can differ between f32 and f64.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct NodeStats {
    /// Cumulative counters (the values from the daemon, verbatim).
    pub in_packets: u64,
    pub in_bytes: u64,
    pub out_packets: u64,
    pub out_bytes: u64,

    /// Per-second rates (delta over `interval`). Only valid AFTER
    /// `Stats::update`; the `Default` impl gives 0.0.
    pub in_packets_rate: f32,
    pub in_bytes_rate: f32,
    pub out_packets_rate: f32,
    pub out_bytes_rate: f32,

    /// Set true when this tick's dump mentioned the node. False
    /// means "node disappeared from daemon's view between ticks"
    /// → DIM display. Cleared at the start of every update; set
    /// true when found in the dump.
    pub known: bool,
}

/// The whole state of the top loop, except the bits that don't change
/// between ticks (`netname` is an argument to `render_header`).
#[derive(Debug)]
pub struct Stats {
    /// Never shrinks. A node that disappears stays here with `known=false`
    /// → dim display. Only cleared by restarting `tinc top`.
    pub nodes: BTreeMap<String, NodeStats>,

    /// Current display order, sorted in-place each frame by `compare()`.
    /// Append-only: new nodes are pushed, none removed. Sorting the same
    /// Vec keeps equal-key entries in their previous-frame positions
    /// (stable sort); rebuilding from `nodes.keys()` would name-sort them.
    pub display_order: Vec<String>,

    /// None on tick 1.
    prev_instant: Option<Instant>,

    /// Starts as `(Name, false)`.
    pub sort_mode: SortMode,
    pub cumulative: bool,

    /// Milliseconds. Starts at 1000.
    pub delay_ms: u16,

    /// `(unit-suffix, scale)` pairs. The four `b`/`k`/`M`/`G` keys
    /// flip these. Starts at `("bytes", 1.0, "pkts", 1.0)`.
    pub bunit: &'static str,
    pub bscale: f32,
    pub punit: &'static str,
    pub pscale: f32,
}

impl Default for Stats {
    /// Defaults match C tinc so the first frame looks identical.
    fn default() -> Self {
        Self {
            nodes: BTreeMap::new(),
            display_order: Vec::new(),
            prev_instant: None,
            sort_mode: SortMode::Name,
            cumulative: false,
            delay_ms: 1000,
            bunit: "bytes",
            bscale: 1.0,
            punit: "pkts",
            pscale: 1.0,
        }
    }
}

/// The seven sort keys. `repr(u8)` so `SORTNAME[self as usize]` works.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SortMode {
    /// `'n'` key. Ascending strcmp.
    Name = 0,
    /// `'I'` key. Uppercase → packets.
    InPackets = 1,
    /// `'i'` key. Lowercase → bytes (heavier).
    InBytes = 2,
    /// `'O'` key.
    OutPackets = 3,
    /// `'o'` key.
    OutBytes = 4,
    /// `'T'` key.
    TotalPackets = 5,
    /// `'t'` key.
    TotalBytes = 6,
}

/// Index by `SortMode as usize`. The header row shows this.
const SORTNAME: [&str; 7] = [
    "name",      // 0
    "in pkts",   // 1
    "in bytes",  // 2
    "out pkts",  // 3
    "out bytes", // 4
    "tot pkts",  // 5
    "tot bytes", // 6
];

impl Stats {
    /// One tick: merge a fetched dump into the accumulators and compute
    /// rates. The I/O half lives in `fetch()` so this is testable without
    /// a socket.
    ///
    /// `now` is a parameter so tests can feed deterministic instants.
    ///
    /// Returns true if a new node appeared.
    #[expect(clippy::cast_precision_loss)] // u64→f32: 1s deltas ≪ 2^24; cumulative is display-only
    pub fn update(&mut self, rows: &[TrafficRow], now: Instant) -> bool {
        use std::collections::btree_map::Entry;

        // First tick: prev=None → interval ≈ epoch seconds → rate ≈ 0
        // (see module doc).
        let interval: f32 = match self.prev_instant {
            Some(prev) => now.duration_since(prev).as_secs_f32(),
            None => {
                // Fallible if clock is pre-1970; unwrap_or(huge) is
                // the same outcome — huge interval, zero rate.
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or(Duration::from_secs(1_700_000_000))
                    .as_secs_f32()
            }
        };
        self.prev_instant = Some(now);

        // Nodes present in this dump get re-marked below; the rest stay
        // false → DIM.
        for s in self.nodes.values_mut() {
            s.known = false;
        }

        let mut changed = false;

        for row in rows {
            let entry = self.nodes.entry(row.name.clone());

            // Match on entry (not `or_insert_with`) so we can record
            // "newly inserted" for `display_order`/`changed`.
            let s = match entry {
                Entry::Vacant(v) => {
                    self.display_order.push(row.name.clone());
                    changed = true;
                    v.insert(NodeStats::default())
                }
                Entry::Occupied(o) => o.into_mut(),
            };

            s.known = true;

            // wrapping_sub: daemon restart shows as a one-tick spike
            // (see module doc).
            let rate = |new: u64, old: u64| new.wrapping_sub(old) as f32 / interval;
            s.in_packets_rate = rate(row.in_packets, s.in_packets);
            s.in_bytes_rate = rate(row.in_bytes, s.in_bytes);
            s.out_packets_rate = rate(row.out_packets, s.out_packets);
            s.out_bytes_rate = rate(row.out_bytes, s.out_bytes);

            // Store for next tick's delta.
            s.in_packets = row.in_packets;
            s.in_bytes = row.in_bytes;
            s.out_packets = row.out_packets;
            s.out_bytes = row.out_bytes;
        }

        changed
    }

    /// In-place stable sort of `display_order` by the current `sort_mode`
    /// + `cumulative`.
    pub fn sort(&mut self) {
        // Name handled here, not in `compare()`: the name is the map
        // key and isn't stored in `NodeStats`.
        if self.sort_mode == SortMode::Name {
            self.display_order.sort();
            return;
        }

        let mode = self.sort_mode;
        let cumulative = self.cumulative;
        // Split the borrow so the closure captures `nodes`, not `self`.
        let nodes = &self.nodes;
        self.display_order.sort_by(|a, b| {
            // Infallible (display_order ⊆ nodes' keys); zeroed
            // fallback sorts last and never fires.
            let na = nodes.get(a).cloned().unwrap_or_default();
            let nb = nodes.get(b).cloned().unwrap_or_default();
            compare(&na, &nb, mode, cumulative)
        });
    }
}

/// The 7-way comparator. Traffic modes sort descending (heavier traffic
/// on top); name mode sorts ascending. `cumulative` flips between rate
/// and counter.
///
/// `partial_cmp` is `None` only for NaN, which can't occur: rates are
/// `delta / interval` with interval always > 0. `unwrap_or(Equal)` covers
/// the unreachable case.
fn compare(a: &NodeStats, b: &NodeStats, mode: SortMode, cumulative: bool) -> std::cmp::Ordering {
    // Descending (heavier first): compare b's key against a's. The
    // u64→f64 cast loses precision past 2^53 but counters that large
    // (9 PB / 9 quadrillion packets) don't happen in practice and the
    // ordering would still be correct to within rounding.
    sort_key(b, mode, cumulative)
        .partial_cmp(&sort_key(a, mode, cumulative))
        .unwrap_or(std::cmp::Ordering::Equal)
}

/// Project a `NodeStats` onto the scalar the current sort mode cares
/// about. `Name` returns 0 — `Stats::sort` handles that mode by sorting
/// keys directly, so the arm only keeps the match exhaustive.
#[expect(clippy::cast_precision_loss)] // see compare()
fn sort_key(s: &NodeStats, mode: SortMode, cumulative: bool) -> f64 {
    use SortMode::{InBytes, InPackets, Name, OutBytes, OutPackets, TotalBytes, TotalPackets};
    let pick = |cum: u64, rate: f32| {
        if cumulative {
            cum as f64
        } else {
            f64::from(rate)
        }
    };
    match mode {
        Name => 0.0,
        InPackets => pick(s.in_packets, s.in_packets_rate),
        InBytes => pick(s.in_bytes, s.in_bytes_rate),
        OutPackets => pick(s.out_packets, s.out_packets_rate),
        OutBytes => pick(s.out_bytes, s.out_bytes_rate),
        TotalPackets => {
            pick(s.in_packets, s.in_packets_rate) + pick(s.out_packets, s.out_packets_rate)
        }
        TotalBytes => pick(s.in_bytes, s.in_bytes_rate) + pick(s.out_bytes, s.out_bytes_rate),
    }
}

// Rendering builds plain Strings with ANSI codes inline; three testable
// pieces (render_header, render_row, render). Row 1 is intentionally blank:
// the cursor parks there and the 's' key prompt overwrites it.

/// Rows 0-2: status line, blank row, reversed column headers.
///
/// The header bar is REVERSE + text + CLEAR_EOL + RESET: erasing while
/// still in reverse fills the rest of the line with the reversed
/// background (xterm/vte "background color erase"), giving the filled-bar
/// look.
///
/// Returns one String with embedded `goto`; caller writes it in one
/// syscall so there is no flicker between rows.
fn render_header(netname: Option<&str>, stats: &Stats) -> String {
    use std::fmt::Write as _;

    let netname = netname.unwrap_or("");
    let count = stats.nodes.len();
    let sortname = SORTNAME[stats.sort_mode as usize];
    let mode = if stats.cumulative {
        "Cumulative"
    } else {
        "Current"
    };

    let mut s = String::with_capacity(256);

    // Row 0: status line. Per-line CLEAR_EOL instead of a full-screen
    // erase — less flicker without a double buffer.
    write!(
        s,
        "{}Tinc {netname:<16}  Nodes: {count:>4}  Sort: {sortname:<10}  {mode}{}",
        tui::goto(0, 0),
        tui::CLEAR_EOL,
    )
    .unwrap(); // String Write is infallible

    // Row 1: blank; cleared so stale 's'-prompt leftovers don't show.
    write!(s, "{}{}", tui::goto(1, 0), tui::CLEAR_EOL).unwrap();

    // Row 2: column headers in REVERSE; CLEAR_EOL before RESET fills the
    // rest of the line with the reversed background. The header spacing is
    // hand-tuned to align with the {:<16} {:>10.0} body columns.
    let punit = stats.punit;
    let bunit = stats.bunit;
    write!(
        s,
        "{goto}{rev}Node                IN {punit}   IN {bunit}   OUT {punit}  OUT {bunit}{clr}{rst}",
        goto = tui::goto(2, 0),
        rev = tui::REVERSE,
        clr = tui::CLEAR_EOL,
        rst = tui::RESET,
    )
    .unwrap();

    s
}

/// One body row: attribute prefix + name + four right-aligned columns.
///
/// Attribute logic:
///
/// | known | nonzero rate | attribute |
/// |---|---|---|
/// | true | true | BOLD (active traffic) |
/// | true | false | NORMAL (idle but present) |
/// | false | — | DIM (gone) |
///
/// "Nonzero rate" checks the packet rates (not bytes, not cumulative
/// counters) because that's what changes when anything is happening.
///
/// `cumulative` flips the four numbers between counter and rate; both are
/// scaled by `bscale`/`pscale` (the b/k/M/G keys). The u64→f32 cast in
/// the cumulative path loses precision past 2^24, display-only.
#[expect(clippy::cast_precision_loss)] // Display-only.
fn render_row(name: &str, s: &NodeStats, stats: &Stats, row: u16) -> String {
    let attr = if !s.known {
        tui::DIM
    } else if s.in_packets_rate != 0.0 || s.out_packets_rate != 0.0 {
        tui::BOLD
    } else {
        "" // NORMAL: RESET at end-of-row already clears SGR
    };

    let (p1, b1, p2, b2): (f32, f32, f32, f32) = if stats.cumulative {
        (
            s.in_packets as f32 * stats.pscale,
            s.in_bytes as f32 * stats.bscale,
            s.out_packets as f32 * stats.pscale,
            s.out_bytes as f32 * stats.bscale,
        )
    } else {
        (
            s.in_packets_rate * stats.pscale,
            s.in_bytes_rate * stats.bscale,
            s.out_packets_rate * stats.pscale,
            s.out_bytes_rate * stats.bscale,
        )
    };

    // CLEAR_EOL after body erases leftover chars from a longer
    // previous-frame row.
    format!(
        "{goto}{attr}{name:<16} {p1:>10.0} {b1:>10.0} {p2:>10.0} {b2:>10.0}{clr}{rst}",
        goto = tui::goto(row, 0),
        clr = tui::CLEAR_EOL,
        rst = tui::RESET,
    )
}

/// Full screen, one frame, as one String — caller writes it in one
/// syscall. Rows past `max_rows` are clipped explicitly.
///
/// Called after `Stats::sort()` — `display_order` is in render order.
/// `max_rows` is passed in (not queried) so tests can assert the clip.
fn render(netname: Option<&str>, stats: &Stats, max_rows: u16) -> String {
    let mut s = String::with_capacity(4096);

    s.push_str(&render_header(netname, stats));

    // Body: rows 3..
    for (i, name) in stats.display_order.iter().enumerate() {
        let Ok(row) = u16::try_from(3 + i) else { break };
        if row >= max_rows {
            break;
        }

        // Infallible (display_order ⊆ nodes' keys); zeroed fallback
        // renders DIM if the invariant ever broke.
        let entry = stats.nodes.get(name).cloned().unwrap_or_default();
        s.push_str(&render_row(name, &entry, stats, row));
    }

    // No need to clear rows past the body: `display_order` is
    // append-only, so body row count is monotone-increasing.

    s
}

/// Send + recv one traffic dump. The merge lives in `Stats::update` so it
/// stays testable without a socket.
///
/// # Errors
/// `CtlError::Io` if the socket dies mid-dump (daemon crashed).
/// `CtlError::Parse` if a row is malformed. Both end the `top` loop.
fn fetch<S: io::Read + io::Write>(ctl: &mut CtlSocket<S>) -> Result<Vec<TrafficRow>, CtlError> {
    ctl.send(CtlRequest::DumpTraffic)?;

    let mut rows = Vec::with_capacity(32);
    ctl.for_each_row(|_, body| {
        // Parse failure ends the whole top session — the daemon is sending
        // garbage. CtlError has no Parse variant; Io is the closest bucket.
        let row = TrafficRow::parse(body).map_err(|_| {
            CtlError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("malformed traffic row from daemon: {body}"),
            ))
        })?;
        rows.push(row);
        Ok(())
    })?;
    Ok(rows)
}

/// Mutates `stats` per the key. Returns `false` for `'q'`.
///
/// The `'s'` key prompts for a new delay via `RawMode::with_cooked`.
/// Returns `Err` if the cooked-mode tcsetattr fails; caller breaks the
/// loop and Drop restores the terminal.
///
/// `out` is where the prompt gets written: stdout in real use, `Vec<u8>`
/// in tests.
fn handle_key(
    key: u8,
    stats: &mut Stats,
    raw: &tui::RawMode,
    out: &mut impl Write,
) -> io::Result<bool> {
    match key {
        // 's': change delay — the one interactive key. Prompt on row 1,
        // read a line in cooked mode, parse f32, clamp. Parse failure
        // means "no change".
        b's' => {
            let current_secs = f32::from(stats.delay_ms) * 1e-3;

            // Row 1 is the parked-cursor row; with_cooked re-shows the cursor.
            write!(
                out,
                "{}Change delay from {:.1}s to: {}",
                tui::goto(1, 0),
                current_secs,
                tui::CLEAR_EOL,
            )?;
            out.flush()?;

            // Parse failure (empty, garbage) → None → keep current delay.
            let new_secs: Option<f32> = raw.with_cooked(|stdin| {
                let mut line = String::new();
                stdin.read_line(&mut line)?;
                Ok(line.trim().parse::<f32>().ok())
            })?;

            // Clamp before storing. "inf" parses; the `as u16` cast
            // saturates to 65535 (~65s tick), harmless.
            if let Some(input) = new_secs {
                let clamped = if input < 0.1 { 0.1 } else { input };
                #[expect(clippy::cast_possible_truncation)] // Saturating; clamped >= 0.1
                #[expect(clippy::cast_sign_loss)] // so it's positive anyway.
                {
                    stats.delay_ms = (clamped * 1e3) as u16;
                }
            }
            // getch_timeout(stats.delay_ms) reads delay_ms fresh each tick.

            Ok(true)
        }

        // 'c': toggle cumulative
        b'c' => {
            stats.cumulative = !stats.cumulative;
            Ok(true)
        }

        // 'q': quit
        b'q' => Ok(false),

        // Unknown keys are ignored, including arrow-key escape sequences
        // (their bytes arrive as separate ignored ticks).
        _ => {
            // Sort mode keys (lowercase → bytes; uppercase → packets)
            if let Some(&(_, m)) = SORT_KEYS.iter().find(|(k, _)| *k == key) {
                stats.sort_mode = m;
            // Unit/scale keys: b/k keep packets at 1×; only M/G scale
            // packets too.
            } else if let Some(&(_, bu, bs, pu, ps)) = UNIT_KEYS.iter().find(|(k, ..)| *k == key) {
                stats.bunit = bu;
                stats.bscale = bs;
                stats.punit = pu;
                stats.pscale = ps;
            }
            Ok(true)
        }
    }
}

/// Key → sort mode. Kept as a flat table so adding a mode is one row.
const SORT_KEYS: &[(u8, SortMode)] = &[
    (b'n', SortMode::Name),
    (b'i', SortMode::InBytes),
    (b'I', SortMode::InPackets),
    (b'o', SortMode::OutBytes),
    (b'O', SortMode::OutPackets),
    (b't', SortMode::TotalBytes),
    (b'T', SortMode::TotalPackets),
];

/// Key → (byte unit, byte scale, packet unit, packet scale). Header
/// strings are 4-5 chars; widths fit `%s` without overflowing.
const UNIT_KEYS: &[(u8, &str, f32, &str, f32)] = &[
    (b'b', "bytes", 1.0, "pkts", 1.0),
    (b'k', "kbyte", 1e-3, "pkts", 1.0),
    (b'M', "Mbyte", 1e-6, "kpkt", 1e-3),
    (b'G', "Gbyte", 1e-9, "Mpkt", 1e-6),
];

/// The top loop: connect, enter raw mode, loop, exit cleanly.
///
/// # Errors
/// `CmdError::BadInput` if the daemon's not running (connect
/// fails) or sends garbage (parse failure). `RawMode::enter`
/// failure (stdin not a tty, e.g. `tinc top < /dev/null`) also
/// becomes `BadInput` — there's no good way to run top without
/// a terminal, so it's a usage error.
#[cfg(unix)]
pub fn run(paths: &Paths, netname: Option<&str>) -> Result<(), CmdError> {
    // Connect before entering raw mode so a connect failure prints its
    // error to a sane terminal.
    let mut ctl = CtlSocket::connect(paths)?;

    // RawMode's Drop restores the terminal, including on panic.
    let raw = tui::RawMode::enter()
        .map_err(|e| CmdError::BadInput(format!("cannot enter raw mode: {e}")))?;

    let mut stats = Stats::default();
    let mut stdout = io::stdout().lock();

    // Daemon dying mid-dump ends the loop silently: the daemon went away,
    // the user gets their prompt back. `fetch` blocks with no timeout;
    // the daemon's traffic dump is fast in practice.
    while let Ok(rows) = fetch(&mut ctl) {
        stats.update(&rows, Instant::now());

        // winsize() each frame so terminal resize is picked up (one-tick
        // lag; SIGWINCH is not caught).
        stats.sort();
        let frame = render(netname, &stats, tui::winsize().rows);
        // One syscall per frame, no flicker. Write errors ignored: a
        // closed stdout eventually surfaces via getch_timeout.
        let _ = stdout.write_all(frame.as_bytes());
        let _ = stdout.flush();

        // getch_timeout returns None on timeout. Poll/read errors (other
        // than EINTR) shouldn't happen on a validated tty; break rather
        // than spin.
        match tui::getch_timeout(stats.delay_ms) {
            Ok(None) => {} // timeout, next tick
            Ok(Some(key)) => {
                // false means 'q'. `?` propagates with_cooked's tcsetattr
                // failure; Drop restores the terminal.
                if !handle_key(key, &mut stats, &raw, &mut stdout)
                    .map_err(|e| CmdError::BadInput(format!("terminal I/O: {e}")))?
                {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    // Explicit drop documents that the terminal is restored before
    // returning.
    drop(raw);
    drop(stdout);

    Ok(())
}

// Tests cover parse, Stats::update with synthetic ticks, the comparator,
// golden ANSI rendering, and the non-interactive keys. `run` and the 's'
// key need a real terminal and are covered by the integration test /
// manual smoke only.

#[cfg(test)]
mod tests;
