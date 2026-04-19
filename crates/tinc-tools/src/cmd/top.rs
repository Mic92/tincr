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
//! `tui.rs` is consumed ONLY by `run`. Everything above it is plain
//! data flow.
//!
//! ## Upstream's stable-sort emulation, NOT ported
//!
//! Upstream sets `sorted[i]->i = i` before `qsort`, then `sortfunc`
//! falls back to `na->i - nb->i` on ties. It's a stable-sort
//! emulation for non-stable `qsort`. Rust's `slice::sort_by` IS
//! stable, so we just sort `Stats::display_order` in place each
//! frame (append-only on new nodes; not rebuilt from `BTreeMap` which
//! would name-sort and undo prior stability).
//!
//! ## Daemon restart wraps to 18 quintillion, ported faithfully
//!
//! Rate computation is `current - previous`, both `uint64_t`.
//! Daemon restarts → counters reset → `0 - huge` wraps. Self-
//! corrects next tick. We use `wrapping_sub` to match: a saturating
//! delta would hide the daemon-restart event; the spike IS the
//! signal.
//!
//! ## First-tick rates are nonsense, ported faithfully
//!
//! Upstream's `static struct timeval prev` is zero-initialized, so
//! tick-1 interval ≈ epoch seconds ≈ 1.7 billion, and rate ≈ 0.
//! `Stats::prev_instant` is `Option<Instant>`; on `None` we use
//! `SystemTime::now().duration_since(UNIX_EPOCH)` for byte-exact
//! match. Tested as `first_tick_rate_is_near_zero`.
//!
//! ## Row clipping is explicit
//!
//! curses clips `mvprintw` past `LINES` to a silent no-op. We don't
//! get that — `goto(100, 0)` on an 80-row terminal will scroll or
//! just dump off-screen, depending on the emulator. So `render_body`
//! takes `max_rows` and the loop is `for (i, name) ... { if 3+i >=
//! max_rows { break } }`. Same effect, explicit.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::cmd::CmdError;
use crate::ctl::{CtlError, CtlRequest, CtlSocket};
use crate::names::Paths;
use crate::tui;

use tinc_proto::{ParseError, Tok};

// Layer 1: wire parse

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
    /// Same error type as `dump.rs`'s row parsers.
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

// Layer 2: state machine — `update()` + `sortfunc()`

/// Per-node accumulator. MINUS the `name` (it's the `BTreeMap` key)
/// and MINUS the `i` (stable-sort emulation we don't need, see
/// module doc).
///
/// `*_rate` are `f32` to match upstream's `float`. `f64` would be
/// "more correct" but observably different — `%10.0f` rounding for
/// borderline values can differ between f32 and f64 at the 7th
/// significant digit.
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

/// The whole state of the top loop, EXCEPT the bits that don't
/// change between ticks (`netname`, those are arguments to
/// `render_header`).
#[derive(Debug)]
pub struct Stats {
    /// Upstream uses a sorted list (linear search, insert-before
    /// to keep sorted); the daemon's `splay_each` iterates name-
    /// sorted so insert-before is amortized O(1) per row. We don't
    /// bother with the trick — `BTreeMap` upsert is O(log n)
    /// regardless of daemon ordering. Same outcome (entries name-
    /// sorted), simpler.
    ///
    /// NEVER shrinks. A node that disappears stays here with
    /// `known=false` → dim display. The user sees the gap. Only
    /// way to clear is restart `tinc top`.
    pub nodes: BTreeMap<String, NodeStats>,

    /// The current display order. Sorted in-place each frame by
    /// `compare()`. Append-only — when a new node appears, push
    /// its name; never remove.
    ///
    /// Why this matters: `slice::sort_by` is stable. Sorting THE
    /// SAME Vec means equal-key entries stay in their previous-
    /// frame positions. If we rebuilt from `nodes.keys()` each
    /// frame, equal-key entries would be name-sorted (`BTreeMap`
    /// iteration), undoing stability.
    pub display_order: Vec<String>,

    /// None on tick 1 (upstream's zero-initialized timeval).
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
    /// Static initializers. The defaults match exactly so the
    /// first frame looks identical.
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

/// The seven sort keys.
///
/// `repr(u8)` so `SORTNAME[self as usize]` works. Values match
/// upstream's 0..6 EXACTLY — the `n`/`i`/`I`/`o`/`O`/`t`/`T` key
/// handlers hardcode them.
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
    /// One tick. Upstream's `update()` MINUS the I/O — caller sends
    /// `DUMP_TRAFFIC` and collects rows; this merges them. Splitting
    /// the I/O from the merge makes the merge testable.
    ///
    /// `now` is a parameter so tests can feed deterministic
    /// instants. `run()` passes `Instant::now()`.
    ///
    /// Returns true if a new node appeared. The caller doesn't
    /// actually need it (`display_order` is updated as a side effect),
    /// but it's the observable signal for "topology changed".
    #[allow(clippy::cast_precision_loss)] // u64→f32: 1s deltas ≪ 2^24; cumulative is display-only
    pub fn update(&mut self, rows: &[TrafficRow], now: Instant) -> bool {
        use std::collections::btree_map::Entry;

        // ─── Timekeeping
        // First tick: prev=None → interval ≈ epoch seconds → rate ≈ 0.
        // See module doc "First-tick rates are nonsense".
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

        // ─── Clear known
        // Survivors get marked true in the loop below; the rest
        // stay false → DIM.
        for s in self.nodes.values_mut() {
            s.known = false;
        }

        let mut changed = false;

        // ─── Merge
        for row in rows {
            let entry = self.nodes.entry(row.name.clone());

            // We CAN'T detect vacancy with `or_insert_with` AND
            // see the result of the closure firing, in one go —
            // the closure runs inside `or_insert_with` and we get
            // the `&mut NodeStats` either way. So: match on the
            // entry first.
            let s = match entry {
                Entry::Vacant(v) => {
                    // `Default` is the same zero-init as `xzalloc`.
                    self.display_order.push(row.name.clone());
                    changed = true;
                    v.insert(NodeStats::default())
                }
                Entry::Occupied(o) => o.into_mut(),
            };

            // This row's dump mentioned us → not gone.
            s.known = true;

            // Rate = delta / interval. The `wrapping_sub` is
            // unsigned subtraction (well-defined modular wrap).
            // See module doc — the wrap is observable (one-tick
            // spike on daemon restart).
            //
            // `as f32` after the sub, not before — `(a - b) as f32`
            // not `a as f32 - b as f32`. Different rounding for
            // huge values.
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

    /// In-place sort of `display_order` by the current `sort_mode` +
    /// `cumulative`.
    ///
    /// Rust `sort_by` is stable, so equal-key entries stay put —
    /// upstream's `i` tiebreak emulates this (see module doc). We
    /// just call sort.
    pub fn sort(&mut self) {
        // ─── Name mode is special
        // Ascending, NOT negated. The other modes return Equal on
        // tie and rely on stability to preserve frame-to-frame
        // position; Name is the only mode that ACTIVELY orders
        // ties (because "tie" means "same name" which can't happen,
        // names are unique). So Name doesn't go through `compare()`
        // — it's just `String::cmp`.
        //
        // Why not have `compare()` handle Name? It'd need the
        // names, which are the BTreeMap keys, not in NodeStats.
        // Passing them in would be 6 args. Upstream dodges this by
        // storing `name` IN `nodestats_t`; we don't (it's the map
        // key, would be redundant). The branch here is the cost of
        // NOT storing the redundant name. Cheap.
        if self.sort_mode == SortMode::Name {
            self.display_order.sort();
            return;
        }

        let mode = self.sort_mode;
        let cumulative = self.cumulative;
        // `sort_by` borrows `&mut self.display_order`; the closure
        // borrows `&self.nodes` (shared). Rust splits the borrow
        // fine (different fields) AS LONG AS we make the splits
        // explicit. `let nodes = &self.nodes` first, then the
        // closure captures `nodes` not `self`.
        let nodes = &self.nodes;
        self.display_order.sort_by(|a, b| {
            // Look up by name. The Vec only contains keys we
            // pushed, so the get is infallible — but `unwrap()`
            // would force `# Panics` doc. `unwrap_or_default()`
            // gives a zeroed stats which sorts last (rate=0.0),
            // and never fires anyway.
            let na = nodes.get(a).cloned().unwrap_or_default();
            let nb = nodes.get(b).cloned().unwrap_or_default();
            compare(&na, &nb, mode, cumulative)
        });
    }
}

/// The 7-way comparator. Each case is `result = -cmp(a.X, b.X)` —
/// note the NEGATION. Heavier traffic sorts to the TOP (descending).
/// Mode 0 (name) is ascending strcmp, no negation.
///
/// `cumulative` flips between rate and counter. The negation becomes
/// `b.cmp(&a)` / `b.partial_cmp(&a)` (swapping args).
///
/// The stable-sort tiebreak is NOT ported; `sort_by` is stable.
///
/// `f32::partial_cmp` is `None` only for NaN. Our rates are
/// `delta / interval` where interval is `>0` always (epoch-seconds
/// first tick, real elapsed after) — no division by zero, no NaN.
/// `unwrap_or(Equal)` covers the unreachable NaN case.
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
/// about. `Name` returns 0 — the caller (`Stats::sort`) handles that
/// mode by sorting keys directly so this arm is unreachable; the
/// constant keeps the match exhaustive.
#[allow(clippy::cast_precision_loss)] // see compare()
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

// Layer 3: render — `redraw()` minus the curses
//
// Upstream calls `mvprintw`, `attrset`, `chgat`. We `format!`
// strings with ANSI codes inline. The `goto(row, 0)` prefix
// replaces `mvprintw(row, 0, ...)`. The `attrset` becomes inline
// `BOLD`/`DIM`/`REVERSE` literals.
//
// Three pieces, each testable as `fn(...) -> String`:
//
//   - `render_header`: row 0 (status) + row 2 (column headers).
//   - `render_row`: one node, one line. The attribute logic
//     (BOLD if active, DIM if gone, NORMAL else) and the `%10.0f`
//     columns.
//   - `render`: assemble. The clipping loop.
//
// Row 1 is BLANK (where the cursor parks, and where the `'s'` key
// prompt overwrites). The `erase()` clears it; we emit `goto(1,0)
// + CLEAR_EOL`.

/// Row 0 + row 2.
///
/// Row 0: `"Tinc %-16s  Nodes: %4d  Sort: %-10s  %s"`. Four
/// fields: netname (left-align 16), node count (right-align 4),
/// sort mode name (left-align 10), cumulative-or-current word.
///
/// Then row 2 with `attrset(A_REVERSE)` and `chgat(-1, A_REVERSE,
/// 0, NULL)` — the latter extends reverse to end-of-line. We
/// emulate with `REVERSE + ... + CLEAR_EOL + RESET`: `CLEAR_EOL`
/// after the text but before `RESET` fills the rest of the line
/// WITH the current SGR (reverse). xterm/vte do this (it's the
/// "background color erase" behavior).
///
/// `netname` is `Option<&str>`: None → empty. `%-16s` with empty
/// is 16 spaces.
///
/// Returns one String with embedded `goto`. Caller writes it via
/// one `print!` (one syscall, no flicker between rows 0 and 2).
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

    // ─── Row 0: status line
    // `goto(0,0)` is `mvprintw(0, 0, ...)`. The `\x1b[K`
    // (`CLEAR_EOL`) replaces `erase()` — we clear-per-line instead
    // of clear-whole-screen. Less flicker. Upstream's `erase()` +
    // `refresh()` is curses' double-buffered diff; we don't have
    // that, so per-line clear is the next best.
    //
    // `{netname:<16}` is `%-16s`. `{count:>4}` is `%4d`. `{sortname
    // :<10}` is `%-10s`. The TWO spaces between fields are literal
    // in the format string: match them.
    write!(
        s,
        "{}Tinc {netname:<16}  Nodes: {count:>4}  Sort: {sortname:<10}  {mode}{}",
        tui::goto(0, 0),
        tui::CLEAR_EOL,
    )
    .unwrap(); // String Write is infallible

    // ─── Row 1: blank, cursor parks here
    // We're hiding the cursor (`CURSOR_HIDE` in `RawMode::enter`)
    // so the park position doesn't visually matter — but the `'s'`
    // key prompt overwrites it. Clear it now so previous-frame
    // leftovers don't show through when nothing's prompting.
    write!(s, "{}{}", tui::goto(1, 0), tui::CLEAR_EOL).unwrap();

    // ─── Row 2: column headers, REVERSEd
    // `chgat(-1, ...)` means "from cursor to end of line, change
    // attribute to REVERSE". After `mvprintw` the cursor is past
    // the printed text, so `chgat(-1)` fills the remainder of the
    // row with reverse.
    //
    // ANSI equivalent: print text in REVERSE, then CLEAR_EOL while
    // still in REVERSE. `\x1b[K` erases with the current SGR
    // background — in REVERSE that's the foreground color, giving
    // the filled-bar look. THEN reset.
    //
    // The header text spacing is hand-tuned to align with the
    // `%-16s %10.0f` body rows. "Node" (4) + 16 spaces = column 20
    // for "IN", roughly centered over the 10-char column (17-26).
    // Visual, not pixel-exact. We use the literal verbatim.
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

/// One body row. `mvprintw(row, 0, "%-16s %10.0f %10.0f %10.0f
/// %10.0f", ...)` with attribute prefix.
///
/// The attribute logic:
///
/// | known | nonzero rate | attribute |
/// |---|---|---|
/// | true | true | BOLD (active traffic) |
/// | true | false | NORMAL (idle but present) |
/// | false | — | DIM (gone) |
///
/// "nonzero rate" is `in_packets_rate || out_packets_rate`. NOT
/// bytes. NOT the cumulative counters. Packets-rate because that's
/// what changes if anything's happening (you can have nonzero
/// counters with zero rate — idle since last tick).
///
/// `cumulative` flips the FOUR numbers between counter (×scale)
/// and rate (×scale). The scale is `bscale`/`pscale` (the
/// `b`/`k`/`M`/`G` keys). Note the cumulative path CASTS u64 to
/// f32 first, which loses precision past 2^24 — but it's display-
/// only via `%10.0f`.
#[allow(clippy::cast_precision_loss)] // Display-only.
fn render_row(name: &str, s: &NodeStats, stats: &Stats, row: u16) -> String {
    // ─── Attribute
    // The nested `if` is awkward to read; the table form is clearer.
    //
    // `clippy::float_cmp`: comparing to literal 0.0 is fine here.
    // The rates ARE 0.0 when nothing happened (`0u64 as f32 /
    // interval == 0.0`, exact). Any nonzero delta gives a nonzero
    // rate (interval is finite positive). No epsilon needed.
    #[allow(clippy::float_cmp)] // 0u64/interval = exact 0.0; nonzero delta ⇒ nonzero rate
    let attr = if !s.known {
        tui::DIM
    } else if s.in_packets_rate != 0.0 || s.out_packets_rate != 0.0 {
        tui::BOLD
    } else {
        // NORMAL is "no SGR" — the RESET at the end of each row
        // (and the start-of-row goto+CLEAR_EOL clears prior SGR
        // anyway, but belt-and-suspenders). Empty string.
        ""
    };

    // ─── Numbers
    // `%10.0f` × 4. Order is `in_pkts, in_bytes, out_pkts,
    // out_bytes` — same in both branches.
    //
    // `{x:>10.0}` is `%10.0f`. The default alignment for numeric
    // types in Rust formatting is RIGHT (same as printf), so
    // `{:10.0}` not `{:>10.0}`. But: explicit `>` matches printf's
    // behavior even if Rust ever changes the default. Belt-and-
    // suspenders, costs nothing.
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

    // `goto + attribute + body + CLEAR_EOL + RESET`. CLEAR_EOL after
    // body so leftover chars from a longer previous-frame row are
    // erased (a node named `verylongnodename` last frame, `bob` this
    // frame, would leave `gnodename` visible without clearing).
    // RESET so the next row's lack-of-attr (NORMAL) actually IS
    // normal.
    format!(
        "{goto}{attr}{name:<16} {p1:>10.0} {b1:>10.0} {p2:>10.0} {b2:>10.0}{clr}{rst}",
        goto = tui::goto(row, 0),
        clr = tui::CLEAR_EOL,
        rst = tui::RESET,
    )
}

/// Full screen, one frame. Returns the whole thing as one String —
/// caller `write!`s it in one syscall.
///
/// `erase()` is replaced by per-line `CLEAR_EOL` (less flicker
/// without curses' double-buffer). Rows past `max_rows` are
/// clipped (curses clips silently; we clip explicitly).
///
/// Called AFTER `Stats::sort()` — `display_order` is in render order.
///
/// `max_rows` is `winsize().rows`. Passed in (not queried here) so
/// tests can give a small value and assert the clip.
fn render(netname: Option<&str>, stats: &Stats, max_rows: u16) -> String {
    let mut s = String::with_capacity(4096);

    // Rows 0, 1, 2.
    s.push_str(&render_header(netname, stats));

    // ─── Body: rows 3..
    // The clip is the only thing curses gave us for free.
    for (i, name) in stats.display_order.iter().enumerate() {
        // Row 3 is the first body row. `i` is `usize`; `3 + i` →
        // `u16` would clamp at 65k rows. Nobody has that many
        // nodes. `try_from` to be precise (the cast would silently
        // wrap; this saturates by breaking the loop).
        let Ok(row) = u16::try_from(3 + i) else { break };
        if row >= max_rows {
            break;
        }

        // The lookup is infallible (display_order is a subset of
        // nodes' keys, by construction in `update`). `unwrap_or_
        // default` for a zeroed-stats fallback (DIM, all 0s) —
        // reads as "this node is gone" if the invariant somehow
        // broke. Better than panic mid-draw.
        let entry = stats.nodes.get(name).cloned().unwrap_or_default();
        s.push_str(&render_row(name, &entry, stats, row));
    }

    // ─── Clear rows past current body
    // Upstream's `erase()` clears the whole screen up front. We do
    // per-line `CLEAR_EOL` instead (no flicker). But: if last frame
    // had 10 nodes and this frame has 8, rows 11-12 still have the
    // old text. We DON'T clear them — `nodes` never shrinks (departed
    // nodes stay, DIM). So body row count is monotone-increasing.
    //
    // Except: body row count can EXCEED max_rows (terminal shrunk).
    // Then on grow, the previously-clipped rows from BEFORE the
    // shrink are stale. ...but no, alt-screen content past the
    // visible area is undefined anyway; on grow the terminal fills
    // with whatever it wants (usually blanks). Don't bother.
    //
    // And: if `display_order.len()` < previous frame's len? Can't
    // happen — `display_order` is append-only. Monotone. No clear
    // needed.

    s
}

// Layer 4: I/O — fetch one dump

/// `update()` first half: send + recv loop, MINUS the merge (which
/// is `Stats::update`). Splitting makes `Stats::update` testable
/// without a socket.
///
/// # Errors
/// `CtlError::Io` if the socket dies mid-dump (daemon crashed).
/// `CtlError::Parse` if a row is malformed. Both end the `top` loop.
fn fetch<S: io::Read + io::Write>(ctl: &mut CtlSocket<S>) -> Result<Vec<TrafficRow>, CtlError> {
    // No third arg — DUMP_TRAFFIC is one of the dumps that doesn't
    // pretend to filter.
    ctl.send(CtlRequest::DumpTraffic)?;

    // The vec preallocation guess: a typical mesh has 10-100 nodes.
    // 32 is fine for the common case, growth handles outliers.
    let mut rows = Vec::with_capacity(32);
    ctl.for_each_row(|_, body| {
        // Parse failure ends the whole top session — the daemon's
        // sending garbage, no point continuing. `CtlError` has no
        // Parse variant; `Io` is the "daemon I/O went bad" bucket
        // and a malformed row is daemon I/O going bad.
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

// Layer 5: keys

/// Mutates `stats` per the key. Returns `false` for `'q'`.
///
/// The `'s'` key prompts for new delay. Needs cooked-mode line
/// input. `RawMode::with_cooked` does the dance. Returns `Err` if
/// the cooked-mode tcsetattr fails (terminal in weird state);
/// caller breaks the loop and Drop restores.
///
/// `getch_timeout` returning `None` (timeout, no key) is handled by
/// the caller, not here.
///
/// `raw` is `&RawMode` not `&mut` — `with_cooked` takes `&self`
/// (it doesn't mutate the stored original termios).
///
/// `out` is where the prompt gets written. stdout in real use;
/// `Vec<u8>` in tests.
fn handle_key(
    key: u8,
    stats: &mut Stats,
    raw: &tui::RawMode,
    out: &mut impl Write,
) -> io::Result<bool> {
    match key {
        // ─── 's': change delay
        // The one INTERACTIVE key. `timeout(-1)` (block forever) →
        // prompt → read float → clamp → `timeout(delay)`. We don't
        // have curses' `scanw`; `with_cooked` restores echo+canon,
        // `read_line`, parse `f32`.
        //
        // Upstream reads into `input` initialized to the CURRENT
        // delay. If parsing fails (non-numeric input), `input`
        // retains the initial value — net effect "no change". We do
        // the same: parse failure → keep current delay.
        b's' => {
            let current_secs = f32::from(stats.delay_ms) * 1e-3;

            // Row 1 is the parked-cursor row. `goto(1,0)` + the
            // message. `with_cooked` will re-show the cursor.
            write!(
                out,
                "{}Change delay from {:.1}s to: {}",
                tui::goto(1, 0),
                current_secs,
                tui::CLEAR_EOL,
            )?;
            out.flush()?;

            // `with_cooked`: restore echo+canon, run closure, re-raw.
            // Closure reads ONE line. Parse failure (empty, garbage)
            // → None → keep current.
            let new_secs: Option<f32> = raw.with_cooked(|stdin| {
                let mut line = String::new();
                stdin.read_line(&mut line)?;
                Ok(line.trim().parse::<f32>().ok())
            })?;

            // Clamp BEFORE storing. NaN doesn't satisfy `< 0.1`
            // (NaN comparisons are false), but `parse::<f32>`
            // rejects "nan" anyway. Infinity DOES parse; `inf *
            // 1000 → inf`, `inf as u16` saturates in Rust (since
            // 1.45). So inf gives `delay_ms = 65535`. ~65s tick.
            // Harmless.
            if let Some(input) = new_secs {
                let clamped = if input < 0.1 { 0.1 } else { input };
                #[allow(clippy::cast_possible_truncation)] // Saturating; clamped >= 0.1
                #[allow(clippy::cast_sign_loss)] // so it's positive anyway.
                {
                    stats.delay_ms = (clamped * 1e3) as u16;
                }
            }
            // Our `getch_timeout(stats.delay_ms)` reads `delay_ms`
            // fresh each tick — no separate set call needed.

            Ok(true)
        }

        // ─── 'c': toggle cumulative
        b'c' => {
            stats.cumulative = !stats.cumulative;
            Ok(true)
        }

        // ─── 'q': quit
        // `KEY_BREAK` is curses' Windows-console Ctrl-Break thing;
        // we're cfg(unix), don't have it.
        b'q' => Ok(false),

        // ─── default: ignore
        // Unknown key, including arrow-key escape sequences (we'd
        // see `\x1b` then `[` then `A` etc as separate ticks — the
        // loop is fast enough that the user doesn't notice three
        // "ignored key" cycles). Upstream has the same behavior:
        // it doesn't call `keypad()`, so curses gives raw escape
        // bytes too.
        _ => {
            // ─── Sort mode keys (lowercase → bytes; uppercase → packets)
            if let Some(&(_, m)) = SORT_KEYS.iter().find(|(k, _)| *k == key) {
                stats.sort_mode = m;
            // ─── Unit/scale keys: four presets. `b`/`k` keep packets
            // at 1×, only `M`/`G` scale packets too.
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

// Layer 6: the loop

/// `top()` itself. Connect, enter raw, loop, exit cleanly.
///
/// # Errors
/// `CmdError::BadInput` if the daemon's not running (connect
/// fails) or sends garbage (parse failure). `RawMode::enter`
/// failure (stdin not a tty, e.g. `tinc top < /dev/null`) also
/// becomes `BadInput` — there's no good way to run top without
/// a terminal, so it's a usage error.
#[cfg(unix)]
pub fn run(paths: &Paths, netname: Option<&str>) -> Result<(), CmdError> {
    // ─── Connect
    // BEFORE entering raw mode — if connect fails the error
    // message goes to a sane terminal.
    let mut ctl = CtlSocket::connect(paths)?;

    // ─── Raw mode
    // RawMode's Drop is `endwin()`. The Drop fires on panic too,
    // which curses' `endwin()` doesn't (panic → terminal stays
    // raw). We're better there.
    let raw = tui::RawMode::enter()
        .map_err(|e| CmdError::BadInput(format!("cannot enter raw mode: {e}")))?;

    let mut stats = Stats::default();
    let mut stdout = io::stdout().lock();

    // ─── Loop
    // `while(running) { update; redraw; switch(getch()) }`.
    //
    // Daemon died mid-dump → exit cleanly. `while let Ok` does
    // exactly that: Err exits the loop. SILENT exit. The daemon
    // went away; the user sees the prompt again.
    //
    // `fetch` blocks until the daemon responds. The daemon's
    // `dump_traffic` is a tight loop, fast. If the daemon hangs
    // (doesn't happen in practice — control thread is single-
    // purpose), we hang too. No timeout.
    while let Ok(rows) = fetch(&mut ctl) {
        stats.update(&rows, Instant::now());

        // Sort then render. `winsize()` each frame so terminal-
        // resize is live (one-tick lag, since we don't catch
        // SIGWINCH; upstream doesn't either).
        stats.sort();
        let frame = render(netname, &stats, tui::winsize().rows);
        // One syscall per frame. No flicker between header and body.
        // Ignore write errors (stdout closed → next iteration's
        // write also fails → we'll notice on getch_timeout via
        // EOF → 'q').
        let _ = stdout.write_all(frame.as_bytes());
        let _ = stdout.flush();

        // `getch` with `timeout(delay)` blocks for `delay` ms then
        // returns `ERR`. Our `getch_timeout` does the same (`None`
        // on timeout).
        //
        // `getch_timeout` errors (poll/read failure other than
        // EINTR) → break. Shouldn't happen (stdin is a tty we
        // already validated). Upstream's `getch` returns `ERR` on
        // error too, indistinguishable from timeout — it would
        // spin. We break instead (better than spin).
        match tui::getch_timeout(stats.delay_ms) {
            Ok(None) => {} // timeout, next tick
            Ok(Some(key)) => {
                // `handle_key` returns `false` for `'q'`. The `?`
                // propagates with_cooked's tcsetattr failure
                // (terminal weird; bail; Drop restores).
                if !handle_key(key, &mut stats, &raw, &mut stdout)
                    .map_err(|e| CmdError::BadInput(format!("terminal I/O: {e}")))?
                {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    // RawMode's Drop. Explicit `drop` for clarity (it'd run anyway
    // at scope end, but we want it BEFORE returning Ok — if anything
    // below printed to stdout it'd be on a sane terminal). Nothing's
    // below, but the explicit drop documents the order.
    drop(raw);
    drop(stdout);

    Ok(())
}

// Tests
//
// Four layers of tests, matching the module structure:
//
// 1. `TrafficRow::parse` against the daemon's printf format.
// 2. `Stats::update` with synthetic ticks. Feed two dumps with
//    known dt, assert rates.
// 3. `compare` with table-driven cases. The 7×2 fanout.
// 4. `render_*` with inline ANSI. Golden strings.
// 5. `handle_key` for the trivial state-mutation keys (NOT 's',
//    that needs a tty).
//
// `run` and `'s'`-key are manual-smoke only (need a real terminal
// + daemon). The integration test in `tinc_cli.rs` does the
// connect-against-fake-daemon thing for one tick's worth.

#[cfg(test)]
mod tests;
