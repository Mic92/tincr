//! `cmd_top` — `top.c` (397 LOC, `#ifdef HAVE_CURSES`).
//!
//! ```text
//!   tinc top                   → real-time per-node traffic stats
//! ```
//!
//! Loop: send `DUMP_TRAFFIC` → recv N rows + terminator → compute
//! per-second rates from delta over previous tick → render → sleep
//! `delay_ms` waiting for a keypress → repeat. The daemon's `dump_
//! traffic` (`node.c:226`) is the simplest dump format: name + 4
//! u64 counters, no `" port "` wrinkle.
//!
//! ## Three layers, two testable
//!
//! | Layer | Touches tty? | Tests |
//! |---|---|---|
//! | `TrafficRow::parse` | no | golden vs `node.c:228` printf |
//! | `Stats::update` (the merge + rate compute) | no | feed two dumps with known dt, assert rates |
//! | `compare` (the 7-way comparator) | no | table-driven |
//! | `render_*` (Row → ANSI String) | no | golden, assert with codes inline |
//! | `run` (the loop) | yes | manual smoke against daemon |
//!
//! `tui.rs` is consumed ONLY by `run`. Everything above it is plain
//! data flow. The C has the same boundary (curses calls only in
//! `redraw()` and `top()`), it's just less visible because `redraw()`
//! reaches into `static node_list` directly.
//!
//! ## The C's stable-sort emulation, NOT ported
//!
//! `top.c:251-259` sets `sorted[i]->i = i` before `qsort`, then
//! `sortfunc` falls back to `na->i - nb->i` on ties (`top.c:231`).
//! It's a stable-sort emulation for non-stable `qsort`. Rust's
//! `slice::sort_by` IS stable, so we just sort `Stats::display_order`
//! in place each frame (append-only on new nodes; not rebuilt from
//! BTreeMap which would name-sort and undo prior stability).
//!
//! ## Daemon restart wraps to 18 quintillion, ported faithfully
//!
//! `top.c:125`: `in_packets - found->in_packets`, both `uint64_t`.
//! Daemon restarts → counters reset → `0 - huge` wraps. Self-corrects
//! next tick. We use `wrapping_sub` to match: a saturating delta
//! would hide the daemon-restart event; the spike IS the signal.
//!
//! ## First-tick rates are nonsense, ported faithfully
//!
//! `top.c:62`: `static struct timeval prev` is zero-initialized, so
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
use crate::ctl::{CtlError, CtlRequest, CtlSocket, DumpRow};
use crate::names::Paths;
use crate::tui;

use tinc_proto::{ParseError, Tok};

// Layer 1: wire parse

/// One row of `DUMP_TRAFFIC`. `node.c:228`: `"%d %d %s %"PRIu64"
/// %"PRIu64" %"PRIu64" %"PRIu64`. That's `code req name in_packets
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
    /// Parse the body (post-`recv_row`-strip). `top.c:96`: `sscanf(
    /// line, "%d %d %4095s %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64,
    /// ...)`. The `%4095s` width limit is the C buffer-size guard;
    /// Rust strings don't overflow, no width.
    ///
    /// # Errors
    /// `ParseError` if any field is missing or not the right type.
    /// Maps to `top.c:102`: `if(n != 7) return false` — daemon's
    /// `dump_traffic` is broken or the wire's corrupt. Same error
    /// type as `dump.rs`'s row parsers (`NodeRow::parse` etc).
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
        // No `.end()`: C `sscanf` doesn't care about trailing
        // garbage. `top.c:96`'s `n != 7` check counts conversions,
        // not whether the line was fully consumed. Future daemon
        // versions adding fields wouldn't break us.
    }
}

// Layer 2: state machine — `update()` + `sortfunc()`

/// Per-node accumulator. `top.c:34-46` `nodestats_t`, MINUS the
/// `name` (it's the BTreeMap key) and MINUS the `i` (stable-sort
/// emulation we don't need, see module doc).
///
/// `*_rate` are `f32` to match the C's `float`. `f64` would be
/// "more correct" but observably different — `%10.0f` rounding for
/// borderline values can differ between f32 and f64 at the 7th
/// significant digit. The C's choice was `float`; we honor it.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct NodeStats {
    /// Cumulative counters (the values from the daemon, verbatim).
    pub in_packets: u64,
    pub in_bytes: u64,
    pub out_packets: u64,
    pub out_bytes: u64,

    /// Per-second rates (delta over `interval`). `top.c:125-128`.
    /// Only valid AFTER `Stats::update`; the `Default` impl gives
    /// 0.0, which is what `xzalloc` gives.
    pub in_packets_rate: f32,
    pub in_bytes_rate: f32,
    pub out_packets_rate: f32,
    pub out_bytes_rate: f32,

    /// Set true when this tick's dump mentioned the node. False
    /// means "node disappeared from daemon's view between ticks"
    /// → DIM display (`top.c:264-269`). `top.c:90`: cleared at
    /// the start of every update; `top.c:124`: set true when
    /// found in the dump.
    pub known: bool,
}

/// The whole state of the top loop, EXCEPT the bits that don't
/// change between ticks (`netname`, those are arguments to
/// `render_header`). C: a pile of `static` globals (`top.c:58-68`).
#[derive(Debug)]
pub struct Stats {
    /// `top.c:61` `static list_t node_list`. The C's a sorted list
    /// (linear search, insert-before to keep sorted, `top.c:107-
    /// 121`); the daemon's `splay_each` iterates name-sorted so
    /// insert-before is amortized O(1) per row. We don't bother
    /// with the trick — BTreeMap upsert is O(log n) regardless of
    /// daemon ordering. Same outcome (entries name-sorted), simpler.
    ///
    /// NEVER shrinks. A node that disappears stays here with
    /// `known=false` → dim display. The user sees the gap. Only
    /// way to clear is restart `tinc top`. Same as C.
    pub nodes: BTreeMap<String, NodeStats>,

    /// `top.c:248` `static nodestats_t **sorted`. The current
    /// display order. Sorted in-place each frame by `compare()`.
    /// Append-only — when a new node appears, push its name; never
    /// remove. The `static` in C makes it persist across `redraw`
    /// calls; here it lives in `Stats` for the same reason.
    ///
    /// Why this matters: `slice::sort_by` is stable. Sorting THE
    /// SAME Vec means equal-key entries stay in their previous-
    /// frame positions. If we rebuilt from `nodes.keys()` each
    /// frame, equal-key entries would be name-sorted (BTreeMap
    /// iteration), undoing stability. The C achieves the same
    /// thing via the `i` field (see module doc).
    pub display_order: Vec<String>,

    /// `top.c:62` `static struct timeval prev`. None on tick 1
    /// (the C's `{0,0}` zero-init).
    prev_instant: Option<Instant>,

    /// `top.c:58-59`. Starts as `(0, false)` — `top.c:58-59`.
    pub sort_mode: SortMode,
    pub cumulative: bool,

    /// `top.c:63`. Milliseconds. Starts at 1000 (`top.c:63`).
    pub delay_ms: u16,

    /// `top.c:65-68`. `(unit-suffix, scale)` pairs. The four
    /// `b`/`k`/`M`/`G` keys flip these. Starts at `("bytes", 1.0,
    /// "pkts", 1.0)` — `top.c:65-68`.
    pub bunit: &'static str,
    pub bscale: f32,
    pub punit: &'static str,
    pub pscale: f32,
}

impl Default for Stats {
    /// `top.c:58-68` static initializers. The defaults match
    /// exactly so the first frame looks identical.
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

/// `top.c:58` `static int sortmode = 0`. The seven sort keys.
///
/// The C uses 0..6 with `SORTNAME[sortmode]` for display. Enum
/// gives us the same indexing (`as usize`) plus exhaustiveness on
/// the `compare` switch.
///
/// `repr(u8)` so `SORTNAME[self as usize]` works (the C does
/// `sortname[sortmode]`, same idea). Values match the C's 0..6
/// EXACTLY — the `n`/`i`/`I`/`o`/`O`/`t`/`T` key handlers
/// (`top.c:308-332`) hardcode them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SortMode {
    /// `'n'` key. `top.c:328-329`. Ascending strcmp.
    Name = 0,
    /// `'I'` key. `top.c:336-337`. Uppercase → packets.
    InPackets = 1,
    /// `'i'` key. `top.c:332-333`. Lowercase → bytes (heavier).
    InBytes = 2,
    /// `'O'` key. `top.c:344-345`.
    OutPackets = 3,
    /// `'o'` key. `top.c:340-341`.
    OutBytes = 4,
    /// `'T'` key. `top.c:352-353`.
    TotalPackets = 5,
    /// `'t'` key. `top.c:348-349`.
    TotalBytes = 6,
}

/// `top.c:48-56`. Index by `SortMode as usize`. The header row
/// shows this (`top.c:241`: `Sort: %-10s`).
///
/// sed-verifiable: `sed -n '48,56p' src/top.c`. Same strings,
/// same order.
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
    /// One tick. `top.c:70-144` `update()`, MINUS the I/O — caller
    /// sends DUMP_TRAFFIC and collects rows; this merges them.
    /// Splitting the I/O from the merge makes the merge testable.
    ///
    /// `top.c:90-92`: clear `known` on all entries. `top.c:107-
    /// 132`: for each row, upsert + compute rate. `top.c:77-79`:
    /// timekeeping.
    ///
    /// `now` is a parameter so tests can feed deterministic
    /// instants. `run()` passes `Instant::now()`.
    ///
    /// Returns true if a new node appeared (the C's `changed`
    /// global, `top.c:64`). The caller doesn't actually need it
    /// (display_order is updated as a side effect), but it's the
    /// observable signal for "topology changed" — the C uses it
    /// to gate the `sorted[]` rebuild (`top.c:243`).
    #[allow(clippy::cast_precision_loss)] // u64 → f32, the C's `(float)(uint64_t)`. Loses
    // precision past 2^24 (~16M), which a 1-second
    // delta will only hit at 16M packets/sec on one
    // node. The cumulative path also casts (`top.c
    // :273`), where the value is the actual counter
    // — but it's display-only, `%10.0f`, nobody's
    // doing arithmetic on the printed value.
    pub fn update(&mut self, rows: &[TrafficRow], now: Instant) -> bool {
        use std::collections::btree_map::Entry;

        // ─── Timekeeping
        // `top.c:75-79`: `gettimeofday(&cur); timersub(&cur, &prev,
        // &diff); prev = cur; interval = diff.tv_sec + diff.tv_usec
        // * 1e-6`.
        //
        // First tick: `prev = {0,0}`. `diff = cur - {0,0} = cur`.
        // `interval ≈ epoch seconds ≈ 1.7e9`. Ported faithfully:
        // `SystemTime::now() - UNIX_EPOCH` IS what `gettimeofday()`
        // returns. We can't use `Instant` for this case (`Instant`
        // is monotonic, no zero, no `Instant::default()`); SystemTime
        // is the wall-clock thing the C uses. `as_secs_f32` matches
        // `tv_sec + tv_usec * 1e-6f` — both are `float`.
        //
        // The PURPOSE of the epoch-seconds first-tick interval is
        // accidental (the C just didn't initialize prev), but the
        // EFFECT is harmless: rate = counter / 1.7e9 ≈ 0.0, prints
        // as `0` via `%10.0f`. Tick 2 (1s later) is correct. We
        // port the accident because (a) the user sees "0 0 0 0"
        // for one tick either way, and (b) NOT porting it means
        // picking some "first tick interval" out of thin air,
        // which is its own kind of wrong.
        let interval: f32 = match self.prev_instant {
            Some(prev) => now.duration_since(prev).as_secs_f32(),
            None => {
                // The epoch-seconds nonsense. Fallible if system
                // clock is before 1970; unwrap_or(huge) is the
                // same outcome as the C's negative tv_sec wrapping
                // to garbage — large interval, zero rate, fixed
                // next tick.
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or(Duration::from_secs(1_700_000_000))
                    .as_secs_f32()
            }
        };
        self.prev_instant = Some(now);

        // ─── Clear known
        // `top.c:90-92`: `for list_each(ns, &node_list) ns->known =
        // false`. Survivors get marked true in the loop below; the
        // rest stay false → DIM.
        for s in self.nodes.values_mut() {
            s.known = false;
        }

        let mut changed = false;

        // ─── Merge
        // `top.c:107-132`. The C does sorted-list linear search +
        // insert-before. We `entry()` for the upsert (O(log n);
        // the C's amortized O(1) only because daemon iteration is
        // sorted, which we don't depend on).
        for row in rows {
            let entry = self.nodes.entry(row.name.clone());

            // `top.c:107-122`: the find-or-create. `or_insert_with`
            // detects "vacant" via the entry API; on vacancy, push
            // to display_order (the C's `changed = true` triggers
            // a `sorted[]` rebuild that does the same thing).
            //
            // We CAN'T detect vacancy with `or_insert_with` AND
            // see the result of the closure firing, in one go —
            // the closure runs inside `or_insert_with` and we get
            // the `&mut NodeStats` either way. So: match on the
            // entry first.
            let s = match entry {
                Entry::Vacant(v) => {
                    // `top.c:116-121`: `xzalloc` (so `*_rate=0.0`,
                    // counters=0, known=false), strdup name, insert.
                    // `Default` is the same zero-init.
                    self.display_order.push(row.name.clone());
                    changed = true;
                    v.insert(NodeStats::default())
                }
                Entry::Occupied(o) => o.into_mut(),
            };

            // `top.c:124`. This row's dump mentioned us → not gone.
            s.known = true;

            // `top.c:125-128`. Rate = delta / interval. The
            // `wrapping_sub` is the C's unsigned subtraction
            // (well-defined modular wrap in C; debug-panic in Rust).
            // See module doc — the wrap is observable (one-tick
            // spike on daemon restart) but the C does it too.
            //
            // `as f32` after the sub, not before — `(a - b) as f32`
            // not `a as f32 - b as f32`. The C does the sub in
            // u64 then casts. Different rounding for huge values;
            // match the C.
            s.in_packets_rate = row.in_packets.wrapping_sub(s.in_packets) as f32 / interval;
            s.in_bytes_rate = row.in_bytes.wrapping_sub(s.in_bytes) as f32 / interval;
            s.out_packets_rate = row.out_packets.wrapping_sub(s.out_packets) as f32 / interval;
            s.out_bytes_rate = row.out_bytes.wrapping_sub(s.out_bytes) as f32 / interval;

            // `top.c:129-132`. Store for next tick's delta.
            s.in_packets = row.in_packets;
            s.in_bytes = row.in_bytes;
            s.out_packets = row.out_packets;
            s.out_bytes = row.out_bytes;
        }

        changed
    }

    /// In-place sort of `display_order` by the current `sort_mode` +
    /// `cumulative`. `top.c:257`: `qsort(sorted, n, ..., sortfunc)`.
    ///
    /// Rust `sort_by` is stable, so equal-key entries stay put —
    /// the C's `i` tiebreak emulates this (see module doc). We
    /// just call sort.
    pub fn sort(&mut self) {
        // ─── Name mode is special
        // `top.c:226`: `default: result = strcmp(...)`. Ascending,
        // NOT negated. The other modes return Equal on tie and rely
        // on stability to preserve frame-to-frame position; Name
        // is the only mode that ACTIVELY orders ties (because
        // "tie" means "same name" which can't happen, names are
        // unique). So Name doesn't go through `compare()` — it's
        // just `String::cmp`.
        //
        // Why not have `compare()` handle Name? It'd need the
        // names, which are the BTreeMap keys, not in NodeStats.
        // Passing them in would be `compare(a_name, &a_stats,
        // b_name, &b_stats, mode, cumulative)` — 6 args. The C
        // dodges this by storing `name` IN `nodestats_t` (`top.c
        // :35`); we don't (it's the map key, would be redundant).
        // The branch here is the cost of NOT storing the redundant
        // name. Cheap.
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
            // and never fires anyway. Same trick as `info.rs`.
            let na = nodes.get(a).cloned().unwrap_or_default();
            let nb = nodes.get(b).cloned().unwrap_or_default();
            compare(&na, &nb, mode, cumulative)
        });
    }
}

/// `sortfunc` (`top.c:156-233`). The 7-way comparator.
///
/// `top.c:165-227`: switch on `sortmode`. Each case is `result =
/// -cmp(a.X, b.X)` — note the NEGATION. Heavier traffic sorts to
/// the TOP (descending). Mode 0 (name) is ascending strcmp, no
/// negation (`top.c:226`).
///
/// `cumulative` flips between rate and counter. The `-cmpu64` /
/// `-cmpfloat` calls become `b.cmp(&a)` / `b.partial_cmp(&a)`
/// (swapping args is the negation).
///
/// `top.c:230-232`: `if(result) return result; else return na->i
/// - nb->i` — the stable-sort tiebreak. NOT ported; `sort_by` is
/// stable. The function just returns the primary `Ordering`.
///
/// `f32::partial_cmp` is `None` only for NaN. Our rates are
/// `delta / interval` where interval is `>0` always (epoch-
/// seconds first tick, real elapsed after) — no division by zero,
/// no NaN. `unwrap_or(Equal)` on the partial_cmp is the C's
/// `cmpfloat` returning 0 on `else` (`top.c:144`), which would
/// also be the NaN case if you fed it one.
#[allow(clippy::too_many_lines)] // 7-arm match, each arm 2-way on cumulative.
// The C is 70 lines (`top.c:165-227`). Factoring
// out the per-field-pair extraction adds
// indirection without reducing the irreducible
// 7×2 fanout.
fn compare(a: &NodeStats, b: &NodeStats, mode: SortMode, cumulative: bool) -> std::cmp::Ordering {
    use SortMode::{InBytes, InPackets, Name, OutBytes, OutPackets, TotalBytes, TotalPackets};
    use std::cmp::Ordering::Equal;

    match mode {
        // `top.c:226`: `default: result = strcmp(na->name, nb->name)`.
        // We don't have the name here (it's the BTreeMap key). The
        // caller (`Stats::sort`) branches on mode FIRST: Name mode
        // sorts the key Vec directly, other modes call `compare()`
        // and rely on stable-sort for ties (matching C's `i` fallback,
        // `top.c:228`). This arm is unreachable; Equal keeps the
        // match exhaustive.
        Name => Equal,

        // `top.c:166-172`. `case 1`. Descending (heavier first):
        // `b.cmp(&a)` not `a.cmp(&b)`.
        InPackets => {
            if cumulative {
                b.in_packets.cmp(&a.in_packets)
            } else {
                b.in_packets_rate
                    .partial_cmp(&a.in_packets_rate)
                    .unwrap_or(Equal)
            }
        }

        // `top.c:175-181`. `case 2`.
        InBytes => {
            if cumulative {
                b.in_bytes.cmp(&a.in_bytes)
            } else {
                b.in_bytes_rate
                    .partial_cmp(&a.in_bytes_rate)
                    .unwrap_or(Equal)
            }
        }

        // `top.c:184-190`. `case 3`.
        OutPackets => {
            if cumulative {
                b.out_packets.cmp(&a.out_packets)
            } else {
                b.out_packets_rate
                    .partial_cmp(&a.out_packets_rate)
                    .unwrap_or(Equal)
            }
        }

        // `top.c:193-199`. `case 4`.
        OutBytes => {
            if cumulative {
                b.out_bytes.cmp(&a.out_bytes)
            } else {
                b.out_bytes_rate
                    .partial_cmp(&a.out_bytes_rate)
                    .unwrap_or(Equal)
            }
        }

        // `top.c:202-208`. `case 5`. Sum, then descending.
        // `wrapping_add` for the same reason as `wrapping_sub` in
        // update — `top.c:204`: `na->in_packets + na->out_packets`.
        // u64 overflow at 18 quintillion total packets; not
        // happening in practice, but C unsigned add wraps and we
        // match.
        TotalPackets => {
            if cumulative {
                let sa = a.in_packets.wrapping_add(a.out_packets);
                let sb = b.in_packets.wrapping_add(b.out_packets);
                sb.cmp(&sa)
            } else {
                let sa = a.in_packets_rate + a.out_packets_rate;
                let sb = b.in_packets_rate + b.out_packets_rate;
                sb.partial_cmp(&sa).unwrap_or(Equal)
            }
        }

        // `top.c:211-217`. `case 6`.
        TotalBytes => {
            if cumulative {
                let sa = a.in_bytes.wrapping_add(a.out_bytes);
                let sb = b.in_bytes.wrapping_add(b.out_bytes);
                sb.cmp(&sa)
            } else {
                let sa = a.in_bytes_rate + a.out_bytes_rate;
                let sb = b.in_bytes_rate + b.out_bytes_rate;
                sb.partial_cmp(&sa).unwrap_or(Equal)
            }
        }
    }
}

// Rewrite Stats::sort with the Name special-case discovered above.
// This is the SECOND attempt; the first inlined `compare` for Name,
// which was wrong (stable sort + Equal already DOES "previous frame
// order" for tied non-Name; Name needs ACTIVE comparison, not Equal).
//
// (Can't put this prose in `Stats::sort`'s doc — it's already
// written. The fix is in the body.)

// Layer 3: render — `redraw()` minus the curses
//
// `top.c:237-280` `redraw()`. The C calls `mvprintw`, `attrset`,
// `chgat`. We `format!` strings with ANSI codes inline. The
// `goto(row, 0)` prefix replaces `mvprintw(row, 0, ...)`. The
// `attrset` becomes inline `BOLD`/`DIM`/`REVERSE` literals.
//
// Three pieces, each testable as `fn(...) -> String`:
//
//   - `render_header`: row 0 (status) + row 2 (column headers).
//     `top.c:240-242`.
//   - `render_row`: one node, one line. `top.c:261-278`. The
//     attribute logic (BOLD if active, DIM if gone, NORMAL else)
//     and the `%10.0f` columns.
//   - `render`: assemble. The clipping loop.
//
// Row 1 is BLANK (`move(1, 0)` at the end, `top.c:279` — that's
// where the cursor parks, and where the `'s'` key prompt overwrites).
// The `erase()` at `top.c:238` clears it; we emit `goto(1,0) +
// CLEAR_EOL`.

/// Row 0 + row 2. `top.c:240-242`.
///
/// `mvprintw(0, 0, "Tinc %-16s  Nodes: %4d  Sort: %-10s  %s", ...)`.
/// Four fields: netname (left-align 16), node count (right-align 4),
/// sort mode name (left-align 10), cumulative-or-current word.
///
/// Then `mvprintw(2, 0, "Node ...")` with `attrset(A_REVERSE)` and
/// `chgat(-1, A_REVERSE, 0, NULL)` — the latter extends reverse to
/// end-of-line. We emulate with `REVERSE + ... + CLEAR_EOL + RESET`:
/// `CLEAR_EOL` after the text but before `RESET` fills the rest of
/// the line WITH the current SGR (reverse). xterm/vte do this (it's
/// the "background color erase" behavior); `chgat(-1, ...)` is
/// curses' name for it.
///
/// `netname` is `Option<&str>`: `top.c:240` does `netname ? netname
/// : ""`. None → empty. `%-16s` with empty is 16 spaces.
///
/// Returns one String with embedded `goto`. Caller writes it via one
/// `print!` (one syscall, no flicker between rows 0 and 2).
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
    // `top.c:240`. `goto(0,0)` is `mvprintw(0, 0, ...)`. The `\x1b
    // [K` (`CLEAR_EOL`) replaces `erase()` — we clear-per-line
    // instead of clear-whole-screen. Less flicker. The C's `erase()`
    // + `refresh()` is curses' double-buffered diff; we don't have
    // that, so per-line clear is the next best.
    //
    // `{netname:<16}` is `%-16s`. `{count:>4}` is `%4d`. `{sortname
    // :<10}` is `%-10s`. The TWO spaces between fields are literal
    // in the C format string (`"%-16s  Nodes:"`): match them.
    write!(
        s,
        "{}Tinc {netname:<16}  Nodes: {count:>4}  Sort: {sortname:<10}  {mode}{}",
        tui::goto(0, 0),
        tui::CLEAR_EOL,
    )
    .unwrap(); // String Write is infallible

    // ─── Row 1: blank, cursor parks here
    // `top.c:279`: `move(1, 0)`. The C does this AT THE END of
    // redraw, so the cursor blinks on row 1 between ticks. We're
    // hiding the cursor (`CURSOR_HIDE` in `RawMode::enter`) so the
    // park position doesn't visually matter — but the `'s'` key
    // prompt (`top.c:304`: `mvprintw(1, 0, ...)`) overwrites it.
    // Clear it now so previous-frame leftovers don't show through
    // when nothing's prompting.
    write!(s, "{}{}", tui::goto(1, 0), tui::CLEAR_EOL).unwrap();

    // ─── Row 2: column headers, REVERSEd
    // `top.c:241-242`: `attrset(A_REVERSE); mvprintw(2,0,"Node ...")
    // ; chgat(-1, A_REVERSE, 0, NULL)`. The `chgat(-1, ...)` means
    // "from cursor to end of line, change attribute to REVERSE".
    // After `mvprintw` the cursor is past the printed text, so
    // `chgat(-1)` fills the remainder of the row with reverse.
    //
    // ANSI equivalent: print text in REVERSE, then CLEAR_EOL while
    // still in REVERSE. `\x1b[K` erases with the current SGR
    // background — in REVERSE that's the foreground color, giving
    // the filled-bar look. THEN reset.
    //
    // The header text is `%s` for `punit`/`bunit` × 2. `top.c:242`:
    // `"Node                IN %s   IN %s   OUT %s  OUT %s"`. The
    // spacing is hand-tuned to align with the `%-16s %10.0f` body
    // rows. Count the spaces in the C: after `Node` is 16 chars
    // (the `%-16s` width). `IN ` + `%s` (4-5 chars: pkts/bytes/etc)
    // + spaces to fill 11-char column. We replicate the literal.
    //
    // Twenty spaces after Node: `top.c:242` has `Node` then padding
    // to column 16+1=17, then `IN` aligned with the first `%10.0f`.
    // Count from the C: `"Node" + 16 spaces` = 20 chars... no, let
    // me actually count. `"Node                IN"` — "Node" is 4
    // chars, then 16 spaces, then "IN". 4+16=20, matching `%-16s `
    // (16-wide field then one space). The body row format is
    // `"%-16s %10.0f"` so the first `%10.0f` starts at column 17.
    // `IN ` should align there. 4 + 16 = 20, but body is 16 + 1 =
    // 17... discrepancy. Read the C again.
    //
    // ACTUALLY: the C is `"Node                IN %s"`. Between
    // "Node" and "IN": count the spaces in `top.c:242`. Sixteen
    // spaces. So "Node" (4) + 16 spaces = column 20 for "IN".
    // Body: `%-16s ` puts content in cols 0-15, space at col 16,
    // `%10.0f` at cols 17-26. "IN" at col 20 is roughly centered
    // over the 10-char column (17-26). Good enough; the C's
    // alignment is visual, not pixel-exact.
    //
    // We sed-verify the literal at commit time and use it verbatim.
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

/// One body row. `top.c:261-278`. `mvprintw(row, 0, "%-16s %10.0f
/// %10.0f %10.0f %10.0f", ...)` with attribute prefix.
///
/// The attribute logic (`top.c:264-269`):
///
/// | known | nonzero rate | attribute |
/// |---|---|---|
/// | true | true | BOLD (active traffic) |
/// | true | false | NORMAL (idle but present) |
/// | false | — | DIM (gone) |
///
/// "nonzero rate" is `in_packets_rate || out_packets_rate` (`top.c
/// :265`). NOT bytes. NOT the cumulative counters. Packets-rate
/// because that's what changes if anything's happening (you can
/// have nonzero counters with zero rate — idle since last tick).
/// The `||` is C's float-to-bool: nonzero is true. We compare to
/// 0.0 explicitly.
///
/// `cumulative` flips the FOUR numbers between counter (×scale)
/// and rate (×scale). `top.c:271-277`. The scale is `bscale`/
/// `pscale` (the `b`/`k`/`M`/`G` keys). Note the cumulative path
/// CASTS u64 to f32 first (`(float) node->in_packets * pscale`,
/// `top.c:274`), which loses precision past 2^24 — but it's
/// display-only via `%10.0f`.
#[allow(clippy::cast_precision_loss)] // `top.c:274`: `(float) node->in_packets * pscale`.
// The cast is in the C; the precision loss is the
// C's. Display-only.
fn render_row(name: &str, s: &NodeStats, stats: &Stats, row: u16) -> String {
    // ─── Attribute
    // `top.c:264-269`. The C's nested `if` is awkward to read
    // (`if known if rate BOLD else NORMAL else DIM`); the table
    // form is clearer.
    //
    // `clippy::float_cmp`: comparing to literal 0.0 is fine here.
    // The rates ARE 0.0 when nothing happened (`0u64 as f32 /
    // interval == 0.0`, exact). Any nonzero delta gives a nonzero
    // rate (interval is finite positive). No epsilon needed.
    #[allow(clippy::float_cmp)]
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
    // `top.c:271-277`. `%10.0f` × 4. Order is `in_pkts, in_bytes,
    // out_pkts, out_bytes` — same in both branches.
    //
    // `{x:>10.0}` is `%10.0f`. `:>10` is right-align width 10
    // (printf `%10` is right-align by default). `.0` is precision
    // 0 (no decimal point — `%10.0f` of `1234.567` is `      1235`).
    //
    // Rust's `{:10.0}` for f32: width 10, precision 0. The default
    // alignment for numeric types in Rust formatting is RIGHT (same
    // as printf), so `{:10.0}` not `{:>10.0}`. But: explicit `>`
    // matches printf's behavior even if Rust ever changes the
    // default. Belt-and-suspenders, costs nothing.
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

/// Full screen, one frame. `top.c:237-280` `redraw()`. Returns the
/// whole thing as one String — caller `write!`s it in one syscall.
///
/// `top.c:238` `erase()` is replaced by per-line `CLEAR_EOL` (less
/// flicker without curses' double-buffer). Rows past `max_rows` are
/// clipped (`top.c:261`'s loop runs to `n`, curses clips silently;
/// we clip explicitly).
///
/// Called AFTER `Stats::sort()` — display_order is in render order.
///
/// `max_rows` is `winsize().rows`. Passed in (not queried here) so
/// tests can give a small value and assert the clip.
fn render(netname: Option<&str>, stats: &Stats, max_rows: u16) -> String {
    let mut s = String::with_capacity(4096);

    // Rows 0, 1, 2.
    s.push_str(&render_header(netname, stats));

    // ─── Body: rows 3..
    // `top.c:261-278`. The clip is the only thing curses gave us
    // for free.
    for (i, name) in stats.display_order.iter().enumerate() {
        // Row 3 is the first body row. `top.c:261`: `row = 3`.
        // `i` is `usize`; `3 + i` → `u16` would clamp at 65k rows.
        // Nobody has that many nodes. `try_from` to be precise
        // (the cast would silently wrap; this saturates by
        // breaking the loop).
        let Ok(row) = u16::try_from(3 + i) else { break };
        if row >= max_rows {
            break;
        }

        // The lookup is infallible (display_order is a subset of
        // nodes' keys, by construction in `update`). `unwrap_or_
        // default` for a zeroed-stats fallback (DIM, all 0s) —
        // reads as "this node is gone" if the invariant somehow
        // broke. Better than panic mid-draw. Same trick as `sort`.
        let entry = stats.nodes.get(name).cloned().unwrap_or_default();
        s.push_str(&render_row(name, &entry, stats, row));
    }

    // ─── Clear rows past current body
    // The C's `erase()` clears the whole screen up front. We do
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

    // `top.c:279`: `move(1, 0)`. The cursor park. We've hidden the
    // cursor so this doesn't matter visually, but the `'s'`-key
    // prompt's `mvprintw(1, 0, ...)` will start there. The header
    // already cleared row 1; no further action.

    s
}

// Layer 4: I/O — fetch one dump

/// `update()` first half: `top.c:71-73` (sendline) + `top.c:94-132`
/// (recvline loop), MINUS the merge (which is `Stats::update`).
///
/// Returns the rows; caller passes them to `Stats::update`. This
/// split makes `Stats::update` testable without a socket.
///
/// # Errors
/// `CtlError::Io` if the socket dies mid-dump (daemon crashed).
/// `CtlError::Parse` if a row is malformed (`top.c:102`: `n != 7`).
/// Both end the `top` loop (`top.c:291`: `if(!update(fd)) break`).
fn fetch<S: io::Read + io::Write>(ctl: &mut CtlSocket<S>) -> Result<Vec<TrafficRow>, CtlError> {
    // `top.c:71`: `sendline(fd, "%d %d", CONTROL, REQ_DUMP_TRAFFIC)`.
    // No third arg (compare info.c's dead third arg) — DUMP_TRAFFIC
    // is one of the dumps that doesn't pretend to filter.
    ctl.send(CtlRequest::DumpTraffic)?;

    // `top.c:94-103`. recv loop, terminator detect, parse. The C
    // does the merge inline; we collect and return. The vec
    // preallocation guess: a typical mesh has 10-100 nodes. 32 is
    // fine for the common case, growth handles outliers.
    let mut rows = Vec::with_capacity(32);
    loop {
        match ctl.recv_row()? {
            DumpRow::End(_) => return Ok(rows),
            DumpRow::Row(_, body) => {
                // `top.c:102`: `if(n != 7) return false`. Parse
                // failure ends the whole top session — the daemon's
                // sending garbage, no point continuing.
                //
                // `CtlError` has no Parse variant. The other dump
                // commands return `CmdError::BadInput` directly
                // (their callers don't sit in a loop). Here the
                // caller IS a loop, and the C's behavior is
                // silent exit (`top.c:291`: `if(!update) break`,
                // no message). We match: `Io(InvalidData)` carries
                // the body in the message but `run()` ignores the
                // error anyway (`Err(_) => break`). The variant
                // choice doesn't matter for behavior; `Io` is the
                // "daemon I/O went bad" bucket and a malformed row
                // is daemon I/O going bad.
                let row = TrafficRow::parse(&body).map_err(|_| {
                    CtlError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("malformed traffic row from daemon: {body}"),
                    ))
                })?;
                rows.push(row);
            }
        }
    }
}

// Layer 5: keys — `top.c:296-370` switch

/// `top.c:296-370`. Mutates `stats` per the key. Returns `false`
/// for `'q'` (the `running = false` case, `top.c:364`).
///
/// The `'s'` key (`top.c:301-313`) prompts for new delay. Needs
/// cooked-mode line input. `RawMode::with_cooked` does the dance.
/// Returns `Err` if the cooked-mode tcsetattr fails (terminal in
/// weird state); caller breaks the loop and Drop restores.
///
/// `default: break` (`top.c:368`) is "ignore unknown key". `getch_
/// timeout` returning `None` (timeout, no key) is handled by the
/// caller, not here.
///
/// `raw` is `&RawMode` not `&mut` — `with_cooked` takes `&self`
/// (it doesn't mutate the stored original termios).
///
/// `out` is where the prompt gets written. stdout in real use;
/// `Vec<u8>` in tests.
#[allow(clippy::too_many_lines)] // 13 single-line match arms + the 's' case.
// `top.c:296-370` is 75 lines. Same fanout.
fn handle_key(
    key: u8,
    stats: &mut Stats,
    raw: &tui::RawMode,
    out: &mut impl Write,
) -> io::Result<bool> {
    match key {
        // ─── 's': change delay
        // `top.c:301-313`. The one INTERACTIVE key. `timeout(-1)`
        // (block forever) → prompt → `scanw("%f")` → clamp →
        // `timeout(delay)`. We don't have `scanw`; `with_cooked`
        // restores echo+canon, `read_line`, parse `f32`.
        //
        // The C reads into `input` initialized to the CURRENT delay
        // (`top.c:303`: `float input = (float)delay * 1e-3f`). If
        // `scanw` fails to parse (non-numeric input), `input`
        // retains the initial value — net effect "no change". We do
        // the same: parse failure → keep current delay.
        b's' => {
            let current_secs = f32::from(stats.delay_ms) * 1e-3;

            // `top.c:304`: `mvprintw(1, 0, "Change delay from
            // %.1fs to: ", input)`. Row 1 is the parked-cursor
            // row. `goto(1,0)` + the message. `with_cooked` will
            // re-show the cursor.
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
            // → None → keep current. The C's `scanw` doesn't tell
            // you it failed; `input` just isn't written.
            let new_secs: Option<f32> = raw.with_cooked(|stdin| {
                let mut line = String::new();
                stdin.read_line(&mut line)?;
                Ok(line.trim().parse::<f32>().ok())
            })?;

            // `top.c:307-309`: `if(input < 0.1) input = 0.1f`.
            // Clamp BEFORE storing. NaN doesn't satisfy `< 0.1`
            // (NaN comparisons are false), so a NaN input would
            // pass through... but `parse::<f32>` rejects "nan"
            // (it's not in the grammar), so NaN can't get here.
            // Infinity DOES parse (`"inf".parse::<f32>()` →
            // `Ok(inf)`). `inf * 1000 → inf`, `inf as u16 →`
            // ... undefined in C, saturating in Rust. So inf
            // gives `delay_ms = 65535`. ~65s tick. Harmless.
            //
            // ACTUALLY checking: Rust `f32 as u16` for out-of-
            // range is saturating since 1.45 (well-defined). C
            // `(int)(float)` for out-of-range is UB. So we're
            // STRICTER than C here (we don't UB on `inf` input).
            // Fine.
            if let Some(input) = new_secs {
                let clamped = if input < 0.1 { 0.1 } else { input };
                // `top.c:310`: `delay = (int)(input * 1e3f)`.
                // f32 → integer cast. Saturating in Rust.
                #[allow(clippy::cast_possible_truncation)] // The C's `(int)`. We saturate;
                #[allow(clippy::cast_sign_loss)] // C is UB. clamped >= 0.1 so
                // it's positive anyway.
                {
                    stats.delay_ms = (clamped * 1e3) as u16;
                }
            }
            // The C: `timeout(delay)` (`top.c:311`). That's curses'
            // input-timeout setter. Our `getch_timeout(stats.
            // delay_ms)` reads `delay_ms` fresh each tick — no
            // separate set call needed.

            Ok(true)
        }

        // ─── 'c': toggle cumulative
        // `top.c:316`.
        b'c' => {
            stats.cumulative = !stats.cumulative;
            Ok(true)
        }

        // ─── Sort mode keys
        // `top.c:308-332`. lowercase → bytes (the heavier metric);
        // uppercase → packets.
        b'n' => {
            stats.sort_mode = SortMode::Name;
            Ok(true)
        }
        b'i' => {
            stats.sort_mode = SortMode::InBytes;
            Ok(true)
        }
        b'I' => {
            stats.sort_mode = SortMode::InPackets;
            Ok(true)
        }
        b'o' => {
            stats.sort_mode = SortMode::OutBytes;
            Ok(true)
        }
        b'O' => {
            stats.sort_mode = SortMode::OutPackets;
            Ok(true)
        }
        b't' => {
            stats.sort_mode = SortMode::TotalBytes;
            Ok(true)
        }
        b'T' => {
            stats.sort_mode = SortMode::TotalPackets;
            Ok(true)
        }

        // ─── Unit/scale keys
        // `top.c:336-360`. Four presets. `b`/`k` keep packets at
        // 1×, only `M`/`G` scale packets too. The header strings
        // are 4-5 chars: `pkts`/`kpkt`/`Mpkt`, `bytes`/`kbyte`/
        // `Mbyte`/`Gbyte`. The C picked widths that fit `%s` in
        // the header without overflowing — we match.
        b'b' => {
            stats.bunit = "bytes";
            stats.bscale = 1.0;
            stats.punit = "pkts";
            stats.pscale = 1.0;
            Ok(true)
        }
        b'k' => {
            stats.bunit = "kbyte";
            stats.bscale = 1e-3;
            stats.punit = "pkts";
            stats.pscale = 1.0;
            Ok(true)
        }
        b'M' => {
            stats.bunit = "Mbyte";
            stats.bscale = 1e-6;
            stats.punit = "kpkt";
            stats.pscale = 1e-3;
            Ok(true)
        }
        b'G' => {
            stats.bunit = "Gbyte";
            stats.bscale = 1e-9;
            stats.punit = "Mpkt";
            stats.pscale = 1e-6;
            Ok(true)
        }

        // ─── 'q': quit
        // `top.c:363-364`. `KEY_BREAK` is curses' Windows-console
        // Ctrl-Break thing; we're cfg(unix), don't have it.
        b'q' => Ok(false),

        // ─── default: ignore
        // `top.c:368`. Unknown key, including arrow-key escape
        // sequences (we'd see `\x1b` then `[` then `A` etc as
        // separate ticks — the loop is fast enough that the user
        // doesn't notice three "ignored key" cycles). The C has
        // the same behavior: curses would give `KEY_UP` for
        // `keypad(TRUE)`, but `top.c` doesn't call `keypad()`,
        // so curses gives raw escape bytes too. Same.
        _ => Ok(true),
    }
}

// Layer 6: the loop — `top()` itself

/// `top.c:283-372`. The whole thing. Connect, enter raw, loop,
/// exit cleanly.
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
    // `tincctl.c:1506`: `if(!connect_tincd(true)) return 1`.
    // BEFORE entering raw mode — if connect fails the error
    // message goes to a sane terminal.
    let mut ctl = CtlSocket::connect(paths).map_err(daemon_err)?;

    // ─── Raw mode
    // `top.c:284`: `initscr()`. RawMode's Drop is `endwin()`
    // (`top.c:372`). The Drop fires on panic too, which curses'
    // `endwin()` doesn't (the C panics → terminal stays raw).
    // We're better there.
    //
    // `top.c:285`: `timeout(delay)`. That's curses' input-timeout
    // setter; we pass `delay_ms` to `getch_timeout` per-call instead.
    let raw = tui::RawMode::enter()
        .map_err(|e| CmdError::BadInput(format!("cannot enter raw mode: {e}")))?;

    let mut stats = Stats::default();
    let mut stdout = io::stdout().lock();

    // ─── Loop
    // `top.c:288-370`: `while(running) { update; redraw; switch
    // (getch()) }`.
    //
    // `top.c:289-291`: `if(!update(fd)) break`. Daemon died mid-
    // dump → exit cleanly. `while let Ok` does exactly that: Err
    // exits the loop. SILENT exit — the C doesn't print a message
    // either. The daemon went away; the user sees the prompt again.
    //
    // `fetch` blocks until the daemon responds. The daemon's
    // `dump_traffic` is a tight loop over `node_tree` (`node.c
    // :226`), fast. If the daemon hangs (doesn't happen in
    // practice — control thread is single-purpose), we hang too.
    // Same as C. No timeout.
    while let Ok(rows) = fetch(&mut ctl) {
        stats.update(&rows, Instant::now());

        // `top.c:293`: `redraw()`. Sort then render. `winsize()`
        // each frame so terminal-resize is live (one-tick lag,
        // since we don't catch SIGWINCH; the C doesn't either —
        // curses' `getmaxyx` reads the current size, but `top.c`
        // never CALLS `getmaxyx`; the clipping is curses-implicit).
        stats.sort();
        let frame = render(netname, &stats, tui::winsize().rows);
        // One syscall per frame. No flicker between header and body.
        // Ignore write errors (stdout closed → next iteration's
        // write also fails → we'll notice on getch_timeout via
        // EOF → 'q'). C `refresh()` doesn't error either.
        let _ = stdout.write_all(frame.as_bytes());
        let _ = stdout.flush();

        // `top.c:296`: `switch(getch())`. `getch` with `timeout(
        // delay)` blocks for `delay` ms then returns `ERR`. Our
        // `getch_timeout` does the same (`None` on timeout).
        //
        // `getch_timeout` errors (poll/read failure other than
        // EINTR) → break. Shouldn't happen (stdin is a tty we
        // already validated). The C's `getch` returns `ERR` on
        // error too, indistinguishable from timeout — the C would
        // spin. We break instead (better than spin).
        match tui::getch_timeout(stats.delay_ms) {
            Ok(None) => {} // timeout, next tick
            Ok(Some(key)) => {
                // `top.c:296-369`. `handle_key` returns `false`
                // for `'q'`. The `?` propagates with_cooked's
                // tcsetattr failure (terminal weird; bail; Drop
                // restores).
                if !handle_key(key, &mut stats, &raw, &mut stdout)
                    .map_err(|e| CmdError::BadInput(format!("terminal I/O: {e}")))?
                {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    // `top.c:372`: `endwin()`. RawMode's Drop. Explicit `drop` for
    // clarity (it'd run anyway at scope end, but we want it BEFORE
    // returning Ok — if anything below printed to stdout it'd be on
    // a sane terminal). Nothing's below, but the explicit drop
    // documents the order.
    drop(raw);
    drop(stdout);

    Ok(())
}

/// Re-declared (modules independent). `dump.rs`, `info.rs`,
/// `ctl_simple.rs` each have their own.
#[allow(clippy::needless_pass_by_value)]
fn daemon_err(e: CtlError) -> CmdError {
    CmdError::BadInput(e.to_string())
}

// Tests
//
// Four layers of tests, matching the module structure:
//
// 1. `TrafficRow::parse` against the `node.c:228` printf format.
//    The seam.
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
mod tests {
    use super::*;

    // SORTNAME table — sed-verifiable vs `top.c:48-56`
    //
    // `sed -n '48,56p' src/top.c | grep '"'` extracts the string
    // literals. Hand-verify at commit time. The test pins the
    // EXPECTED values so a typo in the table is caught.

    #[test]
    fn sortname_matches_top_c() {
        assert_eq!(SORTNAME[SortMode::Name as usize], "name");
        assert_eq!(SORTNAME[SortMode::InPackets as usize], "in pkts");
        assert_eq!(SORTNAME[SortMode::InBytes as usize], "in bytes");
        assert_eq!(SORTNAME[SortMode::OutPackets as usize], "out pkts");
        assert_eq!(SORTNAME[SortMode::OutBytes as usize], "out bytes");
        assert_eq!(SORTNAME[SortMode::TotalPackets as usize], "tot pkts");
        assert_eq!(SORTNAME[SortMode::TotalBytes as usize], "tot bytes");
    }

    // TrafficRow::parse — the wire seam

    /// `node.c:228`: `"%d %d %s %"PRIu64" %"PRIu64" %"PRIu64"
    /// %"PRIu64`. After `recv_row` strips `"18 13 "`, we see
    /// `"NAME N N N N"`. Straightforward.
    #[test]
    fn parse_basic() {
        let r = TrafficRow::parse("alice 100 50000 200 100000").unwrap();
        assert_eq!(r.name, "alice");
        assert_eq!(r.in_packets, 100);
        assert_eq!(r.in_bytes, 50000);
        assert_eq!(r.out_packets, 200);
        assert_eq!(r.out_bytes, 100_000);
    }

    /// `top.c:96` `%"PRIu64"`. Max value. The daemon won't send
    /// this (you'd need 18 exabytes of traffic) but the format
    /// supports it.
    #[test]
    fn parse_u64_max() {
        let r = TrafficRow::parse("bob 18446744073709551615 0 0 0").unwrap();
        assert_eq!(r.in_packets, u64::MAX);
    }

    /// `top.c:102`: `if(n != 7) return false`. Short row.
    #[test]
    fn parse_short_fails() {
        assert!(TrafficRow::parse("alice 100 50000 200").is_err());
    }

    /// `Tok` doesn't enforce end-of-string. `top.c:96`'s sscanf
    /// doesn't either (counts conversions, not consumption). A
    /// future daemon adding fields wouldn't break us.
    #[test]
    fn parse_ignores_trailing() {
        let r = TrafficRow::parse("alice 1 2 3 4 future_field 999").unwrap();
        assert_eq!(r.out_bytes, 4);
    }

    /// Non-numeric in a numeric slot. `top.c:96`'s sscanf would
    /// stop at the bad token, return n<7, fail. We fail too.
    #[test]
    fn parse_non_numeric_fails() {
        assert!(TrafficRow::parse("alice 100 fifty_thousand 200 100000").is_err());
    }

    // Stats::update — the merge + rate machine

    /// `Instant` doesn't have a constructor for "epoch + N seconds";
    /// the only way to make one is `Instant::now()`. Tests need
    /// deterministic instants `dt` apart. `Instant::now()` once,
    /// then add `Duration`s. The ABSOLUTE value doesn't matter
    /// (Instant is monotonic, opaque); only the DIFFERENCES do.
    fn t0() -> Instant {
        // Memoized via static-with-init-once would be cleaner but
        // `Instant::now()` is monotonic so two calls ordered by
        // `now()` then `now() + dt` always give `dt`. The test
        // body calls this once, stores it, adds Durations.
        Instant::now()
    }

    fn row(name: &str, ip: u64, ib: u64, op: u64, ob: u64) -> TrafficRow {
        TrafficRow {
            name: name.into(),
            in_packets: ip,
            in_bytes: ib,
            out_packets: op,
            out_bytes: ob,
        }
    }

    /// First tick: `prev_instant` is None, interval is epoch-seconds.
    /// `top.c:62` `static struct timeval prev` zero-init. `top.c:77`
    /// subtracts {0,0}. Rate = counter / ~1.7e9, basically 0.
    ///
    /// We assert "small" not "exactly 0" because (a) the epoch-
    /// seconds value depends on when the test runs (it grows by 1
    /// every second), and (b) f32 precision. `1000 / 1.7e9 ≈ 6e-7`,
    /// well under 0.001.
    #[test]
    fn first_tick_rate_is_near_zero() {
        let mut s = Stats::default();
        let changed = s.update(&[row("alice", 1000, 500_000, 2000, 1_000_000)], t0());

        assert!(changed); // new node
        let alice = &s.nodes["alice"];
        assert!(alice.known);
        // Counters stored verbatim.
        assert_eq!(alice.in_packets, 1000);
        // Rate is counter / epoch-seconds. Tiny.
        assert!(alice.in_packets_rate < 0.001);
        assert!(alice.in_packets_rate >= 0.0);
    }

    /// Second tick, 1s later. Rate = delta / 1.0. THE useful case.
    /// `top.c:125-128`.
    #[test]
    fn second_tick_rate_is_delta_over_dt() {
        let mut s = Stats::default();
        let base = t0();

        // Tick 1: counter = 1000.
        s.update(&[row("alice", 1000, 500_000, 2000, 1_000_000)], base);

        // Tick 2: counter = 1100, dt = 1s. Rate should be 100.
        let changed = s.update(
            &[row("alice", 1100, 550_000, 2200, 1_100_000)],
            base + Duration::from_secs(1),
        );

        assert!(!changed); // existing node, no topology change
        let alice = &s.nodes["alice"];
        // `(1100 - 1000) / 1.0 = 100.0`. f32 is exact for small
        // integers.
        #[allow(clippy::float_cmp)]
        {
            assert_eq!(alice.in_packets_rate, 100.0);
            assert_eq!(alice.in_bytes_rate, 50000.0);
            assert_eq!(alice.out_packets_rate, 200.0);
            assert_eq!(alice.out_bytes_rate, 100_000.0);
        }
    }

    /// Half-second tick. Rate = delta / 0.5 = 2 × delta.
    /// `top.c:79` `interval` is float seconds, sub-second works.
    #[test]
    fn fractional_dt() {
        let mut s = Stats::default();
        let base = t0();
        s.update(&[row("alice", 1000, 0, 0, 0)], base);
        s.update(
            &[row("alice", 1050, 0, 0, 0)],
            base + Duration::from_millis(500),
        );
        let alice = &s.nodes["alice"];
        // `(1050 - 1000) / 0.5 = 100.0`.
        #[allow(clippy::float_cmp)]
        {
            assert_eq!(alice.in_packets_rate, 100.0);
        }
    }

    /// `top.c:90-92`: `known` cleared on every entry, set true
    /// on rows present. A node missing from tick 2's dump stays
    /// in the map with known=false.
    #[test]
    fn departed_node_stays_dim() {
        let mut s = Stats::default();
        let base = t0();

        // Tick 1: alice + bob.
        s.update(
            &[row("alice", 100, 0, 0, 0), row("bob", 200, 0, 0, 0)],
            base,
        );
        assert!(s.nodes["alice"].known);
        assert!(s.nodes["bob"].known);

        // Tick 2: alice only. bob departs.
        s.update(&[row("alice", 110, 0, 0, 0)], base + Duration::from_secs(1));
        assert!(s.nodes["alice"].known);
        assert!(!s.nodes["bob"].known); // ← THE assertion
        assert_eq!(s.nodes.len(), 2); // never shrinks
        assert_eq!(s.display_order.len(), 2); // also never shrinks
    }

    /// `top.c:125`: u64 - u64 wraps on counter decrease (daemon
    /// restart). `wrapping_sub`. The spike is the C's behavior.
    #[test]
    fn counter_decrease_wraps() {
        let mut s = Stats::default();
        let base = t0();
        s.update(&[row("alice", 1000, 0, 0, 0)], base);
        // Daemon restarted, counter reset to 5.
        s.update(&[row("alice", 5, 0, 0, 0)], base + Duration::from_secs(1));
        let alice = &s.nodes["alice"];
        // `5u64.wrapping_sub(1000) = u64::MAX - 994`. As f32 over
        // 1.0 sec → very large. We just assert "large", not the
        // exact value (f32 precision at 1.8e19 is ~1e12).
        assert!(alice.in_packets_rate > 1e18);
    }

    /// `display_order` is append-only and reflects ARRIVAL order,
    /// not name order. The BTreeMap sorts; the Vec doesn't. The
    /// C's `static nodestats_t **sorted` rebuild (`top.c:243-250`)
    /// iterates `node_list` which IS name-sorted, so the C's
    /// initial display_order IS name-sorted... but ours isn't,
    /// and that's fine because the immediately-following `sort()`
    /// reorders it anyway. The Vec's job is to PERSIST order
    /// across sorts (stability), not to BE sorted on its own.
    #[test]
    fn display_order_is_arrival_order_not_name_order() {
        let mut s = Stats::default();
        let base = t0();
        // bob arrives before alice (reverse name order).
        s.update(&[row("bob", 0, 0, 0, 0), row("alice", 0, 0, 0, 0)], base);
        assert_eq!(s.display_order, vec!["bob", "alice"]);
        // Now sort by name.
        s.sort_mode = SortMode::Name;
        s.sort();
        assert_eq!(s.display_order, vec!["alice", "bob"]);
    }

    // compare — the 7-way comparator

    fn ns(ip: u64, ib: u64, op: u64, ob: u64) -> NodeStats {
        NodeStats {
            in_packets: ip,
            in_bytes: ib,
            out_packets: op,
            out_bytes: ob,
            ..Default::default()
        }
    }

    fn ns_rate(ipr: f32, ibr: f32, opr: f32, obr: f32) -> NodeStats {
        NodeStats {
            in_packets_rate: ipr,
            in_bytes_rate: ibr,
            out_packets_rate: opr,
            out_bytes_rate: obr,
            ..Default::default()
        }
    }

    /// `top.c:166-172` `case 1`. Descending — heavy first. The C's
    /// `result = -cmpu64(a, b)`: negative-of-compare flips order.
    /// `b.cmp(&a)` (args swapped) is the same.
    #[test]
    fn compare_in_packets_cumulative_descending() {
        use std::cmp::Ordering;
        let heavy = ns(1000, 0, 0, 0);
        let light = ns(100, 0, 0, 0);
        // Heavy comes BEFORE light → Less.
        assert_eq!(
            compare(&heavy, &light, SortMode::InPackets, true),
            Ordering::Less
        );
        assert_eq!(
            compare(&light, &heavy, SortMode::InPackets, true),
            Ordering::Greater
        );
    }

    /// Same mode, `cumulative=false` → use rate not counter.
    /// `top.c:170`: `-cmpfloat(a.rate, b.rate)`.
    #[test]
    fn compare_in_packets_rate_descending() {
        use std::cmp::Ordering;
        let fast = ns_rate(100.0, 0.0, 0.0, 0.0);
        let slow = ns_rate(10.0, 0.0, 0.0, 0.0);
        assert_eq!(
            compare(&fast, &slow, SortMode::InPackets, false),
            Ordering::Less
        );
    }

    /// `top.c:202-208` `case 5`: total = in + out. Sum then
    /// compare. The wrapping_add path is unreachable in practice
    /// (18 quintillion packets) but the modes are independent so
    /// we test the SUM logic.
    #[test]
    fn compare_total_packets_sums() {
        use std::cmp::Ordering;
        // a: 100 in + 50 out = 150 total.
        // b: 80 in + 80 out = 160 total. Heavier.
        let a = ns(100, 0, 50, 0);
        let b = ns(80, 0, 80, 0);
        assert_eq!(
            compare(&a, &b, SortMode::TotalPackets, true),
            Ordering::Greater // a is lighter, sorts after
        );
    }

    /// Equal primary key → Equal. The C's `na->i - nb->i` tiebreak
    /// is what `sort_by`'s stability gives us; `compare()` returns
    /// Equal and the stable sort preserves prior position.
    #[test]
    fn compare_equal_is_equal() {
        use std::cmp::Ordering;
        let a = ns(100, 0, 0, 0);
        let b = ns(100, 0, 0, 0);
        assert_eq!(compare(&a, &b, SortMode::InPackets, true), Ordering::Equal);
    }

    /// `Name` arm returns Equal — `Stats::sort` special-cases it.
    /// The arm exists for exhaustiveness.
    #[test]
    fn compare_name_is_equal_placeholder() {
        use std::cmp::Ordering;
        let a = ns(1, 2, 3, 4);
        let b = ns(5, 6, 7, 8);
        assert_eq!(compare(&a, &b, SortMode::Name, true), Ordering::Equal);
        assert_eq!(compare(&a, &b, SortMode::Name, false), Ordering::Equal);
    }

    /// THE stability test. Equal-key nodes stay in previous-frame
    /// order across re-sort. The C's `i` trick.
    ///
    /// Setup: alice, bob, carol all at rate 0.0 (tied). Sort by
    /// `InBytes` (rate, descending). Initial display_order is
    /// arrival order. Re-sort → unchanged (Equal everywhere,
    /// stable sort = identity). Shuffle display_order, re-sort
    /// → unchanged from the SHUFFLE (stable sort with all-Equal
    /// is identity, the shuffle persists). That's the property:
    /// the prior order IS the tiebreak.
    #[test]
    fn sort_stability_preserves_prior_order() {
        let mut s = Stats::default();
        let base = t0();
        s.update(
            &[
                row("alice", 0, 0, 0, 0),
                row("bob", 0, 0, 0, 0),
                row("carol", 0, 0, 0, 0),
            ],
            base,
        );
        s.sort_mode = SortMode::InBytes;
        s.cumulative = false; // rate mode

        // All rates are ~0 (first tick, epoch-seconds interval),
        // and equal (all from counter 0). Tied.
        // Arrival order: alice, bob, carol.
        s.sort();
        assert_eq!(s.display_order, vec!["alice", "bob", "carol"]);

        // Manually permute. (Simulating "carol was heaviest last
        // frame, sorted to top, then traffic stopped, all tied
        // again".)
        s.display_order = vec!["carol".into(), "alice".into(), "bob".into()];
        s.sort();
        // Stable sort + all Equal → identity.
        assert_eq!(s.display_order, vec!["carol", "alice", "bob"]);
    }

    /// One node breaks the tie. Heavier sorts first; the rest stay
    /// in prior relative order. The realistic case.
    #[test]
    fn sort_stability_with_one_tiebreak() {
        let mut s = Stats::default();
        let base = t0();
        s.update(
            &[
                row("alice", 0, 0, 0, 0),
                row("bob", 0, 0, 0, 0),
                row("carol", 0, 0, 0, 0),
            ],
            base,
        );
        // Tick 2: bob gets traffic.
        s.update(
            &[
                row("alice", 0, 0, 0, 0),
                row("bob", 0, 5000, 0, 0),
                row("carol", 0, 0, 0, 0),
            ],
            base + Duration::from_secs(1),
        );
        s.sort_mode = SortMode::InBytes;
        s.cumulative = false;
        s.sort();
        // bob heaviest → first. alice/carol tied → arrival order
        // (alice before carol) preserved.
        assert_eq!(s.display_order, vec!["bob", "alice", "carol"]);
    }

    /// `Stats::sort` Name mode is a SEPARATE code path (not via
    /// `compare`). Ascending strcmp.
    #[test]
    fn sort_name_is_ascending() {
        let mut s = Stats::default();
        let base = t0();
        s.update(
            &[
                row("carol", 0, 0, 0, 0),
                row("alice", 0, 0, 0, 0),
                row("bob", 0, 0, 0, 0),
            ],
            base,
        );
        s.sort_mode = SortMode::Name;
        s.sort();
        assert_eq!(s.display_order, vec!["alice", "bob", "carol"]);
    }

    // render_* — golden ANSI strings
    //
    // We assert WITH the escape codes inline. Stripping them would
    // miss the attribute logic (BOLD/DIM/NORMAL). The codes are
    // string constants; embedding them in expected output is fine.

    /// `top.c:240`: `"Tinc %-16s  Nodes: %4d  Sort: %-10s  %s"`.
    /// Golden the row-0 portion. We can't easily golden row 2
    /// (the REVERSE/CLEAR_EOL combo) without making the test
    /// brittle to exact escape-sequence form, but the row-0 text
    /// is plain.
    ///
    /// `goto(0,0)` is `"\x1b[1;1H"`. Then the body. Then CLEAR_EOL
    /// `"\x1b[K"`.
    #[test]
    fn render_header_row0_golden() {
        let stats = Stats::default(); // 0 nodes, name sort, current
        let h = render_header(Some("vpn"), &stats);

        // Extract row 0 (up to row 1's goto). The `goto(1, 0)` is
        // `\x1b[2;1H` (1-indexed). Split on it.
        let row0_end = h.find("\x1b[2;1H").unwrap();
        let row0 = &h[..row0_end];

        assert_eq!(
            row0,
            // `goto(0,0)` + body + `CLEAR_EOL`. `vpn` left-padded to
            // 16. `0` right-padded to 4. `name` left-padded to 10.
            // TWO spaces between fields (the C literal).
            "\x1b[1;1HTinc vpn               Nodes:    0  Sort: name        Current\x1b[K"
        );
    }

    /// `netname=None` → empty (`top.c:240`: `netname ? netname :
    /// ""`). `%-16s` of empty is 16 spaces.
    #[test]
    fn render_header_no_netname() {
        let stats = Stats::default();
        let h = render_header(None, &stats);
        // After `Tinc ` (5 chars): 16 spaces, then `  Nodes`.
        // `"\x1b[1;1HTinc " + " "*16 + "  Nodes:..."`.
        assert!(h.starts_with("\x1b[1;1HTinc                   Nodes:"));
    }

    /// Row 2: column headers. `top.c:242`. We golden the TEXT
    /// (between the SGR codes); the REVERSE wrapper is checked
    /// for presence.
    #[test]
    fn render_header_row2_text() {
        let stats = Stats::default(); // bunit=bytes, punit=pkts
        let h = render_header(None, &stats);

        // The text between `\x1b[7m` (REVERSE) and `\x1b[K`
        // (CLEAR_EOL). `top.c:242` literal.
        assert!(h.contains(
            "\x1b[7mNode                IN pkts   IN bytes   OUT pkts  OUT bytes\x1b[K\x1b[0m"
        ));
    }

    /// `top.c:264-269` attribute logic. The three-way table.
    #[test]
    fn render_row_attribute_logic() {
        let stats = Stats::default();

        // ─── Gone: known=false → DIM
        let gone = NodeStats {
            known: false,
            ..Default::default()
        };
        let r = render_row("alice", &gone, &stats, 3);
        assert!(r.contains("\x1b[2m")); // DIM
        assert!(!r.contains("\x1b[1m")); // not BOLD

        // ─── Idle: known=true, rate=0 → no SGR (NORMAL)
        let idle = NodeStats {
            known: true,
            ..Default::default()
        };
        let r = render_row("bob", &idle, &stats, 3);
        assert!(!r.contains("\x1b[2m")); // not DIM
        assert!(!r.contains("\x1b[1m")); // not BOLD

        // ─── Active: known=true, in_packets_rate > 0 → BOLD
        let active = NodeStats {
            known: true,
            in_packets_rate: 100.0,
            ..Default::default()
        };
        let r = render_row("carol", &active, &stats, 3);
        assert!(r.contains("\x1b[1m")); // BOLD

        // ─── Out only: known=true, out_packets_rate > 0 → BOLD
        // `top.c:265`: `||` of in OR out.
        let out_only = NodeStats {
            known: true,
            out_packets_rate: 50.0,
            ..Default::default()
        };
        let r = render_row("dave", &out_only, &stats, 3);
        assert!(r.contains("\x1b[1m")); // BOLD

        // ─── Bytes-only nonzero → NORMAL
        // `top.c:265` checks PACKETS rate, not bytes. The C
        // probably figured "nonzero bytes implies nonzero packets"
        // (true for real traffic). But synthetic stats can have
        // bytes!=0, packets==0 (impossible in nature, possible
        // here). Test that we replicate C's check, not the
        // "obvious" check.
        let bytes_only = NodeStats {
            known: true,
            in_bytes_rate: 1000.0,
            ..Default::default() // in_packets_rate=0
        };
        let r = render_row("eve", &bytes_only, &stats, 3);
        assert!(!r.contains("\x1b[1m")); // NOT bold — packets check
    }

    /// `top.c:273`: `"%-16s %10.0f %10.0f %10.0f %10.0f"`. Golden
    /// the column layout. `%10.0f` rounds half-to-even (printf's
    /// default); Rust `{:.0}` rounds half-to-even too (since 1.0).
    #[test]
    fn render_row_column_layout() {
        let stats = Stats::default();
        let n = NodeStats {
            known: true,
            in_packets_rate: 12.0,
            in_bytes_rate: 6789.0,
            out_packets_rate: 34.0,
            out_bytes_rate: 12345.0,
            ..Default::default()
        };
        let r = render_row("alice", &n, &stats, 5);
        // `goto(5,0)` = `\x1b[6;1H`. BOLD (active). Then the body.
        // `alice` left-padded to 16. Four `%10.0f`. CLEAR_EOL+RESET.
        assert_eq!(
            r,
            "\x1b[6;1H\x1b[1malice                    12       6789         34      12345\x1b[K\x1b[0m"
        );
    }

    /// `cumulative=true` uses counters × scale, not rates. `top.c
    /// :273-274`. Scale is `bscale`/`pscale`.
    #[test]
    fn render_row_cumulative() {
        let stats = Stats {
            cumulative: true,
            ..Stats::default()
        };
        let n = NodeStats {
            known: false, // DIM — dead nodes still show counters
            in_packets: 100,
            in_bytes: 50000,
            out_packets: 200,
            out_bytes: 100_000,
            ..Default::default()
        };
        let r = render_row("bob", &n, &stats, 3);
        assert!(r.contains("\x1b[2m")); // DIM
        // Counters at scale 1.0. `bob` left-16, then 100/50000/200/100000.
        assert!(r.contains("bob                     100      50000        200     100000"));
    }

    /// `'k'` scale: bytes/1000. `top.c:345`: `bscale = 1e-3f`.
    /// 50000 × 0.001 = 50.
    #[test]
    fn render_row_kilo_scale() {
        let stats = Stats {
            cumulative: true,
            bscale: 1e-3, // the 'k' key
            ..Stats::default()
        };
        let n = NodeStats {
            in_packets: 100,
            in_bytes: 50000,
            ..Default::default()
        };
        let r = render_row("x", &n, &stats, 3);
        // bytes column shows 50 (50000 × 1e-3). packets unscaled.
        assert!(r.contains("       100         50"));
    }

    /// `render` clips at `max_rows`. The explicit-clip replacing
    /// curses' implicit `mvprintw`-past-LINES no-op.
    #[test]
    fn render_clips_at_max_rows() {
        let mut stats = Stats::default();
        let base = t0();
        // 10 nodes.
        let rows: Vec<_> = (0..10)
            .map(|i| row(&format!("node{i:02}"), 0, 0, 0, 0))
            .collect();
        stats.update(&rows, base);

        // max_rows=6: header is rows 0-2, body is rows 3-5 = 3 nodes.
        let frame = render(None, &stats, 6);
        // First 3 in display_order present.
        assert!(frame.contains("node00"));
        assert!(frame.contains("node01"));
        assert!(frame.contains("node02"));
        // Clipped.
        assert!(!frame.contains("node03"));
        assert!(!frame.contains("node09"));
    }

    // handle_key — the trivial state-mutation arms
    //
    // The 's' key needs `RawMode` (real tty); skip. All others are
    // pure mutation. We test them as a TABLE: `(key, expected_
    // mutation)`. The mutation is checked by inspecting `stats`
    // after.
    //
    // PROBLEM: `handle_key` takes `&RawMode`, which we can't
    // construct in a test (no tty). The non-'s' arms don't TOUCH
    // `raw`, but the signature requires it.
    //
    // Options:
    //   - Dummy RawMode. Can't — RawMode has no constructor that
    //     skips tcgetattr.
    //   - Separate `handle_key_no_tty` for the trivial arms,
    //     `handle_s` for the prompt. Ugly split for testability.
    //   - Don't test `handle_key`; the arms are one-liners. Test
    //     the THINGS they mutate (sort_mode, cumulative) via the
    //     state-machine tests above.
    //
    // Going with option 3. The key→mutation mapping is sed-
    // verifiable against `top.c:308-360` (single-line arms,
    // grep-able). The MUTATIONS are tested above. The mapping
    // is the integration test's job (against fake daemon, send
    // 'i', assert sort changed).

    /// `top.c:308-332`: key → sortmode. sed-verify the table.
    /// We can't run handle_key (RawMode), but we CAN assert the
    /// SortMode discriminants match what the C assigns. Same
    /// pattern as `info.rs`'s status-bit verification.
    #[test]
    fn sortmode_discriminants_match_top_c() {
        // sed -n '328,353p' src/top.c | grep -E "case|mode"
        // `top.c:329`: `case 'n': sortmode = 0`.
        assert_eq!(SortMode::Name as u8, 0);
        // `top.c:337`: `case 'I': sortmode = 1`.
        assert_eq!(SortMode::InPackets as u8, 1);
        // `top.c:333`: `case 'i': sortmode = 2`.
        assert_eq!(SortMode::InBytes as u8, 2);
        // `top.c:345`: `case 'O': sortmode = 3`.
        assert_eq!(SortMode::OutPackets as u8, 3);
        // `top.c:341`: `case 'o': sortmode = 4`.
        assert_eq!(SortMode::OutBytes as u8, 4);
        // `top.c:353`: `case 'T': sortmode = 5`.
        assert_eq!(SortMode::TotalPackets as u8, 5);
        // `top.c:349`: `case 't': sortmode = 6`.
        assert_eq!(SortMode::TotalBytes as u8, 6);
    }
}
