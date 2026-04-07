use super::*;

// TrafficRow::parse — the wire seam

/// Daemon sends `"NAME N N N N"` after `recv_row` strips
/// `"18 13 "`.
#[test]
fn parse_traffic_row() {
    // Basic.
    let r = TrafficRow::parse("alice 100 50000 200 100000").unwrap();
    assert_eq!(r.name, "alice");
    assert_eq!(r.in_packets, 100);
    assert_eq!(r.in_bytes, 50000);
    assert_eq!(r.out_packets, 200);
    assert_eq!(r.out_bytes, 100_000);

    // Max value. Daemon won't send this (18 exabytes of traffic)
    // but the format supports it.
    let r = TrafficRow::parse("bob 18446744073709551615 0 0 0").unwrap();
    assert_eq!(r.in_packets, u64::MAX);

    // `Tok` doesn't enforce end-of-string. A future daemon
    // adding fields wouldn't break us.
    let r = TrafficRow::parse("alice 1 2 3 4 future_field 999").unwrap();
    assert_eq!(r.out_bytes, 4);

    // Err cases.
    for input in [
        // Short row.
        "alice 100 50000 200",
        // Non-numeric in numeric slot.
        "alice 100 fifty_thousand 200 100000",
    ] {
        assert!(TrafficRow::parse(input).is_err(), "input: {input:?}");
    }
}

// Stats::update — the merge + rate machine

/// `Instant` doesn't have a constructor for "epoch + N seconds";
/// the only way to make one is `Instant::now()`. Tests need
/// deterministic instants `dt` apart. `Instant::now()` once,
/// then add `Duration`s. The ABSOLUTE value doesn't matter
/// (Instant is monotonic, opaque); only the DIFFERENCES do.
fn t0() -> Instant {
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
/// Rate = counter / ~1.7e9, basically 0.
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
    #[allow(clippy::float_cmp)] // small int / 1.0 = exact f32; no epsilon needed
    {
        assert_eq!(alice.in_packets_rate, 100.0);
        assert_eq!(alice.in_bytes_rate, 50000.0);
        assert_eq!(alice.out_packets_rate, 200.0);
        assert_eq!(alice.out_bytes_rate, 100_000.0);
    }
}

/// Half-second tick. Rate = delta / 0.5 = 2 × delta.
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
    #[allow(clippy::float_cmp)] // 50 / 0.5 = exact f32 (both representable)
    {
        assert_eq!(alice.in_packets_rate, 100.0);
    }
}

/// `known` cleared on every entry, set true on rows present. A
/// node missing from tick 2's dump stays in the map with
/// known=false.
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

/// u64 - u64 wraps on counter decrease (daemon restart).
/// `wrapping_sub`. The spike is upstream's behavior.
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
/// not name order. The `BTreeMap` sorts; the Vec doesn't. The
/// Vec's job is to PERSIST order across sorts (stability), not
/// to BE sorted on its own.
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

/// `compare` table: the 7-way comparator. Descending — heavy
/// first. `b.cmp(&a)` is the negative-of-compare flip.
#[test]
fn compare_table() {
    use std::cmp::Ordering::{Equal, Greater, Less};
    #[rustfmt::skip]
    let cases: &[(NodeStats, NodeStats, SortMode, bool, std::cmp::Ordering)] = &[
        //          (a,                       b,                       mode,                   cumul, expected)
        // InPackets cumulative: heavy comes BEFORE light → Less.
        (ns(1000,0,0,0),          ns(100,0,0,0),           SortMode::InPackets,    true,  Less),
        (ns(100,0,0,0),           ns(1000,0,0,0),          SortMode::InPackets,    true,  Greater),
        // InPackets rate (cumulative=false): use rate not counter.
        (ns_rate(100.,0.,0.,0.),  ns_rate(10.,0.,0.,0.),   SortMode::InPackets,    false, Less),
        // TotalPackets: sum in+out. a=100+50=150, b=80+80=160 (heavier).
        (ns(100,0,50,0),          ns(80,0,80,0),           SortMode::TotalPackets, true,  Greater),
        // Equal primary key → Equal. compare() returns Equal, stable sort preserves position.
        (ns(100,0,0,0),           ns(100,0,0,0),           SortMode::InPackets,    true,  Equal),
        // Name arm → Equal placeholder. `Stats::sort` special-cases it. Arm exists for exhaustiveness.
        (ns(1,2,3,4),             ns(5,6,7,8),             SortMode::Name,         true,  Equal),
        (ns(1,2,3,4),             ns(5,6,7,8),             SortMode::Name,         false, Equal),
    ];
    for (a, b, mode, cumul, expected) in cases {
        assert_eq!(
            compare(a, b, *mode, *cumul),
            *expected,
            "mode={mode:?} cumul={cumul}"
        );
    }
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

/// `"Tinc %-16s  Nodes: %4d  Sort: %-10s  %s"`. Golden the
/// row-0 portion.
///
/// `goto(0,0)` is `"\x1b[1;1H"`. Then the body. Then `CLEAR_EOL`
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
        // TWO spaces between fields.
        "\x1b[1;1HTinc vpn               Nodes:    0  Sort: name        Current\x1b[K"
    );
}

/// `netname=None` → empty. `%-16s` of empty is 16 spaces.
#[test]
fn render_header_no_netname() {
    let stats = Stats::default();
    let h = render_header(None, &stats);
    // After `Tinc ` (5 chars): 16 spaces, then `  Nodes`.
    assert!(h.starts_with("\x1b[1;1HTinc                   Nodes:"));
}

/// Row 2: column headers. We golden the TEXT (between the SGR
/// codes); the REVERSE wrapper is checked for presence.
#[test]
fn render_header_row2_text() {
    let stats = Stats::default(); // bunit=bytes, punit=pkts
    let h = render_header(None, &stats);

    // The text between `\x1b[7m` (REVERSE) and `\x1b[K`
    // (CLEAR_EOL).
    assert!(h.contains(
        "\x1b[7mNode                IN pkts   IN bytes   OUT pkts  OUT bytes\x1b[K\x1b[0m"
    ));
}

/// Attribute logic. The three-way table.
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
    // `||` of in OR out.
    let out_only = NodeStats {
        known: true,
        out_packets_rate: 50.0,
        ..Default::default()
    };
    let r = render_row("dave", &out_only, &stats, 3);
    assert!(r.contains("\x1b[1m")); // BOLD

    // ─── Bytes-only nonzero → NORMAL
    // The check is on PACKETS rate, not bytes. "Nonzero bytes
    // implies nonzero packets" is true for real traffic. But
    // synthetic stats can have bytes!=0, packets==0 (impossible
    // in nature, possible here). Test that we replicate the
    // upstream check, not the "obvious" check.
    let bytes_only = NodeStats {
        known: true,
        in_bytes_rate: 1000.0,
        ..Default::default() // in_packets_rate=0
    };
    let r = render_row("eve", &bytes_only, &stats, 3);
    assert!(!r.contains("\x1b[1m")); // NOT bold — packets check
}

/// `"%-16s %10.0f %10.0f %10.0f %10.0f"`. Golden the column
/// layout. `%10.0f` rounds half-to-even (printf's default);
/// Rust `{:.0}` rounds half-to-even too (since 1.0).
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

/// `cumulative=true` uses counters × scale, not rates. Scale is
/// `bscale`/`pscale`.
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

/// `'k'` scale: bytes/1000. 50000 × 0.001 = 50.
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
// pure mutation.
//
// PROBLEM: `handle_key` takes `&RawMode`, which we can't
// construct in a test (no tty). The non-'s' arms don't TOUCH
// `raw`, but the signature requires it.
//
// We don't test `handle_key`; the arms are one-liners. Test the
// THINGS they mutate (sort_mode, cumulative) via the state-
// machine tests above. The MUTATIONS are tested above. The
// mapping is the integration test's job (against fake daemon,
// send 'i', assert sort changed).

/// key → sortmode discriminants. We can't run `handle_key`
/// (`RawMode`), but we CAN assert the `SortMode` discriminants
/// match what the key handlers assign.
#[test]
fn sortmode_discriminants_match_expected() {
    // 'n' → 0
    assert_eq!(SortMode::Name as u8, 0);
    // 'I' → 1
    assert_eq!(SortMode::InPackets as u8, 1);
    // 'i' → 2
    assert_eq!(SortMode::InBytes as u8, 2);
    // 'O' → 3
    assert_eq!(SortMode::OutPackets as u8, 3);
    // 'o' → 4
    assert_eq!(SortMode::OutBytes as u8, 4);
    // 'T' → 5
    assert_eq!(SortMode::TotalPackets as u8, 5);
    // 't' → 6
    assert_eq!(SortMode::TotalBytes as u8, 6);
}
