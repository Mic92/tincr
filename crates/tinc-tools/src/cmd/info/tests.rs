use super::*;

// ─── fmt_localtime

/// `0` → `"never"`. We've folded the guard into the function.
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
/// state in parallel; `tzset()` is process-global). Instead: the
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

/// Top 8 bits.
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

/// Builder: minimal `NodeRow` with overridable cascade-relevant
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

/// `Reachability::from_row` cascade table. An if-else-if chain.
/// ORDER matters: a row satisfying multiple arms picks the
/// FIRST. Five-for-five on read-the-spec-before-coding: the
/// first cut had `Unreachable` before `Myself` ("self is
/// reachable by definition, so order doesn't matter") — wrong.
/// Upstream does MYSELF first, the strcmp fires before the
/// bit-read.
#[test]
fn cascade_table() {
    let rv = StatusBit::REACHABLE.0 | StatusBit::VALIDKEY.0;
    #[rustfmt::skip]
    let cases: &[(NodeRow, Reachability)] = &[
        //          (cascade_row(host,     status,                 via,     minmtu, nexthop, rtt),   expected)
        // 1. host=="MYSELF" → Myself. First arm; everything else don't-care.
        //    Even if status says unreachable — MYSELF check is first.
        (cascade_row("MYSELF",   0,                       "-",     0,      "-",     -1),   Reachability::Myself),
        // 2. !reachable → Unreachable. status=0, bit 4 clear, host != MYSELF.
        (cascade_row("1.1.1.1",  0,                       "alice", 0,      "-",     -1),   Reachability::Unreachable),
        // 3. via != name → Indirect. Reachable, but routed (via=bob != alice).
        (cascade_row("1.1.1.1",  StatusBit::REACHABLE.0,  "bob",   0,      "-",     -1),   Reachability::Indirect { via: "bob".into() }),
        // 4. !validkey → Unknown. Reachable, direct (via=alice), validkey CLEAR.
        (cascade_row("1.1.1.1",  StatusBit::REACHABLE.0,  "alice", 0,      "alice", -1),   Reachability::Unknown),
        // 5. minmtu > 0 → DirectUdp. The good case. rtt=1500 → Some(1500).
        (cascade_row("1.1.1.1",  rv,                      "alice", 1400,   "alice", 1500), Reachability::DirectUdp { pmtu: 1518, rtt_us: Some(1500) }),
        //    rtt = -1 → no RTT line.
        (cascade_row("1.1.1.1",  rv,                      "alice", 1400,   "alice", -1),   Reachability::DirectUdp { pmtu: 1518, rtt_us: None }),
        // 6. nexthop == name → DirectTcp. minmtu=0 (no UDP), nexthop=alice (meta conn).
        (cascade_row("1.1.1.1",  rv,                      "alice", 0,      "alice", -1),   Reachability::DirectTcp),
        // 7. else → Forwarded. minmtu=0, nexthop=bob (NOT alice).
        (cascade_row("1.1.1.1",  rv,                      "alice", 0,      "bob",   -1),   Reachability::Forwarded { nexthop: "bob".into() }),
        // ─── ORDER tests: row satisfies multiple arms, FIRST wins ───
        // MYSELF + unreachable → still Myself. (Daemon should never produce
        // this, but the cascade admits it.)
        (cascade_row("MYSELF",   0,                       "alice", 0,      "-",     -1),   Reachability::Myself),
        // Unreachable + indirect (via=bob) → still Unreachable.
        (cascade_row("1.1.1.1",  0,                       "bob",   0,      "-",     -1),   Reachability::Unreachable),
    ];
    for (row, expected) in cases {
        assert_eq!(
            Reachability::from_row(row, "alice"),
            *expected,
            "host={:?} status={:#x} via={:?} minmtu={} nexthop={:?}",
            row.host,
            row.status,
            row.via,
            row.minmtu,
            row.nexthop,
        );
    }
}

// ─── Reachability Display

/// `DirectUdp` is multi-line. The `\n` is INSIDE the `{}`
/// expansion.
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

/// All single-line variants. Exact strings.
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
/// prints. `if(rtt != -1)` not `if(rtt > 0)`. 0us is a valid
/// (loopback-fast) RTT.
#[test]
fn reachability_display_zero_rtt() {
    let r = Reachability::DirectUdp {
        pmtu: 1518,
        rtt_us: Some(0),
    };
    assert!(r.to_string().contains("RTT:          0.000"));
}

// ─── NodeInfo::format — the full golden

/// Build a known `NodeRow`, assert byte-exact output. This is the
/// `diff <(tinc-c info bob) <(tinc-rs info bob)` test, in unit
/// form. The values are chosen to exercise every line.
///
/// `last_state_change = 0` → `"never"`, dodging the TZ question.
/// The TZ-dependent path is covered by the integration test
/// (which runs the subprocess under `TZ=UTC`).
#[test]
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

    // Byte-exact. The column widths (count the spaces) are
    // upstream's. `Status:` and `Options:` and `Edges:`/
    // `Subnets:` are 13 chars (label + spaces); values have
    // leading space. Everything else is 14 chars; values don't.
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

/// Status bits print in upstream order (which is `node.h`
/// declaration order, NOT alphabetical, NOT bit-position-with-
/// gaps).
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
    // The order is upstream's printf order. NOT alphabetical.
    assert!(
        out.contains("Status:       validkey visited reachable indirect sptps udp_confirmed\n")
    );
}

/// Double-space between `packets` and bytes. `diff` against
/// upstream would catch one space.
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
    assert!(out.contains("RX:           5 packets  1024 bytes\n"));
    assert!(!out.contains("packets 1024")); // not single-space
    assert!(!out.contains("packets   1024")); // not triple
}

// ─── StatusBit::REACHABLE etc — pin against node.h packing

/// The bit positions are GCC's LSB-first packing of `node_status_t`.
/// This test pins the assignment so a wrong copy is loud at test
/// time, not at runtime.
#[test]
fn status_bits_match_node_h_order() {
    // In declaration order:
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

/// OPTION_* values.
#[test]
fn option_bits_match_connection_h() {
    assert_eq!(OPTION_INDIRECT, 0x0001);
    assert_eq!(OPTION_TCPONLY, 0x0002);
    assert_eq!(OPTION_PMTU_DISCOVERY, 0x0004);
    assert_eq!(OPTION_CLAMP_MSS, 0x0008);
}
