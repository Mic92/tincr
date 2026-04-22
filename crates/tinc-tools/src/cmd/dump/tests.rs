use super::*;
use std::fs;

use crate::names::PathsInput;

// ─── Kind parsing
//
// The argv → Kind step. The `reachable nodes` shift is the
// tricky one (must shift BEFORE arity check).

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|&x| x.to_owned()).collect()
}

/// `parse_kind` Ok-path table. `strcasecmp` throughout. The
/// `reachable nodes` shift: argv++/argc-- so the rest of the
/// dispatch sees `nodes` as argv[1].
#[test]
fn kind_ok() {
    #[rustfmt::skip]
    let cases: &[(&[&str], Kind)] = &[
        // basic
        (&["nodes"],            Kind::Nodes),
        (&["edges"],            Kind::Edges),
        (&["subnets"],          Kind::Subnets),
        (&["connections"],      Kind::Connections),
        (&["graph"],            Kind::Graph),
        (&["digraph"],          Kind::Digraph),
        (&["invitations"],      Kind::Invitations),
        // strcasecmp: nobody types it this way, but accepted
        (&["NODES"],            Kind::Nodes),
        (&["Digraph"],          Kind::Digraph),
        // reachable shift
        (&["reachable", "nodes"], Kind::ReachableNodes),
        // strcasecmp on `reachable` too
        (&["REACHABLE", "nodes"], Kind::ReachableNodes),
    ];
    for (input, expected) in cases {
        assert_eq!(
            parse_kind(&s(input)).unwrap(),
            *expected,
            "input: {input:?}"
        );
    }
}

/// `parse_kind` Err-path table. All `CmdError::BadInput`;
/// message text is user-facing.
#[test]
fn kind_err() {
    #[rustfmt::skip]
    let cases: &[(&[&str], &str)] = &[
        // `reachable X` for X != nodes.
        (&["reachable", "edges"], "only supported for nodes"),
        // The 90s GNU backtick-apostrophe.
        (&["reachable", "graph"], "`reachable'"),
        // `reachable` alone: `argc > 2` fails first, falls to `argc != 2`.
        // Our match: rest.first() is None → arity message.
        (&["reachable"],          "Invalid number"),
        // Zero args → arity.
        (&[],                     "Invalid number"),
        // Two args without `reachable` → arity. `dump nodes edges`.
        (&["nodes", "edges"],     "Invalid number"),
    ];
    for (input, msg) in cases {
        let err = parse_kind(&s(input)).unwrap_err();
        assert!(
            matches!(err, CmdError::BadInput(m) if m.contains(msg)),
            "input: {input:?}"
        );
    }

    // Unknown type: exact match. Single-quote + trailing period.
    let err = parse_kind(&s(&["lasers"])).unwrap_err();
    assert!(matches!(err, CmdError::BadInput(m) if m == "Unknown dump type 'lasers'."));
}

/// `needs_daemon`: only invitations is false. The binary checks
/// this BEFORE connect — `dump invitations` works daemon-down.
#[test]
fn kind_needs_daemon() {
    assert!(Kind::Nodes.needs_daemon());
    assert!(Kind::Graph.needs_daemon());
    assert!(!Kind::Invitations.needs_daemon());
}

// ─── NodeRow parse
//
// Golden vector: hand-computed from the daemon's format string,
// with realistic values. `n->hostname` = "10.0.0.1 port 655".

/// The reference row. `recv_row` strips `18 3 `, so the body
/// starts at `name`.
///
/// Values chosen for unambiguity:
/// - `status = 0x12` → bit 1 set (validkey), bit 4 set
///   (reachable). 0b10010.
/// - `udp_ping_rtt = 1500` → `rtt 1.500` in output
/// - `host = "10.0.0.1"`, port = "655" — the embedded `port`
///   literal must split correctly.
const NODE_BODY: &str = "alice 0a1b2c3d4e5f 10.0.0.1 port 655 \
    0 0 0 0 1000000c 12 bob alice 1 1518 1400 1518 1700000000 1500 \
    100 50000 200 100000";

#[test]
fn node_parse_golden() {
    let r = NodeRow::parse(NODE_BODY).unwrap();
    assert_eq!(r.name, "alice");
    assert_eq!(r.id, "0a1b2c3d4e5f");
    assert_eq!(r.host, "10.0.0.1");
    assert_eq!(r.port, "655");
    assert_eq!(r.cipher, 0);
    assert_eq!(r.digest, 0);
    assert_eq!(r.maclength, 0);
    assert_eq!(r.compression, 0);
    assert_eq!(r.options, 0x1000_000c);
    assert_eq!(r.status, 0x12);
    assert_eq!(r.nexthop, "bob");
    assert_eq!(r.via, "alice");
    assert_eq!(r.distance, 1);
    assert_eq!(r.pmtu, 1518);
    assert_eq!(r.minmtu, 1400);
    assert_eq!(r.maxmtu, 1518);
    assert_eq!(r.last_state_change, 1_700_000_000);
    assert_eq!(r.udp_ping_rtt, 1500);
    assert_eq!(r.in_packets, 100);
    assert_eq!(r.in_bytes, 50000);
    assert_eq!(r.out_packets, 200);
    assert_eq!(r.out_bytes, 100_000);
    // Status bits: 0x12 = 0b10010 = bit 1 + bit 4.
    assert!(r.validkey());
    assert!(r.reachable());
}

/// Host-field variants beyond the golden vector.
/// - `n->hostname = NULL` → daemon sends `"unknown port unknown"`;
///   the `port` literal still splits.
/// - `MYSELF`: a literal in `sockaddr2hostname` format.
#[test]
fn node_parse_host_variants() {
    // unknown host: status 0 → no reachable/validkey bits
    let r = NodeRow::parse(
        "carol 000000000000 unknown port unknown \
         0 0 0 0 0 0 - - 99 0 0 0 0 -1 0 0 0 0",
    )
    .unwrap();
    assert_eq!(r.host, "unknown", "unknown: host");
    assert_eq!(r.port, "unknown", "unknown: port");
    assert!(!r.reachable(), "unknown: status=0 → !reachable");
    assert!(!r.validkey(), "unknown: status=0 → !validkey");
    assert_eq!(r.distance, 99, "unknown: distance");
    assert_eq!(r.udp_ping_rtt, -1, "unknown: rtt=-1");

    // MYSELF: status 0x1f = bits 0-4 all set
    let r = NodeRow::parse(
        "myself 010203040506 MYSELF port 655 \
         0 0 0 0 0 1f - myself 0 1518 1518 1518 1700000000 -1 0 0 0 0",
    )
    .unwrap();
    assert_eq!(r.host, "MYSELF", "myself: host");
    assert!(r.reachable(), "myself: status=0x1f → reachable");
}

/// Short row → `ParseError`. Our `?` chain bails at first missing
/// field.
#[test]
fn node_parse_short() {
    assert!(NodeRow::parse("alice 0a1b2c3d4e5f 10.0.0.1").is_err());
    // Missing the `port` literal:
    assert!(
        NodeRow::parse("alice 0a1b2c3d4e5f 10.0.0.1 PORT 655 0 0 0 0 0 0 a a 0 0 0 0 0 0 0 0 0 0")
            .is_err()
    );
}

/// `fmt_plain` output: the script-compatible format. If this
/// changes, `tinc dump nodes | awk` scripts break.
///
/// Three facets of one contract:
/// - the full golden line (the spec, byte-for-byte)
/// - rtt suffix: present iff `udp_ping_rtt != -1`, `%03d` padded
/// - status `%04x` pad (contrast conn dump's unpadded `%x`)
#[test]
fn node_fmt_plain_contract() {
    // ─── Full string match. This IS the spec. ───
    let r = NodeRow::parse(NODE_BODY).unwrap();
    assert_eq!(
        r.fmt_plain(),
        "alice id 0a1b2c3d4e5f at 10.0.0.1 port 655 cipher 0 digest 0 \
         maclength 0 compression 0 options 1000000c status 0012 \
         nexthop bob via alice distance 1 pmtu 1518 (min 1400 max 1518) \
         rx 100 50000 tx 200 100000 rtt 1.500",
        "golden line (with rtt)"
    );

    // ─── udp_ping_rtt = -1 → no rtt suffix at all ───
    let no_rtt = NodeRow::parse(
        "carol 000000000000 unknown port unknown \
         0 0 0 0 0 0 - - 99 0 0 0 0 -1 0 0 0 0",
    )
    .unwrap()
    .fmt_plain();
    assert!(!no_rtt.contains("rtt"), "rtt=-1: no `rtt` substring");
    assert!(
        no_rtt.ends_with("tx 0 0"),
        "rtt=-1: ends after tx, no trailing space"
    );

    // ─── substring checks: %03d rtt pad + %04x status pad ───
    let fmt = |body| NodeRow::parse(body).unwrap().fmt_plain();
    #[rustfmt::skip]
    let cases: &[(&str, &str, &str)] = &[
        // (label,                      body,                                                 must_contain)
        ("rtt 50us → 0.050 (%03d pad)", "x 0 h port p 0 0 0 0 0 0 - - 0 0 0 0 0 50 0 0 0 0",    " rtt 0.050"),
        ("rtt 1000us → 1.000",          "x 0 h port p 0 0 0 0 0 0 - - 0 0 0 0 0 1000 0 0 0 0",  " rtt 1.000"),
        ("rtt 12345us → 12.345",        "x 0 h port p 0 0 0 0 0 0 - - 0 0 0 0 0 12345 0 0 0 0", " rtt 12.345"),
        ("status 0x12 → 0012 (%04x)",   NODE_BODY,                                              "status 0012 "),
        ("status 0 → 0000 (4 chars)",   "x 0 h port p 0 0 0 0 0 0 - - 0 0 0 0 0 -1 0 0 0 0",    "status 0000 "),
    ];
    for (label, body, want) in cases {
        assert!(fmt(body).contains(want), "{label}");
    }
}

// ─── DOT format: color cascade

/// `fmt_dot` color cascade, an if-else-if chain in this order:
///   1. MYSELF → green + filled
///   2. !reachable → red
///   3. via != name (indirect, UDP relayed) → orange
///   4. !validkey → black
///   5. minmtu > 0 (UDP works) → green
///   6. fall-through (TCP only) → black
///
/// Order matters: MYSELF wins over !reachable (cascade row 7).
#[test]
fn node_dot_color_cascade() {
    #[rustfmt::skip]
    let cases: &[(&str, &str, bool)] = &[
        //          (body,                                                                          color,   filled)
        // 1. MYSELF → green, filled. status 0x1f = bits 0-4 all set.
        ("me 0 MYSELF port 655 0 0 0 0 0 1f - me 0 1500 1500 1500 0 -1 0 0 0 0",         "green",  true),
        // 2. Unreachable → red. status 0 → bit 4 clear.
        ("dead 0 unknown port unknown 0 0 0 0 0 0 - - 0 0 0 0 0 -1 0 0 0 0",              "red",    false),
        // 3. Indirect: via="bob" != name="alice", status 0x12 (reachable+validkey) → orange.
        ("alice 0 1.1.1.1 port 1 0 0 0 0 0 12 bob bob 1 1500 1400 1500 0 -1 0 0 0 0",     "orange", false),
        // 4. Reachable, direct (via==name), no validkey (status 0x10: bit 4 only) → black.
        ("alice 0 1.1.1.1 port 1 0 0 0 0 0 10 bob alice 1 0 0 0 0 -1 0 0 0 0",            "black",  false),
        // 5. Reachable, direct, validkey (0x12), minmtu=1400 > 0 → green (UDP ok). NOT filled.
        ("alice 0 1.1.1.1 port 1 0 0 0 0 0 12 bob alice 1 1500 1400 1500 0 -1 0 0 0 0",   "green",  false),
        // 6. Reachable, direct, validkey, minmtu=0 → black (TCP only, PMTU not converged).
        ("alice 0 1.1.1.1 port 1 0 0 0 0 0 12 bob alice 1 0 0 1500 0 -1 0 0 0 0",         "black",  false),
        // 7. CASCADE ORDER: host=MYSELF but status=0 (not reachable). MYSELF check is FIRST
        //    → green, not red. Unlikely in practice but the cascade admits it.
        ("me 0 MYSELF port 655 0 0 0 0 0 0 - me 0 0 0 0 0 -1 0 0 0 0",                    "green",  true),
    ];
    for (body, color, filled) in cases {
        let r = NodeRow::parse(body).unwrap();
        let dot = r.fmt_dot();
        assert!(
            dot.contains(&format!("color = \"{color}\"")),
            "body: {body:?}\ndot: {dot}"
        );
        assert_eq!(dot.contains("filled"), *filled, "body: {body:?}");
    }
    // The label = name redundancy (only need to check once).
    let r = NodeRow::parse(cases[0].0).unwrap();
    assert!(r.fmt_dot().contains("\"me\" [label = \"me\""));
}

// ─── EdgeRow

/// Golden vector. Both addresses are `sockaddr2hostname` output
/// (3 tokens each). Body has `recv_row` already stripped `18 4 `.
const EDGE_BODY: &str = "alice bob 10.0.0.2 port 655 192.168.1.5 port 655 1000000c 100";

#[test]
fn edge_parse_golden() {
    let r = EdgeRow::parse(EDGE_BODY).unwrap();
    assert_eq!(r.from, "alice");
    assert_eq!(r.to, "bob");
    assert_eq!(r.host, "10.0.0.2");
    assert_eq!(r.port, "655");
    assert_eq!(r.local_host, "192.168.1.5");
    assert_eq!(r.local_port, "655");
    assert_eq!(r.options, 0x1000_000c);
    assert_eq!(r.weight, 100);
}

/// `AF_UNSPEC` local address: `"unspec port unspec"`. Common —
/// `local_address` is often unset.
#[test]
fn edge_parse_unspec_local() {
    let body = "a b 10.0.0.1 port 655 unspec port unspec 0 1";
    let r = EdgeRow::parse(body).unwrap();
    assert_eq!(r.local_host, "unspec");
    assert_eq!(r.local_port, "unspec");
}

#[test]
fn edge_fmt_plain() {
    let r = EdgeRow::parse(EDGE_BODY).unwrap();
    assert_eq!(
        r.fmt_plain(),
        "alice to bob at 10.0.0.2 port 655 local 192.168.1.5 port 655 \
         options 1000000c weight 100"
    );
}

/// DOT edge weight: `1 + 65536/weight`. `%f` is 6 decimal places.
/// weight=100 → 1+655.36 = 656.36.
#[test]
fn edge_dot_weight_calc() {
    let r = EdgeRow::parse(EDGE_BODY).unwrap();
    let dot = r.fmt_dot(true).unwrap();
    // 1.0 + 65536.0/100.0 = 656.36. Six decimals: 656.360000.
    // BUT: f32 precision. 656.36 might be 656.359985 in f32.
    // Upstream uses float (32-bit) so it has the same issue:
    //   float w = 1.0f + 65536.0f / 100.0f;  → 656.359985
    //   printf("%f", w);                      → "656.359985"
    // We must match that, which we do by using f32. Assert it.
    assert!(dot.contains("w = 656.359985"));
    assert!(dot.contains("weight = 656.359985"));
}

/// `fmt_dot` dedup + arrow style. Digraph emits all (`->`).
/// Undirected: suppress `from > to` half (strcmp is byte-order,
/// Rust String Ord is byte-order). The `>` not `>=` means
/// self-loops emit (tinc has no self-edges, but).
#[test]
fn edge_dot_dedup_table() {
    const BA: &str = "bob alice 10.0.0.1 port 655 unspec port unspec 0 100";
    const AA: &str = "a a h port p h port p 0 1";
    #[rustfmt::skip]
    let cases: &[(&str, &str, bool, Option<&str>)] = &[
        // (label,                       body,      directed, expect_contains_or_None)
        ("digraph a<b: emit ->",          EDGE_BODY, true,  Some("\"alice\" -> \"bob\"")),
        ("digraph b>a: still emit",       BA,        true,  Some("\"bob\" -> \"alice\"")),
        ("undirected a<b: emit --",       EDGE_BODY, false, Some("\"alice\" -- \"bob\"")),
        ("undirected b>a: suppress",      BA,        false, None),
        ("undirected a==a: > is false → emit", AA,  false, Some("")),
    ];
    for (label, body, directed, want) in cases {
        let got = EdgeRow::parse(body).unwrap().fmt_dot(*directed);
        match want {
            None => assert_eq!(got, None, "{label}"),
            Some(sub) => assert!(got.unwrap().contains(sub), "{label}"),
        }
    }
}

// ─── SubnetRow + strip_weight

/// `SubnetRow::parse` shapes. Broadcast owner `"(broadcast)"`
/// (parens are literal). Weight suffix survives parse — stored
/// raw, stripped only at fmt time.
#[test]
fn subnet_parse_table() {
    #[rustfmt::skip]
    let cases: &[(&str, &str, &str, &str)] = &[
        // (label,             input,                         expect_subnet,       expect_owner)
        ("basic",              "10.0.0.0/24 alice",           "10.0.0.0/24",       "alice"),
        ("broadcast (parens)", "ff:ff:ff:ff:ff:ff (broadcast)", "ff:ff:ff:ff:ff:ff", "(broadcast)"),
        ("weight stored raw",  "10.0.0.0/24#5 alice",         "10.0.0.0/24#5",     "alice"),
    ];
    for (label, input, sub, own) in cases {
        let r = SubnetRow::parse(input).unwrap();
        assert_eq!(r.subnet, *sub, "{label}: subnet");
        assert_eq!(r.owner, *own, "{label}: owner");
    }
}

/// `fmt_plain`: `strip_weight` applied. The daemon shouldn't
/// SEND `#10` (its `net2str` already strips default), but defense
/// against older daemons. Non-default weights survive.
#[test]
fn subnet_fmt_table() {
    let row = |s: &str, o: &str| SubnetRow {
        subnet: s.into(),
        owner: o.into(),
    };
    #[rustfmt::skip]
    let cases: &[(&str, SubnetRow, &str)] = &[
        // (label,             row,                              expect_fmt)
        ("basic",              row("10.0.0.0/24",    "alice"), "10.0.0.0/24 owner alice"),
        ("#5 not stripped",    row("10.0.0.0/24#5",  "alice"), "10.0.0.0/24#5 owner alice"),
        ("#10 stripped (default)", row("10.0.0.0/24#10", "alice"), "10.0.0.0/24 owner alice"),
    ];
    for (label, r, want) in cases {
        assert_eq!(r.fmt_plain(), *want, "{label}");
    }
}

/// `strip_weight`: `#10` only. Includes corner cases from
/// upstream's `len >= 3` check.
#[test]
fn strip_weight_table() {
    #[rustfmt::skip]
    let cases: &[(&str, &str)] = &[
        // ─── only `#10` is stripped ───
        ("10.0.0.0/24#10",  "10.0.0.0/24"),
        ("10.0.0.0/24#5",   "10.0.0.0/24#5"),    // other weights survive
        ("10.0.0.0/24#100", "10.0.0.0/24#100"),  // #100 ≠ #10
        ("10.0.0.0/24",     "10.0.0.0/24"),      // no suffix → unchanged
        // ─── upstream `len >= 3` corner cases ───
        // `"#10"` (3 chars) → `""`. Never a valid subnet but it's
        // what upstream does (`!strcmp(netstr + 0, "#10")` matches).
        ("#10",    ""),
        // 2 chars → no match. `len >= 3` fails first.
        ("10",     "10"),
        // "#100" ends in "100", not "#10" → no match.
        ("a#100",  "a#100"),
        // `#10#10`: ends in `#10` → strip once. One pass.
        ("#10#10", "#10"),
    ];
    for (input, expected) in cases {
        assert_eq!(strip_weight(input), *expected, "input: {input:?}");
    }
}

// ─── ConnRow

/// Golden vector. Daemon: 5 fields (after 18 6). CLI: 6 (one
/// `port` literal). `c->hostname` is `sockaddr2hostname` of the
/// peer's address.
const CONN_BODY: &str = "bob 10.0.0.2 port 655 0 7 1a";

#[test]
fn conn_parse_golden() {
    let r = ConnRow::parse(CONN_BODY).unwrap();
    assert_eq!(r.name, "bob");
    assert_eq!(r.host, "10.0.0.2");
    assert_eq!(r.port, "655");
    assert_eq!(r.options, 0);
    assert_eq!(r.socket, 7);
    assert_eq!(r.status, 0x1a);
}

/// `fmt_plain`: full golden line + `status %x` UNPADDED check.
/// Contrast node's `%04x`; upstream is inconsistent and we
/// replicate that.
#[test]
fn conn_fmt_plain_contract() {
    let r = ConnRow::parse(CONN_BODY).unwrap();
    assert_eq!(
        r.fmt_plain(),
        "bob at 10.0.0.2 port 655 options 0 socket 7 status 1a",
        "golden line"
    );
    // status = 0x1a → "1a", not "001a" (proven by golden above too).
    assert!(r.fmt_plain().ends_with("status 1a"), "status 0x1a unpadded");
    // status = 0 → "0", one char.
    let r0 = ConnRow { status: 0, ..r };
    assert!(r0.fmt_plain().ends_with("status 0"), "status 0 → 1 char");
}

// ─── dump_invitations

/// Tempdir for invitations tests. Same shape as invite.rs tests:
/// init confbase, write the invitations dir manually.
fn setup_inv() -> (tempfile::TempDir, Paths) {
    use std::thread;
    let tid = format!("{:?}", thread::current().id());
    let dir = tempfile::Builder::new()
        .prefix(&format!("tinc-dump-inv-{tid}-"))
        .tempdir()
        .unwrap();
    let cb = dir.path().join("vpn");
    fs::create_dir_all(cb.join("invitations")).unwrap();
    let input = PathsInput {
        confbase: Some(cb),
        ..Default::default()
    };
    let paths = Paths::for_cli(&input);
    (dir, paths)
}

/// 24-char valid b64 filename. We DON'T compute a real cookie
/// hash — just need 24 valid b64 chars. The dump function
/// validates b64-ness, not crypto-correctness.
fn mk_filename(tag: u8) -> String {
    // 24 'A's would decode to 18 zero bytes. Mix one byte so
    // multiple invites in one test have distinct names.
    // (Actually we need URL-safe b64; `cookie_filename` uses
    // `b64::encode_url`. 'A' is in both alphabets.)
    let mut s = "A".repeat(23);
    // tag 0 → 'A', 1 → 'B', etc. Stays in valid b64 range.
    s.push((b'A' + tag) as char);
    s
}

/// Empty results: dir present-but-empty AND dir missing both
/// yield `Ok(vec![])`. The dir is created by the first `tinc
/// invite`, not by `init`, so a never-invited node has no
/// `invitations/`.
#[test]
fn inv_empty_cases() {
    // Empty dir.
    let (_d, paths) = setup_inv();
    assert!(
        dump_invitations(&paths).unwrap().is_empty(),
        "empty dir → empty vec"
    );

    // Missing dir (ENOENT → Ok, not error).
    let (d, paths) = setup_inv();
    fs::remove_dir(d.path().join("vpn/invitations")).unwrap();
    assert!(
        dump_invitations(&paths).unwrap().is_empty(),
        "ENOENT → empty vec, not error"
    );
}

/// Valid invitations: 24-char b64 name, `Name = X` first line.
/// rstrip on the name value strips all trailing whitespace
/// (CRLF from Windows-edited files).
#[test]
fn inv_valid_table() {
    #[rustfmt::skip]
    let cases: &[(&str, &str)] = &[
        // (label,                      file content)
        ("plain LF",                    "Name = bob\n# rest of file\n"),
        ("rstrip: CRLF + trailing tab", "Name = bob\t \r\n"),
        // P4: same tokenizer as `tinc.conf` — `Name=bob` must list
        // even though `cmd_invite` always writes the spaced form.
        ("no-space `=`",                "Name=bob\n"),
    ];
    for (label, content) in cases {
        let (d, paths) = setup_inv();
        let name = mk_filename(0);
        fs::write(d.path().join("vpn/invitations").join(&name), content).unwrap();

        let rows = dump_invitations(&paths).unwrap();
        assert_eq!(rows.len(), 1, "{label}: row count");
        assert_eq!(rows[0].cookie_hash, name, "{label}: cookie_hash");
        assert_eq!(rows[0].invitee, "bob", "{label}: invitee (rstripped)");
    }
}

/// Skip table: each entry is a (filename, content) pair that
/// `dump_invitations` must silently skip.
#[test]
fn inv_skipped() {
    // Filenames with non-static lifetimes built up front.
    let valid_name = mk_filename(0);
    let short = "A".repeat(23);
    let long = "A".repeat(25);
    let bad_b64 = "*".repeat(24);

    #[rustfmt::skip]
    let cases: &[(&str, &str, &str)] = &[
        //          (filename,              content,           why)
        // ─── wrong-length filename: the 24-char filter ───
        // `ed25519_key.priv` is in the same dir (per-invitation key);
        // must NOT show up as an invitation.
        ("ed25519_key.priv",     "key blob",         "key file (wrong length)"),
        // 23 chars, valid b64.
        (&short,                 "Name = nope\n",    "23-char name"),
        // 25 chars. Upstream would read first 24 and pass; we tighten to exact.
        (&long,                  "Name = nope\n",    "25-char name"),
        // ─── 24 chars, NOT valid b64 ───
        (&bad_b64,               "Name = bob\n",     "bad b64 (`*` not in alphabet)"),
        // ─── valid filename, bad content ───
        // First line not a `Name` key at all.
        (&valid_name,            "Address = x\n",   "first line not Name"),
        // `check_id` failure: name with hyphen.
        (&valid_name,            "Name = bad-name\n", "bad invitee name"),
        // Empty file.
        (&valid_name,            "",                 "empty file"),
    ];
    for (fname, content, why) in cases {
        let (d, paths) = setup_inv();
        fs::write(d.path().join("vpn/invitations").join(fname), content).unwrap();
        let rows = dump_invitations(&paths).unwrap();
        assert!(rows.is_empty(), "{why}: not skipped");
    }
}

/// Multiple invites: collect all. Order is readdir order
/// (filesystem-defined). We don't sort; upstream doesn't either.
#[test]
fn inv_multiple() {
    let (d, paths) = setup_inv();
    for (i, who) in ["bob", "carol", "dave"].iter().enumerate() {
        #[expect(clippy::cast_possible_truncation)] // i ∈ 0..3 (loop over 3-elem array)
        let name = mk_filename(i as u8);
        fs::write(
            d.path().join("vpn/invitations").join(&name),
            format!("Name = {who}\nrest\n"),
        )
        .unwrap();
    }

    let rows = dump_invitations(&paths).unwrap();
    assert_eq!(rows.len(), 3);
    // All present (order indeterminate).
    let names: Vec<&str> = rows.iter().map(|r| r.invitee.as_str()).collect();
    assert!(names.contains(&"bob"));
    assert!(names.contains(&"carol"));
    assert!(names.contains(&"dave"));
}

/// Mixed: one valid, one bad-b64, one wrong-length, one bad-name.
/// Only the valid one survives. Upstream silently skips bad ones
/// (with stderr warnings; we don't warn from lib code).
#[test]
fn inv_mixed() {
    let (d, paths) = setup_inv();
    let inv_dir = d.path().join("vpn/invitations");

    // Valid.
    fs::write(inv_dir.join(mk_filename(0)), "Name = good\n").unwrap();
    // Bad b64.
    fs::write(inv_dir.join("*".repeat(24)), "Name = x\n").unwrap();
    // Wrong length.
    fs::write(inv_dir.join("ed25519_key.priv"), "blob").unwrap();
    // Bad name.
    fs::write(inv_dir.join(mk_filename(1)), "Name = bad-name\n").unwrap();
    // Wrong first-line format.
    fs::write(inv_dir.join(mk_filename(2)), "NetName = vpn\n").unwrap();

    let rows = dump_invitations(&paths).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].invitee, "good");
}

/// Permission denied on the DIRECTORY → error (not ENOENT).
/// (Upstream's message has a "Cannot not [sic]" double negative
/// typo. We don't replicate the message.)
#[test]
#[cfg(all(unix, not(target_os = "macos")))]
fn inv_dir_perms() {
    let (d, paths) = setup_inv();
    let inv_dir = d.path().join("vpn/invitations");
    // chmod 0 — readdir fails.
    fs::set_permissions(
        &inv_dir,
        std::os::unix::fs::PermissionsExt::from_mode(0o000),
    )
    .unwrap();

    let err = dump_invitations(&paths).unwrap_err();
    // Error, not Ok(empty). ENOENT would be Ok(empty); EACCES
    // is a real error.
    assert!(matches!(err, CmdError::Io { .. }));

    // Restore so tempdir cleanup works.
    fs::set_permissions(
        &inv_dir,
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .unwrap();
}

/// Per-file permission denied → SKIP, not error. The other files
/// still show.
#[test]
#[cfg(all(unix, not(target_os = "macos")))]
fn inv_file_perms_skip() {
    let (d, paths) = setup_inv();
    let inv_dir = d.path().join("vpn/invitations");

    // One bad-perms, one good.
    let bad = inv_dir.join(mk_filename(0));
    fs::write(&bad, "Name = unreadable\n").unwrap();
    fs::set_permissions(&bad, std::os::unix::fs::PermissionsExt::from_mode(0o000)).unwrap();

    fs::write(inv_dir.join(mk_filename(1)), "Name = good\n").unwrap();

    let rows = dump_invitations(&paths).unwrap();
    // The bad one is skipped, the good one survives.
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].invitee, "good");

    // Restore so cleanup works.
    fs::set_permissions(&bad, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
}

// ─── End-to-end with the actual `cmd::invite` output
//
// Contract test: `tinc invite bob` writes a file → `tinc dump
// invitations` finds it. The two functions agree on the format.
// If `invite` ever changes its `Name = ` line, this fires.

/// `invite()` writes a file that `dump_invitations()` accepts.
/// Full-fidelity: real `cookie_filename`, real file content from
/// `build_invitation_file`.
#[test]
fn inv_roundtrip_with_invite() {
    use crate::cmd::invite;

    // ─── init
    let cd = crate::testutil::ConfDir::bare();
    let paths = cd.paths().clone();
    let cb = cd.confbase();
    crate::cmd::init::run(&paths, "alice").unwrap();
    // invite needs Address (we dropped the HTTP probe).
    fs::write(
        cb.join("hosts/alice"),
        format!(
            "Address = 192.0.2.1\n{}",
            fs::read_to_string(cb.join("hosts/alice")).unwrap()
        ),
    )
    .unwrap();

    // ─── invite
    // `now` parameterized for sweep_expired tests; pass real time.
    let now = std::time::SystemTime::now();
    let result = invite::invite(&paths, None, "bob", now).unwrap();
    // The URL is in result.url; we don't need it. The file is
    // written.
    let _ = result;

    // ─── dump
    let rows = dump_invitations(&paths).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].invitee, "bob");
    // cookie_hash is 24 chars, valid b64. We don't check WHICH
    // hash — that's invite's KAT tests.
    assert_eq!(rows[0].cookie_hash.len(), 24);
    assert!(tinc_crypto::b64::decode(&rows[0].cookie_hash).is_some());
}
