//! Adversarial / fuzz-style inputs for the wire parsers.
//!
//! The KATs in `src/` and the round-trip proptests in `roundtrip.rs`
//! exercise the *valid* grammar. This file throws garbage at every
//! `parse()` entry point and asserts it returns `Err` (or a defined
//! `Ok`) — never panics. The point is to pin the "malformed → clean
//! reject" contract so a hostile peer can't crash the daemon by
//! hand-crafting protocol lines.
//!
//! Coverage shape:
//!
//! 1. Hand-picked nasty strings (overflow, truncation, embedded NUL,
//!    wrong-type tokens) per message struct — table-driven so adding
//!    a case is one line.
//! 2. A single proptest that feeds *arbitrary bytes* (lossy-UTF-8)
//!    to every parser. No assertion on the result, only that it
//!    doesn't panic. This is the cheap stand-in for a cargo-fuzz
//!    harness and catches the "forgot a bounds check" class.
//!
//! Anything that *should* be rejected but currently isn't (i.e. a
//! C-compat divergence, not a crash) is pinned as `Ok` in the tables
//! below with a comment, so a future tightening shows up as a test
//! diff rather than a silent behaviour change.

use proptest::prelude::*;

use tinc_proto::msg::{
    AddEdge, AnsKey, DelEdge, KeyChanged, MtuInfo, ReqKey, SptpsPacket, SubnetMsg, TcpPacket,
    UdpInfo,
};
use tinc_proto::{MAX_STRING, Request, Subnet, check_id};

// ────────────────────────────────────────────────────────────────────
// Table-driven reject cases.
//
// Each table entry is a line that MUST NOT panic. Most are expected
// to `Err`; a few are `Ok` (extra trailing tokens — sscanf ignores
// them, so do we) and are marked as such so a future tightening
// doesn't silently change behaviour.

/// One adversarial probe: feed `line` to `parse`, assert it doesn't
/// panic, and that the Ok/Err shape matches `want_ok`.
fn probe<T, E>(what: &str, line: &str, want_ok: bool, parse: impl FnOnce(&str) -> Result<T, E>) {
    // catch_unwind: the whole point of this file. If a parser
    // indexes past end / unwraps on bad input, we want a clear
    // "PANIC on input X" failure, not a thread-abort that nextest
    // reports as "test failed" with no context.
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| parse(line)));
    match r {
        Err(p) => panic!("{what}: PANIC on {line:?}: {p:?}"),
        Ok(r) => assert_eq!(
            r.is_ok(),
            want_ok,
            "{what}: {line:?} expected {} got {}",
            if want_ok { "Ok" } else { "Err" },
            if r.is_ok() { "Ok" } else { "Err" },
        ),
    }
}

#[test]
fn request_peek_garbage() {
    // peek() returns Option, never panics. All of these are None.
    for s in [
        "",
        " ",
        "\n",
        "\0",
        "-1",
        "+12 a b", // leading + not a digit
        "99999999999999999999 overflow",
        "12\0garbage", // NUL after digits — not space-terminated
        "12\tfoo",     // tab not space (peek requires b' ' exactly)
        "𝟙𝟚 unicode-digits",
    ] {
        let r = std::panic::catch_unwind(|| Request::peek(s));
        assert!(matches!(r, Ok(None)), "peek({s:?}) = {r:?}");
    }
}

#[test]
fn check_id_garbage() {
    // check_id is the path-traversal gate. None of these may pass.
    for s in ["", ".", "..", "../x", "a/b", "a\0b", "a b", "a\n", "ä"] {
        assert!(!check_id(s), "check_id({s:?}) accepted");
    }
    // No length cap in check_id itself (C tinc has none either; the
    // charset gate already prevents path traversal). Pinned so a
    // future cap is a deliberate test change.
    let huge = "a".repeat(MAX_STRING);
    assert!(check_id(&huge));
}

#[test]
fn add_edge_adversarial() {
    #[rustfmt::skip]
    let cases: &[(&str, bool)] = &[
        // ─── truncation ───
        ("",                                                false),
        ("12",                                              false),
        ("12 0",                                            false),
        ("12 0 a",                                          false),
        ("12 0 a b",                                        false),
        ("12 0 a b 1.1.1.1",                                false),
        ("12 0 a b 1.1.1.1 655",                            false),
        ("12 0 a b 1.1.1.1 655 0",                          false),
        // ─── integer overflow / wrong type ───
        ("12 0 a b 1.1.1.1 655 0 99999999999999999999",     false), // weight > i64
        ("12 0 a b 1.1.1.1 655 0 2147483648",               false), // weight = i32::MAX+1
        ("12 0 a b 1.1.1.1 655 ffffffffffffffff 1",         false), // options > u32
        ("12 0 a b 1.1.1.1 655 0 -2147483648",              true),  // i32::MIN — silly but %d
        ("12 0 a b 1.1.1.1 655 0 +1",                       true),  // Rust i32 parse accepts +
        ("12 0 a b 1.1.1.1 655 0 1.5",                      false), // float weight
        ("12 0 a b 1.1.1.1 655 -1 1",                       false), // negative hex
        // ─── extra / odd tokens ───
        ("12 0 a b 1.1.1.1 655 0 1 la lp extra",            true),  // 9th token ignored (sscanf compat)
        ("12 0 a b 1.1.1.1 655 0 1 lonelylocal",            false), // 7-token reject (already KAT'd; here for completeness)
        // ─── name validation ───
        ("12 0 a\0x b 1.1.1.1 655 0 1",                     false), // embedded NUL
        ("12 0 .. b 1.1.1.1 655 0 1",                       false), // path traversal
        ("12 0 a a 1.1.1.1 655 0 1",                        false), // self-loop
        // ─── whitespace variants ───
        ("12\t0\ta\tb\t1.1.1.1\t655\t0\t1",                 true),  // tabs split like spaces
        ("12  0  a  b  1.1.1.1  655  0  1",                 true),  // double-space
        ("  12 0 a b 1.1.1.1 655 0 1  ",                    true),  // leading/trailing
    ];
    for &(line, ok) in cases {
        probe("AddEdge", line, ok, AddEdge::parse);
    }
    // 2048-char name: Tok::s accepts (== MAX_STRING), check_id accepts.
    // Pinned as Ok — same as C; charset gate is the security boundary.
    let huge = format!("12 0 {} b 1.1.1.1 655 0 1", "a".repeat(MAX_STRING));
    probe("AddEdge", &huge, true, AddEdge::parse);
    // 2049-char name: Tok::s rejects.
    let huger = format!("12 0 {} b 1.1.1.1 655 0 1", "a".repeat(MAX_STRING + 1));
    probe("AddEdge", &huger, false, AddEdge::parse);
}

#[test]
fn del_edge_adversarial() {
    for &(line, ok) in &[
        ("13", false),
        ("13 0 a", false),
        ("13 0 a a", false),
        ("13 0 a b extra", true), // trailing ignored
        ("13 0 a/b c", false),
    ] {
        probe("DelEdge", line, ok, DelEdge::parse);
    }
}

#[test]
fn subnet_msg_adversarial() {
    for &(line, ok) in &[
        ("10 0 alice 10.0.0.1/33", false),
        ("10 0 alice ::1/129", false),
        ("10 0 alice 10.0.0.1/24#99999999999999999999", false),
        ("10 0 alice 00:11:22:33:44:55/48", false),
        ("10 0 alice ", false), // missing subnet
        ("10 0 .. 10.0.0.1", false),
        ("10 0 alice 10.0.0.1 trailing", true),
    ] {
        probe("SubnetMsg", line, ok, SubnetMsg::parse);
    }
}

#[test]
fn subnet_adversarial() {
    #[rustfmt::skip]
    let cases: &[(&str, bool)] = &[
        ("",                                false),
        ("/24",                             false), // empty addr
        ("#5",                              false), // empty addr
        ("10.0.0.0/",                       false),
        ("10.0.0.0#",                       false),
        ("10.0.0.0/24/5",                   false), // double /
        ("10.0.0.0#5#6",                    false), // double #
        ("10.0.0.0#5/24",                   false), // wrong order (# before /)
        ("10.0.0.0/+24",                    true),  // i32 parse accepts +; pinned
        ("10.0.0.0/ 24",                    false), // space in prefix
        ("10.0.0.0/256",                    false), // > 32, also > u8
        ("::/130",                          false),
        ("::/99999999999",                  false), // i32 overflow
        ("10.0.0.0/24#2147483648",          false), // weight i32 overflow
        ("10.0.0.0/24#-2147483648",         true),
        ("g0:11:22:33:44:55",               false), // bad hex digit
        (":11:22:33:44:55",                 false), // empty MAC part
        ("00:11:22:33:44:55:",              false), // trailing colon
        ("\0",                              false),
        // 64-byte input cap (str2net strncpy guard)
        ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false),
    ];
    for &(s, ok) in cases {
        probe("Subnet", s, ok, str::parse::<Subnet>);
    }
}

#[test]
fn key_msgs_adversarial() {
    // KeyChanged: just one token after %*d %*x — almost anything goes.
    for &(line, ok) in &[
        ("14", false),
        ("14 0", false),
        // NUL is not ascii whitespace → it's a 1-byte token. KeyChanged
        // doesn't check_id → accepted. Pins current (C-compat) behaviour.
        ("14 0 \0", true),
        ("14 0 anything!goes", true),
    ] {
        probe("KeyChanged", line, ok, KeyChanged::parse);
    }

    // ReqKey: lone-trailing-addr already in `msg/key.rs`.
    for &(line, ok) in &[
        ("15", false),
        ("15 a", false),
        ("15 a b notanint", false), // d_opt: token present but bad i32
        ("15 a b 2147483648", false),
        ("15 .. b", false),
        ("15 a b 15 payload a p extra", true), // extra past pair ignored
    ] {
        probe("ReqKey", line, ok, ReqKey::parse);
    }

    // AnsKey: 8-field reject already in `msg/key.rs`.
    for &(line, ok) in &[
        ("16 a b k 0 0 0", false),                      // 6 fields
        ("16 a b k 0 0 18446744073709551616 0", false), // maclen > u64
        ("16 a b k x 0 0 0", false),                    // cipher non-int
        ("16 a-b c k 0 0 0 0", false),                  // bad name
    ] {
        probe("AnsKey", line, ok, AnsKey::parse);
    }
}

#[test]
fn misc_msgs_adversarial() {
    // TcpPacket -1/32768 boundary: see `msg/misc.rs::tcp_packet`.
    for &(line, ok) in &[
        ("17", false),
        ("17 ", false),
        ("17 99999", false), // > i16
        ("17 0 trailing", true),
    ] {
        probe("TcpPacket", line, ok, TcpPacket::parse);
    }
    probe("SptpsPacket", "21", false, SptpsPacket::parse);
    for &(line, ok) in &[
        ("22 a b 1.1.1.1", false), // missing port
        ("22 a b 1.1.1.1 655 extra", true),
    ] {
        probe("UdpInfo", line, ok, UdpInfo::parse);
    }
    // MtuInfo non-int already in `msg/misc.rs`.
    for &(line, ok) in &[
        ("23 a b", false),
        ("23 a b 2147483648", false), // i32 overflow
        ("23 a b -1", true),          // policy check is handler-side
    ] {
        probe("MtuInfo", line, ok, MtuInfo::parse);
    }
}

// ────────────────────────────────────────────────────────────────────
// Blind fuzz: arbitrary bytes → every parser. No result assertion;
// only that nothing panics. `from_utf8_lossy` because the parsers
// take &str — non-UTF-8 is handled one layer up (tincd's
// `parse_add_edge` etc. do the `from_utf8` check) and that layer is
// covered by the integration test.

/// Feed `s` to every public parse entry point. Results discarded; the
/// proptest assertion is "nothing panicked".
fn parse_all(s: &str) {
    let _ = Request::peek(s);
    let _ = check_id(s);
    let _ = s.parse::<Subnet>();
    let _ = AddEdge::parse(s);
    let _ = DelEdge::parse(s);
    let _ = SubnetMsg::parse(s);
    let _ = KeyChanged::parse(s);
    let _ = ReqKey::parse(s);
    let _ = AnsKey::parse(s);
    let _ = TcpPacket::parse(s);
    let _ = SptpsPacket::parse(s);
    let _ = UdpInfo::parse(s);
    let _ = MtuInfo::parse(s);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4000))]

    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
        parse_all(&String::from_utf8_lossy(&bytes));
    }

    /// Same, but with the input space biased toward "looks like a
    /// protocol line": digits + spaces + a few punctuation chars.
    /// Arbitrary bytes above will mostly bounce off the first-token
    /// int parse; this gets deeper.
    #[test]
    fn arbitrary_tokens_never_panic(s in r"[0-9a-fA-F.:/_# +\-]{0,200}") {
        parse_all(&s);
    }
}
