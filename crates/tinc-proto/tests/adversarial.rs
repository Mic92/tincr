//! Malformed input to every parser: tables of hand-picked lines with
//! their expected Ok/Err, plus a proptest that only checks for panics.
//! Lines accepted for C compatibility are pinned as `Ok` so tightening
//! them is a visible test change.

use proptest::prelude::{ProptestConfig, any, proptest};

use std::panic;
use std::panic::AssertUnwindSafe;
use tinc_proto::msg::{
    AddEdge, AnsKey, DelEdge, KeyChanged, MtuInfo, ReqKey, SptpsPacket, SubnetMsg, TcpPacket,
    UdpInfo,
};
use tinc_proto::{MAX_STRING, Request, Subnet, check_id};

fn probe<T, E>(what: &str, line: &str, want_ok: bool, parse: impl FnOnce(&str) -> Result<T, E>) {
    // So a panic names the input.
    let r = panic::catch_unwind(AssertUnwindSafe(|| parse(line)));
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
        let r = panic::catch_unwind(|| Request::peek(s));
        assert!(matches!(r, Ok(None)), "peek({s:?}) = {r:?}");
    }
}

#[test]
fn check_id_garbage() {
    // The path-traversal gate.
    for s in ["", ".", "..", "../x", "a/b", "a\0b", "a b", "a\n", "ä"] {
        assert!(!check_id(s), "check_id({s:?}) accepted");
    }
    // No length cap, as in C.
    let huge = "a".repeat(MAX_STRING);
    assert!(check_id(&huge));
}

#[test]
fn add_edge_adversarial() {
    #[rustfmt::skip]
    let cases: &[(&str, bool)] = &[
        // truncation
        ("",                                                false),
        ("12",                                              false),
        ("12 0",                                            false),
        ("12 0 a",                                          false),
        ("12 0 a b",                                        false),
        ("12 0 a b 1.1.1.1",                                false),
        ("12 0 a b 1.1.1.1 655",                            false),
        ("12 0 a b 1.1.1.1 655 0",                          false),
        // integer overflow / wrong type
        ("12 0 a b 1.1.1.1 655 0 99999999999999999999",     false), // weight > i64
        ("12 0 a b 1.1.1.1 655 0 2147483648",               false), // weight = i32::MAX+1
        ("12 0 a b 1.1.1.1 655 ffffffffffffffff 1",         false), // options > u32
        ("12 0 a b 1.1.1.1 655 0 -2147483648",              true),  // i32::MIN — silly but %d
        ("12 0 a b 1.1.1.1 655 0 +1",                       true),  // Rust i32 parse accepts +
        ("12 0 a b 1.1.1.1 655 0 1.5",                      false), // float weight
        ("12 0 a b 1.1.1.1 655 -1 1",                       false), // negative hex
        // extra / odd tokens
        ("12 0 a b 1.1.1.1 655 0 1 la lp extra",            true),  // 9th token ignored (sscanf compat)
        ("12 0 a b 1.1.1.1 655 0 1 lonelylocal",            false), // 7-token reject (already KAT'd; here for completeness)
        // name validation
        ("12 0 a\0x b 1.1.1.1 655 0 1",                     false), // embedded NUL
        ("12 0 .. b 1.1.1.1 655 0 1",                       false), // path traversal
        ("12 0 a a 1.1.1.1 655 0 1",                        false), // self-loop
        // whitespace variants
        ("12\t0\ta\tb\t1.1.1.1\t655\t0\t1",                 true),  // tabs split like spaces
        ("12  0  a  b  1.1.1.1  655  0  1",                 true),  // double-space
        ("  12 0 a b 1.1.1.1 655 0 1  ",                    true),  // leading/trailing
    ];
    for &(line, ok) in cases {
        probe("AddEdge", line, ok, AddEdge::parse);
    }
    // MAX_STRING is 2048.
    let huge = format!("12 0 {} b 1.1.1.1 655 0 1", "a".repeat(MAX_STRING));
    probe("AddEdge", &huge, true, AddEdge::parse);
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
    for &(line, ok) in &[
        ("14", false),
        ("14 0", false),
        // NUL is a token; KeyChanged does not check_id (as in C).
        ("14 0 \0", true),
        ("14 0 anything!goes", true),
    ] {
        probe("KeyChanged", line, ok, KeyChanged::parse);
    }

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
    for &(line, ok) in &[
        ("23 a b", false),
        ("23 a b 2147483648", false), // i32 overflow
        ("23 a b -1", true),          // policy check is handler-side
    ] {
        probe("MtuInfo", line, ok, MtuInfo::parse);
    }
}

/// Non-UTF-8 is rejected a layer up in tincd, hence `&str` here.
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

    /// Biased towards protocol-looking lines to get past the first token.
    #[test]
    fn arbitrary_tokens_never_panic(s in r"[0-9a-fA-F.:/_# +\-]{0,200}") {
        parse_all(&s);
    }
}
