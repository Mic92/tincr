//! Property tests: `parse(format(x)) == x`.
//!
//! These don't prove wire compat — that's the KATs in `subnet.rs`. They
//! prove the *Rust* parse and format agree on a grammar. The KATs pin
//! that grammar to the C's.
//!
//! Generators are constrained to the Rust types' invariants (e.g.
//! `prefix <= 32` for v4). The full input space — including invalid
//! prefixes — is exercised by the KATs' reject cases.

use proptest::prelude::*;
use std::net::{Ipv4Addr, Ipv6Addr};
use tinc_proto::msg::{AddEdge, AnsKey, DelEdge, MtuInfo, ReqKey, ReqKeyExt, UdpInfo};
use tinc_proto::{AddrStr, Subnet};

// ────────────────────────────────────────────────────────────────────
// Shared generators

/// Node names: `[A-Za-z0-9_]+`. The proptest regex strategy is the right
/// fit — it's exactly the `check_id` charset. Cap at 32 chars; real names
/// are short, and longer ones just slow shrinking without finding bugs.
fn arb_name() -> impl Strategy<Value = String> {
    "[A-Za-z0-9_]{1,32}"
}

/// Two distinct node names. Edges can't self-loop.
fn arb_name_pair() -> impl Strategy<Value = (String, String)> {
    (arb_name(), arb_name()).prop_filter("from != to", |(a, b)| a != b)
}

/// Address-string token. Any non-whitespace ASCII printable, capped
/// short. Real addresses are `inet_ntop` output but `AF_UNKNOWN` makes
/// the wire grammar "any token", so we generate the full space.
fn arb_addr() -> impl Strategy<Value = AddrStr> {
    "[!-~]{1,40}".prop_map(|s| AddrStr::new(s).unwrap())
}

/// Generic non-whitespace token (key hex, base64 payload). Same shape
/// as `arb_addr` but distinct generator so the intent is clear.
fn arb_token() -> impl Strategy<Value = String> {
    "[!-~]{1,200}".prop_map(String::from)
}

// ────────────────────────────────────────────────────────────────────
// Generators

prop_compose! {
    /// Any v4 subnet with prefix in range.
    fn arb_v4()(
        addr in any::<u32>().prop_map(Ipv4Addr::from),
        prefix in 0u8..=32,
        weight in any::<i32>(),
    ) -> Subnet {
        Subnet::V4 { addr, prefix, weight }
    }
}

prop_compose! {
    fn arb_v6()(
        addr in any::<u128>().prop_map(Ipv6Addr::from),
        prefix in 0u8..=128,
        weight in any::<i32>(),
    ) -> Subnet {
        Subnet::V6 { addr, prefix, weight }
    }
}

prop_compose! {
    fn arb_mac()(
        addr in any::<[u8; 6]>(),
        weight in any::<i32>(),
    ) -> Subnet {
        Subnet::Mac { addr, weight }
    }
}

fn arb_subnet() -> impl Strategy<Value = Subnet> {
    prop_oneof![arb_v4(), arb_v6(), arb_mac()]
}

// ────────────────────────────────────────────────────────────────────
// Properties

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// `parse(format(x)) == x`. The fundamental round-trip.
    ///
    /// What this *doesn't* catch: a parser that accepts more than the
    /// formatter emits. That's ok — the C parser is also more lenient
    /// than the formatter (one-digit MAC parts, etc.). The KATs cover
    /// the lenient-input cases.
    #[test]
    fn subnet_roundtrip(s in arb_subnet()) {
        let wire = s.to_string();
        let back: Subnet = wire.parse().unwrap();
        prop_assert_eq!(s, back, "wire={:?}", wire);
    }

    /// `format(x)` is canonical: re-parsing then re-formatting is identity.
    /// Stronger than the above — proves there's exactly one wire form per
    /// Subnet value.
    #[test]
    fn subnet_canonical(s in arb_subnet()) {
        let wire1 = s.to_string();
        let back: Subnet = wire1.parse().unwrap();
        let wire2 = back.to_string();
        prop_assert_eq!(wire1, wire2);
    }

    /// Display output never exceeds the C's 64-byte buffer (the `strncpy`
    /// in `str2net`). MAC is fixed-length 17; v6 caps at 39 + `/128#` +
    /// 11 digits = ~55. This guards against accidentally overflowing it
    /// with a future format change.
    #[test]
    fn subnet_fits_buffer(s in arb_subnet()) {
        prop_assert!(s.to_string().len() < 64);
    }
}

// ────────────────────────────────────────────────────────────────────
// MAC↔v6 disambiguation regression.
//
// The proptest above won't trigger this — `arb_mac` produces MACs and
// `arb_v6` produces v6, neither generates the ambiguous middle. This
// test does it manually.

proptest! {
    /// Any MAC, formatted, parses as MAC. Never as v6.
    ///
    /// `Display` emits `%02x:` so all parts are 2-digit. A 6-part
    /// 2-digit colon-separated string is *also* valid v6-abbreviated
    /// syntax (it'd parse as `aa:bb:cc:dd:ee:ff::`). The MAC-first
    /// ordering in `from_str` ensures it doesn't.
    #[test]
    fn mac_never_parses_as_v6(addr in any::<[u8; 6]>()) {
        let s = Subnet::Mac { addr, weight: 10 };
        let wire = s.to_string();
        // Round-trip already covers this, but the check here is explicit
        // about *what* would go wrong: parsing as the wrong variant.
        let back: Subnet = wire.parse().unwrap();
        prop_assert!(matches!(back, Subnet::Mac { .. }), "{wire:?} parsed as non-MAC");
    }

    /// V6 addresses with exactly 6 visible groups: do they collide with MAC?
    ///
    /// `1:2:3:4:5:6` is both. But `Display` for v6 uses RFC 5952, which
    /// for 6 explicit groups would only emit if there's a `::` somewhere
    /// (otherwise it's 8 groups). So the *output* of v6 Display is never
    /// MAC-ambiguous, only certain *inputs* are. The KAT in subnet.rs
    /// covers the input ambiguity; this just confirms output is safe.
    #[test]
    fn v6_display_never_macish(addr in any::<u128>().prop_map(Ipv6Addr::from)) {
        let s = Subnet::V6 { addr, prefix: 128, weight: 10 };
        let wire = s.to_string();
        // 6 colon-separated parts, all 1-2 hex digits, no `/` or `#`?
        // That'd be MAC-ambiguous. RFC 5952 doesn't produce this:
        // either there's a `::` (≤7 parts but contains "::") or there
        // are 8 parts. Count parts and check for `::`.
        let parts: Vec<_> = wire.split(':').collect();
        let macish = parts.len() == 6
            && !wire.contains("::")
            && parts.iter().all(|p| !p.is_empty() && p.len() <= 2
                && p.chars().all(|c| c.is_ascii_hexdigit()));
        prop_assert!(!macish, "v6 Display produced MAC-ambiguous {wire:?}");
    }
}

// ────────────────────────────────────────────────────────────────────
// Message round-trips. One per struct that has both parse and format.
//
// The pattern is the same throughout: generate a struct, format, parse,
// assert equal. Macro-ized to keep the boilerplate down.

/// Generate a struct, format it (with whatever args `format` takes),
/// re-parse, assert. The `nonce` for nonce-taking formats is fixed: it's
/// not part of the struct (parse skips it with `%*x`), so it doesn't
/// affect the round-trip.
macro_rules! roundtrip {
    ($name:ident, $ty:ty, $strategy:expr_2021, $fmt:expr_2021) => {
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(1000))]
            #[test]
            fn $name(m in $strategy) {
                let wire = $fmt(&m);
                let back = <$ty>::parse(&wire).unwrap();
                prop_assert_eq!(m, back, "wire={:?}", wire);
            }
        }
    };
}

prop_compose! {
    fn arb_add_edge()(
        (from, to) in arb_name_pair(),
        addr in arb_addr(),
        port in arb_addr(),
        options in any::<u32>(),
        // Clamped to >=0 at parse; generate the post-clamp domain.
        weight in 0i32..,
        local in proptest::option::of((arb_addr(), arb_addr())),
    ) -> AddEdge {
        AddEdge { from, to, addr, port, options, weight, local }
    }
}
roundtrip!(add_edge, AddEdge, arb_add_edge(), |m: &AddEdge| m
    .format(0x42));

prop_compose! {
    fn arb_del_edge()((from, to) in arb_name_pair()) -> DelEdge {
        DelEdge { from, to }
    }
}
roundtrip!(del_edge, DelEdge, arb_del_edge(), |m: &DelEdge| m
    .format(0x42));

prop_compose! {
    fn arb_udp_info()(
        from in arb_name(),
        to in arb_name(),
        addr in arb_addr(),
        port in arb_addr(),
    ) -> UdpInfo {
        UdpInfo { from, to, addr, port }
    }
}
roundtrip!(udp_info, UdpInfo, arb_udp_info(), UdpInfo::format);

prop_compose! {
    fn arb_mtu_info()(
        from in arb_name(),
        to in arb_name(),
        mtu in any::<i32>(),
    ) -> MtuInfo {
        MtuInfo { from, to, mtu, udp_rx_len: 0 }
    }
}
roundtrip!(mtu_info, MtuInfo, arb_mtu_info(), MtuInfo::format);

prop_compose! {
    fn arb_req_key()(
        from in arb_name(),
        to in arb_name(),
        ext in proptest::option::of((
            any::<i32>(),
            proptest::option::of(arb_token()),
        ).prop_map(|(reqno, payload)| ReqKeyExt { reqno, payload })),
    ) -> ReqKey {
        // udp_addr None: only round-trips when ext.payload is Some
        // (positional tail); relay path guarantees that, generator doesn't.
        ReqKey { from, to, ext, udp_addr: None }
    }
}
roundtrip!(req_key, ReqKey, arb_req_key(), ReqKey::format);

prop_compose! {
    fn arb_ans_key()(
        from in arb_name(),
        to in arb_name(),
        key in arb_token(),
        cipher in any::<i32>(),
        digest in any::<i32>(),
        maclen in any::<u64>(),
        compression in any::<i32>(),
        udp_addr in proptest::option::of((arb_addr(), arb_addr())),
    ) -> AnsKey {
        AnsKey { from, to, key, cipher, digest, maclen, compression, udp_addr }
    }
}
roundtrip!(ans_key, AnsKey, arb_ans_key(), AnsKey::format);
