//! `parse(format(x)) == x` over valid values; the KATs in `src/` pin the
//! grammar to C's and cover invalid input.

use proptest::prelude::*;
use std::net::{Ipv4Addr, Ipv6Addr};
use tinc_proto::msg::{AddEdge, AnsKey, DelEdge, MtuInfo, ReqKey, ReqKeyExt, UdpInfo};
use tinc_proto::{AddrStr, Subnet};

/// The `check_id` charset.
fn arb_name() -> impl Strategy<Value = String> {
    "[A-Za-z0-9_]{1,32}"
}

fn arb_name_pair() -> impl Strategy<Value = (String, String)> {
    (arb_name(), arb_name()).prop_filter("from != to", |(a, b)| a != b)
}

/// `AF_UNKNOWN` makes addresses "any token" on the wire.
fn arb_addr() -> impl Strategy<Value = AddrStr> {
    "[!-~]{1,40}".prop_map(|s| AddrStr::new(s).unwrap())
}

fn arb_token() -> impl Strategy<Value = String> {
    "[!-~]{1,200}".prop_map(String::from)
}

prop_compose! {
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

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn subnet_roundtrip(s in arb_subnet()) {
        let wire = s.to_string();
        let back: Subnet = wire.parse().unwrap();
        prop_assert_eq!(s, back, "wire={:?}", wire);
    }

    /// Exactly one wire form per value.
    #[test]
    fn subnet_canonical(s in arb_subnet()) {
        let wire1 = s.to_string();
        let back: Subnet = wire1.parse().unwrap();
        let wire2 = back.to_string();
        prop_assert_eq!(wire1, wire2);
    }

    /// C parses subnet strings into a 64-byte buffer.
    #[test]
    fn subnet_fits_buffer(s in arb_subnet()) {
        prop_assert!(s.to_string().len() < 64);
    }
}

proptest! {
    /// `aa:bb:cc:dd:ee:ff` is also valid abbreviated v6; MAC must win.
    #[test]
    fn mac_never_parses_as_v6(addr in any::<[u8; 6]>()) {
        let s = Subnet::Mac { addr, weight: 10 };
        let wire = s.to_string();
        let back: Subnet = wire.parse().unwrap();
        prop_assert!(matches!(back, Subnet::Mac { .. }), "{wire:?} parsed as non-MAC");
    }

    /// RFC 5952 output is never MAC-shaped (either `::` or 8 groups).
    #[test]
    fn v6_display_never_macish(addr in any::<u128>().prop_map(Ipv6Addr::from)) {
        let s = Subnet::V6 { addr, prefix: 128, weight: 10 };
        let wire = s.to_string();
        let parts: Vec<_> = wire.split(':').collect();
        let macish = parts.len() == 6
            && !wire.contains("::")
            && parts.iter().all(|p| !p.is_empty() && p.len() <= 2
                && p.chars().all(|c| c.is_ascii_hexdigit()));
        prop_assert!(!macish, "v6 Display produced MAC-ambiguous {wire:?}");
    }
}

/// The nonce is not part of the struct (parse skips it), so it is fixed.
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
