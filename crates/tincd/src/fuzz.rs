//! Entry points for `fuzz/` (cargo-fuzz). Each takes arbitrary bytes and
//! drives one parser that sees peer- or TUN-controlled input. The only
//! property is "does not panic". Return values are ignored.
//!
//! Only compiled with the `fuzzing` feature (and in tests, so
//! minimised crash inputs can be replayed as ordinary unit tests).

use std::collections::HashMap;

use crate::route_mac::Mac;
use crate::subnet_tree::SubnetTree;
use crate::{fragment, icmp, mss, neighbor, route_decide, route_mac, socks};

/// Split a little-endian `u16` parameter off the front.
fn take_u16(data: &[u8]) -> (u16, &[u8]) {
    match data {
        [a, b, rest @ ..] => (u16::from_le_bytes([*a, *b]), rest),
        _ => (0, data),
    }
}

/// `mss::clamp` on a full ethernet frame. First two bytes: MTU.
pub fn mss_clamp(data: &[u8]) {
    let (mtu, frame) = take_u16(data);
    let _ = mss::clamp(&mut frame.to_vec(), mtu);
}

/// Router- and switch-mode routing plus everything that builds a reply
/// from the routed frame (ICMP errors, ARP/NDP, fragmentation). First
/// two bytes: MTU for the fragmenter and the ICMP `nextmtu` field.
pub fn route_frame(data: &[u8]) {
    let (mtu, frame) = take_u16(data);

    let mut subnets = SubnetTree::new();
    for (subnet, owner) in [
        ("10.0.0.0/8", "bob"),
        ("10.1.2.3/32", "carol"),
        ("fd00::/8", "bob"),
        ("fd00::1/128", "carol"),
        ("02:00:00:00:00:01", "bob"),
    ] {
        #[expect(clippy::expect_used, reason = "static literals")]
        subnets.add(subnet.parse().expect("static subnet"), owner.to_owned());
    }
    let _ = route_decide::route(frame, &subnets, |name| Some(name.to_owned()));

    let macs: HashMap<Mac, String> = HashMap::from([([2, 0, 0, 0, 0, 1], "bob".to_owned())]);
    for from_myself in [false, true] {
        let _ = route_mac::route_mac(frame, from_myself, "bob", "alice", &macs, |name| {
            Some(name.to_owned())
        });
    }

    let _ = icmp::build_v4_unreachable(frame, 3, 4, Some(mtu), None);
    let _ = icmp::build_v4_unreachable(frame, 11, 0, None, Some([10, 0, 0, 1]));
    let _ = icmp::build_v6_unreachable(frame, 2, 0, Some(u32::from(mtu)), None);
    let _ = icmp::build_v6_unreachable(frame, 3, 0, None, Some([0xfd; 16]));
    if neighbor::parse_arp_req(frame).is_some() {
        let _ = neighbor::build_arp_reply(frame);
    }
    if neighbor::parse_ndp_solicit(frame).is_some() {
        let _ = neighbor::build_ndp_advert(frame);
    }
    let _ = fragment::fragment_v4(frame, mtu);
}

/// SOCKS4/5 proxy replies.
pub fn socks_reply(data: &[u8]) {
    for proxy in [socks::ProxyType::Socks4, socks::ProxyType::Socks5] {
        let _ = socks::check_response(proxy, None, data);
    }
}

#[cfg(test)]
mod tests {
    //! Minimised crash inputs from `fuzz/artifacts/` live here, one
    //! `#[test]` per bug, until the class guard (Phase 1 lints) makes
    //! them redundant.

    use super::{mss_clamp, route_frame, socks_reply};

    #[test]
    fn smoke() {
        for data in [&[][..], &[0; 64], &[0xff; 1600]] {
            mss_clamp(data);
            route_frame(data);
            socks_reply(data);
        }
    }
}
