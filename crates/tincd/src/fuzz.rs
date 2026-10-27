//! Entry points for `fuzz/` (cargo-fuzz). Each takes arbitrary bytes and
//! drives one parser that sees peer- or TUN-controlled input. The only
//! property is "does not panic". Return values are ignored.
//!
//! Only compiled with the `fuzzing` feature (and in tests, so
//! minimised crash inputs can be replayed as ordinary unit tests).

use std::collections::HashMap;
use std::fs::File;
use std::os::fd::OwnedFd;
use std::time::Instant;

use tinc_crypto::os_rng;
use tinc_crypto::sign::SigningKey;
use tinc_sptps::{Framing, Output, Role, Sptps};

use crate::conn::{Connection, FeedResult};

use crate::route_mac::Mac;
use crate::socks::{ProxyType, ProxyWait};
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

/// SOCKS4/5 and HTTP CONNECT proxy replies.
pub fn socks_reply(data: &[u8]) {
    for wait in [
        ProxyWait::Socks(ProxyType::Socks4),
        ProxyWait::Socks(ProxyType::Socks5),
        ProxyWait::Http,
    ] {
        if let socks::Reply::Granted(n) = socks::parse_reply(wait, data) {
            assert!(n <= data.len());
        }
    }
}

/// Established meta SPTPS pair: the sender and a post-ACK `Connection`.
fn meta_pair() -> Option<(Sptps, Connection)> {
    let start = |role, me: u8, him: u8| {
        let hispub = *SigningKey::from_seed(&[him; 32]).public_key();
        let mykey = SigningKey::from_seed(&[me; 32]);
        Sptps::start(
            role,
            Framing::Stream,
            mykey,
            hispub,
            b"fuzz".to_vec(),
            0,
            &mut os_rng(),
        )
    };
    let (mut a, a_kex) = start(Role::Initiator, 1, 2);
    let (mut b, b_kex) = start(Role::Responder, 2, 1);
    let (mut to_a, mut to_b) = (wire(b_kex), wire(a_kex));
    while !to_a.is_empty() || !to_b.is_empty() {
        let next_b = deliver(&mut a, &to_a)?;
        let next_a = deliver(&mut b, &to_b)?;
        (to_a, to_b) = (next_a, next_b);
    }
    let fd = OwnedFd::from(File::open("/dev/null").ok()?);
    let addr = ([127, 0, 0, 1], 655).into();
    let mut conn = Connection::new_meta(fd, "fuzz".into(), addr, Instant::now());
    conn.allow_request = None;
    conn.sptps = Some(Box::new(b));
    Some((a, conn))
}

fn wire(outs: Vec<Output>) -> Vec<u8> {
    outs.into_iter()
        .filter_map(|o| match o {
            Output::Wire { bytes, .. } => Some(bytes),
            _ => None,
        })
        .flatten()
        .collect()
}

/// Feed `bytes` to `s`, return what it sends back.
fn deliver(s: &mut Sptps, mut bytes: &[u8]) -> Option<Vec<u8>> {
    let mut reply = Vec::new();
    while !bytes.is_empty() {
        let (n, outs) = s.receive(bytes, &mut os_rng()).ok()?;
        bytes = bytes.get(n..)?;
        reply.extend(wire(outs));
    }
    Some(reply)
}

/// Meta stream framing (`17`/`21` payloads, records, raw bytes) through
/// `Connection::feed_bytes`. Segments: `[tag][len][bytes]`, where tag bit
/// 7 sends the bytes raw and otherwise seals them as a record of type
/// `tag & 0x7f`. The first byte picks the read size.
pub fn meta_feed(data: &[u8]) {
    let Some((&chunk, mut rest)) = data.split_first() else {
        return;
    };
    let Some((mut tx, mut conn)) = meta_pair() else {
        return;
    };
    let mut stream = Vec::new();
    while let [tag, len, tail @ ..] = rest {
        let n = usize::from(*len).min(tail.len());
        let (body, tail) = tail.split_at(n);
        if tag & 0x80 != 0 {
            stream.extend_from_slice(body);
        } else if let Ok(outs) = tx.send_record(tag & 0x7f, body) {
            for o in outs {
                if let Output::Wire { bytes, .. } = o {
                    stream.extend(bytes);
                }
            }
        }
        rest = tail;
    }
    for piece in stream.chunks(usize::from(chunk).max(1)) {
        if matches!(conn.feed_bytes(piece, &mut os_rng()), FeedResult::Dead) {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    //! Minimised crash inputs from `fuzz/artifacts/` live here, one
    //! `#[test]` per bug, until the class guard (Phase 1 lints) makes
    //! them redundant.

    use super::{meta_feed, mss_clamp, route_frame, socks_reply};

    #[test]
    fn smoke() {
        for data in [&[][..], &[0; 64], &[0xff; 1600]] {
            mss_clamp(data);
            route_frame(data);
            socks_reply(data);
            meta_feed(data);
        }
        meta_feed(b"\x03\x00\x0517 4\n\x00\x0421 9\x00\x0621 11\n\x80\x0bjunkjunkjun\x00\x028\n");
    }
}
