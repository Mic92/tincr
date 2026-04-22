//! Port-probe: BEP 5 KRPC `ping` from tincd's own UDP listener to learn
//! the NAT mapping for the *correct* socket (mainline's BEP 42 vote sees
//! mainline's socket, not ours). See module doc in `mod.rs`.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

/// Port-probe re-send interval. UDP conntrack timeout floors: netfilter
/// default 30s (unreplied) / 180s (assured), consumer routers 30–60s, CGNAT
/// 30s. The seed *did* reply so we're in "assured" on most NATs, but a
/// paranoid box might track per-direction. 25s sits under everything.
pub(super) const PROBE_KEEPALIVE: Duration = Duration::from_secs(25);

/// How many DHT nodes to probe per round. One honest reply is enough; three
/// covers transient packet loss. The full-cone hole is per-mapping, not
/// per-destination, so probing more nodes doesn't open more holes — it
/// just gets us more chances at the echo.
pub(super) const PROBE_FANOUT: usize = 3;

/// BEP 5 KRPC `ping` query, hand-rolled bencode. 58 bytes, fixed.
///
/// `a.id` is 20 zero bytes: `ping` responses don't depend on requester id,
/// and a zero id fails BEP 42's secure-id check so we're omitted from the
/// responder's routing table (intended — we're a freeloader). `t=b"tnc1"`
/// is arbitrary; the daemon demuxes replies on source addr, not tid.
pub const PORT_PROBE_PING: &[u8; 58] = b"d1:ad2:id20:\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
      \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
      e1:q4:ping1:t4:tnc11:y1:qe";

/// Parse the BEP 42 `ip` field out of a KRPC response. Substring scan,
/// not full bencode decode: bencode dict keys are sorted, so `ip` is
/// always at offset 1 in conformant replies; the scan tolerates encoders
/// that don't sort. P(false-match in the 20-byte id) ≈ 5×10⁻¹⁴, and the
/// daemon's source-addr gate is the real defence anyway.
///
/// `mainline` unconditionally fills `ip`; libtorrent/transmission have
/// since ~2015. Nodes that omit it → `None` → retry next round.
#[must_use]
pub fn parse_port_probe_reply(pkt: &[u8]) -> Option<SocketAddrV4> {
    const MARKER: &[u8; 6] = b"2:ip6:";
    if pkt.first() != Some(&b'd') {
        return None;
    }
    let idx = pkt.windows(6).position(|w| w == MARKER)?;
    let payload = pkt.get(idx + 6..idx + 12)?;
    // BEP 42 `ip` encoding: 4 octets + 2-byte big-endian port.
    let ip = Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]);
    let port = u16::from_be_bytes([payload[4], payload[5]]);
    Some(SocketAddrV4::new(ip, port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    /// What `testnet_port_probe_roundtrip` can't reach: out-of-spec
    /// inputs (mainline always sorts, always fills `ip`).
    #[test]
    fn port_probe_reply_parse_edges() {
        // Unsorted keys (`ip` not at offset 1): scan still finds it.
        let unsorted: Vec<u8> =
            [b"d1:y1:r2:ip6:".as_ref(), &[10, 20, 30, 40, 0, 80], b"e"].concat();
        assert_eq!(
            parse_port_probe_reply(&unsorted),
            Some("10.20.30.40:80".parse().unwrap())
        );
        // No `ip` (responder doesn't implement BEP 42): None.
        assert_eq!(
            parse_port_probe_reply(b"d1:rd2:id20:....................e1:y1:re"),
            None
        );
    }

    /// Hand-rolled `PORT_PROBE_PING` → real `serde_bencode` deserializer →
    /// real mainline server → real `serde_bencode` serializer → our
    /// `windows(6)` scanner. No mocks. If either end of the contract
    /// drifts, this catches it.
    #[test]
    fn testnet_port_probe_roundtrip() {
        use mainline::Testnet;
        use std::net::UdpSocket;

        let testnet = Testnet::new(1).expect("testnet");
        let target: SocketAddr = testnet.bootstrap[0].parse().expect("testnet addr");

        // recvfrom timeout: a busted PORT_PROBE_PING gets silently
        // dropped, becomes a test failure not a hang.
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind");
        sock.set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set_read_timeout");
        let local = match sock.local_addr().expect("local_addr") {
            SocketAddr::V4(a) => a,
            SocketAddr::V6(_) => unreachable!("bound to 127.0.0.1"),
        };

        sock.send_to(PORT_PROBE_PING, target).expect("send_to");

        let mut buf = [0u8; 256];
        let (n, from) = sock.recv_from(&mut buf).expect(
            "no reply from testnet — PORT_PROBE_PING bencode \
             likely rejected by mainline's deserializer",
        );
        assert_eq!(from, target, "reply from wrong source");

        let echoed =
            parse_port_probe_reply(&buf[..n]).expect("reply lacks `ip` field (or scan is wrong)");
        assert_eq!(
            echoed, local,
            "BEP 42 echo mismatch — \
             check sockaddr_to_bytes encoding (port endianness?)"
        );
    }
}
