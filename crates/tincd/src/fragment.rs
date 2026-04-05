//! RFC 791 IPv4 fragmentation.
//!
//! Only used for the rare case: relaying a too-big IPv4 packet with
//! DF clear. Modern OSes set DF on TCP (PMTUD); this fires for legacy
//! UDP / weird configs. We could drop these (we did before this
//! commit) but RFC 791 §2.3 says routers MUST fragment.
//!
//! The 8-byte alignment (`& !7`) is RFC 791 §3.2: the fragment-offset
//! field is in units of 8 bytes, so every fragment except the last
//! must carry a payload whose length is a multiple of 8.
//!
//! ## Re-fragmentation edge case
//!
//! ```c
//! origf = ip_off & ~IP_OFFMASK;   // preserve DF/MF from original
//! ip_off &= IP_OFFMASK;           // start at original offset
//! ```
//!
//! The input might ALREADY be a fragment (someone upstream fragmented
//! a 4000-byte UDP packet at MTU 1500; one of those 1500-byte
//! fragments now hits our 590-byte hop). Its MF bit is set and its
//! offset is nonzero. We must preserve MF on ALL our output pieces
//! (the original "more fragments" follow ours) and continue counting
//! from the original offset. The C handles this; we port it.

#![forbid(unsafe_code)]

use zerocopy::{FromBytes, IntoBytes};

use crate::packet::{IP_MF, IP_OFFMASK, Ipv4Hdr, inet_checksum};

const ETH_SIZE: usize = 14;
const IP_SIZE: usize = 20;

/// Splits `frame` (eth + IPv4, DF clear, no options) into fragments
/// that fit `dest_mtu`. Returns `None` if the input is malformed
/// (IP options, length mismatch).
/// caller drops.
///
/// `dest_mtu` is the tinc-layer MTU (eth + ip + payload max).
/// Callers apply `MAX(dest->mtu, 590)` at the call site.
#[must_use]
pub fn fragment_v4(frame: &[u8], dest_mtu: u16) -> Option<Vec<Vec<u8>>> {
    if frame.len() < ETH_SIZE + IP_SIZE {
        return None;
    }

    let ip_bytes: &[u8; 20] = frame[ETH_SIZE..ETH_SIZE + IP_SIZE].try_into().ok()?;
    let mut ip = Ipv4Hdr::read_from_bytes(ip_bytes).ok()?;

    // ip.ip_hl != ip_size/4 — options? bail. RFC 791 permits
    // copying options into fragments (per-option Copy bit); we
    // don't bother. Options-carrying packets are
    // vanishingly rare on the modern internet.
    if usize::from(ip.ihl()) != IP_SIZE / 4 {
        return None;
    }

    let ip_len = usize::from(ip.total_len());
    if ip_len < IP_SIZE {
        return None;
    }
    let mut todo = ip_len - IP_SIZE;

    // Length mismatch — header lied or frame is short/padded.
    if ETH_SIZE + IP_SIZE + todo != frame.len() {
        return None;
    }

    // maxlen = (MAX(dest->mtu, 590) - ether_size - ip_size) & ~0x7.
    // The & ~7: fragment offset is in 8-byte units (RFC 791 §3.2),
    // so payload length (except last) must be ≡ 0 mod 8.
    // Caller has already done the MAX(,590) floor, so dest_mtu ≥ 590
    // and the subtraction never wraps.
    let dest_mtu = usize::from(dest_mtu);
    if dest_mtu <= ETH_SIZE + IP_SIZE {
        return None; // defensive; caller floors at 590
    }
    let maxlen = (dest_mtu - ETH_SIZE - IP_SIZE) & !7;
    if maxlen == 0 {
        return None;
    }

    // `origf` preserves the original's flag bits. Normally 0 (DF is
    // clear or we wouldn't be here). But if the input is ALREADY a
    // fragment, its MF bit is set — preserve it on all our pieces.
    let ip_off_full = ip.off();
    let origf = ip_off_full & !IP_OFFMASK;
    let mut ip_off = ip_off_full & IP_OFFMASK;

    let eth_hdr = &frame[..ETH_SIZE];
    let payload = &frame[ETH_SIZE + IP_SIZE..];
    let mut offset = 0usize;
    let mut out = Vec::new();

    while todo > 0 {
        let len = todo.min(maxlen);

        // len ≤ maxlen < dest_mtu ≤ u16::MAX, so IP_SIZE+len fits.
        #[allow(clippy::cast_possible_truncation)] // len < dest_mtu (u16) per above
        ip.set_total_len((IP_SIZE + len) as u16);

        // MF on every fragment except the last — UNLESS origf already
        // has MF set (re-fragmentation), in which case all get it.
        let mf = if todo > len { IP_MF } else { 0 };
        ip.set_off(ip_off | origf | mf);

        ip.ip_sum = 0;
        ip.ip_sum = inet_checksum(ip.as_bytes(), !0);

        let mut frag = Vec::with_capacity(ETH_SIZE + IP_SIZE + len);
        frag.extend_from_slice(eth_hdr);
        frag.extend_from_slice(ip.as_bytes());
        frag.extend_from_slice(&payload[offset..offset + len]);
        out.push(frag);

        // Offset in 8-byte units (RFC 791). `len` is a multiple of 8
        // for all but the last fragment, where ip_off is no longer
        // used.
        todo -= len;
        offset += len;
        #[allow(clippy::cast_possible_truncation)] // len < dest_mtu (u16); /8 makes it smaller
        {
            ip_off += (len / 8) as u16;
        }
    }

    Some(out)
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)] // test fixtures: known-small lengths
mod tests {
    use super::*;

    /// Build a test frame: 14B eth + 20B IPv4 (no options) + payload.
    fn mkframe(payload_len: usize, ip_off: u16) -> Vec<u8> {
        let mut ip = Ipv4Hdr::default();
        ip.set_vhl(4, 5);
        ip.ip_tos = 0;
        ip.set_total_len(u16::try_from(IP_SIZE + payload_len).unwrap());
        ip.set_id(0x1234);
        ip.set_off(ip_off);
        ip.ip_ttl = 64;
        ip.ip_p = 17; // UDP
        ip.ip_src = [10, 0, 0, 1];
        ip.ip_dst = [10, 0, 0, 2];
        ip.ip_sum = 0;
        ip.ip_sum = inet_checksum(ip.as_bytes(), !0);

        let mut f = Vec::with_capacity(ETH_SIZE + IP_SIZE + payload_len);
        // eth: dst, src, ethertype 0x0800
        f.extend_from_slice(&[0xaa; 6]);
        f.extend_from_slice(&[0xbb; 6]);
        f.extend_from_slice(&[0x08, 0x00]);
        f.extend_from_slice(ip.as_bytes());
        // payload: 0, 1, 2, ... wrapping
        f.extend((0..payload_len).map(|i| (i & 0xff) as u8));
        f
    }

    fn parse_ip(frag: &[u8]) -> Ipv4Hdr {
        Ipv4Hdr::read_from_bytes(&frag[ETH_SIZE..ETH_SIZE + IP_SIZE]).unwrap()
    }

    #[test]
    fn fragments_1500_at_mtu_590() {
        // 1500-byte frame: 14 + 20 + 1466 payload.
        let frame = mkframe(1466, 0);
        assert_eq!(frame.len(), 1500);

        let frags = fragment_v4(&frame, 590).expect("should fragment");
        // maxlen = (590 - 14 - 20) & !7 = 556 & !7 = 552
        // 1466 / 552 = 2 rem 362 → 3 fragments: 552, 552, 362
        assert_eq!(frags.len(), 3);

        let exp_paylens = [552usize, 552, 362];
        let exp_offs = [0u16, 552 / 8, 1104 / 8]; // 0, 69, 138
        let exp_mf = [IP_MF, IP_MF, 0];

        for (i, frag) in frags.iter().enumerate() {
            assert_eq!(frag.len(), ETH_SIZE + IP_SIZE + exp_paylens[i]);
            // eth header preserved verbatim
            assert_eq!(&frag[..ETH_SIZE], &frame[..ETH_SIZE]);

            let ip = parse_ip(frag);
            assert_eq!(ip.total_len(), (IP_SIZE + exp_paylens[i]) as u16);
            assert_eq!(ip.off() & IP_OFFMASK, exp_offs[i], "frag {i} offset");
            assert_eq!(ip.off() & IP_MF, exp_mf[i], "frag {i} MF bit");
            // id, ttl, proto, addrs preserved
            assert_eq!(ip.id(), 0x1234);
            assert_eq!(ip.ip_ttl, 64);
            assert_eq!(ip.ip_p, 17);
            assert_eq!(ip.ip_src, [10, 0, 0, 1]);
            assert_eq!(ip.ip_dst, [10, 0, 0, 2]);

            // checksum valid: inet_checksum over a correct header → 0
            let hdr = &frag[ETH_SIZE..ETH_SIZE + IP_SIZE];
            assert_eq!(inet_checksum(hdr, !0), 0, "frag {i} checksum");
        }
    }

    #[test]
    fn rejects_ip_options() {
        let mut frame = mkframe(100, 0);
        // ihl = 6 (24-byte header) — options present
        frame[ETH_SIZE] = (4 << 4) | 6;
        assert!(fragment_v4(&frame, 590).is_none());
    }

    #[test]
    fn rejects_length_mismatch() {
        let mut frame = mkframe(100, 0);
        // claim ip_len = 200 but frame only has 100 payload bytes
        let bogus: u16 = 20 + 200;
        frame[ETH_SIZE + 2..ETH_SIZE + 4].copy_from_slice(&bogus.to_be_bytes());
        assert!(fragment_v4(&frame, 590).is_none());

        // truncated frame
        let frame = mkframe(100, 0);
        assert!(fragment_v4(&frame[..frame.len() - 1], 590).is_none());
    }

    #[test]
    fn reassembly_roundtrip() {
        let frame = mkframe(1466, 0);
        let orig_payload = &frame[ETH_SIZE + IP_SIZE..];

        let frags = fragment_v4(&frame, 590).unwrap();

        // Reassemble: place each fragment's payload at its offset×8.
        let mut reassembled = vec![0u8; 1466];
        let mut covered = 0usize;
        for frag in &frags {
            let ip = parse_ip(frag);
            let off = usize::from(ip.off() & IP_OFFMASK) * 8;
            let pay = &frag[ETH_SIZE + IP_SIZE..];
            reassembled[off..off + pay.len()].copy_from_slice(pay);
            covered += pay.len();
        }
        assert_eq!(covered, 1466);
        assert_eq!(reassembled, orig_payload);
    }

    #[test]
    fn alignment_1499_payload() {
        // 1499-byte payload, mtu=590.
        // maxlen = (590 - 14 - 20) & !7 = 556 & !7 = 552.
        // 552 + 552 + 395 = 1499. First two are 8-aligned; last is 395.
        let frame = mkframe(1499, 0);
        let frags = fragment_v4(&frame, 590).unwrap();
        assert_eq!(frags.len(), 3);
        let paylens: Vec<_> = frags.iter().map(|f| f.len() - ETH_SIZE - IP_SIZE).collect();
        assert_eq!(paylens, vec![552, 552, 395]);
        // 552 % 8 == 0; 395 % 8 != 0 (last fragment, doesn't matter)
        assert_eq!(552 % 8, 0);
    }

    /// Re-fragmentation: input is already a middle fragment (MF set,
    /// nonzero offset). `origf` preservation.
    #[test]
    fn refragmentation_preserves_mf_and_offset() {
        // Input fragment: offset 100 (= 800 bytes into original), MF set.
        let start_off = 100u16;
        let frame = mkframe(1200, start_off | IP_MF);
        let frags = fragment_v4(&frame, 590).unwrap();
        // maxlen = 552; 1200 = 552 + 552 + 96 → 3 fragments
        assert_eq!(frags.len(), 3);

        let exp_offs = [start_off, start_off + 552 / 8, start_off + 1104 / 8]; // 100, 169, 238
        for (i, frag) in frags.iter().enumerate() {
            let ip = parse_ip(frag);
            // ALL fragments have MF set: the original had MF (more
            // fragments follow ours in the larger reassembly).
            assert_eq!(ip.off() & IP_MF, IP_MF, "frag {i} must have MF");
            assert_eq!(ip.off() & IP_OFFMASK, exp_offs[i], "frag {i} offset");
        }
    }

    #[test]
    fn rejects_too_short() {
        assert!(fragment_v4(&[0u8; 10], 590).is_none());
        assert!(fragment_v4(&[0u8; 33], 590).is_none());
    }
}
