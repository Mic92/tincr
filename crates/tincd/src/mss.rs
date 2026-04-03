//! TCP MSS option clamping (`route.c:389-487`).
//!
//! TCP advertises max segment size in the SYN's MSS option. If
//! both endpoints have 1500-MTU NICs but the tinc tunnel between
//! them has a 1400 effective MTU, they'll send 1460-byte segments
//! that fragment (or blackhole if DF is set). Rewriting the MSS
//! to 1360 in the SYN makes both ends pick a segment size that
//! fits.
//!
//! The mutation is in-place: 2 bytes for the new MSS, 2 bytes for
//! the incrementally-adjusted TCP checksum (RFC 1624). The C does
//! this on the per-forward hot path; we do too. No alloc.

#![forbid(unsafe_code)]

// Ethertypes. `ETH_P_IP`/`ETH_P_IPV6` are also in
// `tinc-device/src/ether.rs` but those are crate-private; we only
// need the literals for byte comparison so re-state them locally.
// `ETH_P_8021Q` is not anywhere else in the workspace yet.
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
/// 802.1Q VLAN tag (`route.c:404`).
const ETH_P_8021Q: u16 = 0x8100;

/// Ethernet header is 14 bytes (`route.c` `ether_size`).
const ETHER_SIZE: usize = 14;

/// Walk a packet for a TCP MSS option; clamp it to `mtu - hdrs`
/// if found. Returns `true` if modified.
///
/// `packet` is the full ethernet frame (14-byte eth hdr first).
/// Handles 8021Q (one tag, +4 bytes), IP-in-IP (RFC 2003, one
/// level), v4 and v6. Everything else: no-op, return `false`.
///
/// **Never panics on malformed packets** — every read is bounds-
/// checked, every "this can't be right" returns `false`. Forwarded
/// traffic is untrusted; this fn must be panic-free even on the
/// fuzz corpus.
#[must_use]
pub fn clamp(packet: &mut [u8], mtu: u16) -> bool {
    // route.c:401-402 — read ethertype from eth header.
    // C indexes [12]/[13] without a bounds check (it's gated on
    // packet routing earlier); we must check.
    if packet.len() < ETHER_SIZE {
        return false;
    }
    let mut start = ETHER_SIZE;
    let mut ethertype = u16::from(packet[12]) << 8 | u16::from(packet[13]);

    // route.c:404-407 — 802.1Q: skip the 4-byte VLAN tag and
    // re-read the inner ethertype at offset 16/17. Only one tag
    // (no QinQ); the C only handles one too.
    if ethertype == ETH_P_8021Q {
        start += 4;
        if packet.len() < 18 {
            return false;
        }
        ethertype = u16::from(packet[16]) << 8 | u16::from(packet[17]);
    }

    // route.c:410-413 — IP-in-IP (RFC 2003). Outer IPv4 with
    // protocol field (offset +9) == 4 → the payload is another
    // IPv4 header. Skip a fixed 20 bytes (the C assumes the outer
    // IP header has no options, IHL=5).
    //
    // Bounds: route.c:414 checks `len <= start+20` *after* this
    // bump, but the [start+9] read itself is unchecked in C. We
    // must check, since a 14-byte frame with type=0800 would
    // otherwise read OOB.
    if ethertype == ETH_P_IP {
        if packet.len() <= start + 9 {
            return false;
        }
        if packet[start + 9] == 4 {
            start += 20;
        }
    }

    // route.c:414-416 — must have at least a minimal IP header's
    // worth of bytes left.
    if packet.len() <= start + 20 {
        return false;
    }

    // route.c:418-424 — find TCP. v4: protocol byte at +9 must be
    // 6, then skip IHL*4 bytes. v6: next-header byte at +6 must be
    // 6, then skip the fixed 40-byte header. (No v6 ext-header
    // chasing — the C doesn't either.)
    if ethertype == ETH_P_IP && packet[start + 9] == 6 {
        // route.c:419 — IHL is the low nibble of the first byte,
        // in units of 4 bytes.
        let ihl = (packet[start] & 0x0f) as usize;
        start += ihl * 4;
    } else if ethertype == ETH_P_IPV6 && packet[start + 6] == 6 {
        start += 40;
    } else {
        return false;
    }

    // route.c:426-428 — must have at least a minimal TCP header
    // (20 bytes) after the IP header.
    if packet.len() <= start + 20 {
        return false;
    }

    // route.c:431 — TCP data-offset (high nibble of byte 12, in
    // 32-bit words). Options span from byte 20 to doff*4.
    // `(doff - 5) * 4` = option-bytes count. C uses signed `int`
    // here; doff < 5 makes `len` negative and the loop body never
    // runs. We use usize, so guard explicitly.
    let doff = (packet[start + 12] >> 4) as usize;
    if doff < 5 {
        return false;
    }
    let opt_len = (doff - 5) * 4;

    // route.c:433-435 — full options region must be in-bounds.
    if packet.len() < start + 20 + opt_len {
        return false;
    }

    // route.c:438-487 — TCP option TLV walk. Options are
    // [kind, len, data...] EXCEPT kind 0 (EOL, 1 byte) and kind 1
    // (NOP, 1 byte) which have no len byte.
    let mut i = 0usize;
    while i < opt_len {
        let kind = packet[start + 20 + i];

        // route.c:440-442 — End-of-options. Stop.
        if kind == 0 {
            return false;
        }

        // route.c:444-447 — NOP. Single byte, no length.
        if kind == 1 {
            i += 1;
            continue;
        }

        // route.c:449-451 — bounds check on the length byte and
        // the option body. `i > opt_len - 2` means the length
        // byte itself would be OOB. `i > opt_len - opt[i+1]`
        // means the body would overrun. The C reads
        // `packet[start+21+i]` inside the second condition; that
        // read is itself guarded by the first condition because
        // `i > opt_len - 2` short-circuits.
        //
        // We've already established `opt_len >= 2` here (kind!=0,
        // kind!=1, and i<opt_len means at least one byte; but the
        // C check `i > len-2` also handles the i==opt_len-1 case
        // where the len byte is missing). Mirror the C: compare
        // signed-style by lifting to checked subtraction.
        if i + 2 > opt_len {
            return false;
        }
        let this_len = packet[start + 21 + i] as usize;
        if this_len > opt_len - i {
            // option body would overrun the options region
            return false;
        }

        // route.c:453-460 — not MSS: skip by stated length.
        // The `< 2` guard (route.c:457) catches malformed options
        // claiming length 0 or 1, which would otherwise loop
        // forever (0) or re-read the kind byte as a new len (1).
        if kind != 2 {
            if this_len < 2 {
                return false;
            }
            i += this_len;
            continue;
        }

        // route.c:462-464 — MSS option must have length exactly 4
        // (kind, len, 2-byte MSS).
        //
        // Mirror the C bug-for-bug: it reads `packet[start+21]`
        // (NOT `+i`) — the *first* option's length byte, not this
        // one's. In practice MSS is almost always the first
        // option in a SYN, so the bug rarely fires. We replicate
        // it because the alternative (fixing it) changes
        // observable behavior on weird-but-valid packets, and
        // this module is a faithful port. The packet-level test
        // `mss_not_first_option_c_bug` documents this.
        if packet[start + 21] != 4 {
            return false;
        }

        // route.c:467-469 — read the existing MSS (big-endian).
        let oldmss = u16::from(packet[start + 22 + i]) << 8 | u16::from(packet[start + 23 + i]);

        // route.c:468 — newmss is the path MTU minus everything
        // up to and including the TCP header's first 20 bytes.
        // `start` here already counts eth + (vlan) + (outer IP) +
        // IP, so subtracting it from MTU and then subtracting the
        // 20-byte TCP fixed header leaves the max segment payload.
        // Guard against underflow: if mtu is absurdly small the C
        // would wrap (uint16_t arithmetic). We'd rather noop.
        let hdrs = start + 20;
        let Ok(hdrs_u16) = u16::try_from(hdrs) else {
            return false;
        };
        let Some(newmss) = mtu.checked_sub(hdrs_u16) else {
            return false;
        };

        // route.c:472-475 — never *increase* the MSS. The peer
        // chose a smaller value for a reason (its own MTU, maybe).
        if oldmss <= newmss {
            return false;
        }

        // route.c:477-478 — write the new MSS, big-endian.
        packet[start + 22 + i] = (newmss >> 8) as u8;
        packet[start + 23 + i] = (newmss & 0xff) as u8;

        // route.c:479-485 — incremental TCP checksum adjustment,
        // RFC 1624. The TCP checksum is the one's-complement of
        // the one's-complement sum over the pseudo-header + TCP
        // segment. We changed exactly one 16-bit word (the MSS).
        // RFC 1624 eqn 3: HC' = ~(~HC + ~m + m')
        //   where HC is the old checksum, m the old word, m' new.
        // The naive `HC - m + m'` is WRONG in one's-complement:
        // it doesn't handle the end-around carry, and gets the
        // 0x0000/0xFFFF edge cases wrong. The C does the math in
        // u32 to capture carry-out, then folds twice (because the
        // first fold can itself carry).
        let oldcsum = u32::from(packet[start + 16]) << 8 | u32::from(packet[start + 17]);
        let mut csum = oldcsum ^ 0xffff; // ~HC (16-bit)
        csum += u32::from(oldmss) ^ 0xffff; // + ~m
        csum += u32::from(newmss); // + m'
        csum = (csum & 0xffff) + (csum >> 16); // fold carry
        csum += csum >> 16; // fold again (the fold can carry once more)
        // After two folds csum fits in 16 bits; truncate-then-complement.
        #[allow(clippy::cast_possible_truncation)]
        let csum = !(csum as u16);
        let [hi, lo] = csum.to_be_bytes();
        packet[start + 16] = hi;
        packet[start + 17] = lo;

        return true;
    }

    false
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)] // test fixtures: known-small lengths
mod tests {
    use super::*;

    /// One's-complement sum over 16-bit big-endian words. For
    /// verifying the incremental checksum update produced a valid
    /// result. Reference impl, not optimized.
    fn ones_sum(data: &[u8]) -> u32 {
        let mut sum = 0u32;
        for chunk in data.chunks(2) {
            let word = if chunk.len() == 2 {
                u32::from(chunk[0]) << 8 | u32::from(chunk[1])
            } else {
                u32::from(chunk[0]) << 8
            };
            sum += word;
        }
        sum
    }

    fn fold(mut sum: u32) -> u16 {
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        sum as u16
    }

    /// Compute TCP checksum (IPv4 pseudo-header + TCP segment).
    fn tcp4_checksum(src: [u8; 4], dst: [u8; 4], tcp: &[u8]) -> u16 {
        let mut sum = ones_sum(&src);
        sum += ones_sum(&dst);
        sum += 6; // protocol
        sum += tcp.len() as u32;
        sum += ones_sum(tcp);
        !fold(sum)
    }

    /// Compute TCP checksum (IPv6 pseudo-header + TCP segment).
    fn tcp6_checksum(src: [u8; 16], dst: [u8; 16], tcp: &[u8]) -> u16 {
        let mut sum = ones_sum(&src);
        sum += ones_sum(&dst);
        sum += tcp.len() as u32; // upper-layer length (we know it fits)
        sum += 6; // next header
        sum += ones_sum(tcp);
        !fold(sum)
    }

    /// Build a minimal eth+IPv4+TCP frame with the given TCP
    /// options. IP src=10.0.0.1 dst=10.0.0.2. Computes a valid
    /// TCP checksum so we can verify the incremental update.
    fn build_v4_tcp(opts: &[u8]) -> Vec<u8> {
        assert_eq!(opts.len() % 4, 0, "TCP opts must be 4-aligned");
        let doff = 5 + opts.len() / 4;
        let tcp_len = 20 + opts.len();
        let ip_len = 20 + tcp_len;

        let mut pkt = Vec::new();
        // eth: dst, src, type
        pkt.extend_from_slice(&[0xff; 6]);
        pkt.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
        pkt.extend_from_slice(&ETH_P_IP.to_be_bytes());

        // IPv4 header (20 bytes, no options, no IP checksum —
        // clamp_mss never reads it)
        let src = [10, 0, 0, 1];
        let dst = [10, 0, 0, 2];
        pkt.push(0x45); // ver=4 ihl=5
        pkt.push(0); // tos
        pkt.extend_from_slice(&(ip_len as u16).to_be_bytes());
        pkt.extend_from_slice(&[0, 0, 0, 0]); // id, frag
        pkt.push(64); // ttl
        pkt.push(6); // proto = TCP
        pkt.extend_from_slice(&[0, 0]); // ip csum (don't care)
        pkt.extend_from_slice(&src);
        pkt.extend_from_slice(&dst);

        // TCP header
        let tcp_start = pkt.len();
        pkt.extend_from_slice(&12345u16.to_be_bytes()); // sport
        pkt.extend_from_slice(&80u16.to_be_bytes()); // dport
        pkt.extend_from_slice(&[0; 4]); // seq
        pkt.extend_from_slice(&[0; 4]); // ack
        pkt.push((doff as u8) << 4); // doff | reserved
        pkt.push(0x02); // SYN flag
        pkt.extend_from_slice(&65535u16.to_be_bytes()); // win
        pkt.extend_from_slice(&[0, 0]); // csum placeholder
        pkt.extend_from_slice(&[0, 0]); // urg
        pkt.extend_from_slice(opts);

        // Fill in the real TCP checksum.
        let csum = tcp4_checksum(src, dst, &pkt[tcp_start..]);
        pkt[tcp_start + 16] = (csum >> 8) as u8;
        pkt[tcp_start + 17] = (csum & 0xff) as u8;

        pkt
    }

    /// Verify a v4 packet's TCP checksum is valid (used post-clamp
    /// to check the incremental adjust).
    fn verify_v4_tcp_csum(pkt: &[u8], ip_off: usize) -> bool {
        let src: [u8; 4] = pkt[ip_off + 12..ip_off + 16].try_into().unwrap();
        let dst: [u8; 4] = pkt[ip_off + 16..ip_off + 20].try_into().unwrap();
        let ihl = (pkt[ip_off] & 0x0f) as usize * 4;
        let tcp = &pkt[ip_off + ihl..];
        // Including the checksum field, the one's-complement sum
        // over pseudo+segment must fold to 0xffff (RFC 1071).
        let mut sum = ones_sum(&src);
        sum += ones_sum(&dst);
        sum += 6;
        sum += tcp.len() as u32;
        sum += ones_sum(tcp);
        fold(sum) == 0xffff
    }

    #[test]
    fn clamps_basic_v4_syn() {
        // MSS=1460 (0x05b4). mtu=1400. start = 14+20 = 34.
        // newmss = 1400 - 34 - 20 = 1346 (0x0542).
        let mut pkt = build_v4_tcp(&[0x02, 0x04, 0x05, 0xb4]);
        assert!(verify_v4_tcp_csum(&pkt, 14), "precondition: csum valid");

        assert!(clamp(&mut pkt, 1400));

        // MSS bytes at eth(14) + ip(20) + tcp_fixed(20) + 2 = 56,57
        assert_eq!(pkt[56], 0x05);
        assert_eq!(pkt[57], 0x42);
        assert_eq!(u16::from_be_bytes([pkt[56], pkt[57]]), 1346);

        // The whole point: incremental checksum is still valid.
        assert!(verify_v4_tcp_csum(&pkt, 14), "post-clamp csum valid");
    }

    #[test]
    fn does_not_increase() {
        // MSS=1200, mtu=1500. newmss would be 1500-54=1446 > 1200.
        // route.c:472 — `if oldmss <= newmss: break`.
        let mut pkt = build_v4_tcp(&[0x02, 0x04, 0x04, 0xb0]); // 1200
        let before = pkt.clone();
        assert!(!clamp(&mut pkt, 1500));
        assert_eq!(pkt, before);
    }

    #[test]
    fn no_mss_option_noop() {
        // Just NOPs. No MSS to find.
        let mut pkt = build_v4_tcp(&[0x01, 0x01, 0x01, 0x01]);
        let before = pkt.clone();
        assert!(!clamp(&mut pkt, 1400));
        assert_eq!(pkt, before);
    }

    #[test]
    fn eol_stops_walk() {
        // EOL before MSS — should stop and not see it.
        // [EOL, pad, MSS=1460] — but EOL is at i=0.
        let mut pkt = build_v4_tcp(&[0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x00, 0x00]);
        let before = pkt.clone();
        assert!(!clamp(&mut pkt, 1400));
        assert_eq!(pkt, before);
    }

    #[test]
    fn non_tcp_noop() {
        // proto=17 (UDP). Should return false at the proto gate.
        let mut pkt = build_v4_tcp(&[0x02, 0x04, 0x05, 0xb4]);
        pkt[14 + 9] = 17;
        let before = pkt.clone();
        assert!(!clamp(&mut pkt, 1400));
        assert_eq!(pkt, before);
    }

    #[test]
    fn skips_other_option_then_finds_mss() {
        // [opt 8 (timestamp) len=10, ..8 bytes.., NOP, NOP, MSS]
        // Wait — route.c:462 reads packet[start+21] which is the
        // FIRST option's len byte (10), not the MSS option's (4).
        // So this would bail. The C bug. Skip; covered separately.
        //
        // Instead test: [NOP, NOP, NOP, NOP, MSS]. NOPs are
        // single-byte so they don't trip the start+21 check.
        // But MSS is at i=4, so packet[start+21] is the byte at
        // i=1 — a NOP (0x01). 0x01 != 4 → bail. ALSO the C bug.
        //
        // The only way MSS gets clamped is if the byte at
        // start+21 happens to be 4. That's: MSS first (its own
        // len), or something else with len=4 first. Test the
        // realistic case in `clamps_basic_v4_syn` (MSS first);
        // document the bug here.
        //
        // Actually verify: [opt 3 (wscale, len=3), NOP, MSS].
        // start+21 = wscale's len byte = 3. 3 != 4 → bail.
        let mut pkt = build_v4_tcp(&[0x03, 0x03, 0x07, 0x01, 0x02, 0x04, 0x05, 0xb4]);
        let before = pkt.clone();
        assert!(!clamp(&mut pkt, 1400));
        assert_eq!(pkt, before, "C bug: start+21 not start+21+i");
    }

    #[test]
    fn mss_after_len4_opt_works_by_accident() {
        // The one case where MSS-not-first still works: the first
        // option also has length 4. SACK-permitted is len=2; make
        // up a len-4 opt (kind 30, MPTCP, can be 4 bytes).
        // [kind=30, len=4, 0, 0, MSS=1460].
        let mut pkt = build_v4_tcp(&[30, 4, 0, 0, 0x02, 0x04, 0x05, 0xb4]);
        assert!(clamp(&mut pkt, 1400));
        // MSS is at start+20+4+2 = 14+20+20+6 = 60,61
        assert_eq!(u16::from_be_bytes([pkt[60], pkt[61]]), 1346);
        assert!(verify_v4_tcp_csum(&pkt, 14));
    }

    #[test]
    fn vlan_tagged() {
        // 8021Q: insert [81 00 vid_hi vid_lo] after src MAC.
        // start becomes 18. newmss = 1400 - (18+20) - 20 = 1342.
        let inner = build_v4_tcp(&[0x02, 0x04, 0x05, 0xb4]);
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&inner[0..12]); // dst+src MAC
        pkt.extend_from_slice(&[0x81, 0x00, 0x00, 0x42]); // VLAN tag, vid=66
        pkt.extend_from_slice(&inner[12..]); // ethertype + rest

        assert!(clamp(&mut pkt, 1400));
        // MSS at 18 + 20 + 20 + 2 = 60,61
        assert_eq!(u16::from_be_bytes([pkt[60], pkt[61]]), 1342);
        assert!(verify_v4_tcp_csum(&pkt, 18));
    }

    #[test]
    fn ip_in_ip() {
        // Outer IPv4 (proto=4) wrapping inner IPv4 (proto=6).
        // start = 14 + 20 (outer skipped) = 34, then +20 (inner IHL)
        // = 54. newmss = 1400 - 54 - 20 = 1326.
        let inner_tcp = build_v4_tcp(&[0x02, 0x04, 0x05, 0xb4]);
        // inner_tcp = [eth 14][ip 20][tcp 24]. We want eth +
        // outer_ip + inner_ip + tcp. Splice in an outer IP header
        // with proto=4 right after eth.
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&inner_tcp[0..14]); // eth
        // outer IPv4, 20 bytes, proto=4
        let inner_len = inner_tcp.len() - 14; // ip+tcp
        let outer_len = 20 + inner_len;
        pkt.push(0x45);
        pkt.push(0);
        pkt.extend_from_slice(&(outer_len as u16).to_be_bytes());
        pkt.extend_from_slice(&[0, 0, 0, 0]);
        pkt.push(64);
        pkt.push(4); // proto = IP-in-IP
        pkt.extend_from_slice(&[0, 0]);
        pkt.extend_from_slice(&[192, 168, 1, 1]);
        pkt.extend_from_slice(&[192, 168, 1, 2]);
        // inner IP + TCP (from inner_tcp, skip eth)
        pkt.extend_from_slice(&inner_tcp[14..]);

        assert!(clamp(&mut pkt, 1400));
        // MSS at 14 + 20 + 20 + 20 + 2 = 76,77
        assert_eq!(u16::from_be_bytes([pkt[76], pkt[77]]), 1326);
        // Inner IP starts at 34.
        assert!(verify_v4_tcp_csum(&pkt, 34));
    }

    #[test]
    fn malformed_opt_len_0() {
        // Option kind=5 (SACK) with len=0. route.c:457 catches
        // this — `len < 2 → break`. Otherwise i += 0 loops forever.
        let mut pkt = build_v4_tcp(&[0x05, 0x00, 0x00, 0x00]);
        let before = pkt.clone();
        assert!(!clamp(&mut pkt, 1400));
        assert_eq!(pkt, before);
    }

    #[test]
    fn malformed_opt_len_1() {
        // len=1: the length byte counts the kind but not itself.
        // i += 1 would re-read the len byte as a new kind. Also
        // caught by route.c:457.
        let mut pkt = build_v4_tcp(&[0x05, 0x01, 0x00, 0x00]);
        let before = pkt.clone();
        assert!(!clamp(&mut pkt, 1400));
        assert_eq!(pkt, before);
    }

    #[test]
    fn malformed_opt_len_overrun() {
        // Option claims len=200 but only 4 bytes of options exist.
        // route.c:449-451 — `i > len - opt_len` catches this.
        let mut pkt = build_v4_tcp(&[0x05, 200, 0x00, 0x00]);
        let before = pkt.clone();
        assert!(!clamp(&mut pkt, 1400));
        assert_eq!(pkt, before);
    }

    #[test]
    fn truncated_after_mss_kind() {
        // doff says 6 (24-byte TCP header, 4 opt bytes) but the
        // packet was cut short. route.c:433 — `len < start+20+len`.
        let mut pkt = build_v4_tcp(&[0x02, 0x04, 0x05, 0xb4]);
        pkt.truncate(pkt.len() - 2); // chop the MSS value
        let before = pkt.clone();
        assert!(!clamp(&mut pkt, 1400));
        assert_eq!(pkt, before);
    }

    #[test]
    fn doff_less_than_5_noop() {
        // doff=4 → option length would be negative. C uses signed
        // int (loop never runs); we explicitly guard.
        let mut pkt = build_v4_tcp(&[0x02, 0x04, 0x05, 0xb4]);
        pkt[14 + 20 + 12] = 4 << 4;
        let before = pkt.clone();
        assert!(!clamp(&mut pkt, 1400));
        assert_eq!(pkt, before);
    }

    #[test]
    fn v6_basic() {
        // eth(14) + ipv6(40) + tcp(24, MSS=1440 typical for v6).
        // start = 14+40 = 54. newmss = 1400 - 54 - 20 = 1326.
        let src = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let opts = [0x02, 0x04, 0x05, 0xa0]; // MSS=1440

        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0xff; 6]);
        pkt.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
        pkt.extend_from_slice(&ETH_P_IPV6.to_be_bytes());

        // IPv6 header (40 bytes)
        pkt.extend_from_slice(&[0x60, 0, 0, 0]); // ver=6, tc=0, flow=0
        pkt.extend_from_slice(&24u16.to_be_bytes()); // payload len = TCP
        pkt.push(6); // next header = TCP
        pkt.push(64); // hop limit
        pkt.extend_from_slice(&src);
        pkt.extend_from_slice(&dst);

        // TCP
        let tcp_start = pkt.len();
        pkt.extend_from_slice(&12345u16.to_be_bytes());
        pkt.extend_from_slice(&80u16.to_be_bytes());
        pkt.extend_from_slice(&[0; 8]); // seq+ack
        pkt.push(6 << 4); // doff=6
        pkt.push(0x02); // SYN
        pkt.extend_from_slice(&65535u16.to_be_bytes());
        pkt.extend_from_slice(&[0, 0]); // csum
        pkt.extend_from_slice(&[0, 0]); // urg
        pkt.extend_from_slice(&opts);

        let csum = tcp6_checksum(src, dst, &pkt[tcp_start..]);
        pkt[tcp_start + 16] = (csum >> 8) as u8;
        pkt[tcp_start + 17] = (csum & 0xff) as u8;

        assert!(clamp(&mut pkt, 1400));

        // MSS at 14 + 40 + 20 + 2 = 76,77
        assert_eq!(u16::from_be_bytes([pkt[76], pkt[77]]), 1326);

        // Verify v6 checksum still valid.
        let mut sum = ones_sum(&src);
        sum += ones_sum(&dst);
        sum += 24;
        sum += 6;
        sum += ones_sum(&pkt[tcp_start..]);
        assert_eq!(fold(sum), 0xffff);
    }

    #[test]
    fn mtu_too_small_noop() {
        // mtu=40 < start(34)+20=54. C would wrap u16; we noop.
        let mut pkt = build_v4_tcp(&[0x02, 0x04, 0x05, 0xb4]);
        let before = pkt.clone();
        assert!(!clamp(&mut pkt, 40));
        assert_eq!(pkt, before);
    }

    #[test]
    fn empty_packet_noop() {
        let mut pkt = vec![];
        assert!(!clamp(&mut pkt, 1400));
    }

    #[test]
    fn short_packet_noop() {
        // 13 bytes — can't even read ethertype.
        let mut pkt = vec![0u8; 13];
        assert!(!clamp(&mut pkt, 1400));
    }

    #[test]
    fn vlan_but_truncated() {
        // ethertype=8021Q but packet ends before inner ethertype.
        let mut pkt = vec![0u8; 16];
        pkt[12] = 0x81;
        pkt[13] = 0x00;
        assert!(!clamp(&mut pkt, 1400));
    }

    #[test]
    fn ihl_with_options() {
        // IPv4 with IHL=6 (24-byte header, 4 option bytes).
        // start = 14 + 24 = 38. newmss = 1400 - 38 - 20 = 1342.
        let base = build_v4_tcp(&[0x02, 0x04, 0x05, 0xb4]);
        // Splice 4 bytes of IP options after the 20-byte IP hdr.
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&base[0..14]); // eth
        pkt.push(0x46); // ver=4 ihl=6
        pkt.extend_from_slice(&base[15..34]); // rest of IP hdr (proto etc.)
        pkt.extend_from_slice(&[0, 0, 0, 0]); // 4 bytes IP options (NOPs)
        pkt.extend_from_slice(&base[34..]); // TCP

        // Recompute the TCP checksum (the test helper hardcoded
        // ihl=5 so the old csum is for a different layout — but
        // actually the TCP segment bytes are identical and the
        // pseudo-header doesn't include IHL, so it's still valid).
        assert!(clamp(&mut pkt, 1400));
        // MSS at 14 + 24 + 20 + 2 = 60,61
        assert_eq!(u16::from_be_bytes([pkt[60], pkt[61]]), 1342);
        assert!(verify_v4_tcp_csum(&pkt, 14));
    }

    /// RFC 1624 §3 — the edge case that motivates the whole
    /// `~(~HC + ~m + m')` dance. If the only contributing word
    /// changes from 0x0000 to something, naive subtraction breaks.
    #[test]
    fn checksum_adjust_edge_cases() {
        // Build a packet, clamp it, then independently recompute
        // the checksum from scratch — they must match. This is
        // the strongest possible check. Covered by
        // `clamps_basic_v4_syn` already, but try a sweep of
        // old/new MSS values to hit carry-out paths.
        for oldmss in [1460u16, 65535, 1, 0x8000, 0x7fff, 0xfffe] {
            // Pick mtu so newmss < oldmss.
            for mtu in [55u16, 100, 1400] {
                let opts = [0x02, 0x04, (oldmss >> 8) as u8, (oldmss & 0xff) as u8];
                let mut pkt = build_v4_tcp(&opts);
                let modified = clamp(&mut pkt, mtu);
                let newmss = mtu.saturating_sub(54);
                if newmss < oldmss && newmss > 0 {
                    assert!(modified, "oldmss={oldmss} mtu={mtu}");
                    assert!(
                        verify_v4_tcp_csum(&pkt, 14),
                        "checksum invalid after clamp: oldmss={oldmss} mtu={mtu}"
                    );
                }
            }
        }
    }
}
