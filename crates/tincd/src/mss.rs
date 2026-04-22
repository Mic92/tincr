//! TCP MSS option clamping.
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
/// 802.1Q VLAN tag.
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
pub(crate) fn clamp(packet: &mut [u8], mtu: u16) -> bool {
    // Read ethertype from eth header. We must bounds-check
    // (upstream gates this earlier in routing).
    if packet.len() < ETHER_SIZE {
        return false;
    }
    let mut start = ETHER_SIZE;
    let mut ethertype = u16::from(packet[12]) << 8 | u16::from(packet[13]);

    // 802.1Q: skip the 4-byte VLAN tag and re-read the inner
    // ethertype at offset 16/17. Only one tag (no QinQ).
    if ethertype == ETH_P_8021Q {
        start += 4;
        if packet.len() < 18 {
            return false;
        }
        ethertype = u16::from(packet[16]) << 8 | u16::from(packet[17]);
    }

    // IP-in-IP (RFC 2003). Outer IPv4 with protocol field (offset
    // +9) == 4 → the payload is another IPv4 header. Skip a fixed
    // 20 bytes (assumes the outer
    // IP header has no options, IHL=5).
    //
    // We must bounds-check the [start+9] read here, since a
    // 14-byte frame with type=0800 would
    // otherwise read OOB.
    if ethertype == ETH_P_IP {
        if packet.len() <= start + 9 {
            return false;
        }
        if packet[start + 9] == 4 {
            start += 20;
        }
    }

    // Must have at least a minimal IP header's worth of bytes left.
    if packet.len() <= start + 20 {
        return false;
    }

    // Find TCP. v4: protocol byte at +9 must be 6, then skip IHL*4
    // bytes. v6: next-header byte at +6 must be 6, then skip the
    // fixed 40-byte header. (No v6 ext-header
    // chasing — the C doesn't either.)
    if ethertype == ETH_P_IP && packet[start + 9] == 6 {
        // IHL is the low nibble of the first byte, units of 4 bytes.
        let ihl = (packet[start] & 0x0f) as usize;
        start += ihl * 4;
    } else if ethertype == ETH_P_IPV6 && packet[start + 6] == 6 {
        start += 40;
    } else {
        return false;
    }

    // Must have at least a minimal TCP header (20 bytes) after the
    // IP header.
    if packet.len() <= start + 20 {
        return false;
    }

    // TCP data-offset (high nibble of byte 12, in 32-bit words).
    // Options span from byte 20 to doff*4. `(doff - 5) * 4` =
    // option-bytes count. Upstream uses signed `int`
    // here; doff < 5 makes `len` negative and the loop body never
    // runs. We use usize, so guard explicitly.
    let doff = (packet[start + 12] >> 4) as usize;
    if doff < 5 {
        return false;
    }
    let opt_len = (doff - 5) * 4;

    // Full options region must be in-bounds.
    if packet.len() < start + 20 + opt_len {
        return false;
    }

    // TCP option TLV walk. Options are [kind, len, data...] EXCEPT
    // kind 0 (EOL, 1 byte) and kind 1 (NOP, 1 byte) which have no
    // len byte.
    let mut i = 0usize;
    while i < opt_len {
        let kind = packet[start + 20 + i];

        // End-of-options. Stop.
        if kind == 0 {
            return false;
        }

        // NOP. Single byte, no length.
        if kind == 1 {
            i += 1;
            continue;
        }

        // Bounds check on the length byte and the option body.
        // `i > opt_len - 2` means the length byte itself would be
        // OOB. `i > opt_len - opt[i+1]`
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

        // Not MSS: skip by stated length. The `< 2` guard catches
        // malformed options claiming length 0 or 1, which would
        // otherwise loop forever (0) or re-read the kind byte as a
        // new len (1).
        if kind != 2 {
            if this_len < 2 {
                return false;
            }
            i += this_len;
            continue;
        }

        // MSS option must have length exactly 4 (kind, len, 2-byte
        // MSS).
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

        // Read the existing MSS (big-endian).
        let oldmss = u16::from(packet[start + 22 + i]) << 8 | u16::from(packet[start + 23 + i]);

        // newmss is the path MTU minus everything up to and
        // including the TCP header's first 20 bytes. `start` here
        // already counts eth + (vlan) + (outer IP) +
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

        // Never *increase* the MSS. The peer chose a smaller value
        // for a reason (its own MTU, maybe).
        if oldmss <= newmss {
            return false;
        }

        // Write the new MSS, big-endian.
        packet[start + 22 + i] = (newmss >> 8) as u8;
        packet[start + 23 + i] = (newmss & 0xff) as u8;

        // Incremental TCP checksum adjustment, RFC 1624. The TCP
        // checksum is the one's-complement of
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
        #[allow(clippy::cast_possible_truncation)] // two folds above guarantee high half is zero
        let csum = !(csum as u16);
        let [hi, lo] = csum.to_be_bytes();
        packet[start + 16] = hi;
        packet[start + 17] = lo;

        return true;
    }

    false
}

#[cfg(test)]
mod tests;
