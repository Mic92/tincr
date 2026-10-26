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

use crate::wire::{be16, put_be16, u8_at};

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
/// 802.1Q VLAN tag.
const ETH_P_8021Q: u16 = 0x8100;

/// Ethernet header is 14 bytes (`route.c` `ether_size`).
const ETHER_SIZE: usize = 14;

/// Find a TCP MSS option in the ethernet frame `packet` and clamp it to `mtu -
/// hdrs`. Returns `true` if modified. Handles one 802.1Q tag, one level of IP-in-IP
/// (RFC 2003), v4 and v6. Anything else, including malformed input, is a no-op.
#[must_use]
pub(crate) fn clamp(packet: &mut [u8], mtu: u16) -> bool {
    clamp_checked(packet, mtu).is_some()
}

fn clamp_checked(packet: &mut [u8], mtu: u16) -> Option<()> {
    let mut start = ETHER_SIZE;
    let mut ethertype = be16(packet, 12)?;

    // One VLAN tag, no QinQ.
    if ethertype == ETH_P_8021Q {
        start += 4;
        ethertype = be16(packet, 16)?;
    }

    // IP-in-IP (RFC 2003): outer protocol 4 means another IPv4 header
    // follows. The outer IHL is assumed to be 5, as in C.
    if ethertype == ETH_P_IP && u8_at(packet, start + 9)? == 4 {
        start += 20;
    }

    // A minimal IP header must be present.
    if packet.len() <= start + 20 {
        return None;
    }

    // No v6 extension-header chasing. C doesn't either.
    match ethertype {
        ETH_P_IP if u8_at(packet, start + 9)? == 6 => {
            start += usize::from(u8_at(packet, start)? & 0x0f) * 4;
        }
        ETH_P_IPV6 if u8_at(packet, start + 6)? == 6 => start += 40,
        _ => return None,
    }

    if packet.len() <= start + 20 {
        return None;
    }

    let doff = usize::from(u8_at(packet, start + 12)? >> 4);
    let opt_len = doff.checked_sub(5)? * 4;
    let opts = packet.get(start + 20..start + 20 + opt_len)?;

    // Options are [kind, len, data...] except EOL (0) and NOP (1).
    let mut i = 0usize;
    let mss_at = loop {
        match *opts.get(i)? {
            0 => return None,
            1 => i += 1,
            kind => {
                let this_len = usize::from(*opts.get(i + 1)?);
                if this_len < 2 || this_len > opt_len - i {
                    return None;
                }
                if kind == 2 {
                    // C checks the first option's length byte here, not
                    // this one's. With that, a short MSS option at the end
                    // read past the packet.
                    if this_len != 4 {
                        return None;
                    }
                    break start + 22 + i;
                }
                i += this_len;
            }
        }
    };

    let oldmss = be16(packet, mss_at)?;
    // Payload left after eth + (vlan) + (outer IP) + IP + 20-byte TCP.
    let newmss = mtu.checked_sub(u16::try_from(start + 20).ok()?)?;
    // Never raise it. The peer may have its own reasons.
    if oldmss <= newmss {
        return None;
    }

    // RFC 1624 eqn 3: HC' = ~(~HC + ~m + m'), summed in u32, folded twice.
    let csum_at = start + 16;
    let mut csum = u32::from(be16(packet, csum_at)? ^ 0xffff);
    csum += u32::from(oldmss ^ 0xffff);
    csum += u32::from(newmss);
    csum = (csum & 0xffff) + (csum >> 16);
    csum += csum >> 16;
    #[expect(clippy::cast_possible_truncation)] // two folds leave 16 bits
    let csum = !(csum as u16);

    put_be16(packet, mss_at, newmss)?;
    put_be16(packet, csum_at, csum)
}

#[cfg(test)]
mod tests;
