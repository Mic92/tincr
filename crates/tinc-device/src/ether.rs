//! Ethernet header constants + synthesis. RFC 894 / IEEE 802.3
//! / IANA registry. Not platform-specific.
//!
//! Hoisted from `fd.rs` when BSD became a second consumer. The
//! `read_fd`/`write_fd` don't-factor rule is about platform-varying
//! syscalls; RFC constants don't vary across `cfg`. `pub(crate)`:
//! header synthesis is a backend concern; the daemon only reads.
//!
//! Not here: `ETH_P_ALL` (Linux `PF_PACKET` API value, not a wire
//! ethertype — stays in `raw.rs`); `AF_INET6` (per-platform kernel
//! ABI: 10/Linux, 28/FreeBSD, 30/macOS — stays in `bsd.rs` via
//! `libc`). `0x86DD` is wire-format truth; `AF_INET6` is local
//! convention.

// Ethernet header constants — RFC 894, IEEE 802.3

/// dhost(6) + shost(6) + type(2).
pub(crate) const ETH_HLEN: usize = 14;

/// `ETH_HLEN - ETHER_TYPE_LEN = 12` is the ethertype offset.
const ETHER_TYPE_LEN: usize = 2;

/// IPv4 ethertype. Host order; `to_be_bytes()` at write time.
pub(crate) const ETH_P_IP: u16 = 0x0800;

/// IPv6 ethertype.
pub(crate) const ETH_P_IPV6: u16 = 0x86DD;

/// IP version nibble (high nibble of `buf[ETH_HLEN]`) → ethertype. `None` for
/// unknown versions; the caller drops.
#[must_use]
pub(crate) const fn from_ip_nibble(ip0: u8) -> Option<u16> {
    match ip0 >> 4 {
        4 => Some(ETH_P_IP),
        6 => Some(ETH_P_IPV6),
        _ => None,
    }
}

// set_etherheader — zero MACs + write ethertype

/// Zero MACs, write big-endian ethertype. The MAC zero and the
/// ethertype write touch disjoint bytes (`[0..12]` vs `[12..14]`)
/// so order doesn't matter. Caller guarantees `buf.len() ≥ 14`.
pub(crate) fn set_etherheader(buf: &mut [u8], ethertype: u16) {
    // Zero MACs. 12 bytes. Not 14 — leave ethertype slot alone.
    buf[..ETH_HLEN - ETHER_TYPE_LEN].fill(0);
    // Ethertype, big-endian. Bytes 12-13.
    buf[ETH_HLEN - ETHER_TYPE_LEN..ETH_HLEN].copy_from_slice(&ethertype.to_be_bytes());
}

// Tests
//
// These were in `fd.rs::tests`. Moved with their subjects. Same
// tests, same assertions, same comments. The MOVE preserves test
// count (no new tests, no dropped tests); the diff is location.

#[cfg(test)]
mod tests {
    use super::*;

    // from_ip_nibble

    /// `from_ip_nibble(u8) -> Option<u16>`. Full domain in one
    /// table: only the HIGH nibble matters (IP version field).
    /// Unknown versions yield `None`.
    #[test]
    fn nibble_cases() {
        #[rustfmt::skip]
        let cases: &[(u8, Option<u16>)] = &[
            // IPv4: version=4 in high nibble, IHL in low.
            // `0x45` is the canonical IPv4 first byte (IHL=5 words =
            // 20 bytes, no options). `0x4F` is max IHL (60 bytes).
            (0x45, Some(ETH_P_IP)),
            (0x40, Some(ETH_P_IP)),
            (0x4F, Some(ETH_P_IP)),
            // IPv6: version=6 in high nibble, traffic class high
            // nibble in low. `0x60` is canonical (default TC).
            (0x60, Some(ETH_P_IPV6)),
            (0x6F, Some(ETH_P_IPV6)),
            // Unknown versions → None.
            // IP version 5 was ST-II (RFC 1819, experimental, dead).
            // Version 7-15 unassigned. Version 0-3 pre-IPv4 historical.
            (0x00, None),
            (0x50, None),  // ST-II
            (0x70, None),
            (0xFF, None),
        ];
        for (i, (ip0, expected)) in cases.iter().enumerate() {
            assert_eq!(from_ip_nibble(*ip0), *expected, "case {i}: {ip0:#04x}");
        }
    }

    // set_etherheader

    /// Zero MACs, write ethertype big-endian. Pre-fill with garbage
    /// to verify the zero and that bytes past 14 are untouched.
    #[test]
    fn set_etherheader_cases() {
        #[rustfmt::skip]
        let cases: &[(u16, u8, [u8; 2])] = &[
            //  ethertype     fill   bytes 12..14 (BE)
            (ETH_P_IP,   0xAA, [0x08, 0x00]),
            (ETH_P_IPV6, 0xBB, [0x86, 0xDD]),
        ];
        for (i, (et, fill, et_bytes)) in cases.iter().enumerate() {
            let mut buf = [*fill; 20];
            set_etherheader(&mut buf, *et);
            // dhost + shost: zeroed.
            assert_eq!(&buf[0..12], &[0u8; 12], "case {i}: MACs");
            // ethertype: big-endian.
            assert_eq!(&buf[12..14], et_bytes, "case {i}: ethertype");
            // Past 14: untouched.
            assert_eq!(buf[14], *fill, "case {i}: payload clobbered");
        }
    }
}
