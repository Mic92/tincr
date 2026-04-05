//! Ethernet header constants + synthesis. RFC 894 / IEEE 802.3
//! / IANA registry. NOT platform-specific.
//!
//! Hoisted from `fd.rs` when BSD became a second consumer. The
//! `read_fd`/`write_fd` don't-factor rule is about platform-varying
//! syscalls; RFC constants don't vary across `cfg`. `pub(crate)`:
//! header synthesis is a backend concern; the daemon only reads.
//!
//! NOT here: `ETH_P_ALL` (Linux PF_PACKET API value, not a wire
//! ethertype — stays in `raw.rs`); `AF_INET6` (per-platform kernel
//! ABI: 10/Linux, 28/FreeBSD, 30/macOS — stays in `bsd.rs` via
//! `libc`). `0x86DD` is wire-format truth; `AF_INET6` is local
//! convention.

#![allow(clippy::doc_markdown)]

// Ethernet header constants — `ethernet.h`, RFC 894, IEEE 802.3

/// `ETH_HLEN` — `ethernet.h:31`. dhost(6) + shost(6) + type(2).
/// gcc-verified vs `<linux/if_ether.h>`.
pub(crate) const ETH_HLEN: usize = 14;

/// `ETHER_TYPE_LEN` — `ethernet.h:35`. `ETH_HLEN - ETHER_TYPE_LEN
/// = 12` is the ethertype offset. Module-private: only
/// `set_etherheader` and the `ethertype_at_12` test read it.
const ETHER_TYPE_LEN: usize = 2;

/// `ETH_P_IP` — `ethernet.h:44`. IPv4's IANA-registered ethertype.
/// IANA "EtherType" registry, assigned 1983 (before IANA was
/// IANA). Network byte order on the wire; we hold host order and
/// `to_be_bytes()` at write time.
pub(crate) const ETH_P_IP: u16 = 0x0800;

/// `ETH_P_IPV6` — `ethernet.h:52`. IPv6's ethertype. IANA-
/// registered 1995 (RFC 1883).
pub(crate) const ETH_P_IPV6: u16 = 0x86DD;

// from_ip_nibble — version → ethertype

/// IP version nibble → ethertype. IPv4 and IPv6 both put the
/// version in the high nibble of byte 0; `>> 4` extracts it.
/// The first IP byte is
/// always at `buf[ETH_HLEN]` regardless of read offset.
///
/// `None` for unknown: C uses an `ETH_P_MAX` sentinel or errors
/// inline; both mean "drop". Caller decides the error.
#[must_use]
pub(crate) fn from_ip_nibble(ip0: u8) -> Option<u16> {
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
    // Zero MACs. 12 bytes. NOT 14 — leave ethertype slot alone.
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

    // ─── from_ip_nibble

    /// `from_ip_nibble(u8) -> Option<u16>`. Full domain in one
    /// table: only the HIGH nibble matters (IP version field).
    /// Unknown versions yield `None`.
    #[test]
    fn nibble_cases() {
        #[rustfmt::skip]
        let cases: &[(u8, Option<u16>)] = &[
            // ─── IPv4: version=4 in high nibble, IHL in low.
            // `0x45` is the canonical IPv4 first byte (IHL=5 words =
            // 20 bytes, no options). `0x4F` is max IHL (60 bytes).
            (0x45, Some(ETH_P_IP)),
            (0x40, Some(ETH_P_IP)),
            (0x4F, Some(ETH_P_IP)),
            // ─── IPv6: version=6 in high nibble, traffic class high
            // nibble in low. `0x60` is canonical (default TC).
            (0x60, Some(ETH_P_IPV6)),
            (0x6F, Some(ETH_P_IPV6)),
            // ─── Unknown versions → None.
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

    // ─── set_etherheader

    /// Zero MACs, write ethertype big-endian. Pre-fill with garbage
    /// to verify the zero AND that bytes past 14 are untouched.
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

    /// `to_be_bytes()` matches manual `>> 8` / `& 0xFF` shifting
    /// AND matches literal `0x86` then `0xDD`. Three ways to spell
    /// the same bytes.
    #[test]
    fn set_etherheader_be_matches_manual_split() {
        let et = ETH_P_IPV6;
        // Manual shift/mask:
        let c_high = ((et >> 8) & 0xFF) as u8;
        let c_low = (et & 0xFF) as u8;
        // Literal hex:
        let bsd_high = 0x86u8;
        let bsd_low = 0xDDu8;
        // What we do:
        let rust = et.to_be_bytes();
        // All three agree.
        assert_eq!([c_high, c_low], rust);
        assert_eq!([bsd_high, bsd_low], rust);
    }
}
