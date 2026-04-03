//! Ethernet header constants + synthesis. RFC 894 / IEEE 802.3
//! / IANA registry. NOT platform-specific.
//!
//! ──────────── Why this is its own module ───────────────────────────
//!
//! These started life in `fd.rs` (chunk 2) — that was the first
//! backend that needed to SYNTHESIZE an ethernet header. (`linux.
//! rs` gets its ethertype from `tun_pi.proto` for free; `raw.rs`
//! gets the WHOLE header for free; only `fd.rs` had to fake it.)
//!
//! Then `bsd/device.c` reading happened (post-chunk-3). The BSD
//! `TUN`/`TUNEMU` path at `:419-446` is byte-identical to `fd_
//! device.c` synthesis save for symbolic vs literal constants.
//! The BSD `UTUN`/`TUNIFHEAD` path at `:451-476` is the same
//! synthesis at +10. Second consumer.
//!
//! The "re-declare module-private when modules are independent"
//! rule (from `fd.rs`'s `read_fd`/`write_fd` duplication) said
//! DON'T factor. But that rule was about SYSCALLS — `read_fd` is
//! `cfg(linux)` because the SAFETY argument is Linux-specific (TUN
//! fd is datagram, kernel writes once). These four constants are
//! RFC values: `0x0800` is IPv4's ethertype on every machine that
//! has ever spoken Ethernet, since 1980. `from_ip_nibble` is
//! `match (b >> 4) { 4 => ... }` — there is no platform on which
//! IPv4's version field is something other than 4. The `cfg`-
//! boundary rule doesn't apply because there IS no `cfg` here.
//!
//! Refined rule: **don't factor PLATFORM-VARYING things across
//! `cfg`. RFC constants don't vary.** They lived in `fd.rs` purely
//! because that was their first consumer. Second consumer (BSD)
//! arrives → hoist. THIS is the factoring criterion the chunk-3
//! prediction was groping for: not "fourth instance," not "shared
//! state," but **"second consumer of a platform-invariant thing."**
//!
//! `pub(crate)`, not `pub`: the daemon doesn't synthesize ether
//! headers. `route.c` READS them. The synthesis is purely a
//! device-backend concern (faking the header that the kernel
//! would write if we'd asked for TAP). Crate-internal.
//!
//! ──────────── What's NOT here ──────────────────────────────────────
//!
//! `ETH_P_ALL` (raw.rs): NOT a wire ethertype. It's a kernel
//! socket-option value meaning "give me all protocols." `<linux/
//! if_ether.h>` defines it next to the real ethertypes for
//! convenience but it's a Linux PF_PACKET API constant, not an
//! RFC value. Stays in `raw.rs`.
//!
//! `AF_INET` / `AF_INET6` (BSD utun prefix): NOT wire constants.
//! `AF_INET6` is `10` on Linux, `28` on FreeBSD, `30` on macOS —
//! the value the BSD kernel writes into the utun prefix is
//! whatever THAT platform's `AF_INET6` is. The C uses `htonl(AF_
//! INET6)` which expands per-platform; the kernel reads it on the
//! same platform. Those go in `bsd.rs` as `libc::AF_INET6` so
//! they're correct on whichever BSD we're compiling for. **The
//! distinction MATTERS: `0x86DD` is wire-format truth; `AF_INET6`
//! is local convention.**

#![allow(clippy::doc_markdown)]

// Ethernet header constants — `ethernet.h`, RFC 894, IEEE 802.3

/// `ETH_HLEN` — `ethernet.h:31` (and `<linux/if_ether.h>`, and
/// every BSD `<net/ethernet.h>`). dhost(6) + shost(6) + type(2).
/// The 14-byte header that's been on every Ethernet wire since
/// 1980. `fd.rs` reads at `+ETH_HLEN`; `bsd.rs` TUN reads at
/// `+ETH_HLEN`; everybody's offset arithmetic uses this.
///
/// gcc-verified vs `<linux/if_ether.h>`; the value is the same
/// on BSD (it's the ACTUAL header, defined by the medium, not by
/// any kernel).
pub(crate) const ETH_HLEN: usize = 14;

/// `ETHER_TYPE_LEN` — `ethernet.h:35`. The big-endian u16 at
/// offset 12. `ETH_HLEN - ETHER_TYPE_LEN = 12` is where ethertype
/// lives. Used as the `set_etherheader` slice bound: zero `[..12]`
/// (the MACs), write `[12..14]` (the type).
///
/// Module-private (NOT `pub(crate)`): only `set_etherheader`
/// reads it. `bsd.rs` will call `set_etherheader()`, not name
/// the constant (the C uses literal `12` at `bsd/device.c:445`;
/// our backends use the fn). The `ethertype_at_12` test pins the
/// arithmetic; that's the only other reader and it's in this
/// module.
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

/// IP version nibble → ethertype. `fd_device.c:192-202` AND
/// `bsd/device.c:427-443` (which is the same logic with literal
/// constants instead of symbolic ones — `0x08` then `0x00`
/// instead of `ETH_P_IP >> 8` then `& 0xFF`).
///
/// IPv4 and IPv6 BOTH put the protocol version in the high 4
/// bits of byte 0:
///
/// ```text
///   IPv4:  byte 0 = 0x4? (version=4, IHL in low nibble)
///   IPv6:  byte 0 = 0x6? (version=6, traffic class high nibble in low)
/// ```
///
/// `byte0 >> 4` extracts the version. The byte being inspected
/// is the FIRST byte of the IP packet — `buf[ETH_HLEN]` after a
/// `+14` read, `buf[ETH_HLEN]` after a `+10` read too (the BSD
/// utun case: kernel wrote 4-byte AF prefix at `[10..14]`, then
/// IP at `[14..]`; first IP byte is STILL at `ETH_HLEN`).
///
/// `None` for unknown version. C `fd_device.c:201` returns
/// `ETH_P_MAX` (0xFFFF) sentinel; C `bsd/device.c:438-443`
/// errors directly inside the switch. Either way the caller
/// treats it as "garbage from the other side, drop." We use
/// `Option`; the caller decides the error.
///
/// Pure function. The testable seam. Four call sites coming:
/// `fd.rs` (Android), `bsd.rs` TUN, `bsd.rs` UTUN, eventually
/// any future raw-IP backend.
#[must_use]
pub(crate) fn from_ip_nibble(ip0: u8) -> Option<u16> {
    match ip0 >> 4 {
        4 => Some(ETH_P_IP),
        6 => Some(ETH_P_IPV6),
        _ => None,
    }
}

// set_etherheader — zero MACs + write ethertype

/// `set_etherheader` (`fd_device.c:204-208`); `bsd/device.c
/// :429-445` does the same thing inline. Write the synthetic
/// ethernet header: zero MACs, set ethertype.
///
/// C does it in two steps: `memset(DATA, 0, 12)` then byte-by-
/// byte ethertype. `bsd/device.c` does the SAME memset (`:445`:
/// `memset(DATA, 0, 12)` — literal `12`, not `ETH_HLEN -
/// ETHER_TYPE_LEN`, but same number). The BSD code does the
/// ethertype write FIRST then the memset (`:429-430` then `:445`);
/// `fd_device.c` does memset first. ORDER DOESN'T MATTER —
/// they touch disjoint bytes (`[0..12]` vs `[12..14]`). We do
/// memset first; both C sources produce identical bytes.
///
/// `to_be_bytes()`: ethertype on the wire is big-endian. C
/// `fd_device.c:207-208` does `(ethertype >> 8) & 0xFF` then
/// `& 0xFF` — manual big-endian split. `bsd/device.c:429-430`
/// does the same with literal hex (`0x08` then `0x00`). We use
/// std. Same bytes, three ways to spell them.
///
/// `buf[..ETH_HLEN]`: caller guarantees ≥14 bytes. Both call
/// sites (`fd.rs` and future `bsd.rs`) have `MTU`-sized buffers;
/// `debug_assert` in their `read()` covers.
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

    // ─── Constants — gcc/sed-verified

    /// `ETH_HLEN = 14` per `ethernet.h:31`. The arithmetic that
    /// every offset trick orbits. gcc-verified: `printf("%d",
    /// ETH_HLEN)` → `14`.
    #[test]
    fn eth_hlen_14() {
        assert_eq!(ETH_HLEN, 14);
        // The arithmetic: dhost(6) + shost(6) + type(2).
        assert_eq!(ETH_HLEN, 6 + 6 + 2);
    }

    /// `ETHER_TYPE_LEN = 2`. `ETH_HLEN - ETHER_TYPE_LEN = 12` is
    /// where ethertype goes.
    #[test]
    fn ethertype_at_12() {
        assert_eq!(ETHER_TYPE_LEN, 2);
        assert_eq!(ETH_HLEN - ETHER_TYPE_LEN, 12);
    }

    /// IANA ethertype registrations. Wire format; can't change.
    /// gcc-verified vs `<linux/if_ether.h>`; same on BSD.
    #[test]
    fn ethertypes_iana() {
        assert_eq!(ETH_P_IP, 0x0800);
        assert_eq!(ETH_P_IPV6, 0x86DD);
    }

    // ─── from_ip_nibble

    /// IPv4 byte 0: version=4 in high nibble, IHL in low.
    /// `0x45` is the canonical IPv4 first byte (IHL=5 words =
    /// 20 bytes, no options). `0x4F` is max IHL (60 bytes).
    /// Both → `ETH_P_IP`.
    #[test]
    fn nibble_ipv4() {
        assert_eq!(from_ip_nibble(0x45), Some(ETH_P_IP));
        assert_eq!(from_ip_nibble(0x40), Some(ETH_P_IP));
        assert_eq!(from_ip_nibble(0x4F), Some(ETH_P_IP));
    }

    /// IPv6 byte 0: version=6 in high nibble, traffic class
    /// high nibble in low. `0x60` is canonical (default traffic
    /// class).
    #[test]
    fn nibble_ipv6() {
        assert_eq!(from_ip_nibble(0x60), Some(ETH_P_IPV6));
        assert_eq!(from_ip_nibble(0x6F), Some(ETH_P_IPV6));
    }

    /// Unknown versions → None. C `fd_device.c` returns `ETH_P_
    /// MAX` sentinel; C `bsd/device.c` errors inline. We use
    /// `Option`.
    ///
    /// IP version 5 was ST-II (RFC 1819, experimental, dead).
    /// Version 7-15 unassigned. Version 0-3 pre-IPv4 historical.
    #[test]
    fn nibble_unknown() {
        assert_eq!(from_ip_nibble(0x00), None);
        assert_eq!(from_ip_nibble(0x50), None); // ST-II
        assert_eq!(from_ip_nibble(0x70), None);
        assert_eq!(from_ip_nibble(0xFF), None);
    }

    // ─── set_etherheader

    /// Zero MACs, write ethertype big-endian. `fd_device.c
    /// :204-208`; `bsd/device.c:429-445` inline.
    #[test]
    fn set_etherheader_ipv4() {
        // Pre-fill with garbage to verify the zero.
        let mut buf = [0xAAu8; 20];
        set_etherheader(&mut buf, ETH_P_IP);
        // dhost: zeroed.
        assert_eq!(&buf[0..6], &[0u8; 6]);
        // shost: zeroed.
        assert_eq!(&buf[6..12], &[0u8; 6]);
        // ethertype: 0x0800 big-endian → [0x08, 0x00].
        assert_eq!(&buf[12..14], &[0x08, 0x00]);
        // Past 14: untouched.
        assert_eq!(buf[14], 0xAA);
    }

    /// Same for IPv6. 0x86DD → [0x86, 0xDD].
    #[test]
    fn set_etherheader_ipv6() {
        let mut buf = [0xBBu8; 20];
        set_etherheader(&mut buf, ETH_P_IPV6);
        assert_eq!(&buf[0..12], &[0u8; 12]);
        assert_eq!(&buf[12..14], &[0x86, 0xDD]);
        assert_eq!(buf[14], 0xBB);
    }

    /// Our `to_be_bytes()` matches the C's manual `>> 8` /
    /// `& 0xFF` (`fd_device.c:207-208`) AND matches `bsd/
    /// device.c`'s literal `0x86` then `0xDD` (`:434-435`).
    /// Three ways to spell the same bytes.
    #[test]
    fn set_etherheader_be_matches_c_manual_split() {
        let et = ETH_P_IPV6;
        // What fd_device.c does:
        let c_high = ((et >> 8) & 0xFF) as u8;
        let c_low = (et & 0xFF) as u8;
        // What bsd/device.c does (literal hex):
        let bsd_high = 0x86u8;
        let bsd_low = 0xDDu8;
        // What we do:
        let rust = et.to_be_bytes();
        // All three agree.
        assert_eq!([c_high, c_low], rust);
        assert_eq!([bsd_high, bsd_low], rust);
    }
}
