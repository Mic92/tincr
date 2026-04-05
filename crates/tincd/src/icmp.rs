//! ICMP error synthesis for the routing layer.
//!
//! When `route_ipv4`/`route_ipv6` decides Unreachable, we don't
//! silently drop — we send the originating host a structured "no,
//! that won't work" so its socket gets `ECONNREFUSED` / `EHOSTUNREACH`
//! instead of timing out. The kernel matches the error to the
//! originating socket by parsing the **quoted original headers** in
//! the ICMP body (RFC 792 §3: "Internet Header + 64 bits of Original
//! Data Datagram").
//!
//! Upstream mutates the `vpn_packet_t` in place — `memmove` the
//! quote down, overwrite the front, write back. We build a fresh
//! `Vec`: this fires at most 3×/sec ([`IcmpRateLimit`]), alloc
//! doesn't matter.
//!
//! ## TTL-exceeded source-address override
//!
//! TTL-exceeded does a `socket()/connect()/getsockname()` trick to
//! discover which local IP the kernel would use to reach the
//! original sender — that becomes the ICMP source so `traceroute`
//! shows our hop correctly. Only matters when we're a HOP in the
//! middle (`DecrementTTL=yes` + TTL hit zero), not the endpoint.
//! Without it, original-dst-as-src means traceroute shows the final
//! destination at every relay hop.
//!
//! That trick is I/O; this module is `#![forbid(unsafe_code)]` and
//! pure. The daemon does the discovery (`daemon/net.rs::
//! local_ip_facing`) and passes the result as the `src_override` 5th
//! param. `None` = current behavior (orig dst as ICMP source).

#![forbid(unsafe_code)]

use zerocopy::{FromBytes, IntoBytes};

use crate::packet::{Icmp6Hdr, IcmpHdr, Ipv4Hdr, Ipv6Hdr, Ipv6Pseudo, inet_checksum};

// ── Sizes ──────────────────────────────────────────────────────────

const ETHER_SIZE: usize = 14;
const IP_SIZE: usize = 20;
/// `struct icmp` is 28 bytes (8 hdr + 20 quoted-IP tail in the
/// union); we use only the first 8.
const ICMP_SIZE: usize = 8;
const IP6_SIZE: usize = 40;
const ICMP6_SIZE: usize = 8;
/// `IP_MSS` — `ipv4.h:88`. RFC 791: "Every internet module must be
/// able to forward a datagram of 576 octets". Used as the cap for
/// the synthesized error packet's total IP length.
const IP_MSS: usize = 576;

const IPPROTO_ICMP: u8 = 1;
const IPPROTO_ICMPV6: u8 = 58;

// ── IPv4 unreachable ───────────────────────────────────────────────

/// Max bytes of the original IP datagram quoted in the ICMP body.
/// `IP_MSS - ip_size - icmp_size` = 576−20−8.
pub const V4_QUOTE_CAP: usize = IP_MSS - IP_SIZE - ICMP_SIZE; // 548

/// `route_ipv4_unreachable`. RFC 792.
///
/// `original` is the full ethernet frame as read from the TUN
/// (eth hdr + IP hdr + payload). Returns a new ethernet frame:
/// the original eth hdr with MACs swapped, then a new IP hdr
/// (proto=1 ICMP, TTL=255, src↔dst), then ICMP hdr (type, code),
/// then up to [`V4_QUOTE_CAP`] bytes of the original IP datagram.
///
/// `frag_mtu`: `Some(mtu)` for `(DEST_UNREACH, FRAG_NEEDED)` —
/// fills `icmp.nextmtu`. `None` otherwise. We take it as a
/// parameter so the caller can decide.
///
/// Returns `None` if `original` is too short to contain an eth +
/// IPv4 header (`route.c` guards with `checklength` upstream).
///
/// `src_override`: `Some(addr)` overrides the ICMP packet's IP
/// source (TTL-exceeded `getsockname` dance, done by the caller).
/// `None` = use original-dst.
#[must_use]
pub fn build_v4_unreachable(
    original: &[u8],
    icmp_type: u8,
    icmp_code: u8,
    frag_mtu: Option<u16>,
    src_override: Option<[u8; 4]>,
) -> Option<Vec<u8>> {
    // Need at least eth + IP hdr to parse src/dst (`:140`).
    if original.len() < ETHER_SIZE + IP_SIZE {
        return None;
    }

    // ─── Swap eth MACs (`swap_mac_addresses`, `:112-117`).
    let mut eth = [0u8; ETHER_SIZE];
    eth[0..6].copy_from_slice(&original[6..12]); // dst ← orig src
    eth[6..12].copy_from_slice(&original[0..6]); // src ← orig dst
    eth[12..14].copy_from_slice(&original[12..14]); // ethertype unchanged

    // ─── Parse original IP hdr (`:140`: memcpy(&ip, ...)).
    // Length checked above; .ok()? is unreachable but quiets clippy.
    let orig_ip_bytes: &[u8; IP_SIZE] =
        original[ETHER_SIZE..ETHER_SIZE + IP_SIZE].try_into().ok()?;
    let orig_ip = Ipv4Hdr::read_from_bytes(orig_ip_bytes).ok()?;
    // `:144-145`: remember original src/dst. `:148-169`: caller may
    // override the dst (= our reply's src) for TIME_EXCEEDED —
    // mirrors C's `ip_dst = addr.sin_addr` after getsockname().
    let ip_src = orig_ip.ip_src;
    let ip_dst = src_override.unwrap_or(orig_ip.ip_dst);

    // ─── Quote length (`:170,176-178`).
    // `oldlen = packet->len - ether_size`: the whole original IP
    // datagram (header + payload). Capped at IP_MSS - 28.
    let oldlen = (original.len() - ETHER_SIZE).min(V4_QUOTE_CAP);
    let quote = &original[ETHER_SIZE..ETHER_SIZE + oldlen];

    // ─── Build new IP hdr (`:186-196`).
    let mut ip = Ipv4Hdr::default();
    ip.set_vhl(4, 5); // :186-187: ip_hl = ip_size/4 = 20/4
    ip.ip_tos = 0; // :188
    // truncation: 20+8+548 = 576 < u16::MAX
    #[allow(clippy::cast_possible_truncation)] // oldlen capped at V4_QUOTE_CAP=548
    ip.set_total_len((IP_SIZE + ICMP_SIZE + oldlen) as u16); // :189
    ip.set_id(0); // :190
    ip.set_off(0); // :191
    ip.ip_ttl = 255; // :192
    ip.ip_p = IPPROTO_ICMP; // :193
    ip.ip_sum = 0; // :194
    ip.ip_src = ip_dst; // :195 — SWAPPED
    ip.ip_dst = ip_src; // :196
    // `:198`: `ip.ip_sum = inet_checksum(&ip, ip_size, 0xFFFF)`.
    ip.ip_sum = inet_checksum(ip.as_bytes(), 0xFFFF);

    // ─── Build ICMP hdr (`:173-175,202-208`).
    let mut icmp = IcmpHdr::default();
    icmp.icmp_type = icmp_type; // :202
    icmp.icmp_code = icmp_code; // :203
    icmp.icmp_cksum = 0; // :204
    // `:173-175`: only for FRAG_NEEDED. The C reads packet->len -
    // ether_size (the *original* IP datagram length, BEFORE the cap
    // at :176). We take it as a parameter.
    if let Some(mtu) = frag_mtu {
        icmp.set_nextmtu(mtu);
    }
    // `:206-208`: chain ICMP hdr + quote.
    let mut ck = inet_checksum(icmp.as_bytes(), 0xFFFF);
    ck = inet_checksum(quote, ck);
    icmp.icmp_cksum = ck;

    // ─── Assemble (`:213-216`).
    let mut out = Vec::with_capacity(ETHER_SIZE + IP_SIZE + ICMP_SIZE + oldlen);
    out.extend_from_slice(&eth);
    out.extend_from_slice(ip.as_bytes());
    out.extend_from_slice(icmp.as_bytes());
    out.extend_from_slice(quote);
    Some(out)
}

// ── IPv6 unreachable ───────────────────────────────────────────────

/// Max bytes of the original IPv6 datagram quoted in the `ICMPv6` body.
/// `IP_MSS - ip6_size - icmp6_size` = 576−40−8.
pub const V6_QUOTE_CAP: usize = IP_MSS - IP6_SIZE - ICMP6_SIZE; // 528

/// `route_ipv6_unreachable`. RFC 4443.
///
/// Same shape as [`build_v4_unreachable`] but the `ICMPv6` checksum
/// includes a pseudo-header (RFC 4443 §2.3 → RFC 2460 §8.1):
/// src/dst addrs + upper-layer length + next-hdr.
/// Uses [`Ipv6Pseudo`].
///
/// `pkt_too_big_mtu`: `Some(mtu)` for `ICMP6_PACKET_TOO_BIG` —
/// fills `icmp6.icmp6_mtu`. We take it as a parameter.
///
/// Returns `None` if `original` is too short for eth + IPv6 hdr.
///
/// `src_override`: `Some(addr)` overrides the ICMP packet's IPv6
/// source (TTL-exceeded `getsockname` dance, done by the caller).
/// `None` = use original-dst.
#[must_use]
pub fn build_v6_unreachable(
    original: &[u8],
    icmp_type: u8,
    icmp_code: u8,
    pkt_too_big_mtu: Option<u32>,
    src_override: Option<[u8; 16]>,
) -> Option<Vec<u8>> {
    if original.len() < ETHER_SIZE + IP6_SIZE {
        return None;
    }

    // ─── Swap eth MACs (`:240`).
    let mut eth = [0u8; ETHER_SIZE];
    eth[0..6].copy_from_slice(&original[6..12]);
    eth[6..12].copy_from_slice(&original[0..6]);
    eth[12..14].copy_from_slice(&original[12..14]);

    // ─── Parse original IPv6 hdr (`:244`).
    // Length checked above; .ok()? is unreachable but quiets clippy.
    let orig_ip6_bytes: &[u8; IP6_SIZE] = original[ETHER_SIZE..ETHER_SIZE + IP6_SIZE]
        .try_into()
        .ok()?;
    let orig_ip6 = Ipv6Hdr::read_from_bytes(orig_ip6_bytes).ok()?;

    // `:248-249`: remember swapped. The C stores them directly in
    // `pseudo.ip6_src/dst` and reuses that struct; we keep locals.
    // `:254-275`: caller may override new_src for TIME_EXCEEDED —
    // mirrors C's `pseudo.ip6_src = addr.sin6_addr` post-getsockname.
    let new_src = src_override.unwrap_or(orig_ip6.ip6_dst);
    let new_dst = orig_ip6.ip6_src;

    // ─── Quote length (`:277,282-284`).
    let quote_len = (original.len() - ETHER_SIZE).min(V6_QUOTE_CAP);
    let quote = &original[ETHER_SIZE..ETHER_SIZE + quote_len];

    // ─── Build new IPv6 hdr (`:292-297`).
    let mut ip6 = Ipv6Hdr::default();
    ip6.set_flow(0x6000_0000); // :292
    // truncation: 8+528 = 536 < u16::MAX
    #[allow(clippy::cast_possible_truncation)] // quote_len capped at V6_QUOTE_CAP
    ip6.set_plen((ICMP6_SIZE + quote_len) as u16); // :293
    ip6.ip6_nxt = IPPROTO_ICMPV6; // :294
    ip6.ip6_hlim = 255; // :295
    ip6.ip6_src = new_src; // :296
    ip6.ip6_dst = new_dst; // :297
    // No IPv6 header checksum.

    // ─── Build ICMPv6 hdr (`:278-280,301-303`).
    let mut icmp6 = Icmp6Hdr::default();
    icmp6.icmp6_type = icmp_type; // :301
    icmp6.icmp6_code = icmp_code; // :302
    icmp6.icmp6_cksum = 0; // :303
    if let Some(mtu) = pkt_too_big_mtu {
        icmp6.set_mtu(mtu); // :279
    }

    // ─── Pseudo-header checksum (`:307-316`).
    // RFC 2460 §8.1: src + dst + upper-layer-len + next.
    // The C reuses `pseudo.length` for two purposes: first the quote
    // length (host order), then htonl(icmp6_size + quote) for the
    // checksum. We just build it directly.
    let mut pseudo = Ipv6Pseudo::default();
    pseudo.ip6_src = new_src;
    pseudo.ip6_dst = new_dst;
    // `:308`: `pseudo.length = htonl(icmp6_size + pseudo.length)`.
    // truncation: 8+528 = 536 < u32::MAX
    #[allow(clippy::cast_possible_truncation)] // quote_len capped at V6_QUOTE_CAP
    pseudo.set_length((ICMP6_SIZE + quote_len) as u32);
    pseudo.set_next(u32::from(IPPROTO_ICMPV6)); // :309

    // `:313-315`: chain pseudo → icmp6 hdr → quote.
    let mut ck = inet_checksum(pseudo.as_bytes(), 0xFFFF);
    ck = inet_checksum(icmp6.as_bytes(), ck);
    ck = inet_checksum(quote, ck);
    icmp6.icmp6_cksum = ck;

    // ─── Assemble (`:320-323`).
    let mut out = Vec::with_capacity(ETHER_SIZE + IP6_SIZE + ICMP6_SIZE + quote_len);
    out.extend_from_slice(&eth);
    out.extend_from_slice(ip6.as_bytes());
    out.extend_from_slice(icmp6.as_bytes());
    out.extend_from_slice(quote);
    Some(out)
}

// ── Rate limit ─────────────────────────────────────────────────────

/// `ratelimit`. Per-second token bucket.
///
/// Upstream uses `static time_t lasttime; static int count` — process-
/// global. We make it a small struct the daemon owns. `now` is a
/// parameter (no global `now.tv_sec`).
#[derive(Debug, Default)]
pub struct IcmpRateLimit {
    /// Unix seconds.
    last_sec: u64,
    count: u32,
}

impl IcmpRateLimit {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` if we should DROP (rate-limited).
    ///
    /// Same-second + `count >= freq` → drop (return `true`).
    /// Different second → reset count to 0. Then `count++`.
    /// The boundary (`>=` not `>`) means `freq=3` allows exactly 3
    /// per second: calls 1,2,3 increment to 1,2,3 (return false);
    /// call 4 sees `count(3) >= freq(3)` and returns true early.
    pub fn should_drop(&mut self, now_sec: u64, freq: u32) -> bool {
        if self.last_sec == now_sec {
            // :90-92
            if self.count >= freq {
                return true;
            }
        } else {
            // :94-96
            self.last_sec = now_sec;
            self.count = 0;
        }
        // :98
        self.count += 1;
        false
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route::{ICMP_DEST_UNREACH, ICMP_NET_UNKNOWN};

    /// Hand-built original frame: eth + IPv4(UDP) + 8-byte UDP hdr.
    /// 42 bytes total. Small enough that the whole IP datagram (28
    /// bytes) is quoted uncapped.
    ///
    /// eth: dst=02:00:00:00:00:02 src=02:00:00:00:00:01 type=0800
    /// ip:  10.0.0.1 → 10.0.0.99, UDP, ttl=64, len=28
    /// udp: 1234 → 5678, len=8, cksum=0
    fn v4_orig_frame() -> Vec<u8> {
        let mut f = Vec::new();
        // eth
        f.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]); // dst
        f.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]); // src
        f.extend_from_slice(&[0x08, 0x00]); // ETH_P_IP
        // ip — checksum hand-computed: BE-words sum ~0x9991 = 0x666e
        f.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x1c, // vhl,tos,len=28
            0x00, 0x00, 0x00, 0x00, // id,off
            0x40, 0x11, 0x66, 0x6e, // ttl=64,p=UDP,cksum
            0x0a, 0x00, 0x00, 0x01, // src 10.0.0.1
            0x0a, 0x00, 0x00, 0x63, // dst 10.0.0.99
        ]);
        // udp
        f.extend_from_slice(&[0x04, 0xd2, 0x16, 0x2e, 0x00, 0x08, 0x00, 0x00]);
        assert_eq!(f.len(), 42);
        f
    }

    /// KAT: build the full expected output byte-by-byte using the
    /// same checksum primitive (already KAT-locked against the C in
    /// `packet.rs::tests::inet_checksum_kat`). This is the strongest
    /// test short of a kernel pcap — it exercises every field-fill
    /// in the right order with the right endianness.
    #[test]
    fn v4_net_unknown_kat() {
        let orig = v4_orig_frame();
        let got = build_v4_unreachable(&orig, ICMP_DEST_UNREACH, ICMP_NET_UNKNOWN, None, None)
            .expect("built");

        // ── Expected: assemble piecewise.
        let mut want = Vec::new();
        // eth: MACs swapped, ethertype unchanged
        want.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]); // dst ← orig src
        want.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]); // src ← orig dst
        want.extend_from_slice(&[0x08, 0x00]);

        // new IP hdr: 45 00 0038 0000 0000 ff 01 SUM SUM | 10.0.0.99 | 10.0.0.1
        let mut ip_bytes = [
            0x45, 0x00, 0x00, 0x38, // vhl,tos, len=56 (20+8+28)
            0x00, 0x00, 0x00, 0x00, // id,off
            0xff, 0x01, 0x00, 0x00, // ttl=255,p=ICMP,sum=0
            0x0a, 0x00, 0x00, 0x63, // src = orig dst
            0x0a, 0x00, 0x00, 0x01, // dst = orig src
        ];
        let ip_sum = inet_checksum(&ip_bytes, 0xFFFF);
        ip_bytes[10..12].copy_from_slice(&ip_sum.to_ne_bytes());
        want.extend_from_slice(&ip_bytes);

        // ICMP hdr: type=3 code=6 cksum void=0 nextmtu=0
        let quote = &orig[ETHER_SIZE..]; // 28 bytes
        let mut icmp_bytes = [3u8, 6, 0, 0, 0, 0, 0, 0];
        let mut ck = inet_checksum(&icmp_bytes, 0xFFFF);
        ck = inet_checksum(quote, ck);
        icmp_bytes[2..4].copy_from_slice(&ck.to_ne_bytes());
        want.extend_from_slice(&icmp_bytes);

        // quoted original IP datagram
        want.extend_from_slice(quote);

        assert_eq!(got.len(), 14 + 20 + 8 + 28);
        assert_eq!(got, want);

        // sanity: receiver-side IP checksum verify
        assert_eq!(inet_checksum(&got[14..34], 0xFFFF), 0);
    }

    /// `ip.ip_src = ip_dst; ip.ip_dst = ip_src`.
    #[test]
    fn v4_swaps_addrs() {
        let orig = v4_orig_frame();
        let out =
            build_v4_unreachable(&orig, ICMP_DEST_UNREACH, ICMP_NET_UNKNOWN, None, None).unwrap();
        let ip = Ipv4Hdr::read_from_bytes(&out[14..34]).unwrap();
        assert_eq!(ip.ip_src, [10, 0, 0, 99]); // orig dst
        assert_eq!(ip.ip_dst, [10, 0, 0, 1]); // orig src
        // and eth MACs too (`swap_mac_addresses`, :112)
        assert_eq!(&out[0..6], &orig[6..12]);
        assert_eq!(&out[6..12], &orig[0..6]);
    }

    /// The quote IS the original IP datagram, byte-for-byte.
    #[test]
    fn v4_quotes_original() {
        let orig = v4_orig_frame();
        let out =
            build_v4_unreachable(&orig, ICMP_DEST_UNREACH, ICMP_NET_UNKNOWN, None, None).unwrap();
        let oldlen = orig.len() - ETHER_SIZE; // 28, < cap
        let quote = &out[ETHER_SIZE + IP_SIZE + ICMP_SIZE..];
        assert_eq!(quote.len(), oldlen);
        assert_eq!(quote, &orig[ETHER_SIZE..ETHER_SIZE + oldlen]);
    }

    /// `if(oldlen >= IP_MSS - ip_size - icmp_size) oldlen = ...`.
    /// 1500-byte original → quote capped at 548.
    #[test]
    fn v4_quote_capped_at_548() {
        let mut orig = v4_orig_frame();
        orig.resize(1500, 0xab); // big payload
        let out =
            build_v4_unreachable(&orig, ICMP_DEST_UNREACH, ICMP_NET_UNKNOWN, None, None).unwrap();
        assert_eq!(out.len(), ETHER_SIZE + IP_SIZE + ICMP_SIZE + V4_QUOTE_CAP);
        assert_eq!(out.len(), 14 + 20 + 8 + 548);
        // total IP len reflects the cap
        let ip = Ipv4Hdr::read_from_bytes(&out[14..34]).unwrap();
        assert_eq!(ip.total_len(), 20 + 8 + 548);
        assert_eq!(ip.total_len() as usize, IP_MSS);
        // quote bytes match original up to the cap
        let quote = &out[ETHER_SIZE + IP_SIZE + ICMP_SIZE..];
        assert_eq!(quote, &orig[ETHER_SIZE..ETHER_SIZE + V4_QUOTE_CAP]);
    }

    /// `icmp.icmp_nextmtu = htons(...)`. Bytes 6-7 of the ICMP
    /// header (the second u16 of the union).
    #[test]
    fn v4_frag_needed_sets_mtu() {
        let orig = v4_orig_frame();
        // ICMP_DEST_UNREACH=3, ICMP_FRAG_NEEDED=4 — the type/code
        // that triggers PMTU. Value of frag_mtu is whatever the
        // caller picked (in C it's packet->len - ether_size).
        let out = build_v4_unreachable(&orig, 3, 4, Some(1400), None).unwrap();
        // ICMP hdr lives at [14+20 .. 14+20+8].
        let icmp_bytes = &out[34..42];
        // bytes 6-7 are nextmtu, BE.
        assert_eq!(&icmp_bytes[6..8], &1400u16.to_be_bytes());
        // bytes 4-5 (icmp_void) stay zero.
        assert_eq!(&icmp_bytes[4..6], &[0, 0]);
        // checksum still verifies.
        let quote = &out[42..];
        let mut ck = inet_checksum(icmp_bytes, 0xFFFF);
        ck = inet_checksum(quote, ck);
        // Verify: re-checksumming the wire (cksum included) gives 0.
        // But our chain already includes the cksum field — just
        // assert it directly: hdr-with-cksum + quote → 0.
        let _ = ck; // computed above for documentation
        let mut hdr_zeroed = [0u8; 8];
        hdr_zeroed.copy_from_slice(icmp_bytes);
        hdr_zeroed[2] = 0;
        hdr_zeroed[3] = 0;
        let recomputed = inet_checksum(quote, inet_checksum(&hdr_zeroed, 0xFFFF));
        assert_eq!(
            recomputed.to_ne_bytes(),
            [icmp_bytes[2], icmp_bytes[3]],
            "ICMP checksum mismatch"
        );
    }

    /// Too short to parse the IP header → None. The C handles this
    /// upstream via `checklength` (`:103-110`); we guard inline.
    #[test]
    fn v4_too_short_is_none() {
        assert!(build_v4_unreachable(&[0u8; 10], 3, 0, None, None).is_none());
        // exactly eth-only: still no IP hdr
        assert!(build_v4_unreachable(&[0u8; ETHER_SIZE], 3, 0, None, None).is_none());
        // eth + 19 bytes IP: one short
        assert!(build_v4_unreachable(&[0u8; ETHER_SIZE + IP_SIZE - 1], 3, 0, None, None).is_none());
        // eth + 20 bytes IP: minimum valid
        assert!(build_v4_unreachable(&[0u8; ETHER_SIZE + IP_SIZE], 3, 0, None, None).is_some());
    }

    /// TTL-exceeded source override. The override becomes the new IP
    /// src (→ traceroute shows OUR hop, not the
    /// original destination). dst still = orig src. Checksum covers it.
    #[test]
    fn v4_src_override() {
        let orig = v4_orig_frame();
        // ICMP_TIME_EXCEEDED=11, ICMP_EXC_TTL=0
        let out = build_v4_unreachable(&orig, 11, 0, None, Some([172, 16, 0, 5])).expect("built");
        let ip = Ipv4Hdr::read_from_bytes(&out[14..34]).unwrap();
        assert_eq!(ip.ip_src, [172, 16, 0, 5]); // override, NOT orig dst
        assert_eq!(ip.ip_dst, [10, 0, 0, 1]); // still orig src
        // IP checksum verifies (override is in the summed region).
        assert_eq!(inet_checksum(&out[14..34], 0xFFFF), 0);
        // None = current behavior (orig dst).
        let out_none = build_v4_unreachable(&orig, 11, 0, None, None).unwrap();
        let ip_none = Ipv4Hdr::read_from_bytes(&out_none[14..34]).unwrap();
        assert_eq!(ip_none.ip_src, [10, 0, 0, 99]);
    }

    // ─── IPv6

    /// Hand-built original v6 frame: eth + IPv6(UDP) + 8-byte UDP.
    /// `fe80::1` → `fe80::99`
    fn v6_orig_frame() -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]); // eth dst
        f.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]); // eth src
        f.extend_from_slice(&[0x86, 0xdd]); // ETH_P_IPV6
        // ip6: flow=6<<28, plen=8, nxt=17(UDP), hlim=64
        f.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // flow
        f.extend_from_slice(&[0x00, 0x08]); // plen=8
        f.extend_from_slice(&[17, 64]); // nxt,hlim
        f.extend_from_slice(b"\xfe\x80\0\0\0\0\0\0\0\0\0\0\0\0\0\x01"); // src
        f.extend_from_slice(b"\xfe\x80\0\0\0\0\0\0\0\0\0\0\0\0\0\x99"); // dst
        // udp
        f.extend_from_slice(&[0x04, 0xd2, 0x16, 0x2e, 0x00, 0x08, 0x00, 0x00]);
        assert_eq!(f.len(), 14 + 40 + 8);
        f
    }

    /// One v6 vector. Asserts the pseudo-header checksum is correct
    /// by recomputing it independently. RFC 4443 §2.3.
    #[test]
    fn v6_basic() {
        let orig = v6_orig_frame();
        // ICMP6_DST_UNREACH=1, ICMP6_DST_UNREACH_NOROUTE=0
        let out = build_v6_unreachable(&orig, 1, 0, None, None).expect("built");

        let quote_len = orig.len() - ETHER_SIZE; // 48
        assert_eq!(out.len(), ETHER_SIZE + IP6_SIZE + ICMP6_SIZE + quote_len);

        // eth swapped
        assert_eq!(&out[0..6], &orig[6..12]);
        assert_eq!(&out[6..12], &orig[0..6]);
        assert_eq!(&out[12..14], &[0x86, 0xdd]);

        // ip6 hdr
        let ip6 = Ipv6Hdr::read_from_bytes(&out[14..54]).unwrap();
        assert_eq!(ip6.flow(), 0x6000_0000);
        assert_eq!(ip6.plen() as usize, ICMP6_SIZE + quote_len);
        assert_eq!(ip6.ip6_nxt, IPPROTO_ICMPV6);
        assert_eq!(ip6.ip6_hlim, 255);
        // src ← orig dst, dst ← orig src
        assert_eq!(ip6.ip6_src, *b"\xfe\x80\0\0\0\0\0\0\0\0\0\0\0\0\0\x99");
        assert_eq!(ip6.ip6_dst, *b"\xfe\x80\0\0\0\0\0\0\0\0\0\0\0\0\0\x01");

        // icmp6 hdr
        let icmp6_bytes = &out[54..62];
        assert_eq!(icmp6_bytes[0], 1); // type
        assert_eq!(icmp6_bytes[1], 0); // code
        assert_eq!(&icmp6_bytes[4..8], &[0, 0, 0, 0]); // mtu unused

        // quote
        let quote = &out[62..];
        assert_eq!(quote, &orig[ETHER_SIZE..]);

        // ── Recompute pseudo-header checksum (`:313-315`).
        let mut pseudo = Ipv6Pseudo::default();
        pseudo.ip6_src = ip6.ip6_src;
        pseudo.ip6_dst = ip6.ip6_dst;
        pseudo.set_length(u32::try_from(ICMP6_SIZE + quote_len).unwrap());
        pseudo.set_next(u32::from(IPPROTO_ICMPV6));
        let mut hdr_zeroed = [0u8; 8];
        hdr_zeroed.copy_from_slice(icmp6_bytes);
        hdr_zeroed[2] = 0;
        hdr_zeroed[3] = 0;
        let mut ck = inet_checksum(pseudo.as_bytes(), 0xFFFF);
        ck = inet_checksum(&hdr_zeroed, ck);
        ck = inet_checksum(quote, ck);
        assert_eq!(
            ck.to_ne_bytes(),
            [icmp6_bytes[2], icmp6_bytes[3]],
            "ICMPv6 pseudo-header checksum mismatch"
        );
    }

    /// `PACKET_TOO_BIG` sets `icmp6_mtu`. Bytes 4-7 of the `ICMPv6`
    /// hdr, BE u32.
    #[test]
    fn v6_pkt_too_big_sets_mtu() {
        let orig = v6_orig_frame();
        // ICMP6_PACKET_TOO_BIG=2
        let out = build_v6_unreachable(&orig, 2, 0, Some(1280), None).unwrap();
        let icmp6_bytes = &out[54..62];
        assert_eq!(&icmp6_bytes[4..8], &1280u32.to_be_bytes());
    }

    #[test]
    fn v6_too_short_is_none() {
        assert!(
            build_v6_unreachable(&[0u8; ETHER_SIZE + IP6_SIZE - 1], 1, 0, None, None).is_none()
        );
        assert!(build_v6_unreachable(&[0u8; ETHER_SIZE + IP6_SIZE], 1, 0, None, None).is_some());
    }

    /// v6 TTL-exceeded source override. Override becomes `ip6_src`
    /// AND feeds the pseudo-header checksum.
    #[test]
    fn v6_src_override() {
        let orig = v6_orig_frame();
        let our_ip = *b"\x20\x01\x0d\xb8\0\0\0\0\0\0\0\0\0\0\0\x42";
        // ICMP6_TIME_EXCEEDED=3, ICMP6_TIME_EXCEED_TRANSIT=0
        let out = build_v6_unreachable(&orig, 3, 0, None, Some(our_ip)).expect("built");
        let ip6 = Ipv6Hdr::read_from_bytes(&out[14..54]).unwrap();
        assert_eq!(ip6.ip6_src, our_ip); // override, NOT orig dst
        assert_eq!(ip6.ip6_dst, *b"\xfe\x80\0\0\0\0\0\0\0\0\0\0\0\0\0\x01"); // orig src

        // Pseudo-header checksum verifies with the override addr.
        let icmp6_bytes = &out[54..62];
        let quote = &out[62..];
        let mut pseudo = Ipv6Pseudo::default();
        pseudo.ip6_src = our_ip;
        pseudo.ip6_dst = ip6.ip6_dst;
        pseudo.set_length(u32::try_from(ICMP6_SIZE + quote.len()).unwrap());
        pseudo.set_next(u32::from(IPPROTO_ICMPV6));
        let mut hdr_zeroed = [0u8; 8];
        hdr_zeroed.copy_from_slice(icmp6_bytes);
        hdr_zeroed[2] = 0;
        hdr_zeroed[3] = 0;
        let mut ck = inet_checksum(pseudo.as_bytes(), 0xFFFF);
        ck = inet_checksum(&hdr_zeroed, ck);
        ck = inet_checksum(quote, ck);
        assert_eq!(ck.to_ne_bytes(), [icmp6_bytes[2], icmp6_bytes[3]]);
    }

    // ─── Rate limit

    /// freq=3 allows exactly 3 per second.
    #[test]
    fn ratelimit_allows_then_drops() {
        let mut rl = IcmpRateLimit::new();
        // 3 calls in second 100: all pass
        assert!(!rl.should_drop(100, 3));
        assert!(!rl.should_drop(100, 3));
        assert!(!rl.should_drop(100, 3));
        // 4th call same second: count(3) >= freq(3) → drop
        assert!(rl.should_drop(100, 3));
        assert!(rl.should_drop(100, 3));
        // new second: reset
        assert!(!rl.should_drop(101, 3));
        assert!(!rl.should_drop(101, 3));
        assert!(!rl.should_drop(101, 3));
        assert!(rl.should_drop(101, 3));
    }
}
