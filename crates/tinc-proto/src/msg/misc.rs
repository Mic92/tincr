//! `protocol_misc.c`: `PACKET`, `SPTPS_PACKET`, `UDP_INFO`, `MTU_INFO`.
//!
//! `TERMREQ`/`PING`/`PONG` are body-less (just `"%d"`). They don't need
//! a struct — the daemon dispatches on `Request::peek` and that's the
//! whole message. Format: `Request::Ping.to_string()`.
//!
//! ## The `%hd` length quirk
//!
//! `tcppacket_h` and `sptps_tcppacket_h` parse the length with `%hd`
//! (into `short int`) and check `< 0`. But `send_tcppacket` *emits* with
//! `%d` (full `int`). And `send_sptps_tcppacket` emits with `%lu`
//! (`unsigned long`!).
//!
//! Why the asymmetry? `vpn_packet_t.len` is `uint16_t`, max 65535. The
//! `%hd` parse caps acceptance at 32767 — anything in `[32768, 65535]`
//! parses as negative and gets rejected. That's a *deliberate* sanity
//! bound: `MTU` is well under 32K. We replicate by parsing as `i16` and
//! rejecting negatives. The format side emits `u16` (what's actually in
//! the packet struct), which always fits.
//!
//! `sptps_tcppacket_h` is the same shape but the send side casts to
//! `unsigned long` for `%lu`. SPTPS records also cap well below 32K, so
//! the parse-side `%hd < 0` check still works as a bound.

use crate::addr::AddrStr;
use crate::tok::{ParseError, Tok};
use crate::{Request, check_id};

// ────────────────────────────────────────────────────────────────────
// PACKET / SPTPS_PACKET — length-prefix-only headers

/// Body of `PACKET` (legacy TCP-tunneled VPN packet header).
///
/// The actual packet bytes follow this line on the wire as a raw blob,
/// length-prefixed by this message. `meta.c` reads `c->tcplen` bytes
/// after seeing this. So this struct is *just the prefix*, not the
/// payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpPacket {
    /// Packet length, `0..=32767`. Upper bound from the `%hd < 0` check.
    pub len: u16,
}

impl TcpPacket {
    /// `tcppacket_h`: `sscanf("%*d %hd", &len)`, then `len < 0`.
    ///
    /// # Errors
    /// Missing/bad token, or length parses but exceeds `i16::MAX`
    /// (which the `%hd`-then-check-negative idiom would also reject —
    /// 32768 is `-32768` in a `short`).
    pub fn parse(line: &str) -> Result<Self, ParseError> {
        let mut t = Tok::new(line);
        t.skip()?;
        let len = t.hd()?;
        if len < 0 {
            return Err(ParseError);
        }
        // Safe: just checked `len >= 0`, so it fits in u16.
        #[allow(clippy::cast_sign_loss)] // guarded by len < 0 check above
        Ok(Self { len: len as u16 })
    }

    /// `send_tcppacket`: `send_request("%d %d", PACKET, packet->len)`.
    ///
    /// `packet->len` is `uint16_t`; `%d` is fine since `int` ≥ 16 bits
    /// and the value is non-negative.
    #[must_use]
    pub fn format(&self) -> String {
        format!("{} {}", Request::Packet, self.len)
    }
}

/// Body of `SPTPS_PACKET`. Same shape as `TcpPacket` — length prefix
/// for a raw blob — but the blob is an SPTPS record, not a VPN packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SptpsPacket {
    pub len: u16,
}

impl SptpsPacket {
    /// `sptps_tcppacket_h`: identical to `tcppacket_h`. `%*d %hd`, `< 0`.
    ///
    /// # Errors
    /// Same as [`TcpPacket::parse`].
    pub fn parse(line: &str) -> Result<Self, ParseError> {
        let mut t = Tok::new(line);
        t.skip()?;
        let len = t.hd()?;
        if len < 0 {
            return Err(ParseError);
        }
        #[allow(clippy::cast_sign_loss)] // guarded by len < 0 check above
        Ok(Self { len: len as u16 })
    }

    /// `send_sptps_tcppacket`: `send_request("%d %lu", SPTPS_PACKET, (unsigned long)len)`.
    ///
    /// The `%lu` cast is C noise — `len` is `size_t`, value always fits
    /// in `u16`. We emit `%d`-shaped (no `l` modifier in Rust format
    /// strings anyway). Same wire bytes for the values that occur.
    #[must_use]
    pub fn format(&self) -> String {
        format!("{} {}", Request::SptpsPacket, self.len)
    }
}

// ────────────────────────────────────────────────────────────────────
// UDP_INFO

/// Body of `UDP_INFO`. Tells `to` what address `from` was seen at —
/// hole-punching breadcrumb. No nonce: it's sent point-to-point along
/// the path, not flooded, so no dedup needed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpInfo {
    pub from: String,
    pub to: String,
    /// `from`'s address as observed by the previous hop. May be `unspec`
    /// (the placeholder `send_udp_info` uses on the first hop).
    pub addr: AddrStr,
    pub port: AddrStr,
}

impl UdpInfo {
    /// `udp_info_h`: `sscanf("%*d %s %s %s %s")`, `check_id(from && to)`.
    ///
    /// `from == to` is *not* checked in C. (Edges are directed and
    /// can't self-loop; UDP info is just a hint and a node sending to
    /// itself is weird but not protocol-invalid.)
    ///
    /// # Errors
    /// Too few tokens or bad name.
    pub fn parse(line: &str) -> Result<Self, ParseError> {
        let mut t = Tok::new(line);
        t.skip()?;

        let from = t.s()?;
        let to = t.s()?;
        if !check_id(from) || !check_id(to) {
            return Err(ParseError);
        }
        let addr = AddrStr::new(t.s()?)?;
        let port = AddrStr::new(t.s()?)?;

        Ok(Self {
            from: from.to_string(),
            to: to.to_string(),
            addr,
            port,
        })
    }

    /// `send_udp_info`: `send_request("%d %s %s %s %s", UDP_INFO, from, to, addr, port)`.
    #[must_use]
    pub fn format(&self) -> String {
        format!(
            "{} {} {} {} {}",
            Request::UdpInfo,
            self.from,
            self.to,
            self.addr,
            self.port
        )
    }
}

// ────────────────────────────────────────────────────────────────────
// MTU_INFO

/// Body of `MTU_INFO`. Propagates path-MTU discovery results along the
/// route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MtuInfo {
    pub from: String,
    pub to: String,
    /// Discovered MTU. `mtu_info_h` rejects `< 512` (Ethernet minimum,
    /// roughly); we leave that check to the handler since it's policy,
    /// not parse. We *do* parse as `i32` because that's `%d`.
    pub mtu: i32,
}

impl MtuInfo {
    /// `mtu_info_h`: `sscanf("%*d %s %s %d")`, `check_id(from && to)`.
    ///
    /// The `mtu < 512` check happens *after* parse in C, before
    /// `check_id` — but it logs differently (`"invalid MTU"` vs
    /// `"invalid name"`). We don't enforce it here: it's a policy
    /// bound that the daemon can adjust, not a wire-format rule.
    ///
    /// # Errors
    /// Too few tokens, bad name, or non-integer MTU.
    pub fn parse(line: &str) -> Result<Self, ParseError> {
        let mut t = Tok::new(line);
        t.skip()?;

        let from = t.s()?;
        let to = t.s()?;
        let mtu = t.d()?;
        if !check_id(from) || !check_id(to) {
            return Err(ParseError);
        }

        Ok(Self {
            from: from.to_string(),
            to: to.to_string(),
            mtu,
        })
    }

    /// `send_mtu_info`: `send_request("%d %s %s %d", MTU_INFO, from, to, mtu)`.
    #[must_use]
    pub fn format(&self) -> String {
        format!(
            "{} {} {} {}",
            Request::MtuInfo,
            self.from,
            self.to,
            self.mtu
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_packet() {
        let m = TcpPacket::parse("17 1400").unwrap();
        assert_eq!(m.len, 1400);
        assert_eq!(m.format(), "17 1400");

        // Zero is fine (degenerate but valid).
        assert_eq!(TcpPacket::parse("17 0").unwrap().len, 0);

        // Negative: %hd parses it, < 0 check fires.
        assert!(TcpPacket::parse("17 -1").is_err());

        // 32768: %hd into short would be -32768. Our i16 parse just
        // fails (out of range for i16). Same observable result.
        assert!(TcpPacket::parse("17 32768").is_err());
        assert_eq!(TcpPacket::parse("17 32767").unwrap().len, 32767);
    }

    #[test]
    fn sptps_packet() {
        let m = SptpsPacket::parse("21 84").unwrap();
        assert_eq!(m.len, 84);
        // %lu on emit, %hd on parse — the digits are the digits.
        assert_eq!(m.format(), "21 84");
    }

    #[test]
    fn udp_info() {
        let line = "22 alice bob 10.0.0.1 655";
        let m = UdpInfo::parse(line).unwrap();
        assert_eq!(m.from, "alice");
        assert_eq!(m.to, "bob");
        assert_eq!(m.addr.as_str(), "10.0.0.1");
        assert_eq!(m.format(), line);

        // unspec placeholder (first hop)
        let line = "22 alice bob unspec unspec";
        let m = UdpInfo::parse(line).unwrap();
        assert_eq!(m.addr.as_str(), AddrStr::UNSPEC);
        assert_eq!(m.format(), line);

        // from == to: C doesn't check, we don't either.
        assert!(UdpInfo::parse("22 a a 1.1.1.1 1").is_ok());

        // bad name
        assert!(UdpInfo::parse("22 a-b c 1.1.1.1 1").is_err());
    }

    #[test]
    fn mtu_info() {
        let line = "23 alice bob 1400";
        let m = MtuInfo::parse(line).unwrap();
        assert_eq!(m.mtu, 1400);
        assert_eq!(m.format(), line);

        // mtu < 512: C handler rejects this *after* parse. We parse it.
        let m = MtuInfo::parse("23 a b 100").unwrap();
        assert_eq!(m.mtu, 100);

        // Non-integer: parse error.
        assert!(MtuInfo::parse("23 a b xx").is_err());
    }
}
