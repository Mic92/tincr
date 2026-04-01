//! `subnet_parse.c`: `str2net` / `net2str` / `maskcheck`.
//!
//! A subnet on the wire is one of three things, optionally followed by
//! `/prefixlen` (IP only) and `#weight`:
//!
//! - `aa:bb:cc:dd:ee:ff` — MAC. No prefix length. Hex parts can be one
//!   *or* two digits (older tinc emitted `%x` not `%02x`, so `1:2:3:4:5:6`
//!   is valid wire input even though we'd never emit it).
//! - `1.2.3.4` or `1.2.3.4/24` — IPv4, default prefix 32.
//! - `2001:db8::1` or `2001:db8::/32` — IPv6, default prefix 128.
//!
//! Weight defaults to 10 (`DEFAULT_WEIGHT` in `subnet_parse.c`). It's a
//! routing-table tiebreaker, lower wins.
//!
//! ## Why hand-roll the IP parsers
//!
//! `str2net` calls `inet_pton(AF_INET, ...)` and `inet_pton(AF_INET6, ...)`.
//! `std::net::Ipv4Addr::from_str` and `Ipv6Addr::from_str` are *almost*
//! the same — both implement RFC 4291 textual representation — but there
//! are corner-case divergences in the `inet_pton` family that vary by
//! libc. We use std's parsers and add KATs for the cases that matter
//! (which is to say: the cases tinc actually puts on the wire, which are
//! all bog-standard).
//!
//! The MAC parser is hand-rolled because `sscanf %hx:%hx:...` has the
//! one-digit-part quirk and there's no std equivalent.
//!
//! ## `Display` is the wire format
//!
//! `net2str` is the only serializer. It uses `inet_ntop` for IP (which
//! matches `Ipv{4,6}Addr::Display`) and `%02x:` for MAC. Prefix is
//! omitted if it's the max (32 or 128); weight is omitted if it's 10.
//! That asymmetry — emit canonical, accept sloppy — is the round-trip
//! invariant: `parse(format(x)) == x` always, `format(parse(s)) == s`
//! only if `s` was already canonical.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use crate::tok::ParseError;

/// `DEFAULT_WEIGHT` from `subnet_parse.c`. Omitted on the wire when
/// equal to this.
pub const DEFAULT_WEIGHT: i32 = 10;

/// One subnet, as it appears on the wire and in `hosts/*` config files.
///
/// `weight` is `i32` not `u32` because the C parses it with `%d` and
/// nothing checks for negativity afterward. Negative weight is silly but
/// the protocol accepts it; so do we.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Subnet {
    /// MAC address. No prefix — TAP-mode bridge addresses are exact-match.
    Mac { addr: [u8; 6], weight: i32 },
    /// IPv4. `prefix` is `0..=32`; the parse rejects out-of-range.
    V4 {
        addr: Ipv4Addr,
        prefix: u8,
        weight: i32,
    },
    /// IPv6. `prefix` is `0..=128`.
    V6 {
        addr: Ipv6Addr,
        prefix: u8,
        weight: i32,
    },
}

impl Subnet {
    /// `subnetcheck` from `subnet_parse.c`: are the host bits zero?
    ///
    /// `add_subnet_h` calls this after `str2net` and rejects subnets
    /// where bits below the prefix are set. `10.0.0.1/24` is invalid
    /// (the `.1` is a host bit); `10.0.0.0/24` is valid.
    ///
    /// MAC subnets always pass (no prefix → no host bits).
    #[must_use]
    pub fn is_canonical(&self) -> bool {
        match self {
            Subnet::Mac { .. } => true,
            Subnet::V4 { addr, prefix, .. } => maskcheck(&addr.octets(), *prefix),
            Subnet::V6 { addr, prefix, .. } => maskcheck(&addr.octets(), *prefix),
        }
    }

    /// `weight` accessor — saves matching at every call site.
    #[must_use]
    pub fn weight(&self) -> i32 {
        match self {
            Subnet::Mac { weight, .. } | Subnet::V4 { weight, .. } | Subnet::V6 { weight, .. } => {
                *weight
            }
        }
    }
}

/// `maskcheck` from `subnet_parse.c`: are bytes from bit `prefix`
/// onward all zero?
///
/// Works for both v4 (4 bytes) and v6 (16 bytes); the C takes `void*`.
fn maskcheck(bytes: &[u8], prefix: u8) -> bool {
    let full = usize::from(prefix / 8);
    let bits = prefix % 8;
    let mut i = full;
    if bits != 0 {
        // Partial byte: low (8-bits) bits must be zero.
        // C: `a[i++] & (0xff >> masklen)` — shift right by the *kept*
        // bits, leaving a mask of the cleared ones.
        if bytes[i] & (0xff >> bits) != 0 {
            return false;
        }
        i += 1;
    }
    bytes[i..].iter().all(|&b| b == 0)
}

// ────────────────────────────────────────────────────────────────────
// Parse: str2net

impl FromStr for Subnet {
    type Err = ParseError;

    /// `str2net`. Order of attempts matters: MAC first (six colons would
    /// also satisfy the v6 parser if we tried that first — `1:2:3:4:5:6`
    /// is valid v6 syntax). The C tries MAC, then v4, then v6.
    fn from_str(s: &str) -> Result<Self, ParseError> {
        // The C strncpys into a 64-byte buffer; longer input gets
        // truncated and almost certainly fails to parse. We just reject.
        if s.len() >= 64 {
            return Err(ParseError);
        }

        // Suffix split: `addr [/prefix] [#weight]`, in that order.
        // (`#` after `/` because `subnet_parse.c` does `strchr('#')`
        // first then `strchr('/')` on the truncated string — so weight
        // comes last on the wire and is stripped first in parsing.)
        let (s, weight) = match s.split_once('#') {
            Some((head, w)) => (head, w.parse::<i32>().map_err(|_| ParseError)?),
            None => (s, DEFAULT_WEIGHT),
        };
        let (s, prefix) = match s.split_once('/') {
            Some((head, p)) => {
                // C: sscanf %d into int, then check `< 0`. So negative is
                // a parse-then-reject, not a parse failure. We collapse
                // both into Err — same observable result.
                let p: i32 = p.parse().map_err(|_| ParseError)?;
                if p < 0 {
                    return Err(ParseError);
                }
                // Safe: `p >= 0` and parsed from a string that fits in
                // 64 bytes, so it's well under u8::MAX... wait, `i32`
                // can be > 255. The C checks `> 32` / `> 128` *after*
                // parsing, which is what we do too (in the per-type
                // arms). Keep it as Option<u8> for now would lose the
                // out-of-range info; keep as i32, check in the arms.
                (head, Some(p))
            }
            None => (s, None),
        };

        // MAC: exactly 6 hex parts, 1-2 digits each, colon-separated.
        // The `%hx` quirk: `sscanf %hx` reads any number of hex digits,
        // but the part *string* can't contain a colon (that's the
        // separator), so it's at most whatever's between colons. Old
        // tinc emitted single-digit parts; we accept 1-2 digits.
        if let Some(addr) = parse_mac(s) {
            // C: `if(prefixlength >= 0) return false;` — MAC has no prefix.
            if prefix.is_some() {
                return Err(ParseError);
            }
            return Ok(Subnet::Mac { addr, weight });
        }

        if let Ok(addr) = s.parse::<Ipv4Addr>() {
            let prefix = match prefix {
                None => 32,
                Some(p) if p <= 32 => u8::try_from(p).unwrap(),
                _ => return Err(ParseError),
            };
            return Ok(Subnet::V4 {
                addr,
                prefix,
                weight,
            });
        }

        if let Ok(addr) = s.parse::<Ipv6Addr>() {
            let prefix = match prefix {
                None => 128,
                Some(p) if p <= 128 => u8::try_from(p).unwrap(),
                _ => return Err(ParseError),
            };
            return Ok(Subnet::V6 {
                addr,
                prefix,
                weight,
            });
        }

        Err(ParseError)
    }
}

/// `sscanf("%hx:%hx:%hx:%hx:%hx:%hx%n", ...)`.
///
/// Reads 6 colon-separated hex bytes. The C uses `%hx` into `uint16_t`
/// then casts to `uint8_t` — so `1ff:...` would parse as `0xff` after
/// the cast. We *don't* replicate that: it's never on the wire (no tinc
/// version emits 3-digit MAC parts) and it'd be a footgun. 1-2 digits
/// only.
///
/// Why not insist on exactly 2? See the comment in `subnet_parse.c` line
/// 260: "old tinc versions net2str() will aggressively return MAC
/// addresses with one-digit parts". `0:a:b:c:d:e` is on the wire from
/// 1.0-era peers.
fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut parts = s.split(':');
    for byte in &mut out {
        let p = parts.next()?;
        if p.is_empty() || p.len() > 2 {
            return None;
        }
        *byte = u8::from_str_radix(p, 16).ok()?;
    }
    // Exactly 6 parts: split must be exhausted.
    if parts.next().is_some() {
        return None;
    }
    Some(out)
}

// ────────────────────────────────────────────────────────────────────
// Format: net2str

impl fmt::Display for Subnet {
    /// `net2str`. Canonical form: `%02x` for MAC parts, `inet_ntop`
    /// (= `Ipv*Addr::Display`) for IP. Prefix omitted if max, weight
    /// omitted if default.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Subnet::Mac { addr, weight } => {
                let [a, b, c, d, e, g] = addr;
                write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")?;
                if *weight != DEFAULT_WEIGHT {
                    write!(f, "#{weight}")?;
                }
                Ok(())
            }
            Subnet::V4 {
                addr,
                prefix,
                weight,
            } => {
                write!(f, "{addr}")?;
                if *prefix != 32 {
                    write!(f, "/{prefix}")?;
                }
                if *weight != DEFAULT_WEIGHT {
                    write!(f, "#{weight}")?;
                }
                Ok(())
            }
            Subnet::V6 {
                addr,
                prefix,
                weight,
            } => {
                // `inet_ntop` and `Ipv6Addr::Display` both produce RFC 5952
                // canonical form (lowercase hex, longest zero-run as `::`,
                // no leading zeros). Verified in the KATs below.
                write!(f, "{addr}")?;
                if *prefix != 128 {
                    write!(f, "/{prefix}")?;
                }
                if *weight != DEFAULT_WEIGHT {
                    write!(f, "#{weight}")?;
                }
                Ok(())
            }
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// Tests

#[cfg(test)]
mod tests {
    use super::*;

    /// KAT: wire string → struct → wire string. The right-hand side is
    /// what `net2str` would emit; if it's the same as the input, the
    /// input was already canonical.
    ///
    /// These strings are lifted from `test/integration/` configs and
    /// from staring at `protocol_subnet.c` until the format made sense.
    #[test]
    fn kat_roundtrip() {
        #[rustfmt::skip]
        let cases: &[(&str, &str, Subnet)] = &[
            // ─── IPv4 ───
            ("10.0.0.0/24",     "10.0.0.0/24",     Subnet::V4 { addr: Ipv4Addr::new(10,0,0,0), prefix: 24, weight: 10 }),
            ("10.0.0.1",        "10.0.0.1",        Subnet::V4 { addr: Ipv4Addr::new(10,0,0,1), prefix: 32, weight: 10 }),
            // /32 is canonical-omitted
            ("10.0.0.1/32",     "10.0.0.1",        Subnet::V4 { addr: Ipv4Addr::new(10,0,0,1), prefix: 32, weight: 10 }),
            ("0.0.0.0/0",       "0.0.0.0/0",       Subnet::V4 { addr: Ipv4Addr::UNSPECIFIED,   prefix: 0,  weight: 10 }),
            // weight
            ("10.0.0.0/24#5",   "10.0.0.0/24#5",   Subnet::V4 { addr: Ipv4Addr::new(10,0,0,0), prefix: 24, weight: 5  }),
            // default weight is omitted
            ("10.0.0.0/24#10",  "10.0.0.0/24",     Subnet::V4 { addr: Ipv4Addr::new(10,0,0,0), prefix: 24, weight: 10 }),
            // negative weight: C parses %d, never checks sign
            ("10.0.0.0/24#-1",  "10.0.0.0/24#-1",  Subnet::V4 { addr: Ipv4Addr::new(10,0,0,0), prefix: 24, weight: -1 }),

            // ─── IPv6 ───
            ("2001:db8::/32",   "2001:db8::/32",   Subnet::V6 { addr: "2001:db8::".parse().unwrap(),   prefix: 32,  weight: 10 }),
            ("::1",             "::1",             Subnet::V6 { addr: Ipv6Addr::LOCALHOST,             prefix: 128, weight: 10 }),
            ("fe80::1/64#20",   "fe80::1/64#20",   Subnet::V6 { addr: "fe80::1".parse().unwrap(),      prefix: 64,  weight: 20 }),
            // RFC 5952 canonicalization: input has redundant zeros, output doesn't.
            // This is what inet_ntop does and what Ipv6Addr::Display does.
            ("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1",
             Subnet::V6 { addr: "2001:db8::1".parse().unwrap(), prefix: 128, weight: 10 }),

            // ─── MAC ───
            ("00:11:22:33:44:55",  "00:11:22:33:44:55", Subnet::Mac { addr: [0,0x11,0x22,0x33,0x44,0x55], weight: 10 }),
            ("aa:bb:cc:dd:ee:ff",  "aa:bb:cc:dd:ee:ff", Subnet::Mac { addr: [0xaa,0xbb,0xcc,0xdd,0xee,0xff], weight: 10 }),
            // one-digit parts (1.0-era wire format)
            ("0:1:2:3:4:5",        "00:01:02:03:04:05", Subnet::Mac { addr: [0,1,2,3,4,5], weight: 10 }),
            ("a:b:c:d:e:f#7",      "0a:0b:0c:0d:0e:0f#7", Subnet::Mac { addr: [0xa,0xb,0xc,0xd,0xe,0xf], weight: 7 }),
        ];

        for (input, canonical, expected) in cases {
            let parsed: Subnet = input.parse().unwrap_or_else(|_| panic!("parse {input:?}"));
            assert_eq!(parsed, *expected, "parse({input:?})");
            assert_eq!(parsed.to_string(), *canonical, "format(parse({input:?}))");
        }
    }

    #[test]
    fn kat_reject() {
        for s in [
            "",
            "garbage",
            "10.0.0.1/33",          // prefix > 32
            "::1/129",              // prefix > 128
            "10.0.0.1/-1",          // explicit negative prefix
            "00:11:22:33:44:55/48", // MAC with prefix
            "10.0.0.1#",            // empty weight
            "10.0.0.1/",            // empty prefix
            "00:11:22:33:44",       // 5 MAC parts
            "00:11:22:33:44:55:66", // 7 MAC parts
            "100:11:22:33:44:55",   // 3-digit MAC part (we're stricter than C here)
        ] {
            assert!(s.parse::<Subnet>().is_err(), "{s:?} should reject");
        }
    }

    /// MAC-vs-v6 ambiguity. `1:2:3:4:5:6` is valid syntax for both.
    /// `str2net` tries MAC first, so MAC wins. This is load-bearing for
    /// wire compat: a 1.0 peer that sends a one-digit-part MAC needs it
    /// parsed as MAC, not as the v6 address `1:2:3:4:5:6::` truncated.
    #[test]
    fn mac_shadows_v6() {
        let s: Subnet = "1:2:3:4:5:6".parse().unwrap();
        assert!(matches!(
            s,
            Subnet::Mac {
                addr: [1, 2, 3, 4, 5, 6],
                ..
            }
        ));

        // 7 parts is unambiguously v6 though (the v6 parser may or may
        // not accept it depending on whether it's well-formed v6; the
        // MAC parser definitely won't).
        // `1:2:3:4:5:6:7:8` is valid v6.
        let s: Subnet = "1:2:3:4:5:6:7:8".parse().unwrap();
        assert!(matches!(s, Subnet::V6 { .. }));
    }

    #[test]
    fn maskcheck_basics() {
        // 10.0.0.0/24: host byte is zero, ok.
        assert!(Subnet::V4 {
            addr: Ipv4Addr::new(10, 0, 0, 0),
            prefix: 24,
            weight: 10
        }
        .is_canonical());
        // 10.0.0.1/24: host byte is 1, not ok.
        assert!(!Subnet::V4 {
            addr: Ipv4Addr::new(10, 0, 0, 1),
            prefix: 24,
            weight: 10
        }
        .is_canonical());
        // 10.0.0.1/32: no host bits, always ok.
        assert!(Subnet::V4 {
            addr: Ipv4Addr::new(10, 0, 0, 1),
            prefix: 32,
            weight: 10
        }
        .is_canonical());
        // /23 with bit 23 set: 10.0.1.0 → byte 2 bit 0 is set, mask is /23,
        // so byte 2's low bit is a host bit. Not ok.
        assert!(!Subnet::V4 {
            addr: Ipv4Addr::new(10, 0, 1, 0),
            prefix: 23,
            weight: 10
        }
        .is_canonical());
        // /23 with byte 2 = 2 (bit 1 set): that's a network bit, ok.
        assert!(Subnet::V4 {
            addr: Ipv4Addr::new(10, 0, 2, 0),
            prefix: 23,
            weight: 10
        }
        .is_canonical());

        // v6: fe80::/10 — byte 1 is 0x80, mask is 10 bits, so byte 1's
        // low 6 bits must be zero. 0x80 = 0b10000000, low 6 = 0, ok.
        assert!(Subnet::V6 {
            addr: "fe80::".parse().unwrap(),
            prefix: 10,
            weight: 10
        }
        .is_canonical());
        // fe81::/10 — byte 1 = 0x81, low 6 bits = 1, not ok.
        assert!(!Subnet::V6 {
            addr: "fe81::".parse().unwrap(),
            prefix: 10,
            weight: 10
        }
        .is_canonical());

        // MAC always passes.
        assert!(Subnet::Mac {
            addr: [1, 2, 3, 4, 5, 6],
            weight: 10
        }
        .is_canonical());
    }
}
