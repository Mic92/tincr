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
    pub const fn weight(&self) -> i32 {
        match self {
            Subnet::Mac { weight, .. } | Subnet::V4 { weight, .. } | Subnet::V6 { weight, .. } => {
                *weight
            }
        }
    }

    /// Does `self` match `find`, given a query shape that's either
    /// an exact subnet or a single address?
    ///
    /// `info_subnet` parses the user's input then walks every subnet
    /// the daemon knows, asking "does this one match?". The match
    /// rules diverge depending on whether the user typed `10.0.0.5`
    /// (an address — "which subnet routes this?") or `10.0.0.0/24`
    /// (a subnet — "who advertises exactly this?").
    ///
    /// | `as_address` | meaning | match |
    /// |---|---|---|
    /// | `true`  | route lookup | `find` is INSIDE `self`: top `self.prefix` bits agree |
    /// | `false` | exact subnet | `find` IS `self`: prefix equal AND all addr bytes equal |
    ///
    /// MAC subnets ignore `as_address` (no prefix → only exact-match).
    /// Mismatched types (V4 vs V6) never match. Weight is ignored —
    /// `info_subnet` checks weight separately (only when the user
    /// typed a `#` suffix).
    ///
    /// The C does this inline with three nested `if`s per type. We
    /// pull it here because (a) `Subnet` IS the wire-format type,
    /// (b) `tinc-tools` doesn't have access to `Subnet`'s addr bytes
    /// without re-matching, (c) the daemon's own routing-table lookup
    /// (`subnet.c:lookup_subnet_ipv4`) does the SAME `maskcmp` against
    /// the SAME prefix — this is the routing decision, factored.
    ///
    /// Example:
    /// ```
    /// # use tinc_proto::Subnet;
    /// # use std::str::FromStr;
    /// let net: Subnet = "10.0.0.0/24".parse().unwrap();
    /// let host: Subnet = "10.0.0.5".parse().unwrap();   // /32 by default
    /// let other: Subnet = "10.0.1.0/24".parse().unwrap();
    ///
    /// assert!( net.matches(&host, true));   // 10.0.0.5 is in 10.0.0.0/24
    /// assert!(!net.matches(&host, false));  // /24 != /32
    /// assert!(!net.matches(&other, true));  // 10.0.1.x not in 10.0.0.0/24
    /// assert!( net.matches(&net, false));   // identity
    /// ```
    #[must_use]
    pub fn matches(&self, find: &Self, as_address: bool) -> bool {
        match (self, find) {
            // ─── IPv4 ──────────────────────────────────────────────
            (
                Self::V4 {
                    addr: a, prefix: p, ..
                },
                Self::V4 { addr: fa, .. },
            ) if as_address => {
                // Address lookup: top `p` bits of find.addr must
                // equal `self`. The SUBNET's prefix, not find's.
                // (If find is a /32 address,
                // its own prefix is irrelevant — we're asking
                // "does the /24 contain it?".)
                maskcmp(&a.octets(), &fa.octets(), *p)
            }
            (
                Self::V4 {
                    addr: a, prefix: p, ..
                },
                Self::V4 {
                    addr: fa,
                    prefix: fp,
                    ..
                },
            ) => {
                // Exact subnet: prefix equal, addr bytes equal.
                //
                // The memcmp checks ALL 4 bytes, NOT just the top
                // `p` bits. So `10.0.0.1/24` (which is_canonical()
                // would reject) does NOT match `10.0.0.0/24` here.
                // The daemon never advertises non-canonical subnets,
                // so it's moot in practice; but we replicate.
                p == fp && a == fa
            }

            // ─── IPv6 ──────────────────────────────────────────────
            // Same shape, 16 bytes.
            (
                Self::V6 {
                    addr: a, prefix: p, ..
                },
                Self::V6 { addr: fa, .. },
            ) if as_address => maskcmp(&a.octets(), &fa.octets(), *p),
            (
                Self::V6 {
                    addr: a, prefix: p, ..
                },
                Self::V6 {
                    addr: fa,
                    prefix: fp,
                    ..
                },
            ) => p == fp && a == fa,

            // ─── MAC ───────────────────────────────────────────────
            // Only memcmp. No prefix on MAC, so address-mode and
            // exact-mode collapse. `address` isn't read in this arm.
            (Self::Mac { addr: a, .. }, Self::Mac { addr: fa, .. }) => a == fa,

            // ─── Type mismatch ─────────────────────────────────────
            // V4 query against V6 subnet → no match.
            _ => false,
        }
    }
}

/// Do the top `prefix` bits of `a` and `b` agree?
///
/// Returns `bool` (true = equal-under-mask). Every caller only
/// checks `!= 0`, so the memcmp-style sign isn't needed.
///
/// The C bit-math `0x100 - (1 << (8 - m))` makes a high-bits mask:
/// `m=3` → `0x100 - 0x20` = `0xe0` = `0b1110_0000` (top 3 bits).
/// We spell it `!0 << (8 - m)` which is the same thing (`0xff <<
/// 5` = `0xe0`, after the implicit u8 truncation).
///
/// Generic over 4 vs 16 bytes via slices.
fn maskcmp(a: &[u8], b: &[u8], prefix: u8) -> bool {
    let full = usize::from(prefix / 8);
    let bits = prefix % 8;
    // Full bytes: must be byte-equal. C's loop with `a[i] - b[i]`.
    if a[..full] != b[..full] {
        return false;
    }
    // Partial byte: top `bits` bits must agree. C's tail expr.
    if bits != 0 {
        // `0xffu8 << (8 - bits)` = high-bits mask. Shift count is
        // 1..=7 (bits is 1..=7 here), no overflow.
        let mask = 0xffu8 << (8 - bits);
        if a[full] & mask != b[full] & mask {
            return false;
        }
    }
    // C's `return 0` → our `true`.
    true
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
        // Partial byte: low (8-bits) bits must be zero. Shift right
        // by the *kept* bits, leaving a mask of the cleared ones.
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
                // Negative prefix is rejected; we collapse parse-failure
                // and parse-then-reject into the same Err.
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
            // MAC has no prefix.
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
/// 260: "old tinc versions `net2str()` will aggressively return MAC
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
    #[allow(clippy::many_single_char_names)] // MAC byte destructuring
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
        assert!(
            Subnet::V4 {
                addr: Ipv4Addr::new(10, 0, 0, 0),
                prefix: 24,
                weight: 10
            }
            .is_canonical()
        );
        // 10.0.0.1/24: host byte is 1, not ok.
        assert!(
            !Subnet::V4 {
                addr: Ipv4Addr::new(10, 0, 0, 1),
                prefix: 24,
                weight: 10
            }
            .is_canonical()
        );
        // 10.0.0.1/32: no host bits, always ok.
        assert!(
            Subnet::V4 {
                addr: Ipv4Addr::new(10, 0, 0, 1),
                prefix: 32,
                weight: 10
            }
            .is_canonical()
        );
        // /23 with bit 23 set: 10.0.1.0 → byte 2 bit 0 is set, mask is /23,
        // so byte 2's low bit is a host bit. Not ok.
        assert!(
            !Subnet::V4 {
                addr: Ipv4Addr::new(10, 0, 1, 0),
                prefix: 23,
                weight: 10
            }
            .is_canonical()
        );
        // /23 with byte 2 = 2 (bit 1 set): that's a network bit, ok.
        assert!(
            Subnet::V4 {
                addr: Ipv4Addr::new(10, 0, 2, 0),
                prefix: 23,
                weight: 10
            }
            .is_canonical()
        );

        // v6: fe80::/10 — byte 1 is 0x80, mask is 10 bits, so byte 1's
        // low 6 bits must be zero. 0x80 = 0b10000000, low 6 = 0, ok.
        assert!(
            Subnet::V6 {
                addr: "fe80::".parse().unwrap(),
                prefix: 10,
                weight: 10
            }
            .is_canonical()
        );
        // fe81::/10 — byte 1 = 0x81, low 6 bits = 1, not ok.
        assert!(
            !Subnet::V6 {
                addr: "fe81::".parse().unwrap(),
                prefix: 10,
                weight: 10
            }
            .is_canonical()
        );

        // MAC always passes.
        assert!(
            Subnet::Mac {
                addr: [1, 2, 3, 4, 5, 6],
                weight: 10
            }
            .is_canonical()
        );
    }

    // ─── maskcmp: prefix-bit compare ─────────────────────────────────

    /// The C bit-math `0x100 - (1 << (8 - m))` and our `0xff << (8-m)`
    /// produce the same mask for m=1..7. m=0 doesn't reach the math.
    /// m=8 doesn't either (that's a full byte). Exhaustive over the
    /// 7 reachable values.
    #[test]
    fn maskcmp_mask_equivalence() {
        for m in 1u32..8 {
            #[allow(clippy::cast_possible_truncation)] // m ∈ 1..7 → result ∈ {0x80..0xfe}, fits u8
            let c_mask = (0x100u32 - (1u32 << (8 - m))) as u8;
            let rs_mask = 0xffu8 << (8 - m);
            assert_eq!(c_mask, rs_mask, "m={m}");
        }
    }

    /// Full bytes only: prefix=24 means compare 3 bytes, ignore the 4th.
    #[test]
    fn maskcmp_byte_aligned() {
        // 10.0.0.0 vs 10.0.0.255 under /24 → equal (first 3 bytes match).
        assert!(maskcmp(&[10, 0, 0, 0], &[10, 0, 0, 255], 24));
        // 10.0.0.0 vs 10.0.1.0 under /24 → differ (3rd byte).
        assert!(!maskcmp(&[10, 0, 0, 0], &[10, 0, 1, 0], 24));
        // /32 → all 4 bytes compared.
        assert!(!maskcmp(&[10, 0, 0, 0], &[10, 0, 0, 1], 32));
        assert!(maskcmp(&[10, 0, 0, 1], &[10, 0, 0, 1], 32));
    }

    /// Partial byte: prefix=20 → 2 full bytes + top 4 bits of byte 3.
    /// 10.0.{0x10}.X vs 10.0.{0x1f}.X: top-4 of 0x10 = top-4 of 0x1f
    /// (both `0001_xxxx` → mask 0xf0 → 0x10) → equal.
    #[test]
    fn maskcmp_partial_byte() {
        // Top 4 bits of 0x10 (0001_0000) and 0x1f (0001_1111) under
        // mask 0xf0 are both 0x10. Match.
        assert!(maskcmp(&[10, 0, 0x10, 0], &[10, 0, 0x1f, 0xff], 20));
        // 0x10 vs 0x20 (0010_0000): top-4 differ (0x10 vs 0x20). No.
        assert!(!maskcmp(&[10, 0, 0x10, 0], &[10, 0, 0x20, 0], 20));
        // /1: only the top BIT of byte 0 matters.
        assert!(maskcmp(&[0x80, 0, 0, 0], &[0xff, 0xff, 0xff, 0xff], 1));
        assert!(!maskcmp(&[0x80, 0, 0, 0], &[0x00, 0, 0, 0], 1));
    }

    /// /0 matches everything (no bits compared). The C: full-byte loop
    /// runs zero times, partial-byte branch skipped (`m == 0`).
    #[test]
    fn maskcmp_slash_zero() {
        assert!(maskcmp(&[10, 0, 0, 0], &[192, 168, 1, 1], 0));
        assert!(maskcmp(&[0, 0, 0, 0], &[255, 255, 255, 255], 0));
    }

    /// IPv6: 16 bytes, prefix=64 (the common case).
    #[test]
    fn maskcmp_v6() {
        let a = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let b = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0, 0, 2,
        ];
        // /64: first 8 bytes equal → match.
        assert!(maskcmp(&a, &b, 64));
        // /72: first 9 bytes — byte 9 differs (0 vs 0xff). No.
        assert!(!maskcmp(&a, &b, 72));
    }

    // ─── Subnet::matches: the info_subnet match logic ────────────────

    /// Helper: cuts `unwrap` noise.
    fn sn(s: &str) -> Subnet {
        s.parse().unwrap()
    }

    /// Address mode: "which subnet routes 10.0.0.5?". The /24 wins;
    /// the /16 wins too (it's a less-specific match — `info_subnet`
    /// prints ALL matches, doesn't pick the longest).
    #[test]
    fn matches_address_mode_v4() {
        let host = sn("10.0.0.5"); // /32 default
        // The /24 contains it.
        assert!(sn("10.0.0.0/24").matches(&host, true));
        // The /16 contains it.
        assert!(sn("10.0.0.0/16").matches(&host, true));
        // 10.0.1.0/24 does NOT.
        assert!(!sn("10.0.1.0/24").matches(&host, true));
        // /0 contains everything.
        assert!(sn("0.0.0.0/0").matches(&host, true));
    }

    /// Exact mode: prefix AND addr must match. /24 != /32, so the
    /// host doesn't match the /24 even though it's inside.
    #[test]
    fn matches_exact_mode_v4() {
        let net = sn("10.0.0.0/24");
        // Identity.
        assert!(net.matches(&net, false));
        // Different prefix → no.
        assert!(!net.matches(&sn("10.0.0.0/25"), false));
        // Different addr (same prefix) → no.
        assert!(!net.matches(&sn("10.0.1.0/24"), false));
        // The C uses memcmp on ALL addr bytes, not just the masked
        // ones. So `10.0.0.1/24` (non-canonical, host bit set)
        // does NOT match `10.0.0.0/24`. Daemon never sends non-
        // canonical, but the user could TYPE it (and `str2net`
        // accepts it; only `subnetcheck` rejects, and `info_subnet`
        // doesn't call subnetcheck on the find).
        assert!(!net.matches(&sn("10.0.0.1/24"), false));
    }

    /// V6 address mode. `2001:db8::1` is in `2001:db8::/32`.
    #[test]
    fn matches_address_mode_v6() {
        let host = sn("2001:db8::1");
        assert!(sn("2001:db8::/32").matches(&host, true));
        assert!(sn("2001:db8::/64").matches(&host, true));
        assert!(!sn("2001:db9::/32").matches(&host, true));
    }

    /// MAC: only exact-match. `as_address` is dead.
    #[test]
    fn matches_mac() {
        let mac = sn("01:02:03:04:05:06");
        let other = sn("01:02:03:04:05:07");
        // Both modes are exact-match.
        assert!(mac.matches(&mac, true));
        assert!(mac.matches(&mac, false));
        assert!(!mac.matches(&other, true));
        assert!(!mac.matches(&other, false));
    }

    /// Type mismatch: V4 vs V6 → no.
    #[test]
    fn matches_type_mismatch() {
        // ::ffff:10.0.0.5 is the v4-mapped v6 address. Semantically
        // "the same host", but the type discriminant differs (V6).
        // No v4-in-v6 collapse.
        assert!(!sn("10.0.0.0/24").matches(&sn("::ffff:10.0.0.5"), true));
        // V4 vs MAC → no.
        assert!(!sn("10.0.0.0/24").matches(&sn("01:02:03:04:05:06"), true));
    }

    /// Weight is ignored. `info_subnet` checks weight in a SEPARATE
    /// branch, only when the user typed `#`. `matches` doesn't see
    /// weight at all.
    #[test]
    fn matches_ignores_weight() {
        // 10.0.0.0/24#5 vs 10.0.0.0/24#10 → match (in exact mode).
        // The caller (`info`) checks weight separately if it cares.
        assert!(sn("10.0.0.0/24#5").matches(&sn("10.0.0.0/24#10"), false));
    }
}
