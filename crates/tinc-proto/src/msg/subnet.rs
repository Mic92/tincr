//! `protocol_subnet.c`: `ADD_SUBNET` / `DEL_SUBNET`.
//!
//! Both have the same wire shape: `%d %x %s %s` =
//! `<reqno> <nonce> <owner_name> <subnet>`. The handler `sscanf`s with
//! `%*d %*x` (skipping both prefixes), so the parse here does too.
//!
//! Why one struct, not two: the only difference is the request number,
//! and the parse logic is identical. The daemon dispatches on
//! `Request::peek` *before* calling `parse`, so by the time we're here
//! we already know which it is.

use crate::tok::{ParseError, Tok};
use crate::{Request, Subnet, check_id};

/// Body of `ADD_SUBNET` or `DEL_SUBNET`.
///
/// `owner` is checked against `check_id` during parse; if you construct
/// one of these directly with an invalid name, `format` will emit it
/// faithfully and the peer will reject it. That's the C behaviour too —
/// `send_add_subnet` doesn't validate `subnet->owner->name`, it just
/// `printf`s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubnetMsg {
    /// Node name owning this subnet. `[A-Za-z0-9_]+`, ≤2048 bytes.
    pub owner: String,
    /// The subnet. Handler additionally calls `subnetcheck` (host bits
    /// zero), but that's not a *parse* check — `str2net` doesn't enforce
    /// it. Neither do we.
    pub subnet: Subnet,
}

impl SubnetMsg {
    /// `add_subnet_h` / `del_subnet_h` parse step.
    ///
    /// `sscanf(request, "%*d %*x " MAX_STRING " " MAX_STRING, name, subnetstr)`
    /// then `check_id(name)` then `str2net(&s, subnetstr)`.
    ///
    /// # Errors
    ///
    /// Any of: too few tokens, owner name fails `check_id`, subnet
    /// string fails `str2net`.
    pub fn parse(line: &str) -> Result<Self, ParseError> {
        let mut t = Tok::new(line);
        t.skip()?; // %*d — request number, already dispatched on
        t.skip()?; // %*x — dedup nonce, see module doc

        let owner = t.s()?;
        if !check_id(owner) {
            return Err(ParseError);
        }

        let subnet: Subnet = t.s()?.parse()?;

        // The C doesn't check at_end() — sscanf ignores trailing garbage.
        // We don't either, for compat. If there's a future use for
        // trailing fields (extension), we won't break old wire data.

        Ok(Self {
            owner: owner.to_string(),
            subnet,
        })
    }

    /// `send_add_subnet` / `send_del_subnet` format step.
    ///
    /// `send_request(c, "%d %x %s %s", REQ, prng(...), owner, netstr)`
    ///
    /// Caller picks `which` and supplies a fresh `nonce`. Returns the
    /// full line *without* trailing `\n` — that's added by the meta-layer
    /// (`send_request` in C does `request[len++] = '\n'` after `vsnprintf`).
    #[must_use]
    pub fn format(&self, which: Request, nonce: u32) -> String {
        debug_assert!(
            matches!(which, Request::AddSubnet | Request::DelSubnet),
            "SubnetMsg formatted with wrong request type"
        );
        // `%x` lowercase, no `0x` — matches printf default.
        format!("{which} {nonce:x} {} {}", self.owner, self.subnet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// KAT: a line as `send_add_subnet` would emit it.
    /// `prng(UINT32_MAX)` returns some random u32; we use a fixed one.
    #[test]
    fn kat_parse() {
        let line = "10 deadbeef alice 10.0.0.0/24";
        let m = SubnetMsg::parse(line).unwrap();
        assert_eq!(m.owner, "alice");
        assert_eq!(
            m.subnet,
            Subnet::V4 {
                addr: Ipv4Addr::new(10, 0, 0, 0),
                prefix: 24,
                weight: 10
            }
        );
    }

    #[test]
    fn kat_format() {
        let m = SubnetMsg {
            owner: "alice".into(),
            subnet: Subnet::V4 {
                addr: Ipv4Addr::new(10, 0, 0, 0),
                prefix: 24,
                weight: 10,
            },
        };
        assert_eq!(
            m.format(Request::AddSubnet, 0xdead_beef),
            "10 deadbeef alice 10.0.0.0/24"
        );
        assert_eq!(m.format(Request::DelSubnet, 0x1), "11 1 alice 10.0.0.0/24");
    }

    /// Round-trip via the wire string.
    #[test]
    fn roundtrip() {
        let m = SubnetMsg {
            owner: "Bob_2".into(),
            subnet: "fe80::/10#5".parse().unwrap(),
        };
        let line = m.format(Request::AddSubnet, 42);
        let back = SubnetMsg::parse(&line).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn rejects() {
        // bad name
        assert!(SubnetMsg::parse("10 0 a-b 10.0.0.0").is_err());
        // bad subnet
        assert!(SubnetMsg::parse("10 0 alice garbage").is_err());
        // too few tokens
        assert!(SubnetMsg::parse("10 0 alice").is_err());
        assert!(SubnetMsg::parse("10").is_err());
    }

    /// The C handler ignores trailing garbage (sscanf doesn't check).
    /// We replicate.
    #[test]
    fn trailing_garbage_ok() {
        let m = SubnetMsg::parse("10 0 alice 10.0.0.0/24 ignored extra").unwrap();
        assert_eq!(m.owner, "alice");
    }
}
