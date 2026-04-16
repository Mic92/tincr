//! `protocol_edge.c`: `ADD_EDGE` / `DEL_EDGE`.
//!
//! Edges are the graph the daemon runs Dijkstra over. Adding/removing
//! one is a flooded broadcast (hence the dedup nonce, like the subnet
//! messages). The wire shapes:
//!
//! - `ADD_EDGE`: `%d %x %s %s %s %s %x %d [%s %s]`
//!   `<reqno> <nonce> <from> <to> <addr> <port> <options> <weight> [<laddr> <lport>]`
//!   The local-address suffix is **optional** — present iff the sender
//!   knows its own LAN address (post-1.0.24).
//! - `DEL_EDGE`: `%d %x %s %s` — just from/to, the edge identity.
//!
//! ## The 6-or-8 sscanf return
//!
//! `add_edge_h` does one `sscanf` and accepts return value 6 *or* 8.
//! Not 7: the optional pair is atomic. We model that with
//! `local: Option<(AddrStr, AddrStr)>` and check both-or-neither.
//!
//! ## Why `from != to` is a parse check
//!
//! `add_edge_h` line 88 does `!strcmp(from_name, to_name)` *before*
//! `seen_request` — so it's part of input validation, same tier as
//! `check_id`. A self-loop edge is malformed wire data, not a graph
//! decision. We enforce it here.

use crate::addr::AddrStr;
use crate::tok::{ParseError, Tok};
use crate::{Request, check_id};

/// Body of `ADD_EDGE`. The optional `local` pair is post-1.0.24.
///
/// `options` is a bitfield (see `OPTION_*` in `connection.h`); high
/// byte is the negotiated `PROT_MINOR`. We don't decompose it here —
/// the daemon shifts/masks at use sites.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddEdge {
    pub from: String,
    pub to: String,
    /// Remote peer's address as seen by `from`.
    pub addr: AddrStr,
    pub port: AddrStr,
    /// `e->options`, hex on the wire.
    pub options: u32,
    /// Dijkstra edge weight. `%d` on the wire; clamped to `>= 0` at
    /// parse so a peer can't bias MST/nexthop tie-breaks.
    /// the protocol doesn't reject it (never range-checked).
    pub weight: i32,
    /// `from`'s LAN-side address, if known. Newer peers send it so the
    /// receiver can prefer LAN paths.
    pub local: Option<(AddrStr, AddrStr)>,
}

impl AddEdge {
    /// `add_edge_h` parse step.
    ///
    /// `sscanf("%*d %*x %s %s %s %s %x %d %s %s", ...)`, accept 6 or 8,
    /// then `check_id(from) && check_id(to) && from != to`.
    ///
    /// # Errors
    /// Too few tokens, bad name, `from == to`, malformed hex/int, or
    /// exactly one (not zero, not two) trailing addr/port token.
    pub fn parse(line: &str) -> Result<Self, ParseError> {
        let mut t = Tok::new(line);
        t.skip()?; // %*d
        t.skip()?; // %*x

        let from = t.s()?;
        let to = t.s()?;
        if !check_id(from) || !check_id(to) || from == to {
            return Err(ParseError);
        }

        let addr = AddrStr::new(t.s()?)?;
        let port = AddrStr::new(t.s()?)?;
        let options = t.x()?;
        let weight = t.d()?.max(0); // see field doc

        // Optional pair. Both or neither — sscanf returns 6 or 8, not 7.
        let local = match (t.s_opt()?, t.s_opt()?) {
            (None, None) => None,
            (Some(la), Some(lp)) => Some((AddrStr::new(la)?, AddrStr::new(lp)?)),
            // 7 tokens. `sscanf` would also return 7 here (parses greedily
            // until a %s fails); rejected via the `parameter_count != 6 &&
            // parameter_count != 8` check.
            _ => return Err(ParseError),
        };

        Ok(Self {
            from: from.to_string(),
            to: to.to_string(),
            addr,
            port,
            options,
            weight,
            local,
        })
    }

    /// `send_add_edge` format step.
    ///
    /// `send_request("%d %x %s %s %s %s %x %d", ...)` or
    /// `send_request("%d %x %s %s %s %s %x %d %s %s", ...)`, depending
    /// on whether `e->local_address.sa.sa_family` is set. We mirror.
    #[must_use]
    pub fn format(&self, nonce: u32) -> String {
        // %x lowercase, no `#`/`0x`. %d signed decimal.
        let head = format!(
            "{} {nonce:x} {} {} {} {} {:x} {}",
            Request::AddEdge,
            self.from,
            self.to,
            self.addr,
            self.port,
            self.options,
            self.weight,
        );
        match &self.local {
            None => head,
            Some((la, lp)) => format!("{head} {la} {lp}"),
        }
    }
}

/// Body of `DEL_EDGE`. Just the edge identity — `(from, to)` is the key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelEdge {
    pub from: String,
    pub to: String,
}

impl DelEdge {
    /// `del_edge_h`: `sscanf("%*d %*x %s %s", from, to)`, `check_id`,
    /// `from != to`.
    ///
    /// # Errors
    /// Too few tokens, bad name, or `from == to`.
    pub fn parse(line: &str) -> Result<Self, ParseError> {
        let mut t = Tok::new(line);
        t.skip()?;
        t.skip()?;

        let from = t.s()?;
        let to = t.s()?;
        if !check_id(from) || !check_id(to) || from == to {
            return Err(ParseError);
        }

        Ok(Self {
            from: from.to_string(),
            to: to.to_string(),
        })
    }

    /// `send_del_edge`: `send_request("%d %x %s %s", DEL_EDGE, prng(...), from, to)`.
    #[must_use]
    pub fn format(&self, nonce: u32) -> String {
        format!("{} {nonce:x} {} {}", Request::DelEdge, self.from, self.to)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_edge_kat() {
        // Straight off send_add_edge with PROT_MINOR=7 in high byte
        // (0x07000000) of options. Weight 100. No local addr (1.0-compat).
        let line = "12 abc alice bob 10.0.0.2 655 7000000 100";
        let m = AddEdge::parse(line).unwrap();
        assert_eq!(m.from, "alice");
        assert_eq!(m.to, "bob");
        assert_eq!(m.addr.as_str(), "10.0.0.2");
        assert_eq!(m.port.as_str(), "655");
        assert_eq!(m.options, 0x0700_0000);
        assert_eq!(m.weight, 100);
        assert_eq!(m.local, None);

        // Round-trip.
        assert_eq!(m.format(0xabc), line);
    }

    #[test]
    fn add_edge_with_local() {
        let line = "12 0 a b 1.2.3.4 655 0 50 192.168.1.1 655";
        let m = AddEdge::parse(line).unwrap();
        let (la, lp) = m.local.as_ref().unwrap();
        assert_eq!(la.as_str(), "192.168.1.1");
        assert_eq!(lp.as_str(), "655");
        assert_eq!(m.format(0), line);
    }

    #[test]
    fn add_edge_negative_weight_clamped() {
        let m = AddEdge::parse("12 0 a b 1.2.3.4 655 0 -2147483648").unwrap();
        assert_eq!(m.weight, 0);
    }

    #[test]
    fn add_edge_v6() {
        // getnameinfo NI_NUMERICHOST output for v6: just the address,
        // scope ID stripped by sockaddr2str.
        let line = "12 0 a b 2001:db8::1 655 0 50";
        let m = AddEdge::parse(line).unwrap();
        assert_eq!(m.addr.as_str(), "2001:db8::1");
        assert_eq!(m.format(0), line);
    }

    /// 7 tokens (one local field, not two): `parameter_count != 6 &&
    /// != 8` fires. We reject too.
    #[test]
    fn add_edge_seven_tokens_rejected() {
        assert!(AddEdge::parse("12 0 a b 1.1.1.1 655 0 50 lonely").is_err());
    }

    #[test]
    fn add_edge_self_loop_rejected() {
        // from == to: self-loops are rejected at parse time.
        assert!(AddEdge::parse("12 0 alice alice 1.1.1.1 655 0 50").is_err());
    }

    #[test]
    fn add_edge_bad_name_rejected() {
        assert!(AddEdge::parse("12 0 a-x b 1.1.1.1 655 0 50").is_err());
    }

    #[test]
    fn del_edge_kat() {
        let line = "13 deadbeef alice bob";
        let m = DelEdge::parse(line).unwrap();
        assert_eq!(m.from, "alice");
        assert_eq!(m.to, "bob");
        assert_eq!(m.format(0xdead_beef), line);

        assert!(DelEdge::parse("13 0 alice alice").is_err()); // self-loop
        assert!(DelEdge::parse("13 0 alice").is_err()); // too short
    }

    /// `AF_UNKNOWN` round-trip: addr is whatever string came in.
    /// `str2sockaddr` accepts anything (stuffs it in `sa->unknown.address`
    /// on `getaddrinfo` failure), so a peer can send garbage and it'll
    /// be passed through to the next hop unchanged.
    #[test]
    fn add_edge_unknown_addr() {
        let line = "12 0 a b not.an.ip notaport 0 1";
        let m = AddEdge::parse(line).unwrap();
        assert_eq!(m.addr.as_str(), "not.an.ip");
        assert_eq!(m.port.as_str(), "notaport");
        assert_eq!(m.format(0), line);
    }
}
