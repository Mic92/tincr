//! Invitation URL parsing.

use tinc_crypto::invite::{COOKIE_LEN, SLUG_LEN, parse_slug};
use zeroize::Zeroizing;

/// `host[:port]/slug`, parsed.
///
/// `[derive(Debug)]` deliberately omitted — `Debug` would print the
/// cookie. The host/port aren't secret but the cookie is. If you
/// need to debug, log host and port explicitly.
pub struct ParsedUrl {
    pub host: String,
    pub port: String,
    /// First 18 bytes of `sha512(b64(invitation_pubkey))`. Not secret
    /// — it's a commitment, not a key. Used to verify the daemon's
    /// greeting.
    pub key_hash: [u8; COOKIE_LEN],
    /// 18 random bytes. Secret — bearer token.
    pub cookie: Zeroizing<[u8; COOKIE_LEN]>,
}

/// Parse the invitation URL.
///
/// Accepts: `host:port/SLUG`, `host/SLUG`, `[v6]:port/SLUG`,
/// `[v6]/SLUG`. Port defaults to `"655"`. Slug is exactly 48 b64-url
/// chars.
///
/// Upstream does this with destructive `strchr` + `*p++ = 0` walking.
/// We slice. Same accept set: rejects garbage at every step.
/// `goto invalid` upstream → `None` here. The caller maps `None` to
/// `CmdError::BadInput("Invalid invitation URL.")`.
///
/// Doesn't validate that `host` is a real hostname or that `port`
/// is numeric — `getaddrinfo`/`TcpStream::connect` will fail on
/// garbage and that's a clearer error than "Invalid URL".
#[must_use]
pub fn parse_url(url: &str) -> Option<ParsedUrl> {
    let slash = url.find('/')?;
    let (addr_part, slug_with_slash) = url.split_at(slash);
    let slug = &slug_with_slash[1..]; // skip '/'

    if slug.len() != SLUG_LEN {
        return None;
    }

    // Bracketed IPv6: the brackets are URL syntax, NOT part of the
    // address. Strip them; `TcpStream::connect`'s `(&str, port)`
    // form takes the unbracketed literal.
    let (host, port) = if let Some(v6_body) = addr_part.strip_prefix('[') {
        let close = v6_body.find(']')?;
        let host = &v6_body[..close];
        let after = &v6_body[close + 1..];
        // Anything between `]` and `/` that isn't `:PORT` is garbage.
        // Upstream silently ignores trailing garbage (`]garbage/slug`
        // would parse with default port). We're stricter: only
        // `:PORT` or empty.
        let port = match after.strip_prefix(':') {
            Some(p) if !p.is_empty() => p,
            None if after.is_empty() => "655",
            _ => return None, // `]garbage` or `]:` (empty port)
        };
        (host.to_owned(), port.to_owned())
    } else {
        // Non-bracketed: split on FIRST colon. `1.2.3.4:655` works.
        // Unbracketed `::1/slug` would split at the first `:` and
        // treat `:1` as the port — broken, same as upstream. Use
        // brackets.
        // `host:` (empty port) and `host` (no colon) both default.
        // Upstream does both; unusual but harmless.
        match addr_part.split_once(':') {
            Some((h, p)) if !p.is_empty() => (h.to_owned(), p.to_owned()),
            Some((h, _empty)) => (h.to_owned(), String::from("655")),
            None => (addr_part.to_owned(), String::from("655")),
        }
    };

    if host.is_empty() {
        return None;
    }

    // parse_slug already KAT-tested; it does the length check and
    // alphabet check.
    let (key_hash, cookie) = parse_slug(slug)?;

    Some(ParsedUrl {
        host,
        port,
        key_hash,
        cookie: Zeroizing::new(cookie),
    })
}
