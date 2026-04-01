//! `sscanf`-shaped tokenizer.
//!
//! The protocol is `printf`-space-separated and `sscanf`-space-consumed.
//! `sscanf %s` greedily reads non-whitespace; `%d`/`%x` read whitespace
//! then digits. The format strings always interleave them with single
//! spaces. So: split on whitespace, hand out tokens left-to-right.
//!
//! This is *not* a general `sscanf` — it's exactly enough to cover the 23
//! format strings in `protocol_*.c`. Those use only `%d`, `%x`, `%hd`,
//! `%hu`, `%lu`, `%s`, `%*d`, `%*x`, `%*s` (`*` = skip), and one `%2d.%3d`
//! width pair (in `id_h`, for `17.7` version parsing). The width pair gets
//! its own helper; everything else is just "next token, parse as int".

use crate::MAX_STRING;

/// Parse failure. Not an enum because the C doesn't distinguish either —
/// `sscanf() != expected_count` is all the daemon cares about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseError;

/// Iterator over space-delimited tokens. `sscanf %s` semantics: any run
/// of whitespace separates, leading/trailing whitespace ignored.
///
/// `split_ascii_whitespace` is *almost* right but treats `\n` as a
/// separator, and protocol lines come with the `\n` already stripped (by
/// `meta.c`). We use it anyway — if a stray `\n` shows up mid-string,
/// `sscanf %s` would also stop there.
pub(crate) struct Tok<'a> {
    /// What's left after the last token. Kept around so `rest()` can
    /// return the unconsumed tail (`ANS_KEY` needs this — it has a
    /// variable-length suffix the C parses with a second `sscanf`).
    rest: &'a str,
}

impl<'a> Tok<'a> {
    pub fn new(s: &'a str) -> Self {
        Self { rest: s }
    }

    /// Next token, or `Err` if exhausted. Enforces the 2048-byte limit.
    pub fn s(&mut self) -> Result<&'a str, ParseError> {
        let s = self
            .rest
            .trim_start_matches(|c: char| c.is_ascii_whitespace());
        let end = s.find(|c: char| c.is_ascii_whitespace()).unwrap_or(s.len());
        if end == 0 || end > MAX_STRING {
            return Err(ParseError);
        }
        let (tok, rest) = s.split_at(end);
        self.rest = rest;
        Ok(tok)
    }

    /// `%*s` / `%*d` / `%*x` — skip a token, don't care what's in it.
    pub fn skip(&mut self) -> Result<(), ParseError> {
        self.s().map(|_| ())
    }

    /// `%d`. C `sscanf %d` accepts a leading `+` or `-`; the protocol
    /// only emits unsigned via `%d` so we don't bother with `+`, but
    /// `-` is observably parsed (e.g. `mtu_info_h` checks `mtu < 512`
    /// after `%d` — no separate negativity check, so `i32` semantics).
    pub fn d(&mut self) -> Result<i32, ParseError> {
        self.s()?.parse().map_err(|_| ParseError)
    }

    /// `%x`. Used for the dedup nonce and option bitfields. `printf %x`
    /// is lowercase, no `0x`; that's all we accept. (`sscanf %x` would
    /// also take uppercase and `0x` — not on the wire, not supported.)
    pub fn x(&mut self) -> Result<u32, ParseError> {
        u32::from_str_radix(self.s()?, 16).map_err(|_| ParseError)
    }

    /// `%lu`. Only `ANS_KEY` uses it, for `digest_length` (a `size_t`
    /// cast to `unsigned long`). Realistically always tiny, but the
    /// printf width is `%lu` so we honor that.
    pub fn lu(&mut self) -> Result<u64, ParseError> {
        self.s()?.parse().map_err(|_| ParseError)
    }

    /// `%hd`. `tcppacket_h`/`sptps_tcppacket_h` parse a length as
    /// `short int` then check `< 0`. The send side emits `%d`/`%lu`
    /// (unsigned), so a negative parse means corruption — the C
    /// detects it via the signed type. We do the same.
    pub fn hd(&mut self) -> Result<i16, ParseError> {
        self.s()?.parse().map_err(|_| ParseError)
    }

    /// Next token if there is one; `Ok(None)` if exhausted.
    ///
    /// `ADD_EDGE` has 6 mandatory + 2 optional fields (`sscanf` returns
    /// 6 or 8). `ANS_KEY` has 7 + 2 optional. `REQ_KEY` has 2 + 1
    /// optional. The C handles all three with `sscanf(...) < N` instead
    /// of `!= N` and leaves the trailing locals at their initial value.
    /// This is the moral equivalent.
    pub fn s_opt(&mut self) -> Result<Option<&'a str>, ParseError> {
        match self.s() {
            Ok(tok) => Ok(Some(tok)),
            // s() returns Err on both "exhausted" and "too long"; we
            // need to distinguish. Exhausted = rest is empty/whitespace.
            Err(_) if self.rest_raw().is_empty() => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// `%d` optional. See `s_opt`.
    pub fn d_opt(&mut self) -> Result<Option<i32>, ParseError> {
        match self.s_opt()? {
            Some(t) => t.parse().map(Some).map_err(|_| ParseError),
            None => Ok(None),
        }
    }

    /// Unconsumed tail, leading whitespace stripped. Factored out so
    /// `s_opt` can tell "end of input" from "token too long" without
    /// duplicating the trim.
    fn rest_raw(&self) -> &'a str {
        self.rest
            .trim_start_matches(|c: char| c.is_ascii_whitespace())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic() {
        let mut t = Tok::new("12 deadbeef hello");
        assert_eq!(t.s().unwrap(), "12");
        assert_eq!(t.s().unwrap(), "deadbeef");
        assert_eq!(t.s().unwrap(), "hello");
        assert!(t.s().is_err());
    }

    #[test]
    fn skip() {
        let mut t = Tok::new("  12  abc  trailing ");
        t.skip().unwrap();
        t.skip().unwrap();
        assert_eq!(t.s().unwrap(), "trailing");
        assert!(t.s().is_err()); // trailing whitespace, no token
    }

    #[test]
    fn typed() {
        let mut t = Tok::new("12 deadbeef -5 999999999999");
        assert_eq!(t.d().unwrap(), 12);
        assert_eq!(t.x().unwrap(), 0xdead_beef);
        assert_eq!(t.d().unwrap(), -5);
        assert_eq!(t.lu().unwrap(), 999_999_999_999);
    }

    #[test]
    fn opt() {
        // mandatory present, optional absent
        let mut t = Tok::new("a b");
        assert_eq!(t.s().unwrap(), "a");
        assert_eq!(t.s().unwrap(), "b");
        assert_eq!(t.s_opt().unwrap(), None);
        assert_eq!(t.s_opt().unwrap(), None); // idempotent

        // optional present
        let mut t = Tok::new("a b c");
        t.skip().unwrap();
        t.skip().unwrap();
        assert_eq!(t.s_opt().unwrap(), Some("c"));
        assert_eq!(t.s_opt().unwrap(), None);

        // optional present but too long: that's an Err, not None.
        // (Distinguishes "absent" from "malformed".)
        let bad = format!("a {}", "x".repeat(MAX_STRING + 1));
        let mut t = Tok::new(&bad);
        t.skip().unwrap();
        assert!(t.s_opt().is_err());
    }

    #[test]
    fn hex_lowercase_only() {
        // printf %x is lowercase. sscanf %x would accept upper too;
        // from_str_radix(.., 16) does as well. We don't tighten this:
        // it's never on the wire either way, and the asymmetry doesn't
        // affect compat (we never emit upper, peers never send it).
        assert_eq!(Tok::new("DEADBEEF").x().unwrap(), 0xdead_beef);
        // But 0x prefix is rejected.
        assert!(Tok::new("0xff").x().is_err());
    }

    #[test]
    fn limits() {
        // 2048 chars: ok. 2049: not.
        let ok = "a".repeat(MAX_STRING);
        let bad = "a".repeat(MAX_STRING + 1);
        assert!(Tok::new(&ok).s().is_ok());
        assert!(Tok::new(&bad).s().is_err());
    }
}
