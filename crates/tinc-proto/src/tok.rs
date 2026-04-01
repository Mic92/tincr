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

    // `d()` for signed `%d`, `x()` for `%x`, `rest()` for the
    // ANS_KEY second-sscanf trick — all land with their consumers.
    // SubnetMsg only needs `s` and `skip`.
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
    fn limits() {
        // 2048 chars: ok. 2049: not.
        let ok = "a".repeat(MAX_STRING);
        let bad = "a".repeat(MAX_STRING + 1);
        assert!(Tok::new(&ok).s().is_ok());
        assert!(Tok::new(&bad).s().is_err());
    }
}
