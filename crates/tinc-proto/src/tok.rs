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
//!
//! ## The `" port "` literal
//!
//! `sockaddr2hostname` returns `"10.0.0.1 port 655"` — a single string
//! with embedded spaces. The daemon writes it via *one* `%s`, and the
//! CLI parses it back via `%s port %s`. The literal `port` in the
//! format string is how `sscanf` skips the word. `lit()` does the
//! same here.
//!
//! That means the dump-format strings have ONE more sscanf conversion
//! than they have printf conversions, per `" port "` instance. The
//! `ADD_EDGE` message-protocol format does NOT have this — there `addr`
//! and `port` are separate `%s` tokens both ways — because the daemon
//! formats them with `sockaddr2str` (two outputs) not `sockaddr2hostname`
//! (one fused). Dump uses the fused form. The asymmetry is annoying;
//! it's there because dump is "human-readable-ish" and uses the
//! fused form everywhere it appears in log messages.

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
///
/// Public because `tinc-tools` parses dump rows with the same `sscanf`
/// shape. The dump format is CLI↔daemon (not on the wire to peers) but
/// the cross-impl seam (Rust CLI ↔ C daemon and vice versa) wants to
/// keep working; and the four format strings live next to the
/// message-protocol ones upstream, so co-locating their
/// parser here keeps them in lockstep.
pub struct Tok<'a> {
    /// What's left after the last token. Kept around so `rest()` can
    /// return the unconsumed tail (`ANS_KEY` needs this — it has a
    /// variable-length suffix the C parses with a second `sscanf`).
    rest: &'a str,
}

impl<'a> Tok<'a> {
    #[must_use]
    pub const fn new(s: &'a str) -> Self {
        Self { rest: s }
    }

    /// Next token, or `Err` if exhausted. Enforces the 2048-byte limit.
    ///
    /// # Errors
    /// `ParseError` if no tokens remain or the token exceeds `MAX_STRING`.
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
    ///
    /// # Errors
    /// `ParseError` if no tokens remain.
    pub fn skip(&mut self) -> Result<(), ParseError> {
        self.s().map(|_| ())
    }

    /// `%d`. `sscanf %d` accepts a leading `+` or `-`; the protocol
    /// only emits unsigned via `%d` so we don't bother with `+`, but
    /// `-` is observably parsed (e.g. `mtu_info_h` checks `mtu < 512`
    /// after `%d` — no separate negativity check, so `i32` semantics).
    ///
    /// # Errors
    /// `ParseError` if no tokens remain or the token isn't a valid `i32`.
    pub fn d(&mut self) -> Result<i32, ParseError> {
        self.s()?.parse().map_err(|_| ParseError)
    }

    /// `%x`. Used for the dedup nonce and option bitfields. `printf %x`
    /// is lowercase, no `0x`; that's all we accept. (`sscanf %x` would
    /// also take uppercase and `0x` — not on the wire, not supported.)
    ///
    /// # Errors
    /// `ParseError` if no tokens remain or the token isn't lowercase hex.
    pub fn x(&mut self) -> Result<u32, ParseError> {
        u32::from_str_radix(self.s()?, 16).map_err(|_| ParseError)
    }

    /// `%lu`. Only `ANS_KEY` uses it, for `digest_length` (a `size_t`
    /// cast to `unsigned long`). Realistically always tiny, but the
    /// printf width is `%lu` so we honor that.
    ///
    /// **glibc-permissive**: `sscanf("%lu", "-1")` succeeds and writes
    /// `ULONG_MAX`. C99 7.20.1.4/5: `strtoul` on a string with a leading
    /// `-` parses the digits, then "the value resulting from the
    /// conversion is negated (in the return type)" — i.e. negated as
    /// unsigned. `-1` → `0u64.wrapping_sub(1)` = `u64::MAX`.
    ///
    /// SPTPS-handshake-via-ANS_KEY mode exploits this: it sends the
    /// literal string `"-1 -1 -1"` for cipher/digest/
    /// maclen (the values are placeholders — SPTPS doesn't use legacy
    /// crypto, so `ans_key_h` never reads them). The first two are `%d`
    /// (i32, fine). The third is `%lu`. A strict `u64::parse` would
    /// reject the line and drop the connection. Match glibc.
    ///
    /// # Errors
    /// `ParseError` if no tokens remain or the token parses as neither
    /// `u64` nor `i64`.
    #[allow(clippy::cast_sign_loss)] // intentional: strtoul "negate as unsigned"
    pub fn lu(&mut self) -> Result<u64, ParseError> {
        let s = self.s()?;
        // Fast path: positive. The only on-wire negative is the SPTPS
        // ANS_KEY sentinel; everything else is a real (small) maclen.
        if let Ok(v) = s.parse::<u64>() {
            return Ok(v);
        }
        // glibc strtoul "negate as unsigned": parse signed, wrapping-
        // cast. `-1` → `u64::MAX`, `-2` → `u64::MAX - 1`. The C never
        // actually sends anything but `-1` here, but matching strtoul
        // semantics (rather than special-casing the literal `"-1"`) is
        // the principled fix — future C might send `-7` for all we know.
        // (Clippy: `# Errors` doc on the method itself covers this.)
        s.parse::<i64>().map(|i| i as u64).map_err(|_| ParseError)
    }

    /// `%hd`. `tcppacket_h`/`sptps_tcppacket_h` parse a length as
    /// `short int` then check `< 0`. The send side emits `%d`/`%lu`
    /// (unsigned), so a negative parse means corruption — the C
    /// detects it via the signed type. We do the same.
    ///
    /// `%hd` is also used for pmtu/minmtu/maxmtu in the node dump
    /// (the daemon writes `%d`; those fields are `int` but they're
    /// MTU values ≤ 9000ish so `i16` fits).
    ///
    /// # Errors
    /// `ParseError` if no tokens remain or the token isn't a valid `i16`.
    pub fn hd(&mut self) -> Result<i16, ParseError> {
        self.s()?.parse().map_err(|_| ParseError)
    }

    /// `%ld`. Only `last_state_change` in the node dump uses it —
    /// it's a `time_t` cast to `long`. `time_t` is
    /// `i64` on every platform we care about; `long` is `i32` on
    /// 32-bit systems but `time_t` would already have wrapped by
    /// then, so the C is wrong on 32-bit-with-64-bit-time_t and
    /// we don't try to be wrong the same way. `i64` everywhere.
    ///
    /// # Errors
    /// `ParseError` if no tokens remain or the token isn't a valid `i64`.
    pub fn ld(&mut self) -> Result<i64, ParseError> {
        self.s()?.parse().map_err(|_| ParseError)
    }

    /// Literal token. `sscanf(line, "... port %s ...")` — the
    /// bare word `port` consumes that exact token (after skipping
    /// leading whitespace, like everything else in `sscanf`). If
    /// the next token isn't `port`, `sscanf` returns the count up
    /// to that point. We hard-fail.
    ///
    /// Used for the `" port "` separator in `sockaddr2hostname`
    /// output — see module doc. The four dump formats use it 1-2
    /// times each; the message protocol uses it zero times (it
    /// uses `sockaddr2str`, not `sockaddr2hostname`).
    ///
    /// # Errors
    /// `ParseError` if the next token isn't exactly `expected`.
    /// Case-sensitive: `sscanf` literal matching is `memcmp`, and
    /// the daemon writes lowercase `"port"` always (string literal,
    /// no `tolower` involved).
    pub fn lit(&mut self, expected: &str) -> Result<(), ParseError> {
        if self.s()? == expected {
            Ok(())
        } else {
            Err(ParseError)
        }
    }

    /// Next token if there is one; `Ok(None)` if exhausted.
    ///
    /// `ADD_EDGE` has 6 mandatory + 2 optional fields (`sscanf` returns
    /// 6 or 8). `ANS_KEY` has 7 + 2 optional. `REQ_KEY` has 2 + 1
    /// optional. The C handles all three with `sscanf(...) < N` instead
    /// of `!= N` and leaves the trailing locals at their initial value.
    /// This is the moral equivalent.
    ///
    /// # Errors
    /// `ParseError` if a token is present but exceeds `MAX_STRING`.
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
    ///
    /// # Errors
    /// `ParseError` if a token is present but isn't a valid `i32`.
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
    fn lu_accepts_negative_glibc_style() {
        // SPTPS ANS_KEY placeholder maclen is the literal "-1".
        // sscanf("%lu", "-1") = ULONG_MAX. We must
        // accept it or the cross-impl handshake dies right after SPTPS
        // record exchange.
        assert_eq!(Tok::new("-1").lu().unwrap(), u64::MAX);
        // strtoul semantics, not just the literal "-1":
        assert_eq!(Tok::new("-2").lu().unwrap(), u64::MAX - 1);
        // Still rejects non-numeric garbage.
        assert!(Tok::new("-").lu().is_err());
        assert!(Tok::new("-x").lu().is_err());
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
    fn lit_match() {
        // The dump-node shape: `... HOST port PORT ...`
        // sscanf `%s port %s` re-splits sockaddr2hostname output.
        let mut t = Tok::new("10.0.0.1 port 655");
        assert_eq!(t.s().unwrap(), "10.0.0.1");
        t.lit("port").unwrap();
        assert_eq!(t.s().unwrap(), "655");
    }

    #[test]
    fn lit_mismatch() {
        let mut t = Tok::new("10.0.0.1 PORT 655");
        t.skip().unwrap();
        // case-sensitive (sscanf literal is memcmp)
        assert!(t.lit("port").is_err());
        // and the cursor is past it now — sscanf doesn't rewind
        // on literal mismatch either, but it's irrelevant: we
        // never recover from ParseError, the row is dropped.
    }

    #[test]
    fn ld_type() {
        // time_t-range value, would overflow i32.
        // 2_000_000_000 fits i32; 3_000_000_000 doesn't.
        let mut t = Tok::new("3000000000");
        assert_eq!(t.ld().unwrap(), 3_000_000_000_i64);
        // Negative ok (C %ld is signed). last_state_change should
        // never be negative but the parse doesn't enforce.
        assert_eq!(Tok::new("-1").ld().unwrap(), -1);
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
