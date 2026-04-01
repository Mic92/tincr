//! Proptest round-trips. The PEM round-trip is the high-value one —
//! it composes `b64::encode` (KAT-locked) with our framing, and any
//! drift in the framing shows up as size or decode mismatch.

use proptest::prelude::*;

use tinc_conf::pem::{read_pem, write_pem};
use tinc_conf::{parse_line, Source};

/// Variable names: tinc only emits `[A-Za-z0-9]+`. The C
/// `parse_config_line` doesn't validate (it just splits at `[\t =]`),
/// so the parser accepts anything-but-separator, but we test the space
/// the daemon actually writes via `tincctl` / `append_config_file`.
fn arb_key() -> impl Strategy<Value = String> {
    "[A-Za-z][A-Za-z0-9]{0,30}"
}

/// Values: not starting with `[\t =]`, not ending with `[\t ]`, no
/// newlines.
///
/// The leading-`=` exclusion was found by proptest: `"A\t=0"` parses
/// as `A` / `0`, not `A` / `=0`, because the separator scan eats `\t`
/// then the optional `=`. Ambiguity is real — the C does the same. But
/// tinc never writes values starting with `=`: its b64 has no padding
/// (LSB-first variant), addresses don't, port numbers don't, subnet
/// strings don't. So we constrain the generator to the space tinc
/// emits, and the round-trip holds there.
///
/// Internal `=` is fine and tested: `"A = b=c"` → `A` / `b=c` because
/// only the *first* `=` after the variable is separator-ish.
fn arb_value() -> impl Strategy<Value = String> {
    // First char: `!-~` minus `=` (which is `\x3d`). Ranges: `!-<` then `>-~`.
    // Single-char case via alternation.
    r"[!-<>-~][ -~]{0,40}[!-~]|[!-<>-~]"
}

/// Separator forms: the four tinc actually emits (` = ` from
/// `append_config_file`, ` ` from old hand-written, `=` from `-o`,
/// `\t` from… nobody, but `strspn("\t ")` accepts it).
fn arb_sep() -> impl Strategy<Value = &'static str> {
    prop_oneof![Just(" = "), Just(" "), Just("="), Just("\t"), Just(" =\t ")]
}

proptest! {
    /// Any valid (key, sep, value) parses back to the same (key, value).
    /// Separator is forgotten — that's the parser's job.
    #[test]
    fn line_roundtrip(k in arb_key(), sep in arb_sep(), v in arb_value()) {
        let line = format!("{k}{sep}{v}");
        let entry = parse_line(&line, Source::Cmdline { line: 1 })
            .expect("non-blank line")
            .expect("non-empty value");
        prop_assert_eq!(&entry.variable, &k);
        prop_assert_eq!(&entry.value, &v);
    }

    /// PEM round-trip at arbitrary sizes. The `write_pem` 48-byte
    /// chunking + `read_pem` arbitrary-chunking compose to identity.
    /// Covers single-line (≤48), multi-line, and the boundary cases
    /// (47, 48, 49) that the unit tests pin individually.
    #[test]
    fn pem_roundtrip(blob in prop::collection::vec(any::<u8>(), 1..200)) {
        let mut buf = Vec::new();
        write_pem(&mut buf, "TEST", &blob).unwrap();
        let back = read_pem(&buf[..], "TEST", blob.len()).unwrap();
        prop_assert_eq!(&back[..], &blob[..]);
    }

    /// PEM with junk before BEGIN — `hosts/foo` files have config lines
    /// then a key. The parser must skip past arbitrary preamble.
    #[test]
    fn pem_skips_preamble(
        preamble in r"([A-Za-z]+ = [!-~]+\n){0,10}",
        blob in prop::collection::vec(any::<u8>(), 1..100),
    ) {
        // Preamble must not contain a stray `-----BEGIN TEST` — the
        // generator's char class doesn't include `-` so it can't.
        let mut buf = preamble.into_bytes();
        write_pem(&mut buf, "TEST", &blob).unwrap();
        let back = read_pem(&buf[..], "TEST", blob.len()).unwrap();
        prop_assert_eq!(&back[..], &blob[..]);
    }
}
