//! Proptest round-trips over the input space tinc itself writes.

use proptest::prelude::{Just, Strategy, any, prop, prop_assert_eq, prop_oneof, proptest};

use tinc_conf::pem::{read_pem, write_pem};
use tinc_conf::{Source, parse_line};

fn arb_key() -> impl Strategy<Value = String> {
    "[A-Za-z][A-Za-z0-9]{0,30}"
}

/// No leading `=` (the grammar cannot distinguish `A\t=0` from
/// `A = 0`; tinc never writes such values), no surrounding blanks.
fn arb_value() -> impl Strategy<Value = String> {
    r"[!-<>-~][ -~]{0,40}[!-~]|[!-<>-~]"
}

fn arb_sep() -> impl Strategy<Value = &'static str> {
    prop_oneof![Just(" = "), Just(" "), Just("="), Just("\t"), Just(" =\t ")]
}

proptest! {
    #[test]
    fn line_roundtrip(k in arb_key(), sep in arb_sep(), v in arb_value()) {
        let line = format!("{k}{sep}{v}");
        let entry = parse_line(&line, Source::Cmdline { line: 1 })
            .expect("non-blank line")
            .expect("non-empty value");
        prop_assert_eq!(&entry.variable, &k);
        prop_assert_eq!(&entry.value, &v);
    }

    #[test]
    fn pem_roundtrip(blob in prop::collection::vec(any::<u8>(), 1..200)) {
        let mut buf = Vec::new();
        write_pem(&mut buf, "TEST", &blob).unwrap();
        let back = read_pem(&buf[..], "TEST", blob.len()).unwrap();
        prop_assert_eq!(&back[..], &blob[..]);
    }

    /// `hosts/NAME` has config lines before the key.
    #[test]
    fn pem_skips_preamble(
        preamble in r"([A-Za-z]+ = [!-~]+\n){0,10}",
        blob in prop::collection::vec(any::<u8>(), 1..100),
    ) {
        let mut buf = preamble.into_bytes();
        write_pem(&mut buf, "TEST", &blob).unwrap();
        let back = read_pem(&buf[..], "TEST", blob.len()).unwrap();
        prop_assert_eq!(&back[..], &blob[..]);
    }
}
