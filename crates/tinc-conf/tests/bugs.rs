//! Bug-hunt repros for the config parser. Each test is `#[ignore]`d
//! and demonstrates a defect; see `docs/bugs/FOUND.md`.

use std::path::Path;

/// C tinc reads config files as raw bytes (`fgets`); a Latin-1 byte in
/// a comment (or anywhere) is harmless. The Rust port reads via
/// `BufRead::lines()` which validates UTF-8 and returns
/// `io::ErrorKind::InvalidData` on the first non-UTF-8 byte, so the
/// whole file is rejected and the daemon refuses to start.
///
/// A `hosts/NAME` file produced on a Latin-1 locale (or hand-edited on
/// an old Windows box) that a 1.1 C daemon happily reads will hard-fail
/// here.
#[test]
#[ignore = "bug: non-UTF-8 byte in config (e.g. Latin-1 comment) hard-errors; C tinc accepts"]
fn non_utf8_comment_rejected() {
    // "# café" in ISO-8859-1: 'é' is 0xE9, a lone continuation-less
    // byte in UTF-8 → invalid.
    let input: &[u8] = b"# caf\xe9\nName = alice\n";
    let entries = tinc_conf::parse::parse_reader(input, Path::new("tinc.conf"))
        .expect("C tinc parses this; Rust should too");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].variable, "Name");
    assert_eq!(entries[0].value, "alice");
}

/// UTF-8 BOM at start of file becomes part of the first variable name,
/// so `lookup("Name")` finds nothing. Windows Notepad writes a BOM by
/// default. C tinc has the same defect (parity), noted here as a
/// robustness gap the port could close cheaply.
#[test]
#[ignore = "bug: UTF-8 BOM glued onto first variable name (parity with C, robustness gap)"]
fn bom_on_first_line() {
    let input = "\u{feff}Name = alice\n";
    let entries = tinc_conf::parse::parse_reader(input.as_bytes(), Path::new("tinc.conf")).unwrap();
    let mut cfg = tinc_conf::Config::new();
    cfg.merge(entries);
    assert_eq!(
        cfg.lookup("Name").next().map(|e| e.value.as_str()),
        Some("alice"),
        "BOM should be stripped so the first key is reachable"
    );
}
