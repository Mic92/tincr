//! Regression tests for config-parser robustness gaps vs C tinc.

use std::path::Path;

/// C tinc reads config files as raw bytes (`fgets`); a Latin-1 byte in
/// a comment is harmless. The parser must not hard-fail the whole file
/// on a non-UTF-8 byte — a `hosts/NAME` file produced on a Latin-1
/// locale that a 1.1 C daemon reads should also be readable here.
#[test]
fn non_utf8_bytes_tolerated() {
    // "# café" in ISO-8859-1: 'é' is 0xE9, a lone continuation-less
    // byte in UTF-8 → invalid.
    let input: &[u8] = b"# caf\xe9\nName = alice\n";
    let entries = tinc_conf::parse::parse_reader(input, Path::new("tinc.conf"))
        .expect("C tinc parses this; Rust should too");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].variable, "Name");
    assert_eq!(entries[0].value, "alice");
}

/// Windows Notepad writes a UTF-8 BOM by default. C tinc glues it onto
/// the first variable name; we strip it so `lookup("Name")` works.
#[test]
fn bom_on_first_line_stripped() {
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
