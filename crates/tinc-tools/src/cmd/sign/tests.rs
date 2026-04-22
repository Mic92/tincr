use super::*;
use crate::testutil::ConfDir;
use std::fs;

/// **The contract test.** Sign, then verify. Body round-trips
/// byte-exact. This is what `tinc sign | tinc verify .` does.
#[test]
fn sign_verify_roundtrip() {
    let cd = ConfDir::with_name("alice").with_ed25519_key("alice");
    let paths = cd.paths().clone();

    let data = b"hello world\nsecond line\n";
    // Write to a file (not stdin — testing the file path).
    let input = cd.path().join("payload");
    fs::write(&input, data).unwrap();

    let mut signed = Vec::new();
    sign(&paths, Some(&input), 1_700_000_000, &mut signed).unwrap();

    // ─── Shape check on the output
    // First line is the header, rest is the body byte-exact.
    let nl = signed.iter().position(|&b| b == b'\n').unwrap();
    let header = std::str::from_utf8(&signed[..nl]).unwrap();
    assert!(header.starts_with("Signature = alice 1700000000 "));
    // Sig is the 5th space-separated field.
    let sig_b64 = header.rsplit(' ').next().unwrap();
    assert_eq!(sig_b64.len(), SIG_B64_LEN);
    // Body is the original data, byte-exact.
    assert_eq!(&signed[nl + 1..], data);

    // ─── Verify
    let v = verify_blob(&paths, &Signer::Named("alice".into()), &signed).unwrap();
    assert_eq!(v.signer, "alice");
    assert_eq!(v.body, data);
}

/// `Signer::Any` (`*`) — verify against whoever the header says.
/// Uses the `verify_blob` seam (the blob is the testable layer;
/// `verify_cmd` adds stdin-slurp on top, which blocks under test).
#[test]
fn verify_any_signer() {
    let cd = ConfDir::with_name("alice").with_ed25519_key("alice");
    let paths = cd.paths().clone();

    let input = cd.path().join("payload");
    fs::write(&input, b"data").unwrap();
    let mut signed = Vec::new();
    sign(&paths, Some(&input), 1_700_000_000, &mut signed).unwrap();

    // `*` accepts whatever the header says. Header says "alice".
    let v = verify_blob(&paths, &Signer::Any, &signed).unwrap();
    assert_eq!(v.signer, "alice");
    assert_eq!(v.body, b"data");
}

/// `Signer::Named` mismatch → `"Signature is not made by NAME"`.
#[test]
fn verify_signer_mismatch() {
    let cd = ConfDir::with_name("alice").with_ed25519_key("alice");
    let paths = cd.paths().clone();

    let input = cd.path().join("payload");
    fs::write(&input, b"data").unwrap();
    let mut signed = Vec::new();
    sign(&paths, Some(&input), 1_700_000_000, &mut signed).unwrap();

    // We don't have `hosts/bob`, but the signer-mismatch check
    // runs *before* the pubkey load. So we hit the mismatch
    // error, not "no host file".
    let err = verify_blob(&paths, &Signer::Named("bob".into()), &signed).unwrap_err();
    let CmdError::BadInput(msg) = err else {
        panic!("wrong variant")
    };
    assert_eq!(msg, "Signature is not made by bob");
}

/// Tampered body → "Invalid signature". The signature binds the
/// body; flip one byte and the crypto rejects it.
#[test]
fn verify_tampered_body() {
    let cd = ConfDir::with_name("alice").with_ed25519_key("alice");
    let paths = cd.paths().clone();

    let input = cd.path().join("payload");
    fs::write(&input, b"hello").unwrap();
    let mut signed = Vec::new();
    sign(&paths, Some(&input), 1_700_000_000, &mut signed).unwrap();

    // Flip the last byte (in the body, not the header).
    *signed.last_mut().unwrap() ^= 1;

    let err = verify_blob(&paths, &Signer::Any, &signed).unwrap_err();
    let CmdError::BadInput(msg) = err else {
        panic!()
    };
    assert_eq!(msg, "Invalid signature");
}

/// Tampered header time → "Invalid signature". The trailer
/// (reconstructed from the header) is inside the signed message,
/// so changing `t` in the header changes the trailer, which
/// changes the message, which invalidates the sig.
///
/// This is the test that proves the trailer scheme works. Without
/// the trailer, time is unsigned metadata and you could rewrite
/// it freely.
#[test]
fn verify_tampered_time() {
    let cd = ConfDir::with_name("alice").with_ed25519_key("alice");
    let paths = cd.paths().clone();

    let input = cd.path().join("payload");
    fs::write(&input, b"hello").unwrap();
    let mut signed = Vec::new();
    sign(&paths, Some(&input), 1_700_000_000, &mut signed).unwrap();

    // Swap `1700000000` → `1700000001` in the header.
    let s = std::str::from_utf8(&signed).unwrap();
    let tampered = s.replace("1700000000", "1700000001");

    let err = verify_blob(&paths, &Signer::Any, tampered.as_bytes()).unwrap_err();
    let CmdError::BadInput(msg) = err else {
        panic!()
    };
    assert_eq!(msg, "Invalid signature");
}

/// Tampered signer name → also rejected. With `Signer::Any`, the
/// header's name *is* trusted to pick the host file — but the
/// signature was made over the *original* trailer with the
/// *original* name, so changing the name in the header changes
/// the reconstructed trailer, sig fails.
///
/// (You'd also need a `hosts/evilname` file for the verify to
/// even get to the crypto. We test with a name that *does* exist
/// but has a different key — that's the realistic attack.)
#[test]
fn verify_tampered_signer_name() {
    // Two nodes. alice signs; we tamper the header to say bob.
    let cd_alice = ConfDir::with_name("alice").with_ed25519_key("alice");
    let cd_bob = ConfDir::with_name("bob").with_ed25519_key("bob");
    let alice = cd_alice.paths();
    let bob = cd_bob.paths();

    let input = cd_alice.path().join("payload");
    fs::write(&input, b"hello").unwrap();
    let mut signed = Vec::new();
    sign(alice, Some(&input), 1_700_000_000, &mut signed).unwrap();

    // Tamper: header says bob now. We verify from bob's confbase
    // (which has hosts/bob, with bob's real pubkey).
    let s = std::str::from_utf8(&signed).unwrap();
    let tampered = s.replace("= alice ", "= bob ");

    // Bob's confbase. `Signer::Any` so it uses the header's name
    // → looks up hosts/bob → bob's pubkey. Sig was made by alice's
    // key over `... alice 1700000000`. Reconstructed trailer is
    // `... bob 1700000000`. Wrong key AND wrong message. Fails.
    let err = verify_blob(bob, &Signer::Any, tampered.as_bytes()).unwrap_err();
    let CmdError::BadInput(msg) = err else {
        panic!()
    };
    assert_eq!(msg, "Invalid signature");
}

/// **Leading space in trailer is load-bearing.** Prove it: build
/// the signed message *without* the leading space, sign it, verify
/// fails (because `verify_blob` reconstructs the trailer *with*
/// the space). This pins the format.
#[test]
fn trailer_leading_space() {
    let cd = ConfDir::with_name("alice").with_ed25519_key("alice");
    let paths = cd.paths().clone();
    let sk = keypair::read_private(&paths.ed25519_private()).unwrap();

    let body = b"hello";
    // Build a *wrong* signed message (no leading space).
    let mut wrong_msg = Vec::from(&body[..]);
    wrong_msg.extend_from_slice(b"alice 1700000000"); // NO leading space
    let sig = sk.sign(&wrong_msg);
    let sig_b64 = b64::encode(&sig);

    // Assemble the blob: correct header, body. The sig is over
    // the spaceless trailer. Verify reconstructs *with* space →
    // different message → sig fails.
    let blob = format!("Signature = alice 1700000000 {sig_b64}\nhello");
    let err = verify_blob(&paths, &Signer::Any, blob.as_bytes()).unwrap_err();
    let CmdError::BadInput(msg) = err else {
        panic!()
    };
    assert_eq!(msg, "Invalid signature");

    // Contrast: with the space, it works. (This is the same as
    // the roundtrip test but reduced to first principles.)
    let mut right_msg = Vec::from(&body[..]);
    right_msg.extend_from_slice(b" alice 1700000000"); // WITH leading space
    let sig = sk.sign(&right_msg);
    let sig_b64 = b64::encode(&sig);
    let blob = format!("Signature = alice 1700000000 {sig_b64}\nhello");
    let v = verify_blob(&paths, &Signer::Any, blob.as_bytes()).unwrap();
    assert_eq!(v.body, body);
}

/// `signed_message` is the same function for sign and verify.
/// Prove it directly: same inputs, same output. (Tautological for
/// a single fn, but if someone refactors sign/verify to inline
/// the trailer construction separately, this catches drift.)
#[test]
fn signed_message_format() {
    let msg = signed_message(b"data", "alice", 1_700_000_000);
    // Exact bytes. The trailer is ` alice 1700000000` (leading
    // space, no trailing newline).
    assert_eq!(msg, b"data alice 1700000000");

    // Empty body.
    let msg = signed_message(b"", "bob", 1);
    assert_eq!(msg, b" bob 1");

    // Body with no trailing newline (common for hand-typed files).
    // The space separates body from name regardless.
    let msg = signed_message(b"no newline at end", "carol", 999);
    assert_eq!(msg, b"no newline at end carol 999");
}

/// Header parse: malformed → "Invalid input". Not "Invalid
/// signature" — that's reserved for crypto failure. The
/// distinction matters for diagnostics: parse failure means the
/// file isn't a tinc-signed file at all; crypto failure means it
/// *looks* like one but the sig is wrong.
#[test]
fn verify_malformed_header() {
    let cd = ConfDir::with_name("alice").with_ed25519_key("alice");
    let paths = cd.paths().clone();

    for bad in [
        // No newline at all.
        "no newline".as_bytes(),
        // Wrong prefix.
        b"NotSignature = alice 1 xxx\nbody",
        // Missing fields.
        b"Signature = alice 1\nbody",
        // Too many fields.
        b"Signature = alice 1 xxx extra\nbody",
        // Sig wrong length (85 not 86).
        format!("Signature = alice 1 {}\nbody", "x".repeat(85)).as_bytes(),
        // Time zero. `!t` check.
        format!("Signature = alice 0 {}\nbody", "x".repeat(86)).as_bytes(),
        // Time non-numeric.
        format!("Signature = alice notanumber {}\nbody", "x".repeat(86)).as_bytes(),
        // Signer fails check_id (has a dash).
        format!("Signature = bad-name 1 {}\nbody", "x".repeat(86)).as_bytes(),
    ] {
        let err = verify_blob(&paths, &Signer::Any, bad).unwrap_err();
        let CmdError::BadInput(msg) = err else {
            panic!("input {bad:?}: wrong error variant")
        };
        assert_eq!(msg, "Invalid input", "input {bad:?}");
    }
}

/// Header longer than `MAX_HEADER_LEN` → "Invalid input".
#[test]
fn verify_header_too_long() {
    let cd = ConfDir::with_name("alice").with_ed25519_key("alice");
    let paths = cd.paths().clone();

    // 2049-char header (one over the limit).
    let long_header = format!("{}\nbody", "x".repeat(MAX_HEADER_LEN + 1));
    let err = verify_blob(&paths, &Signer::Any, long_header.as_bytes()).unwrap_err();
    let CmdError::BadInput(msg) = err else {
        panic!()
    };
    assert_eq!(msg, "Invalid input");
}

/// `Signer::parse` cases. `.`, `*`, valid name, invalid name.
#[test]
fn signer_parse() {
    let cd = ConfDir::with_name("alice").with_ed25519_key("alice");
    let paths = cd.paths().clone();

    // `.` → own name.
    match Signer::parse(".", &paths).unwrap() {
        Signer::Named(n) => assert_eq!(n, "alice"),
        Signer::Any => panic!(),
    }
    // `*` → Any.
    assert!(matches!(Signer::parse("*", &paths).unwrap(), Signer::Any));
    // Valid name → Named (NOT looked up — that happens at verify
    // time, not parse time).
    match Signer::parse("bob", &paths).unwrap() {
        Signer::Named(n) => assert_eq!(n, "bob"),
        Signer::Any => panic!(),
    }
    // Invalid name (dash) → error.
    assert!(Signer::parse("bad-name", &paths).is_err());
}

/// `load_host_pubkey` PEM fallback. Host file has no
/// `Ed25519PublicKey =` line but does have a PEM block.
#[test]
fn load_host_pubkey_pem_fallback() {
    // Non-standard host file: PEM block, NO config line.
    let sk = keypair::generate();
    let mut priv_pem = Vec::new();
    tinc_conf::pem::write_pem(&mut priv_pem, "ED25519 PRIVATE KEY", &sk.to_blob()).unwrap();
    let mut pub_pem = Vec::new();
    tinc_conf::pem::write_pem(&mut pub_pem, "ED25519 PUBLIC KEY", sk.public_key()).unwrap();
    let cd = ConfDir::with_name("alice").with_host("alice", &String::from_utf8(pub_pem).unwrap());
    fs::write(cd.confbase().join("ed25519_key.priv"), priv_pem).unwrap();
    let paths = cd.paths();

    // Now sign + verify roundtrips through the PEM-fallback path.
    let input = cd.path().join("payload");
    fs::write(&input, b"data").unwrap();
    let mut signed = Vec::new();
    sign(paths, Some(&input), 1_700_000_000, &mut signed).unwrap();
    let v = verify_blob(paths, &Signer::Any, &signed).unwrap();
    assert_eq!(v.body, b"data");
}

/// `load_host_pubkey` neither-form → error.
#[test]
fn load_host_pubkey_no_key() {
    // Host file with no key at all. Just an Address.
    let cd = ConfDir::bare().with_host("alice", "Address = 1.2.3.4\n");
    let err = load_host_pubkey(&cd.confbase().join("hosts/alice")).unwrap_err();
    let CmdError::BadInput(msg) = err else {
        panic!()
    };
    assert!(msg.contains("Could not read public key from"));
    assert!(msg.contains("hosts/alice"));
}

/// Binary body (NUL bytes, high bytes). The body is `&[u8]`, not
/// `&str` — sign/verify should be byte-transparent. The header is
/// text but the body isn't.
#[test]
fn binary_body_roundtrip() {
    let cd = ConfDir::with_name("alice").with_ed25519_key("alice");
    let paths = cd.paths().clone();

    // All 256 byte values, including NUL.
    let data: Vec<u8> = (0u8..=255).collect();
    let input = cd.path().join("payload");
    fs::write(&input, &data).unwrap();

    let mut signed = Vec::new();
    sign(&paths, Some(&input), 1_700_000_000, &mut signed).unwrap();
    let v = verify_blob(&paths, &Signer::Any, &signed).unwrap();
    assert_eq!(v.body, data);
}

/// **Golden vector from upstream's test suite.** `test/integration/
/// cmd_sign_verify.py` has a blob produced with a fixed key and
/// fixed time `1653397516`. If `verify_blob` accepts it, the
/// format is byte-compatible. The artifact IS the test — no
/// upstream binary needed.
///
/// This proves, simultaneously:
/// - The trailer format (` foo 1653397516`, leading space) matches
/// - The header parse accepts what upstream emits
/// - tinc-b64 encoding matches (sig decodes to 64 bytes)
/// - The Ed25519 verify matches (`tinc-crypto::sign::verify`)
/// - `load_host_pubkey` parses the `Ed25519PublicKey =` line
///
/// If any one of those is wrong, this test fails.
#[test]
fn golden_upstream_vector() {
    // Transcribed from `test/integration/cmd_sign_verify.py:12-29`.
    // The PEM has leading/trailing newlines in the Python (it's a
    // triple-quoted string starting with `\n`); read_pem skips
    // pre-BEGIN lines so they're harmless. Transcribed exactly to
    // make `diff cmd_sign_verify.py cmd/sign.rs` line up.
    const PRIV_KEY: &str = "\
-----BEGIN ED25519 PRIVATE KEY-----
4Q8bJqfN60s0tOiZdAhAWLgB9+o947cta2WMXmQIz8mCdBdcphzhp23Wt2vUzfQ6
XHt9+5IqidIw/lLXG61Nbc6IZ+4Fy1XOO1uJ6j4hqIKjdSytD2Vb7MPlNJfPdCDu
-----END ED25519 PRIVATE KEY-----
";

    // Host file: pubkey config line + a `Port` line (which we
    // ignore — proves `load_host_pubkey` doesn't choke on extra
    // config).
    const HOST: &str = "\
Ed25519PublicKey = nOSmPehc9ljTtbi+IeoKiyYnkc7gd12OzTZTy3TnwgL
Port = 17879
";

    // The signed blob. The Python's `\n` line-continuation joins
    // adjacent strings; the embedded `\n` are literal. Body is
    // `fake testing data\nhello there\n`. Transcribed byte-exact.
    const SIGNED: &[u8] = b"Signature = foo 1653397516 \
T8Bjg7dc7IjsCrZQC/20qLRsWPlrbthnjyDHQM0BMLoTeAHbLt0fxP5CbTy7Cifgg7P0K179GeahBFsnaIr4MA\n\
fake testing data\n\
hello there\n";

    // Expected body (header stripped).
    const BODY: &[u8] = b"fake testing data\nhello there\n";

    // ─── Set up confbase exactly as the Python does
    let cd = ConfDir::with_name("foo").with_host("foo", HOST);
    fs::write(cd.confbase().join("ed25519_key.priv"), PRIV_KEY).unwrap();
    let paths = cd.paths().clone();

    // ─── Verify the upstream-signed blob
    // The Python tests `.` and `foo` and `*`. We do all three.
    // If ANY of them fails, format compat is broken.
    for signer in [
        Signer::Named("foo".into()),
        Signer::Any,
        // `.` resolves to `foo` via tinc.conf above.
        Signer::parse(".", &paths).unwrap(),
    ] {
        let v = verify_blob(&paths, &signer, SIGNED)
            .unwrap_or_else(|e| panic!("signer {signer:?}: {e}"));
        assert_eq!(v.signer, "foo");
        assert_eq!(v.body, BODY);
    }

    // ─── Re-sign and confirm round-trip
    // Ed25519 is deterministic given key+message. Same key, same
    // body, same time, same trailer → same sig. Prove it.
    let body_file = cd.path().join("body");
    fs::write(&body_file, BODY).unwrap();
    let mut resigned = Vec::new();
    sign(&paths, Some(&body_file), 1_653_397_516, &mut resigned).unwrap();

    // **Byte-identical to upstream's output.** This is the
    // strongest possible compat statement: not just "our verify
    // accepts upstream's sign", but "our sign IS upstream's sign".
    assert_eq!(resigned, SIGNED, "Rust sign output != upstream sign output");
}

/// Empty body. Degenerate but valid — you can sign nothing.
#[test]
fn empty_body_roundtrip() {
    let cd = ConfDir::with_name("alice").with_ed25519_key("alice");
    let paths = cd.paths().clone();

    let input = cd.path().join("payload");
    fs::write(&input, b"").unwrap();

    let mut signed = Vec::new();
    sign(&paths, Some(&input), 1_700_000_000, &mut signed).unwrap();
    // Signed output is exactly the header line + nothing.
    let nl = signed.iter().position(|&b| b == b'\n').unwrap();
    assert_eq!(nl + 1, signed.len()); // \n is the last byte

    let v = verify_blob(&paths, &Signer::Any, &signed).unwrap();
    assert_eq!(v.body, b"");
}
