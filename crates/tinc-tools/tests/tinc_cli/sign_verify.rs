use super::{bare_dir, init_dir, tinc, tinc_stdin};

/// **The contract test for sign/verify.** init → sign → verify, all
/// through the binary. `verify .` (`.` = own name) on a sign output
/// emits the original body byte-exact to stdout.
#[test]
fn sign_verify_roundtrip_binary() {
    let (dir, _confbase, cb) = init_dir("alice");

    let payload = dir.path().join("payload");
    let data = b"hello world\nbinary: \x00\xff\n";
    std::fs::write(&payload, data).unwrap();

    // ─── sign ───────────────────────────────────────────────────────
    let out = tinc(&["-c", &cb, "sign", payload.to_str().unwrap()]);
    assert!(out.status.success(), "{out:?}");
    let signed = out.stdout;

    // Header shape. First line, `Signature = alice <time> <86b64>`.
    // Time is non-deterministic (`SystemTime::now()`); just check
    // structure.
    let nl = signed.iter().position(|&b| b == b'\n').unwrap();
    let header = std::str::from_utf8(&signed[..nl]).unwrap();
    let mut fields = header.split(' ');
    assert_eq!(fields.next(), Some("Signature"));
    assert_eq!(fields.next(), Some("="));
    assert_eq!(fields.next(), Some("alice"));
    let t: i64 = fields.next().unwrap().parse().unwrap();
    assert!(t > 1_700_000_000); // sanity: signed after Nov 2023
    assert_eq!(fields.next().unwrap().len(), 86);
    assert!(fields.next().is_none());

    // Body is the original, byte-exact.
    assert_eq!(&signed[nl + 1..], data);

    // ─── verify (file arg) ──────────────────────────────────────────
    let signed_path = dir.path().join("signed");
    std::fs::write(&signed_path, &signed).unwrap();
    let out = tinc(&["-c", &cb, "verify", ".", signed_path.to_str().unwrap()]);
    assert!(out.status.success(), "{out:?}");
    // stdout is the body, byte-exact.
    assert_eq!(out.stdout, data);

    // ─── verify (stdin) ─────────────────────────────────────────────
    let out = tinc_stdin(&["-c", &cb, "verify", "."], &signed);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(out.stdout, data);

    // ─── verify with `*` (any signer) ───────────────────────────────
    let out = tinc_stdin(&["-c", &cb, "verify", "*"], &signed);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(out.stdout, data);

    // ─── verify with explicit name ──────────────────────────────────
    let out = tinc_stdin(&["-c", &cb, "verify", "alice"], &signed);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(out.stdout, data);

    // ─── verify with WRONG name → fail ─────────────────────────────
    let out = tinc_stdin(&["-c", &cb, "verify", "bob"], &signed);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("Signature is not made by bob"));
    // No body output on failure.
    assert!(out.stdout.is_empty());
}

/// sign reads stdin when no file arg. Then verify reads stdin too.
/// `tinc sign | tinc verify .` is the canonical pipeline.
#[test]
fn sign_stdin_verify_stdin() {
    let (_dir, _confbase, cb) = init_dir("alice");

    let data = b"stdin data\n";
    let signed = tinc_stdin(&["-c", &cb, "sign"], data);
    assert!(signed.status.success(), "{signed:?}");

    let verified = tinc_stdin(&["-c", &cb, "verify", "."], &signed.stdout);
    assert!(verified.status.success(), "{verified:?}");
    assert_eq!(verified.stdout, data);
}

/// verify with no signer arg → "No signer given!" (MissingArg).
#[test]
fn verify_no_signer_arg() {
    let (_dir, cb) = bare_dir();
    let out = tinc(&["-c", &cb, "verify"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("No signer given"));
}

/// sign without init → fails (no tinc.conf).
#[test]
fn sign_no_config() {
    let (_dir, cb) = bare_dir();
    let out = tinc(&["-c", &cb, "sign"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("tinc.conf"));
}

/// **Cross-node verify.** alice signs, bob verifies (with
/// `hosts/alice` in bob's confbase). This is the actual deployment
/// pattern: sign on one machine, ship the signed file, verify on
/// another. Uses `*` signer mode (bob doesn't know in advance who
/// signed it; trusts hosts/ as keyring).
#[test]
fn sign_verify_cross_node() {
    let dir = tempfile::tempdir().unwrap();
    let alice_base = dir.path().join("alice");
    let bob_base = dir.path().join("bob");

    let out = tinc(&["-c", alice_base.to_str().unwrap(), "init", "alice"]);
    assert!(out.status.success());
    let out = tinc(&["-c", bob_base.to_str().unwrap(), "init", "bob"]);
    assert!(out.status.success());

    // Ship alice's host file to bob (this is what export|import does;
    // here we just copy).
    std::fs::copy(alice_base.join("hosts/alice"), bob_base.join("hosts/alice")).unwrap();

    // alice signs.
    let data = b"cross-node payload";
    let signed = tinc_stdin(&["-c", alice_base.to_str().unwrap(), "sign"], data);
    assert!(signed.status.success());

    // bob verifies with `*`.
    let out = tinc_stdin(
        &["-c", bob_base.to_str().unwrap(), "verify", "*"],
        &signed.stdout,
    );
    assert!(out.status.success(), "{out:?}");
    assert_eq!(out.stdout, data);

    // bob verifies with explicit `alice` (he knows who should have
    // signed it).
    let out = tinc_stdin(
        &["-c", bob_base.to_str().unwrap(), "verify", "alice"],
        &signed.stdout,
    );
    assert!(out.status.success(), "{out:?}");
    assert_eq!(out.stdout, data);
}
