use super::{init_dir, tinc};
use std::io::Write;

/// `init` then `fsck` → exit 0, no output. The binary contract test.
/// Unit-test `clean_init_passes` proves the Report is empty; this
/// proves "empty Report → exit 0, silent".
#[test]
fn fsck_clean() {
    let (_dir, _confbase, cb) = init_dir("alice");

    let out = tinc(&["-c", &cb, "fsck"]);
    assert!(out.status.success(), "fsck failed on clean init: {out:?}");
    // Silent on success. The C is too — fsck's `fprintf`s are all
    // diagnostic, no "everything OK" message. Unix philosophy.
    assert!(out.stderr.is_empty(), "unexpected output: {out:?}");
}

/// `fsck` on a nonexistent confbase → exit 1, ERROR: prefix,
/// `init` suggestion. The binary's stderr-formatting path.
#[test]
fn fsck_no_config() {
    let dir = tempfile::tempdir().unwrap();
    let cb = dir.path().join("nope");
    let cb_s = cb.to_str().unwrap();
    // Don't create it.

    let out = tinc(&["-c", cb_s, "fsck"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    // The ERROR: prefix from the binary's severity formatting.
    assert!(stderr.contains("ERROR:"), "stderr was: {stderr}");
    // The suggestion from Finding::suggestion(). The cmd_prefix
    // includes `-c <confbase>` — spot-check it's threaded.
    assert!(stderr.contains("init"), "stderr was: {stderr}");
    assert!(stderr.contains(cb_s), "stderr was: {stderr}");
}

/// `fsck` finds a warning → exit 0, WARNING: prefix. Warnings don't
/// fail fsck. C: `check_conffile` is `void`, doesn't contribute to
/// `success`.
#[test]
fn fsck_warning_exits_zero() {
    let (_dir, confbase, cb) = init_dir("alice");

    // Append a host-only var to tinc.conf. Triggers `HostVarInServer`.
    let mut tc = std::fs::OpenOptions::new()
        .append(true)
        .open(confbase.join("tinc.conf"))
        .unwrap();
    writeln!(tc, "Port = 655").unwrap();
    drop(tc);

    let out = tinc(&["-c", &cb, "fsck"]);
    // Warning, not error → exit 0.
    assert!(out.status.success(), "{out:?}");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("WARNING:"), "stderr was: {stderr}");
    assert!(stderr.contains("Port"), "stderr was: {stderr}");
}

/// `--force` reaches fsck. Break the config (mismatched key), `fsck`
/// alone fails, `fsck --force` fixes and succeeds. Then `fsck` alone
/// succeeds. **Contract test through the binary**: --force → fix →
/// idempotent.
#[test]
fn fsck_force_fixes() {
    let (_dir, confbase, cb) = init_dir("alice");

    // Clobber hosts/alice with no pubkey. (Can't use a *wrong*
    // pubkey easily — we'd need a valid-b64-but-different value,
    // and generating one in a shell test is fiddly. "No key" hits
    // the same fix path: `fix_public_key`.)
    std::fs::write(confbase.join("hosts/alice"), "Subnet = 10.0.0.0/24\n").unwrap();

    // Without --force: fail.
    let out = tinc(&["-c", &cb, "fsck"]);
    assert!(!out.status.success(), "expected failure: {out:?}");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("WARNING:"), "stderr was: {stderr}");
    assert!(stderr.contains("public Ed25519"), "stderr was: {stderr}");

    // With --force: succeed, fix message printed.
    let out = tinc(&["--force", "-c", &cb, "fsck"]);
    assert!(out.status.success(), "--force should fix: {out:?}");
    let stderr = String::from_utf8(out.stderr).unwrap();
    // The Info-severity fix message (no prefix in the format, but
    // the message says "Wrote").
    assert!(stderr.contains("Wrote Ed25519"), "stderr was: {stderr}");

    // Verify the file was actually fixed: PEM block now present.
    let host = std::fs::read_to_string(confbase.join("hosts/alice")).unwrap();
    assert!(host.contains("-----BEGIN ED25519 PUBLIC KEY-----"));

    // And fsck without --force is now clean.
    let out = tinc(&["-c", &cb, "fsck"]);
    assert!(out.status.success(), "post-fix fsck failed: {out:?}");
}
