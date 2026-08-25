//! Exit code and severity prefixes; the findings themselves are
//! unit-tested.

use super::{Conf, tinc};

#[test]
fn clean_init_is_silent() {
    let run = Conf::init("alice").tinc(&["fsck"]);
    assert_eq!(run.stderr, "");
    run.succeeds();
}

/// The suggestion includes the `-c` prefix the user needs.
#[test]
fn missing_confbase_suggests_init() {
    let dir = tempfile::tempdir().unwrap();
    let confbase = dir.path().join("nope");
    let confbase = confbase.to_str().unwrap();
    let stderr = tinc(&["-c", confbase, "fsck"]).fails_with("ERROR:");
    assert!(stderr.contains("init"), "{stderr}");
    assert!(stderr.contains(confbase), "{stderr}");
}

/// A host-only variable in tinc.conf is a warning; warnings exit 0.
#[test]
fn warning_exits_zero() {
    let conf = Conf::init("alice");
    conf.write("tinc.conf", "Name = alice\nPort = 655\n");
    let run = conf.tinc(&["fsck"]);
    assert!(run.stderr.contains("WARNING:"), "{}", run.stderr);
    assert!(run.stderr.contains("Port"), "{}", run.stderr);
    run.succeeds();
}

/// Missing public key: error without `--force`, fixed with it, clean
/// afterwards.
#[test]
fn force_fixes_missing_public_key() {
    let conf = Conf::init("alice");
    conf.write("hosts/alice", "Subnet = 10.0.0.0/24\n");
    conf.tinc(&["fsck"]).fails_with("public Ed25519");

    let run = conf.tinc(&["--force", "fsck"]);
    assert!(run.stderr.contains("Wrote Ed25519"), "{}", run.stderr);
    run.succeeds();
    assert!(
        conf.read("hosts/alice")
            .contains("-----BEGIN ED25519 PUBLIC KEY-----")
    );
    conf.tinc(&["fsck"]).succeeds();
}
