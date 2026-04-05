use super::{bare_dir, init_dir, tinc};

/// `tinc init` then `tinc generate-ed25519-keys`. Basic plumbing:
/// the new key is live, the old one is `#`-commented in both files.
#[test]
fn genkey_after_init() {
    let (_dir, confbase, cb) = init_dir("alice");

    // Snapshot pre-rotation.
    let priv_before = std::fs::read_to_string(confbase.join("ed25519_key.priv")).unwrap();
    let host_before = std::fs::read_to_string(confbase.join("hosts/alice")).unwrap();
    assert!(!priv_before.contains('#'), "init writes a clean PEM");
    assert!(!host_before.contains('#'));

    // Rotate.
    let out = tinc(&["-c", &cb, "generate-ed25519-keys"]);
    assert!(out.status.success(), "{out:?}");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("Generating Ed25519 key pair"));
    assert!(stderr.contains("Done."));

    // ─── private key file: one #-block, one live block ──────────
    let priv_after = std::fs::read_to_string(confbase.join("ed25519_key.priv")).unwrap();
    // The old block is the first half, #-prefixed. Check by rough
    // shape: every line that was in priv_before is in priv_after
    // with `#` prepended.
    for line in priv_before.lines() {
        assert!(
            priv_after.contains(&format!("#{line}\n")),
            "old line {line:?} not commented in {priv_after:?}"
        );
    }
    // Exactly one live BEGIN (no leading #).
    assert_eq!(priv_after.matches("\n-----BEGIN ").count(), 1);
    // Two BEGINs total (one #, one live). The first one starts the
    // file (no preceding \n), so count both forms.
    let total_begins = priv_after.matches("-----BEGIN ED25519").count();
    assert_eq!(total_begins, 2);

    // ─── host file: one #Ed25519PublicKey, one live one ─────────
    let host_after = std::fs::read_to_string(confbase.join("hosts/alice")).unwrap();
    assert_eq!(host_after.matches("#Ed25519PublicKey").count(), 1);
    // Live line: starts at beginning-of-line with no #.
    let live_count = host_after
        .lines()
        .filter(|l| l.starts_with("Ed25519PublicKey"))
        .count();
    assert_eq!(live_count, 1);
    // The live one is *different* from the old one. (Tests that
    // genkey actually generates fresh entropy, not... I don't know,
    // re-reads and re-appends. Paranoia.)
    let new_b64 = host_after
        .lines()
        .find(|l| l.starts_with("Ed25519PublicKey"))
        .unwrap();
    assert!(!host_before.contains(new_b64));
}

/// genkey without init → fails (no tinc.conf, can't `get_my_name`).
/// The C falls back to `ed25519_key.pub` PEM in this case; we don't.
/// See `cmd/genkey.rs` module doc.
#[test]
fn genkey_no_config() {
    let (_dir, cb) = bare_dir();
    let out = tinc(&["-c", &cb, "generate-ed25519-keys"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("tinc.conf"));
}
