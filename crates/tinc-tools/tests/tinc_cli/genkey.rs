use super::Conf;

/// The old key is `#`-commented in both files and a fresh one
/// appended.
#[test]
fn generate_keys_rotates() {
    let conf = Conf::init("alice");
    let private_before = conf.read("ed25519_key.priv");
    let host_before = conf.read("hosts/alice");

    let run = conf.tinc(&["generate-ed25519-keys"]);
    assert!(
        run.stderr.contains("Generating Ed25519 key pair"),
        "{}",
        run.stderr
    );
    run.succeeds();

    let private_after = conf.read("ed25519_key.priv");
    for line in private_before.lines() {
        assert!(
            private_after.contains(&format!("#{line}\n")),
            "{private_after}"
        );
    }
    assert_eq!(private_after.matches("-----BEGIN ED25519").count(), 2);
    assert_eq!(
        private_after.matches("\n-----BEGIN ").count(),
        1,
        "one live block"
    );

    let host_after = conf.read("hosts/alice");
    assert_eq!(host_after.matches("#Ed25519PublicKey").count(), 1);
    let live: Vec<&str> = host_after
        .lines()
        .filter(|line| line.starts_with("Ed25519PublicKey"))
        .collect();
    assert_eq!(live.len(), 1);
    assert!(!host_before.contains(live[0]), "key did not change");
}

/// C falls back to writing `ed25519_key.pub`; we require tinc.conf.
#[test]
fn generate_keys_needs_tinc_conf() {
    Conf::bare()
        .tinc(&["generate-ed25519-keys"])
        .fails_with("tinc.conf");
}
