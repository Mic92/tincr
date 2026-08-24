use super::{Conf, tinc, tinc_stdin};

/// File contents and modes are unit-tested; here only that the binary
/// dispatched (case-insensitively, like C) and kept stdout clean.
#[test]
fn init_creates_confbase() {
    let conf = Conf::bare();
    let run = conf.tinc(&["INIT", "alice"]);
    assert!(run.stderr.contains("Generating Ed25519"), "{}", run.stderr);
    assert_eq!(run.ok(), "");
    assert_eq!(conf.read("tinc.conf"), "Name = alice\n");
    assert!(conf.host("alice").exists());
    assert!(conf.base().join("ed25519_key.priv").exists());
}

/// systemd unit files use the glued form.
#[test]
fn init_glued_config_option() {
    let conf = Conf::bare();
    tinc(&[&format!("--config={}", conf.arg()), "init", "bob"]).ok();
    assert_eq!(conf.read("tinc.conf"), "Name = bob\n");
}

/// C reads the name from a non-tty stdin; scripts rely on it. An
/// empty pipe is still an error, with usage.
#[test]
fn init_name_from_stdin() {
    let conf = Conf::bare();
    let stderr = tinc_stdin(&["-c", &conf.arg(), "init"], b"").fails_with("No Name given");
    assert!(stderr.contains("Usage: tinc init NAME"), "{stderr}");
    assert!(!conf.base().join("tinc.conf").exists());

    tinc_stdin(&["-c", &conf.arg(), "init"], b"alice\n").ok();
    assert_eq!(conf.read("tinc.conf"), "Name = alice\n");
}
