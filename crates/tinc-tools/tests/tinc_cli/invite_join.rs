//! `invite` end to end; `join` only up to the points that fail before
//! a TCP connection (the SPTPS exchange is unit-tested in-process).

use super::Conf;
use tinc_crypto::invite::{SLUG_LEN, SLUG_PART_LEN, parse_slug};

fn with_address(name: &str) -> Conf {
    let conf = Conf::init(name);
    let host = conf.read(&format!("hosts/{name}"));
    conf.write(
        &format!("hosts/{name}"),
        &format!("{host}Address = invite-test.example\n"),
    );
    conf
}

/// URL alone on stdout, the restart hint on stderr, and the
/// invitation key must not upset fsck.
#[test]
fn invite_prints_url() {
    let conf = with_address("alice");
    let run = conf.tinc(&["invite", "bob"]);
    assert!(run.stderr.contains("restart or reload"), "{}", run.stderr);
    let stdout = run.succeeds();
    assert_eq!(stdout.lines().count(), 1, "{stdout:?}");
    let slug = stdout
        .trim()
        .strip_prefix("invite-test.example:655/")
        .unwrap_or_else(|| panic!("{stdout}"));
    assert_eq!(slug.len(), SLUG_LEN);
    assert!(parse_slug(slug).is_some());

    let fsck = conf.tinc(&["fsck"]);
    assert_eq!(fsck.stderr, "");
    fsck.succeeds();
}

/// Checked before anything is created (C leaves an empty
/// `invitations/` behind).
#[test]
fn invite_without_address() {
    let conf = Conf::init("alice");
    let stderr = conf.tinc(&["invite", "bob"]).fails_with("No Address");
    assert!(stderr.contains("add Address"), "{stderr}");
    assert!(!conf.base().join("invitations").exists());
}

/// `-n` alongside `-c` still sets the netname global, which ends up
/// as `NetName =` in the invitation file (the 24-character file; the
/// other one is the key).
#[test]
fn invite_records_netname() {
    let conf = with_address("alice");
    conf.tinc(&["-n", "mymesh", "invite", "bob"]).succeeds();
    let invitation = std::fs::read_dir(conf.base().join("invitations"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.file_name().unwrap().len() == SLUG_PART_LEN)
        .unwrap();
    let body = std::fs::read_to_string(invitation).unwrap();
    assert!(body.contains("NetName = mymesh\n"), "{body}");
}

#[test]
fn invite_needs_name() {
    Conf::bare().tinc(&["invite"]).fails_with("node name");
}

/// From argv or stdin; C's message so existing docs apply.
#[test]
fn join_rejects_bad_url() {
    let conf = Conf::bare();
    conf.tinc(&["join", "not-a-url"])
        .fails_with("Invalid invitation URL");
    conf.tinc_stdin(&["join"], b"garbage-url\n")
        .fails_with("Invalid invitation URL");
}

/// An existing tinc.conf is detected before connecting, so the
/// single-use cookie is not burned. Port 1 would refuse quickly if
/// the check did not fire.
#[test]
fn join_with_existing_config_fails_before_connect() {
    let url = format!("127.0.0.1:1/{}", "a".repeat(SLUG_LEN));
    let stderr = Conf::init("alice")
        .tinc(&["join", &url])
        .fails_with("already exists");
    assert!(!stderr.contains("connect"), "{stderr}");
}
