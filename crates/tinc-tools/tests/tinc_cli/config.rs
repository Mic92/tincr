//! `tinc get/set/add/del` and the `config` umbrella verb.

use super::Conf;

#[test]
fn get_name() {
    let conf = Conf::init("alice");
    assert_eq!(conf.tinc(&["get", "Name"]).succeeds().trim(), "alice");
    assert_eq!(conf.tinc(&["config", "Name"]).succeeds().trim(), "alice");
}

/// `ConnectTo` is MULTIPLE: `add` appends, it must not behave like
/// `set` and replace the first value. `del` without a value removes
/// all of them.
#[test]
fn add_appends_del_removes_all() {
    let conf = Conf::init("alice");
    conf.tinc(&["add", "ConnectTo", "bob"]).succeeds();
    conf.tinc(&["add", "ConnectTo", "carol"]).succeeds();
    assert_eq!(conf.tinc(&["get", "ConnectTo"]).succeeds(), "bob\ncarol\n");
    conf.tinc(&["del", "ConnectTo"]).succeeds();
    conf.tinc(&["get", "ConnectTo"]).fails();
}

#[test]
fn set_unknown_variable_needs_force() {
    let stderr = Conf::init("alice")
        .tinc(&["set", "NoSuchVar", "x"])
        .fails_with("not a known configuration variable");
    assert!(stderr.contains("--force"), "{stderr}");
}

/// Only available under `config`.
#[test]
fn config_replace_is_set() {
    let conf = Conf::init("alice");
    conf.tinc(&["config", "replace", "Device", "/dev/tun"])
        .succeeds();
    assert_eq!(conf.tinc(&["get", "Device"]).succeeds().trim(), "/dev/tun");
}

#[test]
fn edits_pass_fsck() {
    let conf = Conf::init("alice");
    conf.tinc(&["add", "Subnet", "10.0.0.0/24"]).succeeds();
    conf.tinc(&["set", "Device", "/dev/tun"]).succeeds();
    conf.tinc(&["add", "ConnectTo", "bob"]).succeeds();
    let run = conf.tinc(&["fsck"]);
    assert_eq!(run.stderr, "");
    run.succeeds();
}

/// After writing, `set` asks a running daemon to reload; with none
/// running that is silently skipped.
#[test]
fn set_reloads_daemon_if_running() {
    let conf = Conf::init("alice");
    let run = conf.tinc(&["set", "Device", "/dev/tun"]);
    assert!(!run.stderr.contains("pid"), "{}", run.stderr);
    run.succeeds();

    let daemon = conf.serve(|ctl| {
        ctl.expect("18 1");
        ctl.send("18 1 0");
    });
    conf.tinc(&["set", "Device", "/dev/tap"]).succeeds();
    daemon.finish();
    assert!(conf.read("tinc.conf").contains("Device = /dev/tap\n"));
}
