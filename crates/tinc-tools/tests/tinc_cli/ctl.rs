//! Pidfile → `kill(pid, 0)` → unix socket → greeting → request, through
//! the binary with real paths. The unit tests use `UnixStream::pair()`
//! and skip the filesystem half.

use super::{Conf, tinc};
use std::fs;

#[test]
fn pidfile_missing() {
    let stderr = Conf::bare()
        .tinc(&["pid"])
        .fails_with("Could not open pid file");
    assert!(stderr.contains("tinc.pid"), "{stderr}");
}

#[test]
fn pidfile_malformed() {
    let conf = Conf::bare();
    fs::write(conf.pidfile(), "1234 toolittle\n").unwrap();
    conf.tinc(&["reload"])
        .fails_with("Could not parse pid file");
}

/// Arity and `check_id` run before anything touches the pidfile.
#[test]
fn disconnect_validates_before_connecting() {
    let conf = Conf::bare();
    conf.tinc(&["disconnect"]).fails_with("No node name given");
    let stderr = tinc(&[
        "-c",
        &conf.arg(),
        "--pidfile",
        "/nonexistent/pid",
        "disconnect",
        "bad/name",
    ])
    .fails_with("Invalid name");
    assert!(!stderr.contains("pid file"), "{stderr}");
}

/// `tinc pid` prints the pid from greeting line 2, not the pidfile's
/// (which is only used for the liveness probe).
#[test]
fn pid_comes_from_greeting() {
    let conf = Conf::bare();
    let daemon = conf.serve(|_| {});
    assert_eq!(conf.tinc(&["pid"]).succeeds().trim(), "1");
    daemon.finish();
}

#[test]
fn reload_round_trip() {
    let conf = Conf::bare();
    let daemon = conf.serve(|ctl| {
        ctl.expect("18 1");
        ctl.send("18 1 0");
    });
    assert_eq!(conf.tinc(&["reload"]).succeeds(), "");
    daemon.finish();
}

#[test]
fn reload_reports_daemon_error() {
    let conf = Conf::bare();
    let daemon = conf.serve(|ctl| {
        ctl.expect("18 1");
        ctl.send("18 1 1");
    });
    conf.tinc(&["reload"]).fails();
    daemon.finish();
}
