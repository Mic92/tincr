use super::tinc;

/// Helper: init a confbase, return its dir + a --pidfile pointing
/// at nothing (so the post-edit reload silently fails).
fn config_init(name: &str) -> (tempfile::TempDir, String, String) {
    let dir = tempfile::tempdir().unwrap();
    let cb = dir.path().join("vpn");
    let cb_s = cb.to_str().unwrap().to_owned();
    let pidfile = dir.path().join("nope.pid");
    let pidfile_s = pidfile.to_str().unwrap().to_owned();

    let out = tinc(&["-c", &cb_s, "init", name]);
    assert!(out.status.success(), "{:?}", out.stderr);
    (dir, cb_s, pidfile_s)
}

#[test]
fn config_get_name() {
    let (_d, cb, pf) = config_init("alice");
    // `tinc get Name` reads tinc.conf (Name is SERVER-only).
    let out = tinc(&["-c", &cb, "--pidfile", &pf, "get", "Name"]);
    assert!(out.status.success());
    assert_eq!(String::from_utf8(out.stdout).unwrap().trim(), "alice");
}

/// THE regression: `tinc add ConnectTo bob` then `tinc add ConnectTo
/// carol` must result in TWO ConnectTo lines. ConnectTo is MULTIPLE.
/// The buggy single-adapter would route both adds to SET, and the
/// second one would delete the first.
#[test]
fn config_add_is_not_set() {
    let (_d, cb, pf) = config_init("alice");

    let out = tinc(&["-c", &cb, "--pidfile", &pf, "add", "ConnectTo", "bob"]);
    assert!(out.status.success(), "{:?}", out.stderr);
    let out = tinc(&["-c", &cb, "--pidfile", &pf, "add", "ConnectTo", "carol"]);
    assert!(out.status.success(), "{:?}", out.stderr);

    // BOTH must survive. If add routed to set, only carol would.
    let out = tinc(&["-c", &cb, "--pidfile", &pf, "get", "ConnectTo"]);
    let stdout = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines,
        vec!["bob", "carol"],
        "add→set bug: only one survived"
    );
}

/// `tinc del ConnectTo` (no value) deletes all. Proves the `del`
/// argv → Action::Del dispatch (the filtered-del *logic* is unit-
/// covered in `config.rs::del_filtered`).
#[test]
fn config_del_all() {
    let (_d, cb, pf) = config_init("alice");
    tinc(&["-c", &cb, "--pidfile", &pf, "add", "ConnectTo", "bob"]);
    tinc(&["-c", &cb, "--pidfile", &pf, "add", "ConnectTo", "carol"]);

    let out = tinc(&["-c", &cb, "--pidfile", &pf, "del", "ConnectTo"]);
    assert!(out.status.success());

    // get now fails (no matches).
    let out = tinc(&["-c", &cb, "--pidfile", &pf, "get", "ConnectTo"]);
    assert!(!out.status.success());
}

/// Unknown var without --force → exit 1, helpful message.
#[test]
fn config_unknown_var() {
    let (_d, cb, pf) = config_init("alice");
    let out = tinc(&["-c", &cb, "--pidfile", &pf, "set", "NoSuchVar", "x"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("not a known configuration variable"));
    assert!(stderr.contains("--force"));
}

/// `tinc config Name` (no verb) → default GET. Also proves the
/// `config` umbrella verb dispatches at all.
#[test]
fn config_umbrella_default_get() {
    let (_d, cb, pf) = config_init("alice");
    let out = tinc(&["-c", &cb, "--pidfile", &pf, "config", "Name"]);
    assert!(out.status.success());
    assert_eq!(String::from_utf8(out.stdout).unwrap().trim(), "alice");
}

/// `tinc config replace` is an alias for set. Only available under
/// `config`, not as toplevel.
#[test]
fn config_replace_alias() {
    let (_d, cb, pf) = config_init("alice");
    let out = tinc(&[
        "-c",
        &cb,
        "--pidfile",
        &pf,
        "config",
        "replace",
        "Device",
        "/dev/tun",
    ]);
    assert!(out.status.success(), "{:?}", out.stderr);
    let out = tinc(&["-c", &cb, "--pidfile", &pf, "get", "Device"]);
    assert_eq!(String::from_utf8(out.stdout).unwrap().trim(), "/dev/tun");
}

/// fsck approves of what set wrote. Contract test — same as
/// `invite_join_roundtrip`'s closing fsck. If `set` ever writes
/// something fsck flags (bad var, mangled PEM), this fires.
#[test]
fn config_set_survives_fsck() {
    let (_d, cb, pf) = config_init("alice");
    tinc(&["-c", &cb, "--pidfile", &pf, "add", "Subnet", "10.0.0.0/24"]);
    tinc(&["-c", &cb, "--pidfile", &pf, "set", "Device", "/dev/tun"]);
    tinc(&["-c", &cb, "--pidfile", &pf, "add", "ConnectTo", "bob"]);

    let out = tinc(&["-c", &cb, "fsck"]);
    assert!(out.status.success(), "{:?}", out.stderr);
}

/// Post-edit opportunistic reload: real fake daemon receives the
/// REQ_RELOAD. Same harness as `ctl_reload_against_fake_daemon`
/// but the reload is triggered by `tinc set`, not `tinc reload`.
///
/// Proves the `let _ = ctl_simple::reload(paths)` line in the binary
/// actually fires and sends the right wire bytes.
#[test]
#[cfg(unix)]
fn config_set_fires_reload() {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;

    // Init a real confbase. We need the file walk to succeed.
    let dir = tempfile::tempdir().unwrap();
    let cb = dir.path().join("vpn");
    let cb_s = cb.to_str().unwrap();
    let out = tinc(&["-c", cb_s, "init", "alice"]);
    assert!(out.status.success());

    // Pidfile + listening socket. Our pid (kill(0) succeeds).
    let pidfile = dir.path().join("tinc.pid");
    let sock = dir.path().join("tinc.socket");
    let cookie = "abcd".repeat(16);
    let our_pid = std::process::id();
    std::fs::write(&pidfile, format!("{our_pid} {cookie} 127.0.0.1 port 655\n")).unwrap();

    let listener = UnixListener::bind(&sock).unwrap();
    let cookie_thr = cookie.clone();
    let daemon = std::thread::spawn(move || -> bool {
        let (stream, _addr) = listener.accept().unwrap();
        let mut br = BufReader::new(&stream);
        let mut w = &stream;

        let mut line = String::new();
        br.read_line(&mut line).unwrap();
        assert!(line.contains(&format!("^{cookie_thr}")));
        writeln!(w, "0 fakedaemon 17.7").unwrap();
        writeln!(w, "4 0 1").unwrap();

        // The actual assertion: REQ_RELOAD arrives.
        let mut req = String::new();
        br.read_line(&mut req).unwrap();
        // "18 1\n" — CONTROL=18, REQ_RELOAD=1. Same as
        // ctl_reload_against_fake_daemon, but THIS time it was
        // `tinc set` that sent it, not `tinc reload`.
        let ok = req.trim_end() == "18 1";
        writeln!(w, "18 1 0").unwrap();
        ok
    });

    let pidfile_s = pidfile.to_str().unwrap();
    let out = tinc(&[
        "-c",
        cb_s,
        "--pidfile",
        pidfile_s,
        "set",
        "Device",
        "/dev/tun",
    ]);

    let reload_received = daemon.join().unwrap();

    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(out.status.success(), "stderr: {stderr}");
    assert!(reload_received, "daemon got something other than '18 1'");

    // And the file was written. The reload is the *side effect*;
    // the write is the *point*.
    let conf = std::fs::read_to_string(cb.join("tinc.conf")).unwrap();
    assert!(conf.contains("Device = /dev/tun\n"));
}

/// `tinc set` with NO daemon listening: file is written, reload
/// silently fails, exit 0. Best-effort means BEST-EFFORT.
///
/// `connect_tincd(false)` — the `false` means "don't error if
/// connect fails". Our `let _ = reload()`
/// is the same swallow.
#[test]
fn config_set_no_daemon_still_succeeds() {
    let (_d, cb, pf) = config_init("alice");
    // pf points at nope.pid which doesn't exist. reload() will
    // fail at Pidfile::read. The `let _ =` swallows it.
    let out = tinc(&["-c", &cb, "--pidfile", &pf, "set", "Device", "/dev/tun"]);
    assert!(out.status.success(), "{:?}", out.stderr);
    // No reload-related noise on stderr.
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(!stderr.contains("pid file"), "{stderr}");
}
