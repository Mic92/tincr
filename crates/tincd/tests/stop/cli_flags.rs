use std::ffi::OsStr;
use std::process::{Command, Output, Stdio};

use super::common::{
    ChildWithLog, Node, read_cookie, read_tcp_addr, tincd_at, tincd_bin, tincd_cmd, wait_for_file,
    write_ed25519_privkey,
};
use super::testnode;
use std::fs;
use std::io;
use std::io::BufRead;
use std::io::BufReader;
use std::os::unix::net::UnixStream;

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Run tincd expecting it to exit non-zero during setup; returns stderr.
fn run_failing(node: &Node, args: &[&str]) -> String {
    let out = tincd_at(&node.confbase, &node.pidfile, &node.socket)
        .args(args)
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    let stderr = stderr_of(&out);
    assert!(!out.status.success(), "tincd {args:?} succeeded:\n{stderr}");
    stderr
}

/// Start with extra args/env tweaks, wait for readiness, return the node.
fn start_with<I, S>(node: &mut Node, args: I, tweak: impl FnOnce(&mut Command))
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut cmd = tincd_at(&node.confbase, &node.pidfile, &node.socket);
    cmd.args(args).stderr(Stdio::piped());
    tweak(&mut cmd);
    node.start_command(cmd);
}

#[test]
fn help_and_version_go_to_stdout() {
    let help = Command::new(tincd_bin()).arg("--help").output().unwrap();
    assert!(help.status.success() && help.stderr.is_empty(), "{help:?}");
    let text = String::from_utf8_lossy(&help.stdout);
    for expected in [
        "Usage: tincd",
        "--pidfile",
        "--socket",
        "--version",
        "--no-detach",
    ] {
        assert!(text.contains(expected), "--help lacks {expected}:\n{text}");
    }

    let version = Command::new(tincd_bin()).arg("--version").output().unwrap();
    assert!(
        version.status.success() && version.stderr.is_empty(),
        "{version:?}"
    );
    let text = String::from_utf8_lossy(&version.stdout);
    assert!(text.contains("tincd") && text.contains("(Rust)"), "{text}");
}

/// C-only debug flag still found in old how-tos: accept and warn
/// rather than refuse to start.
#[test]
fn bypass_security_is_accepted_with_warning() {
    let tmp = tmp!("bypass-sec");
    let mut node = testnode(tmp.path());
    start_with(&mut node, ["--bypass-security"], |_| {});
    let log = node.stop();
    assert!(
        log.contains("bypass-security") && log.to_lowercase().contains("not supported"),
        "{log}"
    );
}

#[test]
fn missing_tinc_conf_fails_without_leaving_files() {
    let tmp = tmp!("noconfig");
    let node = Node::new(tmp.path(), "testnode", 0x42);
    fs::create_dir_all(&node.confbase).unwrap();
    let stderr = run_failing(&node, &[]);
    assert!(stderr.contains("tinc.conf"), "{stderr}");
    assert!(!node.pidfile.exists() && !node.socket.exists());
}

#[test]
fn missing_name_fails() {
    let tmp = tmp!("noname");
    let node = Node::new(tmp.path(), "testnode", 0x42);
    fs::create_dir_all(&node.confbase).unwrap();
    fs::write(node.confbase.join("tinc.conf"), "DeviceType = dummy\n").unwrap();
    let stderr = run_failing(&node, &[]);
    assert!(
        stderr.contains("Name") && stderr.contains("required"),
        "{stderr}"
    );
}

/// Command-line settings sort before file settings.
#[test]
fn dash_o_overrides_tinc_conf() {
    let tmp = tmp!("dash-o");
    let mut node = testnode(tmp.path());
    fs::write(node.confbase.join("hosts").join("override"), "Port = 0\n").unwrap();
    start_with(&mut node, ["-o", "Name = override"], |_| {});

    let cookie = read_cookie(&node.pidfile);
    let socket = UnixStream::connect(&node.socket).unwrap();
    io::Write::write_all(&mut &socket, format!("0 ^{cookie} 0\n").as_bytes()).unwrap();
    let mut id_line = String::new();
    BufRead::read_line(&mut BufReader::new(&socket), &mut id_line).unwrap();
    assert_eq!(id_line, "0 override 17.7\n");
}

#[test]
fn dash_o_without_value_fails() {
    let tmp = tmp!("dash-o-bad");
    let node = testnode(tmp.path());
    let stderr = run_failing(&node, &["-o", "KeyWithoutValue"]);
    assert!(stderr.contains("KeyWithoutValue"), "{stderr}");
}

/// `-n NET` / `$NETNAME` select `CONFDIR/tinc/NET`; we can't write
/// there, so check the derived path via the error message. A netname
/// containing `/` is rejected outright.
#[test]
fn netname_selects_confbase() {
    let tmp = tmp!("netname");
    let run = |args: &[&str], netname_env: Option<&str>| {
        let mut cmd = tincd_cmd();
        cmd.args(args)
            .arg("--pidfile")
            .arg(tmp.path().join("pid"))
            .arg("--socket")
            .arg(tmp.path().join("socket"))
            .stderr(Stdio::piped());
        if let Some(net) = netname_env {
            cmd.env("NETNAME", net);
        }
        let out = cmd.output().unwrap();
        assert!(!out.status.success());
        stderr_of(&out)
    };
    assert!(run(&["-n", "testnet"], None).contains("testnet"));
    assert!(run(&[], Some("envnet")).contains("envnet"));
    let stderr = run(&["-n", "foo/bar"], None).to_lowercase();
    assert!(
        stderr.contains("netname") || stderr.contains("invalid"),
        "{stderr}"
    );
}

/// `hosts/NAME` is optional; `Port` is honoured from `tinc.conf` too.
#[test]
fn starts_without_hosts_dir() {
    let tmp = tmp!("nohosts");
    let mut node = Node::new(tmp.path(), "testnode", 0x42).log_level("tincd=warn");
    fs::create_dir_all(&node.confbase).unwrap();
    fs::write(
        node.confbase.join("tinc.conf"),
        "Name = testnode\nDeviceType = dummy\nAddressFamily = ipv4\nPort = 0\n",
    )
    .unwrap();
    write_ed25519_privkey(&node.confbase, &[0x42; 32]);

    node.start();
    assert_ne!(read_tcp_addr(&node.pidfile).port(), 0);
    let log = node.stop();
    assert!(log.contains("hosts/testnode"), "no warning:\n{log}");
}

/// Every test here depends on `-D` keeping tincd as our direct child.
#[test]
fn no_detach_keeps_pid() {
    let tmp = tmp!("dash-D");
    let mut node = testnode(tmp.path());
    node.start();
    let pidfile_pid: i32 = fs::read_to_string(&node.pidfile)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(pidfile_pid, node.pid().as_raw());
}

#[test]
fn dash_d5_sets_debug_level() {
    let tmp = tmp!("dash-d5");
    let mut node = testnode(tmp.path());
    start_with(&mut node, ["-d5"], |cmd| {
        cmd.env_remove("RUST_LOG");
    });
    let log = node.stop();
    assert!(log.contains("debug level 5"), "{log}");
}

#[test]
fn logfile_replaces_stderr() {
    let tmp = tmp!("logfile");
    let mut node = testnode(tmp.path());
    let logfile = tmp.path().join("tinc.log");
    start_with(
        &mut node,
        [OsStr::new("--logfile"), logfile.as_os_str()],
        |cmd| {
            cmd.env_remove("RUST_LOG");
        },
    );
    let stderr = node.stop();
    let logged = fs::read_to_string(&logfile).unwrap();
    assert!(logged.contains("starting"), "logfile:\n{logged}");
    assert!(!stderr.contains("starting"), "stderr:\n{stderr}");
}

/// Success needs root; the error path shows the option is wired.
#[test]
fn unknown_user_fails() {
    let tmp = tmp!("dash-U");
    let node = testnode(tmp.path());
    let stderr = run_failing(&node, &["-U", "no_such_user_xyz_9999"]);
    assert!(
        stderr.contains("unknown user") && stderr.contains("no_such_user_xyz_9999"),
        "{stderr}"
    );
}

/// Whether `mlockall` succeeds depends on `RLIMIT_MEMLOCK`, so accept
/// either a running daemon or a clear error — not a silently ignored
/// flag.
#[test]
fn mlock_flag_locks_or_fails_loudly() {
    let tmp = tmp!("dash-L");
    let node = testnode(tmp.path());
    let child = tincd_at(&node.confbase, &node.pidfile, &node.socket)
        .arg("-L")
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut child = ChildWithLog::spawn(child);
    let started = wait_for_file(&node.socket);
    let exited = child.child.try_wait().unwrap();
    let log = child.kill_and_log();
    if started {
        assert!(!log.contains("unknown argument"), "{log}");
    } else {
        assert!(exited.is_some_and(|status| !status.success()), "{log}");
        assert!(log.contains("mlockall"), "{log}");
    }
}

/// Unlike C tinc we only warn on a bad `ProcessPriority`; refusing to
/// start over a typo there helps nobody.
#[test]
fn bad_process_priority_only_warns() {
    let tmp = tmp!("priority-bad");
    let mut node = testnode(tmp.path()).log_level("tincd=debug");
    start_with(&mut node, ["-o", "ProcessPriority = bogus"], |_| {});
    let log = node.stop();
    assert!(
        log.contains("Invalid priority") && log.contains("bogus"),
        "{log}"
    );
}

/// Lowering priority needs no privileges, so this exercises the real
/// `setpriority` call.
#[test]
fn process_priority_low_sets_nice_10() {
    let tmp = tmp!("priority-low");
    let mut node = testnode(tmp.path()).log_level("tincd=debug");
    start_with(&mut node, ["-o", "ProcessPriority = low"], |_| {});
    #[expect(clippy::cast_sign_loss)]
    let nice = unsafe { libc::getpriority(libc::PRIO_PROCESS, node.pid().as_raw() as libc::id_t) };
    assert_eq!(nice, 10);
    let log = node.stop();
    assert!(
        !(log.contains("setpriority") && log.contains("failed")),
        "{log}"
    );
}
