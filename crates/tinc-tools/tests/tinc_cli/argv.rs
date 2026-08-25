//! Global options, help/version, dispatch errors.

use super::Run;
use super::{Conf, bin, tinc, tinc_with};
use std::process::Command;

fn tinc_env(env: &[(&str, &str)], args: &[&str]) -> Run {
    tinc_with(args, b"", |cmd| {
        for (key, value) in env {
            cmd.env(key, value);
        }
    })
}

/// `--config=DIR` glued form must parse in `tinc-auth` like in the
/// other binaries. Without a listener it then fails for that reason.
#[test]
fn tinc_auth_glued_long_opts() {
    let out = Command::new(bin("tinc-auth"))
        .args(["--config=/tmp", "--net=mesh", "--pidfile=/tmp/p"])
        .env_remove("LISTEN_PID")
        .env_remove("LISTEN_FDS")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(!stderr.contains("unknown argument"), "{stderr}");
    assert!(stderr.contains("no listener"), "{stderr}");
}

/// `--sockpath` stays as an alias for `--listen-socket` so existing
/// unit files keep working. Binding under /dev/null fails; the point
/// is that the flag was recognised.
#[test]
fn tinc_auth_sockpath_alias() {
    for flag in ["--sockpath=/dev/null/x", "--listen-socket=/dev/null/x"] {
        let out = Command::new(bin("tinc-auth"))
            .arg(flag)
            .env_remove("LISTEN_PID")
            .env_remove("LISTEN_FDS")
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!stderr.contains("unknown argument"), "{flag}: {stderr}");
        assert!(stderr.contains("bind"), "{flag}: {stderr}");
    }
}

#[test]
fn help_and_version_aliases() {
    let version = tinc(&["--version"]).succeeds();
    assert_eq!(tinc(&["version"]).succeeds(), version);
    assert!(
        version.contains("tinc") && version.contains("(Rust)"),
        "{version}"
    );

    let run = tinc(&["--help"]);
    assert_eq!(run.stderr, "");
    let help = run.succeeds();
    assert_eq!(tinc(&["help"]).succeeds(), help);
    assert_eq!(tinc(&["-h"]).succeeds(), help);
    assert!(help.contains("Usage: tinc") && help.contains("init NAME"));
    assert!(help.contains("--pidfile"));
    // `help` and `version` are not listed as commands (only as options).
    for line in help.lines() {
        assert!(!line.trim_start().starts_with("help "), "{line}");
        assert!(
            !line.starts_with("  version") || line.contains("--"),
            "{line}"
        );
    }
}

/// `print_help` re-pads the hand-written command synopses so every
/// description starts in the same column. A synopsis without a
/// double-space separator would print unaligned, so that is an error
/// here rather than skipped.
#[test]
fn help_commands_aligned() {
    let help = tinc(&["--help"]).succeeds();
    let commands = help
        .lines()
        .skip_while(|line| *line != "Commands:")
        .skip(1)
        .take_while(|line| !line.is_empty())
        // dump's indented sub-list
        .filter(|line| !line.starts_with("      "));
    let columns: Vec<usize> = commands
        .map(|line| {
            let body = &line[2..];
            let gap = body
                .find("  ")
                .unwrap_or_else(|| panic!("no column separator in {line:?}"));
            gap + body[gap..].len() - body[gap..].trim_start().len()
        })
        .collect();
    assert!(!columns.is_empty());
    assert!(columns.iter().all(|&c| c == columns[0]), "{columns:?}");
}

#[test]
fn dispatch_errors() {
    let stderr = tinc(&["disconnect"]).fails();
    assert!(stderr.contains("Usage: tinc disconnect NODE"), "{stderr}");
    let run = tinc(&["frobnicate"]);
    assert_eq!(run.stdout, "");
    assert!(run.fails_with("Unknown command").contains("frobnicate"));
    // C enters shell mode here; we have none.
    tinc(&[]).fails_with("No command given");
    tinc(&["--bogus", "init", "alice"]).fails_with("--bogus");
}

/// `tinc network NAME` would switch networks in C's shell mode; we
/// point at `-n` instead (or, for the `.` "no netname" sentinel, at
/// running without it). Listing reads compile-time CONFDIR, so only
/// check it exits rather than dies.
#[test]
fn network_command() {
    tinc(&["network", "foo"]).fails_with("-n");
    let stderr = tinc(&["network", "."]).fails();
    assert!(
        stderr.contains("default") || stderr.contains("no -n"),
        "{stderr}"
    );
    // Only "did not die from a signal" is knowable here.
    let _ = tinc(&["network"]);
}

/// Netname (from `NETNAME` or `-n`) reaching `Paths::for_cli` is
/// observable through the "both given" warning when `-c` is also
/// passed; `NETNAME=.` means none and must not warn. CONFDIR is
/// compile-time `/etc`, so the netname path itself cannot be used.
#[test]
fn netname_sources() {
    const BOTH: &str = "Both netname and configuration directory given";
    let conf = Conf::bare();
    let base = conf.arg();
    let stderr = tinc_env(&[("NETNAME", "fromenv")], &["-c", &base, "init", "a"]).succeeds_stderr();
    assert!(stderr.contains(BOTH), "{stderr}");
    assert!(conf.base().join("tinc.conf").exists(), "confbase wins");

    let conf = Conf::bare();
    let stderr = tinc(&["-n", "fromflag", "-c", &conf.arg(), "init", "a"]).succeeds_stderr();
    assert!(stderr.contains(BOTH), "{stderr}");

    let conf = Conf::bare();
    let stderr = tinc_env(&[("NETNAME", ".")], &["-c", &conf.arg(), "init", "a"]).succeeds_stderr();
    assert!(!stderr.contains(BOTH), "{stderr}");

    tinc_env(&[("NETNAME", "../escape")], &["init", "a"])
        .fails_with("Invalid character in netname");
}

/// C `getopt_long` accepts `-cDIR`; scripts use it.
#[test]
fn glued_short_c() {
    let conf = Conf::bare();
    tinc(&[&format!("-c{}", conf.arg()), "init", "alice"]).succeeds();
    assert!(conf.base().join("tinc.conf").exists());
}
