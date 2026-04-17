use super::{bin, tinc};
use std::process::Command;

// ─── tinc-auth argv surface
// No fake_daemon coverage here (tinc-auth speaks HTTP, separate
// concern); just prove the flag parser matches the other binaries.

/// `--config=DIR` glued form must parse, same as `tinc`/`tincd`.
/// The old parser only matched the spaced form and treated the
/// glued one as "unknown argument".
#[test]
fn tinc_auth_glued_long_opts() {
    // No listener and no socket activation → fails with the
    // "no listener" message, NOT "unknown argument". That's enough
    // to prove the option was consumed.
    let out = Command::new(bin("tinc-auth"))
        .args(["--config=/tmp", "--net=mesh", "--pidfile=/tmp/p"])
        .env_remove("LISTEN_PID")
        .env_remove("LISTEN_FDS")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("unknown argument"), "{stderr}");
    assert!(stderr.contains("no listener"), "{stderr}");
}

/// `--sockpath` stays as a compat alias for `--listen-socket` so
/// existing systemd unit files don't break.
#[test]
fn tinc_auth_sockpath_alias() {
    for flag in ["--sockpath=/dev/null/x", "--listen-socket=/dev/null/x"] {
        let out = Command::new(bin("tinc-auth"))
            .arg(flag)
            .env_remove("LISTEN_PID")
            .env_remove("LISTEN_FDS")
            .output()
            .unwrap();
        // bind() on a path under /dev/null fails; the point is the
        // flag was recognised (error mentions "bind", not "unknown").
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!stderr.contains("unknown argument"), "{flag}: {stderr}");
        assert!(stderr.contains("bind"), "{flag}: {stderr}");
    }
}

fn tinc_with_env(env: &[(&str, &str)], args: &[&str]) -> std::process::Output {
    let mut cmd = Command::new(bin("tinc"));
    cmd.args(args).env_remove("NETNAME");
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().expect("spawn tinc")
}

/// `tinc version` ≡ `tinc --version`. Same stdout: `version()` is
/// the same fn the option calls.
#[test]
fn version_subcommand_same_as_option() {
    let out_cmd = tinc(&["version"]);
    let out_opt = tinc(&["--version"]);
    assert!(out_cmd.status.success());
    assert!(out_opt.status.success());
    assert_eq!(out_cmd.stdout, out_opt.stdout);
    // Contains the package name and "(Rust)".
    let s = String::from_utf8_lossy(&out_cmd.stdout);
    assert!(s.contains("tinc"), "stdout: {s}");
    assert!(s.contains("(Rust)"), "stdout: {s}");
}

/// `tinc help` ≡ `tinc --help` ≡ `tinc -h`. Same `usage(false)` call.
/// `-h` is an addition over C tinc but matches `tincd -h`; keeping the
/// two binaries consistent is cheaper than explaining the difference.
#[test]
fn help_subcommand_same_as_option() {
    let out_cmd = tinc(&["help"]);
    let out_opt = tinc(&["--help"]);
    let out_h = tinc(&["-h"]);
    assert!(out_cmd.status.success());
    assert!(out_opt.status.success());
    assert!(out_h.status.success());
    assert_eq!(out_cmd.stdout, out_opt.stdout);
    assert_eq!(out_h.stdout, out_opt.stdout);
}

// ────────────────────────────────────────────────────────────────────
// network — switch-reject + argc only (list reads compile-time
// CONFDIR /etc/tinc, can't fake from integration test)
// ────────────────────────────────────────────────────────────────────

/// `tinc network NAME` → error with `-n` advice. Deliberate
/// Upstream-behavior-drop #2. The upstream `switch_network` mutates globals
/// for the readline loop; we have no loop.
#[test]
fn network_switch_rejected() {
    let out = tinc(&["network", "foo"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    // The advice. "-n" is what to use INSTEAD.
    assert!(stderr.contains("-n"), "stderr: {stderr}");
}

/// `tinc network .` → different advice (no -n). The `.` sentinel
/// from `tinc network` list output means "anonymous network";
/// `tinc COMMAND` (no -n) reaches it.
#[test]
fn network_switch_dot() {
    let out = tinc(&["network", "."]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("default") || stderr.contains("no -n"),
        "stderr: {stderr}"
    );
}

/// `tinc network` (list mode) — we can't control CONFDIR (it's
/// `option_env!` compile-time). The test runner's /etc/tinc may
/// or may not exist. Either way the binary shouldn't PANIC.
///
/// If /etc/tinc doesn't exist: ENOENT, exit nonzero. If it does:
/// some output (or none), exit zero. Both fine. Just "doesn't
/// crash." The unit tests in `cmd::network` cover the actual
/// list logic against a fake dir.
#[test]
fn network_list_doesnt_panic() {
    let out = tinc(&["network"]);
    // Either success (confdir exists) or clean error (ENOENT).
    // No panic, no signal-termination. `code()` is `Some(_)` for
    // normal exit, `None` for signal.
    assert!(out.status.code().is_some(), "signal-terminated?");
    // If it errored, stderr has the path. If it succeeded,
    // stderr is empty. Either is fine.
}

/// Help output doesn't list `help` or `version` (recursive). The
/// `help: ""` empty string makes `print_help` skip them.
#[test]
fn help_does_not_list_itself() {
    let out = tinc(&["help"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    // The COMMANDS section doesn't have `help`/`version` lines.
    // (The OPTIONS section has `--help`/`--version`, that's fine.)
    // Check no line starts with `  help` or `  version` (the
    // indented command-list format).
    for line in stdout.lines() {
        assert!(
            !line.trim_start().starts_with("help "),
            "help listed in: {line}"
        );
        // `version` would be `version    ...` if listed. Check
        // it doesn't appear as a command (vs `--version` option).
        // De Morgan: `!(a && !b)` = `!a || b`.
        assert!(
            !line.starts_with("  version") || line.contains("--"),
            "version listed in: {line}"
        );
    }
}

#[test]
fn help_exits_zero() {
    let out = tinc(&["--help"]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("Usage: tinc"));
    assert!(stdout.contains("init NAME"));
    // `--pidfile` is parsed but was missing from the option list,
    // leaving no documented way to point at a non-standard runtime
    // dir.
    assert!(stdout.contains("--pidfile"));
    // Help goes to stdout, not stderr. C does this; `man` convention.
    assert!(out.stderr.is_empty());
}

/// The command list aligns descriptions in one column. The help
/// strings in COMMANDS were hand-spaced and drifted; `print_help`
/// now repads, so every first-line description starts at the same
/// offset.
#[test]
fn help_commands_aligned() {
    let out = tinc(&["--help"]);
    let stdout = String::from_utf8(out.stdout).unwrap();
    let mut in_cmds = false;
    let mut col = None;
    for line in stdout.lines() {
        if line == "Commands:" {
            in_cmds = true;
            continue;
        }
        if !in_cmds {
            continue;
        }
        if line.is_empty() {
            break;
        }
        // Skip dump's indented sub-list (4-space indent).
        if line.starts_with("      ") {
            continue;
        }
        // `  NAME ARGS<pad>  DESC` — desc starts after the run of
        // ≥2 spaces past the leading indent. Every top-level command
        // line MUST have that separator: a help string with only
        // single spaces (e.g. `"restart [OPTS] Restart."`) would slip
        // past `print_help`'s split_once and print unaligned, so make
        // the test fail rather than silently skip it.
        let body = &line[2..];
        let Some(i) = body.find("  ") else {
            panic!("no column separator in: {line:?}");
        };
        let rest = &body[i..];
        let i = i + rest.len() - rest.trim_start().len();
        match col {
            None => col = Some(i),
            Some(c) => assert_eq!(c, i, "misaligned: {line:?}"),
        }
    }
    assert!(col.is_some(), "no command lines found");
}

/// Arity errors print a one-line usage hint so the user doesn't have
/// to re-run --help and scan.
#[test]
fn arity_error_shows_usage() {
    let out = tinc(&["disconnect"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("Usage: tinc disconnect NODE"), "{stderr}");
}

#[test]
fn unknown_command_exits_nonzero() {
    let out = tinc(&["frobnicate"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("Unknown command"));
    assert!(stderr.contains("frobnicate"));
    // Error messages go to stderr. stdout is empty.
    assert!(out.stdout.is_empty());
}

#[test]
fn no_command_exits_nonzero() {
    // Bare `tinc`. C enters shell mode; we don't have shell mode.
    let out = tinc(&[]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("No command given"));
}

#[test]
fn unknown_option_exits_nonzero() {
    let out = tinc(&["--bogus", "init", "alice"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("--bogus"));
}

/// `NETNAME` from env reaches `Paths::for_cli`.
///
/// Direct testing is tricky — env-derived netname resolves to
/// `CONFDIR/tinc/NETNAME`, and `CONFDIR` is `/etc` baked at compile
/// time, which we can't write to in tests. The first attempt was
/// asserting the netname appears in the error path, but `makedir`
/// runs on `confdir` (parent) *before* `confbase` (child), so the
/// EPERM is on `/etc/tinc` and netname never makes it into the error.
///
/// Instead: use the both-given warning as the observable. Set
/// `NETNAME` in env, also pass `-c`, expect the "Both netname and
/// configuration directory given" warning. The warning is emitted by
/// `Paths::for_cli` *iff* `input.netname.is_some()`. If the env var
/// wasn't being read, `netname` would be `None` (we `env_remove`'d it
/// from inheritance) and there'd be no warning.
#[test]
fn netname_env_reaches_paths() {
    let dir = tempfile::tempdir().unwrap();
    let confbase = dir.path().join("vpn");

    let out = tinc_with_env(
        &[("NETNAME", "fromenv")],
        &["-c", confbase.to_str().unwrap(), "init", "alice"],
    );
    assert!(out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    // The warning proves the env var was read. If `parse_global_options`
    // didn't read NETNAME, `input.netname` would be None and `for_cli`
    // wouldn't warn.
    assert!(
        stderr.contains("Both netname and configuration directory given"),
        "expected both-given warning, got: {stderr}"
    );
    // confbase wins, so init still succeeded at the -c path.
    assert!(confbase.join("tinc.conf").exists());
}

/// `-n` flag (not env) also reaches `for_cli`. Same observable.
#[test]
fn netname_flag_reaches_paths() {
    let dir = tempfile::tempdir().unwrap();
    let confbase = dir.path().join("vpn");

    let out = tinc(&[
        "-n",
        "fromflag",
        "-c",
        confbase.to_str().unwrap(),
        "init",
        "alice",
    ]);
    assert!(out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("Both netname and configuration"));
}

#[test]
fn netname_dot_is_noop() {
    // `NETNAME=.` means "no netname". The `.` is normalized to
    // None in `parse_options` BEFORE `make_names`
    // does the both-given check. So `NETNAME=. tinc -c /tmp/x init`
    // sees netname=None confbase=/tmp/x → no warning. Our
    // `parse_global_options` and `for_cli` preserve the same order.
    let dir = tempfile::tempdir().unwrap();
    let confbase = dir.path().join("vpn");
    let out = tinc_with_env(
        &[("NETNAME", ".")],
        &["-c", confbase.to_str().unwrap(), "init", "alice"],
    );
    assert!(out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    // The warning string from `Paths::for_cli`.
    assert!(!stderr.contains("Both netname and configuration"));
}

/// `-cFOO` glued short form. C `getopt_long` accepts it; rejecting it
/// breaks scripts written against C tinc.
#[test]
fn glued_short_c() {
    let dir = tempfile::tempdir().unwrap();
    let confbase = dir.path().join("vpn");
    let out = tinc(&[&format!("-c{}", confbase.display()), "init", "alice"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(confbase.join("tinc.conf").exists());
}

#[test]
fn netname_traversal_rejected() {
    let out = tinc_with_env(&[("NETNAME", "../escape")], &["init", "alice"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("Invalid character in netname"));
}
