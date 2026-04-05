//! `tinc edit` integration. Doesn't spawn a real editor; we set
//! `EDITOR` to `/bin/true` (always exits 0) or `/bin/false`
//! (always exits 1) and assert the exit-code path.
//!
//! What this DOESN'T cover: the silent-reload (no daemon up).
//! What it DOES cover: the path resolution, the editor spawn, the
//! exit-code mapping.

use super::{init_dir, tinc};
use std::path::PathBuf;

/// Init a confbase, then run `tinc -c <cb> edit TARGET` with
/// `EDITOR` set and `VISUAL` stripped. Returns confbase + Output.
///
/// `env_remove("VISUAL")` is essential: `pick_editor()` checks
/// VISUAL FIRST; the parent env might have it set.
fn run_edit(editor: &str, target: &str) -> (PathBuf, std::process::Output) {
    let (dir, confbase, cb) = init_dir("node1");
    let out = std::process::Command::new(super::bin("tinc"))
        .args(["-c", &cb, "edit", target])
        .env_remove("NETNAME")
        .env_remove("VISUAL")
        .env("EDITOR", editor)
        .output()
        .unwrap();
    // Leak the tempdir guard — the test only inspects Output and
    // confbase string. (Only ~6 calls per test run.)
    std::mem::forget(dir);
    (confbase, out)
}

/// `EDITOR=true tinc edit alice` → exits 0. `true` exits 0,
/// no reload (no daemon), `Ok(())` → exit 0.
#[test]
fn edit_true_exits_zero() {
    let (_, out) = run_edit("true", "alice");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// `EDITOR=false` → editor exits 1 → our exit nonzero.
#[test]
fn edit_false_exits_nonzero() {
    let (_, out) = run_edit("false", "alice");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    // Our error message includes the editor name and the
    // status. `tincctl.c` just returns the int silently;
    // we say what failed.
    assert!(stderr.contains("false"), "stderr: {stderr}");
    assert!(stderr.contains("exited"), "stderr: {stderr}");
}

/// `EDITOR=echo tinc edit alice` → stdout has the resolved
/// path. THE path-resolution proof: echo prints argv[1].
///
/// Pins `resolve()` end-to-end through `sh -c '$TINC_EDITOR
/// "$@"'`. The path on stdout is the one `"$@"` expanded to.
#[test]
fn edit_echo_shows_resolved_path() {
    let (confbase, out) = run_edit("echo", "alice");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let expected = confbase.join("hosts").join("alice");
    assert_eq!(
        stdout.trim_end(),
        expected.to_str().unwrap(),
        "stdout: {stdout}"
    );
}

/// `EDITOR="echo arg"` (with space) → shell tokenizes →
/// `argv = [echo, arg, <path>]` → stdout `"arg <path>"`.
///
/// THE proof that `sh -c '$TINC_EDITOR "$@"'` word-splits the
/// editor. The upstream `system("\"%s\" ...")` does NOT: it builds
/// `"echo arg" "filename"`, the shell parses `"echo arg"` as ONE
/// token (double-quoted = no word splitting), and `exec("echo arg")`
/// fails ENOENT. We support it via unquoted `$TINC_EDITOR` —
/// stricter-better than C.
#[test]
fn edit_spacey_editor_tokenized() {
    let (confbase, out) = run_edit("echo extraarg", "alice");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let path = confbase.join("hosts").join("alice");
    // `echo extraarg <path>` → stdout `extraarg <path>\n`.
    assert_eq!(stdout.trim_end(), format!("extraarg {}", path.display()));
}

/// `EDITOR=echo`, file with `$` in the name — NOT expanded.
/// THE shell-safety proof: `"$@"` quotes the arg.
///
/// The upstream `system("\"echo\" \"$HOME\"")` would expand `$HOME`
/// (it's inside double-quotes IN THE SHELL). We don't: `$`
/// stays literal in stdout.
#[test]
fn edit_dollar_in_filename_not_expanded() {
    let (_dir, _confbase, cb) = init_dir("node1");
    // Set HOME to something recognizable so expansion is visible.
    let out = std::process::Command::new(super::bin("tinc"))
        .args(["-c", &cb, "edit", "$HOME"])
        .env_remove("NETNAME")
        .env_remove("VISUAL")
        .env("EDITOR", "echo")
        .env("HOME", "/tmp/WRONG")
        .output()
        .unwrap();

    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("$HOME"), "stdout: {stdout}");
    assert!(!stdout.contains("/tmp/WRONG"), "stdout: {stdout}");
}

/// Invalid arg count: `tinc edit` (none) and `tinc edit a b`
/// (two) both error.
#[test]
fn edit_argc_check() {
    let out = tinc(&["edit"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("Invalid number of arguments"));

    let out = tinc(&["edit", "a", "b"]);
    assert!(!out.status.success());
}

/// `tinc edit ../etc/passwd` — our STRICTER reject. The C
/// would resolve to `hosts_dir/../etc/passwd` and run vi.
#[test]
fn edit_reject_traversal() {
    let (_, out) = run_edit("echo", "../etc/passwd");
    assert!(!out.status.success());
    // echo NEVER ran. Stdout is empty.
    assert!(out.stdout.is_empty(), "stdout: {:?}", out.stdout);
}
