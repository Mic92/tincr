//! `tinc edit` with `EDITOR` set to `true`/`false`/`echo` instead of a
//! real editor. `VISUAL` is removed because it takes precedence.

use super::{Conf, tinc, tinc_with};

fn edit(conf: &Conf, editor: &str, target: &str) -> super::Run {
    tinc_with(&["-c", &conf.arg(), "edit", target], b"", |cmd| {
        cmd.env_remove("VISUAL")
            .env("EDITOR", editor)
            .env("HOME", "/tmp/WRONG");
    })
}

#[test]
fn editor_exit_status_propagates() {
    let conf = Conf::init("node1");
    edit(&conf, "true", "alice").ok();
    let stderr = edit(&conf, "false", "alice").fails_with("exited");
    assert!(stderr.contains("false"), "{stderr}");
}

/// The editor runs as `sh -c '$TINC_EDITOR "$@"'`: the editor string
/// is word-split (so flags work), the file name is not (so `$` in it
/// stays literal). `echo` shows what it got.
#[test]
fn editor_invocation_via_shell() {
    let conf = Conf::init("node1");
    let host = conf.host("alice");
    let host = host.to_str().unwrap();
    assert_eq!(edit(&conf, "echo", "alice").ok().trim_end(), host);
    assert_eq!(
        edit(&conf, "echo extraarg", "alice").ok().trim_end(),
        format!("extraarg {host}")
    );
    let stdout = edit(&conf, "echo", "$HOME").ok();
    assert!(
        stdout.contains("$HOME") && !stdout.contains("/tmp/WRONG"),
        "{stdout}"
    );
}

#[test]
fn edit_arity() {
    let stderr = tinc(&["edit"]).fails_with("No FILE given!");
    assert!(stderr.contains("Usage: tinc edit FILE"), "{stderr}");
    tinc(&["edit", "a", "b"]).fails_with("Too many arguments!");
}

/// C would open `hosts/../etc/passwd`.
#[test]
fn edit_rejects_path_traversal() {
    let conf = Conf::init("node1");
    let run = edit(&conf, "echo", "../etc/passwd");
    assert_eq!(run.stdout, "", "editor must not run");
    run.fails();
}
