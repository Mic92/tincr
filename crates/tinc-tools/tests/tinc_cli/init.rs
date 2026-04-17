use super::{bare_dir, tinc, tinc_stdin};

#[test]
fn init_via_dash_c() {
    let dir = tempfile::tempdir().unwrap();
    let confbase = dir.path().join("vpn");

    let out = tinc(&["-c", confbase.to_str().unwrap(), "init", "alice"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The unit tests already check file contents/modes exhaustively.
    // Here we just confirm the binary actually invoked the function.
    assert!(confbase.join("tinc.conf").exists());
    assert!(confbase.join("hosts/alice").exists());
    assert!(confbase.join("ed25519_key.priv").exists());

    // Progress message went to stderr, not stdout.
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("Generating Ed25519"));
    assert!(out.stdout.is_empty());
}

#[test]
fn init_via_glued_config() {
    let dir = tempfile::tempdir().unwrap();
    let confbase = dir.path().join("vpn");

    // `--config=DIR` glued form. systemd unit files use this.
    let out = tinc(&[&format!("--config={}", confbase.display()), "init", "bob"]);
    assert!(out.status.success());
    assert_eq!(
        std::fs::read_to_string(confbase.join("tinc.conf")).unwrap(),
        "Name = bob\n"
    );
}

#[test]
fn init_missing_name() {
    let (dir, cb) = bare_dir();
    // Empty stdin: `tinc_stdin` pipes (so is_terminal()=false) but
    // writes nothing, exercising the "piped but blank" path.
    let out = tinc_stdin(&["-c", &cb, "init"], b"");
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("No Name given"));
    // The arity error now appends a usage hint so the user knows
    // *what* to type, not just that something was missing.
    assert!(stderr.contains("Usage: tinc init NAME"), "{stderr}");
    // Nothing created — arity check fires before any filesystem op.
    assert!(!dir.path().join("tinc.conf").exists());
}

/// `echo NAME | tinc init` — C tinc reads the name from stdin when no
/// arg is given (and stdin isn't a tty). Scripts written for C tinc
/// rely on this; we accept it too (but never prompt on a tty).
#[test]
fn init_name_from_stdin() {
    let dir = tempfile::tempdir().unwrap();
    let confbase = dir.path().join("vpn");
    let out = tinc_stdin(&["-c", confbase.to_str().unwrap(), "init"], b"alice\n");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(confbase.join("tinc.conf")).unwrap(),
        "Name = alice\n"
    );
}

#[test]
fn init_case_insensitive_dispatch() {
    // C uses `strcasecmp` on the command name. `tinc INIT alice` works.
    // Nobody types this, but it's free fidelity.
    let dir = tempfile::tempdir().unwrap();
    let confbase = dir.path().join("vpn");
    let out = tinc(&["-c", confbase.to_str().unwrap(), "INIT", "alice"]);
    assert!(out.status.success());
    assert!(confbase.join("tinc.conf").exists());
}
