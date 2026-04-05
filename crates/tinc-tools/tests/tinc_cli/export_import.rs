use super::{bare_dir, init_dir, tinc, tinc_stdin};

/// `export` without `init` first → fails (no tinc.conf, can't get_my_name).
#[test]
fn export_no_config() {
    let (_dir, cb) = bare_dir();
    let out = tinc(&["-c", &cb, "export"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("tinc.conf"));
}

/// `import` skips existing without `--force`, overwrites with.
#[test]
fn import_force_flag() {
    let (_dir, confbase, cb) = init_dir("alice");

    // alice's hosts file exists (init wrote it). Import a new alice.
    let blob = b"Name = alice\nOVERWRITTEN\n";

    // Without --force: skip, exit 1 (count==0).
    let out = tinc_stdin(&["-c", &cb, "import"], blob);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("already exists"));
    assert!(stderr.contains("No host configuration files imported"));
    // Original contents intact (still has the Ed25519PublicKey from init).
    let content = std::fs::read_to_string(confbase.join("hosts/alice")).unwrap();
    assert!(content.contains("Ed25519PublicKey"));

    // With --force: overwrite.
    let out = tinc_stdin(&["--force", "-c", &cb, "import"], blob);
    assert!(out.status.success(), "{out:?}");
    let content = std::fs::read_to_string(confbase.join("hosts/alice")).unwrap();
    assert_eq!(content, "OVERWRITTEN\n");
}

/// **The contract test.** alice runs `tinc export`, bob runs
/// `tinc import` on alice's output. Then bob's `hosts/alice` should
/// match alice's `hosts/alice` (modulo the trailing-newline quirk
/// from the export-all separator, but single export doesn't have that).
///
/// This is the actual user workflow:
/// ```sh
/// alice$ tinc export | ssh bob tinc import
/// ```
#[test]
fn export_import_workflow() {
    let dir = tempfile::tempdir().unwrap();

    // Two confbases.
    let alice_base = dir.path().join("alice");
    let bob_base = dir.path().join("bob");

    let out = tinc(&["-c", alice_base.to_str().unwrap(), "init", "alice"]);
    assert!(out.status.success());
    let out = tinc(&["-c", bob_base.to_str().unwrap(), "init", "bob"]);
    assert!(out.status.success());

    // Add some realistic content to alice's host file beyond what
    // init wrote.
    let alice_host = alice_base.join("hosts/alice");
    let mut content = std::fs::read_to_string(&alice_host).unwrap();
    content.push_str("Address = 192.0.2.1\nSubnet = 10.0.1.0/24\n");
    std::fs::write(&alice_host, &content).unwrap();

    // ─── alice exports ───────────────────────────────────────────
    let exported = tinc(&["-c", alice_base.to_str().unwrap(), "export"]);
    assert!(exported.status.success());

    // ─── bob imports ─────────────────────────────────────────────
    let out = tinc_stdin(
        &["-c", bob_base.to_str().unwrap(), "import"],
        &exported.stdout,
    );
    assert!(out.status.success(), "{out:?}");

    // ─── verify ──────────────────────────────────────────────────
    let imported = std::fs::read_to_string(bob_base.join("hosts/alice")).unwrap();
    assert_eq!(imported, content);
}

/// `export-all` → `import` through the binary. With separator.
#[test]
fn export_all_import_workflow() {
    let dir = tempfile::tempdir().unwrap();
    let alice_base = dir.path().join("alice");
    let charlie_base = dir.path().join("charlie");

    let out = tinc(&["-c", alice_base.to_str().unwrap(), "init", "alice"]);
    assert!(out.status.success());
    let out = tinc(&["-c", charlie_base.to_str().unwrap(), "init", "charlie"]);
    assert!(out.status.success());

    // Alice has bob in her hosts/ too (she already imported him).
    std::fs::write(
        alice_base.join("hosts/bob"),
        "Subnet = 10.0.2.0/24\nAddress = 192.0.2.2\n",
    )
    .unwrap();

    // export-all gives both alice and bob.
    let exported = tinc(&["-c", alice_base.to_str().unwrap(), "export-all"]);
    assert!(exported.status.success());
    let blob = String::from_utf8_lossy(&exported.stdout);
    assert!(blob.contains("Name = alice"));
    assert!(blob.contains("Name = bob"));
    assert!(blob.contains("#-")); // separator present

    // Charlie imports both.
    let out = tinc_stdin(
        &["-c", charlie_base.to_str().unwrap(), "import"],
        &exported.stdout,
    );
    assert!(out.status.success(), "{out:?}");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("Imported 2"));

    assert!(charlie_base.join("hosts/alice").exists());
    assert!(charlie_base.join("hosts/bob").exists());
    // Separator was stripped — not written into either file.
    let alice_at_charlie = std::fs::read_to_string(charlie_base.join("hosts/alice")).unwrap();
    assert!(!alice_at_charlie.contains("#-"));
}

/// Cross-impl: Rust `tinc export` → same blob as we'd parse with the
/// upstream `sscanf("Name = %s")`. Tested by feeding Rust export output back
/// into Rust import (above) AND by checking the format manually here.
///
/// We can't easily run the upstream `tinc import` (no upstream binary in the
/// fixture), but we *can* prove the format matches: the export blob
/// must start with literally `Name = alice\n` — that's what C
/// `sscanf("Name = %4095s")` matches. If the Rust output were
/// `Name=alice\n` (no spaces) or `name = alice\n` (lowercase),
/// C import would treat it as junk. The unit test
/// `import_name_format_is_exact` proves *our* import has the same
/// pickiness; this test proves our *export* produces what that
/// pickiness expects.
#[test]
fn export_format_matches_c_sscanf() {
    let (_dir, _confbase, cb) = init_dir("node1");

    let out = tinc(&["-c", &cb, "export"]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();

    // The exact byte sequence the upstream `sscanf("Name = %s")` matches.
    // Uppercase N, space, equals, space.
    let first_line = stdout.lines().next().unwrap();
    assert_eq!(first_line, "Name = node1");
    // sscanf %s stops at whitespace; node1 has none.
    // The literal-space-equals-space is mandatory in the format string.
    // Any other format (`Name=node1`, ` Name = node1`) wouldn't match.
}
