use super::*;
use crate::names::PathsInput;
use crate::testutil::{self, ConfDir};

// Stage 1: parse_var_expr — pure string munging, no fs

/// Ok-path table for `parse_var_expr`. The `strcspn` stop set is
/// `\t =`, and `strchr(key, '.')` runs only on the key slice.
#[test]
fn parse_var_expr_ok() {
    #[expect(clippy::type_complexity)] // one-shot test table tuple; typedef just moves the noise
    #[rustfmt::skip]
    let cases: &[(&str, (Option<&str>, &str, &str))] = &[
        // ─── bare var, no value ───
        ("Port",                    (None, "Port", "")),
        // ─── separator variants: stop set is `\t =` ───
        ("Port = 655",              (None, "Port", "655")),
        ("Port=655",                (None, "Port", "655")),  // no-space-around-=
        ("Port\t655",               (None, "Port", "655")),  // tab separator
        ("Port 655",                (None, "Port", "655")),  // argv-join: `tinc set Port 655` → "Port 655"
        // ─── multi-word value: only FIRST `\t /=` is key boundary ───
        // `tinc set Name $HOST` → `"Name = my host name"`. The strncat
        // loop preserves spaces; `args.join(" ")` does too.
        ("Name = host with spaces", (None, "Name", "host with spaces")),
        // ─── node prefix ───
        ("alice.Port",              (Some("alice"), "Port", "")),
        ("alice.Port = 655",        (Some("alice"), "Port", "655")),
        ("alice.Port=655",          (Some("alice"), "Port", "655")),  // no-space + node prefix
        // ─── value with embedded `=`: split on FIRST `=`/ws ───
        ("Device = /dev/tun=x",     (None, "Device", "/dev/tun=x")),
        // ─── dots in value, not key: `.` scan is key-slice-only ───
        ("Address = 10.0.0.1",      (None, "Address", "10.0.0.1")),
        // No separator + dots → whole thing is key → `node=10, var=0.0.1`.
        // Weird but it's what upstream does (`0.0.1` fails `vars::lookup` later).
        ("10.0.0.1",                (Some("10"), "0.0.1", "")),
    ];
    for (input, expected) in cases {
        assert_eq!(
            parse_var_expr(input).unwrap(),
            *expected,
            "input: {input:?}"
        );
    }
}

/// Err-path table. Both produce empty-var via different routes.
#[test]
fn parse_var_expr_err() {
    for input in [
        // `alice.` → empty var after dot.
        "alice.", // `=655` → `=` in stop set, key_end=0 → empty var.
        "=655",
    ] {
        let e = parse_var_expr(input).unwrap_err();
        assert!(
            matches!(e, CmdError::BadInput(m) if m == "No variable given."),
            "input: {input:?}"
        );
    }
}

// split_line — file-line tokenizer (instance #7)

/// `split_line` table. rstrip set is `\t\r\n `. `cmd_config`
/// does NOT have `#` comment awareness — `#` is just a
/// character (`parse_config_line` does, but `cmd_config`
/// doesn't share that code; intentional — `tinc set` operates
/// on files-as-text, not files-as-config).
#[test]
fn split_line_table() {
    #[rustfmt::skip]
    let cases: &[(&str, Option<(&str, &str)>)] = &[
        // ─── separator variants ───
        ("Port = 655\n",   Some(("Port", "655"))),
        ("Port=655\n",     Some(("Port", "655"))),
        ("Port\t655\n",    Some(("Port", "655"))),
        // ─── CRLF (Windows-edited): `\r` mustn't end up in value ───
        ("Port = 655\r\n", Some(("Port", "655"))),
        // ─── trailing ws before newline: rstrip handles ───
        ("Port = 655   \n", Some(("Port", "655"))),
        ("Port = 655\t\n", Some(("Port", "655"))),
        // ─── blank → None: empty key → strcasecmp fails → copy-verbatim ───
        ("\n",    None),
        ("",      None),
        ("   \n", None),
        // ─── `#` comment: tokenizes as key="#", doesn't match any var → preserved ───
        ("# Port = 655\n", Some(("#", "Port = 655"))),
    ];
    for (input, expected) in cases {
        assert_eq!(split_line(input), *expected, "input: {input:?}");
    }
}

/// PEM line: `-----BEGIN PUBLIC KEY-----`. Tokenizes as
/// `key="-----BEGIN"`, doesn't match anything, copies verbatim.
/// Host files have these at the bottom; `tinc set Port 655`
/// must preserve them.
#[test]
fn split_line_pem_passthrough() {
    let line = "-----BEGIN PUBLIC KEY-----\n";
    let (k, _) = split_line(line).unwrap();
    // Doesn't matter what k is, just that it isn't a var name.
    assert!(vars::lookup(k).is_none());
}

// Stage 2: build_intent — needs Paths for the get_my_name call

/// Minimal confbase: tinc.conf with `Name = alice`, hosts/alice.
fn setup(name: &str) -> ConfDir {
    ConfDir::with_name(name)
}

/// Routing + canonicalization table: which file does this var go to?
/// SERVER → tinc.conf (node=None); HOST-only → hosts/$me via
/// `get_my_name`; explicit node prefix wins.
#[test]
fn intent_routing() {
    let cd = setup("alice");
    let paths = cd.paths().clone();
    #[expect(clippy::type_complexity)] // one-shot test table tuple; typedef just moves the noise
    #[rustfmt::skip]
    let cases: &[(Action, Option<&str>, &str, &str, Option<&str>, &str)] = &[
        //          (action,      explicit_node, var,      value,          expect_node,   expect_canonical_var)
        // Device is SERVER-only → tinc.conf.
        (Action::Set, None,        "Device", "/dev/tun",     None,          "Device"),
        // Subnet is HOST-only → resolved via get_my_name → "alice".
        (Action::Add, None,        "Subnet", "10.0.0.0/24",  Some("alice"), "Subnet"),
        // Explicit `bob.Subnet` overrides get_my_name.
        (Action::Add, Some("bob"), "Subnet", "10.0.0.0/24",  Some("bob"),   "Subnet"),
        // Canonicalization: `port` → `Port`.
        (Action::Set, None,        "port",   "655",          Some("alice"), "Port"),
    ];
    for &(action, explicit, var, val, expect_node, expect_var) in cases {
        let (intent, _) = build_intent(&paths, action, explicit, var, val, false).unwrap();
        assert_eq!(intent.node.as_deref(), expect_node, "var: {var:?}");
        assert_eq!(intent.variable, expect_var, "var: {var:?}");
    }
}

/// Port is dual-tagged (SERVER | HOST). The condition `!(type &
/// VAR_SERVER)` means dual-tagged vars take the SERVER path →
/// tinc.conf, not hosts/$me.
#[test]
fn intent_dual_tagged_goes_to_tinc_conf() {
    let cd = setup("alice");
    let paths = cd.paths().clone();
    // Precondition: Cipher really is S|H. If the table changes,
    // this test's premise breaks. (Port is HOST-only. First
    // version of this test wrongly assumed Port was dual.
    // `tinc set Port 655` writes to hosts/$me, not tinc.conf.
    // The pidfile-reading `tinc get Port` is precisely BECAUSE
    // the configured Port lives in the host file but the
    // runtime port is global state.)
    let v = vars::lookup("Cipher").unwrap();
    assert!(v.flags.contains(VarFlags::SERVER));
    assert!(v.flags.contains(VarFlags::HOST));

    let (intent, _) =
        build_intent(&paths, Action::Set, None, "Cipher", "aes-256-gcm", false).unwrap();
    // SERVER bit set → tinc.conf, even though HOST is also set.
    assert_eq!(intent.node, None);
}

/// And the contrapositive: Port is HOST-only → hosts/$me.
/// Separate test so the dual-tagged one above can't accidentally
/// pass for the wrong reason.
#[test]
fn intent_port_is_host_only() {
    let cd = setup("alice");
    let paths = cd.paths().clone();
    let v = vars::lookup("Port").unwrap();
    assert!(!v.flags.contains(VarFlags::SERVER));
    assert!(v.flags.contains(VarFlags::HOST));

    let (intent, _) = build_intent(&paths, Action::Set, None, "Port", "655", false).unwrap();
    // HOST-only → hosts/alice via get_my_name.
    assert_eq!(intent.node.as_deref(), Some("alice"));
}

/// Action coercion table. The MULTIPLE flag and the action
/// interact: `add` on non-MULTIPLE downgrades to `set` (you
/// can't have two Ports), `set` on MULTIPLE warns (you might be
/// wiping a list).
#[test]
fn intent_action_coercion() {
    let cd = setup("alice");
    let paths = cd.paths().clone();
    #[rustfmt::skip]
    let cases: &[(Action, &str, &str, Action, bool)] = &[
        //          (in_action,  var,         value, out_action,  warn_on_remove)
        // `add` on non-MULTIPLE → `set` + warn. Port is not MULTIPLE.
        (Action::Add, "Port",      "655", Action::Set, true),
        // `set` on MULTIPLE → still `set`, but warn. ConnectTo is SERVER|MULTIPLE.
        (Action::Set, "ConnectTo", "bob", Action::Set, true),
        // `add` on MULTIPLE stays `add`. The intended use case.
        (Action::Add, "ConnectTo", "bob", Action::Add, false),
    ];
    for &(in_action, var, val, out_action, warn) in cases {
        let (intent, _) = build_intent(&paths, in_action, None, var, val, false).unwrap();
        assert_eq!(intent.action, out_action, "{in_action:?} {var}");
        assert_eq!(intent.warn_on_remove, warn, "{in_action:?} {var}");
    }
    // `get` with a value → `set`. (Separate because the original
    // didn't pin warn_on_remove; preserving.)
    let (intent, _) = build_intent(&paths, Action::Get, None, "Port", "655", false).unwrap();
    assert_eq!(intent.action, Action::Set);
}

/// Err-path table for `build_intent`. All produce
/// `CmdError::BadInput`; we check the message text since these
/// are user-facing strings.
#[test]
fn intent_errors() {
    let cd = setup("alice");
    let paths = cd.paths().clone();
    #[rustfmt::skip]
    let cases: &[(Action, Option<&str>, &str, &str, &str)] = &[
        //          (action,      explicit_node,    var,      value,          msg_contains)
        // `set` without value.
        (Action::Set, None,             "Port",     "",            "No value for variable given."),
        // Unknown var without force.
        (Action::Set, None,             "NoSuchVar", "x",          "not a known configuration variable"),
        // `node.SERVER_VAR` without force. Device is SERVER-only.
        (Action::Set, Some("bob"),      "Device",   "/dev/tun",    "not a host configuration variable"),
        // Explicit node fails check_id.
        (Action::Get, Some("bad/name"), "Port",     "",            "Invalid name for node."),
        // Subnet validation: malformed.
        (Action::Add, None,             "Subnet",   "not-a-subnet", "Malformed subnet definition"),
        // Subnet: host bits set. 10.0.0.1/24: .1 is in host portion.
        (Action::Add, None,             "Subnet",   "10.0.0.1/24", "Network address and prefix length do not match"),
    ];
    for &(action, explicit, var, val, msg) in cases {
        let e = build_intent(&paths, action, explicit, var, val, false).unwrap_err();
        let CmdError::BadInput(m) = e else {
            panic!("expected BadInput for {var:?}={val:?}")
        };
        assert!(m.contains(msg), "var={var:?} val={val:?}: got {m:?}");
    }
    // The unknown-var error also mentions --force (the escape hatch).
    let e = build_intent(&paths, Action::Set, None, "NoSuchVar", "x", false).unwrap_err();
    let CmdError::BadInput(m) = e else { panic!() };
    assert!(m.contains("--force"));
}

/// Unknown var WITH force → warning, proceed.
#[test]
fn intent_unknown_var_force_proceeds() {
    let cd = setup("alice");
    let paths = cd.paths().clone();
    let (intent, warns) = build_intent(&paths, Action::Set, None, "NoSuchVar", "x", true).unwrap();
    assert_eq!(intent.variable, "NoSuchVar"); // user's casing survives
    assert_eq!(intent.node, None); // unknown → tinc.conf
    assert_eq!(warns.len(), 1);
    assert!(matches!(&warns[0], Warning::Unknown(v) if v == "NoSuchVar"));
}

/// `get`/`del` on unknown var: warning but proceed (no force
/// needed). Reading or deleting something the table doesn't
/// know about is safe — you're not adding cruft, you might be
/// cleaning it up.
#[test]
fn intent_unknown_var_get_proceeds() {
    let cd = setup("alice");
    let paths = cd.paths().clone();
    let (intent, warns) = build_intent(&paths, Action::Get, None, "NoSuchVar", "", false).unwrap();
    assert_eq!(intent.action, Action::Get);
    assert!(matches!(&warns[0], Warning::Unknown(_)));
}

/// Obsolete var → error without force. Find one in the table.
#[test]
fn intent_obsolete_var_fails() {
    let cd = setup("alice");
    let paths = cd.paths().clone();
    // PrivateKey is OBSOLETE (the *file* var; the `PrivateKeyFile`
    // pointer-to-file is current). Check the table to be sure
    // this test isn't a false positive.
    let v = vars::lookup("PrivateKey").expect("PrivateKey is in the table");
    assert!(
        v.flags.contains(VarFlags::OBSOLETE),
        "test assumption: PrivateKey is obsolete"
    );

    let e = build_intent(&paths, Action::Set, None, "PrivateKey", "x", false).unwrap_err();
    let CmdError::BadInput(m) = e else { panic!() };
    assert!(m.contains("obsolete"));
}

/// Obsolete var on GET: fine. The check is set/add only.
#[test]
fn intent_obsolete_var_get_ok() {
    let cd = setup("alice");
    let paths = cd.paths().clone();
    let (intent, warns) = build_intent(&paths, Action::Get, None, "PrivateKey", "", false).unwrap();
    assert_eq!(intent.action, Action::Get);
    // No obsolete warning — the check doesn't fire for get.
    assert!(!warns.iter().any(|w| matches!(w, Warning::Obsolete(_))));
}

// Stage 3: run_get — read-only file walk

/// `run_get` table. Match is case-insensitive; no-match → empty
/// vec (the "no match → error" is in `run()`, not `run_get()`).
#[test]
fn get_table() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("tinc.conf");
    #[rustfmt::skip]
    let cases: &[(&str, &str, &[&str])] = &[
        //          (file_content,                            query,       expected)
        ("Name = alice\nPort = 655\n",             "Port",      &["655"]),
        ("ConnectTo = bob\nConnectTo = carol\n",   "ConnectTo", &["bob", "carol"]),
        // case-insensitive: `port` in file matches `Port` query
        ("port = 655\n",                           "Port",      &["655"]),
        // no match → empty
        ("Name = alice\n",                         "Port",      &[]),
    ];
    for (content, var, expected) in cases {
        fs::write(&f, content).unwrap();
        assert_eq!(
            run_get(&f, var).unwrap(),
            *expected,
            "var={var:?} content={content:?}"
        );
    }
}

#[test]
fn get_file_missing() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("nonexistent");
    let e = run_get(&f, "Port").unwrap_err();
    assert!(matches!(e, CmdError::Io { .. }));
}

// Stage 3: run_edit — the big one

/// Helper: build an Intent without going through stage 2. Tests
/// the file walk in isolation.
fn intent(action: Action, var: &str, val: &str, warn: bool) -> Intent {
    Intent {
        action,
        variable: var.to_owned(),
        value: val.to_owned(),
        node: None, // run_edit doesn't look at node; caller picks the path
        warn_on_remove: warn,
    }
}

#[test]
fn set_replaces_in_place() {
    let (_dir, f) =
        testutil::scratch_file("tinc.conf", "Name = alice\nPort = 655\nDevice = /dev/tun\n");

    run_edit(&f, &intent(Action::Set, "Port", "1234", false)).unwrap();

    // The Port line is replaced *at the same position*. Name
    // and Device stay where they were.
    assert_eq!(
        fs::read_to_string(&f).unwrap(),
        "Name = alice\nPort = 1234\nDevice = /dev/tun\n"
    );
}

/// SET when no match exists → append.
#[test]
fn set_appends_when_absent() {
    let (_dir, f) = testutil::scratch_file("tinc.conf", "Name = alice\n");

    run_edit(&f, &intent(Action::Set, "Port", "655", false)).unwrap();

    assert_eq!(
        fs::read_to_string(&f).unwrap(),
        "Name = alice\nPort = 655\n"
    );
}

/// SET on duplicate keys: first replaced, rest deleted. This is
/// what makes SET dangerous on MULTIPLE vars.
#[test]
fn set_collapses_duplicates() {
    // Weird config (Port shouldn't be dup, but a hand-edited
    // file might have it).
    let (_dir, f) = testutil::scratch_file("tinc.conf", "Port = 1\nPort = 2\nPort = 3\n");

    run_edit(&f, &intent(Action::Set, "Port", "999", false)).unwrap();

    // First replaced, second and third deleted.
    assert_eq!(fs::read_to_string(&f).unwrap(), "Port = 999\n");
}

/// SET with warnonremove: warning fires once per replaced line
/// whose value DIFFERS. Same value → no warning.
#[test]
fn set_warnonremove() {
    let (_dir, f) = testutil::scratch_file(
        "tinc.conf",
        "ConnectTo = bob\nConnectTo = carol\nConnectTo = dave\n",
    );

    // SET on a MULTIPLE var: stage-2 would set warnonremove.
    // We construct directly with warn=true to test the walk.
    let result = run_edit(&f, &intent(Action::Set, "ConnectTo", "carol", true)).unwrap();

    // Three matches: bob (differs → warn), carol (same → no warn),
    // dave (differs → warn). Case-insensitive diff check.
    assert_eq!(result.len(), 2);
    assert!(matches!(
        &result[0],
        Warning::Removing { old_value, .. } if old_value == "bob"
    ));
    assert!(matches!(
        &result[1],
        Warning::Removing { old_value, .. } if old_value == "dave"
    ));

    assert_eq!(fs::read_to_string(&f).unwrap(), "ConnectTo = carol\n");
}

/// SET canonicalizes the key in the output. `port = 655` in,
/// `Port = 1234` out.
#[test]
fn set_canonicalizes_key_case() {
    let (_dir, f) = testutil::scratch_file("tinc.conf", "port = 655\n");

    // The `variable` we pass is already canonical (stage 2 did
    // that). The walk writes it as-is.
    run_edit(&f, &intent(Action::Set, "Port", "1234", false)).unwrap();

    assert_eq!(fs::read_to_string(&f).unwrap(), "Port = 1234\n");
}

#[test]
fn add_appends() {
    let (_dir, f) = testutil::scratch_file("tinc.conf", "ConnectTo = bob\n");

    run_edit(&f, &intent(Action::Add, "ConnectTo", "carol", false)).unwrap();

    assert_eq!(
        fs::read_to_string(&f).unwrap(),
        "ConnectTo = bob\nConnectTo = carol\n"
    );
}

/// ADD when exact value already present → no-op.
#[test]
fn add_dedup_noop() {
    let (_dir, f) = testutil::scratch_file("tinc.conf", "ConnectTo = bob\n");

    run_edit(&f, &intent(Action::Add, "ConnectTo", "bob", false)).unwrap();

    // File unchanged. (Well, rewritten via tmpfile → rename,
    // but bytes identical.)
    assert_eq!(fs::read_to_string(&f).unwrap(), "ConnectTo = bob\n");
}

/// ADD dedup is case-insensitive on the value. `tinc add
/// ConnectTo Alice` after `ConnectTo = alice` is a no-op.
/// Probably correct — node names are case-folded elsewhere too
/// (`check_id` doesn't enforce case).
#[test]
fn add_dedup_case_insensitive() {
    let (_dir, f) = testutil::scratch_file("tinc.conf", "ConnectTo = alice\n");

    run_edit(&f, &intent(Action::Add, "ConnectTo", "ALICE", false)).unwrap();

    // The existing line survives WITH ITS ORIGINAL CASE. ADD
    // doesn't normalize, it just doesn't append.
    assert_eq!(fs::read_to_string(&f).unwrap(), "ConnectTo = alice\n");
}

#[test]
fn del_removes_all() {
    let (_dir, f) = testutil::scratch_file(
        "tinc.conf",
        "ConnectTo = bob\nName = x\nConnectTo = carol\n",
    );

    run_edit(&f, &intent(Action::Del, "ConnectTo", "", false)).unwrap();

    assert_eq!(fs::read_to_string(&f).unwrap(), "Name = x\n");
}

/// DEL with value filter: only matching lines removed.
#[test]
fn del_filtered() {
    let (_dir, f) = testutil::scratch_file("tinc.conf", "ConnectTo = bob\nConnectTo = carol\n");

    run_edit(&f, &intent(Action::Del, "ConnectTo", "bob", false)).unwrap();

    assert_eq!(fs::read_to_string(&f).unwrap(), "ConnectTo = carol\n");
}

/// DEL that matches nothing → error.
#[test]
fn del_nothing_fails() {
    let (_dir, f) = testutil::scratch_file("tinc.conf", "Name = alice\n");

    let e = run_edit(&f, &intent(Action::Del, "ConnectTo", "", false)).unwrap_err();
    assert!(matches!(e, CmdError::BadInput(m) if m == "No configuration variables deleted."));

    // And the original file is untouched.
    assert_eq!(fs::read_to_string(&f).unwrap(), "Name = alice\n");
}

/// DEL filter with no match (var exists but value doesn't) → error.
/// `tinc del ConnectTo nonexistent`.
#[test]
fn del_filter_no_match_fails() {
    let (_dir, f) = testutil::scratch_file("tinc.conf", "ConnectTo = bob\n");

    let e = run_edit(&f, &intent(Action::Del, "ConnectTo", "carol", false)).unwrap_err();
    assert!(matches!(e, CmdError::BadInput(_)));
    // Original survives.
    assert_eq!(fs::read_to_string(&f).unwrap(), "ConnectTo = bob\n");
}

/// Tmpfile is gone after a failed DEL. We do it via
/// `TmpGuard::drop`.
#[test]
fn tmpfile_cleaned_up_on_del_failure() {
    let (dir, f) = testutil::scratch_file("tinc.conf", "Name = alice\n");

    let _ = run_edit(&f, &intent(Action::Del, "Nonexistent", "", false));

    // No `.config.tmp` lying around.
    assert!(!dir.path().join("tinc.conf.config.tmp").exists());
}

/// File without trailing newline: edit must add one before any
/// append. Otherwise you get `Name = alicePort = 655`.
#[test]
fn edit_adds_newline_before_append() {
    let (_dir, f) = testutil::scratch_file("tinc.conf", "Name = alice"); // no trailing \n

    run_edit(&f, &intent(Action::Set, "Port", "655", false)).unwrap();

    assert_eq!(
        fs::read_to_string(&f).unwrap(),
        "Name = alice\nPort = 655\n"
    );
}

/// PEM block at the end of a host file. `tinc set Port 655`
/// must NOT mangle the base64 lines. The `split_line` tokenizer
/// returns `Some((garbage, garbage))` for them but they don't
/// match `Port`, so they copy verbatim.
#[test]
fn edit_preserves_pem() {
    let (_dir, f) = testutil::scratch_file(
        "hosts_alice",
        "\
Port = 655
-----BEGIN ED25519 PUBLIC KEY-----
MCowBQYDK2VwAyEAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=
-----END ED25519 PUBLIC KEY-----
",
    );

    run_edit(&f, &intent(Action::Set, "Port", "1234", false)).unwrap();

    // PEM block byte-identical. Only the Port line changed.
    let after = fs::read_to_string(&f).unwrap();
    assert!(after.starts_with("Port = 1234\n"));
    assert!(after.contains("-----BEGIN ED25519 PUBLIC KEY-----\n"));
    assert!(after.contains("MCowBQYDK2VwAyEA"));
    assert!(after.contains("-----END ED25519 PUBLIC KEY-----\n"));
    // Exactly four lines — nothing got duplicated or eaten.
    assert_eq!(after.lines().count(), 4);
}

/// Comment lines preserved verbatim. We don't parse `#`;
/// they're just lines whose key is `#` and don't match.
#[test]
fn edit_preserves_comments() {
    let (_dir, f) = testutil::scratch_file("tinc.conf", "# this is alice's config\nName = alice\n");

    run_edit(&f, &intent(Action::Set, "Port", "655", false)).unwrap();

    let after = fs::read_to_string(&f).unwrap();
    assert!(after.starts_with("# this is alice's config\n"));
}

/// Edit on a file we can't read → error, no tmpfile created.
#[test]
fn edit_file_missing() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("nonexistent");
    let e = run_edit(&f, &intent(Action::Set, "Port", "655", false)).unwrap_err();
    assert!(matches!(e, CmdError::Io { .. }));
    // No `.config.tmp` — we never got that far.
    assert!(!dir.path().join("nonexistent.config.tmp").exists());
}

// run() — full pipeline

/// `ConfDir::with_name` + conf body, with a resolved pidfile
/// pointing at a nonexistent path so the Port-from-pidfile
/// read fails silently and falls back to config scan.
fn setup_full(name: &str, conf_body: &str) -> (ConfDir, Paths) {
    let cd = ConfDir::with_name(name).append_conf(conf_body);
    let input = PathsInput {
        confbase: Some(cd.confbase().to_owned()),
        pidfile: Some(cd.path().join("no.pid")),
        ..Default::default()
    };
    let mut paths = Paths::for_cli(&input);
    // `get Port` calls `paths.pidfile()`, which panics if unresolved.
    paths.resolve_runtime(&input);
    (cd, paths)
}

#[test]
fn run_full_get() {
    let (_d, paths) = setup_full("alice", "Device = /dev/tun\n");
    let (out, _) = run(&paths, Action::Get, "Device", false).unwrap();
    let ConfigOutput::Got(vals) = out else {
        panic!("expected Got")
    };
    assert_eq!(vals, vec!["/dev/tun"]);
}

#[test]
fn run_full_get_not_found() {
    let (_d, paths) = setup_full("alice", "");
    let e = run(&paths, Action::Get, "Device", false).unwrap_err();
    assert!(
        matches!(e, CmdError::BadInput(m) if m == "No matching configuration variables found.")
    );
}

/// The full `tinc add Subnet 10.0.0.0/24` path: stage 2 routes
/// to hosts/alice (Subnet is HOST-only), stage 3 appends.
#[test]
fn run_full_add_subnet_to_host_file() {
    let (d, paths) = setup_full("alice", "");
    run(&paths, Action::Add, "Subnet 10.0.0.0/24", false).unwrap();

    // Went to hosts/alice, not tinc.conf.
    let host = fs::read_to_string(d.path().join("vpn/hosts/alice")).unwrap();
    assert_eq!(host, "Subnet = 10.0.0.0/24\n");
    // tinc.conf untouched.
    let conf = fs::read_to_string(d.path().join("vpn/tinc.conf")).unwrap();
    assert_eq!(conf, "Name = alice\n");
}

/// `tinc set bob.Subnet 10.0.0.0/24` writes to hosts/bob even
/// though we're alice. The explicit node prefix wins.
#[test]
fn run_full_explicit_node() {
    let (d, paths) = setup_full("alice", "");
    // hosts/bob must exist for the read to succeed.
    fs::write(d.path().join("vpn/hosts/bob"), "").unwrap();

    run(&paths, Action::Set, "bob.Subnet 10.0.0.0/24", false).unwrap();

    let bob = fs::read_to_string(d.path().join("vpn/hosts/bob")).unwrap();
    assert_eq!(bob, "Subnet = 10.0.0.0/24\n");
}

/// `tinc get Port` with daemon running (pidfile exists): returns
/// the *runtime* port from the pidfile, NOT the configured one.
/// `Port = 0` is the use case — daemon picks a free port.
#[test]
fn run_get_port_from_pidfile() {
    // Config says Port = 0.
    let cd = ConfDir::with_name("alice").append_conf("Port = 0\n");
    // Pidfile says the actual port is 47123.
    let pidfile = cd.path().join("tinc.pid");
    let cookie = "a".repeat(64);
    fs::write(&pidfile, format!("1 {cookie} 127.0.0.1 port 47123\n")).unwrap();

    let input = PathsInput {
        confbase: Some(cd.confbase().to_owned()),
        pidfile: Some(pidfile),
        ..Default::default()
    };
    let mut paths = Paths::for_cli(&input);
    paths.resolve_runtime(&input);

    let (out, _) = run(&paths, Action::Get, "Port", false).unwrap();
    let ConfigOutput::Got(vals) = out else {
        panic!()
    };
    // 47123 from the pidfile, NOT 0 from the config.
    assert_eq!(vals, vec!["47123"]);
}

/// `tinc get Port` with no daemon (pidfile missing): falls back
/// to scanning hosts/$me (Port is HOST-only). Upstream would
/// print a stderr warning here; we silently fall back (see
/// module doc).
#[test]
fn run_get_port_fallback_to_config() {
    let (d, paths) = setup_full("alice", "");
    // Port is HOST-only → lives in hosts/alice, not tinc.conf.
    // setup_full creates an empty hosts/alice; overwrite.
    fs::write(d.path().join("vpn/hosts/alice"), "Port = 655\n").unwrap();

    // setup_full's pidfile points nowhere → read fails → fallback.
    let (out, _) = run(&paths, Action::Get, "Port", false).unwrap();
    let ConfigOutput::Got(vals) = out else {
        panic!()
    };
    assert_eq!(vals, vec!["655"]);
}

/// `tinc get alice.Port` does NOT take the pidfile path —
/// explicit node means "the configured port for that host
/// file", not "the running daemon's port". The check runs
/// before any node resolution; the explicit node short-circuits.
#[test]
fn run_get_port_explicit_node_skips_pidfile() {
    // hosts/alice has Port = 1234. Pidfile would say 47123 but we
    // must never read it for an explicit-node get.
    let cd = ConfDir::with_name("alice").with_host("alice", "Port = 1234\n");
    let pidfile = cd.path().join("tinc.pid");
    let cookie = "a".repeat(64);
    fs::write(&pidfile, format!("1 {cookie} 127.0.0.1 port 47123\n")).unwrap();

    let input = PathsInput {
        confbase: Some(cd.confbase().to_owned()),
        pidfile: Some(pidfile),
        ..Default::default()
    };
    let mut paths = Paths::for_cli(&input);
    paths.resolve_runtime(&input);

    // `alice.Port` — explicit node prefix.
    let (out, _) = run(&paths, Action::Get, "alice.Port", false).unwrap();
    let ConfigOutput::Got(vals) = out else {
        panic!()
    };
    // 1234 from hosts/alice, NOT 47123 from the pidfile.
    // Proves the `explicit_node.is_none()` guard in run().
    assert_eq!(vals, vec!["1234"]);
}

/// End-to-end: `tinc get Port 655` is the same as `tinc set
/// Port 655`. The get-with-value coercion.
#[test]
fn run_get_with_value_is_set() {
    let (d, paths) = setup_full("alice", "");
    run(&paths, Action::Get, "Device /dev/tun", false).unwrap();

    // Device was set, not gotten.
    let conf = fs::read_to_string(d.path().join("vpn/tinc.conf")).unwrap();
    assert!(conf.contains("Device = /dev/tun\n"));
}

// Compatibility tests — behaviors that would be easy to get
// subtly wrong.

/// warnonremove's "same value, no warning" check is case-
/// insensitive. Setting `ConnectTo = Alice` over `ConnectTo =
/// alice` is a no-warn (you're not losing anything; it's the
/// same node).
#[test]
fn warnonremove_case_insensitive() {
    let (_dir, f) = testutil::scratch_file("tinc.conf", "ConnectTo = alice\n");

    let result = run_edit(&f, &intent(Action::Set, "ConnectTo", "ALICE", true)).unwrap();

    // Value differs only in case → no warning.
    assert!(result.is_empty());
}

/// get→set coercion happens BEFORE the pidfile-port read. So
/// `tinc get Port 655` does NOT read the pidfile — by the time
/// we'd check, action is already SET. (Our impl checks
/// `value.is_empty()` separately, which gives the same result.
/// This test pins that they're equivalent.)
#[test]
fn get_port_with_value_skips_pidfile() {
    let cd = ConfDir::with_name("alice");
    // Pidfile is BROKEN — if run() reads it, parse fails. If it
    // correctly skips (value non-empty), we never touch it.
    let pidfile = cd.path().join("tinc.pid");
    fs::write(&pidfile, "garbage\n").unwrap();

    let input = PathsInput {
        confbase: Some(cd.confbase().to_owned()),
        pidfile: Some(pidfile),
        ..Default::default()
    };
    let mut paths = Paths::for_cli(&input);
    paths.resolve_runtime(&input);

    // `get Port 655` → set. If this tried to read the broken
    // pidfile we'd... actually fall back silently. So we need
    // a positive assertion: the SET happened.
    // Port is HOST-only → the set goes to hosts/alice.
    run(&paths, Action::Get, "Port 655", false).unwrap();
    let host = fs::read_to_string(paths.hosts_dir().join("alice")).unwrap();
    assert!(host.contains("Port = 655\n"));
}

/// The `!node && !(type & VAR_SERVER)` condition uses
/// NOT-SERVER, not HAS-HOST. A var with NEITHER flag (which
/// doesn't exist in the real table, but the logic admits it)
/// would resolve to hosts/$me. Only SERVER → tinc.conf. The
/// dual-tagged test above covers HAS-BOTH; this covers the
/// symmetry.
///
/// We can't test with a real var (every var has SERVER or
/// HOST), but we CAN check that the test's understanding of
/// the condition is correct by reading the table: every var
/// lacking SERVER must have HOST.
#[test]
fn every_nonserver_var_is_host() {
    // Trip-wire on the variables table. The build_intent logic
    // assumes !SERVER ⇒ must resolve to a host file via
    // get_my_name. If a var were neither SERVER nor HOST, that
    // resolution would still happen but the var wouldn't make
    // sense in a host file. Assert no such var exists.
    for v in vars::VARS {
        assert!(
            v.flags.contains(VarFlags::SERVER) || v.flags.contains(VarFlags::HOST),
            "{} has neither SERVER nor HOST; build_intent's !SERVER\
             ⇒ hosts/$me assumption breaks",
            v.name
        );
    }
}
