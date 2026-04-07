use super::keys::TY_PUBLIC;
use super::*;
use crate::keypair;
use crate::names::PathsInput;
use std::io::Write;
use tinc_crypto::b64;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Build a `Paths` rooted at a tempdir's child. The child doesn't
/// exist yet — tests that need it call `tinc init` (via the
/// helpers below) to create it.
fn paths_at(dir: &tempfile::TempDir) -> (PathBuf, Paths) {
    let confbase = dir.path().join("vpn");
    let paths = Paths::for_cli(&PathsInput {
        confbase: Some(confbase.clone()),
        ..Default::default()
    });
    (confbase, paths)
}

/// `tinc init NAME` via the function, not the binary. Creates
/// the full dir tree + keys. Unit-test scope; the binary is for
/// integration tests.
fn init(paths: &Paths, name: &str) {
    crate::cmd::init::run(paths, name).unwrap();
}

/// Count findings matching a predicate. Shorter than the
/// `iter().filter().count()` chain at every assert site.
fn count<F: Fn(&Finding) -> bool>(report: &Report, f: F) -> usize {
    report.findings.iter().filter(|x| f(x)).count()
}

// Phase 0: tinc.conf existence

/// Clean `tinc init` → fsck passes, zero findings. The contract
/// test: `init` and `fsck` must agree on what "clean" means. If
/// `init` ever starts writing something fsck warns about, this
/// catches it.
#[test]
fn clean_init_passes() {
    let dir = tempfile::tempdir().unwrap();
    let (_, paths) = paths_at(&dir);
    init(&paths, "alice");

    let r = run(&paths, false).unwrap();
    assert!(r.ok, "clean init should pass: {:?}", r.findings);
    assert!(
        r.findings.is_empty(),
        "clean init should have zero findings: {:?}",
        r.findings
    );
}

/// No `tinc.conf` at all → `TincConfMissing`, fail. The
/// suggestion mentions `init`.
#[test]
fn no_tincconf() {
    let dir = tempfile::tempdir().unwrap();
    let (confbase, paths) = paths_at(&dir);
    fs::create_dir_all(&confbase).unwrap();
    // Dir exists but is empty.

    let r = run(&paths, false).unwrap();
    assert!(!r.ok);
    assert_eq!(count(&r, |f| matches!(f, Finding::TincConfMissing)), 1);
    // The suggestion text.
    let f = &r.findings[0];
    assert!(f.suggestion("tinc -c /x").unwrap().contains("init"));
}

/// `tinc.conf` exists but no `Name =` → `NoName`.
#[test]
fn no_name() {
    let dir = tempfile::tempdir().unwrap();
    let (confbase, paths) = paths_at(&dir);
    fs::create_dir_all(&confbase).unwrap();
    // tinc.conf with stuff but no Name.
    fs::write(confbase.join("tinc.conf"), "Port = 655\n").unwrap();

    let r = run(&paths, false).unwrap();
    assert!(!r.ok);
    assert_eq!(count(&r, |f| matches!(f, Finding::NoName)), 1);
}

// Phase 2: Keypair

/// `ed25519_key.priv` deleted → `NoPrivateKey`, fail. The
/// suggestion mentions `generate-ed25519-keys`.
#[test]
fn no_private_key() {
    let dir = tempfile::tempdir().unwrap();
    let (confbase, paths) = paths_at(&dir);
    init(&paths, "alice");
    fs::remove_file(confbase.join("ed25519_key.priv")).unwrap();

    let r = run(&paths, false).unwrap();
    assert!(!r.ok);
    let f = r
        .findings
        .iter()
        .find(|f| matches!(f, Finding::NoPrivateKey { .. }))
        .unwrap();
    assert!(
        f.suggestion("tinc -c /x")
            .unwrap()
            .contains("generate-ed25519-keys")
    );
    // Phase 4+5 still ran (`&` not `&&` semantics). No findings
    // from them on a clean init, but the absence of
    // a panic proves we didn't short-circuit.
}

/// `Ed25519PrivateKeyFile` config respected. The default-location
/// key is gone, but the config points elsewhere.
///
/// This is the check that genkey/sign DON'T do (see module doc) —
/// fsck has the config tree, they don't. Pinning fsck's behavior
/// here so when we fix sign, this test is the reference.
#[test]
fn private_key_file_config() {
    let dir = tempfile::tempdir().unwrap();
    let (confbase, paths) = paths_at(&dir);
    init(&paths, "alice");

    // Move the private key elsewhere.
    let alt = confbase.join("my_key.pem");
    fs::rename(confbase.join("ed25519_key.priv"), &alt).unwrap();
    // Tell tinc.conf where it is. Append (init wrote `Name =`).
    let mut tc = fs::OpenOptions::new()
        .append(true)
        .open(confbase.join("tinc.conf"))
        .unwrap();
    writeln!(tc, "Ed25519PrivateKeyFile = {}", alt.display()).unwrap();

    let r = run(&paths, false).unwrap();
    assert!(r.ok, "should find the relocated key: {:?}", r.findings);
    assert_eq!(count(&r, |f| matches!(f, Finding::NoPrivateKey { .. })), 0);
}

/// `hosts/NAME` deleted entirely → `ConfigReadFailed`. Phase 1
/// (`parse_file(hosts/NAME)`) fails before the keypair check can
/// run. C: `read_host_config` returns false → `success = false`
/// → `if(success) check_keypairs` skipped. Same here.
///
/// (Initially I expected `NoPublicKey` here. Wrong: `NoPublicKey`
/// is for "file exists but has no key", not "file is gone". The
/// distinction matters because the suggestion differs — missing
/// file is `tinc init`-level breakage, missing-key-in-file is
/// a `--force` fix.)
#[test]
fn host_file_deleted() {
    let dir = tempfile::tempdir().unwrap();
    let (confbase, paths) = paths_at(&dir);
    init(&paths, "alice");
    fs::remove_file(confbase.join("hosts/alice")).unwrap();

    let r = run(&paths, false).unwrap();
    assert!(!r.ok);
    // ConfigReadFailed, NOT NoPublicKey. Phase 1 failed.
    assert_eq!(count(&r, |f| matches!(f, Finding::ConfigReadFailed(_))), 1);
    assert_eq!(count(&r, |f| matches!(f, Finding::NoPublicKey { .. })), 0);
}

/// `hosts/NAME` exists but has no pubkey (just `Subnet =` etc.)
/// → `NoPublicKey`, fail. THIS is the path where the keypair
/// check runs and finds nothing. NOT fixable without `--force`.
#[test]
fn no_public_key() {
    let dir = tempfile::tempdir().unwrap();
    let (confbase, paths) = paths_at(&dir);
    init(&paths, "alice");
    // Replace hosts/alice with config-only content. No pubkey,
    // no PEM block. `parse_file` succeeds (it's valid config),
    // `load_ec_pubkey` returns None.
    fs::write(confbase.join("hosts/alice"), "Subnet = 10.0.0.0/24\n").unwrap();

    let r = run(&paths, false).unwrap();
    assert!(!r.ok);
    assert_eq!(count(&r, |f| matches!(f, Finding::NoPublicKey { .. })), 1);
    // File IS readable (we just wrote it); no early-warning.
    assert_eq!(
        count(&r, |f| matches!(f, Finding::HostFileUnreadable { .. })),
        0
    );
    // No fix attempted.
    assert_eq!(
        count(&r, |f| matches!(f, Finding::FixedPublicKey { .. })),
        0
    );
}

/// `hosts/NAME` has the WRONG pubkey → `KeyMismatch`, fail.
/// The most realistic broken-config case: somebody copied a
/// `hosts/alice` from a different node.
#[test]
fn key_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let (confbase, paths) = paths_at(&dir);
    init(&paths, "alice");

    // Overwrite hosts/alice with a different pubkey. We use a
    // freshly-generated one so it's a *valid* pubkey, just wrong.
    // (An invalid b64 would hit a different code path —
    // `load_ec_pubkey` returns None on bad b64.)
    let other = keypair::generate();
    let other_b64 = b64::encode(other.public_key());
    fs::write(
        confbase.join("hosts/alice"),
        format!("Ed25519PublicKey = {other_b64}\n"),
    )
    .unwrap();

    let r = run(&paths, false).unwrap();
    // The tightening (see check_keypairs comment): unfixed
    // mismatch is a *fail*, not a pass. C returns true here
    // (the "decline = success" weirdness). We don't.
    assert!(!r.ok);
    assert_eq!(count(&r, |f| matches!(f, Finding::KeyMismatch { .. })), 1);
}

/// `KeyMismatch` + `--force` → `FixedPublicKey`, pass. The
/// hosts/alice file gets `disable_old_keys` + a fresh PEM block.
/// **Contract test**: re-run fsck on the fixed file; it must pass.
#[test]
fn key_mismatch_force_fixes() {
    let dir = tempfile::tempdir().unwrap();
    let (confbase, paths) = paths_at(&dir);
    init(&paths, "alice");

    let other = keypair::generate();
    let other_b64 = b64::encode(other.public_key());
    fs::write(
        confbase.join("hosts/alice"),
        format!("Ed25519PublicKey = {other_b64}\n"),
    )
    .unwrap();

    // First fsck: --force.
    let r1 = run(&paths, true).unwrap();
    assert!(r1.ok, "--force should fix and pass: {:?}", r1.findings);
    assert_eq!(count(&r1, |f| matches!(f, Finding::KeyMismatch { .. })), 1);
    assert_eq!(
        count(&r1, |f| matches!(f, Finding::FixedPublicKey { .. })),
        1
    );

    // The file shape: old config-line is `#`-commented, new
    // PEM block appended. PEM-not-config-line per module doc.
    let host = fs::read_to_string(confbase.join("hosts/alice")).unwrap();
    assert!(host.starts_with("#Ed25519PublicKey ="));
    assert!(host.contains("-----BEGIN ED25519 PUBLIC KEY-----"));

    // Second fsck: no force. Clean now.
    let r2 = run(&paths, false).unwrap();
    assert!(r2.ok, "second fsck should be clean: {:?}", r2.findings);
    assert!(r2.findings.is_empty());
}

/// `NoPublicKey` + `--force` → PEM block appended. Then fsck-
/// again passes. The `disable_old_keys` is a no-op (no key lines
/// to comment).
#[test]
fn no_public_key_force_fixes() {
    let dir = tempfile::tempdir().unwrap();
    let (confbase, paths) = paths_at(&dir);
    init(&paths, "alice");
    // Existing config with no pubkey.
    fs::write(confbase.join("hosts/alice"), "Subnet = 10.0.0.0/24\n").unwrap();

    let r1 = run(&paths, true).unwrap();
    assert!(r1.ok, "--force should fix and pass: {:?}", r1.findings);
    assert_eq!(
        count(&r1, |f| matches!(f, Finding::FixedPublicKey { .. })),
        1
    );

    // File shape: original Subnet line preserved (no `#` —
    // disable_old_keys had nothing to match), PEM block appended.
    let host = fs::read_to_string(confbase.join("hosts/alice")).unwrap();
    assert!(host.starts_with("Subnet = 10.0.0.0/24\n"));
    assert!(host.contains("-----BEGIN ED25519 PUBLIC KEY-----"));
    assert!(!host.contains('#'));

    let r2 = run(&paths, false).unwrap();
    assert!(r2.ok, "second fsck should be clean: {:?}", r2.findings);
}

/// `Ed25519PublicKey` with bad b64 → `NoPublicKey` (NOT
/// `KeyMismatch`). The `b64::decode` failure means "no usable
/// pubkey"; we don't fall through to PEM. Upstream returns NULL
/// on bad b64, and
/// `read_ecdsa_public_key` returns that NULL, no PEM fallback.
#[test]
fn bad_b64_is_no_pubkey() {
    let dir = tempfile::tempdir().unwrap();
    let (confbase, paths) = paths_at(&dir);
    init(&paths, "alice");

    // Bad b64: `!` isn't in the alphabet.
    fs::write(
        confbase.join("hosts/alice"),
        "Ed25519PublicKey = !!!!!!!!!!!\n",
    )
    .unwrap();

    let r = run(&paths, false).unwrap();
    assert!(!r.ok);
    // NoPublicKey, not KeyMismatch — "no usable pubkey".
    assert_eq!(count(&r, |f| matches!(f, Finding::NoPublicKey { .. })), 1);
    assert_eq!(count(&r, |f| matches!(f, Finding::KeyMismatch { .. })), 0);
}

/// PEM-form pubkey in hosts file works (the fallback path).
/// fsck `--force` writes PEM, so fsck-after-fsck-force must read
/// PEM. Covered implicitly by `key_mismatch_force_fixes`; this
/// covers it explicitly with a hand-written PEM.
#[test]
fn pem_pubkey_read() {
    let dir = tempfile::tempdir().unwrap();
    let (confbase, paths) = paths_at(&dir);
    init(&paths, "alice");

    // Read the *correct* pubkey from the priv key.
    let sk = keypair::read_private(&confbase.join("ed25519_key.priv")).unwrap();
    let pk = sk.public_key();

    // Write it as PEM, not config-line.
    let mut buf = Vec::new();
    tinc_conf::pem::write_pem(&mut buf, TY_PUBLIC, pk).unwrap();
    fs::write(confbase.join("hosts/alice"), &buf).unwrap();

    let r = run(&paths, false).unwrap();
    assert!(r.ok, "PEM-form pubkey should pass: {:?}", r.findings);
}

// Phase 3: Key file mode

/// 0640 priv key → `UnsafeKeyMode` warning. Doesn't fail fsck
/// (it's a warning, and the keypair check still passes).
#[cfg(unix)]
#[test]
fn unsafe_key_mode_warns() {
    let dir = tempfile::tempdir().unwrap();
    let (confbase, paths) = paths_at(&dir);
    init(&paths, "alice");

    let priv_path = confbase.join("ed25519_key.priv");
    fs::set_permissions(&priv_path, fs::Permissions::from_mode(0o640)).unwrap();

    let r = run(&paths, false).unwrap();
    // Still ok — it's a warning, not an error. The C returns
    // success here too (mode check is `void`, doesn't contribute
    // to `success`).
    assert!(r.ok);
    let f = r
        .findings
        .iter()
        .find(|f| matches!(f, Finding::UnsafeKeyMode { .. }))
        .unwrap();
    // We own the file (we just created it).
    assert!(matches!(
        f,
        Finding::UnsafeKeyMode {
            uid_match: true,
            ..
        }
    ));
    // The mode is what we set, modulo type bits.
    let Finding::UnsafeKeyMode { mode, .. } = f else {
        unreachable!()
    };
    assert_eq!(mode & 0o777, 0o640);
}

/// 0640 + `--force` → `FixedMode`, file is now 0600.
#[cfg(unix)]
#[test]
fn unsafe_key_mode_force_fixes() {
    let dir = tempfile::tempdir().unwrap();
    let (confbase, paths) = paths_at(&dir);
    init(&paths, "alice");

    let priv_path = confbase.join("ed25519_key.priv");
    fs::set_permissions(&priv_path, fs::Permissions::from_mode(0o640)).unwrap();

    let r = run(&paths, true).unwrap();
    assert!(r.ok);
    assert_eq!(count(&r, |f| matches!(f, Finding::FixedMode { .. })), 1);

    // The fix is `chmod(mode & ~077)`. From 0640:
    // `0640 & ~077 = 0600`. Verify.
    let mode = fs::metadata(&priv_path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}

// Phase 4: Scripts

/// `tinc-up` made non-executable → `ScriptNotExecutable`.
#[cfg(unix)]
#[test]
fn script_not_exec_warns() {
    let dir = tempfile::tempdir().unwrap();
    let (confbase, paths) = paths_at(&dir);
    init(&paths, "alice");

    // init creates tinc-up at 0755. Chmod it down.
    let up = confbase.join("tinc-up");
    fs::set_permissions(&up, fs::Permissions::from_mode(0o644)).unwrap();

    let r = run(&paths, false).unwrap();
    // Warning, not error. The exec check always returns true
    // regardless.
    assert!(r.ok);
    assert_eq!(
        count(&r, |f| matches!(f, Finding::ScriptNotExecutable { .. })),
        1
    );
}

/// Non-exec + `--force` → `chmod 0755`.
#[cfg(unix)]
#[test]
fn script_not_exec_force_fixes() {
    let dir = tempfile::tempdir().unwrap();
    let (confbase, paths) = paths_at(&dir);
    init(&paths, "alice");

    let up = confbase.join("tinc-up");
    fs::set_permissions(&up, fs::Permissions::from_mode(0o644)).unwrap();

    let r = run(&paths, true).unwrap();
    assert!(r.ok);
    assert_eq!(count(&r, |f| matches!(f, Finding::FixedMode { .. })), 1);

    let mode = fs::metadata(&up).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o755);
}

/// `mystery-up` in confbase → `UnknownScript`. The `*-up`/`*-down`
/// suffix matches but the prefix isn't tinc/host/subnet.
#[test]
fn unknown_script() {
    let dir = tempfile::tempdir().unwrap();
    let (confbase, paths) = paths_at(&dir);
    init(&paths, "alice");

    fs::write(confbase.join("mystery-up"), "#!/bin/sh\n").unwrap();

    let r = run(&paths, false).unwrap();
    // Warning only.
    assert!(r.ok);
    let f = r
        .findings
        .iter()
        .find(|f| matches!(f, Finding::UnknownScript { .. }))
        .unwrap();
    let Finding::UnknownScript { path } = f else {
        unreachable!()
    };
    assert!(path.ends_with("mystery-up"));
}

/// All six valid prefixes recognized. The full set: `tinc`,
/// `host`, `subnet` × `-up`, `-down`.
#[cfg(unix)]
#[test]
fn all_known_scripts() {
    let dir = tempfile::tempdir().unwrap();
    let (confbase, paths) = paths_at(&dir);
    init(&paths, "alice");

    // init created tinc-up. Add the others.
    for s in &[
        "tinc-down",
        "host-up",
        "host-down",
        "subnet-up",
        "subnet-down",
    ] {
        let p = confbase.join(s);
        fs::write(&p, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
    }

    let r = run(&paths, false).unwrap();
    assert!(r.ok);
    // No UnknownScript, no ScriptNotExecutable.
    assert_eq!(count(&r, |f| matches!(f, Finding::UnknownScript { .. })), 0);
    assert_eq!(
        count(&r, |f| matches!(f, Finding::ScriptNotExecutable { .. })),
        0
    );
}

/// `hosts/alice-up` (per-host script) is checked for executability
/// but NOT for prefix validity. Any `*-up` in `hosts/` is a node
/// script.
#[cfg(unix)]
#[test]
fn host_scripts_any_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let (confbase, paths) = paths_at(&dir);
    init(&paths, "alice");

    // `whatever-up` would be unknown in confbase. In hosts/ it's
    // "the script for node `whatever`".
    let s = confbase.join("hosts/whatever-up");
    fs::write(&s, "#!/bin/sh\n").unwrap();
    fs::set_permissions(&s, fs::Permissions::from_mode(0o644)).unwrap();

    let r = run(&paths, false).unwrap();
    // No UnknownScript (hosts/ doesn't validate prefix).
    assert_eq!(count(&r, |f| matches!(f, Finding::UnknownScript { .. })), 0);
    // BUT: not executable, so warned.
    assert_eq!(
        count(&r, |f| matches!(f, Finding::ScriptNotExecutable { .. })),
        1
    );
}

/// Non-script files in confbase are ignored. `tinc.conf`,
/// `ed25519_key.priv` etc. don't end in `-up`/`-down`.
#[test]
fn non_scripts_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let (confbase, paths) = paths_at(&dir);
    init(&paths, "alice");

    // A junk file with no -up/-down suffix.
    fs::write(confbase.join("README"), "hello\n").unwrap();
    // A file ending in `-up` but not as a suffix-match: nope,
    // `-up` IS a suffix match. Let's do something that almost
    // matches: `-ups`.
    fs::write(confbase.join("backup-ups"), "data\n").unwrap();

    let r = run(&paths, false).unwrap();
    // Neither is a script. Zero script-related findings.
    assert_eq!(
        count(&r, |f| matches!(
            f,
            Finding::UnknownScript { .. }
                | Finding::ScriptNotExecutable { .. }
                | Finding::ScriptAccessError { .. }
        )),
        0
    );
}

// Phase 5: Variables

/// `GraphDumpFile` in tinc.conf → `ObsoleteVar`.
#[test]
fn obsolete_var() {
    let dir = tempfile::tempdir().unwrap();
    let (confbase, paths) = paths_at(&dir);
    init(&paths, "alice");

    let mut tc = fs::OpenOptions::new()
        .append(true)
        .open(confbase.join("tinc.conf"))
        .unwrap();
    writeln!(tc, "GraphDumpFile = /tmp/graph").unwrap();

    let r = run(&paths, false).unwrap();
    // Warning only.
    assert!(r.ok);
    let f = r
        .findings
        .iter()
        .find(|f| matches!(f, Finding::ObsoleteVar { .. }))
        .unwrap();
    let Finding::ObsoleteVar { name, .. } = f else {
        unreachable!()
    };
    // User's case preserved (we typed `GraphDumpFile`; that's
    // what's in entry.variable).
    assert_eq!(name, "GraphDumpFile");
}

/// `Port` in tinc.conf → `HostVarInServer`. The most common
/// real-world warning. `Port` is `VAR_HOST` only — your own port
/// goes in `hosts/YOU`, not `tinc.conf`.
#[test]
fn host_var_in_server() {
    let dir = tempfile::tempdir().unwrap();
    let (confbase, paths) = paths_at(&dir);
    init(&paths, "alice");

    let mut tc = fs::OpenOptions::new()
        .append(true)
        .open(confbase.join("tinc.conf"))
        .unwrap();
    writeln!(tc, "Port = 655").unwrap();

    let r = run(&paths, false).unwrap();
    assert!(r.ok); // warning
    let f = r
        .findings
        .iter()
        .find(|f| matches!(f, Finding::HostVarInServer { .. }))
        .unwrap();
    let Finding::HostVarInServer { name, source } = f else {
        unreachable!()
    };
    assert_eq!(name, "Port");
    // Source carries the file + line. tinc.conf, line 2 (init
    // wrote `Name = alice` on line 1).
    let Source::File { path, line } = source else {
        panic!("expected File source")
    };
    assert!(path.ends_with("tinc.conf"));
    assert_eq!(*line, 2);
}

/// `Device` in `hosts/alice` → `ServerVarInHost`. Rarer; here
/// for symmetry.
#[test]
fn server_var_in_host() {
    let dir = tempfile::tempdir().unwrap();
    let (confbase, paths) = paths_at(&dir);
    init(&paths, "alice");

    let mut hf = fs::OpenOptions::new()
        .append(true)
        .open(confbase.join("hosts/alice"))
        .unwrap();
    writeln!(hf, "Device = /dev/net/tun").unwrap();

    let r = run(&paths, false).unwrap();
    assert!(r.ok);
    assert_eq!(
        count(&r, |f| matches!(f, Finding::ServerVarInHost { .. })),
        1
    );
}

/// Two `Name =` lines → `DuplicateVar`. `Name` is non-MULTIPLE.
/// **The only place that surfaces silent-first-wins** — the
/// daemon would silently use the first.
#[test]
fn duplicate_non_multiple() {
    let dir = tempfile::tempdir().unwrap();
    let (confbase, paths) = paths_at(&dir);
    init(&paths, "alice");

    let mut tc = fs::OpenOptions::new()
        .append(true)
        .open(confbase.join("tinc.conf"))
        .unwrap();
    writeln!(tc, "Name = bob").unwrap();

    let r = run(&paths, false).unwrap();
    assert!(r.ok);
    let f = r
        .findings
        .iter()
        .find(|f| matches!(f, Finding::DuplicateVar { .. }))
        .unwrap();
    let Finding::DuplicateVar { name, where_ } = f else {
        unreachable!()
    };
    // Canonical case from VARS, not user's case.
    assert_eq!(name, "Name");
    // Server check → "tinc.conf" (the literal string, not a path).
    assert_eq!(where_, "tinc.conf");
}

/// Two `Subnet =` lines → NO duplicate warning. `Subnet` is
/// `VAR_MULTIPLE`. Multi-homed nodes have many subnets.
#[test]
fn duplicate_multiple_ok() {
    let dir = tempfile::tempdir().unwrap();
    let (confbase, paths) = paths_at(&dir);
    init(&paths, "alice");

    let mut hf = fs::OpenOptions::new()
        .append(true)
        .open(confbase.join("hosts/alice"))
        .unwrap();
    writeln!(hf, "Subnet = 10.0.0.0/24").unwrap();
    writeln!(hf, "Subnet = 10.1.0.0/24").unwrap();

    let r = run(&paths, false).unwrap();
    assert!(r.ok);
    assert_eq!(count(&r, |f| matches!(f, Finding::DuplicateVar { .. })), 0);
}

/// Unknown var → silent skip. NOT a warning. The TODO(feature)
/// case.
#[test]
fn unknown_var_silent() {
    let dir = tempfile::tempdir().unwrap();
    let (confbase, paths) = paths_at(&dir);
    init(&paths, "alice");

    let mut tc = fs::OpenOptions::new()
        .append(true)
        .open(confbase.join("tinc.conf"))
        .unwrap();
    // Typo: `Prot` instead of `Port`. Not in VARS.
    writeln!(tc, "Prot = 655").unwrap();

    let r = run(&paths, false).unwrap();
    assert!(r.ok);
    // Nothing. The typo is invisible. fsck-the-port matches C;
    // fsck-the-feature would warn here. Noted as a future TODO.
    assert!(r.findings.is_empty(), "{:?}", r.findings);
}

/// Variable check runs on ALL hosts files, not just `hosts/MYNAME`.
#[test]
fn checks_all_hosts() {
    let dir = tempfile::tempdir().unwrap();
    let (confbase, paths) = paths_at(&dir);
    init(&paths, "alice");

    // Create hosts/bob with a server-only var.
    fs::write(
        confbase.join("hosts/bob"),
        "Ed25519PublicKey = abc\nDevice = /dev/foo\n",
    )
    .unwrap();

    let r = run(&paths, false).unwrap();
    // The Device line in hosts/bob.
    let f = r
        .findings
        .iter()
        .find(|f| matches!(f, Finding::ServerVarInHost { .. }))
        .unwrap();
    let Finding::ServerVarInHost { source, .. } = f else {
        unreachable!()
    };
    let Source::File { path, .. } = source else {
        panic!("expected File source")
    };
    assert!(path.ends_with("hosts/bob"));
}

/// `hosts/` entries failing `check_id` are skipped. `.dotfile`,
/// `with-dash`, etc. — not valid node names, so not host files.
#[test]
fn hosts_non_id_skipped() {
    let dir = tempfile::tempdir().unwrap();
    let (confbase, paths) = paths_at(&dir);
    init(&paths, "alice");

    // Dash isn't valid in node names (`check_id`: `[A-Za-z0-9_]+`).
    // This file has a server-only var, but it's not a host file
    // because the name is invalid → no warning.
    fs::write(confbase.join("hosts/with-dash"), "Device = /dev/foo\n").unwrap();

    let r = run(&paths, false).unwrap();
    assert_eq!(
        count(&r, |f| matches!(f, Finding::ServerVarInHost { .. })),
        0
    );
}

/// `conf.d/*.conf` is included in the variable check. The
/// 40719189 fix in `read_server_config` carries through here:
/// fsck on a `conf.d/` config actually checks `conf.d/`.
#[test]
fn confd_checked() {
    let dir = tempfile::tempdir().unwrap();
    let (confbase, paths) = paths_at(&dir);
    init(&paths, "alice");

    fs::create_dir(confbase.join("conf.d")).unwrap();
    // Port is HOST-only.
    fs::write(confbase.join("conf.d/10-net.conf"), "Port = 655\n").unwrap();

    let r = run(&paths, false).unwrap();
    let f = r
        .findings
        .iter()
        .find(|f| matches!(f, Finding::HostVarInServer { .. }))
        .unwrap();
    let Finding::HostVarInServer { source, .. } = f else {
        unreachable!()
    };
    let Source::File { path, .. } = source else {
        panic!("expected File source")
    };
    // The 40719189-ported behavior: this finding *exists*. HEAD
    // C would never read this file.
    assert!(path.ends_with("10-net.conf"));
}

// Display formatting smoke tests

/// Every variant has a `Display` impl. Exhaustiveness check.
/// (The match in `Display` is already exhaustive — Rust enforces
/// it. This tests that no variant `panic!`s in formatting, and
/// that the messages contain the expected user-greppable bits.)
#[test]
fn display_exhaustive() {
    use Finding as F;
    let p = PathBuf::from("/x/y");
    let s = Source::File {
        path: p.clone(),
        line: 5,
    };
    // One of each variant. Format and check for the key phrase.
    let cases: &[(Finding, &str)] = &[
        (F::TincConfMissing, "No such file"),
        (
            F::TincConfDenied {
                running_as_root: false,
            },
            "sudo",
        ),
        (
            F::TincConfDenied {
                running_as_root: true,
            },
            "permissions of each",
        ),
        (F::NoName, "valid Name"),
        (F::ConfigReadFailed("err".into()), "err"),
        (F::NoPrivateKey { path: p.clone() }, "Ed25519 private"),
        (
            F::NoPublicKey {
                host_file: p.clone(),
            },
            "public Ed25519",
        ),
        (
            F::KeyMismatch {
                host_file: p.clone(),
            },
            "do not match",
        ),
        (
            F::HostFileUnreadable {
                host_file: p.clone(),
            },
            "/x/y",
        ),
        (
            F::UnsafeKeyMode {
                path: p.clone(),
                mode: 0o640,
                uid_match: true,
            },
            "0640",
        ),
        (
            F::UnsafeKeyMode {
                path: p.clone(),
                mode: 0o640,
                uid_match: false,
            },
            "same uid",
        ),
        (F::UnknownScript { path: p.clone() }, "tinc-up, tinc-down"),
        (F::ScriptNotExecutable { path: p.clone() }, "execute"),
        (
            F::ScriptAccessError {
                path: p.clone(),
                err: "e".into(),
            },
            "/x/y: e",
        ),
        (
            F::DirUnreadable {
                path: p.clone(),
                err: "e".into(),
            },
            "directory",
        ),
        (
            F::ObsoleteVar {
                name: "X".into(),
                source: s.clone(),
            },
            "obsolete",
        ),
        (
            F::HostVarInServer {
                name: "X".into(),
                source: s.clone(),
            },
            "server config",
        ),
        (
            F::ServerVarInHost {
                name: "X".into(),
                source: s,
            },
            "host config",
        ),
        (
            F::DuplicateVar {
                name: "X".into(),
                where_: "tinc.conf".into(),
            },
            "multiple",
        ),
        (F::FixedMode { path: p.clone() }, "Fixed permissions"),
        (F::FixedPublicKey { path: p.clone() }, "Wrote Ed25519"),
        (
            F::FixFailed {
                path: p,
                err: "e".into(),
            },
            "could not fix",
        ),
    ];
    for (f, needle) in cases {
        let formatted = f.to_string();
        assert!(
            formatted.contains(needle),
            "expected `{needle}` in `{formatted}`"
        );
    }
}

/// Severity assignments. Spot-check the three buckets.
#[test]
fn severity_buckets() {
    assert_eq!(Finding::TincConfMissing.severity(), Severity::Error);
    assert_eq!(
        Finding::ObsoleteVar {
            name: "x".into(),
            source: Source::Cmdline { line: 0 }
        }
        .severity(),
        Severity::Warning
    );
    assert_eq!(
        Finding::FixedMode {
            path: PathBuf::from("/x")
        }
        .severity(),
        Severity::Info
    );
}
